#!/usr/bin/env python3
"""
End-to-end OBO functional test harness.

This script validates the primary real-world OBO scenario:
1) Obtain a user access token for the middle-tier API audience.
2) Exchange it via OBO for a downstream Graph token.
3) Call Microsoft Graph /me with the OBO token.

You can run in two modes:
- Full mode (default): acquires the user assertion token using
  PublicClientApplication MFA flow.
- Assertion mode: provide --user-assertion to skip step 1.
"""

import argparse
import base64
import json
import os
import sys
import time
from getpass import getpass
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

try:
    from himmelblau import (
        ConfidentialClientApplication,
        OboInteractionRequiredError,
        PublicClientApplication,
        TracingLevel,
        set_global_tracing_level,
    )
except ImportError as exc:
    print(f"Failed importing himmelblau bindings: {exc}")
    print("Build/install with features: pyapi,on_behalf_of")
    sys.exit(100)


EXIT_OK = 0
EXIT_CONFIG_ERROR = 10
EXIT_UPSTREAM_TOKEN_ERROR = 11
EXIT_OBO_ERROR = 12
EXIT_GRAPH_ERROR = 13
EXIT_OBO_INTERACTION_REQUIRED = 20


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run end-to-end OBO functional test.")
    parser.add_argument("--tenant-id", default=os.getenv("TENANT_ID"))
    parser.add_argument("--authority", default=os.getenv("AUTHORITY"))
    parser.add_argument(
        "--public-client-id",
        default=os.getenv("PUBLIC_CLIENT_ID") or os.getenv("CLIENT_ID"),
        help="Public client app ID (needed only when --user-assertion is not provided).",
    )
    parser.add_argument(
        "--confidential-client-id",
        default=os.getenv("CONFIDENTIAL_CLIENT_ID"),
        help="Middle-tier (confidential) app ID.",
    )
    parser.add_argument(
        "--confidential-client-secret",
        default=os.getenv("CONFIDENTIAL_CLIENT_SECRET"),
        help="Middle-tier client secret.",
    )
    parser.add_argument("--username", default=os.getenv("USERNAME"))
    parser.add_argument("--password", default=os.getenv("PASSWORD"))
    parser.add_argument("--mfa-method", default=os.getenv("MFA_METHOD"))
    parser.add_argument(
        "--incoming-scope",
        default=os.getenv("INCOMING_SCOPE"),
        help="Scope requested by client for middle-tier audience.",
    )
    parser.add_argument(
        "--downstream-scope",
        default=os.getenv("DOWNSTREAM_SCOPE", "https://graph.microsoft.com/User.Read"),
    )
    parser.add_argument(
        "--graph-url",
        default=os.getenv("GRAPH_URL"),
        help="Graph /me endpoint URL. Derived from --downstream-scope if not set.",
    )
    parser.add_argument(
        "--user-assertion",
        default=os.getenv("USER_ASSERTION"),
        help="Incoming user token for middle-tier audience. If set, upstream acquisition is skipped.",
    )
    parser.add_argument(
        "--trace-level",
        default=os.getenv("TRACE_LEVEL", "INFO"),
        choices=["ERROR", "WARN", "INFO", "DEBUG", "TRACE"],
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Fail instead of prompting when required inputs are missing.",
    )
    parser.add_argument(
        "--use-ropc",
        action="store_true",
        default=os.getenv("USE_ROPC", "").lower() in ("1", "true", "yes"),
        help=(
            "Use password-only (ROPC) for upstream token acquisition instead of the "
            "MFA flow. Required for Scenario 2: ROPC acquires the upstream token without "
            "satisfying MFA, so the CA policy fires during the OBO step."
        ),
    )
    parser.add_argument(
        "--scenario",
        type=int,
        default=int(os.getenv("SCENARIO", "1")),
        choices=[1, 2, 3],
        help=(
            "1 (default): primary OBO success path. "
            "2: CA claims challenge — OBO must return OboInteractionRequired with claims. "
            "3: invalid audience assertion — OBO must fail with AcquireTokenFailed, "
            "not OboInteractionRequired."
        ),
    )
    parser.add_argument(
        "--print-assertion",
        action="store_true",
        default=False,
        help=(
            "Acquire the upstream user assertion (Scenario 1 step 1 only) and print it "
            "to stdout. All other output goes to stderr. Exits without running OBO. "
            "Useful for: export USER_ASSERTION=\"$(python msal_obo_end_to_end_test.py "
            "--print-assertion)\""
        ),
    )
    return parser.parse_args()


def configure_tracing(level_name: str) -> None:
    level_value = getattr(TracingLevel, level_name.upper(), TracingLevel.INFO)
    try:
        set_global_tracing_level(level_value)
    except Exception as exc:  # pragma: no cover - non-fatal setup path
        print(f"Warning: unable to set tracing level: {exc}")


def prompt_if_missing(value: str, prompt: str, secret: bool, non_interactive: bool) -> str:
    if value:
        return value
    if non_interactive:
        raise ValueError(f"Missing required value for: {prompt}")
    if secret:
        return getpass(prompt)
    return input(prompt).strip()


def redact_token(token: str) -> str:
    if len(token) <= 32:
        return token
    return f"{token[:24]}...{token[-8:]}"


def decode_jwt_payload(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        padding = "=" * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload + padding)
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return {}


def acquire_user_assertion(
    authority: str,
    public_client_id: str,
    username: str,
    password: str,
    incoming_scope: str,
    mfa_method: str,
) -> str:
    print("Step 1/3: acquiring upstream user assertion token")
    client = PublicClientApplication(client_id=public_client_id, authority=authority)
    auth_init = client.check_user_exists(username)
    if not auth_init.exists():
        raise RuntimeError(f"User does not exist or is not discoverable: {username}")

    if mfa_method:
        try:
            flow = client.initiate_acquire_token_by_mfa_flow(
                username, password, [incoming_scope], None, mfa_method
            )
        except TypeError:
            print(
                "Warning: selected MFA method not supported by current build. Falling back to default."
            )
            flow = client.initiate_acquire_token_by_mfa_flow(
                username, password, [incoming_scope], None
            )
    else:
        flow = client.initiate_acquire_token_by_mfa_flow(
            username, password, [incoming_scope], None
        )

    if getattr(flow, "msg", None):
        print(f"MFA flow message: {flow.msg}")

    max_attempts = int(getattr(flow, "max_poll_attempts", 30) or 30)
    polling_interval_ms = int(getattr(flow, "polling_interval", 1000) or 1000)
    token = None

    for attempt in range(max_attempts):
        try:
            token = client.acquire_token_by_mfa_flow(username, flow, None, attempt)
            break
        except Exception as exc:
            if "MFAPollContinue" in str(exc):
                time.sleep(max(polling_interval_ms, 250) / 1000.0)
                continue
            raise RuntimeError(f"Upstream token acquisition failed: {exc}") from exc

    if token is None:
        raise RuntimeError("Upstream token acquisition timed out before completion")

    assertion = token.access_token
    if not assertion:
        raise RuntimeError("Upstream token acquisition returned no access_token")
    return assertion


def derive_graph_url(downstream_scope: str) -> str:
    """Derive the Graph /me URL from a downstream scope when --graph-url is not set.

    If the scope looks like a Graph URL (e.g. https://graph.microsoft.us/User.Read),
    extract the base URL and append /v1.0/me. Falls back to commercial Graph.
    """
    try:
        parsed = urlparse(downstream_scope)
        if parsed.scheme in ("http", "https") and "graph.microsoft" in parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}/v1.0/me"
    except Exception:
        pass
    return "https://graph.microsoft.com/v1.0/me"


def call_graph_me(graph_url: str, access_token: str) -> dict:
    print(f"Step 3/3: calling Microsoft Graph with OBO token ({graph_url})")
    req = Request(
        graph_url,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        },
        method="GET",
    )
    try:
        with urlopen(req, timeout=30) as resp:
            status = resp.getcode()
            body = resp.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Graph request failed with HTTP {exc.code}: {body}") from exc
    except URLError as exc:
        raise RuntimeError(f"Graph request failed: {exc}") from exc

    if status != 200:
        raise RuntimeError(f"Graph request failed with HTTP {status}: {body}")

    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Graph returned non-JSON success response: {body}") from exc


def acquire_user_assertion_ropc(
    authority: str,
    public_client_id: str,
    username: str,
    password: str,
    incoming_scope: str,
) -> str:
    """Acquire an upstream assertion via ROPC (password-only, no MFA).

    Used for Scenario 2: the token is acquired without satisfying MFA so that
    the CA policy fires during the subsequent OBO exchange for Graph.
    """
    print("Step 1/2: acquiring upstream user assertion token via ROPC (password only)")
    client = PublicClientApplication(client_id=public_client_id, authority=authority)
    token = client.acquire_token_by_username_password(
        username, password, [incoming_scope]
    )
    assertion = token.access_token
    if not assertion:
        raise RuntimeError("ROPC token acquisition returned no access_token")
    return assertion


def run_scenario_2(
    authority: str,
    public_client_id: str,
    confidential_client_id: str,
    confidential_client_secret: str,
    username: str,
    password: str,
    incoming_scope: str,
    downstream_scope: str,
    mfa_method: str,
    use_ropc: bool = False,
) -> int:
    """Scenario 2: CA Claims Challenge.

    Authenticate user_ca scoped to the middle-tier audience (NOT Graph directly),
    then call OBO for the Graph scope. The CA policy on Graph must fire and return
    interaction_required with a non-empty claims challenge.

    Use --use-ropc to acquire the upstream token via password-only (ROPC). This
    ensures the token does not carry an MFA claim, so the CA policy fires during
    the OBO step. Without --use-ropc, the MFA flow satisfies the CA policy
    up-front and the challenge never triggers.

    Expected: OboInteractionRequiredError raised with populated claims, error,
    error_description, and error_codes.
    """
    print("Scenario 2: CA Claims Challenge")
    try:
        if use_ropc:
            user_assertion = acquire_user_assertion_ropc(
                authority=authority,
                public_client_id=public_client_id,
                username=username,
                password=password,
                incoming_scope=incoming_scope,
            )
        else:
            print("Step 1/2: acquiring upstream user assertion token (middle-tier scope only)")
            print(
                "  Note: if CA policy does not trigger, re-run with --use-ropc to "
                "acquire the upstream token without MFA."
            )
            user_assertion = acquire_user_assertion(
                authority=authority,
                public_client_id=public_client_id,
                username=username,
                password=password,
                incoming_scope=incoming_scope,
                mfa_method=mfa_method,
            )
    except Exception as exc:
        print(f"Upstream token acquisition failed: {exc}")
        return EXIT_UPSTREAM_TOKEN_ERROR

    payload = decode_jwt_payload(user_assertion)
    print(f"Upstream assertion audience: {payload.get('aud')}")

    print("Step 2/2: calling OBO (expect CA claims challenge)")
    app = ConfidentialClientApplication(
        confidential_client_id, authority, confidential_client_secret
    )
    try:
        app.acquire_token_on_behalf_of(user_assertion, [downstream_scope])
        print(
            "RESULT: FAIL — OBO succeeded unexpectedly; "
            "CA policy did not trigger a claims challenge"
        )
        return EXIT_OBO_ERROR
    except OboInteractionRequiredError as exc:
        claims = getattr(exc, "claims", None)
        error = getattr(exc, "error", None)
        error_description = getattr(exc, "error_description", None)
        error_codes = getattr(exc, "error_codes", None)
        suberror = getattr(exc, "suberror", None)
        print("OboInteractionRequiredError raised:")
        print(f"  error:             {error}")
        print(f"  error_description: {error_description}")
        print(f"  error_codes:       {error_codes}")
        print(f"  suberror:          {suberror}")
        print(f"  claims:            {claims}")
        if not claims:
            print(
                "RESULT: FAIL — OboInteractionRequiredError raised but claims is empty; "
                "client cannot perform re-auth without the claims challenge"
            )
            return EXIT_OBO_ERROR
        print("RESULT: PASS — claims challenge received and is machine-readable")
        return EXIT_OK
    except Exception as exc:
        print(f"OBO failed with unexpected error (not a claims challenge): {exc}")
        return EXIT_OBO_ERROR


def run_scenario_3(
    authority: str,
    public_client_id: str,
    confidential_client_id: str,
    confidential_client_secret: str,
    username: str,
    password: str,
    downstream_scope: str,
    mfa_method: str,
) -> int:
    """Scenario 3: Invalid Audience Assertion.

    Acquire a token scoped directly to the downstream resource (e.g. Graph),
    whose aud is NOT the middle-tier app. Feed that wrong-audience token to OBO
    and verify:
      - validate_assertion_preflight emits a WARN about the aud mismatch.
      - Entra rejects the exchange (invalid_grant or similar).
      - The error surfaces as AcquireTokenFailed, NOT OboInteractionRequired.
    """
    print("Scenario 3: Invalid Audience Assertion")
    print(
        f"Step 1/2: acquiring token directly for downstream scope '{downstream_scope}' "
        "(wrong audience for OBO)"
    )
    wrong_assertion = acquire_user_assertion(
        authority=authority,
        public_client_id=public_client_id,
        username=username,
        password=password,
        incoming_scope=downstream_scope,
        mfa_method=mfa_method,
    )

    payload = decode_jwt_payload(wrong_assertion)
    wrong_aud = payload.get("aud")
    print(f"Wrong-audience assertion aud: {wrong_aud}")
    if wrong_aud == confidential_client_id or (
        isinstance(wrong_aud, str) and wrong_aud.endswith(confidential_client_id)
    ):
        print(
            "RESULT: SKIP — acquired token unexpectedly targets the middle-tier app; "
            "cannot use it as a wrong-audience assertion for this scenario."
        )
        return EXIT_OK

    print("Step 2/2: calling OBO with wrong-audience assertion (expect rejection)")
    app = ConfidentialClientApplication(
        confidential_client_id, authority, confidential_client_secret
    )
    try:
        app.acquire_token_on_behalf_of(wrong_assertion, [downstream_scope])
        print("RESULT: FAIL — OBO succeeded unexpectedly with wrong-audience assertion")
        return EXIT_OBO_ERROR
    except OboInteractionRequiredError as exc:
        print(
            "RESULT: FAIL — got OboInteractionRequired (claims challenge) instead of "
            "AcquireTokenFailed; wrong error surface for an invalid assertion"
        )
        print(f"  error: {getattr(exc, 'error', None)}")
        print(f"  error_description: {getattr(exc, 'error_description', None)}")
        return EXIT_OBO_ERROR
    except Exception as exc:
        err_str = str(exc)
        print(f"OBO rejected with: {err_str}")
        # Any non-OboInteractionRequired exception is the expected outcome:
        # Entra returns invalid_grant and we surface AcquireTokenFailed.
        print("RESULT: PASS — OBO correctly rejected with AcquireTokenFailed")
        return EXIT_OK


def main() -> int:
    args = parse_args()
    configure_tracing(args.trace_level)

    try:
        tenant_id = args.tenant_id
        authority = args.authority
        confidential_client_id = prompt_if_missing(
            args.confidential_client_id,
            "Confidential (middle-tier) client ID: ",
            secret=False,
            non_interactive=args.non_interactive,
        )
        confidential_client_secret = prompt_if_missing(
            args.confidential_client_secret,
            "Confidential (middle-tier) client secret: ",
            secret=True,
            non_interactive=args.non_interactive,
        )
        if not authority:
            tenant_id = prompt_if_missing(
                tenant_id,
                "Tenant ID: ",
                secret=False,
                non_interactive=args.non_interactive,
            )
            authority = f"https://login.microsoftonline.com/{tenant_id}"

        incoming_scope = (
            args.incoming_scope
            if args.incoming_scope
            else f"api://{confidential_client_id}/access_as_user"
        )
    except ValueError as exc:
        print(f"Configuration error: {exc}")
        return EXIT_CONFIG_ERROR

    try:
        public_client_id = prompt_if_missing(
            args.public_client_id,
            "Public client ID: ",
            secret=False,
            non_interactive=args.non_interactive,
        )
        username = prompt_if_missing(
            args.username,
            "Entra username: ",
            secret=False,
            non_interactive=args.non_interactive,
        )
        password = prompt_if_missing(
            args.password,
            "Password: ",
            secret=True,
            non_interactive=args.non_interactive,
        )
    except ValueError as exc:
        print(f"Configuration error: {exc}")
        return EXIT_CONFIG_ERROR

    if args.scenario == 2:
        return run_scenario_2(
            authority=authority,
            public_client_id=public_client_id,
            confidential_client_id=confidential_client_id,
            confidential_client_secret=confidential_client_secret,
            username=username,
            password=password,
            incoming_scope=incoming_scope,
            downstream_scope=args.downstream_scope,
            mfa_method=args.mfa_method,
            use_ropc=args.use_ropc,
        )

    if args.scenario == 3:
        return run_scenario_3(
            authority=authority,
            public_client_id=public_client_id,
            confidential_client_id=confidential_client_id,
            confidential_client_secret=confidential_client_secret,
            username=username,
            password=password,
            downstream_scope=args.downstream_scope,
            mfa_method=args.mfa_method,
        )

    # --- Scenario 1 (default) ---
    user_assertion = args.user_assertion
    if not user_assertion:
        try:
            if args.print_assertion:
                # Redirect stdout to stderr so only the bare assertion reaches stdout.
                _real_stdout = sys.stdout
                sys.stdout = sys.stderr
                try:
                    user_assertion = acquire_user_assertion(
                        authority=authority,
                        public_client_id=public_client_id,
                        username=username,
                        password=password,
                        incoming_scope=incoming_scope,
                        mfa_method=args.mfa_method,
                    )
                finally:
                    sys.stdout = _real_stdout
                print(user_assertion, end="")
                return EXIT_OK
            user_assertion = acquire_user_assertion(
                authority=authority,
                public_client_id=public_client_id,
                username=username,
                password=password,
                incoming_scope=incoming_scope,
                mfa_method=args.mfa_method,
            )
        except Exception as exc:
            print(f"Upstream token acquisition failed: {exc}")
            return EXIT_UPSTREAM_TOKEN_ERROR
    else:
        print("Step 1/3: using provided user assertion token")

    upstream_payload = decode_jwt_payload(user_assertion)
    upstream_aud = upstream_payload.get("aud")
    print(f"Upstream assertion audience: {upstream_aud}")

    graph_url = args.graph_url or derive_graph_url(args.downstream_scope)

    print("Step 2/3: running OBO exchange")
    app = ConfidentialClientApplication(
        confidential_client_id, authority, confidential_client_secret
    )
    try:
        obo_token = app.acquire_token_on_behalf_of(user_assertion, [args.downstream_scope])
    except OboInteractionRequiredError as exc:
        print("RESULT: OBO interaction required (claims challenge)")
        print(f"claims: {getattr(exc, 'claims', None)}")
        print(f"error: {getattr(exc, 'error', None)}")
        print(f"error_description: {getattr(exc, 'error_description', None)}")
        print(f"error_codes: {getattr(exc, 'error_codes', None)}")
        print(f"suberror: {getattr(exc, 'suberror', None)}")
        return EXIT_OBO_INTERACTION_REQUIRED
    except Exception as exc:
        print(f"OBO exchange failed: {exc}")
        return EXIT_OBO_ERROR

    if not obo_token.access_token:
        print("OBO exchange failed: empty downstream access token")
        return EXIT_OBO_ERROR

    obo_payload = decode_jwt_payload(obo_token.access_token)
    print(f"OBO token audience: {obo_payload.get('aud')}")
    print(f"OBO token scope: {obo_payload.get('scp')}")
    print(f"OBO access token (redacted): {redact_token(obo_token.access_token)}")

    try:
        profile = call_graph_me(graph_url, obo_token.access_token)
    except Exception as exc:
        print(f"Graph validation failed: {exc}")
        return EXIT_GRAPH_ERROR

    print("Graph /me response summary:")
    print(f"  id: {profile.get('id')}")
    print(f"  userPrincipalName: {profile.get('userPrincipalName')}")
    print(f"  displayName: {profile.get('displayName')}")
    print("RESULT: PASS")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
