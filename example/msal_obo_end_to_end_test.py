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
        default=os.getenv("GRAPH_URL", "https://graph.microsoft.com/v1.0/me"),
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


def call_graph_me(graph_url: str, access_token: str) -> dict:
    print("Step 3/3: calling Microsoft Graph with OBO token")
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

    user_assertion = args.user_assertion
    if not user_assertion:
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
        profile = call_graph_me(args.graph_url, obo_token.access_token)
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
