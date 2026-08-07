# Windows–Linux Entra ID parity roadmap

## Purpose

This document is an implementation roadmap for closing client-identity lifecycle gaps between Windows and the Himmelblau Linux stack. It compares the behavior demonstrated by ROADtools and AADInternals with both `libhimmelblau` and its primary consumer, `himmelblau`, then assigns each missing behavior to exactly one repository.

The target is practical Windows parity for an Entra-joined or Entra-registered Linux workstation: sign-in, device registration and removal, Primary Refresh Token (PRT) lifecycle, brokered SSO, Windows Hello/passkeys, certificate and Kerberos authentication, the identity lookups needed by a Linux identity provider, and device management enrollment/check-in.

This is not a request to copy the offensive or tenant-administration surface of the reference projects. Reconnaissance, token theft, forged identities, tenant mutation, credential extraction, persistence tooling, browser injection, and command-line presentation are deliberately excluded.

## Audit basis and reproducibility

The audit used these snapshots:

| Project | Revision audited | Role |
| --- | --- | --- |
| `libhimmelblau` | `18b054e` (crate 0.8.28) | Reusable Rust protocol library under assessment |
| ROADtools | `f72a752700ff5142cc9bfd4cc90391ce5653415d` | Independent implementation and protocol evidence |
| AADInternals | `13f207d9ec08761ac85d9fb1311ecb719e25add4` | Windows/Entra behavior and protocol evidence |
| `himmelblau` | `bc95198711603e7dc81bcd4ef8e75e465335c8c8` | Linux host integration and primary library consumer |

Important source anchors include ROADtools `roadlib/roadtools/roadlib/auth.py`, `deviceauth.py`, `wstrust.py`, and `webauthn.py`; AADInternals `PRT.ps1`, `PRT_Utils.ps1`, `MDM.ps1`, `MDM_utils.ps1`, `CBA.ps1`, `Kerberos.ps1`, and `MFA.ps1`; `libhimmelblau` `src/auth.rs`, `src/discovery.rs`, `src/intune.rs`, `src/graph.rs`, and `src/confidential_client.rs`; and Himmelblau `src/common/src/idprovider/himmelblau.rs`, `src/common/src/auth.rs`, `src/daemon/src/broker.rs`, and `src/daemon/src/prt_memfd.rs`.

ROADtools and AADInternals are behavioral references, not normative specifications. Where they disagree with current service behavior, Microsoft protocol specifications, standards, and captured integration tests must win. Particularly relevant primary documentation is [MS-DVRJ](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dvrj/), [MS-MDE2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mde2/4d7eadd5-3951-4f1c-8159-c39e07cbe692), [MS-MDM](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mdm/d9b0c913-b0b1-4ee5-883c-496a7ed1d3f9), [OMA-DM protocol support](https://learn.microsoft.com/en-us/windows/client-management/oma-dm-protocol-support), [claims challenges and client capabilities](https://learn.microsoft.com/en-us/entra/identity-platform/claims-challenge), and the [Seamless SSO native-client flow](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sso-how-it-works).

## Ownership rule

`libhimmelblau` owns portable protocol mechanisms: endpoints and HTTP rules, serialized wire models, JWT/JWS/JWE processing, cryptographic derivation and certificate formats, protocol-version negotiation, state machines, typed results, and typed errors. Its work is identified as `LIB-*`.

`himmelblau` owns machine and user policy: TPM/HSM key naming and persistence, PAM/NSS and offline authentication, account and token-cache lifecycle, D-Bus broker behavior, browser integration, enrollment UX, system services, policy application, and installation of Kerberos credentials. Its work is identified as `CLIENT-*`.

A cross-repository feature is intentionally represented as two dependency-linked cards. Do not put Linux filesystem, D-Bus, PAM, NSS, systemd, or UI decisions into the library merely to finish a client feature.

## What already exists

The following are not gaps and should be extended rather than reimplemented:

- `libhimmelblau` already performs managed-user password, device-code, authorization-code/MFA web, TAP, FIDO assertion, refresh-token, confidential-client, and on-behalf-of exchanges. OBO already accepts a claims challenge.
- Device discovery, ordinary Entra device registration, transport-key upload, Hello key provisioning, PRT acquisition and renewal, session-key derivation/JWE v2, PRT-backed access-token exchange, PRT SSO cookies, P2P certificates, Entra Kerberos TGT extraction, and Graph identity/group queries exist.
- The consumer already creates and protects device/transport/Hello keys, seals PRT material, persists it across daemon restarts using a sealed memfd, opportunistically renews PRTs, performs online/offline PAM flows, builds real authenticator-backed FIDO assertions, installs Kerberos caches, exposes a Linux identity broker, and implements Linux-native Intune enrollment, compliance, policy retrieval, and status reporting.

The existence of a primitive does not imply complete Windows parity. Several cards below harden versioning, claims, lifecycle, and broker semantics around those existing primitives.

## Priority and completion convention

- **P0** blocks a common sign-in, device lifecycle, or safe broker workflow.
- **P1** is required for broad enterprise parity but can follow the basic lifecycle.
- **P2** covers specialized deployment modes or newer protocol variants.

Every card is intended to be given independently to an implementation LLM. “Done” means public Rust API documentation, redacted fixture tests, negative tests, and no logging of passwords, refresh tokens, PRTs, session keys, private keys, assertions, or certificate private material. Tests that contact Entra must be opt-in and must not be the sole coverage.

---

# Part I — protocol behavior for `libhimmelblau`

## LIB-01 — Federated realm discovery and WS-Trust token acquisition

**Priority:** P0
**Evidence:** ROADtools `auth.py::user_discovery`, `get_mex`, and `get_saml_token_with_username_password`; `wstrust.py`; the explicit rejection of federated identities in `libhimmelblau/src/auth.rs`.
**Unblocks:** CLIENT-01.

Implement the native-client federated sign-in branch that Windows takes after home-realm discovery. Add typed user-realm/credential-type results that distinguish managed, federated, unknown, and consumer accounts and preserve federation metadata such as active-auth URL, federation protocol, cloud instance, tenant/domain hints, and branding fields without making consumers parse arbitrary JSON.

For a federated domain, download and parse WS-Trust MEX safely. Resolve WS-Trust 1.3 and 2005 endpoint references, preferring Windows Integrated endpoints only when the caller requests integrated authentication and otherwise selecting username-mixed endpoints. Resolve relative addresses against the MEX origin. Reject non-HTTPS endpoints by default, redirects to an unrelated origin, XML DTD/entity expansion, oversized XML, and unsupported bindings; offer an explicit test/development override rather than silently weakening validation.

Build SOAP RST requests for username/password authentication with correct WS-Addressing, WS-Security UsernameToken, timestamps, AppliesTo/audience, RequestType, KeyType, and SOAPAction. Parse success responses containing SAML 1.1 or SAML 2.0 assertions and parse SOAP faults into a typed `WsTrustError` retaining safe fault code/reason and retry classification. Never expose a password in a `Debug` implementation or error body.

The output is an assertion plus metadata; token redemption belongs in LIB-02. Keep transport injectable so MEX and SOAP fixtures can be tested without a live federation server.

**Acceptance criteria**

- Managed and federated fixture responses deserialize to distinct exhaustive enum variants.
- MEX fixtures containing multiple namespaces and both WS-Trust generations select the intended endpoint deterministically.
- SOAP 1.1/1.2 success and fault fixtures are covered, including malformed/expired responses and SAML 1.1 versus 2.0.
- XML parser hardening, URL validation, redirect policy, response-size limits, timeouts, and secret-redaction tests exist.
- The current managed-user path remains byte-for-byte compatible unless the caller opts into realm routing.

## LIB-02 — SAML bearer redemption for OAuth tokens and PRT bootstrap

**Priority:** P0
**Evidence:** ROADtools `authenticate_with_saml_*`, federated PRT acquisition in `deviceauth.py`, and the Seamless SSO native-client flow.
**Depends on:** LIB-01 for password federation; LIB-06 for Seamless SSO.

Add a reusable SAML bearer grant accepting an assertion produced by a trusted upstream authentication step. Support the Entra OAuth v1 resource-oriented token endpoint and v2 scope-oriented endpoint where the service accepts them, choosing the correct grant type and assertion encoding for SAML 1.1 and SAML 2.0. The caller must select client ID, tenant/authority, redirect URI if required, resource/scopes, optional claims, and whether refresh-token/PRT bootstrap artifacts are expected.

Do not validate the federation server's signature as though the library were the relying party—Entra performs that validation—but do parse enough metadata to reject empty, obviously malformed, or unexpectedly huge assertions before transmission. Return the same normalized token types used by existing managed flows while retaining raw service error codes, suberrors, correlation IDs, timestamps, and claims challenges.

Add the federated PRT bootstrap variant demonstrated by ROADtools: produce the correct device-bound request, redeem the SAML assertion, decrypt the returned session-key payload with existing transport-key/JWE machinery, and return a normal `PrimaryRefreshToken`. Avoid a second, incompatible PRT type.

**Acceptance criteria**

- Fixture tests verify form fields and encoding for SAML 1.1/2.0 against v1 and v2 endpoints.
- Ordinary access/refresh token and device-bound PRT responses normalize into existing public result types.
- Entra errors such as invalid audience, expired assertion, interaction required, and claims challenge remain distinguishable.
- Assertions and returned credentials are redacted in all debug/error output.

## LIB-03 — General claims, CAE capability, and challenge parsing across token flows

**Priority:** P0
**Evidence:** ROADtools generic `claims`/`cae` handling; AADInternals access-token utilities; Microsoft claims-challenge guidance.
**Unblocks:** CLIENT-05 and CLIENT-06.

Generalize caller-supplied claims beyond the existing OBO path. Introduce a validated claims-request value (structured builder plus raw JSON escape hatch) usable by authorization-code, refresh-token, PRT-backed, device-code continuation where supported, client-credential, and SAML redemption flows. Add a client-capabilities builder that can request `xms_cc: cp1` without overwriting caller claims. Serialize claims exactly once and preserve them through interactive redirects.

Provide a robust parser for `WWW-Authenticate: Bearer` challenges. It must handle multiple authentication schemes, quoted strings and escapes, commas inside quoted JSON/base64 values, case-insensitive parameter names, and either directly encoded JSON or the encoding Entra resources use. Return authorization URI, error, error description, and decoded claims as typed fields while retaining unknown parameters. Malformed or oversized challenges must fail closed without panicking.

Token errors must expose whether a retry is possible silently, needs an interactive transaction, requires claims, or is terminal. The library should not itself replay arbitrary resource requests; it should give the client enough information to invalidate an access-token cache entry and perform exactly one policy-controlled reacquisition.

**Acceptance criteria**

- Every applicable grant has request-shape tests proving claims and `cp1` survive encoding.
- A corpus of real/redacted and adversarial `WWW-Authenticate` headers is parsed correctly.
- Duplicate or conflicting claims are merged deterministically or rejected with a documented error.
- APIs remain source-compatible through optional builders or clearly documented migration shims.

## LIB-04 — Complete OAuth v1/resource and authorization-code/PKCE primitives

**Priority:** P1
**Evidence:** ROADtools parallel v1/v2 device-code, ROPC, refresh, authorization-code, client-credential and OBO implementations.

Make endpoint generation and grant serialization explicitly support both Entra OAuth generations rather than relying on flow-specific hard-coded URLs. Add a typed `TokenTarget` (`Resource` for v1, `Scopes` for v2) that makes invalid combinations unrepresentable. Expose authorization URL construction, state/nonce generation and validation hooks, PKCE S256 generation, redirect response parsing, and code redemption as public portable primitives; browser launching and loopback listeners remain client-owned.

Preserve Entra-specific parameters already used internally (`client_info`, `windows_api_version`, `amr_values`, login/domain hints, claims, correlation IDs) through a documented extension mechanism. Authority construction must support tenant IDs and approved aliases without permitting path/query injection. Discovery metadata should be cacheable but callers must be able to set sovereignty/cloud endpoints.

**Acceptance criteria**

- A matrix test covers every supported grant against v1/resource and v2/scope serialization.
- PKCE only permits S256 by default; state and nonce are generated with a CSPRNG and compared safely.
- Authority/tenant input has path traversal, URL injection, and sovereign-cloud tests.
- Existing high-level APIs continue to call the common implementation.

## LIB-05 — User certificate-based authentication (CBA)

**Priority:** P1
**Evidence:** AADInternals `CBA.ps1` and certificate-authentication helpers.

Implement Entra user CBA as a protocol state machine, not as a filesystem certificate loader. Accept an abstract signing key and certificate chain supplied by the caller. Start the authorize transaction, follow only validated Entra redirects, detect the CBA method, build the required certificate proof/signature, submit it, and return either an authorization result or a typed continuation for method choice, MFA, consent, claims, or failure.

The API must support certificates backed by TPM/PKCS#11 implementations whose private key is non-exportable. Define signing inputs and algorithms explicitly and validate that the selected certificate/key algorithm is service-supported. Validate transaction state, nonce, origin, redirect URI, and correlation. Treat server HTML/JavaScript as unstable: isolate any web-contract models, retain fixtures, and fail with `ProtocolChanged` rather than guessing when required fields disappear.

**Acceptance criteria**

- RSA certificate success and representative error/continuation fixture tests exist; add EC only if verified against the service.
- A mock non-exportable signer completes the flow without exposing key bytes.
- Redirect allowlisting, state/nonce checks, certificate-chain size limits, and redaction are tested.
- No Linux certificate-store or UI policy enters the library.

## LIB-06 — Seamless/Desktop SSO integrated-auth exchange

**Priority:** P1
**Evidence:** ROADtools Desktop SSO functions, AADInternals `Kerberos.ps1`, and Microsoft's documented native-client flow.
**Unblocks:** CLIENT-03; feeds LIB-02.

Implement the Entra integrated-auth half of Seamless SSO. Discover the tenant MEX endpoint, select its integrated Windows authentication endpoint, expose the expected Kerberos SPN/challenge to a caller-provided GSSAPI exchange, send the resulting Negotiate token, and extract the SAML assertion returned by Entra. Redeem that assertion through LIB-02.

Do not implement a Kerberos stack or read a credential cache directly. Define a small async callback/trait that consumes an SPN and optional server challenge and returns a GSS token, allowing the consumer to use system GSSAPI. Correctly handle multi-round `WWW-Authenticate: Negotiate`, channel-binding policy where available, proxy authentication separation, and cookies bound to the transaction. Never forward Negotiate material across an origin change.

**Acceptance criteria**

- Single- and multi-round mock GSS exchanges are covered.
- Cross-origin redirects, a missing Negotiate challenge, proxy 407, and replayed transaction state are rejected.
- The resulting SAML token uses the common LIB-02 redemption path.

## LIB-07 — Hybrid Entra device join (`JoinType=6`)

**Priority:** P1
**Evidence:** AADInternals `PRT_Utils.ps1` hybrid join and ROADtools `deviceauth.py`; [MS-DVRJ].
**Unblocks:** CLIENT-04.

Extend device enrollment with the hybrid-join request used for an existing AD computer identity. Model `ServerAdJoinData` independently from ordinary bearer-authorized join attributes: transport public key, target domain and tenant, device name/type/OS, source domain controller, and `ClientIdentity`. Build the client identity from the on-premises computer SID plus a correctly formatted UTC timestamp, hash/sign the required canonical bytes with a caller-provided AD device-certificate key, and emit `Type=sha256signed` and the signed blob.

The operation uses the DVRJ device URI/HTTP verb and authentication rules appropriate to hybrid join; it must not accidentally attach a user bearer token because ordinary join does. Return the device certificate, IDs and server metadata through the existing enrollment result where possible. Abstract the signing key so a non-exportable machine key works.

**Acceptance criteria**

- A golden request fixture proves property names, timestamp representation, signing input, signature encoding, HTTP method, URL, headers, and absence/presence of authorization.
- SID, domain, tenant and device-ID validation prevents injection or ambiguous canonicalization.
- Clock skew and service conflict/retry responses have typed errors.
- Existing join types 0/4/8 are unchanged.

## LIB-08 — Certificate-authenticated remote device deletion

**Priority:** P0
**Evidence:** AADInternals `Remove-AADIntDeviceFromAzureAD`; consumer currently clears local state only.
**Unblocks:** CLIENT-02.

Add the device self-removal protocol: send certificate-authenticated `DELETE` to the enrollment service's device resource (`EnrollmentServer/device/{deviceId}?api-version=1.0`) using the registered device certificate and key. Support the DVRJ client-name/version, request/correlation and return-client-request-id headers. The HTTP layer must support mTLS with a caller-provided certificate/private-key provider or preconfigured client, including non-exportable keys where the TLS backend permits it.

Return a typed deletion outcome: deleted, already absent/idempotently complete, unauthorized/certificate mismatch, conflict/retryable, or protocol error. Parse `AttestationResult.KeyId` when returned, but do not require it for idempotent success. Never delete local keys; that belongs to CLIENT-02 and only occurs after a policy decision based on this result.

**Acceptance criteria**

- URL path encoding prevents a crafted device ID from changing the endpoint.
- mTLS request, headers, success, not-found, auth failure, throttling, and malformed response fixtures are covered.
- Retry metadata honors `Retry-After`; automatic retries are limited to safe idempotent cases.

## LIB-09 — Device-certificate-signed OAuth token grant

**Priority:** P1
**Evidence:** ROADtools device-certificate token functions and AADInternals PRT utilities.

Implement the Entra grant in which a registered device proves possession of its device key/certificate to obtain device-scoped or broker bootstrap tokens. Build the signed JWT/client assertion with exact audience, issuer/subject/device identifiers, certificate thumbprint/header, nonce when required, issued-at/expiry, and unique JWT ID. Accept an abstract signer and certificate; do not assume PEM files.

Expose the operation as a narrowly typed device credential grant, not a generic “sign arbitrary JWT” API. Validate service nonce freshness and audience binding. Normalize the response with existing token types while retaining device-specific fields and error subcodes.

**Acceptance criteria**

- Golden JWT header/payload/signature-input fixtures match a reference capture.
- Nonce, clock-skew, audience, certificate mismatch, and unsupported-algorithm failures are tested.
- Maximum assertion lifetime is enforced and JWT IDs are never reused.

## LIB-10 — Bulk enrollment token/BPRT issuance and package model

**Priority:** P2
**Evidence:** AADInternals `New-BulkPRTToken`, ROADtools bulk-enrollment flow, and AADInternals MDE2 `BulkAADJ` context.
**Unblocks:** CLIENT-08 and CLIENT-11.

Implement issuance/renewal of the bulk enrollment artifact used by Windows provisioning. Model the requested display name, package ID replacement semantics, expiry (including the service's maximum), target tenant, and zero-touch correlation metadata. Perform the required access-token exchange and return a structured package containing the BPRT and non-secret identifiers rather than writing a JSON file.

Separate secret from metadata so callers can apply different storage and display policies. Validate expiry locally, surface tenant policy/licensing failures, and make replacement explicit to prevent accidental invalidation of an existing package. Add helpers that present the package as credentials to the existing device join/PRT and MDE2 layers without proliferating special-case string checks such as `package_` username detection.

**Acceptance criteria**

- New, replace, expired, overlong-expiry, unauthorized, and tenant-policy fixture cases exist.
- Secret-bearing package debug output is redacted and serialization is opt-in through a secrecy-aware wrapper.
- No file naming, permissions, CLI prompts, or provisioning policy is in the library.

## LIB-11 — PRT request completeness and protocol-version negotiation

**Priority:** P0
**Evidence:** ROADtools PRT v2/v3 exchange and `previous_refresh_token`; existing `libhimmelblau` v1 endpoint with Windows API versions 2.0/2.2.
**Unblocks:** CLIENT-05.

First make the currently implemented Windows API v2.x lifecycle complete. Audit acquisition, refresh-token bootstrap, renewal, access-token exchange, SSO-cookie, Hello, and TGT requests against redacted reference captures. Add missing fields such as `previous_refresh_token` where the service uses them, caller claims, client capabilities, request correlation, and server nonce freshness. Preserve rotated refresh/PRT/session-key material atomically in the returned result: callers must never combine a new PRT with the old session key after partial parsing.

Introduce a `PrtProtocolVersion` capability model. The server and configured client may negotiate only versions for which all crypto and response parsing are implemented. Unknown versions must return a typed unsupported-version error, never fall back after transmitting credentials. Retain version and key-generation metadata in `PrimaryRefreshToken` so a later exchange cannot silently choose the wrong KDF/JWE path.

**Acceptance criteria**

- Golden fixtures cover each existing PRT operation and the complete request field set.
- Rotation results are indivisible and previous-token retry semantics are documented/tested.
- Nonces are audience-bound, expiring, single-transaction values.
- Existing serialized PRTs migrate predictably or fail with an actionable version error.

## LIB-12 — PRT protocol v3 and v4 cryptography

**Priority:** P2
**Evidence:** ROADtools `deviceauth.py` `prt_protocol_version` 3.0/4.0 and v4 ECDH path.
**Depends on:** LIB-11.

Add version 3 only after v2 conformance, then add version 4 behind an explicit capability until verified against live Entra behavior. Implement each version as its own request/response and crypto strategy sharing only proven common pieces. V3 includes its changed broker request fields and proof semantics. V4 uses an EC device key, ES256 signatures, ECDH-ES key agreement, Concat KDF, and A256GCM response protection as demonstrated by ROADtools.

For V4, validate curve, peer public point, algorithm identifiers, `apu`/`apv`, key lengths, Concat-KDF OtherInfo, GCM nonce/tag, and JWE protected-header binding. Reject invalid EC points and algorithm substitution. Use constant-time, audited crypto crates and zeroize derived secrets. Do not present V4 as “Windows parity” until a Windows or Microsoft specification/capture confirms deployment; record it as observed Entra-client parity.

**Acceptance criteria**

- Independent known-answer tests cover signatures, ECDH shared secret, Concat KDF and AES-GCM.
- Cross-version downgrade, wrong curve, altered header, invalid tag, and replay tests fail closed.
- A protocol transcript fixture covers acquisition and one broker exchange for each version.

## LIB-13 — Passkey/WebAuthn credential registration protocol

**Priority:** P1
**Evidence:** ROADtools `webauthn.py` credential creation/attestation and `registerpasskey`; consumer currently supports assertions for authentication but not registration.
**Unblocks:** CLIENT-07.

Add the Entra/Graph wire portion of passkey registration. Retrieve creation options/challenge for the target user, deserialize `PublicKeyCredentialCreationOptions`, validate RP ID/origin/user binding, and accept an authenticator-produced attestation object and client-data JSON. Encode the credential ID, transports, AAGUID, COSE public key, attestation, display name and Graph payload exactly as required, then submit it and return the registered method metadata.

Do not generate or persist a software private key in the library. Define a request/response boundary compatible with platform authenticators, roaming FIDO2 keys, and caBLE where supported by the consumer. Validate `clientDataJSON.type == webauthn.create`, challenge equality, allowed algorithms, credential length, and authenticator-data RP ID hash before upload. Attestation trust policy should be caller-configurable but structural validation is mandatory.

Because parts of the registration endpoint may be beta/internal, isolate endpoint versions and response models, attach `ProtocolChanged` errors to missing required fields, and prefer published Microsoft Graph authentication-method APIs when equivalent.

**Acceptance criteria**

- Golden creation-options and Graph submission fixtures exist.
- Challenge/origin/RP mismatch, disallowed algorithm, malformed CBOR/COSE, duplicate credential, and expired transaction tests exist.
- Authentication assertion behavior remains unchanged.

## LIB-14 — Windows MDM discovery and MS-MDE2 enrollment

**Priority:** P1
**Evidence:** AADInternals `MDM.ps1` and `MDM_utils.ps1`; [MS-MDE2].
**Unblocks:** CLIENT-11.
**Relationship:** additive to, not a replacement for, `src/intune.rs` Linux Company Portal enrollment.

Implement the Windows-compatible management discovery/enrollment protocol as a separate module. Perform enterprise enrollment discovery and parse authentication/enrollment/policy/service URLs. Construct the MS-MDE2 enrollment request chain: obtain the applicable security token, request XCEP policy where required, generate the WSTEP/RST SOAP envelope, carry the CSR and device context (`DeviceType`, `ApplicationVersion`, `OSVersion`, `DeviceDisplayName`, `BulkAADJ`, optional zero-touch correlation), and parse the RSTR/provisioning document.

Return identity and management certificate chains, endpoint/account parameters, retry/enrollment schedule, server IDs, and raw unknown provisioning nodes in typed structures. Accept CSRs and signing operations from abstractions so the consumer can use TPM/HSM keys. Harden all XML as in LIB-01; provisioning documents are untrusted inputs. Validate certificate/key match and chain usage before returning success.

**Acceptance criteria**

- Discovery, SOAP request, normal enrollment, bulk enrollment, federated token, fault, and malformed provisioning fixtures exist.
- XML namespace variations do not break parsing; DTD/entity expansion and oversized content are rejected.
- Certificate/key mismatch, missing management endpoint, conflicting account nodes, throttling, and already-enrolled responses are typed.
- No system certificate installation or daemon scheduling occurs in the library.

## LIB-15 — OMA-DM/SyncML codec and authenticated transport

**Priority:** P1
**Evidence:** AADInternals `New-SyncMLRequest`, `Parse-SyncMLResponse`, `New-SyncMLAutoresponse`, `Invoke-SyncMLRequest`; [MS-MDM] and OMA-DM 1.2.
**Unblocks:** CLIENT-12.
**Depends on:** LIB-14 for enrollment credentials.

Implement a typed SyncML 1.2 device-management session codec. Model `SyncHdr`, credentials/meta, session/message IDs, status/results, sequence/atomic containers, and Add/Replace/Delete/Get/Exec commands with command references and target/source LocURIs. Parse server commands while preserving order and nesting, generate mandatory status acknowledgements, and expose commands to a consumer dispatcher. Unknown commands or CSP nodes must remain representable; they must not be reported as successfully applied.

Implement MS-MDM HTTP transport using the management certificate for TLS client authentication, `application/vnd.syncml.dm+xml`, the expected OMA-DM user agent, and required correlation/device headers. Support the maintenance endpoint returned by enrollment rather than permanently hard-coding one global URL. XML is the initial requirement; WBXML can be a later optimization only if a server requires it.

The session engine must enforce monotonically advancing message IDs, command-ID uniqueness, response correlation, maximum document/depth/item sizes, and a bounded number of server-command/autoresponse rounds. It returns typed work to the client; it does not interpret Linux settings or execute commands.

**Acceptance criteria**

- Round-trip fixtures cover headers, all required command types, nested Sequence/Atomic, status/results, and mixed known/unknown commands.
- Autoresponses correlate every command and accurately report unsupported/failed operations.
- Replay, duplicate command ID, excessive nesting, oversized data, endpoint change, mTLS failure, and retry-after behavior are tested.

## LIB-16 — Read-only user/device relationship queries

**Priority:** P1
**Evidence:** AADInternals MS Graph helpers for owned/registered devices; existing `src/graph.rs` user/group queries.

Extend the Graph client only with identity-provider-relevant read operations: a user's registered devices, owned devices, and the current device/user relationship needed to validate or repair local account binding. Support pagination, Graph error/throttle models, minimal `$select`, and stable v1.0 endpoints where available. Return a normalized directory-device record containing object/device IDs, display name, enabled state, trust/join type, OS, approximate last activity, ownership/registration relation, and extension data needed by existing mapping policy.

Do not add tenant-wide enumeration, credential retrieval, arbitrary OData execution, device mutation, or administration simply because reference projects expose them.

**Acceptance criteria**

- Owned versus registered relationships stay distinct.
- Pagination, deleted/disabled device, permission denied, throttling, and partial/null property fixtures exist.
- Query construction prevents OData or path injection.

## LIB-17 — Broker signed-HTTP-request proof primitive

**Priority:** P1
**Evidence:** the consumer D-Bus contract exposes `generateSignedHttpRequest` but returns “Not implemented”; Windows brokers support proof-of-possession request signing.
**Unblocks:** CLIENT-10.

Provide a narrowly scoped signed HTTP request (SHR)/proof-of-possession primitive compatible with the broker contract. Parse a broker request into method, absolute HTTPS URI, selected headers, body hash, nonce, access-token binding and key reference. Canonicalize exactly as the Entra scheme requires and return the signed artifact plus safe metadata.

The signing key must be abstract and non-exportable. Enforce an allowlist of signed headers, normalize URI host/port/path/query without semantic changes, bind method and body digest, reject ambiguous duplicate headers, and enforce nonce/audience/time windows. Never perform the target HTTP request inside this API.

Before implementation, capture the exact request/response JSON and JOSE profile from a current Windows broker or published Microsoft documentation; ROADtools/AADInternals do not alone establish this contract. If evidence is insufficient, complete a fixture-backed protocol note rather than inventing a format.

**Acceptance criteria**

- A Windows-derived golden vector verifies canonical bytes and signature.
- URI/header ambiguity, body tampering, nonce replay, wrong audience, clock skew, and unsupported algorithm tests exist.

---

# Part II — client behavior for `himmelblau`

## CLIENT-01 — Federated account sign-in orchestration

**Priority:** P0
**Depends on:** LIB-01 and LIB-02.

Route sign-in by realm discovery instead of treating federation as an authentication failure. For username/password PAM flows, invoke the WS-Trust username-mixed path only when the tenant advertises it and tenant policy permits password collection. For integrated federation or browser-only providers, return the appropriate interactive continuation; never scrape arbitrary AD FS forms.

Map federation faults into useful PAM/broker outcomes without revealing whether a guessed account exists more precisely than current behavior. Apply bounded timeouts and cancellation to discovery, MEX, federation and redemption as one transaction. Cache non-secret realm/MEX metadata with expiry and origin binding, but never cache passwords or SAML assertions.

**Acceptance criteria:** managed flows regress unchanged; WS-Trust federated fixture/integration flows work; unsupported federation produces an actionable interactive-required result; cancellation and offline behavior are deterministic; logs contain no credentials/assertions.

## CLIENT-02 — Atomic remote leave and local device cleanup

**Priority:** P0
**Depends on:** LIB-08.

Replace “clear local state” as the normal leave operation with a two-phase lifecycle. Resolve the exact tenant/device/account, authenticate deletion using its stored device certificate, call remote removal, then erase local device certificate, transport/Hello/Intune keys, PRT/refresh/access tokens, broker accounts, Kerberos caches, Intune enrollment state and identity mappings only after remote success or an explicit idempotent “already absent” result.

Persist a small leave journal before the network operation so a crash cannot create an unknowable half-state. If remote deletion cannot be completed, retain keys and mark `leave_pending`; provide an explicit administrator `--local-only` recovery action with a warning. Never delete another tenant's material due to a default-domain mismatch.

**Acceptance criteria:** crash tests at each phase recover safely; not-found is idempotent; auth/network failures preserve recoverable credentials; multi-tenant selection is exact; all per-device artifacts have an enumerated cleanup test.

## CLIENT-03 — Seamless SSO through system GSSAPI

**Priority:** P1
**Depends on:** LIB-06 and LIB-02.

Connect the library's integrated-auth callback to system GSSAPI using the logged-in user's credential cache. Select credentials for the requesting UID, not the daemon's account. Respect enterprise Kerberos configuration and DNS/SPN canonicalization policy, expose no raw ticket, and do not acquire password-based Kerberos credentials implicitly.

Use Seamless SSO as a pre-PRT bootstrap/fallback for managed hybrid users when configured and when a suitable cache exists. PRT SSO remains preferred after device registration. Map expired/missing tickets to a clean fallback; do not repeatedly contact Entra on every NSS lookup.

**Acceptance criteria:** UID isolation, correct SPN, cache selection, missing/expired cache fallback, cancellation, and no-ticket logging are tested with a fake GSS provider plus opt-in realm integration.

## CLIENT-04 — Hybrid-join machine identity workflow

**Priority:** P1
**Depends on:** LIB-07.

Add a privileged enrollment mode for machines that already possess the required AD computer certificate and SID. Discover/select the certificate and signing key through configured system/TPM/PKCS#11 sources, collect target tenant/domain and source-DC metadata, invoke hybrid join, then store the returned Entra device certificate and transport identity using existing HSM tags and permissions.

Preflight certificate expiry, SID match, domain/tenant mapping and clock synchronization. Never silently fall back to ordinary user-driven join because that changes trust type. Make reruns idempotent: detect a matching completed hybrid join, repair only missing local metadata, and refuse to overwrite a different device identity without an explicit leave.

**Acceptance criteria:** non-exportable signer integration, mismatch preflights, idempotent rerun, crash recovery, and join-type reporting are tested.

## CLIENT-05 — PRT/cache lifecycle hardening and CAE-aware reacquisition

**Priority:** P0
**Depends on:** LIB-03 and LIB-11.

Turn the current sealed PRT storage and opportunistic renewal into an explicit per-account lifecycle. Store protocol version, session-key generation, tenant/account/device binding, issue/renew/expiry times, and refresh-token family metadata atomically. Serialize renewal so two PAM/broker requests cannot rotate the same PRT concurrently. Commit a returned PRT/session-key/refresh-token set as one transaction, retaining the previous set only for a bounded documented recovery window.

Maintain access-token cache entries by home account, tenant, environment, client ID, normalized scopes/resource, token type, claims hash and key binding. Proactively refresh near expiry with randomized skew. When a resource supplies a CAE claims challenge, evict/bypass only the matching access token and make one claims-bearing silent request; propagate interactive-required instead of looping. Declare `cp1` only when this path is enabled.

**Acceptance criteria:** concurrent renewal, crash during rotation, clock change, device/account mismatch, daemon restart, claims challenge, throttling, invalid_grant and logout tests exist; no stale session key can be paired with a new PRT.

## CLIENT-06 — Complete interactive broker flow and cancellation

**Priority:** P0
**Depends on:** LIB-03 and LIB-04.

Implement `acquireTokenInteractively` as a real broker transaction rather than forwarding to silent acquisition. Parse and validate the broker request, try policy-compliant silent acquisition once, then launch/hand off an authorization-code + PKCE flow when interaction is required. Bind the transaction to requesting UID, D-Bus unique name, correlation ID, account/tenant, redirect URI, state, nonce, and a single-use cancellation token.

Implement `cancelInteractiveFlow` so it terminates browser/loopback/device-code work, removes temporary listeners and state, and returns a stable cancellation result even if completion races cancellation. Use a bounded transaction registry with expiry and per-UID quotas. Do not allow one process to cancel or receive another process's result.

**Acceptance criteria:** silent success, browser success, consent/MFA, claims challenge, user cancellation, caller disconnect, timeout, duplicate correlation ID, UID isolation, race and restart cleanup tests exist.

## CLIENT-07 — Passkey enrollment UX and authenticator integration

**Priority:** P1
**Depends on:** LIB-13.

Extend existing authenticator assertion support with credential creation. Offer enrollment only after recent strong authentication and policy discovery. Ask the selected platform/roaming authenticator to create a discoverable credential using the server options; present user verification/PIN/touch prompts through the existing conversation model; submit attestation with LIB-13; display and persist only non-secret method metadata.

Do not export authenticator private keys. Software passkey files demonstrated by ROADtools are not the default parity target and, if ever enabled for testing, require an explicit insecure/development gate. Handle duplicate/excluded credentials, authenticator cancellation, unsupported algorithms, tenant attestation policy, rename and partial registration recovery.

**Acceptance criteria:** hardware-backed mock creation, PIN/touch/cancel paths, duplicate credential, server rejection and crash before/after submission are tested; authentication with the new credential is verified in an opt-in integration test.

## CLIENT-08 — Bulk provisioning workflow

**Priority:** P2
**Depends on:** LIB-10; may feed CLIENT-11.

Provide an administrator-controlled workflow to create/import a bulk package, enroll one or more machines, and retire/rotate the package. Store BPRT material in the configured HSM/secret store with root-only access and explicit expiry; never place it in ordinary config, logs, shell arguments, or world-readable JSON. Record package ID and tenant separately for inventory without exposing the secret.

Require explicit confirmation for replacement because it can invalidate an existing package. Rate-limit use, record auditable non-secret outcomes, stop use at expiry, and remove the package after provisioning according to policy. A machine enrolled from BPRT must transition to its own device credentials and must not depend on the bulk secret for normal operation.

**Acceptance criteria:** import/create/replace/expire/revoke, multi-device use, interrupted enrollment, secret permissions and transition to unique device identity are tested.

## CLIENT-09 — Broker account removal and contract hardening

**Priority:** P0
**Depends on:** CLIENT-02 for device-wide removal; independent for account-only removal.

Implement the broker's currently missing `removeAccount` with an explicit distinction between removing one user's broker/token state and leaving the machine's Entra device. A normal application must only remove an account owned by its UID and must not erase the shared device certificate. Purge that account's PRT/access/refresh tokens, Hello association according to policy, pending interactions and Kerberos cache entries, then emit an account-change signal.

Honor and validate `protocol_version` instead of ignoring it. Echo/propagate correlation IDs through library calls and structured errors. Define stable JSON schemas and error codes for unsupported version, malformed request, account not found, interaction required, cancellation, claims required, throttling and internal failure. Enforce request-size, scopes-count and transaction quotas.

**Acceptance criteria:** per-UID isolation, multi-account preservation, protocol negotiation, schema compatibility, correlation, restart, malformed/oversized JSON and account-change notification tests exist.

## CLIENT-10 — Broker signed HTTP request

**Priority:** P1
**Depends on:** LIB-17.

Implement `generateSignedHttpRequest` by validating the broker JSON, resolving only a key/account owned by the requesting UID, invoking LIB-17, and returning the exact broker schema. Establish a policy for which client IDs, target origins, methods and headers may request proof-of-possession signatures. Never expose a general signing oracle over D-Bus.

Bind request lifetime and correlation, rate-limit signing, and log only account/key identifiers safe for audit. Reject requests whose body is omitted ambiguously, whose URI contains credentials/fragments, or whose requested headers differ after normalization.

**Acceptance criteria:** Windows-compatible success fixture, policy denial, cross-UID key request, arbitrary-signing attempt, body/header mutation, nonce replay, cancellation and rate-limit tests exist.

## CLIENT-11 — Windows-compatible MDE2 enrollment lifecycle

**Priority:** P1
**Depends on:** LIB-14; optionally LIB-10/CLIENT-08 for bulk enrollment.

Add a separate management backend/mode for MS-MDE2; retain the existing Linux Company Portal API backend. Generate identity/management keys in the TPM/HSM where possible, construct CSRs, call LIB-14, verify the returned certificates, and atomically persist certificates, server/account IDs, endpoint URLs, enrollment type, tenant/device binding and schedule. Choose backend through explicit configuration and discovery; never enroll both accidentally.

Implement enrollment recovery and unenrollment bookkeeping. A crash before credentials are committed must either resume from a journal or safely restart; a crash after server enrollment must not create unlimited duplicate identities. Integrate BPRT/zero-touch metadata only in provisioning mode. Make certificate renewal and expiry observable before service failure.

**Acceptance criteria:** interactive and bulk enrollment, non-exportable keys, duplicate/already-enrolled, partial commit, certificate renewal warning, backend selection and coexistence/migration policy tests exist.

## CLIENT-12 — OMA-DM service, session scheduler, and Linux CSP mapping

**Priority:** P1
**Depends on:** LIB-15 and CLIENT-11.

Run bounded background OMA-DM sessions using the enrolled management identity. Persist session/message counters and next-run/retry state atomically, honor server schedule and backoff, prevent concurrent sessions, and resume safely after reboot/network loss. Dispatch parsed commands to a strict allowlisted CSP registry.

Implement CSP nodes in small independently tested adapters. Each adapter validates type, range and platform support, stages changes, applies atomically where possible, and returns truthful SyncML status/results. Start with inventory and compliance reporting plus the Linux policies already modeled by the native Intune backend; add configuration CSPs only when there is a documented Linux semantic equivalent. Unknown or Windows-only CSPs must return `NotSupported`, never success. Atomic/Sequence semantics must roll back or report partial failure exactly as the protocol permits.

Protect the service against management-server compromise: cap document and command sizes, paths, execution time and output; never translate an arbitrary `Exec` URI or payload into a shell command; isolate privileged mutations; redact secrets; and audit non-secret command/result metadata.

**Acceptance criteria:** scheduled check-in, reboot resume, retry/throttle, duplicate session, inventory/results, supported/unsupported CSPs, Atomic rollback, malicious URI/data, resource exhaustion and certificate expiry tests exist.

## CLIENT-13 — Device relationship reconciliation

**Priority:** P1
**Depends on:** LIB-16.

Use owned/registered-device relationships to detect stale or conflicting local bindings during enrollment repair and diagnostics. Reconciliation must compare tenant, user home account, directory object ID, device ID and local certificate identity; display/report differences without automatically deleting directory objects. Cache results briefly and never make NSS identity resolution depend synchronously on Graph availability.

Provide clear states: healthy, directory device absent, disabled, user no longer owner/registrant, local certificate mismatch, permission insufficient, and offline/unknown. Automatic remediation is limited to refreshing local non-secret metadata; leave/rejoin requires the explicit CLIENT-02 lifecycle.

**Acceptance criteria:** multi-tenant/multi-device, disabled/deleted, relationship changed, insufficient permission, pagination and offline cache tests exist.

## CLIENT-14 — PRT protocol upgrade and key migration policy

**Priority:** P2
**Depends on:** LIB-12 and CLIENT-05.

Negotiate newer PRT protocol versions only for newly created or explicitly migrated device identities whose key type and HSM backend satisfy the version. Persist the negotiated version and key identifier with every PRT. Never silently replace an RSA device identity with EC or downgrade after a failed credential-bearing request.

Define migration as a journaled lifecycle: capability preflight, new key creation, service registration/update if required, acquisition of new PRT, atomic activation, bounded retention of old material, then destruction. Provide rollback before activation and administrator-visible recovery after it. Keep v4 disabled by default until service and Windows parity evidence is sufficient.

**Acceptance criteria:** upgrade, unsupported HSM, failed acquisition, crash at every phase, rollback, downgrade attack and old-cache compatibility tests exist.

## CLIENT-15 — User CBA certificate selection and sign-in integration

**Priority:** P1
**Depends on:** LIB-05.

Integrate user certificate-based authentication into PAM and broker interactive flows without reproducing AADInternals' Office/Admin portal HTML token extraction. Discover eligible certificates from configured PKCS#11 modules, TPM-backed stores, smart cards and administrator-approved filesystem stores; match tenant CBA policy, UPN/SAN issuer bindings, key usage, validity and supported signing algorithm; then present an unambiguous selection when more than one credential is eligible.

Use the selected non-exportable key through LIB-05. Route smart-card insertion, PIN, touch, certificate choice, MFA/consent and cancellation through the existing conversation state machine. Bind any PIN prompt to the requesting UID/session and let the token/provider enforce retry/lockout policy; never cache a PIN. Cache only non-secret certificate metadata and invalidate it on token removal, expiry or policy change.

Define fallback deliberately. A CBA failure must not silently submit a password or choose another certificate, but an interactive transaction may offer another tenant-approved method after reporting a typed continuation. Offline login using a prior CBA-backed session follows the existing offline policy; possession of the certificate alone must not create a new offline account.

**Acceptance criteria:** single/multiple/no eligible certificates, smart-card insertion/removal, non-exportable signing, PIN retry/lockout, issuer/UPN mismatch, expiry, cancellation, MFA continuation, UID isolation and secret-redaction tests exist.

---

# Recommended delivery order

1. **Safe baseline:** LIB-03, LIB-08, LIB-11; CLIENT-02, CLIENT-05, CLIENT-09.
2. **Federated and interactive sign-in:** LIB-01, LIB-02, LIB-04; CLIENT-01 and CLIENT-06.
3. **Enterprise authentication:** LIB-06 and CLIENT-03; LIB-05 and CLIENT-15; LIB-13 and CLIENT-07.
4. **Hybrid and broker completion:** LIB-07, LIB-17; CLIENT-04 and CLIENT-10.
5. **Management parity:** LIB-14, LIB-15; CLIENT-11 and CLIENT-12.
6. **Provisioning and advanced variants:** LIB-10, LIB-12; CLIENT-08 and CLIENT-14.
7. **Reconciliation:** LIB-16 and CLIENT-13 can proceed once the base Graph abstraction is stable.

This order prioritizes correctness of credentials already handled by Himmelblau before adding new ones. MDE2 and SyncML are intentionally late, separate subsystems: their certificate lifecycle, XML attack surface, privileged policy execution and conformance matrix deserve dedicated review.

# Cross-cutting implementation requirements

## API design

- Prefer typed builders and enums over maps of strings. Preserve unknown response fields where protocol evolution is common, but never require consumers to inspect raw JSON/XML for a normal branch.
- Make secrets use redacting wrappers and zeroize derived key material. No secret-bearing type may derive ordinary `Debug`, `Display`, `Clone`, or serde serialization casually.
- All keys must work through signing/decryption/TLS traits where technically possible; exported PEM/DER private keys cannot be the only API.
- Separate pure message/crypto construction from transport. Golden vectors should test the former; mock HTTP tests should test the latter.
- Preserve Entra error code, suberror, correlation/trace IDs, timestamp, claims and retry metadata in a common error model without retaining a secret-filled response body.

## Interoperability testing

For each protocol card, maintain three test layers:

1. Pure known-answer and parser tests checked into the repository with secrets replaced but byte structure preserved.
2. Mock-server transcript tests asserting method, URL, headers, body, redirects, cookies and error handling.
3. Opt-in live tests against a disposable tenant, named by capability and skipped safely when credentials/policy are absent.

Capture/reference tools must record exact versions, tenant configuration, cloud, date and correlation IDs. Tests should compare semantics when timestamps, nonces and signatures vary. A feature is not complete merely because Entra accepted one happy-path request; failure, replay, rotation, cancellation, concurrency and recovery behavior are part of Windows parity.

## Security and operational review gates

- Federation, CBA, device join/delete, PRT crypto, passkey registration, MDE2 and SHR require focused threat review before release.
- Any HTML/internal/beta endpoint requires a feature flag, fixture-based change detector, and documented fallback.
- Remote deletion, package replacement, unenrollment and key migration require crash-consistent journals.
- The D-Bus broker must authenticate the caller on every method and bind asynchronous results to the caller's UID and unique bus name.
- SyncML commands are remote privileged input. Adding a CSP adapter requires a separate least-privilege and rollback review.

# Explicit non-goals and deferred evidence gaps

The following reference-project features are not roadmap gaps for Windows workstation identity parity:

- Tenant-wide reconnaissance, arbitrary Graph/legacy Azure AD administration, application/role mutation, token or credential dumping, forged federation assertions, PRT theft/injection, browser-cookie injection, phishing/browser automation, and persistence techniques.
- ActiveSync mailbox synchronization, Exchange/SharePoint/Azure management APIs, AD Connect administration, offensive Kerberos ticket construction, and arbitrary OData querying.
- CLI formatting, file formats used only by ROADtools/AADInternals, Selenium automation, and software-passkey private-key files.
- Generic OpenID Connect identity-provider behavior already owned by the consumer is not a `libhimmelblau` Entra parity requirement.

Microsoft Authenticator push-method registration and generic TOTP/HOTP generation appear in AADInternals, but they are not established Windows workstation/device-broker parity requirements in the audited code. They should remain a separate future discovery item unless a concrete Himmelblau user-security-info management goal is approved. Likewise, PRT v4 and signed HTTP request details require current Windows/service captures before their wire formats can be treated as authoritative; LIB-12 and LIB-17 explicitly include that evidence gate.

# Appendix A — reference-operation traceability

This appendix is the completeness ledger. Synchronous and asynchronous ROADtools implementations of the same operation are one row because they describe one protocol behavior. “Present” means the audited stack already supplies the behavior; “Roadmap” names the implementation card; “Excluded” gives the scope decision. This prevents a reference helper from disappearing merely because it was not a missing feature.

## Authentication and OAuth operations

| Reference operations | Disposition | Evidence or destination |
| --- | --- | --- |
| ROADtools `user_discovery_v1`, `user_discovery_v2`, `user_discovery`; AADInternals `Get-UserRealm`, `Get-UserRealmExtended`, `Get-UserRealmV2`, `Get-CredentialType` | Partial; federated result routing is missing | LIB-01 |
| Authority, redirect, tenant and OpenID metadata helpers (`get_authority_url`, `get_redirect_for_client`, `Get-OpenIDConfiguration`, `Get-TenantID`, `Get-TenantLoginUrl`) | Basic behavior present; public/versioned hardening missing | LIB-04 |
| Device-code grants v1/v2 | Present for the client-relevant v2 path; v1 matrix absent | Existing `PublicClientApplication`; LIB-04 for explicit v1 |
| Managed username/password grants v1/v2 | Present for managed v2 | Existing `acquire_token_by_username_password`; LIB-04 for v1 target model |
| Federated username/password, MEX, WS-Trust RST and SOAP parsing | Missing | LIB-01, then LIB-02 |
| Client credential with secret/certificate, v1/v2 | Present for v2 and both credential forms | Existing `ConfidentialClientApplication`; LIB-04 only for v1/resource parity |
| On-behalf-of with secret/certificate, v1/v2 | Present for v2, including claims | Existing confidential client; LIB-04 for v1 |
| Refresh-token exchange v1/v2 | Present for v2 | Existing public/broker clients; LIB-03 claims, LIB-04 v1 |
| Authorization code, encrypted code and PKCE helpers v1/v2 | Internal/partial public surface | LIB-04; encrypted broker response handling stays with existing PRT/JWE code where applicable |
| SAML 1.1/2.0 bearer grants v1/v2 and `Get-OAuthInfoUsingSAML` | Missing | LIB-02 |
| Desktop/Seamless SSO using password or Kerberos, followed by SAML redemption | Missing | LIB-06 and LIB-02; password WS-Trust path is LIB-01 |
| Generic claims request, `Get-CAEClaims`, and `cp1` client capability | OBO-only/partial | LIB-03 and CLIENT-05 |
| Server challenge/nonce and PRT-cookie nonce | Present for existing PRT flow | Existing `auth.rs`; audited further by LIB-11 |
| PRT cookie creation/KDF v2 and PRT-cookie authorization-code redemption | Present | Existing PRT SSO-cookie APIs and consumer SSO path |
| FIDO authentication challenge and assertion submission | Present across repositories | Library challenge parsing plus consumer authenticator integration |
| Login-page parameter/config parsing and interactive authorization | Partial and intentionally isolated from arbitrary page scraping | LIB-04 and CLIENT-06; brittle private web contract only where unavoidable |
| MSAL cache/FOCI client-family helpers | Cache family behavior missing; enumerating Microsoft's client IDs is not a standalone library feature | CLIENT-05; endpoint-independent cache keys belong to client |
| ROADtools agent identity grants and ACS actor/impersonation tokens | Excluded | Agent/legacy Office impersonation surface is not workstation identity lifecycle |
| ROADtools generic authenticated HTTP wrappers | Excluded as a feature | Ordinary HTTP plumbing, not an Entra capability; specific callers use typed transports |
| AADInternals API-key scraping, endpoint IP enumeration and username extraction from captured auth headers | Excluded | Reconnaissance/credential-analysis behavior |

## Device, Hello, PRT and broker operations

| Reference operations | Disposition | Evidence or destination |
| --- | --- | --- |
| Ordinary join/register (`JoinType` 0/4), CSR, BCRYPT transport key, device certificate | Present | Existing `discovery.rs::enroll_device` and consumer join workflow |
| Device ticket/domain variants and join response reuse/SID | Mostly present; retain as regression coverage | Existing enrollment models; LIB-07 must not regress them |
| Hybrid join (`JoinType=6`, `ServerAdJoinData`, signed `ClientIdentity`) | Missing | LIB-07 and CLIENT-04 |
| Certificate-authenticated device deletion | Missing | LIB-08 and CLIENT-02 |
| Device-certificate-signed token request | Missing as a reusable grant | LIB-09 |
| Session-key-signed broker token request | Present for current protocol | Existing broker PRT exchange; LIB-11 completeness audit |
| PRT acquisition with password | Present | Existing broker client and consumer provisioning |
| PRT acquisition with refresh token | Present | Existing broker client; LIB-11 rotation/completeness |
| PRT acquisition with Hello key/assertion | Present | Existing Hello assertion/provisioning and consumer PIN lifecycle |
| PRT acquisition with federated SAML assertion | Missing | LIB-02 |
| PRT renewal and `previous_refresh_token` semantics | Renewal present, request/rotation details incomplete | LIB-11 and CLIENT-05 |
| PRT protocol v3 request/signing path | Missing | LIB-12, CLIENT-14 |
| PRT protocol v4 EC/ECDH path | Missing and evidence-gated | LIB-12, CLIENT-14 |
| PRT KDF v1/v2, KDF context and signed JWE | Present for used v2 path | Existing crypto; LIB-11 conformance, LIB-12 new versions |
| PRT-backed access token and signed PRT request | Present | Existing exchange APIs; LIB-03 adds generic claims |
| TGT request/extraction and P2P device certificate | Present | Existing TGT/P2P APIs and consumer Kerberos cache installation |
| Hello key generation, BCRYPT public blob/JWK, key registration | Present across library and consumer | Existing Hello provisioning; machine storage stays client-owned |
| Device registration authentication-method and transport-key Graph mutations | Excluded | Tenant/device administration rather than self-service client protocol; existing key provisioning is sufficient for lifecycle |
| Deviceless/macOS PRT authorization-code flow | Deferred, not Windows workstation parity | Reconsider only with an explicit platform-SSO target and current evidence |
| ROADtools PEM/PFX/key/PRT file load/save helpers | Excluded as API features | File formats and secret persistence policy belong to clients; library accepts key traits/types |
| Broker silent access-token acquisition, account listing, PRT SSO | Present but contract hardening needed | Existing D-Bus broker; CLIENT-05 and CLIENT-09 |
| Broker interactive acquisition/cancellation | Stub/incorrect | CLIENT-06 |
| Broker account removal | Stub | CLIENT-09 |
| Broker signed HTTP request | Stub; protocol primitive missing | LIB-17 and CLIENT-10 |

## WebAuthn, CBA, Kerberos and MFA operations

| Reference operations | Disposition | Evidence or destination |
| --- | --- | --- |
| WebAuthn authenticator data, client data, assertion signing and credential ID | Present for authentication | Consumer `auth.rs` and library FIDO flow |
| Attested credential data, COSE public key and attestation object for registration | Missing registration flow | LIB-13 and CLIENT-07 |
| Software passkey creation/load | Excluded for production | May remain test-only; private-key files are not Windows hardware-backed parity |
| User certificate-based authentication login parameters and token acquisition | Missing; AADInternals portal HTML extraction is evidence of the auth mechanism, not the target contract | LIB-05 and CLIENT-15 |
| Seamless SSO Kerberos ticket submission for an OAuth token | Missing | LIB-06 and CLIENT-03 |
| Raw Kerberos key derivation, ticket/PAC construction/parsing and forged-ticket helpers | Excluded | Use system GSSAPI/libkrimes; offensive/general Kerberos stack is not an Entra client-library goal |
| Entra Kerberos TGT extraction from token response | Present | Existing library and consumer cache installation |
| TOTP/HOTP generation and secret creation | Deferred | Generic authenticator functionality, not required for Windows workstation parity |
| Microsoft Authenticator push-app registration/listing | Deferred | User security-info administration; requires a separately approved scope and current endpoint evidence |
| Administrative set/get of user MFA methods | Excluded | Tenant/user administration rather than client authentication |

## Graph identity operations

| Reference operations | Disposition | Evidence or destination |
| --- | --- | --- |
| Current user, user lookup, groups, group members and memberships | Present | Existing `graph.rs` |
| User-owned and user-registered devices | Missing | LIB-16 and CLIENT-13 |
| Profile photo, extension attributes and device assignment used by local identity | Present where required | Existing `graph.rs` |
| Manager/direct reports, licenses, Teams/apps, role members, domains, sign-in/audit logs | Excluded unless a demonstrated local identity policy needs one | Tenant/org reconnaissance and application administration |
| Tenant authentication/guest/rollout policy mutation, TAP creation, B2C keys | Excluded | Administrative/security-sensitive operations |
| Arbitrary OData query construction | Excluded | Only narrow typed, least-privilege lookups are accepted |

## Device management operations

| Reference operations | Disposition | Evidence or destination |
| --- | --- | --- |
| Linux Company Portal enrollment, status, policy and compliance APIs | Present | Existing `intune.rs`, consumer policy daemon |
| Windows enterprise enrollment discovery | Missing | LIB-14 |
| MS-MDE2/WSTEP enrollment, CSR, RST/RSTR, provisioning document | Missing | LIB-14 and CLIENT-11 |
| BPRT/zero-touch MDE2 enrollment context | Missing | LIB-10, CLIENT-08, LIB-14, CLIENT-11 |
| Management identity/certificate persistence and renewal | Missing for MDE2 | CLIENT-11 |
| SyncML request construction and response parsing | Missing | LIB-15 |
| SyncML auto-acknowledgement/status/results | Missing | LIB-15 |
| Certificate-authenticated OMA-DM HTTP check-in | Missing | LIB-15 and CLIENT-12 |
| Background callback/session loop | Missing for OMA-DM | CLIENT-12 |
| CSP execution, compliance reporting and truthful unsupported status | Missing for OMA-DM; Linux equivalents partly exist | CLIENT-12 |
| Windows Intune unenrollment and compliance mutation | Protocol-specific self-unenrollment belongs with MDE2 lifecycle; arbitrary “set compliant” is not parity | CLIENT-11/12 for self lifecycle; administrative spoofing excluded |
| ActiveSync WBXML/mail synchronization | Excluded | Not device management despite shared WBXML machinery |

# Appendix B — wire-call catalog for proposed library APIs

Endpoint hosts are discovered or authority/cloud dependent unless marked as a reference default. Implementations must not concatenate untrusted identifiers into URLs. Private or service-evolving calls require captured fixtures and feature/version isolation.

| Call family | HTTP operation and endpoint shape | Authentication/proof | Card |
| --- | --- | --- | --- |
| User realm v1 | `GET https://login.microsoftonline.com/common/UserRealm/{UPN}?api-version=1.0` | None | LIB-01 |
| User realm v2 | `GET https://login.microsoftonline.com/common/userrealm/{UPN}?api-version=2.1` (version must be configurable/evidence-backed) | None | LIB-01 |
| Credential type | `POST https://login.microsoftonline.com/common/GetCredentialType` | None; transaction fields in JSON | LIB-01 |
| Federation metadata | `GET {federation_metadata_url}` | HTTPS/origin policy | LIB-01 |
| WS-Trust active authentication | `POST {endpoint selected from MEX}` | SOAP WS-Security UsernameToken or GSS/Negotiate | LIB-01/LIB-06 |
| OAuth v1 token | `POST {authority}/{tenant}/oauth2/token` | Grant-specific form fields | LIB-02/LIB-04 |
| OAuth v2 token | `POST {authority}/{tenant}/oauth2/v2.0/token` | Grant-specific form fields | LIB-02/LIB-04 |
| OAuth authorize | `GET {authority}/{tenant}/oauth2[/v2.0]/authorize` | Browser transaction, state/nonce/PKCE; PRT cookie when brokered | LIB-04/existing PRT APIs |
| Device-code initiation/poll | `POST .../devicecode`, then `POST .../token` | Device code | Present; LIB-04 version matrix |
| Entra integrated authentication | MEX-discovered active-auth endpoint, normally HTTP Negotiate followed by SAML result | Kerberos GSS token | LIB-06 |
| DVR discovery | `GET https://enterpriseregistration.windows.net/{tenant}/Discover?api-version=1.9` or discovered equivalent | None | Present |
| Ordinary DVRJ enrollment | `POST {EnrollmentService}/EnrollmentServer/device/?api-version=2.0` | User access token plus CSR/key proof | Present |
| Hybrid DVRJ enrollment | `PUT {EnrollmentService}/EnrollmentServer/device/{deviceId}?api-version=1.0` | Signed `ClientIdentity` from AD device certificate | LIB-07 |
| DVRJ self-delete | `DELETE {EnrollmentService}/EnrollmentServer/device/{deviceId}?api-version=1.0` | Device certificate mTLS | LIB-08 |
| Key provisioning | Discovered key-provisioning endpoint | User/device token and key proof | Present |
| Device-bound OAuth/PRT token | `POST {authority}/{tenant}/oauth2/token` with signed/JWE request form | Device certificate, transport key, session key or Hello key depending operation/version | LIB-09/LIB-11/LIB-12 |
| PRT server nonce | Entra challenge endpoint used by current broker protocol | Existing PRT/session proof context | Present; LIB-11 audit |
| Bulk enrollment begin | `POST https://login.microsoftonline.com/webapp/bulkaadjtoken/begin` with JSON `pid`, `name`, `exp` | Bearer token for `urn:ms-drs:enterpriseregistration.windows.net` | LIB-10; private-contract feature gate |
| Bulk enrollment poll | `GET https://login.microsoftonline.com/webapp/bulkaadjtoken/poll?flowToken={opaque}` until terminal state | Same bearer token; opaque flow token | LIB-10; bounded polling and endpoint evidence gate |
| User CBA bootstrap | `GET` the authorize URL, then `POST https://certauth.login.microsoftonline.com/{tenant}/certauth` with transaction context/flow token | User certificate mTLS/signing behavior as required by current service | LIB-05; private web-contract isolation |
| Passkey creation options | Microsoft Graph authentication-method registration endpoint/version selected from current documentation/capture | Recent delegated user token | LIB-13 |
| Passkey registration commit | Microsoft Graph user FIDO2/passkey authentication-method endpoint | Delegated token plus WebAuthn attestation | LIB-13 |
| Owned devices | `GET https://graph.microsoft.com/v1.0/users/{id}/ownedDevices` | Delegated Graph token | LIB-16 |
| Registered devices | `GET https://graph.microsoft.com/v1.0/users/{id}/registeredDevices` | Delegated Graph token | LIB-16 |
| MDM discovery | `GET https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc` or tenant-discovered equivalent with discovery query | User/BPRT context as required | LIB-14 |
| MDE2 policy/enrollment | XCEP `GetPolicies` and WSTEP `RequestSecurityToken` at discovery-returned endpoints | Entra token, CSR and enrollment context | LIB-14 |
| OMA-DM maintenance | `POST {management server}/devicegatewayproxy/cimhandler.ashx?mode=Maintenance&Platform=WoA` (reference shape; prefer provisioned URI) | Management certificate mTLS; SyncML body | LIB-15 |
| Graph/native Linux Intune calls | Existing Company Portal enrollment/status/policy/compliance endpoints | Existing delegated/device credentials | Present; not replaced by LIB-14/15 |

The catalog deliberately does not freeze undocumented endpoint versions into the roadmap. Each card must record the precise endpoint, headers, request fields and response fixture actually implemented. Discovery-returned URLs take precedence over reference defaults after scheme/origin validation.

# Definition of roadmap completion

Parity is achieved when a supported Linux workstation can perform the applicable lifecycle without Windows-only helper software: discover and authenticate managed or federated users; join/register/hybrid-join and safely leave; provision and rotate device/transport/Hello credentials; acquire, persist, renew and use a device-bound PRT with claims-aware broker SSO; enroll and use passkeys; obtain Entra/on-premises Kerberos tickets through supported flows; expose a caller-isolated interactive/silent broker; and, when selected, enroll/check in through Windows-compatible MDE2/OMA-DM while reporting only policies it can truthfully enforce.

Completion does not mean matching every private Windows API forever. It means each supported contract has explicit versioning, safe failure on protocol drift, fixture and live interoperability evidence, crash-consistent credential lifecycle, and a clear owner on the library/client boundary.
