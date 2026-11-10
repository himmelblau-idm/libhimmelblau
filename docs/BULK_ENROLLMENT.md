# Bulk Entra enrollment at installation time

Enable `bulk_enrollment` in the consuming application's Cargo dependency. It
enables `broker` and exposes the Rust APIs through `himmelblau::auth` and the
crate root. The feature is disabled by default because the WCD web endpoints
are a private contract. Only the public Entra cloud is supported.

This feature registers devices in **Entra ID only**. It does not implement bulk
Intune enrollment, MDE2 provisioning, compliance, or automatic user sign-in.
Bulk Intune enrollment does not work for the intended Linux deployment.

## How it works

1. An authorized operator authenticates once on an administrator workstation
   and obtains a delegated DRS access token.
2. `create_bulk_enrollment_token` posts `pid`, `name`, and `exp` to
   `/webapp/bulkaadjtoken/begin`, then polls
   `/webapp/bulkaadjtoken/poll?flowToken=...` with the same bearer token.
   This creates a `package_<uuid>@<tenant-default-domain>` user. Its refresh
   token is the reusable bulk primary refresh token (BPRT).
3. The deployment system delivers the BPRT and non-secret package metadata to
   each installation.
4. `enroll_device_with_bulk_package` exchanges the BPRT using OAuth v1, the
   **AADJ CSP** client `b90d5b8f-5503-4153-b545-b31cecfaece2`, and resource
   `urn:ms-drs:enterpriseregistration.windows.net`. This is different from the
   normal broker refresh-token exchange.
5. The existing Entra join implementation generates a distinct device
   certificate key, transport key, and CSR for each machine. The caller
   persists the returned keys and device ID using its existing protected
   machine-state storage.
6. Users authenticate normally later, using that device identity. The BPRT is
   a provisioning credential and must not be substituted for a user's PRT.

## Create a package

The caller supplies a `PublicClientApplication` and an already authenticated
administrator access token with DRS audience and the intended tenant ID.
AADInternals requests this token using Azure AD PowerShell client ID
`1b730954-1685-4b74-9bfd-dac224a7b894`. Authentication and tenant consent remain
the caller's responsibility; this API does not bypass Conditional Access.

```rust,ignore
use chrono::{Duration as Days, Utc};
use himmelblau::{BulkEnrollmentRequest, PublicClientApplication};
use std::time::Duration;
use uuid::Uuid;

// app and admin_access_token come from the administrator's authentication flow.
let request = BulkEnrollmentRequest::new(
    tenant_id, // Uuid, not a domain alias
    "Linux deployment",
    Utc::now().date_naive() + Days::days(30),
)?;
// Retain request.metadata().package_id before issuing the request.
let package = app
    .create_bulk_enrollment_token(
        admin_access_token,
        &request,
        Duration::from_secs(120),
    )
    .await?;

// Store these separately. The library performs no filesystem operations.
let inventory = package.metadata();
let secret_for_protected_storage = package.refresh_token();
```

The package and internal wire response buffers zeroize secrets on drop.
`Debug` prints metadata and a redacted credential. The package deliberately
implements neither Serde serialization nor deserialization; exposing the
secret for storage is explicit.

New issuance accepts expiry dates 1-90 days after the current UTC date, using
the conservative limit in the current Microsoft documentation. Older
AADInternals material describes 180 days. The server remains authoritative;
any earlier `expires_on` returned by the server shortens the local expiry.
Clients stop using a package at the **start** of its UTC expiry date.

To replace/renew a known package, explicitly opt in before issuance:

```rust,ignore
let request = BulkEnrollmentRequest::new(tenant_id, "Linux deployment", expires)?
    .replace_existing_package(existing_package_id)?;
```

Replacement can invalidate an existing package. The caller must obtain operator
authorization for that operation. Creation sends `begin` only once and uses
bounded, asynchronous polling. A timeout, cancellation, or malformed response
does not roll back the remote package user. Preserve the package ID and inspect
the tenant before retrying; do not automatically generate new package IDs.
Unknown states and terminal service errors fail immediately. Polling recognizes
`Started`, `InProgress`, and `CompleteSuccess`; errors containing `Error`
surface the nested OAuth error. These fixtures require confirmation against
current service responses before production use.

The implementation rejects an administrator token whose tenant or audience
does not match before creating a user. Returned package ID-token claims are
also checked for tenant/package consistency. These are consistency checks,
not JWT signature validation; Entra authenticates the bearer token.

## Import an AADInternals/WCD BPRT and join a machine

An existing AADInternals `New-AADIntBulkPRTToken` result can be used directly:
pass its `refresh_token` value and trusted inventory metadata. Import does not
create or replace any tenant object.

```rust,ignore
use himmelblau::{BulkEnrollmentMetadata, BulkEnrollmentPackage, EnrollAttrs};

let package = BulkEnrollmentPackage::import(
    BulkEnrollmentMetadata {
        tenant_id,
        package_id,
        display_name: "Linux deployment".into(),
        expires, // chrono::NaiveDate, from trusted provisioning metadata
    },
    bprt_from_secret_store,
)?;
let attrs = EnrollAttrs::new(
    tenant_domain.to_string(),
    Some(machine_hostname.to_string()),
    None, // Linux
    Some(0), // Entra join
    None, // local OS version
)?;
let (transport_key, cert_key, device_id) = broker
    .enroll_device_with_bulk_package(&package, attrs, &mut tpm, &storage_key)
    .await?;
// Persist these keys together with the machine storage key and device ID
// using Himmelblau's existing device-state transaction.
// Reconstruct BrokerClientApplication with these keys for normal user login.
drop(package);
```

Keep the bulk credential in protected deployment storage, out of shell
arguments, logs, ordinary configuration, and installed golden images.
Provision each machine with fresh keys after imaging. The installer must
detect already-enrolled machines before retrying a join, and handle a remote
join succeeding while local persistence fails. This library does not implement
installer retries, inventory cleanup, or package rotation policy.

The machine's in-memory broker keys are committed together only after
certificate finalization succeeds. The caller remains responsible for durable
atomic persistence, and subsequent logins should use the existing identity
rather than triggering a second join.

## Tenant setup and validation

Microsoft's current Windows provisioning documentation lists Cloud Device
Administrator, Intune Administrator, and Password Administrator as token
creation roles, and requires the Microsoft.Azure.SyncFabric service principal
(`00000014-0000-0000-c000-000000000000`). Tenant enrollment permissions,
consent, MFA policy, and revocation still apply. No Intune enrollment is
attempted by this implementation.

Deleting the associated package user revokes the provisioning package.
Expire/retire the provisioning secret after deployment; the enrolled machines
should continue using their own device credentials.

Synthetic HTTP fixtures cover begin/poll, query encoding, deadlines, service
errors, replacement, expiry, cross-tenant rejection, BPRT redemption, and
independent SoftTPM device identities. Run:

```sh
cargo fmt --check
cargo test --features bulk_enrollment bulk_enrollment
cargo test --features bulk_enrollment
cargo clippy --features bulk_enrollment --all-targets -- -D warnings
cargo check --all-features --all-targets
```

Before production use, test issuance/import and joining two Linux machines
in a test tenant, verify distinct Entra device identities, persist and reload
their keys, then verify a normal user sign-in does not perform another join.
Also test expiry/revocation and tenant policy failures. A live tenant check
has not been performed as part of this change.

## Protocol references

- [AADInternals PRT.ps1, New-BulkPRTToken](https://github.com/Gerenios/AADInternals/blob/13f207d9ec08761ac85d9fb1311ecb719e25add4/PRT.ps1)
- [AADInternals AccessToken.ps1, BPRT branch](https://github.com/Gerenios/AADInternals/blob/13f207d9ec08761ac85d9fb1311ecb719e25add4/AccessToken.ps1)
- [Author's BPRT protocol walkthrough](https://aadinternals.com/post/bprt/)
- [Current Microsoft provisioning requirements and expiry](https://learn.microsoft.com/en-us/intune/device-enrollment/windows/create-bulk-package)

The AADInternals MIT notice is retained in
[LICENSES/AADInternals-MIT.txt](../LICENSES/AADInternals-MIT.txt).
