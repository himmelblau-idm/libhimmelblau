//! Opt-in support for the private bulk Azure AD join protocol.
//!
//! Based on AADInternals' New-BulkPRTToken (PRT.ps1) and the BPRT branch of
//! Get-AccessToken (AccessToken.ps1), revision
//! 13f207d9ec08761ac85d9fb1311ecb719e25add4.
//! See ../LICENSES/AADInternals-MIT.txt for attribution and license.
//! This implements Entra device registration.

use super::*;
use chrono::{NaiveDate, Utc};
use tokio::time::{sleep as async_sleep, timeout};

const BULK_CLIENT_ID: &str = "b90d5b8f-5503-4153-b545-b31cecfaece2";
const BULK_RESOURCE: &str = "urn:ms-drs:enterpriseregistration.windows.net";
// Current Microsoft Learn documentation specifies 90 days. Older AADInternals
// documentation says 180; use the conservative current documented limit.
const MAX_VALIDITY_DAYS: i64 = 90;
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Non-secret inventory information. It can be stored separately from the BPRT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BulkEnrollmentMetadata {
    pub tenant_id: Uuid,
    pub package_id: Uuid,
    pub display_name: String,
    /// Requested expiration date in UTC. Clients stop using it at midnight at
    /// the start of this date, conservatively avoiding ambiguous server times.
    pub expires: NaiveDate,
}

/// An explicit request to create or replace a bulk enrollment package.
#[derive(Clone, Debug)]
pub struct BulkEnrollmentRequest {
    metadata: BulkEnrollmentMetadata,
}

impl BulkEnrollmentRequest {
    /// Create a new package ID. The expiry must be after today and no more than
    /// 90 days away. Service policy may impose a shorter lifetime.
    pub fn new(tenant_id: Uuid, display_name: &str, expires: NaiveDate) -> Result<Self, MsalError> {
        let request = Self {
            metadata: BulkEnrollmentMetadata {
                tenant_id,
                package_id: Uuid::new_v4(),
                display_name: display_name.to_string(),
                expires,
            },
        };
        request.validate(Utc::now().date_naive())?;
        Ok(request)
    }

    /// Reuse a package ID, which can replace its existing package user and
    /// invalidate previously issued credentials. Callers must obtain explicit
    /// operator authorization for replacement before calling this method.
    pub fn replace_existing_package(mut self, package_id: Uuid) -> Result<Self, MsalError> {
        if package_id.is_nil() {
            return Err(MsalError::ConfigError("Package ID must not be nil".into()));
        }
        self.metadata.package_id = package_id;
        Ok(self)
    }

    pub fn metadata(&self) -> &BulkEnrollmentMetadata {
        &self.metadata
    }

    fn validate(&self, today: NaiveDate) -> Result<(), MsalError> {
        let days = (self.metadata.expires - today).num_days();
        if self.metadata.tenant_id.is_nil()
            || self.metadata.package_id.is_nil()
            || self.metadata.display_name.trim().is_empty()
            || self.metadata.display_name.chars().count() > 256
            || !(1..=MAX_VALIDITY_DAYS).contains(&days)
        {
            return Err(MsalError::ConfigError(
                "Bulk enrollment requires non-nil tenant/package IDs, a name of 1-256 characters, and expiry 1-90 days in the future".into(),
            ));
        }
        Ok(())
    }
}

/// A reusable provisioning secret and its separate inventory metadata.
///
/// Deliberately does not implement Serialize or Deserialize. Use
/// refresh_token() only for explicit secret-store export. No files are written.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BulkEnrollmentPackage {
    #[zeroize(skip)]
    metadata: BulkEnrollmentMetadata,
    refresh_token: String,
}

impl fmt::Debug for BulkEnrollmentPackage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BulkEnrollmentPackage")
            .field("metadata", &self.metadata)
            .field("refresh_token", &"[REDACTED]")
            .finish()
    }
}

impl BulkEnrollmentPackage {
    /// Import a BPRT from WCD, AADInternals, or a secret store. Metadata is
    /// supplied by the trusted provisioning system; a BPRT is opaque.
    /// Importing does not create or replace a package user.
    pub fn import(metadata: BulkEnrollmentMetadata, refresh_token: &str) -> Result<Self, MsalError> {
        if metadata.tenant_id.is_nil()
            || metadata.package_id.is_nil()
            || metadata.expires <= Utc::now().date_naive()
            || refresh_token.trim().is_empty()
        {
            return Err(MsalError::ConfigError(
                "Bulk enrollment package is expired or missing IDs/credential".into(),
            ));
        }
        Ok(Self {
            metadata,
            refresh_token: refresh_token.to_string(),
        })
    }

    pub fn metadata(&self) -> &BulkEnrollmentMetadata {
        &self.metadata
    }

    /// Expose the BPRT for deliberate export to a protected secret store.
    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }

    fn validate(&self) -> Result<(), MsalError> {
        if self.metadata.expires <= Utc::now().date_naive() {
            return Err(MsalError::ConfigError(
                "Bulk enrollment package has expired".into(),
            ));
        }
        Ok(())
    }
}

// Neither flow tokens nor raw resultData must appear in diagnostic output.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct BulkResponse {
    state: String,
    #[serde(rename = "flowToken")]
    flow_token: Option<String>,
    #[serde(rename = "resultData")]
    result_data: Option<String>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct BulkTokenResult {
    refresh_token: String,
    id_token: String,
    #[serde(default)]
    #[zeroize(skip)]
    expires_on: Option<Value>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct BulkAccessToken {
    access_token: String,
}

fn protocol_error(message: &str) -> MsalError {
    MsalError::DeviceEnrollmentFail(message.to_string())
}

fn token_claims(token: &str) -> Result<Value, MsalError> {
    token
        .split('.')
        .nth(1)
        .and_then(|payload| URL_SAFE_NO_PAD.decode(payload).ok())
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .ok_or_else(|| protocol_error("Malformed bulk enrollment token claims"))
}

fn validate_authority(authority: &Url) -> Result<(), MsalError> {
    let public_cloud = authority.scheme() == "https"
        && authority.host_str() == Some("login.microsoftonline.com")
        && authority.port_or_known_default() == Some(443)
        && authority.username().is_empty()
        && authority.password().is_none();
    #[cfg(test)]
    let public_cloud = public_cloud
        || (authority.scheme() == "http" && authority.host_str() == Some("127.0.0.1"));
    if !public_cloud {
        return Err(MsalError::ConfigError(
            "Bulk enrollment supports the public Entra cloud only".into(),
        ));
    }
    Ok(())
}

// Do not include serde errors with response contents, or reqwest URLs which
// contain the flowToken query secret, in returned errors.
async fn bulk_response(response: Response) -> Result<BulkResponse, MsalError> {
    if !response.status().is_success() {
        return Err(bulk_http_error(response).await);
    }
    response
        .json()
        .await
        .map_err(|_| protocol_error("Malformed bulk enrollment response"))
}

async fn bulk_http_error(response: Response) -> MsalError {
    let status = response.status();
    match response.json::<ErrorResponse>().await {
        Ok(error) => MsalError::AcquireTokenFailed(error),
        Err(_) => protocol_error(&format!("Bulk enrollment HTTP status {}", status)),
    }
}

fn check_bulk_error(response: &BulkResponse) -> Result<(), MsalError> {
    if response.state.to_ascii_lowercase().contains("error") {
        let error: ErrorResponse = response
            .result_data
            .as_deref()
            .and_then(|data| serde_json::from_str(data).ok())
            .ok_or_else(|| protocol_error("Bulk enrollment returned an error without details"))?;
        return Err(MsalError::AcquireTokenFailed(error));
    }
    Ok(())
}

fn package_from_response(
    request: &BulkEnrollmentRequest,
    response: &BulkResponse,
) -> Result<BulkEnrollmentPackage, MsalError> {
    let result: BulkTokenResult = serde_json::from_str(
        response
            .result_data
            .as_deref()
            .ok_or_else(|| protocol_error("Bulk enrollment result is missing"))?,
    )
    .map_err(|_| protocol_error("Malformed bulk enrollment token result"))?;
    // This is a consistency check on an ID token received over TLS from the
    // service, not a replacement for JWT signature validation/authentication.
    let claims = token_claims(&result.id_token)?;
    let expected_tenant = request.metadata.tenant_id.to_string();
    let expected_user = format!("package_{}@", request.metadata.package_id);
    if claims.get("tid").and_then(Value::as_str) != Some(expected_tenant.as_str())
        || !claims
            .get("upn")
            .or_else(|| claims.get("unique_name"))
            .and_then(Value::as_str)
            .is_some_and(|upn| upn.to_ascii_lowercase().starts_with(&expected_user))
    {
        return Err(protocol_error("Bulk enrollment tenant/package mismatch"));
    }
    let mut metadata = request.metadata.clone();
    if let Some(expires_on) = &result.expires_on {
        let seconds = expires_on
            .as_str()
            .and_then(|value| value.parse::<i64>().ok())
            .or_else(|| expires_on.as_i64())
            .ok_or_else(|| protocol_error("Malformed bulk enrollment expiration"))?;
        let date = chrono::DateTime::from_timestamp(seconds, 0)
            .ok_or_else(|| protocol_error("Invalid bulk enrollment expiration"))?
            .date_naive();
        metadata.expires = metadata.expires.min(date);
    }
    BulkEnrollmentPackage::import(metadata, &result.refresh_token)
}

impl PublicClientApplication {
    /// Create a BPRT using the private WCD begin/poll endpoints, following
    /// AADInternals. Requires the opt-in bulk_enrollment feature.
    ///
    /// admin_access_token must have the DRS audience
    /// urn:ms-drs:enterpriseregistration.windows.net and sufficient tenant
    /// privileges. AADInternals obtains it with client ID
    /// 1b730954-1685-4b74-9bfd-dac224a7b894. Authenticate on an administrator's
    /// workstation, not separately on each installation.
    ///
    /// The timeout bounds begin, polling, network calls, and sleeps. Cancellation
    /// or timeout does not undo creation of the package user. Retain the request's
    /// package ID to inspect/revoke it; do not blindly retry creation with new IDs.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn create_bulk_enrollment_token(
        &self,
        admin_access_token: &str,
        request: &BulkEnrollmentRequest,
        polling_timeout: Duration,
    ) -> Result<BulkEnrollmentPackage, MsalError> {
        request.validate(Utc::now().date_naive())?;
        if admin_access_token.trim().is_empty() || polling_timeout.is_zero() {
            return Err(MsalError::ConfigError(
                "An administrator access token and nonzero timeout are required".into(),
            ));
        }
        // These unverified claims are used only to reject an accidental
        // tenant/audience mismatch before the begin call creates a user.
        // The server remains responsible for authentication and authorization.
        let claims = token_claims(admin_access_token)?;
        let tenant_id = request.metadata.tenant_id.to_string();
        if claims.get("tid").and_then(Value::as_str) != Some(tenant_id.as_str())
            || !matches!(
                claims.get("aud").and_then(Value::as_str),
                Some(BULK_RESOURCE) | Some(DRS_APP_ID)
            )
        {
            return Err(MsalError::ConfigError(
                "Administrator token must target the requested tenant and DRS audience".into(),
            ));
        }
        let authority = Url::parse(&self.authority()?)
            .map_err(|_| MsalError::URLFormatFailed("Invalid bulk enrollment authority".into()))?;
        // This private contract is evidenced only in the public cloud.
        // Never send an admin bearer to an unverified sovereign-cloud endpoint.
        validate_authority(&authority)?;
        let begin = authority
            .join("/webapp/bulkaadjtoken/begin")
            .map_err(|_| MsalError::URLFormatFailed("Invalid bulk enrollment endpoint".into()))?;
        let poll = authority
            .join("/webapp/bulkaadjtoken/poll")
            .map_err(|_| MsalError::URLFormatFailed("Invalid bulk enrollment endpoint".into()))?;
        timeout(polling_timeout, async {
            let response = self
                .client()
                .post(begin)
                .bearer_auth(admin_access_token)
                .json(&json!({
                    "pid": request.metadata.package_id.to_string(),
                    "name": request.metadata.display_name,
                    "exp": request.metadata.expires.format("%m/%d/%Y").to_string(),
                }))
                .send()
                .await
                .map_err(|e| MsalError::request_failed(&e.without_url()))?;
            let mut response = bulk_response(response).await?;
            loop {
                check_bulk_error(&response)?;
                match response.state.as_str() {
                    "CompleteSuccess" => return package_from_response(request, &response),
                    "Started" | "InProgress" => {}
                    _ => return Err(protocol_error("Unknown bulk enrollment state")),
                }
                let flow_token = response
                    .flow_token
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| protocol_error("Bulk enrollment flow token is missing"))?;
                // Query encoding is essential: flow tokens may contain +, /, &.
                let next = self
                    .client()
                    .get(poll.clone())
                    .query(&[("flowToken", flow_token)])
                    .bearer_auth(admin_access_token)
                    .send()
                    .await
                    .map_err(|_| {
                        MsalError::RequestFailed("Bulk enrollment poll request failed".into())
                    })?;
                let mut next = bulk_response(next).await?;
                if matches!(next.state.as_str(), "Started" | "InProgress") {
                    // Some pending responses omit the unchanged flow token.
                    if next.flow_token.as_deref().is_none_or(str::is_empty) {
                        next.flow_token = response.flow_token.take();
                    }
                    async_sleep(POLL_INTERVAL).await;
                }
                response = next;
            }
        })
        .await
        .map_err(|_| protocol_error("Bulk enrollment timed out; package user may have been created"))?
    }
}

impl BrokerClientApplication {
    /// Join a machine at installation time using a reusable bulk package.
    ///
    /// Uses the AADInternals BPRT refresh grant (AADJ CSP client ID, OAuth v1,
    /// DRS resource), then the existing device enrollment/key generation path.
    /// Does not sign in a person, issue their PRT, or enroll in Intune.
    /// Persist the returned machine-specific keys and device ID in Himmelblau's
    /// existing protected storage. Discard the bulk secret after provisioning.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn enroll_device_with_bulk_package(
        &mut self,
        package: &BulkEnrollmentPackage,
        attrs: EnrollAttrs,
        tpm: &mut BoxedDynTpm,
        storage_key: &StorageKey,
    ) -> Result<(LoadableMsOapxbcRsaKey, LoadableMsDeviceEnrolmentKey, String), MsalError> {
        package.validate()?;
        let token = self.bulk_enrollment_access_token(package).await?;
        self.enroll_device_with_access_token(&token.access_token, attrs, tpm, storage_key)
            .await
    }

    async fn bulk_enrollment_access_token(
        &self,
        package: &BulkEnrollmentPackage,
    ) -> Result<BulkAccessToken, MsalError> {
        package.validate()?;
        let authority = Url::parse(&self.app.authority()?)
            .map_err(|_| MsalError::URLFormatFailed("Invalid bulk enrollment authority".into()))?;
        validate_authority(&authority)?;
        let endpoint = authority
            .join(&format!("/{}/oauth2/token", package.metadata.tenant_id))
            .map_err(|_| MsalError::URLFormatFailed("Invalid bulk token endpoint".into()))?;
        let response = self
            .client()
            .post(endpoint)
            .form(&[
                ("client_id", BULK_CLIENT_ID),
                ("resource", BULK_RESOURCE),
                ("grant_type", "refresh_token"),
                ("refresh_token", package.refresh_token()),
            ])
            .send()
            .await
            .map_err(|e| MsalError::request_failed(&e.without_url()))?;
        if !response.status().is_success() {
            return Err(bulk_http_error(response).await);
        }
        let token: BulkAccessToken = response
            .json()
            .await
            .map_err(|_| protocol_error("Malformed bulk enrollment access token response"))?;
        if token.access_token.trim().is_empty() {
            return Err(protocol_error("Bulk enrollment access token is empty"));
        }
        Ok(token)
    }
}

#[cfg(test)]
#[path = "bulk_enrollment_tests.rs"]
mod tests;
