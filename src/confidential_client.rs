/*
   MIT License

   Copyright (c) 2022 freedit-org
   Copyright (c) 2025 David Mulder <dmulder@samba.org>

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/
use crate::error::{ErrorResponse, MsalError};
use crate::ClientApplication;
#[cfg(feature = "ipvers")]
use crate::IpVersion;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use compact_jwt::crypto::JwsTpmRs256Signer;
use compact_jwt::jws::JwsBuilder;
use compact_jwt::traits::JwsMutSigner as _;
use crypto_glue::sha1::Sha1;
use crypto_glue::traits::{Digest, EncodeDer};
use crypto_glue::x509::Certificate;
use kanidm_hsm_crypto::{provider::BoxedDynTpm, structures::RS256Key};
use reqwest::Client;
use serde::{Deserialize, Serialize};
#[cfg(feature = "on_behalf_of")]
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[cfg(feature = "on_behalf_of")]
use tracing::{debug, warn};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

const CLIENT_ID: &str = "client_id";
const SCOPES: &str = "scope";
const GRANT_TYPE: &str = "grant_type";
const CLIENT_CREDENTIALS_GRANT: &str = "client_credentials";
const CLIENT_SECRET: &str = "client_secret";
const CLIENT_ASSERTION: &str = "client_assertion";
const ASSERTION_TYPE: &str = "client_assertion_type";
const CLIENT_ASSERTION_GRANT_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
#[cfg(feature = "on_behalf_of")]
const OBO_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
#[cfg(feature = "on_behalf_of")]
const USER_ASSERTION: &str = "assertion";
#[cfg(feature = "on_behalf_of")]
const REQUESTED_TOKEN_USE: &str = "requested_token_use";
#[cfg(feature = "on_behalf_of")]
const REQUESTED_TOKEN_USE_OBO: &str = "on_behalf_of";

#[derive(Debug, Serialize)]
struct AssertionClaims<'a> {
    aud: &'a str,
    sub: &'a str,
    iss: &'a str,
    jti: &'a str,
    iat: u64,
    exp: u64,
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Secret {
    value: String,
}

pub enum ClientCredential {
    ClientSecret(Secret),
    Certificate(Box<Certificate>, RS256Key),
}

impl ClientCredential {
    /// Create a new client credential from a client secret.
    ///
    /// See: [1-Call-MsGraph-WithSecret](https://github.com/Azure-Samples/ms-identity-python-daemon/blob/master/1-Call-MsGraph-WithSecret/README.md)
    pub fn from_secret(secret: String) -> Self {
        ClientCredential::ClientSecret(Secret { value: secret })
    }

    /// Create a new client credential from a certificate.
    ///
    /// See: [2-Call-MsGraph-WithCertificate](https://github.com/Azure-Samples/ms-identity-python-daemon/blob/master/2-Call-MsGraph-WithCertificate/README.md)
    pub fn from_certificate(cert: &Certificate, key: RS256Key) -> Self {
        ClientCredential::Certificate(Box::new(cert.clone()), key)
    }
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct AccessTokenPayload {
    tid: String,
}

#[derive(Clone, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ClientToken {
    pub token_type: String,
    pub expires_in: u32,
    pub ext_expires_in: u32,
    pub access_token: String,
}

impl ClientToken {
    /// Fetch the tenant id from the client token
    ///
    /// # Returns
    ///
    /// * Success: The user's tenant id
    /// * Failure: An MsalError, indicating the failure.
    pub fn tenant_id(&self) -> Result<String, MsalError> {
        let mut siter = self.access_token.splitn(3, '.');
        siter.next(); // Ignore the header
        let payload: AccessTokenPayload = serde_json::from_str(
            &String::from_utf8(
                URL_SAFE_NO_PAD
                    .decode(siter.next().ok_or_else(|| {
                        MsalError::InvalidParse("Payload not present".to_string())
                    })?)
                    .map_err(|e| MsalError::InvalidBase64(format!("{}", e)))?,
            )
            .map_err(|e| MsalError::InvalidParse(format!("{}", e)))?,
        )
        .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
        Ok(payload.tid.clone())
    }
}

/// Token response from an OBO exchange. This carries the user's identity
/// context for the downstream API.
#[cfg(feature = "on_behalf_of")]
#[derive(Clone, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct OboToken {
    pub token_type: String,
    #[serde(default)]
    pub scope: Option<String>,
    pub expires_in: u32,
    #[serde(default)]
    pub ext_expires_in: u32,
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

/// Pre-flight claims extracted from a JWT assertion for local validation.
/// Only the payload is decoded; signature verification is left to Azure.
#[cfg(feature = "on_behalf_of")]
#[derive(Deserialize)]
struct AssertionPreflightClaims {
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    aud: Option<AssertionAudience>,
    /// Tenant ID of the user — used to build a tenant-specific OBO authority.
    #[serde(default)]
    tid: Option<String>,
}

#[cfg(feature = "on_behalf_of")]
#[derive(Deserialize)]
#[serde(untagged)]
enum AssertionAudience {
    Single(String),
    Multiple(Vec<String>),
}

/// Decode the payload of a JWT assertion and return the pre-flight claims.
/// Only the base64url-decoded payload is examined; signature verification
/// is left to Azure. Returns `None` if the token cannot be decoded.
#[cfg(feature = "on_behalf_of")]
fn decode_assertion_preflight_claims(assertion: &str) -> Option<AssertionPreflightClaims> {
    let mut parts = assertion.splitn(3, '.');
    parts.next(); // Skip header
    let payload_b64 = parts.next()?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    serde_json::from_slice(&payload_bytes).ok()
}

pub struct ConfidentialClientApplication {
    app: ClientApplication,
    credential: ClientCredential,
}

impl ConfidentialClientApplication {
    /// Create an instance of an application.
    ///
    /// # Arguments
    ///
    /// * `client_id` - Your app has a client_id after you register it on
    ///   AAD.
    ///
    /// * `authority` - A URL that identifies a token authority. It should
    ///   be of the format <https://login.microsoftonline.com/your_tenant> By
    ///   default, we will use <https://login.microsoftonline.com/common>.
    ///
    /// * `credential` - Either a LoadableRS256Key (associated with a certificate
    ///   uploaded as a credential), or a client secret string.
    pub fn new(
        client_id: &str,
        authority: Option<&str>,
        credential: ClientCredential,
        #[cfg(feature = "set_timeout")] timeout: Duration,
        #[cfg(feature = "ipvers")] ip_version: &[IpVersion],
    ) -> Result<Self, MsalError> {
        Ok(ConfidentialClientApplication {
            app: ClientApplication::new(
                client_id,
                authority,
                #[cfg(feature = "set_timeout")]
                timeout,
                #[cfg(feature = "ipvers")]
                ip_version,
            )?,
            credential,
        })
    }

    fn client(&self) -> &Client {
        &self.app.client
    }

    fn client_id(&self) -> &str {
        &self.app.client_id
    }

    fn authority(&self) -> Result<String, MsalError> {
        self.app.authority()
    }

    /// Changes the authority url set at initialization time
    ///
    /// # Arguments
    ///
    /// * `new_authority` - The new authority url to be used when communicating
    ///   with Entra Id.
    ///
    /// # Returns
    /// * Failure: An MsalError, indicating the failure.
    pub fn set_authority(&self, new_authority: &str) -> Result<(), MsalError> {
        self.app.set_authority(new_authority)
    }

    /// Build a signed client assertion JWT for certificate-based authentication.
    ///
    /// This is used by both `acquire_token_silent` (client_credentials) and
    /// `acquire_token_on_behalf_of` (OBO) when the credential is a certificate.
    fn build_client_assertion(
        &self,
        audience: &str,
        cert: &Certificate,
        signing_key: &RS256Key,
        tpm: &mut BoxedDynTpm,
    ) -> Result<String, MsalError> {
        let now: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| MsalError::GeneralFailure(format!("Failed choosing iat: {}", e)))?
            .as_secs();
        let issuer = self.client_id();
        let uuid = Uuid::new_v4().to_string();
        let claims = AssertionClaims {
            aud: audience,
            sub: issuer,
            iss: issuer,
            exp: 600 + now,
            iat: now,
            jti: uuid.as_str(),
        };

        let sha1_thumbprint =
            URL_SAFE_NO_PAD.encode(Sha1::digest(&cert.to_der().map_err(|e| {
                MsalError::GeneralFailure(format!("Failed getting certificate DER: {:?}", e))
            })?));

        let jwt = JwsBuilder::from(
            serde_json::to_vec(&claims)
                .map_err(|e| MsalError::InvalidJson(format!("Failed to serialize JWT: {}", e)))?,
        )
        .set_x5t(&sha1_thumbprint)
        .build();

        let mut jws_tpm_signer = JwsTpmRs256Signer::new(tpm, signing_key)
            .map_err(|e| MsalError::TPMFail(format!("Failed loading tpm signer: {}", e)))?;

        let signed_jwt = jws_tpm_signer
            .sign(&jwt)
            .map_err(|e| MsalError::TPMFail(format!("Failed signing jwk: {}", e)))?;

        Ok(format!("{}", signed_jwt))
    }

    /// Insert client credential parameters into the request params map.
    ///
    /// For `ClientSecret`, inserts the `client_secret` parameter.
    /// For `Certificate`, builds a signed JWT client assertion and inserts
    /// `client_assertion` and `client_assertion_type` parameters.
    fn insert_credential_params<'a>(
        &'a self,
        params: &mut HashMap<&'a str, &'a str>,
        signed_jwt_out: &'a mut String,
        token_url: &str,
        tpm: Option<&mut BoxedDynTpm>,
    ) -> Result<(), MsalError> {
        match &self.credential {
            ClientCredential::ClientSecret(client_secret) => {
                params.insert(CLIENT_SECRET, client_secret.value.as_str());
            }
            ClientCredential::Certificate(cert, signing_key) => {
                let tpm =
                    tpm.ok_or_else(|| MsalError::TPMFail("tpm object not provided".to_string()))?;
                *signed_jwt_out = self.build_client_assertion(token_url, cert, signing_key, tpm)?;
                params.insert(CLIENT_ASSERTION, signed_jwt_out.as_str());
                params.insert(ASSERTION_TYPE, CLIENT_ASSERTION_GRANT_TYPE);
            }
        }
        Ok(())
    }

    /// Validate an incoming user assertion (JWT) before sending it to Azure.
    ///
    /// Performs best-effort diagnostics without signature verification:
    /// - Warn if the `exp` claim is in the past
    /// - Warn if the `aud` claim doesn't appear to target this application
    ///
    /// If decoding fails, diagnostics are skipped and Azure provides definitive errors.
    #[cfg(feature = "on_behalf_of")]
    fn validate_assertion_preflight(&self, assertion: &str) {
        let claims = match decode_assertion_preflight_claims(assertion) {
            Some(c) => c,
            None => return,
        };

        if let Some(exp) = claims.exp {
            match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(now) if exp <= now.as_secs() => {
                    warn!("User assertion appears expired in OBO preflight (exp={exp})");
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("Unable to validate user assertion exp in OBO preflight: {e}");
                }
            }
        }

        if let Some(aud) = claims.aud {
            let target = self.client_id();
            // The aud claim may be the bare client_id GUID or an App ID URI
            // such as `api://<client_id>` — both are valid and accepted by Azure.
            let aud_matches_target = |candidate: &str| {
                candidate == target
                    || candidate == format!("api://{}", target)
                    || candidate.ends_with(&format!("/{}", target))
            };
            let aud_matches = match aud {
                AssertionAudience::Single(single_aud) => aud_matches_target(&single_aud),
                AssertionAudience::Multiple(multi_aud) => multi_aud
                    .iter()
                    .any(|candidate| aud_matches_target(candidate)),
            };
            if !aud_matches {
                warn!(
                    "User assertion audience did not match client_id in OBO preflight (client_id={})",
                    target
                );
            }
        }
    }

    /// Attempts to acquire a token silently for the configured confidential client application.
    ///
    /// This function uses a client credential to obtain a new access token without prompting the user.
    ///
    /// # Arguments
    ///
    /// * `scopes` - Scopes requested to access a protected API (a resource).
    ///
    /// * `tpm` - An optional TPM interface. Required only if the client was initialized
    ///   with a `LoadableRS256Key` tied to a client certificate.
    ///
    /// # Returns
    /// * Success: A `ClientToken` containing an access token.
    /// * Failure: An `MsalError`, indicating the reason the silent token acquisition failed.
    pub async fn acquire_token_silent(
        &self,
        scopes: Vec<&str>,
        tpm: Option<&mut BoxedDynTpm>,
    ) -> Result<ClientToken, MsalError> {
        let url = format!("{}/oauth2/v2.0/token", self.authority()?);
        let mut params = HashMap::new();
        let mut signed_jwt = String::new();

        self.insert_credential_params(&mut params, &mut signed_jwt, &url, tpm)?;

        params.insert(CLIENT_ID, self.client_id());
        let scope = scopes.join(" ");
        params.insert(SCOPES, &scope);
        params.insert(GRANT_TYPE, CLIENT_CREDENTIALS_GRANT);

        let resp = self
            .client()
            .post(url)
            .timeout(Duration::from_secs(30))
            .form(&params)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let token: ClientToken = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;

            Ok(token)
        } else {
            let json_resp: ErrorResponse = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            Err(MsalError::AcquireTokenFailed(json_resp))
        }
    }

    /// Acquire a token on behalf of a user.
    ///
    /// Exchanges an incoming user access token (the assertion) for a new access
    /// token targeting a downstream API, preserving the user's identity and
    /// permissions through the request chain.
    ///
    /// This implements the OAuth 2.0 On-Behalf-Of (OBO) flow as defined in:
    /// <https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow>
    ///
    /// # Arguments
    ///
    /// * `user_assertion` - The access token received by the middle-tier API
    ///   from the calling client. This token's `aud` claim MUST match this
    ///   application's `client_id`.
    ///
    /// * `scopes` - Scopes for the downstream API (e.g.,
    ///   `["https://graph.microsoft.com/User.Read"]`). Include `offline_access`
    ///   if a refresh token is needed.
    ///
    /// * `tpm` - An optional TPM interface. Required only if the client was
    ///   initialized with a certificate credential.
    ///
    /// # Returns
    ///
    /// * `Ok(OboToken)` - Token for the downstream API with user context.
    /// * `Err(MsalError::OboInteractionRequired)` - Conditional Access requires
    ///   user interaction. The `claims` field must be propagated back to the
    ///   original client for re-authentication.
    /// * `Err(MsalError)` - Other errors (network, configuration, etc.)
    #[cfg(feature = "on_behalf_of")]
    pub async fn acquire_token_on_behalf_of(
        &self,
        user_assertion: &str,
        scopes: Vec<&str>,
        tpm: Option<&mut BoxedDynTpm>,
    ) -> Result<OboToken, MsalError> {
        debug!("Acquiring token via On-Behalf-Of flow");

        self.validate_assertion_preflight(user_assertion);

        // Per MSAL guidance, OBO should target the user's specific tenant rather
        // than a multi-tenant endpoint. Extract the tid from the assertion and, if
        // the configured authority is /common or /organizations, override it with
        // the tenant-specific authority so the token is issued for the correct
        // home tenant (important for guest users).
        let base_authority = self.authority()?;
        let normalized = base_authority.trim_end_matches('/');
        let obo_authority = match decode_assertion_preflight_claims(user_assertion)
            .and_then(|c| c.tid)
        {
            Some(tid) => {
                if let Some(pos) = normalized.rfind('/') {
                    let suffix = &normalized[pos + 1..];
                    if suffix == "common" || suffix == "organizations" {
                        debug!(
                            "OBO: overriding multi-tenant authority with tenant-specific authority (tid={})",
                            tid
                        );
                        format!("{}/{}", &normalized[..pos], tid)
                    } else {
                        normalized.to_string()
                    }
                } else {
                    normalized.to_string()
                }
            }
            None => normalized.to_string(),
        };
        let url = format!("{}/oauth2/v2.0/token", obo_authority);
        let mut params = HashMap::new();
        let mut signed_jwt = String::new();

        self.insert_credential_params(&mut params, &mut signed_jwt, &url, tpm)?;

        params.insert(CLIENT_ID, self.client_id());
        params.insert(GRANT_TYPE, OBO_GRANT_TYPE);
        params.insert(USER_ASSERTION, user_assertion);
        params.insert(REQUESTED_TOKEN_USE, REQUESTED_TOKEN_USE_OBO);
        let scope = scopes.join(" ");
        params.insert(SCOPES, &scope);

        debug!("POST {} (OBO exchange, scopes: {})", url, scope);

        let resp = self
            .client()
            .post(url)
            .timeout(Duration::from_secs(30))
            .form(&params)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;

        if resp.status().is_success() {
            let token: OboToken = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            debug!(
                "OBO token acquired, expires in {} seconds",
                token.expires_in
            );
            Ok(token)
        } else {
            // Parse as generic JSON first to check for interaction_required + claims
            let body: Value = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            let claims = body.get("claims").and_then(|claim| match claim {
                Value::Null => None,
                Value::String(s) => {
                    let trimmed = s.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    }
                }
                other => {
                    let encoded = other.to_string();
                    if encoded.trim().is_empty() || encoded == "null" {
                        None
                    } else {
                        Some(encoded)
                    }
                }
            });
            let error_resp: ErrorResponse = serde_json::from_value(body).map_err(|e| {
                MsalError::InvalidJson(format!("Failed to parse OBO error response: {}", e))
            })?;
            if claims.is_some() || error_resp.error == "interaction_required" {
                return Err(MsalError::OboInteractionRequired {
                    error: error_resp,
                    claims,
                });
            }
            Err(MsalError::AcquireTokenFailed(error_resp))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    #[cfg(feature = "on_behalf_of")]
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    #[cfg(feature = "on_behalf_of")]
    use base64::Engine;
    #[cfg(feature = "on_behalf_of")]
    use serde_json::json;

    /// Helper: build a minimal ConfidentialClientApplication for testing
    /// private methods.
    #[cfg(feature = "on_behalf_of")]
    fn test_app(client_id: &str) -> ConfidentialClientApplication {
        let credential = ClientCredential::from_secret("test-secret".to_string());
        ConfidentialClientApplication::new(client_id, None, credential)
            .expect("Failed to create test app")
    }

    /// Helper: build a JWT-shaped string (header.payload.signature) from
    /// a JSON Value payload.  The header and signature are dummies.
    #[cfg(feature = "on_behalf_of")]
    fn make_jwt(payload: &serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(b"{}");
        let body = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
        format!("{}.{}.sig", header, body)
    }

    // ---------------------------------------------------------------
    // validate_assertion_preflight
    // ---------------------------------------------------------------

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn preflight_valid_token_passes() {
        let app = test_app("my-client-id");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let jwt = make_jwt(&json!({
            "aud": "my-client-id",
            "exp": now + 3600,
        }));
        app.validate_assertion_preflight(&jwt);
    }

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn preflight_expired_token_is_non_blocking() {
        let app = test_app("my-client-id");
        let jwt = make_jwt(&json!({
            "aud": "my-client-id",
            "exp": 1000, // far in the past
        }));
        app.validate_assertion_preflight(&jwt);
    }

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn preflight_app_id_uri_audience_passes() {
        // aud = api://<client_id> is a valid App ID URI audience — should not warn
        let app = test_app("my-client-id");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let jwt = make_jwt(&json!({
            "aud": "api://my-client-id",
            "exp": now + 3600,
        }));
        app.validate_assertion_preflight(&jwt);
    }

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn preflight_wrong_audience_is_non_blocking() {
        let app = test_app("my-client-id");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let jwt = make_jwt(&json!({
            "aud": "some-other-id",
            "exp": now + 3600,
        }));
        app.validate_assertion_preflight(&jwt);
    }

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn preflight_audience_array_passes() {
        let app = test_app("my-client-id");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let jwt = make_jwt(&json!({
            "aud": ["other-client", "my-client-id"],
            "exp": now + 3600,
        }));
        app.validate_assertion_preflight(&jwt);
    }

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn preflight_empty_string_passes() {
        let app = test_app("my-client-id");
        // Empty string — can't decode, should pass through to Azure
        app.validate_assertion_preflight("");
    }

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn preflight_no_dots_passes() {
        let app = test_app("my-client-id");
        // No dots — splitn yields only one part, payload is None
        app.validate_assertion_preflight("justanopaquetokenstring");
    }

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn preflight_garbage_payload_passes() {
        let app = test_app("my-client-id");
        // Valid structure but garbage base64 payload
        app.validate_assertion_preflight("aaa.!!!notbase64!!!.bbb");
    }

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn preflight_missing_claims_passes() {
        let app = test_app("my-client-id");
        // Valid JWT with no exp and no aud — both checks skipped
        let jwt = make_jwt(&json!({"sub": "user"}));
        app.validate_assertion_preflight(&jwt);
    }

    // ---------------------------------------------------------------
    // OBO tenant-specific authority override
    // ---------------------------------------------------------------

    /// Helper: build an app with a specific authority URL.
    #[cfg(feature = "on_behalf_of")]
    fn test_app_with_authority(client_id: &str, authority: &str) -> ConfidentialClientApplication {
        let credential = ClientCredential::from_secret("test-secret".to_string());
        ConfidentialClientApplication::new(client_id, Some(authority), credential)
            .expect("Failed to create test app with authority")
    }

    /// Helper: compute the OBO authority the same way `acquire_token_on_behalf_of`
    /// does, without making a network call.
    #[cfg(feature = "on_behalf_of")]
    fn compute_obo_authority(app: &ConfidentialClientApplication, jwt: &str) -> String {
        let base_authority = app.authority().unwrap();
        let normalized = base_authority.trim_end_matches('/');
        match decode_assertion_preflight_claims(jwt).and_then(|c| c.tid) {
            Some(tid) => {
                if let Some(pos) = normalized.rfind('/') {
                    let suffix = &normalized[pos + 1..];
                    if suffix == "common" || suffix == "organizations" {
                        format!("{}/{}", &normalized[..pos], tid)
                    } else {
                        normalized.to_string()
                    }
                } else {
                    normalized.to_string()
                }
            }
            None => normalized.to_string(),
        }
    }

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn obo_authority_override_common_with_tid() {
        let app = test_app_with_authority("cid", "https://login.microsoftonline.com/common");
        let jwt = make_jwt(&json!({"tid": "tenant-abc-123"}));
        let authority = compute_obo_authority(&app, &jwt);
        assert_eq!(
            authority,
            "https://login.microsoftonline.com/tenant-abc-123"
        );
    }

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn obo_authority_override_organizations_with_tid() {
        let app = test_app_with_authority("cid", "https://login.microsoftonline.com/organizations");
        let jwt = make_jwt(&json!({"tid": "tenant-xyz"}));
        let authority = compute_obo_authority(&app, &jwt);
        assert_eq!(authority, "https://login.microsoftonline.com/tenant-xyz");
    }

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn obo_authority_keeps_specific_tenant() {
        let app = test_app_with_authority("cid", "https://login.microsoftonline.com/my-tenant-id");
        let jwt = make_jwt(&json!({"tid": "other-tenant"}));
        let authority = compute_obo_authority(&app, &jwt);
        assert_eq!(authority, "https://login.microsoftonline.com/my-tenant-id");
    }

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn obo_authority_override_common_trailing_slash() {
        let app = test_app_with_authority("cid", "https://login.microsoftonline.com/common/");
        let jwt = make_jwt(&json!({"tid": "tenant-trailing"}));
        let authority = compute_obo_authority(&app, &jwt);
        assert_eq!(
            authority,
            "https://login.microsoftonline.com/tenant-trailing"
        );
    }

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn obo_authority_gcch_override_common() {
        let app = test_app_with_authority("cid", "https://login.microsoftonline.us/common");
        let jwt = make_jwt(&json!({"tid": "gcch-tenant"}));
        let authority = compute_obo_authority(&app, &jwt);
        assert_eq!(authority, "https://login.microsoftonline.us/gcch-tenant");
    }

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn obo_authority_no_tid_in_assertion() {
        let app = test_app_with_authority("cid", "https://login.microsoftonline.com/common");
        let jwt = make_jwt(&json!({"sub": "user"}));
        let authority = compute_obo_authority(&app, &jwt);
        assert_eq!(authority, "https://login.microsoftonline.com/common");
    }

    // ---------------------------------------------------------------
    // OboToken deserialization
    // ---------------------------------------------------------------

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn obo_token_full_response() {
        let json_str = r#"{
            "token_type": "Bearer",
            "scope": "https://graph.microsoft.com/User.Read",
            "expires_in": 3600,
            "ext_expires_in": 7200,
            "access_token": "eyJ0eXAi...",
            "refresh_token": "OAAABAAAAi..."
        }"#;
        let token: OboToken = serde_json::from_str(json_str).unwrap();
        assert_eq!(token.token_type, "Bearer");
        assert_eq!(
            token.scope,
            Some("https://graph.microsoft.com/User.Read".to_string())
        );
        assert_eq!(token.expires_in, 3600);
        assert_eq!(token.ext_expires_in, 7200);
        assert_eq!(token.access_token, "eyJ0eXAi...");
        assert_eq!(token.refresh_token, Some("OAAABAAAAi...".to_string()));
    }

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn obo_token_minimal_response() {
        // Azure returns only the required fields; optional ones use defaults
        let json_str = r#"{
            "token_type": "Bearer",
            "expires_in": 3600,
            "access_token": "eyJ0eXAi..."
        }"#;
        let token: OboToken = serde_json::from_str(json_str).unwrap();
        assert_eq!(token.token_type, "Bearer");
        assert_eq!(token.scope, None);
        assert_eq!(token.ext_expires_in, 0);
        assert_eq!(token.refresh_token, None);
    }

    // ---------------------------------------------------------------
    // ClientToken deserialization
    // ---------------------------------------------------------------

    #[test]
    fn client_token_deserialization() {
        let json_str = r#"{
            "token_type": "Bearer",
            "expires_in": 3600,
            "ext_expires_in": 7200,
            "access_token": "eyJ0eXAi..."
        }"#;
        let token: ClientToken = serde_json::from_str(json_str).unwrap();
        assert_eq!(token.token_type, "Bearer");
        assert_eq!(token.expires_in, 3600);
        assert_eq!(token.ext_expires_in, 7200);
        assert_eq!(token.access_token, "eyJ0eXAi...");
    }

    // ---------------------------------------------------------------
    // interaction_required error parsing
    // ---------------------------------------------------------------

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn parse_interaction_required_with_claims() {
        let body = json!({
            "error": "interaction_required",
            "error_description": "AADSTS50076: Due to a configuration change",
            "error_codes": [50076],
            "claims": "{\"access_token\":{\"polids\":{\"essential\":true}}}"
        });

        let error_str = body
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or_default();
        assert_eq!(error_str, "interaction_required");

        let claims = body
            .get("claims")
            .and_then(|c| c.as_str())
            .map(String::from);
        assert!(claims.is_some());
        assert!(claims.as_ref().unwrap().contains("polids"));

        let error_resp: ErrorResponse = serde_json::from_value(body).unwrap();
        assert_eq!(error_resp.error, "interaction_required");
        assert_eq!(error_resp.error_codes, vec![50076]);
        let classified = if claims.is_some() || error_resp.error == "interaction_required" {
            MsalError::OboInteractionRequired {
                error: error_resp,
                claims,
            }
        } else {
            MsalError::AcquireTokenFailed(error_resp)
        };
        assert!(matches!(
            classified,
            MsalError::OboInteractionRequired { .. }
        ));
    }

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn parse_interaction_required_without_claims() {
        let body = json!({
            "error": "interaction_required",
            "error_description": "AADSTS16000: Interaction required",
            "error_codes": [16000]
        });

        let claims = body
            .get("claims")
            .and_then(|c| c.as_str())
            .map(String::from);
        assert!(claims.is_none());

        let error_resp: ErrorResponse = serde_json::from_value(body).unwrap();
        assert_eq!(error_resp.error_codes, vec![16000]);
    }

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn parse_interaction_required_missing_error_codes() {
        // After the #[serde(default)] fix, this should now parse successfully
        let body = json!({
            "error": "interaction_required",
            "error_description": "Some error"
        });

        let error_resp: ErrorResponse = serde_json::from_value(body).unwrap();
        assert_eq!(error_resp.error, "interaction_required");
        assert_eq!(error_resp.suberror, None);
        assert!(error_resp.error_codes.is_empty());
    }

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn parse_error_response_missing_all_optional_fields() {
        // After #[serde(default)], only "error" is truly required
        let body = json!({
            "error": "invalid_grant"
        });

        let error_resp: ErrorResponse = serde_json::from_value(body).unwrap();
        assert_eq!(error_resp.error, "invalid_grant");
        assert_eq!(error_resp.error_description, "");
        assert_eq!(error_resp.suberror, None);
        assert!(error_resp.error_codes.is_empty());
    }

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn parse_standard_obo_error() {
        let body = json!({
            "error": "invalid_grant",
            "error_description": "AADSTS65001: The user has not consented",
            "error_codes": [65001]
        });

        let error_resp: ErrorResponse = serde_json::from_value(body).unwrap();
        assert_eq!(error_resp.error, "invalid_grant");
        assert_eq!(error_resp.suberror, None);
        assert_eq!(error_resp.error_codes, vec![65001]);
    }

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn parse_claims_with_non_interaction_error_still_has_claims() {
        let body = json!({
            "error": "invalid_grant",
            "error_description": "AADSTS50076",
            "claims": "{\"access_token\":{\"xms_cc\":{\"values\":[\"cp1\"]}}}",
            "error_codes": [50076]
        });
        let claims = body
            .get("claims")
            .and_then(|claim| claim.as_str())
            .map(str::trim)
            .filter(|claim| !claim.is_empty())
            .map(String::from);
        assert!(claims.is_some());
        let error_resp: ErrorResponse = serde_json::from_value(body).unwrap();
        let classified = if claims.is_some() || error_resp.error == "interaction_required" {
            MsalError::OboInteractionRequired {
                error: error_resp,
                claims,
            }
        } else {
            MsalError::AcquireTokenFailed(error_resp)
        };
        assert!(matches!(
            classified,
            MsalError::OboInteractionRequired { .. }
        ));
    }

    #[cfg(feature = "on_behalf_of")]
    #[test]
    fn parse_object_claims_with_non_interaction_error_still_has_claims() {
        let body = json!({
            "error": "invalid_grant",
            "error_description": "AADSTS50076",
            "claims": {
                "access_token": {
                    "xms_cc": {
                        "values": ["cp1"]
                    }
                }
            },
            "error_codes": [50076]
        });

        let claims = body.get("claims").and_then(|claim| match claim {
            Value::Null => None,
            Value::String(s) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            }
            other => {
                let encoded = other.to_string();
                if encoded.trim().is_empty() || encoded == "null" {
                    None
                } else {
                    Some(encoded)
                }
            }
        });
        assert!(claims.is_some());
        assert!(claims.as_ref().unwrap().contains("xms_cc"));

        let error_resp: ErrorResponse = serde_json::from_value(body).unwrap();
        let classified = if claims.is_some() || error_resp.error == "interaction_required" {
            MsalError::OboInteractionRequired {
                error: error_resp,
                claims,
            }
        } else {
            MsalError::AcquireTokenFailed(error_resp)
        };
        assert!(matches!(
            classified,
            MsalError::OboInteractionRequired { .. }
        ));
    }
}
