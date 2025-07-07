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
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
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
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

const CLIENT_ID: &str = "client_id";
const SCOPES: &str = "scope";
const GRANT_TYPE: &str = "grant_type";
const CLIENT_CREDENTIALS_GRANT: &str = "client_credentials";
const CLIENT_SECRET: &str = "client_secret";
const ASSERTION: &str = "client_assertion";
const ASSERTION_TYPE: &str = "client_assertion_type";
const CLIENT_ASSERTION_GRANT_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

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
    ) -> Result<Self, MsalError> {
        Ok(ConfidentialClientApplication {
            app: ClientApplication::new(client_id, authority)?,
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
        let url = format!("{}/oAuth2/v2.0/token", self.authority()?);
        let mut params = HashMap::new();

        let signed_jwt;
        match &self.credential {
            ClientCredential::ClientSecret(client_secret) => {
                params.insert(CLIENT_SECRET, client_secret.value.as_str());
            }
            ClientCredential::Certificate(cert, signing_key) => {
                let tpm =
                    tpm.ok_or_else(|| MsalError::TPMFail("tpm object not provided".to_string()))?;
                let now: u64 = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| MsalError::GeneralFailure(format!("Failed choosing iat: {}", e)))?
                    .as_secs();
                let audience = &url;
                let issuer = &self.client_id();
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
                    STANDARD.encode(Sha1::digest(&cert.to_der().map_err(|e| {
                        MsalError::GeneralFailure(format!(
                            "Failed getting certificate PEM: {:?}",
                            e
                        ))
                    })?));

                let jwt = JwsBuilder::from(serde_json::to_vec(&claims).map_err(|e| {
                    MsalError::InvalidJson(format!("Failed to serialize JWT: {}", e))
                })?)
                .set_x5t(&sha1_thumbprint)
                .build();

                let mut jws_tpm_signer = match JwsTpmRs256Signer::new(tpm, &signing_key) {
                    Ok(jws_tpm_signer) => jws_tpm_signer,
                    Err(e) => {
                        return Err(MsalError::TPMFail(format!(
                            "Failed loading tpm signer: {}",
                            e
                        )))
                    }
                };

                signed_jwt = match jws_tpm_signer.sign(&jwt) {
                    Ok(signed_jwt) => format!("{}", signed_jwt),
                    Err(e) => return Err(MsalError::TPMFail(format!("Failed signing jwk: {}", e))),
                };

                params.insert(ASSERTION, &signed_jwt);
                params.insert(ASSERTION_TYPE, CLIENT_ASSERTION_GRANT_TYPE);
            }
        }

        params.insert(CLIENT_ID, self.client_id());
        let scope = scopes.join(" ");
        params.insert(SCOPES, &scope);
        params.insert(GRANT_TYPE, CLIENT_CREDENTIALS_GRANT);

        let resp = self
            .client()
            .post(url)
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
}
