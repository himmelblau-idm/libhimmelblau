use crate::error::{ErrorResponse, MsalError};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use reqwest::{header, Client};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{from_str as json_from_str, Value};
use urlencoding::encode as url_encode;
use uuid::Uuid;

#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
use compact_jwt::compact::JweCompact;
#[cfg(all(feature = "broker", not(feature = "tpm")))]
#[doc(cfg(all(feature = "broker", not(feature = "tpm"))))]
use compact_jwt::crypto::JwsRs256Signer;
#[cfg(all(feature = "broker", feature = "tpm"))]
#[doc(cfg(all(feature = "broker", feature = "tpm")))]
use compact_jwt::crypto::JwsTpmSigner;
#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
use compact_jwt::crypto::MsOapxbcSessionKey;
#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
use compact_jwt::jws::JwsBuilder;
#[cfg(all(feature = "broker", feature = "tpm"))]
#[doc(cfg(all(feature = "broker", feature = "tpm")))]
use compact_jwt::traits::JwsMutSigner;
#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
use compact_jwt::Jws;
#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
use compact_jwt::JwsSigner;
#[cfg(all(feature = "broker", feature = "tpm"))]
#[doc(cfg(all(feature = "broker", feature = "tpm")))]
use kanidm_hsm_crypto::{BoxedDynTpm, IdentityKey, LoadableIdentityKey, MachineKey, Tpm};
#[cfg(all(feature = "broker", not(feature = "tpm")))]
#[doc(cfg(all(feature = "broker", not(feature = "tpm"))))]
use openssl::hash::MessageDigest;
#[cfg(all(feature = "broker", not(feature = "tpm")))]
#[doc(cfg(all(feature = "broker", not(feature = "tpm"))))]
use openssl::pkey::PKey;
#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
use openssl::pkey::Private;
#[cfg(all(feature = "broker", feature = "tpm"))]
#[doc(cfg(all(feature = "broker", feature = "tpm")))]
use openssl::pkey::Public;
#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
use openssl::rsa::Rsa;
#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
use openssl::x509::X509;
#[cfg(all(feature = "broker", not(feature = "tpm")))]
#[doc(cfg(all(feature = "broker", not(feature = "tpm"))))]
use openssl::x509::{X509NameBuilder, X509ReqBuilder};
#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
use os_release::OsRelease;
#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
use reqwest::Url;
#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
use std::str::FromStr;
#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
use tracing::debug;

/* The following is permitted because Rsa<Private> is a superset of
 * Rsa<Public>. */
#[cfg(all(feature = "broker", feature = "tpm"))]
#[doc(cfg(all(feature = "broker", feature = "tpm")))]
type EnrollmentKey = Rsa<Public>;
#[cfg(all(feature = "broker", not(feature = "tpm")))]
#[doc(cfg(all(feature = "broker", not(feature = "tpm"))))]
type EnrollmentKey = Rsa<Private>;

#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
use crate::discovery::{
    discover_enrollment_services, DISCOVERY_URL, DRS_CLIENT_NAME_HEADER_FIELD,
    DRS_CLIENT_VERSION_HEADER_FIELD,
};
#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
use serde_json::{json, to_string_pretty};

#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
#[derive(Debug, Deserialize)]
struct Certificate {
    #[serde(rename = "RawBody")]
    raw_body: String,
}

#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
#[derive(Debug, Deserialize)]
struct DRSResponse {
    #[serde(rename = "Certificate")]
    certificate: Certificate,
}

#[derive(Serialize, Clone, Default)]
struct JoinPayload {}

#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
const BROKER_CLIENT_IDENT: &str = "38aa3b87-a06d-4817-b275-7a316988d93b";
#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
pub const BROKER_APP_ID: &str = "29d9ed98-a469-4536-ade2-f981bc1d605e";
#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
const DRS_APP_ID: &str = "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9";

/* RFC8628: 3.2. Device Authorization Response */
#[derive(Default, Clone, Deserialize)]
pub struct DeviceAuthorizationResponse {
    device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    // MS doesn't implement verification_uri_complete yet
    pub verification_uri_complete: Option<String>,
    pub expires_in: u32,
    pub interval: Option<u32>,
    pub message: Option<String>,
}

#[derive(Clone, Deserialize)]
pub struct IdToken {
    pub name: String,
    pub oid: String,
    pub preferred_username: Option<String>,
    pub puid: Option<String>,
    pub tenant_region_scope: Option<String>,
    pub tid: String,
}

fn decode_id_token<'de, D>(d: D) -> Result<IdToken, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(d)?;
    let mut siter = s.splitn(3, '.');
    if siter.next().is_none() {
        return Err(serde::de::Error::custom("Failed parsing id_token header"));
    }
    let payload_str = match siter.next() {
        Some(payload_str) => URL_SAFE_NO_PAD
            .decode(payload_str)
            .map_err(|e| serde::de::Error::custom(format!("Failed parsing id_token: {}", e)))
            .and_then(|bytes| {
                String::from_utf8(bytes).map_err(|e| {
                    serde::de::Error::custom(format!("Failed parsing id_token: {}", e))
                })
            })?,
        None => {
            return Err(serde::de::Error::custom("Failed parsing id_token payload"));
        }
    };
    let payload: IdToken = json_from_str(&payload_str).map_err(|e| {
        serde::de::Error::custom(format!("Failed parsing id_token from json: {}", e))
    })?;
    Ok(payload)
}

#[derive(Clone, Default)]
pub struct ClientInfo {
    pub uid: Option<Uuid>,
    pub utid: Option<Uuid>,
}

fn decode_client_info<'de, D>(d: D) -> Result<ClientInfo, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(d)?;
    let client_info: Value = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| serde::de::Error::custom(format!("Failed parsing client_info: {}", e)))
        .and_then(|bytes| {
            String::from_utf8(bytes)
                .map_err(|e| serde::de::Error::custom(format!("Failed parsing client_info: {}", e)))
        })
        .and_then(|client_info_str| {
            json_from_str(&client_info_str)
                .map_err(|e| serde::de::Error::custom(format!("Failed parsing client_info: {}", e)))
        })?;

    let uid_str = client_info["uid"].to_string();
    let uid = Uuid::parse_str(uid_str.trim_matches('"'))
        .map_err(|e| serde::de::Error::custom(format!("Failed parsing client_info: {}", e)))?;

    let utid_str = client_info["utid"].to_string();
    let utid = Uuid::parse_str(utid_str.trim_matches('"'))
        .map_err(|e| serde::de::Error::custom(format!("Failed parsing client_info: {}", e)))?;

    Ok(ClientInfo {
        uid: Some(uid),
        utid: Some(utid),
    })
}

#[derive(Clone, Deserialize)]
pub struct UserToken {
    pub token_type: String,
    pub scope: String,
    pub expires_in: u32,
    pub ext_expires_in: u32,
    pub access_token: String,
    pub refresh_token: String,
    #[serde(deserialize_with = "decode_id_token")]
    pub id_token: IdToken,
    #[serde(deserialize_with = "decode_client_info", default)]
    pub client_info: ClientInfo,
}

#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
#[derive(Serialize, Clone, Default)]
struct UsernamePasswordAuthenticationPayload {
    client_id: String,
    request_nonce: String,
    scope: String,
    win_ver: Option<String>,
    grant_type: String,
    username: String,
    password: String,
}

#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
impl UsernamePasswordAuthenticationPayload {
    fn new(username: &str, password: &str, request_nonce: &str) -> Self {
        let os_release = match OsRelease::new() {
            Ok(os_release) => Some(format!(
                "{} {}",
                os_release.pretty_name, os_release.version_id
            )),
            Err(_) => None,
        };
        UsernamePasswordAuthenticationPayload {
            client_id: BROKER_CLIENT_IDENT.to_string(),
            request_nonce: request_nonce.to_string(),
            scope: "openid aza ugs".to_string(),
            win_ver: os_release,
            grant_type: "password".to_string(),
            username: username.to_string(),
            password: password.to_string(),
        }
    }
}

#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
#[derive(Serialize, Clone, Default)]
struct RefreshTokenAuthenticationPayload {
    client_id: String,
    request_nonce: String,
    scope: String,
    win_ver: Option<String>,
    grant_type: String,
    refresh_token: String,
}

#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
impl RefreshTokenAuthenticationPayload {
    fn new(refresh_token: &str, request_nonce: &str) -> Self {
        let os_release = match OsRelease::new() {
            Ok(os_release) => Some(format!(
                "{} {}",
                os_release.pretty_name, os_release.version_id
            )),
            Err(_) => None,
        };
        RefreshTokenAuthenticationPayload {
            client_id: BROKER_CLIENT_IDENT.to_string(),
            request_nonce: request_nonce.to_string(),
            scope: "openid aza ugs".to_string(),
            win_ver: os_release,
            grant_type: "refresh_token".to_string(),
            refresh_token: refresh_token.to_string(),
        }
    }
}

#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
#[derive(Serialize, Clone, Default)]
struct ExchangePRTPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<i64>,
    client_id: String,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<String>,
    grant_type: String,
    refresh_token: String,
}

#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
impl ExchangePRTPayload {
    fn new(
        prt: &PrimaryRefreshToken,
        scope: &[&str],
        resource: Option<String>,
    ) -> Result<Self, MsalError> {
        let (iat, exp): (Option<i64>, Option<i64>) =
            match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(now) => match now.as_secs().try_into() {
                    Ok(iat) => (Some(iat), Some(iat + 300)),
                    Err(e) => {
                        return Err(MsalError::GeneralFailure(format!(
                            "Failed choosing iat and exp: {}",
                            e
                        )));
                    }
                },
                Err(e) => {
                    return Err(MsalError::GeneralFailure(format!(
                        "Failed choosing iat and exp: {}",
                        e
                    )))
                }
            };
        Ok(ExchangePRTPayload {
            iat,
            exp,
            client_id: BROKER_CLIENT_IDENT.to_string(),
            scope: format!("openid {}", scope.join(" ")),
            resource,
            grant_type: "refresh_token".to_string(),
            refresh_token: prt.refresh_token.clone(),
        })
    }
}

#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
#[derive(Debug, Deserialize)]
struct Nonce {
    #[serde(rename = "Nonce")]
    nonce: String,
}

#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
fn decode_jwe<'de, D>(d: D) -> Result<JweCompact, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(d)?;
    Ok(JweCompact::from_str(&s)
        .map_err(|e| serde::de::Error::custom(format!("Failed parsing jwe: {}", e)))?)
}

#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
#[derive(Clone, Deserialize)]
pub struct PrimaryRefreshToken {
    pub refresh_token: String,
    pub refresh_token_expires_in: u64,
    #[serde(rename = "session_key_jwe")]
    #[serde(deserialize_with = "decode_jwe")]
    session_key: JweCompact,
    #[serde(deserialize_with = "decode_id_token")]
    pub id_token: IdToken,
    /*#[serde(deserialize_with = "decode_jwe")]
    tgt_client_key: JweCompact,*/
}

#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
impl PrimaryRefreshToken {
    pub fn session_key(&self, id_key: &Rsa<Private>) -> Result<MsOapxbcSessionKey, MsalError> {
        let client_key =
            MsOapxbcSessionKey::complete_rsa_oaep_key_agreement(id_key.clone(), &self.session_key)
                .map_err(|e| MsalError::CryptoFail(format!("Unable to decipher jwe: {}", e)))?;

        Ok(client_key)
    }

    /*pub fn tgt_client_key(&self, id_key: &Rsa<Private>) -> Result<Vec<u8>, MsalError> {
        let rsa_oaep_decipher = JweRSAOAEPDecipher::try_from(id_key.clone())
            .map_err(|e| MsalError::CryptoFail(format!("Unable to create decipher: {}", e)))?;
        let tgt: Jwe = rsa_oaep_decipher
            .decipher(&self.tgt_client_key)
            .map_err(|e| MsalError::CryptoFail(format!("Unable to decipher jwe: {}", e)))?;

        Ok(tgt.payload().to_vec())
    }*/
}

struct ClientApplication {
    client: Client,
    client_id: String,
    authority: String,
}

impl ClientApplication {
    fn new(client_id: &str, authority: Option<&str>) -> Self {
        ClientApplication {
            client: reqwest::Client::new(),
            client_id: client_id.to_string(),
            authority: match authority {
                Some(authority) => authority.to_string(),
                None => "https://login.microsoftonline.com/common".to_string(),
            },
        }
    }

    async fn acquire_token_by_username_password(
        &self,
        username: &str,
        password: &str,
        scopes: Vec<&str>,
    ) -> Result<UserToken, MsalError> {
        let mut all_scopes = vec!["openid", "profile", "offline_access"];
        all_scopes.extend(scopes);
        let scopes_str = all_scopes.join(" ");

        let params = [
            ("client_id", self.client_id.as_str()),
            ("scope", &scopes_str),
            ("username", username),
            ("password", password),
            ("grant_type", "password"),
            ("client_info", "1"),
        ];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, url_encode(v)))
            .collect::<Vec<String>>()
            .join("&");

        let resp = self
            .client
            .post(format!("{}/oauth2/v2.0/token", self.authority))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .body(payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let token: UserToken = resp
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

    async fn acquire_token_by_refresh_token(
        &self,
        refresh_token: &str,
        scopes: Vec<&str>,
    ) -> Result<UserToken, MsalError> {
        let mut all_scopes = vec!["openid", "profile", "offline_access"];
        all_scopes.extend(scopes);
        let scopes_str = all_scopes.join(" ");

        let params = [
            ("client_id", self.client_id.as_str()),
            ("scope", &scopes_str),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_info", "1"),
        ];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, url_encode(v)))
            .collect::<Vec<String>>()
            .join("&");

        let resp = self
            .client
            .post(format!("{}/oauth2/v2.0/token", self.authority))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .body(payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let token: UserToken = resp
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

pub struct PublicClientApplication {
    app: ClientApplication,
}

impl PublicClientApplication {
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
    pub fn new(client_id: &str, authority: Option<&str>) -> Self {
        PublicClientApplication {
            app: ClientApplication::new(client_id, authority),
        }
    }

    fn client(&self) -> &Client {
        &self.app.client
    }

    fn client_id(&self) -> &str {
        &self.app.client_id
    }

    fn authority(&self) -> &str {
        &self.app.authority
    }

    /// Gets a token for a given resource via user credentials.
    ///
    /// # Arguments
    ///
    /// * `username` - Typically a UPN in the form of an email address.
    ///
    /// * `password` - The password.
    ///
    /// * `scopes` - Scopes requested to access a protected API (a resource).
    ///
    /// # Returns
    /// * Success: A UserToken containing an access_token.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn acquire_token_by_username_password(
        &self,
        username: &str,
        password: &str,
        scopes: Vec<&str>,
    ) -> Result<UserToken, MsalError> {
        self.app
            .acquire_token_by_username_password(username, password, scopes)
            .await
    }

    /// Acquire token(s) based on a refresh token (RT) obtained from elsewhere.
    ///
    /// # Arguments
    ///
    /// * `refresh_token` - The old refresh token, as a string.
    ///
    /// * `scopes` - The scopes associated with this old RT.
    ///
    /// # Returns
    ///
    /// * Success: A UserToken, which means migration was successful.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn acquire_token_by_refresh_token(
        &self,
        refresh_token: &str,
        scopes: Vec<&str>,
    ) -> Result<UserToken, MsalError> {
        self.app
            .acquire_token_by_refresh_token(refresh_token, scopes)
            .await
    }

    /// Initiate a Device Flow instance, which will be used in
    /// acquire_token_by_device_flow.
    ///
    /// # Arguments
    ///
    /// * `scopes` - Scopes requested to access a protected API (a resource).
    ///
    /// # Returns
    ///
    /// * Success: A DeviceAuthorizationResponse containing a user_code key,
    ///   among others
    /// * Failure: An MsalError, indicating the failure.
    pub async fn initiate_device_flow(
        &self,
        scopes: Vec<&str>,
    ) -> Result<DeviceAuthorizationResponse, MsalError> {
        let mut all_scopes = vec!["openid", "profile", "offline_access"];
        all_scopes.extend(scopes);
        let scopes_str = all_scopes.join(" ");

        let params = [("client_id", self.client_id()), ("scope", &scopes_str)];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, url_encode(v)))
            .collect::<Vec<String>>()
            .join("&");

        let resp = self
            .client()
            .post(format!("{}/oauth2/v2.0/devicecode", self.authority()))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .body(payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let json_resp: DeviceAuthorizationResponse = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            Ok(json_resp)
        } else {
            let json_resp: ErrorResponse = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            Err(MsalError::AcquireTokenFailed(json_resp))
        }
    }

    /// Obtain token by a device flow object, with customizable polling effect.
    ///
    /// # Arguments
    ///
    /// * `flow` - A DeviceAuthorizationResponse previously generated by
    /// initiate_device_flow.
    ///
    /// # Returns
    ///
    /// * Success: A UserToken containing an access_token.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn acquire_token_by_device_flow(
        &self,
        flow: DeviceAuthorizationResponse,
    ) -> Result<UserToken, MsalError> {
        let params = [
            ("client_id", self.client_id()),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", &flow.device_code),
        ];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, url_encode(v)))
            .collect::<Vec<String>>()
            .join("&");

        let resp = self
            .client()
            .post(format!("{}/oauth2/v2.0/token", self.authority()))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .body(payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let token: UserToken = resp
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

pub struct EnrollAttrs {
    device_display_name: String,
    device_type: String,
    join_type: u32,
    os_version: String,
    target_domain: String,
}

impl EnrollAttrs {
    pub fn new(
        target_domain: String,
        device_display_name: Option<String>,
        device_type: Option<String>,
        join_type: Option<u32>,
        os_version: Option<String>,
    ) -> Result<Self, MsalError> {
        let device_display_name_int = match device_display_name {
            Some(device_display_name) => device_display_name,
            None => match hostname::get()
                .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?
                .to_str()
            {
                Some(host) => String::from(host),
                None => {
                    return Err(MsalError::GeneralFailure(
                        "Failed to get machine hostname for enrollment".to_string(),
                    ))
                }
            },
        };
        let device_type_int = match device_type {
            Some(device_type) => device_type,
            None => "Linux".to_string(),
        };
        let join_type_int = match join_type {
            Some(join_type) => join_type,
            None => 0,
        };
        let os_version_int = match os_version {
            Some(os_version) => os_version,
            None => {
                let os_release =
                    OsRelease::new().map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?;
                format!("{} {}", os_release.pretty_name, os_release.version_id)
            }
        };
        Ok(EnrollAttrs {
            device_display_name: device_display_name_int,
            device_type: device_type_int,
            join_type: join_type_int,
            os_version: os_version_int,
            target_domain,
        })
    }
}

#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
pub struct BrokerClientApplication {
    app: ClientApplication,
}

#[cfg(feature = "broker")]
#[doc(cfg(feature = "broker"))]
impl BrokerClientApplication {
    /// Create an instance of an application.
    ///
    /// # Arguments
    ///
    /// * `authority` - A URL that identifies a token authority. It should
    ///   be of the format <https://login.microsoftonline.com/your_tenant> By
    ///   default, we will use <https://login.microsoftonline.com/common>.
    pub fn new(authority: Option<&str>) -> Self {
        BrokerClientApplication {
            app: ClientApplication::new(BROKER_APP_ID, authority),
        }
    }

    fn client(&self) -> &Client {
        &self.app.client
    }

    fn authority(&self) -> &str {
        &self.app.authority
    }

    /// Enroll the device in the directory.
    ///
    /// # Arguments
    ///
    /// * `username` - Typically a UPN in the form of an email address.
    ///
    /// * `password` - The password.
    ///
    /// * `domain` - The domain the device is to be enrolled in.
    ///
    /// * `machine_key` - The TPM MachineKey associated with this application.
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `loadable_id_key` - A LoadableIdentityKey which will be used to
    ///   create the CSR and transport key for enrolling the device.
    ///
    /// # Returns
    ///
    /// * Success: The `id_key` (which has been loaded with a signed
    ///   certificate), and a `device_id`.
    /// * Failure: An MsalError, indicating the failure.
    #[cfg(feature = "tpm")]
    pub async fn enroll_device(
        &self,
        username: &str,
        password: &str,
        attrs: EnrollAttrs,
        machine_key: &MachineKey,
        tpm: &mut BoxedDynTpm,
        loadable_id_key: &LoadableIdentityKey,
    ) -> Result<(LoadableIdentityKey, String), MsalError> {
        let token = self
            .acquire_token_for_device_enrollment(username, password)
            .await?;

        // Create the CSR
        let csr_der = match tpm.identity_key_certificate_request(
            machine_key,
            loadable_id_key,
            "7E980AD9-B86D-4306-9425-9AC066FB014A",
        ) {
            Ok(csr_der) => csr_der,
            Err(e) => return Err(MsalError::TPMFail(format!("Failed creating CSR: {:?}", e))),
        };

        // Load the transport key
        let id_key = match tpm.identity_key_load(machine_key, loadable_id_key) {
            Ok(id_key) => id_key,
            Err(e) => {
                return Err(MsalError::TPMFail(format!(
                    "Failed loading id key: {:?}",
                    e
                )))
            }
        };
        let transport_key_der = match tpm.identity_key_public_as_der(&id_key) {
            Ok(transport_key_pem) => transport_key_pem,
            Err(e) => {
                return Err(MsalError::TPMFail(format!(
                    "Failed getting transport key as der: {:?}",
                    e
                )))
            }
        };
        let transport_key_rsa = Rsa::public_key_from_der(&transport_key_der)
            .map_err(|e| MsalError::TPMFail(format!("{}", e)))?;

        let (cert, device_id) = self
            .enroll_device_internal(&token.access_token, attrs, &transport_key_rsa, &csr_der)
            .await?;

        let new_loadable_id_key = match tpm.identity_key_associate_certificate(
            machine_key,
            loadable_id_key,
            &cert
                .to_der()
                .map_err(|e| MsalError::TPMFail(format!("{}", e)))?,
        ) {
            Ok(loadable_id_key) => loadable_id_key,
            Err(e) => {
                return Err(MsalError::TPMFail(format!(
                    "Failed creating loadable identity key: {:?}",
                    e
                )))
            }
        };

        Ok((new_loadable_id_key, device_id.to_string()))
    }

    /// Enroll the device in the directory.
    ///
    /// # Arguments
    ///
    /// * `username` - Typically a UPN in the form of an email address.
    ///
    /// * `password` - The password.
    ///
    /// * `domain` - The domain the device is to be enrolled in.
    ///
    /// * `id_key` - An RSA private key which will be used to
    ///   create the CSR and transport key for enrolling the device.
    ///
    /// # Returns
    ///
    /// * Success: An x509 certificate signed during enrollment, and a
    ///   `device_id`.
    /// * Failure: An MsalError, indicating the failure.
    #[cfg(not(feature = "tpm"))]
    #[doc(cfg(not(feature = "tpm")))]
    pub async fn enroll_device(
        &self,
        username: &str,
        password: &str,
        attrs: EnrollAttrs,
        id_key: &Rsa<Private>,
    ) -> Result<(X509, String), MsalError> {
        let token = self
            .acquire_token_for_device_enrollment(username, password)
            .await?;

        let mut req_builder =
            X509ReqBuilder::new().map_err(|e| MsalError::TPMFail(format!("{}", e)))?;

        let mut x509_name =
            X509NameBuilder::new().map_err(|e| MsalError::TPMFail(format!("{}", e)))?;

        x509_name
            .append_entry_by_text("CN", "7E980AD9-B86D-4306-9425-9AC066FB014A")
            .map_err(|e| MsalError::TPMFail(format!("{}", e)))?;

        let x509_name = x509_name.build();
        req_builder
            .set_subject_name(&x509_name)
            .map_err(|e| MsalError::TPMFail(format!("{}", e)))?;

        let id_pkey =
            PKey::from_rsa(id_key.clone()).map_err(|e| MsalError::TPMFail(format!("{}", e)))?;
        req_builder
            .set_pubkey(&id_pkey)
            .map_err(|e| MsalError::TPMFail(format!("{}", e)))?;

        req_builder
            .sign(&id_pkey, MessageDigest::sha256())
            .map_err(|e| MsalError::TPMFail(format!("{}", e)))?;

        let csr_der = req_builder
            .build()
            .to_der()
            .map_err(|e| MsalError::TPMFail(format!("{}", e)))?;

        self.enroll_device_internal(&token.access_token, attrs, id_key, &csr_der)
            .await
    }

    async fn enroll_device_internal(
        &self,
        access_token: &str,
        attrs: EnrollAttrs,
        transport_key: &EnrollmentKey,
        csr_der: &Vec<u8>,
    ) -> Result<(X509, String), MsalError> {
        let enrollment_services =
            discover_enrollment_services(&self.client(), access_token, &attrs.target_domain)
                .await?;
        let (join_endpoint, service_version) = match enrollment_services.device_join_service {
            Some(device_join_service) => {
                let join_endpoint = match device_join_service.endpoint {
                    Some(join_endpoint) => join_endpoint,
                    None => format!("{}/EnrollmentServer/device/", DISCOVERY_URL).to_string(),
                };
                let service_version = match device_join_service.service_version {
                    Some(service_version) => service_version,
                    None => "2.0".to_string(),
                };
                (join_endpoint, service_version)
            }
            None => (
                format!("{}/EnrollmentServer/device/", DISCOVERY_URL).to_string(),
                "2.0".to_string(),
            ),
        };

        let url = Url::parse_with_params(&join_endpoint, &[("api-version", service_version)])
            .map_err(|e| MsalError::URLFormatFailed(format!("{}", e)))?;

        let transport_key_der = transport_key
            .public_key_to_der()
            .map_err(|e| MsalError::DeviceEnrollmentFail(format!("{}", e)))?;
        let jwk = json!({
            "kty": "RSA",
            "kid": Uuid::new_v4(),
            "e": URL_SAFE_NO_PAD.encode(transport_key.e().to_vec()),
            "n": URL_SAFE_NO_PAD.encode(transport_key_der)
        });
        let encoded_stk = URL_SAFE.encode(jwk.to_string());

        let payload = json!({
            "CertificateRequest": {
                "Type": "pkcs10",
                "Data": STANDARD.encode(csr_der)
            },
            "DeviceDisplayName": attrs.device_display_name,
            "DeviceType": attrs.device_type,
            "JoinType": attrs.join_type,
            "OSVersion": attrs.os_version,
            "TargetDomain": attrs.target_domain,
            "TransportKey": encoded_stk,
            "Attributes": {
                "ReuseDevice": "true",
                "ReturnClientSid": "true"
            }
        });
        if let Ok(pretty) = to_string_pretty(&payload) {
            debug!("POST {}: {}", url, pretty);
        }
        let resp = self
            .client()
            .post(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .header(header::CONTENT_TYPE, "application/json")
            .header(DRS_CLIENT_NAME_HEADER_FIELD, env!("CARGO_PKG_NAME"))
            .header(DRS_CLIENT_VERSION_HEADER_FIELD, env!("CARGO_PKG_VERSION"))
            .header(header::ACCEPT, "application/json, text/plain, */*")
            .json(&payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let res: DRSResponse = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            let cert = X509::from_pem(
                format!(
                    "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                    res.certificate.raw_body
                )
                .as_bytes(),
            )
            .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?;
            let subject_name = cert.subject_name();
            let device_id = match subject_name.entries().next() {
                Some(entry) => entry
                    .data()
                    .as_utf8()
                    .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?,
                None => {
                    return Err(MsalError::GeneralFailure(
                        "The device id was missing from the certificate response".to_string(),
                    ))
                }
            };
            Ok((cert, device_id.to_string()))
        } else {
            Err(MsalError::GeneralFailure(
                resp.text()
                    .await
                    .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?,
            ))
        }
    }

    /// Gets a token for a given resource via user credentials.
    ///
    /// # Arguments
    ///
    /// * `username` - Typically a UPN in the form of an email address.
    ///
    /// * `password` - The password.
    ///
    /// * `scopes` - Scopes requested to access a protected API (a resource).
    ///
    /// * `id_key` - The private key used during device enrollment.
    ///
    /// # Returns
    /// * Success: A UserToken containing an access_token.
    /// * Failure: An MsalError, indicating the failure.
    #[cfg(not(feature = "tpm"))]
    #[doc(cfg(not(feature = "tpm")))]
    pub async fn acquire_token_by_username_password(
        &self,
        username: &str,
        password: &str,
        scopes: Vec<&str>,
        id_key: &Rsa<Private>,
        cert: &X509,
    ) -> Result<UserToken, MsalError> {
        let prt = self
            .acquire_user_prt_by_username_password(username, password, id_key, cert)
            .await?;
        let session_key = prt.session_key(id_key)?;
        self.exchange_prt_for_access_token(&prt, scopes, None, &session_key)
            .await
    }

    /// Gets a token for a given resource via user credentials.
    ///
    /// # Arguments
    ///
    /// * `username` - Typically a UPN in the form of an email address.
    ///
    /// * `password` - The password.
    ///
    /// * `scopes` - Scopes requested to access a protected API (a resource).
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `id_key` - The identity key used during device enrollment.
    ///
    /// # Returns
    /// * Success: A UserToken containing an access_token.
    /// * Failure: An MsalError, indicating the failure.
    #[cfg(feature = "tpm")]
    #[doc(cfg(feature = "tpm"))]
    pub async fn acquire_token_by_username_password(
        &self,
        _username: &str,
        _password: &str,
        _scopes: Vec<&str>,
        _tpm: &mut BoxedDynTpm,
        _id_key: &IdentityKey,
    ) -> Result<UserToken, MsalError> {
        Err(MsalError::NotImplemented)
    }

    /// Acquire token(s) based on a refresh token (RT) obtained from elsewhere.
    ///
    /// # Arguments
    ///
    /// * `refresh_token` - The old refresh token, as a string.
    ///
    /// * `scopes` - The scopes associated with this old RT.
    ///
    /// * `id_key` - The private key used during device enrollment.
    ///
    /// # Returns
    /// * Success: A UserToken, which means migration was successful.
    /// * Failure: An MsalError, indicating the failure.
    #[cfg(not(feature = "tpm"))]
    #[doc(cfg(not(feature = "tpm")))]
    pub async fn acquire_token_by_refresh_token(
        &self,
        refresh_token: &str,
        scopes: Vec<&str>,
        id_key: &Rsa<Private>,
        cert: &X509,
    ) -> Result<UserToken, MsalError> {
        let prt = self
            .acquire_user_prt_by_refresh_token(refresh_token, id_key, cert)
            .await?;
        let session_key = prt.session_key(id_key)?;
        self.exchange_prt_for_access_token(&prt, scopes, None, &session_key)
            .await
    }

    /// Acquire token(s) based on a refresh token (RT) obtained from elsewhere.
    ///
    /// # Arguments
    ///
    /// * `refresh_token` - The old refresh token, as a string.
    ///
    /// * `scopes` - The scopes associated with this old RT.
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `id_key` - The identity key used during device enrollment.
    ///
    /// # Returns
    /// * Success: A UserToken, which means migration was successful.
    /// * Failure: An MsalError, indicating the failure.
    #[cfg(feature = "tpm")]
    #[doc(cfg(feature = "tpm"))]
    pub async fn acquire_token_by_refresh_token(
        &self,
        _refresh_token: &str,
        _scopes: Vec<&str>,
        _tpm: &mut BoxedDynTpm,
        _id_key: &IdentityKey,
    ) -> Result<UserToken, MsalError> {
        Err(MsalError::NotImplemented)
    }

    async fn acquire_token_for_device_enrollment(
        &self,
        username: &str,
        password: &str,
    ) -> Result<UserToken, MsalError> {
        let drs_scope = format!("{}/.default", DRS_APP_ID);
        self.app
            .acquire_token_by_username_password(username, password, vec![&drs_scope])
            .await
    }

    async fn request_nonce(&self) -> Result<String, MsalError> {
        let resp = self
            .client()
            .post(format!("{}/oauth2/token", self.authority()))
            .body("grant_type=srv_challenge")
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let json_resp: Nonce = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            Ok(json_resp.nonce)
        } else {
            let json_resp: ErrorResponse = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            Err(MsalError::AcquireTokenFailed(json_resp))
        }
    }

    async fn build_jwt_by_username_password(
        &self,
        username: &str,
        password: &str,
        cert: Option<&X509>,
    ) -> Result<Jws, MsalError> {
        let nonce = self.request_nonce().await?;

        let mut builder = JwsBuilder::from(
            serde_json::to_vec(&UsernamePasswordAuthenticationPayload::new(
                username, password, &nonce,
            ))
            .map_err(|e| {
                MsalError::InvalidJson(format!("Failed serializing UsernamePassword JWT: {}", e))
            })?,
        )
        .set_typ(Some("JWT"));

        if let Some(cert) = cert {
            builder = builder.set_x5c(Some(vec![cert
                .to_der()
                .map_err(|e| MsalError::CryptoFail(format!("{}", e)))?]));
        }

        Ok(builder.build())
    }

    /// Gets a Primary Refresh Token (PRT) via user credentials.
    ///
    /// # Arguments
    ///
    /// * `username` - Typically a UPN in the form of an email address.
    ///
    /// * `password` - The password.
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `id_key` - The identity key used during device enrollment.
    ///
    /// # Returns
    /// * Success: A PrimaryRefreshToken, containing a refresh_token and tgt.
    /// * Failure: An MsalError, indicating the failure.
    #[cfg(feature = "tpm")]
    pub async fn acquire_user_prt_by_username_password(
        &self,
        username: &str,
        password: &str,
        tpm: &mut BoxedDynTpm,
        id_key: &IdentityKey,
    ) -> Result<PrimaryRefreshToken, MsalError> {
        let jwt = self
            .build_jwt_by_username_password(username, password, None)
            .await?;
        let signed_jwt = self.sign_jwt(&jwt, tpm, id_key).await?;

        self.acquire_user_prt_jwt(&signed_jwt).await
    }

    /// Gets a Primary Refresh Token (PRT) via user credentials.
    ///
    /// # Arguments
    ///
    /// * `username` - Typically a UPN in the form of an email address.
    ///
    /// * `password` - The password.
    ///
    /// * `id_key` - The private key used during device enrollment.
    ///
    /// # Returns
    /// * Success: A PrimaryRefreshToken, containing a refresh_token and tgt.
    /// * Failure: An MsalError, indicating the failure.
    #[cfg(not(feature = "tpm"))]
    #[doc(cfg(not(feature = "tpm")))]
    pub async fn acquire_user_prt_by_username_password(
        &self,
        username: &str,
        password: &str,
        id_key: &Rsa<Private>,
        cert: &X509,
    ) -> Result<PrimaryRefreshToken, MsalError> {
        let jwt = self
            .build_jwt_by_username_password(username, password, Some(cert))
            .await?;
        let signed_jwt = self.sign_jwt(&jwt, id_key).await?;

        self.acquire_user_prt_jwt(&signed_jwt).await
    }

    async fn build_jwt_by_refresh_token(
        &self,
        refresh_token: &str,
        cert: Option<&X509>,
    ) -> Result<Jws, MsalError> {
        let nonce = self.request_nonce().await?;

        let mut builder = JwsBuilder::from(
            serde_json::to_vec(&RefreshTokenAuthenticationPayload::new(
                refresh_token,
                &nonce,
            ))
            .map_err(|e| {
                MsalError::InvalidJson(format!("Failed serializing RefreshToken JWT: {}", e))
            })?,
        )
        .set_typ(Some("JWT"));

        if let Some(cert) = cert {
            builder = builder.set_x5c(Some(vec![cert
                .to_der()
                .map_err(|e| MsalError::CryptoFail(format!("{}", e)))?]));
        }

        Ok(builder.build())
    }

    /// Gets a Primary Refresh Token (PRT) via a refresh token (RT) obtained
    /// previously.
    ///
    /// # Arguments
    ///
    /// * `refresh_token` - The old refresh token, as a string.
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `id_key` - The identity key used during device enrollment.
    ///
    /// # Returns
    /// * Success: A PrimaryRefreshToken, containing a refresh_token and tgt.
    /// * Failure: An MsalError, indicating the failure.
    #[cfg(feature = "tpm")]
    pub async fn acquire_user_prt_by_refresh_token(
        &self,
        refresh_token: &str,
        tpm: &mut BoxedDynTpm,
        id_key: &IdentityKey,
    ) -> Result<PrimaryRefreshToken, MsalError> {
        let jwt = self.build_jwt_by_refresh_token(refresh_token, None).await?;
        let signed_jwt = self.sign_jwt(&jwt, tpm, id_key).await?;

        self.acquire_user_prt_jwt(&signed_jwt).await
    }

    /// Gets a Primary Refresh Token (PRT) via a refresh token (RT) obtained
    /// previously.
    ///
    /// # Arguments
    ///
    /// * `refresh_token` - The old refresh token, as a string.
    ///
    /// * `id_key` - The private key used during device enrollment.
    ///
    /// # Returns
    /// * Success: A PrimaryRefreshToken, containing a refresh_token and tgt.
    /// * Failure: An MsalError, indicating the failure.
    #[cfg(not(feature = "tpm"))]
    #[doc(cfg(not(feature = "tpm")))]
    pub async fn acquire_user_prt_by_refresh_token(
        &self,
        refresh_token: &str,
        id_key: &Rsa<Private>,
        cert: &X509,
    ) -> Result<PrimaryRefreshToken, MsalError> {
        let jwt = self
            .build_jwt_by_refresh_token(refresh_token, Some(cert))
            .await?;
        let signed_jwt = self.sign_jwt(&jwt, id_key).await?;

        self.acquire_user_prt_jwt(&signed_jwt).await
    }

    #[cfg(feature = "tpm")]
    async fn sign_jwt(
        &self,
        jwt: &Jws,
        tpm: &mut BoxedDynTpm,
        id_key: &IdentityKey,
    ) -> Result<String, MsalError> {
        let mut jws_tpm_signer = match JwsTpmSigner::new(tpm, id_key) {
            Ok(jws_tpm_signer) => jws_tpm_signer,
            Err(e) => {
                return Err(MsalError::TPMFail(format!(
                    "Failed loading tpm signer: {}",
                    e
                )))
            }
        };

        let signed_jwt = match jws_tpm_signer.sign(jwt) {
            Ok(signed_jwt) => signed_jwt,
            Err(e) => return Err(MsalError::TPMFail(format!("Failed signing jwk: {}", e))),
        };

        Ok(format!("{}", signed_jwt))
    }

    #[cfg(not(feature = "tpm"))]
    async fn sign_jwt(&self, jwt: &Jws, id_key: &Rsa<Private>) -> Result<String, MsalError> {
        let jws_rs256_signer = match JwsRs256Signer::from_rs256_der(
            &id_key
                .private_key_to_der()
                .map_err(|e| MsalError::CryptoFail(format!("{}", e)))?,
        ) {
            Ok(jws_rs256_signer) => jws_rs256_signer,
            Err(e) => {
                return Err(MsalError::CryptoFail(format!(
                    "Failed loading rs256 signer: {}",
                    e
                )))
            }
        };

        let signed_jwt = match jws_rs256_signer.sign(jwt) {
            Ok(signed_jwt) => signed_jwt,
            Err(e) => return Err(MsalError::CryptoFail(format!("Failed signing jwk: {}", e))),
        };

        Ok(format!("{}", signed_jwt))
    }

    async fn acquire_user_prt_jwt(
        &self,
        signed_jwt: &str,
    ) -> Result<PrimaryRefreshToken, MsalError> {
        // [MS-OAPXBC] 3.2.5.1.2 POST (Request for Primary Refresh Token)
        let params = [
            ("windows_api_version", "2.0"),
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("request", &signed_jwt),
            ("client_info", "1"),
            ("tgt", "true"),
        ];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<String>>()
            .join("&");

        let resp = self
            .client()
            .post(format!("{}/oauth2/token", self.authority()))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let json_resp: PrimaryRefreshToken = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            Ok(json_resp)
        } else {
            let json_resp: ErrorResponse = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            Err(MsalError::AcquireTokenFailed(json_resp))
        }
    }

    async fn sign_exchange_jwt(
        &self,
        jwt: &Jws,
        session_key: &MsOapxbcSessionKey,
    ) -> Result<String, MsalError> {
        let signed_jwt = match session_key.sign(jwt) {
            Ok(signed_jwt) => signed_jwt,
            Err(e) => return Err(MsalError::CryptoFail(format!("Failed signing jwk: {}", e))),
        };

        Ok(format!("{}", signed_jwt))
    }

    /// Given the primary refresh token, this method requests an access token.
    ///
    /// # Arguments
    ///
    /// * `prt` -  A primary refresh token that was previously received from
    ///   the server.
    ///
    /// * `scope` - The scope that the client requests for the access token.
    ///
    /// * `resource` - The resource for which the access token is requested.
    ///
    /// * `session_key` - The session key deciphered from the PRT
    ///   session_key_jwe property. See `prt.session_key(id_key)`.
    ///
    /// # Returns
    /// * Success: A UserToken containing an access_token.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn exchange_prt_for_access_token(
        &self,
        prt: &PrimaryRefreshToken,
        scope: Vec<&str>,
        resource: Option<String>,
        session_key: &MsOapxbcSessionKey,
    ) -> Result<UserToken, MsalError> {
        let jwt = JwsBuilder::from(
            serde_json::to_vec(&ExchangePRTPayload::new(prt, &scope, resource)).map_err(|e| {
                MsalError::InvalidJson(format!("Failed serializing ExchangePRT JWT: {}", e))
            })?,
        )
        .set_typ(Some("JWT"))
        .build();
        let signed_jwt = self.sign_exchange_jwt(&jwt, session_key).await?;

        let params = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("request", &signed_jwt),
        ];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<String>>()
            .join("&");

        let resp = self
            .client()
            .post(format!("{}/oauth2/token", self.authority()))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let token: UserToken = resp
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
