use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use reqwest::{header, Client};
use serde::{Deserialize, Deserializer};
use serde_json::{from_str as json_from_str, Value};
use tracing::error;
use urlencoding::encode as url_encode;
use uuid::Uuid;

pub const INVALID_CRED: u32 = 0xC3CE;
pub const REQUIRES_MFA: u32 = 0xC39C;
pub const INVALID_USER: u32 = 0xC372;
pub const NO_CONSENT: u32 = 0xFDE9;
pub const NO_GROUP_CONSENT: u32 = 0xFDEA;
pub const NO_SECRET: u32 = 0x6AD09A;
pub const AUTH_PENDING: u32 = 0x11180;

#[derive(Debug, Clone, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: String,
    pub error_codes: Vec<u32>,
}

#[derive(Debug)]
pub enum MsalError {
    /// MSAL failed to parse a json input
    InvalidJson,
    /// MSAL failed when acquiring a token
    AcquireTokenFailed(ErrorResponse),
    /// Failure encountered in the reqwest module
    RequestFailed,
}

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
    pub preferred_username: String,
    pub puid: String,
    pub tenant_region_scope: String,
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
            .map_err(|e| serde::de::Error::custom(format!("Failed parsing client_info: {:?}", e)))
            .and_then(|bytes| {
                String::from_utf8(bytes).map_err(|e| {
                    serde::de::Error::custom(format!("Failed parsing client_info: {:?}", e))
                })
            })?,
        None => {
            return Err(serde::de::Error::custom("Failed parsing id_token payload"));
        }
    };
    let payload: IdToken =
        json_from_str(&payload_str).map_err(|e| serde::de::Error::custom(format!("{:?}", e)))?;
    Ok(payload)
}

#[derive(Clone)]
pub struct ClientInfo {
    pub uid: Uuid,
    pub utid: Uuid,
}

fn decode_client_info<'de, D>(d: D) -> Result<ClientInfo, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(d)?;
    let client_info: Value = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| serde::de::Error::custom(format!("Failed parsing client_info: {:?}", e)))
        .and_then(|bytes| {
            String::from_utf8(bytes).map_err(|e| {
                serde::de::Error::custom(format!("Failed parsing client_info: {:?}", e))
            })
        })
        .and_then(|client_info_str| {
            json_from_str(&client_info_str).map_err(|e| {
                serde::de::Error::custom(format!("Failed parsing client_info: {:?}", e))
            })
        })?;

    let uid_str = client_info["uid"].to_string();
    let uid = Uuid::parse_str(uid_str.trim_matches('"'))
        .map_err(|e| serde::de::Error::custom(format!("Failed parsing client_info: {:?}", e)))?;

    let utid_str = client_info["utid"].to_string();
    let utid = Uuid::parse_str(utid_str.trim_matches('"'))
        .map_err(|e| serde::de::Error::custom(format!("Failed parsing client_info: {:?}", e)))?;

    Ok(ClientInfo { uid, utid })
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
    #[serde(deserialize_with = "decode_client_info")]
    pub client_info: ClientInfo,
}

pub struct PublicClientApplication {
    client: Client,
    client_id: String,
    tenant_id: String,
    authority_host: String,
}

impl PublicClientApplication {
    pub fn new(client_id: &str, tenant_id: &str, authority_host: &str) -> Self {
        PublicClientApplication {
            client: reqwest::Client::new(),
            client_id: client_id.to_string(),
            tenant_id: tenant_id.to_string(),
            authority_host: authority_host.to_string(),
        }
    }

    pub async fn acquire_token_by_username_password(
        &mut self,
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
            .post(format!(
                "https://{}/{}/oauth2/v2.0/token",
                self.authority_host, self.tenant_id
            ))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .body(payload)
            .send()
            .await
            .map_err(|e| {
                error!("{:?}", e);
                MsalError::RequestFailed
            })?;
        if resp.status().is_success() {
            let token: UserToken = resp.json().await.map_err(|e| {
                error!("{:?}", e);
                MsalError::InvalidJson
            })?;

            Ok(token)
        } else {
            let json_resp: ErrorResponse = resp.json().await.map_err(|e| {
                error!("{:?}", e);
                MsalError::InvalidJson
            })?;
            Err(MsalError::AcquireTokenFailed(json_resp))
        }
    }

    pub async fn initiate_device_flow(
        &self,
        scopes: Vec<&str>,
    ) -> Result<DeviceAuthorizationResponse, MsalError> {
        let mut all_scopes = vec!["openid", "profile", "offline_access"];
        all_scopes.extend(scopes);
        let scopes_str = all_scopes.join(" ");

        let params = [
            ("client_id", self.client_id.as_str()),
            ("scope", &scopes_str),
        ];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, url_encode(v)))
            .collect::<Vec<String>>()
            .join("&");

        let resp = self
            .client
            .post(format!(
                "https://{}/{}/oauth2/v2.0/devicecode",
                self.authority_host, self.tenant_id
            ))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .body(payload)
            .send()
            .await
            .map_err(|e| {
                error!("{:?}", e);
                MsalError::RequestFailed
            })?;
        if resp.status().is_success() {
            let json_resp: DeviceAuthorizationResponse = resp.json().await.map_err(|e| {
                error!("{:?}", e);
                MsalError::InvalidJson
            })?;
            Ok(json_resp)
        } else {
            let json_resp: ErrorResponse = resp.json().await.map_err(|e| {
                error!("{:?}", e);
                MsalError::InvalidJson
            })?;
            Err(MsalError::AcquireTokenFailed(json_resp))
        }
    }

    pub async fn acquire_token_by_device_flow(
        &mut self,
        flow: DeviceAuthorizationResponse,
    ) -> Result<UserToken, MsalError> {
        let params = [
            ("client_id", self.client_id.as_str()),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", &flow.device_code),
        ];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, url_encode(v)))
            .collect::<Vec<String>>()
            .join("&");

        let resp = self
            .client
            .post(format!(
                "https://{}/{}/oauth2/v2.0/token",
                self.authority_host, self.tenant_id
            ))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .body(payload)
            .send()
            .await
            .map_err(|e| {
                error!("{:?}", e);
                MsalError::RequestFailed
            })?;
        if resp.status().is_success() {
            let token: UserToken = resp.json().await.map_err(|e| {
                error!("{:?}", e);
                MsalError::InvalidJson
            })?;

            Ok(token)
        } else {
            let json_resp: ErrorResponse = resp.json().await.map_err(|e| {
                error!("{:?}", e);
                MsalError::InvalidJson
            })?;
            Err(MsalError::AcquireTokenFailed(json_resp))
        }
    }

    pub async fn acquire_token_silent(
        &mut self,
        scopes: Vec<&str>,
        refresh_token: &str,
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
            .post(format!(
                "https://{}/{}/oauth2/v2.0/token",
                self.authority_host, self.tenant_id
            ))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .body(payload)
            .send()
            .await
            .map_err(|e| {
                error!("{:?}", e);
                MsalError::RequestFailed
            })?;
        if resp.status().is_success() {
            let token: UserToken = resp.json().await.map_err(|e| {
                error!("{:?}", e);
                MsalError::InvalidJson
            })?;

            Ok(token)
        } else {
            let json_resp: ErrorResponse = resp.json().await.map_err(|e| {
                error!("{:?}", e);
                MsalError::InvalidJson
            })?;
            Err(MsalError::AcquireTokenFailed(json_resp))
        }
    }
}
