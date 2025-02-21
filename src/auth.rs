/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2024

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

use crate::aadsts_err_gen::AADSTSError;
use crate::error::{ErrorResponse, MsalError, AUTH_PENDING};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use percent_encoding::percent_decode_str;
use reqwest::redirect::Policy;
#[cfg(feature = "proxyable")]
use reqwest::Proxy;
use reqwest::{header, Client, Response, Url};
use scraper::{Html, Selector};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{from_str as json_from_str, json, Value};
use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;
use tracing::{error, info};
use urlencoding::encode as url_encode;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "interactive")]
use browser_window::{application::*, browser::*};
#[cfg(feature = "interactive")]
use std::sync::mpsc::channel;

#[cfg(feature = "broker")]
use compact_jwt::compact::JweCompact;
#[cfg(feature = "broker")]
use compact_jwt::crypto::JwsTpmSigner;
#[cfg(feature = "broker")]
use compact_jwt::crypto::MsOapxbcSessionKey;
#[cfg(feature = "broker")]
use compact_jwt::jwe::Jwe;
#[cfg(feature = "broker")]
use compact_jwt::jws::JwsBuilder;
#[cfg(feature = "broker")]
use compact_jwt::traits::JwsMutSigner;
#[cfg(feature = "broker")]
use compact_jwt::traits::JwsSignable;
#[cfg(feature = "broker")]
use compact_jwt::Jws;
#[cfg(feature = "broker")]
use kanidm_hsm_crypto::{
    BoxedDynTpm, IdentityKey, KeyAlgorithm, LoadableIdentityKey, MachineKey, PinValue, SealedData,
    Tpm,
};
#[cfg(feature = "broker")]
use kanidm_hsm_crypto::{LoadableMsOapxbcRsaKey, MsOapxbcRsaKey};
#[cfg(feature = "broker")]
use openssl::hash::{hash, MessageDigest};
#[cfg(feature = "broker")]
use openssl::pkey::Public;
#[cfg(feature = "broker")]
use openssl::rsa::Rsa;
#[cfg(feature = "broker")]
use openssl::x509::X509;
#[cfg(feature = "broker")]
use os_release::OsRelease;
#[cfg(feature = "broker")]
use regex::Regex;
#[cfg(feature = "broker")]
use serde_json::{from_slice as json_from_slice, to_vec as json_to_vec};
#[cfg(feature = "broker")]
use std::convert::TryInto;
#[cfg(feature = "broker")]
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(feature = "broker")]
use tracing::debug;

#[cfg(feature = "broker")]
use crate::discovery::Services;
#[cfg(feature = "broker")]
use crate::discovery::{BcryptRsaKeyBlob, EnrollAttrs};
#[cfg(feature = "broker")]
use crate::krb5::FileCredentialCache;
#[cfg(feature = "broker")]
use crate::krb5::IntegerAsn1;
#[cfg(feature = "broker")]
use base64::engine::general_purpose::STANDARD;
#[cfg(feature = "broker")]
use compact_jwt::JwtError;
#[cfg(feature = "broker")]
use himmelblau_kerberos_crypto::{AesCipher, AesSizes, KerberosCipher};
#[cfg(feature = "broker")]
use picky_krb::messages::AsRep;
#[cfg(feature = "broker")]
use serde_json::to_string_pretty;
#[cfg(feature = "broker")]
use zeroize::Zeroizing;

#[cfg(feature = "broker")]
const BROKER_CLIENT_IDENT: &str = "38aa3b87-a06d-4817-b275-7a316988d93b";
#[cfg(feature = "broker")]
pub const BROKER_APP_ID: &str = "29d9ed98-a469-4536-ade2-f981bc1d605e";
#[cfg(feature = "broker")]
pub const LINUX_BROKER_APP_ID: &str = "b743a22d-6705-4147-8670-d92fa515ee2b";
#[cfg(feature = "broker")]
const DRS_APP_ID: &str = "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9";
#[cfg(feature = "broker")]
const AZURE_PORTAL_APP_ID: &str = "c44b4083-3bb0-49c1-b47d-974e53cbdf3c";
const HIMMELBLAU_REDIRECT_URI: &str = "himmelblau://Himmelblau.EntraId.BrokerPlugin";

/* FIDO Authentication requires specifying a user agent which
 * MS endorses as appropriate for FIDO */
#[cfg(feature = "broker")]
const FIDO_USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0";

/* RFC8628: 3.2. Device Authorization Response */
#[derive(Default, Clone, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    // MS doesn't implement verification_uri_complete yet
    pub verification_uri_complete: Option<String>,
    pub expires_in: u32,
    pub interval: Option<u32>,
    pub message: Option<String>,
}

#[derive(Deserialize)]
struct ArrUserProofs {
    #[serde(rename = "authMethodId")]
    auth_method_id: String,
    #[serde(rename = "isDefault")]
    is_default: bool,
    display: String,
}

#[derive(Deserialize)]
struct AuthConfig {
    #[serde(rename = "sessionId")]
    session_id: String,
    #[serde(rename = "sFT")]
    sft: Option<String>,
    #[serde(rename = "sCtx")]
    sctx: Option<String>,
    #[serde(rename = "urlPost")]
    url_post: Option<String>,
    canary: String,
    #[serde(rename = "iAllowedIdentities")]
    allowed_identities: Option<u32>,
    #[serde(rename = "strServiceExceptionMessage")]
    service_exception_msg: Option<String>,
    pgid: Option<String>,
    #[serde(rename = "iRemainingDaysToSkipMfaRegistration")]
    remaining_days_to_skip_mfa_reg: Option<u32>,
    #[serde(rename = "arrUserProofs")]
    arr_user_proofs: Option<Vec<ArrUserProofs>>,
    #[serde(rename = "arrFidoAllowList")]
    fido_allow_list: Option<Vec<String>>,
    #[serde(rename = "urlEndAuth")]
    url_end_auth: Option<String>,
    #[serde(rename = "urlBeginAuth")]
    url_begin_auth: Option<String>,
    #[serde(rename = "urlFidoLogin")]
    url_fido_login: Option<String>,
    #[serde(rename = "urlResume")]
    url_resume: Option<String>,
    #[serde(rename = "iMaxPollAttempts")]
    max_poll_attempts: Option<u32>,
    #[serde(rename = "iPollingInterval")]
    polling_interval: Option<u32>,
    #[serde(rename = "sErrorCode")]
    error_code: Option<String>,
    #[serde(rename = "sErrTxt")]
    err_txt: Option<String>,
    #[serde(rename = "sFidoChallenge")]
    fido_challenge: Option<String>,
    #[serde(rename = "sCrossDomainCanary")]
    cross_domain_canary: Option<String>,
    #[serde(rename = "urlGetOneTimeCode")]
    url_get_one_time_code: Option<String>,
    #[serde(rename = "urlGetCredentialType")]
    url_get_credential_type: Option<String>,
    #[serde(rename = "urlSessionState")]
    url_session_state: Option<String>,
    #[cfg(feature = "changepassword")]
    #[serde(rename = "urlAsyncSsprBegin")]
    url_async_sspr_begin: Option<String>,
    #[cfg(feature = "changepassword")]
    #[serde(rename = "urlAsyncSsprPoll")]
    url_async_sspr_poll: Option<String>,
}

#[derive(Deserialize, Serialize, Default)]
pub struct MFAAuthContinue {
    pub mfa_method: String,
    pub msg: String,
    pub entropy: Option<u8>,
    pub max_poll_attempts: Option<u32>,
    pub polling_interval: Option<u32>,
    pub session_id: String,
    pub flow_token: String,
    pub ctx: String,
    pub canary: String,
    pub url_end_auth: Option<String>,
    pub url_post: String,
    pub url_session_state: Option<String>,
    pub resource: Option<String>,
    pub dag: Option<DeviceAuthorizationResponse>,
    pub fido_challenge: Option<String>,
    pub fido_allow_list: Option<Vec<String>>,
    pub cross_domain_canary: Option<String>,
}

impl From<DeviceAuthorizationResponse> for MFAAuthContinue {
    fn from(item: DeviceAuthorizationResponse) -> Self {
        let msg = match &item.message {
            Some(msg) => msg.to_string(),
            None => format!(
                "Using a browser on another device, visit:\n{}\n \
                    And enter the code:\n{}",
                item.verification_uri, item.user_code
            ),
        };
        // Interval is in seconds, but polling_interval expects milliseconds
        let polling_interval = item.interval.unwrap_or(5);
        // Convert `expires_in` (a lifetime in seconds) to max_poll_attempts
        let max_poll_attempts = item.expires_in / polling_interval;
        MFAAuthContinue {
            msg,
            max_poll_attempts: Some(max_poll_attempts),
            polling_interval: Some(polling_interval * 1000),
            dag: Some(item),
            ..Default::default()
        }
    }
}

#[derive(Deserialize)]
struct AuthResponse {
    #[serde(rename = "Success")]
    success: bool,
    #[serde(rename = "Retry")]
    retry: Option<bool>,
    #[serde(rename = "Message")]
    message: Option<String>,
    #[serde(rename = "Ctx")]
    ctx: String,
    #[serde(rename = "FlowToken")]
    flow_token: String,
    #[serde(rename = "Entropy")]
    entropy: u8,
}

#[derive(Deserialize)]
struct DeviceCodeStatus {
    #[serde(rename = "AuthorizationState")]
    authorization_state: u8,
}

#[derive(Deserialize)]
struct RemoteNgcParams {
    #[serde(rename = "SessionIdentifier")]
    session_identifier: String,
    #[serde(rename = "Entropy")]
    entropy: u8,
}

#[derive(Deserialize)]
struct OTCError {
    message: String,
}

#[derive(Deserialize)]
struct OneTimeCode {
    #[serde(rename = "RemoteNgcParams")]
    remote_ngc_params: Option<RemoteNgcParams>,
    error: Option<OTCError>,
}

#[derive(Deserialize)]
struct Credentials {
    #[serde(rename = "FederationRedirectUrl")]
    federation_redirect_url: Option<String>,
    #[serde(rename = "HasPassword")]
    has_password: bool,
    #[serde(rename = "RemoteNgcParams")]
    remote_ngc_params: Option<RemoteNgcParams>,
}

#[derive(Deserialize)]
struct CredType {
    #[serde(rename = "Credentials")]
    credentials: Credentials,
    #[serde(rename = "ThrottleStatus")]
    throttle_status: u8,
    #[serde(rename = "IfExistsResult")]
    if_exists_result: u8,
}

#[derive(Default, Clone, Deserialize, Serialize)]
pub struct IdToken {
    pub name: String,
    pub oid: String,
    pub preferred_username: Option<String>,
    pub puid: Option<String>,
    pub tenant_region_scope: Option<String>,
    pub tid: String,
}

fn decode_string_or_struct<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: Deserialize<'de> + FromStr<Err = MsalError>,
    D: Deserializer<'de>,
{
    struct StringOrStruct<T>(PhantomData<fn() -> T>);

    impl<'de, T> Visitor<'de> for StringOrStruct<T>
    where
        T: Deserialize<'de> + FromStr<Err = MsalError>,
    {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string or map")
        }

        fn visit_str<E>(self, value: &str) -> Result<T, E>
        where
            E: de::Error,
        {
            FromStr::from_str(value)
                .map_err(|e| serde::de::Error::custom(format!("Failed to parse string: {:?}", e)))
        }

        fn visit_map<M>(self, map: M) -> Result<T, M::Error>
        where
            M: MapAccess<'de>,
        {
            Deserialize::deserialize(de::value::MapAccessDeserializer::new(map))
        }
    }

    deserializer.deserialize_any(StringOrStruct(PhantomData))
}

impl FromStr for IdToken {
    type Err = MsalError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut siter = s.splitn(3, '.');
        if siter.next().is_none() {
            return Err(MsalError::InvalidParse(
                "Failed parsing id_token header".to_string(),
            ));
        }
        let payload_str = match siter.next() {
            Some(payload_str) => URL_SAFE_NO_PAD
                .decode(payload_str)
                .map_err(|e| MsalError::InvalidParse(format!("Failed parsing id_token: {}", e)))
                .and_then(|bytes| {
                    String::from_utf8(bytes).map_err(|e| {
                        MsalError::InvalidParse(format!("Failed parsing id_token: {}", e))
                    })
                })?,
            None => {
                return Err(MsalError::InvalidParse(
                    "Failed parsing id_token payload".to_string(),
                ));
            }
        };
        let payload: IdToken = json_from_str(&payload_str).map_err(|e| {
            MsalError::InvalidParse(format!("Failed parsing id_token from json: {}", e))
        })?;
        Ok(payload)
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct ClientInfo {
    pub uid: Option<Uuid>,
    pub utid: Option<Uuid>,
}

impl FromStr for ClientInfo {
    type Err = MsalError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let client_info: Value = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| MsalError::InvalidParse(format!("Failed parsing client_info: {}", e)))
            .and_then(|bytes| {
                String::from_utf8(bytes).map_err(|e| {
                    MsalError::InvalidParse(format!("Failed parsing client_info: {}", e))
                })
            })
            .and_then(|client_info_str| {
                json_from_str(&client_info_str).map_err(|e| {
                    MsalError::InvalidParse(format!("Failed parsing client_info: {}", e))
                })
            })?;

        let uid_str = client_info["uid"].to_string();
        let uid = Uuid::parse_str(uid_str.trim_matches('"'))
            .map_err(|e| MsalError::InvalidParse(format!("Failed parsing client_info: {}", e)))?;

        let utid_str = client_info["utid"].to_string();
        let utid = Uuid::parse_str(utid_str.trim_matches('"'))
            .map_err(|e| MsalError::InvalidParse(format!("Failed parsing client_info: {}", e)))?;

        Ok(ClientInfo {
            uid: Some(uid),
            utid: Some(utid),
        })
    }
}

fn decode_number_from_string<'de, D>(d: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let v: Value = Deserialize::deserialize(d)?;
    match v {
        Value::Number(n) => Ok(n
            .as_u64()
            .ok_or(serde::de::Error::custom("Expected number or string"))?
            as u32),
        Value::String(s) => s
            .parse::<u32>()
            .map_err(|e| serde::de::Error::custom(format!("{}", e))),
        _ => Err(serde::de::Error::custom("Expected number or string")),
    }
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AccessTokenPayload {
    amr: Vec<String>,
    tid: String,
    upn: String,
}

#[derive(Clone, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct UserToken {
    pub token_type: String,
    pub scope: Option<String>,
    #[serde(deserialize_with = "decode_number_from_string")]
    pub expires_in: u32,
    #[serde(deserialize_with = "decode_number_from_string")]
    pub ext_expires_in: u32,
    pub access_token: Option<String>,
    pub refresh_token: String,
    #[serde(deserialize_with = "decode_string_or_struct", default)]
    #[zeroize(skip)]
    pub id_token: IdToken,
    #[serde(deserialize_with = "decode_string_or_struct", default)]
    #[zeroize(skip)]
    pub client_info: ClientInfo,
    #[cfg(feature = "broker")]
    #[zeroize(skip)]
    pub prt: Option<SealedData>,
}

impl UserToken {
    /// Fetch the tenant id from the user token
    ///
    /// # Returns
    ///
    /// * Success: The user's tenant id
    /// * Failure: An MsalError, indicating the failure.
    pub fn tenant_id(&self) -> Result<String, MsalError> {
        if !self.id_token.tid.is_empty() {
            Ok(self.id_token.tid.clone())
        } else if let Some(utid) = self.client_info.utid {
            Ok(utid.to_string())
        } else if let Some(access_token) = &self.access_token {
            let mut siter = access_token.splitn(3, '.');
            siter.next(); // Ignore the header
            let payload: AccessTokenPayload = json_from_str(
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
        } else {
            Err(MsalError::GeneralFailure(
                "No tid available for UserToken".to_string(),
            ))
        }
    }

    /// Fetch the UUID from the user token
    ///
    /// # Returns
    ///
    /// * Success: The user Azure UUID
    /// * Failure: An MsalError, indicating the failure.
    pub fn uuid(&self) -> Result<Uuid, MsalError> {
        Uuid::parse_str(&self.id_token.oid).map_err(|e| MsalError::InvalidParse(format!("{}", e)))
    }

    /// Fetch the spn from the user token
    ///
    /// # Returns
    ///
    /// * Success: The user Azure spn
    /// * Failure: An MsalError, indicating the failure.
    pub fn spn(&self) -> Result<String, MsalError> {
        match &self.id_token.preferred_username {
            Some(spn) => Ok(spn.to_string()),
            // If all else fails, extract the upn from the access_token
            None => match &self.access_token {
                Some(access_token) => {
                    let mut siter = access_token.splitn(3, '.');
                    siter.next(); // Ignore the header
                    let payload: AccessTokenPayload = json_from_str(
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
                    Ok(payload.upn.clone())
                }
                None => Err(MsalError::GeneralFailure(
                    "No spn available for UserToken".to_string(),
                )),
            },
        }
    }

    /// Check if the access token amr contains an MFA authorization
    ///
    /// # Returns
    ///
    /// * Success: Whether or not the token has MFA authorization.
    /// * Failure: An MsalError, indicating the failure.
    pub fn amr_mfa(&self) -> Result<bool, MsalError> {
        match &self.access_token {
            Some(access_token) => {
                let mut siter = access_token.splitn(3, '.');
                siter.next(); // Ignore the header
                let payload: AccessTokenPayload = json_from_str(
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
                Ok(payload.amr.iter().any(|s| s == "ngcmfa" || s == "mfa"))
            }
            None => Err(MsalError::GeneralFailure(
                "No access token available for UserToken".to_string(),
            )),
        }
    }

    /// Check if the access token amr contains an NGC MFA authorization
    ///
    /// Sometimes it isn't sufficient simply to know if MFA has been
    /// performed. Key enrollment (such as a Hello Key), for example,
    /// explicitly requires an NGC MFA authorization.
    ///
    /// # Returns
    ///
    /// * Success: Whether or not the token has an NGC MFA authorization.
    /// * Failure: An MsalError, indicating the failure.
    pub fn amr_ngcmfa(&self) -> Result<bool, MsalError> {
        match &self.access_token {
            Some(access_token) => {
                let mut siter = access_token.splitn(3, '.');
                siter.next(); // Ignore the header
                let payload: AccessTokenPayload = json_from_str(
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
                Ok(payload.amr.iter().any(|s| s == "ngcmfa"))
            }
            None => Err(MsalError::GeneralFailure(
                "No access token available for UserToken".to_string(),
            )),
        }
    }
}

#[cfg(feature = "broker")]
#[derive(Serialize, Clone, Default, Zeroize, ZeroizeOnDrop)]
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
#[derive(Serialize, Clone, Default, Zeroize, ZeroizeOnDrop)]
struct RefreshTokenAuthenticationPayload {
    client_id: String,
    request_nonce: String,
    scope: String,
    win_ver: Option<String>,
    grant_type: String,
    refresh_token: String,
}

#[cfg(feature = "broker")]
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
            client_id: BROKER_APP_ID.to_string(),
            request_nonce: request_nonce.to_string(),
            scope: "openid aza ugs".to_string(),
            win_ver: os_release,
            grant_type: "refresh_token".to_string(),
            refresh_token: refresh_token.to_string(),
        }
    }
}

#[cfg(feature = "broker")]
#[derive(Serialize, Clone, Default, Zeroize, ZeroizeOnDrop)]
struct HelloForBusinessAssertion {
    iss: String,
    aud: String,
    iat: u64,
    exp: u64,
    scope: String,
    request_nonce: String,
}

#[cfg(feature = "broker")]
impl HelloForBusinessAssertion {
    fn new(username: &str, request_nonce: &str) -> Result<Self, MsalError> {
        let iat: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| MsalError::GeneralFailure(format!("Failed choosing iat: {}", e)))?
            .as_secs();
        Ok(HelloForBusinessAssertion {
            iss: username.to_string(),
            aud: "common".to_string(),
            iat: iat - 300,
            exp: iat + 300,
            scope: "openid aza ugs".to_string(),
            request_nonce: request_nonce.to_string(),
        })
    }
}

#[cfg(feature = "broker")]
#[derive(Serialize, Clone, Default, Zeroize, ZeroizeOnDrop)]
struct HelloForBusinessPayload {
    client_id: String,
    request_nonce: String,
    scope: String,
    win_ver: Option<String>,
    grant_type: String,
    username: String,
    assertion: String,
}

#[cfg(feature = "broker")]
impl HelloForBusinessPayload {
    fn new(username: &str, assertion: &str, request_nonce: &str) -> Self {
        let os_release = match OsRelease::new() {
            Ok(os_release) => Some(format!(
                "{} {}",
                os_release.pretty_name, os_release.version_id
            )),
            Err(_) => None,
        };
        HelloForBusinessPayload {
            client_id: BROKER_APP_ID.to_string(),
            request_nonce: request_nonce.to_string(),
            scope: "openid aza ugs".to_string(),
            win_ver: os_release,
            grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
            username: username.to_string(),
            assertion: assertion.to_string(),
        }
    }
}

#[cfg(feature = "broker")]
#[derive(Serialize, Clone, Default)]
struct ExchangePRTPayload {
    win_ver: Option<String>,
    scope: String,
    resource: Option<String>,
    request_nonce: String,
    refresh_token: String,
    iss: String,
    grant_type: String,
    client_id: String,
    aud: String,
}

#[cfg(feature = "broker")]
impl ExchangePRTPayload {
    fn new(
        prt: &PrimaryRefreshToken,
        nonce: &str,
        resource: Option<String>,
        request_prt: bool,
    ) -> Result<Self, MsalError> {
        let mut scopes = "openid ugs".to_string();
        if request_prt {
            scopes = format!("{} aza", scopes);
        }
        let os_release = match OsRelease::new() {
            Ok(os_release) => Some(format!(
                "{} {}",
                os_release.pretty_name, os_release.version_id
            )),
            Err(_) => None,
        };
        Ok(ExchangePRTPayload {
            win_ver: os_release,
            scope: scopes,
            resource,
            request_nonce: nonce.to_string(),
            refresh_token: prt.refresh_token.clone(),
            iss: "aad:brokerplugin".to_string(),
            grant_type: "refresh_token".to_string(),
            client_id: BROKER_CLIENT_IDENT.to_string(),
            aud: "login.microsoftonline.com".to_string(),
        })
    }
}

#[cfg(feature = "broker")]
#[derive(Serialize, Clone, Default, Zeroize, ZeroizeOnDrop)]
struct RefreshTokenCredentialPayload {
    iat: Option<i64>,
    refresh_token: String,
    request_nonce: String,
    ua_client_id: Option<String>,
    ua_redirect_uri: Option<String>,
    x_client_platform: Option<String>,
    win_ver: Option<String>,
    windows_api_version: Option<String>,
}

#[cfg(feature = "broker")]
impl RefreshTokenCredentialPayload {
    fn new(prt: &PrimaryRefreshToken, nonce: &str) -> Result<Self, MsalError> {
        let iat: i64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| MsalError::GeneralFailure(format!("Failed choosing iat: {}", e)))?
            .as_secs()
            .try_into()
            .map_err(|e| MsalError::GeneralFailure(format!("Failed choosing iat: {}", e)))?;
        let os_release = match OsRelease::new() {
            Ok(os_release) => Some(format!(
                "{} {}",
                os_release.pretty_name, os_release.version_id
            )),
            Err(_) => None,
        };
        Ok(RefreshTokenCredentialPayload {
            iat: Some(iat),
            refresh_token: prt.refresh_token.clone(),
            request_nonce: nonce.to_string(),
            ua_client_id: None,
            ua_redirect_uri: None,
            x_client_platform: None,
            win_ver: os_release,
            windows_api_version: Some("2.0.1".to_string()),
        })
    }
}

#[cfg(feature = "broker")]
#[derive(Serialize, Clone, Default, Zeroize, ZeroizeOnDrop)]
struct DeviceCredentialPayload {
    grant_type: String,
    iss: String,
    request_nonce: String,
    ua_client_id: Option<String>,
    ua_redirect_uri: Option<String>,
    x_client_platform: Option<String>,
    win_ver: Option<String>,
    windows_api_version: Option<String>,
}

#[cfg(feature = "broker")]
impl DeviceCredentialPayload {
    fn new(nonce: &str) -> Result<Self, MsalError> {
        let os_release = match OsRelease::new() {
            Ok(os_release) => Some(format!(
                "{} {}",
                os_release.pretty_name, os_release.version_id
            )),
            Err(_) => None,
        };
        Ok(DeviceCredentialPayload {
            grant_type: "device_auth".to_string(),
            iss: "aad:brokerplugin".to_string(),
            request_nonce: nonce.to_string(),
            ua_client_id: None,
            ua_redirect_uri: None,
            x_client_platform: None,
            win_ver: os_release,
            windows_api_version: Some("2.0.1".to_string()),
        })
    }
}

#[cfg(feature = "broker")]
#[derive(Debug, Deserialize)]
struct Nonce {
    #[serde(rename = "Nonce")]
    nonce: String,
}

#[cfg(feature = "broker")]
impl FromStr for TGT {
    type Err = MsalError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        json_from_str(s).map_err(|e| MsalError::InvalidParse(format!("Failed parsing tgt: {}", e)))
    }
}

#[cfg(feature = "broker")]
#[derive(Default, Clone, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct TGT {
    #[serde(rename = "clientKey")]
    client_key: Option<String>,
    #[serde(rename = "keyType")]
    key_type: u32,
    error: Option<String>,
    #[serde(rename = "messageBuffer")]
    message_buffer: Option<String>,
    pub realm: Option<String>,
    pub sn: Option<String>,
    pub cn: Option<String>,
    #[serde(rename = "sessionKeyType")]
    pub session_key_type: u32,
    #[serde(rename = "accountType")]
    pub account_type: u32,
}

#[cfg(feature = "broker")]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AesKey {
    key: Vec<u8>,
    etype: u16,
}

impl AesKey {
    fn new(key: &[u8], etype: u16) -> Result<Self, MsalError> {
        Ok(AesKey {
            key: key.to_vec(),
            etype,
        })
    }

    pub(crate) fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, MsalError> {
        let aes_sizes = match self.etype {
            17 => AesSizes::Aes128,
            18 => AesSizes::Aes256,
            _ => {
                return Err(MsalError::CryptoFail(format!(
                    "Encryption type {} not supported",
                    self.etype
                )))
            }
        };
        let cipher = AesCipher::new(aes_sizes);
        cipher
            .decrypt(&self.key, 3, ciphertext)
            .map_err(|e| MsalError::CryptoFail(format!("{:?}", e)))
            .map(Zeroizing::new)
    }
}

#[cfg(feature = "broker")]
impl TGT {
    fn client_key(
        &self,
        tpm: &mut BoxedDynTpm,
        transport_key: &MsOapxbcRsaKey,
        session_key: &SessionKey,
    ) -> Result<AesKey, MsalError> {
        if self.key_type == 0 {
            return Err(MsalError::CryptoFail("TGT key type is invalid".to_string()));
        }
        let tgt = self.message()?;
        let etype: u16 = IntegerAsn1(&tgt.0.enc_part.0.etype.0).try_into()?;
        if etype != 18 && etype != 17 {
            return Err(MsalError::CryptoFail(format!(
                "Encryption type {} not supported",
                etype
            )));
        }
        match &self.client_key {
            Some(client_key) => {
                let jwe = JweCompact::from_str(client_key)
                    .map_err(|e| MsalError::InvalidParse(format!("{}", e)))?;
                let client_key = session_key
                    .decipher_tgt_client_key(tpm, transport_key, &jwe)
                    .map_err(|e| {
                        MsalError::CryptoFail(format!(
                            "Failed to unwrap the tgt session key: {:?}",
                            e
                        ))
                    })?;
                Ok(AesKey::new(&client_key, etype).map_err(|e| {
                    MsalError::CryptoFail(format!("Failed to load the Aes256 key: {:?}", e))
                })?)
            }
            None => Err(MsalError::CryptoFail(
                "TGT client key is missing".to_string(),
            )),
        }
    }

    pub fn message(&self) -> Result<AsRep, MsalError> {
        let tgt: AsRep = match &self.message_buffer {
            Some(message_buffer) => picky_asn1_der::from_bytes(
                &STANDARD
                    .decode(message_buffer.as_str())
                    .map_err(|e| MsalError::CryptoFail(format!("{:?}", e)))?,
            )
            .map_err(|e| MsalError::CryptoFail(format!("{:?}", e)))?,
            None => {
                return Err(MsalError::CryptoFail(
                    "TGT message buffer is missing".to_string(),
                ))
            }
        };
        Ok(tgt)
    }
}

#[cfg(feature = "broker")]
#[derive(Clone, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
struct PrimaryRefreshToken {
    token_type: String,
    expires_in: String,
    ext_expires_in: String,
    expires_on: String,
    refresh_token: String,
    refresh_token_expires_in: u64,
    session_key_jwe: Option<String>,
    #[serde(deserialize_with = "decode_string_or_struct")]
    #[zeroize(skip)]
    id_token: IdToken,
    #[serde(deserialize_with = "decode_string_or_struct", default)]
    #[zeroize(skip)]
    client_info: ClientInfo,
    device_tenant_id: Option<String>,
    #[serde(deserialize_with = "decode_string_or_struct", default)]
    tgt_ad: TGT,
    #[serde(deserialize_with = "decode_string_or_struct", default)]
    tgt_cloud: TGT,
    kerberos_top_level_names: Option<String>,
}

#[cfg(feature = "broker")]
impl PrimaryRefreshToken {
    fn name(&self) -> String {
        self.id_token.name.clone()
    }

    fn spn(&self) -> Result<String, MsalError> {
        match &self.id_token.preferred_username {
            Some(spn) => Ok(spn.to_string()),
            None => Err(MsalError::GeneralFailure(
                "No spn available for PRT".to_string(),
            )),
        }
    }

    fn uuid(&self) -> Result<Uuid, MsalError> {
        Uuid::parse_str(&self.id_token.oid).map_err(|e| MsalError::InvalidParse(format!("{}", e)))
    }

    fn session_key(&self) -> Result<SessionKey, MsalError> {
        match &self.session_key_jwe {
            Some(session_key_jwe) => SessionKey::new(session_key_jwe),
            None => Err(MsalError::CryptoFail("session_key_jwe missing".to_string())),
        }
    }

    fn clone_session_key(&self, new_prt: &mut PrimaryRefreshToken) {
        new_prt.session_key_jwe.clone_from(&self.session_key_jwe);
    }
}

#[cfg(feature = "broker")]
struct SessionKey {
    session_key_jwe: JweCompact,
}

#[cfg(feature = "broker")]
impl SessionKey {
    fn new(session_key_jwe: &str) -> Result<Self, MsalError> {
        Ok(SessionKey {
            session_key_jwe: JweCompact::from_str(session_key_jwe)
                .map_err(|e| MsalError::InvalidParse(format!("Failed parsing jwe: {}", e)))?,
        })
    }

    fn decipher_prt_v2(
        &self,
        tpm: &mut BoxedDynTpm,
        transport_key: &MsOapxbcRsaKey,
        jwe: &JweCompact,
    ) -> Result<Jwe, MsalError> {
        let session_key = MsOapxbcSessionKey::complete_tpm_rsa_oaep_key_agreement(
            tpm,
            transport_key,
            &self.session_key_jwe,
        )
        .map_err(|e| MsalError::CryptoFail(format!("Unable to decipher session_key_jwe: {}", e)))?;
        session_key
            .decipher_prt_v2(tpm, transport_key, jwe)
            .map_err(|e| MsalError::CryptoFail(format!("Failed to decipher Jwe: {}", e)))
    }

    fn decipher_tgt_client_key(
        &self,
        tpm: &mut BoxedDynTpm,
        transport_key: &MsOapxbcRsaKey,
        jwe: &JweCompact,
    ) -> Result<Zeroizing<Vec<u8>>, MsalError> {
        let session_key = MsOapxbcSessionKey::complete_tpm_rsa_oaep_key_agreement(
            tpm,
            transport_key,
            &self.session_key_jwe,
        )
        .map_err(|e| MsalError::CryptoFail(format!("Unable to decipher session_key_jwe: {}", e)))?;
        match session_key.decipher_prt_v2(tpm, transport_key, jwe) {
            Ok(decrypted) => Ok(Zeroizing::new(decrypted.payload().to_vec())),
            Err(JwtError::OpenSSLError) => match session_key.decipher(tpm, transport_key, jwe) {
                Ok(decrypted) => Ok(Zeroizing::new(decrypted.payload().to_vec())),
                Err(e) => Err(MsalError::CryptoFail(format!(
                    "Failed to decipher Jwe: {}",
                    e
                ))),
            },
            Err(e) => Err(MsalError::CryptoFail(format!(
                "Failed to decipher Jwe: {}",
                e
            ))),
        }
    }

    fn sign<V: JwsSignable>(
        &self,
        tpm: &mut BoxedDynTpm,
        transport_key: &MsOapxbcRsaKey,
        jws: &V,
    ) -> Result<V::Signed, MsalError> {
        let session_key = MsOapxbcSessionKey::complete_tpm_rsa_oaep_key_agreement(
            tpm,
            transport_key,
            &self.session_key_jwe,
        )
        .map_err(|e| MsalError::CryptoFail(format!("Unable to decipher session_key_jwe: {}", e)))?;
        session_key
            .sign(tpm, transport_key, jws)
            .map_err(|e| MsalError::CryptoFail(format!("Failed signing jwk: {}", e)))
    }
}

#[derive(PartialEq)]
pub enum AuthOption {
    Fido,
    Passwordless,
    NoDAGFallback,
}

struct ClientApplication {
    client: Client,
    client_id: String,
    authority: String,
}

impl ClientApplication {
    fn new(client_id: &str, authority: Option<&str>) -> Result<Self, MsalError> {
        #[allow(unused_mut)]
        let mut builder = reqwest::Client::builder()
            .redirect(Policy::none())
            .cookie_store(true);

        #[cfg(feature = "proxyable")]
        {
            if let Some(proxy_var) = std::env::var("HTTPS_PROXY")
                .ok()
                .or_else(|| std::env::var("ALL_PROXY").ok())
            {
                let proxy = Proxy::https(proxy_var)
                    .map_err(|e| MsalError::GeneralFailure(format!("{:?}", e)))?;
                builder = builder.proxy(proxy).danger_accept_invalid_certs(true);
            }
        }

        let client = builder
            .build()
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;

        Ok(ClientApplication {
            client,
            client_id: client_id.to_string(),
            authority: match authority {
                Some(authority) => authority.to_string(),
                None => "https://login.microsoftonline.com/common".to_string(),
            },
        })
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

    fn get_auth_redirect_uri(&self, client_id: Option<&str>, resource: Option<&str>) -> String {
        let client_id = client_id.unwrap_or(self.client_id.as_str());
        let resource = resource.unwrap_or("");

        match client_id {
            "1fec8e78-bce4-4aaf-ab1b-5451cc387264" => {
                "https://login.microsoftonline.com/common/oauth2/nativeclient".to_string()
            },
            "9bc3ab49-b65d-410a-85ad-de819febfddc" => {
                "https://oauth.spops.microsoft.com/".to_string()
            },
            "c44b4083-3bb0-49c1-b47d-974e53cbdf3c" => {
                "https://portal.azure.com/signin/index/?feature.prefetchtokens=true&feature.showservicehealthalerts=true&feature.usemsallogin=true".to_string()
            },
            "0000000c-0000-0000-c000-000000000000" => {
                "https://account.activedirectory.windowsazure.com/".to_string()
            },
            "19db86c3-b2b9-44cc-b339-36da233a3be2" => {
                "https://mysignins.microsoft.com".to_string()
            },
            "29d9ed98-a469-4536-ade2-f981bc1d605e" => {
                if resource.contains("enrollment.manage.microsoft.com") {
                    "ms-aadj-redir://auth/drs".to_string()
                } else {
                    "msauth://Microsoft.AAD.BrokerPlugin".to_string()
                }
            },
            "b743a22d-6705-4147-8670-d92fa515ee2b" => {
                "companyportal://com.microsoft.CompanyPortal".to_string()
            }
            "d3590ed6-52b3-4102-aeff-aad2292ab01c" => {
                "ms-appx-web://Microsoft.AAD.BrokerPlugin/d3590ed6-52b3-4102-aeff-aad2292ab01c".to_string()
            },
            "0c1307d4-29d6-4389-a11c-5cbe7f65d7fa" => {
                "https://azureapp".to_string()
            },
            "33be1cef-03fb-444b-8fd3-08ca1b4d803f" => {
                "https://admin.onedrive.com/".to_string()
            },
            "ab9b8c07-8f02-4f72-87fa-80105867a763" => {
                "https://login.windows.net/common/oauth2/nativeclient".to_string()
            },
            "3d5cffa9-04da-4657-8cab-c7f074657cad" => {
                "http://localhost/m365/commerce".to_string()
            },
            "4990cffe-04e8-4e8b-808a-1175604b879f" => {
                "https://partner.microsoft.com/aad/authPostGateway".to_string()
            },
            "fb78d390-0c51-40cd-8e17-fdbfab77341b" |
            "fdd7719f-d61e-4592-b501-793734eb8a0e" |
            "a0c73c16-a7e3-4564-9a95-2bdf47383716" => {
                "https://login.microsoftonline.com/common/oauth2/nativeclient".to_string()
            },
            "3b511579-5e00-46e1-a89e-a6f0870e2f5a" => {
                "https://windows365.microsoft.com/signin-oidc".to_string()
            },
            "08e18876-6177-487e-b8b5-cf950c1e598c" => {
                "https://*-admin.sharepoint.com/_forms/spfxsinglesignon.aspx".to_string()
            },
            "dd762716-544d-4aeb-a526-687b73838a22" => {
                "ms-appx-web://microsoft.aad.brokerplugin/dd762716-544d-4aeb-a526-687b73838a22".to_string()
            },
            "4765445b-32c6-49b0-83e6-1d93765276ca" => {
                "https://www.office.com/landingv2".to_string()
            },
            _ => {
                "https://login.microsoftonline.com/common/oauth2/nativeclient".to_string()
            },
        }
    }
}

pub struct AuthInit {
    auth_config: AuthConfig,
    cred_type: CredType,
}

impl AuthInit {
    /// Whether the user exists in the directory
    pub fn exists(&self) -> bool {
        self.cred_type.if_exists_result == 0
    }

    /// Whether passwordless authentication was negotiated
    pub fn passwordless(&self) -> bool {
        self.cred_type.credentials.remote_ngc_params.is_some()
    }
}

#[cfg(feature = "changepassword")]
#[derive(Deserialize)]
struct SsprResponse {
    #[serde(rename = "IsJobPending")]
    is_job_pending: bool,
    #[serde(rename = "Ctx")]
    ctx: String,
    #[serde(rename = "FlowToken")]
    flow_token: String,
    #[serde(rename = "CoupledDataCenter")]
    coupled_data_center: String,
    #[serde(rename = "CoupledScaleUnit")]
    coupled_scale_unit: String,
    #[serde(rename = "ErrorMessage")]
    error_message: Option<String>,
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
    pub fn new(client_id: &str, authority: Option<&str>) -> Result<Self, MsalError> {
        Ok(PublicClientApplication {
            app: ClientApplication::new(client_id, authority)?,
        })
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
    ///   initiate_device_flow.
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

    #[allow(unused_variables)]
    fn parse_auth_config(
        &self,
        text: &str,
        initial: bool,
        password_change: bool,
    ) -> Result<AuthConfig, MsalError> {
        let document = Html::parse_document(text);
        for script in
            document.select(&Selector::parse("script").map_err(|e| {
                MsalError::GeneralFailure(format!("Failed parsing auth config: {}", e))
            })?)
        {
            let text = script.inner_html();
            if let Some(config_index) = text.find(r"$Config=") {
                let sconfig = &text[config_index + 8..];
                if let Some(end_index) = sconfig.rfind(r"//]]&gt;") {
                    let config = &sconfig[..end_index - 2];
                    let auth_config: AuthConfig = json_from_str(config).map_err(|e| {
                        MsalError::InvalidJson(format!("Failed parsing auth config: {}", e))
                    })?;
                    // MS always throws errors when we're just setting up the
                    // *initial* authorize. MS then ignores them, so shall we.
                    if !initial {
                        if let Some(error_code) = auth_config.error_code {
                            // Check to see if we can get the failure message
                            if let Some(err_txt) = auth_config.err_txt {
                                if !err_txt.is_empty() {
                                    error!("{}", err_txt);
                                }
                            }
                            let error_code = error_code.parse::<u32>().map_err(|e| {
                                MsalError::InvalidParse(format!(
                                    "error_code {}: {:?}",
                                    error_code, e
                                ))
                            })?;
                            return Err(MsalError::AADSTSError(AADSTSError::new(error_code)));
                        }
                    }
                    #[cfg(feature = "changepassword")]
                    if !password_change {
                        if let Some(ref pgid) = auth_config.pgid {
                            if pgid == "ConvergedChangePassword" {
                                return Err(MsalError::ChangePassword);
                            }
                        }
                    }
                    return Ok(auth_config);
                }
            }
        }
        Err(MsalError::GeneralFailure(
            "Auth config was not found".to_string(),
        ))
    }

    /// Change the password for an Entra Id user.
    ///
    /// This function allows changing the password for an Entra Id user. It
    /// requires the current username and password to validate the user's
    /// identity before updating the password.
    ///
    /// # Arguments
    ///
    /// * `username` - The username associated with the account for which the
    ///   password is being changed.
    /// * `password` - The current password for the account.
    /// * `new_password` - The new password that will replace the current
    ///   password.
    ///
    /// # Returns
    ///
    /// * Success: An empty Ok result indicating the password has been changed
    ///   successfully.
    /// * Failure: An MsalError, indicating problems such as authentication
    ///   failures or password complexity requirements not met.
    #[cfg(feature = "changepassword")]
    pub async fn handle_password_change(
        &self,
        username: &str,
        password: &str,
        new_password: &str,
    ) -> Result<(), MsalError> {
        let request_id = Uuid::new_v4().to_string();
        let auth_config = self
            .request_auth_config_internal(vec![], &request_id, None, false)
            .await?;
        let ctx = auth_config
            .sctx
            .clone()
            .ok_or(MsalError::GeneralFailure("ctx is missing".to_string()))?;
        let flow_token = auth_config
            .sft
            .clone()
            .ok_or(MsalError::GeneralFailure("sft is missing".to_string()))?;

        let params = vec![
            ("login", username),
            ("passwd", password),
            ("ctx", &ctx),
            ("flowToken", &flow_token),
            ("canary", &auth_config.canary),
            ("client_id", self.client_id()),
            ("client-request-id", &request_id),
        ];
        let auth_config = self
            .handle_auth_config_req_internal(&params, &auth_config, &[], true)
            .await?;

        let payload = json!({
            "Ctx": &auth_config
                    .sctx
                    .ok_or(MsalError::GeneralFailure("ctx is missing".to_string()))?,
            "FlowToken": &auth_config
                    .sft
                    .ok_or(MsalError::GeneralFailure("sft is missing".to_string()))?,
            "OldPassword": password,
            "NewPassword": new_password,
        });

        let url_async_sspr_begin = match &auth_config.url_async_sspr_begin {
            Some(url_async_sspr_begin) => url_async_sspr_begin.clone(),
            None => {
                return Err(MsalError::GeneralFailure(
                    "url_async_sspr_begin missing from auth config".to_string(),
                ))
            }
        };
        let url = match url_async_sspr_begin.starts_with('/') {
            true => {
                let authority = self.authority().to_string();
                let index = authority.rfind('/').ok_or(MsalError::GeneralFailure(
                    "Failed to splice auth config url".to_string(),
                ))?;
                format!("{}/{}", &authority[..index], &url_async_sspr_begin)
            }
            false => url_async_sspr_begin.clone(),
        };

        let resp = self
            .client()
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let mut sspr_response: SsprResponse = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;

            let url_async_sspr_poll = match &auth_config.url_async_sspr_poll {
                Some(url_async_sspr_poll) => url_async_sspr_poll.clone(),
                None => {
                    return Err(MsalError::GeneralFailure(
                        "url_async_sspr_poll missing from auth config".to_string(),
                    ))
                }
            };
            let url = match url_async_sspr_poll.starts_with('/') {
                true => {
                    let authority = self.authority().to_string();
                    let index = authority.rfind('/').ok_or(MsalError::GeneralFailure(
                        "Failed to splice auth config url".to_string(),
                    ))?;
                    format!("{}/{}", &authority[..index], &url_async_sspr_poll)
                }
                false => url_async_sspr_poll.clone(),
            };

            while sspr_response.is_job_pending {
                sleep(Duration::from_secs(1));
                let poll_body = json!({
                    "Ctx": sspr_response.ctx,
                    "FlowToken": sspr_response.flow_token,
                    "CoupledDataCenter": sspr_response.coupled_data_center,
                    "CoupledScaleUnit": sspr_response.coupled_scale_unit,
                });
                sspr_response = self
                    .client()
                    .post(&url)
                    .json(&poll_body)
                    .send()
                    .await
                    .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?
                    .json()
                    .await
                    .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;

                if let Some(e) = sspr_response.error_message {
                    return Err(MsalError::GeneralFailure(format!(
                        "Failed changing password: {}",
                        e
                    )));
                }
            }

            let url_post = match &auth_config.url_post {
                Some(url_post) => url_post.clone(),
                None => {
                    return Err(MsalError::GeneralFailure(
                        "urlPost missing from auth config".to_string(),
                    ))
                }
            };
            let url = match url_post.starts_with('/') {
                true => {
                    let authority = self.authority().to_string();
                    let index = authority.rfind('/').ok_or(MsalError::GeneralFailure(
                        "Failed to splice auth config url".to_string(),
                    ))?;
                    format!("{}/{}", &authority[..index], &url_post)
                }
                false => url_post.clone(),
            };

            let final_body = json!({
                "Ctx": sspr_response.ctx,
                "FlowToken": sspr_response.flow_token,
                "currentpasswd": password,
                "confirmnewpasswd": new_password,
                "canary": auth_config.canary,
            });
            let resp = self
                .client()
                .post(&url)
                .json(&final_body)
                .send()
                .await
                .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
            if resp.status().is_success() {
                Ok(())
            } else {
                let text = resp.text().await.map_err(|e| {
                    MsalError::GeneralFailure(format!("Failed changing password: {}", e))
                })?;
                Err(MsalError::GeneralFailure(format!(
                    "Failed changing password: {}",
                    text
                )))
            }
        } else {
            let text = resp.text().await.map_err(|e| {
                MsalError::GeneralFailure(format!("Failed changing password: {}", e))
            })?;
            Err(MsalError::GeneralFailure(format!(
                "Failed changing password: {}",
                text
            )))
        }
    }

    async fn handle_auth_config_fido_get(
        &self,
        username: &str,
        auth_config: &AuthConfig,
        request_id: &str,
    ) -> Result<AuthConfig, MsalError> {
        let url_post = match &auth_config.url_post {
            Some(url_post) => url_post.clone(),
            None => {
                return Err(MsalError::GeneralFailure(
                    "urlPost missing from auth config".to_string(),
                ))
            }
        };

        let url_resume = match &auth_config.url_resume {
            Some(url_resume) => url_resume.clone(),
            None => {
                return Err(MsalError::GeneralFailure(
                    "urlResume missing from auth config".to_string(),
                ))
            }
        };

        let credentials_json = match &auth_config.fido_allow_list {
            Some(fido_allow_list) => {
                if !fido_allow_list.is_empty() {
                    &fido_allow_list[0]
                } else {
                    return Err(MsalError::GeneralFailure(
                        "arrFidoAllowList missing from auth config".to_string(),
                    ));
                }
            }
            None => {
                return Err(MsalError::GeneralFailure(
                    "arrFidoAllowList missing from auth config".to_string(),
                ))
            }
        };

        let sctx = match &auth_config.sctx {
            Some(sctx) => sctx.clone(),
            None => {
                return Err(MsalError::GeneralFailure(
                    "sCtx missing from auth config".to_string(),
                ));
            }
        };

        let sft = match &auth_config.sft {
            Some(sft) => sft.clone(),
            None => {
                return Err(MsalError::GeneralFailure(
                    "sFt missing from auth config".to_string(),
                ));
            }
        };

        let allowed_identities = match &auth_config.allowed_identities {
            Some(allowed_identities) => format!("{}", allowed_identities),
            None => {
                return Err(MsalError::GeneralFailure(
                    "iAllowedIdentities missing from auth config".to_string(),
                ));
            }
        };

        let params = [
            ("flow", "mfa"),
            ("allowedIdentities", &allowed_identities),
            ("canary", &sft),
            ("serverChallenge", &sft),
            ("postBackUrl", &url_post),
            ("postBackUrlAad", &url_post),
            ("cancelUrl", &url_resume),
            ("resumeUrl", &url_resume),
            ("correlationId", request_id),
            ("credentialsJson", credentials_json),
            ("ctx", &sctx),
            ("username", username),
            ("loginCanary", &auth_config.canary),
        ];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, url_encode(v)))
            .collect::<Vec<String>>()
            .join("&");

        let url_fido_login = match &auth_config.url_fido_login {
            Some(url_fido_login) => url_fido_login.clone(),
            None => {
                return Err(MsalError::GeneralFailure(
                    "urlFidoLogin missing from auth config".to_string(),
                ))
            }
        };

        let mut resp = self
            .client()
            .post(url_fido_login)
            .header(header::USER_AGENT, FIDO_USER_AGENT)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        let text;
        (text, resp) = self.await_working(resp).await?;
        if resp.status().is_success() {
            self.parse_auth_config(&text, false, false)
        } else {
            Err(MsalError::GeneralFailure(
                resp.text()
                    .await
                    .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?,
            ))
        }
    }

    async fn handle_auth_config_req_internal(
        &self,
        req_params: &[(&str, &str)],
        auth_config: &AuthConfig,
        options: &[AuthOption],
        password_change: bool,
    ) -> Result<AuthConfig, MsalError> {
        let payload = req_params
            .iter()
            .map(|(k, v)| format!("{}={}", k, url_encode(v)))
            .collect::<Vec<String>>()
            .join("&");

        let url_post = match &auth_config.url_post {
            Some(url_post) => url_post.clone(),
            None => {
                return Err(MsalError::GeneralFailure(
                    "urlPost missing from auth config".to_string(),
                ))
            }
        };
        let url = match url_post.starts_with('/') {
            true => {
                let authority = self.authority().to_string();
                let index = authority.rfind('/').ok_or(MsalError::GeneralFailure(
                    "Failed to splice auth config url".to_string(),
                ))?;
                format!("{}/{}", &authority[..index], &url_post)
            }
            false => url_post.clone(),
        };

        let user_agent = if options.contains(&AuthOption::Fido) {
            FIDO_USER_AGENT
        } else {
            env!("CARGO_PKG_NAME")
        };
        let mut resp = self
            .client()
            .post(url)
            .header(header::USER_AGENT, user_agent)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        let text;
        (text, resp) = self.await_working(resp).await?;
        if resp.status().is_success() {
            self.parse_auth_config(&text, false, password_change)
        } else {
            Err(MsalError::GeneralFailure(
                resp.text()
                    .await
                    .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?,
            ))
        }
    }

    /// Check if a user exists in Azure Entra ID
    ///
    /// # Arguments
    ///
    /// * `username` - Typically a UPN in the form of an email address.
    ///
    /// * `resource` - A resource for obtaining an access token.
    ///   Default is the MS Graph API (00000002-0000-0000-c000-000000000000).
    ///
    /// * `options` - Authentication options to enable, such as Fido and
    ///   Passwordless auth.
    ///
    /// # Returns
    /// * Success: An AuthInit object. Call `exists` to get the result.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn check_user_exists(
        &self,
        username: &str,
        resource: Option<&str>,
        options: &[AuthOption],
    ) -> Result<AuthInit, MsalError> {
        let request_id = Uuid::new_v4().to_string();
        let auth_config = self
            .request_auth_config_internal(vec![], &request_id, resource, true)
            .await?;
        let cred_type = self
            .get_cred_type(username, &auth_config, &request_id, options)
            .await?;
        Ok(AuthInit {
            auth_config,
            cred_type,
        })
    }

    /// Initiate an MFA flow via user credentials.
    ///
    /// # Arguments
    ///
    /// * `username` - Typically a UPN in the form of an email address.
    ///
    /// * `password` - The password.
    ///
    /// * `scopes` - Scopes requested to access a protected API (a resource).
    ///
    /// * `resource` - A resource for obtaining an access token.
    ///   Default is the MS Graph API (00000002-0000-0000-c000-000000000000).
    ///
    /// * `options` - Authentication options to enable, such as Fido.
    ///
    /// * `auth_init` - The result of `check_user_exists`, required if called
    ///   prior to `initiate_acquire_token_by_mfa_flow`.
    ///
    /// # Returns
    /// * Success: A MFAAuthContinue containing the information needed to continue the
    ///   authentication flow.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn initiate_acquire_token_by_mfa_flow(
        &self,
        username: &str,
        password: Option<&str>,
        scopes: Vec<&str>,
        resource: Option<&str>,
        options: &[AuthOption],
        auth_init: Option<AuthInit>,
    ) -> Result<MFAAuthContinue, MsalError> {
        macro_rules! dag_fallback {
            () => {
                if !options.contains(&AuthOption::NoDAGFallback) {
                    let mut dag_scopes: Vec<String> =
                        scopes.into_iter().map(|s| s.to_string()).collect();
                    // Enforce MFA via the azure portal
                    dag_scopes.push(format!("{}/.default", AZURE_PORTAL_APP_ID));
                    info!("MFA auth failed, falling back to Device Authorization Grant.");
                    let flow = self
                        .initiate_device_flow(dag_scopes.iter().map(|i| i.as_str()).collect())
                        .await?;
                    let mut flow: MFAAuthContinue = flow.into();
                    flow.resource = resource.map(|s| s.to_string());
                    return Ok(flow);
                } else {
                    return Err(MsalError::GeneralFailure(
                        "MFA failed and DAG fallback is disabled".to_string(),
                    ));
                }
            };
            ($err:expr) => {
                if !options.contains(&AuthOption::NoDAGFallback) {
                    // If we got a change password request, return it.
                    #[cfg(feature = "changepassword")]
                    if let MsalError::ChangePassword = $err {
                        return Err($err);
                    }

                    // If we got an AADSTSError, then we don't want to perform a
                    // fallback, since the authentication legitimately failed.
                    if let MsalError::AADSTSError(ref e) = $err {
                        // There are a couple of exceptions to the rule. If
                        // interaction is required, or MFA enrollment is required,
                        // continue with the fallback.
                        // AADSTS16000: InteractionRequired
                        // AADSTS50072: UserStrongAuthEnrollmentRequiredInterrupt
                        if ![16000, 50072].contains(&e.code) {
                            return Err($err);
                        }
                    }

                    let mut dag_scopes: Vec<String> =
                        scopes.into_iter().map(|s| s.to_string()).collect();
                    // Enforce MFA via the azure portal
                    dag_scopes.push(format!("{}/.default", AZURE_PORTAL_APP_ID));
                    info!("MFA auth failed, falling back to Device Authorization Grant.");
                    let flow = self
                        .initiate_device_flow(dag_scopes.iter().map(|i| i.as_str()).collect())
                        .await?;
                    let mut flow: MFAAuthContinue = flow.into();
                    flow.resource = resource.map(|s| s.to_string());
                    return Ok(flow);
                } else {
                    return Err($err);
                }
            };
        }
        let request_id = Uuid::new_v4().to_string();
        let (auth_config, cred_type) = if let Some(auth_init) = auth_init {
            (auth_init.auth_config, auth_init.cred_type)
        } else {
            let auth_config = match self
                .request_auth_config_internal(scopes.clone(), &request_id, resource, true)
                .await
            {
                Ok(auth_config) => auth_config,
                Err(e) => {
                    error!("{:?}", e);
                    dag_fallback!();
                }
            };
            let cred_type = match self
                .get_cred_type(username, &auth_config, &request_id, options)
                .await
            {
                Ok(cred_type) => cred_type,
                Err(e) => {
                    error!("{:?}", e);
                    dag_fallback!(e);
                }
            };
            (auth_config, cred_type)
        };
        if let Some(remote_ngc_params) = cred_type.credentials.remote_ngc_params {
            // Passwordless is enabled, we can drop out here
            let sctx = match &auth_config.sctx {
                Some(sctx) => sctx.clone(),
                None => return Err(MsalError::GeneralFailure("sCtx is missing".to_string())),
            };
            let sft = match &auth_config.sft {
                Some(sft) => sft.clone(),
                None => return Err(MsalError::GeneralFailure("sFt is missing".to_string())),
            };
            let remote_ngc_params = self
                .get_one_time_code(&auth_config, &remote_ngc_params, &request_id)
                .await?;
            let msg = format!(
                "Open your Authenticator app, and enter the number '{}' to sign in.",
                remote_ngc_params.entropy
            );
            let url_post = match &auth_config.url_post {
                Some(url_post) => url_post.clone(),
                None => {
                    return Err(MsalError::GeneralFailure(
                        "urlBeginAuth is missing".to_string(),
                    ))
                }
            };
            return Ok(MFAAuthContinue {
                mfa_method: "PhoneAppNotification".to_string(),
                msg,
                entropy: Some(remote_ngc_params.entropy),
                max_poll_attempts: auth_config.max_poll_attempts,
                polling_interval: Some(5000),
                session_id: remote_ngc_params.session_identifier,
                flow_token: sft,
                ctx: sctx,
                canary: auth_config.canary,
                url_end_auth: None,
                url_post,
                resource: resource.map(|s| s.to_string()),
                dag: None,
                fido_challenge: None,
                fido_allow_list: None,
                cross_domain_canary: None,
                url_session_state: auth_config.url_session_state,
            });
        }
        if cred_type.credentials.federation_redirect_url.is_some() {
            info!("Federated identities are not supported.");
            dag_fallback!();
        }
        if cred_type.throttle_status == 1 {
            return Err(MsalError::GeneralFailure(
                "Authentication throttled. Wait a minute and try again.".to_string(),
            ));
        }
        if cred_type.if_exists_result != 0 {
            return Err(MsalError::GeneralFailure(
                "An account with that name does not exist.".to_string(),
            ));
        }
        if !cred_type.credentials.has_password {
            info!("Password authentication is not supported.");
            dag_fallback!();
        }

        let sctx = match &auth_config.sctx {
            Some(sctx) => sctx.clone(),
            None => {
                info!("sCtx is missing");
                dag_fallback!();
            }
        };
        let sft = match &auth_config.sft {
            Some(sft) => sft.clone(),
            None => {
                info!("sFt is missing");
                dag_fallback!();
            }
        };
        let params = vec![
            ("login", username),
            (
                "passwd",
                password.ok_or(MsalError::GeneralFailure("password is missing".to_string()))?,
            ),
            ("ctx", &sctx),
            ("flowToken", &sft),
            ("canary", &auth_config.canary),
            ("client_id", self.client_id()),
            ("client-request-id", &request_id),
        ];
        match self
            .handle_auth_config_req_internal(&params, &auth_config, options, false)
            .await
        {
            Ok(mut auth_config) => {
                if let Some(msg) = auth_config.service_exception_msg {
                    error!("{}", msg);
                    dag_fallback!();
                }
                if let Some(ref pgid) = auth_config.pgid {
                    if pgid == "KmsiInterrupt" {
                        let sctx = match &auth_config.sctx {
                            Some(sctx) => sctx.clone(),
                            None => {
                                info!("sCtx is missing");
                                dag_fallback!();
                            }
                        };
                        let sft = match &auth_config.sft {
                            Some(sft) => sft.clone(),
                            None => {
                                info!("sFt is missing");
                                dag_fallback!();
                            }
                        };
                        let params = vec![
                            ("LoginOptions", "1"),
                            ("ctx", &sctx),
                            ("flowToken", &sft),
                            ("canary", &auth_config.canary),
                            ("client-request-id", &request_id),
                        ];
                        auth_config = match self
                            .handle_auth_config_req_internal(&params, &auth_config, options, false)
                            .await
                        {
                            Ok(auth_config) => auth_config,
                            Err(e) => {
                                error!("{:?}", e);
                                dag_fallback!(e);
                            }
                        };
                    }
                }
                if let Some(ref pgid) = auth_config.pgid {
                    if pgid == "ConvergedProofUpRedirect" {
                        if let Some(remaining_days) = auth_config.remaining_days_to_skip_mfa_reg {
                            info!("MFA must be set up in {} days", remaining_days);
                            let params = vec![
                                ("LoginOptions", "1"),
                                ("ctx", &sctx),
                                ("flowToken", &sft),
                                ("canary", &auth_config.canary),
                                ("client-request-id", &request_id),
                            ];
                            auth_config = match self
                                .handle_auth_config_req_internal(
                                    &params,
                                    &auth_config,
                                    options,
                                    false,
                                )
                                .await
                            {
                                Ok(auth_config) => auth_config,
                                Err(e) => {
                                    error!("{:?}", e);
                                    dag_fallback!(e);
                                }
                            };
                        } else {
                            info!("MFA method must be registered.");
                            dag_fallback!();
                        }
                    }
                }
                if let Some(ref pgid) = auth_config.pgid {
                    if pgid == "ConvergedChangePassword" {
                        info!("Password is expired!");
                        #[cfg(feature = "changepassword")]
                        return Err(MsalError::ChangePassword);
                        #[cfg(not(feature = "changepassword"))]
                        dag_fallback!();
                    }
                }
                if let Some(ref arr_user_proofs) = auth_config.arr_user_proofs {
                    let default_auth_method =
                        match arr_user_proofs.iter().find(|proof| proof.is_default) {
                            Some(default_auth_method) => default_auth_method,
                            None => {
                                if arr_user_proofs.is_empty() {
                                    info!("No MFA methods found");
                                    dag_fallback!();
                                } else {
                                    // Sometimes MS fails to set is_default on
                                    // any method. In this case, just choose
                                    // the first one (which may be the only
                                    // one).
                                    &arr_user_proofs[0]
                                }
                            }
                        };
                    let sctx = match &auth_config.sctx {
                        Some(sctx) => sctx.clone(),
                        None => {
                            info!("sCtx is missing");
                            dag_fallback!();
                        }
                    };
                    let sft = match &auth_config.sft {
                        Some(sft) => sft.clone(),
                        None => {
                            info!("sFt is missing");
                            dag_fallback!();
                        }
                    };
                    let url_begin_auth = match &auth_config.url_begin_auth {
                        Some(url_begin_auth) => url_begin_auth.clone(),
                        None => {
                            info!("urlBeginAuth is missing");
                            dag_fallback!();
                        }
                    };
                    let url_post = match &auth_config.url_post {
                        Some(url_post) => url_post.clone(),
                        None => {
                            info!("urlPost is missing");
                            dag_fallback!();
                        }
                    };
                    let (flow_token, ctx, msg) = if default_auth_method.auth_method_id == "FidoKey"
                    {
                        let fido_auth_config = self
                            .handle_auth_config_fido_get(username, &auth_config, &request_id)
                            .await?;
                        auth_config.fido_challenge = fido_auth_config.fido_challenge.clone();
                        auth_config.session_id = fido_auth_config.session_id.clone();
                        auth_config.cross_domain_canary =
                            fido_auth_config.cross_domain_canary.clone();
                        (sft, sctx, "".to_string())
                    } else {
                        let auth_response = match self
                            .mfa_begin_auth_internal(
                                &default_auth_method.auth_method_id,
                                &url_begin_auth,
                                &sctx,
                                &sft,
                                &auth_config.canary,
                            )
                            .await
                        {
                            Ok(auth_response) => match auth_response.success {
                                true => auth_response,
                                false => {
                                    return Err(MsalError::GeneralFailure(
                                        "Begin Auth failed".to_string(),
                                    ))
                                }
                            },
                            Err(e) => {
                                error!("{:?}", e);
                                dag_fallback!(e);
                            }
                        };
                        let msg = match default_auth_method.auth_method_id.as_str() {
                            "PhoneAppNotification" => format!("Open your Authenticator app, and enter the number '{}' to sign in.", auth_response.entropy),
                            "PhoneAppOTP" =>
                                "Please type in the code displayed on your authenticator app from your device:".to_string(),
                            "ConsolidatedTelephony" | "OneWaySMS" =>
                                format!("We texted your phone {}. Please enter the code to sign in:", default_auth_method.display),
                            "TwoWayVoiceMobile" =>
                                format!("We're calling your phone {}. Please answer it to continue.", default_auth_method.display),
                            "TwoWayVoiceAlternateMobile" =>
                                format!("We're calling your phone {}. Please answer it to continue.", default_auth_method.display),
                            method => {
                                info!("Unsupported MFA method {}", method);
                                dag_fallback!();
                            }
                        };
                        (auth_response.flow_token, auth_response.ctx, msg)
                    };
                    Ok(MFAAuthContinue {
                        mfa_method: default_auth_method.auth_method_id.clone(),
                        msg,
                        entropy: None,
                        max_poll_attempts: auth_config.max_poll_attempts,
                        polling_interval: auth_config.polling_interval,
                        session_id: auth_config.session_id,
                        flow_token,
                        ctx,
                        canary: auth_config.canary,
                        url_end_auth: auth_config.url_end_auth,
                        url_post,
                        resource: resource.map(|s| s.to_string()),
                        dag: None,
                        fido_challenge: auth_config.fido_challenge.clone(),
                        fido_allow_list: auth_config.fido_allow_list.clone(),
                        cross_domain_canary: auth_config.cross_domain_canary.clone(),
                        url_session_state: None,
                    })
                } else {
                    info!("No MFA methods found");
                    dag_fallback!();
                }
            }
            Err(e) => {
                error!("{:?}", e);
                dag_fallback!(e);
            }
        }
    }

    async fn get_one_time_code(
        &self,
        auth_config: &AuthConfig,
        remote_ngc_params: &RemoteNgcParams,
        request_id: &str,
    ) -> Result<RemoteNgcParams, MsalError> {
        let payload = json!({
            "Channel": "Authenticator",
            "FlowToken": &auth_config.sft,
            "OldDeviceCode": remote_ngc_params.session_identifier,
            "OriginalRequest": &auth_config.sctx,
        });

        let url = match &auth_config.url_get_one_time_code {
            Some(url) => url.to_string(),
            None => format!("{}/GetOneTimeCode", self.authority()),
        };

        let resp = self
            .client()
            .post(url)
            .header(header::CONTENT_TYPE, "application/json; charset=UTF-8")
            .header("client-request-id", request_id)
            .header("Canary", &auth_config.canary)
            .json(&payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let json_resp: OneTimeCode = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            if let Some(error) = &json_resp.error {
                return Err(MsalError::GeneralFailure(error.message.clone()));
            }
            json_resp.remote_ngc_params.ok_or(MsalError::GeneralFailure(
                "remote_ngc_params missing".to_string(),
            ))
        } else {
            let text = resp
                .text()
                .await
                .map_err(|e| MsalError::GeneralFailure(format!("Failed getting otc: {}", e)))?;
            Err(MsalError::GeneralFailure(text))
        }
    }

    async fn get_cred_type(
        &self,
        username: &str,
        auth_config: &AuthConfig,
        request_id: &str,
        options: &[AuthOption],
    ) -> Result<CredType, MsalError> {
        let payload = json!({
            "username": username,
            "isOtherIdpSupported": true,
            "checkPhones": true,
            "isRemoteNGCSupported": options.contains(&AuthOption::Passwordless),
            "isCookieBannerShown": false,
            "isFidoSupported": options.contains(&AuthOption::Fido),
            "originalRequest": &auth_config.sctx,
            "flowToken": &auth_config.sft,
        });

        let url = match &auth_config.url_get_credential_type {
            Some(url) => url.to_string(),
            None => format!("{}/GetCredentialType", self.authority()),
        };

        let resp = self
            .client()
            .post(url)
            .header(header::CONTENT_TYPE, "application/json; charset=UTF-8")
            .header("client-request-id", request_id)
            .header(header::USER_AGENT, FIDO_USER_AGENT)
            .json(&payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let json_resp: CredType = resp
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

    async fn request_auth_config_internal(
        &self,
        scopes: Vec<&str>,
        request_id: &str,
        resource: Option<&str>,
        mfa: bool,
    ) -> Result<AuthConfig, MsalError> {
        let scope = format!("openid profile {}", scopes.join(" "));
        let redirect_uri = self.app.get_auth_redirect_uri(None, resource);
        let caller_app_redirect_uri = self
            .app
            .get_auth_redirect_uri(Some(LINUX_BROKER_APP_ID), resource);
        let mut params = vec![
            ("client_id", self.client_id()),
            ("response_type", "code"),
            ("redirect_uri", redirect_uri.as_str()),
            ("client-request-id", request_id),
            ("prompt", "login"),
            ("scope", &scope),
            ("response_mode", "query"),
            ("sso_reload", "True"),
            (
                "resource",
                (resource.unwrap_or("https://graph.microsoft.com")),
            ),
            ("caller_app_client_id", LINUX_BROKER_APP_ID),
            ("caller_app_redirect_uri", caller_app_redirect_uri.as_str()),
        ];
        // This will almost always be true. We have to disable it for password
        // changes though.
        if mfa {
            params.push(("amr_values", "ngcmfa"));
        }
        let url = Url::parse_with_params(
            &format!("{}/oauth2/authorize", self.authority()),
            &params.to_vec(),
        )
        .map_err(|e| MsalError::URLFormatFailed(format!("{}", e)))?;

        let resp = self
            .client()
            .get(url)
            .header(header::USER_AGENT, FIDO_USER_AGENT)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            self.parse_auth_config(
                &resp.text().await.map_err(|e| {
                    MsalError::GeneralFailure(format!("Failed parsing auth config: {}", e))
                })?,
                true,
                false,
            )
        } else {
            Err(MsalError::GeneralFailure(
                "Failed requesting auth config".to_string(),
            ))
        }
    }

    async fn mfa_begin_auth_internal(
        &self,
        mfa_method: &str,
        url_begin_auth: &str,
        ctx: &str,
        flow_token: &str,
        canary: &str,
    ) -> Result<AuthResponse, MsalError> {
        let payload = json!({
            "AuthMethodId": mfa_method,
            "ctx": ctx,
            "flowToken": flow_token,
            "Method": "BeginAuth",
        });

        let resp = self
            .client()
            .post(url_begin_auth)
            .header(header::USER_AGENT, FIDO_USER_AGENT)
            .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
            .header("canary", canary)
            .json(&payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let text = resp
                .text()
                .await
                .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?;
            let auth_response: AuthResponse =
                json_from_str(&text).map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            if auth_response.success {
                Ok(auth_response)
            } else if let Some(msg) = auth_response.message {
                Err(MsalError::GeneralFailure(msg))
            } else {
                Err(MsalError::GeneralFailure("BeginAuth failed".to_string()))
            }
        } else {
            Err(MsalError::GeneralFailure(
                "BeginAuth Authentication request failed".to_string(),
            ))
        }
    }

    async fn await_working(&self, mut resp: Response) -> Result<(String, Response), MsalError> {
        // We have to read the response in chunks, because Response.text()
        // consumes the Response object.
        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?
        {
            body.extend(&chunk);
        }
        let mut text = String::from_utf8(body)
            .map_err(|e| MsalError::GeneralFailure(format!("UTF-8 error: {}", e)))?;
        for _ in 0..10 {
            if !text.contains("Click Submit to continue")
                && !text.contains("Working...")
                && !text.contains("Click here to finish the authorization process")
                && !text.contains("<input type=\"submit\"")
            {
                return Ok((text, resp));
            }
            sleep(Duration::from_secs(1));
            let (post_url, form_data) = tokio::task::spawn_blocking(
                move || -> Result<(String, HashMap<String, String>), MsalError> {
                    let document = Html::parse_document(&text);
                    let form_selector = Selector::parse("form")
                        .map_err(|e| MsalError::InvalidParse(format!("{:?}", e)))?;
                    let input_selector = Selector::parse("input")
                        .map_err(|e| MsalError::InvalidParse(format!("{:?}", e)))?;

                    let form = document
                        .select(&form_selector)
                        .next()
                        .ok_or(MsalError::InvalidParse("Document parse failed".to_string()))?;
                    let post_url = form
                        .value()
                        .attr("action")
                        .ok_or(MsalError::InvalidParse("Form action not found".to_string()))?;

                    let mut form_data = HashMap::new();

                    for input in form.select(&input_selector) {
                        if let Some(name) = input.value().attr("name") {
                            if let Some(value) = input.value().attr("value") {
                                form_data.insert(name.to_string(), value.to_string());
                            }
                        }
                    }

                    Ok((post_url.to_string(), form_data))
                },
            )
            .await
            .map_err(|e| MsalError::InvalidParse(format!("{:?}", e)))??;

            resp = self
                .client()
                .post(post_url)
                .form(&form_data)
                .send()
                .await
                .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
            let mut body = Vec::new();
            while let Some(chunk) = resp
                .chunk()
                .await
                .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?
            {
                body.extend(&chunk);
            }
            text = String::from_utf8(body)
                .map_err(|e| MsalError::GeneralFailure(format!("UTF-8 error: {}", e)))?;
        }
        Err(MsalError::GeneralFailure(
            "Pending request timed out after 10 seconds".to_string(),
        ))
    }

    async fn auth_code_intercept_internal(
        &self,
        url: &str,
        payload: String,
    ) -> Result<String, MsalError> {
        let mut resp = self
            .client()
            .post(url)
            .header(header::USER_AGENT, env!("CARGO_PKG_NAME"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        let text;
        (text, resp) = self.await_working(resp).await?;
        if resp.status().is_redirection() {
            let redirect = resp.headers()["location"]
                .to_str()
                .map_err(|e| MsalError::InvalidParse(format!("{}", e)))?;
            let url =
                Url::parse(redirect).map_err(|e| MsalError::InvalidParse(format!("{}", e)))?;
            let (_, code) =
                url.query_pairs()
                    .find(|(k, _)| k == "code")
                    .ok_or(MsalError::InvalidParse(
                        "Authorization code missing from redirect".to_string(),
                    ))?;
            Ok(code.to_string())
        } else if resp.status().is_success() {
            // MS may have returned an AuthConfig here with an error attached.
            // Return the error from that AuthConfig if possible. If a required
            // password change is indicated, raise an error.
            match self.parse_auth_config(&text, false, false) {
                #[cfg(feature = "changepassword")]
                Err(MsalError::ChangePassword) => return Err(MsalError::ChangePassword),
                Err(MsalError::AADSTSError(e)) => return Err(MsalError::AADSTSError(e)),
                _ => return Err(MsalError::GeneralFailure(text)),
            }
        } else {
            Err(MsalError::GeneralFailure(
                "ProcessAuth Authorization request failed".to_string(),
            ))
        }
    }

    async fn request_authorization_passwordless_internal(
        &self,
        username: &str,
        flow: &MFAAuthContinue,
    ) -> Result<String, MsalError> {
        let entropy = format!(
            "{}",
            flow.entropy
                .ok_or(MsalError::GeneralFailure("Missing entropy".to_string()))?
        );
        let params = [
            ("code", &flow.session_id),
            ("psRNGCSLK", &flow.session_id),
            ("login", &username.to_string()),
            ("loginfmt", &username.to_string()),
            ("psRNGCEntropy", &entropy),
            ("flowToken", &flow.flow_token),
            ("canary", &flow.canary),
            ("ctx", &flow.ctx),
        ];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, url_encode(v)))
            .collect::<Vec<String>>()
            .join("&");

        let url = match &flow.url_post.starts_with('/') {
            true => {
                let authority = self.authority().to_string();
                let index = authority.rfind('/').ok_or(MsalError::GeneralFailure(
                    "Failed to splice auth config url".to_string(),
                ))?;
                format!("{}/{}", &authority[..index], &flow.url_post)
            }
            false => flow.url_post.clone(),
        };

        let mut resp = self
            .client()
            .post(url)
            .header(header::USER_AGENT, env!("CARGO_PKG_NAME"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        let _text;
        (_text, resp) = self.await_working(resp).await?;
        if resp.status().is_redirection() {
            let redirect = resp.headers()["location"]
                .to_str()
                .map_err(|e| MsalError::InvalidParse(format!("{}", e)))?;
            let url =
                Url::parse(redirect).map_err(|e| MsalError::InvalidParse(format!("{}", e)))?;
            let (_, code) =
                url.query_pairs()
                    .find(|(k, _)| k == "code")
                    .ok_or(MsalError::InvalidParse(
                        "Authorization code missing from redirect".to_string(),
                    ))?;
            Ok(code.to_string())
        } else {
            Err(MsalError::GeneralFailure(
                "ProcessAuth Authorization request failed".to_string(),
            ))
        }
    }

    async fn request_authorization_internal(
        &self,
        username: &str,
        flow: &MFAAuthContinue,
    ) -> Result<String, MsalError> {
        let mfa_method = match flow.mfa_method.as_str() {
            // ConsolidatedTelephony simply means OneWaySMS internally to Azure,
            // it seems. If we don't swap them during the ProcessAuth though,
            // this request is rejected. I observed this odd behavior in a
            // browser auth to Azure also.
            "ConsolidatedTelephony" => "OneWaySMS".to_string(),
            other => other.to_string(),
        };
        let params = [
            ("request", &flow.ctx),
            ("mfaAuthMethod", &mfa_method),
            ("login", &username.to_string()),
            ("flowToken", &flow.flow_token),
            ("canary", &flow.canary),
        ];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, url_encode(v)))
            .collect::<Vec<String>>()
            .join("&");

        self.auth_code_intercept_internal(&flow.url_post, payload)
            .await
    }

    async fn exchange_authorization_code_for_access_token_internal(
        &self,
        authorization_code: String,
        resource: Option<&str>,
        custom_redirect_uri: Option<&str>,
    ) -> Result<UserToken, MsalError> {
        let redirect_uri = if let Some(custom_redirect_uri) = custom_redirect_uri {
            custom_redirect_uri.to_string()
        } else {
            self.app.get_auth_redirect_uri(None, resource)
        };
        let params = [
            ("client_id", self.client_id()),
            ("grant_type", "authorization_code"),
            ("code", &authorization_code),
            ("redirect_uri", &redirect_uri),
        ];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<String>>()
            .join("&");

        let resp = self
            .client()
            .post(format!("{}/oauth2/token", self.authority()))
            .header(header::USER_AGENT, env!("CARGO_PKG_NAME"))
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

    async fn exchange_fido_assertion_for_auth_code_internal(
        &self,
        assertion: &str,
        flow: &mut MFAAuthContinue,
    ) -> Result<String, MsalError> {
        let cross_domain_canary = flow.cross_domain_canary.clone().ok_or(MsalError::Missing(
            "sCrossDomainCanary missing from response".to_string(),
        ))?;
        let params = [
            ("type", "23"),
            ("ps", "23"),
            ("assertion", assertion),
            ("lmcCanary", &cross_domain_canary),
            ("hpgrequestid", &flow.session_id),
            ("ctx", &flow.ctx),
            ("canary", &flow.canary),
            ("flowToken", &flow.flow_token),
        ];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<String>>()
            .join("&");

        let mut resp = self
            .client()
            .post(&flow.url_post)
            .header(header::USER_AGENT, env!("CARGO_PKG_NAME"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        let text;
        (text, resp) = self.await_working(resp).await?;
        if resp.status().is_redirection() {
            let document = Html::parse_document(&text);
            let selector = Selector::parse("a[href]").map_err(|_| {
                MsalError::RequestFailed("Failed parsing auth code response".to_string())
            })?;
            if let Some(element) = document.select(&selector).next() {
                if let Some(href_encoded) = element.value().attr("href") {
                    let href = percent_decode_str(href_encoded)
                        .decode_utf8()
                        .map_err(|e| {
                            MsalError::URLFormatFailed(format!("Failed decoding url: {:?}", e))
                        })?;
                    if let Ok(url) = Url::parse(&href) {
                        return url
                            .query_pairs()
                            .find_map(|(key, value)| {
                                if key == "code" {
                                    Some(value.into_owned())
                                } else {
                                    None
                                }
                            })
                            .ok_or(MsalError::GeneralFailure(
                                "Authorization code not found".to_string(),
                            ));
                    }
                }
            }
            Err(MsalError::GeneralFailure(
                "Authorization code not found".to_string(),
            ))
        } else {
            let document = Html::parse_document(&text);
            let selector = Selector::parse("a[href]").map_err(|_| {
                MsalError::RequestFailed(format!("Failed parsing error response: {}", text))
            })?;
            if let Some(element) = document.select(&selector).next() {
                if let Some(href_encoded) = element.value().attr("href") {
                    let href = percent_decode_str(href_encoded)
                        .decode_utf8()
                        .map_err(|e| {
                            MsalError::URLFormatFailed(format!("Failed decoding url: {:?}", e))
                        })?;
                    if let Ok(url) = Url::parse(&href) {
                        if let Some(error) = url.query_pairs().find_map(|(key, value)| {
                            if key == "error_description" {
                                Some(value.to_string())
                            } else {
                                None
                            }
                        }) {
                            return Err(MsalError::RequestFailed(error));
                        }
                    }
                }
            }
            Err(MsalError::RequestFailed(format!(
                "Failed parsing error response: {}",
                text
            )))
        }
    }

    /// Obtain token by a MFA flow object.
    ///
    /// # Arguments
    ///
    /// * `username` - Typically a UPN in the form of an email address.
    ///
    /// * `auth_data` - An optional token received for the MFA flow (some MFA
    ///   flows do not require input). For a FidoKey flow, this will be a fido
    ///   assertion.
    ///
    /// * `poll_attempt` - The polling attempt number.
    ///
    /// * `flow` - A MFAAuthContinue previously generated by
    ///   initiate_acquire_token_by_mfa_flow.
    ///
    /// # Returns
    ///
    /// * Success: A UserToken containing an access_token.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn acquire_token_by_mfa_flow(
        &self,
        username: &str,
        auth_data: Option<&str>,
        poll_attempt: Option<u32>,
        flow: &mut MFAAuthContinue,
    ) -> Result<UserToken, MsalError> {
        if let Some(dag_flow) = &flow.dag {
            // The initiate phase already fell back to a DAG
            return match self.acquire_token_by_device_flow(dag_flow.clone()).await {
                Ok(token) => {
                    if token.spn()?.to_lowercase() != username.to_lowercase() {
                        return Err(MsalError::GeneralFailure(
                            "The authenticating user did not match".to_string(),
                        ));
                    }
                    // Exchange the Portal MFA token for the requested token
                    let token = if let Some(resource) = &flow.resource {
                        let scope = format!("{}/.default", resource);
                        self.acquire_token_by_refresh_token(&token.refresh_token, vec![&scope])
                            .await?
                    } else {
                        token
                    };
                    Ok(token)
                }
                Err(MsalError::AcquireTokenFailed(ref resp)) => {
                    if resp.error_codes.contains(&AUTH_PENDING) {
                        info!("Polling for acquire_token_by_device_flow");
                        return Err(MsalError::MFAPollContinue);
                    }
                    error!("{}", resp.error_description);
                    Err(MsalError::AcquireTokenFailed(resp.clone()))
                }
                Err(e) => Err(e),
            };
        }
        match auth_data {
            Some(auth_data) => {
                if flow.mfa_method == "FidoKey" {
                    let auth_code = self
                        .exchange_fido_assertion_for_auth_code_internal(auth_data, flow)
                        .await?;
                    self.exchange_authorization_code_for_access_token_internal(
                        auth_code,
                        flow.resource.as_deref(),
                        None,
                    )
                    .await
                } else {
                    let payload = json!({
                        "AdditionalAuthData": auth_data.trim(),
                        "AuthMethodId": &flow.mfa_method,
                        "SessionId": &flow.session_id,
                        "FlowToken": &flow.flow_token,
                        "Ctx": &flow.ctx,
                        "Method": "EndAuth",
                    });
                    let url_end_auth = match &flow.url_end_auth {
                        Some(url_end_auth) => url_end_auth,
                        None => {
                            return Err(MsalError::GeneralFailure(
                                "urlEndAuth is missing".to_string(),
                            ))
                        }
                    };

                    let resp = self
                        .client()
                        .post(url_end_auth)
                        .header(header::USER_AGENT, env!("CARGO_PKG_NAME"))
                        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
                        .header("canary", &flow.canary)
                        .json(&payload)
                        .send()
                        .await
                        .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
                    if resp.status().is_success() {
                        let text = resp
                            .text()
                            .await
                            .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?;
                        // Check for an error in an auth Config
                        if let Ok(auth_config) = self.parse_auth_config(&text, false, false) {
                            if let Some(service_exception_msg) = auth_config.service_exception_msg {
                                return Err(MsalError::GeneralFailure(
                                    service_exception_msg.to_string(),
                                ));
                            }
                        }
                        // Parse what should be a json response otherwise
                        let auth_response: AuthResponse = json_from_str(&text)
                            .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
                        if auth_response.success {
                            flow.ctx = auth_response.ctx;
                            flow.flow_token = auth_response.flow_token;
                            let auth_code =
                                self.request_authorization_internal(username, flow).await?;
                            self.exchange_authorization_code_for_access_token_internal(
                                auth_code,
                                flow.resource.as_deref(),
                                None,
                            )
                            .await
                        } else if let Some(msg) = auth_response.message {
                            Err(MsalError::GeneralFailure(msg))
                        } else {
                            Err(MsalError::GeneralFailure("EndAuth failed".to_string()))
                        }
                    } else {
                        Err(MsalError::GeneralFailure(
                            "EndAuth Authentication request failed".to_string(),
                        ))
                    }
                }
            }
            None => {
                let resp = if let Some(url_end_auth) = &flow.url_end_auth {
                    let url = Url::parse_with_params(
                        url_end_auth,
                        [
                            ("authMethodId", &flow.mfa_method),
                            (
                                "pollCount",
                                &format!(
                                    "{}",
                                    poll_attempt.ok_or(MsalError::GeneralFailure(
                                        "Poll attempt required".to_string()
                                    ))?
                                ),
                            ),
                        ],
                    )
                    .map_err(|e| MsalError::URLFormatFailed(format!("{}", e)))?;

                    self.client()
                        .get(url)
                        .header(header::USER_AGENT, env!("CARGO_PKG_NAME"))
                        .header("x-ms-sessionId", &flow.session_id)
                        .header("x-ms-flowToken", &flow.flow_token)
                        .header("x-ms-ctx", &flow.ctx)
                        .send()
                        .await
                        .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?
                } else if let Some(url_session_state) = &flow.url_session_state {
                    let url =
                        Url::parse_with_params(url_session_state, [("code", &flow.session_id)])
                            .map_err(|e| MsalError::URLFormatFailed(format!("{}", e)))?;
                    let payload = json!({
                        "DeviceCode": &flow.session_id,
                    });

                    self.client()
                        .post(url)
                        .header(header::USER_AGENT, env!("CARGO_PKG_NAME"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .header("canary", &flow.canary)
                        .json(&payload)
                        .send()
                        .await
                        .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?
                } else {
                    return Err(MsalError::GeneralFailure("Request invalid".to_string()));
                };
                if resp.status().is_success() {
                    let text = resp
                        .text()
                        .await
                        .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?;
                    if flow.url_end_auth.is_some() {
                        // Check for an error in an auth Config
                        if let Ok(auth_config) = self.parse_auth_config(&text, false, false) {
                            if let Some(service_exception_msg) = auth_config.service_exception_msg {
                                return Err(MsalError::GeneralFailure(
                                    service_exception_msg.to_string(),
                                ));
                            }
                        }
                        // Parse what should be a json response otherwise
                        let auth_response: AuthResponse = json_from_str(&text)
                            .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
                        if auth_response.success {
                            flow.ctx = auth_response.ctx;
                            flow.flow_token = auth_response.flow_token;
                            let auth_code =
                                self.request_authorization_internal(username, flow).await?;
                            return self
                                .exchange_authorization_code_for_access_token_internal(
                                    auth_code,
                                    flow.resource.as_deref(),
                                    None,
                                )
                                .await;
                        } else if !auth_response.retry.ok_or(MsalError::GeneralFailure(
                            "Auth response Retry missing".to_string(),
                        ))? {
                            if let Some(msg) = auth_response.message {
                                return Err(MsalError::GeneralFailure(msg));
                            } else {
                                return Err(MsalError::GeneralFailure(
                                    "EndAuth failed".to_string(),
                                ));
                            }
                        }
                        Err(MsalError::MFAPollContinue)
                    } else {
                        let status: DeviceCodeStatus = json_from_str(&text)
                            .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
                        if status.authorization_state == 0 {
                            Err(MsalError::MFAPollContinue)
                        } else if status.authorization_state == 2 {
                            let auth_code = self
                                .request_authorization_passwordless_internal(username, flow)
                                .await?;
                            return self
                                .exchange_authorization_code_for_access_token_internal(
                                    auth_code,
                                    flow.resource.as_deref(),
                                    None,
                                )
                                .await;
                        } else {
                            return Err(MsalError::GeneralFailure(text));
                        }
                    }
                } else {
                    Err(MsalError::GeneralFailure(
                        "EndAuth Authentication request failed".to_string(),
                    ))
                }
            }
        }
    }

    /// Obtain token interactively.
    ///
    /// # Arguments
    ///
    /// * `username` - Typically a UPN in the form of an email address.
    ///
    /// * `resource` - A resource for obtaining an access token.
    ///   Default is the MS Graph API (00000002-0000-0000-c000-000000000000).
    ///
    /// # Returns
    ///
    /// * Success: A UserToken containing an access_token.
    /// * Failure: An MsalError, indicating the failure.
    #[cfg(feature = "interactive")]
    pub async fn acquire_token_interactive(
        &self,
        username: &str,
        resource: Option<&str>,
    ) -> Result<UserToken, MsalError> {
        // We use this redirect because it's the only approved https redirect
        let broker_redirect = "https://login.microsoftonline.com/applebroker/msauth";
        let params = [
            ("client_id", self.client_id()),
            ("login_hint", username),
            ("response_type", "code"),
            ("redirect_uri", broker_redirect),
            ("response_mode", "query"),
            (
                "resource",
                (resource.unwrap_or("https://graph.microsoft.com")),
            ),
            ("amr_values", "ngcmfa"),
        ];
        let url = Url::parse_with_params(
            &format!("{}/oauth2/authorize", self.authority()),
            &params.to_vec(),
        )
        .map_err(|e| MsalError::URLFormatFailed(format!("{}", e)))?;

        let application = Application::initialize(&ApplicationSettings::default())
            .map_err(|e| MsalError::GeneralFailure(format!("{:?}", e)))?;
        let runtime = application.start();

        let (tx, rx) = channel();
        runtime.run_async(|app| async move {
            let mut bwb = BrowserWindowBuilder::new(Source::Url(url.to_string()));
            bwb.dev_tools(false);
            bwb.size(800, 600);
            bwb.title("Azure Entra Id Interactive Authentication");
            let bw = bwb.build_async(&app).await;
            bw.show();

            while !bw.url().contains(broker_redirect) {
                app.sleep(Duration::from_millis(100)).await;
            }

            let redirect = bw.url().to_string();
            tx.send(redirect).unwrap_or_else(|e| {
                error!("{:?}", e);
            });
            app.exit(0);
        });

        let redirect = rx.recv_timeout(Duration::from_secs(900)).map_err(|e| {
            error!("{:?}", e);
            MsalError::GeneralFailure(
                "Failed receiving redirect from interactive acquire".to_string(),
            )
        })?;
        let url = Url::parse(&redirect).map_err(|e| MsalError::InvalidParse(format!("{}", e)))?;
        let (_, auth_code) =
            url.query_pairs()
                .find(|(k, _)| k == "code")
                .ok_or(MsalError::InvalidParse(
                    "Authorization code missing from redirect".to_string(),
                ))?;

        application.finish();

        self.exchange_authorization_code_for_access_token_internal(
            auth_code.to_string(),
            resource,
            Some(broker_redirect),
        )
        .await
    }

    fn get_auth_redirect_uri(&self, client_id: Option<&str>, resource: Option<&str>) -> String {
        self.app.get_auth_redirect_uri(client_id, resource)
    }
}

#[cfg(feature = "broker")]
pub struct BrokerClientApplication {
    app: PublicClientApplication,
    transport_key: Option<LoadableMsOapxbcRsaKey>,
    cert_key: Option<LoadableIdentityKey>,
    on_behalf_of_client_id: Option<String>,
}

#[cfg(feature = "broker")]
impl BrokerClientApplication {
    /// Create an instance of an application.
    ///
    /// # Arguments
    ///
    /// * `authority` - A URL that identifies a token authority. It should
    ///   be of the format <https://login.microsoftonline.com/your_tenant> By
    ///   default, we will use <https://login.microsoftonline.com/common>.
    ///
    /// * `client_id` - The optional client id of an app which you may
    ///   register in Azure Entra Id. If not specified, certain group
    ///   attributes will be unresolvable. This app may also delegate
    ///   permissions for your logon script access token.
    ///
    /// * `transport_key` - An optional LoadableMsOapxbcRsaKey transport key
    ///   from enrolling the device.
    ///
    /// * `cert_key` - An optional LoadableIdentityKey which was used to create
    ///   the enrollment CSR.
    ///
    /// NOTE: If `transport_key` and `cert_key` are not provided from a previous
    /// device enrollment, then enrollment will be required.
    pub fn new(
        authority: Option<&str>,
        client_id: Option<&str>,
        transport_key: Option<LoadableMsOapxbcRsaKey>,
        cert_key: Option<LoadableIdentityKey>,
    ) -> Result<Self, MsalError> {
        Ok(BrokerClientApplication {
            app: PublicClientApplication::new(BROKER_APP_ID, authority)?,
            transport_key,
            cert_key,
            on_behalf_of_client_id: client_id.map(|s| s.to_string()),
        })
    }

    fn client(&self) -> &Client {
        self.app.client()
    }

    fn authority(&self) -> &str {
        self.app.authority()
    }

    fn transport_key(
        &self,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<MsOapxbcRsaKey, MsalError> {
        match &self.transport_key {
            Some(transport_key) => {
                let transport_key = tpm.msoapxbc_rsa_key_load(machine_key, transport_key)
            .map_err(|e| {
                MsalError::TPMFail(format!("Failed to load IdentityKey: {:?}", e))
            })?;
                Ok(transport_key)
            },
            None => Err(MsalError::ConfigError("The transport key was not found. Please provide the transport key during initialize of the BrokerClientApplication, or enroll the device.".to_string())),
        }
    }

    /// Set the enrollment transport key
    ///
    /// # Arguments
    ///
    /// * `transport_key` - An optional LoadableMsOapxbcRsaKey transport key
    ///   from enrolling the device.
    pub fn set_transport_key(&mut self, transport_key: Option<LoadableMsOapxbcRsaKey>) {
        self.transport_key = transport_key;
    }

    fn cert_key(
        &self,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<IdentityKey, MsalError> {
        match &self.cert_key {
            Some(cert_key) => {
                let cert_key = tpm.identity_key_load(machine_key, None, cert_key)
            .map_err(|e| {
                MsalError::TPMFail(format!("Failed to load IdentityKey: {:?}", e))
            })?;
                Ok(cert_key)
            },
            None => Err(MsalError::ConfigError("The certificate key was not found. Please provide the certificate key during initialize of the BrokerClientApplication, or enroll the device.".to_string())),
        }
    }

    /// Set the enrollment certificate key
    ///
    /// # Arguments
    ///
    /// * `cert_key` - An optional LoadableIdentityKey which was used to create
    ///   the enrollment CSR.
    pub fn set_cert_key(&mut self, cert_key: Option<LoadableIdentityKey>) {
        self.cert_key = cert_key;
    }

    /// Enroll the device in the directory.
    ///
    /// # Arguments
    ///
    /// * `token` - Token obtained via either
    ///   acquire_token_by_username_password_for_device_enrollment
    ///   or acquire_token_by_device_flow.
    ///
    /// * `domain` - The domain the device is to be enrolled in.
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `machine_key` - The TPM MachineKey associated with this application.
    ///
    /// # Returns
    ///
    /// * Success: A LoadableMsOapxbcRsaKey transport key, a LoadableIdentityKey certificate key,
    ///   and a `device_id`.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn enroll_device(
        &mut self,
        refresh_token: &str,
        attrs: EnrollAttrs,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<(LoadableMsOapxbcRsaKey, LoadableIdentityKey, String), MsalError> {
        // Acquire an actual enrollment token from the token received.
        let token = self
            .acquire_token_by_refresh_token_for_device_enrollment(refresh_token)
            .await?;
        // Create the transport and cert keys
        let loadable_cert_key = tpm
            .identity_key_create(machine_key, None, KeyAlgorithm::Rsa2048)
            .map_err(|e| MsalError::TPMFail(format!("Failed creating certificate key: {:?}", e)))?;
        let loadable_transport_key = tpm
            .msoapxbc_rsa_key_create(machine_key)
            .map_err(|e| MsalError::TPMFail(format!("Failed creating tranport key: {:?}", e)))?;
        self.transport_key = Some(loadable_transport_key.clone());

        // Create the CSR
        let csr_der = match tpm.identity_key_certificate_request(
            machine_key,
            None,
            &loadable_cert_key,
            "7E980AD9-B86D-4306-9425-9AC066FB014A",
        ) {
            Ok(csr_der) => csr_der,
            Err(e) => return Err(MsalError::TPMFail(format!("Failed creating CSR: {:?}", e))),
        };

        // Load the transport key
        let transport_key = match tpm.msoapxbc_rsa_key_load(machine_key, &loadable_transport_key) {
            Ok(transport_key) => transport_key,
            Err(e) => {
                return Err(MsalError::TPMFail(format!(
                    "Failed loading id key: {:?}",
                    e
                )))
            }
        };
        let transport_key_der = match tpm.msoapxbc_rsa_public_as_der(&transport_key) {
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

        let (cert, device_id) = match &token.access_token {
            Some(access_token) => {
                self.enroll_device_internal(access_token, attrs, &transport_key_rsa, &csr_der)
                    .await?
            }
            None => {
                return Err(MsalError::GeneralFailure(
                    "Access token not found".to_string(),
                ))
            }
        };

        let new_loadable_cert_key = match tpm.identity_key_associate_certificate(
            machine_key,
            None,
            &loadable_cert_key,
            &cert
                .to_der()
                .map_err(|e| MsalError::TPMFail(format!("{}", e)))?,
        ) {
            Ok(loadable_cert_key) => loadable_cert_key,
            Err(e) => {
                return Err(MsalError::TPMFail(format!(
                    "Failed creating loadable identity key: {:?}",
                    e
                )))
            }
        };

        self.cert_key = Some(new_loadable_cert_key.clone());
        Ok((
            loadable_transport_key,
            new_loadable_cert_key,
            device_id.to_string(),
        ))
    }

    async fn enroll_device_internal(
        &self,
        access_token: &str,
        attrs: EnrollAttrs,
        transport_key: &Rsa<Public>,
        csr_der: &Vec<u8>,
    ) -> Result<(X509, String), MsalError> {
        let services = Services::new(access_token, &attrs.target_domain).await?;
        services
            .enroll_device(access_token, attrs, transport_key, csr_der)
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
    /// * `request_resource` - A resource for obtaining an access token.
    ///   Default is the MS Graph API (00000002-0000-0000-c000-000000000000).
    ///
    /// * `on_behalf_of_client_id`: Request a resource or scope on behalf of
    ///   the specified client_id. Optional. This option requires libhimmelblau
    ///   be built with the `on_behalf_of` feature.
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `machine_key` - The TPM MachineKey associated with this application.
    ///
    /// # Returns
    /// * Success: A UserToken containing an access_token.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn acquire_token_by_username_password(
        &self,
        username: &str,
        password: &str,
        scopes: Vec<&str>,
        request_resource: Option<String>,
        #[cfg(feature = "on_behalf_of")] on_behalf_of_client_id: Option<&str>,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<UserToken, MsalError> {
        let v2_endpoint = !scopes.is_empty();
        if !scopes.is_empty() && request_resource.is_some() {
            return Err(MsalError::GeneralFailure(
                "Scopes cannot be specified with a request_resource".to_string(),
            ));
        }
        let prt = self
            .acquire_user_prt_by_username_password_internal(username, password, tpm, machine_key)
            .await?;
        let transport_key = self.transport_key(tpm, machine_key)?;
        let session_key = prt.session_key()?;
        let mut token = self
            .exchange_prt_for_access_token_internal(
                &prt,
                scopes.clone(),
                v2_endpoint,
                tpm,
                machine_key,
                &session_key,
                request_resource,
                #[cfg(feature = "on_behalf_of")]
                on_behalf_of_client_id,
            )
            .await?;
        token.client_info = prt.client_info.clone();
        token.prt = Some(self.seal_user_prt(&prt, tpm, &transport_key)?);
        Ok(token)
    }

    /// Acquire token(s) based on a refresh token (RT) obtained from elsewhere.
    ///
    /// # Arguments
    ///
    /// * `refresh_token` - The old refresh token, as a string.
    ///
    /// * `scopes` - The scopes associated with this old RT.
    ///
    /// * `request_resource` - A resource for obtaining an access token.
    ///   Default is the MS Graph API (00000002-0000-0000-c000-000000000000).
    ///
    /// * `on_behalf_of_client_id`: Request a resource or scope on behalf of
    ///   the specified client_id. Optional. This option requires libhimmelblau
    ///   be built with the `on_behalf_of` feature.
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `machine_key` - The TPM MachineKey associated with this application.
    ///
    /// # Returns
    /// * Success: A UserToken, which means migration was successful.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn acquire_token_by_refresh_token(
        &self,
        refresh_token: &str,
        scopes: Vec<&str>,
        request_resource: Option<String>,
        #[cfg(feature = "on_behalf_of")] on_behalf_of_client_id: Option<&str>,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<UserToken, MsalError> {
        let prt = self
            .acquire_user_prt_by_refresh_token_internal(refresh_token, tpm, machine_key)
            .await?;
        let transport_key = self.transport_key(tpm, machine_key)?;
        let session_key = prt.session_key()?;
        let v2_endpoint = !scopes.is_empty();
        if !scopes.is_empty() && request_resource.is_some() {
            return Err(MsalError::GeneralFailure(
                "Scopes cannot be specified with a request_resource".to_string(),
            ));
        }
        let mut token = self
            .exchange_prt_for_access_token_internal(
                &prt,
                scopes.clone(),
                v2_endpoint,
                tpm,
                machine_key,
                &session_key,
                request_resource,
                #[cfg(feature = "on_behalf_of")]
                on_behalf_of_client_id,
            )
            .await?;
        token.client_info = prt.client_info.clone();
        token.prt = Some(self.seal_user_prt(&prt, tpm, &transport_key)?);
        Ok(token)
    }

    /// Gets a token for enrollment via user credentials.
    ///
    /// # Arguments
    ///
    /// * `username` - Typically a UPN in the form of an email address.
    ///
    /// * `password` - The password.
    ///
    /// # Returns
    /// * Success: A UserToken containing an access_token.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn acquire_token_by_username_password_for_device_enrollment(
        &self,
        username: &str,
        password: &str,
    ) -> Result<UserToken, MsalError> {
        let drs_scope = "https://enrollment.manage.microsoft.com/.default";
        self.app
            .acquire_token_by_username_password(username, password, vec![drs_scope])
            .await
    }

    async fn acquire_token_by_refresh_token_for_device_enrollment(
        &self,
        refresh_token: &str,
    ) -> Result<UserToken, MsalError> {
        let drs_scope = format!("{}/.default", DRS_APP_ID);
        self.app
            .acquire_token_by_refresh_token(refresh_token, vec![&drs_scope])
            .await
    }

    /// Initiate a Device Flow instance for enrollment, which will be
    /// used in acquire_token_by_device_flow.
    ///
    /// # Returns
    ///
    /// * Success: A DeviceAuthorizationResponse containing a user_code key,
    ///   among others
    /// * Failure: An MsalError, indicating the failure.
    pub async fn initiate_device_flow_for_device_enrollment(
        &self,
    ) -> Result<DeviceAuthorizationResponse, MsalError> {
        let portal_scope = format!("{}/.default", AZURE_PORTAL_APP_ID);
        self.app.initiate_device_flow(vec![&portal_scope]).await
    }

    /// Obtain token for enrollment by a device flow object, with customizable
    /// polling effect.
    ///
    /// # Arguments
    ///
    /// * `flow` - A DeviceAuthorizationResponse previously generated by
    ///   initiate_device_flow.
    ///
    /// # Returns
    ///
    /// * Success: A UserToken containing an access_token.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn acquire_token_by_device_flow(
        &self,
        flow: DeviceAuthorizationResponse,
    ) -> Result<UserToken, MsalError> {
        let portal_token = self.app.acquire_token_by_device_flow(flow).await?;
        let drs_scope = "https://enrollment.manage.microsoft.com/.default";
        self.app
            .acquire_token_by_refresh_token(&portal_token.refresh_token, vec![&drs_scope])
            .await
    }

    /// Check if a user exists in Azure Entra ID
    ///
    /// # Arguments
    ///
    /// * `username` - Typically a UPN in the form of an email address.
    ///
    /// * `options` - Authentication options to enable, such as Fido and
    ///   Passwordless auth.
    ///
    /// # Returns
    /// * Success: An AuthInit object. Call `exists` to get the result.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn check_user_exists(
        &self,
        username: &str,
        options: &[AuthOption],
    ) -> Result<AuthInit, MsalError> {
        let drs_resource = "https://enrollment.manage.microsoft.com/";
        self.app
            .check_user_exists(username, Some(drs_resource), options)
            .await
    }

    /// Initiate an MFA flow for enrollment via user credentials.
    ///
    /// # Arguments
    ///
    /// * `username` - Typically a UPN in the form of an email address.
    ///
    /// * `password` - The password.
    ///
    /// * `options` - Authentication options to enable, such as Fido.
    ///
    /// * `auth_init` - The result of `check_user_exists`, required if called
    ///   prior to `initiate_acquire_token_by_mfa_flow_for_device_enrollment`.
    ///
    /// # Returns
    /// * Success: A MFAAuthContinue containing the information needed to continue the
    ///   authentication flow.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn initiate_acquire_token_by_mfa_flow_for_device_enrollment(
        &self,
        username: &str,
        password: Option<&str>,
        options: &[AuthOption],
        auth_init: Option<AuthInit>,
    ) -> Result<MFAAuthContinue, MsalError> {
        let drs_resource = "https://enrollment.manage.microsoft.com/";
        self.app
            .initiate_acquire_token_by_mfa_flow(
                username,
                password,
                vec![],
                Some(drs_resource),
                options,
                auth_init,
            )
            .await
    }

    /// Obtain token by a MFA flow object.
    ///
    /// # Arguments
    ///
    /// * `username` - Typically a UPN in the form of an email address.
    ///
    /// * `auth_data` - An optional token received for the MFA flow (some MFA
    ///   flows do not require input).
    ///
    /// * `poll_attempt` - The polling attempt number.
    ///
    /// * `flow` - A MFAAuthContinue previously generated by
    ///   initiate_acquire_token_by_mfa_flow.
    ///
    /// # Returns
    ///
    /// * Success: A UserToken containing an access_token.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn acquire_token_by_mfa_flow(
        &self,
        username: &str,
        auth_data: Option<&str>,
        poll_attempt: Option<u32>,
        flow: &mut MFAAuthContinue,
    ) -> Result<UserToken, MsalError> {
        self.app
            .acquire_token_by_mfa_flow(username, auth_data, poll_attempt, flow)
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

        let jwt = builder.build();

        if let Ok(mut debug_jwt) = jwt.from_json::<Value>() {
            debug_jwt["password"] = "**********".into();
            if let Ok(pretty) = to_string_pretty(&debug_jwt) {
                debug!("Username/Password JWT: {}", pretty);
            }
        }

        Ok(jwt)
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
    /// * `machine_key` - The TPM MachineKey associated with this application.
    ///
    /// # Returns
    /// * Success: An encrypted PrimaryRefreshToken, containing a refresh_token and tgt.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn acquire_user_prt_by_username_password(
        &self,
        username: &str,
        password: &str,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<SealedData, MsalError> {
        let prt = self
            .acquire_user_prt_by_username_password_internal(username, password, tpm, machine_key)
            .await?;
        let transport_key = self.transport_key(tpm, machine_key)?;
        self.seal_user_prt(&prt, tpm, &transport_key)
    }

    async fn acquire_user_prt_by_username_password_internal(
        &self,
        username: &str,
        password: &str,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<PrimaryRefreshToken, MsalError> {
        debug!("Acquiring User PRT via Username/Password");

        let jwt = self
            .build_jwt_by_username_password(username, password, None)
            .await?;
        let signed_jwt = self.sign_jwt(&jwt, tpm, machine_key).await?;

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

        let jwt = builder.build();

        if let Ok(mut debug_jwt) = jwt.from_json::<Value>() {
            debug_jwt["refresh_token"] = "**********".into();
            if let Ok(pretty) = to_string_pretty(&debug_jwt) {
                debug!("Refresh Token JWT: {}", pretty);
            }
        }

        Ok(jwt)
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
    /// * `machine_key` - The TPM MachineKey associated with this application.
    ///
    /// # Returns
    /// * Success: An encrypted PrimaryRefreshToken, containing a refresh_token and tgt.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn acquire_user_prt_by_refresh_token(
        &self,
        refresh_token: &str,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<SealedData, MsalError> {
        let prt = self
            .acquire_user_prt_by_refresh_token_internal(refresh_token, tpm, machine_key)
            .await?;
        let transport_key = self.transport_key(tpm, machine_key)?;
        self.seal_user_prt(&prt, tpm, &transport_key)
    }

    async fn acquire_user_prt_by_refresh_token_internal(
        &self,
        refresh_token: &str,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<PrimaryRefreshToken, MsalError> {
        debug!("Acquiring User PRT via Refresh Token");

        let jwt = self.build_jwt_by_refresh_token(refresh_token, None).await?;
        let signed_jwt = self.sign_jwt(&jwt, tpm, machine_key).await?;

        self.acquire_user_prt_jwt(&signed_jwt).await
    }

    async fn sign_jwt(
        &self,
        jwt: &Jws,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<String, MsalError> {
        let cert_key = self.cert_key(tpm, machine_key)?;
        let mut jws_tpm_signer = match JwsTpmSigner::new(tpm, &cert_key) {
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

    async fn acquire_user_prt_jwt(
        &self,
        signed_jwt: &str,
    ) -> Result<PrimaryRefreshToken, MsalError> {
        debug!("Acquiring User PRT via JWT");

        // [MS-OAPXBC] 3.2.5.1.2 POST (Request for Primary Refresh Token)
        let params = [
            ("windows_api_version", "2.0"),
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("request", signed_jwt),
            ("client_info", "1"),
            ("tgt", "true"),
        ];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<String>>()
            .join("&");

        let url = format!("{}/oauth2/token", self.authority());

        let mut debug_payload = params;
        debug_payload[2] = ("request", "**********");
        if let Ok(pretty) = to_string_pretty(&debug_payload) {
            debug!("POST {}: {}", url, pretty);
        }

        let resp = self
            .client()
            .post(url)
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

    async fn sign_session_key_jwt(
        &self,
        jwt: &Jws,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
        session_key: &SessionKey,
    ) -> Result<String, MsalError> {
        let transport_key = self.transport_key(tpm, machine_key)?;
        let signed_jwt = session_key.sign(tpm, &transport_key, jwt)?;

        Ok(format!("{}", signed_jwt))
    }

    /// Given the primary refresh token, this method requests an access token.
    ///
    /// # Arguments
    ///
    /// * `sealed_prt` -  An encrypted primary refresh token that was
    ///   previously received from the server.
    ///
    /// * `scope` - The scope that the client requests for the access token.
    ///
    /// * `request_resource` - A resource for obtaining an access token.
    ///   Default is the MS Graph API (00000002-0000-0000-c000-000000000000).
    ///
    /// * `on_behalf_of_client_id`: Request a resource or scope on behalf of
    ///   the specified client_id. Optional. This option requires libhimmelblau
    ///   be built with the `on_behalf_of` feature.
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `machine_key` - The TPM MachineKey associated with this application.
    ///
    /// # Returns
    /// * Success: A UserToken containing an access_token.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn exchange_prt_for_access_token(
        &self,
        sealed_prt: &SealedData,
        scope: Vec<&str>,
        request_resource: Option<String>,
        #[cfg(feature = "on_behalf_of")] on_behalf_of_client_id: Option<&str>,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<UserToken, MsalError> {
        let v2_endpoint = !scope.is_empty();
        if !scope.is_empty() && request_resource.is_some() {
            return Err(MsalError::GeneralFailure(
                "Scopes cannot be specified with a request_resource".to_string(),
            ));
        }
        let transport_key = self.transport_key(tpm, machine_key)?;
        let prt = self.unseal_user_prt(sealed_prt, tpm, &transport_key)?;
        let session_key = prt.session_key()?;
        self.exchange_prt_for_access_token_internal(
            &prt,
            scope,
            v2_endpoint,
            tpm,
            machine_key,
            &session_key,
            request_resource,
            #[cfg(feature = "on_behalf_of")]
            on_behalf_of_client_id,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn exchange_prt_for_access_token_internal(
        &self,
        prt: &PrimaryRefreshToken,
        scope: Vec<&str>,
        v2_endpoint: bool,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
        session_key: &SessionKey,
        request_resource: Option<String>,
        #[cfg(feature = "on_behalf_of")] on_behalf_of_client_id: Option<&str>,
    ) -> Result<UserToken, MsalError> {
        debug!("Exchanging a PRT for an Access Token");

        let request_id = Uuid::new_v4().to_string();
        let auth_code = self
            .exchange_prt_for_auth_code(
                prt,
                scope.clone(),
                &request_id,
                request_resource.as_deref(),
                v2_endpoint,
                session_key,
                #[cfg(feature = "on_behalf_of")]
                on_behalf_of_client_id,
                tpm,
                machine_key,
            )
            .await?;

        self.exchange_auth_code_for_access_token_internal(
            scope,
            &request_id,
            v2_endpoint,
            auth_code,
            request_resource.as_deref(),
            #[cfg(feature = "on_behalf_of")]
            on_behalf_of_client_id,
        )
        .await
    }

    /// Given the primary refresh token, this method requests a new primary
    /// refresh token
    ///
    /// # Arguments
    ///
    /// * `sealed_prt` -  An encrypted primary refresh token that was
    ///   previously received from the server.
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `machine_key` - The TPM MachineKey associated with this application.
    ///
    /// * `request_tgt` - Whether to include a request for a TGT.
    ///
    /// # Returns
    /// * Success: An encrypted PrimaryRefreshToken, containing a refresh_token
    ///   and optionally a tgt. The session key is copied from the old PRT.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn exchange_prt_for_prt(
        &self,
        sealed_prt: &SealedData,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
        request_tgt: bool,
    ) -> Result<SealedData, MsalError> {
        debug!("Exchanging a PRT for a new PRT");

        let transport_key = self.transport_key(tpm, machine_key)?;
        let prt = self.unseal_user_prt(sealed_prt, tpm, &transport_key)?;
        let session_key = prt.session_key()?;
        let nonce = self.request_nonce().await?;
        let jwt = JwsBuilder::from(
            serde_json::to_vec(&ExchangePRTPayload::new(&prt, &nonce, None, true)?).map_err(
                |e| MsalError::InvalidJson(format!("Failed serializing ExchangePRT JWT: {}", e)),
            )?,
        )
        .set_typ(Some("JWT"))
        .build();

        if let Ok(mut payload) = jwt.from_json::<Value>() {
            payload["refresh_token"] = "**********".into();
            if let Ok(pretty) = to_string_pretty(&payload) {
                debug!("Exchange PRT Payload JWT: {}", pretty);
            }
        }

        let signed_jwt = self
            .sign_session_key_jwt(&jwt, tpm, machine_key, &session_key)
            .await?;

        let mut params = vec![
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("windows_api_version", "2.2"),
            ("request", &signed_jwt),
            ("client_info", "1"),
        ];
        if request_tgt {
            params.push(("tgt", "true"));
        }
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<String>>()
            .join("&");

        let url = format!("{}/oauth2/token", self.authority());

        let mut debug_payload = params.clone();
        debug_payload[2] = ("request", "**********");
        if let Ok(pretty) = to_string_pretty(&debug_payload) {
            debug!("POST {}: {}", url, pretty);
        }

        let resp = self
            .client()
            .post(url)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let enc = resp
                .text()
                .await
                .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?;
            let jwe = JweCompact::from_str(&enc)
                .map_err(|e| MsalError::InvalidParse(format!("{}", e)))?;
            let mut new_prt: PrimaryRefreshToken = json_from_str(
                std::str::from_utf8(
                    session_key
                        .decipher_prt_v2(tpm, &transport_key, &jwe)?
                        .payload(),
                )
                .map_err(|e| MsalError::InvalidParse(format!("{}", e)))?,
            )
            .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            prt.clone_session_key(&mut new_prt);
            self.seal_user_prt(&new_prt, tpm, &transport_key)
        } else {
            let json_resp: ErrorResponse = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            Err(MsalError::AcquireTokenFailed(json_resp))
        }
    }

    /// Provision a new Hello for Business Key
    ///
    /// # Arguments
    ///
    /// * `token` - Token obtained via either
    ///   acquire_token_by_username_password_for_device_enrollment
    ///   or acquire_token_by_device_flow.
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `machine_key` - The TPM MachineKey associated with this application.
    ///
    /// * `pin` - The PIN code which will be used to unlock the key.
    ///
    /// # Returns
    /// * Success: Either the existing LoadableIdentityKey, or a new created
    ///   key if none was provided.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn provision_hello_for_business_key(
        &self,
        token: &UserToken,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
        pin: &str,
    ) -> Result<LoadableIdentityKey, MsalError> {
        debug!("Provisioning a Hello for Business Key");

        if !token.amr_ngcmfa()? {
            error!("Key provisioning is impossible without an ngcmfa amr!");
            return Err(MsalError::GeneralFailure(
                "Token is missing an ngcmfa amr".to_string(),
            ));
        }

        let pin = PinValue::new(pin)
            .map_err(|e| MsalError::TPMFail(format!("Failed setting pin value: {:?}", e)))?;

        // Discover the KeyProvisioningService
        let access_token = match &token.access_token {
            Some(access_token) => access_token.clone(),
            None => {
                return Err(MsalError::GeneralFailure(
                    "Access token missing".to_string(),
                ))
            }
        };
        let services = Services::new(&access_token, &token.tenant_id()?).await?;
        let resource_id = services.key_provisioning_resource_id();

        // Acquire an access token for the key provisioning service
        let token = self
            .acquire_token_by_refresh_token(
                &token.refresh_token,
                vec![],
                Some(resource_id),
                #[cfg(feature = "on_behalf_of")]
                None,
                tpm,
                machine_key,
            )
            .await?;

        // Create a new hello key (using the TPM)
        let loadable_win_hello_key = tpm
            .identity_key_create(machine_key, Some(&pin), KeyAlgorithm::Rsa2048)
            .map_err(|e| {
                MsalError::TPMFail(format!("Failed creating Windows Hello Key: {:?}", e))
            })?;
        let win_hello_key = tpm
            .identity_key_load(machine_key, Some(&pin), &loadable_win_hello_key)
            .map_err(|e| {
                MsalError::TPMFail(format!("Failed loading Windows Hello Key: {:?}", e))
            })?;
        let win_hello_pub_der = tpm
            .identity_key_public_as_der(&win_hello_key)
            .map_err(|e| {
                MsalError::TPMFail(format!("Failed getting Windows Hello Key as der: {:?}", e))
            })?;
        let win_hello_rsa = Rsa::public_key_from_der(&win_hello_pub_der)
            .map_err(|e| MsalError::TPMFail(format!("{}", e)))?;

        let access_token = match &token.access_token {
            Some(access_token) => access_token.clone(),
            None => {
                return Err(MsalError::GeneralFailure(
                    "Access token missing".to_string(),
                ))
            }
        };

        match services.provision_key(&access_token, &win_hello_rsa).await {
            Ok(()) => Ok(loadable_win_hello_key.clone()),
            Err(_) => Err(MsalError::GeneralFailure(
                "Failed registering Windows Hello Key".to_string(),
            )),
        }
    }

    /// Gets a token for a given resource via a Hello for Business Key
    ///
    /// # Arguments
    ///
    /// * `username` - Typically a UPN in the form of an email address.
    ///
    /// * `key` - A LoadableIdentityKey provisioned using
    ///   provision_hello_for_business_key.
    ///
    /// * `scopes` - Scopes requested to access a protected API (a resource).
    ///
    /// * `request_resource` - A resource for obtaining an access token.
    ///   Default is the MS Graph API (00000002-0000-0000-c000-000000000000).
    ///
    /// * `on_behalf_of_client_id`: Request a resource or scope on behalf of
    ///   the specified client_id. Optional. This option requires libhimmelblau
    ///   be built with the `on_behalf_of` feature.
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `machine_key` - The TPM MachineKey associated with this application.
    ///
    /// * `pin` - The PIN code required to unlock the key.
    ///
    /// # Returns
    /// * Success: A UserToken containing an access_token.
    /// * Failure: An MsalError, indicating the failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn acquire_token_by_hello_for_business_key(
        &self,
        username: &str,
        key: &LoadableIdentityKey,
        scopes: Vec<&str>,
        request_resource: Option<String>,
        #[cfg(feature = "on_behalf_of")] on_behalf_of_client_id: Option<&str>,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
        pin: &str,
    ) -> Result<UserToken, MsalError> {
        let v2_endpoint = !scopes.is_empty();
        if !scopes.is_empty() && request_resource.is_some() {
            return Err(MsalError::GeneralFailure(
                "Scopes cannot be specified with a request_resource".to_string(),
            ));
        }

        let pin = PinValue::new(pin)
            .map_err(|e| MsalError::TPMFail(format!("Failed setting pin value: {:?}", e)))?;

        let prt = self
            .acquire_user_prt_by_hello_for_business_key_internal(
                username,
                key,
                tpm,
                machine_key,
                &pin,
            )
            .await?;
        let transport_key = self.transport_key(tpm, machine_key)?;
        let session_key = prt.session_key()?;
        let mut token = self
            .exchange_prt_for_access_token_internal(
                &prt,
                scopes.clone(),
                v2_endpoint,
                tpm,
                machine_key,
                &session_key,
                request_resource,
                #[cfg(feature = "on_behalf_of")]
                on_behalf_of_client_id,
            )
            .await?;
        token.client_info = prt.client_info.clone();
        token.prt = Some(self.seal_user_prt(&prt, tpm, &transport_key)?);
        Ok(token)
    }

    async fn build_jwt_by_hello_for_business_key(
        &self,
        username: &str,
        loadable_key: &LoadableIdentityKey,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
        pin: &PinValue,
    ) -> Result<Jws, MsalError> {
        debug!("Building a Hello for Business JWT");

        let mut nonce = self.request_nonce().await?;
        let key = tpm
            .identity_key_load(machine_key, Some(pin), loadable_key)
            .map_err(|e| MsalError::TPMFail(format!("{:?}", e)))?;
        let win_hello_pub_der = tpm.identity_key_public_as_der(&key).map_err(|e| {
            MsalError::TPMFail(format!("Failed getting Windows Hello Key as der: {:?}", e))
        })?;
        let win_hello_rsa = Rsa::public_key_from_der(&win_hello_pub_der)
            .map_err(|e| MsalError::TPMFail(format!("{}", e)))?;
        let win_hello_blob: Vec<u8> = BcryptRsaKeyBlob::new(
            2048,
            &win_hello_rsa.e().to_vec(),
            &win_hello_rsa.n().to_vec(),
        )
        .try_into()?;
        let kid = STANDARD.encode(
            hash(MessageDigest::sha256(), &win_hello_blob)
                .map_err(|e| MsalError::CryptoFail(format!("{}", e)))?,
        );
        let assertion_jwt = JwsBuilder::from(
            serde_json::to_vec(
                &HelloForBusinessAssertion::new(username, &nonce)
                    .map_err(|e| MsalError::GeneralFailure(format!("{:?}", e)))?,
            )
            .map_err(|e| {
                MsalError::InvalidJson(format!(
                    "Failed serializing Hello for Business Assertion JWT: {}",
                    e
                ))
            })?,
        )
        .set_typ(Some("JWT"))
        .set_use(Some("ngc"))
        .set_kid(Some(&kid))
        .build();

        if let Ok(payload) = assertion_jwt.from_json::<Value>() {
            if let Ok(pretty) = to_string_pretty(&payload) {
                debug!("Hello for Business Assertion: {}", pretty);
            }
        }

        let mut jws_tpm_signer = match JwsTpmSigner::new(tpm, &key) {
            Ok(jws_tpm_signer) => jws_tpm_signer,
            Err(e) => {
                return Err(MsalError::TPMFail(format!(
                    "Failed loading tpm signer: {}",
                    e
                )))
            }
        };
        let signed_assertion = match jws_tpm_signer.sign(&assertion_jwt) {
            Ok(signed_jwt) => signed_jwt,
            Err(e) => return Err(MsalError::TPMFail(format!("Failed signing jwk: {}", e))),
        };
        let assertion = format!("{}", signed_assertion);

        nonce = self.request_nonce().await?;

        let jwt = JwsBuilder::from(
            serde_json::to_vec(&HelloForBusinessPayload::new(username, &assertion, &nonce))
                .map_err(|e| {
                    MsalError::InvalidJson(format!(
                        "Failed serializing Hello for Business JWT: {}",
                        e
                    ))
                })?,
        )
        .set_typ(Some("JWT"))
        .build();

        if let Ok(mut jwt_debug) = jwt.from_json::<Value>() {
            jwt_debug["assertion"] = "**********".into();
            if let Ok(pretty) = to_string_pretty(&jwt_debug) {
                debug!("Hello for Business Payload: {}", pretty);
            }
        }

        Ok(jwt)
    }

    async fn acquire_user_prt_by_hello_for_business_key_internal(
        &self,
        username: &str,
        key: &LoadableIdentityKey,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
        pin: &PinValue,
    ) -> Result<PrimaryRefreshToken, MsalError> {
        debug!("Acquiring a User PRT via a Hello for Business Key");

        let jwt = self
            .build_jwt_by_hello_for_business_key(username, key, tpm, machine_key, pin)
            .await?;
        let signed_jwt = self.sign_jwt(&jwt, tpm, machine_key).await?;

        self.acquire_user_prt_jwt(&signed_jwt).await
    }

    /// Gets a Primary Refresh Token (PRT) via a Hello for Business Key
    ///
    /// # Arguments
    ///
    /// * `username` - Typically a UPN in the form of an email address.
    ///
    /// * `key` - A LoadableIdentityKey provisioned using
    ///   provision_hello_for_business_key.
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `machine_key` - The TPM MachineKey associated with this application.
    ///
    /// * `pin` - The PIN code required to unlock the key.
    ///
    /// # Returns
    /// * Success: An encrypted PrimaryRefreshToken, containing a refresh_token and tgt.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn acquire_user_prt_by_hello_for_business_key(
        &self,
        username: &str,
        key: &LoadableIdentityKey,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
        pin: &str,
    ) -> Result<SealedData, MsalError> {
        let pin = PinValue::new(pin)
            .map_err(|e| MsalError::TPMFail(format!("Failed setting pin value: {:?}", e)))?;

        let prt = self
            .acquire_user_prt_by_hello_for_business_key_internal(
                username,
                key,
                tpm,
                machine_key,
                &pin,
            )
            .await?;
        let transport_key = self.transport_key(tpm, machine_key)?;
        self.seal_user_prt(&prt, tpm, &transport_key)
    }

    async fn exchange_prt_for_auth_code_internal(
        &self,
        scope: Vec<&str>,
        request_id: &str,
        resource: Option<&str>,
        v2_endpoint: bool,
        signed_prt_payload: Option<String>,
        signed_device_payload: Option<String>,
        #[cfg(feature = "on_behalf_of")] on_behalf_of_client_id: Option<&str>,
    ) -> Result<String, MsalError> {
        #[cfg(not(feature = "on_behalf_of"))]
        let on_behalf_of_client_id: Option<&str> = None;

        let scope = format!("openid profile {}", scope.join(" "));
        let (client_id, redirect_uri) = if v2_endpoint {
            if let Some(on_behalf_of_client_id) = on_behalf_of_client_id {
                (
                    on_behalf_of_client_id.to_string(),
                    self.app
                        .get_auth_redirect_uri(Some(on_behalf_of_client_id), resource),
                )
            } else if let Some(on_behalf_of_client_id) = &self.on_behalf_of_client_id {
                (
                    on_behalf_of_client_id.clone(),
                    HIMMELBLAU_REDIRECT_URI.to_string(),
                )
            } else {
                (
                    LINUX_BROKER_APP_ID.to_string(),
                    self.app
                        .get_auth_redirect_uri(Some(LINUX_BROKER_APP_ID), resource),
                )
            }
        } else {
            (
                self.app.client_id().to_string(),
                self.app.get_auth_redirect_uri(None, resource),
            )
        };

        let mut params = vec![
            ("client_id", client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", redirect_uri.as_str()),
            ("client-request-id", request_id),
        ];
        if v2_endpoint {
            params.push(("scope", &scope));
        } else if let Some(resource) = resource {
            params.push(("resource", resource));
        } else {
            params.push(("resource", "https://graph.microsoft.com"));
        }
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, url_encode(v)))
            .collect::<Vec<String>>()
            .join("&");

        let url = if v2_endpoint {
            format!("{}/oAuth2/v2.0/authorize?{}", self.authority(), payload)
        } else {
            format!("{}/oauth2/authorize?{}", self.authority(), payload)
        };
        debug!("GET {}", url);

        let mut req = self.client().get(url).header(header::USER_AGENT, "");
        if let Some(signed_prt_payload) = signed_prt_payload {
            req = req.header("x-ms-RefreshTokenCredential", signed_prt_payload);
        }
        if let Some(signed_device_payload) = signed_device_payload {
            req = req.header("x-ms-DeviceCredential", signed_device_payload);
        }
        let mut resp = req
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        let text;
        (text, resp) = self.app.await_working(resp).await?;
        if resp.status().is_redirection() {
            let document = Html::parse_document(&text);
            let selector = Selector::parse("a[href]").map_err(|_| {
                MsalError::RequestFailed("Failed parsing auth code response".to_string())
            })?;
            if let Some(element) = document.select(&selector).next() {
                if let Some(href_encoded) = element.value().attr("href") {
                    let href = percent_decode_str(href_encoded)
                        .decode_utf8()
                        .map_err(|e| {
                            MsalError::URLFormatFailed(format!("Failed decoding url: {:?}", e))
                        })?;
                    if let Ok(url) = Url::parse(&href) {
                        return url
                            .query_pairs()
                            .find_map(|(key, value)| {
                                if key == "code" {
                                    Some(value.into_owned())
                                } else {
                                    None
                                }
                            })
                            .ok_or(MsalError::GeneralFailure(
                                "Authorization code not found".to_string(),
                            ));
                    }
                }
            }

            Err(MsalError::GeneralFailure(format!(
                "Authorization code not found in: {}",
                text
            )))
        } else if resp.status().is_success() {
            let re = Regex::new(r#"document\.location\.replace\("([^"]+)"\)"#)
                .map_err(|e| MsalError::InvalidRegex(format!("{}", e)))?;
            if let Some(m) = re.captures(&text) {
                if let Some(redirect) = m.get(1) {
                    let redirect_decoded = Url::parse(&redirect.as_str().replace(r#"\u0026"#, "&"))
                        .map_err(|e| MsalError::InvalidParse(format!("{}", e)))?;
                    for (k, v) in redirect_decoded.query_pairs().collect::<Vec<_>>() {
                        if k == "code" {
                            return Ok(v.to_string());
                        }
                        if k == "error_description" {
                            return Err(MsalError::GeneralFailure(v.to_string()));
                        }
                    }
                }
            }

            // MS may have returned an AuthConfig here with an error attached.
            // Return the error from that AuthConfig if possible. If a required
            // password change is indicated, raise an error.
            match self.app.parse_auth_config(&text, false, false) {
                #[cfg(feature = "changepassword")]
                Err(MsalError::ChangePassword) => return Err(MsalError::ChangePassword),
                Err(MsalError::AADSTSError(e)) => return Err(MsalError::AADSTSError(e)),
                _ => {}
            }

            Err(MsalError::GeneralFailure(format!(
                "Authorization code not found in: {}",
                text
            )))
        } else {
            let json_resp: ErrorResponse = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            Err(MsalError::AcquireTokenFailed(json_resp))
        }
    }

    /// Creates a single sign-on (SSO) JWT Cookie from an encrypted Primary
    /// Refresh Token (PRT).
    ///
    /// # Arguments
    ///
    /// * `prt` - The encrypted Primary Refresh Token (PRT) that will be used
    ///   to generate the SSO cookie.
    ///
    /// * `tpm` - The TPM object used to interface with the hardware for
    ///   cryptographic operations.
    ///
    /// * `machine_key` - The TPM MachineKey associated with the current
    ///   device/application.
    ///
    /// # Returns
    /// * Success: A JWT (as a String) that can be used for single sign-on
    ///   (SSO) authentication.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn acquire_prt_sso_cookie(
        &self,
        prt: &SealedData,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<String, MsalError> {
        debug!("Creating a prt sso cookie");

        let transport_key = self.transport_key(tpm, machine_key)?;
        let prt = self.unseal_user_prt(prt, tpm, &transport_key)?;
        let session_key = prt.session_key()?;

        let nonce = self.request_nonce().await?;

        let jwt = JwsBuilder::from(
            serde_json::to_vec(&RefreshTokenCredentialPayload::new(&prt, &nonce)?).map_err(
                |e| MsalError::InvalidJson(format!("Failed serializing Authorization JWT: {}", e)),
            )?,
        )
        .set_typ(Some("JWT"))
        .build();

        self.sign_session_key_jwt(&jwt, tpm, machine_key, &session_key)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn exchange_prt_for_auth_code(
        &self,
        prt: &PrimaryRefreshToken,
        scope: Vec<&str>,
        request_id: &str,
        resource: Option<&str>,
        v2_endpoint: bool,
        session_key: &SessionKey,
        #[cfg(feature = "on_behalf_of")] on_behalf_of_client_id: Option<&str>,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<String, MsalError> {
        debug!("Exchanging a PRT for an Authorization Code");

        let nonce = self.request_nonce().await?;

        let jwt = JwsBuilder::from(
            serde_json::to_vec(&RefreshTokenCredentialPayload::new(prt, &nonce)?).map_err(|e| {
                MsalError::InvalidJson(format!("Failed serializing Authorization JWT: {}", e))
            })?,
        )
        .set_typ(Some("JWT"))
        .build();
        let signed_prt_payload = self
            .sign_session_key_jwt(&jwt, tpm, machine_key, session_key)
            .await?;
        if let Ok(mut payload) = jwt.from_json::<Value>() {
            payload["refresh_token"] = "**********".into();
            if let Ok(pretty) = to_string_pretty(&payload) {
                debug!("Refresh Token Credential Payload: {}", pretty);
            }
        }

        let jwt = JwsBuilder::from(
            serde_json::to_vec(&DeviceCredentialPayload::new(&nonce)?).map_err(|e| {
                MsalError::InvalidJson(format!("Failed serializing Authorization JWT: {}", e))
            })?,
        )
        .set_typ(Some("JWT"))
        .build();
        let signed_device_payload = self.sign_jwt(&jwt, tpm, machine_key).await?;
        if let Ok(payload) = jwt.from_json::<Value>() {
            if let Ok(pretty) = to_string_pretty(&payload) {
                debug!("Device Credential Payload: {}", pretty);
            }
        }

        self.exchange_prt_for_auth_code_internal(
            scope,
            request_id,
            resource,
            v2_endpoint,
            Some(signed_prt_payload),
            Some(signed_device_payload),
            #[cfg(feature = "on_behalf_of")]
            on_behalf_of_client_id,
        )
        .await
    }

    async fn exchange_auth_code_for_access_token_internal(
        &self,
        scope: Vec<&str>,
        request_id: &str,
        v2_endpoint: bool,
        authorization_code: String,
        request_resource: Option<&str>,
        #[cfg(feature = "on_behalf_of")] on_behalf_of_client_id: Option<&str>,
    ) -> Result<UserToken, MsalError> {
        debug!("Exchanging an Authorization Code for an Access Token");
        #[cfg(not(feature = "on_behalf_of"))]
        let on_behalf_of_client_id: Option<&str> = None;

        let scopes_str = format!("openid profile offline_access {}", scope.join(" "));
        let (client_id, redirect_uri) = if v2_endpoint {
            if let Some(on_behalf_of_client_id) = on_behalf_of_client_id {
                (
                    on_behalf_of_client_id.to_string(),
                    self.app
                        .get_auth_redirect_uri(Some(on_behalf_of_client_id), request_resource),
                )
            } else if let Some(on_behalf_of_client_id) = &self.on_behalf_of_client_id {
                (
                    on_behalf_of_client_id.clone(),
                    HIMMELBLAU_REDIRECT_URI.to_string(),
                )
            } else {
                (
                    LINUX_BROKER_APP_ID.to_string(),
                    self.app
                        .get_auth_redirect_uri(Some(LINUX_BROKER_APP_ID), request_resource),
                )
            }
        } else {
            (
                self.app.client_id().to_string(),
                self.app.get_auth_redirect_uri(None, request_resource),
            )
        };
        let mut params = vec![
            ("client_id", client_id.as_str()),
            ("grant_type", "authorization_code"),
            ("code", &authorization_code),
            ("redirect_uri", &redirect_uri),
            ("client-request-id", request_id),
        ];
        if v2_endpoint {
            params.push(("scope", &scopes_str));
        } else if let Some(request_resource) = request_resource {
            params.push(("resource", request_resource));
        } else {
            params.push(("resource", "https://graph.microsoft.com"));
        }
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<String>>()
            .join("&");

        let url = if v2_endpoint {
            format!("{}/oAuth2/v2.0/token", self.authority())
        } else {
            format!("{}/oauth2/token", self.authority())
        };
        let mut debug_payload = params;
        debug_payload[2] = ("code", "**********");
        if let Ok(pretty) = to_string_pretty(&debug_payload) {
            debug!("POST {}: {}", url, pretty);
        }

        let resp = self
            .client()
            .post(url)
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

    /// Change the password for an Entra Id user.
    ///
    /// This function allows changing the password for an Entra Id user. It
    /// requires the current username and password to validate the user's
    /// identity before updating the password.
    ///
    /// # Arguments
    ///
    /// * `username` - The username associated with the account for which the
    ///   password is being changed.
    /// * `password` - The current password for the account.
    /// * `new_password` - The new password that will replace the current
    ///   password.
    ///
    /// # Returns
    ///
    /// * Success: An empty Ok result indicating the password has been changed
    ///   successfully.
    /// * Failure: An MsalError, indicating problems such as authentication
    ///   failures or password complexity requirements not met.
    #[cfg(feature = "changepassword")]
    pub async fn handle_password_change(
        &self,
        username: &str,
        password: &str,
        new_password: &str,
    ) -> Result<(), MsalError> {
        self.app
            .handle_password_change(username, password, new_password)
            .await
    }

    /// Fetch the name (GECOS) from the PRT
    ///
    /// # Arguments
    ///
    /// * `prt` - The encrypted Primary Refresh Token (PRT) that will be used
    ///   to generate the SSO cookie.
    ///
    /// * `tpm` - The TPM object used to interface with the hardware for
    ///   cryptographic operations.
    ///
    /// * `machine_key` - The TPM MachineKey associated with the current
    ///   device/application.
    ///
    /// # Returns
    ///
    /// * Success: The user Azure spn
    /// * Failure: An MsalError, indicating the failure.
    pub fn name_from_prt(
        &self,
        sealed_data: &SealedData,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<String, MsalError> {
        let transport_key = self.transport_key(tpm, machine_key)?;
        let prt = self.unseal_user_prt(sealed_data, tpm, &transport_key)?;
        Ok(prt.name())
    }

    /// Fetch the spn from the PRT
    ///
    /// # Arguments
    ///
    /// * `prt` - The encrypted Primary Refresh Token (PRT) that will be used
    ///   to generate the SSO cookie.
    ///
    /// * `tpm` - The TPM object used to interface with the hardware for
    ///   cryptographic operations.
    ///
    /// * `machine_key` - The TPM MachineKey associated with the current
    ///   device/application.
    ///
    /// # Returns
    ///
    /// * Success: The user Azure spn
    /// * Failure: An MsalError, indicating the failure.
    pub fn spn_from_prt(
        &self,
        sealed_data: &SealedData,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<String, MsalError> {
        let transport_key = self.transport_key(tpm, machine_key)?;
        let prt = self.unseal_user_prt(sealed_data, tpm, &transport_key)?;
        prt.spn()
    }

    /// Fetch the UUID from the PRT
    ///
    /// # Arguments
    ///
    /// * `prt` - The encrypted Primary Refresh Token (PRT) that will be used
    ///   to generate the SSO cookie.
    ///
    /// * `tpm` - The TPM object used to interface with the hardware for
    ///   cryptographic operations.
    ///
    /// * `machine_key` - The TPM MachineKey associated with the current
    ///   device/application.
    ///
    /// # Returns
    ///
    /// * Success: The user Azure UUID
    /// * Failure: An MsalError, indicating the failure.
    pub fn uuid_from_prt(
        &self,
        sealed_data: &SealedData,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<Uuid, MsalError> {
        let transport_key = self.transport_key(tpm, machine_key)?;
        let prt = self.unseal_user_prt(sealed_data, tpm, &transport_key)?;
        prt.uuid()
    }

    /// Gets the Cloud TGT from a sealed PRT and stores it in the Kerberos CCache
    ///
    /// # Arguments
    ///
    /// * `sealed_prt` -  An encrypted primary refresh token that was
    ///   previously received from the server.
    ///
    /// * `filename` - The filename for the Kerberos Credential Cache.
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `machine_key` - The TPM MachineKey associated with this application.
    ///
    /// # Returns
    /// * Failure: An MsalError, indicating the failure.
    pub fn store_cloud_tgt(
        &self,
        sealed_prt: &SealedData,
        filename: &str,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<(), MsalError> {
        let transport_key = self.transport_key(tpm, machine_key)?;
        let prt = self.unseal_user_prt(sealed_prt, tpm, &transport_key)?;
        if let Some(error) = &prt.tgt_cloud.error {
            return Err(MsalError::Missing(error.to_string()));
        }
        let session_key = prt.session_key()?;
        let client_key = prt
            .tgt_cloud
            .client_key(tpm, &transport_key, &session_key)?;
        let message = prt.tgt_cloud.message()?;
        let ccache = FileCredentialCache::new(&message, &client_key)?;
        ccache.save_keytab_file(filename)
    }

    /// Gets the AD TGT from a sealed PRT and stores it in the Kerberos CCache
    ///
    /// # Arguments
    ///
    /// * `sealed_prt` -  An encrypted primary refresh token that was
    ///   previously received from the server.
    ///
    /// * `filename` - The filename for the Kerberos Credential Cache.
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `machine_key` - The TPM MachineKey associated with this application.
    ///
    /// # Returns
    /// * Failure: An MsalError, indicating the failure.
    pub fn store_ad_tgt(
        &self,
        sealed_prt: &SealedData,
        filename: &str,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<(), MsalError> {
        let transport_key = self.transport_key(tpm, machine_key)?;
        let prt = self.unseal_user_prt(sealed_prt, tpm, &transport_key)?;
        if let Some(error) = &prt.tgt_ad.error {
            return Err(MsalError::Missing(error.to_string()));
        }
        let session_key = prt.session_key()?;
        let client_key = prt.tgt_ad.client_key(tpm, &transport_key, &session_key)?;
        let message = prt.tgt_ad.message()?;
        let ccache = FileCredentialCache::new(&message, &client_key)?;
        ccache.save_keytab_file(filename)
    }

    /// Gets the Cloud TGT from a sealed PRT and returns it in a Kerberos CCache
    ///
    /// # Arguments
    ///
    /// * `sealed_prt` -  An encrypted primary refresh token that was
    ///   previously received from the server.
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `machine_key` - The TPM MachineKey associated with this application.
    ///
    /// # Returns
    /// * Success: Byte representation of a Kerberos CCache
    /// * Failure: An MsalError, indicating the failure.
    pub fn fetch_cloud_ccache(
        &self,
        sealed_prt: &SealedData,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<Vec<u8>, MsalError> {
        let transport_key = self.transport_key(tpm, machine_key)?;
        let prt = self.unseal_user_prt(sealed_prt, tpm, &transport_key)?;
        if let Some(error) = &prt.tgt_cloud.error {
            return Err(MsalError::Missing(error.to_string()));
        }
        let session_key = prt.session_key()?;
        let client_key = prt
            .tgt_cloud
            .client_key(tpm, &transport_key, &session_key)?;
        let message = prt.tgt_cloud.message()?;
        let ccache = FileCredentialCache::new(&message, &client_key)?;
        Ok(ccache.to_bytes())
    }

    /// Gets the AD TGT from a sealed PRT and returns it in a Kerberos CCache
    ///
    /// # Arguments
    ///
    /// * `sealed_prt` -  An encrypted primary refresh token that was
    ///   previously received from the server.
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `machine_key` - The TPM MachineKey associated with this application.
    ///
    /// # Returns
    /// * Success: Byte representation of a Kerberos CCache
    /// * Failure: An MsalError, indicating the failure.
    pub fn fetch_ad_ccache(
        &self,
        sealed_prt: &SealedData,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<Vec<u8>, MsalError> {
        let transport_key = self.transport_key(tpm, machine_key)?;
        let prt = self.unseal_user_prt(sealed_prt, tpm, &transport_key)?;
        if let Some(error) = &prt.tgt_ad.error {
            return Err(MsalError::Missing(error.to_string()));
        }
        let session_key = prt.session_key()?;
        let client_key = prt.tgt_ad.client_key(tpm, &transport_key, &session_key)?;
        let message = prt.tgt_ad.message()?;
        let ccache = FileCredentialCache::new(&message, &client_key)?;
        Ok(ccache.to_bytes())
    }

    /// Get the Kerberos top level names from a sealed PRT
    ///
    /// # Arguments
    ///
    /// * `sealed_prt` -  An encrypted primary refresh token that was
    ///   previously received from the server.
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `machine_key` - The TPM MachineKey associated with this application.
    ///
    /// # Returns
    /// * Success: The Kerberos top level names
    /// * Failure: An MsalError, indicating the failure.
    pub fn unseal_prt_kerberos_top_level_names(
        &self,
        sealed_prt: &SealedData,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<String, MsalError> {
        let transport_key = self.transport_key(tpm, machine_key)?;
        let prt = self.unseal_user_prt(sealed_prt, tpm, &transport_key)?;
        let kerberos_top_level_names =
            prt.kerberos_top_level_names
                .clone()
                .ok_or(MsalError::Missing(
                    "kerberos_top_level_names missing from PRT".to_string(),
                ))?;
        Ok(kerberos_top_level_names.clone())
    }

    fn seal_user_prt(
        &self,
        prt: &PrimaryRefreshToken,
        tpm: &mut BoxedDynTpm,
        key: &MsOapxbcRsaKey,
    ) -> Result<SealedData, MsalError> {
        let prt_data = json_to_vec(prt)
            .map_err(|e| MsalError::InvalidJson(format!("Failed serializing PRT {:?}", e)))?;
        tpm.msoapxbc_rsa_seal_data(key, &prt_data)
            .map_err(|e| MsalError::TPMFail(format!("Failed sealing PRT {:?}", e)))
    }

    fn unseal_user_prt(
        &self,
        sealed_data: &SealedData,
        tpm: &mut BoxedDynTpm,
        key: &MsOapxbcRsaKey,
    ) -> Result<PrimaryRefreshToken, MsalError> {
        let prt_data = tpm
            .msoapxbc_rsa_unseal_data(key, sealed_data)
            .map_err(|e| MsalError::TPMFail(format!("Failed unsealing PRT {:?}", e)))?;
        json_from_slice(&prt_data)
            .map_err(|e| MsalError::InvalidJson(format!("Failed deserializing PRT {:?}", e)))
    }

    /// Obtain token interactively for device enrollment.
    ///
    /// # Arguments
    ///
    /// * `username` - Typically a UPN in the form of an email address.
    ///
    /// # Returns
    ///
    /// * Success: A UserToken containing an access_token.
    /// * Failure: An MsalError, indicating the failure.
    #[cfg(feature = "interactive")]
    pub async fn acquire_token_interactive_for_device_enrollment(
        &self,
        username: &str,
    ) -> Result<UserToken, MsalError> {
        let resource = "https://enrollment.manage.microsoft.com";
        self.app
            .acquire_token_interactive(username, Some(resource))
            .await
    }
}
