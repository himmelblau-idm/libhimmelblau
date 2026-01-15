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

pub use crate::aadsts_err_gen::*;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const INVALID_CRED: u32 = 0xC3CE;
pub const REQUIRES_MFA: u32 = 0xC39C;
pub const INVALID_USER: u32 = 0xC372;
pub const NO_CONSENT: u32 = 0xFDE9;
pub const NO_GROUP_CONSENT: u32 = 0xFDEA;
pub const NO_SECRET: u32 = 0x6AD09A;
pub const AUTH_PENDING: u32 = 0x11180;
pub const DEVICE_AUTH_FAIL: u32 = 0xC3EB;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: String,
    pub error_codes: Vec<u32>,
}

#[derive(Serialize, Debug)]
pub enum MsalError {
    /// MSAL failed to parse a json input
    InvalidJson(String),
    /// MSAL failed to parse a base64 input
    InvalidBase64(String),
    /// MSAL failed to parse a regex
    InvalidRegex(String),
    /// MSAL failed to parse something
    InvalidParse(String),
    /// MSAL failed when acquiring a token
    AcquireTokenFailed(ErrorResponse),
    /// General failure with text
    GeneralFailure(String),
    /// Failure encountered in the reqwest module
    RequestFailed(String),
    /// The Authentication type is not supported
    AuthTypeUnsupported,
    /// Failure encountered interacting with the TPM
    TPMFail(String),
    /// Failed whil formatting a URL
    URLFormatFailed(String),
    /// Enrollment failure
    DeviceEnrollmentFail(String),
    /// Crypto failure
    CryptoFail(String),
    /// This functionality is not yet implemented
    NotImplemented,
    /// A configuration error was detected
    ConfigError(String),
    /// Continuing polling for an MFA auth
    MFAPollContinue,
    /// An AADSTSError
    AADSTSError(AADSTSError),
    /// TGT missing from PRT
    Missing(String),
    /// A formatting error
    FormatError(String),
    /// A password change was requested
    #[cfg(feature = "changepassword")]
    ChangePassword,
    /// A password entry is required
    PasswordRequired,
    /// An error was encountered because MS Authenticator registration was requested
    SkipMfaRegistration(String, Option<String>, String),
    /// ConvergedConsent
    ConsentRequested(String),
    /// An authorization code was received directly from login (no MFA required).
    /// The String contains the auth code to exchange for tokens.
    AuthCodeReceived(String),
    /// MFA is required to complete authentication (e.g., when Hello for Business
    /// auth gets an MFA challenge page instead of an auth code)
    MFARequired,
}

impl fmt::Display for MsalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MsalError::InvalidJson(msg) => write!(f, "Invalid JSON: {}", msg),
            MsalError::InvalidBase64(msg) => write!(f, "Invalid base64: {}", msg),
            MsalError::InvalidRegex(msg) => write!(f, "Invalid regex: {}", msg),
            MsalError::InvalidParse(msg) => write!(f, "Parse error: {}", msg),
            MsalError::AcquireTokenFailed(err) => write!(
                f,
                "Token acquisition failed: {} ({})",
                err.error, err.error_description
            ),
            MsalError::GeneralFailure(msg) => write!(f, "General failure: {}", msg),
            MsalError::RequestFailed(msg) => write!(f, "Request failed: {}", msg),
            MsalError::AuthTypeUnsupported => write!(f, "Authentication type is not supported"),
            MsalError::TPMFail(msg) => write!(f, "TPM error: {}", msg),
            MsalError::URLFormatFailed(msg) => write!(f, "URL format error: {}", msg),
            MsalError::DeviceEnrollmentFail(msg) => write!(f, "Device enrollment failed: {}", msg),
            MsalError::CryptoFail(msg) => write!(f, "Cryptography failure: {}", msg),
            MsalError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            MsalError::AADSTSError(err) => write!(f, "{}", err),
            MsalError::Missing(msg) => write!(f, "Missing value: {}", msg),
            MsalError::FormatError(msg) => write!(f, "Formatting error: {}", msg),
            #[cfg(feature = "changepassword")]
            MsalError::ChangePassword => write!(f, "Unexpected error"),
            MsalError::NotImplemented
            | MsalError::MFAPollContinue
            | MsalError::PasswordRequired
            | MsalError::SkipMfaRegistration(..) => write!(f, "Unexpected error"),
            MsalError::ConsentRequested(msg) => write!(f, "{}", msg),
            MsalError::AuthCodeReceived(_) => {
                write!(f, "Authorization code received directly from login")
            }
            MsalError::MFARequired => {
                write!(f, "MFA is required to complete authentication")
            }
        }
    }
}
