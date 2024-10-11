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

use serde::{Deserialize, Serialize};
use std::convert::From;

pub use crate::aadsts_err_gen::*;

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
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub enum MSAL_ERROR {
    INVALID_JSON,
    INVALID_BASE64,
    INVALID_REGEX,
    INVALID_PARSE,
    ACQUIRE_TOKEN_FAILED,
    GENERAL_FAILURE,
    REQUEST_FAILED,
    AUTH_TYPE_UNSUPPORTED,
    TPM_FAIL,
    URL_FORMAT_FAILED,
    DEVICE_ENROLLMENT_FAIL,
    CRYPTO_FAIL,
    NOT_IMPLEMENTED,
    CONFIG_ERROR,
    MFA_POLL_CONTINUE,
    SUCCESS,
    INVALID_POINTER,
    NO_MEMORY,
    AADSTS_ERROR,
}

impl From<MsalError> for MSAL_ERROR {
    fn from(error: MsalError) -> Self {
        match error {
            MsalError::InvalidJson(_) => MSAL_ERROR::INVALID_JSON,
            MsalError::InvalidBase64(_) => MSAL_ERROR::INVALID_BASE64,
            MsalError::InvalidRegex(_) => MSAL_ERROR::INVALID_REGEX,
            MsalError::InvalidParse(_) => MSAL_ERROR::INVALID_PARSE,
            MsalError::AcquireTokenFailed(_) => MSAL_ERROR::ACQUIRE_TOKEN_FAILED,
            MsalError::GeneralFailure(_) => MSAL_ERROR::GENERAL_FAILURE,
            MsalError::RequestFailed(_) => MSAL_ERROR::REQUEST_FAILED,
            MsalError::AuthTypeUnsupported => MSAL_ERROR::AUTH_TYPE_UNSUPPORTED,
            MsalError::TPMFail(_) => MSAL_ERROR::TPM_FAIL,
            MsalError::URLFormatFailed(_) => MSAL_ERROR::URL_FORMAT_FAILED,
            MsalError::DeviceEnrollmentFail(_) => MSAL_ERROR::DEVICE_ENROLLMENT_FAIL,
            MsalError::CryptoFail(_) => MSAL_ERROR::CRYPTO_FAIL,
            MsalError::NotImplemented => MSAL_ERROR::NOT_IMPLEMENTED,
            MsalError::ConfigError(_) => MSAL_ERROR::CONFIG_ERROR,
            MsalError::MFAPollContinue => MSAL_ERROR::MFA_POLL_CONTINUE,
            MsalError::AADSTSError(_) => MSAL_ERROR::AADSTS_ERROR,
        }
    }
}
