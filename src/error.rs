use serde::Deserialize;

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
    InvalidJson(String),
    /// MSAL failed to parse a base64 input
    InvalidBase64(String),
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
}
