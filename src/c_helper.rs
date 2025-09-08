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

use crate::error::MsalError;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::slice;
use tracing::error;

#[allow(dead_code)]
pub(crate) fn wrap_c_char(input: *const c_char) -> Option<String> {
    if input.is_null() {
        return None;
    }

    let c_str = unsafe { CStr::from_ptr(input) };
    match c_str.to_str() {
        Ok(output) => Some(output.to_string()),
        Err(_) => None,
    }
}

pub(crate) fn wrap_string(input: &str) -> *mut c_char {
    match CString::new(input.to_string()) {
        Ok(msg) => msg.into_raw(),
        Err(e) => {
            error!("{:?}", e);
            ptr::null_mut()
        }
    }
}

macro_rules! free_object {
    ($input:ident) => {{
        if !$input.is_null() {
            unsafe {
                let _ = Box::from_raw($input);
            }
        }
    }};
}

#[allow(unused_macros)]
macro_rules! run_async {
    ($client:ident, $func:ident $(, $arg:expr)* $(,)?) => {{
        match runtime::Runtime::new() {
            Ok(rt) => rt.block_on(async {
                match $client.$func($($arg),*).await {
                    Ok(resp) => Ok(resp),
                    Err(e) => Err(make_error_from_msal_error(e)),
                }
            }),
            Err(e) => {
                Err(make_error(MSAL_ERROR_CODE::NO_MEMORY, e.to_string()))
            }
        }
    }}
}

#[allow(dead_code)]
pub(crate) fn str_array_to_vec(
    arr: *const *const c_char,
    len: c_int,
) -> Result<Vec<String>, *mut MSAL_ERROR> {
    if arr.is_null() && len == 0 {
        return Ok(vec![]);
    }
    let slice = unsafe { slice::from_raw_parts(arr, len as usize) };
    let mut array = Vec::new();
    for &item in slice {
        if item.is_null() {
            return Err(make_error(
                MSAL_ERROR_CODE::INVALID_POINTER,
                format!("Invalid input {}", stringify!($arr)),
            ));
        }
        let c_item = unsafe { CStr::from_ptr(item) };
        let str_item = match c_item.to_str() {
            Ok(str_item) => str_item,
            Err(e) => {
                return Err(make_error(MSAL_ERROR_CODE::INVALID_POINTER, e.to_string()));
            }
        };
        array.push(str_item.to_string());
    }
    Ok(array)
}

#[allow(unused_macros)]
macro_rules! str_vec_ref {
    ($items:ident) => {
        $items.iter().map(|i| i.as_str()).collect()
    };
}

macro_rules! c_str_from_object_string {
    ($obj:ident, $item:ident, $out:ident) => {{
        let obj = unsafe { &mut *$obj };
        let c_str = wrap_string(&obj.$item);
        if !c_str.is_null() {
            unsafe {
                *$out = c_str;
            }
            no_error()
        } else {
            make_error(
                MSAL_ERROR_CODE::INVALID_POINTER,
                format!("Invalid object {}.{}", stringify!($obj), stringify!($item)),
            )
        }
    }};
}

macro_rules! c_str_from_object_option_string {
    ($obj:ident, $item:ident, $out:ident) => {{
        let obj = unsafe { &mut *$obj };
        match &obj.$item {
            Some(item) => {
                let c_str = wrap_string(&item);
                if !c_str.is_null() {
                    unsafe {
                        *$out = c_str;
                    }
                    no_error()
                } else {
                    make_error(
                        MSAL_ERROR_CODE::INVALID_POINTER,
                        format!("Invalid object {}.{}", stringify!($obj), stringify!($item)),
                    )
                }
            }
            None => make_error(
                MSAL_ERROR_CODE::INVALID_POINTER,
                format!("Object is None {}.{}", stringify!($obj), stringify!($item)),
            ),
        }
    }};
}

macro_rules! c_str_from_object_func {
    ($obj:ident, $func:ident, $out:ident $(, $arg:expr)* $(,)?) => {{
        let obj = unsafe { &mut *$obj };
        match obj.$func($($arg),*) {
            Ok(item) => {
                let c_str = wrap_string(&item);
                if !c_str.is_null() {
                    unsafe {
                        *$out = c_str;
                    }
                    no_error()
                } else {
                    make_error(
                        MSAL_ERROR_CODE::INVALID_POINTER,
                        format!("Invalid response {}.{}()", stringify!($obj), stringify!($func))
                    )
                }
            }
            Err(e) => {
                make_error(MSAL_ERROR_CODE::INVALID_POINTER, e.to_string())
            }
        }
    }};
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
pub enum MSAL_ERROR_CODE {
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
    MISSING,
    FORMAT_ERROR,
    INVALID_POINTER,
    NO_MEMORY,
    AADSTS_ERROR,
    #[cfg(feature = "changepassword")]
    CHANGE_PASSWORD,
    PASSWORD_REQUIRED,
    SKIP_MFA_REGISTRATION,
    CONSENT_REQUESTED,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct MSAL_ERROR {
    pub code: MSAL_ERROR_CODE,
    pub msg: *const c_char,
    pub aadsts_code: u32,
    pub acquire_token_error_codes: *const u32,
    pub acquire_token_error_codes_len: usize,
}

impl From<MsalError> for MSAL_ERROR_CODE {
    fn from(error: MsalError) -> Self {
        match error {
            MsalError::InvalidJson(_) => MSAL_ERROR_CODE::INVALID_JSON,
            MsalError::InvalidBase64(_) => MSAL_ERROR_CODE::INVALID_BASE64,
            MsalError::InvalidRegex(_) => MSAL_ERROR_CODE::INVALID_REGEX,
            MsalError::InvalidParse(_) => MSAL_ERROR_CODE::INVALID_PARSE,
            MsalError::AcquireTokenFailed(_) => MSAL_ERROR_CODE::ACQUIRE_TOKEN_FAILED,
            MsalError::GeneralFailure(_) => MSAL_ERROR_CODE::GENERAL_FAILURE,
            MsalError::RequestFailed(_) => MSAL_ERROR_CODE::REQUEST_FAILED,
            MsalError::AuthTypeUnsupported => MSAL_ERROR_CODE::AUTH_TYPE_UNSUPPORTED,
            MsalError::TPMFail(_) => MSAL_ERROR_CODE::TPM_FAIL,
            MsalError::URLFormatFailed(_) => MSAL_ERROR_CODE::URL_FORMAT_FAILED,
            MsalError::DeviceEnrollmentFail(_) => MSAL_ERROR_CODE::DEVICE_ENROLLMENT_FAIL,
            MsalError::CryptoFail(_) => MSAL_ERROR_CODE::CRYPTO_FAIL,
            MsalError::NotImplemented => MSAL_ERROR_CODE::NOT_IMPLEMENTED,
            MsalError::ConfigError(_) => MSAL_ERROR_CODE::CONFIG_ERROR,
            MsalError::MFAPollContinue => MSAL_ERROR_CODE::MFA_POLL_CONTINUE,
            MsalError::AADSTSError(_) => MSAL_ERROR_CODE::AADSTS_ERROR,
            MsalError::Missing(_) => MSAL_ERROR_CODE::MISSING,
            MsalError::FormatError(_) => MSAL_ERROR_CODE::FORMAT_ERROR,
            #[cfg(feature = "changepassword")]
            MsalError::ChangePassword => MSAL_ERROR_CODE::CHANGE_PASSWORD,
            MsalError::PasswordRequired => MSAL_ERROR_CODE::PASSWORD_REQUIRED,
            MsalError::SkipMfaRegistration(_, _, _) => MSAL_ERROR_CODE::SKIP_MFA_REGISTRATION,
            MsalError::ConsentRequested(_) => MSAL_ERROR_CODE::CONSENT_REQUESTED,
        }
    }
}

impl From<MsalError> for MSAL_ERROR {
    fn from(error: MsalError) -> Self {
        let aadsts_code = match error {
            MsalError::AADSTSError(ref err) => err.code,
            _ => 0,
        };

        // If the error is an AcquireTokenFailed, also extract error codes
        let acquire_token_error_codes = match error {
            MsalError::AcquireTokenFailed(ref err) => err.error_codes.clone(),
            _ => vec![],
        };

        let msg = match CString::new(error.to_string()) {
            Ok(cstr) => cstr.into_raw(),
            Err(_) => std::ptr::null(),
        };

        let code = MSAL_ERROR_CODE::from(error);

        MSAL_ERROR {
            code,
            msg,
            aadsts_code,
            acquire_token_error_codes: if acquire_token_error_codes.is_empty() {
                std::ptr::null()
            } else {
                let buf = acquire_token_error_codes.clone().into_boxed_slice();
                Box::into_raw(buf) as *const u32
            },
            acquire_token_error_codes_len: acquire_token_error_codes.len(),
        }
    }
}

pub fn no_error() -> *mut MSAL_ERROR {
    std::ptr::null_mut()
}

pub fn make_error(code: MSAL_ERROR_CODE, msg: String) -> *mut MSAL_ERROR {
    let msg = match CString::new(msg) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => std::ptr::null(),
    };

    Box::into_raw(Box::new(MSAL_ERROR {
        code,
        msg,
        aadsts_code: 0,
        acquire_token_error_codes: std::ptr::null(),
        acquire_token_error_codes_len: 0,
    }))
}

pub fn make_error_from_msal_error(error: MsalError) -> *mut MSAL_ERROR {
    Box::into_raw(Box::new(MSAL_ERROR::from(error)))
}
