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

#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
#![doc = include_str!("../README.md")]
#[cfg(feature = "broker")]
use kanidm_hsm_crypto::soft::SoftTpm;
#[cfg(all(feature = "tpm", feature = "broker"))]
use kanidm_hsm_crypto::tpm::TpmTss;
#[cfg(feature = "broker")]
use kanidm_hsm_crypto::{
    AuthValue, BoxedDynTpm as BoxedDynTpmIn, LoadableIdentityKey as LoadableIdentityKeyIn,
    LoadableMachineKey as LoadableMachineKeyIn, LoadableMsOapxbcRsaKey as LoadableMsOapxbcRsaKeyIn,
    MachineKey as MachineKeyIn, SealedData as SealedDataIn, Tpm,
};
use paste::paste;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::slice;
#[cfg(feature = "broker")]
use std::str::FromStr;
#[cfg(feature = "broker")]
use tokio::runtime;
use tracing::{error, warn, Level};
use tracing_subscriber::FmtSubscriber;

use crate::auth::*;
use crate::c_helper::*;
use crate::error::MSAL_ERROR;
use crate::serializer::{deserialize_obj, serialize_obj};
#[cfg(feature = "broker")]
use crate::EnrollAttrs;

#[cfg(feature = "broker")]
pub struct BoxedDynTpm(BoxedDynTpmIn);
#[cfg(feature = "broker")]
pub struct LoadableIdentityKey(LoadableIdentityKeyIn);
#[cfg(feature = "broker")]
pub struct LoadableMsOapxbcRsaKey(LoadableMsOapxbcRsaKeyIn);
#[cfg(feature = "broker")]
pub struct MachineKey(MachineKeyIn);
#[cfg(feature = "broker")]
pub struct LoadableMachineKey(LoadableMachineKeyIn);
#[cfg(feature = "broker")]
pub struct SealedData(SealedDataIn);

macro_rules! serialize_and_deserialize_funcs {
    ($type:ty) => {
        paste! {
            #[no_mangle]
            #[doc = "Serialize a `" $type "` object to bytes."]
            pub unsafe extern "C" fn [<serialize _ $type:snake:lower>] (value: &$type,
                                                                        out_buf: *mut *mut u8,
                                                                        out_len: *mut usize,
            ) -> MSAL_ERROR {
                let bytes = match serialize_obj(&value.0) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        error!("{:?}", e);
                        return MSAL_ERROR::INVALID_JSON;
                    },
                };

                let mut bytes = std::mem::ManuallyDrop::new(bytes);
                unsafe {
                    *out_buf = bytes.as_mut_ptr();
                    *out_len = bytes.len();
                }

                MSAL_ERROR::SUCCESS
            }

            #[no_mangle]
            #[doc = "Deserialize a `" $type "` object from bytes."]
            pub unsafe extern "C" fn [<deserialize _ $type:snake:lower>] (in_buf: *mut u8,
                                                                          in_len: usize,
                                                                          out: *mut *mut $type,
            ) -> MSAL_ERROR {
                let bytes = slice::from_raw_parts(in_buf, in_len);
                let res = match deserialize_obj(bytes) {
                    Ok(res) => res,
                    Err(e) => {
                        error!("{:?}", e);
                        return MSAL_ERROR::INVALID_JSON;
                    },
                };
                unsafe {
                    *out = Box::into_raw(Box::new($type(res)));
                }

                MSAL_ERROR::SUCCESS
            }
        }
    };
}
serialize_and_deserialize_funcs!(LoadableMachineKey);
serialize_and_deserialize_funcs!(LoadableMsOapxbcRsaKey);
serialize_and_deserialize_funcs!(LoadableIdentityKey);
serialize_and_deserialize_funcs!(SealedData);

/// # Safety
///
/// The calling function must ensure that the `input` raw pointer is valid and
/// can be dereferenced.
#[no_mangle]
pub unsafe extern "C" fn raw_serialized_free(input: *mut u8, len: usize) {
    if !input.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(input, len, len);
        }
    }
}

#[repr(C)]
pub enum TracingLevel {
    ERROR,
    WARN,
    INFO,
    DEBUG,
    TRACE,
}

impl From<TracingLevel> for Level {
    fn from(level: TracingLevel) -> Self {
        match level {
            TracingLevel::ERROR => Level::ERROR,
            TracingLevel::WARN => Level::WARN,
            TracingLevel::INFO => Level::INFO,
            TracingLevel::DEBUG => Level::DEBUG,
            TracingLevel::TRACE => Level::TRACE,
        }
    }
}

#[no_mangle]
pub extern "C" fn set_global_tracing_level(level: TracingLevel) -> MSAL_ERROR {
    let level: Level = level.into();
    let subscriber = FmtSubscriber::builder().with_max_level(level).finish();

    match tracing::subscriber::set_global_default(subscriber) {
        Ok(_) => MSAL_ERROR::SUCCESS,
        Err(e) => {
            error!("{:?}", e);
            MSAL_ERROR::GENERAL_FAILURE
        }
    }
}

/// Initialize a TPM struct
///
/// # Arguments
///
/// * `tcti_name` - An optional TPM Transmission Interface. If this parameter
///   is NULL, a Soft Tpm is initialized.
///
/// * `out` - An output parameter which will contain the initialized
///   BoxedDynTpm.
///
/// # Safety
///
/// The calling function must ensure that the `tcti_name` is either a valid c
/// string, or NULL. It must also ensure that `out` is a valid c BoxedDynTpm
/// double pointer.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn tpm_init(
    tcti_name: *const c_char,
    out: *mut *mut BoxedDynTpm,
) -> MSAL_ERROR {
    if out.is_null() {
        error!("Invalid output parameter!");
        return MSAL_ERROR::INVALID_POINTER;
    }

    let tpm = BoxedDynTpm(match wrap_c_char(tcti_name) {
        #[cfg(feature = "tpm")]
        Some(tcti_name) => match TpmTss::new(&tcti_name) {
            Ok(tpm_tss) => BoxedDynTpmIn::new(tpm_tss),
            Err(e) => {
                error!("{:?}", e);
                return MSAL_ERROR::TPM_FAIL;
            }
        },
        #[cfg(not(feature = "tpm"))]
        Some(_) => {
            warn!(
                "{} not built with tpm feature. Hardware tpm request ignored.",
                env!("CARGO_PKG_NAME")
            );
            BoxedDynTpmIn::new(SoftTpm::new())
        }
        None => BoxedDynTpmIn::new(SoftTpm::new()),
    });
    unsafe {
        *out = Box::into_raw(Box::new(tpm));
    }

    MSAL_ERROR::SUCCESS
}

/// # Safety
///
/// The calling function must ensure that `out` is a valid c
/// char double pointer.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn auth_value_generate(out: *mut *mut c_char) -> MSAL_ERROR {
    match AuthValue::generate() {
        Ok(auth_str) => {
            unsafe {
                *out = wrap_string(&auth_str);
            }
            MSAL_ERROR::SUCCESS
        }
        Err(e) => {
            error!("{:?}", e);
            MSAL_ERROR::NO_MEMORY
        }
    }
}

/// # Safety
///
/// The calling function must ensure that the `tpm` is a valid BoxedDynTpm,
/// that `auth_value` is a valid C string, and that `out` is a valid c
/// LoadableMachineKey double pointer.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn tpm_machine_key_create(
    tpm: *mut BoxedDynTpm,
    auth_value: *const c_char,
    out: *mut *mut LoadableMachineKey,
) -> MSAL_ERROR {
    let tpm = &mut unsafe { &mut *tpm }.0;
    let auth_str = match wrap_c_char(auth_value) {
        Some(auth_str) => auth_str,
        None => {
            error!("Invalid auth_value parameter!");
            return MSAL_ERROR::INVALID_POINTER;
        }
    };
    let auth_value = match AuthValue::from_str(&auth_str) {
        Ok(auth_value) => auth_value,
        Err(e) => {
            error!("{:?}", e);
            return MSAL_ERROR::TPM_FAIL;
        }
    };

    let loadable_machine_key = match tpm.machine_key_create(&auth_value) {
        Ok(loadable_machine_key) => loadable_machine_key,
        Err(e) => {
            error!("{:?}", e);
            return MSAL_ERROR::TPM_FAIL;
        }
    };

    unsafe {
        *out = Box::into_raw(Box::new(LoadableMachineKey(loadable_machine_key)));
    }

    MSAL_ERROR::SUCCESS
}

/// # Safety
///
/// The calling function must ensure that the `tpm` is a valid BoxedDynTpm,
/// that `auth_value` is a valid C string, that `exported_key` is a valid
/// LoadableMachineKey, and that `out` is a valid C MachineKey double pointer.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn tpm_machine_key_load(
    tpm: *mut BoxedDynTpm,
    auth_value: *const c_char,
    exported_key: *mut LoadableMachineKey,
    out: *mut *mut MachineKey,
) -> MSAL_ERROR {
    let tpm = &mut unsafe { &mut *tpm }.0;
    let auth_str = match wrap_c_char(auth_value) {
        Some(auth_str) => auth_str,
        None => {
            error!("Invalid auth_value parameter!");
            return MSAL_ERROR::INVALID_POINTER;
        }
    };
    let auth_value = match AuthValue::from_str(&auth_str) {
        Ok(auth_value) => auth_value,
        Err(e) => {
            error!("{:?}", e);
            return MSAL_ERROR::TPM_FAIL;
        }
    };
    let exported_key = &mut unsafe { &mut *exported_key }.0;

    let machine_key = match tpm.machine_key_load(&auth_value, exported_key) {
        Ok(machine_key) => machine_key,
        Err(e) => {
            error!("{:?}", e);
            return MSAL_ERROR::TPM_FAIL;
        }
    };

    unsafe {
        *out = Box::into_raw(Box::new(MachineKey(machine_key)));
    }

    MSAL_ERROR::SUCCESS
}

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
/// * `out` - An output parameter which will contain the initialized
///   BrokerClientApplication.
///
/// NOTE: If `transport_key` and `cert_key` are not provided from a previous
/// device enrollment, then enrollment will be required.
///
/// # Safety
///
/// The calling function must ensure that the `authority` is either a valid c
/// string, or NULL. It must also ensure that `transport_key` is a valid c
/// LoadableMsOapxbcRsaKey pointer or NULL, that `cert_key` is a valid c
/// LoadableIdentityKey pointer or NULL, and that `out` is a valid c
/// BrokerClientApplication double pointer.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn broker_init(
    authority: *const c_char,
    client_id: *const c_char,
    transport_key: *mut LoadableMsOapxbcRsaKey,
    cert_key: *mut LoadableIdentityKey,
    out: *mut *mut BrokerClientApplication,
) -> MSAL_ERROR {
    if out.is_null() {
        return MSAL_ERROR::INVALID_POINTER;
    }
    let transport_key = match transport_key.is_null() {
        true => None,
        false => Some(unsafe { &mut *transport_key }.0.clone()),
    };
    let cert_key = match cert_key.is_null() {
        true => None,
        false => Some(unsafe { &mut *cert_key }.0.clone()),
    };
    match BrokerClientApplication::new(
        wrap_c_char(authority).as_deref(),
        wrap_c_char(client_id).as_deref(),
        transport_key,
        cert_key,
    ) {
        Ok(client) => {
            unsafe {
                *out = Box::into_raw(Box::new(client));
            }
            MSAL_ERROR::SUCCESS
        }
        Err(e) => {
            error!("{:?}", e);
            MSAL_ERROR::from(e)
        }
    }
}

/// Initialize attributes for device enrollment
///
/// # Arguments
///
/// * `target_domain` - The domain to be enrolled in.
///
/// * `device_display_name` - An optional chosen display name for the
///   enrolled device. Defaults to the system hostname.
///
/// * `device_type` - An optional device type. Defaults to 'Linux'. This
///   effects which Intune policies are distributed to the client.
///
/// * `join_type` - A join type. Possible values are:
///     - 0: Azure AD join.
///     - 4: Azure AD register only.
///     - 6: Azure AD hybrid join.
///     - 8: Azure AD join.
///
/// * `os_version` - An optional OS version. Defaults to the contents of
///   /etc/os-release.
///
/// * `out` - A new EnrollAttrs for device enrollment.
///
/// # Safety
///
/// The calling function must ensure that `target_domain` is a valid c string,
/// that `device_display_name` is either a valid c string or NULL, that
/// `device_type` is either a valid c string or NULL, that `os_version` is
/// either a valid c string or NULL, and that `out` is a valid c EnrollAttrs
/// double pointer.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn enroll_attrs_init(
    target_domain: *const c_char,
    device_display_name: *mut c_char,
    device_type: *mut c_char,
    join_type: c_int,
    os_version: *mut c_char,
    out: *mut *mut EnrollAttrs,
) -> MSAL_ERROR {
    if out.is_null() {
        error!("Invalid output parameter!");
        return MSAL_ERROR::INVALID_POINTER;
    }
    match EnrollAttrs::new(
        match wrap_c_char(target_domain) {
            Some(target_domain) => target_domain,
            None => {
                error!("Invalid target_domain parameter!");
                return MSAL_ERROR::INVALID_POINTER;
            }
        },
        wrap_c_char(device_display_name),
        wrap_c_char(device_type),
        Some(join_type as u32),
        wrap_c_char(os_version),
    ) {
        Ok(attrs) => {
            unsafe {
                *out = Box::into_raw(Box::new(attrs));
            }
            MSAL_ERROR::SUCCESS
        }
        Err(e) => {
            error!("{:?}", e);
            MSAL_ERROR::from(e)
        }
    }
}

/// Enroll the device in the directory.
///
/// # Arguments
///
/// * `client` - A BrokerClientApplication created by a call to
///   `broker_init`.
///
/// * `token` - Token obtained via either
///   acquire_token_by_username_password_for_device_enrollment
///   or acquire_token_by_device_flow.
///
/// * `attrs` - A EnrollAttrs created by a call to `enroll_attrs_init`. This
///   parameter is consumed and destroyed by the recipient.
///
/// * `tpm` - The tpm object.
///
/// * `machine_key` - The TPM MachineKey associated with this application.
///
/// * `out_transport_key` - A LoadableMsOapxbcRsaKey transport key output
///   parameter.
///
/// * `out_cert_key` - A LoadableIdentityKey certificate key output parameter.
///
/// * `out_device_id` - An output parameter which is the device id of the
///   enrolled device.
///
/// # Safety
///
/// The calling function should ensure that `client`, `token`, `attrs`, `tpm`,
/// and `machine_key` are valid pointers to their respective types.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn broker_enroll_device(
    client: *mut BrokerClientApplication,
    refresh_token: *mut c_char,
    attrs: *mut EnrollAttrs,
    tpm: *mut BoxedDynTpm,
    machine_key: *mut MachineKey,
    out_transport_key: *mut *mut LoadableMsOapxbcRsaKey,
    out_cert_key: *mut *mut LoadableIdentityKey,
    out_device_id: *mut *mut c_char,
) -> MSAL_ERROR {
    // Ensure our input parameters are not NULL
    if client.is_null() || attrs.is_null() || tpm.is_null() || machine_key.is_null() {
        error!("Invalid input parameters!");
        return MSAL_ERROR::INVALID_POINTER;
    }
    // Ensure our out parameters are not NULL
    if out_transport_key.is_null() || out_cert_key.is_null() || out_device_id.is_null() {
        error!("Invalid output parameters!");
        return MSAL_ERROR::INVALID_POINTER;
    }

    let client = unsafe { &mut *client };
    let refresh_token = match wrap_c_char(refresh_token) {
        Some(refresh_token) => refresh_token,
        None => {
            error!("Invalid refresh_token input!");
            return MSAL_ERROR::INVALID_POINTER;
        }
    };
    let attrs = unsafe { Box::from_raw(attrs) };
    let tpm = unsafe { &mut *tpm };
    let machine_key = unsafe { &mut *machine_key };
    let (transport_key, cert_key, device_id) = match run_async!(
        client,
        enroll_device,
        &refresh_token,
        *attrs,
        &mut tpm.0,
        &machine_key.0,
    ) {
        Ok(resp) => resp,
        Err(e) => return e,
    };
    let c_device_id = match CString::new(device_id) {
        Ok(c_device_id) => c_device_id,
        Err(e) => {
            error!("{:?}", e);
            return MSAL_ERROR::NO_MEMORY;
        }
    };
    unsafe {
        *out_transport_key = Box::into_raw(Box::new(LoadableMsOapxbcRsaKey(transport_key)));
        *out_cert_key = Box::into_raw(Box::new(LoadableIdentityKey(cert_key)));
        *out_device_id = c_device_id.into_raw();
    }
    MSAL_ERROR::SUCCESS
}

/// Gets a token for a given resource via user credentials.
///
/// # Arguments
///
/// * `client` - A BrokerClientApplication created by a call to
///   `broker_init`.
///
/// * `username` - Typically a UPN in the form of an email address.
///
/// * `password` - The password.
///
/// * `scopes` - An array of scopes requested to access a protected API (a
///   resource).
///
/// * `request_resource` - A resource for obtaining an access token.
///   Default is the MS Graph API (00000002-0000-0000-c000-000000000000).
///
/// * `tpm` - The tpm object.
///
/// * `machine_key` - The TPM MachineKey associated with this application.
///
/// * `out` - A UserToken containing an access_token.
///
/// # Safety
///
/// The calling function should ensure that `client`, `username`, `password`,
/// `scopes`, `tpm`, and `machine_key` are valid pointers to their respective types.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn broker_acquire_token_by_username_password(
    client: *mut BrokerClientApplication,
    username: *const c_char,
    password: *const c_char,
    scopes: *const *const c_char,
    scopes_len: c_int,
    request_resource: *const c_char,
    #[cfg(feature = "on_behalf_of")] on_behalf_of_client_id: *const c_char,
    tpm: *mut BoxedDynTpm,
    machine_key: *mut MachineKey,
    out: *mut *mut UserToken,
) -> MSAL_ERROR {
    if client.is_null() || tpm.is_null() || machine_key.is_null() {
        error!("Invalid input parameters!");
        return MSAL_ERROR::INVALID_POINTER;
    }
    // Ensure our out parameter is not NULL
    if out.is_null() {
        error!("Invalid output parameter!");
        return MSAL_ERROR::INVALID_POINTER;
    }

    let client = unsafe { &mut *client };
    let username = match wrap_c_char(username) {
        Some(username) => username,
        None => {
            error!("Invalid input username!");
            return MSAL_ERROR::INVALID_POINTER;
        }
    };
    let password = match wrap_c_char(password) {
        Some(password) => password,
        None => {
            error!("Invalid input password!");
            return MSAL_ERROR::INVALID_POINTER;
        }
    };
    let scopes = match str_array_to_vec(scopes, scopes_len) {
        Ok(scopes) => scopes,
        Err(e) => return e,
    };
    let request_resource = wrap_c_char(request_resource);
    let tpm = unsafe { &mut *tpm };
    let machine_key = unsafe { &mut *machine_key };
    #[cfg(feature = "on_behalf_of")]
    let on_behalf_of_client_id = wrap_c_char(on_behalf_of_client_id);
    let resp = match run_async!(
        client,
        acquire_token_by_username_password,
        &username,
        &password,
        str_vec_ref!(scopes),
        request_resource,
        #[cfg(feature = "on_behalf_of")]
        on_behalf_of_client_id.as_deref(),
        &mut tpm.0,
        &machine_key.0,
    ) {
        Ok(resp) => resp,
        Err(e) => return e,
    };
    unsafe {
        *out = Box::into_raw(Box::new(resp));
    }
    MSAL_ERROR::SUCCESS
}

/// Acquire token(s) based on a refresh token (RT) obtained from elsewhere.
///
/// # Arguments
///
/// * `client` - A BrokerClientApplication created by a call to
///   `broker_init`.
///
/// * `refresh_token` - The old refresh token, as a string.
///
/// * `scopes` - The scopes associated with this old RT.
///
/// * `request_resource` - A resource for obtaining an access token.
///   Default is the MS Graph API (00000002-0000-0000-c000-000000000000).
///
/// * `tpm` - The tpm object.
///
/// * `machine_key` - The TPM MachineKey associated with this application.
///
/// * `out` - A UserToken, which means migration was successful.
///
/// # Safety
///
/// The calling function must ensure that `client`, `tpm`, `machine_key`, are
/// valid pointers to their respective types.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn broker_acquire_token_by_refresh_token(
    client: *mut BrokerClientApplication,
    refresh_token: *const c_char,
    scopes: *const *const c_char,
    scopes_len: c_int,
    request_resource: *const c_char,
    #[cfg(feature = "on_behalf_of")] on_behalf_of_client_id: *const c_char,
    tpm: *mut BoxedDynTpm,
    machine_key: *mut MachineKey,
    out: *mut *mut UserToken,
) -> MSAL_ERROR {
    if client.is_null() || tpm.is_null() || machine_key.is_null() {
        error!("Invalid input parameters!");
        return MSAL_ERROR::INVALID_POINTER;
    }
    // Ensure our out parameter is not NULL
    if out.is_null() {
        error!("Invalid output parameter!");
        return MSAL_ERROR::INVALID_POINTER;
    }

    let client = unsafe { &mut *client };
    let refresh_token = match wrap_c_char(refresh_token) {
        Some(refresh_token) => refresh_token,
        None => {
            error!("Invalid input refresh_token!");
            return MSAL_ERROR::INVALID_POINTER;
        }
    };
    let scopes = match str_array_to_vec(scopes, scopes_len) {
        Ok(scopes) => scopes,
        Err(e) => return e,
    };
    let request_resource = wrap_c_char(request_resource);
    #[cfg(feature = "on_behalf_of")]
    let on_behalf_of_client_id = wrap_c_char(on_behalf_of_client_id);
    let tpm = unsafe { &mut *tpm };
    let machine_key = unsafe { &mut *machine_key };
    let resp = match run_async!(
        client,
        acquire_token_by_refresh_token,
        &refresh_token,
        str_vec_ref!(scopes),
        request_resource,
        #[cfg(feature = "on_behalf_of")]
        on_behalf_of_client_id.as_deref(),
        &mut tpm.0,
        &machine_key.0,
    ) {
        Ok(resp) => resp,
        Err(e) => return e,
    };
    unsafe {
        *out = Box::into_raw(Box::new(resp));
    }
    MSAL_ERROR::SUCCESS
}

/// Gets a token for enrollment via user credentials.
///
/// # Arguments
///
/// * `client` - A BrokerClientApplication created by a call to
///   `broker_init`.
///
/// * `username` - Typically a UPN in the form of an email address.
///
/// * `password` - The password.
///
/// * `out` - A UserToken containing an access_token.
///
/// # Safety
///
/// The calling function must ensure that `client` is a valid pointer.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn broker_acquire_token_by_username_password_for_device_enrollment(
    client: *mut BrokerClientApplication,
    username: *const c_char,
    password: *const c_char,
    out: *mut *mut UserToken,
) -> MSAL_ERROR {
    if client.is_null() {
        error!("Invalid input parameters!");
        return MSAL_ERROR::INVALID_POINTER;
    }
    // Ensure our out parameter is not NULL
    if out.is_null() {
        error!("Invalid output parameter!");
        return MSAL_ERROR::INVALID_POINTER;
    }

    let client = unsafe { &mut *client };
    let username = match wrap_c_char(username) {
        Some(username) => username,
        None => {
            error!("Invalid input username!");
            return MSAL_ERROR::INVALID_POINTER;
        }
    };
    let password = match wrap_c_char(password) {
        Some(password) => password,
        None => {
            error!("Invalid input password!");
            return MSAL_ERROR::INVALID_POINTER;
        }
    };
    let resp = match run_async!(
        client,
        acquire_token_by_username_password_for_device_enrollment,
        &username,
        &password,
    ) {
        Ok(resp) => resp,
        Err(e) => return e,
    };
    unsafe {
        *out = Box::into_raw(Box::new(resp));
    }
    MSAL_ERROR::SUCCESS
}

/// Initiate a Device Flow instance for enrollment, which will be
/// used in acquire_token_by_device_flow.
///
/// # Arguments
///
/// * `client` - A BrokerClientApplication created by a call to
///   `broker_init`.
///
/// * `out` - A DeviceAuthorizationResponse containing a user_code key,
///   among others
///
/// # Safety
///
/// The calling function must ensure that `client` is a valid pointer.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn broker_initiate_device_flow_for_device_enrollment(
    client: *mut BrokerClientApplication,
    out: *mut *mut DeviceAuthorizationResponse,
) -> MSAL_ERROR {
    if client.is_null() {
        error!("Invalid input parameter!");
        return MSAL_ERROR::INVALID_POINTER;
    }
    // Ensure our out parameter is not NULL
    if out.is_null() {
        error!("Invalid output parameter!");
        return MSAL_ERROR::INVALID_POINTER;
    }

    let client = unsafe { &mut *client };
    let resp = match run_async!(client, initiate_device_flow_for_device_enrollment) {
        Ok(resp) => resp,
        Err(e) => return e,
    };
    unsafe {
        *out = Box::into_raw(Box::new(resp));
    }
    MSAL_ERROR::SUCCESS
}

/// Obtain token for enrollment by a device flow object, with customizable
/// polling effect.
///
/// # Arguments
///
/// * `client` - A BrokerClientApplication created by a call to
///   `broker_init`.
///
/// * `flow` - A DeviceAuthorizationResponse previously generated by
/// initiate_device_flow.
///
/// * `out` - A UserToken containing an access_token.
///
/// # Safety
///
/// The calling function must ensure that `client` is a valid pointer.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn broker_acquire_token_by_device_flow(
    client: *mut BrokerClientApplication,
    flow: *mut DeviceAuthorizationResponse,
    out: *mut *mut UserToken,
) -> MSAL_ERROR {
    if client.is_null() || flow.is_null() {
        error!("Invalid input parameters!");
        return MSAL_ERROR::INVALID_POINTER;
    }
    // Ensure our out parameter is not NULL
    if out.is_null() {
        error!("Invalid output parameter!");
        return MSAL_ERROR::INVALID_POINTER;
    }

    let client = unsafe { &mut *client };
    let flow = unsafe { &mut *flow }.clone();
    let resp = match run_async!(client, acquire_token_by_device_flow, flow) {
        Ok(resp) => resp,
        Err(e) => return e,
    };
    unsafe {
        *out = Box::into_raw(Box::new(resp));
    }
    MSAL_ERROR::SUCCESS
}

/// Check if a user exists in Azure Entra ID
///
/// # Arguments
///
/// * `client` - A BrokerClientApplication created by a call to
///   `broker_init`.
///
/// * `username` - Typically a UPN in the form of an email address.
///
/// * `out` - true|false
///
/// # Safety
///
/// The calling function must ensure that `client` is a valid pointer.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn broker_check_user_exists(
    client: *mut BrokerClientApplication,
    username: *const c_char,
    out: *mut bool,
) -> MSAL_ERROR {
    if client.is_null() {
        error!("Invalid input parameter!");
        return MSAL_ERROR::INVALID_POINTER;
    }
    // Ensure our out parameter is not NULL
    if out.is_null() {
        error!("Invalid output parameter!");
        return MSAL_ERROR::INVALID_POINTER;
    }

    let client = unsafe { &mut *client };
    let username = match wrap_c_char(username) {
        Some(username) => username,
        None => {
            error!("Invalid input username!");
            return MSAL_ERROR::INVALID_POINTER;
        }
    };
    let resp = match run_async!(client, check_user_exists, &username, &[]) {
        Ok(resp) => resp,
        Err(e) => return e,
    };
    unsafe {
        *out = resp.exists();
    }
    MSAL_ERROR::SUCCESS
}

/// Initiate an MFA flow for enrollment via user credentials.
///
/// # Arguments
///
/// * `client` - A BrokerClientApplication created by a call to
///   `broker_init`.
///
/// * `username` - Typically a UPN in the form of an email address.
///
/// * `password` - The password.
///
/// * `out` - A MFAAuthContinue containing the information needed to continue the
///   authentication flow.
///
/// # Safety
///
/// The calling function should ensure that `client`, `username`, and
/// `password`, are valid pointers to their respective types.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn broker_initiate_acquire_token_by_mfa_flow_for_device_enrollment(
    client: *mut BrokerClientApplication,
    username: *const c_char,
    password: *const c_char,
    out: *mut *mut MFAAuthContinue,
) -> MSAL_ERROR {
    // Ensure our out parameter is not NULL
    if out.is_null() {
        error!("Invalid output parameter!");
        return MSAL_ERROR::INVALID_POINTER;
    }
    let client = unsafe { &mut *client };
    let username = match wrap_c_char(username) {
        Some(username) => username,
        None => {
            error!("Invalid input username!");
            return MSAL_ERROR::INVALID_POINTER;
        }
    };
    let password = match wrap_c_char(password) {
        Some(password) => password,
        None => {
            error!("Invalid input password!");
            return MSAL_ERROR::INVALID_POINTER;
        }
    };
    let flow = match run_async!(
        client,
        initiate_acquire_token_by_mfa_flow_for_device_enrollment,
        &username,
        Some(&password),
        &[],
        None,
    ) {
        Ok(resp) => resp,
        Err(e) => return e,
    };
    unsafe {
        *out = Box::into_raw(Box::new(flow));
    }
    MSAL_ERROR::SUCCESS
}

/// Obtain token by a MFA flow object.
///
/// # Arguments
///
/// * `client` - A BrokerClientApplication created by a call to
///   `broker_init`.
///
/// * `username` - Typically a UPN in the form of an email address.
///
/// * `auth_data` - An optional token received for the MFA flow (some MFA
///   flows do not require input). If this MFA type does not require input,
///   this MUST be NULL.
///
/// * `poll_attempt` - The polling attempt number. If this MFA type requires
///   input, this should be 0.
///
/// * `flow` - A MFAAuthContinue previously generated by
/// initiate_acquire_token_by_mfa_flow.
///
/// * `out` - A UserToken containing an access_token.
/// # Safety
///
/// The calling function should ensure that `client`, `username`, `auth_data`,
/// `poll_attempt`, and `flow` are valid pointers to their respective types.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn broker_acquire_token_by_mfa_flow(
    client: *mut BrokerClientApplication,
    username: *const c_char,
    auth_data: *const c_char,
    poll_attempt: c_int,
    flow: *mut MFAAuthContinue,
    out: *mut *mut UserToken,
) -> MSAL_ERROR {
    // Ensure our out parameter is not NULL
    if out.is_null() {
        error!("Invalid output parameter!");
        return MSAL_ERROR::INVALID_POINTER;
    }
    let client = unsafe { &mut *client };
    let username = match wrap_c_char(username) {
        Some(username) => username,
        None => {
            error!("Invalid input username!");
            return MSAL_ERROR::INVALID_POINTER;
        }
    };
    let auth_data = wrap_c_char(auth_data);
    let poll_attempt = match auth_data {
        Some(_) => None,
        None => Some(poll_attempt as u32),
    };
    let flow = unsafe { &mut *flow };
    let resp = match run_async!(
        client,
        acquire_token_by_mfa_flow,
        &username,
        auth_data.as_deref(),
        poll_attempt,
        flow,
    ) {
        Ok(resp) => resp,
        Err(e) => return e,
    };
    unsafe {
        *out = Box::into_raw(Box::new(resp));
    }
    MSAL_ERROR::SUCCESS
}

/// Get the msg from a MFAAuthContinue flow
///
/// # Safety
///
/// The calling function should ensure that `flow` is a valid MFAAuthContinue
/// pointer, and that `out` is a valid double c_char pointer.
#[no_mangle]
pub unsafe extern "C" fn mfa_auth_continue_msg(
    flow: *mut MFAAuthContinue,
    out: *mut *mut c_char,
) -> MSAL_ERROR {
    c_str_from_object_string!(flow, msg, out)
}

/// Get the mfa_method from a MFAAuthContinue flow
///
/// # Safety
///
/// The calling function should ensure that `flow` is a valid MFAAuthContinue
/// pointer, and that `out` is a valid double c_char pointer.
#[no_mangle]
pub unsafe extern "C" fn mfa_auth_continue_mfa_method(
    flow: *mut MFAAuthContinue,
    out: *mut *mut c_char,
) -> MSAL_ERROR {
    c_str_from_object_string!(flow, mfa_method, out)
}

/// Get the polling_interval from a MFAAuthContinue flow
///
/// If no polling_interval was defined by Entra ID, this function returns -1.
///
/// # Safety
///
/// The calling function should ensure that `flow` is a valid MFAAuthContinue
/// pointer.
#[no_mangle]
pub unsafe extern "C" fn mfa_auth_continue_polling_interval(flow: *mut MFAAuthContinue) -> c_int {
    let flow = unsafe { &mut *flow };
    match flow.polling_interval {
        Some(polling_interval) => polling_interval as c_int,
        None => -1,
    }
}

/// Get the max_poll_attempts from a MFAAuthContinue flow
///
/// If no max_poll_attempts was defined by Entra ID, this function returns -1.
///
/// # Safety
///
/// The calling function should ensure that `flow` is a valid MFAAuthContinue
/// pointer.
#[no_mangle]
pub unsafe extern "C" fn mfa_auth_continue_max_poll_attempts(flow: *mut MFAAuthContinue) -> c_int {
    let flow = unsafe { &mut *flow };
    match flow.max_poll_attempts {
        Some(max_poll_attempts) => max_poll_attempts as c_int,
        None => -1,
    }
}

/// Gets a Primary Refresh Token (PRT) via user credentials.
///
/// # Arguments
///
/// * `client` - A BrokerClientApplication created by a call to
///   `broker_init`.
///
/// * `username` - Typically a UPN in the form of an email address.
///
/// * `password` - The password.
///
/// * `tpm` - The tpm object.
///
/// * `machine_key` - The TPM MachineKey associated with this application.
///
/// * `out` - An encrypted PrimaryRefreshToken, containing a refresh_token and tgt.
///
/// # Safety
///
/// The calling function should ensure that `client`, `username`, `password`,
/// `tpm`, and `machine_key` are valid pointers to their respective types.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn broker_acquire_user_prt_by_username_password(
    client: *mut BrokerClientApplication,
    username: *const c_char,
    password: *const c_char,
    tpm: *mut BoxedDynTpm,
    machine_key: *mut MachineKey,
    out: *mut *mut SealedData,
) -> MSAL_ERROR {
    if client.is_null() || tpm.is_null() || machine_key.is_null() {
        error!("Invalid input parameters!");
        return MSAL_ERROR::INVALID_POINTER;
    }
    // Ensure our out parameter is not NULL
    if out.is_null() {
        error!("Invalid output parameter!");
        return MSAL_ERROR::INVALID_POINTER;
    }

    let client = unsafe { &mut *client };
    let username = match wrap_c_char(username) {
        Some(username) => username,
        None => {
            error!("Invalid input username!");
            return MSAL_ERROR::INVALID_POINTER;
        }
    };
    let password = match wrap_c_char(password) {
        Some(password) => password,
        None => {
            error!("Invalid input password!");
            return MSAL_ERROR::INVALID_POINTER;
        }
    };
    let tpm = unsafe { &mut *tpm };
    let machine_key = unsafe { &mut *machine_key };
    let resp = match run_async!(
        client,
        acquire_user_prt_by_username_password,
        &username,
        &password,
        &mut tpm.0,
        &machine_key.0,
    ) {
        Ok(resp) => resp,
        Err(e) => return e,
    };
    unsafe {
        *out = Box::into_raw(Box::new(SealedData(resp)));
    }
    MSAL_ERROR::SUCCESS
}

/// Gets a Primary Refresh Token (PRT) via a refresh token (RT) obtained
/// previously.
///
/// # Arguments
///
/// * `client` - A BrokerClientApplication created by a call to
///   `broker_init`.
///
/// * `refresh_token` - The old refresh token, as a string.
///
/// * `tpm` - The tpm object.
///
/// * `machine_key` - The TPM MachineKey associated with this application.
///
/// * `out` - An encrypted PrimaryRefreshToken, containing a refresh_token and tgt.
/// # Safety
///
/// The calling function should ensure that `client`, `refresh_token`, `tpm`,
/// and `machine_key` are valid pointers to their respective types.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn broker_acquire_user_prt_by_refresh_token(
    client: *mut BrokerClientApplication,
    refresh_token: *const c_char,
    tpm: *mut BoxedDynTpm,
    machine_key: *mut MachineKey,
    out: *mut *mut SealedData,
) -> MSAL_ERROR {
    if client.is_null() || tpm.is_null() || machine_key.is_null() {
        error!("Invalid input parameters!");
        return MSAL_ERROR::INVALID_POINTER;
    }
    // Ensure our out parameter is not NULL
    if out.is_null() {
        error!("Invalid output parameter!");
        return MSAL_ERROR::INVALID_POINTER;
    }

    let client = unsafe { &mut *client };
    let refresh_token = match wrap_c_char(refresh_token) {
        Some(refresh_token) => refresh_token,
        None => {
            error!("Invalid input refresh_token!");
            return MSAL_ERROR::INVALID_POINTER;
        }
    };
    let tpm = unsafe { &mut *tpm };
    let machine_key = unsafe { &mut *machine_key };
    let resp = match run_async!(
        client,
        acquire_user_prt_by_refresh_token,
        &refresh_token,
        &mut tpm.0,
        &machine_key.0,
    ) {
        Ok(resp) => resp,
        Err(e) => return e,
    };
    unsafe {
        *out = Box::into_raw(Box::new(SealedData(resp)));
    }
    MSAL_ERROR::SUCCESS
}

/// Given the primary refresh token, this method requests an access token.
///
/// # Arguments
///
/// * `client` - A BrokerClientApplication created by a call to
///   `broker_init`.
///
/// * `sealed_prt` -  An encrypted primary refresh token that was
///   previously received from the server.
///
/// * `scopes` - The scopes that the client requests for the access token.
///
/// * `request_resource` - A resource for obtaining an access token.
///   Default is the MS Graph API (00000002-0000-0000-c000-000000000000).
///
/// * `tpm` - The tpm object.
///
/// * `machine_key` - The TPM MachineKey associated with this application.
///
/// * `out` - A UserToken containing an access_token.
///
/// # Safety
///
/// The calling function should ensure that `client`, `sealed_prt`, `scope`,
/// `request_resource`, `tpm`, and `machine_key` are valid pointers to their
/// respective types.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn broker_exchange_prt_for_access_token(
    client: *mut BrokerClientApplication,
    sealed_prt: *mut SealedData,
    scopes: *const *const c_char,
    scopes_len: c_int,
    request_resource: *const c_char,
    #[cfg(feature = "on_behalf_of")] on_behalf_of_client_id: *const c_char,
    tpm: *mut BoxedDynTpm,
    machine_key: *mut MachineKey,
    out: *mut *mut UserToken,
) -> MSAL_ERROR {
    if client.is_null() || tpm.is_null() || machine_key.is_null() {
        error!("Invalid input parameters!");
        return MSAL_ERROR::INVALID_POINTER;
    }
    // Ensure our out parameter is not NULL
    if out.is_null() {
        error!("Invalid output parameter!");
        return MSAL_ERROR::INVALID_POINTER;
    }

    let client = unsafe { &mut *client };
    let sealed_prt = unsafe { &mut *sealed_prt };
    let scopes = match str_array_to_vec(scopes, scopes_len) {
        Ok(scopes) => scopes,
        Err(e) => return e,
    };
    let request_resource = wrap_c_char(request_resource);
    #[cfg(feature = "on_behalf_of")]
    let on_behalf_of_client_id = wrap_c_char(on_behalf_of_client_id);
    let tpm = unsafe { &mut *tpm };
    let machine_key = unsafe { &mut *machine_key };
    let resp = match run_async!(
        client,
        exchange_prt_for_access_token,
        &sealed_prt.0,
        str_vec_ref!(scopes),
        request_resource,
        #[cfg(feature = "on_behalf_of")]
        on_behalf_of_client_id.as_deref(),
        &mut tpm.0,
        &machine_key.0,
    ) {
        Ok(resp) => resp,
        Err(e) => return e,
    };
    unsafe {
        *out = Box::into_raw(Box::new(resp));
    }
    MSAL_ERROR::SUCCESS
}

/// Given the primary refresh token, this method requests a new primary
/// refresh token
///
/// # Arguments
///
/// * `client` - A BrokerClientApplication created by a call to
///   `broker_init`.
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
/// * `out` - An encrypted PrimaryRefreshToken, containing a refresh_token
///   and optionally a tgt. The session key is copied from the old PRT.
///
/// # Safety
///
/// The calling function should ensure that `client`, `sealed_prt`,
/// `tpm`, and `machine_key` are valid pointers to their respective types.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn broker_exchange_prt_for_prt(
    client: *mut BrokerClientApplication,
    sealed_prt: *mut SealedData,
    tpm: *mut BoxedDynTpm,
    machine_key: *mut MachineKey,
    request_tgt: c_int,
    out: *mut *mut SealedData,
) -> MSAL_ERROR {
    if client.is_null() || sealed_prt.is_null() || tpm.is_null() || machine_key.is_null() {
        error!("Invalid input parameters!");
        return MSAL_ERROR::INVALID_POINTER;
    }
    // Ensure our out parameter is not NULL
    if out.is_null() {
        error!("Invalid output parameter!");
        return MSAL_ERROR::INVALID_POINTER;
    }

    let client = unsafe { &mut *client };
    let sealed_prt = unsafe { &mut *sealed_prt };
    let tpm = unsafe { &mut *tpm };
    let machine_key = unsafe { &mut *machine_key };
    let request_tgt = request_tgt != 0;
    let resp = match run_async!(
        client,
        exchange_prt_for_prt,
        &sealed_prt.0,
        &mut tpm.0,
        &machine_key.0,
        request_tgt,
    ) {
        Ok(resp) => resp,
        Err(e) => return e,
    };
    unsafe {
        *out = Box::into_raw(Box::new(SealedData(resp)));
    }
    MSAL_ERROR::SUCCESS
}

/// Provision a new Hello for Business Key
///
/// # Arguments
///
/// * `client` - A BrokerClientApplication created by a call to
///   `broker_init`.
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
/// * `out` - Either the existing LoadableIdentityKey, or a new created
///   key if none was provided.
///
/// # Safety
///
/// The calling function should ensure that `client`, `token`, `tpm`,
/// `machine_key`, and `pin` are valid pointers to their respective types.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn broker_provision_hello_for_business_key(
    client: *mut BrokerClientApplication,
    token: *mut UserToken,
    tpm: *mut BoxedDynTpm,
    machine_key: *mut MachineKey,
    pin: *const c_char,
    out: *mut *mut LoadableIdentityKey,
) -> MSAL_ERROR {
    if client.is_null() || token.is_null() || tpm.is_null() || machine_key.is_null() {
        error!("Invalid input parameters!");
        return MSAL_ERROR::INVALID_POINTER;
    }
    // Ensure our out parameter is not NULL
    if out.is_null() {
        error!("Invalid output parameter!");
        return MSAL_ERROR::INVALID_POINTER;
    }

    let client = unsafe { &mut *client };
    let token = unsafe { &mut *token };
    let tpm = unsafe { &mut *tpm };
    let machine_key = unsafe { &mut *machine_key };
    let pin = match wrap_c_char(pin) {
        Some(pin) => pin,
        None => {
            error!("Invalid input pin!");
            return MSAL_ERROR::INVALID_POINTER;
        }
    };
    let resp = match run_async!(
        client,
        provision_hello_for_business_key,
        token,
        &mut tpm.0,
        &machine_key.0,
        &pin,
    ) {
        Ok(resp) => resp,
        Err(e) => return e,
    };
    unsafe {
        *out = Box::into_raw(Box::new(LoadableIdentityKey(resp)));
    }
    MSAL_ERROR::SUCCESS
}

/// Gets a token for a given resource via a Hello for Business Key
///
/// # Arguments
///
/// * `client` - A BrokerClientApplication created by a call to
///   `broker_init`.
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
/// * `tpm` - The tpm object.
///
/// * `machine_key` - The TPM MachineKey associated with this application.
///
/// * `pin` - The PIN code required to unlock the key.
///
/// * `out` - A UserToken containing an access_token.
///
/// # Safety
///
/// The calling function should ensure that `client`, `username`, `key`, `scopes`,
/// `request_resource`, `tpm`, `machine_key`, and `pin` are valid pointers to their respective types.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn broker_acquire_token_by_hello_for_business_key(
    client: *mut BrokerClientApplication,
    username: *const c_char,
    key: *mut LoadableIdentityKey,
    scopes: *const *const c_char,
    scopes_len: c_int,
    request_resource: *const c_char,
    #[cfg(feature = "on_behalf_of")] on_behalf_of_client_id: *const c_char,
    tpm: *mut BoxedDynTpm,
    machine_key: *mut MachineKey,
    pin: *const c_char,
    out: *mut *mut UserToken,
) -> MSAL_ERROR {
    if client.is_null() || key.is_null() || tpm.is_null() || machine_key.is_null() {
        error!("Invalid input parameters!");
        return MSAL_ERROR::INVALID_POINTER;
    }
    // Ensure our out parameter is not NULL
    if out.is_null() {
        error!("Invalid output parameter!");
        return MSAL_ERROR::INVALID_POINTER;
    }

    let client = unsafe { &mut *client };
    let username = match wrap_c_char(username) {
        Some(username) => username,
        None => {
            error!("Invalid input username!");
            return MSAL_ERROR::INVALID_POINTER;
        }
    };
    let key = unsafe { &mut *key };
    let scopes = match str_array_to_vec(scopes, scopes_len) {
        Ok(scopes) => scopes,
        Err(e) => return e,
    };
    let request_resource = wrap_c_char(request_resource);
    #[cfg(feature = "on_behalf_of")]
    let on_behalf_of_client_id = wrap_c_char(on_behalf_of_client_id);
    let tpm = unsafe { &mut *tpm };
    let machine_key = unsafe { &mut *machine_key };
    let pin = match wrap_c_char(pin) {
        Some(pin) => pin,
        None => {
            error!("Invalid input pin!");
            return MSAL_ERROR::INVALID_POINTER;
        }
    };
    let resp = match run_async!(
        client,
        acquire_token_by_hello_for_business_key,
        &username,
        &key.0,
        str_vec_ref!(scopes),
        request_resource,
        #[cfg(feature = "on_behalf_of")]
        on_behalf_of_client_id.as_deref(),
        &mut tpm.0,
        &machine_key.0,
        &pin,
    ) {
        Ok(resp) => resp,
        Err(e) => return e,
    };
    unsafe {
        *out = Box::into_raw(Box::new(resp));
    }
    MSAL_ERROR::SUCCESS
}

/// Gets a Primary Refresh Token (PRT) via a Hello for Business Key
///
/// # Arguments
///
/// * `client` - A BrokerClientApplication created by a call to
///   `broker_init`.
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
/// * `out` - An encrypted PrimaryRefreshToken, containing a refresh_token and tgt.
///
/// # Safety
///
/// The calling function should ensure that `client`, `username`, `key`, `tpm`,
/// `machine_key`, and `pin` are valid pointers to their respective types.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn broker_acquire_user_prt_by_hello_for_business_key(
    client: *mut BrokerClientApplication,
    username: *const c_char,
    key: *mut LoadableIdentityKey,
    tpm: *mut BoxedDynTpm,
    machine_key: *mut MachineKey,
    pin: *const c_char,
    out: *mut *mut SealedData,
) -> MSAL_ERROR {
    if client.is_null() || key.is_null() || tpm.is_null() || machine_key.is_null() {
        error!("Invalid input parameters!");
        return MSAL_ERROR::INVALID_POINTER;
    }
    // Ensure our out parameter is not NULL
    if out.is_null() {
        error!("Invalid output parameter!");
        return MSAL_ERROR::INVALID_POINTER;
    }

    let client = unsafe { &mut *client };
    let username = match wrap_c_char(username) {
        Some(username) => username,
        None => {
            error!("Invalid input username!");
            return MSAL_ERROR::INVALID_POINTER;
        }
    };
    let key = unsafe { &mut *key };
    let tpm = unsafe { &mut *tpm };
    let machine_key = unsafe { &mut *machine_key };
    let pin = match wrap_c_char(pin) {
        Some(pin) => pin,
        None => {
            error!("Invalid input pin!");
            return MSAL_ERROR::INVALID_POINTER;
        }
    };
    let resp = match run_async!(
        client,
        acquire_user_prt_by_hello_for_business_key,
        &username,
        &key.0,
        &mut tpm.0,
        &machine_key.0,
        &pin,
    ) {
        Ok(resp) => resp,
        Err(e) => return e,
    };
    unsafe {
        *out = Box::into_raw(Box::new(SealedData(resp)));
    }
    MSAL_ERROR::SUCCESS
}

/// Creates a single sign-on (SSO) JWT Cookie from an encrypted Primary
/// Refresh Token (PRT).
///
/// # Arguments
///
/// * `client` - A BrokerClientApplication created by a call to `broker_init`.
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
/// * `out` - A JWT (as a C string) that can be used for single sign-on (SSO)
///   authentication.
///
/// # Safety
///
/// The calling function should ensure that `client`, `prt`, `tpm`, `machine_key`, and `out` are valid pointers to their respective types.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn broker_acquire_prt_sso_cookie(
    client: *mut BrokerClientApplication,
    prt: *mut SealedData,
    tpm: *mut BoxedDynTpm,
    machine_key: *mut MachineKey,
    out: *mut *mut c_char,
) -> MSAL_ERROR {
    if client.is_null() || prt.is_null() || tpm.is_null() || machine_key.is_null() {
        error!("Invalid input parameters!");
        return MSAL_ERROR::INVALID_POINTER;
    }

    // Ensure our out parameter is not NULL
    if out.is_null() {
        error!("Invalid output parameter!");
        return MSAL_ERROR::INVALID_POINTER;
    }

    let client = unsafe { &mut *client };
    let prt = unsafe { &mut *prt };
    let tpm = unsafe { &mut *tpm };
    let machine_key = unsafe { &mut *machine_key };

    let resp = match run_async!(
        client,
        acquire_prt_sso_cookie,
        &prt.0,
        &mut tpm.0,
        &machine_key.0,
    ) {
        Ok(jwt) => jwt,
        Err(e) => return e,
    };

    let c_str = wrap_string(&resp);
    if !c_str.is_null() {
        unsafe {
            *out = c_str;
        }
        MSAL_ERROR::SUCCESS
    } else {
        MSAL_ERROR::INVALID_POINTER
    }
}

/// # Safety
///
/// The calling function must ensure that the `token` raw pointer is valid and
/// can be dereferenced, and that `out` is a valid pointer to a char*.
#[no_mangle]
pub unsafe extern "C" fn user_token_refresh_token(
    token: *mut UserToken,
    out: *mut *mut c_char,
) -> MSAL_ERROR {
    c_str_from_object_string!(token, refresh_token, out)
}

/// # Safety
///
/// The calling function must ensure that the `token` raw pointer is valid and
/// can be dereferenced, and that `out` is a valid pointer to a char*.
#[no_mangle]
pub unsafe extern "C" fn user_token_access_token(
    token: *mut UserToken,
    out: *mut *mut c_char,
) -> MSAL_ERROR {
    c_str_from_object_option_string!(token, access_token, out)
}

/// # Safety
///
/// The calling function must ensure that the `token` raw pointer is valid and
/// can be dereferenced, and that `out` is a valid pointer to a char*.
#[no_mangle]
pub unsafe extern "C" fn user_token_tenant_id(
    token: *mut UserToken,
    out: *mut *mut c_char,
) -> MSAL_ERROR {
    c_str_from_object_func!(token, tenant_id, out)
}

/// # Safety
///
/// The calling function must ensure that the `token` raw pointer is valid and
/// can be dereferenced, and that `out` is a valid pointer to a char*.
#[no_mangle]
pub unsafe extern "C" fn user_token_spn(
    token: *mut UserToken,
    out: *mut *mut c_char,
) -> MSAL_ERROR {
    c_str_from_object_func!(token, spn, out)
}

/// # Safety
///
/// The calling function must ensure that the `token` raw pointer is valid and
/// can be dereferenced, and that `out` is a valid pointer to a char*.
#[no_mangle]
pub unsafe extern "C" fn user_token_uuid(
    token: *mut UserToken,
    out: *mut *mut c_char,
) -> MSAL_ERROR {
    let token = unsafe { &mut *token };
    match token.uuid() {
        Ok(uuid) => {
            let c_str = wrap_string(&uuid.to_string());
            if !c_str.is_null() {
                unsafe {
                    *out = c_str;
                }
                MSAL_ERROR::SUCCESS
            } else {
                error!("Invalid response token.uuid()",);
                MSAL_ERROR::INVALID_POINTER
            }
        }
        Err(e) => {
            error!("{:?}", e);
            MSAL_ERROR::INVALID_POINTER
        }
    }
}

/// # Safety
///
/// The calling function must ensure that the `token` raw pointer is valid and
/// can be dereferenced, and that `out` is a valid pointer to a bool.
#[no_mangle]
pub unsafe extern "C" fn user_token_amr_mfa(token: *mut UserToken, out: *mut bool) -> MSAL_ERROR {
    let token = unsafe { &mut *token };
    match token.amr_mfa() {
        Ok(res) => {
            unsafe {
                *out = res;
            }
            MSAL_ERROR::SUCCESS
        }
        Err(e) => {
            error!("{:?}", e);
            MSAL_ERROR::INVALID_POINTER
        }
    }
}

/// # Safety
///
/// The calling function must ensure that the `token` raw pointer is valid and
/// can be dereferenced, and that `out` is a valid pointer to a bool.
#[no_mangle]
pub unsafe extern "C" fn user_token_prt(
    token: *mut UserToken,
    out: *mut *mut SealedData,
) -> MSAL_ERROR {
    let token = unsafe { &mut *token };
    match &token.prt {
        Some(prt) => {
            unsafe {
                *out = Box::into_raw(Box::new(SealedData(prt.clone())));
            }
            MSAL_ERROR::SUCCESS
        }
        None => {
            error!("PRT not found!");
            MSAL_ERROR::INVALID_POINTER
        }
    }
}

macro_rules! broker_store_tgt {
    ($func:ident, $client:ident, $sealed_prt:ident, $filename:ident, $tpm:ident, $machine_key:ident) => {{
        if $client.is_null() || $sealed_prt.is_null() || $tpm.is_null() || $machine_key.is_null() {
            error!("Invalid input parameters!");
            return MSAL_ERROR::INVALID_POINTER;
        }

        let client = unsafe { &mut *$client };
        let sealed_prt = unsafe { &mut *$sealed_prt };
        let filename = match wrap_c_char($filename) {
            Some(filename) => filename,
            None => {
                error!("Invalid input username!");
                return MSAL_ERROR::INVALID_POINTER;
            }
        };
        let tpm = unsafe { &mut *$tpm };
        let machine_key = unsafe { &mut *$machine_key };

        match client.$func(&sealed_prt.0, &filename, &mut tpm.0, &machine_key.0) {
            Ok(res) => res,
            Err(e) => {
                error!("{:?}", e);
                return MSAL_ERROR::from(e);
            }
        }

        MSAL_ERROR::SUCCESS
    }};
}

/// Gets the Cloud TGT from a sealed PRT and stores it in the Kerberos CCache
///
/// # Arguments
///
/// * `client` - A BrokerClientApplication created by a call to
///   `broker_init`.
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
/// # Safety
///
/// The calling function must ensure that `sealed_prt`, `tpm`, and
/// `machine_key` are valid pointers to their respective types.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn broker_store_cloud_tgt(
    client: *mut BrokerClientApplication,
    sealed_prt: *mut SealedData,
    filename: *const c_char,
    tpm: *mut BoxedDynTpm,
    machine_key: *mut MachineKey,
) -> MSAL_ERROR {
    broker_store_tgt!(
        store_cloud_tgt,
        client,
        sealed_prt,
        filename,
        tpm,
        machine_key
    )
}

/// Gets the AD TGT from a sealed PRT and stores it in the Kerberos CCache
///
/// # Arguments
///
/// * `client` - A BrokerClientApplication created by a call to
///   `broker_init`.
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
/// # Safety
///
/// The calling function must ensure that `sealed_prt`, `tpm`, and
/// `machine_key` are valid pointers to their respective types.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn broker_store_ad_tgt(
    client: *mut BrokerClientApplication,
    sealed_prt: *mut SealedData,
    filename: *const c_char,
    tpm: *mut BoxedDynTpm,
    machine_key: *mut MachineKey,
) -> MSAL_ERROR {
    broker_store_tgt!(store_ad_tgt, client, sealed_prt, filename, tpm, machine_key)
}

/// Get the Kerberos top level names from a sealed PRT
///
/// # Arguments
///
/// * `client` - A BrokerClientApplication created by a call to
///   `broker_init`.
///
/// * `sealed_prt` -  An encrypted primary refresh token that was
///   previously received from the server.
///
/// * `tpm` - The tpm object.
///
/// * `machine_key` - The TPM MachineKey associated with this application.
///
/// * `out` - The Kerberos top level names
///
/// # Safety
///
/// The calling function must ensure that `sealed_prt`, `tpm`, and
/// `machine_key` are valid pointers to their respective types.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn broker_unseal_prt_kerberos_top_level_names(
    client: *mut BrokerClientApplication,
    sealed_prt: *mut SealedData,
    tpm: *mut BoxedDynTpm,
    machine_key: *mut MachineKey,
    out: *mut *mut c_char,
) -> MSAL_ERROR {
    let sealed_prt = unsafe { &mut *sealed_prt };
    let tpm = unsafe { &mut *tpm };
    let machine_key = unsafe { &mut *machine_key };
    c_str_from_object_func!(
        client,
        unseal_prt_kerberos_top_level_names,
        out,
        &sealed_prt.0,
        &mut tpm.0,
        &machine_key.0
    )
}

/// # Safety
///
/// The calling function must ensure that the `client` raw pointer is valid and
/// can be dereferenced.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn broker_free(client: *mut BrokerClientApplication) {
    free_object!(client);
}

/// # Safety
///
/// The calling function must ensure that the `input` raw pointer is valid and
/// can be dereferenced.
#[no_mangle]
pub unsafe extern "C" fn string_free(input: *mut c_char) {
    if !input.is_null() {
        unsafe {
            let _ = CString::from_raw(input);
        }
    }
}

/// # Safety
///
/// The calling function must ensure that the `input` raw pointer is valid and
/// can be dereferenced.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn machine_key_free(input: *mut MachineKey) {
    free_object!(input);
}

/// # Safety
///
/// The calling function must ensure that the `input` raw pointer is valid and
/// can be dereferenced.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn loadable_machine_key_free(input: *mut LoadableMachineKey) {
    free_object!(input);
}

/// # Safety
///
/// The calling function must ensure that the `input` raw pointer is valid and
/// can be dereferenced.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn loadable_ms_oapxbc_rsa_key_free(input: *mut LoadableMsOapxbcRsaKey) {
    free_object!(input);
}

/// # Safety
///
/// The calling function must ensure that the `input` raw pointer is valid and
/// can be dereferenced.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn loadable_identity_key_free(input: *mut LoadableIdentityKey) {
    free_object!(input);
}

/// # Safety
///
/// The calling function must ensure that the `input` raw pointer is valid and
/// can be dereferenced.
#[no_mangle]
pub unsafe extern "C" fn user_token_free(input: *mut UserToken) {
    free_object!(input);
}

/// # Safety
///
/// The calling function must ensure that the `input` raw pointer is valid and
/// can be dereferenced.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn tpm_free(input: *mut BoxedDynTpm) {
    free_object!(input);
}

/// # Safety
///
/// The calling function must ensure that the `input` raw pointer is valid and
/// can be dereferenced.
#[no_mangle]
pub unsafe extern "C" fn mfa_auth_continue_free(input: *mut MFAAuthContinue) {
    free_object!(input);
}

/// # Safety
///
/// The calling function must ensure that the `input` raw pointer is valid and
/// can be dereferenced.
#[cfg(feature = "broker")]
#[no_mangle]
pub unsafe extern "C" fn sealed_data_free(input: *mut SealedData) {
    free_object!(input);
}
