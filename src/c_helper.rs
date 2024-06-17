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

use crate::error::MSAL_ERROR;
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
                    Err(e) => {
                        error!("{:?}", e);
                        Err(MSAL_ERROR::from(e))
                    }
                }
            }),
            Err(e) => {
                error!("{:?}", e);
                Err(MSAL_ERROR::NO_MEMORY)
            }
        }
    }}
}

#[allow(dead_code)]
pub(crate) fn str_array_to_vec(
    arr: *const *const c_char,
    len: c_int,
) -> Result<Vec<String>, MSAL_ERROR> {
    if arr.is_null() && len == 0 {
        return Ok(vec![]);
    }
    let slice = unsafe { slice::from_raw_parts(arr, len as usize) };
    let mut array = Vec::new();
    for &item in slice {
        if item.is_null() {
            error!("Invalid input {}!", stringify!($arr));
            return Err(MSAL_ERROR::INVALID_POINTER);
        }
        let c_item = unsafe { CStr::from_ptr(item) };
        let str_item = match c_item.to_str() {
            Ok(str_item) => str_item,
            Err(e) => {
                error!("{:?}", e);
                return Err(MSAL_ERROR::INVALID_POINTER);
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
            MSAL_ERROR::SUCCESS
        } else {
            error!("Invalid object {}.{}", stringify!($obj), stringify!($item));
            MSAL_ERROR::INVALID_POINTER
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
                    MSAL_ERROR::SUCCESS
                } else {
                    error!("Invalid object {}.{}", stringify!($obj), stringify!($item));
                    MSAL_ERROR::INVALID_POINTER
                }
            }
            None => {
                error!("Object is None {}.{}", stringify!($obj), stringify!($item));
                MSAL_ERROR::INVALID_POINTER
            }
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
                    MSAL_ERROR::SUCCESS
                } else {
                    error!(
                        "Invalid response {}.{}()",
                        stringify!($obj),
                        stringify!($func)
                    );
                    MSAL_ERROR::INVALID_POINTER
                }
            }
            Err(e) => {
                error!("{:?}", e);
                MSAL_ERROR::INVALID_POINTER
            }
        }
    }};
}
