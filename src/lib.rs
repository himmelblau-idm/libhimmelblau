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

pub mod error;

pub mod auth;
pub use auth::*;

#[cfg(feature = "broker")]
pub mod discovery;

pub mod graph;
#[cfg(feature = "broker")]
pub use discovery::EnrollAttrs;

#[cfg(feature = "capi")]
#[macro_use]
mod c_helper;
#[cfg(feature = "capi")]
pub mod capi;

#[cfg(all(feature = "broker", not(feature = "capi"), feature = "pyapi"))]
pub mod pyapi;

#[cfg(any(feature = "pyapi", feature = "capi"))]
pub mod serializer;

pub mod aadsts_err_gen;

#[cfg(feature = "broker")]
mod krb5;
