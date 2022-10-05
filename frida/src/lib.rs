/*
 * Copyright © 2020-2022 Keegan Saunders
 * Copyright © 2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Frida bindings for Rust.

#![cfg_attr(doc_cfg, feature(doc_cfg))]
#![deny(warnings)]
#![deny(missing_docs)]
#![allow(clippy::missing_safety_doc)]

use std::ffi::CStr;

pub mod device;
pub use device::*;

pub mod device_manager;
pub use device_manager::*;

mod error;
pub use error::Error;

pub mod process;
pub use process::*;

pub mod script;
pub use script::*;

pub mod session;
pub use session::*;

#[doc(hidden)]
pub type Result<T> = std::result::Result<T, error::Error>;

/// Context required for instantiation of all structures under the Frida namespace.
pub struct Frida;

impl Frida {
    /// Obtain a Frida handle, ensuring that the runtime is properly initialized. This may
    /// be called as many times as needed, and results in a no-op if the Frida runtime is
    /// already initialized.
    pub unsafe fn obtain() -> Frida {
        frida_sys::frida_init();
        Frida {}
    }

    /// Gets the current version of frida core
    pub fn version() -> &'static str {
        let version = unsafe { CStr::from_ptr(frida_sys::frida_version_string() as _) };
        version.to_str().unwrap_or_default()
    }
}

impl Drop for Frida {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_deinit() };
    }
}
