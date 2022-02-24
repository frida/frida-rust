/*
 * Copyright © 2020-2021 Keegan Saunders
 * Copyright © 2021-2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */
#![cfg_attr(doc_cfg, feature(doc_cfg))]
#![deny(warnings)]
#![allow(clippy::missing_safety_doc)]

pub mod device;
pub mod device_manager;
pub mod error;
pub mod process;
pub mod script;
pub mod session;

use device_manager::DeviceManager;
use std::ffi::CStr;
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

    /// Obtains a new instance of device manager
    pub fn obtain_device_manager(&self) -> DeviceManager {
        unsafe { DeviceManager::new(frida_sys::frida_device_manager_new()) }
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
