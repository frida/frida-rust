/*
 * Copyright © 2025 Zhi Zhou
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use frida_sys::{FridaApplicationQueryOptions, FridaFrontmostQueryOptions, _FridaApplication};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::marker::PhantomData;

use crate::variant::Variant;
use crate::Result;

/// App management in Frida.
pub struct Application<'a> {
    application_ptr: *mut _FridaApplication,
    phantom: PhantomData<&'a _FridaApplication>,
}

impl<'a> Application<'a> {
    pub(crate) fn from_raw(application_ptr: *mut _FridaApplication) -> Application<'a> {
        Application {
            application_ptr,
            phantom: PhantomData,
        }
    }

    /// Returns the name of the application.
    pub fn get_name(&self) -> &str {
        let application_name = unsafe {
            CStr::from_ptr(frida_sys::frida_application_get_name(self.application_ptr) as _)
        };

        application_name.to_str().unwrap_or_default()
    }

    /// Returns the identifier of the application.
    pub fn get_identifier(&self) -> &str {
        let application_identifier = unsafe {
            CStr::from_ptr(frida_sys::frida_application_get_identifier(self.application_ptr) as _)
        };

        application_identifier.to_str().unwrap_or_default()
    }

    /// Returns the pid of the application.
    pub fn get_pid(&self) -> u32 {
        unsafe { frida_sys::frida_application_get_pid(self.application_ptr) }
    }

    /// Returns parameters of the application.
    ///
    ///
    /// # Example
    /// ```ignore
    ///# use std::collections::HashMap;
    ///# let frida = unsafe { frida::Frida::obtain() };
    ///# let device_manager = frida::DeviceManager::obtain(&frida);
    ///# let device = device_manager.get_device_by_type(DeviceType::USB).unwrap();
    ///# let app = device.enumerate_applications().into_iter().find(|app| app.get_identifier() == "com.example.app").unwrap();
    /// let params = app.get_parameters()
    ///    .expect("Failed to get parameters");
    /// ```
    pub fn get_parameters(&self) -> Result<HashMap<String, Variant>> {
        let ht = unsafe { frida_sys::frida_application_get_parameters(self.application_ptr) };
        let mut iter: frida_sys::GHashTableIter =
            unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        unsafe { frida_sys::g_hash_table_iter_init(&mut iter, ht) };
        let size = unsafe { frida_sys::g_hash_table_size(ht) };
        let mut map = HashMap::with_capacity(size as usize);

        let mut key = std::ptr::null_mut();
        let mut val = std::ptr::null_mut();
        while (unsafe { frida_sys::g_hash_table_iter_next(&mut iter, &mut key, &mut val) }
            != frida_sys::FALSE as i32)
        {
            let key = unsafe { CStr::from_ptr(key as _) };
            let val = unsafe { Variant::from_ptr(val as _) };
            map.insert(key.to_string_lossy().to_string(), val);
        }

        Ok(map)
    }
}

impl Drop for Application<'_> {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.application_ptr as _) }
    }
}

/// Frontmost Application Query Options
pub struct FrontmostApplicationQueryOptions<'a> {
    pub(crate) options_ptr: *mut FridaFrontmostQueryOptions,
    phantom: PhantomData<&'a FridaFrontmostQueryOptions>,
}

impl FrontmostApplicationQueryOptions<'_> {
    pub(crate) fn from_raw(options_ptr: *mut FridaFrontmostQueryOptions) -> Self {
        Self {
            options_ptr,
            phantom: PhantomData,
        }
    }

    /// Create an empty FrontmostApplicationQueryOptions instance
    pub fn new() -> Self {
        let options_ptr = unsafe { frida_sys::frida_frontmost_query_options_new() };
        Self::from_raw(options_ptr)
    }

    /// Set the scope of the query.
    pub fn set_scope(&self, scope: u32) {
        unsafe { frida_sys::frida_frontmost_query_options_set_scope(self.options_ptr, scope as _) }
    }
}

/// Application Query Options
pub struct ApplicationQueryOptions<'a> {
    pub(crate) options_ptr: *mut FridaApplicationQueryOptions,
    phantom: PhantomData<&'a FridaApplicationQueryOptions>,
}

impl ApplicationQueryOptions<'_> {
    pub(crate) fn from_raw(options_ptr: *mut FridaApplicationQueryOptions) -> Self {
        Self {
            options_ptr,
            phantom: PhantomData,
        }
    }

    /// Create an empty ApplicationQueryOptions instance
    pub fn new() -> Self {
        let options_ptr = unsafe { frida_sys::frida_application_query_options_new() };
        Self::from_raw(options_ptr)
    }

    /// Set the scope of the query.
    pub fn set_scope(&self, scope: u32) {
        unsafe {
            frida_sys::frida_application_query_options_set_scope(self.options_ptr, scope as _)
        }
    }

    /// Append identifier to the query.
    pub fn add_identifier(&self, identifier: &str) {
        let identifier = CString::new(identifier).expect("Failed to convert identifier to CString");
        unsafe {
            frida_sys::frida_application_query_options_select_identifier(
                self.options_ptr,
                identifier.as_ptr(),
            )
        }
    }
}

impl Drop for ApplicationQueryOptions<'_> {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.options_ptr as _) }
    }
}
