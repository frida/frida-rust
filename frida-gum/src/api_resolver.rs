/*
 * Copyright © 2020-2021 Keegan Saunders
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! API resolver for finding functions by pattern matching.
//!
//! The ApiResolver allows you to find APIs using wildcard patterns like:
//! - `"exports:*!open*"` - Find all exports starting with "open"
//! - `"imports:libc.so!*"` - Find all imports from libc.so
//! - `"module:kernel32.dll!CreateFile*"` - Find CreateFile* in kernel32.dll

use {
    crate::NativePointer,
    core::ffi::{CStr, c_void},
    cstr_core::CString,
    frida_gum_sys as gum_sys,
};

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

#[cfg(feature = "std")]
use std::{string::String, vec::Vec};

/// Details about a resolved API match.
#[derive(Debug, Clone)]
pub struct ApiMatch {
    /// Name of the matched API
    pub name: String,
    /// Address of the matched API
    pub address: NativePointer,
    /// Size of the matched API (if available)
    pub size: Option<usize>,
}

/// API resolver for finding functions by pattern.
pub struct ApiResolver {
    resolver: *mut gum_sys::GumApiResolver,
}

impl ApiResolver {
    /// Create a new ApiResolver of the specified type.
    ///
    /// # Arguments
    ///
    /// * `resolver_type` - Type of resolver: "module", "objc", or "swift"
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use frida_gum::ApiResolver;
    ///
    /// let resolver = ApiResolver::make("module").expect("Failed to create resolver");
    /// ```
    pub fn make(resolver_type: &str) -> Option<Self> {
        let type_cstr = match CString::new(resolver_type) {
            Ok(s) => s,
            Err(_) => return None,
        };

        let resolver = unsafe { gum_sys::gum_api_resolver_make(type_cstr.as_ptr().cast()) };

        if resolver.is_null() {
            None
        } else {
            Some(ApiResolver { resolver })
        }
    }

    /// Find all APIs matching the given query pattern.
    ///
    /// # Arguments
    ///
    /// * `query` - Pattern to match, e.g., "exports:*!open*"
    ///
    /// # Returns
    ///
    /// A vector of matched APIs with their names and addresses.
    ///
    /// # Pattern Syntax
    ///
    /// - `exports:*!open*` - All exports starting with "open"
    /// - `exports:libc.so!*` - All exports from libc.so
    /// - `imports:*!malloc` - All imports named malloc
    /// - `imports:mylib!free` - Import "free" in mylib
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use frida_gum::ApiResolver;
    ///
    /// let resolver = ApiResolver::make("module").unwrap();
    /// let matches = resolver.enumerate_matches("exports:*!CreateFile*");
    /// for m in matches {
    ///     println!("{} at {:?}", m.name, m.address);
    /// }
    /// ```
    pub fn enumerate_matches(&self, query: &str) -> Vec<ApiMatch> {
        let query_cstr = match CString::new(query) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let mut matches = Vec::new();

        unsafe extern "C" fn callback(
            details: *const gum_sys::GumApiDetails,
            user_data: gum_sys::gpointer,
        ) -> gum_sys::gboolean {
            unsafe {
                let matches = &mut *(user_data as *mut Vec<ApiMatch>);

                let name = if !(*details).name.is_null() {
                    CStr::from_ptr((*details).name)
                        .to_string_lossy()
                        .into_owned()
                } else {
                    String::new()
                };

                let address = NativePointer((*details).address as *mut c_void);

                let size = if (*details).size > 0 {
                    Some((*details).size as usize)
                } else {
                    None
                };

                matches.push(ApiMatch {
                    name,
                    address,
                    size,
                });

                1 // Continue enumeration
            }
        }

        let mut error: *mut gum_sys::GError = core::ptr::null_mut();
        unsafe {
            gum_sys::gum_api_resolver_enumerate_matches(
                self.resolver,
                query_cstr.as_ptr().cast(),
                Some(callback),
                &mut matches as *mut _ as *mut c_void,
                &mut error,
            );
            if !error.is_null() {
                crate::glib_compat::g_error_free(error);
            }
        }

        matches
    }
}

impl Drop for ApiResolver {
    fn drop(&mut self) {
        unsafe { frida_gum_sys::g_object_unref(self.resolver as *mut c_void) };
    }
}

unsafe impl Send for ApiResolver {}
unsafe impl Sync for ApiResolver {}
