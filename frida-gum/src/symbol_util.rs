/*
 * Copyright © 2020-2021 Keegan Saunders
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Symbol resolution and manipulation utilities.
//!
//! The SymbolUtil module provides functions for resolving symbols by name,
//! finding symbol information by address, and locating functions.

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

/// Symbol resolution utilities.
pub struct SymbolUtil;

impl SymbolUtil {
    /// Get the name of the symbol at the specified address.
    ///
    /// Returns the symbol name if found, or None if no symbol exists at that address.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use frida_gum::{SymbolUtil, NativePointer};
    ///
    /// let addr = NativePointer(std::ptr::null_mut());
    /// if let Some(name) = SymbolUtil::name_from_address(addr) {
    ///     println!("Symbol: {}", name);
    /// }
    /// ```
    pub fn name_from_address(address: NativePointer) -> Option<String> {
        let name_ptr = unsafe { gum_sys::gum_symbol_name_from_address(address.0) };

        if name_ptr.is_null() {
            None
        } else {
            let name = unsafe { CStr::from_ptr(name_ptr).to_string_lossy().into_owned() };
            unsafe { gum_sys::g_free(name_ptr as *mut c_void) };
            Some(name)
        }
    }

    /// Find a function by name.
    ///
    /// Returns the address of the function if found, or None if not found.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use frida_gum::SymbolUtil;
    ///
    /// if let Some(addr) = SymbolUtil::find_function("malloc") {
    ///     println!("malloc is at {:?}", addr);
    /// }
    /// ```
    pub fn find_function(name: &str) -> Option<NativePointer> {
        let name_cstr = match CString::new(name) {
            Ok(s) => s,
            Err(_) => return None,
        };

        let ptr = unsafe { gum_sys::gum_find_function(name_cstr.as_ptr()) };

        if ptr.is_null() {
            None
        } else {
            Some(NativePointer(ptr))
        }
    }

    /// Find all functions with the specified name.
    ///
    /// This is useful when multiple functions have the same name (e.g., across
    /// different modules or due to name mangling).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use frida_gum::SymbolUtil;
    ///
    /// let addrs = SymbolUtil::find_functions_named("malloc");
    /// for addr in addrs {
    ///     println!("Found malloc at {:?}", addr);
    /// }
    /// ```
    pub fn find_functions_named(name: &str) -> Vec<NativePointer> {
        let name_cstr = match CString::new(name) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let array = unsafe { gum_sys::gum_find_functions_named(name_cstr.as_ptr()) };

        let mut results = Vec::new();
        if !array.is_null() {
            unsafe {
                let len = (*array).len as usize;
                let data = (*array).data as *const gum_sys::gpointer;
                for i in 0..len {
                    let ptr = *data.add(i);
                    if !ptr.is_null() {
                        results.push(NativePointer(ptr));
                    }
                }
                gum_sys::g_array_free(array, gum_sys::true_ as _);
            }
        }

        results
    }

    /// Find all functions matching a pattern.
    ///
    /// The pattern can include wildcards:
    /// - `*` matches any sequence of characters
    /// - `?` matches any single character
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use frida_gum::SymbolUtil;
    ///
    /// // Find all malloc-related functions
    /// let addrs = SymbolUtil::find_functions_matching("*alloc*");
    /// for addr in addrs {
    ///     println!("Found function at {:?}", addr);
    /// }
    /// ```
    pub fn find_functions_matching(pattern: &str) -> Vec<NativePointer> {
        let pattern_cstr = match CString::new(pattern) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let array = unsafe { gum_sys::gum_find_functions_matching(pattern_cstr.as_ptr()) };

        let mut results = Vec::new();
        if !array.is_null() {
            unsafe {
                let len = (*array).len as usize;
                let data = (*array).data as *const gum_sys::gpointer;
                for i in 0..len {
                    let ptr = *data.add(i);
                    if !ptr.is_null() {
                        results.push(NativePointer(ptr));
                    }
                }
                gum_sys::g_array_free(array, gum_sys::true_ as _);
            }
        }

        results
    }
}
