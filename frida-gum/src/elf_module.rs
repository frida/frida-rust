/*
 * Copyright © 2025 Mimic
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! ELF module inspection — enumerate dynamic entries and query ELF metadata.
//!
//! Added in Frida 17.15.0. Only available on platforms that load ELF binaries
//! (Linux, Android, FreeBSD). Guarded by `#[cfg(not(target_os = "windows"))]`
//! and `#[cfg(not(target_os = "macos"))]`.

#![cfg(not(any(target_os = "windows", target_os = "macos", target_os = "ios")))]

use {
    core::ffi::c_void,
    cstr_core::CString,
    frida_gum_sys as gum_sys,
    frida_gum_sys::{GumElfDynamicEntryDetails, GumElfDynamicTag, gpointer},
};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::{ffi::CStr, string::ToString};

#[cfg(not(feature = "std"))]
use core::ffi::CStr;

/// ELF dynamic section entry — mirrors `GumElfDynamicEntryDetails`.
#[derive(Clone, Debug)]
pub struct ElfDynamicEntry {
    /// The dynamic tag (e.g. `DT_NEEDED`, `DT_SONAME`, etc.)
    pub tag: u32,
    /// The value associated with the tag (address, offset, or integer).
    pub val: u64,
}

impl ElfDynamicEntry {
    fn from_raw(details: *const GumElfDynamicEntryDetails) -> Self {
        unsafe {
            Self {
                tag: (*details).tag as u32,
                val: (*details).val,
            }
        }
    }
}

extern "C" fn enumerate_dynamic_entries_callout(
    details: *const GumElfDynamicEntryDetails,
    user_data: *mut c_void,
) -> gum_sys::gboolean {
    let mut f = unsafe {
        Box::from_raw(user_data as *mut Box<dyn FnMut(ElfDynamicEntry) -> bool>)
    };
    let r = f(ElfDynamicEntry::from_raw(details));
    Box::leak(f);
    r as gum_sys::gboolean
}

/// An ELF module loaded by Frida.
pub struct ElfModule {
    inner: *mut gum_sys::GumElfModule,
}

impl ElfModule {
    /// Open an ELF file from disk.
    ///
    /// Returns `None` if the file cannot be opened or parsed.
    pub fn from_file(path: &str) -> Option<Self> {
        let path = CString::new(path).ok()?;
        let mut error: *mut gum_sys::GError = core::ptr::null_mut();
        let ptr = unsafe {
            gum_sys::gum_elf_module_new_from_file(path.as_ptr(), &mut error)
        };
        if ptr.is_null() {
            None
        } else {
            Some(Self { inner: ptr })
        }
    }

    /// Open an ELF module already mapped into memory at `base_address`.
    pub fn from_memory(path: &str, base_address: u64) -> Option<Self> {
        let path = CString::new(path).ok()?;
        let mut error: *mut gum_sys::GError = core::ptr::null_mut();
        let ptr = unsafe {
            gum_sys::gum_elf_module_new_from_memory(path.as_ptr(), base_address, &mut error)
        };
        if ptr.is_null() {
            None
        } else {
            Some(Self { inner: ptr })
        }
    }

    /// Pointer size of this ELF binary (4 for 32-bit, 8 for 64-bit).
    pub fn pointer_size(&self) -> u32 {
        unsafe { gum_sys::gum_elf_module_get_pointer_size(self.inner) }
    }

    /// Byte order — 0 = little-endian, 1 = big-endian (matches `GLib.ByteOrder`).
    pub fn byte_order(&self) -> i32 {
        unsafe { gum_sys::gum_elf_module_get_byte_order(self.inner) }
    }

    /// OS ABI version field from the ELF header.
    pub fn os_abi_version(&self) -> u8 {
        unsafe { gum_sys::gum_elf_module_get_os_abi_version(self.inner) }
    }

    /// Total mapped memory size of this module.
    pub fn mapped_size(&self) -> u64 {
        unsafe { gum_sys::gum_elf_module_get_mapped_size(self.inner) }
    }

    /// Base (load) address of this module.
    pub fn base_address(&self) -> u64 {
        unsafe { gum_sys::gum_elf_module_get_base_address(self.inner) }
    }

    /// Preferred (link-time) address of this module.
    pub fn preferred_address(&self) -> u64 {
        unsafe { gum_sys::gum_elf_module_get_preferred_address(self.inner) }
    }

    /// Entry point address, if any.
    pub fn entrypoint(&self) -> u64 {
        unsafe { gum_sys::gum_elf_module_get_entrypoint(self.inner) }
    }

    /// Path to the dynamic linker interpreter (`PT_INTERP`), if any.
    pub fn interpreter(&self) -> Option<String> {
        let ptr = unsafe { gum_sys::gum_elf_module_get_interpreter(self.inner) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned())
        }
    }

    /// File path this module was loaded from.
    pub fn source_path(&self) -> Option<String> {
        let ptr = unsafe { gum_sys::gum_elf_module_get_source_path(self.inner) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned())
        }
    }

    /// Enumerate the ELF dynamic section entries, calling `callback` for each.
    ///
    /// Return `true` from the callback to continue, `false` to stop early.
    ///
    /// # Example
    /// ```rust,no_run
    /// use frida_gum::elf_module::ElfModule;
    /// if let Some(m) = ElfModule::from_file("/lib/x86_64-linux-gnu/libc.so.6") {
    ///     m.enumerate_dynamic_entries(|entry| {
    ///         println!("tag={} val={:#x}", entry.tag, entry.val);
    ///         true
    ///     });
    /// }
    /// ```
    pub fn enumerate_dynamic_entries<F>(&self, mut callback: F)
    where
        F: FnMut(ElfDynamicEntry) -> bool,
    {
        let callback: Box<dyn FnMut(ElfDynamicEntry) -> bool> = Box::new(&mut callback);
        let callback = Box::into_raw(Box::new(callback));
        unsafe {
            gum_sys::gum_elf_module_enumerate_dynamic_entries(
                self.inner,
                Some(enumerate_dynamic_entries_callout),
                callback as gpointer,
            );
            drop(Box::from_raw(callback));
        }
    }

    /// Collect all dynamic entries into a `Vec`.
    pub fn dynamic_entries(&self) -> Vec<ElfDynamicEntry> {
        let mut result = Vec::new();
        self.enumerate_dynamic_entries(|entry| {
            result.push(entry);
            true
        });
        result
    }
}

impl Drop for ElfModule {
    fn drop(&mut self) {
        unsafe { gum_sys::g_object_unref(self.inner as *mut c_void) };
    }
}
