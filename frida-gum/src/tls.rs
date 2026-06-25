/*
 * Copyright © 2020-2021 Keegan Saunders
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Thread-local storage keys.
//!
//! Provides a Rust wrapper around Frida's thread-local storage API. Each
//! [`TlsKey`] manages an OS-level TLS slot whose lifetime is tied to the
//! Rust value: dropping the key releases the slot.

use {crate::NativePointer, frida_gum_sys as gum_sys};

/// A thread-local storage key.
///
/// The slot is freed when the key is dropped. Cloning a key is intentionally
/// not provided — the underlying TLS slot has unique ownership.
pub struct TlsKey {
    key: gum_sys::GumTlsKey,
}

impl TlsKey {
    /// Allocate a new TLS slot.
    pub fn new() -> Self {
        TlsKey {
            key: unsafe { gum_sys::gum_tls_key_new() },
        }
    }

    /// Read the value of this slot for the current thread.
    pub fn get(&self) -> NativePointer {
        NativePointer(unsafe { gum_sys::gum_tls_key_get_value(self.key) })
    }

    /// Write a value into this slot for the current thread.
    pub fn set(&self, value: NativePointer) {
        unsafe { gum_sys::gum_tls_key_set_value(self.key, value.0) };
    }

    /// Get the raw `GumTlsKey` (typically `pthread_key_t` on Unix or `DWORD`
    /// on Windows). Provided for FFI use.
    pub fn raw(&self) -> gum_sys::GumTlsKey {
        self.key
    }
}

impl Drop for TlsKey {
    fn drop(&mut self) {
        unsafe { gum_sys::gum_tls_key_free(self.key) };
    }
}

unsafe impl Send for TlsKey {}
unsafe impl Sync for TlsKey {}

impl Default for TlsKey {
    fn default() -> Self {
        Self::new()
    }
}
