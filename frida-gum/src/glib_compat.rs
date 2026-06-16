/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Cross-platform GLib symbol shims.
//!
//! Frida's static devkit exposes GLib helpers under their bare `g_*` names on
//! Windows and macOS, but under a `_frida_g_*` prefix on the Linux/FreeBSD/iOS
//! devkits (to avoid clashing with a system GLib). This module papers over that
//! difference so call sites can use a single stable name regardless of platform,
//! mirroring the existing `_frida_g_get_*_dir` handling in [`crate::process`].

use frida_gum_sys::{GError, gpointer};

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "ios"))]
mod sys {
    pub use frida_gum_sys::{_frida_g_error_free as g_error_free, _frida_g_free as g_free};
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "ios")))]
mod sys {
    pub use frida_gum_sys::{g_error_free, g_free};
}

/// Free a block previously allocated by GLib.
///
/// # Safety
///
/// `mem` must have been returned by a GLib allocation and not yet freed.
pub unsafe fn g_free(mem: gpointer) {
    unsafe { sys::g_free(mem) }
}

/// Free a `GError`.
///
/// # Safety
///
/// `error` must be a valid `GError` that has not already been freed.
pub unsafe fn g_error_free(error: *mut GError) {
    unsafe { sys::g_error_free(error) }
}
