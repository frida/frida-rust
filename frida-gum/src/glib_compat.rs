/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Cross-platform GLib symbol shims.
//!
//! Frida's static devkit exposes GLib helpers under their bare `g_*` names on
//! Windows and macOS, but under a `_frida_g_*` prefix on the Linux/FreeBSD/iOS
//! devkits (to avoid clashing with a system GLib). `frida-gum-sys` therefore
//! only generates bindings for whichever name the current target's devkit
//! provides. This module papers over that difference so the rest of the crate
//! can call a single stable name regardless of platform (mirroring the existing
//! `_frida_g_get_*_dir` handling in [`crate::process`]).

use frida_gum_sys::{gboolean, gchar, gpointer, guint, GArray, GError, GPtrArray};

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "ios"))]
mod sys {
    pub use frida_gum_sys::{
        _frida_g_array_free as g_array_free, _frida_g_error_free as g_error_free,
        _frida_g_free as g_free, _frida_g_ptr_array_add as g_ptr_array_add,
        _frida_g_ptr_array_free as g_ptr_array_free,
        _frida_g_ptr_array_sized_new as g_ptr_array_sized_new,
    };
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "ios")))]
mod sys {
    pub use frida_gum_sys::{
        g_array_free, g_error_free, g_free, g_ptr_array_add, g_ptr_array_free,
        g_ptr_array_sized_new,
    };
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

/// Free a `GArray`, optionally freeing the element segment.
///
/// # Safety
///
/// `array` must be a valid `GArray` that has not already been freed.
pub unsafe fn g_array_free(array: *mut GArray, free_segment: gboolean) -> *mut gchar {
    unsafe { sys::g_array_free(array, free_segment) }
}

/// Allocate a `GPtrArray` with space reserved for `reserved_size` elements.
pub fn g_ptr_array_sized_new(reserved_size: guint) -> *mut GPtrArray {
    unsafe { sys::g_ptr_array_sized_new(reserved_size) }
}

/// Append a pointer to a `GPtrArray`.
///
/// # Safety
///
/// `array` must be a valid `GPtrArray`.
pub unsafe fn g_ptr_array_add(array: *mut GPtrArray, data: gpointer) {
    unsafe { sys::g_ptr_array_add(array, data) }
}

/// Free a `GPtrArray`, optionally freeing the underlying segment.
///
/// # Safety
///
/// `array` must be a valid `GPtrArray` that has not already been freed.
pub unsafe fn g_ptr_array_free(array: *mut GPtrArray, free_seg: gboolean) -> *mut gpointer {
    unsafe { sys::g_ptr_array_free(array, free_seg) }
}
