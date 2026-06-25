/*
 * Copyright © 2020-2021 Keegan Saunders
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Cloaking utilities to hide threads, memory ranges, and file descriptors
//! from instrumentation.
//!
//! The Cloak module allows hiding instrumentation-related resources so that
//! they do not appear when enumerating threads, memory ranges, or file
//! descriptors. This is commonly used to prevent self-introspection from
//! detecting Frida's own threads and memory regions.

use {
    crate::{MemoryRange, NativePointer},
    core::ffi::c_void,
    frida_gum_sys as gum_sys,
};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

#[cfg(feature = "std")]
use std::{boxed::Box, vec::Vec};

/// Static interface to Frida's cloak machinery.
pub struct Cloak;

impl Cloak {
    /// Hide the specified thread from enumeration.
    pub fn add_thread(id: usize) {
        unsafe { gum_sys::gum_cloak_add_thread(id as gum_sys::GumThreadId) };
    }

    /// Stop hiding the specified thread.
    pub fn remove_thread(id: usize) {
        unsafe { gum_sys::gum_cloak_remove_thread(id as gum_sys::GumThreadId) };
    }

    /// Check whether the specified thread is currently hidden.
    pub fn has_thread(id: usize) -> bool {
        unsafe { gum_sys::gum_cloak_has_thread(id as gum_sys::GumThreadId) != 0 }
    }

    /// Iterate over all currently cloaked threads, invoking the callback for each.
    ///
    /// Returning `false` from the callback halts iteration.
    pub fn enumerate_threads<F>(mut callback: F)
    where
        F: FnMut(usize) -> bool,
    {
        unsafe extern "C" fn trampoline<F>(
            id: gum_sys::GumThreadId,
            user_data: gum_sys::gpointer,
        ) -> gum_sys::gboolean
        where
            F: FnMut(usize) -> bool,
        {
            unsafe {
                let cb = &mut *(user_data as *mut F);
                if cb(id as usize) { 1 } else { 0 }
            }
        }

        unsafe {
            gum_sys::gum_cloak_enumerate_threads(
                Some(trampoline::<F>),
                &mut callback as *mut _ as *mut c_void,
            );
        }
    }

    /// Hide the specified memory range from enumeration.
    pub fn add_range(range: &MemoryRange) {
        unsafe { gum_sys::gum_cloak_add_range(&range.memory_range as *const _) };
    }

    /// Stop hiding the specified memory range.
    pub fn remove_range(range: &MemoryRange) {
        unsafe { gum_sys::gum_cloak_remove_range(&range.memory_range as *const _) };
    }

    /// Check whether any cloaked range contains the given address.
    pub fn has_range_containing(address: NativePointer) -> bool {
        unsafe { gum_sys::gum_cloak_has_range_containing(address.0 as gum_sys::GumAddress) != 0 }
    }

    /// Clip the specified range against currently cloaked ranges.
    ///
    /// Returns the sub-ranges that remain visible after clipping. If the
    /// entire range is hidden, the returned vector is empty.
    pub fn clip_range(range: &MemoryRange) -> Vec<MemoryRange> {
        let mut results = Vec::new();
        unsafe {
            let array = gum_sys::gum_cloak_clip_range(&range.memory_range as *const _);
            if array.is_null() {
                return results;
            }

            let len = (*array).len as usize;
            let data = (*array).data as *const gum_sys::GumMemoryRange;
            for i in 0..len {
                let r = *data.add(i);
                results.push(MemoryRange::new(
                    NativePointer(r.base_address as *mut c_void),
                    r.size as usize,
                ));
            }
            crate::glib_compat::g_array_free(array, gum_sys::true_ as _);
        }
        results
    }

    /// Iterate over all currently cloaked memory ranges.
    ///
    /// Returning `false` from the callback halts iteration.
    pub fn enumerate_ranges<F>(mut callback: F)
    where
        F: FnMut(&MemoryRange) -> bool,
    {
        unsafe extern "C" fn trampoline<F>(
            range: *const gum_sys::GumMemoryRange,
            user_data: gum_sys::gpointer,
        ) -> gum_sys::gboolean
        where
            F: FnMut(&MemoryRange) -> bool,
        {
            unsafe {
                let cb = &mut *(user_data as *mut F);
                let r = *range;
                let memory_range = MemoryRange::new(
                    NativePointer(r.base_address as *mut c_void),
                    r.size as usize,
                );
                if cb(&memory_range) { 1 } else { 0 }
            }
        }

        unsafe {
            gum_sys::gum_cloak_enumerate_ranges(
                Some(trampoline::<F>),
                &mut callback as *mut _ as *mut c_void,
            );
        }
    }

    /// Hide the specified file descriptor from enumeration.
    pub fn add_file_descriptor(fd: i32) {
        unsafe { gum_sys::gum_cloak_add_file_descriptor(fd) };
    }

    /// Stop hiding the specified file descriptor.
    pub fn remove_file_descriptor(fd: i32) {
        unsafe { gum_sys::gum_cloak_remove_file_descriptor(fd) };
    }

    /// Check whether the specified file descriptor is currently hidden.
    pub fn has_file_descriptor(fd: i32) -> bool {
        unsafe { gum_sys::gum_cloak_has_file_descriptor(fd) != 0 }
    }

    /// Iterate over all currently cloaked file descriptors.
    pub fn enumerate_file_descriptors<F>(mut callback: F)
    where
        F: FnMut(i32) -> bool,
    {
        unsafe extern "C" fn trampoline<F>(
            fd: gum_sys::gint,
            user_data: gum_sys::gpointer,
        ) -> gum_sys::gboolean
        where
            F: FnMut(i32) -> bool,
        {
            unsafe {
                let cb = &mut *(user_data as *mut F);
                if cb(fd) { 1 } else { 0 }
            }
        }

        unsafe {
            gum_sys::gum_cloak_enumerate_file_descriptors(
                Some(trampoline::<F>),
                &mut callback as *mut _ as *mut c_void,
            );
        }
    }

    /// Run the callback while holding the cloak's internal lock.
    ///
    /// This guarantees a consistent view of cloaked resources for the duration
    /// of the callback.
    pub fn with_lock_held<F: FnOnce()>(callback: F) {
        unsafe extern "C" fn trampoline<F: FnOnce()>(user_data: gum_sys::gpointer) {
            unsafe {
                let cb = Box::from_raw(user_data as *mut F);
                cb();
            }
        }

        let boxed = Box::new(callback);
        unsafe {
            gum_sys::gum_cloak_with_lock_held(
                Some(trampoline::<F>),
                Box::into_raw(boxed) as *mut c_void,
            );
        }
    }

    /// Check whether the cloak's internal lock is currently held.
    pub fn is_locked() -> bool {
        unsafe { gum_sys::gum_cloak_is_locked() != 0 }
    }
}
