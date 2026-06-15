/*
 * Copyright © 2020-2021 Keegan Saunders
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Allocate executable memory in a way that honours the host's code-signing
//! policy.
//!
//! On platforms where pages cannot simply be mapped writable-and-executable
//! (Windows with CET, Apple with hardened runtime, etc.) Frida implements a
//! shadow-mapping scheme: the segment is allocated read-write, code is
//! written to it, then [`CodeSegment::realize`] makes it executable and
//! [`CodeSegment::map`] exposes it at a target address as read-execute.
//!
//! Use [`CodeSegment::is_supported`] to check availability before relying on
//! this API.

use {
    crate::{NativePointer, error::Error},
    core::ptr,
    frida_gum_sys as gum_sys,
};

/// A region of executable memory managed by Frida.
pub struct CodeSegment {
    inner: *mut gum_sys::GumCodeSegment,
}

impl CodeSegment {
    /// Returns whether the running platform supports `CodeSegment`.
    pub fn is_supported() -> bool {
        unsafe { gum_sys::gum_code_segment_is_supported() != 0 }
    }

    /// Allocate a new segment of at least `size` bytes.
    ///
    /// Returns `None` if the host does not support code segments or the
    /// allocation fails.
    pub fn new(size: usize) -> Option<Self> {
        let inner = unsafe { gum_sys::gum_code_segment_new(size as u64, ptr::null()) };
        if inner.is_null() {
            None
        } else {
            Some(CodeSegment { inner })
        }
    }

    /// Allocate a segment whose pages will live within `max_distance` bytes
    /// of `near`. Useful for short-jump trampolines.
    pub fn new_near(size: usize, near: NativePointer, max_distance: usize) -> Option<Self> {
        let spec = gum_sys::GumAddressSpec {
            near_address: near.0,
            max_distance: max_distance as u64,
        };
        let inner = unsafe { gum_sys::gum_code_segment_new(size as u64, &spec) };
        if inner.is_null() {
            None
        } else {
            Some(CodeSegment { inner })
        }
    }

    /// Get the writable shadow address where code should be staged.
    ///
    /// Write your instructions here, then call [`Self::realize`] and
    /// [`Self::map`] to publish them as executable.
    pub fn address(&self) -> NativePointer {
        NativePointer(unsafe { gum_sys::gum_code_segment_get_address(self.inner) })
    }

    /// Get the size of the underlying file mapping.
    pub fn size(&self) -> usize {
        unsafe { gum_sys::gum_code_segment_get_size(self.inner) as usize }
    }

    /// Get the size of the address space reserved for the segment.
    pub fn virtual_size(&self) -> usize {
        unsafe { gum_sys::gum_code_segment_get_virtual_size(self.inner) as usize }
    }

    /// Finalize the segment so it becomes executable.
    pub fn realize(&self) {
        unsafe { gum_sys::gum_code_segment_realize(self.inner) };
    }

    /// Publish a portion of the segment at `target_address` as read-execute.
    ///
    /// # Safety
    ///
    /// `target_address` must point to a valid region of at least `source_size`
    /// bytes that the caller owns. This typically pairs with memory previously
    /// reserved by [`crate::Memory::allocate`] or similar.
    pub unsafe fn map(
        &self,
        source_offset: usize,
        source_size: usize,
        target_address: NativePointer,
    ) {
        unsafe {
            gum_sys::gum_code_segment_map(
                self.inner,
                source_offset as u64,
                source_size as u64,
                target_address.0,
            );
        }
    }

    /// Mark `code` of `size` bytes as executable.
    ///
    /// Convenience wrapper around `gum_code_segment_mark` for cases where
    /// you have already allocated code memory by other means and just need
    /// the OS-level "make this executable" call.
    ///
    /// # Safety
    ///
    /// `code` must point to a region of at least `size` bytes that the
    /// caller owns and that contains valid instructions for the host CPU.
    pub unsafe fn mark(code: NativePointer, size: usize) -> Result<(), Error> {
        unsafe {
            let mut err: *mut gum_sys::GError = ptr::null_mut();
            let ok = gum_sys::gum_code_segment_mark(code.0, size as u64, &mut err) != 0;
            if !err.is_null() {
                gum_sys::g_error_free(err);
            }
            if ok {
                Ok(())
            } else {
                Err(Error::MemoryAccessError)
            }
        }
    }
}

impl Drop for CodeSegment {
    fn drop(&mut self) {
        unsafe { gum_sys::gum_code_segment_free(self.inner) };
    }
}

unsafe impl Send for CodeSegment {}
unsafe impl Sync for CodeSegment {}
