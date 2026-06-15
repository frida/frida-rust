/*
 * Copyright © 2020-2021 Keegan Saunders
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Memory allocator for executable code.
//!
//! The CodeAllocator provides efficient allocation of executable memory,
//! which is useful when generating code at runtime.

use {crate::NativePointer, frida_gum_sys as gum_sys};

/// A slice of executable memory.
pub struct CodeSlice {
    slice: *mut gum_sys::GumCodeSlice,
}

impl CodeSlice {
    /// Get the base address of this code slice.
    pub fn base(&self) -> NativePointer {
        NativePointer(unsafe { (*self.slice).data })
    }

    /// Get the size of this code slice.
    pub fn size(&self) -> usize {
        unsafe { (*self.slice).size as usize }
    }

    /// Get a mutable pointer to the data for writing code.
    ///
    /// # Safety
    ///
    /// The caller must ensure they don't write beyond the size of the slice.
    pub unsafe fn as_mut_ptr(&mut self) -> *mut u8 {
        (*self.slice).data as *mut u8
    }

    /// Get a slice view of the code memory.
    ///
    /// # Safety
    ///
    /// The caller must ensure the memory contains valid data.
    pub unsafe fn as_slice(&self) -> &[u8] {
        core::slice::from_raw_parts((*self.slice).data as *const u8, (*self.slice).size as usize)
    }

    /// Get a mutable slice view of the code memory.
    ///
    /// # Safety
    ///
    /// The caller must ensure proper synchronization if the code is being executed.
    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        core::slice::from_raw_parts_mut((*self.slice).data as *mut u8, (*self.slice).size as usize)
    }
}

impl Clone for CodeSlice {
    fn clone(&self) -> Self {
        CodeSlice {
            slice: unsafe { gum_sys::gum_code_slice_ref(self.slice) },
        }
    }
}

impl Drop for CodeSlice {
    fn drop(&mut self) {
        unsafe { gum_sys::gum_code_slice_unref(self.slice) };
    }
}

unsafe impl Send for CodeSlice {}
unsafe impl Sync for CodeSlice {}

/// Allocator for executable code memory.
///
/// Provides efficient allocation of memory regions that can contain
/// executable code. This is useful when generating code at runtime.
pub struct CodeAllocator {
    allocator: gum_sys::GumCodeAllocator,
}

impl CodeAllocator {
    /// Create a new CodeAllocator with the specified slice size.
    ///
    /// # Arguments
    ///
    /// * `slice_size` - Size of each allocated code slice
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use frida_gum::CodeAllocator;
    ///
    /// let mut allocator = CodeAllocator::new(1024);
    /// let slice = allocator.alloc_slice();
    /// ```
    pub fn new(slice_size: usize) -> Self {
        let mut allocator: gum_sys::GumCodeAllocator = unsafe { core::mem::zeroed() };
        unsafe {
            gum_sys::gum_code_allocator_init(&mut allocator as *mut _, slice_size as u64);
        }
        CodeAllocator { allocator }
    }

    /// Allocate a code slice.
    ///
    /// Returns a new code slice of the size specified during allocator creation.
    pub fn alloc_slice(&mut self) -> Option<CodeSlice> {
        let slice = unsafe { gum_sys::gum_code_allocator_alloc_slice(&mut self.allocator) };
        if slice.is_null() {
            None
        } else {
            Some(CodeSlice { slice })
        }
    }

    /// Try to allocate a code slice within `max_distance` bytes of `near`.
    ///
    /// # Arguments
    ///
    /// * `near` - Target address to allocate near.
    /// * `max_distance` - Maximum distance in bytes (e.g. `i32::MAX as usize`
    ///   for x86 short branches).
    /// * `alignment` - Alignment requirement (power of two).
    pub fn try_alloc_slice_near(
        &mut self,
        near: NativePointer,
        max_distance: usize,
        alignment: usize,
    ) -> Option<CodeSlice> {
        let spec = gum_sys::GumAddressSpec {
            near_address: near.0,
            max_distance: max_distance as u64,
        };

        let slice = unsafe {
            gum_sys::gum_code_allocator_try_alloc_slice_near(
                &mut self.allocator,
                &spec,
                alignment as u64,
            )
        };

        if slice.is_null() {
            None
        } else {
            Some(CodeSlice { slice })
        }
    }

    /// Commit any pending allocations.
    ///
    /// This ensures all allocated slices are fully committed and ready for use.
    pub fn commit(&mut self) {
        unsafe { gum_sys::gum_code_allocator_commit(&mut self.allocator) };
    }
}

impl Drop for CodeAllocator {
    fn drop(&mut self) {
        unsafe { gum_sys::gum_code_allocator_free(&mut self.allocator) };
    }
}

unsafe impl Send for CodeAllocator {}
unsafe impl Sync for CodeAllocator {}
