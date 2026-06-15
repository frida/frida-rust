/*
 * Copyright © 2020-2021 Keegan Saunders
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Memory manipulation utilities.
//!
//! Provides functions for reading, writing, allocating, and patching memory.

use {
    crate::{MemoryRange, NativePointer, PageProtection},
    core::ffi::c_void,
    frida_gum_sys as gum_sys,
};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

#[cfg(feature = "std")]
use std::{boxed::Box, vec::Vec};

/// Memory allocation and manipulation utilities.
pub struct Memory;

impl Memory {
    /// Read memory from the specified address.
    ///
    /// Returns a `Vec` containing the read bytes, or `None` if the address
    /// is unreadable. The returned `Vec` may be shorter than `size` if the
    /// read terminated early at an unreadable boundary.
    ///
    /// # Safety
    ///
    /// `address` must be a value the caller believes points to memory; the
    /// underlying probe is fault-tolerant but undefined memory layouts can
    /// still cause crashes on some platforms.
    pub unsafe fn read(address: NativePointer, size: usize) -> Option<Vec<u8>> {
        unsafe {
            let mut n_read: u64 = 0;
            let buf = gum_sys::gum_memory_read(address.0, size as u64, &mut n_read);

            if buf.is_null() {
                return None;
            }

            let n = n_read as usize;
            let slice = core::slice::from_raw_parts(buf, n);
            let owned = slice.to_vec();
            gum_sys::g_free(buf as *mut c_void);
            Some(owned)
        }
    }

    /// Write data to the specified address.
    ///
    /// Returns true if the write succeeded.
    ///
    /// # Safety
    ///
    /// The address must point to valid, writable memory of at least `data.len()` bytes.
    pub unsafe fn write(address: NativePointer, data: &[u8]) -> bool {
        unsafe {
            gum_sys::gum_memory_write(address.0, data.as_ptr() as *const _, data.len() as u64) != 0
        }
    }

    /// Allocate memory with the specified size, alignment, and protection.
    ///
    /// `alignment` must be a power of two; pass `1` if no specific alignment
    /// is required. Returns the address of the allocated memory, or `None`
    /// if allocation fails.
    pub fn allocate(
        size: usize,
        alignment: usize,
        protection: PageProtection,
    ) -> Option<NativePointer> {
        let ptr = unsafe {
            gum_sys::gum_memory_allocate(
                core::ptr::null_mut(),
                size as u64,
                alignment as u64,
                protection as u32,
            )
        };

        if ptr.is_null() {
            None
        } else {
            Some(NativePointer(ptr))
        }
    }

    /// Allocate memory within `max_distance` bytes of `near`.
    ///
    /// Useful for position-dependent code that requires the new region to be
    /// reachable by a short branch from the target address.
    ///
    /// # Arguments
    ///
    /// * `near` - Target address to allocate near.
    /// * `max_distance` - Maximum distance in bytes; e.g. `i32::MAX as usize`
    ///   for x86 short branches.
    /// * `size` - Size in bytes to allocate.
    /// * `alignment` - Alignment requirement (power of two).
    /// * `protection` - Memory protection flags.
    pub fn allocate_near(
        near: NativePointer,
        max_distance: usize,
        size: usize,
        alignment: usize,
        protection: PageProtection,
    ) -> Option<NativePointer> {
        let spec = gum_sys::GumAddressSpec {
            near_address: near.0,
            max_distance: max_distance as u64,
        };

        let ptr = unsafe {
            gum_sys::gum_memory_allocate_near(
                &spec,
                size as u64,
                alignment as u64,
                protection as u32,
            )
        };

        if ptr.is_null() {
            None
        } else {
            Some(NativePointer(ptr))
        }
    }

    /// Free previously allocated memory.
    ///
    /// Returns true if the free succeeded.
    ///
    /// # Safety
    ///
    /// The address must have been allocated with [`Memory::allocate()`] or
    /// [`Memory::allocate_near()`], and must not have been freed already.
    pub unsafe fn free(address: NativePointer, size: usize) -> bool {
        unsafe { gum_sys::gum_memory_free(address.0, size as u64) != 0 }
    }

    /// Release memory back to the system.
    ///
    /// Like free, but may keep the virtual address space reserved.
    ///
    /// # Safety
    ///
    /// The address and size must correspond to a previously allocated region.
    pub unsafe fn release(address: NativePointer, size: usize) -> bool {
        unsafe { gum_sys::gum_memory_release(address.0, size as u64) != 0 }
    }

    /// Decommit memory pages.
    ///
    /// Releases the physical memory backing the pages while keeping the virtual
    /// address space reserved.
    ///
    /// # Safety
    ///
    /// The address and size must correspond to a previously allocated region.
    pub unsafe fn decommit(address: NativePointer, size: usize) -> bool {
        unsafe { gum_sys::gum_memory_decommit(address.0, size as u64) != 0 }
    }

    /// Recommit previously decommitted memory pages.
    ///
    /// # Safety
    ///
    /// The address and size must correspond to a previously decommitted region.
    pub unsafe fn recommit(
        address: NativePointer,
        size: usize,
        protection: PageProtection,
    ) -> bool {
        unsafe { gum_sys::gum_memory_recommit(address.0, size as u64, protection as u32) != 0 }
    }

    /// Discard the contents of memory pages.
    ///
    /// Hints to the OS that the pages' contents can be discarded, potentially
    /// improving performance.
    ///
    /// # Safety
    ///
    /// The address and size must point to valid memory.
    pub unsafe fn discard(address: NativePointer, size: usize) -> bool {
        unsafe { gum_sys::gum_memory_discard(address.0, size as u64) != 0 }
    }

    /// Query the protection flags for a memory region.
    ///
    /// # Safety
    ///
    /// The address must point to valid memory.
    pub unsafe fn query_protection(address: NativePointer) -> Option<PageProtection> {
        unsafe {
            let mut prot: gum_sys::GumPageProtection = 0;
            if gum_sys::gum_memory_query_protection(address.0, &mut prot) != 0 {
                num::FromPrimitive::from_u32(prot)
            } else {
                None
            }
        }
    }

    /// Check if memory at the specified address is readable.
    ///
    /// # Safety
    ///
    /// The address should be a valid pointer.
    pub unsafe fn is_readable(address: NativePointer, size: usize) -> bool {
        unsafe { gum_sys::gum_memory_is_readable(address.0, size as u64) != 0 }
    }

    /// Mark a memory region as executable code.
    ///
    /// This is a hint to the system that the region contains executable code,
    /// which may enable certain optimizations.
    ///
    /// Returns true if successful.
    ///
    /// # Safety
    ///
    /// The address and size must point to valid memory with appropriate permissions.
    pub unsafe fn mark_code(address: NativePointer, size: usize) -> bool {
        unsafe { gum_sys::gum_memory_mark_code(address.0, size as u64) != 0 }
    }

    /// Change the protection of a memory region, aborting on failure.
    ///
    /// Use [`Memory::try_mprotect`] if you need to handle failure gracefully.
    ///
    /// # Safety
    ///
    /// `address`/`size` must describe a region of mapped pages owned by the
    /// caller; changing protection on memory in use elsewhere can crash the
    /// process.
    pub unsafe fn mprotect(address: NativePointer, size: usize, prot: PageProtection) {
        unsafe { gum_sys::gum_mprotect(address.0, size as u64, prot as u32) };
    }

    /// Try to change the protection of a memory region.
    ///
    /// Returns `true` if the protection was changed successfully.
    ///
    /// # Safety
    ///
    /// `address`/`size` must describe a region of mapped pages owned by the
    /// caller.
    pub unsafe fn try_mprotect(address: NativePointer, size: usize, prot: PageProtection) -> bool {
        unsafe { gum_sys::gum_try_mprotect(address.0, size as u64, prot as u32) != 0 }
    }

    /// Flush the CPU instruction cache for a region of freshly written code.
    ///
    /// Required on architectures with separate instruction/data caches (e.g.
    /// ARM/AArch64) after writing code that is about to be executed.
    ///
    /// # Safety
    ///
    /// `address`/`size` must describe a region of mapped, executable memory.
    pub unsafe fn clear_cache(address: NativePointer, size: usize) {
        unsafe { gum_sys::gum_clear_cache(address.0, size as u64) };
    }

    /// Ensure a region of code is readable, faulting it in if necessary.
    ///
    /// # Safety
    ///
    /// `address`/`size` must describe a region of mapped code memory.
    pub unsafe fn ensure_code_readable(address: NativePointer, size: usize) {
        unsafe { gum_sys::gum_ensure_code_readable(address.0, size as u64) };
    }

    /// Atomically patch code at the specified address.
    ///
    /// This function temporarily makes the memory writable, applies the patch,
    /// then restores the original protection. This is safer than manually changing
    /// permissions and ensures atomicity.
    ///
    /// # Arguments
    ///
    /// * `address` - Address to patch
    /// * `size` - Size of the region to patch
    /// * `apply` - Callback that performs the actual patching
    ///
    /// Returns true if the patch succeeded.
    ///
    /// # Safety
    ///
    /// The address must point to valid code memory. The apply callback must not
    /// access memory outside the specified region.
    pub unsafe fn patch_code<F>(address: NativePointer, size: usize, apply: F) -> bool
    where
        F: FnOnce(*mut u8),
    {
        unsafe {
            unsafe extern "C" fn trampoline<F>(mem: gum_sys::gpointer, user_data: gum_sys::gpointer)
            where
                F: FnOnce(*mut u8),
            {
                unsafe {
                    let callback = Box::from_raw(user_data as *mut F);
                    callback(mem as *mut u8);
                }
            }

            let callback = Box::new(apply);
            let user_data = Box::into_raw(callback) as *mut _;

            gum_sys::gum_memory_patch_code(address.0, size as u64, Some(trampoline::<F>), user_data)
                != 0
        }
    }

    /// Atomically patch code spanning multiple pages.
    ///
    /// Like [`Memory::patch_code`], but for a set of page-aligned addresses. The
    /// `apply` callback is invoked with `(mem, target_page, n_pages)` for each
    /// contiguous run, where `mem` is a temporarily-writable mirror of
    /// `target_page`. When `coalesce` is `true`, adjacent pages are merged into
    /// a single callback invocation.
    ///
    /// Returns `true` if the patch succeeded.
    ///
    /// # Safety
    ///
    /// Every entry of `pages` must be a page-aligned address of mapped code
    /// memory, and the callback must not write outside the mirrored pages.
    pub unsafe fn patch_code_pages<F>(pages: &[NativePointer], coalesce: bool, apply: F) -> bool
    where
        F: FnMut(*mut u8, *mut u8, u32),
    {
        unsafe {
            unsafe extern "C" fn trampoline<F>(
                mem: gum_sys::gpointer,
                target_page: gum_sys::gpointer,
                n_pages: gum_sys::guint,
                user_data: gum_sys::gpointer,
            ) where
                F: FnMut(*mut u8, *mut u8, u32),
            {
                let callback = unsafe { &mut *(user_data as *mut F) };
                callback(mem as *mut u8, target_page as *mut u8, n_pages);
            }

            // gum_memory_patch_code_pages takes a GPtrArray of page addresses.
            let array = gum_sys::g_ptr_array_sized_new(pages.len() as u32);
            for page in pages {
                gum_sys::g_ptr_array_add(array, page.0);
            }

            let mut apply = apply;
            let ok = gum_sys::gum_memory_patch_code_pages(
                array,
                i32::from(coalesce),
                Some(trampoline::<F>),
                &mut apply as *mut _ as *mut c_void,
            ) != 0;

            gum_sys::g_ptr_array_free(array, gum_sys::true_ as _);
            ok
        }
    }

    /// Find all pointers in memory ranges that point to any of the specified values.
    ///
    /// This is useful for finding references to specific addresses or objects.
    ///
    /// # Arguments
    ///
    /// * `ranges` - Memory ranges to search within
    /// * `values` - Target values to find pointers to
    /// * `mask` - Bit mask to apply when comparing pointers
    ///
    /// Returns a Vec of addresses where matching pointers were found.
    ///
    /// # Safety
    ///
    /// The ranges must point to valid, readable memory.
    pub unsafe fn find_pointers(
        ranges: &[MemoryRange],
        values: &[usize],
        mask: usize,
    ) -> Vec<NativePointer> {
        unsafe {
            let ranges_raw: Vec<gum_sys::GumMemoryRange> =
                ranges.iter().map(|r| r.memory_range).collect();

            let values_u64: Vec<u64> = values.iter().map(|&v| v as u64).collect();

            let result_array = gum_sys::gum_memory_find_pointers(
                ranges_raw.as_ptr(),
                ranges_raw.len() as u32,
                values_u64.as_ptr(),
                values_u64.len() as u32,
                mask as u64,
            );

            let mut results = Vec::new();
            if !result_array.is_null() {
                let len = (*result_array).len as usize;
                let data = (*result_array).data as *const u64;
                for i in 0..len {
                    results.push(NativePointer(*data.add(i) as *mut c_void));
                }
                frida_gum_sys::g_array_free(result_array, frida_gum_sys::true_ as _);
            }

            results
        }
    }

    /// Check if writable pages can be remapped.
    ///
    /// Returns true if the system supports remapping writable pages to different addresses.
    pub fn can_remap_writable() -> bool {
        unsafe { gum_sys::gum_memory_can_remap_writable() != 0 }
    }

    /// Remap `n_pages` whole pages starting at `first_page` so they are
    /// writable. Returns the base address of the writable mirror, or `None`
    /// if remapping is not possible.
    ///
    /// # Safety
    ///
    /// `first_page` must be page-aligned, and the range
    /// `[first_page, first_page + n_pages * page_size)` must be a valid set
    /// of whole pages owned by the caller.
    pub unsafe fn try_remap_writable_pages(
        first_page: NativePointer,
        n_pages: u32,
    ) -> Option<NativePointer> {
        unsafe {
            let result = gum_sys::gum_memory_try_remap_writable_pages(first_page.0, n_pages);
            if result.is_null() {
                None
            } else {
                Some(NativePointer(result))
            }
        }
    }

    /// Release a writable mirror previously obtained from
    /// [`Memory::try_remap_writable_pages`].
    ///
    /// # Safety
    ///
    /// `first_page` and `n_pages` must match the values that were passed to
    /// the corresponding [`Memory::try_remap_writable_pages`] call.
    pub unsafe fn dispose_writable_pages(first_page: NativePointer, n_pages: u32) {
        unsafe {
            gum_sys::gum_memory_dispose_writable_pages(first_page.0, n_pages);
        }
    }

    /// Allocate a number of whole pages with the given protection.
    ///
    /// Returns the base address of the allocation, or `None` if it fails.
    pub fn alloc_n_pages(n_pages: u32, protection: PageProtection) -> Option<NativePointer> {
        let ptr = unsafe { gum_sys::gum_alloc_n_pages(n_pages, protection as u32) };
        if ptr.is_null() {
            None
        } else {
            Some(NativePointer(ptr))
        }
    }

    /// Try to allocate `n_pages` pages, returning `None` on failure rather than
    /// aborting. This is the non-fatal variant of [`Memory::alloc_n_pages`].
    pub fn try_alloc_n_pages(n_pages: u32, protection: PageProtection) -> Option<NativePointer> {
        let ptr = unsafe { gum_sys::gum_try_alloc_n_pages(n_pages, protection as u32) };
        if ptr.is_null() {
            None
        } else {
            Some(NativePointer(ptr))
        }
    }

    /// Allocate `n_pages` whole pages within `max_distance` bytes of `near`.
    pub fn alloc_n_pages_near(
        n_pages: u32,
        protection: PageProtection,
        near: NativePointer,
        max_distance: usize,
    ) -> Option<NativePointer> {
        let spec = gum_sys::GumAddressSpec {
            near_address: near.0,
            max_distance: max_distance as u64,
        };
        let ptr = unsafe { gum_sys::gum_alloc_n_pages_near(n_pages, protection as u32, &spec) };
        if ptr.is_null() {
            None
        } else {
            Some(NativePointer(ptr))
        }
    }

    /// Try to allocate `n_pages` pages within `max_distance` bytes of `near`,
    /// returning `None` on failure rather than aborting. This is the non-fatal
    /// variant of [`Memory::alloc_n_pages_near`].
    pub fn try_alloc_n_pages_near(
        n_pages: u32,
        protection: PageProtection,
        near: NativePointer,
        max_distance: usize,
    ) -> Option<NativePointer> {
        let spec = gum_sys::GumAddressSpec {
            near_address: near.0,
            max_distance: max_distance as u64,
        };
        let ptr = unsafe { gum_sys::gum_try_alloc_n_pages_near(n_pages, protection as u32, &spec) };
        if ptr.is_null() {
            None
        } else {
            Some(NativePointer(ptr))
        }
    }

    /// Free pages previously allocated with [`Memory::alloc_n_pages`] /
    /// [`Memory::try_alloc_n_pages`] / [`Memory::alloc_n_pages_near`].
    ///
    /// # Safety
    ///
    /// The address must have been returned by one of the page-allocation APIs
    /// above and must not have been freed already.
    pub unsafe fn free_pages(address: NativePointer) {
        unsafe {
            gum_sys::gum_free_pages(address.0);
        }
    }
}
