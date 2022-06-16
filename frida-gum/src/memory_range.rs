/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use frida_gum_sys as gum_sys;
use std::ffi::CString;
use std::os::raw::c_void;

use crate::NativePointer;

pub struct MatchPattern {
    pub(crate) internal: *mut gum_sys::GumMatchPattern,
}

impl MatchPattern {
    pub fn from_string(pattern: &str) -> Self {
        let pattern = CString::new(pattern).unwrap();
        Self {
            internal: unsafe { gum_sys::gum_match_pattern_new_from_string(pattern.as_ptr()) },
        }
    }
}

impl Drop for MatchPattern {
    fn drop(&mut self) {
        unsafe { gum_sys::gum_match_pattern_unref(self.internal) }
    }
}

pub struct MemoryRange {
    pub(crate) memory_range: gum_sys::GumMemoryRange,
}

impl MemoryRange {
    pub(crate) fn from_raw(memory_range: *const gum_sys::GumMemoryRange) -> MemoryRange {
        MemoryRange {
            memory_range: unsafe { *memory_range },
        }
    }

    pub fn new(base_address: NativePointer, size: usize) -> MemoryRange {
        MemoryRange {
            memory_range: gum_sys::GumMemoryRange {
                base_address: base_address.0 as u64,
                size: size as _,
            },
        }
    }

    /// Get the start address of the range.
    pub fn base_address(&self) -> NativePointer {
        NativePointer(self.memory_range.base_address as *mut c_void)
    }

    /// Get the size of the range.
    /// The end address of the range can be computed by adding the [`MemoryRange::base_address()`]
    /// to the size.
    pub fn size(&self) -> usize {
        self.memory_range.size as usize
    }

    pub fn scan(&self, pattern: &MatchPattern) -> Vec<(usize, usize)> {
        let mut results = Vec::new();
        unsafe {
            extern "C" fn callback(address: u64, size: u64, user_data: *mut c_void) -> i32 {
                let results: &mut Vec<(usize, usize)> =
                    unsafe { &mut *(user_data as *mut Vec<(usize, usize)>) };
                log::debug!("address: {:x}, size: {:x}", address, size);
                results.push((address as usize, size as usize));
                0
            }
            gum_sys::gum_memory_scan(
                &self.memory_range as *const gum_sys::GumMemoryRange,
                pattern.internal,
                Some(callback),
                &mut results as *mut _ as *mut _,
            );
        }

        results
    }
}
