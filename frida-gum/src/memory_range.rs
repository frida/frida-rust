use frida_gum_sys as gum_sys;
use std::os::raw::c_void;

use crate::NativePointer;

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
}
