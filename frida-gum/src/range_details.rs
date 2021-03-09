use frida_gum_sys as gum_sys;
use std::ffi::CStr;
use std::os::raw::c_void;

use crate::{NativePointer, MemoryRange};

pub struct FileMapping {
    file_mapping: gum_sys::GumFileMapping,
}

impl FileMapping {
    pub fn new_from_raw(file: gum_sys::GumFileMapping) -> Self {
        Self {
            file_mapping: file
        }
    }

    pub fn get_path(&self) -> &str {
       unsafe {
         CStr::from_ptr(self.file_mapping.path).to_str().unwrap()
       }
    }

    pub fn get_offset(&self) -> u64 {
        self.file_mapping.offset
    }

    pub fn get_size(&self) -> u64 {
        self.file_mapping.size
    }
}
pub struct RangeDetails {
    range_details: gum_sys::GumRangeDetails,
}

impl RangeDetails {
    pub fn new_from_raw(range_details: gum_sys::GumRangeDetails) -> Self {
        Self {
            range_details,
        }
    }

    pub fn get_memory_range(&self) -> MemoryRange {
        unsafe {
            MemoryRange::new(
                NativePointer((*self.range_details.range).base_address as *mut c_void),
                (*self.range_details.range).size as usize)
        }
    }

    pub fn get_protection(&self) -> gum_sys::GumPageProtection {
        self.range_details.protection
    }

    pub fn get_file_mapping(&self) -> FileMapping {
       unsafe {
          FileMapping::new_from_raw(*self.range_details.file)
       }
    }
}
