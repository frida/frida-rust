use frida_gum_sys as gum_sys;
use std::ffi::CStr;
use std::os::raw::c_void;

use crate::{NativePointer, MemoryRange};

#[derive(FromPrimitive)]
#[repr(u32)]
pub enum PageProtection {
    NoAccess = gum_sys::_GumPageProtection_GUM_PAGE_NO_ACCESS,
    Read = gum_sys::_GumPageProtection_GUM_PAGE_READ,
    Write = gum_sys::_GumPageProtection_GUM_PAGE_WRITE,
    Execute = gum_sys::_GumPageProtection_GUM_PAGE_EXECUTE,
    ReadWrite = gum_sys::_GumPageProtection_GUM_PAGE_READ | gum_sys::_GumPageProtection_GUM_PAGE_WRITE,
    ReadExecute = gum_sys::_GumPageProtection_GUM_PAGE_READ | gum_sys::_GumPageProtection_GUM_PAGE_EXECUTE,
    ReadWriteExecute = gum_sys::_GumPageProtection_GUM_PAGE_READ | gum_sys::_GumPageProtection_GUM_PAGE_WRITE | gum_sys::_GumPageProtection_GUM_PAGE_EXECUTE,
}

pub struct FileMapping {
    file_mapping: gum_sys::GumFileMapping,
}

impl FileMapping {
    pub(crate) fn from_raw(file: gum_sys::GumFileMapping) -> Self {
        Self {
            file_mapping: file
        }
    }

    pub fn path(&self) -> &str {
       unsafe {
         CStr::from_ptr(self.file_mapping.path).to_str().unwrap()
       }
    }

    pub fn offset(&self) -> u64 {
        self.file_mapping.offset
    }

    pub fn size(&self) -> u64 {
        self.file_mapping.size
    }
}

pub struct RangeDetails {
    range_details: gum_sys::GumRangeDetails,
}

impl RangeDetails {
    pub(crate) fn from_raw(range_details: gum_sys::GumRangeDetails) -> Self {
        Self {
            range_details,
        }
    }

    pub fn memory_range(&self) -> MemoryRange {
        unsafe {
            MemoryRange::new(
                NativePointer((*self.range_details.range).base_address as *mut c_void),
                (*self.range_details.range).size as usize)
        }
    }

    pub fn protection(&self) -> PageProtection {
        num::FromPrimitive::from_u32(self.range_details.protection).unwrap()
    }

    pub fn file_mapping(&self) -> FileMapping {
       unsafe {
          FileMapping::from_raw(*self.range_details.file)
       }
    }
}
