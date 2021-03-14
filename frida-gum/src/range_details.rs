use frida_gum_sys as gum_sys;
use std::ffi::CStr;
use std::marker::PhantomData;

use crate::MemoryRange;

#[derive(FromPrimitive)]
#[repr(u32)]
pub enum PageProtection {
    NoAccess = gum_sys::_GumPageProtection_GUM_PAGE_NO_ACCESS,
    Read = gum_sys::_GumPageProtection_GUM_PAGE_READ,
    Write = gum_sys::_GumPageProtection_GUM_PAGE_WRITE,
    Execute = gum_sys::_GumPageProtection_GUM_PAGE_EXECUTE,
    ReadWrite =
        gum_sys::_GumPageProtection_GUM_PAGE_READ | gum_sys::_GumPageProtection_GUM_PAGE_WRITE,
    ReadExecute =
        gum_sys::_GumPageProtection_GUM_PAGE_READ | gum_sys::_GumPageProtection_GUM_PAGE_EXECUTE,
    ReadWriteExecute = gum_sys::_GumPageProtection_GUM_PAGE_READ
        | gum_sys::_GumPageProtection_GUM_PAGE_WRITE
        | gum_sys::_GumPageProtection_GUM_PAGE_EXECUTE,
}

pub struct FileMapping<'a> {
    file_mapping: *const gum_sys::GumFileMapping,
    phantom: PhantomData<&'a gum_sys::GumFileMapping>,
}

impl<'a> FileMapping<'a> {
    pub(crate) fn from_raw(file: *const gum_sys::GumFileMapping) -> Self {
        Self {
            file_mapping: file,
            phantom: PhantomData,
        }
    }

    pub fn path(&self) -> &str {
        unsafe { CStr::from_ptr((*self.file_mapping).path).to_str().unwrap() }
    }

    pub fn offset(&self) -> u64 {
        unsafe { (*self.file_mapping).offset }
    }

    pub fn size(&self) -> u64 {
        unsafe { (*self.file_mapping).size }
    }
}

pub struct RangeDetails<'a> {
    range_details: *const gum_sys::GumRangeDetails,
    phantom: PhantomData<&'a gum_sys::GumRangeDetails>,
}

impl<'a> RangeDetails<'a> {
    pub(crate) fn from_raw(range_details: *const gum_sys::GumRangeDetails) -> Self {
        Self {
            range_details,
            phantom: PhantomData,
        }
    }

    pub fn memory_range(&self) -> MemoryRange {
        unsafe { MemoryRange::from_raw((*self.range_details).range) }
    }

    pub fn protection(&self) -> PageProtection {
        let protection = unsafe { (*self.range_details).protection };
        num::FromPrimitive::from_u32(protection).unwrap()
    }

    pub fn file_mapping(&self) -> FileMapping {
        unsafe { FileMapping::from_raw((*self.range_details).file) }
    }
}
