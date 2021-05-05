/*
 * Copyright © 2021 Keegan Saunders
 * Copyright © 2021 S Rubenstein
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use frida_gum_sys as gum_sys;
use std::ffi::CStr;
use std::marker::PhantomData;

use crate::MemoryRange;

/// The memory protection of an unassociated page.
#[derive(FromPrimitive)]
#[repr(u32)]
pub enum PageProtection {
    NoAccess = gum_sys::_GumPageProtection_GUM_PAGE_NO_ACCESS as u32,
    Read = gum_sys::_GumPageProtection_GUM_PAGE_READ as u32,
    Write = gum_sys::_GumPageProtection_GUM_PAGE_WRITE as u32,
    Execute = gum_sys::_GumPageProtection_GUM_PAGE_EXECUTE as u32,
    ReadWrite = gum_sys::_GumPageProtection_GUM_PAGE_READ as u32
        | gum_sys::_GumPageProtection_GUM_PAGE_WRITE as u32,
    ReadExecute = gum_sys::_GumPageProtection_GUM_PAGE_READ as u32
        | gum_sys::_GumPageProtection_GUM_PAGE_EXECUTE as u32,
    ReadWriteExecute = gum_sys::_GumPageProtection_GUM_PAGE_READ as u32
        | gum_sys::_GumPageProtection_GUM_PAGE_WRITE as u32
        | gum_sys::_GumPageProtection_GUM_PAGE_EXECUTE as u32,
}

/// The file association to a page.
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

    /// The path of the file mapping on disk.
    pub fn path(&self) -> &str {
        unsafe { CStr::from_ptr((*self.file_mapping).path).to_str().unwrap() }
    }

    /// The offset into the file mapping.
    pub fn offset(&self) -> u64 {
        unsafe { (*self.file_mapping).offset }
    }

    /// The size of the mapping.
    pub fn size(&self) -> u64 {
        unsafe { (*self.file_mapping).size }
    }
}

/// Details a range of virtual memory.
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

    /// The range of memory that is detailed.
    pub fn memory_range(&self) -> MemoryRange {
        unsafe { MemoryRange::from_raw((*self.range_details).range) }
    }

    /// The page protection of the range.
    pub fn protection(&self) -> PageProtection {
        let protection = unsafe { (*self.range_details).protection };
        num::FromPrimitive::from_u32(protection).unwrap()
    }

    /// The associated file mapping, if present.
    pub fn file_mapping(&self) -> Option<FileMapping> {
        if self.range_details.is_null() {
            None
        } else {
            Some(unsafe { FileMapping::from_raw((*self.range_details).file) })
        }
    }
}
