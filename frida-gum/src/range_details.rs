/*
 * Copyright © 2021 Keegan Saunders
 * Copyright © 2021 S Rubenstein
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#![cfg_attr(
    any(target_arch = "x86_64", target_arch = "x86"),
    allow(clippy::unnecessary_cast)
)]

use {
    crate::MemoryRange,
    core::{
        ffi::{c_void, CStr},
        marker::PhantomData,
    },
    frida_gum_sys as gum_sys,
};

#[cfg(not(feature = "module-names"))]
use alloc::boxed::Box;

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
        unsafe { (*self.file_mapping).size as u64 }
    }
}

struct SaveRangeDetailsByAddressContext {
    address: u64,
    details: *const gum_sys::GumRangeDetails,
}

unsafe extern "C" fn save_range_details_by_address(
    details: *const gum_sys::GumRangeDetails,
    context: *mut c_void,
) -> i32 {
    let mut context = &mut *(context as *mut SaveRangeDetailsByAddressContext);
    let range = (*details).range;
    let start = (*range).base_address as u64;
    let end = start + (*range).size as u64;
    if start <= context.address && context.address < end {
        context.details = details;
        return 0;
    }

    1
}

unsafe extern "C" fn enumerate_ranges_stub(
    details: *const gum_sys::GumRangeDetails,
    context: *mut c_void,
) -> i32 {
    if !(*(context as *mut Box<&mut dyn FnMut(&RangeDetails) -> bool>))(&RangeDetails::from_raw(
        details,
    )) {
        return 0;
    }
    1
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

    /// Get a [`RangeDetails`] for the range containing the given address.
    pub fn with_address(address: u64) -> Option<RangeDetails<'a>> {
        let mut context = SaveRangeDetailsByAddressContext {
            address,
            details: core::ptr::null_mut(),
        };
        unsafe {
            gum_sys::gum_process_enumerate_ranges(
                gum_sys::_GumPageProtection_GUM_PAGE_NO_ACCESS as u32,
                Some(save_range_details_by_address),
                &mut context as *mut _ as *mut c_void,
            );
        }

        if !context.details.is_null() {
            Some(RangeDetails::from_raw(context.details))
        } else {
            None
        }
    }

    /// Enumerate all ranges which match the given [`PageProtection`], calling the callback
    /// function for each such range.
    pub fn enumerate_with_prot(
        prot: PageProtection,
        callback: &mut dyn FnMut(&RangeDetails) -> bool,
    ) {
        unsafe {
            gum_sys::gum_process_enumerate_ranges(
                prot as u32,
                Some(enumerate_ranges_stub),
                &mut Box::new(callback) as *mut _ as *mut c_void,
            );
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
