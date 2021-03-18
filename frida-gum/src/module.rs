/*
 * Copyright (C) 2020-2021 meme <keegan@sdf.org>
 * Copyright (C) 2021 S Rubenstein <s1341@shmarya.net>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Module helpers.
//!

use frida_gum_sys as gum_sys;
use std::ffi::CString;
use std::os::raw::c_void;

use crate::{NativePointer, PageProtection, RangeDetails};

extern "C" fn enumerate_ranges_callout(
    range_details: *const gum_sys::_GumRangeDetails,
    user_data: *mut c_void,
) -> gum_sys::gboolean {
    let mut f = unsafe { Box::from_raw(user_data as *mut Box<dyn FnMut(RangeDetails) -> bool>) };
    let r = f(RangeDetails::from_raw(range_details));
    Box::leak(f);
    r as gum_sys::gboolean
}

pub struct Module;

impl Module {
    /// The absolute address of the export. In the event that no such export
    /// could be found, returns NULL.
    pub fn find_export_by_name(module_name: Option<&str>, symbol_name: &str) -> NativePointer {
        let symbol_name = CString::new(symbol_name).unwrap();

        NativePointer(match module_name {
            None => unsafe {
                gum_sys::gum_module_find_export_by_name(std::ptr::null_mut(), symbol_name.as_ptr())
            },
            Some(name) => unsafe {
                let module_name = CString::new(name).unwrap();
                gum_sys::gum_module_find_export_by_name(module_name.as_ptr(), symbol_name.as_ptr())
            },
        } as *mut c_void)
    }

    /// Returns the base address of the specified module. In the event that no
    /// such module could be found, returns NULL.
    pub fn find_base_address(module_name: &str) -> NativePointer {
        let module_name = CString::new(module_name).unwrap();

        unsafe {
            NativePointer(gum_sys::gum_module_find_base_address(module_name.as_ptr()) as *mut c_void)
        }
    }

    /// Enumerates memory ranges satisfying protection given.
    pub fn enumerate_ranges(
        module_name: &str,
        prot: PageProtection,
        callout: impl FnMut(RangeDetails) -> bool,
    ) {
        let module_name = CString::new(module_name).unwrap();

        unsafe {
            let user_data = Box::leak(Box::new(
                Box::new(callout) as Box<dyn FnMut(RangeDetails) -> bool>
            )) as *mut _ as *mut c_void;

            gum_sys::gum_module_enumerate_ranges(
                module_name.as_ptr(),
                prot as u32,
                Some(enumerate_ranges_callout),
                user_data,
            );

            let _ = Box::from_raw(user_data as *mut Box<dyn FnMut(RangeDetails) -> bool>);
        }
    }
}
