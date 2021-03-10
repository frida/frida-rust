//! Module helpers.
//!

use frida_gum_sys as gum_sys;
use std::ffi::CString;
use std::os::raw::c_void;

use crate::{NativePointer, PageProtection, RangeDetails};

pub struct Module;

struct EnumerateRangesUserDataWrapper<'a> {
    func: &'a mut dyn FnMut(RangeDetails, *mut c_void) -> i32,
    user_data: *mut c_void,
}

unsafe extern "C" fn enumerate_ranges_thunk(details: *const gum_sys::_GumRangeDetails, user_data: *mut c_void) -> i32 {
    let user_data_box = Box::from_raw(user_data as *mut Box<&mut EnumerateRangesUserDataWrapper>);

    let ret = (user_data_box.func)(RangeDetails::from_raw(*details), user_data_box.user_data);
    Box::leak(user_data_box);
    ret
}

impl Module {
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

    pub fn find_base_address(module_name: &str) -> NativePointer {
        let module_name = CString::new(module_name).unwrap();

        unsafe {
            NativePointer(gum_sys::gum_module_find_base_address(module_name.as_ptr()) as *mut c_void)
        }
    }

    pub fn enumerate_ranges(
        module_name: &str,
        prot: PageProtection,
        mut func: impl FnMut(RangeDetails, *mut c_void) -> i32,
        user_data: *mut c_void) {

        let module_name = CString::new(module_name).unwrap();

        unsafe {
            let mut user_data_wrapper = EnumerateRangesUserDataWrapper {
                func: &mut func,
                user_data
            };

            gum_sys::gum_module_enumerate_ranges(
                module_name.as_ptr(),
                prot as u32,
                Some(enumerate_ranges_thunk),
                Box::into_raw(Box::new(Box::new(&mut user_data_wrapper))) as *mut _ as *mut c_void)
        }
    }
}

