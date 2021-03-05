//! Module helpers.
//!

use frida_gum_sys as gum_sys;
use std::ffi::CString;
use std::os::raw::c_void;

use crate::NativePointer;

pub struct Module;

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
}
