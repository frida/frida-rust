/*
 * Copyright © 2020-2021 Keegan Saunders
 * Copyright © 2021 S Rubenstein
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Module helpers.
//!

use frida_gum_sys as gum_sys;
use std::ffi::CString;
use std::os::raw::c_void;

use frida_gum_sys::{GumExportDetails, gpointer, gboolean, GumModuleDetails, GumSymbolDetails};

use crate::{NativePointer, PageProtection, RangeDetails, ExportDetails, ModuleDetails, FromCString, SymbolDetails};

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
    pub fn find_export_by_name(
        module_name: Option<&str>,
        symbol_name: &str,
    ) -> Option<NativePointer> {
        let symbol_name = CString::new(symbol_name).unwrap();

        let ptr = match module_name {
            None => unsafe {
                gum_sys::gum_module_find_export_by_name(std::ptr::null_mut(), symbol_name.as_ptr())
            },
            Some(name) => unsafe {
                let module_name = CString::new(name).unwrap();
                gum_sys::gum_module_find_export_by_name(module_name.as_ptr(), symbol_name.as_ptr())
            },
        } as *mut c_void;

        if ptr.is_null() {
            None
        } else {
            Some(NativePointer(ptr))
        }
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

    /// Enumerates modules.
    pub fn enumerate_modules() -> Vec<ModuleDetails> {

        let  result: Vec<ModuleDetails> = vec![];

        unsafe extern "C" fn callback(details: *const GumModuleDetails, _user_data: gpointer) -> gboolean
        {
            let res =  &mut *(_user_data as *mut Vec<ModuleDetails>);

            let name = String::from_c_string((*details).name);
            let path = String::from_c_string((*details).path);
            let range = (*details).range;
            let base_addr = (*range).base_address as usize;
            let size = (*range).size as usize;
            let mi = ModuleDetails {name,path, base_addr, size };
            res.push(mi);

            1
        }

        unsafe {
            frida_gum_sys::gum_process_enumerate_modules(Some(callback), &result as * const _ as *mut std::ffi::c_void);

        }
        result
    }

    /// Enumerates exports in module.
    pub fn enumerate_exports(module_name: &str) -> Vec<ExportDetails> {

        let result: Vec<ExportDetails> = vec![];

        unsafe extern "C"  fn callback(details: *const GumExportDetails, user_data: gpointer) -> gboolean
        {
            let res =   &mut *(user_data as *mut Vec<ExportDetails>) ;
            let name = String::from_c_string((*details).name);

            let address = (*details).address as usize;
            let type_ = (*details).type_ as u32;
            let info = ExportDetails{type_, name, address};
            res.push(info);
            1
        }

        let module_name = CString::new(module_name).unwrap();

        unsafe {
            frida_gum_sys::gum_module_enumerate_exports(module_name.as_ptr(),Some(callback),&result as * const _ as *mut std::ffi::c_void );
        }
        result
    }

    /// Enumerates symbols in module.
    pub fn enumerate_symbols(module_name: &str) -> Vec<SymbolDetails> {

        let  result: Vec<SymbolDetails> = vec![];
        unsafe extern "C"  fn callback(details: *const GumSymbolDetails, user_data: gpointer) -> gboolean
        {

            let res =  &mut *(user_data as *mut Vec<SymbolDetails>);

            let name = String::from_c_string((*details).name);
            let address = (*details).address as usize;
            let size = (*details).size as usize;

            let info = SymbolDetails{name,address,size};
            res.push(info);

            1
        }

        let module_name = CString::new(module_name).unwrap();

        unsafe {
            frida_gum_sys::gum_module_enumerate_symbols(module_name.as_ptr(),Some(callback),&result as * const _ as *mut std::ffi::c_void );
        }
        result
    }
}
