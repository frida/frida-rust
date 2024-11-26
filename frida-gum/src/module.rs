/*
 * Copyright © 2020-2021 Keegan Saunders
 * Copyright © 2021 S Rubenstein
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Module helpers.
//!

#![cfg_attr(
    any(target_arch = "x86_64", target_arch = "x86"),
    allow(clippy::unnecessary_cast)
)]

use {
    crate::{Gum, NativePointer, PageProtection, RangeDetails},
    core::{ffi::c_void, fmt},
    cstr_core::CString,
    frida_gum_sys as gum_sys,
    frida_gum_sys::{
        gboolean, gpointer, GumExportDetails, GumModuleDetails, GumSectionDetails, GumSymbolDetails,
    },
};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String, vec, vec::Vec};

extern "C" fn enumerate_ranges_callout(
    range_details: *const gum_sys::_GumRangeDetails,
    user_data: *mut c_void,
) -> gum_sys::gboolean {
    let mut f = unsafe { Box::from_raw(user_data as *mut Box<dyn FnMut(RangeDetails) -> bool>) };
    let r = f(RangeDetails::from_raw(range_details));
    Box::leak(f);
    r as gum_sys::gboolean
}

/// Export type.
#[derive(Clone, FromPrimitive, Debug)]
#[repr(u32)]
pub enum ExportType {
    Function = gum_sys::_GumExportType_GUM_EXPORT_FUNCTION as u32,
    Variable = gum_sys::_GumExportType_GUM_EXPORT_VARIABLE as u32,
}

impl fmt::Display for ExportType {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExportType::Function => write!(fmt, "function"),
            ExportType::Variable => write!(fmt, "variable"),
        }
    }
}

impl ModuleDetailsOwned {
    pub unsafe fn from_module_details(details: *const GumModuleDetails) -> Self {
        let name: String = NativePointer((*details).name as *mut _)
            .try_into()
            .unwrap_or_default();
        let path: String = NativePointer((*details).path as *mut _)
            .try_into()
            .unwrap_or_default();
        let range = (*details).range;
        let base_address = (*range).base_address as usize;
        let size = (*range).size as usize;

        ModuleDetailsOwned {
            name,
            path,
            base_address,
            size,
        }
    }
}

impl fmt::Display for ModuleDetailsOwned {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            fmt,
            "{{\n\tbase: 0x{:x}\n\tname: {}\n\tpath: {}\n\tsize: {}\n}}",
            self.base_address, self.name, self.path, self.size
        )
    }
}

/// Module symbol details returned by [`Module::enumerate_symbols`].
pub struct SymbolDetails {
    pub name: String,
    pub address: usize,
    pub size: usize,
}

/// Module symbol details returned by [`Module::enumerate_sections`].
pub struct SectionDetails {
    pub id: String,
    pub name: String,
    pub address: usize,
    pub size: usize,
}

/// Module export details returned by [`Module::enumerate_exports`].
pub struct ExportDetails {
    pub typ: ExportType,
    pub name: String,
    pub address: usize,
}

/// Module details returned by [`Module::enumerate_modules`].
pub struct ModuleDetailsOwned {
    pub name: String,
    pub path: String,
    pub base_address: usize,
    pub size: usize,
}

pub struct Module<'a> {
    // This is to verify that Gum is initialized before using any Module methods which requires
    // intialization.
    // Note that Gum is expected to be initialized via OnceCell which provides &Gum for every
    // instance.
    _gum: &'a Gum,
}

impl<'a> Module<'a> {
    pub fn obtain(gum: &Gum) -> Module {
        Module { _gum: gum }
    }

    /// The absolute address of the export. In the event that no such export
    /// could be found, returns NULL.
    pub fn find_export_by_name(
        &self,
        module_name: Option<&str>,
        symbol_name: &str,
    ) -> Option<NativePointer> {
        let symbol_name = CString::new(symbol_name).unwrap();

        let ptr = match module_name {
            None => unsafe {
                gum_sys::gum_module_find_export_by_name(
                    core::ptr::null_mut(),
                    symbol_name.as_ptr().cast(),
                )
            },
            Some(name) => unsafe {
                let module_name = CString::new(name).unwrap();
                gum_sys::gum_module_find_export_by_name(
                    module_name.as_ptr().cast(),
                    symbol_name.as_ptr().cast(),
                )
            },
        } as *mut c_void;

        if ptr.is_null() {
            None
        } else {
            Some(NativePointer(ptr))
        }
    }

    /// The absolute address of the symbol. In the event that no such symbol
    /// could be found, returns NULL.
    pub fn find_symbol_by_name(
        &self,
        module_name: &str,
        symbol_name: &str,
    ) -> Option<NativePointer> {
        let symbol_name = CString::new(symbol_name).unwrap();

        let module_name = CString::new(module_name).unwrap();
        let ptr = unsafe {
            gum_sys::gum_module_find_symbol_by_name(
                module_name.as_ptr().cast(),
                symbol_name.as_ptr().cast(),
            )
        } as *mut c_void;

        if ptr.is_null() {
            None
        } else {
            Some(NativePointer(ptr))
        }
    }

    /// Returns the base address of the specified module. In the event that no
    /// such module could be found, returns NULL.
    pub fn find_base_address(&self, module_name: &str) -> NativePointer {
        let module_name = CString::new(module_name).unwrap();

        unsafe {
            NativePointer(
                gum_sys::gum_module_find_base_address(module_name.as_ptr().cast()) as *mut c_void,
            )
        }
    }

    /// Enumerates memory ranges satisfying protection given.
    pub fn enumerate_ranges(
        &self,
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
                module_name.as_ptr().cast(),
                prot as u32,
                Some(enumerate_ranges_callout),
                user_data,
            );

            let _ = Box::from_raw(user_data as *mut Box<dyn FnMut(RangeDetails) -> bool>);
        }
    }

    /// Enumerates modules.
    pub fn enumerate_modules(&self) -> Vec<ModuleDetailsOwned> {
        let result: Vec<ModuleDetailsOwned> = vec![];

        unsafe extern "C" fn callback(
            details: *const GumModuleDetails,
            user_data: gpointer,
        ) -> gboolean {
            let res = &mut *(user_data as *mut Vec<ModuleDetailsOwned>);
            res.push(ModuleDetailsOwned::from_module_details(details));

            1
        }

        unsafe {
            frida_gum_sys::gum_process_enumerate_modules(
                Some(callback),
                &result as *const _ as *mut c_void,
            );
        }

        result
    }

    /// Enumerates exports in module.
    pub fn enumerate_exports(&self, module_name: &str) -> Vec<ExportDetails> {
        let result: Vec<ExportDetails> = vec![];

        unsafe extern "C" fn callback(
            details: *const GumExportDetails,
            user_data: gpointer,
        ) -> gboolean {
            let res = &mut *(user_data as *mut Vec<ExportDetails>);
            let name: String = NativePointer((*details).name as *mut _)
                .try_into()
                .unwrap_or_default();

            let address = (*details).address as usize;
            let typ = num::FromPrimitive::from_u32((*details).type_ as u32).unwrap();
            let info = ExportDetails { typ, name, address };
            res.push(info);
            1
        }

        let module_name = CString::new(module_name).unwrap();

        unsafe {
            frida_gum_sys::gum_module_enumerate_exports(
                module_name.as_ptr().cast(),
                Some(callback),
                &result as *const _ as *mut c_void,
            );
        }
        result
    }

    /// Enumerates symbols in module.
    pub fn enumerate_symbols(&self, module_name: &str) -> Vec<SymbolDetails> {
        let result: Vec<SymbolDetails> = vec![];
        unsafe extern "C" fn callback(
            details: *const GumSymbolDetails,
            user_data: gpointer,
        ) -> gboolean {
            let res = &mut *(user_data as *mut Vec<SymbolDetails>);

            let name: String = NativePointer((*details).name as *mut _)
                .try_into()
                .unwrap_or_default();
            let address = (*details).address as usize;
            let size = (*details).size as usize;

            let info = SymbolDetails {
                name,
                address,
                size,
            };
            res.push(info);

            1
        }

        let module_name = CString::new(module_name).unwrap();

        unsafe {
            frida_gum_sys::gum_module_enumerate_symbols(
                module_name.as_ptr().cast(),
                Some(callback),
                &result as *const _ as *mut c_void,
            );
        }
        result
    }

    /// Enumerates sections of module.
    pub fn enumerate_sections(&self, module_name: &str) -> Vec<SectionDetails> {
        let result: Vec<SectionDetails> = vec![];

        unsafe extern "C" fn callback(
            details: *const GumSectionDetails,
            user_data: gpointer,
        ) -> gboolean {
            let res = &mut *(user_data as *mut Vec<SectionDetails>);

            let id: String = NativePointer((*details).id as *mut _)
                .try_into()
                .unwrap_or_default();
            let name: String = NativePointer((*details).name as *mut _)
                .try_into()
                .unwrap_or_default();
            let address = (*details).address as usize;
            let size = (*details).size as usize;

            let info = SectionDetails {
                id,
                name,
                address,
                size,
            };
            res.push(info);

            1
        }

        let module_name = CString::new(module_name).unwrap();

        unsafe {
            frida_gum_sys::gum_module_enumerate_sections(
                module_name.as_ptr().cast(),
                Some(callback),
                &result as *const _ as *mut c_void,
            );
        }
        result
    }
}
