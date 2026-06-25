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

use crate::MemoryRange;
#[cfg(feature = "std")]
use std::{ffi::CStr, string::ToString};

use {
    crate::{Gum, NativePointer, PageProtection, RangeDetails},
    core::{ffi::c_void, fmt, fmt::Debug},
    cstr_core::CString,
    frida_gum_sys as gum_sys,
    frida_gum_sys::{
        GumDependencyDetails, GumExportDetails, GumImportDetails, GumModule, GumSectionDetails,
        GumSymbolDetails, gboolean, gpointer,
    },
};

#[cfg(not(feature = "std"))]
use {
    alloc::{boxed::Box, string::String, string::ToString, vec, vec::Vec},
    core::ffi::CStr,
};

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
    Function = gum_sys::GumExportType_GUM_EXPORT_FUNCTION as u32,
    Variable = gum_sys::GumExportType_GUM_EXPORT_VARIABLE as u32,
}

impl fmt::Display for ExportType {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExportType::Function => write!(fmt, "function"),
            ExportType::Variable => write!(fmt, "variable"),
        }
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

/// Import type — function, variable, or unknown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportType {
    /// The import is a function.
    Function,
    /// The import is a variable.
    Variable,
    /// The import type could not be determined.
    Unknown,
}

/// Dependency type — how the module depends on the named library.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DependencyType {
    /// A standard runtime dependency.
    Regular,
    /// A weak link — the dependency may be absent.
    Weak,
    /// The dependency is a re-export.
    Reexport,
    /// An upward (parent) dependency.
    Upward,
}

/// Details about an imported symbol returned by [`Module::enumerate_imports`].
pub struct ImportDetails {
    pub typ: ImportType,
    pub name: String,
    pub module: Option<String>,
    pub address: usize,
    pub slot: usize,
}

/// Details about a module dependency returned by
/// [`Module::enumerate_dependencies`].
pub struct DependencyDetails {
    pub name: String,
    pub typ: DependencyType,
}

/// Module export details returned by [`Module::enumerate_exports`].
pub struct ExportDetails {
    pub typ: ExportType,
    pub name: String,
    pub address: usize,
}

impl Drop for Module {
    fn drop(&mut self) {
        unsafe {
            gum_sys::g_object_unref(self.inner as _);
        }
    }
}

pub struct Module {
    inner: *mut GumModule,
}

impl Module {
    pub(crate) fn from_raw(module: *mut GumModule) -> Self {
        unsafe {
            gum_sys::g_object_ref(module.cast());
        }
        Self { inner: module }
    }

    /// Load a module by name
    pub fn load(_gum: &Gum, module_name: &str) -> Self {
        let module_name = CString::new(module_name).unwrap();
        Self {
            inner: unsafe {
                gum_sys::gum_module_load(module_name.as_ptr().cast(), core::ptr::null_mut())
            },
        }
    }

    /// Get the name of this module
    pub fn name(&self) -> String {
        unsafe {
            CStr::from_ptr(gum_sys::gum_module_get_name(self.inner))
                .to_string_lossy()
                .to_string()
        }
    }

    /// Get the path of this module
    pub fn path(&self) -> String {
        unsafe {
            CStr::from_ptr(gum_sys::gum_module_get_path(self.inner))
                .to_string_lossy()
                .to_string()
        }
    }

    /// Get the range of this module
    pub fn range(&self) -> MemoryRange {
        MemoryRange::from_raw(unsafe { gum_sys::gum_module_get_range(self.inner) })
    }

    /// The absolute address of the export. In the event that no such export
    /// could be found, returns NULL.
    pub fn find_export_by_name(&self, symbol_name: &str) -> Option<NativePointer> {
        let symbol_name = CString::new(symbol_name).unwrap();

        let ptr = unsafe {
            gum_sys::gum_module_find_export_by_name(self.inner, symbol_name.as_ptr().cast())
                as *mut c_void
        };

        if ptr.is_null() {
            None
        } else {
            Some(NativePointer(ptr))
        }
    }

    /// The absolute address of the export. In the event that no such export
    /// could be found, returns NULL.
    pub fn find_global_export_by_name(symbol_name: &str) -> Option<NativePointer> {
        let symbol_name = CString::new(symbol_name).unwrap();

        let ptr = unsafe {
            gum_sys::gum_module_find_global_export_by_name(symbol_name.as_ptr().cast())
                as *mut c_void
        };

        if ptr.is_null() {
            None
        } else {
            Some(NativePointer(ptr))
        }
    }

    /// The absolute address of the symbol. In the event that no such symbol
    /// could be found, returns NULL.
    pub fn find_symbol_by_name(&self, symbol_name: &str) -> Option<NativePointer> {
        let symbol_name = CString::new(symbol_name).unwrap();

        let ptr = unsafe {
            gum_sys::gum_module_find_symbol_by_name(self.inner, symbol_name.as_ptr().cast())
        } as *mut c_void;

        if ptr.is_null() {
            None
        } else {
            Some(NativePointer(ptr))
        }
    }

    /// Enumerates memory ranges satisfying protection given.
    pub fn enumerate_ranges(
        &self,
        prot: PageProtection,
        callout: impl FnMut(RangeDetails) -> bool,
    ) {
        unsafe {
            let user_data = Box::leak(Box::new(
                Box::new(callout) as Box<dyn FnMut(RangeDetails) -> bool>
            )) as *mut _ as *mut c_void;

            gum_sys::gum_module_enumerate_ranges(
                self.inner,
                prot as u32,
                Some(enumerate_ranges_callout),
                user_data,
            );

            let _ = Box::from_raw(user_data as *mut Box<dyn FnMut(RangeDetails) -> bool>);
        }
    }

    /// Enumerates exports in module.
    pub fn enumerate_exports(&self) -> Vec<ExportDetails> {
        let mut result: Vec<ExportDetails> = vec![];

        unsafe extern "C" fn callback(
            details: *const GumExportDetails,
            user_data: gpointer,
        ) -> gboolean {
            unsafe {
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
        }

        unsafe {
            frida_gum_sys::gum_module_enumerate_exports(
                self.inner,
                Some(callback),
                &mut result as *mut _ as *mut c_void,
            );
        }
        result
    }

    /// Enumerates symbols in module.
    pub fn enumerate_symbols(&self) -> Vec<SymbolDetails> {
        let mut result: Vec<SymbolDetails> = vec![];
        unsafe extern "C" fn callback(
            details: *const GumSymbolDetails,
            user_data: gpointer,
        ) -> gboolean {
            unsafe {
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
        }

        unsafe {
            frida_gum_sys::gum_module_enumerate_symbols(
                self.inner,
                Some(callback),
                &mut result as *mut _ as *mut c_void,
            );
        }
        result
    }

    /// Enumerates sections of module.
    pub fn enumerate_sections(&self) -> Vec<SectionDetails> {
        let mut result: Vec<SectionDetails> = vec![];

        unsafe extern "C" fn callback(
            details: *const GumSectionDetails,
            user_data: gpointer,
        ) -> gboolean {
            unsafe {
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
        }

        unsafe {
            frida_gum_sys::gum_module_enumerate_sections(
                self.inner,
                Some(callback),
                &mut result as *mut _ as *mut c_void,
            );
        }
        result
    }

    /// Enumerate the module's imports.
    pub fn enumerate_imports(&self) -> Vec<ImportDetails> {
        let mut result: Vec<ImportDetails> = Vec::new();

        unsafe extern "C" fn callback(
            details: *const GumImportDetails,
            user_data: gpointer,
        ) -> gboolean {
            unsafe {
                let res = &mut *(user_data as *mut Vec<ImportDetails>);

                let name: String = NativePointer((*details).name as *mut _)
                    .try_into()
                    .unwrap_or_default();

                let module = if (*details).module.is_null() {
                    None
                } else {
                    Some(
                        NativePointer((*details).module as *mut _)
                            .try_into()
                            .unwrap_or_default(),
                    )
                };

                let typ = match (*details).type_ as u32 {
                    x if x == gum_sys::GumImportType_GUM_IMPORT_FUNCTION as u32 => {
                        ImportType::Function
                    }
                    x if x == gum_sys::GumImportType_GUM_IMPORT_VARIABLE as u32 => {
                        ImportType::Variable
                    }
                    _ => ImportType::Unknown,
                };

                res.push(ImportDetails {
                    typ,
                    name,
                    module,
                    address: (*details).address as usize,
                    slot: (*details).slot as usize,
                });
                1
            }
        }

        unsafe {
            frida_gum_sys::gum_module_enumerate_imports(
                self.inner,
                Some(callback),
                &mut result as *mut _ as *mut c_void,
            );
        }
        result
    }

    /// Enumerate the module's dependencies.
    pub fn enumerate_dependencies(&self) -> Vec<DependencyDetails> {
        let mut result: Vec<DependencyDetails> = Vec::new();

        unsafe extern "C" fn callback(
            details: *const GumDependencyDetails,
            user_data: gpointer,
        ) -> gboolean {
            unsafe {
                let res = &mut *(user_data as *mut Vec<DependencyDetails>);

                let name: String = NativePointer((*details).name as *mut _)
                    .try_into()
                    .unwrap_or_default();

                let typ = match (*details).type_ as u32 {
                    x if x == gum_sys::GumDependencyType_GUM_DEPENDENCY_WEAK as u32 => {
                        DependencyType::Weak
                    }
                    x if x == gum_sys::GumDependencyType_GUM_DEPENDENCY_REEXPORT as u32 => {
                        DependencyType::Reexport
                    }
                    x if x == gum_sys::GumDependencyType_GUM_DEPENDENCY_UPWARD as u32 => {
                        DependencyType::Upward
                    }
                    _ => DependencyType::Regular,
                };

                res.push(DependencyDetails { name, typ });
                1
            }
        }

        unsafe {
            frida_gum_sys::gum_module_enumerate_dependencies(
                self.inner,
                Some(callback),
                &mut result as *mut _ as *mut c_void,
            );
        }
        result
    }

    /// Get the version string of the module, if any.
    pub fn version(&self) -> Option<String> {
        unsafe {
            let ptr = gum_sys::gum_module_get_version(self.inner);
            if ptr.is_null() {
                None
            } else {
                Some(CStr::from_ptr(ptr).to_string_lossy().to_string())
            }
        }
    }

    /// Ensure the module is fully initialized.
    ///
    /// On platforms with lazy module loading (e.g. Linux ld.so), this
    /// resolves any pending fixups so subsequent enumeration calls produce
    /// stable results.
    pub fn ensure_initialized(&self) {
        unsafe { gum_sys::gum_module_ensure_initialized(self.inner) };
    }
}

impl Debug for Module {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Module")
            .field("name", &self.name())
            .field("path", &self.path())
            .finish_non_exhaustive()
    }
}
