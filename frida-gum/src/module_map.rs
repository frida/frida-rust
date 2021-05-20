/*
 * Copyright © 2020-2021 Keegan Saunders
 * Copyright © 2021 S Rubenstein
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use frida_gum_sys as gum_sys;
use std::{ffi::CStr, os::raw::c_void, path::Path};

use crate::MemoryRange;

pub struct ModuleDetails {
    module_details: *const gum_sys::GumModuleDetails,
}

/// Represents a loaded module
impl ModuleDetails {
    pub(crate) fn from_raw(module_details: *const gum_sys::_GumModuleDetails) -> Self {
        Self { module_details }
    }

    /// Get a new [`ModuleDetails`] instance for the module matching the given name. The name may
    /// be a full path, in which case the matching module must have the same full path, or a
    /// file name, in which case only the file name portion of the module must match.
    pub fn with_name(name: String) -> Option<Self> {
        struct SaveModuleDetailsByNameContext {
            name: String,
            details: *mut gum_sys::GumModuleDetails,
        }

        unsafe extern "C" fn save_module_details_by_name(
            details: *const gum_sys::GumModuleDetails,
            context: *mut c_void,
        ) -> i32 {
            let mut context = &mut *(context as *mut SaveModuleDetailsByNameContext);
            let path_string = CStr::from_ptr((*details).path as *const _)
                .to_string_lossy()
                .to_string();
            if (context.name.starts_with('/') && path_string.eq(&context.name))
                || (context.name.contains('/')
                    && Path::new(&path_string)
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .eq(&context.name))
            {
                context.details = gum_sys::gum_module_details_copy(details);
                return 0;
            }

            1
        }

        let mut context = SaveModuleDetailsByNameContext {
            name,
            details: std::ptr::null_mut(),
        };

        unsafe {
            gum_sys::gum_process_enumerate_modules(
                Some(save_module_details_by_name),
                &mut context as *mut _ as *mut c_void,
            );
        }

        if context.details.is_null() {
            None
        } else {
            Some(Self::from_raw(context.details))
        }
    }

    /// Get the name of this module
    pub fn name(&self) -> String {
        unsafe {
            CStr::from_ptr((*self.module_details).name)
                .to_string_lossy()
                .to_string()
        }
    }

    /// Get the path of this module
    pub fn path(&self) -> String {
        unsafe {
            CStr::from_ptr((*self.module_details).path)
                .to_string_lossy()
                .to_string()
        }
    }

    /// Get the range of this module
    pub fn range(&self) -> MemoryRange {
        MemoryRange::from_raw(unsafe { (*self.module_details).range })
    }
}

pub struct ModuleMap {
    pub(crate) module_map: *mut gum_sys::GumModuleMap,
}

impl ModuleMap {
    pub(crate) fn from_raw(module_map: *mut gum_sys::GumModuleMap) -> Self {
        Self { module_map }
    }

    /// Create a new [`ModuleMap`]
    pub fn new() -> Self {
        Self::from_raw(unsafe { gum_sys::gum_module_map_new() })
    }

    /// Create a new [`ModuleMap`] with a filter function
    pub fn new_with_filter(filter: &mut dyn FnMut(ModuleDetails) -> bool) -> Self {
        unsafe extern "C" fn module_map_filter(
            details: *const gum_sys::_GumModuleDetails,
            callback: *mut c_void,
        ) -> i32 {
            let callback = &mut *(callback as *mut Box<&mut dyn FnMut(ModuleDetails) -> bool>);
            if (callback)(ModuleDetails::from_raw(details)) {
                1
            } else {
                0
            }
        }
        Self::from_raw(unsafe {
            gum_sys::gum_module_map_new_filtered(
                Some(module_map_filter),
                &mut Box::new(filter) as *mut _ as *mut c_void,
                None,
            )
        })
    }

    /// Create a new [`ModuleMap`] from a list of names
    pub fn new_from_names(names: &[&str]) -> Self {
        Self::new_with_filter(&mut |details: ModuleDetails| {
            for name in names {
                if (name.starts_with('/') && details.path().eq(name))
                    || (name.contains('/')
                        && details.name().eq(Path::new(name)
                            .file_name()
                            .unwrap()
                            .to_str()
                            .unwrap()))
                    || (details.name().eq(name))
                {
                    return true;
                }
            }
            false
        })
    }
    /// Find the given address in the [`ModuleMap`]
    pub fn find(&self, address: u64) -> Option<ModuleDetails> {
        let res = unsafe { gum_sys::gum_module_map_find(self.module_map, address) };

        if res.is_null() {
            None
        } else {
            Some(ModuleDetails::from_raw(res))
        }
    }
    /// Update the [`ModuleMap`]. This function must be called before using find.
    pub fn update(&mut self) {
        unsafe { gum_sys::gum_module_map_update(self.module_map) }
    }
}

impl Drop for ModuleMap {
    fn drop(&mut self) {
        unsafe { gum_sys::g_object_unref(self.module_map as *mut c_void) }
    }
}
