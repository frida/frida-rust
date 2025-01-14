/*
 * Copyright © 2020-2021 Keegan Saunders
 * Copyright © 2021 S Rubenstein
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#![cfg_attr(
    any(target_arch = "x86_64", target_arch = "x86"),
    allow(clippy::unnecessary_cast)
)]

use {
    crate::{Gum, Module},
    core::{ffi::c_void, slice::from_raw_parts},
    frida_gum_sys as gum_sys,
};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

#[cfg(feature = "module-names")]
use std::path::Path;

#[cfg(feature = "module-names")]
struct SaveModuleDetailsByNameContext {
    name: String,
    details: Module,
}

#[cfg(feature = "module-names")]
unsafe extern "C" fn save_module_details_by_name(
    details: *mut gum_sys::GumModule,
    context: *mut c_void,
) -> i32 {
    let context = &mut *(context as *mut SaveModuleDetailsByNameContext);
    let module = Module::from_raw(gum_sys::g_object_ref(details.cast()).cast());
    let path_string = CStr::from_ptr(module.path() as *const _)
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
        context.details = module;
        return 0;
    }

    1
}

pub struct ModuleMap<'a> {
    _gum: &'a Gum,
    pub(crate) module_map: *mut gum_sys::GumModuleMap,
}

impl<'a> ModuleMap<'a> {
    pub(crate) fn from_raw(gum: &'a Gum, module_map: *mut gum_sys::GumModuleMap) -> Self {
        Self {
            _gum: gum,
            module_map,
        }
    }

    /// Create a new [`ModuleMap`]
    pub fn new(_gum: &'a Gum) -> Self {
        Self::from_raw(_gum, unsafe { gum_sys::gum_module_map_new() })
    }

    /// Create a new [`ModuleMap`] with a filter function
    pub fn new_with_filter(_gum: &'a Gum, filter: &mut dyn FnMut(Module) -> bool) -> Self {
        unsafe extern "C" fn module_map_filter(
            details: *mut gum_sys::GumModule,
            callback: *mut c_void,
        ) -> i32 {
            let callback = &mut *(callback as *mut Box<&mut dyn FnMut(Module) -> bool>);
            i32::from((callback)(Module::from_raw(details)))
        }
        Self::from_raw(_gum, unsafe {
            gum_sys::gum_module_map_new_filtered(
                Some(module_map_filter),
                &mut Box::new(filter) as *mut _ as *mut c_void,
                None,
            )
        })
    }

    /// Create a new [`ModuleMap`] from a list of names
    #[cfg(feature = "module-names")]
    pub fn new_from_names(gum: &Gum, names: &[&str]) -> Self {
        Self::new_with_filter(gum, &mut |details: Module| {
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
    pub fn find(&self, address: u64) -> Option<Module> {
        let res = unsafe { gum_sys::gum_module_map_find(self.module_map, address) };

        if res.is_null() {
            None
        } else {
            Some(Module::from_raw(res))
        }
    }

    /// Get an array of the [`ModuleDetails`] which make up this [`ModuleMap`]
    pub fn values(&self) -> Vec<Module> {
        unsafe {
            let array = gum_sys::gum_module_map_get_values(self.module_map);
            let raw_module_details = from_raw_parts(
                (*array).pdata as *const *mut gum_sys::GumModule,
                (*array).len as usize,
            );

            raw_module_details
                .iter()
                .map(|raw| Module::from_raw(raw.clone()))
                .collect::<Vec<_>>()
        }
    }

    /// Update the [`ModuleMap`]. This function must be called before using find.
    pub fn update(&mut self) {
        unsafe { gum_sys::gum_module_map_update(self.module_map) }
    }
}

impl<'a> Drop for ModuleMap<'a> {
    fn drop(&mut self) {
        unsafe { gum_sys::g_object_unref(self.module_map as *mut c_void) }
    }
}
