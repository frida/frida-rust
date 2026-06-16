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
    crate::Module,
    core::{ffi::c_void, slice::from_raw_parts},
    frida_gum_sys as gum_sys,
};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

#[cfg(feature = "module-names")]
use std::path::Path;

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

    /// Create a new [`ModuleMap`] with a filter function.
    ///
    /// The filter is retained by the underlying `GumModuleMap` and re-invoked
    /// on every [`ModuleMap::update`]. The closure is boxed and owned by the
    /// map; `destroy` is called by Frida when the map is finalized, ensuring
    /// the closure is dropped at the right time. No `'static` bound is required
    /// because the box is freed before the map's drop — the lifetime is
    /// managed explicitly via the `destroy` callback.
    pub fn new_with_filter<F>(filter: F) -> Self
    where
        F: FnMut(Module) -> bool,
    {
        unsafe extern "C" fn module_map_filter<F>(
            details: *mut gum_sys::GumModule,
            callback: *mut c_void,
        ) -> i32
        where
            F: FnMut(Module) -> bool,
        {
            unsafe {
                let callback = &mut *(callback as *mut F);
                i32::from(callback(Module::from_raw(details)))
            }
        }

        // Frees the boxed closure when the GumModuleMap is finalized.
        unsafe extern "C" fn destroy<F>(data: *mut c_void) {
            unsafe {
                drop(Box::from_raw(data as *mut F));
            }
        }

        let filter = Box::into_raw(Box::new(filter));
        Self::from_raw(unsafe {
            gum_sys::gum_module_map_new_filtered(
                Some(module_map_filter::<F>),
                filter as *mut c_void,
                Some(destroy::<F>),
            )
        })
    }

    /// Create a new [`ModuleMap`] from a list of names
    #[cfg(feature = "module-names")]
    pub fn new_from_names(names: &[&str]) -> Self {
        // The filter outlives this call (Frida retains it), so capture owned
        // copies of the names rather than borrowing the caller's slice.
        let names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
        Self::new_with_filter(move |details: Module| {
            names.iter().any(|name| {
                (name.starts_with('/') && details.path().eq(name))
                    || (name.contains('/')
                        && Path::new(name)
                            .file_name()
                            .and_then(|f| f.to_str())
                            .is_some_and(|f| details.name().eq(f)))
                    || details.name().eq(name)
            })
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

    /// Get an array of the [`Module`] which make up this [`ModuleMap`]
    pub fn values(&self) -> Vec<Module> {
        unsafe {
            let array = gum_sys::gum_module_map_get_values(self.module_map);
            let raw_module_details = from_raw_parts(
                (*array).pdata as *const *mut gum_sys::GumModule,
                (*array).len as usize,
            );

            raw_module_details
                .iter()
                .map(|raw| Module::from_raw(*raw))
                .collect::<Vec<_>>()
        }
    }

    /// Update the [`ModuleMap`]. This function must be called before using find.
    pub fn update(&mut self) {
        unsafe { gum_sys::gum_module_map_update(self.module_map) }
    }
}

impl Default for ModuleMap {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ModuleMap {
    fn drop(&mut self) {
        unsafe { gum_sys::g_object_unref(self.module_map as *mut c_void) }
    }
}
