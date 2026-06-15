/*
 * Copyright © 2020-2021 Keegan Saunders
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Locked snapshots of process-wide module and thread registries.
//!
//! [`ModuleRegistry`] and [`ThreadRegistry`] expose Frida's internal lookup
//! tables. Unlike [`crate::Process::enumerate_modules`] /
//! [`crate::Process::enumerate_threads`], a registry can be **locked** so
//! that successive operations observe a consistent snapshot.

use {
    crate::{Module, Thread},
    core::ffi::c_void,
    frida_gum_sys as gum_sys,
};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Process-wide module registry.
///
/// Calls to [`Self::lock`] / [`Self::unlock`] guarantee the snapshot
/// observed by [`Self::enumerate_modules`] is stable across invocations.
pub struct ModuleRegistry {
    inner: *mut gum_sys::GumModuleRegistry,
}

impl ModuleRegistry {
    /// Get the singleton registry instance.
    pub fn obtain() -> Self {
        ModuleRegistry {
            inner: unsafe { gum_sys::gum_module_registry_obtain() },
        }
    }

    /// Acquire the registry's read/write lock.
    ///
    /// While the lock is held, the module list cannot be modified by Frida
    /// or by other callers of [`Self::lock`].
    pub fn lock(&self) {
        unsafe { gum_sys::gum_module_registry_lock(self.inner) };
    }

    /// Release a lock previously acquired with [`Self::lock`].
    ///
    /// # Safety
    ///
    /// Must be paired one-for-one with [`Self::lock`].
    pub unsafe fn unlock(&self) {
        unsafe {
            gum_sys::gum_module_registry_unlock(self.inner);
        }
    }

    /// Run `f` while holding the registry lock.
    pub fn with_lock_held<R>(&self, f: impl FnOnce(&Self) -> R) -> R {
        self.lock();
        let result = f(self);
        unsafe { self.unlock() };
        result
    }

    /// Enumerate all modules known to the registry.
    pub fn enumerate_modules(&self) -> Vec<Module> {
        let mut result: Vec<Module> = Vec::new();

        unsafe extern "C" fn callback(
            module: *mut gum_sys::GumModule,
            user_data: gum_sys::gpointer,
        ) -> gum_sys::gboolean {
            unsafe {
                let res = &mut *(user_data as *mut Vec<Module>);
                res.push(Module::from_raw(module));
                1
            }
        }

        unsafe {
            gum_sys::gum_module_registry_enumerate_modules(
                self.inner,
                Some(callback),
                &mut result as *mut _ as *mut c_void,
            );
        }

        result
    }
}

unsafe impl Send for ModuleRegistry {}
unsafe impl Sync for ModuleRegistry {}

/// Process-wide thread registry.
pub struct ThreadRegistry {
    inner: *mut gum_sys::GumThreadRegistry,
}

impl ThreadRegistry {
    /// Get the singleton registry instance.
    pub fn obtain() -> Self {
        ThreadRegistry {
            inner: unsafe { gum_sys::gum_thread_registry_obtain() },
        }
    }

    /// Acquire the registry's lock.
    pub fn lock(&self) {
        unsafe { gum_sys::gum_thread_registry_lock(self.inner) };
    }

    /// Release the registry's lock.
    ///
    /// # Safety
    ///
    /// Must be paired one-for-one with [`Self::lock`].
    pub unsafe fn unlock(&self) {
        unsafe {
            gum_sys::gum_thread_registry_unlock(self.inner);
        }
    }

    /// Run `f` while holding the registry lock.
    pub fn with_lock_held<R>(&self, f: impl FnOnce(&Self) -> R) -> R {
        self.lock();
        let result = f(self);
        unsafe { self.unlock() };
        result
    }

    /// Enumerate all threads known to the registry.
    pub fn enumerate_threads(&self) -> Vec<Thread> {
        let mut result: Vec<Thread> = Vec::new();

        unsafe extern "C" fn callback(
            details: *const gum_sys::GumThreadDetails,
            user_data: gum_sys::gpointer,
        ) -> gum_sys::gboolean {
            unsafe {
                let res = &mut *(user_data as *mut Vec<Thread>);
                res.push(Thread::from_raw(details));
                1
            }
        }

        unsafe {
            gum_sys::gum_thread_registry_enumerate_threads(
                self.inner,
                Some(callback),
                &mut result as *mut _ as *mut c_void,
            );
        }

        result
    }
}

unsafe impl Send for ThreadRegistry {}
unsafe impl Sync for ThreadRegistry {}
