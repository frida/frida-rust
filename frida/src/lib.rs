/*
 * Copyright © 2020-2022 Keegan Saunders
 * Copyright © 2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Frida bindings for Rust.

#![cfg_attr(doc_cfg, feature(doc_cfg))]
#![deny(warnings)]
#![deny(missing_docs)]
#![allow(clippy::missing_safety_doc)]

use std::ffi::CStr;

mod device;
pub use device::*;

mod device_manager;
pub use device_manager::*;

mod error;
pub use error::Error;

mod injector;
pub use injector::*;

mod process;
pub use process::*;

mod script;
pub use script::*;

mod session;
pub use session::*;

mod variant;
pub use variant::*;

#[doc(hidden)]
pub type Result<T> = std::result::Result<T, error::Error>;

/// Context required for instantiation of all structures under the Frida namespace.
pub struct Frida;

impl Frida {
    /// Obtain a Frida handle, ensuring that the runtime is properly initialized. This may
    /// be called as many times as needed, and results in a no-op if the Frida runtime is
    /// already initialized.
    pub unsafe fn obtain() -> Frida {
        frida_sys::frida_init();
        Frida {}
    }

    /// Gets the current version of frida core
    pub fn version() -> &'static str {
        let version = unsafe { CStr::from_ptr(frida_sys::frida_version_string() as _) };
        version.to_str().unwrap_or_default()
    }

    /// Schedules the closure to be executed on the main frida context.
    pub fn schedule_on_main<F>(&self, func: F)
    where
        F: FnOnce() + Send + 'static,
    {
        unsafe {
            unsafe extern "C" fn trampoline<F: FnOnce() + Send + 'static>(
                func: frida_sys::gpointer,
            ) -> frida_sys::gboolean {
                let func: &mut Option<F> = &mut *(func as *mut Option<F>);
                let func = func
                    .take()
                    .expect("schedule_on_main closure called multiple times");
                func();
                frida_sys::G_SOURCE_REMOVE as frida_sys::gboolean
            }
            unsafe extern "C" fn destroy_closure<F: FnOnce() + Send + 'static>(
                ptr: frida_sys::gpointer,
            ) {
                let _ = Box::<Option<F>>::from_raw(ptr as *mut _);
            }

            let func = Box::into_raw(Box::new(Some(func)));
            let source = frida_sys::g_idle_source_new();
            let ctx = frida_sys::frida_get_main_context();

            frida_sys::g_source_set_callback(
                source,
                Some(trampoline::<F>),
                func as frida_sys::gpointer,
                Some(destroy_closure::<F>),
            );
            frida_sys::g_source_attach(source, ctx);
            frida_sys::g_source_unref(source);
        }
    }
}

impl Drop for Frida {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_deinit() };
    }
}
