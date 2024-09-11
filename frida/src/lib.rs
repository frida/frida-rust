/*
 * Copyright © 2020-2022 Keegan Saunders
 * Copyright © 2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Frida bindings for Rust.

#![deny(warnings)]
#![deny(missing_docs)]
#![allow(clippy::missing_safety_doc)]

use std::{
    ffi::CStr,
    sync::{Arc, Mutex},
};

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
#[derive(Clone)]
pub struct Frida {
    inner: Option<Arc<FridaSingleton>>,
}

impl Drop for Frida {
    fn drop(&mut self) {
        let inner = self.inner.take().expect("frida taken more than once");
        drop(inner);
        let mut singleton = THE_ONE_TRUE_FRIDA.lock().unwrap();
        let Some(v) = singleton.take_if(|v| Arc::strong_count(v) == 1) else {
            return;
        };
        match Arc::try_unwrap(v) {
            Ok(v) => drop(v),
            Err(_v) => panic!("programming error!"),
        }
    }
}

impl Frida {
    /// Obtain a Frida handle, ensuring that the runtime is properly initialized. This may
    /// be called as many times as needed, and results in a no-op if the Frida runtime is
    /// already initialized.
    pub fn obtain() -> Self {
        let mut singleton = THE_ONE_TRUE_FRIDA.lock().unwrap();
        let v = singleton.get_or_insert_with(|| Arc::new(FridaSingleton::new()));
        Self {
            inner: Some(v.clone()),
        }
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

// A marker type that exists only while Gum is initialized.
struct FridaSingleton;

impl FridaSingleton {
    fn new() -> Self {
        unsafe { frida_sys::frida_init() };
        FridaSingleton
    }
}

impl Drop for FridaSingleton {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_deinit() }
    }
}

static THE_ONE_TRUE_FRIDA: Mutex<Option<Arc<FridaSingleton>>> = Mutex::new(None);

type GObject<T> = gobject::GObject<T, Frida>;

mod gobject {

    pub(crate) trait Runtime: Clone {
        fn unref<T>(ptr: *mut T);
    }

    impl Runtime for super::Frida {
        fn unref<T>(ptr: *mut T) {
            unsafe { frida_sys::frida_unref(ptr as *mut _) }
        }
    }

    pub(crate) struct GObject<T, RT: Runtime>(*mut T, RT);

    impl<T, RT: Runtime> GObject<T, RT> {
        pub(crate) fn ptr(&self) -> *mut T {
            let &Self(ptr, _) = self;
            ptr
        }

        pub(crate) fn new(ptr: *mut T, runtime: RT) -> Self {
            Self(ptr, runtime.clone())
        }

        pub(crate) fn runtime(&self) -> &RT {
            let Self(_, rt) = self;
            rt
        }
    }

    impl<T, RT: Runtime> Drop for GObject<T, RT> {
        fn drop(&mut self) {
            RT::unref(self.0)
        }
    }
}
