//! Function hooking engine.
//!
use frida_gum_sys as gum_sys;
use std::marker::PhantomData;
#[cfg(feature = "invocation-listener")]
use std::os::raw::c_void;
#[cfg(feature = "invocation-listener")]
use std::ptr;

use crate::Gum;
#[cfg(feature = "invocation-listener")]
use crate::NativePointer;

#[cfg(feature = "invocation-listener")]
mod invocation_listener;
#[cfg(feature = "invocation-listener")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "invocation-listener")))]
pub use invocation_listener::*;

/// Function hooking engine interface.
pub struct Interceptor<'a> {
    interceptor: *mut gum_sys::GumInterceptor,
    phantom: PhantomData<&'a gum_sys::GumInterceptor>,
}

impl<'a> Interceptor<'a> {
    /// Obtain an Interceptor handle, ensuring that the runtime is properly initialized. This may
    /// be called as many times as needed, and results in a no-op if the Interceptor is
    /// already initialized.
    pub fn obtain<'b>(_gum: &'b Gum) -> Interceptor
    where
        'b: 'a,
    {
        Interceptor {
            interceptor: unsafe { gum_sys::gum_interceptor_obtain() },
            phantom: PhantomData,
        }
    }

    /// Attach a listener to the beginning of a function address.
    ///
    /// # Safety
    ///
    /// The provided address *must* point to the start of a function in a valid
    /// memory region.
    #[cfg(feature = "invocation-listener")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "invocation-listener")))]
    pub fn attach<I: InvocationListener>(
        &mut self,
        f: NativePointer,
        listener: &mut I,
    ) -> NativePointer {
        let listener = invocation_listener_transform(listener);
        unsafe {
            gum_sys::gum_interceptor_attach(self.interceptor, f.0, listener, ptr::null_mut())
        };
        NativePointer(listener as *mut c_void)
    }

    /// Detach an attached listener.
    ///
    /// # Safety
    ///
    /// The listener *must* have been attached with [`Interceptor::attach()`].
    #[cfg(feature = "invocation-listener")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "invocation-listener")))]
    pub fn detach(&mut self, listener: NativePointer) {
        unsafe {
            gum_sys::gum_interceptor_detach(
                self.interceptor,
                listener.0 as *mut gum_sys::GumInvocationListener,
            )
        };
    }

    /// Begin an [`Interceptor`] transaction. This may improve performance if
    /// applying many hooks.
    ///
    /// # Safety
    ///
    /// After placing hooks, the transaction must be ended with [`Interceptor::end_transaction()`].
    pub fn begin_transaction(&mut self) {
        unsafe { gum_sys::gum_interceptor_begin_transaction(self.interceptor) };
    }

    /// End an [`Interceptor`] transaction. This must be called after placing hooks
    /// if in a transaction started with [`Interceptor::begin_transaction()`].
    pub fn end_transaction(&mut self) {
        unsafe { gum_sys::gum_interceptor_end_transaction(self.interceptor) };
    }
}
