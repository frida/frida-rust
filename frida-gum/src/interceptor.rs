/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

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

pub struct InvocationContext {
    context: *mut gum_sys::GumInvocationContext,
}

impl InvocationContext {
    pub(crate) fn from_ptr(context: *mut gum_sys::GumInvocationContext) -> Self {
        Self {
            context,
        }
    }

    /// Get the return address for the current [`InvocationContext`]
    pub fn return_address(&self) -> usize {
        unsafe { gum_sys::gum_invocation_context_get_return_address(self.context) as usize }
    }

    /// Get the 'replacement_data' passed at replace time.
    pub fn replacement_data(&mut self) -> *mut c_void {
        unsafe { gum_sys::gum_invocation_context_get_replacement_data(self.context) }
    }
}

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

    /// Replace a function with another function. The new function should have the same signature
    /// as the old one.
    ///
    /// # Safety
    ///
    /// Assumes that the provided function and replacement addresses are valid and point to the
    /// start of valid functions
    pub fn replace(&mut self, function: NativePointer, replacement: NativePointer, replacement_data: NativePointer) -> Result<(), String> {
        unsafe {
            println!("replacing {:?} with {:?}", function.0, replacement.0);
            match gum_sys::gum_interceptor_replace(
                self.interceptor,
                function.0,
                replacement.0,
                replacement_data.0) {
                gum_sys::GumReplaceReturn_GUM_REPLACE_OK => Ok(()),
                gum_sys::GumReplaceReturn_GUM_REPLACE_WRONG_SIGNATURE => Err("Wrong signature".to_string()),
                gum_sys::GumReplaceReturn_GUM_REPLACE_ALREADY_REPLACED => Err("Target function has already been replaced".to_string()),
                gum_sys::GumReplaceReturn_GUM_REPLACE_POLICY_VIOLATION => Err("Policy violation".to_string()),
                _ => Err("Unknown gum_interceptor_replace error".to_string()),
            }
        }
    }

    /// Reverts a function replacement for the given function, such that the implementation is the
    /// original function.
    ///
    /// # Safety
    ///
    /// Assumes that function is the start of a real function previously replaced uisng
    /// [`Interceptor::replace`].
    pub fn revert(&mut self, function: NativePointer) {
        unsafe {
            gum_sys::gum_interceptor_revert(self.interceptor, function.0);
        }
    }

    /// Retrieve the current [`InvocationContext`].
    ///
    /// # Safety
    ///
    /// Should only be called from within a hook or replacement function.
    pub fn current_invocation() -> InvocationContext {
        InvocationContext::from_ptr(unsafe { gum_sys::gum_interceptor_get_current_invocation() })
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
