/*
 * Copyright © 2020-2021 Keegan Saunders
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Exception handling and signal interception.
//!
//! The Exceptor allows you to intercept and handle exceptions/signals
//! before they reach the application's normal exception handlers.

use {
    crate::Gum,
    core::ffi::{CStr, c_char, c_void},
    frida_gum_sys as gum_sys,
};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String};

#[cfg(feature = "std")]
use std::{boxed::Box, string::String};

/// Operating mode for the global exceptor.
#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ExceptorMode {
    /// Full handling: signals are caught and dispatched to registered handlers,
    /// and Gum's `try_catch` mechanism is also functional.
    Full = gum_sys::GumExceptorMode_GUM_EXCEPTOR_MODE_FULL as _,
    /// Only registered handlers receive signals; `try_catch` is disabled.
    HandlerOnly = gum_sys::GumExceptorMode_GUM_EXCEPTOR_MODE_HANDLER_ONLY as _,
    /// The exceptor is fully disabled.
    Off = gum_sys::GumExceptorMode_GUM_EXCEPTOR_MODE_OFF as _,
}

/// Types of exceptions that can be caught.
#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ExceptionType {
    /// Abort/terminate signal
    Abort = gum_sys::_GumExceptionType_GUM_EXCEPTION_ABORT as _,
    /// Access violation / segmentation fault
    AccessViolation = gum_sys::_GumExceptionType_GUM_EXCEPTION_ACCESS_VIOLATION as _,
    /// Guard page violation
    GuardPage = gum_sys::_GumExceptionType_GUM_EXCEPTION_GUARD_PAGE as _,
    /// Illegal instruction
    IllegalInstruction = gum_sys::_GumExceptionType_GUM_EXCEPTION_ILLEGAL_INSTRUCTION as _,
    /// Stack overflow
    StackOverflow = gum_sys::_GumExceptionType_GUM_EXCEPTION_STACK_OVERFLOW as _,
    /// Arithmetic exception
    Arithmetic = gum_sys::_GumExceptionType_GUM_EXCEPTION_ARITHMETIC as _,
    /// Breakpoint
    Breakpoint = gum_sys::_GumExceptionType_GUM_EXCEPTION_BREAKPOINT as _,
    /// Single step
    SingleStep = gum_sys::_GumExceptionType_GUM_EXCEPTION_SINGLE_STEP as _,
    /// System exception
    System = gum_sys::_GumExceptionType_GUM_EXCEPTION_SYSTEM as _,
}

/// Exception handler interface.
///
/// Handlers registered with [`Exceptor::add`] are **not** removed automatically
/// when the `Exceptor` is dropped: the underlying exceptor is a process-wide
/// singleton, so dropping this handle does not tear down the C-side registration.
/// Each handler must be explicitly removed with [`Exceptor::remove`] before the
/// data captured by its closure goes out of scope; otherwise the closure leaks
/// and a subsequent exception could invoke a callback over freed state.
pub struct Exceptor {
    exceptor: *mut gum_sys::GumExceptor,
    _gum: Gum,
}

impl Exceptor {
    /// Obtain the global Exceptor instance.
    pub fn obtain(gum: &Gum) -> Exceptor {
        Exceptor {
            exceptor: unsafe { gum_sys::gum_exceptor_obtain() },
            _gum: gum.clone(),
        }
    }

    /// Add an exception handler.
    ///
    /// The handler will be called when an exception occurs. Return `true` from
    /// the handler to indicate that the exception was handled and execution
    /// should continue, or `false` to pass it to the next handler.
    ///
    /// # Arguments
    ///
    /// * `callback` - Function to call when an exception occurs
    ///
    /// # Returns
    ///
    /// A handle that can be used to remove the exception handler.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use frida_gum::{Gum, Exceptor};
    ///
    /// let gum = unsafe { Gum::obtain() };
    /// let mut exceptor = Exceptor::obtain(&gum);
    ///
    /// let handle = exceptor.add(|details| {
    ///     // Handle exception
    ///     println!("Exception caught!");
    ///     false // Don't handle, pass to next handler
    /// });
    ///
    /// // Later, remove the handler
    /// exceptor.remove(handle);
    /// ```
    pub fn add<F>(&mut self, callback: F) -> ExceptionHandlerHandle
    where
        F: FnMut(*mut gum_sys::GumExceptionDetails) -> bool + Send + 'static,
    {
        unsafe extern "C" fn trampoline<F>(
            details: *mut gum_sys::GumExceptionDetails,
            user_data: gum_sys::gpointer,
        ) -> gum_sys::gboolean
        where
            F: FnMut(*mut gum_sys::GumExceptionDetails) -> bool,
        {
            unsafe {
                let callback = &mut *(user_data as *mut F);
                if callback(details) { 1 } else { 0 }
            }
        }

        let callback = Box::new(callback);
        let user_data = Box::into_raw(callback) as *mut _;

        unsafe extern "C" fn cleanup<F>(user_data: *mut c_void)
        where
            F: FnMut(*mut gum_sys::GumExceptionDetails) -> bool,
        {
            unsafe {
                // Reconstruct and drop the Box with the correct type
                let _ = Box::from_raw(user_data as *mut F);
            }
        }

        unsafe {
            gum_sys::gum_exceptor_add(self.exceptor, Some(trampoline::<F>), user_data);
        }

        ExceptionHandlerHandle {
            func: Some(trampoline::<F>),
            user_data,
            cleanup: cleanup::<F>,
        }
    }

    /// Remove a previously added exception handler.
    ///
    /// # Arguments
    ///
    /// * `handle` - The handle returned by [`Exceptor::add()`]
    pub fn remove(&mut self, handle: ExceptionHandlerHandle) {
        unsafe {
            gum_sys::gum_exceptor_remove(self.exceptor, handle.func, handle.user_data);
            // Clean up the callback using the stored cleanup function
            (handle.cleanup)(handle.user_data);
        }
    }

    /// Reset the exceptor's internal state.
    ///
    /// Restores Gum's signal-handling primitives. Useful after the host has
    /// installed its own signal handlers and you want Frida to take control
    /// back.
    pub fn reset(&mut self) {
        unsafe { gum_sys::gum_exceptor_reset(self.exceptor) };
    }

    /// Check whether the specified thread currently has an active
    /// `try_catch` scope (corresponding to `gum_exceptor_try` in the C API).
    pub fn has_scope(&self, thread_id: usize) -> bool {
        unsafe {
            gum_sys::gum_exceptor_has_scope(self.exceptor, thread_id as gum_sys::GumThreadId) != 0
        }
    }

    /// Set the global exceptor mode.
    ///
    /// This affects every Exceptor in the process; pass [`ExceptorMode::Off`]
    /// to fully disable Frida's signal handling.
    pub fn set_mode(mode: ExceptorMode) {
        unsafe { gum_sys::gum_exceptor_set_mode(mode as gum_sys::GumExceptorMode) };
    }

    /// Format the given exception details into a human-readable string.
    ///
    /// `details` is the pointer handed to an exception handler registered with
    /// [`Exceptor::add`].
    ///
    /// # Safety
    ///
    /// `details` must be a valid `GumExceptionDetails` pointer (e.g. the one
    /// received by an exception handler).
    pub unsafe fn exception_details_to_string(
        details: *const gum_sys::GumExceptionDetails,
    ) -> String {
        unsafe {
            let raw = gum_sys::gum_exception_details_to_string(details);
            if raw.is_null() {
                return String::new();
            }
            let owned = CStr::from_ptr(raw as *const c_char)
                .to_string_lossy()
                .into_owned();
            // gum_exception_details_to_string returns a newly-allocated string
            // (transfer-full) that the caller must release.
            crate::glib_compat::g_free(raw as *mut c_void);
            owned
        }
    }
}

impl Drop for Exceptor {
    fn drop(&mut self) {
        unsafe { frida_gum_sys::g_object_unref(self.exceptor as *mut c_void) };
    }
}

/// Handle for a registered exception handler.
///
/// This handle can be used to remove the exception handler via [`Exceptor::remove()`].
pub struct ExceptionHandlerHandle {
    func: gum_sys::GumExceptionHandler,
    user_data: *mut c_void,
    cleanup: unsafe extern "C" fn(*mut c_void),
}

unsafe impl Send for Exceptor {}
unsafe impl Sync for Exceptor {}
