/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Function hooking engine.
//!

use {
    crate::{Error, Gum, NativePointer, Result},
    core::ptr,
    frida_gum_sys as gum_sys,
};

#[cfg(feature = "invocation-listener")]
use core::ffi::c_void;
#[cfg(feature = "invocation-listener")]
mod invocation_listener;
#[cfg(feature = "invocation-listener")]
#[cfg_attr(docsrs, doc(cfg(feature = "invocation-listener")))]
pub use invocation_listener::*;

/// Function hooking engine interface.
pub struct Interceptor {
    interceptor: *mut gum_sys::GumInterceptor,
    _gum: Gum,
}

impl Clone for Interceptor {
    fn clone(&self) -> Self {
        Interceptor {
            interceptor: unsafe {
                frida_gum_sys::g_object_ref(self.interceptor as *mut _) as *mut _
            },
            _gum: self._gum.clone(),
        }
    }
}

impl Drop for Interceptor {
    fn drop(&mut self) {
        unsafe { frida_gum_sys::g_object_unref(self.interceptor as *mut _) }
    }
}

impl Interceptor {
    /// Obtain an Interceptor handle, ensuring that the runtime is properly initialized. This may
    /// be called as many times as needed, and results in a no-op if the Interceptor is
    /// already initialized.
    pub fn obtain(gum: &Gum) -> Interceptor {
        Interceptor {
            interceptor: unsafe { gum_sys::gum_interceptor_obtain() },
            _gum: gum.clone(),
        }
    }

    /// Attach a listener to the beginning of a function address.
    ///
    /// # Safety
    ///
    /// The provided address *must* point to the start of a function in a valid
    /// memory region.
    #[cfg(feature = "invocation-listener")]
    #[cfg_attr(docsrs, doc(cfg(feature = "invocation-listener")))]
    pub fn attach<I: InvocationListener>(
        &mut self,
        f: NativePointer,
        listener: &mut I,
    ) -> Result<Listener> {
        let listener = invocation_listener_transform(listener);
        match unsafe {
            gum_sys::gum_interceptor_attach(self.interceptor, f.0, listener, ptr::null_mut())
        } {
            gum_sys::GumAttachReturn_GUM_ATTACH_OK => {
                Ok(Listener(NativePointer(listener as *mut c_void)))
            }
            gum_sys::GumAttachReturn_GUM_ATTACH_WRONG_SIGNATURE => {
                Err(Error::InterceptorBadSignature)
            }
            gum_sys::GumAttachReturn_GUM_ATTACH_ALREADY_ATTACHED => {
                Err(Error::InterceptorAlreadyAttached)
            }
            gum_sys::GumAttachReturn_GUM_ATTACH_POLICY_VIOLATION => Err(Error::PolicyViolation),
            gum_sys::GumAttachReturn_GUM_ATTACH_WRONG_TYPE => Err(Error::WrongType),
            _ => Err(Error::InterceptorError),
        }
    }

    /// Attach a listener to an instruction address.
    ///
    /// # Safety
    ///
    /// The provided address *must* point to a valid instruction.
    #[cfg(feature = "invocation-listener")]
    #[cfg_attr(docsrs, doc(cfg(feature = "invocation-listener")))]
    pub fn attach_instruction<I: ProbeListener>(
        &mut self,
        instr: NativePointer,
        listener: &mut I,
    ) -> Result<Listener> {
        let listener = probe_listener_transform(listener);
        match unsafe {
            gum_sys::gum_interceptor_attach(self.interceptor, instr.0, listener, ptr::null_mut())
        } {
            gum_sys::GumAttachReturn_GUM_ATTACH_OK => {
                Ok(Listener(NativePointer(listener as *mut c_void)))
            }
            gum_sys::GumAttachReturn_GUM_ATTACH_WRONG_SIGNATURE => {
                Err(Error::InterceptorBadSignature)
            }
            gum_sys::GumAttachReturn_GUM_ATTACH_ALREADY_ATTACHED => {
                Err(Error::InterceptorAlreadyAttached)
            }
            gum_sys::GumAttachReturn_GUM_ATTACH_POLICY_VIOLATION => Err(Error::PolicyViolation),
            gum_sys::GumAttachReturn_GUM_ATTACH_WRONG_TYPE => Err(Error::WrongType),
            _ => Err(Error::InterceptorError),
        }
    }

    /// Detach an attached listener.
    ///
    /// # Safety
    ///
    /// The listener *must* have been attached with [`Interceptor::attach()`].
    #[cfg(feature = "invocation-listener")]
    #[cfg_attr(docsrs, doc(cfg(feature = "invocation-listener")))]
    pub fn detach(&mut self, listener: Listener) {
        let Listener(NativePointer(ptr)) = listener;
        unsafe {
            gum_sys::gum_interceptor_detach(
                self.interceptor,
                ptr as *mut gum_sys::GumInvocationListener,
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
    pub fn replace(
        &mut self,
        function: NativePointer,
        replacement: NativePointer,
        replacement_data: NativePointer,
    ) -> Result<NativePointer> {
        let mut original_function = NativePointer(ptr::null_mut());
        unsafe {
            let options = gum_sys::GumReplaceOptions {
                instrumentation: gum_sys::GumInterceptorOptions {
                    scratch_register: -1,
                    scenario: gum_sys::GumInterceptorScenario_GUM_INTERCEPTOR_SCENARIO_DEFAULT,
                    relocation_policy: gum_sys::GumRelocationPolicy_GUM_RELOCATION_DEFAULT,
                    write_redirect: None,
                    write_redirect_data: ptr::null_mut(),
                    redirect_space_hint: 0,
                },
                replacement_data: replacement_data.0,
            };
            match gum_sys::gum_interceptor_replace(
                self.interceptor,
                function.0,
                replacement.0,
                &mut original_function.0,
                &options,
            ) {
                gum_sys::GumReplaceReturn_GUM_REPLACE_OK => Ok(original_function),
                gum_sys::GumReplaceReturn_GUM_REPLACE_WRONG_SIGNATURE => {
                    Err(Error::InterceptorBadSignature)
                }
                gum_sys::GumReplaceReturn_GUM_REPLACE_ALREADY_REPLACED => {
                    Err(Error::InterceptorAlreadyReplaced)
                }
                gum_sys::GumReplaceReturn_GUM_REPLACE_POLICY_VIOLATION => {
                    Err(Error::PolicyViolation)
                }
                gum_sys::GumReplaceReturn_GUM_REPLACE_WRONG_TYPE => Err(Error::WrongType),
                _ => Err(Error::InterceptorError),
            }
        }
    }

    /// Replace a function with another function. The new function should have the same signature
    /// as the old one. This implementation avoids the overhead of the re-entrancy checking and
    /// context push/pop of conventional interceptors returning the address of a simple trampoline
    /// and patching the original function with the provided replacement. This type is not
    /// interoperable with `attach` and requires the caller to pass any required data to the hook
    /// function themselves.
    ///
    /// # Safety
    ///
    /// Assumes that the provided function and replacement addresses are valid and point to the
    /// start of valid functions
    pub fn replace_fast(
        &mut self,
        function: NativePointer,
        replacement: NativePointer,
    ) -> Result<NativePointer> {
        let mut original_function = NativePointer(ptr::null_mut());
        unsafe {
            let options = gum_sys::GumInterceptorOptions {
                scratch_register: -1,
                scenario: gum_sys::GumInterceptorScenario_GUM_INTERCEPTOR_SCENARIO_DEFAULT,
                relocation_policy: gum_sys::GumRelocationPolicy_GUM_RELOCATION_DEFAULT,
                write_redirect: None,
                write_redirect_data: ptr::null_mut(),
                redirect_space_hint: 0,
            };
            match gum_sys::gum_interceptor_replace_fast(
                self.interceptor,
                function.0,
                replacement.0,
                &mut original_function.0,
                &options,
            ) {
                gum_sys::GumReplaceReturn_GUM_REPLACE_OK => Ok(original_function),
                gum_sys::GumReplaceReturn_GUM_REPLACE_WRONG_SIGNATURE => {
                    Err(Error::InterceptorBadSignature)
                }
                gum_sys::GumReplaceReturn_GUM_REPLACE_ALREADY_REPLACED => {
                    Err(Error::InterceptorAlreadyReplaced)
                }
                gum_sys::GumReplaceReturn_GUM_REPLACE_POLICY_VIOLATION => {
                    Err(Error::PolicyViolation)
                }
                gum_sys::GumReplaceReturn_GUM_REPLACE_WRONG_TYPE => Err(Error::WrongType),
                _ => Err(Error::InterceptorError),
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
    #[cfg(feature = "invocation-listener")]
    #[cfg_attr(docsrs, doc(cfg(feature = "invocation-listener")))]
    pub fn current_invocation<'a>() -> InvocationContext<'a> {
        InvocationContext::from_raw(unsafe { gum_sys::gum_interceptor_get_current_invocation() })
    }

    /// Retrieve the current thread's invocation stack.
    ///
    /// The returned pointer is only valid until the current hook returns; it
    /// must not be retained or accessed from another thread.
    ///
    /// # Safety
    ///
    /// Must be called from within a hook or replacement function. The
    /// returned pointer aliases Frida-owned memory whose lifetime is bounded
    /// by the current invocation.
    pub unsafe fn current_stack() -> *mut gum_sys::GumInvocationStack {
        gum_sys::gum_interceptor_get_current_stack()
    }

    /// Translate a return address inside Stalker- or Interceptor-generated
    /// trampoline code back to its address in the original (pre-instrumented)
    /// program.
    ///
    /// Returns the original address, or the input address unchanged if no
    /// translation is available.
    ///
    /// # Safety
    ///
    /// `stack` must come from [`Self::current_stack`] or an equivalent live
    /// invocation stack pointer.
    pub unsafe fn translate(
        stack: *mut gum_sys::GumInvocationStack,
        return_address: NativePointer,
    ) -> NativePointer {
        NativePointer(gum_sys::gum_invocation_stack_translate(
            stack,
            return_address.0,
        ))
    }

    /// Ignore all calls from the current thread.
    ///
    /// This causes the interceptor to bypass any hooks installed on the current thread
    /// until [`Interceptor::unignore_current_thread()`] is called.
    pub fn ignore_current_thread(&mut self) {
        unsafe { gum_sys::gum_interceptor_ignore_current_thread(self.interceptor) };
    }

    /// Resume intercepting calls from the current thread.
    ///
    /// Re-enables hook interception on the current thread after a call to
    /// [`Interceptor::ignore_current_thread()`].
    pub fn unignore_current_thread(&mut self) {
        unsafe { gum_sys::gum_interceptor_unignore_current_thread(self.interceptor) };
    }

    /// Conditionally resume intercepting calls from the current thread.
    ///
    /// Re-enables hook interception only if the current ignore count is 1 (i.e., only one
    /// ignore is active). This is useful when multiple components may be ignoring threads.
    ///
    /// Returns `true` if the thread was unignored, `false` otherwise.
    pub fn maybe_unignore_current_thread(&mut self) -> bool {
        unsafe { gum_sys::gum_interceptor_maybe_unignore_current_thread(self.interceptor) != 0 }
    }

    /// Ignore all calls from threads other than the current thread.
    ///
    /// This causes the interceptor to only process hooks on the current thread until
    /// [`Interceptor::unignore_other_threads()`] is called.
    pub fn ignore_other_threads(&mut self) {
        unsafe { gum_sys::gum_interceptor_ignore_other_threads(self.interceptor) };
    }

    /// Resume intercepting calls from all threads.
    ///
    /// Re-enables hook interception on all threads after a call to
    /// [`Interceptor::ignore_other_threads()`].
    pub fn unignore_other_threads(&mut self) {
        unsafe { gum_sys::gum_interceptor_unignore_other_threads(self.interceptor) };
    }

    /// Check if the interceptor is currently locked.
    ///
    /// Returns `true` if the interceptor's internal lock is held, indicating that
    /// modifications to hooks are currently prohibited.
    pub fn is_locked(&self) -> bool {
        unsafe { gum_sys::gum_interceptor_is_locked(self.interceptor) != 0 }
    }

    /// Execute a function while holding the interceptor's lock.
    ///
    /// This ensures exclusive access to the interceptor's internal state during the
    /// callback execution.
    ///
    /// # Safety
    ///
    /// The callback should not attempt to recursively acquire the lock or perform
    /// operations that could deadlock.
    pub fn with_lock_held<F>(&mut self, f: F)
    where
        F: FnOnce(),
    {
        #[cfg(not(feature = "std"))]
        use alloc::boxed::Box;
        #[cfg(feature = "std")]
        use std::boxed::Box;

        unsafe extern "C" fn trampoline<F>(user_data: gum_sys::gpointer)
        where
            F: FnOnce(),
        {
            let callback = Box::from_raw(user_data as *mut F);
            callback();
        }

        let callback = Box::new(f);
        unsafe {
            gum_sys::gum_interceptor_with_lock_held(
                self.interceptor,
                Some(trampoline::<F>),
                Box::into_raw(callback) as *mut _,
            )
        };
    }

    /// Flush any pending interceptor operations.
    ///
    /// Forces the interceptor to immediately apply any pending hook modifications.
    /// Returns `true` if any modifications were flushed, `false` otherwise.
    pub fn flush(&mut self) -> bool {
        unsafe { gum_sys::gum_interceptor_flush(self.interceptor) != 0 }
    }

    /// Set default options for interceptor operations.
    ///
    /// Configures global default options that will be used for subsequent attach and
    /// replace operations when no explicit options are provided.
    ///
    /// # Arguments
    ///
    /// * `scratch_register` - Register to use for temporary operations (-1 for auto)
    /// * `scenario` - Interceptor scenario (DEFAULT, EXCLUSIVE, etc.)
    /// * `relocation_policy` - Code relocation strategy
    pub fn set_default_options(
        &mut self,
        scratch_register: i32,
        scenario: gum_sys::GumInterceptorScenario,
        relocation_policy: gum_sys::GumRelocationPolicy,
    ) {
        let options = gum_sys::GumInterceptorOptions {
            scratch_register,
            scenario,
            relocation_policy,
            write_redirect: None,
            write_redirect_data: ptr::null_mut(),
            redirect_space_hint: 0,
        };
        unsafe {
            gum_sys::gum_interceptor_set_default_options(self.interceptor, &options);
        }
    }

    /// Detect the minimum size needed to hook a function at the given address.
    ///
    /// Analyzes the code at the specified address to determine how many bytes are
    /// needed to safely install a hook without breaking instruction boundaries.
    ///
    /// Returns the size in bytes, or 0 if the code cannot be safely hooked.
    ///
    /// # Safety
    ///
    /// `address` must point to readable, valid executable code.
    pub unsafe fn detect_hook_size(address: NativePointer) -> usize {
        gum_sys::gum_interceptor_detect_hook_size(address.0, 0, ptr::null_mut()) as usize
    }

    /// Save the current invocation state into `state`.
    ///
    /// Captures the current interceptor invocation state so it can be restored
    /// with [`Interceptor::restore()`]. Useful when temporarily suspending
    /// interception.
    ///
    /// # Safety
    ///
    /// Must be called from within a hook. `state` must remain accessible (and
    /// not move) until [`Interceptor::restore`] is called on the same thread.
    pub unsafe fn save(state: &mut gum_sys::GumInvocationState) {
        gum_sys::gum_interceptor_save(state);
    }

    /// Restore a previously saved invocation state.
    ///
    /// # Safety
    ///
    /// `state` must have been populated by [`Interceptor::save`] on the same
    /// thread, and the corresponding hook must still be on the call stack.
    pub unsafe fn restore(state: &mut gum_sys::GumInvocationState) {
        gum_sys::gum_interceptor_restore(state);
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

/// An instance of a listener attached to an instruction or function.
#[allow(dead_code)]
pub struct Listener(NativePointer);

impl Drop for Listener {
    fn drop(&mut self) {
        let Self(NativePointer(ptr)) = self;
        unsafe { frida_gum_sys::g_object_unref(*ptr) }
    }
}

impl Clone for Listener {
    fn clone(&self) -> Self {
        let Self(NativePointer(ptr)) = self;
        Self(NativePointer(unsafe { frida_gum_sys::g_object_ref(*ptr) }))
    }
}
