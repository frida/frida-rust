/*
 * Copyright © 2021-2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use std::{
    ffi::{c_void, CStr, CString},
    ptr::null_mut,
};

use frida_sys::{FridaScriptOptions, _FridaScript};

use crate::error::FridaCoreError;

unsafe extern "C" fn call_on_message<I: ScriptHandler>(
    _script_ptr: *mut _FridaScript,
    message: *const i8,
    _data: &frida_sys::_GBytes,
    user_data: *mut c_void,
) {
    let handler: &mut I = &mut *(user_data as *mut I);

    handler.on_message(CStr::from_ptr(message).to_str().unwrap_or_default());
}

/// A trait to handle script signals.
pub trait ScriptHandler {
    fn on_message(&mut self, message: &str);
}

pub struct Script {
    script_ptr: *mut _FridaScript,
}

impl Script {
    /// Creates new instance of script.
    pub fn new(script_ptr: *mut _FridaScript) -> Self {
        Script { script_ptr }
    }

    /// Loads the script into the process.
    pub fn load(&self) -> Result<(), FridaCoreError> {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        unsafe { frida_sys::frida_script_load_sync(self.script_ptr, null_mut(), &mut error) };

        if error.is_null() {
            Ok(())
        } else {
            Err(FridaCoreError::LoadingFailed)
        }
    }

    /// Unloads the script into the process.
    pub fn unload(&self) -> Result<(), FridaCoreError> {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        unsafe { frida_sys::frida_script_unload_sync(self.script_ptr, null_mut(), &mut error) };

        if error.is_null() {
            Ok(())
        } else {
            Err(FridaCoreError::UnloadingFailed)
        }
    }

    /// Handles the `message` signal for the script and wrap into [`ScriptHandler`].
    ///
    /// # Example
    /// ```
    /// struct Handler;
    ///
    /// impl ScriptHandler for Handler {
    ///     fn on_message(&mut self, message: &str) {
    ///         println!("{message}");
    ///     }
    /// }
    /// ```
    pub fn handle_message<I: ScriptHandler>(&self, handler: &mut I) -> Result<(), FridaCoreError> {
        let message = CString::new("message").map_err(|_| FridaCoreError::CStringFailed)?;
        unsafe {
            let callback = Some(std::mem::transmute(call_on_message::<I> as *mut c_void));

            frida_sys::g_signal_connect_data(
                self.script_ptr as _,
                message.as_ptr(),
                callback,
                handler as *mut _ as *mut c_void,
                None,
                0,
            )
        };

        Ok(())
    }
}

impl Drop for Script {
    /// Destroys the ptr to the script when Script doesn't exist anymore
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.script_ptr as _) }
    }
}

/// The javascript runtime of frida.
pub enum FridaScriptRuntime {
    Default,
    QJS,
    V8,
}

impl FridaScriptRuntime {
    fn to_frida(&self) -> frida_sys::FridaScriptRuntime {
        match self {
            FridaScriptRuntime::Default => {
                frida_sys::FridaScriptRuntime_FRIDA_SCRIPT_RUNTIME_DEFAULT
            }
            FridaScriptRuntime::QJS => frida_sys::FridaScriptRuntime_FRIDA_SCRIPT_RUNTIME_QJS,
            FridaScriptRuntime::V8 => frida_sys::FridaScriptRuntime_FRIDA_SCRIPT_RUNTIME_V8,
        }
    }
}

pub struct ScriptOption {
    ptr: *mut FridaScriptOptions,
}

impl ScriptOption {
    pub fn new() -> Self {
        let ptr = unsafe { frida_sys::frida_script_options_new() };
        Self { ptr }
    }

    pub fn get_name(&self) -> &'static str {
        let name = unsafe { CStr::from_ptr(frida_sys::frida_script_options_get_name(self.ptr)) };
        name.to_str().unwrap_or_default()
    }

    pub fn set_name(self, name: &str) -> Self {
        unsafe { frida_sys::frida_script_options_set_name(self.ptr, name.as_ptr() as _) };
        self
    }

    pub fn set_runtime(self, runtime: FridaScriptRuntime) -> Self {
        unsafe { frida_sys::frida_script_options_set_runtime(self.ptr, runtime.to_frida()) };
        self
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut FridaScriptOptions {
        self.ptr
    }
}

impl Default for ScriptOption {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ScriptOption {
    /// Clears the option object of the script when we drop the struct.
    fn drop(&mut self) {
        unsafe {
            frida_sys::g_clear_object(
                &mut self.ptr as *mut *mut frida_sys::_FridaScriptOptions as _,
            )
        }
    }
}
