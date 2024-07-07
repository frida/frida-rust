/*
 * Copyright © 2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use frida_sys::{FridaScriptOptions, _FridaScript, g_bytes_new, g_bytes_unref};
use std::marker::PhantomData;
use std::{
    ffi::{c_char, c_void, CStr, CString},
    ptr::null_mut,
};

use crate::{Error, Result};

unsafe extern "C" fn call_on_message<I: ScriptHandler>(
    _script_ptr: *mut _FridaScript,
    message: *const i8,
    _data: &frida_sys::_GBytes,
    user_data: *mut c_void,
) {
    let handler: &mut I = &mut *(user_data as *mut I);

    handler.on_message(
        CStr::from_ptr(message as *const c_char)
            .to_str()
            .unwrap_or_default(),
    );
}

/// Represents a script signal handler.
pub trait ScriptHandler {
    /// Handler called when a message is shared from JavaScript to Rust.
    fn on_message(&mut self, message: &str);
}

/// Reprents a Frida script.
pub struct Script<'a> {
    script_ptr: *mut _FridaScript,
    phantom: PhantomData<&'a _FridaScript>,
}

impl<'a> Script<'a> {
    pub(crate) fn from_raw(script_ptr: *mut _FridaScript) -> Script<'a> {
        Script {
            script_ptr,
            phantom: PhantomData,
        }
    }

    /// Loads the script into the process.
    pub fn load(&self) -> Result<()> {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        unsafe { frida_sys::frida_script_load_sync(self.script_ptr, null_mut(), &mut error) };

        if error.is_null() {
            Ok(())
        } else {
            Err(Error::LoadingFailed)
        }
    }

    /// Unloads the script from the process.
    pub fn unload(&self) -> Result<()> {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        unsafe { frida_sys::frida_script_unload_sync(self.script_ptr, null_mut(), &mut error) };

        if error.is_null() {
            Ok(())
        } else {
            Err(Error::UnloadingFailed)
        }
    }

    /// Handles the `message` signal for the script and wraps into [`ScriptHandler`].
    ///
    /// # Example
    ///
    /// ```
    /// use frida::ScriptHandler;
    ///
    /// struct Handler;
    ///
    /// impl ScriptHandler for Handler {
    ///     fn on_message(&mut self, message: &str) {
    ///         println!("{message}");
    ///     }
    /// }
    /// ```
    pub fn handle_message<I: ScriptHandler>(&self, handler: &mut I) -> Result<()> {
        let message = CString::new("message").map_err(|_| Error::CStringFailed)?;
        unsafe {
            let callback = Some(std::mem::transmute::<
                *mut std::ffi::c_void,
                unsafe extern "C" fn(),
            >(call_on_message::<I> as *mut c_void));

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

    /// Post a JSON-encoded message to the script with optional binary data
    ///
    /// NOTE: `message` must be valid JSON otherwise the script will throw a SyntaxError
    pub fn post<S: AsRef<str>>(&self, message: S, data: Option<&[u8]>) -> Result<()> {
        let message = CString::new(message.as_ref()).map_err(|_| Error::CStringFailed)?;

        unsafe {
            let g_data = if let Some(data) = data {
                g_bytes_new(data.as_ptr() as _, data.len() as _)
            } else {
                std::ptr::null_mut()
            };
            frida_sys::frida_script_post(self.script_ptr as _, message.as_ptr() as _, g_data);
            g_bytes_unref(g_data);
        }

        Ok(())
    }
}

impl<'a> Drop for Script<'a> {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.script_ptr as _) }
    }
}

/// The JavaScript runtime of Frida.
pub enum ScriptRuntime {
    /// Default Frida runtime.
    Default,
    /// QuickJS runtime.
    QJS,
    /// Google V8 runtime.
    V8,
}

impl From<ScriptRuntime> for frida_sys::FridaScriptRuntime {
    fn from(runtime: ScriptRuntime) -> Self {
        match runtime {
            ScriptRuntime::Default => frida_sys::FridaScriptRuntime_FRIDA_SCRIPT_RUNTIME_DEFAULT,
            ScriptRuntime::QJS => frida_sys::FridaScriptRuntime_FRIDA_SCRIPT_RUNTIME_QJS,
            ScriptRuntime::V8 => frida_sys::FridaScriptRuntime_FRIDA_SCRIPT_RUNTIME_V8,
        }
    }
}

/// Represents options passed to the Frida script registrar.
pub struct ScriptOption {
    ptr: *mut FridaScriptOptions,
}

impl ScriptOption {
    /// Create a new set of script options.
    pub fn new() -> Self {
        let ptr = unsafe { frida_sys::frida_script_options_new() };
        Self { ptr }
    }

    /// Get the name of the script.
    pub fn get_name(&self) -> &'static str {
        let name = unsafe { CStr::from_ptr(frida_sys::frida_script_options_get_name(self.ptr)) };
        name.to_str().unwrap_or_default()
    }

    /// Set the name of the script.
    pub fn set_name(self, name: &str) -> Self {
        unsafe { frida_sys::frida_script_options_set_name(self.ptr, name.as_ptr() as _) };
        self
    }

    /// Set the runtime of the script.
    pub fn set_runtime(self, runtime: ScriptRuntime) -> Self {
        unsafe { frida_sys::frida_script_options_set_runtime(self.ptr, runtime.into()) };
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
    fn drop(&mut self) {
        unsafe {
            frida_sys::g_clear_object(
                &mut self.ptr as *mut *mut frida_sys::_FridaScriptOptions as _,
            )
        }
    }
}
