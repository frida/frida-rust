/*
 * Copyright © 2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use frida_sys::{_FridaSession, g_bytes_get_data, g_bytes_new, g_bytes_unref, gsize};
use std::ffi::CString;
use std::marker::PhantomData;
use std::ptr::null_mut;

use crate::script::{Script, ScriptOption};
use crate::{Error, Result};

/// Represents a Frida session.
pub struct Session<'a> {
    session_ptr: *mut _FridaSession,
    phantom: PhantomData<&'a _FridaSession>,
}

impl<'a> Session<'a> {
    pub(crate) fn from_raw(session_ptr: *mut _FridaSession) -> Session<'a> {
        Session {
            session_ptr,
            phantom: PhantomData,
        }
    }

    /// Returns if the session is detached or not.
    pub fn is_detached(&self) -> bool {
        unsafe { frida_sys::frida_session_is_detached(self.session_ptr) == 1 }
    }

    /// Creates a [`Script`] attached to current session.
    pub fn create_script<'b>(
        &'a self,
        source: &str,
        option: &mut ScriptOption,
    ) -> Result<Script<'b>>
    where
        'a: 'b,
    {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        match CString::new(source) {
            Ok(source) => {
                let script = unsafe {
                    frida_sys::frida_session_create_script_sync(
                        self.session_ptr,
                        source.as_ptr(),
                        option.as_mut_ptr(),
                        null_mut(),
                        &mut error,
                    )
                };
                if error.is_null() {
                    Ok(Script::from_raw(script))
                } else {
                    Err(Error::ScriptCreationError)
                }
            }
            Err(_) => Err(Error::CStringFailed),
        }
    }

    /// Creates a [`Script`] from a pre-compiled bytecode blob produced by
    /// `frida_session_compile_script_sync` (or e.g. `session.compileScript`
    /// in the Node binding).
    ///
    /// Note: bytecode is runtime-specific. A blob produced with the QJS
    /// runtime won't load under V8 and vice-versa — make sure the bytecode
    /// was compiled with the same `ScriptRuntime` you pass here.
    pub fn create_script_from_bytes<'b>(
        &'a self,
        bytes: &[u8],
        option: &mut ScriptOption,
    ) -> Result<Script<'b>>
    where
        'a: 'b,
    {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        let script = unsafe {
            let g = g_bytes_new(bytes.as_ptr() as _, bytes.len() as _);
            let s = frida_sys::frida_session_create_script_from_bytes_sync(
                self.session_ptr,
                g,
                option.as_mut_ptr(),
                null_mut(),
                &mut error,
            );
            g_bytes_unref(g);
            s
        };
        if error.is_null() {
            Ok(Script::from_raw(script))
        } else {
            Err(Error::ScriptCreationError)
        }
    }

    /// Compile JS source to V8/QJS bytecode. Runtime is taken from `option`
    /// (default = QJS as of frida 16.x). The returned bytes can later be
    /// loaded with [`create_script_from_bytes`](Self::create_script_from_bytes).
    pub fn compile_script(&self, source: &str, option: &mut ScriptOption) -> Result<Vec<u8>> {
        let source_c = CString::new(source).map_err(|_| Error::CStringFailed)?;
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        unsafe {
            let g = frida_sys::frida_session_compile_script_sync(
                self.session_ptr,
                source_c.as_ptr(),
                option.as_mut_ptr(),
                null_mut(),
                &mut error,
            );
            if !error.is_null() {
                return Err(Error::ScriptCreationError);
            }
            let mut len: gsize = 0;
            let raw = g_bytes_get_data(g, &mut len) as *const u8;
            let out = if raw.is_null() || len == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(raw, len as usize).to_vec()
            };
            g_bytes_unref(g);
            Ok(out)
        }
    }

    /// Detaches the current session.
    pub fn detach(&self) -> Result<()> {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        unsafe {
            frida_sys::frida_session_detach_sync(self.session_ptr, std::ptr::null_mut(), &mut error)
        }

        if error.is_null() {
            Ok(())
        } else {
            Err(Error::SessionDetachError)
        }
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.session_ptr as _) }
    }
}
