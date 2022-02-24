/*
 * Copyright © 2021-2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use frida_sys::_FridaSession;
use std::ptr::null_mut;

use crate::{
    error::FridaCoreError,
    script::{Script, ScriptOption},
};

pub struct Session {
    session_ptr: *mut _FridaSession,
}

impl Session {
    /// Creates new instance of session.
    pub fn new(session_ptr: *mut _FridaSession) -> Self {
        Session { session_ptr }
    }

    /// Checks if the session is detached or not.
    pub fn is_detached(&self) -> bool {
        unsafe { frida_sys::frida_session_is_detached(self.session_ptr) == 1 }
    }

    /// Creates a [`Script`] struct attached to current session.
    pub fn create_script(
        &self,
        source: &str,
        option: &mut ScriptOption,
    ) -> Result<Script, FridaCoreError> {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        let script = unsafe {
            frida_sys::frida_session_create_script_sync(
                self.session_ptr,
                source.as_ptr() as _,
                option.as_mut_ptr(),
                null_mut(),
                &mut error,
            )
        };

        if error.is_null() {
            Ok(Script::new(script))
        } else {
            Err(FridaCoreError::ScriptCreationError)
        }
    }

    /// Detaches the current session.
    pub fn detach(&self) -> Result<(), FridaCoreError> {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        unsafe {
            frida_sys::frida_session_detach_sync(self.session_ptr, std::ptr::null_mut(), &mut error)
        }

        if error.is_null() {
            Ok(())
        } else {
            Err(FridaCoreError::SessionDetachError)
        }
    }
}

impl Drop for Session {
    /// Destroy the ptr to the session when Session doesn't exist anymore
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.session_ptr as _) }
    }
}
