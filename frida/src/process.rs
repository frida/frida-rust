/*
 * Copyright © 2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Process helper.

use frida_sys::_FridaProcess;
use std::ffi::CStr;
use std::marker::PhantomData;

/// Process management in Frida.
pub struct Process<'a> {
    process_ptr: *mut _FridaProcess,
    phantom: PhantomData<&'a _FridaProcess>,
}

impl<'a> Process<'a> {
    pub(crate) fn from_raw(process_ptr: *mut _FridaProcess) -> Process<'a> {
        Process {
            process_ptr,
            phantom: PhantomData,
        }
    }

    /// Returns the name of the process.
    pub fn get_name(&self) -> &str {
        let process_name =
            unsafe { CStr::from_ptr(frida_sys::frida_process_get_name(self.process_ptr) as _) };

        process_name.to_str().unwrap_or_default()
    }

    /// Returns the process ID of the process.
    pub fn get_pid(&self) -> u32 {
        unsafe { frida_sys::frida_process_get_pid(self.process_ptr) }
    }
}

impl<'a> Drop for Process<'a> {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.process_ptr as _) }
    }
}
