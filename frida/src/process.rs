/*
 * Copyright © 2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use frida_sys::_FridaProcess;
use std::ffi::CStr;

pub struct Process {
    process_ptr: *mut _FridaProcess,
}

impl Process {
    /// Creates new instance of a process.
    pub fn new(process_ptr: *mut _FridaProcess) -> Self {
        Process { process_ptr }
    }

    /// Gets the name of the process.
    pub fn get_name(&self) -> &str {
        let process_name =
            unsafe { CStr::from_ptr(frida_sys::frida_process_get_name(self.process_ptr) as _) };

        process_name.to_str().unwrap_or_default()
    }

    /// Gets the pid of the process.
    pub fn get_pid(&self) -> u32 {
        unsafe { frida_sys::frida_process_get_pid(self.process_ptr) }
    }
}

impl Drop for Process {
    /// Destroys the ptr to the process when Process doesn't exist anymore.
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.process_ptr as _) }
    }
}
