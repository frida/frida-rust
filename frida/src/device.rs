/*
 * Copyright © 2021-2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use crate::error::FridaCoreError;
use crate::process::Process;
use crate::session::Session;
use frida_sys::_FridaDevice;
use std::ffi::CStr;

pub struct Device {
    device_ptr: *mut _FridaDevice,
}

impl Device {
    // Creates new instance of device
    pub fn new(device_ptr: *mut _FridaDevice) -> Self {
        Device { device_ptr }
    }

    /// Gets the device's name
    pub fn get_name(&self) -> &str {
        let version =
            unsafe { CStr::from_ptr(frida_sys::frida_device_get_name(self.device_ptr) as _) };
        version.to_str().unwrap_or_default()
    }

    /// Checks if the device is lost or not.
    pub fn is_lost(&self) -> bool {
        unsafe { frida_sys::frida_device_is_lost(self.device_ptr) == 1 }
    }

    /// Obtains all processes
    pub fn enumerate_processes(&self) -> Vec<Process> {
        let mut processes = Vec::new();
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();

        let processes_ptr = unsafe {
            frida_sys::frida_device_enumerate_processes_sync(
                self.device_ptr,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut error,
            )
        };

        if error.is_null() {
            let num_processes = unsafe { frida_sys::frida_process_list_size(processes_ptr) };
            processes.reserve(num_processes as usize);

            for i in 0..num_processes {
                let process_ptr = unsafe { frida_sys::frida_process_list_get(processes_ptr, i) };
                let process = Process::new(process_ptr);
                processes.push(process);
            }
        }

        unsafe { frida_sys::frida_unref(processes_ptr as _) };
        processes
    }

    /// Creates [`Session`] and attaches the device to the current PID.
    pub fn attach(&self, pid: u32) -> Result<Session, FridaCoreError> {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        let session = unsafe {
            frida_sys::frida_device_attach_sync(
                self.device_ptr,
                pid,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut error,
            )
        };

        if error.is_null() {
            Ok(Session::new(session))
        } else {
            Err(FridaCoreError::DeviceAttachError)
        }
    }
}

impl Drop for Device {
    /// Destroys the ptr to the device when Device doesn't exist anymore
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.device_ptr as _) }
    }
}
