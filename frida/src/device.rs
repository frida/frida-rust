/*
 * Copyright © 2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use frida_sys::_FridaDevice;
use std::ffi::CStr;
use std::marker::PhantomData;

use crate::process::Process;
use crate::session::Session;
use crate::{Error, Result};

/// Access to a Frida device.
pub struct Device<'a> {
    pub(crate) device_ptr: *mut _FridaDevice,
    phantom: PhantomData<&'a _FridaDevice>,
}

impl<'a> Device<'a> {
    pub(crate) fn from_raw(device_ptr: *mut _FridaDevice) -> Device<'a> {
        Device {
            device_ptr,
            phantom: PhantomData,
        }
    }

    /// Returns the device's name.
    pub fn get_name(&self) -> &str {
        let name =
            unsafe { CStr::from_ptr(frida_sys::frida_device_get_name(self.device_ptr) as _) };
        name.to_str().unwrap_or_default()
    }

    /// Returns the device's id.
    pub fn get_id(&self) -> &str {
        let id = unsafe { CStr::from_ptr(frida_sys::frida_device_get_id(self.device_ptr) as _) };
        id.to_str().unwrap_or_default()
    }

    /// Returns if the device is lost or not.
    pub fn is_lost(&self) -> bool {
        unsafe { frida_sys::frida_device_is_lost(self.device_ptr) == 1 }
    }

    /// Returns all processes.
    pub fn enumerate_processes<'b>(&'a self) -> Vec<Process<'b>>
    where
        'a: 'b,
    {
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
                let process = Process::from_raw(process_ptr);
                processes.push(process);
            }
        }

        unsafe { frida_sys::frida_unref(processes_ptr as _) };
        processes
    }

    /// Creates [`Session`] and attaches the device to the current PID.
    pub fn attach<'b>(&'a self, pid: u32) -> Result<Session<'b>>
    where
        'a: 'b,
    {
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
            Ok(Session::from_raw(session))
        } else {
            Err(Error::DeviceAttachError)
        }
    }
}

impl<'a> Drop for Device<'a> {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.device_ptr as _) }
    }
}

/// Frida device type.
pub enum DeviceType {
    /// Local Frida device.
    Local,
    /// Remote Frida device.
    Remote,
    /// USB Frida device.
    USB,
}

impl From<DeviceType> for frida_sys::FridaDeviceType {
    fn from(value: DeviceType) -> Self {
        match value {
            DeviceType::Local => frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_LOCAL,
            DeviceType::Remote => frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_REMOTE,
            DeviceType::USB => frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_USB,
        }
    }
}
