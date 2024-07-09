/*
 * Copyright © 2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use frida_sys::_FridaDeviceManager;
use std::ffi::CString;
use std::marker::PhantomData;

use crate::device::Device;
use crate::DeviceType;
use crate::Error;
use crate::Frida;
use crate::Result;

/// Platform-independent device manager abstraction access.
pub struct DeviceManager<'a> {
    manager_ptr: *mut _FridaDeviceManager,
    phantom: PhantomData<&'a _FridaDeviceManager>,
}

impl<'a> DeviceManager<'a> {
    /// Obtain an DeviceManager handle, ensuring that the runtime is properly initialized. This may be called as many
    /// times as needed, and results in a no-op if the DeviceManager is already initialized.
    pub fn obtain<'b>(_frida: &'b Frida) -> Self
    where
        'b: 'a,
    {
        DeviceManager {
            manager_ptr: unsafe { frida_sys::frida_device_manager_new() },
            phantom: PhantomData,
        }
    }

    /// Returns all devices.
    pub fn enumerate_all_devices<'b>(&'a self) -> Vec<Device<'b>>
    where
        'a: 'b,
    {
        let mut devices = Vec::new();
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();

        let devices_ptr = unsafe {
            frida_sys::frida_device_manager_enumerate_devices_sync(
                self.manager_ptr,
                std::ptr::null_mut(),
                &mut error,
            )
        };

        if error.is_null() {
            let num_devices = unsafe { frida_sys::frida_device_list_size(devices_ptr) };
            devices.reserve(num_devices as usize);

            for i in 0..num_devices {
                let device =
                    Device::from_raw(unsafe { frida_sys::frida_device_list_get(devices_ptr, i) });
                devices.push(device);
            }
        }

        unsafe { frida_sys::frida_unref(devices_ptr as _) }
        devices
    }

    /// Returns the device of the specified type.
    pub fn get_device_by_type(&'a self, r#type: DeviceType) -> Result<Device<'a>> {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();

        let device_ptr = unsafe {
            frida_sys::frida_device_manager_get_device_by_type_sync(
                self.manager_ptr,
                r#type.into(),
                0,
                std::ptr::null_mut(),
                &mut error,
            )
        };

        if !error.is_null() {
            return Err(Error::DeviceLookupFailed);
        }

        return Ok(Device::from_raw(device_ptr));
    }

    /// Returns the remote device with the specified host.
    pub fn get_remote_device(&'a self, host: &str) -> Result<Device<'a>> {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        let host_cstring = CString::new(host).map_err(|_| Error::CStringFailed)?;

        let device_ptr = unsafe {
            frida_sys::frida_device_manager_add_remote_device_sync(
                self.manager_ptr,
                host_cstring.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut error,
            )
        };

        if !error.is_null() {
            return Err(Error::DeviceLookupFailed);
        }

        return Ok(Device::from_raw(device_ptr));
    }

    /// Returns the device with the specified id.
    ///
    /// # Example
    ///
    /// let frida = unsafe { frida::Frida::obtain() };
    /// let device_manager = frida::DeviceManager::obtain(&frida);
    ///
    /// let id = "<some id>";
    /// let device = device_manager.get_device_by_id(id).unwrap();
    /// assert_eq!(device.get_id(), id);
    ///
    pub fn get_device_by_id(&'a self, device_id: &str) -> Result<Device<'a>> {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        let cstring = CString::new(device_id).unwrap();

        let device_ptr = unsafe {
            frida_sys::frida_device_manager_get_device_by_id_sync(
                self.manager_ptr,
                cstring.as_ptr(),
                0,
                std::ptr::null_mut(),
                &mut error,
            )
        };

        if !error.is_null() {
            return Err(Error::DeviceLookupFailed);
        }

        return Ok(Device::from_raw(device_ptr));
    }
}

impl<'a> Drop for DeviceManager<'a> {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.manager_ptr as _) }
    }
}
