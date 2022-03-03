/*
 * Copyright © 2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use frida_sys::_FridaDeviceManager;
use std::marker::PhantomData;

use crate::device::Device;
use crate::Frida;

pub struct DeviceManager<'a> {
    manager_ptr: *mut _FridaDeviceManager,
    phantom: PhantomData<&'a _FridaDeviceManager>,
}

impl<'a> DeviceManager<'a> {
    /// Obtains a new instance device manager.
    pub fn obtain<'b>(_frida: &'b Frida) -> Self
    where
        'b: 'a,
    {
        DeviceManager {
            manager_ptr: unsafe { frida_sys::frida_device_manager_new() },
            phantom: PhantomData,
        }
    }

    /// Obtains all devices
    pub fn enumerate_all_devices(&self) -> Vec<Device> {
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
                    Device::new(unsafe { frida_sys::frida_device_list_get(devices_ptr, i) });
                devices.push(device);
            }
        }

        unsafe { frida_sys::frida_unref(devices_ptr as _) }
        devices
    }
}

impl<'a> Drop for DeviceManager<'a> {
    /// Destroys the ptr to the manager when DeviceManager doesn't exist anymore
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.manager_ptr as _) }
    }
}
