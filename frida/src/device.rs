/*
 * Copyright © 2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use frida_sys::_FridaDevice;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::marker::PhantomData;

use crate::process::Process;
use crate::session::Session;
use crate::variant::Variant;
use crate::{Error, Result, SpawnOptions};

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

    /// Returns the device's type
    ///
    /// # Example
    /// ```
    ///# use frida::DeviceType;
    ///# let frida = unsafe { frida::Frida::obtain() };
    ///# let device_manager = frida::DeviceManager::obtain(&frida);
    ///# let device = device_manager.enumerate_all_devices().into_iter().find(|device| device.get_id() == "local").unwrap();
    /// assert_eq!(device.get_type(), DeviceType::Local);
    /// ```
    pub fn get_type(&self) -> DeviceType {
        unsafe { frida_sys::frida_device_get_dtype(self.device_ptr).into() }
    }

    /// Returns the device's system parameters
    ///
    /// # Example
    /// ```
    ///# use std::collections::HashMap;
    ///# let frida = unsafe { frida::Frida::obtain() };
    ///# let device_manager = frida::DeviceManager::obtain(&frida);
    ///# let device = device_manager.enumerate_all_devices().into_iter().find(|device| device.get_id() == "local").unwrap();
    /// let params = device.query_system_parameters().unwrap();
    /// let os_version = params
    ///     .get("os")
    ///     .expect("No parameter \"os\" present")
    ///     .get_map()
    ///     .expect("Parameter \"os\" was not a mapping")
    ///     .get("version")
    ///     .expect("Parameter \"os\" did not contain a version field")
    ///     .get_string()
    ///     .expect("Version is not a string");
    /// ```
    pub fn query_system_parameters(&self) -> Result<HashMap<String, Variant>> {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();

        let ht = unsafe {
            frida_sys::frida_device_query_system_parameters_sync(
                self.device_ptr,
                std::ptr::null_mut(),
                &mut error,
            )
        };

        if !error.is_null() {
            let message = unsafe { CString::from_raw((*error).message) }
                .into_string()
                .map_err(|_| Error::CStringFailed)?;
            let code = unsafe { (*error).code };

            return Err(Error::DeviceQuerySystemParametersFailed { code, message });
        }

        let mut iter: frida_sys::GHashTableIter =
            unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        unsafe { frida_sys::g_hash_table_iter_init(&mut iter, ht) };
        let size = unsafe { frida_sys::g_hash_table_size(ht) };
        let mut map = HashMap::with_capacity(size as usize);

        let mut key = std::ptr::null_mut();
        let mut val = std::ptr::null_mut();
        while (unsafe { frida_sys::g_hash_table_iter_next(&mut iter, &mut key, &mut val) }
            != frida_sys::FALSE as _)
        {
            let key = unsafe { CStr::from_ptr(key as _) };
            let val = unsafe { Variant::from_ptr(val as _) };
            map.insert(key.to_string_lossy().to_string(), val);
        }

        Ok(map)
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

    /// Spawn a process on the device
    ///
    /// Returns the PID of the newly spawned process.
    /// On spawn, the process will be halted, and [`resume`](Device::resume) will need to be
    /// called to continue execution.
    pub fn spawn<S: AsRef<str>>(&mut self, program: S, options: &SpawnOptions) -> Result<u32> {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        let program = CString::new(program.as_ref()).unwrap();

        let pid = unsafe {
            frida_sys::frida_device_spawn_sync(
                self.device_ptr,
                program.as_ptr(),
                options.options_ptr,
                std::ptr::null_mut(),
                &mut error,
            )
        };

        if !error.is_null() {
            let message = unsafe { CString::from_raw((*error).message) }
                .into_string()
                .map_err(|_| Error::CStringFailed)?;
            let code = unsafe { (*error).code };

            return Err(Error::SpawnFailed { code, message });
        }

        Ok(pid)
    }

    /// Resumes the process with given pid.
    pub fn resume(&self, pid: u32) -> Result<()> {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        unsafe {
            frida_sys::frida_device_resume_sync(
                self.device_ptr,
                pid,
                std::ptr::null_mut(),
                &mut error,
            )
        };

        if !error.is_null() {
            let message = unsafe { CString::from_raw((*error).message) }
                .into_string()
                .map_err(|_| Error::CStringFailed)?;
            let code = unsafe { (*error).code };

            return Err(Error::ResumeFailed { code, message });
        }

        Ok(())
    }

    /// Kill a process on the device
    pub fn kill(&mut self, pid: u32) -> Result<()> {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        unsafe {
            frida_sys::frida_device_kill_sync(
                self.device_ptr,
                pid,
                std::ptr::null_mut(),
                &mut error,
            )
        };

        if !error.is_null() {
            let message = unsafe { CString::from_raw((*error).message) }
                .into_string()
                .map_err(|_| Error::CStringFailed)?;
            let code = unsafe { (*error).code };

            return Err(Error::KillFailed { code, message });
        }

        Ok(())
    }
}

impl<'a> Drop for Device<'a> {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.device_ptr as _) }
    }
}

#[repr(u32)]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
/// Frida device type.
///
/// Represents different connection types
// On Windows, the constants are i32 instead of u32, so we need to cast accordingly.
pub enum DeviceType {
    /// Local Frida device.
    Local = frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_LOCAL as _,

    /// Remote Frida device, connected via network
    Remote = frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_REMOTE as _,

    /// Device connected via USB
    USB = frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_USB as _,
}

#[cfg(not(target_family = "windows"))]
impl From<u32> for DeviceType {
    fn from(value: u32) -> Self {
        match value {
            frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_LOCAL => Self::Local,
            frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_REMOTE => Self::Remote,
            frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_USB => Self::USB,
            value => unreachable!("Invalid Device type {}", value),
        }
    }
}

#[cfg(target_family = "windows")]
impl From<i32> for DeviceType {
    fn from(value: i32) -> Self {
        match value {
            frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_LOCAL => Self::Local,
            frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_REMOTE => Self::Remote,
            frida_sys::FridaDeviceType_FRIDA_DEVICE_TYPE_USB => Self::USB,
            value => unreachable!("Invalid Device type {}", value),
        }
    }
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

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
