use frida_sys::_FridaApplication;
use std::ffi::CStr;
use std::marker::PhantomData;

/// Application in Frida.
pub struct FridaApplication<'a> {
    application_ptr: *mut _FridaApplication,
    phantom: PhantomData<&'a _FridaApplication>,
}

impl<'a> FridaApplication<'a> {
    pub(crate) fn from_raw(application_ptr: *mut _FridaApplication) -> FridaApplication<'a> {
        FridaApplication {
            application_ptr,
            phantom: PhantomData,
        }
    }

    /// Returns the app's name.
    pub fn get_name(&self) -> &str {
        let name = unsafe {
            CStr::from_ptr(frida_sys::frida_application_get_name(self.application_ptr) as _)
        };
        name.to_str().unwrap_or_default()
    }

    /// Returns the app's pid.
    pub fn get_pid(&self) -> u32 {
        unsafe { frida_sys::frida_application_get_pid(self.application_ptr) }
    }

    /// Returns the app's identifier.
    pub fn get_identifier(&self) -> &str {
        let id = unsafe {
            CStr::from_ptr(frida_sys::frida_application_get_identifier(self.application_ptr) as _)
        };
        id.to_str().unwrap_or_default()
    }
}
