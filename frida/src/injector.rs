use crate::{Device, Error, Frida, Result};
use std::ffi::CString;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

use frida_sys::{_FridaInjector, g_bytes_new, g_bytes_unref};

/// Local library injector
///
/// Implements [Inject] to allow library injection into a target process.
pub struct Injector {
    _frida: Frida,
    injector_ptr: *mut _FridaInjector,
}

unsafe impl Send for Injector {}

impl Injector {
    pub(crate) fn from_raw(frida: Frida, injector_ptr: *mut _FridaInjector) -> Injector {
        Injector {
            _frida: frida,
            injector_ptr,
        }
    }

    /// Create a new Injector using a `frida-helper` process.
    ///
    /// The `frida-helper` is a binary compiled into the Frida devkit, and is codesigned
    /// to allow debugging. It is spawned and injection is delegated to the helper.
    pub fn new(frida: Frida) -> Self {
        Self::from_raw(frida, unsafe { frida_sys::frida_injector_new() })
    }

    /// Create a new inprocess Injector
    ///
    /// Create a new Injector without using a `frida-helper` process.
    ///
    /// See [Injector::new] for details about the `frida-helper` process. Using an
    /// in_process injector may require the debugger process to be codesigned on some
    /// platforms.
    pub fn in_process(frida: Frida) -> Self {
        Self::from_raw(frida, unsafe { frida_sys::frida_injector_new_inprocess() })
    }
}

impl Drop for Injector {
    fn drop(&mut self) {
        eprintln!("dropping injector");
        unsafe {
            frida_sys::frida_injector_close_sync(
                self.injector_ptr,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            frida_sys::frida_unref(self.injector_ptr as _)
        }
    }
}

/// Extension trait that allows injecting a library into a target process.
///
/// This is an extension trait to [Device], allowing injection of a library into a target process.
/// For local injection, the [Injector] struct implements [Inject], allowing library
/// injection into a target process without acquiring a [Device].
///
/// On injection, the function with a given symbol is executed in a new thread, receiving
/// two parameters:
/// ```
/// type Entrypoint = extern "C" fn(data: *const u8, stay_resident: *mut u32);
/// ```
/// The string passed in `data` is passed from the host process. On start, the parameter
/// `stay_resident` can be set to `1`, preventing that the library from
/// being unloaded after execution of the entrypoint.
///
/// # Injection on remote devices
///
/// Using a [Device], a library may be injected into the target process on a remote device.
/// When injecting a library file using [Inject::inject_library_file_sync], the given path
/// refers to the target device's filesystem; the library must be present on the device.
/// The [Inject::inject_library_blob_sync] function can be used to inject a library from the
/// host device, writing the library to a file on the target where required.
///
/// # Examples
///
/// Inject the library at `/path/to/payload.so` into the process with PID `1337`, and execute
/// the function with the symbol `entrypoint` in a new thread. This function will receive the
/// string "hello world" passed in the first parameter.
/// ```no_run
///# use crate::frida::{Injector, Inject};
/// let mut injector = Injector::new();
/// injector.inject_library_file_sync(1337, "/path/to/payload.so", "entrypoint", "hello world")
///     .expect("Could not inject library");
/// ```
pub trait Inject {
    /// Inject a library into a target process
    ///
    /// Inject the library at `path` on the target device into the process identified by `pid`.
    /// On injection, the given entrypoint is executed and passed the string in `data`.
    fn inject_library_file_sync<D, E, P>(
        &mut self,
        pid: u32,
        path: P,
        entrypoint: E,
        data: D,
    ) -> Result<u32>
    where
        D: Into<Vec<u8>>,
        P: AsRef<Path>,
        E: AsRef<str>;

    /// Inject a library blob into a target process
    ///
    /// Inject the library given in `blob` into the process identified by `pid`.
    /// On injection, the given entrypoint is executed and passed the string in `data`.
    fn inject_library_blob_sync<D, E>(
        &mut self,
        pid: u32,
        blob: &[u8],
        entrypoint: E,
        data: D,
    ) -> Result<u32>
    where
        D: Into<Vec<u8>>,
        E: AsRef<str>;
}

impl<'a> Inject for Injector {
    fn inject_library_file_sync<D, E, P>(
        &mut self,
        pid: u32,
        path: P,
        entrypoint: E,
        data: D,
    ) -> Result<u32>
    where
        D: Into<Vec<u8>>,
        P: AsRef<Path>,
        E: AsRef<str>,
    {
        #[cfg(unix)]
        let path =
            CString::new(path.as_ref().as_os_str().as_bytes()).map_err(|_| Error::CStringFailed)?;

        #[cfg(windows)]
        let path = CString::new(
            path.as_ref()
                .as_os_str()
                .to_str()
                .ok_or(Error::CStringFailed)?,
        )
        .map_err(|_| Error::CStringFailed)?;

        let entrypoint = CString::new(entrypoint.as_ref()).unwrap();

        let data = CString::new(data).unwrap();
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();

        let id = unsafe {
            frida_sys::frida_injector_inject_library_file_sync(
                self.injector_ptr,
                pid as frida_sys::guint,
                path.as_ptr() as *const frida_sys::gchar,
                entrypoint.as_ptr() as *const frida_sys::gchar,
                data.as_ptr() as *const frida_sys::gchar,
                std::ptr::null_mut(),
                &mut error,
            )
        };
        if !error.is_null() {
            let message = unsafe { CString::from_raw((*error).message) }
                .into_string()
                .map_err(|_| Error::CStringFailed)?;
            let code = unsafe { (*error).code };

            return Err(Error::InjectFailed { code, message });
        }

        Ok(id)
    }

    fn inject_library_blob_sync<D, E>(
        &mut self,
        pid: u32,
        blob: &[u8],
        entrypoint: E,
        data: D,
    ) -> Result<u32>
    where
        D: Into<Vec<u8>>,
        E: AsRef<str>,
    {
        let entrypoint = CString::new(entrypoint.as_ref()).unwrap();

        let data = CString::new(data).unwrap();
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();

        let id = unsafe {
            let g_blob = g_bytes_new(blob.as_ptr() as _, blob.len() as _);
            let id = frida_sys::frida_injector_inject_library_blob_sync(
                self.injector_ptr,
                pid,
                g_blob,
                entrypoint.as_ptr() as *const frida_sys::gchar,
                data.as_ptr() as *const frida_sys::gchar,
                std::ptr::null_mut(),
                &mut error,
            );
            g_bytes_unref(g_blob);
            id
        };

        if !error.is_null() {
            let message = unsafe { CString::from_raw((*error).message) }
                .into_string()
                .map_err(|_| Error::CStringFailed)?;
            let code = unsafe { (*error).code };

            return Err(Error::InjectFailed { code, message });
        }

        Ok(id)
    }
}

impl Inject for Device {
    fn inject_library_file_sync<D, E, P>(
        &mut self,
        pid: u32,
        path: P,
        entrypoint: E,
        data: D,
    ) -> Result<u32>
    where
        D: Into<Vec<u8>>,
        P: AsRef<Path>,
        E: AsRef<str>,
    {
        #[cfg(unix)]
        let path =
            CString::new(path.as_ref().as_os_str().as_bytes()).map_err(|_| Error::CStringFailed)?;

        #[cfg(windows)]
        let path = CString::new(
            path.as_ref()
                .as_os_str()
                .to_str()
                .ok_or(Error::CStringFailed)?,
        )
        .map_err(|_| Error::CStringFailed)?;

        let entrypoint = CString::new(entrypoint.as_ref()).unwrap();

        let data = CString::new(data).unwrap();
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();

        let id = unsafe {
            frida_sys::frida_device_inject_library_file_sync(
                self.ptr(),
                pid as frida_sys::guint,
                path.as_ptr() as *const frida_sys::gchar,
                entrypoint.as_ptr() as *const frida_sys::gchar,
                data.as_ptr() as *const frida_sys::gchar,
                std::ptr::null_mut(),
                &mut error,
            )
        };
        if !error.is_null() {
            let message = unsafe { CString::from_raw((*error).message) }
                .into_string()
                .map_err(|_| Error::CStringFailed)?;
            let code = unsafe { (*error).code };

            return Err(Error::InjectFailed { code, message });
        }

        Ok(id)
    }

    fn inject_library_blob_sync<D, E>(
        &mut self,
        pid: u32,
        blob: &[u8],
        entrypoint: E,
        data: D,
    ) -> Result<u32>
    where
        D: Into<Vec<u8>>,
        E: AsRef<str>,
    {
        let entrypoint = CString::new(entrypoint.as_ref()).unwrap();

        let data = CString::new(data).unwrap();
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();

        let id = unsafe {
            let g_blob = g_bytes_new(blob.as_ptr() as _, blob.len() as _);
            let id = frida_sys::frida_device_inject_library_blob_sync(
                self.ptr(),
                pid,
                g_blob,
                entrypoint.as_ptr() as *const frida_sys::gchar,
                data.as_ptr() as *const frida_sys::gchar,
                std::ptr::null_mut(),
                &mut error,
            );
            g_bytes_unref(g_blob);
            id
        };

        if !error.is_null() {
            let message = unsafe { CString::from_raw((*error).message) }
                .into_string()
                .map_err(|_| Error::CStringFailed)?;
            let code = unsafe { (*error).code };

            return Err(Error::InjectFailed { code, message });
        }

        Ok(id)
    }
}
