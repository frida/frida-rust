use crate::{error, Error, Frida};
use frida_sys::_FridaCompiler;
use std::ffi::CStr;
use std::marker::PhantomData;

/// Process management in Frida.
pub struct Compiler<'a> {
    compiler_ptr: *mut _FridaCompiler,
    phantom: PhantomData<&'a _FridaCompiler>,
}

impl<'a> Compiler<'a> {
    /// Obtain a compiler object with a new device manager.
    pub fn obtain<'b>(_frida: &'b Frida) -> Self
    where
        'b: 'a,
    {
        Compiler {
            compiler_ptr: unsafe {
                frida_sys::frida_compiler_new(frida_sys::frida_device_manager_new())
            },
            phantom: PhantomData,
        }
    }

    /// Build a frida script.
    pub fn build(&self, program: &str) -> Result<&str, error::Error> {
        let c_program_str = std::ffi::CString::new(program).map_err(|_| Error::CStringFailed);
        //  gchar * frida_compiler_build_sync (FridaCompiler * self, const gchar * entrypoint, FridaBuildOptions * options, GCancellable * cancellable, GError ** error);
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        let bundle = unsafe {
            frida_sys::frida_compiler_build_sync(
                self.compiler_ptr,
                c_program_str?.as_ptr() as _,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut error,
            )
        };

        // If no error, return the bundle
        if error.is_null() {
            let bundle_script = unsafe { CStr::from_ptr(bundle as _) };
            Ok(bundle_script.to_str().unwrap_or_default())
        } else {
            Err(Error::FridaCompileError)
        }
    }
}

impl<'a> Drop for Compiler<'a> {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.compiler_ptr as _) }
    }
}
