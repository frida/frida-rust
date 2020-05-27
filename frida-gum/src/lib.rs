pub use frida_gum_sys;
use std::ffi::CString;
use std::os::raw::{c_void, c_char};
use std::marker::PhantomData;


pub struct Gum;

impl Gum {
    pub fn obtain() -> Gum {
        unsafe { frida_gum_sys::gum_init_embedded() };
        Gum {}
    }
}


pub struct FunctionPointer {
    ptr: *mut c_void
}

impl FunctionPointer {
    pub unsafe fn from_raw(ptr: *mut c_void) -> FunctionPointer {
        FunctionPointer {
            ptr
        }
    }

    pub unsafe fn from_fn<F>(f: F) -> FunctionPointer {
        FunctionPointer {
            ptr: std::mem::transmute(&f)
        }
    } 

    pub fn to_raw(&self) -> *mut c_void {
        self.ptr
    }
}

pub struct Interceptor<'a> {
    interceptor: *mut frida_gum_sys::GumInterceptor,
    phantom: PhantomData<&'a frida_gum_sys::GumInterceptor>
}

impl<'a> Interceptor<'a> {
    pub fn obtain<'b>(gum: &'b Gum) -> Interceptor where 'b: 'a {
        Interceptor {
            interceptor: unsafe { frida_gum_sys::gum_interceptor_obtain() },
            phantom: PhantomData
        }
    }

    pub fn replace(&self, f: FunctionPointer, replacement: FunctionPointer) {
        unsafe { frida_gum_sys::gum_interceptor_replace(self.interceptor, f.to_raw(), replacement.to_raw(), std::ptr::null_mut()) };
    }
}

pub struct Module;

impl Module {
    pub fn find_export_by_name(library: Option<&str>, name: &str) -> Option<FunctionPointer> {
        let library_c: *const c_char = match library {
            Some(v) => CString::new(v).unwrap().into_raw(),
            None => std::ptr::null()
        };

        let name_c = CString::new(name).unwrap().into_raw();

        let ptr = unsafe {
            std::mem::transmute::<u64, *mut c_void>(frida_gum_sys::gum_module_find_export_by_name(library_c, name_c))
        };

        Some(unsafe { FunctionPointer::from_raw(ptr) })
    }
}

// struct InvocationContext;

// trait InvocationListener {
//     fn on_enter(&self, context: &mut InvocationContext);
//     fn on_leave(&self, context: &mut InvocationContext);
// }

// mod test {
//     use super::{FunctionPointer, Interceptor, InvocationContext, InvocationListener};
//     use std::os::raw::{c_char, c_int};

//     struct OpenInvocationListener;
    
//     impl InvocationListener for OpenInvocationListener {
//         fn on_enter(&self, context: &mut InvocationContext) {

//         }

//         fn on_leave(&self, context: &mut InvocationContext) {

//         }
//     }

    // unsafe extern "C" fn open(path: *const c_char, flags: c_int, mut args: ...) {
    //     unimplemented!()
    // }

//     fn test_can_attach() {
//         let f = unsafe { FunctionPointer::from_fn(open) };
//         let mut listener = OpenInvocationListener {};
//         let interceptor = Interceptor::obtain();
//         interceptor.attach(&f, &mut listener);
//     }
// }