extern crate num;
#[allow(unused_imports)]
#[macro_use]
extern crate num_derive;

pub use frida_gum_sys;
use std::os::raw::c_void;

pub mod stalker;

mod cpu_context;
pub use cpu_context::*;

pub struct Gum;

impl Gum {
    pub fn obtain() -> Gum {
        unsafe { frida_gum_sys::gum_init_embedded() };
        Gum {}
    }
}

impl Drop for Gum {
    fn drop(&mut self) {
        unsafe { frida_gum_sys::gum_deinit_embedded() };
    }
}

pub struct NativePointer(*mut c_void);

impl NativePointer {
    pub fn raw(&self) -> *mut c_void {
        self.0
    }
}

// pub struct Interceptor<'a> {
//     interceptor: *mut frida_gum_sys::GumInterceptor,
//     phantom: PhantomData<&'a frida_gum_sys::GumInterceptor>,
// }
//
// impl<'a> Interceptor<'a> {
//     pub fn obtain<'b>(_gum: &'b Gum) -> Interceptor
//     where
//         'b: 'a,
//     {
//         Interceptor {
//             interceptor: unsafe { frida_gum_sys::gum_interceptor_obtain() },
//             phantom: PhantomData,
//         }
//     }
//
//     pub fn replace(&self, f: NativePointer, replacement: NativePointer) {
//         unsafe {
//             frida_gum_sys::gum_interceptor_replace(
//                 self.interceptor,
//                 f.raw(),
//                 replacement.raw(),
//                 std::ptr::null_mut(),
//             )
//         };
//     }
// }
//
// pub struct Module;
//
// impl Module {
//     pub fn find_export_by_name(library: Option<&str>, name: &str) -> Option<NativePointer> {
//         let library_c: *const c_char = match library {
//             Some(v) => CString::new(v).unwrap().into_raw(),
//             None => std::ptr::null(),
//         };
//
//         let name_c = CString::new(name).unwrap().into_raw();
//
//         let ptr = unsafe {
//             std::mem::transmute::<u64, *mut c_void>(frida_gum_sys::gum_module_find_export_by_name(
//                 library_c, name_c,
//             ))
//         };
//
//         Some(NativePointer(ptr))
//     }
// }
