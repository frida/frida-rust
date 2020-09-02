//! Gum bindings for Rust
//!
//! Gum provides a number of utilities for instrumenting binary applications,
//! and traditionally is consumed via the JavaScript API known as GumJS.
//! This crate aims to provide a complete interface to the instrumentation
//! API provided by Gum, rather than GumJS (s.t. these bindings exclude the `Java` and `ObjC`
//! modules).
//!
//! # Quick Start
//! First, ensure that your platform is supported by Gum. You can find a listing of
//! development kits on the [Frida releases page](https://github.com/frida/frida/releases).
//! To get started using Gum, you need to obtain a global [`Gum`] object; this is required
//! to safely ensure that Gum has been properly initialized as required. Next, you are
//! free to use any available APIs, such as the [`stalker::Stalker`]:
//! ```
//! use frida_gum as gum;
//! use lazy_static::lazy_static;
//!
//! lazy_static! {
//!     static ref GUM: gum::Gum = gum::Gum::obtain();
//! }
//!
//! fn main() {
//!     let mut stalker = Stalker::new(&GUM);
//!
//!     let transformer = Transformer::from_callback(&GUM, |basic_block, _output| {
//!         for instr in basic_block {
//!             instr.keep();
//!         }
//!     });
//!
//!     stalker.follow_me(transformer, None);
//!     stalker.unfollow_me();
//! }
//! ```

extern crate num;
#[allow(unused_imports)]
#[macro_use]
extern crate num_derive;

use std::os::raw::c_void;

pub mod stalker;

pub mod interceptor;

mod cpu_context;
pub use cpu_context::*;

mod memory_range;
pub use memory_range::*;

/// Context required for instantiation of all structures under the Gum namespace.
pub struct Gum;

impl Gum {
    /// Obtain a Gum handle, ensuring that the runtime is properly initialized. This may
    /// be called as many times as needed, and results in a no-op if the Gum runtime is
    /// already initialized.
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
