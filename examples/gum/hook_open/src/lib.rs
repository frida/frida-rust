#![feature(c_variadic)]
use frida_gum::{
    interceptor::{Interceptor},
    Gum,
    Module, NativePointer
};
use lazy_static::lazy_static;
use ctor::ctor;
use libc::{c_void, c_int, c_char};

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
}

unsafe extern "C" fn open_detour(
    name: *const c_char, 
    flags: c_int,
) -> c_int {
    println!("open_detour: {}", std::ffi::CStr::from_ptr(name).to_str().unwrap());
    let res = libc::open(name, flags);
    res
}

#[ctor]
fn init() {
    let mut interceptor = Interceptor::obtain(&GUM);
    let open = Module::find_export_by_name(None, "open").unwrap();
    interceptor.replace(open, NativePointer(open_detour as *mut c_void), NativePointer(0 as *mut c_void)).unwrap();
}

