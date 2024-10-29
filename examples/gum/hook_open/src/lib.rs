use ctor::ctor;
use frida_gum::{interceptor::Interceptor, Gum, Module, NativePointer};
use lazy_static::lazy_static;
use libc::{c_char, c_int, c_void};
use std::cell::UnsafeCell;
use std::sync::Mutex;
use std::sync::OnceLock;

lazy_static! {
    static ref ORIGINAL_OPEN: Mutex<UnsafeCell<Option<OpenFunc>>> =
        Mutex::new(UnsafeCell::new(None));
}

type OpenFunc = unsafe extern "C" fn(*const c_char, flags: c_int) -> c_int;

unsafe extern "C" fn open_detour(name: *const c_char, flags: c_int) -> c_int {
    println!(
        "open_detour: {}",
        std::ffi::CStr::from_ptr(name).to_str().unwrap()
    );
    ORIGINAL_OPEN
        .lock()
        .unwrap()
        .get()
        .as_ref()
        .unwrap()
        .unwrap()(name, flags)
}

#[ctor]
fn init() {
    static CELL: OnceLock<Gum> = OnceLock::new();
    let gum = CELL.get_or_init(|| Gum::obtain());
    let module = Module::obtain(gum);
    let mut interceptor = Interceptor::obtain(gum);
    let open = module.find_export_by_name(None, "open").unwrap();
    unsafe {
        *ORIGINAL_OPEN.lock().unwrap().get_mut() = Some(std::mem::transmute::<
            *mut libc::c_void,
            unsafe extern "C" fn(*const i8, i32) -> i32,
        >(
            interceptor
                .replace(
                    open,
                    NativePointer(open_detour as *mut c_void),
                    NativePointer(std::ptr::null_mut()),
                )
                .unwrap()
                .0,
        ));
    }
}
