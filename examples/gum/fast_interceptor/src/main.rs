use {
    frida_gum::{interceptor::Interceptor, Gum, NativePointer},
    lazy_static::lazy_static,
    libc::{c_char, c_uint, c_void},
    std::{
        cell::UnsafeCell,
        ffi::CStr,
        sync::Mutex,
        time::{Duration, Instant},
    },
};

const RUNS: usize = 1000000;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
    static ref ORIGINAL_TEST: Mutex<UnsafeCell<Option<TestFunc>>> =
        Mutex::new(UnsafeCell::new(None));
}

fn get_test_string_ptr() -> *const c_char {
    "test_string\0".as_ptr() as *const c_char
}

fn get_test_string() -> &'static str {
    unsafe { CStr::from_ptr(get_test_string_ptr()).to_str().unwrap() }
}

type TestFunc = extern "C" fn(*const c_char) -> c_uint;

extern "C" fn test_func(name: *const c_char) -> c_uint {
    let name_str = unsafe { CStr::from_ptr(name).to_str().unwrap() };
    let test_str = get_test_string();
    if name_str != get_test_string() {
        panic!("Invalid param: {} != {}", name_str, test_str);
    }
    0xdeadface
}

extern "C" fn test_detour(name: *const c_char) -> c_uint {
    let name_str = unsafe { CStr::from_ptr(name).to_str().unwrap() };
    let test_str = get_test_string();
    if name_str != get_test_string() {
        panic!("Invalid param: {} != {}", name_str, test_str);
    }

    let orig = unsafe {
        ORIGINAL_TEST
            .lock()
            .unwrap()
            .get()
            .as_ref()
            .unwrap()
            .unwrap()(name)
    };
    0x00ff00ff + orig
}

fn expect_test_func(test_string: *const c_char, expected_ret: c_uint) {
    let ret = test_func(test_string);
    if ret != expected_ret {
        panic!("Invalid ret: {:x} != {:x}", ret, expected_ret);
    }
}

fn time(test_string: *const c_char, expected_ret: c_uint) -> Duration {
    let start = Instant::now();
    for _ in 0..RUNS {
        expect_test_func(test_string, expected_ret);
    }
    start.elapsed()
}

fn replace_normal() {
    let mut interceptor = Interceptor::obtain(&GUM);
    let test_func_ptr = test_func as *mut c_void;
    let test_detour_ptr = test_detour as *mut c_void;
    unsafe {
        *ORIGINAL_TEST.lock().unwrap().get_mut() = Some(std::mem::transmute::<
            *mut libc::c_void,
            extern "C" fn(*const i8) -> u32,
        >(
            interceptor
                .replace(
                    NativePointer(test_func_ptr),
                    NativePointer(test_detour_ptr),
                    NativePointer(std::ptr::null_mut()),
                )
                .unwrap()
                .0,
        ));
    }
}

fn replace_fast() {
    let mut interceptor = Interceptor::obtain(&GUM);
    let test_func_ptr = test_func as *mut c_void;
    let test_detour_ptr = test_detour as *mut c_void;
    unsafe {
        *ORIGINAL_TEST.lock().unwrap().get_mut() = Some(std::mem::transmute::<
            *mut libc::c_void,
            extern "C" fn(*const i8) -> u32,
        >(
            interceptor
                .replace_fast(NativePointer(test_func_ptr), NativePointer(test_detour_ptr))
                .unwrap()
                .0,
        ));
    }
}

fn revert() {
    let mut interceptor = Interceptor::obtain(&GUM);
    let test_func_ptr = test_func as *mut c_void;
    interceptor.revert(NativePointer(test_func_ptr));
}

fn main() {
    let test_string_ptr = get_test_string_ptr();

    expect_test_func(test_string_ptr, 0xdeadface);

    replace_fast();
    expect_test_func(test_string_ptr, 0xdeadface + 0x00ff00ff);
    revert();

    let original_time = time(test_string_ptr, 0xdeadface);
    println!("original: {original_time:?}");

    replace_normal();
    let normal_time = time(test_string_ptr, 0xdeadface + 0x00ff00ff);
    println!("normal: {normal_time:?}");
    revert();

    replace_fast();
    let fast_time = time(test_string_ptr, 0xdeadface + 0x00ff00ff);
    println!("fast_time: {fast_time:?}");
    revert();
}
