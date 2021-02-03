// #![feature(c_variadic)]
// use frida_gum as gum;
// use lazy_static::lazy_static;
// use std::ffi::CStr;
// use std::os::raw::{c_char, c_int, c_void};

// lazy_static! {
//     static ref GUM: gum::Gum = gum::Gum::obtain();
// }

// unsafe extern "C" fn open(path: *const c_char, flags: c_int, mut _args: ...) -> c_int {
//     eprintln!(
//         "open({}, {:x})",
//         CStr::from_ptr(path).to_string_lossy(),
//         flags
//     );
//     -1
// }

// #[no_mangle]
// extern "C" fn example_agent_main(_user_data: *const c_void, resident: *mut c_int) {
//     while unsafe { gum::frida_gum_sys::gum_process_is_debugger_attached() == 0 } {
//         use std::thread;
//         thread::sleep_ms(1000);
//     }

//     unsafe { *resident = 1 };

//     println!("example_agent_main()");

//     let interceptor = gum::Interceptor::obtain(&GUM);
//     let open_ptr = gum::Module::find_export_by_name(None, "open").unwrap();
//     // interceptor.replace(open_ptr, unsafe { gum::NativePointer::from_fn(open) });
// }
