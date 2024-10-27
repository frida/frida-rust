#[no_mangle]
pub fn injected_function(data: *const std::os::raw::c_char) {
    unsafe {
        if let Some(c_str) = data.as_ref() {
            let message = std::ffi::CStr::from_ptr(c_str).to_string_lossy();
            println!("injected_function called with data: '{}'", message);
        }
    }
}
