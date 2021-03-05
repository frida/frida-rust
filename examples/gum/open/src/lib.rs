use frida_gum as gum;
use gum::{
    interceptor::{Interceptor, InvocationContext, InvocationListener},
    Gum, Module,
};
use lazy_static::lazy_static;
use std::os::raw::{c_int, c_void};

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
}

struct OpenListener;

impl InvocationListener for OpenListener {
    fn on_enter(&mut self, _context: InvocationContext) {
        println!("Enter: open()");
    }

    fn on_leave(&mut self, _context: InvocationContext) {
        println!("Leave: open()");
    }
}

#[no_mangle]
extern "C" fn example_agent_main(_user_data: *const c_void, resident: *mut c_int) {
    unsafe { *resident = 1 };

    let mut interceptor = Interceptor::obtain(&GUM);
    let mut listener = OpenListener {};
    let open = Module::find_export_by_name(None, "open");
    interceptor.attach(open, &mut listener);
}
