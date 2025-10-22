/* This example is in the public domain */

use frida_gum as gum;
use gum::{
    interceptor::{Interceptor, InvocationContext, InvocationListener},
    Gum, Module, Process,
};
use std::os::raw::{c_int, c_void};
use std::sync::OnceLock;

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

    static CELL: OnceLock<Gum> = OnceLock::new();
    let gum = CELL.get_or_init(|| Gum::obtain());

    let mut interceptor = Interceptor::obtain(gum);
    let mut listener = OpenListener {};
    
    let process = Process::obtain(gum);
    let modules = process.enumerate_modules();
    for module in modules {
        println!(
            "{}@{:#x}/{:#x}",
            module.name(),
            module.range().base_address(),
            module.range().size()
        );
    }

    let open = Module::find_global_export_by_name("open").unwrap();
    interceptor.attach(open, &mut listener).unwrap();
}
