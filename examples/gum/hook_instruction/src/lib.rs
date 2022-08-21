use ctor::ctor;
use frida_gum::{
    interceptor::{InstructionInvocationListener, Interceptor, InvocationContext},
    Gum, Module,
};
use lazy_static::lazy_static;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
}
#[derive(Default, Debug)]
struct OpenInstructionListener;

impl InstructionInvocationListener for OpenInstructionListener {
    fn callback(&mut self, _context: InvocationContext) {
        println!("callback: open()");
    }
}

#[ctor]
fn init() {
    let mut interceptor = Interceptor::obtain(&GUM);
    let open = Module::find_export_by_name(None, "open").unwrap();
    let mut listener = OpenInstructionListener::default();
    interceptor.attach_instruction(open, &mut listener);
}
