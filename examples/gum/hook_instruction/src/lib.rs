use ctor::ctor;
use frida_gum::{
    interceptor::{ProbeListener, Interceptor, InvocationContext},
    Gum, Module,
};
use lazy_static::lazy_static;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
}
#[derive(Default, Debug)]
struct OpenProbeListener;

impl ProbeListener for OpenProbeListener {
    fn on_hit(&mut self, _context: InvocationContext) {
        println!("on_hit: open()");
    }
}

#[ctor]
fn init() {
    let mut interceptor = Interceptor::obtain(&GUM);
    let open = Module::find_export_by_name(None, "open").unwrap();
    let mut listener = OpenProbeListener::default();
    interceptor.attach_instruction(open, &mut listener);
}
