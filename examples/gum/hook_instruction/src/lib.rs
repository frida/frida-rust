use ctor::ctor;
use frida_gum::{
    interceptor::{Interceptor, InvocationContext, ProbeListener},
    Gum, Module,
};
use std::sync::OnceLock;
#[derive(Default, Debug)]
struct OpenProbeListener;

impl ProbeListener for OpenProbeListener {
    fn on_hit(&mut self, _context: InvocationContext) {
        println!("on_hit: open()");
    }
}

#[ctor]
fn init() {
    static CELL: OnceLock<Gum> = OnceLock::new();
    let gum = CELL.get_or_init(|| Gum::obtain());
    let mut interceptor = Interceptor::obtain(gum);
    let module = Module::from_gum(gum);
    let open = module.find_export_by_name(None, "open").unwrap();
    let mut listener = OpenProbeListener;
    interceptor.attach_instruction(open, &mut listener).unwrap();
}
