use ctor::ctor;
use frida_gum::{
    interceptor::{Interceptor, InvocationContext, ProbeListener},
    Gum, Module,
};
use std::{sync::OnceLock, thread};

#[derive(Default, Debug)]
struct OpenProbeListener;

fn sleep_loop(secs: usize) {
    for _ in 0..secs {
        thread::sleep(std::time::Duration::from_millis(1000));
    }
}

// I just made this function to test Process.enumerate_threads
impl ProbeListener for OpenProbeListener {
    fn on_hit(&mut self, _context: InvocationContext<'_>) {
        // println!("on_hit: open()");

        let mut tasks = Vec::new();
        for _ in 0..3 {
            let task = thread::spawn(|| sleep_loop(3));
            tasks.push(task);
        }
    }
}

#[ctor]
fn init() {
    static CELL: OnceLock<Gum> = OnceLock::new();
    let gum = CELL.get_or_init(|| Gum::obtain());

    let handle = thread::spawn(move || {
        let mut interceptor = Interceptor::obtain(gum);

        // Load libc and find the export for open()
        let module = Module::load(gum, "libc.so.6");
        let open = module.find_export_by_name("open").unwrap();

        let mut listener = OpenProbeListener;
        interceptor.attach_instruction(open, &mut listener).unwrap();
    });

    let process = frida_gum::Process::obtain(&gum);

    println!("Process Information");
    println!("-------------------");
    println!(" - ID: {}", process.id);
    println!(" - Platform {:?}", process.platform);
    println!(" - Code signing policy: {:?}", process.code_signing_policy);
    println!(" - Main module: {:?}", process.main_module);
    println!(" - Current directory: {}", process.current_dir());
    println!(" - Home directory: {}", process.home_dir());
    println!(" - Tmp directory: {}", process.tmp_dir());
    println!(
        " - Is debugger attached? {}",
        process.is_debugger_attached()
    );
    println!(" - Current thread ID: {}", process.current_thread_id());

    println!(" - Enumerate threads:");
    let threads = process.enumerate_threads();
    for thread in threads {
        println!("   - {:?}", thread);
    }

    println!(" - Enumerate modules:");
    let ranges = process.enumerate_modules();
    for module in ranges {
        println!("   - {:?}", module);
    }

    println!(" - Enumerate ranges (rwx):");
    let ranges = process.enumerate_ranges(frida_gum::PageProtection::ReadWriteExecute);
    for range in ranges {
        println!("   - {:#?}", range);
    }

    handle.join();
}
