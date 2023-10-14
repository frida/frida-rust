use frida_gum::{MemoryAccessMonitor, MemoryRange, NativePointer};
use std::sync::atomic::AtomicUsize;

static HIT: AtomicUsize = AtomicUsize::new(0);
const BLK_SIZE: usize = 0x3;

fn main() {
    let block =
        unsafe { std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(BLK_SIZE, 1)) };
    let range = MemoryRange::new(NativePointer(block as *mut _), BLK_SIZE);
    let gum = unsafe { frida_gum::Gum::obtain() };
    let mam = MemoryAccessMonitor::new(
        &gum,
        vec![range],
        frida_gum::PageProtection::Write,
        true,
        |_, details| {
            println!(
                "[monitor callback] hit: {}, details: {}",
                HIT.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                details
            );
        },
    );
    if let Ok(()) = mam.enable() {
        unsafe {
            for i in 0..BLK_SIZE {
                println!("writing at block + {:#x}", i);
                let ptr = block.add(i);
                std::ptr::write(ptr, 0);
            }
        }
        mam.disable();
    } else {
        println!("failed to enable memory access monitor");
    }
}
