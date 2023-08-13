#![no_std]
#![no_main]
#![allow(internal_features)]
#![feature(alloc_error_handler, lang_items)]

use {
    core::{alloc::Layout, panic::PanicInfo},
    frida_gum::Gum,
    libc::{_exit, abort},
    libc_print::libc_println as println,
    static_alloc::Bump,
};

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("panic: {:#?}", info);
    unsafe {
        abort();
    }
}

#[lang = "eh_personality"]
#[no_mangle]
extern "C" fn rust_eh_personality() {
    println!("rust_eh_personality");
    unsafe {
        abort();
    }
}

#[alloc_error_handler]
fn alloc_error_handler(layout: Layout) -> ! {
    println!("alloc_error_handler: {:#?}", layout);
    unsafe {
        abort();
    }
}

pub const HEAP_SIZE: usize = 32 << 10;

#[global_allocator]
static ALLOC: Bump<[u8; HEAP_SIZE]> = Bump::uninit();

#[no_mangle]
extern "C" fn main() {
    println!("NOSTD START");
    let gum = unsafe { Gum::obtain() };
    println!("gum: {:p}", &gum);
    println!("NOSTD DONE");
    unsafe { _exit(0) };
}
