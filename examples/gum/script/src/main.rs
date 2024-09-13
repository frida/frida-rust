/* This example is in the public domain */

use frida_gum::{self as gum, Backend};
use gum::{Gum, Script};
use lazy_static::lazy_static;

lazy_static! {
    static ref GUM: Gum = Gum::obtain();
}

#[no_mangle]
extern "C" fn test1(value: u32) {
    println!("TEST: {}", value);
}

#[no_mangle]
extern "C" fn test2(value: u32) -> u32 {
    value
}

fn callback(s: &str, b: &[u8]) {
    println!("callback - msg: {} bytes: {:?}", s, b);
}

pub fn main() {
    println!("Script example!");

    let payload = include_str!("script.js");
    println!("payload: {}", payload);

    let backend = Backend::obtain_v8(&GUM);
    let script = Script::load(&backend, "script.js", payload, Some(callback)).unwrap();

    let t2 = test2(987);
    println!("TEST2: {}", t2);

    /* Run the loop to continue handling callbacks */
    script.run_event_loop();
}
