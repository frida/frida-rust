/* This example is in the public domain */

use frida::Frida;
use lazy_static::lazy_static;

lazy_static! {
    static ref FRIDA: Frida = unsafe { Frida::obtain() };
}

fn main() {
    println!("Hello, world!");
}
