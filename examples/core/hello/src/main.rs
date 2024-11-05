/* This example is in the public domain */

use frida::Frida;
use std::sync::LazyLock;

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

fn main() {
    println!("Hello, world!");
}
