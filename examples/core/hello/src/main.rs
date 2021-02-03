use frida::Frida;
use lazy_static::lazy_static;

lazy_static! {
    static ref FRIDA: Frida = Frida::obtain();
}

fn main() {
    println!("Hello, world!");
}
