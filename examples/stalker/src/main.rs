#![feature(c_variadic)]
use frida_gum as gum;
use frida_gum::stalker::{Stalker, Transformer};
use lazy_static::lazy_static;

lazy_static! {
    static ref GUM: gum::Gum = gum::Gum::obtain();
}

struct SampleState {
    counter: i32,
}

fn main() {
    let stalker = Stalker::new(&GUM);
    let mut state = SampleState { counter: 0 };

    let transformer = Transformer::from_callback(&GUM, |iterator, output| {
        println!("Transformed...");
        state.counter += 1;
    });

    let transformer2 = Transformer::from_callback(&GUM, |iterator, output| {
        println!("Transformed again...");
        state.counter += 2;
    });
}
