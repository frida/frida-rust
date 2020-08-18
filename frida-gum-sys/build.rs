extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=event_sink.c");
    println!("cargo:rerun-if-changed=event_sink.h");

    println!(
        "cargo:rustc-link-search={}",
        env::var("CARGO_MANIFEST_DIR").unwrap()
    );
    println!("cargo:rustc-link-lib=frida-gum");
    println!("cargo:rustc-link-lib=pthread");

    let bindings = bindgen::Builder::default()
        .header("frida-gum.h")
        .header("event_sink.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .unwrap();

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .unwrap();

    cc::Build::new()
        .file("event_sink.c")
        // .warnings_into_errors(true)
        .compile("event_sink");
}
