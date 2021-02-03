extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    println!(
        "cargo:rustc-link-search={}",
        env::var("CARGO_MANIFEST_DIR").unwrap()
    );

    println!("cargo:rustc-link-lib=frida-core");
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rustc-link-lib=resolv");

    let bindings = bindgen::Builder::default()
        .header("frida-core.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate_comments(false)
        .generate()
        .unwrap();

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .unwrap();
}
