extern crate bindgen;

use std::env;
use std::path::{PathBuf};

#[cfg(feature  = "autodownload")]
use frida_build::download_and_use_devkit;

fn main() {
    println!(
        "cargo:rustc-link-search={}",
        env::var("CARGO_MANIFEST_DIR").unwrap()
    );

    #[cfg(feature = "autodownload")]
    download_and_use_devkit("core", include_str!("../FRIDA_VERSION").trim());

    #[cfg(not(feature = "autodownload"))]
    println!("cargo:rustc-link-lib=frida-core");

    #[cfg(not(target = "android"))]
    println!("cargo:rustc-link-lib=pthread");
    #[cfg(not(target = "android"))]
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
