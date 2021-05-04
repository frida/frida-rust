/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

extern crate bindgen;

use std::env;
use std::path::PathBuf;

#[cfg(feature = "auto-download")]
use frida_build::download_and_use_devkit;

fn main() {
    println!(
        "cargo:rustc-link-search={}",
        env::var("CARGO_MANIFEST_DIR").unwrap()
    );

    #[cfg(feature = "auto-download")]
    download_and_use_devkit("core", include_str!("FRIDA_VERSION").trim());

    #[cfg(not(feature = "auto-download"))]
    println!("cargo:rustc-link-lib=frida-core");

    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=resolv");
    }

    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=framework=AppKit");
    }

    let header = "frida-core.h";

    let bindings = bindgen::Builder::default();

    // If we auto-download, the header files are in the build directory.
    let bindings = if cfg!(feature = "auto-download") {
        let out_dir = env::var_os("OUT_DIR").unwrap();
        bindings.header(
            PathBuf::from(out_dir)
                .join(header)
                .as_os_str()
                .to_string_lossy(),
        )
    } else {
        bindings.header(header)
    };

    let bindings = bindings
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate_comments(false)
        .generate()
        .unwrap();

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .unwrap();
}
