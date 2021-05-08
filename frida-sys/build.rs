/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    println!(
        "cargo:rustc-link-search={}",
        env::var("CARGO_MANIFEST_DIR").unwrap()
    );

    #[cfg(feature = "auto-download")]
    let include_dir = {
        use frida_build::download_and_use_devkit;
        download_and_use_devkit("core", include_str!("FRIDA_VERSION").trim())
    };

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

    let bindings = bindgen::Builder::default();

    #[cfg(feature = "auto-download")]
    let bindings = bindings.clang_arg(format!("-I{}", include_dir));

    #[cfg(not(feature = "auto-download"))]
    let bindings = if std::env::var("DOCS_RS").is_ok() {
        bindings.clang_arg("-Iinclude")
    } else {
        bindings
    };

    let bindings = bindings
        .header_contents("core.h", "#include \"frida-core.h\"")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate_comments(false)
        .generate()
        .unwrap();

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .unwrap();

    #[cfg(target_os = "windows")]
    &[
        "dnsapi", "iphlpapi", "psapi", "winmm", "ws2_32", "advapi32", "crypt32", "gdi32",
        "kernel32", "ole32", "secur32", "shell32", "shlwapi", "user32",
    ]
    .iter()
    .for_each(|lib| {
        println!("cargo:rustc-link-lib=dylib={}", lib);
    });
}
