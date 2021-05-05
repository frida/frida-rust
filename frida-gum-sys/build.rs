/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

extern crate bindgen;

use std::path::PathBuf;
use std::{env, fs};

#[cfg(feature = "auto-download")]
use frida_build::download_and_use_devkit;

fn main() {
    let out_path = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    #[cfg(feature = "event-sink")]
    {
        println!("cargo:rerun-if-changed=event_sink.c");
        println!("cargo:rerun-if-changed=event_sink.h");
    }

    #[cfg(feature = "invocation-listener")]
    {
        println!("cargo:rerun-if-changed=invocation_listener.c");
        println!("cargo:rerun-if-changed=invocation_listener.h");
    }

    println!(
        "cargo:rustc-link-search={}",
        env::var("CARGO_MANIFEST_DIR").unwrap()
    );

    #[cfg(feature = "auto-download")]
    download_and_use_devkit("core", include_str!("FRIDA_VERSION").trim());
    #[cfg(feature = "auto-download")]
    download_and_use_devkit("gum", include_str!("FRIDA_VERSION").trim());

    #[cfg(not(feature = "auto-download"))]
    println!("cargo:rustc-link-lib=frida-gum");

    if env::var("CARGO_CFG_TARGET_OS").unwrap() != "android" {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        println!("cargo:rustc-link-lib=pthread");
    }

    let header = "frida-gum.h";

    let bindings = bindgen::Builder::default();

    // If we auto-download, the header files are in the build directory.
    let bindings = if cfg!(feature = "auto-download") {
        let header_dir = out_path.join(header);
        let header_path = header_dir.as_os_str().to_string_lossy();
        println!("bindgen for autodownloaded header file {}", &header_path);
        bindings.header(header_path)
    } else {
        bindings.header(header)
    };

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    fs::copy("event_sink.h", &out_path.join("event_sink.h")).unwrap();
    fs::copy(
        "invocation_listener.h",
        &out_path.join("invocation_listener.h"),
    )
    .unwrap();

    #[cfg(feature = "event-sink")]
    let bindings = bindings.header(out_path.join("event_sink.h").to_string_lossy());
    #[cfg(feature = "invocation-listener")]
    let bindings = bindings.header(out_path.join("invocation_listener.h").to_string_lossy());
    let bindings = bindings
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate_comments(false)
        .generate()
        .unwrap();

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .unwrap();

    #[cfg(any(feature = "event-sink", feature = "invocation-listener"))]
    let mut build = cc::Build::new();
    #[cfg(not(windows))]
    let build = build.warnings_into_errors(true);
    #[cfg(feature = "event-sink")]
    let build = build.file("event_sink.c");
    #[cfg(feature = "invocation-listener")]
    let build = build.file("invocation_listener.c");
    #[cfg(any(feature = "event-sink", feature = "invocation-listener"))]
    build
        .include(out_path)
        .opt_level(3)
        .compile("frida-gum-sys");

    #[cfg(windows)]
    &[
        "dnsapi", "iphlpapi", "psapi", "winmm", "ws2_32", "advapi32", "crypt32", "gdi32",
        "kernel32", "ole32", "secur32", "shell32", "shlwapi", "user32",
    ]
    .iter()
    .for_each(|lib| {
        println!("cargo:rustc-link-lib=dylib={}", lib);
    });
}
