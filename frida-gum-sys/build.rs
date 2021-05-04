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
    download_and_use_devkit("gum", include_str!("FRIDA_VERSION").trim());

    #[cfg(not(feature = "auto-download"))]
    println!("cargo:rustc-link-lib=frida-gum");

    if env::var("CARGO_CFG_TARGET_OS").unwrap() != "android" {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        println!("cargo:rustc-link-lib=pthread");
    }

    let bindings = bindgen::Builder::default().header("frida-gum.h");
    #[cfg(feature = "event-sink")]
    let bindings = bindings.header("event_sink.h");
    #[cfg(feature = "invocation-listener")]
    let bindings = bindings.header("invocation_listener.h");
    let bindings = bindings
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate_comments(false)
        .generate()
        .unwrap();

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
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
    build.opt_level(3).compile("frida-gum-sys");
}
