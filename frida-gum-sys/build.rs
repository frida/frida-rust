/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_vendor = env::var("CARGO_CFG_TARGET_VENDOR").unwrap();
    #[cfg(feature = "event-sink")]
    {
        println!("cargo:rerun-if-changed=event_sink.c");
        println!("cargo:rerun-if-changed=event_sink.h");
    }

    #[cfg(feature = "invocation-listener")]
    {
        println!("cargo:rerun-if-changed=invocation_listener.c");
        println!("cargo:rerun-if-changed=invocation_listener.h");
        println!("cargo:rerun-if-changed=probe_listener.c");
        println!("cargo:rerun-if-changed=probe_listener.h");
    }

    #[cfg(feature = "stalker-observer")]
    {
        println!("cargo:rerun-if-changed=stalker_observer.c");
        println!("cargo:rerun-if-changed=stalker_observer.h");
    }

    #[cfg(feature = "stalker-params")]
    {
        println!("cargo:rerun-if-changed=stalker_params.c");
        println!("cargo:rerun-if-changed=stalker_params.h");
    }

    println!(
        "cargo:rustc-link-search={}",
        env::var("CARGO_MANIFEST_DIR").unwrap()
    );

    #[cfg(feature = "auto-download")]
    let include_dir = {
        use frida_build::download_and_use_devkit;
        download_and_use_devkit("gum", include_str!("FRIDA_VERSION").trim())
    };

    #[cfg(not(feature = "auto-download"))]
    println!("cargo:rustc-link-lib=frida-gum");

    if target_os != "android" && (target_os == "linux" || target_vendor == "apple") {
        println!("cargo:rustc-link-lib=pthread");
    }

    let bindings = bindgen::Builder::default().use_core();

    #[cfg(feature = "auto-download")]
    let bindings = bindings.clang_arg(format!("-I{include_dir}"));

    #[cfg(not(feature = "auto-download"))]
    let bindings = if std::env::var("DOCS_RS").is_ok() {
        bindings.clang_arg("-Iinclude")
    } else {
        bindings
    };

    let bindings = bindings
        .header_contents("gum.h", "#include \"frida-gum.h\"")
        .header("event_sink.h")
        .header("invocation_listener.h")
        .header("probe_listener.h")
        .header("stalker_observer.h")
        .header("stalker_params.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .blocklist_type("GumChainedPtr64Rebase")
        .blocklist_type("GumChainedPtrArm64eRebase")
        .blocklist_type("_GumChainedPtr64Rebase")
        .blocklist_type("_GumChainedPtrArm64eRebase")
        .generate_comments(false)
        .layout_tests(false)
        .generate()
        .unwrap();

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .unwrap();

    #[cfg(feature = "event-sink")]
    {
        let mut builder = cc::Build::new();

        #[cfg(feature = "auto-download")]
        #[allow(unused_mut)]
        let mut builder = builder.include(include_dir.clone());

        #[cfg(not(feature = "auto-download"))]
        let builder = if std::env::var("DOCS_RS").is_ok() {
            builder.include("include")
        } else {
            &mut builder
        };

        builder
            .file("event_sink.c")
            .opt_level(3)
            .compile("event_sink");
    }

    #[cfg(feature = "invocation-listener")]
    {
        let mut builder = cc::Build::new();

        #[cfg(feature = "auto-download")]
        #[allow(unused_mut)]
        let mut builder = builder.include(include_dir.clone());

        #[cfg(not(feature = "auto-download"))]
        let builder = if std::env::var("DOCS_RS").is_ok() {
            builder.include("include")
        } else {
            &mut builder
        };

        builder
            .file("invocation_listener.c")
            .opt_level(3)
            .compile("invocation_listener");

        let mut builder = cc::Build::new();

        #[cfg(feature = "auto-download")]
        #[allow(unused_mut)]
        let mut builder = builder.include(include_dir.clone());

        #[cfg(not(feature = "auto-download"))]
        let builder = if std::env::var("DOCS_RS").is_ok() {
            builder.include("include")
        } else {
            &mut builder
        };
        builder
            .file("probe_listener.c")
            .opt_level(3)
            .compile("probe_listener");
    }

    #[cfg(feature = "stalker-observer")]
    {
        let mut builder = cc::Build::new();

        #[cfg(feature = "auto-download")]
        #[allow(unused_mut)]
        let mut builder = builder.include(include_dir.clone());

        #[cfg(not(feature = "auto-download"))]
        let builder = if std::env::var("DOCS_RS").is_ok() {
            builder.include("include")
        } else {
            &mut builder
        };

        builder
            .file("stalker_observer.c")
            .opt_level(3)
            .compile("stalker_observer");
    }

    #[cfg(feature = "stalker-params")]
    {
        let mut builder = cc::Build::new();

        #[cfg(feature = "auto-download")]
        #[allow(unused_mut)]
        let mut builder = builder.include(include_dir);

        #[cfg(not(feature = "auto-download"))]
        let builder = if std::env::var("DOCS_RS").is_ok() {
            builder.include("include")
        } else {
            &mut builder
        };

        builder
            .file("stalker_params.c")
            .opt_level(3)
            .compile("stalker_params");
    }

    if target_os == "windows" {
        for lib in [
            "dnsapi", "iphlpapi", "psapi", "winmm", "ws2_32", "advapi32", "crypt32", "gdi32",
            "kernel32", "ole32", "secur32", "shell32", "shlwapi", "user32",
        ] {
            println!("cargo:rustc-link-lib=dylib={lib}");
        }
    }
}
