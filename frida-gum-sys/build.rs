extern crate bindgen;

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn download_and_uncompress_devkit(kind: &str, version: &str, target_arch: &String) {
    let cwd = env::current_dir().unwrap().to_string_lossy().to_string();

    let devkit = format!(
        "{}/frida-{}-devkit-{}-{}-{}",
        env::var("CARGO_MANIFEST_DIR").unwrap(),
        kind,
        version,
        env::var("CARGO_CFG_TARGET_OS").unwrap(),
        target_arch
    );
    let devkit_path = Path::new(&devkit);
    let devkit_tar = format!("{}.tar.xz", devkit);

    let out_dir_path = Path::new(&cwd);

    if !devkit_path.is_dir() {
        if !Path::new(&devkit_tar).is_file() {
            println!(
                "cargo:warning=Frida {} devkit not found, downloading...",
                kind
            );
            // Download devkit
            Command::new("wget")
                .arg("-c")
                .arg(format!(
                        "https://github.com/frida/frida/releases/download/{}/frida-{}-devkit-{}-{}-{}.tar.xz",
                        version,
                        kind,
                        version,
                        env::var("CARGO_CFG_TARGET_OS").unwrap(),
                        target_arch))
                .arg("-O")
                .arg(&devkit_tar)
                .status()
                .unwrap();
        }
        Command::new("tar")
            .current_dir(&out_dir_path)
            .arg("-xvf")
            .arg(&devkit_tar)
            .status()
            .unwrap();
        Command::new("mv")
            .current_dir(&out_dir_path)
            .arg(format!("libfrida-{}.a", kind))
            .arg(format!(
                "libfrida-{}-{}-{}.a",
                kind,
                env::var("CARGO_CFG_TARGET_OS").unwrap(),
                target_arch
            ))
            .status()
            .unwrap();
    }
}

fn main() {
    let mut target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    if target_arch == "aarch64" {
        target_arch = "arm64".to_string();
    }
    download_and_uncompress_devkit("gum", "14.2.3", &target_arch);

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

    println!(
        "cargo:rustc-link-lib=frida-gum-{}-{}",
        env::var("CARGO_CFG_TARGET_OS").unwrap(),
        target_arch
    );
    #[cfg(not(target = "android"))]
    println!("cargo:rustc-link-lib=pthread");

    let bindings = bindgen::Builder::default()
        .header("frida-gum.h")
        .header("event_sink.h")
        .header("invocation_listener.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate_comments(false)
        .generate()
        .unwrap();

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .unwrap();

    #[cfg(feature = "event-sink")]
    cc::Build::new()
        .file("event_sink.c")
        .opt_level(3)
        .warnings_into_errors(true)
        .compile("event_sink");

    #[cfg(feature = "invocation-listener")]
    cc::Build::new()
        .file("invocation_listener.c")
        .warnings_into_errors(true)
        .compile("invocation_listener");
}
