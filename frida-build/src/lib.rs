/*
 * Copyright © 2021 S Rubenstein
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use std::env;
use std::fs::File;
use std::io;
use std::path::Path;

use tar::Archive;
use xz::read::XzDecoder;

pub fn download_and_use_devkit(kind: &str, version: &str) {
    let mut target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir_path = Path::new(&out_dir);

    if target_arch == "aarch64" {
        target_arch = "arm64".to_string();
    }

    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();

    let (lib_prefix, lib_suffix) = if os == "windows" {
        ("", "") // technically, suffix is .lib, but cargo adds it, apparently.
    } else {
        ("", "")
    };

    let devkit_name = format!("frida-{}-devkit-{}-{}-{}", kind, version, os, target_arch,);

    let devkit_path = out_dir_path.join(&devkit_name);
    let devkit_tar = out_dir_path.join(format!("{}.tar.xz", &devkit_name));

    println!("Checking for devkit at {:?}", &devkit_path);

    if !devkit_path.is_dir() {
        if !devkit_tar.is_file() {
            let frida_url = format!(
                "https://github.com/frida/frida/releases/download/{}/{}.tar.xz",
                version, devkit_name,
            );

            println!(
                "cargo:warning=Frida {} devkit not found, downloading from {}...",
                kind, &frida_url,
            );
            // Download devkit
            let mut resp =
                reqwest::blocking::get(&frida_url).expect("devkit download request failed");
            let mut out = File::create(&devkit_tar).expect("failed to create devkit tar file");
            io::copy(&mut resp, &mut out).expect("failed to copy devkit tar content");
        }
        println!("unpacking {:#?}", &devkit_tar);
        let tar_xz = File::open(&devkit_tar).expect("failed to open devkit tar.xz for extraction");
        let tar = XzDecoder::new(tar_xz);
        let mut archive = Archive::new(tar);
        archive
            .unpack(&out_dir_path)
            .expect("cannot extract the devkit tar.gz");
    }
    let lib_path = out_dir_path.join(format!("{}frida-{}{}", lib_prefix, kind, lib_suffix));

    if kind == "core" {
        println!("Got lib at {:?}", lib_path);
    }

    println!("cargo:include={}", out_dir.to_string_lossy());

    println!("cargo:rustc-link-search={}", out_dir.to_string_lossy());
    println!(
        "cargo:rustc-link-lib=static={}frida-{}{}",
        lib_prefix, kind, lib_suffix,
    );
}
