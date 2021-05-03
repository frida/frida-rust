/*
 * Copyright © 2021 S Rubenstein
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use std::env;
use std::fs;
use std::fs::File;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use tar::Archive;
use xz::read::XzDecoder;

pub fn download_and_use_devkit(kind: &str, version: &str) {
    let mut target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    if target_arch == "aarch64" {
        target_arch = "arm64".to_string();
    }

    let cwd = env::current_dir().unwrap().to_string_lossy().to_string();

    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();

    let (lib_prefix, lib_suffix) = if os == "windows" {
        ("", ".lib")
    } else {
        ("lib", ".a")
    };

    let devkit = format!(
        "{}/frida-{}-devkit-{}-{}-{}",
        env::var("CARGO_MANIFEST_DIR").unwrap(),
        kind,
        version,
        os,
        target_arch
    );
    let devkit_path = Path::new(&devkit);
    let devkit_tar = format!("{}.tar.xz", devkit);

    let out_dir_path = Path::new(&cwd);

    if !devkit_path.is_dir() {
        if !Path::new(&devkit_tar).is_file() {
            let frida_url = format!(
                "https://github.com/frida/frida/releases/download/{}/frida-{}-devkit-{}-{}-{}.tar.xz",
                version,
                kind,
                version,
                env::var("CARGO_CFG_TARGET_OS").unwrap(),
                target_arch);

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

        let mut src_a = PathBuf::from(&out_dir_path);
        src_a.push(format!("{}frida-{}{}", lib_prefix, kind, lib_suffix));
        let mut dst_a = PathBuf::from(&out_dir_path);
        dst_a.push(format!(
            "{}frida-{}-{}-{}{}",
            lib_prefix,
            kind,
            env::var("CARGO_CFG_TARGET_OS").unwrap(),
            target_arch,
            lib_suffix
        ));
        fs::rename(src_a, dst_a).expect("failed to move libfrida");
    }

    println!(
        "cargo:rustc-link-lib=frida-{}-{}-{}",
        kind,
        env::var("CARGO_CFG_TARGET_OS").unwrap(),
        target_arch
    );
}
