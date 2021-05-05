/*
 * Copyright © 2021 S Rubenstein
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use std::env;
use std::path::Path;
use std::process::Command;

pub fn download_and_use_devkit(kind: &str, version: &str) {
    let mut target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    if target_arch == "aarch64" {
        target_arch = "arm64".to_string();
    }

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

    println!(
        "cargo:rustc-link-lib=frida-{}-{}-{}",
        kind,
        env::var("CARGO_CFG_TARGET_OS").unwrap(),
        target_arch
    );
}
