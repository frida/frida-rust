extern crate bindgen;

use std::env;
use std::path::{PathBuf, Path};
use std::process::Command;

fn download_and_uncompress_devkit(kind: &str, version: &str, target_arch: &String) {
    let cwd = env::current_dir().unwrap().to_string_lossy().to_string();

    let devkit = format!(
        "{}/frida-{}-devkit-{}-{}-{}",
        env::var("CARGO_MANIFEST_DIR").unwrap(),
        kind,
        version,
        env::var("CARGO_CFG_TARGET_OS").unwrap(),
        target_arch);
    let devkit_path = Path::new(&devkit);
    let devkit_tar = format!("{}.tar.xz", devkit);

    let out_dir_path = Path::new(&cwd);

    if !devkit_path.is_dir() {
        if !Path::new(&devkit_tar).is_file() {
            println!("cargo:warning=Frida {} devkit not found, downloading...", kind);
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
            .arg(format!("libfrida-{}-{}-{}.a", kind, env::var("CARGO_CFG_TARGET_OS").unwrap(), target_arch))
            .status()
            .unwrap();
    }
}

fn main() {
    let mut target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    if target_arch == "aarch64" {
        target_arch = "arm64".to_string();
    }
    download_and_uncompress_devkit("core", "14.2.3", &target_arch);

    println!(
        "cargo:rustc-link-search={}",
        env::var("CARGO_MANIFEST_DIR").unwrap()
    );
    println!("cargo:rustc-link-lib=frida-core-{}-{}", env::var("CARGO_CFG_TARGET_OS").unwrap(), target_arch);
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
