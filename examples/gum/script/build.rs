fn main() {
    println!("cargo:rustc-link-arg=-rdynamic");
    
    #[cfg(target_os = "macos")]
    println!("cargo:rustc-link-lib=dylib=c++");
}
