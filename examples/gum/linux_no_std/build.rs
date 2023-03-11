fn main() {
    // By default a no_std target will not link against libc. We want libc for
    // our target since FRIDA requires it and also we need to use the function
    // `abort`
    println!("cargo:rustc-link-arg=-lc");
    // Also link against the library containing the exception handlers for GCC.
    println!("cargo:rustc-link-arg=-lgcc_eh");
}
