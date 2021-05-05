frida-rust
==========

Rust bindings for [Frida](http://www.frida.re/).

## Install

- Build Frida, or download the devkits for your system (see `frida-gum` or `frida-core` README for verison)
- For crate installation:
    - Move the frida-gum and frida-core devkits into `rustc-link-search`, e.g.: `/usr/local/{include, lib}` on Unix
- For local development:
    - Move the frida-gum devkit into `frida-gum-sys`, and the frida-core devkit into `frida-sys` and `cargo build` in the root
