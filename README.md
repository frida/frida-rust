frida-rust
==========

Rust bindings for [Frida](http://www.frida.re/).

## Install

- Build Frida, or download the devkit for your system
- For crate installation:
    - Move the devkit into `rustc-link-search`, e.g.: `/usr/local/{include, lib}` on Unix
- For local development:
    - Move the devkit into `frida-gum-sys` and `cargo build` in the root

## Progress

- [x] Stalker
    - [x] EventSink
    - [x] Transformer
- [ ] Interceptor
    - [ ] InvocationContext
