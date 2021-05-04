# frida-gum [![docs.rs](https://docs.rs/frida-gum/badge.svg)](https://docs.rs/frida-gum)

Rust bindings for [Frida Gum](https://github.com/frida/frida-gum).

## Before Installing

- Build Frida or download the [14.2.17 package](https://github.com/frida/frida/releases/tag/14.2.17)
- Move `frida-gum.h` and `libfrida-gum.a` into `/usr/local/include` and `/usr/local/lib` (or a more appropriate folder that Rust can detect)

Or: use the `auto-download` feature to install Frida. This requires
`wget` and `tar` to be present in the Rust-accessible `PATH`.

See the documentation for usage instructions.
