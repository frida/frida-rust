# frida [![docs.rs](https://docs.rs/frida/badge.svg)](https://docs.rs/frida)

Rust bindings for [Frida](https://frida.re).

## Before Installing

- Build Frida or download the [14.2.14 package](https://github.com/frida/frida/releases/tag/14.2.14)
- Move `frida-core.h` and `libfrida-core.a` into `/usr/local/include` and `/usr/local/lib` (or a more appropriate folder that Rust can detect)

Or: use the `auto-download` feature to install Frida. This requires
`wget` and `tar` to be present in the Rust-accessible `PATH`.

See the documentation for usage instructions.
