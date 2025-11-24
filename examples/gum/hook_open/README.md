## hook-open

This is an example on how to hook "open" libc function using frida-rust.

### Linux

To test this on Linux, run a binary that calls "open" with this library LD_PRELOAD-ed:

```sh
LD_PRELOAD=../../../target/release/libhook_open.so cat /tmp/test
```

### MacOS

Find a binary that supports `DYLD_INSERT_LIBRARIES` and call it

```sh
DYLD_INSERT_LIBRARIES=hook_openlib.so somebinary"
```
