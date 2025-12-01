Example to show all available `Process` functions.

```sh
cargo build --release

LD_PRELOAD=../../../target/release/libprocess_check.so cat /tmp/test.txt
```
