```sh
# Enter the example directory
cd examples/core/inject_lib_blob/

# Build the library and the executable
cargo build --release --lib
cargo build --release

# Execute it
../../../target/release/inject_lib_blob <PID>

# Examples:
../../../target/release/inject_lib_blob 4178767
../../../target/release/inject_lib_blob $(ps -ax | grep Twitter | grep -v "grep" | awk '{print $1}')
```
