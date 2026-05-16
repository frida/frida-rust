Example showing how to precompile a JavaScript script into bytecode with
`Session::compile_script` and later load it through
`Session::create_script_from_bytes`.

The bytecode is runtime-specific — both the compile and the load step here use
`ScriptRuntime::QJS`. A blob produced for QJS will not load under V8.

What it does:

1. Attaches to itself (`device.attach(0)`).
2. Compiles a tiny `console.log` script to QJS bytecode.
3. Writes the bytecode to `compiled.bin`, then reads it back to demonstrate the
   "ship a `.bin` artifact" workflow.
4. Loads the bytecode with `create_script_from_bytes` and runs it.

Run it:

```
cargo run -p compile_script
```

Expected output (sizes will vary by Frida version):

```
[*] Frida version: 17.x.x
[*] Device: Local System
[*] Attached to self (pid=0)
[*] Compiled 256 bytes of bytecode
[*] Wrote bytecode to compiled.bin
[*] Read 256 bytes back from disk
- Log(MessageLog { level: Info, payload: "Hello from precompiled bytecode! pid=12345" })
[*] Script loaded from bytecode
[*] Script unloaded
[*] Session detached
```
