Example to showing how to use `script.list_exports()`.
Once ran you should expect an output similar to the next one:

```
[*] Frida version: 16.4.8
[*] Device name: Local System
[*] Attached to PID 7581
- Log(MessageLog { level: Info, payload: "Logging message from JS" })
- Log(MessageLog { level: Warning, payload: "Warning message from JS" })
- Log(MessageLog { level: Debug, payload: "Debug message from JS" })
- Log(MessageLog { level: Error, payload: "Error message from JS" })
[*] Script loaded.
Some(["increment", "getvalue"])
Some(["increment", "getvalue"])
Some(["increment", "getvalue"])
[*] Script unloaded
[*] Session detached
Exiting...
```
