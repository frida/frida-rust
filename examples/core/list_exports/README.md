Example to showing how to use `script.list_exports()`.
Once ran you should expect an output similar to the next one:

```
[*] Frida version: 16.4.8
[*] Device name: Local System
[*] Attached to PID 1124009
- Log(MessageLog { level: Info, payload: "Logging message from JS" })
- Log(MessageLog { level: Warning, payload: "Warning message from JS" })
- Log(MessageLog { level: Debug, payload: "Debug message from JS" })
- Log(MessageLog { level: Error, payload: "Error message from JS" })
- Error(MessageError { description: "ReferenceError: 'sdfsa' is not defined", stack: "ReferenceError: 'sdfsa' is not defined\n    at <eval> (/script1.js:18)", file_name: "/script1.js", line_number: 18, column_number: 1 })
[*] Script loaded.
Some(["increment", "getvalue"])
Some(["increment", "getvalue"])
Some(["increment", "getvalue"])
[*] Script unloaded
[*] Session detached
Exiting...
```
