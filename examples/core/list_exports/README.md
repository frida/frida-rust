Example to showing how to use `script.list_exports()`.
Once ran you should expect an output similar to the next one:

```
[*] Frida version: 17.5.1
[*] Device name: Local System
[*] Info: "Logging message from JS"
[*] Warning: "Warning message from JS"
[*] Debug: "Debug message from JS"
[*] Error: "Error message from JS"
[*] Send: String("Send message from JS")
[*] Send: String("Send message with data"), Data: [1, 2, 3]
[*] Script loaded.
["increment", "getvalue"]
["increment", "getvalue"]
["increment", "getvalue"]
[*] Script unloaded
[*] Session detached
Exiting...
```
