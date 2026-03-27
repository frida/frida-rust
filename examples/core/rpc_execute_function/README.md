Example to showing how to execute a JavaScript Frida function from Rust using `script.exports`.
Once ran you should expect an output similar to the next one:

```
[*] Frida version: 17.5.1
[*] Device name: Local System
[*] Script loaded.
["increment", "nIncrement", "getValue", "sumVals", "bye"]
[*] Info: "globalVar incremented by 1"
[*] Info: "globalVar incremented by 2"
js_global_var: 3
[*] Info: "Bye Potato"
total: 10
This is an error from JS: Error on the JavaScript side: unable to find method 'NonExistentFunc'
[*] Script unloaded
[*] Session detached
Exiting...
```
