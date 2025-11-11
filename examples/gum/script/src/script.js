console.log("[*] Hello, world!");

/* Test a message containing some bytes */
send("message", [0x10, 0x20, 0x30, 0x40]);

const test1 = Module.getGlobalExportByName("test1");
console.log(`[*] test1: ${test1}`);

const test2 = Module.getGlobalExportByName("test2");
console.log(`[*] test2: ${test2}`);

/* Call test1 from our script */
const test1fn = new NativeFunction(test1, "void", ["int"]);
test1fn(123);

/* Patch test2 from our script */
Interceptor.attach(test2, {
    onEnter: (args) => {
        console.log("Entering test2");
        args[0] = ptr(654);
        console.log("Leaving test2");
    },
});

console.log("Script Complete");