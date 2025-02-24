const ghidraImageBase = 0x00010000;
const moduleName = "libandroid-sake-lib.so";

function waitForModuleAsync(name, callback) {
    const checkInterval = 100;
    const interval = setInterval(() => {
        const baseAddress = Module.findBaseAddress(name);
        if (baseAddress !== null) {
            clearInterval(interval);
            console.log(`[+] Module ${name} loaded at ${baseAddress}`);
            callback(baseAddress);
        }
    }, checkInterval);
}

waitForModuleAsync(moduleName, (moduleBaseAddress) => {
    const maybe_calc_cmac = moduleBaseAddress.add(0x00015f04 - ghidraImageBase);
    console.log("fncptr = " + maybe_calc_cmac);
    console.log(Instruction.parse(ptr(maybe_calc_cmac)).toString());
    
    Interceptor.attach(maybe_calc_cmac, {
        onEnter(args) {
            console.log("[+] Entered maybe_calc_cmac");
            for (let i = 0; i < 4; i++) { // Adjust if more args are expected
                let isPointer = args[i].isPointer();
                console.log(`[arg${i}] (Pointer: ${isPointer})`, hexdump(args[i], {length: 64}));
            }
            console.log("[+] Traceback:");
            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join("\n"));
        },
        onLeave(retval) {
            console.log("[+] Leaving maybe_calc_cmac");
            let isPointer = retval.isPointer();
            console.log(`[retval] (Pointer: ${isPointer})`, hexdump(retval, {length: 64}));
        }
    });
});
