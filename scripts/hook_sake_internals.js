
const allocationSize = 0xd000;
const moduleName = "libandroid-sake-lib.so";

var moduleBase = 0;

const hooks = [
	{
		name: "aes_encrypt_round_internal",
		signature: "F0 B5 03 AF 2D E9 00 0F 8C B0 00 92 D0 E9 00 A0",
		paramLengths: [0x10, 0x10, 0x10],
	//	print_retval: false, 
	},
	{
		name: "maybe_sign",
		signature: "F0 B5 03 AF 2D E9 00 0F E1 B0 05 46 25 48 00 2D",
		paramLengths: [0x10, 0x10, 0x10, 0x10]
	},

	
];

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
	const range = {
		base: moduleBaseAddress,
		size: allocationSize
	};

	console.log("\n\n****** reattach ******");
	console.log("Scanning memory region from: " + range.base + " size: " + range.size);

	moduleBase = moduleBaseAddress;

	hooks.forEach(hook => {
		let matchCount = 0;
		Memory.scan(range.base, range.size, hook.signature, {
			onMatch: function (address, size) {
				if (matchCount > 0) {
					console.log(`[!] Multiple matches found for ${hook.name}, skipping hook.`);
					return;
				}
				matchCount++;
			//	console.log(`[+] Pattern for ${hook.name} found at: ` + address.toString());
				attachToFunction(ptr(address).add(1), hook);
			},
			onError: function (reason) {
				console.log("[!] Error scanning memory: " + reason);
			},
			onComplete: function () {
			//	console.log(`[+] Scan complete for ${hook.name}`);
			}
		});
	});
});

function isProbablyPointer(value) {
	try {
		let addr = ptr(value);
		/*
		if ((addr.shr(28).toInt32() !== moduleBase.shr(28).toInt32())) {
			//	console.log("not a pointer due to shit msb");
			return false;
		}
		
		if (addr.toInt32() >= allocationSize) {
			console.log("not a pointer due to shit size");
			return false;
		}*/
		Memory.readU8(addr); // Try reading a byte to ensure it's a valid address
		return true;
	} catch (e) {
		//	console.log("not a pointer due to mem read failed");
		return false;
	}
}

function attachToFunction(targetAddress, hook) {
	console.log(`[+] Attaching to function ${hook.name} at: ` + targetAddress);


	/*
	Interceptor.attach(targetAddress, function (args) { 
		console.log(`${hook.name} at ${targetAddress} called!`);

		for (let i = 0; i < hook.paramLengths.length; i++) {
			if (isProbablyPointer(args[i])) {
				console.log(`  [arg${i}] = *0x`, hexdump(args[i], { length: hook.paramLengths[i], header:false, ansi:false}));
			} else {
				console.log(`  [arg${i}] = ${args[i]}`);
			}
		}
		console.log(`\n\n`);


	});


	Interceptor.attach(targetAddress, {
		onEnter(args) {
		  console.log("onEnter!");
		},
		onLeave(retval) {
			console.log("onLeave!");
		}
	  });



	*/


	Interceptor.attach(targetAddress, {
		onEnter(args) {
			console.log(hook.name + ":");
	
			this.localArgs = [];
	
			for (let i = 0; i < hook.paramLengths.length; i++) {
				this.localArgs.push(args[i]);
	
				if (isProbablyPointer(args[i])) {
					console.log(`  [arg${i}] before = *0x`, hexdump(args[i], { length: hook.paramLengths[i], header: false, ansi: false }));
				} else {
					console.log(`  [arg${i}] before = ${args[i]}`);
				}
			}
			console.log(`\n\n`);
		},
		onLeave(retval) {
	
			if (isProbablyPointer(retval)) {
				console.log("  retval = *0x", hexdump(retval, { length: 8, header: false, ansi: false }));
			} else {
				console.log(`  retval = ${retval}`);
			}
	
			for (let i = 0; i < hook.paramLengths.length; i++) {
	
				if (this.localArgs[i] instanceof NativePointer) {  // Loop through localArgs
					if (isProbablyPointer(this.localArgs[i])) {
						console.log(`  [arg${i}] after = *0x`, hexdump(this.localArgs[i], { length: hook.paramLengths[i], header: false, ansi: false }));
					} else {
						console.log(`  [arg${i}] after = ${this.localArgs[i]}`);
					}
				} else {
					console.log("not a native pointer");
				}
			}
		}
	});
	

}
