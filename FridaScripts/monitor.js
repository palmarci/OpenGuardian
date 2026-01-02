// credits:
// https://github.com/frida/frida/issues/310#issuecomment-462447292
// https://raw.githubusercontent.com/optiv/blemon/master/frida/blemon.js

if (Java.available) {
	Java.perform(function() {
		console.log("\n");
		hook_ble_standalone(); // hopefully
	  //  hook_sake_minimed_v121();
		hook_sake_minimed_v221();
	});
}

let first_memmove = true;

function hook_sake_guardian_vUnknown() { // i dont know remember what version but probably guardian 134
	var sake_class_name = "e.g.f.a.d.a.w";
	var bt_class_name = "e.g.g.a.a.f.b.e$a";
	let sake_class = Java.use(sake_class_name);
	sake_class.h.overload('[B').implementation = function(arg0) {
		var to_return = this.h.overload('[B', ).call(this, arg0);
		log("sake", "open_key_db", [arg0, to_return]);
		return to_return;
	};
	sake_class.d.overload('[B').implementation = function(arg0) {
		var to_return = this.d.overload('[B', ).call(this, arg0);
		log("sake", "handshake", [arg0, to_return]);
		return to_return;
	};
	sake_class.b.overload('[B').implementation = function(arg0) {
		var to_return = this.b.overload('[B', ).call(this, arg0);
		log("sake", "decrypt", [arg0, to_return]);
		return to_return;
	};
	sake_class.a.overload('[B').implementation = function(arg0) {
		var to_return = this.a.overload('[B', ).call(this, arg0);
		log("sake", "encrypt", [arg0, to_return]);
		return to_return;
	};
}

function hook_sake_minimed_v121() {

	let SakeServerImpl = Java.use("com.medtronic.minimed.ngpsdk.connect.pump.sake.i");

	/*
	// openkeydb
	let SakeShit = Java.use("com.medtronic.minimed.sake.i");

	// i dont know what to hook tbh... idc
	SakeShit["a"].overload('com.medtronic.minimed.sake.h', '[B').implementation = function(c2947h, bArr) {
		console.log(`SakeShit.m12406a is called: c2947h=${c2947h}, bArr=${bArr}`);
		this["a"](c2947h, bArr);

	//handshake - the two null byte arrays at the beginning seem to crash the apk, oh well idc...
	SakeServerImpl["a"].overload('[B').implementation = function(bArr) {
		console.log(`SakeServerImpl.mo11909a is called: bArr=${bArr}`);
		let result = this["a"](bArr);
		console.log(`SakeServerImpl.mo11909a result=${result}`);
		return result;
	};
	*/

	//encrypt - secureaftersending
	SakeServerImpl["b"].overload('[B').implementation = function(bArr) {
		let result = this["b"](bArr);
		log("sake", "encrypt", [bArr, result]);
		return result;
	};

	//decrypt - unsecureaftersending
	SakeServerImpl["c"].overload('[B').implementation = function(bArr) {
		let result = this["c"](bArr);
		log("sake", "decrypt", [bArr, result]);
		return result;
	};
}

function hook_sake_minimed_v221() {

	  // Hook into the "b" method of the "Sake" class
	let Sake = Java.use("com.medtronic.minimed.sake.c");

	Sake["b"].implementation = function (sake_key_database_s, swigTypeCharPtr, j10) {

		console.log(`Sake.KeyDbOpen is called: sake_key_database_s=${sake_key_database_s}, swigTypeCharPtr=${swigTypeCharPtr}, j10=${j10}`);

		let temp_ptr = Java.use("com.medtronic.minimed.sake.a")["a"](swigTypeCharPtr);
		let actualDataPointer = ptr(temp_ptr.toString())
		console.log(`Pointer to the actual data: ${actualDataPointer}`);

		if (actualDataPointer) {
			console.log(hexdump(actualDataPointer, {header: false, ansi:false, length:j10}));
		}

		let result = this["b"](sake_key_database_s, swigTypeCharPtr, j10);

		console.log(`Sake.KeyDbOpen result=${result}`);

		return result;
	};




	let SakeServerImpl = Java.use("com.medtronic.minimed.ngpsdk.connect.pump.sake.d");
	SakeServerImpl["decrypt"].implementation = function (bArr) {
	//    console.log(`SakeServerImpl.decrypt is called: bArr=${bArr}`);
		let result = this["decrypt"](bArr);
	 //   console.log(`SakeServerImpl.decrypt result=${result}`);
	  log("sake", "decrypt", [bArr, result]);

		return result;
	};

   // let SakeServerImpl = Java.use("com.medtronic.minimed.ngpsdk.connect.pump.sake.d");
	SakeServerImpl["encrypt"].implementation = function (bArr) {
	   // console.log(`SakeServerImpl.encrypt is called: bArr=${bArr}`);
		let result = this["encrypt"](bArr);
		log("sake", "encrypt", [bArr, result]);

	//    console.log(`SakeServerImpl.encrypt result=${result}`);
		return result;
	};

   // let SakeServerImpl = Java.use("com.medtronic.minimed.ngpsdk.connect.pump.sake.d");
	SakeServerImpl["b"].implementation = function (bArr) {
	   // console.log(`SakeServerImpl.mo10902b is called: bArr=${bArr}`);
		let result = this["b"](bArr);
	 //   console.log(`SakeServerImpl.mo10902b result=${result}`);
		log("sake", "handshake", [bArr, result]);

		return result;
	};

}


function hook_ble_standalone() {
	var BTGattCB = Java.use("android.bluetooth.BluetoothGattCallback");
	BTGattCB.$init.overload().implementation = function() {
		//console.log("[+] BluetoothGattCallback constructor called from " + this.$className);
		const NewCB = Java.use(this.$className);
		NewCB.onCharacteristicRead.implementation = function(g, c, s) {
			const retVal = NewCB.onCharacteristicRead.call(this, g, c, s);
			var uuid = c.getUuid().toString();
			log("bt", "read", [uuid, c.getValue()]);
			return retVal;
		};
		NewCB.onCharacteristicWrite.implementation = function(g, c, s) {
			const retVal = NewCB.onCharacteristicWrite.call(this, g, c, s);
			var uuid = c.getUuid().toString();
			log("bt", "write", [uuid, c.getValue()]);
			return retVal;
		};
		NewCB.onCharacteristicChanged.implementation = function(g, c) {
			const retVal = NewCB.onCharacteristicChanged.call(this, g, c);
			var uuid = c.getUuid().toString();
			log("bt", "notify", [uuid, c.getValue()]);
			return retVal;
		};
		return this.$init();
	};
}

function bytes_to_hexstr(array) {
	var result = '';
	if (array == null) {
		return '<null>';
	}
	for (var i = 0; i < array.length; ++i) result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
	return result;
};

function log(maintype, subtype, parameters = []) {
	var ts = Date.now();
	var text = ts + "," + maintype + "," + subtype + ",";
	parameters.forEach(element => {
		if (element != null) {
			var type = typeof(element);
			if (type == "boolean" || type == "string") {
				text += element;
			} else {
				text += bytes_to_hexstr(element);
			}
		} else {
			text += "null";
		}
		text += ";";
	});
	var lastChar = text.slice(-1);
	if (lastChar == ';') {
		text = text.slice(0, -1);
	}
	console.log(text);
}