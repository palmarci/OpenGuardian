// credits:
// https://github.com/frida/frida/issues/310#issuecomment-462447292
// https://raw.githubusercontent.com/optiv/blemon/master/frida/blemon.js

if (Java.available) {
    Java.perform(function() {
        console.log("\n");
        hook_ble_standalone(); // hopefully
        hook_sake_minimed_v121();
    });
}

function hook_sake_guardian_vUnknown() { // i dont know remember what version :=(
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