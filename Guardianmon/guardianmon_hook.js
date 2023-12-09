/*

Credits: https://github.com/optiv/blemon/blob/master/frida/blemon.js

*/

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
            var type = typeof (element);
            if (type == "boolean" || type == "string") {
                text += element;
            }
            else {
                text += bytes_to_hexstr(element);
            }
        }
        else {
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
var isGuardian = true;


if (isGuardian) {

    var sake_class_name = "e.g.f.a.d.a.w";
    var bt_class_name = "e.g.g.a.a.f.b.e$a";

    Java.perform(function () {
        let sake_class = Java.use(sake_class_name);
        var bt_class = Java.use(bt_class_name);

        console.log("\nStarting in Guardian mode")

        /*
        sake_class.$init.overload('[B').implementation = function (arg0) {
            var to_return = this.init.overload('[B',).call(this, arg0);
            log("sake", "constructor");
            return to_return;
        };
        */
        sake_class.h.overload('[B').implementation = function (arg0) {
            var to_return = this.h.overload('[B',).call(this, arg0);
            log("sake", "open_key_db", [arg0, to_return]);
            return to_return;
        };
        sake_class.d.overload('[B').implementation = function (arg0) {
            var to_return = this.d.overload('[B',).call(this, arg0);
            log("sake", "handshake", [arg0, to_return]);
            return to_return;
        };
        sake_class.b.overload('[B').implementation = function (arg0) {
            var to_return = this.b.overload('[B',).call(this, arg0);
            log("sake", "decrypt", [arg0, to_return]);
            return to_return;
        };
        sake_class.a.overload('[B').implementation = function (arg0) {
            var to_return = this.a.overload('[B',).call(this, arg0);
            log("sake", "encrypt", [arg0, to_return]);
            return to_return;
        };

        bt_class.onCharacteristicRead.implementation = function (g, c, s) {
            const retVal = bt_class.onCharacteristicRead.call(this, g, c, s);
            var uuid = c.getUuid().toString();
            log("bt", "read", [uuid, c.getValue()]);
            return retVal;
        };
        bt_class.onCharacteristicWrite.implementation = function (g, c, s) {
            const retVal = bt_class.onCharacteristicWrite.call(this, g, c, s);
            var uuid = c.getUuid().toString();
            log("bt", "write", [uuid, c.getValue()]);
            return retVal;
        };
        bt_class.onCharacteristicChanged.implementation = function (g, c) {
            const retVal = bt_class.onCharacteristicChanged.call(this, g, c);
            var uuid = c.getUuid().toString();
            log("bt", "notify", [uuid, c.getValue()]);
            return retVal;
        };
    });


} else {
    var sake_class_name = "com.medtronic.minimed.ngpsdk.connect.pump.sake.d"; // search for SakeServerImpl
    var bt_class_name = "a7.g$b";

    Java.perform(function () {
        let sake_class = Java.use(sake_class_name);
        var bt_class = Java.use(bt_class_name);

        console.log("\nStarting in Minimed mode")

        /*
        sake_class.$init.overload('[B').implementation = function (arg0) {
            var to_return = this.init.overload('[B',).call(this, arg0);
            log("sake", "constructor");
            return to_return;
        };
        */

        sake_class.b.overload('[B').implementation = function (arg0) {
            var to_return = this.b.overload('[B',).call(this, arg0);
            log("sake", "handshake", [arg0, to_return]);
            return to_return;
        };
        sake_class.decrypt.overload('[B').implementation = function (arg0) {
            var to_return = this.decrypt.overload('[B',).call(this, arg0);
            log("sake", "decrypt", [arg0, to_return]);
            return to_return;
        };
        sake_class.encrypt.overload('[B').implementation = function (arg0) {
            var to_return = this.encrypt.overload('[B',).call(this, arg0);
            log("sake", "encrypt", [arg0, to_return]);
            return to_return;
        };

        bt_class.onCharacteristicRead.implementation = function (g, c, s) {
            const retVal = bt_class.onCharacteristicRead.call(this, g, c, s);
            var uuid = c.getUuid().toString();
            log("bt", "read", [uuid, c.getValue()]);
            return retVal;
        };
        bt_class.onCharacteristicWrite.implementation = function (g, c, s) {
            const retVal = bt_class.onCharacteristicWrite.call(this, g, c, s);
            var uuid = c.getUuid().toString();
            log("bt", "write", [uuid, c.getValue()]);
            return retVal;
        };
        bt_class.onCharacteristicChanged.implementation = function (g, c) {
            const retVal = bt_class.onCharacteristicChanged.call(this, g, c);
            var uuid = c.getUuid().toString();
            log("bt", "notify", [uuid, c.getValue()]);
            return retVal;
        };
    });

}