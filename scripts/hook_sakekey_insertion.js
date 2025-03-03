// maybe also for v2.2.1 

function hexToBytes(hex) {
    let bytes = [];
    for (let c = 0; c < hex.length; c += 2) bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}

var real_sake_key = hexToBytes("5fe5928308010230f0b50df613f2e429c8c5e8713854add1a69b837235a3e974304d8055ccb397838b90823c73236d6a83dcc9db3a2a939ff16145ca4169ef93a7fa39b20962b05e57413bff8b3d61fce0dfef2c43b326")

setTimeout(function() {

    console.log("[i] script started")

    Java.perform(function() {
        let SakeKeysDecryptor = Java.use("ne.h");
        SakeKeysDecryptor["a"].implementation = function(bArr, str, str2) {
            console.log(`SakeKeysDecryptor.check_and_decrypt is called: bArr=${bArr}, str=${str}, str2=${str2}`);
            let result = this["a"](bArr, str, str2);
            console.log(`SakeKeysDecryptor.check_and_decrypt result=${result}`);
            return result;
        };

        var eu = Java.use('com.medtronic.securerepositories.internal.utility.EncryptionUtility');
        eu.decryptCbcAes.overload('java.lang.String', 'java.lang.String').implementation = function(key, data) {
            console.log("\n[i] decryptCbcAes called with params: key = " + key, "\ndata=" + data);
            var toret = this.decryptCbcAes.overload('java.lang.String', 'java.lang.String').call(this, key, data)
            return toret;
        }
        
        let q = Java.use("io.reactivex.q");
        q["b"].implementation = function() {
            console.log(`q.try_and_decrypt_sake_key_event is called, returning guardian's sake key `);
            //  let result = this["b"]();
            // console.log(`q.try_and_decrypt_sake_key_event result=${result}`);
            return real_sake_key;
        };
    })
}, 0);