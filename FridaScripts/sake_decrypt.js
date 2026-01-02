/*
	usage: frida -U -f com.medtronic.diabetes.minimedmobile.eu -l bypass.js -l sake_decrypt.js
	for MiniMed™ Mobile_1.2.1_apkcombo.com.apk
	sha256sum: 7b5e1b98e0ff3ce1ba71f1a51c1826fe93bbdb32e9f585e3f228ae2cf538caf8

	info: - tested and working as of 2024.03.27.
		  - use an unmodified apk, the authenticity of the binary is chekced via play integrity
		  	and medtronic will return an INVALID key
		  	i dont know if this is a security feature or they return different key types based on the 
		  	application hashes/signatures, but it wont work
		  - this older app version may use the old safetynet api, which will be shut down in the near future
		  	so this may not work
		  - you have to hide the app in magisk denylist and install the play integrity fix magisk addon
		  	check your integrity status via gr.nikolasspyr.integritycheck, you should pass "device" and "basic" checks
		  	you may need to clear the app's data & cache, because the minimed app can remember if you have a modified phone
	  	  - this script is a bit unstable and may cause random crashes when entering the main screen, but the decryption
	  	  	will be already done at that point
		  
*/
var hooked = false;
var classname = 'com.medtronic.minimed.ngpsdk.connect.pump.sake.a.h';

function hookDecryptor() {
	hooked = true;
	console.log("[+] SakeKeysDecryptor hooked")
	Java.perform(function() {
		var SakeKeysDecryptor = Java.use(classname);
		SakeKeysDecryptor.a.overload('[B', 'java.lang.String', 'java.lang.String').implementation = function(bArr, str, str2) {
			console.log(`[+] decryption routine called: encrypted data=${byteArrayToHexString(bArr)}, hardcoded_key (in base64)=${str}, client_secret (or app id)=${str2}`);
			let result = this.a(bArr, str, str2);
			console.log(`[+] decrypted data = ${byteArrayToHexString(result)}`);
			return result;
		};
	});
}

function byteArrayToHexString(byteArray) {
	return Array.from(byteArray, function(byte) {
		return ('0' + (byte & 0xFF).toString(16)).slice(-2);
	}).join('');
}

function waitForClass() {
	Java.perform(function() {
		Java.choose(classname, {
			onMatch: function(instance) {
				if (!hooked){
					hookDecryptor();
				} 
			},
			onComplete: function() {
				setTimeout(waitForClass, 10);
			}
		});
	});
}

console.log("\nstarted");
waitForClass();