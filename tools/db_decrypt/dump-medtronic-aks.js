Java.perform(function() {
	var encryptionUtilityClass = Java.use("com.medtronic.securerepositories.internal.utility.EncryptionUtility");
	var Gson = Java.use("com.google.gson.Gson");
	var aliases = ["DATABASE_KEY", "APP_LOGS_DATABASE_KEY", "APP_ANALYTICS_DATABASE_KEY", "SAKE"];
	for (var i = 0; i < aliases.length; i++) {
		var alias = aliases[i];
		var privateKey = encryptionUtilityClass.getPrivateKey.overload('java.lang.String').call(encryptionUtilityClass, alias);
		console.log("\n\ntrying " + alias + " ...");
		var publicKey = encryptionUtilityClass.getPublicKey.overload('java.lang.String').call(encryptionUtilityClass, alias);
		var gson = Gson.$new();
		var privateKeyJson = gson.toJson(privateKey);
		var publicKeyJson = gson.toJson(publicKey);

		if (privateKeyJson != null) {
			console.log(privateKeyJson);
		}
		var publicKeyJson = gson.toJson(publicKey);
		if (publicKeyJson != null) {
			console.log(publicKeyJson);
		}
	}
});