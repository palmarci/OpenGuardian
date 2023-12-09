var baseTeneo = 'com.medtronic.teneo.';
var socketTeneo = "com.medtronic.securerepositories.internal.websocket.";
var sakepath = 'com.medtronic.minimed.sake.SAKE_KEY_DATABASE_S';
//https://stackoverflow.com/questions/69668741/setting-a-member-in-current-class-using-frida
//https://stackoverflow.com/questions/69503358/unable-to-retrieve-value-from-interface-using-frida

function bytes_to_hexstr(array) {
    var result = '';
    if (array == null) {
        return '<null>';
    }
    for (var i = 0; i < array.length; ++i) result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
    return result;
};


setTimeout(function () {

	Java.perform(function () {
		var request = Java.use(baseTeneo + "HttpConnectionRequest");
		var response = Java.use(baseTeneo + "HttpConnectionResponse");
		var socket_sender = Java.use(socketTeneo + "WebSocketCommunicator");
		var socket_receiver = Java.use(socketTeneo + "WebSocketCommunicator$EchoWebSocketListener");
		var sake = Java.use(sakepath);

		request.$init.overload('java.net.URL', baseTeneo + 'HttpMethod', 'java.util.Map', 'java.util.Map', baseTeneo + 'bodybuilders.BodyBuilder').implementation = function (url, method, headers, data, bodyBuilder) {
			console.log("cert called");
			var toret = this.init.overload('java.net.URL', baseTeneo + 'HttpMethod', 'java.util.Map', 'java.util.Map', baseTeneo + 'bodybuilders.BodyBuilder').call(this, url, method, headers, data, bodyBuilder)
			console.log(toret);
			return toret;
		}
		request.$init.overload('java.net.URL', baseTeneo + 'HttpMethod', 'java.util.Map', 'java.util.Map', baseTeneo + 'bodybuilders.BodyBuilder', 'java.security.cert.X509Certificate').implementation = function (url, method, headers, data, bodyBuilder, cert) {
			console.log("nocert called");
			var toret = this.init.overload('java.net.URL', baseTeneo + 'HttpMethod', 'java.util.Map', 'java.util.Map', baseTeneo + 'bodybuilders.BodyBuilder', 'java.security.cert.X509Certificate').call(this, url, method, headers, data, bodyBuilder, cert)
			console.log(toret);
			return toret;
		}

		response.$init.overload("java.net.HttpURLConnection").implementation = function (conn) {
			console.log("response init called");
			var toret = this.init.overload("java.net.HttpURLConnection").call(this, conn);
			return toret;
		}

	
		socket_receiver.onMessage.overload("okhttp3.WebSocket", "java.lang.String").implementation = function (socket, str) {
			console.log(">>", str);
			var toret = this.onMessage.overload("okhttp3.WebSocket", "java.lang.String").call(this, socket, str);
			return toret;
		}

		socket_receiver.onMessage.overload("okhttp3.WebSocket", "okio.ByteString").implementation = function (socket, bytestr) {
			console.log(">>", bytes_to_hexstr(msg));
			var toret = this.onMessage.overload("okhttp3.WebSocket", "okio.ByteString").call(this, socket, bytestr);
			return toret;
		}
		

		socket_sender.sendByteStringMessage.overload("[B").implementation = function (msg) {
			console.log("<<", bytes_to_hexstr(msg));
			var toret = this.sendByteStringMessage.overload("[B").call(this, msg);
			return toret;
		}
		socket_sender.sendStringMessage.overload("java.lang.String").implementation = function (msg) {
			console.log("<< ", msg);
			var toret = this.sendStringMessage.overload("java.lang.String").call(this, msg);
			return toret;
		}
		
		sake.$init.overload("long", "boolean").implementation = function(j, z) {
			var toret = this.sendStringMessage.overload("long", "boolean").call(this, j,z);
			console.log("init key db called:", j,z, "toret: ", toret);
			return toret;

		}

	})
}, 0);