#include <HTTPClient.h>
#include "config.h"
#include "utils.h"
#include <ArduinoJson.h>

String performAction(String action, byte *request_data, int request_data_len, bool &success)
{
	HTTPClient http;
	String request_hex = "null";
	if (request_data == 0 || request_data_len == 0) {
		do_log("[sake] " + action + " warning: sending \"null\" as request!");
	} else {
		request_hex = byteArrayToHexString(request_data, request_data_len);
	}

	http.begin(serverName);
	http.addHeader("Content-Type", "application/json");

	String jsonPayload = "{\"action\": \"" + action + "\", \"data\":\"" + request_hex + "\"}";
	int httpResponseCode = http.POST(jsonPayload);

	if (httpResponseCode > 0)
	{
		// get response
		String response = http.getString();
		DynamicJsonDocument doc(response.length());
		deserializeJson(doc, response);
		String response_data = doc["data"];

		// get success
		String success_str = doc["success"];
		success_str.toLowerCase();
		success = false;
		if (success_str.equals("true")) {
			success = true;
		} 

		// log, cleanup, return
		if (response_data.equals("")) {
			response_data = "<empty>";
		}
		String log_msg = String("[sake] ") + action + String(" response: code=") + String(httpResponseCode) + String(", success=") + success + String(", data=") + String(response_data);
		do_log(log_msg);
		http.end();
		return response_data;
	}
	else
	{
		do_log("[sake] invalid response from server:" + String(httpResponseCode));
	}

	// Free resources
	http.end();
	return "";
}

String sake_get_status()
{
	bool unused;
	return performAction("status", 0, 0, unused);
}

bool sake_init(byte *key_db, int key_db_length, int &resp_len)
{
	bool toret;
	String resp = performAction("init", key_db, key_db_length, toret);
	return toret;
}

bool sake_close()
{
	bool toret;
	performAction("close", 0, 0, toret);
	return toret;
}

byte* sake_encrypt(byte *data, int data_len, int &resp_len) {
	bool success;
	String resp_str = performAction("encrypt", data, data_len, success);
	byte* resp = hexStringToByteArray(resp_str, resp_len);
	return resp;

}

byte* sake_decrypt(byte *data, int data_len, int &resp_len) {
	bool success;
	String resp_str = performAction("decrypt", data, data_len, success);
	byte* resp = hexStringToByteArray(resp_str, resp_len);
	return resp;
}

byte* sake_handshake(byte *data, int data_len, int &resp_len) {
	bool success;
	String resp_str = performAction("handshake", data, data_len, success);
	if (success) { // return may be a string containing the java exception
		byte* resp = hexStringToByteArray(resp_str, resp_len);
		return resp;
	} else {
		return 0;
	}
}