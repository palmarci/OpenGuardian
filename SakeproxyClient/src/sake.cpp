#include <HTTPClient.h>
#include "config.h"
#include "utils.h"
#include <ArduinoJson.h>

String performAction(String action, byte *request_data, int request_data_len)
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
		String response = http.getString();
		DynamicJsonDocument doc(response.length());
		deserializeJson(doc, response);
		String response_data = doc["data"];
		String success = doc["success"];
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
	return performAction("status", 0, 0);
}

byte* sake_init(byte *key_db, int key_db_length, int &resp_len)
{
	String resp = performAction("init", key_db, key_db_length);
	byte *byteArray = hexStringToByteArray(resp, resp_len);
	return byteArray;
}