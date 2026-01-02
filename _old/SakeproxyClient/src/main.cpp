#include <Arduino.h>
#include <WiFi.h>
#include "config.h"
#include "utils.h"
#include "sake.h"

void wifi_connect()
{
	int wifi_counter = 0;
	const int max_tries = 10;
	do_log("connecting to wifi...");
	WiFi.begin(ssid, password);
	while (true)
	{
		delay(1000);
		wifi_counter++;
		auto status = WiFi.status();
		do_log("[main] try #" + String(wifi_counter) + ", wifi status= " + String(status));

		if (status == WL_CONNECTED)
		{
			do_log("[main] " + String("Connected to WiFi \"") + String(ssid) + String("\""));
			return;
		}

		if (wifi_counter > max_tries)
		{
			do_log("[main] wifi connection failed after " + String(max_tries) + " max tries, entering loop...");
			while (true)
			{
				__asm("nop");
			}
		}
	}
}

void setup()
{
	// setup
	Serial.begin(115200);
	wifi_connect();

	// close library first - unknown state on the server side
	sake_close();

	// read status
	String status = sake_get_status();
	do_log("[main] status after library close: " + status);
	
	// open key db
	int db_len = 0;
	int resp_len = 0;
	String test_db = "5fe5928308010230f0b50df613f2e429c8c5e8713854add1a69b837235a3e974304d8055ccb397838b90823c73236d6a83dcc9db3a2a939ff16145ca4169ef93a7fa39b20962b05e57413bff8b3d61fce0dfef2c43b326";
	byte* keydb = hexStringToByteArray(test_db, db_len);
	bool resp = sake_init(keydb, db_len, resp_len);
	do_log("[main] key DB open succeeded? " + String(resp));
	do_log("[main] status after db open: " + sake_get_status());

	// TODO: examples for handshake, encrypt, decrypt 
}

void loop()
{
	__asm("nop");
}
