#include <Arduino.h>
#include <WiFi.h>
#include "config.h"
#include "utils.h"
#include "sake.h"

void setup()
{
	Serial.begin(115200);
	WiFi.begin(ssid, password);

	do_log("Connecting to WiFi...");
	while (WiFi.status() != WL_CONNECTED)
	{
		delay(1000);
	}
	do_log(String("Connected to WiFi \"") + String(ssid) + String("\""));
	sake_get_status();
}

void loop()
{
}
