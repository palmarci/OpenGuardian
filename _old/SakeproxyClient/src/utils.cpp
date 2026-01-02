#include <Arduino.h>

String byteArrayToHexString(byte *byteArray, int length)
{
	String hexString = "";
	for (int i = 0; i < length; i++)
	{
		if (byteArray[i] < 0x10)
		{
			hexString += "0";
		}
		hexString += String(byteArray[i], HEX);
	}
	return hexString;
}

byte *hexStringToByteArray(String input_str, int &return_length)
{
	input_str.replace("0x", "");
	input_str.replace(" ", "");
	return_length = input_str.length() / 2;
	byte *byteArray = new byte[return_length];
	for (int i = 0; i < return_length; i++)
	{
		String byteString = input_str.substring(i * 2, (i * 2) + 2);
		byteArray[i] = (byte)strtol(byteString.c_str(), NULL, 16);
	}
	return byteArray;
}

void do_log(String msg)
{
	Serial.println(msg.c_str());
}