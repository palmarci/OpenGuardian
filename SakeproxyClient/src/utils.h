#ifndef UTILS
#define UTILS

#include <Arduino.h>

String byteArrayToHexString(byte *byteArray, int length);
byte *hexStringToByteArray(String input_str, int &return_length);
void do_log(String msg);

#endif /* UTILS */
