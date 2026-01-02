#ifndef SAKE
#define SAKE

#include <Arduino.h>

String sake_get_status();
bool sake_init(byte *key_db, int key_db_length, int &resp_len);
bool sake_close();
byte* sake_encrypt(byte *data, int data_len, int &resp_len);
byte* sake_decrypt(byte *data, int data_len, int &resp_len);
byte* sake_handshake(byte *data, int data_len, int &resp_len);

#endif /* SAKE */
