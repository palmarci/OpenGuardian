#ifndef SAKE
#define SAKE

#include <Arduino.h>

String sake_get_status();
byte* sake_init(byte *key_db, int key_db_length, int &resp_len);

#endif /* SAKE */
