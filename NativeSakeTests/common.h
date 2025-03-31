#ifndef COMMON
#define COMMON

#include <stdint.h>
#include <stdbool.h>

#define SAKE_LIBRARY_PATH "/data/local/tmp/sakeloader/libandroid-sake-lib.so"
#define HOOK_RANDOM false


typedef struct {
    char data[0x20];
    uint32_t size;
} SakeMsg;


#endif /* COMMON */
