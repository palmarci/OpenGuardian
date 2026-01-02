#include "keydb.h"

static char* keydb;

static SakeKeyDatabaseOpen_t SakeKeyDatabaseOpen = NULL;

char* keydb_init(void* handle, char* p_rawkeydb, int keydb_size) {

    SakeKeyDatabaseOpen = (SakeKeyDatabaseOpen_t)load_function(handle, "Java_com_medtronic_minimed_sake_SakeJNI_Sake_1KeyDatabase_1Open");

    keydb = malloc(KEY_DB_SIZE);
	printf("[+] Key database allocated at %p\n", keydb);

	int retval = SakeKeyDatabaseOpen(0xAAAAAAAA, 0xBBBBBBBB, keydb, 0xDDDDDDDD, p_rawkeydb, keydb_size);
	if (retval != 1) {
        printf("[-] failed to open keydb: %x\n", retval);
    }

    return keydb;
    
}