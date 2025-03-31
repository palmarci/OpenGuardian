#ifndef KEYDB
#define KEYDB

#include <jni.h>
#include <stdbool.h>

typedef bool (*SakeKeyDatabaseOpen_t)(JNIEnv *, jclass, jlong, jobject, jlong, jlong);

char* keydb_init(void* handle, char* p_rawkeydb, int keydb_size);

#define KEY_DB_SIZE 8

#endif /* KEYDB */
