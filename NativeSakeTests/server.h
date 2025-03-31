#ifndef SERVER
#define SERVER

#include <jni.h>
#include <stdbool.h>

#include "common.h"

typedef void (*SakeServer_Init_t)(JNIEnv *env, jclass thiz, jobject unused1, jlong sake_server, jobject unused2, jlong p_key_db);
typedef uint32_t* (*SakeNewServer_t)(JNIEnv *env,jclass thiz);
typedef uint32_t (*SakeServerHandshake_t)(JNIEnv *env,jclass thiz, jlong p_sake_server, jobject unused1, jlong p_in_msg, jobject unused2, jlong p_out_msg, jobject unused3); 

void server_print_status();
void server_init(void *hLib, void* key_db);
int server_handshake(SakeMsg* msg_in, SakeMsg* msg_out);

#endif /* SERVER */
