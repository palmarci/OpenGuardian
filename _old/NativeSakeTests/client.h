#ifndef CLIENT
#define CLIENT

#include <jni.h>
#include <stdbool.h>

#include "common.h"

typedef void (*SakeClient_Init_t)(JNIEnv *env, jclass thiz, jobject unused1, jlong sake_client, jobject unused2, jlong p_key_db);
typedef uint32_t* (*SakeNewClient_t)(JNIEnv *env,jclass thiz);
typedef uint32_t (*SakeClientHandshake_t)(JNIEnv *env,jclass thiz, jlong p_sake_client, jobject unused1, jlong p_in_msg, jobject unused2, jlong p_out_msg, jobject unused3); 

int client_handshake(SakeMsg* msg_in, SakeMsg* msg_out);
void client_print_status();
void client_init(void *hLib, void* key_db);

#endif /* CLIENT */
