package com.medtronic.minimed.sake;

/* loaded from: classes.dex */
public class SakeJNI {
    public static final native long AsVoidPtr(long j);

    public static final native int E_SAKE_HANDSHAKE_ERROR_INVALID_get();

    public static final native int E_SAKE_HANDSHAKE_ERROR_LAST_get();

    public static final native int E_SAKE_HANDSHAKE_NO_ERROR_get();

    public static final native long MAX_SAKE_SECURE_MESSAGE_BYTE_COUNT_get();

    public static final native long MAX_SAKE_USER_MESSAGE_BYTE_COUNT_get();

    public static final native long MIN_SAKE_SECURE_MESSAGE_BYTE_COUNT_get();

    public static final native int SAKE_CLIENT_S_lastError_get(long j, SakeClient SakeClient);

    public static final native long SAKE_KEY_DATABASE_CRC_BYTE_COUNT_get();

    public static final native long SAKE_KEY_DATABASE_DEVICE_TYPE_BYTE_COUNT_get();

    public static final native long SAKE_KEY_DATABASE_HEADER_BYTE_COUNT_get();

    public static final native long SAKE_KEY_DATABASE_REMOTE_DEVICE_COUNT_BYTE_COUNT_get();

    public static final native long SAKE_KEY_DATABASE_REMOTE_DEVICE_KEY_COUNT_get();

    public static final native long SAKE_PERMIT_PROPRIETARY_BYTE_COUNT_get();

    public static final native long SAKE_SECURE_MESSAGE_S_byteCount_get(long j, SakeSecureMessage SakeSecureMessage);

    public static final native void SAKE_SECURE_MESSAGE_S_byteCount_set(long j, SakeSecureMessage SakeSecureMessage, long j2);

    public static final native long SAKE_SECURE_MESSAGE_S_pBytes_get(long j, SakeSecureMessage SakeSecureMessage);

    public static final native void SAKE_SECURE_MESSAGE_S_pBytes_set(long j, SakeSecureMessage SakeSecureMessage, long j2);

    public static final native long SAKE_USER_MESSAGE_S_pBytes_get(long j, SakeUserMessage SakeUserMessage);

    public static final native void SAKE_USER_MESSAGE_S_pBytes_set(long j, SakeUserMessage SakeUserMessage, long j2);



    public static final native long SAKE_USER_MESSAGE_S_byteCount_get(long j, SakeUserMessage SakeUserMessage);

    public static final native void SAKE_USER_MESSAGE_S_byteCount_set(long j, SakeUserMessage SakeUserMessage, long j2);

    public static final native int Sake_Client_Handshake(long j, SakeClient SakeClient, long j2, SakeSecureMessage SakeSecureMessage, long j3, SakeSecureMessage SakeSecureMessage2);

    public static final native void Sake_Client_Init(long clientPointer, SakeClient SakeClient, long dbPointer, SakeKeyDatabase SakeKeyDatabase);

    public static final native boolean Sake_Client_SecureForSending(long j, SakeClient SakeClient, long j2, SakeUserMessage SakeUserMessage, long j3, SakeSecureMessage SakeSecureMessage);

    public static final native boolean Sake_Client_UnsecureAfterReceiving(long j, SakeClient SakeClient, long j2, SakeSecureMessage SakeSecureMessage, long j3, SakeUserMessage SakeUserMessage);

    public static final native boolean Sake_KeyDatabase_Open(long j, SakeKeyDatabase SakeKeyDatabase, long j2, long j3);

    public static final native byte[] cdata(long j, int i);

    public static final native void delete_SAKE_CLIENT_S(long j);

    public static final native void delete_SAKE_KEY_DATABASE_S(long j);

    public static final native void delete_SAKE_SECURE_MESSAGE_S(long j);

    public static final native void delete_SAKE_USER_MESSAGE_S(long j);

  //  public static final native void delete_SAKE_KEY_DATABASE_S(long j);


    public static final native void delete_p_uint8_t(long j);

    public static final native void memmove(long j, byte[] bArr);

    public static final native long new_SAKE_CLIENT_S();


    public static final native long new_SAKE_KEY_DATABASE_S();

    public static final native long new_SAKE_SECURE_MESSAGE_S();

    public static final native long new_SAKE_SERVER_S();

    public static final native long new_SAKE_USER_MESSAGE_S();


/*
    public static final native long new_SakeKeyDatabase();

    public static final native long new_SakeSecureMessage();

    public static final native long new_SakeUserMessage();
    */


    public static final native long new_p_uint8_t(int i10);

    public static final native long p_uint8_t_cast(long j10, SakeCharPointer pChar);


    // *******************************************************


    public static final native int Sake_Server_Handshake(long j10, SakeServer sake_server_s, long j11, SakeSecureMessage SakeSecureMessage, long j12, SakeSecureMessage SakeSecureMessage2);

    public static final native void Sake_Server_Init(long j10, SakeServer sake_server_s, long j11, SakeKeyDatabase SakeKeyDatabase);

    public static final native boolean Sake_Server_SecureForSending(long j10, SakeServer sake_server_s, long j11, SakeUserMessage sake_user_message_s, long j12, SakeSecureMessage SakeSecureMessage);

    public static final native boolean Sake_Server_UnsecureAfterReceiving(long j10, SakeServer sake_server_s, long j11, SakeSecureMessage SakeSecureMessage, long j12, SakeUserMessage sake_user_message_s);

    public static final native void delete_SAKE_SERVER_S(long j10);

    public static final native int SAKE_SERVER_S_lastError_get(long j10, SakeServer sake_server_s);

    public static final native void Sake_Server_Destroy(long j10, SakeServer sake_server_s);

}