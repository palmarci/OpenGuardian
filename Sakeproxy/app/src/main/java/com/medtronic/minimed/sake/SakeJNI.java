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

    public static final native int SAKE_CLIENT_S_lastError_get(long j, NativeSakeClient nativeSakeClient);

    public static final native long SAKE_KEY_DATABASE_CRC_BYTE_COUNT_get();

    public static final native long SAKE_KEY_DATABASE_DEVICE_TYPE_BYTE_COUNT_get();

    public static final native long SAKE_KEY_DATABASE_HEADER_BYTE_COUNT_get();

    public static final native long SAKE_KEY_DATABASE_REMOTE_DEVICE_COUNT_BYTE_COUNT_get();

    public static final native long SAKE_KEY_DATABASE_REMOTE_DEVICE_KEY_COUNT_get();

    public static final native long SAKE_PERMIT_PROPRIETARY_BYTE_COUNT_get();

    public static final native long SAKE_SECURE_MESSAGE_S_byteCount_get(long j, NativeSakeSecureMessage nativeSakeSecureMessage);

    public static final native void SAKE_SECURE_MESSAGE_S_byteCount_set(long j, NativeSakeSecureMessage nativeSakeSecureMessage, long j2);

    public static final native long SAKE_SECURE_MESSAGE_S_pBytes_get(long j, NativeSakeSecureMessage nativeSakeSecureMessage);

    public static final native void SAKE_SECURE_MESSAGE_S_pBytes_set(long j, NativeSakeSecureMessage nativeSakeSecureMessage, long j2);

    public static final native long SAKE_USER_MESSAGE_S_byteCount_get(long j, NativeSakeUserMessage nativeSakeUserMessage);

    public static final native void SAKE_USER_MESSAGE_S_byteCount_set(long j, NativeSakeUserMessage nativeSakeUserMessage, long j2);

    public static final native long SAKE_USER_MESSAGE_S_pBytes_get(long j, NativeSakeUserMessage nativeSakeUserMessage);

    public static final native void SAKE_USER_MESSAGE_S_pBytes_set(long j, NativeSakeUserMessage nativeSakeUserMessage, long j2);

    public static final native int Sake_Client_Handshake(long j, NativeSakeClient nativeSakeClient, long j2, NativeSakeSecureMessage nativeSakeSecureMessage, long j3, NativeSakeSecureMessage nativeSakeSecureMessage2);

    public static final native void Sake_Client_Init(long clientPointer, NativeSakeClient nativeSakeClient, long dbPointer, NativeSakeKeyDatabase sake_key_database_s);

    public static final native boolean Sake_Client_SecureForSending(long j, NativeSakeClient nativeSakeClient, long j2, NativeSakeUserMessage nativeSakeUserMessage, long j3, NativeSakeSecureMessage nativeSakeSecureMessage);

    public static final native boolean Sake_Client_UnsecureAfterReceiving(long j, NativeSakeClient nativeSakeClient, long j2, NativeSakeSecureMessage nativeSakeSecureMessage, long j3, NativeSakeUserMessage nativeSakeUserMessage);

    public static final native boolean Sake_KeyDatabase_Open(long j, NativeSakeKeyDatabase sake_key_database_s, long j2, long j3);

    public static final native byte[] cdata(long j, int i);

    public static final native byte[] cdata_uint8_t(long j, int i);

    public static final native void delete_SAKE_CLIENT_S(long j);

    public static final native void delete_SAKE_KEY_DATABASE_S(long j);

    public static final native void delete_SAKE_SECURE_MESSAGE_S(long j);

    public static final native void delete_SAKE_USER_MESSAGE_S(long j);

    public static final native void delete_p_uint8_t(long j);

    public static final native void memmove(long j, byte[] bArr);

    public static final native long new_SAKE_CLIENT_S();

    public static final native long new_SAKE_KEY_DATABASE_S();

    public static final native long new_SAKE_SECURE_MESSAGE_S();

    public static final native long new_SAKE_USER_MESSAGE_S();

    public static final native long new_p_uint8_t(int i);

    public static final native long p_uint8_t_cast(long j, p_uint8_t p_uint8_tVar);
}