package com.medtronic.SakeClient;

import com.medtronic.minimed.sake.NativeSakeClient;
import com.medtronic.minimed.sake.NativeSakeKeyDatabase;
import com.medtronic.minimed.sake.NativeSakeSecureMessage;
import com.medtronic.minimed.sake.NativeSakeUserMessage;
import com.medtronic.minimed.sake.SakeJNI;
import com.medtronic.minimed.sake.SwigPtr;

public class SakeJNIWrapper {
    /* renamed from: a */
    public static VoidPtr getPointer(SwigPtr swigPtr) {
        long AsVoidPtr = SakeJNI.AsVoidPtr(SwigPtr.getPointer(swigPtr));
        if (AsVoidPtr == 0) {
            return null;
        }
        return new VoidPtr(AsVoidPtr, false);
    }

    /* renamed from: b */
    public static SakeHandshakeStatus getStatus(NativeSakeClient nativeSakeClient, NativeSakeSecureMessage nativeSakeSecureMessage, NativeSakeSecureMessage nativeSakeSecureMessage2) {
        return SakeHandshakeStatus.getStatus(SakeJNI.Sake_Client_Handshake(NativeSakeClient.getPointer(nativeSakeClient), nativeSakeClient, NativeSakeSecureMessage.m24084c(nativeSakeSecureMessage), nativeSakeSecureMessage, NativeSakeSecureMessage.m24084c(nativeSakeSecureMessage2), nativeSakeSecureMessage2));
    }

    /* renamed from: c */
    public static void clientInit(NativeSakeClient nativeSakeClient, NativeSakeKeyDatabase nativeSakeKeyDatabase) {
        SakeJNI.Sake_Client_Init(NativeSakeClient.getPointer(nativeSakeClient), nativeSakeClient, NativeSakeKeyDatabase.getPointer(nativeSakeKeyDatabase), nativeSakeKeyDatabase);
    }

    /* renamed from: d */
    public static boolean isSecureForSending(NativeSakeClient nativeSakeClient, NativeSakeUserMessage nativeSakeUserMessage, NativeSakeSecureMessage nativeSakeSecureMessage) {
        return SakeJNI.Sake_Client_SecureForSending(NativeSakeClient.getPointer(nativeSakeClient), nativeSakeClient, NativeSakeUserMessage.getPointer(nativeSakeUserMessage), nativeSakeUserMessage, NativeSakeSecureMessage.m24084c(nativeSakeSecureMessage), nativeSakeSecureMessage);
    }

    /* renamed from: e */
    public static boolean isInsecureAfterReceive(NativeSakeClient nativeSakeClient, NativeSakeSecureMessage nativeSakeSecureMessage, NativeSakeUserMessage nativeSakeUserMessage) {
        return SakeJNI.Sake_Client_UnsecureAfterReceiving(NativeSakeClient.getPointer(nativeSakeClient), nativeSakeClient, NativeSakeSecureMessage.m24084c(nativeSakeSecureMessage), nativeSakeSecureMessage, NativeSakeUserMessage.getPointer(nativeSakeUserMessage), nativeSakeUserMessage);
    }

    /* renamed from: f */
    public static boolean keyDbOpen(NativeSakeKeyDatabase nativeSakeKeyDatabase, SwigPtr swigPtr, long j) {
        return SakeJNI.Sake_KeyDatabase_Open(NativeSakeKeyDatabase.getPointer(nativeSakeKeyDatabase), nativeSakeKeyDatabase, SwigPtr.getPointer(swigPtr), j);
    }

    /* renamed from: g */
    public static byte[] cdata(VoidPtr voidPtr, int i) {
        return SakeJNI.cdata(VoidPtr.m3609a(voidPtr), i);
    }

    /* renamed from: h */
    public static byte[] cdataUint(SwigPtr swigPtr, int i) {
        return SakeJNI.cdata_uint8_t(SwigPtr.getPointer(swigPtr), i);
    }

    /* renamed from: i */
    public static void memMove(VoidPtr voidPtr, byte[] bArr) {
        SakeJNI.memmove(VoidPtr.m3609a(voidPtr), bArr);
    }
}