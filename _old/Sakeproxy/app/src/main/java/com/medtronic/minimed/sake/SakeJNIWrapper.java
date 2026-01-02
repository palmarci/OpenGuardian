package com.medtronic.minimed.sake;

import com.medtronic.minimed.sake.*;
import com.medtronic.minimed.sake.*;
import com.medtronic.minimed.sake.*;
import com.medtronic.minimed.sake.*;
import com.medtronic.minimed.sake.*;
import com.medtronic.minimed.sake.*;

public class SakeJNIWrapper {
    /* renamed from: a */
    /*public static SakeVoidPointer getValue(SakeVoidPointer SakeVoidPointer) {
        long AsVoidPtr = SakeJNI.AsVoidPtr(SakeVoidPointer.getValue(SakeVoidPointer));
        if (AsVoidPtr == 0) {
            return null;
        }
        return new SakePtr(AsVoidPtr, false);
    }*/

    /* renamed from: b */
    public static SakeHandshakeStatus Client_GetHandshakeStatus(SakeClient SakeClient, SakeSecureMessage SakeSecureMessage, SakeSecureMessage SakeSecureMessage2) {
        return SakeHandshakeStatus.fromInt(SakeJNI.Sake_Client_Handshake(SakeClient.getValue(SakeClient), SakeClient, SakeSecureMessage.getValue(SakeSecureMessage), SakeSecureMessage, SakeSecureMessage.getValue(SakeSecureMessage2), SakeSecureMessage2));
    }

    /* renamed from: c */
    public static void Client_Init(SakeClient SakeClient, SakeKeyDatabase SakeKeyDatabase) {
        SakeJNI.Sake_Client_Init(SakeClient.getValue(SakeClient), SakeClient, SakeKeyDatabase.getValue(SakeKeyDatabase), SakeKeyDatabase);
    }

    /* renamed from: d */
    public static boolean Client_SecureForSending(SakeClient SakeClient, SakeUserMessage SakeUserMessage, SakeSecureMessage SakeSecureMessage) {
        return SakeJNI.Sake_Client_SecureForSending(SakeClient.getValue(SakeClient), SakeClient, SakeUserMessage.getValue(SakeUserMessage), SakeUserMessage, SakeSecureMessage.getValue(SakeSecureMessage), SakeSecureMessage);
    }

    /* renamed from: e */
    public static boolean Client_UnsecureAfterReceiving(SakeClient SakeClient, SakeSecureMessage SakeSecureMessage, SakeUserMessage SakeUserMessage) {
        return SakeJNI.Sake_Client_UnsecureAfterReceiving(SakeClient.getValue(SakeClient), SakeClient, SakeSecureMessage.getValue(SakeSecureMessage), SakeSecureMessage, SakeUserMessage.getValue(SakeUserMessage), SakeUserMessage);
    }

    /* renamed from: f */
    public static boolean KeyDatabase_Open(SakeKeyDatabase SakeKeyDatabase, SakeVoidPointer SakeVoidPointer, long j) {
        return SakeJNI.Sake_KeyDatabase_Open(SakeKeyDatabase.getValue(SakeKeyDatabase), SakeKeyDatabase, SakeVoidPointer.getValue(SakeVoidPointer), j);
    }

    /* renamed from: g */
    public static byte[] cdata(SakeVoidPointer SakePtr, int i) {
        return SakeJNI.cdata(SakePtr.getValue(SakePtr), i);
    }

    /* renamed from: h */
    /*
    public static byte[] copyData8(SakeVoidPointer SakeVoidPointer, int i) {
        return SakeJNI.cdata_uint8_t(SakeVoidPointer.getValue(SakeVoidPointer), i);
    }
    */

    /* renamed from: i */
    public static void memmove(SakeVoidPointer SakePtr, byte[] bArr) {
        SakeJNI.memmove(SakePtr.getValue(SakePtr), bArr);
    }

    // *********************************************************************
    // *********************************************************************
    // *********************************************************************


    /* renamed from: c */
    public static void Server_ServerDestroy(SakeServer sake_server_s) {
        SakeJNI.Sake_Server_Destroy(SakeServer.getValue(sake_server_s), sake_server_s);
    }

    /* renamed from: d */
    public static SakeHandshakeStatus Server_Handshake_Step(SakeServer sake_server_s, SakeSecureMessage SakeSecureMessage, SakeSecureMessage SakeSecureMessage2) {
        return SakeHandshakeStatus.fromInt(SakeJNI.Sake_Server_Handshake(SakeServer.getValue(sake_server_s), sake_server_s, SakeSecureMessage.getValue(SakeSecureMessage), SakeSecureMessage, SakeSecureMessage.getValue(SakeSecureMessage2), SakeSecureMessage2));
    }

    /* renamed from: e */
    public static void Server_Init(SakeServer sake_server_s, SakeKeyDatabase SakeKeyDatabase) {
        SakeJNI.Sake_Server_Init(SakeServer.getValue(sake_server_s), sake_server_s, SakeKeyDatabase.getValue(SakeKeyDatabase), SakeKeyDatabase);
    }

    /* renamed from: f */
    public static boolean Server_SecureForSending(SakeServer sake_server_s, SakeUserMessage sake_user_message_s, SakeSecureMessage SakeSecureMessage) {
        return SakeJNI.Sake_Server_SecureForSending(SakeServer.getValue(sake_server_s), sake_server_s, SakeUserMessage.getValue(sake_user_message_s), sake_user_message_s, SakeSecureMessage.getValue(SakeSecureMessage), SakeSecureMessage);
    }

    /* renamed from: g */
    public static boolean Server_UnsecureAfterReceiving(SakeServer sake_server_s, SakeSecureMessage SakeSecureMessage, SakeUserMessage sake_user_message_s) {
        return SakeJNI.Sake_Server_UnsecureAfterReceiving(SakeServer.getValue(sake_server_s), sake_server_s, SakeSecureMessage.getValue(SakeSecureMessage), SakeSecureMessage, SakeUserMessage.getValue(sake_user_message_s), sake_user_message_s);
    }






}

