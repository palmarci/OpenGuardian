package com.medtronic;

import com.medtronic.minimed.sake.*;

import com.openguardian4.sakeproxy.Utils;

public class SakeCommon {

	static SakeAuthenticationStatus handshakeToAuthStatus(SakeHandshakeStatus sakeStatus) {
        return sakeStatus == SakeHandshakeStatus.E_SAKE_HANDSHAKE_SUCCESSFUL ? SakeAuthenticationStatus.AUTHORIZED
            : sakeStatus == SakeHandshakeStatus.E_SAKE_HANDSHAKE_IN_PROGRESS ? SakeAuthenticationStatus.IN_PROGRESS
                : sakeStatus == SakeHandshakeStatus.E_SAKE_HANDSHAKE_FAILED ? SakeAuthenticationStatus.FAILED
                    : SakeAuthenticationStatus.UNAUTHORIZED;
	}


    /* renamed from: a */
    public static final long f12618a = SakeJNI.MIN_SAKE_SECURE_MESSAGE_BYTE_COUNT_get();

    /* renamed from: b */
    public static final long maxSecureMessageByteCount = SakeJNI.MAX_SAKE_SECURE_MESSAGE_BYTE_COUNT_get();

    /* renamed from: c */
    public static final long maxUserMessageByteCount = SakeJNI.MAX_SAKE_USER_MESSAGE_BYTE_COUNT_get();

    /* renamed from: d */
    public static final long f12621d = SakeJNI.SAKE_KEY_DATABASE_CRC_BYTE_COUNT_get();

    /* renamed from: e */
    public static final long f12622e = SakeJNI.SAKE_KEY_DATABASE_DEVICE_TYPE_BYTE_COUNT_get();

    /* renamed from: f */
    public static final long f12623f = SakeJNI.SAKE_KEY_DATABASE_REMOTE_DEVICE_COUNT_BYTE_COUNT_get();

    /* renamed from: g */
    public static final long f12624g = SakeJNI.SAKE_KEY_DATABASE_HEADER_BYTE_COUNT_get();

    /* renamed from: h */
    public static final long f12625h = SakeJNI.SAKE_KEY_DATABASE_REMOTE_DEVICE_KEY_COUNT_get();

    /* renamed from: i */
    public static final long f12626i = SakeJNI.SAKE_PERMIT_PROPRIETARY_BYTE_COUNT_get();


    public static SakeVoidPointer ConvertPtrType(SakeCharPointer charptr) {
        long AsVoidPtr = SakeJNI.AsVoidPtr(SakeVoidPointer.getValue(charptr.GetAsVoidPtr()));
        if (AsVoidPtr == 0) {
            return null;
        }
        return new SakeVoidPointer(AsVoidPtr, false);
    }

    public static SakeVoidPointer ConvertPtrType(SakeVoidPointer voidptr) {
      //  Utils.logPrint("fake ConvertPtrType called!");
        return voidptr;
        /*
        long AsVoidPtr = SakeJNI.AsVoidPtr(charptr.AsVoidPtr().getValue());
        if (AsVoidPtr == 0) {
            return null;
        }
        return new SakeVoidPointer(AsVoidPtr, false);
        */
    }


}
