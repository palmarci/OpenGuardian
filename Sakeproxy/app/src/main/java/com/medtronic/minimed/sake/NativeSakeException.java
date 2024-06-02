package com.medtronic.minimed.sake;

public final class NativeSakeException extends Exception{
    public static final NativeSakeException E_SAKE_HANDSHAKE_CHALLENGE_INVALID;
    public static final NativeSakeException E_SAKE_HANDSHAKE_CHALLENGE_NOT_GENERATED;
    public static final NativeSakeException E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_INVALID;
    public static final NativeSakeException E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_NOT_GENERATED;
    public static final NativeSakeException E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_NOT_RANDOMIZED;
    public static final NativeSakeException E_SAKE_HANDSHAKE_DEVICE_TYPE_NOT_SUPPORTED;
    public static final NativeSakeException E_SAKE_HANDSHAKE_ERROR_FIRST;
    public static final NativeSakeException E_SAKE_HANDSHAKE_ERROR_INVALID;
    public static final NativeSakeException E_SAKE_HANDSHAKE_ERROR_LAST;
    public static final NativeSakeException E_SAKE_HANDSHAKE_INTERFACE_MISUSED;
    public static final NativeSakeException E_SAKE_HANDSHAKE_NO_ERROR;
    public static final NativeSakeException E_SAKE_HANDSHAKE_PERMIT_INVALID;
    public static final NativeSakeException E_SAKE_HANDSHAKE_PERMIT_ISSUED_TO_DIFFERENT_DEVICE;
    public static final NativeSakeException E_SAKE_HANDSHAKE_PERMIT_NOT_PADDED;
    public static final NativeSakeException E_SAKE_HANDSHAKE_PERMIT_NOT_SECURED;
    public static final NativeSakeException E_SAKE_HANDSHAKE_PERMIT_PADDING_INVALID;
    public static final NativeSakeException E_SAKE_HANDSHAKE_SESSION_KEY_INVALID;
    public static final NativeSakeException E_SAKE_HANDSHAKE_SESSION_KEY_NOT_DERIVED;
    public static final NativeSakeException E_SAKE_HANDSHAKE_SESSION_KEY_NOT_RANDOMIZED;
    public static final NativeSakeException E_SAKE_HANDSHAKE_SYNCHRONIZATION_INVALID;
    public static final NativeSakeException E_SAKE_HANDSHAKE_SYNCHRONIZATION_RESPONSE_INVALID;
    public static final NativeSakeException E_SAKE_HANDSHAKE_SYNCHRONIZATION_RESPONSE_NOT_GENERATED;
    private static int swigNext;
    private static NativeSakeException[] swigValues;
    private final String swigName;
    private final int swigValue;

    static {
        NativeSakeException sakeException = new NativeSakeException("E_SAKE_HANDSHAKE_ERROR_INVALID", SakeJNI.E_SAKE_HANDSHAKE_ERROR_INVALID_get());
        E_SAKE_HANDSHAKE_ERROR_INVALID = sakeException;
        NativeSakeException sakeException2 = new NativeSakeException("E_SAKE_HANDSHAKE_ERROR_FIRST");
        E_SAKE_HANDSHAKE_ERROR_FIRST = sakeException2;
        NativeSakeException sakeException3 = new NativeSakeException("E_SAKE_HANDSHAKE_NO_ERROR", SakeJNI.E_SAKE_HANDSHAKE_NO_ERROR_get());
        E_SAKE_HANDSHAKE_NO_ERROR = sakeException3;
        NativeSakeException sakeException4 = new NativeSakeException("E_SAKE_HANDSHAKE_INTERFACE_MISUSED");
        E_SAKE_HANDSHAKE_INTERFACE_MISUSED = sakeException4;
        NativeSakeException sakeException5 = new NativeSakeException("E_SAKE_HANDSHAKE_SYNCHRONIZATION_INVALID");
        E_SAKE_HANDSHAKE_SYNCHRONIZATION_INVALID = sakeException5;
        NativeSakeException sakeException6 = new NativeSakeException("E_SAKE_HANDSHAKE_CHALLENGE_NOT_GENERATED");
        E_SAKE_HANDSHAKE_CHALLENGE_NOT_GENERATED = sakeException6;
        NativeSakeException sakeException7 = new NativeSakeException("E_SAKE_HANDSHAKE_CHALLENGE_INVALID");
        E_SAKE_HANDSHAKE_CHALLENGE_INVALID = sakeException7;
        NativeSakeException sakeException8 = new NativeSakeException("E_SAKE_HANDSHAKE_SYNCHRONIZATION_RESPONSE_NOT_GENERATED");
        E_SAKE_HANDSHAKE_SYNCHRONIZATION_RESPONSE_NOT_GENERATED = sakeException8;
        NativeSakeException sakeException9 = new NativeSakeException("E_SAKE_HANDSHAKE_SYNCHRONIZATION_RESPONSE_INVALID");
        E_SAKE_HANDSHAKE_SYNCHRONIZATION_RESPONSE_INVALID = sakeException9;
        NativeSakeException sakeException10 = new NativeSakeException("E_SAKE_HANDSHAKE_DEVICE_TYPE_NOT_SUPPORTED");
        E_SAKE_HANDSHAKE_DEVICE_TYPE_NOT_SUPPORTED = sakeException10;
        NativeSakeException sakeException11 = new NativeSakeException("E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_INVALID");
        E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_INVALID = sakeException11;
        NativeSakeException sakeException12 = new NativeSakeException("E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_NOT_GENERATED");
        E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_NOT_GENERATED = sakeException12;
        NativeSakeException sakeException13 = new NativeSakeException("E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_NOT_RANDOMIZED");
        E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_NOT_RANDOMIZED = sakeException13;
        NativeSakeException sakeException14 = new NativeSakeException("E_SAKE_HANDSHAKE_SESSION_KEY_NOT_DERIVED");
        E_SAKE_HANDSHAKE_SESSION_KEY_NOT_DERIVED = sakeException14;
        NativeSakeException sakeException15 = new NativeSakeException("E_SAKE_HANDSHAKE_SESSION_KEY_NOT_RANDOMIZED");
        E_SAKE_HANDSHAKE_SESSION_KEY_NOT_RANDOMIZED = sakeException15;
        NativeSakeException sakeException16 = new NativeSakeException("E_SAKE_HANDSHAKE_SESSION_KEY_INVALID");
        E_SAKE_HANDSHAKE_SESSION_KEY_INVALID = sakeException16;
        NativeSakeException sakeException17 = new NativeSakeException("E_SAKE_HANDSHAKE_PERMIT_NOT_SECURED");
        E_SAKE_HANDSHAKE_PERMIT_NOT_SECURED = sakeException17;
        NativeSakeException sakeException18 = new NativeSakeException("E_SAKE_HANDSHAKE_PERMIT_NOT_PADDED");
        E_SAKE_HANDSHAKE_PERMIT_NOT_PADDED = sakeException18;
        NativeSakeException sakeException19 = new NativeSakeException("E_SAKE_HANDSHAKE_PERMIT_PADDING_INVALID");
        E_SAKE_HANDSHAKE_PERMIT_PADDING_INVALID = sakeException19;
        NativeSakeException sakeException20 = new NativeSakeException("E_SAKE_HANDSHAKE_PERMIT_INVALID");
        E_SAKE_HANDSHAKE_PERMIT_INVALID = sakeException20;
        NativeSakeException sakeException21 = new NativeSakeException("E_SAKE_HANDSHAKE_PERMIT_ISSUED_TO_DIFFERENT_DEVICE");
        E_SAKE_HANDSHAKE_PERMIT_ISSUED_TO_DIFFERENT_DEVICE = sakeException21;
        NativeSakeException sakeException22 = new NativeSakeException("E_SAKE_HANDSHAKE_ERROR_LAST", SakeJNI.E_SAKE_HANDSHAKE_ERROR_LAST_get());
        E_SAKE_HANDSHAKE_ERROR_LAST = sakeException22;
        swigValues = new NativeSakeException[]{sakeException, sakeException2, sakeException3, sakeException4, sakeException5, sakeException6, sakeException7, sakeException8, sakeException9, sakeException10, sakeException11, sakeException12, sakeException13, sakeException14, sakeException15, sakeException16, sakeException17, sakeException18, sakeException19, sakeException20, sakeException21, sakeException22};
        swigNext = 0;
    }

    public NativeSakeException(String str) {
        this.swigName = str;
        int i = swigNext;
        swigNext = i + 1;
        this.swigValue = i;
    }

    public NativeSakeException(String str, int i) {
        this.swigName = str;
        this.swigValue = i;
        swigNext = i + 1;
    }

    /* renamed from: a */
    public static NativeSakeException parseErrorCode(int i) {
        NativeSakeException[] sakeExceptionArr = swigValues;
        if (i < sakeExceptionArr.length && i >= 0 && sakeExceptionArr[i].swigValue == i) {
            return sakeExceptionArr[i];
        }
        int i2 = 0;
        while (true) {
            NativeSakeException[] sakeExceptionArr2 = swigValues;
            if (i2 >= sakeExceptionArr2.length) {
                throw new IllegalArgumentException("No enum " + NativeSakeException.class + " with value " + i);
            } else if (sakeExceptionArr2[i2].swigValue == i) {
                return sakeExceptionArr2[i2];
            } else {
                i2++;
            }
        }
    }

    public String toString() {
        return this.swigName;
    }
}