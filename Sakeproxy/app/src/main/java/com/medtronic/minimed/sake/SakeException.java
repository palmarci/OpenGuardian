package com.medtronic.minimed.sake;

public final class SakeException extends Exception{
    public static final SakeException E_SAKE_HANDSHAKE_CHALLENGE_INVALID;
    public static final SakeException E_SAKE_HANDSHAKE_CHALLENGE_NOT_GENERATED;
    public static final SakeException E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_INVALID;
    public static final SakeException E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_NOT_GENERATED;
    public static final SakeException E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_NOT_RANDOMIZED;
    public static final SakeException E_SAKE_HANDSHAKE_DEVICE_TYPE_NOT_SUPPORTED;
    public static final SakeException E_SAKE_HANDSHAKE_ERROR_FIRST;
    public static final SakeException E_SAKE_HANDSHAKE_ERROR_INVALID;
    public static final SakeException E_SAKE_HANDSHAKE_ERROR_LAST;
    public static final SakeException E_SAKE_HANDSHAKE_INTERFACE_MISUSED;
    public static final SakeException E_SAKE_HANDSHAKE_NO_ERROR;
    public static final SakeException E_SAKE_HANDSHAKE_PERMIT_INVALID;
    public static final SakeException E_SAKE_HANDSHAKE_PERMIT_ISSUED_TO_DIFFERENT_DEVICE;
    public static final SakeException E_SAKE_HANDSHAKE_PERMIT_NOT_PADDED;
    public static final SakeException E_SAKE_HANDSHAKE_PERMIT_NOT_SECURED;
    public static final SakeException E_SAKE_HANDSHAKE_PERMIT_PADDING_INVALID;
    public static final SakeException E_SAKE_HANDSHAKE_SESSION_KEY_INVALID;
    public static final SakeException E_SAKE_HANDSHAKE_SESSION_KEY_NOT_DERIVED;
    public static final SakeException E_SAKE_HANDSHAKE_SESSION_KEY_NOT_RANDOMIZED;
    public static final SakeException E_SAKE_HANDSHAKE_SYNCHRONIZATION_INVALID;
    public static final SakeException E_SAKE_HANDSHAKE_SYNCHRONIZATION_RESPONSE_INVALID;
    public static final SakeException E_SAKE_HANDSHAKE_SYNCHRONIZATION_RESPONSE_NOT_GENERATED;
    private static int swigNext;
    private static SakeException[] swigValues;
    private final String swigName;
    private final int swigValue;

    static {
        SakeException sakeException = new SakeException("E_SAKE_HANDSHAKE_ERROR_INVALID", SakeJNI.E_SAKE_HANDSHAKE_ERROR_INVALID_get());
        E_SAKE_HANDSHAKE_ERROR_INVALID = sakeException;
        SakeException sakeException2 = new SakeException("E_SAKE_HANDSHAKE_ERROR_FIRST");
        E_SAKE_HANDSHAKE_ERROR_FIRST = sakeException2;
        SakeException sakeException3 = new SakeException("E_SAKE_HANDSHAKE_NO_ERROR", SakeJNI.E_SAKE_HANDSHAKE_NO_ERROR_get());
        E_SAKE_HANDSHAKE_NO_ERROR = sakeException3;
        SakeException sakeException4 = new SakeException("E_SAKE_HANDSHAKE_INTERFACE_MISUSED");
        E_SAKE_HANDSHAKE_INTERFACE_MISUSED = sakeException4;
        SakeException sakeException5 = new SakeException("E_SAKE_HANDSHAKE_SYNCHRONIZATION_INVALID");
        E_SAKE_HANDSHAKE_SYNCHRONIZATION_INVALID = sakeException5;
        SakeException sakeException6 = new SakeException("E_SAKE_HANDSHAKE_CHALLENGE_NOT_GENERATED");
        E_SAKE_HANDSHAKE_CHALLENGE_NOT_GENERATED = sakeException6;
        SakeException sakeException7 = new SakeException("E_SAKE_HANDSHAKE_CHALLENGE_INVALID");
        E_SAKE_HANDSHAKE_CHALLENGE_INVALID = sakeException7;
        SakeException sakeException8 = new SakeException("E_SAKE_HANDSHAKE_SYNCHRONIZATION_RESPONSE_NOT_GENERATED");
        E_SAKE_HANDSHAKE_SYNCHRONIZATION_RESPONSE_NOT_GENERATED = sakeException8;
        SakeException sakeException9 = new SakeException("E_SAKE_HANDSHAKE_SYNCHRONIZATION_RESPONSE_INVALID");
        E_SAKE_HANDSHAKE_SYNCHRONIZATION_RESPONSE_INVALID = sakeException9;
        SakeException sakeException10 = new SakeException("E_SAKE_HANDSHAKE_DEVICE_TYPE_NOT_SUPPORTED");
        E_SAKE_HANDSHAKE_DEVICE_TYPE_NOT_SUPPORTED = sakeException10;
        SakeException sakeException11 = new SakeException("E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_INVALID");
        E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_INVALID = sakeException11;
        SakeException sakeException12 = new SakeException("E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_NOT_GENERATED");
        E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_NOT_GENERATED = sakeException12;
        SakeException sakeException13 = new SakeException("E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_NOT_RANDOMIZED");
        E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_NOT_RANDOMIZED = sakeException13;
        SakeException sakeException14 = new SakeException("E_SAKE_HANDSHAKE_SESSION_KEY_NOT_DERIVED");
        E_SAKE_HANDSHAKE_SESSION_KEY_NOT_DERIVED = sakeException14;
        SakeException sakeException15 = new SakeException("E_SAKE_HANDSHAKE_SESSION_KEY_NOT_RANDOMIZED");
        E_SAKE_HANDSHAKE_SESSION_KEY_NOT_RANDOMIZED = sakeException15;
        SakeException sakeException16 = new SakeException("E_SAKE_HANDSHAKE_SESSION_KEY_INVALID");
        E_SAKE_HANDSHAKE_SESSION_KEY_INVALID = sakeException16;
        SakeException sakeException17 = new SakeException("E_SAKE_HANDSHAKE_PERMIT_NOT_SECURED");
        E_SAKE_HANDSHAKE_PERMIT_NOT_SECURED = sakeException17;
        SakeException sakeException18 = new SakeException("E_SAKE_HANDSHAKE_PERMIT_NOT_PADDED");
        E_SAKE_HANDSHAKE_PERMIT_NOT_PADDED = sakeException18;
        SakeException sakeException19 = new SakeException("E_SAKE_HANDSHAKE_PERMIT_PADDING_INVALID");
        E_SAKE_HANDSHAKE_PERMIT_PADDING_INVALID = sakeException19;
        SakeException sakeException20 = new SakeException("E_SAKE_HANDSHAKE_PERMIT_INVALID");
        E_SAKE_HANDSHAKE_PERMIT_INVALID = sakeException20;
        SakeException sakeException21 = new SakeException("E_SAKE_HANDSHAKE_PERMIT_ISSUED_TO_DIFFERENT_DEVICE");
        E_SAKE_HANDSHAKE_PERMIT_ISSUED_TO_DIFFERENT_DEVICE = sakeException21;
        SakeException sakeException22 = new SakeException("E_SAKE_HANDSHAKE_ERROR_LAST", SakeJNI.E_SAKE_HANDSHAKE_ERROR_LAST_get());
        E_SAKE_HANDSHAKE_ERROR_LAST = sakeException22;
        swigValues = new SakeException[]{sakeException, sakeException2, sakeException3, sakeException4, sakeException5, sakeException6, sakeException7, sakeException8, sakeException9, sakeException10, sakeException11, sakeException12, sakeException13, sakeException14, sakeException15, sakeException16, sakeException17, sakeException18, sakeException19, sakeException20, sakeException21, sakeException22};
        swigNext = 0;
    }

    public SakeException(String str) {
        this.swigName = str;
        int i = swigNext;
        swigNext = i + 1;
        this.swigValue = i;
    }

    public SakeException(String str, int i) {
        this.swigName = str;
        this.swigValue = i;
        swigNext = i + 1;
    }

    /* renamed from: a */
    public static SakeException parseErrorCode(int i) {
        SakeException[] sakeExceptionArr = swigValues;
        if (i < sakeExceptionArr.length && i >= 0 && sakeExceptionArr[i].swigValue == i) {
            return sakeExceptionArr[i];
        }
        int i2 = 0;
        while (true) {
            SakeException[] sakeExceptionArr2 = swigValues;
            if (i2 >= sakeExceptionArr2.length) {
                throw new IllegalArgumentException("No enum " + SakeException.class + " with value " + i);
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