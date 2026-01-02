package com.medtronic.minimed.sake;

public final class SakeError extends Exception {
    public static final SakeError E_SAKE_HANDSHAKE_CHALLENGE_INVALID;
    public static final SakeError E_SAKE_HANDSHAKE_CHALLENGE_NOT_GENERATED;
    public static final SakeError E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_INVALID;
    public static final SakeError E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_NOT_GENERATED;
    public static final SakeError E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_NOT_RANDOMIZED;
    public static final SakeError E_SAKE_HANDSHAKE_DEVICE_TYPE_NOT_SUPPORTED;
    public static final SakeError E_SAKE_HANDSHAKE_ERROR_FIRST;
    public static final SakeError E_SAKE_HANDSHAKE_ERROR_INVALID;
    public static final SakeError E_SAKE_HANDSHAKE_ERROR_LAST;
    public static final SakeError E_SAKE_HANDSHAKE_INTERFACE_MISUSED;
    public static final SakeError E_SAKE_HANDSHAKE_NO_ERROR;
    public static final SakeError E_SAKE_HANDSHAKE_PERMIT_INVALID;
    public static final SakeError E_SAKE_HANDSHAKE_PERMIT_ISSUED_TO_DIFFERENT_DEVICE;
    public static final SakeError E_SAKE_HANDSHAKE_PERMIT_NOT_PADDED;
    public static final SakeError E_SAKE_HANDSHAKE_PERMIT_NOT_SECURED;
    public static final SakeError E_SAKE_HANDSHAKE_PERMIT_PADDING_INVALID;
    public static final SakeError E_SAKE_HANDSHAKE_SESSION_KEY_INVALID;
    public static final SakeError E_SAKE_HANDSHAKE_SESSION_KEY_NOT_DERIVED;
    public static final SakeError E_SAKE_HANDSHAKE_SESSION_KEY_NOT_RANDOMIZED;
    public static final SakeError E_SAKE_HANDSHAKE_SYNCHRONIZATION_INVALID;
    public static final SakeError E_SAKE_HANDSHAKE_SYNCHRONIZATION_RESPONSE_INVALID;
    public static final SakeError E_SAKE_HANDSHAKE_SYNCHRONIZATION_RESPONSE_NOT_GENERATED;
    private static int swigNext;
    private static SakeError[] swigValues;
    private final String text;
    private final int swigValue;

    static {
        SakeError err_invalid = new SakeError("E_SAKE_HANDSHAKE_ERROR_INVALID", SakeJNI.E_SAKE_HANDSHAKE_ERROR_INVALID_get());
        E_SAKE_HANDSHAKE_ERROR_INVALID = err_invalid;
        SakeError error_first = new SakeError("E_SAKE_HANDSHAKE_ERROR_FIRST");
        E_SAKE_HANDSHAKE_ERROR_FIRST = error_first;
        SakeError no_err = new SakeError("E_SAKE_HANDSHAKE_NO_ERROR", SakeJNI.E_SAKE_HANDSHAKE_NO_ERROR_get());
        E_SAKE_HANDSHAKE_NO_ERROR = no_err;
        SakeError interface_misused = new SakeError("E_SAKE_HANDSHAKE_INTERFACE_MISUSED");
        E_SAKE_HANDSHAKE_INTERFACE_MISUSED = interface_misused;
        SakeError sync_invalid = new SakeError("E_SAKE_HANDSHAKE_SYNCHRONIZATION_INVALID");
        E_SAKE_HANDSHAKE_SYNCHRONIZATION_INVALID = sync_invalid;
        SakeError chall_not_generated = new SakeError("E_SAKE_HANDSHAKE_CHALLENGE_NOT_GENERATED");
        E_SAKE_HANDSHAKE_CHALLENGE_NOT_GENERATED = chall_not_generated;
        SakeError SakeError7 = new SakeError("E_SAKE_HANDSHAKE_CHALLENGE_INVALID");
        E_SAKE_HANDSHAKE_CHALLENGE_INVALID = SakeError7;
        SakeError SakeError8 = new SakeError("E_SAKE_HANDSHAKE_SYNCHRONIZATION_RESPONSE_NOT_GENERATED");
        E_SAKE_HANDSHAKE_SYNCHRONIZATION_RESPONSE_NOT_GENERATED = SakeError8;
        SakeError SakeError9 = new SakeError("E_SAKE_HANDSHAKE_SYNCHRONIZATION_RESPONSE_INVALID");
        E_SAKE_HANDSHAKE_SYNCHRONIZATION_RESPONSE_INVALID = SakeError9;
        SakeError SakeError10 = new SakeError("E_SAKE_HANDSHAKE_DEVICE_TYPE_NOT_SUPPORTED");
        E_SAKE_HANDSHAKE_DEVICE_TYPE_NOT_SUPPORTED = SakeError10;
        SakeError SakeError11 = new SakeError("E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_INVALID");
        E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_INVALID = SakeError11;
        SakeError SakeError12 = new SakeError("E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_NOT_GENERATED");
        E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_NOT_GENERATED = SakeError12;
        SakeError SakeError13 = new SakeError("E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_NOT_RANDOMIZED");
        E_SAKE_HANDSHAKE_CHALLENGE_RESPONSE_NOT_RANDOMIZED = SakeError13;
        SakeError SakeError14 = new SakeError("E_SAKE_HANDSHAKE_SESSION_KEY_NOT_DERIVED");
        E_SAKE_HANDSHAKE_SESSION_KEY_NOT_DERIVED = SakeError14;
        SakeError SakeError15 = new SakeError("E_SAKE_HANDSHAKE_SESSION_KEY_NOT_RANDOMIZED");
        E_SAKE_HANDSHAKE_SESSION_KEY_NOT_RANDOMIZED = SakeError15;
        SakeError SakeError16 = new SakeError("E_SAKE_HANDSHAKE_SESSION_KEY_INVALID");
        E_SAKE_HANDSHAKE_SESSION_KEY_INVALID = SakeError16;
        SakeError SakeError17 = new SakeError("E_SAKE_HANDSHAKE_PERMIT_NOT_SECURED");
        E_SAKE_HANDSHAKE_PERMIT_NOT_SECURED = SakeError17;
        SakeError SakeError18 = new SakeError("E_SAKE_HANDSHAKE_PERMIT_NOT_PADDED");
        E_SAKE_HANDSHAKE_PERMIT_NOT_PADDED = SakeError18;
        SakeError SakeError19 = new SakeError("E_SAKE_HANDSHAKE_PERMIT_PADDING_INVALID");
        E_SAKE_HANDSHAKE_PERMIT_PADDING_INVALID = SakeError19;
        SakeError SakeError20 = new SakeError("E_SAKE_HANDSHAKE_PERMIT_INVALID");
        E_SAKE_HANDSHAKE_PERMIT_INVALID = SakeError20;
        SakeError SakeError21 = new SakeError("E_SAKE_HANDSHAKE_PERMIT_ISSUED_TO_DIFFERENT_DEVICE");
        E_SAKE_HANDSHAKE_PERMIT_ISSUED_TO_DIFFERENT_DEVICE = SakeError21;
        SakeError SakeError22 = new SakeError("E_SAKE_HANDSHAKE_ERROR_LAST", SakeJNI.E_SAKE_HANDSHAKE_ERROR_LAST_get());
        E_SAKE_HANDSHAKE_ERROR_LAST = SakeError22;
        swigValues = new SakeError[]{err_invalid, error_first, no_err, interface_misused, sync_invalid, chall_not_generated, SakeError7, SakeError8, SakeError9, SakeError10, SakeError11, SakeError12, SakeError13, SakeError14, SakeError15, SakeError16, SakeError17, SakeError18, SakeError19, SakeError20, SakeError21, SakeError22};
        swigNext = 0;
    }

    public SakeError(String str) {
        this.text = str;
        int i = swigNext;
        swigNext = i + 1;
        this.swigValue = i;
    }

    public SakeError(String str, int i) {
        this.text = str;
        this.swigValue = i;
        swigNext = i + 1;
    }

    /* renamed from: a */
    public static SakeError parseErrorCode(int i) {
        SakeError[] SakeErrorArr = swigValues;
        if (i < SakeErrorArr.length && i >= 0 && SakeErrorArr[i].swigValue == i) {
            return SakeErrorArr[i];
        }
        int i2 = 0;
        while (true) {
            SakeError[] SakeErrorArr2 = swigValues;
            if (i2 >= SakeErrorArr2.length) {
                throw new IllegalArgumentException("No enum " + SakeError.class + " with value " + i);
            } else if (SakeErrorArr2[i2].swigValue == i) {
                return SakeErrorArr2[i2];
            } else {
                i2++;
            }
        }
    }

    public String toString() {
        return this.text;
    }
}