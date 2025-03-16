package com.medtronic.minimed.sake;


/* renamed from: e.g.g.b.b */
/* loaded from: classes.dex */
public final class SakeHandshakeStatus {
    public static final SakeHandshakeStatus E_SAKE_HANDSHAKE_FAILED;
    public static final SakeHandshakeStatus E_SAKE_HANDSHAKE_IN_PROGRESS;
    public static final SakeHandshakeStatus E_SAKE_HANDSHAKE_SUCCESSFUL;

    private static int swigNext;
    private static SakeHandshakeStatus[] swigValues;
    private final String swigName;
    private final int swigValue;

    static {
        SakeHandshakeStatus sakeStatus = new SakeHandshakeStatus("E_SAKE_HANDSHAKE_SUCCESSFUL");
        E_SAKE_HANDSHAKE_SUCCESSFUL = sakeStatus;
        SakeHandshakeStatus sakeStatus2 = new SakeHandshakeStatus("E_SAKE_HANDSHAKE_FAILED");
        E_SAKE_HANDSHAKE_FAILED = sakeStatus2;
        SakeHandshakeStatus sakeStatus3 = new SakeHandshakeStatus("E_SAKE_HANDSHAKE_IN_PROGRESS");
        E_SAKE_HANDSHAKE_IN_PROGRESS = sakeStatus3;



        swigValues = new SakeHandshakeStatus[]{sakeStatus, sakeStatus2, sakeStatus3};
        swigNext = 0;
    }

    public SakeHandshakeStatus(String str) {
        this.swigName = str;
        int i = swigNext;
        swigNext = i + 1;
        this.swigValue = i;
    }

    /* renamed from: a */
    public static SakeHandshakeStatus fromInt(int i) {
        SakeHandshakeStatus[] sakeStatusArr = swigValues;
        if (i < sakeStatusArr.length && i >= 0 && sakeStatusArr[i].swigValue == i) {
            return sakeStatusArr[i];
        }
        int i2 = 0;
        while (true) {
            SakeHandshakeStatus[] sakeStatusArr2 = swigValues;
            if (i2 >= sakeStatusArr2.length) {
                throw new IllegalArgumentException("No enum " + SakeHandshakeStatus.class + " with value " + i);
            } else if (sakeStatusArr2[i2].swigValue == i) {
                return sakeStatusArr2[i2];
            } else {
                i2++;
            }
        }
    }

    public String toString() {
        return this.swigName;
    }
}