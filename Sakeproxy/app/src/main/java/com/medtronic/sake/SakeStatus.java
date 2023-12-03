package com.medtronic.sake;

/* renamed from: e.g.g.b.b */
/* loaded from: classes.dex */
public final class SakeStatus {
    public static final SakeStatus E_SAKE_HANDSHAKE_FAILED;
    public static final SakeStatus E_SAKE_HANDSHAKE_IN_PROGRESS;
    public static final SakeStatus E_SAKE_HANDSHAKE_SUCCESSFUL;
    private static int swigNext;
    private static SakeStatus[] swigValues;
    private final String swigName;
    private final int swigValue;

    static {
        SakeStatus sakeStatus = new SakeStatus("E_SAKE_HANDSHAKE_SUCCESSFUL");
        E_SAKE_HANDSHAKE_SUCCESSFUL = sakeStatus;
        SakeStatus sakeStatus2 = new SakeStatus("E_SAKE_HANDSHAKE_FAILED");
        E_SAKE_HANDSHAKE_FAILED = sakeStatus2;
        SakeStatus sakeStatus3 = new SakeStatus("E_SAKE_HANDSHAKE_IN_PROGRESS");
        E_SAKE_HANDSHAKE_IN_PROGRESS = sakeStatus3;
        swigValues = new SakeStatus[]{sakeStatus, sakeStatus2, sakeStatus3};
        swigNext = 0;
    }

    public SakeStatus(String str) {
        this.swigName = str;
        int i = swigNext;
        swigNext = i + 1;
        this.swigValue = i;
    }

    /* renamed from: a */
    public static SakeStatus getStatus(int i) {
        SakeStatus[] sakeStatusArr = swigValues;
        if (i < sakeStatusArr.length && i >= 0 && sakeStatusArr[i].swigValue == i) {
            return sakeStatusArr[i];
        }
        int i2 = 0;
        while (true) {
            SakeStatus[] sakeStatusArr2 = swigValues;
            if (i2 >= sakeStatusArr2.length) {
                throw new IllegalArgumentException("No enum " + SakeStatus.class + " with value " + i);
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