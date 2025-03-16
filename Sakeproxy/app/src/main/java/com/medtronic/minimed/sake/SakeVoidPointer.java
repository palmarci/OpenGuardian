package com.medtronic.minimed.sake;

/* loaded from: classes.dex */
public class SakeVoidPointer {
    private transient long swigCPtr;

    public SakeVoidPointer() {
        this.swigCPtr = 0L;
    }

    public SakeVoidPointer(long j, boolean z) {
        this.swigCPtr = j;
    }

    /* renamed from: a */
    public static long getValue(SakeVoidPointer SakeVoidPointer) {
        if (SakeVoidPointer == null) {
            return 0L;
        }
        return SakeVoidPointer.swigCPtr;
    }
}