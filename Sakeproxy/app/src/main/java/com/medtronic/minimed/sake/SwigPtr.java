package com.medtronic.minimed.sake;

/* loaded from: classes.dex */
public class SwigPtr {
    private transient long swigCPtr;

    public SwigPtr() {
        this.swigCPtr = 0L;
    }

    public SwigPtr(long j, boolean z) {
        this.swigCPtr = j;
    }

    /* renamed from: a */
    public static long getPointer(SwigPtr swigPtr) {
        if (swigPtr == null) {
            return 0L;
        }
        return swigPtr.swigCPtr;
    }
}