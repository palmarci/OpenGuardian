package com.medtronic.sake;

public class VoidPtr {
    private transient long swigCPtr;

    public VoidPtr() {
        this.swigCPtr = 0L;
    }

    public VoidPtr(long j, boolean z) {
        this.swigCPtr = j;
    }

    /* renamed from: a */
    public static long m3609a(VoidPtr voidPtr) {
        if (voidPtr == null) {
            return 0L;
        }
        return voidPtr.swigCPtr;
    }
}