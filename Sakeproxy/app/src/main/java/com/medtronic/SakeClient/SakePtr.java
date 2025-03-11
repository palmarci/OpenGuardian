package com.medtronic.SakeClient;

public class SakePtr {
    private transient long ptr;

    public SakePtr() {
        this.ptr = 0L;
    }

    public SakePtr(long ptr, boolean z) {
        this.ptr = ptr;
    }

    /* renamed from: a */
    public static long getPointer(SakePtr SakePtr) {
        if (SakePtr == null) {
            return 0L;
        }
        return SakePtr.ptr;
    }
}