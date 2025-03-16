package com.medtronic.minimed.sake;

public class SakeCharPointer {
    public transient boolean alive;
    private transient long swigCPtr;

    public SakeCharPointer(int size) {
        this(SakeJNI.new_p_uint8_t(size), true);
    }

    public SakeCharPointer(long j, boolean z) {
        this.alive = z;
        this.swigCPtr = j;
    }

    /* renamed from: a */
    public SakeVoidPointer GetAsVoidPtr() {
        long SakeCharPointer_cast = SakeJNI.p_uint8_t_cast(this.swigCPtr, this);
        if (SakeCharPointer_cast == 0) {
            return null;
        }
        return new SakeVoidPointer(SakeCharPointer_cast, false);
    }

    /* renamed from: b */
    public synchronized void destroy() {
        long j = this.swigCPtr;
        if (j != 0) {
            if (this.alive) {
                this.alive = false;
                SakeJNI.delete_p_uint8_t(j);
            }
            this.swigCPtr = 0L;
        }
    }

    public void finalize() {
        destroy();
    }
}