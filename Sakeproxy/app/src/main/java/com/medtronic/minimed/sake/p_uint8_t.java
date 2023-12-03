package com.medtronic.minimed.sake;

public class p_uint8_t {
    public transient boolean swigCMemOwn;
    private transient long swigCPtr;

    public p_uint8_t(int size) {
        this(SakeJNI.new_p_uint8_t(size), true);
    }

    public p_uint8_t(long j, boolean z) {
        this.swigCMemOwn = z;
        this.swigCPtr = j;
    }

    /* renamed from: a */
    public SwigPtr GetAsPointer() {
        long p_uint8_t_cast = SakeJNI.p_uint8_t_cast(this.swigCPtr, this);
        if (p_uint8_t_cast == 0) {
            return null;
        }
        return new SwigPtr(p_uint8_t_cast, false);
    }

    /* renamed from: b */
    public synchronized void m24072b() {
        long j = this.swigCPtr;
        if (j != 0) {
            if (this.swigCMemOwn) {
                this.swigCMemOwn = false;
                SakeJNI.delete_p_uint8_t(j);
            }
            this.swigCPtr = 0L;
        }
    }

    public void finalize() {
        m24072b();
    }
}