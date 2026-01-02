package com.medtronic.minimed.sake;

//import p123e.p416g.p517g.p535b.SakeVoidPointer;

/* renamed from: com.medtronic.SakeInternal.SakeUserMessage */
/* loaded from: classes.dex */
public class SakeUserMessage {
    public transient boolean swigCMemOwn;
    private transient long swigCPtr;

    public SakeUserMessage() {
        this(SakeJNI.new_SAKE_USER_MESSAGE_S(), true);
    }

    public SakeUserMessage(long j, boolean z) {
        this.swigCMemOwn = z;
        this.swigCPtr = j;
    }

    /* renamed from: c */
    public static long getValue(SakeUserMessage SakeUserMessage) {
        if (SakeUserMessage == null) {
            return 0L;
        }
        return SakeUserMessage.swigCPtr;
    }

    /* renamed from: a */
    public synchronized void delete() {
        long j = this.swigCPtr;
        if (j != 0) {
            if (this.swigCMemOwn) {
                this.swigCMemOwn = false;
                SakeJNI.delete_SAKE_USER_MESSAGE_S(j);
            }
            this.swigCPtr = 0L;
        }
    }

    /* renamed from: b */
    public long getByteCount() {
        return SakeJNI.SAKE_USER_MESSAGE_S_byteCount_get(this.swigCPtr, this);
    }

    /* renamed from: d */
    public SakeVoidPointer getPBytes() {
        long SAKE_USER_MESSAGE_S_pBytes_get = SakeJNI.SAKE_USER_MESSAGE_S_pBytes_get(this.swigCPtr, this);
        if (SAKE_USER_MESSAGE_S_pBytes_get == 0) {
            return null;
        }
        return new SakeVoidPointer(SAKE_USER_MESSAGE_S_pBytes_get, false);
    }

    /* renamed from: e */
    public void setByteCount(long j) {
        SakeJNI.SAKE_USER_MESSAGE_S_byteCount_set(this.swigCPtr, this, j);
    }

    /* renamed from: f */
    public void setPBytes(SakeVoidPointer SakeVoidPointer) {
        SakeJNI.SAKE_USER_MESSAGE_S_pBytes_set(this.swigCPtr, this, SakeVoidPointer.getValue(SakeVoidPointer));
    }

    public void finalize() {
        delete();
    }
}