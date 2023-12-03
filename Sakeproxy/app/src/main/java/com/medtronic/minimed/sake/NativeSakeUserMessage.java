package com.medtronic.minimed.sake;

//import p123e.p416g.p517g.p535b.SwigPtr;

/* renamed from: com.medtronic.minimed.sake.SAKE_USER_MESSAGE_S */
/* loaded from: classes.dex */
public class NativeSakeUserMessage {
    public transient boolean swigCMemOwn;
    private transient long swigCPtr;

    public NativeSakeUserMessage() {
        this(SakeJNI.new_SAKE_USER_MESSAGE_S(), true);
    }

    public NativeSakeUserMessage(long j, boolean z) {
        this.swigCMemOwn = z;
        this.swigCPtr = j;
    }

    /* renamed from: c */
    public static long getPointer(NativeSakeUserMessage nativeSakeUserMessage) {
        if (nativeSakeUserMessage == null) {
            return 0L;
        }
        return nativeSakeUserMessage.swigCPtr;
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
    public SwigPtr m24077d() {
        long SAKE_USER_MESSAGE_S_pBytes_get = SakeJNI.SAKE_USER_MESSAGE_S_pBytes_get(this.swigCPtr, this);
        if (SAKE_USER_MESSAGE_S_pBytes_get == 0) {
            return null;
        }
        return new SwigPtr(SAKE_USER_MESSAGE_S_pBytes_get, false);
    }

    /* renamed from: e */
    public void m24076e(long j) {
        SakeJNI.SAKE_USER_MESSAGE_S_byteCount_set(this.swigCPtr, this, j);
    }

    /* renamed from: f */
    public void m24075f(SwigPtr swigPtr) {
        SakeJNI.SAKE_USER_MESSAGE_S_pBytes_set(this.swigCPtr, this, SwigPtr.getPointer(swigPtr));
    }

    public void finalize() {
        delete();
    }
}