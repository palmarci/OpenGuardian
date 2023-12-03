package com.medtronic.minimed.sake;


/* renamed from: com.medtronic.minimed.sake.SAKE_SECURE_MESSAGE_S */
/* loaded from: classes.dex */
public class NativeSakeSecureMessage {
    public transient boolean swigCMemOwn;
    private transient long swigCPtr;

    public NativeSakeSecureMessage() {
        this(SakeJNI.new_SAKE_SECURE_MESSAGE_S(), true);
    }

    public NativeSakeSecureMessage(long j, boolean z) {
        this.swigCMemOwn = z;
        this.swigCPtr = j;
    }

    /* renamed from: c */
    public static long m24084c(NativeSakeSecureMessage nativeSakeSecureMessage) {
        if (nativeSakeSecureMessage == null) {
            return 0L;
        }
        return nativeSakeSecureMessage.swigCPtr;
    }

    /* renamed from: a */
    public synchronized void deleteSecureMessage() {
        long j = this.swigCPtr;
        if (j != 0) {
            if (this.swigCMemOwn) {
                this.swigCMemOwn = false;
                SakeJNI.delete_SAKE_SECURE_MESSAGE_S(j);
            }
            this.swigCPtr = 0L;
        }
    }

    /* renamed from: b */
    public long getSecureMessageByteCount() {
        return SakeJNI.SAKE_SECURE_MESSAGE_S_byteCount_get(this.swigCPtr, this);
    }

    /* renamed from: d */
    public SwigPtr getBytes() {
        long SAKE_SECURE_MESSAGE_S_pBytes_get = SakeJNI.SAKE_SECURE_MESSAGE_S_pBytes_get(this.swigCPtr, this);
        if (SAKE_SECURE_MESSAGE_S_pBytes_get == 0) {
            return null;
        }
        return new SwigPtr(SAKE_SECURE_MESSAGE_S_pBytes_get, false);
    }

    /* renamed from: e */
    public void setByteCount(long j) {
        SakeJNI.SAKE_SECURE_MESSAGE_S_byteCount_set(this.swigCPtr, this, j);
    }

    /* renamed from: f */
    public void setBytes(SwigPtr swigPtr) {
        SakeJNI.SAKE_SECURE_MESSAGE_S_pBytes_set(this.swigCPtr, this, SwigPtr.getPointer(swigPtr));
    }

    public void finalize() {
        deleteSecureMessage();
    }
}