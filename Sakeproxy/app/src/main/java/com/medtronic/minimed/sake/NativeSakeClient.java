package com.medtronic.minimed.sake;


//import p123e.p416g.p517g.p535b.SakeException;

/* renamed from: com.medtronic.minimed.sake.SAKE_CLIENT_S */
/* loaded from: classes.dex */
public class NativeSakeClient {
    public transient boolean swigCMemOwn;
    private transient long swigCPtr;

    public NativeSakeClient() {
        this(SakeJNI.new_SAKE_CLIENT_S(), true);
    }

    public NativeSakeClient(long j, boolean z) {
        this.swigCMemOwn = z;
        this.swigCPtr = j;
    }

    /* renamed from: b */
    public static long getPointer(NativeSakeClient nativeSakeClient) {
        if (nativeSakeClient == null) {
            return 0L;
        }
        return nativeSakeClient.swigCPtr;
    }

    /* renamed from: a */
    public synchronized void m24091a() {
        long j = this.swigCPtr;
        if (j != 0) {
            if (this.swigCMemOwn) {
                this.swigCMemOwn = false;
                SakeJNI.delete_SAKE_CLIENT_S(j);
            }
            this.swigCPtr = 0L;
        }
    }

    /* renamed from: c */
    public SakeException getLastError() {
        return SakeException.parseErrorCode(SakeJNI.SAKE_CLIENT_S_lastError_get(this.swigCPtr, this));
    }

    public void finalize() {
        m24091a();
    }
}