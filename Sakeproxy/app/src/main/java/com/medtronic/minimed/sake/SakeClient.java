package com.medtronic.minimed.sake;


//import p123e.p416g.p517g.p535b.SakeException;

/* renamed from: com.medtronic.SakeInternal.SAKE_CLIENT_S */
/* loaded from: classes.dex */
public class SakeClient {
    public transient boolean alive;
    private transient long ptr;

    public SakeClient() {
        this(SakeJNI.new_SAKE_CLIENT_S(), true);
    }

    public SakeClient(long j, boolean z) {
        this.alive = z;
        this.ptr = j;
    }

    /* renamed from: b */
    public static long getValue(SakeClient SakeClient) {
        if (SakeClient == null) {
            return 0L;
        }
        return SakeClient.ptr;
    }

    /* renamed from: a */
    public synchronized void destroy() {
        long j = this.ptr;
        if (j != 0) {
            if (this.alive) {
                this.alive = false;
                SakeJNI.delete_SAKE_CLIENT_S(j);
            }
            this.ptr = 0L;
        }
    }

    /* renamed from: c */
    public SakeException getLastError() {
        return SakeException.parseErrorCode(SakeJNI.SAKE_CLIENT_S_lastError_get(this.ptr, this));
    }

    public void finalize() {
        destroy();
    }


}