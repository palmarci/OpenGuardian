package com.medtronic.minimed.sake;


//import p148k9.SakeHandshakeStatus;

/* loaded from: classes.dex */
public class SakeServer {

    /* renamed from: a */
    private transient long ptr;

    /* renamed from: b */
    protected transient boolean alive;

    protected SakeServer(long j10, boolean z10) {
        this.alive = z10;
        this.ptr = j10;
    }

    /* renamed from: b */
    protected static long getValue(SakeServer SakeServer) {
        if (SakeServer == null) {
            return 0L;
        }
        return SakeServer.ptr;
    }

    /* renamed from: a */
    public synchronized void destroy() {
        long j10 = this.ptr;
        if (j10 != 0) {
            if (this.alive) {
                this.alive = false;
                SakeJNI.delete_SAKE_SERVER_S(j10);
            }
            this.ptr = 0L;
        }
    }

    /* renamed from: c */
    public SakeError getLastError() {
        return SakeError.parseErrorCode(SakeJNI.SAKE_SERVER_S_lastError_get(this.ptr, this));
    }

    protected void finalize() {
        destroy();
    }

    public SakeServer() {
        this(SakeJNI.new_SAKE_SERVER_S(), true);
    }
}