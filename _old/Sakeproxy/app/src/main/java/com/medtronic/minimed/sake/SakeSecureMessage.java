package com.medtronic.minimed.sake;


/* renamed from: com.medtronic.SakeInternal.SakeSecureMessage */
/* loaded from: classes.dex */
public class SakeSecureMessage {
    public transient boolean alive;
    private transient long ptr;

    public SakeSecureMessage() {
        this(SakeJNI.new_SAKE_SECURE_MESSAGE_S(), true);
    }

    public SakeSecureMessage(long j, boolean z) {
        this.alive = z;
        this.ptr = j;
    }

    /* renamed from: c */
    public static long getValue(SakeSecureMessage SakeSecureMessage) {
        if (SakeSecureMessage == null) {
            return 0L;
        }
        return SakeSecureMessage.ptr;
    }

    /* renamed from: a */
    public synchronized void deleteSecureMessage() {
        long j = this.ptr;
        if (j != 0) {
            if (this.alive) {
                this.alive = false;
                SakeJNI.delete_SAKE_SECURE_MESSAGE_S(j);
            }
            this.ptr = 0L;
        }
    }

    /* renamed from: b */
    public long getByteCount() {
        return SakeJNI.SAKE_SECURE_MESSAGE_S_byteCount_get(this.ptr, this);
    }

    /* renamed from: d */
    public SakeVoidPointer getPBytes() {
        long SAKE_SECURE_MESSAGE_S_pBytes_get = SakeJNI.SAKE_SECURE_MESSAGE_S_pBytes_get(this.ptr, this);
        if (SAKE_SECURE_MESSAGE_S_pBytes_get == 0) {
            return null;
        }
        return new SakeVoidPointer(SAKE_SECURE_MESSAGE_S_pBytes_get, false);
    }

    /* renamed from: e */
    public void setByteCount(long j) {
        SakeJNI.SAKE_SECURE_MESSAGE_S_byteCount_set(this.ptr, this, j);
    }

    /* renamed from: f */
    public void setPBytes(SakeVoidPointer SakeVoidPointer) {
        SakeJNI.SAKE_SECURE_MESSAGE_S_pBytes_set(this.ptr, this, SakeVoidPointer.getValue(SakeVoidPointer));
    }

    public void finalize() {
        deleteSecureMessage();
    }
}