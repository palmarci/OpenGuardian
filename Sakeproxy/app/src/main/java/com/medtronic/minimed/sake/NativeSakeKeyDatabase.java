package com.medtronic.minimed.sake;


/* renamed from: com.medtronic.minimed.sake.SAKE_KEY_DATABASE_S */
/* loaded from: classes.dex */
public class NativeSakeKeyDatabase {
    public transient boolean swigCMemOwn;
    private transient long swigCPtr;

    public NativeSakeKeyDatabase() {
        this(SakeJNI.new_SAKE_KEY_DATABASE_S(), true);
    }

    public NativeSakeKeyDatabase(long j, boolean z) {
        this.swigCMemOwn = z;
        this.swigCPtr = j;
    }

    /* renamed from: b */
    public static long getPointer(NativeSakeKeyDatabase nativeSakeKeyDatabase) {
        if (nativeSakeKeyDatabase == null) {
            return 0L;
        }
        return nativeSakeKeyDatabase.swigCPtr;
    }

    /* renamed from: a */
    public synchronized void m24088a() {
        long j = this.swigCPtr;
        if (j != 0) {
            if (this.swigCMemOwn) {
                this.swigCMemOwn = false;
                SakeJNI.delete_SAKE_KEY_DATABASE_S(j);
            }
            this.swigCPtr = 0L;
        }
    }

    public void finalize() {
        m24088a();
    }
}