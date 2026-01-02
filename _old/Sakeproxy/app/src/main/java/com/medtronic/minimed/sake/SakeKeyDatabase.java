package com.medtronic.minimed.sake;


/* renamed from: com.medtronic.SakeInternal.SakeKeyDatabase */
/* loaded from: classes.dex */
public class SakeKeyDatabase {
    public transient boolean alive;
    private transient long ptr;

    public SakeKeyDatabase() {
        this(SakeJNI.new_SAKE_KEY_DATABASE_S(), true);
    }

    public SakeKeyDatabase(long j, boolean z) {
        this.alive = z;
        this.ptr = j;
    }

    /* renamed from: b */
    public static long getValue(SakeKeyDatabase SakeKeyDatabase) {
        if (SakeKeyDatabase == null) {
            return 0L;
        }
        return SakeKeyDatabase.ptr;
    }

    /* renamed from: a */
    public synchronized void destroy() {
        long j = this.ptr;
        if (j != 0) {
            if (this.alive) {
                this.alive = false;
                SakeJNI.delete_SAKE_KEY_DATABASE_S(j);
            }
            this.ptr = 0L;
        }
    }

    public void finalize() {
        destroy();
    }
}