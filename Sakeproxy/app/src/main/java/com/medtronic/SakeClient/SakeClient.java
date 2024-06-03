package com.medtronic.SakeClient;

/*
import com.medtronic.minimed.sake.NativeSakeClient;
import com.medtronic.minimed.sake.NativeSakeKeyDatabase;
import com.medtronic.minimed.sake.NativeSakeSecureMessage;
import com.medtronic.minimed.sake.NativeSakeUserMessage;

import com.medtronic.minimed.sake.p_uint8_t;
*/
import com.medtronic.minimed.sake.*;
import com.openguardian4.sakeproxy.Utils;

import java.util.Arrays;

public class SakeClient {
    // private static final InterfaceC9254c LOGGER = C9255d.m255i("SakeClientImpl");
    private p_uint8_t pKeyDatabaseBytes;
    private NativeSakeClient nativeSakeClient;
    // private final List<Isakeclient.InterfaceC7174a> listeners = new
    // CopyOnWriteArrayList();
    private SakeClientStatus clientStatus = SakeClientStatus.UNAUTHORIZED;

    /* renamed from: e.g.f.a.d.a.w$a */
    /* loaded from: classes.dex */

    static {
        System.loadLibrary("android-sake-lib");
    }

    public SakeClient(byte[] bArr) {
        if (!initClient(bArr)) {
            throw new SakeClientException("KEY_INIT_FAILED");
        } else {
            Utils.logPrint("Sake initialized successfully");
        }
    }

    /* renamed from: i */
    private static SakeClientStatus adaptHandshakeStatus(SakeHandshakeStatus sakeStatus) {
        return sakeStatus == SakeHandshakeStatus.E_SAKE_HANDSHAKE_SUCCESSFUL ? SakeClientStatus.AUTHORIZED
                : sakeStatus == SakeHandshakeStatus.E_SAKE_HANDSHAKE_IN_PROGRESS ? SakeClientStatus.IN_PROGRESS
                        : sakeStatus == SakeHandshakeStatus.E_SAKE_HANDSHAKE_FAILED ? SakeClientStatus.FAILED
                                : SakeClientStatus.UNAUTHORIZED;
    }

    // @Override // p123e.p416g.p471f.p472a.p473d.Sake.Isakeclient
    /* renamed from: a */
    public byte[] encrypt(byte[] bArr) {
        NativeSakeSecureMessage nativeSakeSecureMessage;
        // Object SakeJNI;
        boolean z = ((long) bArr.length) <= SakeJNI.MAX_SAKE_USER_MESSAGE_BYTE_COUNT_get();
        if (z) {
            p_uint8_t p_uint8_tVar = new p_uint8_t(bArr.length);
            SakeJNIWrapper.memMove(SakeJNIWrapper.getPointer(p_uint8_tVar.GetAsPointer()), bArr);
            NativeSakeUserMessage nativeSakeUserMessage = new NativeSakeUserMessage();
            nativeSakeUserMessage.m24076e(bArr.length);
            nativeSakeUserMessage.m24075f(p_uint8_tVar.GetAsPointer());
            nativeSakeSecureMessage = new NativeSakeSecureMessage();
            z = SakeJNIWrapper.isSecureForSending(this.nativeSakeClient, nativeSakeUserMessage,
                    nativeSakeSecureMessage);
            if (!z && this.clientStatus == SakeClientStatus.AUTHORIZED) {
                setStatus(SakeClientStatus.LINK_SYNC_LOST);
            }
        } else {
            nativeSakeSecureMessage = null;
        }
        if (z) {
            return SakeJNIWrapper.cdataUint(nativeSakeSecureMessage.getBytes(),
                    (int) nativeSakeSecureMessage.getSecureMessageByteCount());
        }
        Utils.logPrint("does not seem to be able to get");
        return null;
    }

    // @Override // p123e.p416g.p471f.p472a.p473d.Sake.Isakeclient
    /* renamed from: b */
    public byte[] decrypt(byte[] bArr) {
        NativeSakeUserMessage nativeSakeUserMessage;
        boolean z = ((long) bArr.length) <= SakeJNI.MAX_SAKE_SECURE_MESSAGE_BYTE_COUNT_get();
        if (z) {
            p_uint8_t p_uint8_tVar = new p_uint8_t(bArr.length);
            SakeJNIWrapper.memMove(SakeJNIWrapper.getPointer(p_uint8_tVar.GetAsPointer()), bArr);
            NativeSakeSecureMessage nativeSakeSecureMessage = new NativeSakeSecureMessage();
            nativeSakeSecureMessage.setByteCount(bArr.length);
            nativeSakeSecureMessage.setBytes(p_uint8_tVar.GetAsPointer());
            nativeSakeUserMessage = new NativeSakeUserMessage();
            z = SakeJNIWrapper.isInsecureAfterReceive(this.nativeSakeClient, nativeSakeSecureMessage,
                    nativeSakeUserMessage);
            if (!z && this.clientStatus == SakeClientStatus.AUTHORIZED) {
                setStatus(SakeClientStatus.LINK_SYNC_LOST);
            }
        } else {
            nativeSakeUserMessage = null;
        }

        if (z) {
            return SakeJNIWrapper.cdataUint(nativeSakeUserMessage.m24077d(),
                    (int) nativeSakeUserMessage.getByteCount());
        }
        return null;
    }

    // @Override // p123e.p416g.p471f.p472a.p473d.Sake.Isakeclient
    /* renamed from: d */
    public byte[] doHandshake(byte[] bArr) {
        NativeSakeSecureMessage nativeSakeSecureMessage;
        if (bArr != null) {
            int min = (int) Math.min(bArr.length, SakeJNI.MAX_SAKE_SECURE_MESSAGE_BYTE_COUNT_get());
            p_uint8_t p_uint8_tVar = new p_uint8_t(bArr.length);
            SakeJNIWrapper.memMove(SakeJNIWrapper.getPointer(p_uint8_tVar.GetAsPointer()),
                    min < bArr.length ? Arrays.copyOf(bArr, min) : bArr);
            nativeSakeSecureMessage = new NativeSakeSecureMessage();
            nativeSakeSecureMessage.setByteCount(bArr.length);
            nativeSakeSecureMessage.setBytes(p_uint8_tVar.GetAsPointer());
        } else {
            nativeSakeSecureMessage = null;
        }
        NativeSakeSecureMessage nativeSakeSecureMessage2 = new NativeSakeSecureMessage();
        SakeHandshakeStatus m3607b = SakeJNIWrapper.getStatus(this.nativeSakeClient, nativeSakeSecureMessage,
                nativeSakeSecureMessage2);
        if (m3607b == SakeHandshakeStatus.E_SAKE_HANDSHAKE_FAILED) {
            setStatus(SakeClientStatus.FAILED);
            String errorReason = this.nativeSakeClient.getLastError().toString();
            Utils.logPrint("Sake handshake failed with error " + errorReason);
            throw new SakeClientException(errorReason);
        }
        setStatus(adaptHandshakeStatus(m3607b));
        if (nativeSakeSecureMessage2.getSecureMessageByteCount() > 0) {
            return SakeJNIWrapper.cdata(SakeJNIWrapper.getPointer(nativeSakeSecureMessage2.getBytes()),
                    (int) nativeSakeSecureMessage2.getSecureMessageByteCount());
        }
        return null;
    }

    // p123e.p416g.p471f.p472a.p473d.Sake.Isakeclient
    /* renamed from: f */
    public SakeClientStatus getClientStatus() {
        return this.clientStatus;
    }

    /* renamed from: g */
    private final void setStatus(SakeClientStatus sakeAuthStatus) {
        this.clientStatus = sakeAuthStatus;
        Utils.logPrint("SAKE client status changed, new status: " + sakeAuthStatus);
        // for (Isakeclient.InterfaceC7174a interfaceC7174a : this.listeners) {
        // interfaceC7174a.mo4949a(sakeAuthStatus);
        // }
    }

    /* renamed from: h */
    public boolean initClient(byte[] keydb) {
        p_uint8_t keydbbuffer = new p_uint8_t(keydb.length);
        this.pKeyDatabaseBytes = keydbbuffer;
        SakeJNIWrapper.memMove(SakeJNIWrapper.getPointer(keydbbuffer.GetAsPointer()), keydb);
        NativeSakeKeyDatabase nativeSakeKeyDatabase = new NativeSakeKeyDatabase();
        boolean isDbOpen = SakeJNIWrapper.keyDbOpen(nativeSakeKeyDatabase, this.pKeyDatabaseBytes.GetAsPointer(),
                keydb.length);

        if (isDbOpen) {
            NativeSakeClient nativeSakeClient = new NativeSakeClient();
            this.nativeSakeClient = nativeSakeClient;
            SakeJNIWrapper.clientInit(nativeSakeClient, nativeSakeKeyDatabase);
        } else {
            Utils.logPrint("Failed to open provided key database:");
        }
        return isDbOpen;
    }
}