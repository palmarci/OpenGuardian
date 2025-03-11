package com.medtronic.SakeClient;

import com.medtronic.minimed.sake.*;
import com.openguardian4.sakeproxy.Utils;

import java.util.Arrays;

public class SakeClient {

    private p_uint8_t pKeyDatabaseBytes;
    private NativeSakeClient nativeSakeClient;
    private SakeClientStatus clientStatus = SakeClientStatus.UNAUTHORIZED;

    public SakeClient() {
        NativeSakeClient nativeSakeClient = new NativeSakeClient();
        this.nativeSakeClient = nativeSakeClient;
    }

    private static SakeClientStatus adaptHandshakeStatus(SakeHandshakeStatus sakeStatus) {
        return sakeStatus == SakeHandshakeStatus.E_SAKE_HANDSHAKE_SUCCESSFUL ? SakeClientStatus.AUTHORIZED
                : sakeStatus == SakeHandshakeStatus.E_SAKE_HANDSHAKE_IN_PROGRESS ? SakeClientStatus.IN_PROGRESS
                        : sakeStatus == SakeHandshakeStatus.E_SAKE_HANDSHAKE_FAILED ? SakeClientStatus.FAILED
                                : SakeClientStatus.UNAUTHORIZED;
    }

    public byte[] encrypt(byte[] bArr) {
        NativeSakeSecureMessage nativeSakeSecureMessage;
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
            Utils.logPrint("data with invalid length given to encrypt!");
        }
        if (z) {
            return SakeJNIWrapper.cdataUint(nativeSakeSecureMessage.getBytes(),
                    (int) nativeSakeSecureMessage.getSecureMessageByteCount());
        }
        return null;
    }

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
            Utils.logPrint("data with invalid length given to decrypt!!");

        }

        if (z) {
            return SakeJNIWrapper.cdataUint(nativeSakeUserMessage.m24077d(),
                    (int) nativeSakeUserMessage.getByteCount());
        }
        return null;
    }

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
        NativeSakeSecureMessage out_msg = new NativeSakeSecureMessage();
        SakeHandshakeStatus curr_status = SakeJNIWrapper.getStatus(this.nativeSakeClient, nativeSakeSecureMessage,
                out_msg);
        if (curr_status == SakeHandshakeStatus.E_SAKE_HANDSHAKE_FAILED) {
            setStatus(SakeClientStatus.FAILED);
            String errorReason = this.nativeSakeClient.getLastError().toString();
            Utils.logPrint("Sake handshake failed with error " + errorReason);
            throw new SakeClientException(errorReason);
        }
        setStatus(adaptHandshakeStatus(curr_status));
        if (out_msg.getSecureMessageByteCount() > 0) {
            return SakeJNIWrapper.cdata(SakeJNIWrapper.getPointer(out_msg.getBytes()),
                    (int) out_msg.getSecureMessageByteCount());
        }
        return null;
    }

    public SakeClientStatus getClientStatus() {
        return this.clientStatus;
    }

    private final void setStatus(SakeClientStatus sakeAuthStatus) {
        this.clientStatus = sakeAuthStatus;
        Utils.logPrint("SAKE client status changed, new status: " + sakeAuthStatus);
        // for (Isakeclient.InterfaceC7174a interfaceC7174a : this.listeners) {
        // interfaceC7174a.mo4949a(sakeAuthStatus);
        // }
    }

    public boolean initKeyDb(byte[] keydb) {
        Utils.logPrint("using key db = " + Utils.bytesToHexStr(keydb));
        p_uint8_t keydbbuffer = new p_uint8_t(keydb.length);
        this.pKeyDatabaseBytes = keydbbuffer;
        SakeJNIWrapper.memMove(SakeJNIWrapper.getPointer(keydbbuffer.GetAsPointer()), keydb);
        NativeSakeKeyDatabase nativeSakeKeyDatabase = new NativeSakeKeyDatabase();
        boolean isDbOpen = SakeJNIWrapper.keyDbOpen(nativeSakeKeyDatabase, this.pKeyDatabaseBytes.GetAsPointer(),
                keydb.length);

        if (isDbOpen) {
            SakeJNIWrapper.clientInit(nativeSakeClient, nativeSakeKeyDatabase);
        } else {
        //    Utils.logPrint("Failed to open provided key database:");
        }
        return isDbOpen;
    }


    public String getLastError() {
        return this.nativeSakeClient.getLastError().toString();
    }

}