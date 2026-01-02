package com.medtronic;

import com.medtronic.minimed.sake.*;import com.openguardian4.sakeproxy.Utils;

import java.util.Arrays;

public class SakeClientWrapper {

    private SakeCharPointer pKeyDatabaseBytes;
    private SakeClientWrapper SakeClientWrapper;
    private SakeAuthenticationStatus clientStatus = SakeAuthenticationStatus.UNAUTHORIZED;

    public SakeClientWrapper() {
        SakeClientWrapper SakeClientWrapper = new SakeClientWrapper();
        this.SakeClientWrapper = SakeClientWrapper;
    }


    public byte[] encrypt(byte[] bArr) {
        SakeSecureMessage SakeSecureMessage;
        boolean z = ((long) bArr.length) <= SakeJNI.MAX_SAKE_USER_MESSAGE_BYTE_COUNT_get();
        if (z) {
            SakeCharPointer SakeCharPointerVar = new SakeCharPointer(bArr.length);
            SakeJNIWrapper.memmove(SakeJNIWrapper.getValue(SakeCharPointerVar.GetAsVoidPtr()), bArr);
            SakeUserMessage SakeUserMessage = new SakeUserMessage();
            SakeUserMessage.setByteCount(bArr.length);
            SakeUserMessage.setPBytes(SakeCharPointerVar.GetAsVoidPtr());
            SakeSecureMessage = new SakeSecureMessage();
            z = SakeJNIWrapper.SecureForSending(this.SakeClientWrapper, SakeUserMessage,
                    SakeSecureMessage);
            if (!z && this.clientStatus == SakeAuthenticationStatus.AUTHORIZED) {
                setStatus(SakeAuthenticationStatus.LINK_SYNC_LOST);
            }
        } else {
            SakeSecureMessage = null;
            Utils.logPrint("data with invalid length given to encrypt!");
        }
        if (z) {
            return SakeJNIWrapper.copyData8(SakeSecureMessage.getPBytes(),
                    (int) SakeSecureMessage.getSecureMessageByteCount());
        }
        return null;
    }

    public byte[] decrypt(byte[] bArr) {
        SakeUserMessage SakeUserMessage;
        boolean z = ((long) bArr.length) <= SakeJNI.MAX_SAKE_SECURE_MESSAGE_BYTE_COUNT_get();
        if (z) {
            SakeCharPointer SakeCharPointerVar = new SakeCharPointer(bArr.length);
            SakeJNIWrapper.memmove(SakeJNIWrapper.getValue(SakeCharPointerVar.GetAsVoidPtr()), bArr);
            SakeSecureMessage SakeSecureMessage = new SakeSecureMessage();
            SakeSecureMessage.setByteCount(bArr.length);
            SakeSecureMessage.setPBytes(SakeCharPointerVar.GetAsVoidPtr());
            SakeUserMessage = new SakeUserMessage();
            z = SakeJNIWrapper.InsecureAfterReceive(this.SakeClientWrapper, SakeSecureMessage,
                    SakeUserMessage);
            if (!z && this.clientStatus == SakeAuthenticationStatus.AUTHORIZED) {
                setStatus(SakeAuthenticationStatus.LINK_SYNC_LOST);
            }
        } else {
            SakeUserMessage = null;
            Utils.logPrint("data with invalid length given to decrypt!!");

        }

        if (z) {
            return SakeJNIWrapper.copyData8(SakeUserMessage.getPBytes(),
                    (int) SakeUserMessage.getByteCount());
        }
        return null;
    }

    public byte[] doHandshake(byte[] bArr) {
        SakeSecureMessage SakeSecureMessage;
        if (bArr != null) {
            int min = (int) Math.min(bArr.length, SakeJNI.MAX_SAKE_SECURE_MESSAGE_BYTE_COUNT_get());
            SakeCharPointer SakeCharPointerVar = new SakeCharPointer(bArr.length);
            SakeJNIWrapper.memmove(SakeJNIWrapper.getValue(SakeCharPointerVar.GetAsVoidPtr()),
                    min < bArr.length ? Arrays.copyOf(bArr, min) : bArr);
            SakeSecureMessage = new SakeSecureMessage();
            SakeSecureMessage.setByteCount(bArr.length);
            SakeSecureMessage.setPBytes(SakeCharPointerVar.GetAsVoidPtr());
        } else {
            SakeSecureMessage = null;
        }
        SakeSecureMessage out_msg = new SakeSecureMessage();
        SakeHandshakeStatus curr_status = SakeJNIWrapper.fromInt(this.SakeClientWrapper, SakeSecureMessage,
                out_msg);
        if (curr_status == SakeHandshakeStatus.E_SAKE_HANDSHAKE_FAILED) {
            setStatus(SakeAuthenticationStatus.FAILED);
            String errorReason = this.SakeClientWrapper.getLastError().toString();
            Utils.logPrint("Sake handshake failed with error " + errorReason);
            throw new Exception(errorReason);
        }
        setStatus(handshakeToAuthStatus(curr_status));
        if (out_msg.getSecureMessageByteCount() > 0) {
            return SakeJNIWrapper.cdata(SakeJNIWrapper.getValue(out_msg.getPBytes()),
                    (int) out_msg.getSecureMessageByteCount());
        }
        return null;
    }

    public SakeAuthenticationStatus getClientStatus() {
        return this.clientStatus;
    }

    private final void setStatus(SakeAuthenticationStatus sakeAuthStatus) {
        this.clientStatus = sakeAuthStatus;
        Utils.logPrint("SAKE client status changed, new status: " + sakeAuthStatus);
        // for (ISakeClientWrapper.InterfaceC7174a interfaceC7174a : this.listeners) {
        // interfaceC7174a.mo4949a(sakeAuthStatus);
        // }
    }

    public boolean initKeyDb(byte[] keydb) {
        Utils.logPrint("using key db = " + Utils.bytesToHexStr(keydb));
        SakeCharPointer keydbbuffer = new SakeCharPointer(keydb.length);
        this.pKeyDatabaseBytes = keydbbuffer;
        SakeJNIWrapper.memmove(SakeJNIWrapper.getValue(keydbbuffer.GetAsVoidPtr()), keydb);
        SakeKeyDatabase SakeKeyDatabase = new SakeKeyDatabase();
        boolean isDbOpen = SakeJNIWrapper.KeyDatabase_Open(SakeKeyDatabase, this.pKeyDatabaseBytes.GetAsVoidPtr(),
                keydb.length);

        if (isDbOpen) {
            SakeJNIWrapper.clientInit(SakeClientWrapper, SakeKeyDatabase);
        } else {
        //    Utils.logPrint("Failed to open provided key database:");
        }
        return isDbOpen;
    }


    public String getLastError() {
        return this.SakeClientWrapper.getLastError().toString();
    }

}