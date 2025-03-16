package com.medtronic;

import com.medtronic.minimed.sake.*;import com.openguardian4.sakeproxy.Utils;

import com.medtronic.SakeCommon;
import com.medtronic.minimed.sake.*;
import com.medtronic.minimed.sake.*;

import java.util.Arrays;


public class SakeServerWrapper {

   
    /* renamed from: a */
  //  private final List<SakeServer.a> f9051a = new CopyOnWriteArrayList();

    /* renamed from: b */
    private SakeAuthenticationStatus authStatus = SakeAuthenticationStatus.UNAUTHORIZED;

    /* renamed from: c */
    private SakeServer sakeServer;

    /* renamed from: d */
    private SakeCharPointer keyDbPtr;


    /* renamed from: g */
    private void setAuthStatus(SakeAuthenticationStatus authenticationStatus) {
        this.authStatus = authenticationStatus;
        Utils.logPrint("SAKE server status changed, new status: " + authenticationStatus);
    //    Iterator<SakeServer.a> it = this.f9051a.iterator();
      //  while (it.hasNext()) {
      //      it.next().mo10848a(authenticationStatus);
      //  }
    }

 

    /* renamed from: i */
    public boolean initKeyDb(byte[] keydb) {
        this.sakeServer = new SakeServer();
        SakeKeyDatabase SakeKeyDatabase = new SakeKeyDatabase();
        this.authStatus = SakeAuthenticationStatus.UNAUTHORIZED;
        SakeCharPointer keydbptr = new SakeCharPointer(keydb.length);
        this.keyDbPtr = keydbptr;
        SakeJNIWrapper.memmove(SakeCommon.ConvertPtrType(keydbptr.GetAsVoidPtr()), keydb);
        if (SakeJNIWrapper.KeyDatabase_Open(SakeKeyDatabase, this.keyDbPtr.GetAsVoidPtr(), keydb.length)) {
            Utils.logPrint("Successfully opened the provided key database.");
        } else {
            Utils.logPrint("Failed to open the provided key database.");
            return false;
        }
        SakeJNIWrapper.Server_Init(this.sakeServer, SakeKeyDatabase);
        return true;
    }

    public void Destroy() {
        SakeJNIWrapper.Server_ServerDestroy(this.sakeServer);
    }


    //@Override // com.medtronic.minimed.ngpsdk.connect.pump.sake.SakeServer
    /* renamed from: a */
   /*
    public void mo10842a() {
        SakeAuthenticationStatus authenticationStatus = this.authStatus;
        SakeAuthenticationStatus authenticationStatus2 = SakeAuthenticationStatus.UNAUTHORIZED;
        if (authenticationStatus != authenticationStatus2) {
            setAuthStatus(authenticationStatus2);
        }
        SakeServer sake_server_s = this.sakeServer;
        if (sake_server_s != null) {
            SakeJNIWrapper.ServerDestroy(sake_server_s);
            this.sakeServer.m11176a();
            this.sakeServer = null;
        }
        SakeCharPointer SakeCharPointer = this.keyDbPtr;
        if (SakeCharPointer != null) {
            SakeCharPointer.finalize2();
            this.keyDbPtr = null;
        }
    }
    */

    //@Override // com.medtronic.minimed.ngpsdk.connect.pump.sake.SakeServer
    /* renamed from: b */
//   public void mo10843b(SakeServer.a aVar) {
 //       this.f9051a.remove(aVar);
 //   }

    //@Override // com.medtronic.minimed.ngpsdk.connect.pump.sake.SakeServer
    /* renamed from: c */
    public final byte[] doHandshake(byte[] bArr) {
        SakeSecureMessage SakeSecureMessage;
     //   m10850h();
        if (bArr != null) {
            int min = (int) Math.min(bArr.length, SakeCommon.maxSecureMessageByteCount);
            SakeSecureMessage = new SakeSecureMessage();
            SakeVoidPointer ConvertPtrType = SakeCommon.ConvertPtrType(SakeSecureMessage.getPBytes());
            if (min < bArr.length) {
                bArr = Arrays.copyOf(bArr, min);
            }
            SakeJNIWrapper.memmove(ConvertPtrType, bArr);
            SakeSecureMessage.setByteCount(min);
        } else {
            SakeSecureMessage = null;
        }
        SakeSecureMessage SakeSecureMessage2 = new SakeSecureMessage();
        SakeHandshakeStatus handshakeStatus = SakeJNIWrapper.Server_GetHandshakeStatus(this.sakeServer, SakeSecureMessage, SakeSecureMessage2);
        if (handshakeStatus == SakeHandshakeStatus.E_SAKE_HANDSHAKE_FAILED) {
            Utils.logPrint("Sake handshake failed with error " + this.sakeServer.getLastError());
        }
        setAuthStatus(SakeCommon.handshakeToAuthStatus(handshakeStatus));
       // setAuthStatus(m10852j(handshakeStatus));
        if (SakeSecureMessage2.getByteCount() > 0) {
            return SakeJNIWrapper.cdata(SakeCommon.ConvertPtrType(SakeSecureMessage2.getPBytes()), (int) SakeSecureMessage2.getByteCount());
        }
        return null;
    }

    //@Override // com.medtronic.minimed.ngpsdk.connect.pump.sake.SakeServer
    public final byte[] decrypt(byte[] bArr) {
        SakeUserMessage sake_user_message_s;
     //   m10850h();
        boolean z10 = ((long) bArr.length) <= SakeCommon.maxSecureMessageByteCount;
        if (z10) {
            SakeSecureMessage SakeSecureMessage = new SakeSecureMessage();
            SakeJNIWrapper.memmove(SakeCommon.ConvertPtrType(SakeSecureMessage.getPBytes()), bArr);
            SakeSecureMessage.setByteCount(bArr.length);
            sake_user_message_s = new SakeUserMessage();
            z10 = SakeJNIWrapper.Server_UnsecureAfterReceiving(this.sakeServer, SakeSecureMessage, sake_user_message_s);
            if (!z10 && this.authStatus == SakeAuthenticationStatus.AUTHORIZED) {
                setAuthStatus(SakeAuthenticationStatus.LINK_SYNC_LOST);
            }
        } else {
            sake_user_message_s = null;
        }
        if (z10) {
            return SakeJNIWrapper.cdata(SakeCommon.ConvertPtrType(sake_user_message_s.getPBytes()), (int) sake_user_message_s.getByteCount());
        }
        return null;
    }

    //@Override // com.medtronic.minimed.ngpsdk.connect.pump.sake.SakeServer
    /* renamed from: e */
    public SakeAuthenticationStatus getAuthStatus() {
        return this.authStatus;
    }

    //@Override // com.medtronic.minimed.ngpsdk.connect.pump.sake.SakeServer
    public final byte[] encrypt(byte[] bArr) {
        SakeSecureMessage SakeSecureMessage;
     //   m10850h();
        boolean z10 = ((long) bArr.length) <= SakeCommon.maxUserMessageByteCount;
        if (z10) {
            SakeUserMessage sake_user_message_s = new SakeUserMessage();
            SakeJNIWrapper.memmove(SakeCommon.ConvertPtrType(sake_user_message_s.getPBytes()), bArr);
            sake_user_message_s.setByteCount(bArr.length);
            SakeSecureMessage = new SakeSecureMessage();
            z10 = SakeJNIWrapper.Server_SecureForSending(this.sakeServer, sake_user_message_s, SakeSecureMessage);
            if (!z10 && this.authStatus == SakeAuthenticationStatus.AUTHORIZED) {
                setAuthStatus(SakeAuthenticationStatus.LINK_SYNC_LOST);
            }
        } else {
            SakeSecureMessage = null;
        }
        if (z10) {
            return SakeJNIWrapper.cdata(SakeCommon.ConvertPtrType(SakeSecureMessage.getPBytes()), (int) SakeSecureMessage.getByteCount());
        }
        return null;
    }

    //@Override // com.medtronic.minimed.ngpsdk.connect.pump.sake.SakeServer
    /* renamed from: f */
    /*public void mo10847f(SakeServer.a aVar) {
        this.f9051a.add(aVar);
    }*/

    //@Override // com.medtronic.minimed.ngpsdk.connect.pump.sake.SakeServer
    public boolean isAlive() {
        return this.sakeServer != null;
    }

    public String getLastError() {
        return this.sakeServer.getLastError().toString();
    }
}