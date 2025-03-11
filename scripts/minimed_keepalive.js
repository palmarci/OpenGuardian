setTimeout(function() {
    Java.perform(function() {
        console.log("[+] minimed mobile v2.2.1 lifesupport hook started")

        // hook compatibility and root checks
        var MobileSecurityConfigurations = Java.use("com.medtronic.minimed.data.carelink.model.MobileSecurityConfigurations");
        let MobileConfigurationCompatibilityChecker = Java.use("z4.f");
        let MobileApprovedConfigurationsManager = Java.use("y4.d$a");
        let ConfigurationManager = Java.use("com.ca.mas.core.conf.ConfigurationManager");
        MobileSecurityConfigurations["$init"].implementation = function(z10, z11) {
            console.log(`[+] MobileSecurityConfigurations.$init is called: z10=${z10}, z11=${z11} -> returning false for both`);
            this["$init"](false, false);
        };
        MobileConfigurationCompatibilityChecker["f"].implementation = function() {
            let toret = MobileApprovedConfigurationsManager.SUPPORTED.value;
            console.log(`[+] MobileConfigurationCompatibilityChecker.m21904f is called, returning ${toret}`);
            return toret;
        };

        // remove ssl pinning
        ConfigurationManager["isSslPinningEnabled"].implementation = function() {
            console.log(`ConfigurationManager.isSslPinningEnabled is called, return false`);
            //  let result = this["isSslPinningEnabled"]();
            // console.log(`ConfigurationManager.isSslPinningEnabled result=${result}`);
            return false;
        };
        let WebSocketCommunicator = Java.use("com.medtronic.securerepositories.internal.websocket.WebSocketCommunicator");
        WebSocketCommunicator["addCertificate"].implementation = function (certificate) {
            console.log(`WebSocketCommunicator.addCertificate is called: certificate=${certificate}`);
            return;
            //this["addCertificate"](certificate);
        };


        // hooks for debugging
        let keydb = null;
        let AppSetupPresenterBase = Java.use("com.medtronic.minimed.ui.startupwizard.AppSetupPresenterBase");
        AppSetupPresenterBase["showCareLinkErrorMessage"].overload('java.lang.Runnable', 'java.lang.Runnable', 'com.medtronic.minimed.ui.util.d', 'java.lang.Throwable').implementation = function(runnable, runnable2, carelinkDialogMetadata, th) {
            console.log(`AppSetupPresenterBase.showCareLinkErrorMessage is called: runnable=${runnable}, runnable2=${runnable2}, carelinkDialogMetadata=${carelinkDialogMetadata}, th=${th}`);
            this["showCareLinkErrorMessage"](runnable, runnable2, carelinkDialogMetadata, th);
        };
        let PairPumpPresenterBase = Java.use("com.medtronic.minimed.ui.startupwizard.PairPumpPresenterBase");
        PairPumpPresenterBase["onSakeKeysRetrievingError"].implementation = function () {
            console.log(`PairPumpPresenterBase.onSakeKeysRetrievingError is called`);
            this["onSakeKeysRetrievingError"]();
        };
        PairPumpPresenterBase["lambda$handlePairingFailed$29"].implementation = function (aVar) {
            console.log(`PairPumpPresenterBase.lambda$handlePairingFailed$29 is called: aVar=${aVar}`);
            this["lambda$handlePairingFailed$29"](aVar);
        };
        let PumpConnectionManagerImpl = Java.use("com.medtronic.minimed.ngpsdk.connect.api.b3");
        PumpConnectionManagerImpl["E2"].implementation = function (th) {
            console.log(`PumpConnectionManagerImpl.m10511E2 is called: th=${th}`);
            let result = this["E2"](th);
            console.log(`PumpConnectionManagerImpl.m10511E2 result=${result}`);
            return result;
        };
        let AttestationJob = Java.use("com.medtronic.securerepositories.internal.sequencejobs.network.AttestationJob");
        AttestationJob["getGooglePlayServiceStatus"].implementation = function () {
            console.log(`AttestationJob.getGooglePlayServiceStatus is called`);
            let result = this["getGooglePlayServiceStatus"]();
            console.log(`AttestationJob.getGooglePlayServiceStatus result=${result}`);
            return result;
        };
        /*
        let EncryptionUtility = Java.use("com.medtronic.securerepositories.internal.utility.EncryptionUtility");
        EncryptionUtility["decryptCbcAes"].implementation = function (str, str2) {
            console.log(`EncryptionUtility.decryptCbcAes is called: str=${str}, str2=${str2}`);
            let result = this["decryptCbcAes"](str, str2);
            console.log(`EncryptionUtility.decryptCbcAes result=${result}`);
            return result;
        };
        */
        /*
        let C3673c = Java.use("com.medtronic.minimed.sake.c");
        C3673c["i"].implementation = function (c3672b, bArr) {
            if (keydb == null) {
                keydb = bArr;
            //    console.log("keydb probably set!:");
             //   console.log(bArr);
            }
            console.log(`C3673c.memmove is called: c3672b=${c3672b}, bArr=${bArr}`);
            this["i"](c3672b, bArr);
        };*/

        let InterfaceC5243c = Java.use("hd.c");
        InterfaceC5243c["debug"].overload('java.lang.String').implementation = function (str) {
            console.log(`sake.debug is called: str=${str}`);
            this["debug"](str);
        };
       // let InterfaceC5243c = Java.use("hd.c");
        InterfaceC5243c["warn"].overload('java.lang.String').implementation = function (str) {
            console.log(`sake.warn is called: str=${str}`);
            this["warn"](str);
        };
     //   let InterfaceC5243c = Java.use("hd.c");
        InterfaceC5243c["error"].overload('java.lang.String', 'java.lang.Throwable').implementation = function (str, th) {
            console.log(`sake.error is called: str=${str}, th=${th}`);
            this["error"](str, th);
        };
        let SAKE_SERVER_S = Java.use("com.medtronic.minimed.sake.SAKE_SERVER_S");
        SAKE_SERVER_S["c"].implementation = function () {
            //console.log(`SAKE_SERVER_S.m11241c is called`);
            let result = this["c"]();
            console.log(`SAKE_SERVER_S.GET LAST ERROR=${result}`);
            return result;
        };

        let AbstractC5408q = Java.use("io.reactivex.q");
        AbstractC5408q["b"].implementation = function () {
            //console.log(`maybe se.m15157b is called`);
            let result = this["b"]();
            console.log(`MAYBE SAKE KEY=${result}`);
            return result;
        };
        

        // remove sslv3 support
        let TLSSocketFactory = Java.use("com.ca.mas.core.io.ssl.TLSSocketFactory");
        let SSLSocket = Java.use("javax.net.ssl.SSLSocket");
        TLSSocketFactory["enableTLS"].implementation = function(socket) {
            console.log(`TLSSocketFactory.enableTLS is called: socket=${socket}`);
            try {
                let sslSocket = Java.cast(socket, SSLSocket);
                let supported = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"];
                sslSocket.setEnabledProtocols(supported);
                console.log("SSLSocket protocols updated");
            } catch (e) {
                console.log("skipping possibly non-ssl socket: " + e);
            }
            return socket;
        };
    });
}, 0);