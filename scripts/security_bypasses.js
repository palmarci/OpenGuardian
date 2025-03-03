// https://codeshare.frida.re/@voker2311/android-common-security-bypasses/

/* 
    Author: Akshay Shinde (v0k3r)
    Organization: XYSec Labs (Appknox)
*/

Java.perform(function() {
    var androidSettings = ['adb_enabled', 'development_settings_enabled', 'play_protect_enabled']; // different properties can be added over here
    var sdkVersion = Java.use('android.os.Build$VERSION');
    console.log("Android SDK Version : " + sdkVersion.SDK_INT.value);

    var settingGlobal = Java.use('android.provider.Settings$Secure');
    settingGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, def) {
        if (name == androidSettings[0]) {
            console.log('[+] Bypassing USB Debugging protections')
            return 0;
        }
        if (name == androidSettings[1]) {
            console.log('[+] Bypassing Developer Options')
            return 0;
        }
        if (name == androidSettings[2]) {
            console.log('[+] Bypassing Play Protect checks')
            return 1;
        }
        var ret = this.getInt(cr, name, def);
        return ret;
    }
});