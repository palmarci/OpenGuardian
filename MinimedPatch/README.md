# patching the MiniMed Mobile v2.2.0 apk

## requirements
- jadx
- apktool
- uber-apk-signer
- adb access
- rooted android phone
- (frida server on phone & frida client on pc)
- unmodified v2.2.0 apk, sha256 checksum: `437556f9e562073293ace335468cc35a1a9c0e1cae79be58de5a3bf716511e2d`

## patching

### security checks
- dump classes (to let the app load the classes we should only attach): `frida -U -p (adb shell pidof com.medtronic.diabetes.minimedmobile.eu) -l list_classes.js > classes.txt` 
- find the interesting `com.medtronic.minimed.data.carelink.model.MobileSecurityConfigurations` class
- try and hook it to see if we can bypass the checks: `frida -U -f com.medtronic.diabetes.minimedmobile.eu -l hook_securityconfig.js`
- success! lets modify the app
	- `apktool d [apk]`
	- find the smali file: `grep -rnw . -e 'MobileSecurityConfigurations'`
	- override the constructor's argument to fake the `isDeveloperOptionsEnabled` and `isRooted` variables:
		- ```
			const/4 p1,0
   			const/4 p2,0
		  ```
### phone type & os version checks
- MobileConfigurationCompatibilityChecker has an interesting function: `z4.f.f` (./smali/z4/f.smali)
- we can inject the following code at the beginning of the function:
	```
    sget-object v0, Ly4/d$a;->SUPPORTED:Ly4/d$a;
    return-object v0
	```
### log encryption keys

- Medtronic does not use the adb logcat logs but instead stores the information in an encrypted database which they upload periodically to their servers
- This encryption key is hardcoded and can be found very easily, search for the text `Applying US logger encryption key`, it should be inside the classes `AppLoggerConfigurator` and `CarelinkAnalyticsConfigurator`
- You can generate an RSA 2048 keypair and patch every public key to your own
- You can manually force the app to export the diagnostic logs which will be at `/sdcard/Android/data/com.medtronic.diabetes.minimedmobile.eu/files/diagnostic logs`
- I also implemented a script which can encrypt & decrypt the logs using Medtronic's format, check the `logdecrypt` folder

### rebuild the apk
- execute `../rebuild_reinstall.sh` in the apktool decode output folder