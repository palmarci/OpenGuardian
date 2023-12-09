# OpenGuardian4

Reverse engineering the BT communication for the Medtronic Guardian 4 glucose monitoring system. This work is based on the Guardian 1.3.4 application, but there is a big overlap with the Medtronic insulin pumps. 

## sub-projects
- Sakeproxy: android app to interface with the native sake crpyto library
- Guardianmon: 
	- frida script to hook and monitor the messages
	- example dumps 
	- python script to decode the dumps into a human readable format
- OpenGuardian4: the java parser to decode the decrypted messages
- Sake_RE: the ghidra project to fully reverse engineer the armv7 sake library
- MinimedPatch: guide & patched apk for the Minimed Mobile version 2.2.0 to remove whitelist, root and developer option checks at startup + debug log decryption
- CarelinkApi: script which can communicate with the CareLink mobile API

## jadx usage
1. get the Guardian apk here: https://m.apkpure.com/guardian%E2%84%A2/com.medtronic.diabetes.guardian/download
	(md5sum of the original file: 865d1872c197c073830c02416d63f294)
2. place it in the project's root folder under the name "Guardian_134.apk"
3. get jadx from here: https://github.com/skylot/jadx/releases
4. open the project
5. start reversing: you will mostly need just two buttons: X for references, N for rename, and also the search menu

#### finding the converter map

1.  **just search for classes > ConverterMap** 

or from sketch:


1. look for a uuid string of a gatt service (for example "00000202-0000-1000-0000-009132591325".
2. there should be 1/2 results, check the call for the super
3. look for an injection of a class into an interface, thats the target class
4. right click on the class > find usage, and find a class which maps other classes, starting with Void, String, Byte[] to other random classes
5. those are the conveters and the target classes that we are interested in


## Sake_RE
- TODO
- https://github.com/Ayrx/JNIAnalyzer

## Guardianmon

Usage: 

0. get a rooted android phone
1. download frida server (https://frida.re/docs/android)
3. connect to adb via usb 
4. start your frida server as root
5. frida -U -f com.medtronic.diabetes.guardian -l guardianmon.js
6. save the output to a txt file and use the dump printer to inspect the communication