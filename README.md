# OpenGuardian4

Reverse engineering the BT communication for the Medtronic Guardian 4 glucose monitoring system. This work is based on the Guardian 1.3.4 application.

## sub-projects
- Sakeproxy: android app to interface with the native sake crpyto library
- Guardianmon: 
	- frida script to hook and monitor the messages
	- example dumps 
	- python script to decode the dumps into a human readable format
- OpenGuardian4: the java parser to decode the decrypted messages
- libsake_re: the ghidra project to fully reverse engineer the armv7 sake library

## jadx usage
1. get the apk here: https://m.apkpure.com/guardian%E2%84%A2/com.medtronic.diabetes.guardian/download
	(md5sum of the original file: 865d1872c197c073830c02416d63f294.
2. place it under the name "Guardian_134.apk"
3. get jadx from here: https://github.com/skylot/jadx/releases
4. open the project
5. profit (you will mostly need just two buttons: X for references and N for rename.

#### finding the converter map

1.  **just search for classes > ConverterMap** 

or from sketch:


1. look for a uuid string of a gatt service (for example "00000202-0000-1000-0000-009132591325".
2. there should be 1/2 results, check the call for the super
3. look for an injection of a class into an interface, thats the target class
4. right click on the class > find usage, and find a class which maps other classes, starting with Void, String, Byte[] to other random classes
5. those are the conveters and the target classes that we are interested in


## libsake ghidra
- TODO

## Guardianmon

Usage: 

0. get a rooted android phone
1. download frida server (https://frida.re/docs/android/.
3. connect to adb via usb 
4. start your frida server as root
5. frida -U -f com.medtronic.diabetes.guardian -l guardianmon.js
6. save the output to a txt file and use the dump printer to inspect the communication