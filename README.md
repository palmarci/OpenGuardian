# guardian-134-decompilation

## java - jadx usage
- md5sum of the original file: 865d1872c197c073830c02416d63f294
- you can get it here: https://m.apkpure.com/guardian%E2%84%A2/com.medtronic.diabetes.guardian/download
- place it under the name "Guardian_134.apk"
- get jadx from here: https://github.com/skylot/jadx/releases
- open the project
- you will mostly need just two buttons: X for references and N for rename

### finding the converter map

- **just search for classes > ConverterMap** or
	- look for a uuid string of a gatt service (for example "00000202-0000-1000-0000-009132591325")
	- there should be 1/2 results, check the call for the super
	- it will inject a class into an interface, thats the class that it will decode into
	- right click on the class > find usage, and find the class which maps classes starting with Void, String, Byte[] to other random classes
	- you will see the conveters and the classes mapped there


## sake - ghidra
- TBD