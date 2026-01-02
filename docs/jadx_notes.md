## JADX notes

1. get the Guardian apk here: https://m.apkpure.com/guardian%E2%84%A2/com.medtronic.diabetes.guardian/download
	(md5sum of the original file: 865d1872c197c073830c02416d63f294)
2. place it in the project's root folder under the name "Guardian_134.apk"
3. get jadx from here: https://github.com/skylot/jadx/releases
4. open the project
5. start reversing: you will mostly need just two buttons: X for references, N for rename, and also the search menu

### finding the converter map

1.  **just search for classes > ConverterMap** 

or from sketch:


1. look for a uuid string of a gatt service (for example "00000202-0000-1000-0000-009132591325")
2. there should be 1/2 results, check the call for the super
3. look for an injection of a class into an interface, thats the target class
4. right click on the class > find usage, and find a class which maps other classes, starting with Void, String, Byte[] to other random classes
5. those are the conveters and the target classes that we are interested in

