# guardian-134-decompilation

- md5sum of the original file: 865d1872c197c073830c02416d63f294
- you can get it here: https://m.apkpure.com/guardian%E2%84%A2/com.medtronic.diabetes.guardian/download
- place it under the name "Guardian_134.apk"
- get jadx from here: https://github.com/skylot/jadx/releases

### how to find the decoder setup

- look for a uuid string of a gatt service (for example "00000202-0000-1000-0000-009132591325")
- there should be 1/2 results, check the call for the super
- it will inject a class into an interface, thats the class that it will decode into
- right click on the class > find usage, there should be one usage in the "DecodeMapper"
- you will see the decoders and the classes mapped there