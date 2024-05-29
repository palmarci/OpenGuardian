# THIS IS BIASED AND OUTDATED! JUST FOR HISTORICAL PURPOSES!!!

# Medtronic Guardian 4 technical info

If you wish to use the Guardian 4 CGM device, there are a few interesting things to know.

## The App
The original app is bad and barely usable. However, the technology behind it and the actual device are quite good. There are a few tweaks you can make to have a great experience (see below).

The app is built on Flutter and runs on the Dart VM. It has two native ELF binary components: one is called the SCP (likely standing for Security Content Provider), and the other is the SAKE library, used for secure communication with the transmitter.

The app implements various security measures:

- White and blacklists for tested device models and Android versions.
- Root detection.
- SafetyNet checks.
- Database encryption (via SQLCipher).

## The Communication
The app pairs with the transmitter device using Bluetooth Low Energy and utilizes GATT services for communication. They implement a few standard GATT services and have custom, encrypted ones as well.

The services running on the device include:

1. **Device Info Service (0000180A-0000-1000-8000-00805F9B34FB)**
   - Unencrypted, GATT standard.

2. **Battery Service (0000180F-0000-1000-8000-00805F9B34FB)**
   - Unencrypted, GATT standard.

3. **CGM Service (0000181F-0000-1000-8000-00805F9B34FB)**
   - GATT standard with extended values; appears unencrypted but may require different parsing.
   - CGM Measurement (00002aa7-0000-1000-8000-00805f9b34fb).
   -  CGM Session Start Time (00002aaa-0000-1000-8000-00805f9b34fb)
	-  CGM Session Run Time (00002aab-0000-1000-8000-00805f9b34fb)
	-   Record Access Control Point (00002a52-0000-1000-8000-00805f9b34fb)
	- CGM Specific Ops Control Point (00002aac-0000-1000-8000-00805f9b34fb)
	-  **cgmMeasurementMdtExtChar (00000200-0000-1000-0000-009132591325)**
		 - Probably encrypted.
	    -   sensorConnectedState (00000201-0000-1000-0000-009132591325)
	    -   sensorExpirationTime (00000202-0000-1000-0000-009132591325)
	    -   sensorCalibartionTime (00000203-0000-1000-0000-009132591325)
	    -   algorithmData (00000205-0000-1000-0000-009132591325)
	    -   calibrationTimeRecommended (00000204-0000-1000-0000-009132591325)

4. **Connection Management Service (4484fae0-be34-11e4-851e-0002a5d5c51b)**
   - Probably encrypted.
   - Client Requested Params (500d8e40-be34-11e4-9b24-0002a5d5c51b).
   - Active Params (5f0b2420-be34-11e4-bc62-0002a5d5c51b).

5. **SAKE Service (0000FE82-0000-1000-8000-00805F9B34FB)**
   - Used for establishing and maintaining encrypted communication.
   - SAKE Port (0000FE82-0000-1000-0000-009132591325).

6. **History and Trace Service (00000300-0000-1000-0000-00913259132)**
   - Probably encrypted and used for storing and providing old measurements that were not synced with the app due to being outside of Bluetooth range.
   - ???

## The Encryption
There is a whitepaper available with the same name: [SAKE: scalable authenticated key exchange for mobile e-health networks](https://onlinelibrary.wiley.com/doi/epdf/10.1002/sec.1198). The native SAKE library is used with a Java wrapper class, and it's not difficult to call it from your own code (there is an x86_64 library inside the APK).

The app connects to Medtronic servers while pairing with the transmitter, and the interesting communication is encrypted from that point. I did not have the time and motivation to reverse engineer this because I found an easier solution (see below).

## The Improvements
The main problems of the app can be divided into three categories:

1. The app will not run on your phone.
2. The app cannot run in the background properly.
3. The app is still not very good when it's working.

The first problem is the harder one to fix. You can buy a newer Android phone or try switching to iOS. Maybe you have an older Android device in your drawer, but then your only choice is to run custom firmware. If you choose to run custom firmware, your problem will be the aforementioned Root and SafetyNet checks. In short, you have to install Magisk, hide it, turn on Zygisk mode, configure the Denylist, install a SafetyNet fixer module, and pass the checks. If any check fails the SCP will not let you connect to the SAKE server while trying to search for transmitters, you will get a connection error. 
**IMPORTANT NOTE**: If the app detects once that your phone is rooted or is not passing SafetyNet, it will remember that, and you will need to clear the app's data and cache (or reinstall it). This took a painfully long time to figure out.

The second problem is actually not the developers' fault. Modern Android devices are notorious for killing apps in the background. There is a very good website that will help you fix this problem: [dontkillmyapp.com](https://dontkillmyapp.com/).

The third problem is also easily fixable: don't use the app. There is a perfect, free, and open-source alternative called [xDrip](https://jamorham.github.io/#xdrip-plus). The only problem is that due to encryption, the transmitters are not supported, but you can bypass this by enabling the built-in [CareLink Follower](https://github.com/benceszasz/xDripCareLinkFollower). This will pull your measurements from the Medtronic servers and will basically work as a proxy between your phone and the transmitter device. Or even better, there is a Companion Mode in xDrip, which will read the glucose values from the persistent notification of the Guardian app. 

## Author's Advice
I went down with the custom Android firmware route.

I am currently using two phones: one is an old Android phone with LineageOS installed, and the other is my daily driver. Technically you dont not need two phones, I just did not want to bother hacking my main phone, but probably i will do that in the future.

The old phone has one job, which is to run the Medtronic app and send the data 24/7 to their servers. I have disabled every blood sugar alert, and the phone also has a cheap SIM card with prepaid mobile data (usage is just a few MBs a week). I can put this phone inside my little bag where I store my medicine, which is with me all the time anyways. It can run a few days with one charge but on mobile data, the phone drains faster than on WiFi. 

My other phone runs xDrip, where I get the alerts and can monitor the data in real-time, add notes, and log my 
insulin usage. I can export the database and generate nice HTML graphs using my [Python script](https://github.com/palmarci/xdrip-visualizer).

You can also try hosting your own [Nightscout](https://github.com/nightscout/cgm-remote-monitor) instance and enabling the Cloud Sync feature in xDrip. With the aforementioned Companion Mode you could bypass Medtronic's Carelink servers (except when pairing the transmitter)