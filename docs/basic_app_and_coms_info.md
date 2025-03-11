## The (Guardian) App

The app is built on Flutter and runs on the Dart VM. It has two native ELF binary components: one is called the SCP (likely standing for Security ? Provider), and the other is the SAKE library, used for secure communication with the transmitter.

The app implements various security measures:

- White and blacklists for tested device models and Android versions.
- Root detection.
- SafetyNet checks.
- Database encryption (via SQLCipher).

If the app is patched it will NOT be able to receive the SAKE keys, because PlayIntegrity will detect it but MITM is still possible for login and the "Teneo secure communications" (after some Frida scripts).


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
