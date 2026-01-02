# OpenGuardian

This repo contains tools and data for reverse engineering the Medtronic Guardian Continous Glucose Monitoring Systems and Insulin Pumps. 

Join our [Discord](https://discord.gg/tb4egy8VYh)!

![banner](./docs/attachments/banner.png)

## Sub projects

- JadxProjects 
	- it contains the [JADX](https://github.com/skylot/jadx) projects to reverse engineer the APK contents

- PythonConnector
  - python scripts to be used on a PC that can connect and talk to the devices
  - **contains a full SAKE implementation!**

- OpenGuardian4
	 - Java code for parsing and decoding already decrypted BT messages. 
	 - this is intended to be used in an Android app hopefully in the foreseeable future
	- limited support for GATT characteristics

- SakeRE
	- the [Ghidra](https://github.com/NationalSecurityAgency/ghidra) project to reverse engineer the Medtronic's crypto library called SAKE
	- using an older version of the library built for ARMv7 from the Minimed 2.1.0
	
- (Sakeproxy)
	- an Android application which uses the prebuilt SAKE libraries extracted from the original APKs
	- it provides a simple HTTP API and it can be used to perform the crypto functions without an actual device
	- only a temporary solution until we can fully reverse enginer the crypto library, but will be very useful for development
	- it only supports one user at a time

- (NativeSakeRE)
  - a native android ELF that can load sake and call its exported functions
  - this is a painless experience (at least compared to what was before) and works very nicely with ghidra
  
- (SakeproxyClient)
  - shitty arduino and python wrapper for the Sakeproxy HTTP API 

- Data 
	- decrypted SAKE "key databases"
	- logs from the frida Monitor script
	- GATT service & char information
	- sniffed BT traffic in pcap format
	- 
	
- FridaScripts
	- various scripts to be used with frida (including the Monitor)
	- TODO: go trough the old backups and upload everything

- Docs
  

- Tools
	- log_decrypt
		- the app contains functionality to dump decrypted logs into a zip file for debugging with Medtronic's email support (?)
		- the algorithm has been reversed, after manually patching the public key in the APK, it can be decrypted and will contain juicy info for reversing
	- db_decrypt
		- scripts to dump the AndroidKeyStore, where the keys are stored for the app's databases
	- minimal API for CareLink Cloud
		- I have reversed the API where the data upload/download takes place
		- the code now has been integrated in some open-source projects, this is just a mirror (see  [carelink-python-client](https://github.com/ondrej1024/carelink-python-client), [xDripCareLinkFollower](https://github.com/benceszasz/xDripCareLinkFollower/))
	- key_db
    	- crc calculation and validation of old and incorrect key database dumps 
	- .. other scripts used for dev
	- TODO: sort out scripts used for MITM