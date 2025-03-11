# OpenGuardian

Reverse engineering the BT communication for the Medtronic Guardian Continous Glucose Monitoring Systems and Insulin Pumps. This work originally started on the Guardian 4 Sensor and the long term goal is to support the insulin pumps too. 

Check the discord for more info: https://discord.gg/tb4egy8VYh (no Medtronic spies please!)

![alt text](data/banner.png)

## Project structure

- Jadx_Projects: 
	- it contains the [JADX](https://github.com/skylot/jadx) projects to reverse engineer the APK contents  
	
- OpenGuardian4
	 - the Java code for parsing and decoding already decrypted BT messages. 
	 - this is intended to be used in an Android app hopefully in the forseable future
	- limited support for UUIDs, but can also parse some Guardian 4 messages

- Sake_RE
	- the [Ghidra](https://github.com/NationalSecurityAgency/ghidra) project to reverse engineer the Medtronic's crypto library called SAKE
	- using an older version of the library built for ARMv7
	- SAKE has two parts: a client and a server side, currently the focus is on the server side (mobile app) for now
	- i got to a point where i think i can not go futher with only static reversing
	- current goal is to debug out the unknowns and the crypto with ghidra
	- a guy has successfully paired (?) with a medtronic device, i am positive that he knows what he is talking about, but i could not reach him for more details, [see this](./data/info.png)
	
- Sakeproxy
	- an Android application which uses the prebuilt SAKE libraries extracted from the original APKs
	- it provides a simple HTTP API and it can be used to perform the crypto functions without an actual device
	- only a temporary solution until we can fully reverse enginer the crypto library, but will be very useful for development
	- it only supports one user at a time
	- <del>also I am planning on hosting some kind of development server for other people to talk with their devices</del> the server for it is currently offline due to lack of interest, but i can start up again if necessary
	- **Sakeproxy is now also used to simulate a real application around sake, since it is A LOT easier to debug**
- SakeproxyClient
  - shitty arduino and python wrapper for the Sakeproxy HTTP API 

- Data 
	- decrypted SAKE "key databases"
	- logs from the Monitor script
	- UUID information
	- sniffed BT traffic in pcap format
	- TODO: document them properly, maybe create a wiki on github
	
- Scripts
	- various scripts to be used with frida (including the Monitor)
	- TODO: go trough the old backups and upload everything

- Docs
	- random guides and useful notes
	- TODO: organize them

- Tools
	- log_decrypt
		- the app contains functionality to dump decrypted logs into a zip file for debugging with Medtronic's email support (???)
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