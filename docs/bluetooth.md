# BT communication

All devices use Bluetooth Low Energy. The Pumps acts in central mode, while the sensors act as a Peripheral. They do NOT use LE Secure Connections, meaning the communication should be crackable and sniffable. (https://github.com/mikeryan/crackle).

The sensor can be easily connected with the provided [python script](/PythonConnector/). The pump is a bit different and it requires MITM protection. It still currently under investigation.

The devices utilize standardized and custom GATT services and characteristics. The interesting data is encrypted using a Medtronic protocol called SAKE (Secure? Authenticated? Key Exchange?). The protocol seems to have 2 versions, a v1.0 and a v2.0. They use the service ID 0xfe82 (and perhaps 0xfe81 for the older one).

Please check out the [Communication Matrix](./attachments/com_matrix.ods) for more info.


## MAC addresses

The sensor MACs start with DC-16-A2 (Medtronic Diabetes, https://standards-oui.ieee.org/oui/oui.txt), while the pump uses a private address. The lower 3 bytes are the serial number, if converted to hex. For example:

CGM GT1122867N -> 1122867 = 0x112233 -> MAC should be DC:16:A2:11:22:33.


## Device names

The mobile apps and the pump use a pseudo device name. The apps on first startup will generate a "Mobile xxxxxx" like string, where the number is always a random 6 digit **odd** number. 

The pump probably derives it's name from its own MAC, in a string "Pump xxxxxxH" which is similar to the sensor.