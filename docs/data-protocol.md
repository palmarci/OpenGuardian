# Data protocol

This documents what we know about the way an insulin pump exchanges data with the MiniMed Mobile app (glucose readings for instance) over Bluetooth LE.

Unless noted otherwise, this applies to a pump of type 780G. Other models in the 700-series probably work the same way.

This document uses example data retrieved from captured Bluetooth communication between the pump and the app. Data for SAKE-encrypted characteristics are presented only in decrypted form.

For brevity, we will abbreviate _MiniMed Mobile app_ with _MMM_ in this document.


## Introduction

The Bluetooth SIG actually specifies an official _Insulin Delivery Profile_ (IDP). It defines two roles:

* _Insulin Delivery Sensor_ (in our case: the pump, an _Insulin Delivery Device_ (IDD))
* _Collector_ (in our case: the MiniMed Mobile app)

The _Insulin Delivery Sensor_ provides, among other services, the _Insulin Delivery Service_ (IDS, UUID 0x183A) and associated characteristics. Through them, a device can "control the IDD" and "obtain its status and historical therapy data" [IDP_v1.0.2].

For simplicity, we will mostly refer to _pump_ and _app_ instead of _Insulin Delivery Sensor_ and _Collector_ in this documentation.

The pump in question provides an _Insulin Delivery Service_, but its UUID is 00000100-0000-1000-0000-009132591325. This is a Medtronic custom GATT service nearly all of whose characteristics are SAKE-encoded.

Judging by their names, Medtronic's version of the IDS is actually comprised of the same characteristics as the one specified, only with Medtronic's own UUIDs; with the exception of the _IDD Record Access Control Point_ (UUID 0x2B27) which is replaced by the _Record Access Control Point_ (UUID 0x2A52). So it seems save to assume that this service is an implementation of the IDS specified in [IDS_v1.0.2]; maybe only with some non-standard extensions (such as the SAKE encryption).

The spec also mentions an optional _E2E-Protection_ (End-to-End) of the data, without going into much detail about it. It does, however, sound very different from Medtronic's custom SAKE encryption, and our pump's features indeed confirm that _E2E-Protection_ is _not_ enabled (see section below).


## Data types

All multi-byte data is in Little-Endian, i.e. the least-significant bytes comes first.

Two different floating-point types are used: one using 16 bits (the spec calls this _sfloat_), the other using 32 bits:

	f = m × 10^e

where `m` is the mantissa and `e` is the exponent. Both are encoded in 2's complement. The exponent is stored in the most-significant bits:

	16 bit (sfloat):                     eeee mmmm mmmm mmmm
	32 bit:          eeee eeee mmmm mmmm mmmm mmmm mmmm mmmm

So, for example:

	0xf90f     =   -1777 × 10^-1 = -177.7
	0xf82625a0 = 2500000 × 10^-8 =    0.025


## Reading pump features

The spec for the _Insulin Delivery Service_ [IDS_v1.0.2] defines a characteristic _IDD Feature_ which can be read to determine the supported features of the pump. Medtronic SAKE-encrypts the returned data. See our [com matrix] for the characteristic's UUID.

For our particular pump the following data was read: `ffff006400fede801f` which decodes to the following:

<pre>
ffff .. .... ...... ..  E2E-CRC:               default for E2E unused
.... 00 .... ...... ..  E2E-Counter:           default for E2E unused
.... .. 6400 ...... ..  Insulin Concentration: 100.0 IU/mL (type sfloat)
.... .. .... fede80 1f  Flags:                 0x1f80defe

Flags (details):
0001 1111 1000 0000 1101 1110 1111 1110
.... .... .... .... .... .... .... ...0  E2E-Protection:        no
.... .... .... .... .... .... .... ..1.  Basal Rate:            yes
.... .... .... .... .... .... .... .1..  TBR Absolute:          yes
.... .... .... .... .... .... .... 1...  TBR Relative:          yes
.... .... .... .... .... .... ...1 ....  TBR Template:          yes
.... .... .... .... .... .... ..1. ....  Fast Bolus:            yes
.... .... .... .... .... .... .1.. ....  Extended Bolus:        yes
.... .... .... .... .... .... 1... ....  Multiwave Bolus:       yes
.... .... .... .... .... ...0 .... ....  Bolus Delay Time:      no
.... .... .... .... .... ..1. .... ....  Bolus Template:        yes
.... .... .... .... .... .1.. .... ....  Bolus Activation Type: yes
.... .... .... .... .... 1... .... ....  Multiple Bond:         yes
.... .... .... .... ...1 .... .... ....  ISF Profile Template:  yes
.... .... .... .... ..0. .... .... ....  I2CHO Ratio Profile Template: yes
.... .... .... .... .1.. .... .... ....  Target Glucose Range Profile Template: yes
.... .... .... .... 1... .... .... ....  Insulin On Board:      yes
.... .... .000 0000 .... .... .... ....  (reserved)
.... .... 1... .... .... .... .... ....  Feature Extension:     yes
.... ...1 .... .... .... .... .... ....  custom extension: Reservoir Size 300IU Supported
.... ..1. .... .... .... .... .... ....  custom extension: Glucose Unit mg/dL Used
.... .1.. .... .... .... .... .... ....  custom extension: LGS Feature Supported
.... 1... .... .... .... .... .... ....  custom extension: PLGM Feature Supported
...1 .... .... .... .... .... .... ....  custom extension: HCL Feature Supported
.00. .... .... .... .... .... .... ....  (unknown extended features)
0... .... .... .... .... .... .... ....  Feature Extension:     no
</pre>

These features look sane and also nicely fit the features of a 780G. So we are pretty confident that this characteristic is indeed implemented as found in the spec.

The extended feature flags are likely vendor-specific and the less cryptic ones also match the specific 780G used. Their names were extracted from the MiniMed Mobile app.


## Reading status changes

The spec for the _Insulin Delivery Service_ [IDS_v1.0.2] defines a characteristic _IDD Status Changed_ which can be read to determine various status changes of the pump.The app can also configure this characteristic for indications to automatically receive the status changes when they happen.

Medtronic SAKE-encrypts the returned data. See our [com matrix] for the characteristic's UUID.

The specified characteristic value consists of a single 16-bit flags field. Medtronic extends this to up to 48 bits in their version. They also populate some of the reserved bits with their custom ones. The extension mechanism is very similar to the one in _IDD Feature_: If the highest bit in the current block is _set_, another block of 16 bits is appended, thus extending the flags.

Field Name    | Data Type    | Size (octets) | Unit | Byte Order
--------------|--------------|---------------|------|-----------
Flags         | 16–48 bit    | 2–6           | None | LSO...MSO

Per the spec, the pump is expected to retain the status of a bit of the _Flags_ field until its value is reset by the app through the _Reset Status_ procedure using the characteristic _IDD Status Reader Control Point_.

Bits in the _Flags_ field are defined as follows (Medtronic's custom extensions marked):

Bit   | Definition                               | Description
------|------------------------------------------|-------------
 0    | Therapy Control State Changed            |
 1    | Operational State Changed                |
 2    | Reservoir Status Changed                 |
 3    | Annunciation Status Changed              |
 4    | Total Daily Insulin Status Changed       |
 5    | Active Basal Rate Status Changed         |
 6    | Active Bolus Status Changed              |
 7    | History Event Recorded                   |
 8    | Time In Range Status Changed             | custom extension; marked as reserved in the spec
 9–14 | reserved/unused                          |
15    | Extended Status                          | custom extension; If this bit is set, two additional octets are attached (bits 16–31).
16    | Therapy Algorithm State                  | custom extension
17    | Insulin On Board                         | custom extension
18    | New CGM Measurement                      | custom extension
19    | Sensor EOL                               | custom extension
20    | CGM Calibration                          | custom extension
21    | Sensor Status Message                    | custom extension
22    | Sensor Connectivity State                | custom extension
23    | Display Format Changed                   | custom extension
24    | High/Low Settings Changed                | custom extension
25    | Sensor Changed                           | custom extension
26    | CGM Calibration Context Changed          | custom extension
27    | CGM Time Calibration Recommended Changed | custom extension
28    | Remote Bolus Option Changed              | custom extension
29    | Local UI Interaction Requested           | custom extension
30    | Sensor Warm-up Time Remaining Changed    | custom extension
31    | Extended Status 1                        | custom extension; If this bit is set, two additional octets are attached (bits 32–47).
32    | Sensor Calibration Status Icon Changed   | custom extension
33    | Early Sensor Calibration Time Changed    | custom extension


## Sending commands to the pump

The spec for the _Insulin Delivery Service_ defines the characteristic _IDD Command Control Point_ for "adapting therapy parameters to enable the remote operation of the insulin therapy as well as the remote operation for device maintenance" [IDS_v1.0.2]. Together with a second characteristic _IDD Command Data_ it implements a simple "command in, data out" interface:

* _IDD Command Control Point_
	* app sends command to the pump
	* pump sends back data in response (indications)
	* also acts as indicator for "command execution finished"
	* SAKE-encrypted
* _IDD Command Data_
	* pump sends back data in response (notifications)
	* SAKE-encrypted

See our [com matrix] for their respective UUID.

The app (the client) writes commands to the _Command Control Point_ and receives a response from the pump (the server) either via _Command Control Point_ or _Command Data_. Commands include things like "set a bolus" or "get the basal rate profile template" [IDS_v1.0.2, sec. 4.6.1].

The type of command is encoded in its _opcode_. The client may send multiple commands without waiting for a response. Responses from the server also include an opcode which references the command's opcode. This allows the client to map responses to the original command.

The spec defines the following behavior: If the server wants/needs to respond to a command with more than one record (for example, lengthy basal rate profile templates), it shall use multiple _notifications_ of the _Command Data_ to do so (one per record). It shall then _indicate_ the _Command Control Point_ to confirm the end of the command's execution. Therefore, the app shall configure the _Command Data_ characteristic for notifications and the _Command Control Point_ characteristic for indications before sending its first command. Since an _indication_ in Bluetooth LE requires an acknowledgement from the client, the pump will know that the app received that final confirmation of execution.

In practice we observe a 780G pump sending notifications of the Command Control Point even for single-record responses that could have been sent through the Command Control Point. Medtronic probably chose to do so because they _always_ wanted to indicate the response code (either success or one of various error codes), which they could not simply send along with other data in the response. There is only _one_ opcode allowed per response package, and "Response Code" is one of them.

### Opcodes

The spec defines a large table of opcodes encoding different commands. Some portions of the value range are marked as "prohibited". Medtronic uses on of these for custom opcodes. The part of the MMM that implements the client side of the _Insulin Delivery Service_ internally defines the following opcodes:

<pre>
RESPONSE_CODE                     = 0x0f55
SET_BOLUS                         = 0x114b
SET_BOLUS_RESPONSE                = 0x1177
CANCEL_BOLUS                      = 0x1178
CANCEL_BOLUS_RESPONSE             = 0x1187
GET_MAX_BOLUS_AMOUNT              = 0x147d
GET_MAX_BOLUS_AMOUNT_RESPONSE     = 0x1482
GET_HIGH_LOW_SG_SETTINGS          = 0x148e (Medtronic custom)
GET_HIGH_LOW_SG_SETTINGS_RESPONSE = 0x148f (Medtronic custom)
</pre>

Judging from its code, the MMM can only ever send commands with the following opcodes, though:

* `GET_HIGH_LOW_SG_SETTINGS`
* `SET_BOLUS`

### Format of custom _Get High/Low SG Settings_ command and response

The command is sent by writing to the _IDD Command Control Point_ characteristic. The pump responds by sending a notification for the _IDD Command Data_ characteristic.

#### Command structure

Field Name    | Data Type    | Size (octets) | Unit | Byte Order
--------------|--------------|---------------|------|-----------
Opcode        | Value 0x148e | 2             | None | LSO...MSO
Settings Type | Enum of u8   | 1             | None | N/A

The following values are defined for the _Settings Type_ field:

Value | Description
------|------------
0x00  | Low
0x01  | High

#### Response structure

Field Name                  |  Data Type   | Size (octets) | Unit     | Byte Order
----------------------------|--------------|---------------|----------|-----------
Response Opcode             | Value 0x148f | 2             | None     | LSO...MSO
Flags                       | 8 bit        | 1             | None     | N/A
Settings Type               | Enum of u8   | 1             | None     | N/A
1st Time Block Number Index | u8           | 1             | None     | N/A
1st Duration                | u16          | 2             | minutes  | LSO...MSO
1st SG Limit                | sfloat       | 2             | see note | LSO...MSO
2nd Duration                | u16          | 2             | minutes  | LSO...MSO
2nd SG Limit                | sfloat       | 2             | see note | LSO...MSO
3rd Duration                | u16          | 2             | minutes  | LSO...MSO
3rd SG Limit                | sfloat       | 2             | see note | LSO...MSO

NOTE: The unit of the _SG Limit_ fields probably depends on the value of the bit _Glucose Unit mg/dL Used_ in the data read from the _IDD Feature_ characteristic. So it is likely mg/dL if the flag is set, and mmol/L otherwise.

Bits in the _Flags_ field are defined as follows:

Bit | Definition             | Description
----|------------------------|-------------
0   | 2nd Time Block Present | If this bit is set, fields _2nd Duration_ and _2nd SG Limit_ are present
1   | 3rd Time Block Present | If this bit is set, fields _3rd Duration_ and _3rd SG Limit_ are present


### Example capture

Following is an annotated capture of the MMM requesting the high/low sensor glucose settings from a 780G pump. This happens in two parts: First, the app requests the _high_ settings through Medtronic's custom command. After this command has been completed by the pump, the app requests the _low_ settings using the same command.

1. App writes command _Get High/Low SG Settings_ to the _IDD Command Control Point_:

		8e14 01
		8e14 ..  Opcode:  GET_HIGH_LOW_SG_SETTINGS
		.... 01  Operand: HIGH

2. Pump responds with notification for _IDD Command Data_:

		8f14 03 01 00 e001 1801 0c03 0000 b400 1801
		8f14 .. .. .. .... .... .... .... .... ....  Response Opcode: GET_HIGH_LOW_SG_SETTINGS_RESPONSE
		.... 03 .. .. .... .... .... .... .... ....  Operand: SECOND_TIME_BLOCK_PRESENT (0x1) | THIRD_TIME_BLOCK_PRESENT (0x2)
		.... .. 01 .. .... .... .... .... .... ....  Operand: HIGH
		.... .. .. 00 .... .... .... .... .... ....  Operand: 1st Time Block Number Index (u8)
		.... .. .. .. e001 .... .... .... .... ....  Operand: 1st Duration (u16):    480
		.... .. .. .. .... 1801 .... .... .... ....  Operand: 1st SG Limit (sfloat): 280.0
		.... .. .. .. .... .... 0c03 .... .... ....  Operand: 2nd Duration (u16):    780
		.... .. .. .. .... .... .... 0000 .... ....  Operand: 2nd SG Limit (sfloat): 0.0
		.... .. .. .. .... .... .... .... b400 ....  Operand: 3rd Duration (u16):    180
		.... .. .. .. .... .... .... .... .... 1801  Operand: 3rd SG Limit (sfloat): 280.0

	If the flag for 2nd and 3rd time block are _not_ set, the corresponding block is not part of the packet, i.e. the packet shown above would be shorter by 2 or 4 bytes, respectively.

3. Pump finishes with indication for _IDD Command Control Point_:

		550f 8e14 0f
		550f .... ..  Opcode:  Response Code
		.... 8e14 ..  Operand: Request Opcode: GET_HIGH_LOW_SG_SETTINGS
		.... .... 0f  Operand: Response Code Value: Success

4. App writes command _Get High/Low SG Settings_ to the _IDD Command Control Point_:

		8e14 00
		8e14 ..  Opcode:  GET_HIGH_LOW_SG_SETTINGS
		.... 00  Operand: LOW

5. Pump responds with notification for _IDD Command Data_:

		8f14 03 00 00 c201 5000 ee02 4600 f000 5000
		8f14 .. .. .. .... .... .... .... .... ....  Response Opcode: GET_HIGH_LOW_SG_SETTINGS_RESPONSE
		.... 03 .. .. .... .... .... .... .... ....  Operand: SECOND_TIME_BLOCK_PRESENT (0x1) | THIRD_TIME_BLOCK_PRESENT (0x2)
		.... .. 00 .. .... .... .... .... .... ....  Operand: LOW
		.... .. .. 00 .... .... .... .... .... ....  Operand: 1st Time Block Number Index (u8)
		.... .. .. .. c201 .... .... .... .... ....  Operand: 1st Duration (u16):    450
		.... .. .. .. .... 5000 .... .... .... ....  Operand: 2nd SD Limit (sfloat): 80.0
		.... .. .. .. .... .... ee02 .... .... ....  Operand: 2nd Duration (u16):    750
		.... .. .. .. .... .... .... 4600 .... ....  Operand: 3rd SD Limit (sfloat): 70.0
		.... .. .. .. .... .... .... .... f000 ....  Operand: 3rd Duration (u16):    240
		.... .. .. .. .... .... .... .... .... 5000  Operand: 3rd SD Limit (sfloat): 80.0

6.  Pump finishes with indication for _Command Control Point_:

		550f 8e14 0f
		550f .... ..  Opcode:  Response Code
		.... 8e14 ..  Operand: Request Opcode: GET_HIGH_LOW_SG_SETTINGS
		.... .... 0f  Operand: Response Code Value: Success


## Reading history

Similar to the _IDD Command_ interface, Medtronic's _Insulin Delivery Service_ defines two characteristics _Record Access Control Point_ (_RACP_) and _IDD History Data_ that also appear in the spec [IDS_v1.0.2] for this service (only difference being a dedicated _IDD RACP_ in the spec). They provide a means of accessing the pump's history database which stores _events_ such as sensor values and boluses. The app can retrieve the number of stored records as well as the actual records, including optional filtering such as "last record" or "all records within a given range of sequence numbers".

The setup and workflow is analogous to that of the _IDD Command_ interface: The app sends requests through the _RACP_ and the pump sends the data by notifications of the _IDD History Data_. Since this reply can span multiple records, the pump _indicates_ the _RACP_ to confirm the end of execution.

* _Record Access Control Point_
	* app sends command to the pump
	* pump sends back data in response (indications)
	* also acts as indicator for "command execution finished"
	* not encrypted (!)
* _IDD History Data_
	* pump sends back data in response (notifications)
	* SAKE-encrypted

See our [com matrix] for their respective UUID.


### Format of History Data

The structure of the _IDD History Data_ responses follows the spec [IDS_v1.0.2, sec. 4.9]:

Field Name                  | Data Type    | Size (octets) | Unit     | Byte Order
----------------------------|--------------|---------------|----------|-----------
Event Type                  | Enum of u16  | 2             | None     | LSO...MSO
Sequence Number             | u32          | 4             | None     | LSO...MSO
Relative Offset             | u16          | 2             | seconds  | LSO...MSO
Event Data                  | variable     | 0–10          | None     | LSO...MSO

Medtronic defines a couple of custom event types in the spec's manufacturer-reserved range of event types. They also slightly modify existing event types defined in the spec:

- Event type _Bolus Programmed Part 1 of 2_ uses 4-byte floats for fields _Programmed Bolus Fast Amount_ and _Programmed Bolus Extended Amount_ instead of 2-byte sfloats
- Event type _Bolus Delivered Part 1 of 2_ uses 4-byte floats for fields _Delivered Bolus Fast Amount_ and _Delivered Bolus Extended Amount_ instead of 2-byte sfloats
- Event type _Delivered Basal Rate Changed_ uses 4-byte floats for fields _Old Basal Rate Value_ and _New Basal Rate Value_ instead of 2-byte sfloats
- Event type _Max Bolus Amount Changed_ uses 4-byte floats for fields _Old Max Bolus Amount_ and _New Max Bolus Amount_ instead of 2-byte sfloats

The field _Relative Offset_ encodes the event's timestamp relative to the latest event of type _NGP Reference Time_ preceeding it. The latter encodes an absolute date time and is automatically generated by the pump every hour or so.

The _Event Data_ field for the custom Medtronic event types in responses to _Report Stored Records_ requests (opcode 0x33) is structured as follows:


#### Auto Basal Delivery (event type 0xf001)

Field Name                  | Data Type    | Size (octets) | Unit     | Byte Order
----------------------------|--------------|---------------|----------|-----------
Bolus Number                | u8           | 1             | None     | N/A
Bolus Amount                | f32          | 4             | IU       | LSO...MSO


#### CL1 Transition (event type 0xf002)

Field Name                  | Data Type    | Size (octets) | Unit     | Byte Order
----------------------------|--------------|---------------|----------|-----------
Transition State            | Enum of u8   | 1             | None     | N/A

The following values are defined for field _Transition State_:

Value | Description
------|-----------------
0x00  | Into SI Pass
0x01  | Out User Override
0x02  | Out Alarm
0x03  | Out Timeout Safe Basal
0x04  | Out High SG


#### Therapy Context (event type 0xf004)

Field Name                      | Data Type    | Size (octets) | Unit     | Byte Order
--------------------------------|--------------|---------------|----------|-----------
Flags                           | 8 bit        | 1             | None     | N/A
Basal Rate                      | f32          | 4             | IU/h (?) | LSO...MSO
Insulin Delivery Stopped Reason | Enum of u8   | 1             | None     | N/A
TBR Type                        | Enum of u8   | 1             | None     | N/A
TBR Adjustment                  | f32          | 4             | IU/h (?) | LSO...MSO

NOTE: TBR stands for "temporary basal rate".

Bits in the _Flags_ field are defined as follows:

Bit | Definition               | Description
----|--------------------------|-------------
0   | Sensor Enabled           |
1   | Basal Rate Active        | If this bit is set, field _Basal Rate_ is present
2   | Auto Mode Active         |
3   | Insulin Delivery Stopped | If this bit is set, field _Insulin Delivery Stopped Reason_ is present
4   | TBR Active               | If this bit is set, fields _TBR Type_ and _TBR Adjustment_ are present

The following values are defined for field _Insulin Delivery Stopped Reason_:

Value | Description
------|-----------------
0x01  | Alarm Suspended
0x02  | User Suspended
0x03  | Auto Suspended
0x04  | Low SG Suspended
0x05  | Not Seated
0x0a  | PLGM On Low SG Suspended

The values for field _TBR Type_ are as defined in [IDS_v1.0.2, sec. 4.5.2.8.2]:

Value | Description
------|--------------
0x0f  | Undetermined
0x33  | Absolute
0x3c  | Relative


#### Meal (event type 0xf005)

Field Name                  | Data Type    | Size (octets) | Unit     | Byte Order
----------------------------|--------------|---------------|----------|-----------
Food Amount                 | sfloat       | 2             | g (?)    | LSO...MSO


#### BG Reading (event type 0xf007)

Field Name                  | Data Type    | Size (octets) | Unit     | Byte Order
----------------------------|--------------|---------------|----------|-----------
Time Offset                 | u16          | 2             | ???      | LSO...MSO
BG Value                    | sfloat       | 2             | kg/L     | LSO...MSO

NOTE: Convert the value in field _BG Value_ to the more common unit mg/dL by multiplying with 10⁵.


#### Calibration Complete (0xf008)

Field Name                  | Data Type    | Size (octets) | Unit     | Byte Order
----------------------------|--------------|---------------|----------|-----------
Time Offset                 | u16          | 2             | ???      | LSO...MSO
BG Measurement              | sfloat       | 2             | kg/L     | LSO...MSO

NOTE: Convert the value in field _BG Measurement_ to the more common unit mg/dL by multiplying with 10⁵.


#### Calibration Rejected (0xf009)

Field Name                  | Data Type    | Size (octets) | Unit     | Byte Order
----------------------------|--------------|---------------|----------|-----------
Time Offset                 | u16          | 2             | ???      | LSO...MSO
BG Measurement              | sfloat       | 2             | kg/L     | LSO...MSO

NOTE: Convert the value in field _BG Measurement_ to the more common unit mg/dL by multiplying with 10⁵.


#### Insulin Delivery Stopped (event type 0xf00a)

Field Name                      | Data Type    | Size (octets) | Unit     | Byte Order
--------------------------------|--------------|---------------|----------|-----------
Insulin Delivery Stopped Reason | Enum of u8   | 1             | None     | N/A

See section _Therapy Context (event type 0xf004)_ for a definition of values for this field.


#### Insulin Delivery Restarted (event type 0xf00b)

Field Name                        | Data Type    | Size (octets) | Unit     | Byte Order
----------------------------------|--------------|---------------|----------|-----------
Insulin Delivery Restarted Reason | Enum of u8   | 1             | None     | N/A

The following values are defined for field _Insulin Delivery Restarted Reason_:

Value | Description
------|-----------------
0x01  | User Selects Resume
0x02  | User Clears Alarm
0x03  | LGM Manual Resume
0x04  | LGM Auto Resume Due Max Suspended Time
0x05  | LGM Auto Resume Du PSG And SG
0x06  | LGM Manual Resume Via Disable


#### SG Measurement (event type 0xf00c)

Field Name                  | Data Type    | Size (octets) | Unit     | Byte Order
----------------------------|--------------|---------------|----------|-----------
Time Offset                 | u16          | 2             | ???      | LSO...MSO
SG Value                    | u16          | 2             | mg/dL    | LSO...MSO
ISIG                        | u16          | 2             | ???      | LSO...MSO
V Counter                   | u16          | 2             | ???      | LSO...MSO

NOTE: The unit of the _SG Value_ field may depend on the value of the bit _Glucose Unit mg/dL Used_ in the data read from the _IDD Feature_ characteristic.

NOTE: The _ISIG_ field probably encodes the raw glucose sensor values. Older pumps such as the 640G, together with a _Guardian 2 Link_, exposed an "ISIG value" to the user. Calibrating the sensor would compute a scaling factor that translated the raw ISIG value into a blood glucose value in mg/dL. The 780G does not show the ISIG value to the user anymore.


#### CGM Analytics Data Backfill (event type 0xf00d)

Field Name                  | Data Type    | Size (octets) | Unit     | Byte Order
----------------------------|--------------|---------------|----------|-----------
Time Offset                 | u16          | 2             | ???      | LSO...MSO
PSGV                        | sfloat       | 2             | ???      | LSO...MSO
Cal Factor                  | u16          | 2             | ???      | LSO...MSO


#### NGP Reference Time (event type 0xf00e)

Field Name                  | Data Type    | Size (octets) | Unit     | Byte Order
----------------------------|--------------|---------------|----------|-----------
Recording Reason            | Enum of u8   | 1             | None     | N/A
Date Time                   | see note     | 7             | see note | see note

This is a stripped-down version of the _Reference Time_ defined in [IDS_v1.0.2, sec. 4.9.4.1], without time zone and DST offset.

All other event types reference this absolute time stamp by their _Relative Offset_ field.

NOTE: See [GSS_2025-12-23, sec. 3.79] for the definition of this type.


#### Annunciation Cleared (event type 0xf00f)

Field Name                  | Data Type    | Size (octets) | Unit     | Byte Order
----------------------------|--------------|---------------|----------|-----------
Fault ID                    | u16          | 2             | None     | LSO...MSO
Instance ID                 | u16          | 2             | None     | LSO...MSO


#### Annunciation Consolidated (event type 0xf010)


#### Max Auto Basal Rate Changed (event type 0xf01a)

Field Name              | Data Type    | Size (octets) | Unit     | Byte Order
------------------------|--------------|---------------|----------|-----------
Old Rate                | f32          | 4             | IU/h (?) | LSO...MSO
New Rate                | f32          | 4             | IU/h (?) | LSO...MSO
