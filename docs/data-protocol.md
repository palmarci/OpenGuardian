# Data protocol

This documents what we know about the way an insulin pump exchanges data with the MiniMed Mobile app (glucose readings for instance) over Bluetooth LE.

Unless noted otherwise, this applies to a pump of type 780G. Other models in the 700-series probably work the same way.

This document uses example data retrieved from captured Bluetooth communication between the pump and the app. Data for SAKE-encrypted characteristics are presented only in decrypted form.


## Introduction

The Bluetooth SIG actually specifies an official _Insulin Delivery Profile_ (IDP). It defines two roles:

* _Insulin Delivery Sensor_ (in our case: the pump, an _Insulin Delivery Device_ (IDD))
* _Collector_ (in our case: the MiniMed Mobile app)

The _Insulin Delivery Sensor_ provides, among other services, the _Insulin Delivery Service_ (IDS, UUID 0x183A) and associated characteristics. Through them, a device can "control the IDD" and "obtain its status and historical therapy data" [IDP_v1.0.2].

For simplicity, we will mostly refer to _pump_ and _app_ instead of _Insulin Delivery Sensor_ and _Collector_ in this documentation.

The pump in question provides an _Insulin Delivery Service_, but its UUID is 00000100-0000-1000-0000-009132591325. This is a Medtronic custom GATT service nearly all of whose characteristics are SAKE-encoded.

Judging by their names, Medtronic's version of the IDS is actually comprised of the same characteristics as the one specified, only with Medtronic's own UUIDs; with the exception of the _IDD Record Access Control Point_ (UUID 0x2B27) which is replaced by the _Record Access Control Point_ (UUID 0x2A52). So it seems save to assume that this service is an implementation of the IDS specified in [IDS_v1.0.2]; maybe only with some non-standard extensions (such as the SAKE encryption).

The spec also mentions an optional _E2E-Protection_ (End-to-End) of the data, without going into much detail about it. It does, however, sound very different from Medtronic's custom SAKE encryption, and our pump's features indeed confirm that _E2E-Protection_ is _not_ enabled (see section below).


## Reading pump features

The spec for the _Insulin Delivery Service_ [IDS_v1.0.2] defines a characteristic _IDD Feature_ which can be read to determine the supported features of the pump. Medtronic SAKE-encrypts the returned data.

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
.... .111 .... .... .... .... .... ....  (unknown extended features)
.... 1... .... .... .... .... .... ....  Feature Extension:     yes
.001 .... .... .... .... .... .... ....  (unknown extended features)
0... .... .... .... .... .... .... ....  Feature Extension:     no
</pre>

These features look sane and also nicely fit the features of a 780G. Only the extended feature bits we cannot comment on. So we are pretty confident that this characteristic is indeed implemented as found in the spec.
