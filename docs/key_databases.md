# Key databases

Medtronic uses "key databases" to initialize a SAKE server / client.

## DB Format

| Field (bytes) | Name |
| :---  | :--- |
| 0-3 | CRC32 |
| 4 | Local device type |
| 5 | Number of static keys |
| 6  - end | Static keys | 

## Static Keys

| Field (bytes) | Name |
| :---  | :--- |
| 0 | remote device type |
| 1-16 | derivation_key |
| 17-32| handshake_auth_key |
| 33-48| permit_decrypt_key |
| 49-64| permit_auth_key |
| 65-80| handshake_payload |

## Device types

From [Sake RE project](/SakeRE/), function at <code>0x0001dcf0</code>. There was a small update to this list in the Guardian app, highlighted in *italic*.

| ID | Name |
| :---  | :--- |
| 1 | Insulin Pump |
| 2 | Glucose Sensor |
| 3 | Blood Glucose Meter (according to [this](https://www.medtronic.com/content/dam/medtronic-wide/public/canada/products/diabetes/post-software-update-re-pairing-guide.pdf) Accu-Check meters can sync with the pump?!) |
| 4 | Mobile Application  / *Secondary Display* |
| 5 | CareLink Upload Application|
| 6 | Firmware Update Application |
| 7 | Diagnostic Application |
| 8 | *Primary Display* | 



## Keys


Mobile Application <-> Insulin Pump

f75995e7 04 01 01 1bc1bf7cbf36fa1e2367d795ff09211903da6afbe986b650f14179c0e6852e0ce393781078ffc6f51919e2eaefbde69b8eca21e41ab59b881a0bea0286ea91dc7582a86a714e1737f558f0d66dc1895c

---
Primary Display (Guardian Mobile app) <-> Glucose Sensor

5fe59283 08 01 02 30f0b50df613f2e429c8c5e8713854add1a69b837235a3e974304d8055ccb397838b90823c73236d6a83dcc9db3a2a939ff16145ca4169ef93a7fa39b20962b05e57413bff8b3d61fce0dfef2c43b326

extracted from [g4s monitor logs](/data/monitor_logs/g4s/)


---

Mobile Application <-> Insulin Pump

c2cdfdd1 04 01 01 fce36ed66ef21def3b0763975494b239038ebe8606f79a9bf00d9f11b6db04c7c0434787cbf00d5476289c22288e2105ae40e01391837f9476fa5003895c5a1afe35662a2a6211826af016eebe30e4ba

found hardcoded in MiniMed Mobile v1.2.1 (class com.medtronic.minimed.ngpsdk.connect.a) by foobar:
