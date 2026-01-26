# LogSniffer

The scripts in this folder can be used to convert, decrypt and display sniffed data.

This was developed on Wireshark/TShark 4.6+, however it needs a specific [fix](https://github.com/KimiNewt/pyshark/pull/744) in pyshark to work properly. You might try other versions **at least 4.0**.


## Steps 

TODO: extend the description.

1. get a BTLE sniffer (CC1352R1 recommended)
2. sniff FROM PAIRING!
3. decrypt the bluetooth encryption (use https://github.com/mikeryan/crackle)
4. use <code>extractor.py</code> to convert it into the expected format
5. use <code>decryptor.py</code> to decrypt the data

## Gattlog format

- all fields are separated by a ','
- spaces can be used, but shall be ignored by the parser
- first line shall start with a '#' character. it shall contain the:
    1. the original filename (if applicable), if not use "unknown"
    2. conversion date
    3. decryption state: decrypted / encrypted
    4. other notes (should be ignored)

- then it shall contain the following fields separated by a ','
   1. frame: Bluetooth frame number in the original capture (for easier cross-referencing)
   2. source: APP / PUMP / SENSOR
   3. dest: APP / PUMP / SENSOR
   4. opcode: READ / WRITE / NOTIFY
   5. service uuid: in raw hex string format, without any special characters. may be 128 or 16 bit long, and also can be None.
   6. characteristic uuid: same as above, but with no None possibility
   1. data: in hex with no special characters
