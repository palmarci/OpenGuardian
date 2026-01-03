# LogSniffer

This folder's scripts can be used to convert, decrypt and visualize sniffed data.


## Steps 

TODO: extend the description.

1. get a BTLE sniffer (nRF52840 / CC1352R1)
2. sniff FROM PAIRING!
3. decrypt the bluetooth encryption (use https://github.com/mikeryan/crackle)
4. use <code>pcap_to_gattlog.py</code> to convert it into the expected format
5. use <code>TODO</code> to decrypt the data
6. run OpenGuardian4 against the log

## Gattlog format

- all fields are separated by a ','
- spaces can be used, but shall be ignored by the parser
- first line shall start with a '#' character. it shall contain the:
    1. the original filename (if applicable), if not use "unknown"
    2. conversion date
    3. decryption state: decrypted / encrypted
    4. other notes, ignored

- then it shall contain the following fields separated by a ','
   1. source: APP / PUMP / SENSOR
   2. dest: APP / PUMP / SENSOR
   3. opcode: READ / WRITE / NOTIFY
   4. uuid: in full format with no special characters
   5. data: in hex with no special characters