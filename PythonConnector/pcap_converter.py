#!/usr/bin/env python3

import argparse
import pyshark
import sys


ATT_OPCODES = {
    "0x0a": "WRITE_REQ",
    "0x12": "WRITE_CMD",
    "0x0c": "READ_RSP",
    "0x1b": "NOTIFY",
}

def parse_args():
    ap = argparse.ArgumentParser(description="Extract BLE GATT read/write/notify data")
    ap.add_argument("pcap", help="pcap/pcapng file")
    return ap.parse_args()

def is_pump(pkt):

    # pump MACs usually start with 00:23:f7
    src_parts = pkt.bluetooth.src.split(":")
    
    if src_parts[0] == "00" and src_parts[1] == "23":
        return True
    
    dst_parts = pkt.bluetooth.dst.split(":")
    if dst_parts[0] == "00" and dst_parts[1] == "23":
        raise Exception("Could not decide which device is the pump!")

    return False

def get_uuid(att):
    # Wireshark resolves UUIDs if it knows the GATT DB
    for field in (
        "uuid128",
        "uuid",
        "characteristic_uuid",
        "service_uuid",
    ):
        if hasattr(att, field):
            return getattr(att, field)
    return None

def get_value(att):
    for field in (
        "value_raw",
        "handle_value_raw",
        "value",
        "handle_value",
    ):
        if hasattr(att, field):
            return getattr(att, field)
    return None

def reformat_uuid(u):
    u = u.replace(":", "")
    # TODO: human readable
    return u

def parse_data(a):
    return bytes.fromhex(a.replace(":", ""))

def main():
    args = parse_args()

    display_filter = (
        "btatt.opcode == 0x0A || "  # Write Request
        "btatt.opcode == 0x12 || "  # Write Command
        "btatt.opcode == 0x0C || "  # Read Response
        "btatt.opcode == 0x1B"     # Notification
    )

    cap = pyshark.FileCapture(
        args.pcap,
        display_filter=display_filter,
        #keep_packets=False,
        custom_parameters=["-2"], # enable 2 pass loading, workaround for https://github.com/KimiNewt/pyshark/issues/745
    )

    #cap.set_debug()

    for pkt in cap:
        if not hasattr(pkt, "btatt"):
            continue

        att = pkt.btatt

        pktno = pkt.number

        dir = "<<" if is_pump(pkt) else ">>"

        opcode_raw = att.opcode
        opcode = ATT_OPCODES.get(opcode_raw.lower(), opcode_raw)

        handle = getattr(att, "handle", None)
        uuid = get_uuid(att)
        data = get_value(att)

        if handle is None or data is None or uuid is None:
            continue

        uuid = reformat_uuid(uuid)
        data = parse_data(data)

        print(
            dir + " "+
       #     f"pkt={pktno} "
       #     f"dir={dir} "
            f"op={opcode} "
        #    f"handle={handle} "
            f"uuid={uuid} "
            f"data={data.hex()}"
        )

    cap.close()

if __name__ == "__main__":
    main()
