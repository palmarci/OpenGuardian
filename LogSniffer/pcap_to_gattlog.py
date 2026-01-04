#!/usr/bin/env python3

from datetime import datetime
import argparse
import pyshark
import os
import sys

ATT_OPCODES = {
    "0x12": "WRITE", # ATT_WRITE_REQ
    "0x0b": "READ", # ATT_READ_RSP
    "0x1b": "NOTIFY", # ATT_HANDLE_VALUE_NTF
    "0x1d": "INDICATE", # ATT_HANDLE_VALUE_IND
    # https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/attribute-protocol--att-.html
}

def parse_args():
    ap = argparse.ArgumentParser(description="Extract BLE GATT read/write/notify data")
    ap.add_argument("pcap", help="pcap/pcapng input file")
    ap.add_argument("--out", help="output file", default="output.gattlog")
    ap.add_argument("-f", "--force-output", action="store_true", help="overwrite existing output file", default=False)

    return ap.parse_args()

def get_device_type(address:str) -> str:
    """
    address: MAC in a string format, separated by ":"
    returns: PUMP / APP / SENSOR
    """

    addr_parts = address.split(":")
    
    if addr_parts[0] == "00" and addr_parts[1] == "23": 
        # pump MACs usually start with 00:23:f7
        return "PUMP"
    
    if addr_parts[0] == "DC" and addr_parts[1] == "16":
        # they are DC:16:A2 -> Medtronic Diabetes
        return "SENSOR"
    
    return "APP" # it must be app then. not the best

def get_uuid(att):
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
    u = u.replace(":", "").lower()
    return u

def parse_data(a):
    return bytes.fromhex(a.replace(":", ""))

def main():
    args = parse_args()

    # check arguments
    in_fn = os.path.abspath(args.pcap)
    out_fn = os.path.abspath(args.out)
    if not os.path.exists(in_fn):
        raise FileNotFoundError(in_fn)
    if os.path.exists(out_fn):
        if args.force_output:
            os.remove(out_fn)
        else:
            print(f"Error: output file '{out_fn}' already exists on disk.")
            sys.exit(1)

    # calculate filter we are interested in (GATT opcodes)
    display_filter = ""
    SEP = " || "
    for i in ATT_OPCODES.keys():
        display_filter += f"btatt.opcode == {i}{SEP}" 
    display_filter = display_filter.strip(SEP)

    
    # open tshark
    cap = pyshark.FileCapture(
        args.pcap,
        display_filter=display_filter,
        custom_parameters=["-2"], # enable 2 pass loading, workaround for https://github.com/KimiNewt/pyshark/issues/745
    )

    # you can enable debug prints if needed
    # cap.set_debug()


    # write output header
    outf = open(out_fn, "w")
    ts = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    outf.write(f"# {os.path.basename(in_fn).replace(',', '')},{ts},encrypted\n")

    count = 0
    for pkt in cap:

        if not hasattr(pkt, "btatt"):
            continue

        bt_att = pkt.btatt
        pkt_number = pkt.number
        opcode = bt_att.opcode
        opcode = ATT_OPCODES.get(opcode.lower(), opcode)

        src_type = get_device_type(pkt.bluetooth.src)
        dst_type = get_device_type(pkt.bluetooth.dst)

        handle = getattr(bt_att, "handle", None)
        uuid = get_uuid(bt_att)
        data = get_value(bt_att)

        if handle is None or data is None or uuid is None:
            continue

        uuid = reformat_uuid(uuid)
        data = parse_data(data)

        towrite = f"{pkt_number},{src_type},{dst_type},{opcode},{uuid},{data.hex()}"
        #print(towrite)
        outf.write(towrite + "\n")
        count += 1

    outf.close()
    cap.close()
    print(f"done, wrote {count} gatt messages")

if __name__ == "__main__":
    main()

