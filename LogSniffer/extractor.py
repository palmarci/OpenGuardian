#!/usr/bin/env python3

from datetime import datetime
import argparse
import pyshark
import os
import sys

ATT_OPCODES = {
    0x12: "WRITE", # ATT_WRITE_REQ
    0x0b: "READ", # ATT_READ_RSP
    0x1b: "NOTIFY", # ATT_HANDLE_VALUE_NTF
    0x1d: "INDICATE", # ATT_HANDLE_VALUE_IND
    # https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/attribute-protocol--att-.html
}

def parse_opcode_handle(args: bytes):

    SINGLE_HANDLE_OPCODES = {
        0x0A,  # Read Request
    #    0x0B,  # Read Response (note: no handle, usually filtered out)
        0x12,  # Write Request
        0x52,  # Write Command
        0x1B,  # Handle Value Notification
        0x1D,  # Handle Value Indication
    }


    if len(args) < 3:
        print("warning: packet too short")
        return None

    opcode = args[0]

    if opcode not in SINGLE_HANDLE_OPCODES:
        print(f"warning: unexpected opcode 0x{opcode:02X}")
        return None

    handle = int.from_bytes(args[1:3], "little")
    data = args[3:]

    return data


def dump(obj):
    """
    Best-effort dump of all *data* fields of any Python object.
    Handles __dict__, __slots__, and C-extension objects.
    """
    cls = obj.__class__
    print(f"{cls.__name__} @ {hex(id(obj))}")

    seen = set()

    # 1) __dict__ (normal Python objects)
    if hasattr(obj, "__dict__"):
        for k, v in vars(obj).items():
            seen.add(k)
            print(f"  {k}: {v!r}")

    # 2) __slots__ (slotted classes)
    slots = getattr(cls, "__slots__", ())
    if isinstance(slots, str):
        slots = (slots,)

    for s in slots:
        if s in seen:
            continue
        try:
            v = getattr(obj, s)
            seen.add(s)
            print(f"  {s}: {v!r}")
        except Exception:
            pass

    # 3) dir() fallback (C-extension / proxy objects)
    for name in dir(obj):
        if name.startswith("_") or name in seen:
            continue
        try:
            val = getattr(obj, name)
        except Exception:
            continue
        if callable(val):
            continue
        print(f"  {name}: {val!r}")


def parse_args():
    ap = argparse.ArgumentParser(description="Extract BLE GATT read/write/notify data")
    ap.add_argument("pcap", help="pcap/pcapng input file")
    ap.add_argument("-o", "--out", help="output file", default="output.gattlog")
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

def get_uuid(att, pktno) -> tuple[str,str]:
    _key_service_128 = "service_uuid128"
    _key_char_16 = "uuid16"
    _key_char_128 = "uuid128"
    _key_service_16 = "service_uuid16"

    # mostly it uses regular 128 bit char uuids
    if hasattr(att, _key_char_128):
        return None, getattr(att, _key_char_128)
    
    # or else it 128 bit service with 16 bit char
    if hasattr(att, _key_service_128):
        return getattr(att, _key_service_128), getattr(att, _key_char_16)

    # or 16 bit service with 16 bit char
    if hasattr(att, _key_service_16):
        return getattr(att, _key_service_16), getattr(att, _key_char_16)
    
    # or just 16 bit char
    if hasattr(att, _key_char_16):
        return None, getattr(att, _key_char_16)

    print(f"\n\nWARNING: could not get char uuid for packet #{pktno}")
    print(dump(att))
    return None, None

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

def reformat_uuid(uuid:int|str):
    if isinstance(uuid, int):
        uuid = hex(uuid)
    uuid = uuid.replace(":", "").lower().replace("0x", "")
    return uuid

def parse_biggest_raw_flag(raw_dict,pktno):
    raws = []
    for k,v in raw_dict.items():
        
        print(k,v)
        if k == "btatt_btatt_value_raw":
            if isinstance(v, str):
                return bytes.fromhex(v)
            else:
                print(f"WARNING: btatt_btatt_value_raw was not a string for #{pktno}")
                return None
            

        if k.endswith("_raw") and isinstance(v, str) and len(v) % 2 == 0:
            #print(v)
            raws.append(bytes.fromhex(v))

    raws = sorted(raws, key=len, reverse=True)
    if len(raws) == 0:
        print(f"WARNING: failed to find any data for #{pktno}")
        return None
    
    return raws[0] # hack level 1000

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
        display_filter += f"btatt.opcode == {hex(i)}{SEP}" 
    display_filter = display_filter.strip(SEP)

    
    # open tshark
    cap = pyshark.FileCapture(
        args.pcap,
        display_filter=display_filter,
        custom_parameters=["-2"], # enable 2 pass loading, workaround for https://github.com/KimiNewt/pyshark/issues/745
        use_ek=True,
        include_raw=True
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

        pktno = int(pkt.number)
        full_bytes = bytes.fromhex(pkt.btatt_raw._fields_dict)
        print("-"*10)
        print(pktno)
        print(dump(pkt.btatt))
        print(dump(pkt.btatt_raw))
        print(full_bytes.hex())

        opcode = ATT_OPCODES.get(pkt.btatt.opcode.value)
    
        if not opcode:
            print(f"WARNING: could not get opcode for #{pktno}") 
            continue

        # get src and det
        src_type = get_device_type(pkt.bluetooth.src)
        dst_type = get_device_type(pkt.bluetooth.dst)

        if opcode == "READ":
            # swap them, since this is a response
            dest_type_bak = dst_type 
            dst_type = src_type
            src_type = dest_type_bak

        # get uuids
        uuids = get_uuid(pkt.btatt, pktno)

        # data

        # first try it from the raw btatt traffic, if we can
        data = parse_opcode_handle(full_bytes)

        if data == None: # else, try the longest "_raw" flag from tshark
            data = parse_biggest_raw_flag(pkt.btatt._fields_dict, pktno)
        #print(uuids)
        if data == None or data.hex() == "0b":
            print(f"WARNING: no data decoded #{pktno}!!!!!")
            continue


        serv_uuid, char_uuid = uuids
        if serv_uuid is None and char_uuid is None:
            continue
   
        char_uuid = reformat_uuid(char_uuid)

        if char_uuid == "2902": # ignore these for now
            continue

        if serv_uuid is not None:
            serv_uuid = reformat_uuid(serv_uuid)

        datastr = data.hex() if data is not None else "None"
        towrite = f"{pktno},{src_type},{dst_type},{opcode},{serv_uuid},{char_uuid},{datastr}"
        #print(towrite)
        outf.write(towrite + "\n")
        count += 1

    outf.close()
    cap.close()
    print(f"done, wrote {count} gatt messages")

if __name__ == "__main__":
    main()

