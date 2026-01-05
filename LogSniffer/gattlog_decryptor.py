#!/usr/bin/env python3

import argparse
import sys
import os
import logging
import sys
from pathlib import Path

sys.path.append(str((Path.cwd() / "../PythonConnector").resolve())) # hack for now
from sake_crypto import KeyDatabase, AVAILABLE_KEYS, SAKE_LOGGER, Session as SakeSession

from com_matrix import ComMatrixParser, Characteristic

SAKE_UUID = "0000fe82000010000000009132591325"
DEVICE_TYPE_MAP = {
    "APP": [4,8], # there was a library update
    "PUMP": [1],
    "SENSOR": [2]
}
CHARS = None # will be filled up
DEBUG_SAKE = False

def parse_header(line):
    if not line.startswith("#"):
        raise ValueError("First line must start with '#'")

    # remove '#' and split by comma, ignoring spaces
    parts = [p.strip() for p in line[1:].split(",")]

    if len(parts) < 3:
        raise ValueError("Header must contain at least 3 fields")

    return {
        "original_filename": parts[0] or "unknown",
        "conversion_date": parts[1],
        "decryption_state": parts[2],
        "notes": parts[3:] if len(parts) > 3 else "",
    }

def parse_entry(line, lineno):
    parts = [p.strip() for p in line.split(",")]

    if len(parts) != 6:
        raise ValueError(f"Line {lineno}: expected 6 fields, got {len(parts)}")

    pkt_number, source, dest, opcode, uuid, data = parts

    return {
        "frame": int(pkt_number),
        "source": source,
        "dest": dest,
        "opcode": opcode,
        "uuid": uuid,
        "data": bytes.fromhex(data),
    }

def parse_file(path):
    with open(path, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip()]

    if not lines:
        raise ValueError("File is empty")

    header = parse_header(lines[0])
    entries = []

    for i, line in enumerate(lines[1:], start=2):
        entries.append(parse_entry(line, i))

    return header, entries

def get_uuid_name(uuid) -> str:
    """
    Resolve UUID to human name.
    """
    for i in CHARS:
        if uuid == i.uuid:
            return i.name
    return uuid # fallback

def get_matching_keydb(entries:list[dict]) -> KeyDatabase:
    """
    This function tries to resolve the applicable key db, based on the communicating device types.
    """
    types = []
    keys = ["dest", "source"]
    for e in entries:
        for k in keys:
            if e[k] not in types:
                types.append(e[k])
    if len(types) != 2:
        raise Exception("Got unexpected number of devices in the log!")

    types.sort()

    local = types[0]
    if local != "APP":
        raise NotImplementedError("Currently only traffic using the APP is supported!")

    other_ids = DEVICE_TYPE_MAP.get(types[1])
    if not other_ids or len(other_ids) < 1:
        raise Exception("Invalid other device name!")

    for kdb_name, kdb in AVAILABLE_KEYS.items():
        for local_ids in DEVICE_TYPE_MAP.get(local):
            for other_id in other_ids:
                if local_ids == kdb.local_device_type and kdb.remote_devices.get(other_id):
                    print(f"found applicable key db: {kdb_name} (alias {kdb.crc.hex()})")
                    return kdb

    raise Exception("Could not find applicable key db! Please manually force it if you know what are you doing. See -h for more info.")

def separate_sake_and_data(entries:list[dict]) -> tuple[bytes, list[dict]]:
    """
    This function will separate the handshake and the actual data payload.
    Returns: handshake messages (6), data messages 
    """

    sakes = []
    msgs = []

    for e in entries:
        if e["uuid"] == SAKE_UUID:
            sakes.append(e["data"])
        else:
            msgs.append(e)

    if len(sakes) != 8:
        raise Exception("Log file does not contain 8 sake messages at the beginning!")
    
    for i in [sakes[0], sakes[1]]:
        if i != bytearray(20):
            raise Exception("Sake handshake does not start with 2x all zero messages!")
        
    # remove the first two zeroes
    del sakes[0]
    del sakes[0]

    return sakes, msgs

def put_to_output(msg:dict, outfile) -> None:
    """
    This function prints and logs the final data to the out file.
    """
    uuid = get_uuid_name(msg["uuid"])
    d = f'{msg["frame"]},{msg["source"]},{msg["dest"]},{msg["opcode"]},{uuid},{msg["data"].hex()}'
    outfile.write(d + "\n")
    if DEBUG_SAKE:
        print(d)
    return

def main():

    global CHARS, DEBUG_SAKE

    # init logging
    logging.basicConfig(
        level=logging.INFO, 
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        stream=sys.stdout
    )

    # parse the args
    parser = argparse.ArgumentParser(description="Gattlog decryptor")
    parser.add_argument("file", help="Gattlog file to parse")
    parser.add_argument("-o", "--out", help="output file", default="decrypted.gattlog")
    _com_matrix_default = os.path.relpath(os.path.join(os.path.dirname(__file__), "..", "data", "com_matrix"))
    parser.add_argument("-m", "--com-matrix", help=f"com matrix directory. default is compatible with the repo: {_com_matrix_default}", default=_com_matrix_default)
    parser.add_argument("-r",  "--resolve-uuids", action="store_true", help="resolve uuid names for debugging", default=False)
    parser.add_argument("-f", "--force-output", action="store_true", help="overwrite existing output file", default=False)
    parser.add_argument("-k", "--key-db", choices=AVAILABLE_KEYS.keys(), help="use this specific key database instead of automatically resolving it")
    parser.add_argument("-d", "--debug-sake", help="turn on SAKE crypto debug logging", action="store_true", default=False)
    args = parser.parse_args()

    # check the output file
    out_fn = os.path.abspath(args.out)
    if os.path.exists(out_fn):
        if args.force_output:
            os.remove(out_fn)
        else:
            print(f"Error: output file '{out_fn}' already exists on disk.")
            sys.exit(1)

    # parse the com matrix
    cm_path = Path(args.com_matrix).expanduser().resolve()
    if not cm_path.is_dir():
        raise NotADirectoryError(args.com_matrix) 
    cm_parser = ComMatrixParser(str(cm_path))
    CHARS = cm_parser.parse()
    print(f"parsed {len(CHARS)} characteristics successfully")

    # turn on crypto logging if needed
    DEBUG_SAKE = args.debug_sake
    if DEBUG_SAKE:
        SAKE_LOGGER.setLevel(logging.DEBUG)

    # parse the input file
    entries_len = 0
    try:
        header, entries = parse_file(args.file)
        entries_len = len(entries)
        print(f"read {entries_len} messages")
    except Exception as msg:
        print(f"Error reading input file: {msg}", file=sys.stderr)
        sys.exit(1)

    # open the output file
    out_f = open(out_fn, "w")
    
    # write back the headers but with "decrypted" flag
    text = "# "
    for _, v in header.items():
        if v == "encrypted":
            v = "decrypted"
        text += f"{v},"
    text = text.strip(",")
    out_f.write(text + "\n")

    # get the key db based on args or auto resolve
    if args.key_db:
        kdb = AVAILABLE_KEYS[args.key_db]
        print(f"forced key db: {kdb.crc.hex()}")
    else:
        kdb = get_matching_keydb(entries)

    # separate our data
    handsake, data = separate_sake_and_data(entries) # hands(h)ake ;) i am very funny
    del entries
    
    # create the sake objects
    sess = SakeSession(server_key_database=kdb) # TODO: when to try client_key_database ?
    sess.handshake_0_s(handsake[0])
    sess.handshake_1_c(handsake[1])
    sess.handshake_2_s(handsake[2])
    sess.handshake_3_c(handsake[3])
    sess.handshake_4_s(handsake[4])
    sess.handshake_5_c(handsake[5])

    # chars a lookup-able dict
    char_dict:dict[Characteristic] = {}
    for c in CHARS:
        char_dict[c.uuid] = c

    # main loop
    out_count = 0
    decrypted_count = 0
    print("")
    for msg in data:

        # get uuid
        ret = char_dict.get(msg["uuid"])
        if ret is None:
            print(f"WARNING: {msg['uuid']} is not in the db yet!")
            put_to_output(msg, out_f)
            out_count += 1
            continue

        # get chars' details
        name = ret.name
        enc = ret.encrypted

        # if we dont even know the name, then dont decrypt for now
        if name is None:
            print(f"WARNING: skipping unknown char with uuid {msg['uuid']}")
            put_to_output(msg, out_f)
            out_count += 1
            continue

        # it is not encrypted
        if not enc:
            put_to_output(msg, out_f)
            out_count += 1
            continue

        ciphertext = msg["data"]
        plaintext = None
        err = None

        # for now, try both direction (TODO: sequence number problems?)
        try:
            plaintext = sess.client_crypt.decrypt(ciphertext)
        except Exception as e:
            err = e
            pass

        try:
            plaintext = sess.server_crypt.decrypt(ciphertext)
        except Exception as e:
            err = e
            pass
        
        # put the decrypted data back
        if not plaintext:
            print(f"msg {name} failed to decrypt: {ciphertext.hex()} -> {err}")
        else:
            msg["data"] = plaintext
            decrypted_count += 1 
        
        # write it
        put_to_output(msg, out_f)
        out_count += 1

    # housekeeping
    print("")
    out_f.close()
    if decrypted_count == 0:
        print(f"there was nothing we could decrypt :(")
        print(f"{out_fn} file was deleted...")
        os.remove(out_fn)
    
    print(f"decrypted {decrypted_count} messages, wrote {out_count}")
    assert out_count == (entries_len - 8), "Not all messages were written" # 8 sake messages wasted

if __name__ == "__main__":
    main()

