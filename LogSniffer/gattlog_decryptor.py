#!/usr/bin/env python3

import argparse
import sys
import os

import sys
from pathlib import Path
sys.path.append(str((Path.cwd() / "../PythonConnector").resolve())) # hack for now

from sake_crypto import AVAILABLE_KEYS, KeyDatabase, SeqCrypt
from sake_crypto import Session as SakeSession

SAKE_UUID = "0000fe82000010000000009132591325"

from odf.opendocument import load
from odf.table import Table, TableRow, TableCell
from odf.text import P
from odf import teletype

def decrypt_traffic(entries:dict, cm:tuple, crypt:SeqCrypt):

    # make it a lookupable dict
    cm_dict = {}
    for l in cm:
        uuid, name, enc = l
        cm_dict[uuid] = (name, enc)

    decrypted_e = []
    count = 0
    for e in entries:

        if e["uuid"] == SAKE_UUID:
            continue

        ret = cm_dict.get(e["uuid"])

        if ret is None:
            print(f"WARNING: {e['uuid']} is not in the db yet!")
            continue

        name, enc = ret

        # if we dont even know the name, then dont decrypt for now
        if name is None:
            continue

        # not even encrypted -> skip
        if not enc:
            continue

        # Figure out whether the server or the client is writing. We need to
        # know whose message we are trying to decrypt.
        #
        # This is really ugly. We should probably put the information
        # directly into the gattlog instead of deriving it from the
        # source/destination strings.
        # if e["source"] == "PUMP":
        #     # pump as source is always the server
        #     use_server = True
        # elif e["source"] == "APP" and e["dest"] == "SENSOR":
        #     # app as source talking to sensor is the server
        #     use_server = True
        # else:
        #     use_server = False

        # # invert who's message it is
        # if not use_server:
        #     func = ses.server_crypt.decrypt
        # else:
        #     func = ses.client_crypt.decrypt

        try:
            d = bytes.fromhex(e["data"])
            if len(d) > 3:
                decrypted = crypt.decrypt(d) # for now just depend on the brute forced crypt object
                e["decrypted"] = decrypted
                decrypted_e.append(e)
            else:
                print(f"WARNING: skipping too small message: {e}")
        except Exception as e:
            print(f"msg #{count} ({name}) failed to decrypt: {d.hex()} -> {e}")

        count += 1

    print(f"\ndecrypted {len(decrypted_e)} messages!")
    return decrypted_e

def read_com_matrix(path) -> list[tuple]:
    """
    this function reads up the com matrix ods file.

    returns: list of tuples (uuid:str, char name:str, is encrypted:bool)
    """

    def expand_cells(row): # chatgpt black magic
        out = []
        for cell in row.getElementsByType(TableCell):
            repeat = int(cell.getAttribute("numbercolumnsrepeated") or 1)
            out.extend([cell] * repeat)
        return out

    to_read = [0, 1, 2] # uuid, name, encrypted
    doc = load(path)
    sheets = doc.spreadsheet.getElementsByType(Table)

    result = []

    for sheet in sheets[1:]: # skip first sheet
        rows = sheet.getElementsByType(TableRow)

        for row in rows[1:]: # skip header
            cells = expand_cells(row)

            if len(cells) <= max(to_read):
                continue

            local = []
            for i in to_read:
                local.append(teletype.extractText(cells[i]).strip())

            result.append(tuple(local))


    toret = []    
    for r in result:

        # clean stuff
        uuid, name, is_enc = r
        uuid = uuid.replace("-", "").replace("0x", "").lower()
        name = name.strip(" ")

        # check if is actually an entry or not
        if len(name) < 3 and len(uuid) < 3:
            continue

        # validate the uuid length
        if len(uuid) != 32:
            raise Exception(f"Invalid uuid length in db: {name} {uuid}")

        # parse encrypted field
        okay = ["yes", "no", "?"]
        if is_enc not in okay:
            raise Exception(f"Com matric ods file is filled incorrectly. Found '{is_enc}' in encrypted column for {uuid}")
        is_enc = True if is_enc == "yes" else False # if we dont know, assume no for now?
        
        # clear out the name if we dont know it
        if name == "?":
            name = None
    
        toret.append((uuid,name,is_enc))

    return toret

def try_session(kdb:KeyDatabase, entries:dict) -> None | SeqCrypt:
    sakes = []
    for e in entries:
        if e["uuid"] == SAKE_UUID:
            sakes.append(e)

    if len(sakes) != 8:
        raise Exception("Log file does not contain 8 sake messages at the beginning!")
    
    for i in [sakes[0], sakes[1]]:
        if bytes.fromhex(i["data"]) != bytearray(20):
            raise Exception("Sake handshake does not start with 2x all zero messages!")
        
    # get initiator device type. currently not used, since we are hacky brute forcing ;)
    init_dev = bytes.fromhex(sakes[2]["data"])[0]
    
    # try the client
    try:
        sess = SakeSession(client_key_database=kdb)
        sess.handshake_0_s(bytes.fromhex(sakes[2]["data"]))
        sess.handshake_1_c(bytes.fromhex(sakes[3]["data"]))
        sess.handshake_2_s(bytes.fromhex(sakes[4]["data"]))
        sess.handshake_3_c(bytes.fromhex(sakes[5]["data"]))
        sess.handshake_4_s(bytes.fromhex(sakes[6]["data"]))
        succ = sess.handshake_5_c(bytes.fromhex(sakes[7]["data"]))
        if succ:
            print("  client db works, returning server object")
            return sess.server_crypt
    except Exception as e:
        print(f"  client reject this keydb: {e}")
        pass

    # try the server
    try:
        sess = SakeSession(server_key_database=kdb)
        sess.handshake_0_s(bytes.fromhex(sakes[2]["data"]))
        sess.handshake_1_c(bytes.fromhex(sakes[3]["data"]))
        sess.handshake_2_s(bytes.fromhex(sakes[4]["data"]))
        sess.handshake_3_c(bytes.fromhex(sakes[5]["data"]))
        sess.handshake_4_s(bytes.fromhex(sakes[6]["data"]))
        succ = sess.handshake_5_c(bytes.fromhex(sakes[7]["data"]))
        if succ:
            print("  server db works, returning client object")
            return sess.client_crypt
    except Exception as e:
        print(f"  server reject this keydb: {e}")
        pass

    return None
    
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

    if len(parts) != 5:
        raise ValueError(f"Line {lineno}: expected 5 fields, got {len(parts)}")

    source, dest, opcode, uuid, data = parts

    return {
        "source": source,
        "dest": dest,
        "opcode": opcode,
        "uuid": uuid,
        "data": data,
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

def get_uuid_name(uuid, com_matrix) -> str:
    for i in com_matrix:
        i_uuid, name, _ = i
        if uuid == i_uuid:
            return name
    return uuid # fallback

def main():
    parser = argparse.ArgumentParser(description="Gattlog decryptor")
    parser.add_argument("file", help="Gattlog file to parse")
    parser.add_argument("--out", help="output file", default="decrypted.gattlog")
    parser.add_argument("--com_matrix", help="com matrix file", default="../docs/attachments/com_matrix.ods")
    parser.add_argument("-r",  "--resolve_uuids", action="store_true", help="resolve uuid names for debugging", default=False)
    parser.add_argument("-f", "--force-output", action="store_true", help="overwrite existing output file", default=False)
    parser.add_argument("-k", "--key-db", choices=AVAILABLE_KEYS.keys(), help="use this specific key database instead of trying the available ones until a working one is found")

    args = parser.parse_args()

    # check outfile
    out_fn = os.path.abspath(args.out)
    if os.path.exists(out_fn):
        if args.force_output:
            os.remove(out_fn)
        else:
            print(f"Error: output file '{out_fn}' already exists on disk.")
            sys.exit(1)

    # parse the com matrix
    if not os.path.isfile(args.com_matrix):
        raise FileNotFoundError(args.com_matrix)
    com_matrix = read_com_matrix(args.com_matrix)
    # for c in com_matrix:
    #     print(c)
    # return

    # parse the file
    try:
        header, entries = parse_file(args.file)
        print(f"read {len(entries)} messages!\n")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # open output file
    out_f = open(out_fn, "w")
    
    # write back the headers but with "decrypted"
    text = "# "
    for k, v in header.items():
        if v == "encrypted":
            v = "decrypted"
        text += f"{v},"
    text = text.strip(",")
    out_f.write(text + "\n")

    if args.key_db:
        # use key database chosen by user
        kdb_list = {args.key_db: AVAILABLE_KEYS[args.key_db]}
    else:
        # use all available key databases
        kdb_list = AVAILABLE_KEYS

    # successively try to decrypt the data with all keys available
    for kdb_name, kdb in kdb_list.items():
        print(f"trying keydb {kdb_name}...")
        crypt = try_session(kdb, entries)
        if crypt != None:
            print(f"\nWORKING KEYDB FOUND: {kdb_name}!\n")
            decrypted = decrypt_traffic(entries, com_matrix, crypt)
            
            # make it indexable
            dec_i = {}
            for d in decrypted:
                dec_i[d["data"]] = d["decrypted"]

            # combine them
            e_out = []
            for e in entries:
                dec = dec_i.get(e["data"])
                if dec != None:
                    e["data"] = dec.hex()
                e_out.append(e)

            for e in e_out:
                if args.resolve_uuids:
                    uuid = get_uuid_name(e["uuid"], com_matrix)
                else:
                    uuid = e["uuid"]
                out_f.write(f'{e["source"]},{e["dest"]},{e["opcode"]},{uuid},{e["data"]}\n')
            print(f"{len(e_out)} messages were written!")
            out_f.close()
            return

    # decryption failed
    print("no compatible key db found, deleting out file!")
    out_f.close()
    os.remove(out_fn)
    return

if __name__ == "__main__":
    main()