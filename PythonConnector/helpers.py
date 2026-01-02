import logging

def resolve_char(client, find1, find2):
    """
    It is necessary do it this way, since sometimes a middle bit is flipped to 1. I dont know why though.
    """

    for service in client.services:
        for char in service.characteristics:
            parts = char.uuid.split("-")
            if find1 in parts[0] and find2 in parts[-1]: 
                return char.uuid

    raise Exception(f"Can not resolve characteristic {find1} {find2}!")


async def read_string(client, char):
    r = await client.read_gatt_char(char)
    r = r[0:-1] # null terminator
    return r.decode("utf-8",  errors="ignore")

async def read_bytes(client, char):
    r = await client.read_gatt_char(char)
    return r

async def write_char(client, char:str, data:bytearray):
    try:
        if client is None or not getattr(client, "is_connected", False):
            raise Exception("device is not connected! can not write")
        logging.info(f"<< [{char}] {data.hex()}")
        await client.write_gatt_char(char, data)
    except EOFError:
        logging.info("write failed: EOFError (connection closed)")
    except Exception as e:
        logging.info("write failed:", repr(e))
    return