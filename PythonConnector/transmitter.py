import argparse
import asyncio
from datetime import datetime
from bleak import BleakScanner, BleakClient
from bleak.exc import BleakDBusError
import sys
import logging

from helpers import resolve_char, read_string, write_char, read_bytes
from handshake_client import HandshakeClient, KEYDB_G4_CGM

# ***** USAGE *****
# 1. put device on charger
# 2. wait 10s on charger
# 3. start script
# 4. wait 2s
# 5. disconnect from charger
# 6. wait until pairing, handshake, and sensor connected message
# 7. connect green test tool to the device
# ???


# globals (dont touch)
SAKE_INITED = False
CLIENT = None
CHAR_SAKE = None
HANDSHAKE_DONE = False
HANDSHAKE_COUNT = 0
HSC = HandshakeClient(KEYDB_G4_CGM)

# setup logging: console + file with timestamped filename, same format including date
_LOG_FMT = "%(asctime)s %(levelname)s: %(message)s"
_datefmt = "%Y-%m-%d %H:%M:%S"
_timestamp_fname = datetime.now().strftime("%Y%m%d_%H%M%S.log")
logging.basicConfig(level=logging.DEBUG, format=_LOG_FMT, datefmt=_datefmt, handlers=[
    logging.StreamHandler(),
    logging.FileHandler(_timestamp_fname, mode="a", encoding="utf-8"),
])
logger = logging.getLogger(__name__)


def common_callback(char, data: bytearray):
    logger.debug(
        "RX from %s | handle=%s | data=%s", char.uuid, char.handle, data.hex()
    )
    if "00002aa7" in char.uuid:  # measurement
        dec = try_decrypt(data)
        logger.debug("decrypted measurement = %s", dec.hex())
    return


async def scan(timeout=30):
    logger.info("scanning for bt devices... (%s s)", timeout)
    devices = await BleakScanner.discover(timeout=timeout)
    for d in devices:

        # https://standards-oui.ieee.org/oui/oui.txt
        if d.address.replace(":", "").startswith("DC16A2"):
            # Medtronic Diabetes device
            logger.info("GOT MEDTRONIC DEVICE: %s", d.address)
            return d.address
        else:
            logger.debug("Non-medtronic device found: %s - %s", d.name, d.address)

    return None


def try_decrypt(data):
    if len(data) < 1:
        raise Exception("data too small to decrypt")
    try:
        decrypted = HSC.session.server_crypt.decrypt(data)
        logger.debug("decryption ok! %s -> %s", data.hex(), decrypted.hex())
        return decrypted
    except Exception as e:
        raise Exception(f"failed to decrypt with server_crypt: {e}")


async def user_logic():

    global CLIENT, HANDSHAKE_DONE

    char_cgm_ses_start = resolve_char(CLIENT, "2aaa", "805f9b34fb")
    char_cgm_sens_connected = resolve_char(CLIENT, "201", "9132591325")

    # wait for handshake to complete
    while not HANDSHAKE_DONE:
        await asyncio.sleep(0.1)

    while True:

      #  try:
            # check if we are alive
            if not CLIENT.is_connected:
                logger.error("device disconnected!")
                sys.exit(1)

            # read if sensor is connected
            c = await read_bytes(CLIENT, char_cgm_sens_connected)
            is_conn = bool(c[0])
            logger.info("sensor connected? %s", is_conn)

            # read session start (we crash if we read this too often???)
            # data = await CLIENT.read_gatt_char(char_cgm_ses_start)
            # ses_start = try_decrypt(data)

            await asyncio.sleep(5)
#        except BleakDBusError as e:

            # ignore for now: bleak.exc.BleakDBusError: [org.bluez.Error.Failed] Operation failed with ATT error: 0x0e (Unlikely Error)
 #           if "0x0e" not in repr(e):
  #              raise e


def sake_notification_handler(_: int, data: bytearray):

    global SAKE_INITED, HANDSHAKE_COUNT, HANDSHAKE_DONE

    logger.debug(">> [sake] %s", data.hex())

    # if we get an all zeroes, we need to send the same back
    if not SAKE_INITED:
        zeroes = bytearray(20)
        if data != zeroes:
            raise Exception("expected all zeroes!")

        asyncio.create_task(write_char(CLIENT, CHAR_SAKE, zeroes))
        SAKE_INITED = True

    else:
        out = HSC.handshake(data)
        HANDSHAKE_COUNT += 1

        if out:
            asyncio.create_task(write_char(CLIENT, CHAR_SAKE, out))
        else:
            logger.warning("handshake already done??, unexpected notification from device!")

        # final handshake count may vary; original expected 3
        if HANDSHAKE_COUNT >= 3:
            HANDSHAKE_DONE = True
            logger.info("sake handshake is done!")

    return


async def connect(mac, timeout=120):

    global CLIENT, CHAR_SAKE

    start = datetime.now()
    logger.info("connecting to %s... started at %s, timeout=%s\nit might take a while!", mac, start, timeout)


    async with BleakClient(mac, timeout=timeout, pair=True) as client:

        CLIENT = client

        # ensure we are connected
        if CLIENT.is_connected:
            logger.info("Connected to %s after %s s", mac, (datetime.now() - start).seconds)
        else:
            raise Exception("Device is not connected!")

        # get basic info of the device
        char_manuf = resolve_char(CLIENT, "2a29", "805f9b34fb")
        char_model = resolve_char(CLIENT, "2a24", "805f9b34fb")
        char_hw_rev = resolve_char(CLIENT, "2a27", "805f9b34fb")
        char_fw_rev = resolve_char(CLIENT, "2a26", "805f9b34fb")
        char_sw_rev = resolve_char(CLIENT, "2a28", "805f9b34fb")
        char_battery = resolve_char(CLIENT, "2a19", "805f9b34fb")

        # read stuff
        manuf = await read_string(CLIENT, char_manuf)
        model = await read_string(CLIENT, char_model)
        hw = await read_string(CLIENT, char_hw_rev)
        fw = await read_string(CLIENT, char_fw_rev)
        sw = await read_string(CLIENT, char_sw_rev)
        batt = await read_bytes(CLIENT, char_battery)

        devinfo = f"{manuf} {model}, HW: {hw}, FW: {fw}, SW: {sw}, BATT: {batt[0]} %"
        logger.info("Device details = %s", devinfo)

        # get the sake port and subscribe to perform the handshake
        CHAR_SAKE = resolve_char(CLIENT, "fe82", "9132591325")
        await CLIENT.start_notify(CHAR_SAKE, sake_notification_handler)

  
        # subscribe to all OTHER chars that the device may send us
        for serv in CLIENT.services:
            for char in serv.characteristics:
                props = char.properties
                if ("notify" in props or "indicate" in props) and char.uuid != CHAR_SAKE:
                    logger.info("subscribing to %s with default callback", char.uuid)
                    await CLIENT.start_notify(
                        char,
                        lambda sender, data, c=char: common_callback(c, data)
                    )

        # create a seperate task for user logic code
        asyncio.create_task(user_logic())

        # wait forever so we keep receiving notifications
        await asyncio.Event().wait()


async def main(mac):

    if not mac:
        mac = await scan()
        if mac is None:
            raise Exception("Could not find any Medtronic device! Try hardcoding the MAC!")

    await connect(mac)
    return


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("-m", "--mac", help="initial MAC address (if omitted, scanning will be used)", default=None)
    args = p.parse_args()
    mac_val = args.mac if args.mac != "" else None

    bleak_logger = logging.getLogger("bleak")
    bleak_logger.setLevel(logging.WARNING)

    asyncio.run(main(mac_val))
