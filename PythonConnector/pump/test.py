#!/usr/bin/env python3
from bluezero import peripheral, adapter, advertisement
from bluezero.broadcaster import Beacon
from gi.repository import GLib
import json
import os
import random
import time
import sys
from time import sleep

script_dir = os.path.realpath(os.path.dirname(__file__))
sys.path.append(os.path.join(script_dir, "../PythonConnector"))
from advertise import advertise
from threading import Thread

# NOTE: does not seem to work, since bluez rejects MITM = 1 flag when no input no output io capabilities is presented!
# avertise.py contains a hacky advertisement method, since dbus does not allow type flag to be set ?


# sudo btmgmt power off
# sudo btmgmt bredr off
# sudo btmgmt le on
# sudo btmgmt io-cap 4
# sudo btmgmt power on

connected = False

def adv_thread():
    while not connected:
        advertise(mobile_name)

# ---------------- BLE Peripheral Settings ----------------
SERVICE_UUID = "980c2f36-bde3-11e4-8dfc-aa07a5b093db" # extracted from SSO config (see carelink api repo)
CHAR_UUID    = "980c34cc-bde3-11e4-8dfc-aa07a5b093db"
EOM = b"EOM" # hardcoded in minimedmobile apk
buffer = bytearray()
characteristic = None
loop = GLib.MainLoop()

# ---------------- Utility Functions ----------------
def gen_mobile_name():
    while True:
        num = random.randint(100000, 999999)
        if num % 2 == 1:
            return f"Mobile {num}"

mobile_name = "Mobile 000001"
print(f"using mobile name {mobile_name}")

# ---------------- BLE Callbacks ----------------
def on_connect(dev):
    global connected
    connected = True
    print("Connected:", dev.address)

def on_disconnect(adapter_addr, device_addr):
    print("Disconnected:", device_addr)

def read_callback():
    print("!!! READ")
    return [42,]

def notify_callback(notifying, char):
    print("!!! NOTIFY")
    print("Notifications:", "enabled" if notifying else "disabled")

def write_callback(value, options):
    global buffer, characteristic

    print("!!! WRITE", value)


# ---------------- BLE Adapter ----------------
adapter_addr = list(adapter.Adapter.available())[0].address
print(f"Using adapter: {adapter_addr}")

# ---------------- BLE Advertisement ----------------

#while True:



# ---------------- BLE Peripheral ----------------
ble = peripheral.Peripheral(
    adapter_address=adapter_addr,
    local_name=mobile_name,
    
    # you might need to run
    # sudo btmgmt io-cap keyboard-display
    # bluetoothctl
    # agent KeyboardDisplay
    # default-agent

    
    #pairable=True,
    #bondable=True,
)


###############################
### App Information service ###
###############################

ble.add_service(
    srv_id=1,
    uuid="00000900-0000-1000-0000-009132591325",
    primary=True
)

# MANUFACTURER_NAME_STRING_CHAR
ble.add_characteristic(
    srv_id=1,
    chr_id=1,
    uuid="00002A29-0000-1000-0000-00805F9B34FB",
    value=[],
    notifying=False,
    flags=["read"],
    read_callback=read_callback,
)
# MODEL_NUMBER_STRING_CHAR
ble.add_characteristic(
    srv_id=1,
    chr_id=2,
    uuid="00002A24-0000-1000-0000-00805F9B34FB",
    value=[],
    notifying=False,
    flags=["read"],
    read_callback=read_callback,
)
# SERIAL_NUMBER_STRING_CHAR
ble.add_characteristic(
    srv_id=1,
    chr_id=3,
    uuid="00002A25-0000-1000-0000-00805F9B34FB",
    value=[],
    notifying=False,
    flags=["read"],
    read_callback=read_callback,
)
# HARDWARE_REVISION_STRING_CHAR
ble.add_characteristic(
    srv_id=1,
    chr_id=4,
    uuid="00002A27-0000-1000-0000-00805F9B34FB",
    value=[],
    notifying=False,
    flags=["read"],
    read_callback=read_callback,
)
# FIRMWARE_REVISION_STRING_CHAR
ble.add_characteristic(
    srv_id=1,
    chr_id=5,
    uuid="00002A26-0000-1000-0000-00805F9B34FB",
    value=[],
    notifying=False,
    flags=["read"],
    read_callback=read_callback,
)
# SOFTWARE_REVISION_STRING_CHAR
ble.add_characteristic(
    srv_id=1,
    chr_id=6,
    uuid="00002A28-0000-1000-0000-00805F9B34FB",
    value=[],
    notifying=False,
    flags=["read"],
    read_callback=read_callback,
)
# SYSTEM_ID_CHAR
ble.add_characteristic(
    srv_id=1,
    chr_id=7,
    uuid="00002A23-0000-1000-0000-00805F9B34FB",
    value=[],
    notifying=False,
    flags=["read"],
    read_callback=read_callback,
)
# PNP_ID_CHAR
ble.add_characteristic(
    srv_id=1,
    chr_id=8,
    uuid="00002A50-0000-1000-0000-00805F9B34FB",
    value=[],
    notifying=False,
    flags=["read"],
    read_callback=read_callback,
)
# CERTIFICATION_DATA_LIST_CHAR
ble.add_characteristic(
    srv_id=1,
    chr_id=9,
    uuid="00002A2A-0000-1000-0000-00805F9B34FB",
    value=[],
    notifying=False,
    flags=["read"],
    read_callback=read_callback,
)


#########################
### Medtronic service ###
#########################

ble.add_service(
    srv_id=2,
    uuid="0000FE82-0000-1000-8000-00805F9B34FB",
    #uuid="FE82"
    primary=True,
)

ble.add_characteristic(
    srv_id=2,
    chr_id=10,
    uuid="0000FE82-0000-1000-8000-009132591325",
    value=[],
    notifying=False,
    flags=["read", "notify"],
    read_callback=read_callback,
    notify_callback=notify_callback,
)



# Save characteristic object for later use
#characteristic = ble.services[0].characteristics[0]

ble.on_connect = on_connect
ble.on_disconnect = on_disconnect


thread = Thread(target = adv_thread)
thread.start()

ble.publish()

