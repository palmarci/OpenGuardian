#!/usr/bin/env python3
from bluezero import peripheral, adapter, advertisement
from bluezero.broadcaster import Beacon
from gi.repository import GLib
import json
import random
import time
import sys
from time import sleep

from PythonConnector.pump.advertise import advertise
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

mobile_name = gen_mobile_name()
print(f"using mobile name {mobile_name}")

# ---------------- BLE Callbacks ----------------
def on_connect(dev):
    global connected
    connected = True
    print("Connected:", dev.address)

def on_disconnect(adapter_addr, device_addr):
    print("Disconnected:", device_addr)

def notify_callback(notifying, char):
    print("Notifications:", "enabled" if notifying else "disabled")

def write_callback(value, options):
    global buffer, characteristic

    print("WRITE:", value)

    #if value != EOM:
    #    buffer.extend(value)
    #    return

    # EOM received
    try:
        data = json.loads(buffer.decode())
        buffer.clear()

        provider_url = data["provider_url"]
        device_name = data.get("device_name", "Unknown")

        print("Auth request from:", device_name)
        print("Provider URL:", provider_url)

        # ---- CONSENT / AUTH LOGIC ----
        approved = True

        if approved:
            characteristic.set_value(b"0")  # SUCCESS
        else:
            characteristic.set_value(b"1")  # CANCEL

        characteristic.notify()

    except Exception as e:
        print("Error:", e)
        #characteristic.set_value(str(e).encode())
        #characteristic.notify()

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

ble.add_service(
    srv_id=1,
    uuid=SERVICE_UUID,
    primary=True
)

ble.add_characteristic(
    srv_id=1,
    chr_id=1,
    uuid=CHAR_UUID,
    value=[],
    notifying=False,
    flags=['write', 'notify'],
    write_callback=write_callback,
    notify_callback=notify_callback
)

# Save characteristic object for later use
#characteristic = ble.services[0].characteristics[0]

ble.on_connect = on_connect
ble.on_disconnect = on_disconnect


thread = Thread(target = adv_thread)
thread.start()

ble.publish()

