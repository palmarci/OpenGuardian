#!/usr/bin/env python3

from bluezero import peripheral, adapter, advertisement
from bluezero.broadcaster import Beacon
from threading import Thread

from utils import *

STARTUP_COMMANDS = [
    "sudo btmgmt power off",
    "sudo btmgmt bredr off",
    "sudo btmgmt le on",
    "sudo btmgmt io-cap 3",
    "sudo btmgmt power on"
]

CONNECTED = False
MOBILE_NAME = None

def adv_thread():
    print("\n"*3)
    print("-"*10 + " starting advertisement!" + "-"*10)
    print(" "*10 + "(ignore error 0x0d)")
    while True:
        if not CONNECTED:
            advertise(MOBILE_NAME)
        sleep(0.1)

def on_connect(dev):
    global CONNECTED
    CONNECTED = True
    print("Connected:", dev.address)

def on_disconnect(adapter_addr, device_addr):
    global CONNECTED
    CONNECTED = False
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


def main():
    global MOBILE_NAME

    MOBILE_NAME = gen_mobile_name()
    print(f"using name: {MOBILE_NAME}")

    batch_exec(STARTUP_COMMANDS)    # configure the BT adapter

    adapter_addr = list(adapter.Adapter.available())[0].address
    print(f"using adapter: {adapter_addr}")

    ble = peripheral.Peripheral(
        adapter_address=adapter_addr,
        local_name=MOBILE_NAME
    )

    add_chars_and_services(ble, read_callback, notify_callback)
    print(f"set up {len(ble.services)} services and {len(ble.characteristics)} chars ")

    ble.on_connect = on_connect
    ble.on_disconnect = on_disconnect

    thread = Thread(target = adv_thread)
    thread.start()

    ble.publish()
    
    return

if __name__ == "__main__":
    main()