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
BLE = None
SAKE_CHAR = None

def adv_thread():
    print("\n"*3)
    print("-"*10 + " starting advertisement!" + "-"*10)
    print(" "*10 + "(ignore error 0x0d)")
    while True:
        if not CONNECTED:
            advertise(MOBILE_NAME)
        sleep(0.1)

def send_sake_notif():
    zero = list(bytes.fromhex("00"*20))
    print("calling sake char set value...")
    SAKE_CHAR.set_value(zero)
    for i in range(1000):
        print("notifying? " + str(SAKE_CHAR.is_notifying))

def on_connect(dev):
    global CONNECTED
    CONNECTED = True
    print(f"Connected: {dev.address}, waiting before sake notification...")
    sleep(3)
    send_sake_notif()

def on_disconnect(adapter_addr, device_addr):
    global CONNECTED
    CONNECTED = False
    print(f"Disconnected {device_addr}, going back to advertising!")
    forget_pump_devices()

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
    global MOBILE_NAME, BLE, SAKE_CHAR

    MOBILE_NAME = gen_mobile_name()
    print(f"using name: {MOBILE_NAME}")

    print("\n\n")
    for i in range(5):
        print("ALWAYS ACCEPT THE PAIRING IF YOUR DESKTOP ENVIRONMENT SHOWS IT UP!")
    print("\n\n")

    forget_pump_devices()

    batch_exec(STARTUP_COMMANDS)    # configure the BT adapter

    adapter_addr = list(adapter.Adapter.available())[0].address
    print(f"using adapter: {adapter_addr}")

    BLE = peripheral.Peripheral(
        adapter_address=adapter_addr,
        local_name=MOBILE_NAME
    )

    sake_srv_id, sake_char_id = add_chars_and_services(BLE, write_callback, notify_callback)
    print(f"set up {len(BLE.services)} services and {len(BLE.characteristics)} chars ")

    SAKE_CHAR = None
    for char in BLE.characteristics:
        s, c = parse_id_from_path(char.path)
        if s == sake_srv_id and c == sake_char_id:
            SAKE_CHAR = char
            break
    if SAKE_CHAR == None:
        raise Exception("Could not find SAKE char!")
    print(f"sake char resolved to {SAKE_CHAR.path}")

    BLE.on_connect = on_connect
    BLE.on_disconnect = on_disconnect

    thread = Thread(target = adv_thread)
    thread.start()

    BLE.publish()
    
    return

if __name__ == "__main__":
    main()