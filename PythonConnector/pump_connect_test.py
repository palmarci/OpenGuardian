#!/usr/bin/env python3
from bluezero import peripheral, adapter, advertisement
from gi.repository import GLib
import json
import random
import time

# sudo btmgmt io-cap 4

# ---------------- BLE Peripheral Settings ----------------
SERVICE_UUID = "980c2f36-bde3-11e4-8dfc-aa07a5b093db" # extracted from SSO config (see carelink api repo)
CHAR_UUID    = "980c34cc-bde3-11e4-8dfc-aa07a5b093db"
EOM = b"EOM" # hardcoded in minimedmobile apk
buffer = bytearray()
characteristic = None
loop = GLib.MainLoop()

# ---------------- Utility Functions ----------------
def gen_mobile_name():
    # stolen from minimed mobile apk too
    while True:
        num = random.randint(100000, 999999)
        if num % 2 == 1:
            return f"Mobile {num}"

mobile_name = "Mobile 042069" # gen_mobile_name()
print(f"using mobile name {mobile_name}")

# ---------------- BLE Callbacks ----------------
def on_connect(dev):
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
adv_id = random.randint(1000, 9999)
beacon = advertisement.Advertisement(adv_id, "peripheral")
beacon.service_UUIDs = ['0000fe82-0000-1000-8000-00805f9b34fb']  # Medtronic SAKE service
beacon.manufacturer_data = {0x01F9: b'\x00' + mobile_name.encode() + b'\x00'}
beacon.include_tx_power = True
beacon.local_name = mobile_name

ad_manager = advertisement.AdvertisingManager()
ad_manager.register_advertisement(beacon, {})
beacon.start()
print(f"Advertising as {mobile_name}")

# ---------------- BLE Peripheral ----------------
ble = peripheral.Peripheral(
    adapter_address=adapter_addr,
    local_name=mobile_name,
    #io_capabilities='KeyboardDisplay', # MITM protection, device asks for it
    pairable=True,
    bondable=True,
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
characteristic = ble.services[0].characteristics[0]

ble.on_connect = on_connect
ble.on_disconnect = on_disconnect

ble.publish()
print("Peripheral running. Waiting for connections...")

# ---------------- Main Loop ----------------
try:
    loop.run()
except KeyboardInterrupt:
    print("Shutting down...")
    beacon.stop()
