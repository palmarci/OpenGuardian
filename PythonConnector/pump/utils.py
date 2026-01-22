import random
import subprocess
from time import sleep

def advertise(mobile_name:str, instance_id:int=1) -> None:
    
    subprocess.run("sudo btmgmt clr-adv", shell=True)

    cmd = "02 01 02"  # flags
    cmd += f" 12 FF F901 00 {mobile_name.encode().hex()} 00"  # manufacturer data
    cmd += " 02 0A 01"  # tx power
    cmd += " 03 03 82 FE"  # 16-bit service UUID

    cmd = cmd.replace(" ", "")

    full_cmd = f"sudo btmgmt add-adv -d {cmd} {instance_id}"
    print("Running:", full_cmd)

    try:
        subprocess.run(full_cmd, shell=True, check=True)
        sleep(4.8) # check nRF app to see advertisement delay & latency and tune it if needed
    except KeyboardInterrupt:
        print("Advertisement interrupted by user")
    # except subprocess.CalledProcessError as e:
    #     print(e)

    return

def gen_mobile_name():
    while True:
        num = random.randint(100000, 999999)
        if num % 2 == 1:
            return f"Mobile {num}"

def add_chars_and_services(ble, write_callback, notify_callback):

    # DEVICE INFO
    ble.add_service(
        srv_id=1,
        uuid="00000900-0000-1000-0000-009132591325",
        primary=True
    )

    # handler for read requests to one of the device info characteristics
    def device_info_read_callback(s):
        print("!!! READ: Device Info Service:", s)
        # send s as response to the read operation
        return list(bytes(s, "ascii"))

    # MANUFACTURER_NAME_STRING_CHAR
    ble.add_characteristic(
        srv_id=1,
        chr_id=1,
        uuid="00002A29-0000-1000-0000-00805F9B34FB",
        value=[],
        notifying=False,
        flags=["read"],
        read_callback=lambda: device_info_read_callback("Manufacturer Name String"),
    )
    # MODEL_NUMBER_STRING_CHAR
    ble.add_characteristic(
        srv_id=1,
        chr_id=2,
        uuid="00002A24-0000-1000-0000-00805F9B34FB",
        value=[],
        notifying=False,
        flags=["read"],
        read_callback=lambda: device_info_read_callback("Model Number String"),
    )
    # SERIAL_NUMBER_STRING_CHAR
    ble.add_characteristic(
        srv_id=1,
        chr_id=3,
        uuid="00002A25-0000-1000-0000-00805F9B34FB",
        value=[],
        notifying=False,
        flags=["read"],
        read_callback=lambda: device_info_read_callback("Serial Number String"),
    )
    # HARDWARE_REVISION_STRING_CHAR
    ble.add_characteristic(
        srv_id=1,
        chr_id=4,
        uuid="00002A27-0000-1000-0000-00805F9B34FB",
        value=[],
        notifying=False,
        flags=["read"],
        read_callback=lambda: device_info_read_callback("Hardware Revision String"),
    )
    # FIRMWARE_REVISION_STRING_CHAR
    ble.add_characteristic(
        srv_id=1,
        chr_id=5,
        uuid="00002A26-0000-1000-0000-00805F9B34FB",
        value=[],
        notifying=False,
        flags=["read"],
        read_callback=lambda: device_info_read_callback("Firmware Revision String"),
    )
    # SOFTWARE_REVISION_STRING_CHAR
    ble.add_characteristic(
        srv_id=1,
        chr_id=6,
        uuid="00002A28-0000-1000-0000-00805F9B34FB",
        value=[],
        notifying=False,
        flags=["read"],
        read_callback=lambda: device_info_read_callback("Software Revision String"),
    )
    # SYSTEM_ID_CHAR
    ble.add_characteristic(
        srv_id=1,
        chr_id=7,
        uuid="00002A23-0000-1000-0000-00805F9B34FB",
        value=[],
        notifying=False,
        flags=["read"],
        read_callback=lambda: device_info_read_callback("System ID"),
    )
    # PNP_ID_CHAR
    ble.add_characteristic(
        srv_id=1,
        chr_id=8,
        uuid="00002A50-0000-1000-0000-00805F9B34FB",
        value=[],
        notifying=False,
        flags=["read"],
        read_callback=lambda: device_info_read_callback("PNP ID"),
    )
    # CERTIFICATION_DATA_LIST_CHAR
    ble.add_characteristic(
        srv_id=1,
        chr_id=9,
        uuid="00002A2A-0000-1000-0000-00805F9B34FB",
        value=[],
        notifying=False,
        flags=["read"],
        read_callback=lambda: device_info_read_callback("Certification Data List"),
    )

    # SAKE
    SAKE_SRV_ID = 2
    SAKE_CHR_ID = 10
    ble.add_service(
        srv_id=SAKE_SRV_ID,
        uuid="FE82"
        primary=True,
    )

    ble.add_characteristic(
        srv_id=SAKE_SRV_ID,
        chr_id=SAKE_CHR_ID,
        uuid="0000FE82-0000-1000-0000-009132591325",
        value=[],
        notifying=False,
        flags=["write", "notify"],
        write_callback=write_callback,
        notify_callback=notify_callback,
    )

    return SAKE_SRV_ID, SAKE_CHR_ID # TODO: return the other ones + map them nicely??

def batch_exec(cmd_list:list[str]) -> None:
    for c in cmd_list:
        print(f"executing {c}")
        subprocess.run(c, shell=True)
        sleep(0.1)
    return

def parse_id_from_path(path: str) -> tuple[int, int]:
    """
    Extracts service and characteristic IDs from a Bluezero D-Bus path.

    Example:
        /ukBaz/bluezero/service0001/char0003  -> (1, 3)
    """
    parts = path.split('/')
    service_str = parts[-2]  # e.g., "service0001"
    char_str = parts[-1]     # e.g., "char0003"

    service_id = int(service_str.replace('service', ''))
    char_id = int(char_str.replace('char', ''))

    return (service_id, char_id)

import subprocess

def forget_pump_devices():
    """
    Forget all paired Bluetooth devices whose name starts with "Pump".
    Uses bluetoothctl CLI.
    """
    try:
        # Get list of paired devices
        result = subprocess.run(
            ['bluetoothctl', 'devices', 'Paired'],
            capture_output=True,
            text=True,
            check=True
        )
        lines = result.stdout.splitlines()

        for line in lines:
            # Format: Device XX:XX:XX:XX:XX:XX DeviceName
            parts = line.split(maxsplit=2)
            if len(parts) < 3:
                continue
            mac, name = parts[1], parts[2]
            if name.startswith("Pump"):
                print(f"Removing pairing for {name} ({mac})")
                subprocess.run(['bluetoothctl', 'remove', mac], check=False)

    except subprocess.CalledProcessError as e:
        print(f"Error running bluetoothctl: {e}")


if __name__ == "__main__":
    advertise("Mobile 000001")