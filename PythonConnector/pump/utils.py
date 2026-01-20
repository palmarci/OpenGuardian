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

def add_chars_and_services(ble, read_callback, notify_callback):

    # DEVICE INFO
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

    # SAKE
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

    return

def batch_exec(cmd_list:list[str]) -> None:
    for c in cmd_list:
        print(f"executing {c}")
        subprocess.run(c, shell=True)
        sleep(0.1)
    return

if __name__ == "__main__":
    advertise("Mobile 000001")