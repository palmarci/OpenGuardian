import os
from time import sleep

def advertise(mobile_name: str, instance_id:int=1) -> str:

    # sends 4 over 1.2 delay each
    # check nrf connect app to see adv latency

    os.system("sudo btmgmt clr-adv")

    base = "sudo btmgmt add-adv -d"
    cmd = ""

    cmd += "02 01 02" # flags = 02. you might need sudo btmgmt bredr on
    cmd += f"12 FF F901 00 {mobile_name.encode().hex()} 00" # manufacturer data (F901 = medtronic)
    cmd += "02 0A 01" # tx power
    cmd += "030382FE" # fe82 service uuid 16 bit

    cmd = cmd.replace(" ", "")

    f = base + " " + cmd + " " + str(instance_id)
    print(f)
    os.system(f)
    sleep(4.8)

    return