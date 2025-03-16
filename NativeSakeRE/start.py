import os
import sys
from time import sleep

sys.path.append("/home/marci/src/Diab/OpenGuardian/Sake_RE/")

from common import run_cmd

GDBSERVER_PATH = "/data/local/tmp/gdbserver-7.7.1-armhf-eabi5-v1-sysv"
PORT = 5555


run_cmd('adb shell su -c "pkill -f "gdb*"')
run_cmd('adb shell su -c "pkill -f "sakeloader*"')

gdbserver_starter = f'{GDBSERVER_PATH} 0.0.0.0:{PORT} /data/local/tmp/sakeloader/sakeloader' # --break main
run_cmd(f'adb shell su -c "{gdbserver_starter}"', background=True)
#sleep(0.5)
run_cmd(f'adb forward tcp:{PORT} tcp:{PORT}')
#sleep(0.5)

gdb_com = f'aarch64-linux-gnu-gdb -q -ex "set architecture armv7" -ex "target remote localhost:{PORT}" -ex "continue" -ex "info sharedlibrary"'
print(gdb_com)

input("PRESS ENTER TO ATTACH MANUALLY!")
os.system(gdb_com)