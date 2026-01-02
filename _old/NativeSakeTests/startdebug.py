import os
import sys
from time import sleep

sys.path.append("/home/marci/src/Diab/OpenGuardian/Sake_RE/")

from common import run_cmd

GDBSERVER_PATH = "/data/local/tmp/gdbserver-7.7.1-armhf-eabi5-v1-sysv"
PORT = 5555

run_cmd('adb shell su -c "pkill -f gdb*"')
#sleep(0.5)
run_cmd('adb shell su -c "pkill -f sakeloader*"')
#sleep(0.5)

gdbserver_starter = f'{GDBSERVER_PATH} 127.0.0.1:{PORT} /data/local/tmp/sakeloader/sakeloader debug' # --break main
run_cmd(f'adb shell su -c "{gdbserver_starter}"', background=True)
#sleep(0.5)
run_cmd(f'adb forward tcp:{PORT} tcp:{PORT}')
#sleep(0.5)


gdb_com = f'aarch64-linux-gnu-gdb -q -ex "set architecture armv7" -ex "set debuginfod enable off" -ex "set pagination off" -ex "target remote localhost:{PORT}" -ex "continue" -ex "sharedlibrary" -ex "info sharedlibrary"'
print(gdb_com)

input("\n\n***PRESS ENTER TO ATTACH MANUALLY!*** \n\n")
os.system(gdb_com)