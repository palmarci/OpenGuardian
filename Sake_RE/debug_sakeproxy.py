#!/usr/bin/env python3
import subprocess
import time
import tempfile
import argparse
import os
import sys
import socket
from common import *

GDBSERVER = "/data/local/tmp/gdbserver_arm-eabi-linux_7.11" # on the device
FRIDASERVER = "/data/local/tmp/frida-server-16.5.6-android-arm64" # on the device
GDBCLIENT = "aarch64-linux-gnu-gdb"
PORT = 6666
PKG = "com.openguardian4.sakeproxy" 

def main():
	# try to soft close the app so that it may save the authentication data (to skip login at startup)
	run_cmd("adb shell input keyevent KEYCODE_HOME")
	run_cmd(f"adb shell am kill {PKG}")
	#run_cmd(f"adb uninstall {PKG}")
	#run_cmd(f"adb install '/home/marci/src/Diab/OpenGuardian/Sakeproxy/app/build/outputs/apk/release/app-armeabi-v7a-release-aligned-debugSigned.apk'")


	# cleanup gadgets
	run_cmd('adb shell su -c \'pkill -f "gdb*"\'')
	run_cmd('adb shell su -c \'pkill -f "frida*"\'')

	# try to disable ASLR - does not work
	#run_cmd('adb shell su -c \'echo 0 > /proc/sys/kernel/randomize_va_space\'')
	
	# start frida server
#	run_cmd(f'adb shell su -c "{FRIDASERVER}"', background=True)

	# create frida client command
	start_cmd = f'adb shell monkey -p {PKG} 1' 
	run_cmd(start_cmd, background=True)
	
	input("\nPRESS ENTER TO CONNECT WITH GDB!")

	pid = get_pid(PKG)

	# attach and forward the gdb port
	gdbserver_cmd = f'{GDBSERVER} localhost:{PORT} --attach {pid}'
	run_cmd(f'adb shell su -c "{gdbserver_cmd}"', background=True)
	run_cmd(f'adb forward tcp:{PORT} tcp:{PORT}')

	print("gdb server started!")

	gdb_start_cmd = f'{GDBCLIENT} -q -ex "set architecture armv7" -ex "set debuginfod enabled off" -ex "target remote localhost:{PORT}"'
	#gdb_start_cmd += f' -ex "set auto-solib-add 0" -ex "sharedlibrary {get_elf_location()}"'
	
	print(f"\nyou can attach using:\n{gdb_start_cmd}\n")

	input("\nPRESS ENTER TO CONNECT WITH GDB!")

	os.system(gdb_start_cmd)

if __name__ == "__main__":
	main()