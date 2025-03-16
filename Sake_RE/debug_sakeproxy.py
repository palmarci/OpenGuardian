#!/usr/bin/env python3
import subprocess
import time
import tempfile
import argparse
import os
import sys
import socket

from common import *

def main():
	run_cmd(f"adb shell am kill {PKG}")
	run_cmd('adb shell su -c \'pkill -f "gdb*"\'')
	time.sleep(1)

	start_cmd = f'adb shell monkey -p {PKG} 1' 
	run_cmd(start_cmd, background=True)
	
	time.sleep(3)
	
	pid = get_pid()

	gdbserver_cmd = f'{GDBSERVER} localhost:{PORT} --attach {pid}'
	run_cmd(f'adb shell su -c "{gdbserver_cmd}"', background=True)
	run_cmd(f'adb forward tcp:{PORT} tcp:{PORT}')

	print("gdb server started!")

	gdb_start_cmd = f'{GDBCLIENT} -q -ex "set architecture armv7" -ex "set debuginfod enabled off"'
#	gdb_start_cmd += f' -ex "set auto-solib-add 0" -ex "sharedlibrary {get_elf_location()}"'
	gdb_start_cmd += f' -ex "handle SIGSTOP nostop noprint"'
	gdb_start_cmd += f' -ex "set pagination off"'
	#gdb_start_cmd += f' -ex "layout split"'

	for i in range(33, 36):
			gdb_start_cmd += f' -ex "handle SIG{i} nostop"'

	gdb_start_cmd += f' -ex "target remote localhost:{PORT}"'
	#gdb_start_cmd += f' -ex "layout split"'

	
	print(f"\nyou can attach using:\n{gdb_start_cmd}\n")

	#input("\nPRESS ENTER TO ATTACH WITH GDB!")

	os.system(gdb_start_cmd)


if __name__ == "__main__":
	main()