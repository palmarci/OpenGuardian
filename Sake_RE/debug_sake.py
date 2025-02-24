#!/usr/bin/env python3
import subprocess
import time
import tempfile
import argparse
import os
import sys

FRIDA_SCRIPTS = [
	"fridantiroot.js",
	"bypass_developer.js",
	"minimed_keepalive.js"
]

INTERESTING_FUNCTIONS = {
	"Server_1Handshake_inner": 0x00107dc0
}

def run_cmd(cmd_str, background=False):
	print(f"running: {cmd_str}")
	if background:
		subprocess.Popen(f"nohup {cmd_str} > /dev/null 2>&1 &", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		return None
	else:
		result = subprocess.run(cmd_str, shell=True, capture_output=True, text=True)
		return result.stdout.strip("\n") #+ result.stderr

def calculate_breakpoints(map_start_addr:int) -> list[int]:
	base_addr = 0x00100000
	for name, addr in INTERESTING_FUNCTIONS.items():
		real_addr = addr + base_addr + map_start_addr 
		print(f"{name}= {hex(real_addr)}")

def resolve_map(pid):
	#path = run_cmd('adb shell su -c "find /data/app/ -type f -name libandroid-sake-lib.so"')
	maps_result = run_cmd(f"adb shell su -c \"cat /proc/{pid}/maps | grep libandroid-sake-lib.so\"")
	maps_result = maps_result.split("\n")
	maps_result.reverse() # hack to print all of them
	for res in maps_result:
		if len(res) > 3:
			res = res.split(" ")[0]
			start, end = res.split("-")
			start = int(start, 16)
			end = int(end, 16)
			size = end - start
			print(f"mapped address: {hex(start)}--{hex(end)}, size {hex(size)}")
			if size > 0x10000:
				return start, end

	raise Exception("Could not find mapped address of sake lib!")
		#print(res)
	#print(f"res = {maps_result}")

def main(pkg, script_dir, gdbserver_path, frida_server_path, port, gdb_exe):

	# try to close the app so that it may save the authentication data (to skip login at startup)
	run_cmd("adb shell input keyevent KEYCODE_HOME")
	run_cmd(f"adb shell am kill {pkg}")
	sleep(1)

	# cleanup gadgets
	run_cmd('adb shell su -c \'pkill -f "gdb*"\'')
	run_cmd('adb shell su -c \'pkill -f "frida*"\'')
	
	# start frida server
	run_cmd(f'adb shell su -c "{frida_server_path}"', background=True)

	# create frida client command
	os.chdir(script_dir)
	frida_cmd = f'frida -U -f {pkg}'
	for script in FRIDA_SCRIPTS:
		frida_cmd += f' -l {script}'
	log_location = "log.txt"
	frida_cmd += f' -o {log_location}'
	
	# wait for frida server to start then start the client
	time.sleep(1)
	run_cmd(frida_cmd, background=True)
	
	input("\nPRESS ENTER TO ATTACH GDB WHEN ON PAIRING SCREEN!")

	# get the pid
	pid = int(run_cmd(f'adb shell su -c "pidof {pkg}"'))
	print(f"pid = {pid}")

	start, end = resolve_map(pid)

	# attach and forward the gdb port
	gdbserver_cmd = f'{gdbserver_path} :{port} --attach {pid}'
	run_cmd(f'adb shell su -c "{gdbserver_cmd}"', background=True)
	run_cmd(f'adb forward tcp:{port} tcp:{port}')

	print("gdb server started!")

#	os.system(f'{gdb_exe} -q -ex "target remote :{port}"')


if __name__ == "__main__":
	#calculate_breakpoints(0x0000006d54d45510)
	#sys.exit(1)

	parser = argparse.ArgumentParser(description="Launch Frida and GDB for an Android app.")
	parser.add_argument("--pkg", default="com.medtronic.diabetes.minimedmobile.eu", help="Package name")
	parser.add_argument("--script-dir", default="/home/marci/src/Diab/OpenGuardian/scripts", help="Directory containing frida scripts")
	parser.add_argument("--gdbserver-path", default="/data/local/tmp/gdbserver-8.3.1-aarch64-le", help="Path to gdbserver on the device")
	parser.add_argument("--frida-server-path", default="/data/local/tmp/frida-server-16.5.6-android-arm64", help="Path to frida-server on the device")
	parser.add_argument("--port", default="1337", help="Port to use for gdbserver")
	parser.add_argument("--gdb-exe", default="aarch64-linux-gnu-gdb", help="Local GDB executable")
	args = parser.parse_args()

	main(args.pkg, args.script_dir, args.gdbserver_path, args.frida_server_path, args.port, args.gdb_exe)