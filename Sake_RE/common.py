import subprocess
import re
import os
import shlex

TMP_FOLDER_PC = "/tmp"
TEMP_FOLDER_PHONE = "/data/local/tmp"
TEMP_DUMP_FILE_NAME = "output.bin"
TARGET_DUMP_FILE = "/tmp/sake.dump"
PKG = "com.openguardian4.sakeproxy" 
GDBSERVER = TEMP_FOLDER_PHONE + "/gdbserver_arm-eabi-linux_7.11" # on the device
FRIDASERVER = TEMP_FOLDER_PHONE + "/frida-server-16.5.6-android-arm64" # on the device
GDBCLIENT = "aarch64-linux-gnu-gdb"
PORT = 6666

def run_cmd(cmd_str, background=False):
	"""Run a shell command, optionally in the background using subprocess."""
	try:
		# Ensure the command is properly escaped and split into a list of arguments
		cmd_list = shlex.split(cmd_str)  # This automatically handles spaces and special characters

		if background:
			# Run the command in the background, suppressing output
			cmd_list.insert(0, "nohup")
			cmd_list.append(">/dev/null 2>&1 &")
			print(f" > {' '.join(cmd_list)}")
			subprocess.Popen(' '.join(cmd_list), shell=True)
			return None
		else:
			# Run the command and capture the output
			print(f" > {' '.join(cmd_list)}")
			result = subprocess.check_output(cmd_list, stderr=subprocess.STDOUT, text=True)
			return result.strip()  # Capture and strip leading/trailing spaces from the result
	
	except subprocess.CalledProcessError as e:
		print(f"{e}")
		return None

def get_pid():
	pid = run_cmd('adb shell su -c "pidof ' + PKG + '"')
	pid = int(pid)
	print("pid = " + str(pid))
	return pid

def resolve_map():
	pid = get_pid()
	lines = run_cmd('adb shell su -c "cat /proc/' + str(pid) + '/maps"')
	lines = lines.split("\n")

	for i, l in enumerate(lines):
		if l is not None and len(l) > 3 and "r-xp" in l and "libandroid-sake-lib.so" in l:
			l = l.split(" ")[0]
			start, end = l.split("-")
			start = int(start, 16)
			end = int(end, 16)
			size = end - start
			print("sake .text is mapped at @" + str(i) + ": " + hex(start) + "--" + hex(end) + ", size " + hex(size))
			return i, start, end

	raise Exception("Can not find mapped .text")

def get_elf_location():
	path = run_cmd('adb shell su -c "find /data/app/ -type f -name libandroid-sake-lib.so"')
	print("elf is at " + path)
	return path

def dump_memory():
	pid = get_pid()
	i, start, end = resolve_map()
	# del original file
	run_cmd('adb shell su -c "rm -rf ' + TEMP_FOLDER_PHONE + '/' + TEMP_DUMP_FILE_NAME + '"')
	# call dumper
	cmd_inner = TEMP_FOLDER_PHONE + "/dumper " + str(pid) + " " + str(i)
	cmd_root = "adb shell su -c '" + cmd_inner + "'"
	run_cmd(cmd_root)
	# get the output file
	run_cmd("adb pull '" + TEMP_FOLDER_PHONE + "/" + TEMP_DUMP_FILE_NAME + "' '" + TMP_FOLDER_PC + "'")
	# move and check it
	os.rename(TMP_FOLDER_PC + "/" + TEMP_DUMP_FILE_NAME, TARGET_DUMP_FILE)
	if not os.path.isfile(TARGET_DUMP_FILE):
		raise Exception("dumping failed")
	else:
		print("dump OK!")
	return

if __name__ == "__main__":
	dump_memory()