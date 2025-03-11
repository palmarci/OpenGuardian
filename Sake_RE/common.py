import subprocess

TMP_ELF = "/tmp/dump.bin"

def run_cmd(cmd_str, background=False):
	print(f" > {cmd_str}")
	if background:
		subprocess.Popen(f"nohup {cmd_str} > /dev/null 2>&1 &", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		return None
	else:
		result = subprocess.run(cmd_str, shell=True, capture_output=True, text=True)
		return result.stdout.strip("\n") #+ result.stderr

def get_pid(pkg):
	pid = run_cmd(f'adb shell su -c "pidof {pkg}"')
	print(f"pid = {pid}")
	return int(pid)

def resolve_map():
	pid = get_pid()
	lines = run_cmd(f"adb shell su -c \"cat /proc/{pid}/maps | grep libandroid-sake-lib.so\"")
	lines = lines.split("\n")

	for l in lines:
		if l is not None and len(l) > 3 and "r-xp" in l:
			l = l.split(" ")[0]
			start, end = l.split("-")
			start = int(start, 16)
			end = int(end, 16)
			size = end - start
			print(f"sake .text is mapped at: {hex(start)}--{hex(end)}, size {hex(size)}")
			return start, end
	raise Exception("Can not find mapped .text")

def get_elf_location():
	path = run_cmd(f'adb shell su -c "find /data/app/ -type f -name libandroid-sake-lib.so"')
	print(f"elf is at {path}")
	return path