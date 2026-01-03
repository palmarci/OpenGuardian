import re
import os
import argparse

# manual search: grep -R -P 'byte\s*\[\s*]\s*\w+\s*=\s*\{\s*-?\d+(?:\s*,\s*-?\d+)*\s*,?\s*}' .

PATT = r'byte\[\]\s+.*?\s*=\s*\{(.*?)\}'

def check_size(len) -> bool:
	len += 1 # + 1 extra if there is x number of delimiters
	for n in range(1, 20): # max 8 but whatever
		return (6 +  n * 81) == len

def java_bytes(int_list):
    return bytes([int(i) & 0xFF for i in int_list])

def scan_folder(folder):
	pattern = re.compile(PATT, re.DOTALL)

	toret = []

	for root, dirs, files in os.walk(folder):
		for file in files:

			filepath = os.path.join(root, file)
			# if "medtronic" in filepath.lower():
	
			with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
				content = f.read()
				matches = pattern.findall(content)
				for match in matches:
					array_len = match.count(',')
					#print(match)
					if check_size(array_len):
					#if SEARCH_LEN == array_len:
						spl = match.split(",")
						try:
							crc_data = java_bytes(spl[0:4]).hex()
						except:
							crc_data = None
						print(f"possible SAKE key found at {filepath}, len={array_len + 1} crc = {crc_data}")
						toret.append(filepath)
	return toret


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Scan for hardcoded byte arrays in Java files")
	parser.add_argument("folder", help="Folder to recursively scan")
	args = parser.parse_args()

	scan_folder(args.folder)
