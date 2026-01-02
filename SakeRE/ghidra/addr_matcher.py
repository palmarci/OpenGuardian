from binascii import hexlify
from ghidra.program.model.listing import FunctionManager
from ghidra.program.model.listing import CodeUnit
from ghidra.util.task import TaskMonitor
from ghidra.app.services import ProgramManager

import os
import sys
import subprocess

parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(parent_dir)

from common import TARGET_DUMP_FILE, resolve_map, dump_memory

def copy_to_clipboard(text):
	os.system('echo -n "' + text + '" | xclip -selection clipboard')

def get_function_code_bytes(function):
	body = function.getBody()
	code_bytes = bytearray()
	current_addr = body.getMinAddress()
	end_addr = body.getMaxAddress()

	while current_addr <= end_addr:
		instruction = getInstructionAt(current_addr)

		if instruction:
			code_bytes.extend(instruction.getBytes())
			current_addr = instruction.getMaxAddress().add(1)
		else:
			print("Hole detected at address: " + str(current_addr))
			return None
	#print(hexlify(code_bytes))
	return code_bytes

def main():
	current_function = getFunctionContaining(currentAddress)

	if current_function is None:
		print("No function found at the current address.")
		return

	code_bytes = get_function_code_bytes(current_function)

	if code_bytes is None:
		print("Function contains holes in its code.")
		return

	print("Function code bytes length = " + str(len(code_bytes)))

	if not os.path.isfile(TARGET_DUMP_FILE):
		print("sake dump does not exist, dumping...")
		dump_memory()

	with open(TARGET_DUMP_FILE, "rb") as target_file:
		file_content = target_file.read()

		matches = []
		match_offset = 0

		while True:
			match_offset = file_content.find(code_bytes, match_offset)
			if match_offset == -1:
				break
			matches.append(match_offset)
			match_offset += 1

		if len(matches) == 1:
			print("Function code bytes match found at offset: " + hex(matches[0]))
		elif len(matches) > 1:
			print("Multiple matches found: " + str(matches))
			return
		else:
			print("Function code bytes not found in the target dump file.")
			return

	current_cursor_address = currentAddress

	#print("Current cursor address: " + str(current_cursor_address))

	function_entry_point = current_function.getEntryPoint()

	#print("Function entry point address: " + str(function_entry_point))

	offset_from_entry = int(current_cursor_address.subtract(function_entry_point))

	print("Offset from function entry point: " + hex(offset_from_entry))

	i, start, end = resolve_map()

	break_point_address = matches[0] + start + offset_from_entry
	break_point_address = hex(break_point_address)[:-1]
	print("Break should be set at: " + break_point_address)
	copy_to_clipboard(break_point_address)

	if int(str(current_cursor_address),16) & 0xFF != int(break_point_address,16) & 0xFF:
		print("WARNING: ADDRESS LOOKS SUS!")

main()