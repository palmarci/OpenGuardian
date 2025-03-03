import os
import sys
sys.path.append(os.path.abspath(os.getcwd())) # hack for gdb
from common import resolve_map
from sigsearch import find_signature

start, end = resolve_map()
gdb.execute(f"dump binary memory /tmp/dump.bin {hex(start)} {hex(end)}")
print("dumped!")
sig = start + find_signature("F0 B5 03 AF 2D E9 00 0F 8C B0 00 92 D0 E9 00 A0")
gdb.execute(f"break *{hex(sig)}")