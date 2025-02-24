# How to debug sake with ghidra

1. python debug_sake.py
2. openg ghidra debugger
3. drop the so file in
5. left side window > delete all targets
6. ribbon > debugger > debug xyz.so > in gdb local vm
7. launch command = /usr/bin/aarch64-linux-gnu-gdb > connect
8. cancel on launch options
9. in the terminal enter: target remote :1337
10. WAIT! for everything to load (it will like its doing nothing but wait like 1-2 minutes)
11. you can go to modules > find sake.so > right click > map to your ghidra file (may be not necessary)
12. clicking on an exported function should take you to its memory contents on the device
13. you should check if the bytes are the same, if yes you are good to go, you can set breakpoints


# Hooking with frida
- may be a good idea but i wanted to check out ghidra: https://stackoverflow.com/a/68335254

# GDB cheatsheet
- info sharedlibrary sake*
- info functions sake*
- info reg
- info b(reakpoints)
- continue
- disassemble funcname
- dump binary memory /temp/dump.bin 0x200000000 0x20000c350