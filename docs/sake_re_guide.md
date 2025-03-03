# How to debug sake with ghidra

1. python debug_sake.py
2. open ghidra debugger
3. drop the so file in
5. left side window > delete all targets
6. ribbon > debugger > debug xyz.so > in gdb local vm
7. launch command = /usr/bin/aarch64-linux-gnu-gdb > connect
8. cancel on launch options
9. in the terminal enter: set architecture armv7 and target remote :1337
10. WAIT! for everything to load (it will be like its doing nothing but wait 1-2 minutes)
11. you can go to modules > find sake.so > right click > map to your ghidra file (may be not necessary)
12. clicking on an exported function should take you to its memory contents on the device
13. you should check if the bytes are the same, if yes you are good to go, you can set breakpoints now
14. UPDATE: it fucking crashes every minute, it is almost usable but no: TODO why? maybe some kind of timeout on a different thread kills the sake stuff and re-loads it after throwing and exception internally?
	- try a windows machine with latest ghidra release (maybe its RAM related, im running on 100%)


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
- set auto-solib-add 0
- python exec(open("sigbreak.py").read())
- x/20xbw 0xe7974810
- set scheduler-locking on
- b dlclose
  
# Relocated address shit
- if the app says "pairing timeout reached" it will re-load the library and the addresses will change?
- i cant even calculate the new addresses by hand for some reason, maybe im just dumb but it is always in a diffrent space (ASLR????)
	- manually dumping the code segment and searching for the bytes is the workaround for now
	- maybe some kind of "tracing" would be better then breaking and debugging since the other -> maybe check out frida

# ABI mismatch
- for some reason i thought it would be a cool idea to start reversing the armv7 binary instead of the aarch64
- luckily we can use a hack to force the armv7 to load: just reinstall the apk with adb install --abi armeabi-v7a xyz.apk
echo 0 > /proc/sys/kernel/randomize_va_space