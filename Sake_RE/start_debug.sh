#!/bin/bash

PKG="com.medtronic.diabetes.minimedmobile.eu"
SCRIPTDIR="/home/marci/src/Diab/OpenGuardian/scripts"
GDBSERVER_PATH="/data/local/tmp/gdbserver-8.3.1-aarch64-le"
FRIDASERVER_PATH="/data/local/tmp/frida-server-16.5.6-android-arm64"
PORT="1337"

# cleanup
adb shell su -c pkill -f "gdb*"
adb shell su -c pkill -f "frida*"
pkill -f "aarch64-linux-gnu-gdb*"
pkill -f "frida*"

# start frida on phone
adb shell su -c "$FRIDASERVER_PATH & " &
sleep 3

# start pkg with keep alive scripts
cd "$SCRIPTDIR"
frida -U -f "$PKG" -l fridantiroot.js -l bypass_developer.js -l minimed_keepalive.js -l hook_teneoapi.js &
sleep 3

# wait for user
read -p 'PRESS ENTER TO ATTACH GDB!' none

# start gdb server on port 1337
PID=$(adb shell su -c pidof "$PKG")
echo "pid = $PID"
adb shell su -c "$GDBSERVER_PATH :$PORT --attach $PID" &
adb forward tcp:1337 tcp:1337

# enter debugger
gdb_script=$(mktemp)
echo "target remote :$PORT" > "$gdb_script"
# echo "set pagination off" >> "$gdb_script"
echo "$gdb_script"
aarch64-linux-gnu-gdb -q -x "$gdb_script"
rm "$gdb_script"