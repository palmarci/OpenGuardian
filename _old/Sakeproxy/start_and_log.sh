adb shell am kill com.openguardian4.sakeproxy && sleep 1 && adb shell monkey -p com.openguardian4.sakeproxy 1 && sleep 2 && python /home/marci/src/aklog/aklog.py -p "com.openguardian4.sakeproxy"
