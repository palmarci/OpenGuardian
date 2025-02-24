## Monitor script

Usage: 

0. get a rooted android phone
1. download frida server (https://frida.re/docs/android)
3. connect to adb via usb & install frida on your phone
4. start your frida server as root on the device
5. edit the beginning of the monitor.js script to select your app version  
6. `frida -U -f com.medtronic.diabetes.guardian -l guardianmon.js` (you can stack additional scripts to bypass the security checks like: `-l bypass_developer.js`)
7. save the output to a txt file and use OpenGuardian to parse them