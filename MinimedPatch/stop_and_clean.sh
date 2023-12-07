package='com.medtronic.diabetes.minimedmobile.eu'
echo "killing and cleaning $package"
adb shell am kill "$package"
adb shell pm clear "$package"