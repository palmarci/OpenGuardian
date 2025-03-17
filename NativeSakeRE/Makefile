# Set the Android NDK path
NDK_PATH = /home/marci/Desktop/android-ndk-r21e

# COMPILER = aarch64-linux-android21-clang
COMPILER = armv7a-linux-androideabi21-clang

# Set the Android NDK toolchain for ARM64
CC = $(NDK_PATH)/toolchains/llvm/prebuilt/linux-x86_64/bin/$(COMPILER)
CXX = $(NDK_PATH)/toolchains/llvm/prebuilt/linux-x86_64/bin/$(COMPILER)++
LD = $(NDK_PATH)/toolchains/llvm/prebuilt/linux-x86_64/bin/ld
AR = $(NDK_PATH)/toolchains/llvm/prebuilt/linux-x86_64/bin/ar
SYSROOT = $(NDK_PATH)/platforms/android-21/arch-arm64

# Compiler and linker flags for JNI and JVM
CFLAGS = -g -Wall -O2 -fPIC -I$(SYSROOT)/usr/include -I$(NDK_PATH)/sysroot/usr/include/jni -I$(NDK_PATH)/sysroot/usr/include/jni.h
LDFLAGS = -L$(SYSROOT)/usr/lib -L$(NDK_PATH)/platforms/android-21/arch-arm64/usr/lib -ldl -L$(NDK_PATH)/platforms/android-21/arch-arm64/usr/lib

LIBS = -ldl  # Link with libdl for dynamic loading

TARGET = sakeloader
SRC = main.c

# Build rules
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS) $(LIBS)

# Push the binary to the Android device
push: $(TARGET)
	@echo "Pushing $(TARGET) to /data/local/tmp/ on Android device..."
	adb shell "mkdir -p /data/local/tmp/sakeloader"
	adb push $(TARGET) /data/local/tmp/sakeloader/
	@echo "File pushed to /data/local/tmp/sakeloader"

# Clean the build
clean:
	rm -f $(TARGET)