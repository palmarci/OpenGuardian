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

# Paths for additional archives and includes
HOOKER_ARCHIVE = /home/marci/src/Diab/OpenGuardian/NativeSakeRE/InlineHook/jni/hook/libhooker.a
INCLUDE_DIR = /home/marci/src/Diab/OpenGuardian/NativeSakeRE/InlineHook/jni/hook/

# Compiler and linker flags for JNI and JVM
CFLAGS = -g -Wall -O2 -fPIC -I$(SYSROOT)/usr/include -I$(NDK_PATH)/sysroot/usr/include/jni -I$(NDK_PATH)/sysroot/usr/include/jni.h -I$(INCLUDE_DIR)
LDFLAGS = -L$(SYSROOT)/usr/lib -L$(NDK_PATH)/platforms/android-21/arch-arm64/usr/lib -L$(INCLUDE_DIR) -ldl

LIBS = -ldl -L$(INCLUDE_DIR) -lhooker # Link with libhooker.a and libTKHooklib

TARGET = sakeloader
SRC = *.c

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
