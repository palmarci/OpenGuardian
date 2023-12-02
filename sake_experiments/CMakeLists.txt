cmake_minimum_required(VERSION 3.27)


# Define the target name and sources
set(TARGET_NAME sakewrapper)
set(INSTALL_DIR ${CMAKE_BINARY_DIR}/install)
set(ADDITIONAL_FILE_NAME libandroid-sake-lib.so)
set(DEVICE_INSTALL_PATH /data/local/tmp/${TARGET_NAME})


# Add your source files here
set(SOURCES
	main.cpp
	# Add other source files if needed
)

add_executable(${TARGET_NAME} ${SOURCES})

# Set the NDK path
set(NDK_PATH "/opt/android-ndk")

# Set the C++ compiler
set(CMAKE_CXX_COMPILER ${NDK_PATH}/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++)
set(CMAKE_CXX_FLAGS "-static-libstdc++ --target=armv7-none-linux-androideabi19 --gcc-toolchain=${NDK_PATH}/toolchains/llvm/prebuilt/linux-x86_64 --sysroot=${NDK_PATH}/toolchains/llvm/prebuilt/linux-x86_64/sysroot")

project(${TARGET_NAME} CXX)




# Check if adb shell whoami returns "root"
execute_process(COMMAND adb shell whoami OUTPUT_VARIABLE ANDROID_USER OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT ANDROID_USER STREQUAL "root")
	message(FATAL_ERROR "Android device is not running as root. Please ensure the device is rooted.")
endif()

# Delete existing files on the device
add_custom_target(delete_existing_files
	COMMAND adb shell rm -rf ${DEVICE_INSTALL_PATH}
	COMMENT "Deleting existing files on Android device"
)

# Create the install folder
file(MAKE_DIRECTORY ${INSTALL_DIR})

# Create the install target
install(TARGETS ${TARGET_NAME} DESTINATION ${INSTALL_DIR})

# Copy the additional file to the install folder
set(ADDITIONAL_FILE ${CMAKE_SOURCE_DIR}/${ADDITIONAL_FILE_NAME})
configure_file(${ADDITIONAL_FILE} ${INSTALL_DIR}/ COPYONLY)

# Add custom target to execute adb push
add_custom_target(install_adb
	DEPENDS delete_existing_files
	COMMAND cp ${TARGET_NAME} ${INSTALL_DIR}
	COMMAND adb shell mkdir ${DEVICE_INSTALL_PATH}
	COMMAND adb push ${INSTALL_DIR}/${TARGET_NAME} ${DEVICE_INSTALL_PATH}/${TARGET_NAME}
	COMMAND adb push ${INSTALL_DIR}/${ADDITIONAL_FILE_NAME} ${DEVICE_INSTALL_PATH}/${ADDITIONAL_FILE_NAME}
	COMMENT "Installing ${TARGET_NAME} and ${ADDITIONAL_FILE_NAME} on Android device"
)

# Add install_android target to the default make target
#add_dependencies(install_android ${TARGET_NAME})