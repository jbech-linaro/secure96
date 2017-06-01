#set(CMAKE_TOOLCHAIN_FILE CMakeToolchain.txt)
project(secmezz C)

# Required cmake version
cmake_minimum_required(VERSION 3.0.2)

# global needed variables
set(APPLICATION_NAME ${PROJECT_NAME})

set(APPLICATION_VERSION_MAJOR "0")
set(APPLICATION_VERSION_MINOR "1")
set(APPLICATION_VERSION_PATCH "0")

set(APPLICATION_VERSION
	"${APPLICATION_VERSION_MAJOR}.${APPLICATION_VERSION_MINOR}.${APPLICATION_VERSION_PATCH}")

include_directories(include)

set(SECMEZZ-SRC src/cmd.c
		src/crc_local.c
		src/debug.c
		src/io.c
		src/main.c
		src/gpl/crc.c
		src/i2c_linux.c
		src/packet.c)

add_definitions(-DI2C_DEVICE="/dev/i2c-0")
add_definitions(-DDEBUG)
#add_definitions(-DEXT_DEBUG_INFO)
add_definitions(-DCMAKE_BUILD_TYPE=Debug)

add_executable(cshield ${SECMEZZ-SRC})
target_link_libraries(cshield)


