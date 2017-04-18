#set(CMAKE_TOOLCHAIN_FILE CMakeToolchain.txt)
project(secmezz C)

# Required cmake version
cmake_minimum_required(VERSION 3.6.2)

# global needed variables
set(APPLICATION_NAME ${PROJECT_NAME})

set(APPLICATION_VERSION_MAJOR "0")
set(APPLICATION_VERSION_MINOR "1")
set(APPLICATION_VERSION_PATCH "0")

set(APPLICATION_VERSION
	"${APPLICATION_VERSION_MAJOR}.${APPLICATION_VERSION_MINOR}.${APPLICATION_VERSION_PATCH}")

include_directories(include)

set(SECMEZZ-SRC src/main.c src/gpl/crc.c)

#add_library(tee SHARED ${LIBTEE-SRC})

#set(TS-SRC tee-supplicant/src/handle.c)

add_definitions(-DI2C_DEVICE="/dev/i2c-1")

add_executable(cshield ${SECMEZZ-SRC})
target_link_libraries(cshield)


