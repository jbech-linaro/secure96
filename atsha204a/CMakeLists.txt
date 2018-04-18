#set(CMAKE_TOOLCHAIN_FILE CMakeToolchain.txt)
project(s96-204 C)

# Required cmake version
cmake_minimum_required(VERSION 3.0.2)

set(PROJECT_VERSION "0.1.0")

add_compile_options(-Wall -Werror)
include_directories(include)

set(SRC src/cmd.c
	src/crc.c
	src/debug.c
	src/io.c
	src/main.c
	src/i2c_linux.c
	src/packet.c
	src/personalize.c)

#add_definitions(-DPERSONALIZE)
#add_definitions(-DEXT_DEBUG_INFO)
add_definitions(-DCMAKE_BUILD_TYPE=Debug)

add_executable(${PROJECT_NAME} ${SRC})

target_compile_definitions(${PROJECT_NAME}
	PRIVATE -DI2C_DEVICE="/dev/i2c-0"
	PRIVATE -DDEBUG
)
