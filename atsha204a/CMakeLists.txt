#set(CMAKE_TOOLCHAIN_FILE CMakeToolchain.txt)
project(s96-204 C)

# Required cmake version
cmake_minimum_required(VERSION 3.0.2)

set(PROJECT_VERSION "0.1.0")

MESSAGE(STATUS "CMAKE_C_COMPILER: " ${CMAKE_C_COMPILER})

add_compile_options(-Wall -Werror)
include_directories(include)

set(SRC src/cmd.c
	src/config.c
	src/crc.c
	src/debug.c
	src/io.c
	src/main.c
	src/i2c_linux.c
	src/packet.c)

#add_definitions(-DPERSONALIZE)
set(I2C_DEVICE "/dev/i2c-0")

#add_definitions(-DEXT_DEBUG_INFO)
add_definitions(-DCMAKE_BUILD_TYPE=Debug)

add_executable(${PROJECT_NAME} ${SRC})

target_compile_definitions(${PROJECT_NAME}
	PRIVATE -DI2C_DEVICE="${I2C_DEVICE}"
	#PRIVATE -DDEBUG
	PRIVATE -DPROJECT_VERSION="${PROJECT_VERSION}"
)

add_subdirectory(tests)
add_custom_target(tests)
add_dependencies(tests s96-204_tests)
