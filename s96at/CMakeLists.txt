#set(CMAKE_TOOLCHAIN_FILE CMakeToolchain.txt)
project(s96at C)

include(GNUInstallDirs)

# Required cmake version
cmake_minimum_required(VERSION 3.0.2)

set(PROJECT_VERSION "0.1.0")

MESSAGE(STATUS "CMAKE_C_COMPILER: " ${CMAKE_C_COMPILER})

add_compile_options(-Wall -Werror -std=gnu99)
include_directories(include)

set(SRC ${CMAKE_SOURCE_DIR}/src/s96at.c
	${CMAKE_SOURCE_DIR}/src/cmd.c
	${CMAKE_SOURCE_DIR}/src/crc.c
	${CMAKE_SOURCE_DIR}/src/debug.c
	${CMAKE_SOURCE_DIR}/src/device.c
	${CMAKE_SOURCE_DIR}/src/io.c
	${CMAKE_SOURCE_DIR}/src/i2c_linux.c
	${CMAKE_SOURCE_DIR}/src/packet.c
	${CMAKE_SOURCE_DIR}/src/sha.c)

set(I2C_DEVICE "/dev/i2c-0")

#add_definitions(-DEXT_DEBUG_INFO)
add_definitions(-DCMAKE_BUILD_TYPE=Debug)

add_library(${PROJECT_NAME} SHARED ${SRC})

set(PUBLIC_HEADERS ${CMAKE_SOURCE_DIR}/include/s96at.h
		   ${CMAKE_SOURCE_DIR}/include/s96at_private.h)
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${PUBLIC_HEADERS}")

target_compile_definitions(${PROJECT_NAME}
	PRIVATE -DI2C_DEVICE="${I2C_DEVICE}"
	PRIVATE -DDEBUG
)
install(TARGETS ${PROJECT_NAME} LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/secure96)

add_subdirectory(tests)
add_custom_target(tests)
add_dependencies(tests s96-204_tests)
