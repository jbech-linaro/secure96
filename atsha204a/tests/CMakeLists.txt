project(s96-204_tests C)

cmake_minimum_required(VERSION 3.0.2)

file(GLOB SRC ${CMAKE_SOURCE_DIR}/src/*.c)
list(REMOVE_ITEM SRC ${CMAKE_SOURCE_DIR}/src/main.c)

add_executable(${PROJECT_NAME} EXCLUDE_FROM_ALL ${SRC} tests.c)

target_compile_definitions(${PROJECT_NAME}
	PRIVATE -DI2C_DEVICE="${I2C_DEVICE}"
	PRIVATE -DDEBUG
)
