project(s96-204_tests C)

cmake_minimum_required(VERSION 3.0.2)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(${PROJECT_NAME} EXCLUDE_FROM_ALL ${SRC} tests.c)

target_compile_definitions(${PROJECT_NAME}
	PRIVATE -DI2C_DEVICE="${I2C_DEVICE}"
	PRIVATE -DDEBUG
)
target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES})
