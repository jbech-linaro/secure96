#ifndef __IO_H
#define __IO_H
#include <stdint.h>

#define IO_I2C_LINUX 0

struct io_interface {
	void *ctx;
	uint32_t (*open)(void *ctx);
};

uint32_t register_io_interface(uint8_t io_interface_type,
			       struct io_interface **ioif);
#endif
