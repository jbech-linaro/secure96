#ifndef __IO_H
#define __IO_H
#include <stddef.h>
#include <stdint.h>

#define IO_I2C_LINUX 0

struct cmd_packet;

/*
 * IO block, section 8.1
 */
struct io_block {
	uint8_t count;
	void *data;
	uint16_t checksum;
};


struct io_interface {
	void *ctx;
	uint32_t (*open)(void *ctx);
	size_t (*write)(void *ctx, const void *buf, size_t size);
	size_t (*read)(void *ctx, void *buf, size_t size);
	uint32_t (*close)(void *ctx);
};

uint32_t register_io_interface(uint8_t io_interface_type,
			       struct io_interface **ioif);

int at204_open(struct io_interface *ioif);
int at204_write(struct io_interface *ioif, void *buf, size_t size);
int at204_write2(struct io_interface *ioif, struct cmd_packet *p);
int at204_read(struct io_interface *ioif, void *buf, size_t size);
int at204_close(struct io_interface *ioif);
int at204_msg(struct io_interface *ioif, struct cmd_packet *p, void *resp_buf,
	      size_t size);
#endif
