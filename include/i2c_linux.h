#ifndef __I2C_LINUX_H
#define __I2C_LINUX_H

#include <status.h>
#include <stdint.h>
#include <linux/i2c-dev.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


struct i2c_linux_ctx {
	int fd;
};

/* Just of testing/development purpose, should be removed later on */
#include <io.h>
int get_fd(struct io_interface *ioif);
#endif
