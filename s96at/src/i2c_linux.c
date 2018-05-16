/*
 * Copyright 2017, Linaro Ltd and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <assert.h>
#include <fcntl.h>
#include <i2c_linux.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <debug.h>
#include <device.h>
#include <io.h>
#include <status.h>

static uint32_t i2c_linux_open(void *ctx)
{
	struct i2c_linux_ctx *ictx = ctx;
	ictx->fd = open(I2C_DEVICE, O_RDWR);
	if (ictx->fd < 0) {
		logd("Couldn't open the device\n");
		return STATUS_EXEC_ERROR;
	}

	if (ioctl(ictx->fd, I2C_SLAVE, ATSHA204A_ADDR) < 0) {
		logd("Couldn't talk to the slave\n");
		return STATUS_EXEC_ERROR;
	}

	return STATUS_OK;
}

static size_t i2c_linux_write(void *ctx, const void *buf, size_t size)
{
	struct i2c_linux_ctx *ictx = ctx;

	assert(ictx);
	assert(ictx->fd != 0);
	assert(ictx);

	return write(ictx->fd, buf, size);
}

static size_t i2c_linux_read(void *ctx, void *buf, size_t size)
{
	struct i2c_linux_ctx *ictx = ctx;

	assert(ictx);
	assert(ictx->fd != 0);
	assert(buf);

	return read(ictx->fd, buf, size);
}

static uint32_t i2c_linux_close(void *ctx)
{
	struct i2c_linux_ctx *ictx = ctx;

	assert(ictx);
	assert(ictx->fd != 0);
	logd("Closing fd: %d\n", ictx->fd);

	return close(ictx->fd) == 0 ? STATUS_OK : STATUS_EXEC_ERROR;
}

/* As Linux ioctls do not provide a way to control the I2C lines directly,
 * we send a request to address 0x00, which pulls SDA low for 7 cycles.
 * This method is not failsafe as the wakeup low duration is 60 usec
 * and the device can operate on frequencies up to 1MHz. This will therefore
 * only work on systems clocked up to 133KHz.
 */
static uint32_t i2c_linux_wake(void *ctx)
{
	int fd;
	uint8_t data = 0;

	fd = open(I2C_DEVICE, O_RDWR);
	if (fd < 0) {
		loge("Couldn't open the device\n");
		return STATUS_EXEC_ERROR;
	}
	if (ioctl(fd, I2C_SLAVE, 0) < 0) {
		loge("Couldn't talk to the slave\n");
		return STATUS_EXEC_ERROR;
	}
	write(fd, &data, sizeof(data));
	close(fd);

	return STATUS_OK;
}

static struct i2c_linux_ctx i2c_ctx;

struct io_interface i2c_linux = {
	.ctx = &i2c_ctx,
	.open = i2c_linux_open,
	.write = i2c_linux_write,
	.read = i2c_linux_read,
	.close = i2c_linux_close,
	.wake = i2c_linux_wake
};
