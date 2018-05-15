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

static struct i2c_linux_ctx i2c_ctx;

struct io_interface i2c_linux = {
	.ctx = &i2c_ctx,
	.open = i2c_linux_open,
	.write = i2c_linux_write,
	.read = i2c_linux_read,
	.close = i2c_linux_close
};
