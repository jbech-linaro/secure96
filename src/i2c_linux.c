#include <i2c_linux.h>
#include <debug.h>
#include <device.h>
#include <io.h>
#include <status.h>

int get_fd(struct io_interface *ioif)
{
	struct i2c_linux_ctx *ctx = ioif->ctx;
	return ctx->fd;
}

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

static struct i2c_linux_ctx i2c_ctx;

struct io_interface i2c_linux = {
	.ctx = &i2c_ctx,
	.open = i2c_linux_open
};
