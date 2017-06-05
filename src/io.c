#include <assert.h>
#include <string.h>

#include <crc_local.h>
#include <debug.h>
#include <io.h>
#include <status.h>

extern struct io_interface i2c_linux;

uint32_t register_io_interface(uint8_t io_interface_type,
			       struct io_interface **ioif)
{
	switch (io_interface_type) {
	case 0:
		*ioif = (struct io_interface *)&i2c_linux;
		break;

	default:
		logd("Unknown IO interface\n");
	}

	return STATUS_OK;
}

int at204_open(struct io_interface *ioif)
{
	return ioif->open(ioif->ctx);
}

int at204_write(struct io_interface *ioif, void *buf, size_t size)
{
	return ioif->write(ioif->ctx, buf, size);
}

int at204_read(struct io_interface *ioif, void *buf, size_t size)
{
	int n = 0;
	int ret = STATUS_EXEC_ERROR;
	uint8_t *resp_buf = NULL;
	uint8_t resp_size = 0;

	assert(ioif);
	assert(buf);

	/*
	 * Response will be on the format:
	 *  [packet size: 1 byte | data: size bytes | crc: 2 bytes]
	 *
	 * Therefore we need allocate 3 more bytes for the response.
	 */
	resp_size = 1 + size + CRC_LEN;
	resp_buf = calloc(resp_size, sizeof(uint8_t));
	if (!resp_buf)
		return 0;

	n = ioif->read(ioif->ctx, resp_buf, resp_size);

	logd("n: %d, Resp[0] size: %d, Resp[1] status/err: 0x%02x\n", n, resp_buf[0], resp_buf[1]);

	/*
	 * We expect something to be read and if read, we expect either the size
	 * 4 or the full response length as calculated above.
	 */
	if (n <= 0 || resp_buf[0] != 4 && resp_buf[0] != resp_size)
		goto out;

	if (!crc_valid(resp_buf, resp_buf + (resp_size - CRC_LEN),
		       resp_size - CRC_LEN)) {
		logd("Got incorrect CRC\n");
		ret = STATUS_CRC_ERROR;
		goto out;
	}

	if (resp_buf[0] == resp_size) {
		logd("Got the expexted amount of data\n");
		memcpy(buf, resp_buf + 1, size);
		ret = STATUS_OK;
	} else {
		logd("Something went wrong!\n");
	}
out:
	free(resp_buf);
	return ret;
}


int at204_close(struct io_interface *ioif)
{
	return ioif->close(ioif->ctx);
}
