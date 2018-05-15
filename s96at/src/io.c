/*
 * Copyright 2017, Linaro Ltd and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include <crc.h>
#include <debug.h>
#include <io.h>
#include <packet.h>
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
	logd("Read n: %d bytes -> Resp[0] size: %d\n", n, resp_buf[0]);

	/*
	 * We expect something to be read and if read, we expect either the size
	 * 4 or the full response length as calculated above.
	 */
	if (n <= 0 || resp_buf[0] > n || (resp_buf[0] != 4 && resp_buf[0] != resp_size))
		goto out;

#if DEBUG
	if (resp_buf[0] == 4 && n >= 4) {
		logd("Got status packet! status/err: 0x%02x (%s)\n",
		     resp_buf[1], resp2str(resp_buf[1]));
	}
#endif

	if (!crc_valid(resp_buf, resp_buf + (resp_buf[0] - CRC_LEN),
		       resp_buf[0] - CRC_LEN)) {
		logd("Got incorrect CRC\n");
		ret = STATUS_CRC_ERROR;
		goto out;
	}

	if (resp_buf[0] == resp_size) {
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

int at204_write2(struct io_interface *ioif, struct cmd_packet *p)
{
	uint8_t *serialized_pkt = NULL;
	int n = 0;

	serialized_pkt = serialize(p);
	if (!serialized_pkt)
		goto err;

	n = ioif->write(ioif->ctx, serialized_pkt, get_total_packet_size(p));

	logd("Wrote n = 0x%02x (%d) bytes to ATSHA204A\n", n, n);

	/* Time in p is in ms */
	usleep(p->max_time * 1000);
err:
	free(serialized_pkt);

	return n > 0 ? STATUS_OK : STATUS_EXEC_ERROR;
}

int at204_msg(struct io_interface *ioif, struct cmd_packet *p, void *resp_buf,
	      size_t size)
{
	int ret = STATUS_EXEC_ERROR;
	assert(resp_buf);

	ret = at204_write2(ioif, p);
	if (ret != STATUS_OK) {
		logd("Didn't write anything\n");
		return ret;
	}

	return at204_read(ioif, resp_buf, size);
}
