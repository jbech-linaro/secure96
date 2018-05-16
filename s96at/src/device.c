/*
 * Copyright 2017, Linaro Ltd and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stddef.h>
#include <stdint.h>

#include <device.h>
#include <io.h>
#include <packet.h>
#include <status.h>

uint8_t device_idle(struct io_interface *ioif)
{
	uint8_t ret;
	uint8_t data;
	uint8_t word_addr = PKT_FUNC_IDLE;

	at204_write(ioif, &word_addr, sizeof(word_addr));

	/* If idle was successful, we expect a NAK on read */
	ret = at204_read(ioif, &data, sizeof(data));

	if (ret != STATUS_OK)
		ret = STATUS_OK;
	else
		ret = STATUS_EXEC_ERROR;

	return ret;
}

uint8_t device_sleep(struct io_interface *ioif)
{
	uint8_t ret;
	uint8_t data;
	uint8_t word_addr = PKT_FUNC_SLEEP;

	at204_write(ioif, &word_addr, sizeof(word_addr));

	/* If sleep was successful, we expect a NAK on read */
	ret = at204_read(ioif, &data, sizeof(data));

	if (ret != STATUS_OK)
		ret = STATUS_OK;
	else
		ret = STATUS_EXEC_ERROR;

	return ret;
}

uint8_t device_reset(struct io_interface *ioif)
{
	uint8_t word_addr = PKT_FUNC_RESET;

	at204_write(ioif, &word_addr, sizeof(word_addr));

	return STATUS_OK;
}

