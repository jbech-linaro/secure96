/*
 * Copyright 2017, Linaro Ltd and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmd.h>
#include <crc.h>
#include <debug.h>
#include <device.h>
#include <packet.h>
#include <status.h>
#include <s96at.h>
#include <s96at_private.h>

uint8_t SLOT_CONFIG_ADDR(uint8_t slotnbr)
{
	uint8_t addr = 0x5;

	if (slotnbr % 2)
		slotnbr--;
	slotnbr >>= 1;
	return addr + slotnbr;
}

/* atsha204a max execution times in ms
 * See Table 8.4 in the atsha204a spec
 */
static uint8_t atsha204a_get_exec_time(uint8_t opcode)
{
	uint8_t max_time;

	switch (opcode) {
	case OPCODE_DERIVEKEY:
		max_time = 62;
		break;
	case OPCODE_DEVREV:
		max_time = 2;
		break;
	case OPCODE_GENDIG:
		max_time = 43;
		break;
	case OPCODE_HMAC:
		max_time = 69;
		break;
	case OPCODE_CHECKMAC:
		max_time = 38;
		break;
	case OPCODE_LOCK:
		max_time = 24;
		break;
	case OPCODE_MAC:
		max_time = 35;
		break;
	case OPCODE_NONCE:
		max_time = 60;
		break;
	case OPCODE_PAUSE:
		max_time = 2;
		break;
	case OPCODE_RANDOM:
		max_time = 50;
		break;
	case OPCODE_READ:
		max_time = 4;
		break;
	case OPCODE_SHA:
		max_time = 22;
		break;
	case OPCODE_UPDATEEXTRA:
		max_time = 8;
		break;
	case OPCODE_WRITE:
		max_time = 20; /* Max is 42, lowered it to get better performance */
		break;
	default:
		break;
	}

	return max_time;
}

/* atecc508a max execution times in ms
 * See Table 9.4 in the atecc508a spec
 */
static uint8_t atecc508a_get_exec_time(uint8_t opcode)
{
	uint8_t max_time;

	switch (opcode) {
	case OPCODE_CHECKMAC:
		max_time = 13;
		break;
	case OPCODE_COUNTER:
		max_time = 20;
		break;
	case OPCODE_DERIVEKEY:
		max_time = 50;
		break;
	case OPCODE_ECDH:
		max_time = 58;
		break;
	case OPCODE_GENDIG:
		max_time = 11;
		break;
	case OPCODE_GENKEY:
		max_time = 115;
		break;
	case OPCODE_HMAC:
		max_time = 23;
		break;
	case OPCODE_INFO:
		max_time = 1;
		break;
	case OPCODE_LOCK:
		max_time = 32;
		break;
	case OPCODE_MAC:
		max_time = 14;
		break;
	case OPCODE_NONCE:
		max_time = 7;
		break;
	case OPCODE_PAUSE:
		max_time = 3;
		break;
	case OPCODE_PRIV_WRITE:
		max_time = 48;
		break;
	case OPCODE_RANDOM:
		max_time = 23;
		break;
	case OPCODE_READ:
		max_time = 1;
		break;
	case OPCODE_SHA:
		max_time = 9;
		break;
	case OPCODE_SIGN:
		max_time = 50;
		break;
	case OPCODE_UPDATEEXTRA:
		max_time = 10;
		break;
	case OPCODE_VERIFY:
		max_time = 58;
		break;
	case OPCODE_WRITE:
		max_time = 26;
		break;
	default:
		break;
	}

	return max_time;
}

/*
 * Initializes a command packet.
 */
void get_command(uint8_t dev, struct cmd_packet *p, uint8_t opcode)
{
	assert(p);

	memset(p, 0, sizeof(struct cmd_packet));
	p->command = PKT_FUNC_COMMAND;
	p->opcode = opcode;

	if (dev == S96AT_ATSHA204A)
		p->max_time = atsha204a_get_exec_time(opcode);
	else
		p->max_time = atecc508a_get_exec_time(opcode);
}

uint8_t cmd_read(struct s96at_desc *desc, uint8_t zone, uint8_t addr,
		 uint8_t offset, size_t size, void *data, size_t data_size)
{
	int ret = STATUS_EXEC_ERROR;
	struct cmd_packet p;
	uint8_t resp_buf[size];

	assert(zone < ZONE_END);
	assert(size == 4 || size == 32);

	get_command(desc->dev, &p, OPCODE_READ);

	/*
	 * Bit 7 should be '1' for 32 byte reads and always zero, when zone is
	 * OTP (see Table 8-33 in the specification).
	 */
	if (zone == ZONE_OTP)
		zone &= ~(1 << 7);
	else if (data_size == 32)
		zone |= (1 << 7);

	p.param1 = zone;
	p.param2[0] = addr;
	p.param2[1] = 0;

	ret = at204_msg(desc->ioif, &p, resp_buf, sizeof(resp_buf));

	if (ret == STATUS_OK)
		memcpy(data, &resp_buf[offset], data_size);
	else
		loge("Failed to read from %s zone!\n", zone2str(zone));

	return ret;
}

uint8_t cmd_derive_key(struct s96at_desc *desc, uint8_t random, uint8_t slotnbr,
		       uint8_t *buf, size_t size)
{
	uint8_t resp;
	struct cmd_packet p;

	get_command(desc->dev, &p, OPCODE_DERIVEKEY);
	p.param1 = random;
	p.param2[0] = slotnbr & 0xff;
	p.param2[1] = slotnbr >> 8;
	p.data = buf;
	p.data_length = size;

	return at204_msg(desc->ioif, &p, &resp, sizeof(resp));
}

uint8_t cmd_check_mac(struct s96at_desc *desc, uint8_t *in, size_t in_size,
		      uint8_t mode, uint16_t slotnbr, uint8_t *out, size_t out_size)
{
	struct cmd_packet p;

	get_command(desc->dev, &p, OPCODE_CHECKMAC);
	p.param1 = mode;
	p.param2[0] = slotnbr;
	p.data = in;
	p.data_length = in_size;

	return at204_msg(desc->ioif, &p, out, out_size);
}

uint8_t cmd_get_devrev(struct s96at_desc *desc, uint8_t *buf, size_t size)
{
	struct cmd_packet p;

	get_command(desc->dev, &p, OPCODE_DEVREV);

	return at204_msg(desc->ioif, &p, buf, size);
}

uint8_t cmd_get_hmac(struct s96at_desc *desc, uint8_t mode, uint16_t slotnbr,
		     uint8_t *hmac)
{
	struct cmd_packet p;

	get_command(desc->dev, &p, OPCODE_HMAC);

	p.param1 = mode;
	/* Only the 4 least significant bits are used when determining
	 * the SlotID. Yet, when param2 is used in a SHA-256 operation,
	 * the entire 16-bit value is used (see Section 13.3 in the
	 * specification)
	 */
	p.param2[0] = slotnbr & 0xff;
	p.param2[1] = slotnbr >> 8;

	return at204_msg(desc->ioif, &p, hmac, HMAC_LEN);
}

uint8_t cmd_lock_zone(struct s96at_desc *desc, uint8_t zone,
		      const uint16_t *expected_crc)
{
	int ret = STATUS_EXEC_ERROR;
	struct cmd_packet p;
	uint8_t resp_buf;

	if (zone != ZONE_CONFIG && zone != ZONE_OTP && zone != ZONE_DATA)
		goto out;

	get_command(desc->dev, &p, OPCODE_LOCK);

	/* Zero for config and one for data and OTP. */
	if (zone == ZONE_CONFIG)
		p.param1 = 0;
	else
		p.param1 = 1;

	/*
	 * If no crc was provided set the bit for that in param1 to indicate
	 * that no CRC check will be performed by ATSHA204A when locking the
	 * zone.
	 */
	if (!expected_crc) {
		p.param1 |= 0x80;
		p.param2[0] = 0;
		p.param2[1] = 0;
	} else {
		p.param2[0] = (uint8_t)(*expected_crc & 0xff);
		p.param2[1] = (uint8_t)((*expected_crc >> 8) & 0xff);
	}

	logd("Locking zone: %s with param1: 0x%02x, param2: 0x%02x 0x%02x\n",
	     zone2str(zone), p.param1, p.param2[0], p.param2[1]);
	ret = at204_msg(desc->ioif, &p, &resp_buf, sizeof(resp_buf));

	/*
	 * Both data and config has the same value when locked, so here we just
	 * picked data.
	 */
	if (ret == STATUS_OK && resp_buf == LOCK_DATA_LOCKED)
		logd("Successfully locked %s zone!\n", zone2str(zone));
	else
		ret = STATUS_EXEC_ERROR;
out:
	return ret;
}

uint8_t cmd_get_mac(struct s96at_desc *desc, const uint8_t *in, size_t in_size,
		    uint8_t mode, uint16_t slotnbr, uint8_t *out, size_t out_size)
{
	int ret = STATUS_EXEC_ERROR;
	struct cmd_packet p;

	get_command(desc->dev, &p, OPCODE_MAC);

	p.param1 = mode;
	p.param2[0] = slotnbr & 0xff;
	p.param2[1] = slotnbr >> 8;
	p.data = in;
	p.data_length = in_size;

	ret = at204_msg(desc->ioif, &p, out, out_size);

	return ret;
}

uint8_t cmd_get_nonce(struct s96at_desc *desc, const uint8_t *in, size_t in_size,
		      uint8_t mode, uint8_t *out, size_t out_size)
{
	int ret = STATUS_EXEC_ERROR;
	struct cmd_packet p;

	get_command(desc->dev, &p, OPCODE_NONCE);

	p.param1 = mode;
	p.data = in;
	p.data_length = in_size;

	ret = at204_msg(desc->ioif, &p, out, out_size);

	return ret;
}

uint8_t cmd_get_random(struct s96at_desc *desc, uint8_t mode,
		       uint8_t *buf, size_t size)
{
	struct cmd_packet p;

	get_command(desc->dev, &p, OPCODE_RANDOM);
	p.param1 = mode;

	return at204_msg(desc->ioif, &p, buf, size);
}

uint8_t cmd_gen_dig(struct s96at_desc *desc, const uint8_t *in, size_t in_size,
		    uint8_t zone, uint16_t slotnbr)
{
	uint8_t resp;
	struct cmd_packet p;

	get_command(desc->dev, &p, OPCODE_GENDIG);
	p.param1 = zone;
	p.param2[0] = slotnbr & 0xff;
	p.param2[1] = slotnbr >> 8;
	p.data = in;
	p.data_length = in_size;

	return at204_msg(desc->ioif, &p, &resp, sizeof(resp));
}

uint8_t cmd_pause(struct s96at_desc *desc, uint8_t selector)
{
	struct cmd_packet p;
	uint8_t resp_buf;

	get_command(desc->dev, &p, OPCODE_PAUSE);
	p.param1 = selector;

	return at204_msg(desc->ioif, &p, &resp_buf, 1);
}

uint8_t cmd_sha(struct s96at_desc *desc, uint8_t mode, const uint8_t *in,
		size_t in_size, uint8_t *out, size_t out_size)
{
	struct cmd_packet p;

	get_command(desc->dev, &p, OPCODE_SHA);
	p.param1 = mode;
	p.data = in;
	p.data_length = in_size;

	return at204_msg(desc->ioif, &p, out, out_size);
}

uint8_t cmd_update_extra(struct s96at_desc *desc, uint8_t mode, uint8_t value)
{
	uint8_t resp_buf;
	struct cmd_packet p;

	get_command(desc->dev, &p, OPCODE_UPDATEEXTRA);
	p.param1 = mode;
	p.param2[0] = value;

	return at204_msg(desc->ioif, &p, &resp_buf, sizeof(resp_buf));
}

uint8_t cmd_write(struct s96at_desc *desc, uint8_t zone, uint8_t addr,
		  bool encrypted, const uint8_t *data, size_t size)
{
	uint8_t resp;
	struct cmd_packet p;

	assert(zone < ZONE_END);
	assert(size == 4 || size == 32);

	if (encrypted)
		zone |= (1 << 6);

	if (size == 32)
		zone |= (1 << 7);

	get_command(desc->dev, &p, OPCODE_WRITE);
	p.param1 = zone;
	p.param2[0] = addr;
	p.data = data;
	p.data_length = size;

	return at204_msg(desc->ioif, &p, &resp, 1);
}
