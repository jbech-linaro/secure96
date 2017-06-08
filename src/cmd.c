#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmd.h>
#include <crc_local.h>
#include <debug.h>
#include <packet.h>
#include <status.h>

/*
 * This serializes a command packet. It will also calculate and store the
 * checksum for the package.
 */
void get_command(struct cmd_packet *p, uint8_t opcode)
{
	assert(p);

	p->count = 0;
	p->command = PKT_FUNC_COMMAND;
	p->opcode = opcode;
	p->data = NULL;
	p->data_length = 0;

	switch (p->opcode)
	{
	case OPCODE_DERIVEKEY:
		break;
	case OPCODE_DEVREV:
		p->count = 0;
		p->param1 = 0;
		p->param2[0] = 0;
		p->param2[1] = 0;
		p->data = NULL;
		p->data_length = 0;
		p->max_time = 2; /* Table 8.4 */
		break;
	case OPCODE_GENDIG:
		break;
	case OPCODE_HMAC:
		break;
	case OPCODE_CHECKMAC:
		break;
	case OPCODE_LOCK:
		break;
	case OPCODE_MAC:
		break;
	case OPCODE_NONCE:
		p->count = 0;
		p->param1 = 0;
		p->param2[0] = 0x00;
		p->param2[1] = 0x00;
		p->max_time = 60; /* Table 8.4 */
		break;
	case OPCODE_PAUSE:
		break;

	case OPCODE_RANDOM:
		p->count = 0;
		p->param1 = 0;
		p->param2[0] = 0x00;
		p->param2[1] = 0x00;
		p->data = NULL;
		p->data_length = 0;
		p->max_time = 50; /* Table 8.4 */
		break;

	case OPCODE_READ:
		p->count = 0;
		p->data = NULL;
		p->data_length = 0;
		p->max_time = 4; /* Table 8.4 */
		break;
	case OPCODE_SHA:
		break;
	case OPCODE_UPDATEEXTRA:
		break;
	case OPCODE_WRITE:
		p->max_time = 42;
		break;

	default:
		break;
	}
}

bool cmd_wake(struct io_interface *ioif)
{
	int ret = STATUS_EXEC_ERROR;
	ssize_t n = 0;
	uint8_t cmd = CMD_WAKEUP;
	uint8_t buf;

	n = at204_write(ioif, &cmd, sizeof(cmd));
	if (n <= 0)
		return false;

	ret = at204_read(ioif, &buf, sizeof(buf));
	return ret == STATUS_OK || ret == STATUS_AFTER_WAKE;
}

int cmd_read(struct io_interface *ioif, uint8_t zone, uint8_t addr,
	     uint8_t offset, size_t size, void *data, size_t data_size)
{
	int ret = STATUS_EXEC_ERROR;
	struct cmd_packet p;
	uint8_t resp_buf[size];

	assert(zone < ZONE_END);
	assert(size == 4 || size == 32);

	get_command(&p, OPCODE_READ);

	/*
	 * Bit 7 should be '1' for 32 byte reads and always zero, when zone is
	 * OTP (see Table 8-33 in the specification).
	 */
	if (zone == ZONE_OTP)
		zone &= ~(1 << 7);
	else if (data_size == 32)
		zone &= (1 << 7);

	p.param1 = zone;
	p.param2[0] = addr;
	p.param2[1] = 0;

	ret = at204_msg(ioif, &p, resp_buf, sizeof(resp_buf));

	if (ret == STATUS_OK)
		memcpy(data, &resp_buf[offset], data_size);
	else
		loge("Failed to read from config zone!\n");

	return ret;
}

int cmd_get_devrev(struct io_interface *ioif)
{
	int ret = STATUS_EXEC_ERROR;
	struct cmd_packet p;
	uint8_t resp_buf[DEVREV_LEN];

	get_command(&p, OPCODE_DEVREV);

	ret = at204_msg(ioif, &p, resp_buf, sizeof(resp_buf));

	if (ret == STATUS_OK)
		hexdump("devrev", resp_buf, DEVREV_LEN);
	else {
		loge("Failed to get devrev!\n");
	}
	return ret;
}

int cmd_get_lock_config(struct io_interface *ioif)
{
	uint8_t lock_config = 0;
	int ret = STATUS_EXEC_ERROR; 
	ret = cmd_read(ioif, ZONE_CONFIG, LOCK_CONFIG_ADDR, LOCK_CONFIG_OFFSET,
		       WORD_SIZE, &lock_config, LOCK_CONFIG_SIZE);
	logd("lock_config: 0x%02x\n", lock_config);
	return ret;
}

int cmd_get_lock_data(struct io_interface *ioif)
{
	uint8_t lock_data = 0;
	int ret = STATUS_EXEC_ERROR;
	ret = cmd_read(ioif, ZONE_CONFIG, LOCK_DATA_ADDR, LOCK_DATA_OFFSET,
		       WORD_SIZE, &lock_data, LOCK_DATA_SIZE);
	logd("lock_data: 0x%02x\n", lock_data);
	return ret;
}

int cmd_get_nonce(struct io_interface *ioif)
{
	int ret = STATUS_EXEC_ERROR;
	uint8_t resp_buf[NONCE_LEN];
	uint8_t in[20] = { 0x0,   0x1,  0x2,  0x3,
			   0x4,   0x5,  0x6,  0x7,
			   0x8,   0x9,  0xa,  0xb,
			   0xc,   0xd,  0xe,  0xf,
			   0x10, 0x11, 0x12, 0x13 };

	struct cmd_packet p;

	get_command(&p, OPCODE_NONCE);
	p.data = in;
	p.data_length = sizeof(in);

	ret = at204_msg(ioif, &p, resp_buf, sizeof(resp_buf));
	if (ret == STATUS_OK)
		hexdump("nonce", &resp_buf, sizeof(resp_buf));
	else
		loge("Failed to get nonce\n");
	return ret;
}

int cmd_get_otp_mode(struct io_interface *ioif)
{
	uint8_t otp_mode = 0;
	int ret = STATUS_EXEC_ERROR;
	ret = cmd_read(ioif, ZONE_CONFIG, OTP_ADDR, OTP_OFFSET, WORD_SIZE,
		       &otp_mode, OTP_SIZE);

	logd("otp_mode: 0x%02x", otp_mode);
	switch(otp_mode) {
	case 0xAA:
		logd(" (Read only mode)\n");
		break;
	case 0x55:
		logd(" (Consumption mode)\n");
		break;
	case 0x00:
		logd(" (Legacy mode)\n");
		break;
	default:
		logd(" (Uknown mode)\n");
	}
	return ret;
}

int cmd_get_random(struct io_interface *ioif)
{
	int ret = STATUS_EXEC_ERROR;
	uint8_t resp_buf[RANDOM_LEN];
	struct cmd_packet p;

	get_command(&p, OPCODE_RANDOM);

	ret = at204_msg(ioif, &p, resp_buf, sizeof(resp_buf));
	if (ret == STATUS_OK)
		hexdump("random", resp_buf, RANDOM_LEN);
	else {
		loge("Failed to get random number!\n");
	}
	return ret;
}

int cmd_get_serialnbr(struct io_interface *ioif)
{
	/* Only 9 are used, but we read 4 bytes at a time */
	uint8_t serial_nbr[12] = { 0 };
	int ret = STATUS_EXEC_ERROR;

	ret = cmd_read(ioif, ZONE_CONFIG, SERIALNBR_ADDR0_3,
		       SERIALNBR_OFFSET0_3, WORD_SIZE, serial_nbr,
		       SERIALNBR_SIZE0_3);
	if (ret != STATUS_OK)
		goto err;

	ret = cmd_read(ioif, ZONE_CONFIG, SERIALNBR_ADDR4_7,
		       SERIALNBR_OFFSET4_7, WORD_SIZE, serial_nbr +
		       SERIALNBR_SIZE0_3, SERIALNBR_SIZE4_7);
	if (ret != STATUS_OK)
		goto err;

	ret = cmd_read(ioif, ZONE_CONFIG, SERIALNBR_ADDR8, SERIALNBR_OFFSET8,
		       WORD_SIZE, serial_nbr + SERIALNBR_SIZE4_7,
		       SERIALNBR_SIZE8);
err:
	if (ret == STATUS_OK)
		hexdump("serialnbr", serial_nbr, SERIALNUM_LEN);
	else
		loge("Failed to get serial number!\n");
	return ret;
}

int cmd_get_slot_config(struct io_interface *ioif, uint8_t slotnbr)
{
	uint16_t slot_config;
	int ret = STATUS_EXEC_ERROR;

	logd("slotnbr: %d, addr: 0x%02x, offset: %d\n", slotnbr,
	     SLOT_CONFIG_ADDR(slotnbr), SLOT_CONFIG_OFFSET(slotnbr));

	ret = cmd_read(ioif, ZONE_CONFIG, SLOT_CONFIG_ADDR(slotnbr),
		       SLOT_CONFIG_OFFSET(slotnbr), WORD_SIZE, &slot_config,
		       SLOT_CONFIG_SIZE);
	if (ret == STATUS_OK)
		hexdump("slot_config", &slot_config, SLOT_CONFIG_SIZE);
	else
		loge("Failed to read slotconfig!\n");

	return ret;
}

int cmd_write(struct io_interface *ioif, uint8_t zone, uint8_t addr,
	       uint8_t *data, size_t size)
{
	ssize_t n = 0;
	struct cmd_packet p;
	int ret = STATUS_EXEC_ERROR;

	get_command(&p, OPCODE_WRITE);
	p.param1 = zone;
	p.param2[0] = addr;
	p.data = data;
	p.data_length = size;

#if 0
	if (size != 0 && size != 4 && size != 32) {
		loge("Wrong size when trying to write\n");
		goto err;
	}
#endif

	n = at204_write2(ioif, &p);
	logd("cmd_write: wrote %d bytes\n", n);
err:
	return ret;
}
