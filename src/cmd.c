#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmd.h>
#include <crc_local.h>
#include <debug.h>
#include <status.h>

static size_t get_total_packet_size(struct cmd_packet *p)
{
	return sizeof(p->command) + sizeof(p->count) + sizeof(p->opcode) +
		sizeof(p->param1) + sizeof(p->param2) + p->data_length +
		sizeof(p->checksum);
}

/*
 * Calculate the number of bytes used in CRC calculation. Note that this
 * function is dependant on the struct cmd_packet and it is important that the
 * struct is packed.
 */
static size_t get_payload_size(struct cmd_packet *p)
{
	return get_total_packet_size(p) - sizeof(p->command) -
		sizeof(p->checksum);
}

/*
 * Counts the size of the packet, this includes all elements in the struct
 * cmd_packet except the command type.
 */
static size_t get_count_size(struct cmd_packet *p)
{
	return get_total_packet_size(p) - sizeof(p->command);
}

/*
 * This serializes a command packet. It will also calculate and store the
 * checksum for the package.
 */
static uint8_t *serialize(struct cmd_packet *p)
{
	uint8_t *pkt;
	size_t pkt_size = get_total_packet_size(p);
	size_t pl_size;

	assert(p);

	p->count = get_count_size(p);
	pl_size = get_payload_size(p);
	logd("pkt_size: %d, count: %d, payload_size: %d\n", pkt_size, p->count, pl_size);

	pkt = calloc(pkt_size, sizeof(uint8_t));
	if (!pkt)
		return NULL;

	pkt[0] = p->command;
	pkt[1] = p->count;
	pkt[2] = p->opcode;
	pkt[3] = p->param1;
	pkt[4] = p->param2[0];
	pkt[5] = p->param2[1];

	/*
	 * No need to set "data" to NULL if there is no data, since calloc
	 * already set it to 0.
	 */
	if (p->data && p->data_length)
		memcpy(&pkt[6], p->data, p->data_length);

	p->checksum = get_serialized_crc(&pkt[1], pl_size);
	logd("checksum: 0x%x\n", p->checksum);

	memcpy(&pkt[pkt_size - CRC_LEN], &p->checksum, CRC_LEN);

	return pkt;
}

void get_command(struct cmd_packet *p, uint8_t opcode)
{
	assert(p);

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
		break;

	default:
		break;
	}
}

void cmd_devrev(struct io_interface *ioif)
{
	int n = 0;
	int ret = STATUS_EXEC_ERROR;
	struct cmd_packet req_cmd;
	uint8_t resp_buf[DEVREV_LEN];
	uint8_t *serialized_pkt = NULL;

	get_command(&req_cmd, OPCODE_DEVREV);

	serialized_pkt = serialize(&req_cmd);
	if (!serialized_pkt)
		goto err;

	n = at204_write(ioif, serialized_pkt,
			get_total_packet_size(&req_cmd));
	if (n <= 0)
		logd("Didn't write anything\n");

	/* Time in req_cmd is in ms */
	usleep(req_cmd.max_time * 1000);

	ret = at204_read(ioif, resp_buf, DEVREV_LEN);
	if (ret == STATUS_OK)
		hexdump("devrev", resp_buf, DEVREV_LEN);
err:
	free(serialized_pkt);
}

void cmd_get_nonce(struct io_interface *ioif)
{
	int n = 0;
	int ret = STATUS_EXEC_ERROR;
	uint8_t *serialized_pkt = NULL;
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

	serialized_pkt = serialize(&p);
	if (!serialized_pkt)
		goto err;

	hexdump("serialized_pkt: ", serialized_pkt,
		get_total_packet_size(&p));

	n = at204_write(ioif, serialized_pkt,
			get_total_packet_size(&p));
	if (n <= 0)
		logd("Didn't write anything\n");

	/* Time in req_cmd is in ms */
	usleep(p.max_time * 1000);

	ret = at204_read(ioif, &resp_buf, sizeof(resp_buf));
	if (ret == STATUS_OK)
		hexdump("nonce", &resp_buf, sizeof(resp_buf));
	else
		logd("Failed to get nonce\n");
err:
	free(serialized_pkt);
	return;
}

void cmd_get_random(struct io_interface *ioif)
{
	int n = 0;
	int ret = STATUS_EXEC_ERROR;
	uint8_t *serialized_pkt = NULL;
	uint8_t resp_buf[RANDOM_LEN];

	struct cmd_packet req_cmd;

	get_command(&req_cmd, OPCODE_RANDOM);

	serialized_pkt = serialize(&req_cmd);
	if (!serialized_pkt)
		goto err;

	n = at204_write(ioif, serialized_pkt,
			get_total_packet_size(&req_cmd));
	if (n <= 0)
		logd("Didn't write anything\n");

	/* Time in req_cmd is in ms */
	usleep(req_cmd.max_time * 1000);

	ret = at204_read(ioif, resp_buf, RANDOM_LEN);
	if (ret == STATUS_OK)
		hexdump("random", resp_buf, RANDOM_LEN);
err:
	free(serialized_pkt);
}

void cmd_get_serialnbr(struct io_interface *ioif)
{
	/* Only 9 are used, but we read 4 bytes at a time */
	uint8_t serial_nbr[12] = { 0 };

	cmd_config_zone_read(ioif, SERIALNBR_ADDR0_3, SERIALNBR_OFFSET0_3,
			     WORD_SIZE, serial_nbr, SERIALNBR_SIZE0_3);

	cmd_config_zone_read(ioif, SERIALNBR_ADDR4_7, SERIALNBR_OFFSET4_7,
			     WORD_SIZE, serial_nbr + SERIALNBR_SIZE0_3,
			     SERIALNBR_SIZE4_7);

	cmd_config_zone_read(ioif, SERIALNBR_ADDR8, SERIALNBR_OFFSET8,
			     WORD_SIZE, serial_nbr + SERIALNBR_SIZE4_7,
			     SERIALNBR_SIZE8);

	hexdump("serialnbr", serial_nbr, SERIALNUM_LEN);
}

void cmd_get_otp_mode(struct io_interface *ioif)
{
	uint8_t otp_mode = 0;
	cmd_config_zone_read(ioif, OTP_ADDR, OTP_OFFSET, WORD_SIZE, &otp_mode,
			     OTP_SIZE);

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
}

void cmd_get_slot_config(struct io_interface *ioif, uint8_t slotnbr)
{
	uint16_t slot_config;

	logd("slotnbr: %d, addr: 0x%02x, offset: %d\n", slotnbr,
	     SLOT_CONFIG_ADDR(slotnbr), SLOT_CONFIG_OFFSET(slotnbr));

	cmd_config_zone_read(ioif, SLOT_CONFIG_ADDR(slotnbr),
			     SLOT_CONFIG_OFFSET(slotnbr), WORD_SIZE,
			     &slot_config, SLOT_CONFIG_SIZE);
	hexdump("slot_config", &slot_config, SLOT_CONFIG_SIZE);
}

void cmd_get_lock_data(struct io_interface *ioif)
{
	uint8_t lock_data = 0;
	cmd_config_zone_read(ioif, LOCK_DATA_ADDR, LOCK_DATA_OFFSET, WORD_SIZE,
			     &lock_data, LOCK_DATA_SIZE);
	logd("lock_data: 0x%02x\n", lock_data);
}

void cmd_get_lock_config(struct io_interface *ioif)
{
	uint8_t lock_config = 0;
	cmd_config_zone_read(ioif, LOCK_CONFIG_ADDR, LOCK_CONFIG_OFFSET, WORD_SIZE,
			     &lock_config, LOCK_CONFIG_SIZE);
	logd("lock_config: 0x%02x\n", lock_config);
}

void cmd_config_zone_read(struct io_interface *ioif, uint8_t addr,
			  uint8_t offset, size_t size, void *data,
			  size_t data_size)
{
	int n = 0;
	int ret = STATUS_EXEC_ERROR;
	struct cmd_packet req_cmd;
	uint8_t resp_buf[size];
	uint8_t *serialized_pkt = NULL;

	get_command(&req_cmd, OPCODE_READ);

	req_cmd.param2[0] = addr;
	req_cmd.param2[1] = 0;

	serialized_pkt = serialize(&req_cmd);
	if (!serialized_pkt)
		goto err;

	n = at204_write(ioif, serialized_pkt,
			get_total_packet_size(&req_cmd));
	if (n <= 0)
		logd("Didn't write anything\n");

	/* Time in req_cmd is in ms */
	usleep(req_cmd.max_time * 1000);

	ret = at204_read(ioif, resp_buf, OTP_MODE_LEN);

	if (ret == STATUS_OK)
		memcpy(data, &resp_buf[offset], data_size);
err:
	free(serialized_pkt);
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

	/* FIXME: Eventually we should return true on STATUS_OK also? */
	return at204_read(ioif, &buf, sizeof(buf)) == STATUS_AFTER_WAKE;
}
