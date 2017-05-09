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

/*
 * Calculate the number of bytes used in CRC calculation. Note that this
 * function is dependant on the struct cmd_packet and it is important that the
 * struct is packed.
 */
static size_t get_payload_size(struct cmd_packet *p)
{
	return offsetof(struct cmd_packet, data) -
		offsetof(struct cmd_packet, count);
}

static size_t get_total_packet_size(struct cmd_packet *p)
{
	return sizeof(p->command) + sizeof(p->count) + sizeof(p->opcode) +
		sizeof(p->param1) + sizeof(p->param2) + p->data_length +
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
	logd("count: %d\n", p->count);

	pl_size = get_payload_size(p);

	p->checksum = get_packet_crc(p, pl_size);
	logd("checksum: 0x%x\n", p->checksum);

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

	memcpy(&pkt[pkt_size - CRC_LEN], &p->checksum, CRC_LEN);

	return pkt;
}

void get_command(struct cmd_packet *p, uint8_t opcode)
{
	assert(p);

	p->command = PKT_FUNC_COMMAND;
	p->opcode = opcode;

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
	int n = 0;
	int i = 0;
	int ret = STATUS_EXEC_ERROR;
	uint8_t offset = 0;
	uint8_t addr = 0;
	uint8_t *serialized_pkt = NULL;
	uint8_t resp_buf[4]; /* FIXME: magic nbr ... */
	uint8_t serial_nbr[12] = { 0 }; /* Only 9 are used, but we read 4 bytes at a time */

	struct cmd_packet req_cmd;

	get_command(&req_cmd, OPCODE_READ);

	req_cmd.param1 = ZONE_CONFIGURATION_BITS;

	for (i = 0; i < 3; i++) {

		switch (i) {
		case 0:
			offset = 0;
			addr = 0;
			break;
		case 1:
			offset = 4;
			addr = 2;
			break;
		case 2:
			offset = 8;
			addr = 3;
			break;
		default:
			logd("Bad addr\n");
			break;
		}

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

		ret = at204_read(ioif, &serial_nbr[offset], 4);
	}

	if (ret == STATUS_OK)
		hexdump("serial number", serial_nbr, SERIALNUM_LEN);
err:
	free(serialized_pkt);
}

bool cmd_wake(struct io_interface *ioif)
{
	int ret = STATUS_EXEC_ERROR;
	ssize_t n = 0;
	uint32_t cmd = CMD_WAKEUP;
	uint8_t buf;

	n = at204_write(ioif, &cmd, sizeof(uint32_t));
	if (n <= 0)
		return false;

	/* FIXME: Eventually we should return true on STATUS_OK also? */
	return at204_read(ioif, &buf,
			  sizeof(buf)) == STATUS_AFTER_WAKE;
}
