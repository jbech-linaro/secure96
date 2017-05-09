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
 * cmd_packet expect the command type.
 */
static size_t get_count_size(struct cmd_packet *p)
{
	return get_total_packet_size(p) - sizeof(p->command);
}

static uint8_t *serialize(struct cmd_packet *p)
{
	uint8_t *pkt;
	size_t pkt_size = get_total_packet_size(p);

	assert(p);

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

void get_random(struct io_interface *ioif)
{
	int n = 0;
	int ret = STATUS_EXEC_ERROR;
	uint8_t *serialized_pkt = NULL;
	uint8_t resp_buf[RANDOM_LEN];
	size_t pl_size;

	struct cmd_packet req_cmd;

	get_command(&req_cmd, OPCODE_RANDOM);

	req_cmd.count = get_count_size(&req_cmd);
	logd("count: %d\n", req_cmd.count);

	pl_size = get_payload_size(&req_cmd);
	req_cmd.checksum = get_packet_crc(&req_cmd, pl_size);
	logd("checksum: 0x%x\n", req_cmd.checksum);

	serialized_pkt = serialize(&req_cmd);
	if (!serialized_pkt)
		goto err;

	n = ioif->write(ioif->ctx, serialized_pkt,
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

bool wake(struct io_interface *ioif)
{
	int ret = STATUS_EXEC_ERROR;
	ssize_t n = 0;
	uint32_t cmd = CMD_WAKEUP;
	uint8_t buf;

	n = ioif->write(ioif->ctx, &cmd, sizeof(uint32_t));
	if (n <= 0)
		return false;

	/* FIXME: Eventually we should return true on STATUS_OK also? */
	return at204_read(ioif, &buf,
			  sizeof(buf)) == STATUS_AFTER_WAKE;
}
