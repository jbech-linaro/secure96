#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmd.h>
#include <debug.h>
#include <status.h>

/* FIXME: CRC related functionality needs to go into separate files later on */
#define CRC_LEN 2 /* In bytes */

/* 
 * The calculate_crc16 comes from the hashlet code and since that is GPL
 * code it might be necessary to replace it with some other implementation.
 *
 * @param data	Pointer to the data we shall check
 * @param crc	Pointer to the expected checksum
 */
static bool crc_valid(const uint8_t *data, uint8_t *crc, size_t data_len)
{
	uint16_t buf_crc = 0;
	buf_crc = calculate_crc16(data, data_len);
	hexdump("calculated CRC", &buf_crc, CRC_LEN);
	return memcmp(crc, &buf_crc, CRC_LEN) == 0;
}

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

static uint16_t get_packet_crc(struct cmd_packet *p)
{
	size_t payload_size = get_payload_size(p);
	logd("payload_size: %d\n", payload_size);
	return calculate_crc16(&p->count, payload_size);
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

int atsha204x_read(struct io_interface *ioif, void *buf, size_t size)
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

	/* This indicates a status code or an error, see 8.1.1. */
	if (resp_buf[0] == 4) {
		logd("Got status/error code: 0x%0x when reading\n", resp_buf[1]);
		ret = resp_buf[1];
	} else if (resp_buf[0] == resp_size) {
		logd("Got the expexted amount of data\n");
		memcpy(buf, resp_buf + 1, size);
		ret = STATUS_OK;
	}
out:
	free(resp_buf);
	return ret;
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

void get_random(struct io_interface *ioif)
{
	int n = 0;
	int ret = STATUS_EXEC_ERROR;
	uint8_t *serialized_pkt = NULL;
	uint8_t resp_buf[RANDOM_LEN];
	struct timespec ts = {0, 11000000}; /* FIXME: this should a well defined value */

	struct cmd_packet req_cmd = {
		.command = PKT_FUNC_COMMAND,
		.count = 0,
		.opcode = OPCODE_RANDOM,
		.param1 = 0, /* Automatical Eeprom seed update */
		.param2[0] = 0x00,
		.param2[1] = 0x00,
		.data = NULL,
		.data_length = 0,
	};

	req_cmd.count = get_count_size(&req_cmd);
	logd("count: %d\n", req_cmd.count);

	req_cmd.checksum = get_packet_crc(&req_cmd);
	logd("checksum: 0x%x\n", req_cmd.checksum);

	serialized_pkt = serialize(&req_cmd);
	if (!serialized_pkt)
		goto err;

	n = ioif->write(ioif->ctx, serialized_pkt,
			get_total_packet_size(&req_cmd));
	if (n <= 0)
		logd("Didn't write anything\n");

	nanosleep(&ts, NULL);

	ret = atsha204x_read(ioif, resp_buf, RANDOM_LEN);
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
	return atsha204x_read(ioif, &buf,
			      sizeof(buf)) == STATUS_AFTER_WAKE;
}
