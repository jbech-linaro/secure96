#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include <crc.h>
#include <debug.h>
#include <packet.h>
#include <string.h>

size_t get_total_packet_size(struct cmd_packet *p)
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
size_t get_payload_size(struct cmd_packet *p)
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


uint8_t *serialize(struct cmd_packet *p)
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

