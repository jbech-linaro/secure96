#include <crc_local.h>
#include <debug.h>
#include <packet.h>

/* 
 * The calculate_crc16 comes from the hashlet code and since that is GPL
 * code it might be necessary to replace it with some other implementation.
 *
 * @param data	Pointer to the data we shall check
 * @param crc	Pointer to the expected checksum
 */
bool crc_valid(const uint8_t *data, uint8_t *crc, size_t data_len)
{
	uint16_t buf_crc = 0;
	buf_crc = calculate_crc16(data, data_len);
	hexdump("calculated CRC", &buf_crc, CRC_LEN);
	return memcmp(crc, &buf_crc, CRC_LEN) == 0;
}

uint16_t get_packet_crc(struct cmd_packet *p, size_t payload_size)
{
	return calculate_crc16(&p->count, payload_size);
}

uint16_t get_serialized_crc(void *p, size_t size)
{
	return calculate_crc16(p, size);
}

