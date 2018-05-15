/*
 * Copyright 2017, Linaro Ltd and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <string.h>
#include <crc.h>
#include <debug.h>
#include <packet.h>

/*
 * Computes and check that the computed CRC is the same as the one provided as
 * an argument to the function.
 *
 * @param data	Pointer to the data we shall check
 * @param crc	Pointer to the expected checksum
 */
bool crc_valid(const uint8_t *data, uint8_t *crc, size_t data_len)
{
	uint16_t buf_crc = 0;
	buf_crc = calculate_crc16(data, data_len, 0);
	hexdump("calculated CRC", &buf_crc, CRC_LEN);

	return memcmp(crc, &buf_crc, CRC_LEN) == 0;
}

uint16_t get_packet_crc(struct cmd_packet *p, size_t payload_size)
{
	return calculate_crc16(&p->count, payload_size, 0);
}

uint16_t get_serialized_crc(void *p, size_t size)
{
	return calculate_crc16(p, size, 0);
}

/*
 * Compute the CRC for a certain payload. This function takes a crc
 * (current_crc) as an argument. This is useful if you cannot compute the entire
 * CRC in one go.
 */
uint16_t calculate_crc16(const uint8_t *data, size_t size, uint16_t current_crc)
{
	uint16_t i;
	uint16_t crc = current_crc;
	uint8_t shift_register;
	uint8_t data_bit;
	uint8_t crc_bit;

	for (i = 0; i < size; i++) {
		for (shift_register = 0x01; shift_register > 0x00; shift_register <<= 1) {
			data_bit = (data[i] & shift_register) ? 1 : 0;
			crc_bit = crc >> 15;
			crc <<= 1;

			if ((data_bit ^ crc_bit) != 0)
				crc ^= CRC_POLYNOM;
		}
	}

	return crc;
}
