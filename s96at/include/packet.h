/*
 * Copyright 2017, Linaro Ltd and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _PACKET_H
#define _PACKET_H

#include <stdint.h>
#include <stddef.h>

/*
 * Device command structure according to section 8.5.1 in the ATSHA204A
 * datasheet.
 * @param command	the command flag
 * @param count		packet size in bytes, includes count, opcode, param1,
 * 			param2, data and checksum (command NOT included)
 * @param opcode	the operation being called
 * @param param1	first parameter, always present
 * @param param2	second parameter, always present
 * @param data		optional data for the command being called
 * @param checksum	two bytes always at the end
 */
struct __attribute__ ((__packed__)) cmd_packet {
	uint8_t command;
	uint8_t count;
	uint8_t opcode;
	uint8_t param1;
	uint8_t param2[2];
	const uint8_t *data;
	uint8_t data_length;
	/* crc = count + opcode + param{1, 2} + data */
	uint8_t max_time; /* Max time in ms for the command */
	uint16_t checksum;
};

size_t get_total_packet_size(struct cmd_packet *p);
size_t get_payload_size(struct cmd_packet *p);
uint8_t *serialize(struct cmd_packet *p);

#endif
