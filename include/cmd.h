#ifndef __CMD_H
#define __CMD_H
#include <stdint.h>

#include <io.h>

#define CMD_WAKEUP 0x0

#define RANDOM_LEN 32

/* Word address values */
#define PKT_FUNC_RESET		0x0
#define PKT_FUNC_SLEEP		0x1
#define PKT_FUNC_IDLE		0x2
#define PKT_FUNC_COMMAND	0x3

/* OP-codes for each command, see section 8.5.4 in spec */
#define OPCODE_DERIVEKEY	0x1c
#define OPCODE_DEVREV 		0x30
#define OPCODE_GENDIG 		0x15
#define OPCODE_HMAC 		0x11
#define OPCODE_CHECKMAC		0x28
#define OPCODE_LOCK 		0x17
#define OPCODE_MAC 		0x08
#define OPCODE_NONCE 		0x16
#define OPCODE_PAUSE 		0x01
#define OPCODE_RANDOM 		0x1b
#define OPCODE_READ 		0x02
#define OPCODE_SHA 		0x47
#define OPCODE_UPDATEEXTRA 	0x20
#define OPCODE_WRITE 		0x12

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
	uint8_t *data;
	uint8_t data_length;
	/* crc = count + opcode + param{1, 2} + data */
	uint8_t max_time; /* Max time in ms for the command */
	uint16_t checksum;
};

void get_random(struct io_interface *ioif);
bool wake(struct io_interface *ioif);

#endif
