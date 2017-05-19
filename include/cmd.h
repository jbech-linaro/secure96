#ifndef __CMD_H
#define __CMD_H
#include <stdint.h>

#include <io.h>

/* Zone encoding, this is typically param1 */
#define ZONE_CONFIGURATION_BITS 0
#define ZONE_OTP_BITS 		1
#define ZONE_DATA_BITS 		2

#define RANDOM_LEN 32
#define DEVREV_LEN 4
#define SERIALNUM_LEN 9
#define OTP_MODE_LEN 4

/* Word address values */
#define PKT_FUNC_RESET		0x0
#define PKT_FUNC_SLEEP		0x1
#define PKT_FUNC_IDLE		0x2
#define PKT_FUNC_COMMAND	0x3

#define CMD_WAKEUP 0x0

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

/* Addresses etc for the configuration zone. */
#define OTP_ADDR		0x4
#define OTP_OFFSET		0x2
#define OTP_SIZE		0x1

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
void cmd_get_serialnbr(struct io_interface *ioif);
void cmd_get_otp_mode(struct io_interface *ioif);

void cmd_config_zone_read(struct io_interface *ioif, uint8_t addr,
			  uint8_t offset, size_t size, uint8_t *data,
			  size_t data_size);

bool wake(struct io_interface *ioif);

#endif
