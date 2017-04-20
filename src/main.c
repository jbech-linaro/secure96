#include <assert.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define RET_OK 0
#define RET_ERROR 1

#define ATSHA204A_ADDR 0x64

#define CMD_WAKEUP 0x0

#define CRC_LEN 2 /* In bytes */
#define CRC_POLYNOMIAL 0x8005

#define RANDOM_LEN 32


#ifndef EXT_DEBUG_INFO
#define log(fmt, ...) \
	do { if (DEBUG) \
		fprintf(stderr, fmt, ##__VA_ARGS__); \
	} while (0)
#else
#define log(fmt, ...) \
	do { if (DEBUG) \
		fprintf(stderr, "[%s : %d]: " fmt, \
			__func__, __LINE__, ##__VA_ARGS__); \
	} while (0)
#endif

void hexdump(char *message, void *buf, size_t len)
{
#ifdef DEBUG
	int i;
	uint8_t *b = (uint8_t *)buf;

	assert(message);
	assert(buf);
	assert(len);

	log("%s: ", message);
	for (i = 0; i < len; i++)
		printf("0x%02x ", b[i]);
	printf("%s", "\n");
#else
	(void)message;
	(void)buf;
	(void)len;
#endif
}

/* Word address values */
#define PKT_FUNC_RESET		0x0
#define PKT_FUNC_SLEEP		0x1
#define PKT_FUNC_IDLE		0x2
#define PKT_FUNC_COMMAND	0x3

/* Zone encoding, this is typicall param1 */
#define ZONE_CONFIGURATION_BITS 0b00000000 /* 0 */
#define ZONE_OTP_BITS 		0b00000001 /* 1 */
#define ZONE_DATA_BITS 		0b00000010 /* 2 */

#define MAX_CMD_DATA 16

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

/* See section 8.1.1 in the spec */
#define STATUS_OK		0x00
#define STATUS_CHECKMAC_FAIL	0x01
#define STATUS_PARSE_ERROR	0x03
#define STATUS_EXEC_ERROR	0x0f
#define STATUS_AFTER_WAKE	0x11
#define STATUS_CRC_ERROR	0xff

/*
 * IO block, section 8.1
 */
struct io_block {
	uint8_t count;
	void *data;
	uint16_t checksum;
};

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
	uint16_t checksum;
};

/* 
 * FIXME: This uses a hardcoded length of two, which should be OK for all use
 * cases with ATSHA204A. Eventually it would be better to make this generic such
 * that it can be used in a more generic way.
 *
 * Also, the calculate_crc16 comes from the hashlet code and since that is GPL
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

int exit_err(int status, char *msg)
{
	printf("%s", msg);
	exit(status);
}

bool i2c_close(int fd)
{
	return close(fd) == 0;
}

int i2c_configure(void)
{
	int fd = open(I2C_DEVICE, O_RDWR);
	if (fd < 0)
		exit_err(RET_ERROR, "Couldn't open the device\n");

	if (ioctl(fd, I2C_SLAVE, ATSHA204A_ADDR) < 0)
		exit_err(RET_ERROR, "Couldn't talk to the slave\n");

	return fd;
}

bool wake(int fd)
{
	ssize_t n = 0;
	uint32_t cmd = CMD_WAKEUP;
	uint8_t buf[4];
	int crc_offset = 0;

	n = write(fd, &cmd, sizeof(uint32_t));
	if (n <= 0)
		return false;

	n = read(fd, &buf, sizeof(buf));
	if (n == 0)
		return false;

	crc_offset = sizeof(buf) - CRC_LEN;
	return crc_valid(buf, buf + crc_offset, CRC_LEN);
}

/*
 * Calculate the number of bytes used in CRC calculation. Note that this
 * function is dependant on the struct cmd_packet and it is important that the
 * struct is packed.
 */
size_t get_payload_size(struct cmd_packet *p)
{
	return offsetof(struct cmd_packet, data) -
		offsetof(struct cmd_packet, count);
}

size_t get_total_packet_size(struct cmd_packet *p)
{
	return sizeof(p->command) + sizeof(p->count) + sizeof(p->opcode) +
		sizeof(p->param1) + sizeof(p->param2) + p->data_length +
		sizeof(p->checksum);
}

/*
 * Counts the size of the packet, this includes all elements in the struct
 * cmd_packet expect the command type.
 */
size_t get_count_size(struct cmd_packet *p)
{
	return get_total_packet_size(p) - sizeof(p->command);
}

uint16_t get_packet_crc(struct cmd_packet *p)
{
	size_t payload_size = get_payload_size(p);
	log("payload_size: %d\n", payload_size);
	return calculate_crc16(&p->count, payload_size);
}

uint8_t *serialize(struct cmd_packet *p)
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

int atsha204x_read(int fd, void *buf, size_t len)
{
	int n = 0;
	int ret = STATUS_EXEC_ERROR;
	uint8_t *resp_buf = NULL;
	uint8_t resp_len = 0;
	assert(buf);

	/*
	 * Response will be on the format:
	 *  [packet size: 1 byte | data: len bytes | crc: 2 bytes]
	 *
	 * Therefore we need allocate 3 more bytes for the response.
	 */
	resp_len = 1 + len + CRC_LEN;
	resp_buf = calloc(resp_len, sizeof(uint8_t));
	if (!resp_buf)
		return 0;

	n = read(fd, resp_buf, resp_len);

	/*
	 * We expect something to be read and if read, we expect either the size
	 * 4 or the full response length as calculated above.
	 */
	if (n <= 0 || resp_buf[0] != 4 && resp_buf[0] != resp_len)
		goto out;

	if (!crc_valid(resp_buf, resp_buf + (resp_len - CRC_LEN),
		       resp_len - CRC_LEN)) {
		log("Got incorrect CRC\n");
		ret = STATUS_CRC_ERROR;
		goto out;
	}

	/* This indicates a status code or an error, see 8.1.1. */
	if (resp_buf[0] == 4) {
		log("Got status/error code: 0x%0x when reading\n", resp_buf[1]);
		ret = resp_buf[1];
	} else if (resp_buf[0] == resp_len) {
		log("Got the expexted amount of data\n");
		memcpy(buf, resp_buf + 1, len);
		ret = STATUS_OK;
	}
out:
	free(resp_buf);
	return n;
}

void get_random(fd)
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
	log("count: %d\n", req_cmd.count);

	req_cmd.checksum = get_packet_crc(&req_cmd);
	log("checksum: 0x%x\n", req_cmd.checksum);

	serialized_pkt = serialize(&req_cmd);
	if (!serialized_pkt)
		goto err;

	n = write(fd, serialized_pkt, get_total_packet_size(&req_cmd));
	if (n <= 0)
		log("Didn't write anything\n");

	nanosleep(&ts, NULL);
	ret = atsha204x_read(fd, resp_buf, RANDOM_LEN);
	if (ret == STATUS_OK)
		hexdump("random", resp_buf, 32);
err:
	free(serialized_pkt);
}

int main(int argc, char *argv[])
{
	int fd = -1;
	printf("ATSHA204A on %s @ addr 0x%x\n", I2C_DEVICE, ATSHA204A_ADDR);
	fd = i2c_configure();
	if (fd >= 0)
		printf("Successfully opened the device (fd: %d)\n", fd);

	while (!wake(fd)) {};
	printf("ATSHA204A is awake\n");

	get_random(fd);

	if (!i2c_close(fd))
		exit_err(RET_ERROR, "Couldn't close the device\n");
	return 0;
}
