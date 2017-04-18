#include <linux/i2c-dev.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define RET_OK 0
#define RET_ERROR 1

#define ATSHA204A_ADDR 0x64

#define CMD_WAKEUP 0x0

#define CRC_LEN 2 /* In bytes */
#define CRC_POLYNOMIAL 0x8005

#define PRINT_CRC(crc) { \
	int __crc_i = 0;\
	printf("crc: "); \
	for (; __crc_i < CRC_LEN; __crc_i++) \
		printf("0x%02x ", (uint8_t *)crc + __crc_i); \
	printf("\n"); \
	}

/* FIXME: This uses a hardcoded length of two, which should be OK for all use
 * cases with ATSHA204A. Eventually it would be better to make this generic such
 * that it can be used in a more generic way.
 *
 * Also, the calculate_crc16 comes from the hashlet code and since that is GPL
 * code it might be necessary to replace it with some other implementation.
 */
bool crc_valid(const uint8_t *data, uint8_t *crc)
{
	uint16_t buf_crc = 0;
	buf_crc = calculate_crc16(data, 2);
	//PRINT_CRC(&buf_crc);
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
	return crc_valid(buf, buf + crc_offset);
}

int main()
{
	int fd = -1;
	printf("ATSHA204A on %s @ addr 0x%x\n", I2C_DEVICE, ATSHA204A_ADDR);
	fd = i2c_configure();
	if (fd >= 0)
		printf("Successfully opened the device (fd: %d)\n", fd);

	while (!wake(fd)) {};
	printf("ATSHA204A is awake\n");

	if (!i2c_close(fd))
		exit_err(RET_ERROR, "Couldn't close the device\n");
	return 0;
}
