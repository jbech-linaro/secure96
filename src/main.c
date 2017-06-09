#include <stdlib.h>
#include <string.h>

#include <cmd.h>
#include <debug.h>
#include <device.h>
#include <io.h>
#include <status.h>

#define CHECK_RES(str, ret, buf, size) \
	if (ret == STATUS_OK) \
		hexdump(str, buf, size); \
	else { \
		loge("Failed to get %s!\n", str); \
	}

static struct io_interface *ioif;

int main(int argc, char *argv[])
{
	int fd = -1;
	int ret = STATUS_EXEC_ERROR;
	uint8_t dummy[] = {
		0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
		0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
		0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
		0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1
	};
	uint8_t buf[32] = { 0 };

	printf("ATSHA204A on %s @ addr 0x%x\n", I2C_DEVICE, ATSHA204A_ADDR);

	ret = register_io_interface(IO_I2C_LINUX, &ioif);
	if (ret != STATUS_OK) {
	    logd("Couldn't register the IO interface\n");
	    goto out;
	}

	ret = at204_open(ioif);

	printf("\n - Wake -\n");
	while (!cmd_wake(ioif)) {};
	printf("ATSHA204A is awake\n");

	printf("\n - Random -\n");
	ret = cmd_get_random(ioif, buf, RANDOM_LEN);
	CHECK_RES("random", ret, buf, RANDOM_LEN);

	printf("\n - Devrev -\n");
	ret = cmd_get_devrev(ioif, buf, DEVREV_LEN);
	CHECK_RES("devrev", ret, buf, DEVREV_LEN);

	printf("\n - Serial number  -\n");
	ret = cmd_get_serialnbr(ioif, buf, SERIALNUM_LEN);
	CHECK_RES("serial number", ret, buf, SERIALNUM_LEN);

	printf("\n - OTP mode -\n");
	ret = cmd_get_otp_mode(ioif, buf);
	CHECK_RES("otp mode", ret, buf, OTP_CONFIG_SIZE);

	{
		int i;
		printf("\n - Slotconfig  -\n");
		for (i = 0; i < 16; i++) {
			printf("\n");
			ret = cmd_get_slot_config(ioif, i, (uint16_t*)buf);
			CHECK_RES("slotconfig", ret, buf, SLOT_CONFIG_SIZE);
		}
	}

	printf("\n - Lock Data -\n");
	ret = cmd_get_lock_data(ioif, buf);
	CHECK_RES("Lock Data", ret, buf, LOCK_DATA_SIZE);

	printf("\n - Lock Config -\n");
	ret = cmd_get_lock_config(ioif, buf);
	CHECK_RES("Lock Config", ret, buf, LOCK_CONFIG_SIZE);

	{
		uint8_t in[NONCE_SHORT_NUMIN] =
			{ 0x0,   0x1,  0x2,  0x3,
			  0x4,   0x5,  0x6,  0x7,
			  0x8,   0x9,  0xa,  0xb,
			  0xc,   0xd,  0xe,  0xf,
			  0x10, 0x11, 0x12, 0x13 };
		printf("\n - Nonce -\n");
		ret = cmd_get_nonce(ioif, in, sizeof(in), 0, buf, NONCE_LONG_LEN);
		CHECK_RES("nonce", ret, buf, NONCE_LONG_LEN);
	}

	{
		uint8_t conf[] = { 0x01, 0x02, 0x03, 0x04 };
		uint16_t slot_config = 0x0;
		printf("\n - Write Slot Config 0/1 -\n");
		cmd_write(ioif, ZONE_CONFIG, SLOT_CONFIG_ADDR(0x00), conf, sizeof(conf));

		printf("\n - Read Slot Config 0 -\n");
		cmd_get_slot_config(ioif, 0, &slot_config);
		CHECK_RES("slotconfig 0", ret, &slot_config, sizeof(slot_config));

		printf("\n - Read Slot Config 1 -\n");
		cmd_get_slot_config(ioif, 1, &slot_config);
		CHECK_RES("slotconfig 1", ret, &slot_config, sizeof(slot_config));
	}

	printf("\n - Write 0x01 to data zone -\n");
	cmd_write(ioif, ZONE_DATA, SLOT_ADDR(0x01), dummy, sizeof(dummy));

	ret = at204_close(ioif);
	if (ret != STATUS_OK) {
		ret = STATUS_EXEC_ERROR;
		logd("Couldn't close the device\n");
	}
out:
	return ret;
}
