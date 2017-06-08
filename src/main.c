#include <stdlib.h>
#include <string.h>

#include <cmd.h>
#include <debug.h>
#include <device.h>
#include <io.h>
#include <status.h>

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
	cmd_get_random(ioif);

	printf("\n - Devrev -\n");
	cmd_get_devrev(ioif);

	printf("\n - Serial number  -\n");
	cmd_get_serialnbr(ioif);

	printf("\n - OTP mode -\n");
	cmd_get_otp_mode(ioif);
	{
		int i;
		printf("\n - Slotconfig  -\n");
		for (i = 0; i < 16; i++) {
			printf("\n");
			cmd_get_slot_config(ioif, i);
		}
	}

	printf("\n - Lock Data -\n");
	cmd_get_lock_data(ioif);

	printf("\n - Lock Config -\n");
	cmd_get_lock_config(ioif);

	printf("\n - Nonce -\n");
	cmd_get_nonce(ioif);

	{
		uint8_t conf[] = { 0x01, 0x02, 0x03, 0x04 };
		printf("\n - Write Slot Config 1 -\n");
		cmd_write(ioif, ZONE_CONFIG, SLOT_CONFIG_ADDR(0x00), conf, sizeof(conf));

		printf("\n - Read Slot Config 0/1 -\n");
		cmd_get_slot_config(ioif, 0);

		printf("\n - Read Slot Config 0 -\n");
		cmd_get_slot_config(ioif, 0);

		printf("\n - Read Slot Config 1 -\n");
		cmd_get_slot_config(ioif, 1);
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
