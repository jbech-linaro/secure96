#include <stdlib.h>
#include <string.h>

#include <debug.h>
#include <device.h>
#include <io.h>
#include <status.h>

static struct io_interface *ioif;

int main(int argc, char *argv[])
{
	int fd = -1;
	int ret = STATUS_EXEC_ERROR;

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
		for (i = 0; i < 16; i++)
			cmd_get_slot_config(ioif, i);
	}

	printf("\n - Lock Data -\n");
	cmd_get_lock_data(ioif);

	printf("\n - Lock Config -\n");
	cmd_get_lock_config(ioif);

	printf("\n - Nonce -\n");
	cmd_get_nonce(ioif);

	ret = at204_close(ioif);
	if (ret != STATUS_OK) {
		ret = STATUS_EXEC_ERROR;
		logd("Couldn't close the device\n");
	}
out:
	return ret;
}
