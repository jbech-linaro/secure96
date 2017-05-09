#include <stdlib.h>
#include <string.h>

#include <debug.h>
#include <device.h>
#include <io.h>
#include <status.h>

/* Zone encoding, this is typicall param1 */
#define ZONE_CONFIGURATION_BITS 0b00000000 /* 0 */
#define ZONE_OTP_BITS 		0b00000001 /* 1 */
#define ZONE_DATA_BITS 		0b00000010 /* 2 */

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

	while (!wake(ioif)) {};
	printf("ATSHA204A is awake\n");

	get_random(ioif);

	ret = at204_close(ioif);
	if (ret != STATUS_OK) {
		ret = STATUS_EXEC_ERROR;
		logd("Couldn't close the device\n");
	}
out:
	return ret;
}
