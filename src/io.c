#include <debug.h>
#include <io.h>
#include <status.h>

extern struct io_interface i2c_linux;

uint32_t register_io_interface(uint8_t io_interface_type,
			       struct io_interface **ioif)
{
	switch (io_interface_type) {
	case 0:
		*ioif = (struct io_interface *)&i2c_linux;
		break;

	default:
		logd("Unknown IO interface\n");
	}

	return STATUS_OK;
}
