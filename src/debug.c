#include <assert.h>
#include <debug.h>
#include <stdint.h>
#include <stdlib.h>

void hexdump(char *message, void *buf, size_t len)
{
	int i;
	uint8_t *b = (uint8_t *)buf;

	assert(message);
	assert(buf);
	assert(len);

	logd("%s: ", message);
	for (i = 0; i < len; i++)
		logd("0x%02x ", b[i]);
	logd("%s", "\n");
}
