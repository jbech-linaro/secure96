#include <assert.h>
#include <debug.h>
#include <stdint.h>
#include <stdlib.h>

void hexdump(char *message, void *buf, size_t len)
{
#ifdef DEBUG
	int i;
	uint8_t *b = (uint8_t *)buf;

	assert(message);
	assert(buf);
	assert(len);

	printf("%s: ", message);
	for (i = 0; i < len; i++)
		printf("0x%02x ", b[i]);
	printf("%s", "\n");
#else
	(void)message;
	(void)buf;
	(void)len;
#endif
}
