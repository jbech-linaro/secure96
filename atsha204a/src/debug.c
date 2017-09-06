#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include <cmd.h>
#include <debug.h>

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

char *resp2str(uint8_t response_code)
{
	switch (response_code) {
	case 0x00:
		return "Successful";
	case 0x01:
		return "CheckMac miscompare";
	case 0x03:
		return "Parse Error";
	case 0x0F:
		return "Execution Error";
	case 0x11:
		return "Awake";
	case 0xFF:
		return "CRC/Communication Error";
	default:
		return "Unknown error code";
	}
}

char *zone2str(uint8_t zone)
{
	switch (zone) {
	case ZONE_CONFIG:
		return "Config";
	case ZONE_DATA:
	case ZONE_OTP:
		return "Data/OTP";
	default:
		return "Unknown error code";
	}
}
