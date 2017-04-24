#ifndef __DEBUG_H
#define __DEBUG_H
#include <stdlib.h>
#include <stdio.h>

#ifndef EXT_DEBUG_INFO
#define logd(fmt, ...) \
	do { if (DEBUG) \
		fprintf(stderr, fmt, ##__VA_ARGS__); \
	} while (0)
#else
#define logd(fmt, ...) \
	do { if (DEBUG) \
		fprintf(stderr, "[%s : %d]: " fmt, \
			__func__, __LINE__, ##__VA_ARGS__); \
	} while (0)
#endif

void hexdump(char *message, void *buf, size_t len);

#endif
