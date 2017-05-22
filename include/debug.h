#ifndef __DEBUG_H
#define __DEBUG_H
#include <stdlib.h>
#include <stdio.h>

#ifndef EXT_DEBUG_INFO

#ifdef DEBUG
#define logd(fmt, ...) \
	fprintf(stdout, fmt, ##__VA_ARGS__);
#else
#define logd(fmt, ...)
#endif

#else

#ifdef DEBUG
#define logd(fmt, ...) \
		fprintf(stdout, "[%s : %d]: " fmt,
			__func__, __LINE__, ##__VA_ARGS__;
#else
#define logd(fmt, ...)
#endif

#endif

void hexdump(char *message, void *buf, size_t len);

#endif
