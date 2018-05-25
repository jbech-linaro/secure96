/*
 * Copyright 2017, Linaro Ltd and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __I2C_LINUX_H
#define __I2C_LINUX_H

#include <stdint.h>

struct i2c_linux_ctx {
	uint8_t addr;
	int fd;
};
#endif
