/*
 * Copyright 2017, Linaro Ltd and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __DEVICE_H
#define __DEVICE_H

#include <io.h>

/* Default I2C address for the ATSHA204a */
#define ATSHA204A_ADDR 0x64

/* Word address values */
#define PKT_FUNC_RESET		0x0
#define PKT_FUNC_SLEEP		0x1
#define PKT_FUNC_IDLE		0x2
#define PKT_FUNC_COMMAND	0x3

uint8_t device_idle(struct io_interface *ioif);

uint8_t device_reset(struct io_interface *ioif);

uint8_t device_sleep(struct io_interface *ioif);

#endif
