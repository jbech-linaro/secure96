/*
 * Copyright 2017, Linaro Ltd and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __STATUS_H
#define __STATUS_H

/* See section 8.1.1 in the ATSHA204A spec
 *     section 9.1.2 in the ATECC508A spec
 */
#define STATUS_OK		0x00
#define STATUS_CHECKMAC_FAIL	0x01
#define STATUS_PARSE_ERROR	0x03
#define STATUS_ECC_FAULT	0x05 /* ATECC508A */
#define STATUS_EXEC_ERROR	0x0f
#define STATUS_AFTER_WAKE	0x11
#define STATUS_WATCHDOG_EXPIRE	0xee /* ATECC508A */
#define STATUS_CRC_ERROR	0xff

#endif

