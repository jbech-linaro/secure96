/*
 * Copyright 2017, Linaro Ltd and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <s96at.h>
#include <sha.h>

/* FIPS 180-2 Sect 5.1.1
 *
 * Padding:
 * The message is appended with the bit "1", followed by
 * k zero bits, where k is calculated as the smallest
 * non-negative solution to:
 *
 * msg_len + 1 + k ≡ 448 mod 512
 *
 * Length:
 * An 8 bit block is appended after padding, storing the
 * binary representation of the message length in bits.
 */
int sha_apply_padding(uint8_t *buf, size_t buf_len, size_t msg_len, size_t *padded_msg_len)
{
	int i;
	size_t padding_len;

	/* Padding length in bytes, including the trailing 1 */
	padding_len = (((448 - (msg_len * 8 + 1)) % 512) + 1) / 8;

	/* Make sure we have enough space to store padding and length */
	if (buf_len - msg_len < padding_len + SHA_PADDING_LENGTH_LEN)
		return S96AT_STATUS_PADDING_ERROR;

	memset(buf + msg_len, 0x00, buf_len - msg_len);
	buf[msg_len] |= 0x80;
	for (i = 0; i < SHA_PADDING_LENGTH_LEN; i++) {
		buf[msg_len + padding_len + i] = ((msg_len * 8) >> (56 - i * 8)) & 0xff;
	}
	*padded_msg_len = msg_len + padding_len + SHA_PADDING_LENGTH_LEN;

	return S96AT_STATUS_OK;
}

