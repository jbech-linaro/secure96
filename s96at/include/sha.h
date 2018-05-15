/*
 * Copyright 2017, Linaro Ltd and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __SHA_H
#define __SHA_H

#define SHA_BLOCK_LEN		64
#define SHA_PADDING_LENGTH_LEN	8

/* Apply SHA padding as defined in FIPS 180-2.
 * The message buffer is modified in-place.
 */
int sha_apply_padding(uint8_t *buf, size_t buf_len, size_t msg_len,
		      size_t *padded_msg_len);

#endif
