/*
 * Copyright 2017, Linaro Ltd and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <string.h>

#include <cmd.h>
#include <crc.h>
#include <io.h>
#include <s96at.h>
#include <sha.h>
#include <status.h>

uint8_t s96at_init(enum s96at_device device, enum s96at_io_interface_type iface,
		   struct s96at_desc *desc)
{
	uint8_t ret;

	desc->dev = device;

	ret = register_io_interface(IO_I2C_LINUX, &desc->ioif);
	if (ret != STATUS_OK)
	    return ret;

	ret = at204_open(desc->ioif);

	return ret;
}

uint8_t s96at_cleanup(struct s96at_desc *desc)
{
	uint8_t ret = S96AT_STATUS_OK;

	if (desc->ioif)
		ret = at204_close(desc->ioif);

	return ret;
}

uint8_t s96at_wake(struct s96at_desc *desc)
{
	uint8_t ret;
	uint8_t buf;

	if (at204_wake(desc->ioif) != STATUS_OK)
		return S96AT_STATUS_EXEC_ERROR;

	ret = at204_read(desc->ioif, &buf, sizeof(buf));

	if (ret == S96AT_STATUS_OK && buf == S96AT_STATUS_READY)
		ret = S96AT_STATUS_READY;

	return ret;
}

uint8_t s96at_derive_key(struct s96at_desc *desc, uint8_t slot, uint8_t *mac,
			 uint32_t flags)
{
	size_t len;
	uint8_t tempkey_source;

	if ((flags != S96AT_FLAG_TEMPKEY_SOURCE_INPUT) &&
	   (flags != S96AT_FLAG_TEMPKEY_SOURCE_RANDOM))
		return S96AT_STATUS_BAD_PARAMETERS;

	if (mac)
		len = S96AT_MAC_LEN;
	else
		len = 0;

	if (flags & S96AT_FLAG_TEMPKEY_SOURCE_INPUT)
		tempkey_source = (TEMPKEY_SOURCE_INPUT << MAC_MODE_TEMPKEY_SOURCE_SHIFT);

	if (flags & S96AT_FLAG_TEMPKEY_SOURCE_RANDOM)
		tempkey_source = (TEMPKEY_SOURCE_RANDOM << MAC_MODE_TEMPKEY_SOURCE_SHIFT);

	return cmd_derive_key(desc->ioif, tempkey_source, slot, mac, len);
}

uint8_t s96at_pause(struct s96at_desc *desc, uint8_t selector)
{
	return cmd_pause(desc->ioif, selector);
}

uint16_t s96at_get_crc(const uint8_t *buf, size_t buf_len, uint16_t current_crc)
{
	return calculate_crc16(buf, buf_len, current_crc);
}

uint8_t s96at_get_random(struct s96at_desc *desc, enum s96at_random_mode mode,
		     uint8_t *buf)
{
	uint8_t ret;

	ret = cmd_get_random(desc->ioif, mode, buf, S96AT_RANDOM_LEN);

	if (ret != STATUS_OK)
		memset(buf, 0, S96AT_RANDOM_LEN);

	return ret;
}

uint8_t s96at_get_devrev(struct s96at_desc *desc, uint8_t *buf)
{
	return cmd_get_devrev(desc->ioif, buf, S96AT_DEVREV_LEN);
}

uint8_t s96at_gen_digest(struct s96at_desc *desc, enum s96at_zone zone,
			 uint8_t slot, uint8_t *data)
{
	size_t data_len;
	if (data)
		data_len = S96AT_GENDIG_INPUT_LEN;
	else
		data_len = 0;

	return cmd_gen_dig(desc->ioif, data, data_len, zone, slot);
}

uint8_t s96at_gen_nonce(struct s96at_desc *desc, enum s96at_nonce_mode mode,
		    uint8_t *data, uint8_t *random)
{
	uint8_t ret;
	uint8_t *out;
	uint8_t nonce_resp;
	size_t out_len;
	size_t data_len;

	if (!data)
		return S96AT_STATUS_BAD_PARAMETERS;

	if (mode == S96AT_NONCE_MODE_RANDOM && !random)
		return S96AT_STATUS_BAD_PARAMETERS;

	if (mode == S96AT_NONCE_MODE_PASSTHROUGH) {
		data_len = S96AT_CHALLENGE_LEN;
		out = &nonce_resp;
		out_len = sizeof(nonce_resp);
	} else {
		data_len = S96AT_NONCE_INPUT_LEN;
		out = random;
		out_len = S96AT_RANDOM_LEN;
	}

	ret = cmd_get_nonce(desc->ioif, data, data_len, mode, out, out_len);

	if (ret != STATUS_OK && random)
		memset(random, 0, S96AT_RANDOM_LEN);

	return ret;
}

uint8_t s96at_get_mac(struct s96at_desc *desc, enum s96at_mac_mode mode, uint8_t slot,
		  const uint8_t *challenge, uint32_t flags, uint8_t *mac)
{
	uint8_t ret;
	uint8_t challenge_len;

	if ((mode == S96AT_MAC_MODE_0 || mode == S96AT_MAC_MODE_2) && !challenge)
		return S96AT_STATUS_BAD_PARAMETERS;

	if ((flags & S96AT_FLAG_TEMPKEY_SOURCE_INPUT) &&
	   (flags & S96AT_FLAG_TEMPKEY_SOURCE_RANDOM))
		return S96AT_STATUS_BAD_PARAMETERS;

	if (!(flags & S96AT_FLAG_TEMPKEY_SOURCE_INPUT) &&
	   !(flags & S96AT_FLAG_TEMPKEY_SOURCE_RANDOM))
		return S96AT_STATUS_BAD_PARAMETERS;

	if ((flags & S96AT_FLAG_USE_OTP_64_BITS) && (flags & S96AT_FLAG_USE_OTP_88_BITS))
		return S96AT_STATUS_BAD_PARAMETERS;

	if (mode == S96AT_MAC_MODE_0 || mode == S96AT_MAC_MODE_2)
		challenge_len = S96AT_CHALLENGE_LEN;
	else
		challenge_len = 0;

	if (flags & S96AT_FLAG_TEMPKEY_SOURCE_INPUT)
		mode |= (TEMPKEY_SOURCE_INPUT << MAC_MODE_TEMPKEY_SOURCE_SHIFT);

	if (flags & S96AT_FLAG_TEMPKEY_SOURCE_RANDOM)
		mode |= (TEMPKEY_SOURCE_RANDOM << MAC_MODE_TEMPKEY_SOURCE_SHIFT);

	if (flags & S96AT_FLAG_USE_OTP_64_BITS)
		mode |= (1 << MAC_MODE_USE_OTP_64_BITS_SHIFT);

	if (flags & S96AT_FLAG_USE_OTP_88_BITS)
		mode |= (1 << MAC_MODE_USE_OTP_88_BITS_SHIFT);

	if (flags & S96AT_FLAG_USE_SN)
		mode |= (1 << MAC_MODE_USE_SN_SHIFT);

	ret = cmd_get_mac(desc->ioif, (uint8_t *)challenge, challenge_len, mode, slot,
			  mac, S96AT_MAC_LEN);

	if (ret != STATUS_OK)
		memset(mac, 0, S96AT_MAC_LEN);

	return ret;
}

uint8_t s96at_check_mac(struct s96at_desc *desc, enum s96at_mac_mode mode,
			uint8_t slot, uint32_t flags, struct s96at_check_mac_data *data,
			const uint8_t *mac)
{
	uint8_t ret;
	uint8_t check_mac_data[77] = { 0 };
	uint8_t check_mac_resp;
	uint8_t mac_mode = mode;

	/* Mode used in CheckMac */
	if ((mode == S96AT_MAC_MODE_0 || mode == S96AT_MAC_MODE_2) && !data->challenge)
		return S96AT_STATUS_BAD_PARAMETERS;

	if (flags & S96AT_FLAG_TEMPKEY_SOURCE_INPUT)
		mode |= (TEMPKEY_SOURCE_INPUT << MAC_MODE_TEMPKEY_SOURCE_SHIFT);

	if (flags & S96AT_FLAG_TEMPKEY_SOURCE_RANDOM)
		mode |= (TEMPKEY_SOURCE_RANDOM << MAC_MODE_TEMPKEY_SOURCE_SHIFT);

	/* Mode used in MAC */
	if ((mac_mode == S96AT_MAC_MODE_0 || mac_mode == S96AT_MAC_MODE_2) && !data->challenge)
		return S96AT_STATUS_BAD_PARAMETERS;

	if (data->flags & S96AT_FLAG_TEMPKEY_SOURCE_INPUT)
		mac_mode |= (TEMPKEY_SOURCE_INPUT << MAC_MODE_TEMPKEY_SOURCE_SHIFT);

	if (data->flags & S96AT_FLAG_TEMPKEY_SOURCE_RANDOM)
		mac_mode |= (TEMPKEY_SOURCE_RANDOM << MAC_MODE_TEMPKEY_SOURCE_SHIFT);

	if (data->flags & S96AT_FLAG_USE_OTP_64_BITS)
		mac_mode |= (1 << MAC_MODE_USE_OTP_64_BITS_SHIFT);

	if (data->flags & S96AT_FLAG_USE_OTP_88_BITS)
		mac_mode |= (1 << MAC_MODE_USE_OTP_88_BITS_SHIFT);

	if (data->flags & S96AT_FLAG_USE_SN)
		mac_mode |= (1 << MAC_MODE_USE_SN_SHIFT);

	/* Challenge sent to the client */
	memcpy(check_mac_data, data->challenge, S96AT_CHALLENGE_LEN);

	/* Response generated by the client */
	memcpy(check_mac_data + S96AT_CHALLENGE_LEN, mac, S96AT_MAC_LEN);

	/* OtherData contains the parameters used for the MAC command */
	check_mac_data[64] = OPCODE_MAC; /* Opcode */
	check_mac_data[65] = mac_mode;
	check_mac_data[66] = 0x00; 	 /* Slot ID MSB */
	check_mac_data[67] = data->slot; /* Slot ID LSB */

	if (data->otp) {
		check_mac_data[68] = data->otp[8];
		check_mac_data[69] = data->otp[9];
		check_mac_data[70] = data->otp[10];
	}

	if (data->sn) {
		check_mac_data[71] = data->sn[4];
		check_mac_data[72] = data->sn[5];
		check_mac_data[73] = data->sn[6];
		check_mac_data[74] = data->sn[7];
		check_mac_data[75] = data->sn[2];
		check_mac_data[76] = data->sn[3];
	}

	ret = cmd_check_mac(desc->ioif, check_mac_data, 77, mode, slot,
			    &check_mac_resp, sizeof(check_mac_resp));
	if (ret == STATUS_OK)
		ret = check_mac_resp;

	return ret;
}

uint8_t s96at_get_hmac(struct s96at_desc *desc, uint8_t slot, uint32_t flags,
		   uint8_t *hmac)
{
	uint8_t mode = 0;

	if (flags & S96AT_FLAG_TEMPKEY_SOURCE_INPUT)
		mode |= (TEMPKEY_SOURCE_INPUT << MAC_MODE_TEMPKEY_SOURCE_SHIFT);

	if (flags & S96AT_FLAG_TEMPKEY_SOURCE_RANDOM)
		mode |= (TEMPKEY_SOURCE_RANDOM << MAC_MODE_TEMPKEY_SOURCE_SHIFT);

	if (flags & S96AT_FLAG_USE_OTP_64_BITS)
		mode |= (1 << MAC_MODE_USE_OTP_64_BITS_SHIFT);

	if (flags & S96AT_FLAG_USE_OTP_88_BITS)
		mode |= (1 << MAC_MODE_USE_OTP_88_BITS_SHIFT);

	if (flags & S96AT_FLAG_USE_SN)
		mode |= (1 << MAC_MODE_USE_SN_SHIFT);

	return cmd_get_hmac(desc->ioif, mode, slot, hmac);
}

uint8_t s96at_get_lock_config(struct s96at_desc *desc, uint8_t *lock_config)
{
	uint8_t _lock_config;
	int ret = STATUS_EXEC_ERROR;

	ret = cmd_read(desc->ioif, ZONE_CONFIG, LOCK_CONFIG_ADDR, LOCK_CONFIG_OFFSET,
		       WORD_SIZE, &_lock_config, LOCK_CONFIG_SIZE);

	if (ret == STATUS_OK)
		*lock_config = _lock_config;
	else
		*lock_config = 0;

	return ret;
}

uint8_t s96at_get_lock_data(struct s96at_desc *desc, uint8_t *lock_data)
{
	uint8_t _lock_data = 0;
	int ret = STATUS_EXEC_ERROR;

	ret = cmd_read(desc->ioif, ZONE_CONFIG, LOCK_DATA_ADDR, LOCK_DATA_OFFSET,
		       WORD_SIZE, &_lock_data, LOCK_DATA_SIZE);

	if (ret == STATUS_OK)
		*lock_data = _lock_data;
	else
		*lock_data = 0;

	return ret;
}

uint8_t s96at_get_otp_mode(struct s96at_desc *desc, uint8_t *otp_mode)
{
	uint32_t _otp_mode = 0;
	int ret = STATUS_EXEC_ERROR;

	if (!otp_mode)
		return ret;

	ret = cmd_read(desc->ioif, ZONE_CONFIG, OTP_CONFIG_ADDR, OTP_CONFIG_OFFSET,
		       WORD_SIZE, &_otp_mode, OTP_CONFIG_SIZE);

	*otp_mode = _otp_mode & 0xFF;

	return ret;
}

uint8_t s96at_get_serialnbr(struct s96at_desc *desc, uint8_t *buf)
{
	int ret = STATUS_EXEC_ERROR;
	uint8_t serial_nbr[S96AT_SERIAL_NUMBER_LEN] = { 0 };

	if (!buf)
		return S96AT_STATUS_BAD_PARAMETERS;

	ret = cmd_read(desc->ioif, ZONE_CONFIG, SERIALNBR_ADDR0_3,
		       SERIALNBR_OFFSET0_3, WORD_SIZE, serial_nbr,
		       SERIALNBR_SIZE0_3);

	if (ret != STATUS_OK)
		goto err;

	ret = cmd_read(desc->ioif, ZONE_CONFIG, SERIALNBR_ADDR4_7,
		       SERIALNBR_OFFSET4_7, WORD_SIZE, serial_nbr +
		       SERIALNBR_SIZE0_3, SERIALNBR_SIZE4_7);

	if (ret != STATUS_OK)
		goto err;

	ret = cmd_read(desc->ioif, ZONE_CONFIG, SERIALNBR_ADDR8, SERIALNBR_OFFSET8,
		       WORD_SIZE, serial_nbr + SERIALNBR_SIZE0_3 + SERIALNBR_SIZE4_7,
		       SERIALNBR_SIZE8);
err:
	if (ret == STATUS_OK)
		memcpy(buf, serial_nbr, S96AT_SERIAL_NUMBER_LEN);
	else
		memset(buf, 0, S96AT_SERIAL_NUMBER_LEN);

	return ret;
}

uint8_t s96at_get_zone_config(struct s96at_desc *desc, uint8_t *buf)
{
	int i;
	int ret = STATUS_EXEC_ERROR;

	if (!buf)
		return S96AT_STATUS_BAD_PARAMETERS;

	/* Read word by word into the buffer */
	for (i = 0; i < ZONE_CONFIG_SIZE / WORD_SIZE; i++) {
		ret = cmd_read(desc->ioif, ZONE_CONFIG, i, 0, WORD_SIZE,
			       buf + (i * WORD_SIZE), WORD_SIZE);
		if (ret != STATUS_OK)
			break;
	}

	return ret;
}

uint8_t s96at_get_sha(struct s96at_desc *desc, uint8_t *buf,
		  size_t buf_len, size_t msg_len, uint8_t *hash)
{
	int i;
	uint8_t ret;
	uint8_t sha_resp;
	size_t padded_msg_len;

	if (!buf || buf_len < 0 || msg_len < 0)
		return S96AT_STATUS_BAD_PARAMETERS;

	if (buf_len <= msg_len)
		return S96AT_STATUS_BAD_PARAMETERS;

	if (buf_len % SHA_BLOCK_LEN)
		return S96AT_STATUS_BAD_PARAMETERS;

	ret = sha_apply_padding(buf, buf_len, msg_len, &padded_msg_len);
	if (ret != S96AT_STATUS_OK)
		return ret;

	ret = cmd_sha(desc->ioif, SHA_MODE_INIT, NULL, 0, &sha_resp,
		      sizeof(sha_resp));
	if (ret != STATUS_OK)
		return ret;

	for (i = 0; i < padded_msg_len / SHA_BLOCK_LEN; i++) {
		ret = cmd_sha(desc->ioif, SHA_MODE_COMPUTE, buf + SHA_BLOCK_LEN * i,
			      SHA_BLOCK_LEN, hash, S96AT_SHA_LEN);
		if (ret != STATUS_OK)
			goto out;
	}
out:
	return ret;
}

uint8_t s96at_lock_zone(struct s96at_desc *desc, enum s96at_zone zone, uint16_t crc)
{
	return cmd_lock_zone(desc->ioif, zone, &crc);
}

uint8_t s96at_read(struct s96at_desc *desc, enum s96at_zone zone, uint8_t id,
		   uint8_t *buf)
{
	uint8_t ret = STATUS_EXEC_ERROR;
	uint8_t addr;
	uint8_t length;

	switch (zone) {
	case S96AT_ZONE_CONFIG:
		if (id > ZONE_CONFIG_NUM_WORDS - 1)
			return S96AT_STATUS_BAD_PARAMETERS;
		addr = id;
		length = S96AT_READ_CONFIG_LEN;
		break;
	case S96AT_ZONE_DATA:
		if (id > ZONE_DATA_NUM_SLOTS - 1)
			return S96AT_STATUS_BAD_PARAMETERS;
		addr = SLOT_ADDR(id);
		length = S96AT_READ_DATA_LEN;
		break;
	case S96AT_ZONE_OTP:
		if (id > ZONE_OTP_NUM_WORDS - 1)
			return S96AT_STATUS_BAD_PARAMETERS;
		addr = id;
		length = S96AT_READ_OTP_LEN;
		break;
	}

	ret = cmd_read(desc->ioif, zone, addr, 0, length, buf, length);

	if (ret != STATUS_OK)
		memset(buf, 0, length);

	return ret;
}

uint8_t s96at_write(struct s96at_desc *desc, enum s96at_zone zone, uint8_t id,
		    uint32_t flags, const uint8_t *buf)
{
	uint8_t addr;
	uint8_t length;
	uint8_t encrypted  = false;

	switch (zone) {
	case S96AT_ZONE_CONFIG:
		if (id > ZONE_CONFIG_NUM_WORDS - 1)
			return S96AT_STATUS_BAD_PARAMETERS;
		addr = id;
		length = S96AT_READ_CONFIG_LEN;
		break;
	case S96AT_ZONE_DATA:
		if (id > ZONE_DATA_NUM_SLOTS - 1)
			return S96AT_STATUS_BAD_PARAMETERS;
		addr = SLOT_ADDR(id);
		length = S96AT_READ_DATA_LEN;
		break;
	case S96AT_ZONE_OTP:
		if (id > ZONE_OTP_NUM_WORDS - 1)
			return S96AT_STATUS_BAD_PARAMETERS;
		addr = id;
		length = S96AT_READ_OTP_LEN;
		break;
	}

	if (flags & S96AT_FLAG_ENCRYPT)
		encrypted = true;

	return cmd_write(desc->ioif, zone, addr, encrypted, buf, length);
}

