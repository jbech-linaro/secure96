/*
 * Copyright 2017, Linaro Ltd and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <string.h>

#include <cmd.h>
#include <crc.h>
#include <device.h>
#include <io.h>
#include <s96at.h>
#include <sha.h>
#include <status.h>

uint8_t s96at_init(enum s96at_device device, enum s96at_io_interface_type iface,
		   struct s96at_desc *desc)
{
	uint8_t ret;

	desc->dev = device;

	ret = register_io_interface(device, IO_I2C_LINUX, &desc->ioif);
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

uint8_t s96at_idle(struct s96at_desc *desc)
{
	return device_idle(desc->ioif);
}

uint8_t s96at_reset(struct s96at_desc *desc)
{
	return device_reset(desc->ioif);
}

uint8_t s96at_sleep(struct s96at_desc *desc)
{
	return device_sleep(desc->ioif);
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

	return cmd_derive_key(desc, tempkey_source, slot, mac, len);
}

uint8_t s96at_pause(struct s96at_desc *desc, uint8_t selector)
{
	return cmd_pause(desc, selector);
}

uint16_t s96at_crc(const uint8_t *buf, size_t buf_len, uint16_t current_crc)
{
	return calculate_crc16(buf, buf_len, current_crc);
}

uint8_t s96at_ecdh(struct s96at_desc *desc, uint8_t slot, struct s96at_ecc_pub *pub,
		   uint8_t *buf)
{
	uint8_t ret;
	size_t resp_size;
	uint8_t data[ECC_PUB_LEN] = {0};
	uint8_t config_buf[2 * S96AT_BLOCK_SIZE];
	uint8_t resp_buf[S96AT_ECDH_SECRET_LEN];
	uint8_t transmit_secret;

	if (!pub)
		return S96AT_STATUS_BAD_PARAMETERS;

	/* Read SlotConfig to determine whether the slot is configured
	 * to output the ECDH secret. That determines the response length.
	 * In ATECC508A the Configuration Zone is split into 32-byte blocks,
	 * and SlotConfig is spread among the first two blocks.
	 */
	ret = s96at_read_config(desc, 0, config_buf);
	if (ret != S96AT_STATUS_OK)
		return ret;
	ret = s96at_read_config(desc, 1, config_buf + S96AT_BLOCK_SIZE);
	if (ret != S96AT_STATUS_OK)
		return ret;
	transmit_secret = !(config_buf[SLOT_CONFIG_OFFSET +
			    slot * SLOT_CONFIG_ENTRY_SIZE] &
			    ECDH_TRANSMIT_SECRET_MASK);

	if (transmit_secret) {
		if (!buf)
			return S96AT_STATUS_BAD_PARAMETERS;
		resp_size = S96AT_ECDH_SECRET_LEN;
	} else {
		resp_size = 1;
	}
	memcpy(data, pub->x, S96AT_ECC_PUB_X_LEN);
	memcpy(data + S96AT_ECC_PUB_X_LEN, pub->y, S96AT_ECC_PUB_Y_LEN);

	ret = cmd_ecdh(desc, slot, data, ECC_PUB_LEN, resp_buf, resp_size);

	if (transmit_secret)
		memcpy(buf, resp_buf, S96AT_ECDH_SECRET_LEN);

	return ret;
}

uint8_t s96at_get_random(struct s96at_desc *desc, enum s96at_random_mode mode,
		     uint8_t *buf)
{
	uint8_t ret;

	ret = cmd_random(desc, mode, buf, S96AT_RANDOM_LEN);

	if (ret != STATUS_OK)
		memset(buf, 0, S96AT_RANDOM_LEN);

	return ret;
}

uint8_t s96at_get_devrev(struct s96at_desc *desc, uint8_t *buf)
{
	uint8_t ret;

	if (desc->dev == S96AT_ATECC508A)
		ret = cmd_info(desc, INFO_MODE_REVISION, 0, buf, INFO_LEN);
	else
		ret = cmd_devrev(desc, buf, DEVREV_LEN);

	return ret;
}

uint8_t s96at_gen_digest(struct s96at_desc *desc, enum s96at_zone zone,
			 uint8_t slot, uint8_t *data)
{
	size_t data_len;

	if (data)
		data_len = S96AT_GENDIG_INPUT_LEN;
	else
		data_len = 0;

	return cmd_gen_dig(desc, data, data_len, zone, slot);
}

uint8_t s96at_gen_key(struct s96at_desc *desc, enum s96at_genkey_mode mode,
		      uint8_t slot, struct s96at_ecc_pub *pub)
{
	uint8_t ret;
	uint8_t out[ECC_PUB_LEN];

	if (mode == S96AT_GENKEY_MODE_DIGEST) {
		ret = cmd_gen_key(desc, mode, slot, NULL, 0, out, 1);
		if (ret != STATUS_OK)
			return ret;
	} else {
		if (!pub)
			return S96AT_STATUS_BAD_PARAMETERS;

		ret = cmd_gen_key(desc, mode, slot, NULL, 0, out, ECC_PUB_LEN);
		if (ret != STATUS_OK)
			return ret;

		memcpy(pub->x, out, S96AT_ECC_PUB_X_LEN);
		memcpy(pub->y, out + S96AT_ECC_PUB_X_LEN, S96AT_ECC_PUB_Y_LEN);
	}

	return ret;
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

	ret = cmd_nonce(desc, data, data_len, mode, out, out_len);

	if (ret != STATUS_OK && random)
		memset(random, 0, S96AT_RANDOM_LEN);

	return ret;
}

uint8_t s96at_get_counter(struct s96at_desc *desc, uint8_t counter, uint32_t *val)
{
	if (!val)
		return S96AT_STATUS_BAD_PARAMETERS;

	if (counter != 0 && counter != 1)
		return S96AT_STATUS_BAD_PARAMETERS;

	return cmd_counter(desc, COUNTER_MODE_READ, counter, val);
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

	ret = cmd_mac(desc, (uint8_t *)challenge, challenge_len, mode, slot,
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
	check_mac_data[66] = 0x00;	 /* Slot ID MSB */
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

	ret = cmd_check_mac(desc, check_mac_data, 77, mode, slot,
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

	return cmd_hmac(desc, mode, slot, hmac);
}

uint8_t s96at_get_key_valid(struct s96at_desc *desc, uint8_t slot, uint8_t *valid)
{
	uint8_t ret;
	uint8_t resp_buf[INFO_LEN] = {0};

	ret = cmd_info(desc, INFO_MODE_KEY_VALID, slot, resp_buf, INFO_LEN);
	if (ret == STATUS_OK)
		*valid = resp_buf[0];
	else
		*valid = S96AT_KEY_INVALID;

	return ret;
}

uint8_t s96at_get_lock_config(struct s96at_desc *desc, uint8_t *lock_config)
{
	uint8_t _lock_config;
	int ret = STATUS_EXEC_ERROR;

	ret = cmd_read(desc, ZONE_CONFIG, LOCK_CONFIG_ADDR, LOCK_CONFIG_OFFSET,
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

	ret = cmd_read(desc, ZONE_CONFIG, LOCK_DATA_ADDR, LOCK_DATA_OFFSET,
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

	ret = cmd_read(desc, ZONE_CONFIG, OTP_CONFIG_ADDR, OTP_CONFIG_OFFSET,
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

	ret = cmd_read(desc, ZONE_CONFIG, SERIALNBR_ADDR0_3,
		       SERIALNBR_OFFSET0_3, WORD_SIZE, serial_nbr,
		       SERIALNBR_SIZE0_3);

	if (ret != STATUS_OK)
		goto err;

	ret = cmd_read(desc, ZONE_CONFIG, SERIALNBR_ADDR4_7,
		       SERIALNBR_OFFSET4_7, WORD_SIZE, serial_nbr +
		       SERIALNBR_SIZE0_3, SERIALNBR_SIZE4_7);

	if (ret != STATUS_OK)
		goto err;

	ret = cmd_read(desc, ZONE_CONFIG, SERIALNBR_ADDR8, SERIALNBR_OFFSET8,
		       WORD_SIZE, serial_nbr + SERIALNBR_SIZE0_3 + SERIALNBR_SIZE4_7,
		       SERIALNBR_SIZE8);
err:
	if (ret == STATUS_OK)
		memcpy(buf, serial_nbr, S96AT_SERIAL_NUMBER_LEN);
	else
		memset(buf, 0, S96AT_SERIAL_NUMBER_LEN);

	return ret;
}

uint8_t s96at_get_state(struct s96at_desc *desc, uint8_t *buf)
{
	uint8_t ret;
	uint8_t resp_buf[INFO_LEN] = {0};

	ret = cmd_info(desc, INFO_MODE_STATE, 0, resp_buf, INFO_LEN);
	if (ret == STATUS_OK)
		memcpy(buf, resp_buf, S96AT_STATE_LEN);
	else
		memset(buf, 0, S96AT_STATE_LEN);

	return ret;
}

uint8_t s96at_get_sha(struct s96at_desc *desc, uint8_t *buf,
		  size_t buf_len, size_t msg_len, uint8_t *hash)
{
	uint8_t ret;
	uint8_t sha_resp;
	size_t padded_msg_len;

	if (!buf)
		return S96AT_STATUS_BAD_PARAMETERS;

	/* ATECC508A requires a message of at least 64 bytes, and expects the message
	 * to be passed raw. ATSHA204A requires that the SHA-256 padding is applied to
	 * the message before passed to the device, therefore it does not impose any
	 * restrictions on the minimum message length.
	 */
	if (desc->dev == S96AT_ATECC508A) {

		uint8_t *extra_ptr;
		uint8_t extra_len; /* 63 Bytes max */

		if (buf_len < msg_len)
			return S96AT_STATUS_BAD_PARAMETERS;

		if (msg_len < SHA_BLOCK_LEN)
			return S96AT_STATUS_BAD_PARAMETERS;

		ret = cmd_sha(desc, SHA_MODE_INIT, NULL, 0, &sha_resp,
			      sizeof(sha_resp));
		if (ret != STATUS_OK)
			goto out;

		for (int i = 0; i < msg_len / SHA_BLOCK_LEN; i++) {
			ret = cmd_sha(desc, SHA_MODE_COMPUTE, buf + SHA_BLOCK_LEN * i,
				      SHA_BLOCK_LEN, &sha_resp, sizeof(sha_resp));
			if (ret != STATUS_OK)
				goto out;
		}

		extra_len = msg_len % SHA_BLOCK_LEN;
		if (extra_len)
			extra_ptr = buf + SHA_BLOCK_LEN * (msg_len / SHA_BLOCK_LEN);
		else
			extra_ptr = NULL;

		ret = cmd_sha(desc, SHA_MODE_END, extra_ptr, extra_len, hash,
			      S96AT_SHA_LEN);
		if (ret != STATUS_OK)
			goto out;
	} else {

		if (buf_len % SHA_BLOCK_LEN)
			return S96AT_STATUS_BAD_PARAMETERS;

		if (buf_len <= msg_len)
			return S96AT_STATUS_BAD_PARAMETERS;

		ret = sha_apply_padding(buf, buf_len, msg_len, &padded_msg_len);
		if (ret != S96AT_STATUS_OK)
			goto out;

		ret = cmd_sha(desc, SHA_MODE_INIT, NULL, 0, &sha_resp,
			      sizeof(sha_resp));
		if (ret != STATUS_OK)
			goto out;

		for (int i = 0; i < padded_msg_len / SHA_BLOCK_LEN; i++) {
			ret = cmd_sha(desc, SHA_MODE_COMPUTE, buf + SHA_BLOCK_LEN * i,
				      SHA_BLOCK_LEN, hash, S96AT_SHA_LEN);
			if (ret != STATUS_OK)
				goto out;
		}
	}
out:
	return ret;
}

uint8_t s96at_increment_counter(struct s96at_desc *desc, uint8_t counter)
{
	if (counter != 0 && counter != 1)
		return S96AT_STATUS_BAD_PARAMETERS;

	return cmd_counter(desc, COUNTER_MODE_INCREMENT, counter, NULL);
}

uint8_t s96at_lock_zone(struct s96at_desc *desc, enum s96at_zone zone, uint16_t crc)
{
	if (!crc)
		return S96AT_STATUS_BAD_PARAMETERS;

	return cmd_lock(desc, zone, &crc);
}

uint8_t s96at_read_config(struct s96at_desc *desc, uint8_t id, uint8_t *buf)
{
	uint8_t ret;
	uint8_t length;

	if (desc->dev == S96AT_ATSHA204A) {
		if (id > S96AT_ATSHA204A_ZONE_CONFIG_NUM_WORDS - 1)
			return S96AT_STATUS_BAD_PARAMETERS;
		length = S96AT_WORD_SIZE;
	}

	if (desc->dev == S96AT_ATECC508A) {
		if (id > S96AT_ATECC508A_ZONE_CONFIG_NUM_BLOCKS - 1)
			return S96AT_STATUS_BAD_PARAMETERS;
		length = S96AT_BLOCK_SIZE;
		id <<= 3;
	}

	ret = cmd_read(desc, ZONE_CONFIG, id, 0, length, buf, length);

	if (ret != STATUS_OK)
		memset(buf, 0, length);

	return ret;
}

uint8_t s96at_read_data(struct s96at_desc *desc, struct s96at_slot_addr *addr,
			uint32_t flags, uint8_t *buf, size_t length)
{
	uint8_t ret = STATUS_EXEC_ERROR;
	uint8_t _addr;

	if (addr->slot > ZONE_DATA_NUM_SLOTS - 1)
		return S96AT_STATUS_BAD_PARAMETERS;

	if (length != 32 && length != 4)
		return S96AT_STATUS_BAD_PARAMETERS;

	if (length == 32 && addr->offset)
		return S96AT_STATUS_BAD_PARAMETERS;

	_addr = SLOT_ADDR(addr->slot, addr->block, addr->offset);

	ret = cmd_read(desc, ZONE_DATA, _addr, 0, length, buf, length);
	if (ret != STATUS_OK)
		memset(buf, 0, length);

	return ret;
}

uint8_t s96at_read_otp(struct s96at_desc *desc, uint8_t id, uint8_t *buf)
{
	uint8_t ret;
	uint8_t length = WORD_SIZE;

	if (id > ZONE_OTP_NUM_WORDS - 1)
		return S96AT_STATUS_BAD_PARAMETERS;

	ret = cmd_read(desc, ZONE_OTP, id, 0, length, buf, length);
	if (ret != STATUS_OK)
		memset(buf, 0, length);

	return ret;
}

uint8_t s96at_sign(struct s96at_desc *desc, enum s96at_sign_mode mode, uint8_t slot,
		   uint32_t flags, struct s96at_ecdsa_sig *sig)
{
	uint8_t ret;
	uint8_t buf[ECDSA_SIGNATURE_LEN];

	if (!sig)
		return S96AT_STATUS_BAD_PARAMETERS;

	if (flags & S96AT_FLAG_USE_SN)
		mode |= 0x40;

	if (flags & S96AT_FLAG_INVALIDATE)
		mode |= 0x01;

	ret = cmd_sign(desc, mode, slot, buf);
	if (ret != STATUS_OK)
		return ret;

	memcpy(sig->r, buf, S96AT_ECDSA_R_LEN);
	memcpy(sig->s, buf + S96AT_ECDSA_R_LEN, S96AT_ECDSA_S_LEN);

	return ret;
}

uint8_t s96at_update_extra(struct s96at_desc *desc, enum s96at_update_extra_mode mode,
			   uint8_t val)
{
	return cmd_update_extra(desc, mode, val);
}

uint8_t s96at_verify_key(struct s96at_desc *desc, enum s96at_verify_key_mode mode,
			 struct s96at_ecdsa_sig *sig, uint8_t slot, const uint8_t *buf)
{
	uint8_t data[ECDSA_SIGNATURE_LEN + KEY_VALIDATE_MSG_LEN];

	if (!sig)
		return S96AT_STATUS_BAD_PARAMETERS;

	if (!buf)
		return S96AT_STATUS_BAD_PARAMETERS;

	if (slot < 8 || slot > 15)
		return S96AT_STATUS_BAD_PARAMETERS;

	memcpy(data, sig->r, S96AT_ECDSA_R_LEN);
	memcpy(data + S96AT_ECDSA_R_LEN, sig->s, S96AT_ECDSA_S_LEN);
	memcpy(data + ECDSA_SIGNATURE_LEN, buf, 19);

	return cmd_verify(desc, mode, slot, data, ECDSA_SIGNATURE_LEN +
			  KEY_VALIDATE_MSG_LEN);
}

uint8_t s96at_verify_sig(struct s96at_desc *desc, enum s96at_verify_sig_mode mode,
			 struct s96at_ecdsa_sig *sig, uint8_t slot,
			 struct s96at_ecc_pub *pub)
{
	uint8_t data[ECDSA_SIGNATURE_LEN + ECC_PUB_LEN];
	size_t data_len = ECDSA_SIGNATURE_LEN;
	uint8_t _slot = slot;

	if (!sig)
		return S96AT_STATUS_BAD_PARAMETERS;

	if (mode == S96AT_VERIFY_SIG_MODE_EXTERNAL && !pub)
		return S96AT_STATUS_BAD_PARAMETERS;

	memcpy(data, sig->r, S96AT_ECDSA_R_LEN);
	memcpy(data + S96AT_ECDSA_R_LEN, sig->s, S96AT_ECDSA_S_LEN);

	if (mode == S96AT_VERIFY_SIG_MODE_EXTERNAL) {
		memcpy(data + ECDSA_SIGNATURE_LEN, pub->x, S96AT_ECC_PUB_X_LEN);
		memcpy(data + ECDSA_SIGNATURE_LEN + S96AT_ECC_PUB_X_LEN,
		       pub->y, S96AT_ECC_PUB_Y_LEN);
		data_len += ECDSA_SIGNATURE_LEN;
		/* In External mode, KeyId contains the curve type to be used
		 * as encoded in KeyType (Table 9.54 in the ATECC508A spec)
		 */
		_slot = EC_NIST_P256;
	}

	return cmd_verify(desc, mode, _slot, data, data_len);
}

uint8_t s96at_write_config(struct s96at_desc *desc, uint8_t id, const uint8_t *buf)
{
	if (desc->dev == S96AT_ATSHA204A &&
	    id > S96AT_ATSHA204A_ZONE_CONFIG_NUM_WORDS - 1)
		return S96AT_STATUS_BAD_PARAMETERS;

	if (desc->dev == S96AT_ATECC508A &&
	    id > S96AT_ATECC508A_ZONE_CONFIG_NUM_WORDS - 1)
		return S96AT_STATUS_BAD_PARAMETERS;

	return cmd_write(desc, ZONE_CONFIG, id, false, buf, WORD_SIZE);
}

uint8_t s96at_write_data(struct s96at_desc *desc, struct s96at_slot_addr *addr,
			 uint32_t flags, const uint8_t *buf, size_t length)
{
	uint16_t _addr;
	uint8_t encrypted = false;

	if (length != 32 && length != 4)
		return S96AT_STATUS_BAD_PARAMETERS;

	if (addr->slot > ZONE_DATA_NUM_SLOTS - 1)
		return S96AT_STATUS_BAD_PARAMETERS;

	_addr = SLOT_ADDR(addr->slot, addr->block, addr->offset);

	if (flags & S96AT_FLAG_ENCRYPT)
		encrypted = true;

	return cmd_write(desc, ZONE_DATA, _addr, encrypted, buf, length);
}

uint8_t s96at_write_otp(struct s96at_desc *desc, uint8_t id, const uint8_t *buf,
			size_t length)
{
	if (id > ZONE_OTP_NUM_WORDS - 1)
		return S96AT_STATUS_BAD_PARAMETERS;

	if (length != 32 && length != 4)
		return S96AT_STATUS_BAD_PARAMETERS;

	if (length == 32 && !(id == 0 || id == 8))
		return S96AT_STATUS_BAD_PARAMETERS;

	return cmd_write(desc, ZONE_OTP, id, false, buf, length);
}

uint8_t s96at_write_priv(struct s96at_desc *desc, uint8_t slot, uint8_t *priv,
			 uint8_t *mac)
{
	uint8_t ret;
	uint8_t resp;
	uint8_t encrypt = mac ? true : false;

	if (!priv)
		return S96AT_STATUS_BAD_PARAMETERS;

	ret = cmd_privwrite(desc, encrypt, slot, priv, mac, &resp);
	if (ret == S96AT_STATUS_OK && resp != 0)
		ret = S96AT_STATUS_EXEC_ERROR;

	return ret;
}

