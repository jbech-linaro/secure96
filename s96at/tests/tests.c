/*
 * Copyright 2017, Linaro Ltd and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>

#include <cmd.h>
#include <debug.h>
#include <device.h>
#include <s96at.h>

#define ARRAY_LEN(arr) (sizeof(arr) / sizeof(arr[0]))

#define CHECK_RES(str, ret, buf, size) \
	if (ret == S96AT_STATUS_OK) { \
		if (buf != NULL) \
			hexdump(str, buf, size); \
	} else { \
		loge("Error (%s): 0x%02x %s\n", str, ret, resp2str(ret)); \
	}

struct atsha204a_testcase {
	char *name;
	int (*func)(void);
};

static struct s96at_desc desc;

#define NONCE_DATA 		\
	0x00, 0x01, 0x02, 0x03,	\
	0x04, 0x05, 0x06, 0x07,	\
	0x08, 0x09, 0x0a, 0x0b,	\
	0x0c, 0x0d, 0x0e, 0x0f,	\
	0x10, 0x11, 0x12, 0x13

#define CHALLENGE 					\
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,	\
	0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,	\
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,	\
	0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF	\

uint8_t challenge[S96AT_CHALLENGE_LEN] = { CHALLENGE };

uint8_t nonce_data[S96AT_NONCE_INPUT_LEN] = { NONCE_DATA };

static void sha256(uint8_t *msg, size_t len, uint8_t hash[S96AT_SHA_LEN])
{
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, msg, len);
	SHA256_Final(hash, &ctx);
}

static unsigned char *hmac_sha256(uint8_t *msg, size_t msg_len, uint8_t *key,
				  size_t key_len, uint8_t *hmac, unsigned int *hmac_len)
{
	return HMAC(EVP_sha256(), key, key_len, msg, msg_len, hmac, hmac_len);
}

static int test_random(void)
{
	uint8_t ret;
	uint8_t random[S96AT_RANDOM_LEN];

	ret = s96at_get_random(&desc, S96AT_RANDOM_MODE_UPDATE_SEED, random);
	CHECK_RES("Random", ret, random, ARRAY_LEN(random));

	return ret;
}

static int test_random_no_seed(void)
{
	uint8_t ret;
	uint8_t random[S96AT_RANDOM_LEN];

	ret = s96at_get_random(&desc, S96AT_RANDOM_MODE_UPDATE_SEED, random);
	CHECK_RES("Random", ret, random, ARRAY_LEN(random));

	return ret;
}

static int test_devrev(void)
{
	uint8_t ret;
	uint8_t buf[S96AT_DEVREV_LEN];

	ret = s96at_get_devrev(&desc, buf);
	CHECK_RES("DevRev", ret, buf, ARRAY_LEN(buf));

	return ret;
}

static int test_nonce_random(void)
{
	uint8_t ret;
	uint8_t random[S96AT_RANDOM_LEN];

	ret = s96at_gen_nonce(&desc, S96AT_NONCE_MODE_RANDOM, nonce_data, random);
	CHECK_RES("Nonce", ret, random, ARRAY_LEN(random));

	return ret;
}

static int test_nonce_random_no_seed(void)
{
	uint8_t ret;
	uint8_t random[S96AT_RANDOM_LEN];

	ret = s96at_gen_nonce(&desc, S96AT_NONCE_MODE_RANDOM_NO_SEED, nonce_data, random);
	CHECK_RES("Nonce", ret, random, ARRAY_LEN(random));

	return ret;
}

static int test_nonce_passthrough(void)
{
	return s96at_gen_nonce(&desc, S96AT_NONCE_MODE_PASSTHROUGH, challenge, NULL);
}

/*
 * GenDig
 *
 * Since we cannot access the generated digest directly, we verify
 * GenDig implicitly as follows:
 *
 * 1. Run Nonce to populate TempKey (use pass-through for simplicity)
 * 2. Run GenDigest and compute the expected value
 * 3. Generate MACs both in hardware and software
 * 4. Compare values
 */
static int test_gendig(void)
{
	uint8_t ret;
	uint8_t zone = ZONE_DATA;
	uint8_t slot = 0;
	uint8_t mac_mode = S96AT_MAC_MODE_2;

	uint8_t digest_e[SHA_LEN] = { 0 };

	uint8_t buf_a[MAC_LEN] = { 0 }; /* actual (atsha204a) */
	uint8_t buf_e[MAC_LEN] = { 0 }; /* expected (openssl) */

	ret = s96at_gen_nonce(&desc, S96AT_NONCE_MODE_PASSTHROUGH, challenge, NULL);
	CHECK_RES("Nonce", ret, NULL, 0);

	ret = s96at_gen_digest(&desc, zone, slot, NULL);
	if (ret != S96AT_STATUS_OK) {
		loge("Could not generate digest\n");
	}

	ret = s96at_get_mac(&desc, mac_mode, slot, challenge, S96AT_FLAG_TEMPKEY_SOURCE_INPUT, buf_a);
	CHECK_RES("MAC (actual)", ret, buf_a, ARRAY_LEN(buf_a));

	/* Now compute the expected value */
	uint8_t digest_in[] = {
		/* 32 bytes: Data[SlotID] */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* 1 byte: Opcode */
		OPCODE_GENDIG,
		/* 1 byte: Param1 */
		zone,
		/* 2 bytes: Param2[LSB], Param2[MSB] */
		slot, 0x00,
		/* 1 byte SN[8] */
		0xee,
		/* 2 bytes: SN[0:1] */
		0x01, 0x23,
		/* 25 bytes: MBZ */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,
		/* 32 bytes: TempKey value */
		CHALLENGE
	};

	uint8_t mac_in[] = {
		/* 32 bytes: TempKey[0:31]; populated with digest */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* 32 bytes: Challenge[0:31] */
		CHALLENGE,
		/* 1 byte: Opcode */
		OPCODE_MAC,
		/* 1 byte: Mode */
		mac_mode |= (TEMPKEY_SOURCE_INPUT << MAC_MODE_TEMPKEY_SOURCE_SHIFT),
		/* 2 bytes: Param2[LSB], Param2[MSB] */
		slot, 0x00,
		/* 8 bytes: OTP[0:7] or zeros */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* 3 bytes OTP[8:10] or zeros */
		0x00, 0x00, 0x00,
		/* 1 byte SN[8] */
		0xee,
		/* 4 bytes: SN[4:7] or zeros */
		0x00, 0x00, 0x00, 0x00,
		/* 2 bytes: SN[0:1] */
		0x01, 0x23,
		/* 2 bytes SN[2:3] or zeros */
		0x00, 0x00
	};
	sha256(digest_in, sizeof(digest_in), digest_e);
	hexdump("Digest (expect)", digest_e, MAC_LEN);

	memcpy(mac_in, digest_e, 32);
	sha256(mac_in, sizeof(mac_in), buf_e);
	hexdump("MAC (expect)", buf_e, MAC_LEN);

	return memcmp(buf_a, buf_e, MAC_LEN);
}

static int test_hmac(void)
{
	uint8_t ret;
	unsigned int hmac_len;
	uint8_t slot = 0;

	uint8_t buf_a[S96AT_HMAC_LEN] = { 0 }; /* actual (atsha204a) */
	uint8_t buf_e[S96AT_HMAC_LEN] = { 0 }; /* expected (openssl) */

	uint8_t msg[] = {
		/* 32 bytes: MBZ */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* 32 bytes: TempKey */
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		/* 1 byte: Opcode */
		0x11,
		/* 1 byte: Mode */
		0x04,
		/* 2 bytes: SlotID */
		0x00, 0x00,
		/* 8 bytes: OTP[0:7] or zeros */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* 8 bytes: OTP[8:10] or zeros */
		0x00, 0x00, 0x00,
		/* 1 byte SN[8] */
		0xee,
		/* 4 bytes: SN[4:7] or zeros */
		0x00, 0x00, 0x00, 0x00,
		/* 2 bytes: SN[0:1] */
		0x01, 0x23,
		/* 2 bytes SN[2:3] or zeros */
		0x00, 0x00
	};

	uint8_t key[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	ret = s96at_gen_nonce(&desc, S96AT_NONCE_MODE_PASSTHROUGH, challenge, NULL);
	CHECK_RES("Nonce", ret, NULL, 0);

	ret = s96at_get_hmac(&desc, slot, S96AT_FLAG_TEMPKEY_SOURCE_INPUT, buf_a);
	CHECK_RES("hmac", ret, buf_a, ARRAY_LEN(buf_a));

	hmac_sha256(msg, sizeof(msg), key, sizeof(key), buf_e, &hmac_len);

	return memcmp(buf_a, buf_e, S96AT_HMAC_LEN);
}

static int test_mac_mode0(void)
{
	uint8_t ret = S96AT_STATUS_EXEC_ERROR;

	uint8_t buf_a[S96AT_MAC_LEN] = { 0 }; /* actual (atsha204a) */
	uint8_t buf_e[S96AT_MAC_LEN] = { 0 }; /* expected (openssl) */

	uint8_t slot = 0;
	uint8_t mode = S96AT_MAC_MODE_0; /* 1st 32 bytes: Slot, 2nd 32 bytes: Challenge */

	ret = s96at_gen_nonce(&desc, S96AT_NONCE_MODE_PASSTHROUGH, challenge, NULL);
	CHECK_RES("Nonce", ret, NULL, 0);

	ret = s96at_get_mac(&desc, mode, slot, challenge, S96AT_FLAG_TEMPKEY_SOURCE_INPUT, buf_a);
	CHECK_RES("MAC", ret, buf_a, ARRAY_LEN(buf_a));

	/* Now compute the expected value */
	uint8_t mac_in[] = {
		/* 32 bytes: Slot[0][0:31] */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* 32 bytes: Challenge */
		CHALLENGE,
		/* 1 byte: Opcode */
		OPCODE_MAC,
		/* 1 byte: Mode */
		mode |= (TEMPKEY_SOURCE_INPUT << MAC_MODE_TEMPKEY_SOURCE_SHIFT),
		/* 2 bytes: Param2[LSB], Param2[MSB] */
		slot, 0x00,
		/* 8 bytes: OTP[0:7] or zeros */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* 3 bytes OTP[8:10] or zeros */
		0x00, 0x00, 0x00,
		/* 1 byte SN[8] */
		0xee,
		/* 4 bytes: SN[4:7] or zeros */
		0x00, 0x00, 0x00, 0x00,
		/* 2 bytes: SN[0:1] */
		0x01, 0x23,
		/* 2 bytes SN[2:3] or zeros */
		0x00, 0x00
	};

	sha256(mac_in, ARRAY_LEN(mac_in), buf_e);
	hexdump("Expected mac", buf_e, ARRAY_LEN(buf_e));

	return memcmp(buf_a, buf_e, S96AT_MAC_LEN);
}

static int test_mac_mode1(void)
{
	uint8_t ret = S96AT_STATUS_EXEC_ERROR;

	uint8_t buf_a[S96AT_MAC_LEN] = { 0 }; /* actual (atsha204a) */
	uint8_t buf_e[S96AT_MAC_LEN] = { 0 }; /* expected (openssl) */

	uint8_t slot = 0;
	uint8_t mode = S96AT_MAC_MODE_1; /* 1st 32 bytes: Slot, 2nd 32 bytes: TempKey */

	ret = s96at_gen_nonce(&desc, S96AT_NONCE_MODE_PASSTHROUGH, challenge, NULL);
	CHECK_RES("Nonce", ret, NULL, 0);

	ret = s96at_get_mac(&desc, mode, slot, NULL, S96AT_FLAG_TEMPKEY_SOURCE_INPUT, buf_a);
	CHECK_RES("MAC", ret, buf_a, ARRAY_LEN(buf_a));

	/* Now compute the expected value */
	uint8_t mac_in[] = {
		/* 32 bytes: Slot[0][0:31] */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* 32 bytes: TempKey[0:31] */
		CHALLENGE,
		/* 1 byte: Opcode */
		OPCODE_MAC,
		/* 1 byte: Mode */
		mode |= (TEMPKEY_SOURCE_INPUT << MAC_MODE_TEMPKEY_SOURCE_SHIFT),
		/* 2 bytes: Param2[LSB], Param2[MSB] */
		slot, 0x00,
		/* 8 bytes: OTP[0:7] or zeros */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* 3 bytes OTP[8:10] or zeros */
		0x00, 0x00, 0x00,
		/* 1 byte SN[8] */
		0xee,
		/* 4 bytes: SN[4:7] or zeros */
		0x00, 0x00, 0x00, 0x00,
		/* 2 bytes: SN[0:1] */
		0x01, 0x23,
		/* 2 bytes SN[2:3] or zeros */
		0x00, 0x00
	};
	sha256(mac_in, ARRAY_LEN(mac_in), buf_e);
	hexdump("Expected mac", buf_e, ARRAY_LEN(buf_e));

	return memcmp(buf_a, buf_e, S96AT_MAC_LEN);
}

static int test_mac_mode2(void)
{
	uint8_t ret = S96AT_STATUS_EXEC_ERROR;

	uint8_t buf_a[S96AT_MAC_LEN] = { 0 }; /* actual (atsha204a) */
	uint8_t buf_e[S96AT_MAC_LEN] = { 0 }; /* expected (openssl) */

	uint8_t slot = 0;
	uint8_t mode = S96AT_MAC_MODE_2; /* 1st 32 bytes: TempKey, 2nd 32 bytes: Challenge */

	ret = s96at_gen_nonce(&desc, S96AT_NONCE_MODE_PASSTHROUGH, challenge, NULL);
	CHECK_RES("Nonce", ret, NULL, 0);

	ret = s96at_get_mac(&desc, mode, slot, challenge, S96AT_FLAG_TEMPKEY_SOURCE_INPUT, buf_a);
	CHECK_RES("MAC", ret, buf_a, ARRAY_LEN(buf_a));

	/* Now compute the expected value */
	uint8_t mac_in[] = {
		/* 32 bytes: TempKey[0:31] */
		CHALLENGE,
		/* 32 bytes: Challenge */
		CHALLENGE,
		/* 1 byte: Opcode */
		OPCODE_MAC,
		/* 1 byte: Mode */
		mode |= (TEMPKEY_SOURCE_INPUT << MAC_MODE_TEMPKEY_SOURCE_SHIFT),
		/* 2 bytes: Param2[LSB], Param2[MSB] */
		slot, 0x00,
		/* 8 bytes: OTP[0:7] or zeros */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* 3 bytes OTP[8:10] or zeros */
		0x00, 0x00, 0x00,
		/* 1 byte SN[8] */
		0xee,
		/* 4 bytes: SN[4:7] or zeros */
		0x00, 0x00, 0x00, 0x00,
		/* 2 bytes: SN[0:1] */
		0x01, 0x23,
		/* 2 bytes SN[2:3] or zeros */
		0x00, 0x00
	};

	sha256(mac_in, ARRAY_LEN(mac_in), buf_e);
	hexdump("Expected mac", buf_e, ARRAY_LEN(buf_e));

	return memcmp(buf_a, buf_e, S96AT_MAC_LEN);
}

static int test_mac_mode3(void)
{
	uint8_t ret = S96AT_STATUS_EXEC_ERROR;

	uint8_t buf_a[S96AT_MAC_LEN] = { 0 }; /* actual (atsha204a) */
	uint8_t buf_e[S96AT_MAC_LEN] = { 0 }; /* expected (openssl) */

	uint8_t slot = 0;
	uint8_t mode = S96AT_MAC_MODE_3; /* 1st 32 bytes: TempKey, 2nd 32 bytes: TempKey */

	ret = s96at_gen_nonce(&desc, S96AT_NONCE_MODE_PASSTHROUGH, challenge, NULL);
	CHECK_RES("Nonce", ret, NULL, 0);

	ret = s96at_get_mac(&desc, mode, slot, NULL, S96AT_FLAG_TEMPKEY_SOURCE_INPUT, buf_a);
	CHECK_RES("MAC", ret, buf_a, ARRAY_LEN(buf_a));

	/* Now compute the expected value */
	uint8_t mac_in[] = {
		/* 32 bytes: TempKey[0:31] */
		CHALLENGE,
		/* 32 bytes: TempKey[0:31] */
		CHALLENGE,
		/* 1 byte: Opcode */
		OPCODE_MAC,
		/* 1 byte: Mode */
		mode |= (TEMPKEY_SOURCE_INPUT << MAC_MODE_TEMPKEY_SOURCE_SHIFT),
		/* 2 bytes: Param2[LSB], Param2[MSB] */
		slot, 0x00,
		/* 8 bytes: OTP[0:7] or zeros */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* 3 bytes OTP[8:10] or zeros */
		0x00, 0x00, 0x00,
		/* 1 byte SN[8] */
		0xee,
		/* 4 bytes: SN[4:7] or zeros */
		0x00, 0x00, 0x00, 0x00,
		/* 2 bytes: SN[0:1] */
		0x01, 0x23,
		/* 2 bytes SN[2:3] or zeros */
		0x00, 0x00
	};
	sha256(mac_in, ARRAY_LEN(mac_in), buf_e);
	hexdump("Expected mac", buf_e, ARRAY_LEN(buf_e));

	return memcmp(buf_a, buf_e, S96AT_MAC_LEN);
}

static int test_checkmac_mode0(void)
{
	uint8_t ret;

	uint8_t slot = 0;
	uint8_t mode = S96AT_MAC_MODE_0; /* 1st 32 bytes: Slot, 2nd 32 bytes: Challenge */
	uint32_t flags = S96AT_FLAG_TEMPKEY_SOURCE_INPUT;
	uint8_t mac[S96AT_MAC_LEN] = { 0 };

	struct s96at_check_mac_data data;

	data.challenge = challenge;
	data.slot = 0;
	data.flags = flags;
	data.otp = NULL;
	data.sn = NULL;

	ret = s96at_gen_nonce(&desc, S96AT_NONCE_MODE_PASSTHROUGH, challenge, NULL);
	CHECK_RES("Nonce", ret, NULL, 0);

	ret = s96at_get_mac(&desc, mode, slot, challenge, flags, mac);
	CHECK_RES("MAC", ret, mac, ARRAY_LEN(mac));

	ret = s96at_check_mac(&desc, mode, slot, flags, &data, mac);
	CHECK_RES("CheckMac", ret, NULL, 0);

	return ret;
}

static int test_checkmac_mode1(void)
{
	uint8_t ret;

	uint8_t slot = 0;
	uint8_t mode = S96AT_MAC_MODE_1; /* 1st 32 bytes: Slot, 2nd 32 bytes: TempKey */
	uint32_t flags = S96AT_FLAG_TEMPKEY_SOURCE_INPUT;
	uint8_t mac[S96AT_MAC_LEN] = { 0 };

	struct s96at_check_mac_data data;

	data.challenge = challenge;
	data.slot = 0;
	data.flags = flags;
	data.otp = NULL;
	data.sn = NULL;

	ret = s96at_gen_nonce(&desc, S96AT_NONCE_MODE_PASSTHROUGH, challenge, NULL);
	CHECK_RES("Nonce", ret, NULL, 0);

	ret = s96at_get_mac(&desc, mode, slot, NULL, flags, mac);
	CHECK_RES("MAC", ret, mac, ARRAY_LEN(mac));

	ret = s96at_gen_nonce(&desc, S96AT_NONCE_MODE_PASSTHROUGH, challenge, NULL);
	CHECK_RES("Nonce", ret, NULL, 0);

	ret = s96at_check_mac(&desc, mode, slot, flags, &data, mac);
	CHECK_RES("CheckMac", ret, NULL, 0);

	return ret;
}

static int test_checkmac_mode2(void)
{
	uint8_t ret;

	uint8_t slot = 0;
	uint8_t mode = S96AT_MAC_MODE_2; /* 1st 32 bytes: TempKey, 2nd 32 bytes: Challenge */
	uint32_t flags = S96AT_FLAG_TEMPKEY_SOURCE_INPUT;
	uint8_t mac[S96AT_MAC_LEN] = { 0 };

	struct s96at_check_mac_data data;

	data.challenge = challenge;
	data.slot = 0;
	data.flags = flags;
	data.otp = NULL;
	data.sn = NULL;

	ret = s96at_gen_nonce(&desc, S96AT_NONCE_MODE_PASSTHROUGH, challenge, NULL);
	CHECK_RES("Nonce", ret, NULL, 0);

	ret = s96at_get_mac(&desc, mode, slot, challenge, flags, mac);
	CHECK_RES("MAC", ret, mac, ARRAY_LEN(mac));

	ret = s96at_gen_nonce(&desc, S96AT_NONCE_MODE_PASSTHROUGH, challenge, NULL);
	CHECK_RES("Nonce", ret, NULL, 0);

	ret = s96at_check_mac(&desc, mode, slot, flags, &data, mac);
	CHECK_RES("CheckMac", ret, NULL, 0);

	return ret;
}

static int test_checkmac_mode3(void)
{
	uint8_t ret;

	uint8_t slot = 0;
	uint8_t mode = S96AT_MAC_MODE_3; /* 1st 32 bytes: TempKey, 2nd 32 bytes: TempKey */
	uint32_t flags = S96AT_FLAG_TEMPKEY_SOURCE_INPUT;
	uint8_t mac[S96AT_MAC_LEN] = { 0 };

	struct s96at_check_mac_data data;

	data.challenge = challenge;
	data.slot = 0;
	data.flags = flags;
	data.otp = NULL;
	data.sn = NULL;

	ret = s96at_gen_nonce(&desc, S96AT_NONCE_MODE_PASSTHROUGH, challenge, NULL);
	CHECK_RES("Nonce", ret, NULL, 0);

	ret = s96at_get_mac(&desc, mode, slot, NULL, flags, mac);
	CHECK_RES("MAC", ret, mac, ARRAY_LEN(mac));

	ret = s96at_gen_nonce(&desc, S96AT_NONCE_MODE_PASSTHROUGH, challenge, NULL);
	CHECK_RES("Nonce", ret, NULL, 0);

	ret = s96at_check_mac(&desc, mode, slot, flags, &data, mac);
	CHECK_RES("CheckMac", ret, NULL, 0);

	return ret;
}

static int test_sha(void)
{
	uint8_t ret;

	uint8_t buf_a[S96AT_SHA_LEN] = { 0 }; /* actual (atsha204a) */
	uint8_t buf_e[S96AT_SHA_LEN] = { 0 }; /* expected (openssl) */

	uint8_t sha_in[64] = {
		/* Message (32 bytes) */
		CHALLENGE,
		/* Padding space */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	ret = s96at_get_sha(&desc, sha_in, ARRAY_LEN(sha_in), S96AT_CHALLENGE_LEN, buf_a);
	CHECK_RES("SHA (actual)", ret, buf_a, ARRAY_LEN(buf_a));

	/* Now compute the expected value. We only pass the message
	 * part as the padding is computed by openssl.
	 */
	sha256(sha_in, S96AT_CHALLENGE_LEN, buf_e);
	hexdump("SHA (expect)", buf_e, S96AT_SHA_LEN);

	return memcmp(buf_a, buf_e, S96AT_SHA_LEN);
}

/* DeriveKey
 *
 * Since we cannot read the generated key directly, we
 * validate DeriveKey implicitly as follows:
 *
 * 1. Compute the key
 * 2. Generate the MAC of a known challenge using both actual
 *    and computed keys
 * 3. Compare MACs
 */
static int test_derivekey(void)
{
	uint8_t ret;
	uint8_t key_e[S96AT_KEY_LEN] = { 0 };

	uint8_t slot = 3;

	uint8_t mac_a[S96AT_MAC_LEN] = { 0 }; /* actual (atsha204a) */
	uint8_t mac_e[S96AT_MAC_LEN] = { 0 }; /* expected (openssl) */

	uint8_t sha_in[] = {
		/* 32 bytes: Parent key (ie Key 0) */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* 1 byte: Opcode */
		OPCODE_DERIVEKEY,
		/* 1 byte: Param1 */
		TEMPKEY_SOURCE_INPUT << 2,
		/* 2 bytes: Param2[LSB], Param2[MSB] */
		slot, 0x00,
		/* 1 byte: SN[8] */
		0xee,
		/* 2 bytes: SN[0:1] */
		0x01, 0x23,
		/* 25 bytes: Zero */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,
		/* 32 bytes: TempKey[0:31] */
		CHALLENGE
	};

	uint8_t mac_in[] = {
		/* 32 bytes: Slot6 - Populate with the key */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* 32 bytes: Challenge[0:31] */
		CHALLENGE,
		/* 1 byte: Opcode */
		OPCODE_MAC,
		/* 1 byte: Mode */
		S96AT_MAC_MODE_0 | (TEMPKEY_SOURCE_INPUT << MAC_MODE_TEMPKEY_SOURCE_SHIFT),
		/* 2 bytes: Param2[LSB], Param2[MSB] */
		slot, 0x00,
		/* 8 bytes: OTP[0:7] or zeros */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* 3 bytes OTP[8:10] or zeros */
		0x00, 0x00, 0x00,
		/* 1 byte SN[8] */
		0xee,
		/* 4 bytes: SN[4:7] or zeros */
		0x00, 0x00, 0x00, 0x00,
		/* 2 bytes: SN[0:1] */
		0x01, 0x23,
		/* 2 bytes SN[2:3] or zeros */
		0x00, 0x00
	};

	ret = s96at_gen_nonce(&desc, S96AT_NONCE_MODE_PASSTHROUGH, challenge, NULL);
	CHECK_RES("Nonce", ret, NULL, 0);

	/* Only test the case where the new key is derived from the parent key
	 * (aka Create). Testing a rolling key not as straightforward, as we can't
	 * verify the expected value unless we know the current key. It would
	 * still be possible if we used UpdateCount to perform as many rolling
	 * operations during the computation of the expected value.
	 */
	ret = s96at_derive_key(&desc, slot, NULL, S96AT_FLAG_TEMPKEY_SOURCE_INPUT);
	if (ret != S96AT_STATUS_OK) {
		loge("Derive Key failed\n");
		goto out;
	}

	/*
	 * Mode = 0x00 0000 0000
	 * Bit 0: The 2nd 32 bytes are taken from the input challenge
	 * Bit 1: The 1st 32 bytes are filled from one of the data slots
	 * Bit 2: Value of TempKey.SourceFlag
	 * Bit 3: MBZ
	 * Bit 4: Don't include OTP[0:10]; fill with zeros
	 * Bit 5: Don't include OTP[0:7]; fill with zeros
	 * Bit 6: Don't include SN[2:3] and SN[4:7]; fill with zeros
	 * Bit 7: MBZ
	 */
	ret = s96at_get_mac(&desc, S96AT_MAC_MODE_0, slot, challenge,
			    S96AT_FLAG_TEMPKEY_SOURCE_INPUT, mac_a);
	CHECK_RES("MAC (actual)", ret, mac_a, ARRAY_LEN(mac_a));

	sha256(sha_in, ARRAY_LEN(sha_in), key_e);
	hexdump("Key", key_e, ARRAY_LEN(key_e));

	/* Populate the top 32 bytes with the key */
	memcpy(mac_in, key_e, ARRAY_LEN(key_e));

	sha256(mac_in, ARRAY_LEN(mac_in), mac_e);
	hexdump("MAC (expect)", mac_e, ARRAY_LEN(mac_e));

out:
	return memcmp(mac_a, mac_e, S96AT_MAC_LEN);
}

static int test_read_config(void)
{
	uint8_t ret;
	uint8_t id = 0;
	uint8_t length = 32;
	uint8_t buf[32];

	ret = s96at_read_config(&desc, id, buf, length);
	CHECK_RES("Value", ret, buf, ARRAY_LEN(buf));

	return ret;
}

static int test_read_config_4byte(void)
{
	uint8_t ret;
	uint8_t id = 0;
	uint8_t length = 4;
	uint8_t buf[4];

	ret = s96at_read_config(&desc, id, buf, length);
	CHECK_RES("Value", ret, buf, ARRAY_LEN(buf));

	return ret;
}

static int test_read_data(void)
{
	uint8_t ret;
	uint8_t id = 12;
	size_t length = 32;
	uint8_t buf_a[32];
	uint8_t buf_e[] = {
		0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
		0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
		0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
		0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc
	};

	ret = s96at_read_data(&desc, id, 0, S96AT_FLAG_NONE, buf_a, length);
	CHECK_RES("Value", ret, buf_a, ARRAY_LEN(buf_a));

	return memcmp(buf_a, buf_e, ARRAY_LEN(buf_e));
}

static int test_read_data_4byte(void)
{
	uint8_t ret;
	uint8_t id = 12;
	uint8_t offset = 3;
	size_t length = 4;
	uint8_t buf_a[4];
	uint8_t buf_e[] = {0xcc, 0xcc, 0xcc, 0xcc};

	ret = s96at_read_data(&desc, id, offset, S96AT_FLAG_NONE, buf_a, length);
	CHECK_RES("Value", ret, buf_a, ARRAY_LEN(buf_a));

	return memcmp(buf_a, buf_e, ARRAY_LEN(buf_e));
}

static int test_read_otp(void)
{
	uint8_t ret;
	uint8_t id = 8;
	uint8_t buf_a[4] = {0};
	uint8_t buf_e[] = {0x88, 0x88, 0x88, 0x88};

	ret = s96at_read_otp(&desc, id, buf_a);
	CHECK_RES("Value", ret, buf_a, ARRAY_LEN(buf_a));

	return memcmp(buf_a, buf_e, ARRAY_LEN(buf_e));
}

static int test_reset(void)
{
	uint8_t ret;
	uint8_t random1[S96AT_RANDOM_LEN];
	uint8_t random2[S96AT_RANDOM_LEN];

	ret = s96at_get_random(&desc, S96AT_RANDOM_MODE_UPDATE_SEED, random1);
	CHECK_RES("Random 1", ret, random1, ARRAY_LEN(random1));

	/* Now send a reset and read the FIFO again */
	s96at_reset(&desc);
	ret = at204_read(desc.ioif, random2, ARRAY_LEN(random2));
	CHECK_RES("Random 2", ret, random2, ARRAY_LEN(random2));

	return memcmp(random1, random2, ARRAY_LEN(random2));
}

int main(int argc, char *argv[])
{
	uint8_t ret;
	uint32_t tests_total = 0;
	uint32_t tests_pass = 0;
	uint32_t tests_fail = 0;

	struct atsha204a_testcase tests[] = {
		{"CheckMAC: Mode 0", test_checkmac_mode0},
		{"CheckMAC: Mode 1", test_checkmac_mode1},
		{"CheckMAC: Mode 2", test_checkmac_mode2},
		{"CheckMAC: Mode 3", test_checkmac_mode3},
		{"DeriveKey", test_derivekey},
		{"DevRev", test_devrev},
		{"GenDig", test_gendig},
		{"HMAC", test_hmac},
		{"MAC: Mode 0", test_mac_mode0},
		{"MAC: Mode 1", test_mac_mode1},
		{"MAC: Mode 2", test_mac_mode2},
		{"MAC: Mode 3", test_mac_mode3},
		{"Nonce: Mode Random", test_nonce_random},
		{"Nonce: Mode Random No Seed", test_nonce_random_no_seed},
		{"Nonce: Mode Passthrough", test_nonce_passthrough},
		{"Random: Update seed", test_random},
		{"Random: No update seed", test_random_no_seed},
		{"Read: Config (32 bytes)", test_read_config},
		{"Read: Config (4 bytes)", test_read_config_4byte},
		{"Read: Data (32 bytes)", test_read_data},
		{"Read: Data (4 bytes)", test_read_data_4byte},
		{"Read: OTP", test_read_otp},
		{"Reset", test_reset},
		{"SHA", test_sha},
		{0, NULL}
	};

	printf("ATSHA204A on %s @ addr 0x%x\n", I2C_DEVICE, ATSHA204A_ADDR);

	ret = s96at_init(S96AT_ATSHA204A, IO_I2C_LINUX, &desc);
	if (ret != S96AT_STATUS_OK) {
	    logd("Could not initialize the device\n");
	    goto out;
	}

	logd("\n - Wake -\n");
	while (s96at_wake(&desc) != S96AT_STATUS_READY) {};
	logd("ATSHA204A is awake\n");

	for (int i = 0 ; tests[i].func != NULL; i++) {
		logd("\n - %s -\n", tests[i].name);
		ret = tests[i].func();
		printf("%-30s %s\n", tests[i].name,
		       ret ? "\x1B[31m[FAIL]\033[0m" : "\x1B[32m[PASS]\033[0m");

		/* Force an idle-wake cycle every 4 tests to prevent the watchdog
		 * from putting the device to sleep during the execution of a test.
		 */
		if ((i + 1) % 4 == 0) {
			s96at_idle(&desc);
			while (s96at_wake(&desc) != S96AT_STATUS_READY) {};
		}
		if (ret)
			tests_fail++;
		else
			tests_pass++;
		tests_total++;
	}
	printf("All done. Total: %d Passed: %d Failed: %d\n",
	       tests_total, tests_pass, tests_fail);
out:
	ret = s96at_cleanup(&desc);
	if (ret != S96AT_STATUS_OK)
		logd("Couldn't close the device\n");
	return ret;
}

