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
#include <io.h>
#include <status.h>

#define CHECK_RES(str, ret, buf, size) \
	if (ret == STATUS_OK) \
		hexdump(str, buf, size); \
	else { \
		loge("Failed to get %s!\n", str); \
	}

struct atsha204a_testcase {
	char *name;
	int (*func)(void);
};

static struct io_interface *ioif;

static void sha256(uint8_t *msg, size_t len, uint8_t hash[SHA_LEN])
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
	int ret;
	uint8_t buf[RANDOM_LEN];
	logd("\n - Random -\n");
	ret = cmd_get_random(ioif, buf, sizeof(buf));
	CHECK_RES("random", ret, buf, RANDOM_LEN);
	return ret;
}

static int test_devrev(void)
{
	int ret;
	uint8_t buf[DEVREV_LEN];
	logd("\n - DevRev -\n");
	ret = cmd_get_devrev(ioif, buf, sizeof(buf));
	CHECK_RES("devrev", ret, buf, DEVREV_LEN);
	return ret;
}

static int test_nonce(void)
{
	int ret;
	uint8_t buf[NONCE_LONG_LEN];
	uint8_t in_short[NONCE_SHORT_NUMIN] = {
		  0x00, 0x01, 0x02, 0x03,
		  0x04, 0x05, 0x06, 0x07,
		  0x08, 0x09, 0x0a, 0x0b,
		  0x0c, 0x0d, 0x0e, 0x0f,
		  0x10, 0x11, 0x12, 0x13 };
	uint8_t in_long[NONCE_LONG_NUMIN] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
	logd("\n - Nonce (short) -\n");
	ret = cmd_get_nonce(ioif, in_short, sizeof(in_short), NONCE_MODE_UPDATE_SEED, buf, NONCE_LONG_LEN);
	CHECK_RES("nonce", ret, buf, NONCE_LONG_LEN);

	/*
	 * For the passthrough/nonce long we only expect a status
	 * packet, since there is no random number returned back to the
	 * caller.
	 */
	logd("\n - Nonce (long) -\n");
	ret = cmd_get_nonce(ioif, in_long, sizeof(in_long), NONCE_MODE_PASSTHROUGH, buf, 1);
	CHECK_RES("nonce (long) response code", ret, buf, 1);

	return ret;
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
	int ret;
	uint8_t nonce_res;

	uint8_t digest_e[SHA_LEN] = { 0 };

	uint8_t buf_a[MAC_LEN] = { 0 }; /* actual (atsha204a) */
	uint8_t buf_e[MAC_LEN] = { 0 }; /* expected (openssl) */

	uint8_t nonce_in[NONCE_LONG_NUMIN] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
	};

	uint8_t mac_challenge[32] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
	};

	uint8_t digest_in[] = {
		/* 32 bytes: Data[SlotID] */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* 1 byte: Opcode */
		0x15,
		/* 1 byte: Param1 */
		0x02,
		/* 2 bytes: Param2[LSB], Param2[MSB] */
		0x00, 0x00,
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
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
	};

	uint8_t mac_in[] = {
		/* 32 bytes: TempKey[0:31]; populated with digest */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* 32 bytes: Challenge[0:31] */
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		/* 1 byte: Opcode */
		0x08,
		/* 1 byte: Mode */
		0x06,
		/* 2 bytes: Param2[LSB], Param2[MSB] */
		0x00, 0x00,
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

	logd("\n - Gendig -\n");

	ret = cmd_get_nonce(ioif, nonce_in, sizeof(nonce_in),
			    NONCE_MODE_PASSTHROUGH, &nonce_res, sizeof(nonce_res));
	CHECK_RES("nonce (long) response code", ret, &nonce_res,
		  sizeof(nonce_res));

	ret = cmd_gen_dig(ioif, NULL, 0, ZONE_DATA, 0);
	if (ret != STATUS_OK) {
		loge("Could not generate digest\n");
	}

	ret = cmd_get_mac(ioif, mac_challenge, sizeof(mac_challenge), 0x06,
			  0, buf_a, sizeof(buf_a));
	CHECK_RES("actual mac", ret, buf_a, MAC_LEN);

	sha256(digest_in, sizeof(digest_in), digest_e);
	hexdump("expected digest", digest_e, MAC_LEN);

	memcpy(mac_in, digest_e, 32);
	sha256(mac_in, sizeof(mac_in), buf_e);
	hexdump("expected mac", buf_e, MAC_LEN);

	return memcmp(buf_a, buf_e, MAC_LEN);
}

static int test_hmac(void)
{
	int ret;
	uint8_t nonce_res;
	unsigned int hmac_len = 0;

	uint8_t buf_a[HMAC_LEN] = { 0 }; /* actual (atsha204a) */
	uint8_t buf_e[HMAC_LEN] = { 0 }; /* expected (openssl) */

	uint8_t in_long[NONCE_LONG_NUMIN] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

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

	logd("\n - HMAC -\n");
	ret = cmd_get_nonce(ioif, in_long, sizeof(in_long), NONCE_MODE_PASSTHROUGH,
			    &nonce_res, sizeof(nonce_res));
	CHECK_RES("nonce (long) response code", ret, &nonce_res, sizeof(nonce_res));

	/* 1 << 2 is to set the TempKey.SourceFlag, since we just above did a
	 * passthrough nonce and therefore we used no internal randomness. */
	ret = cmd_get_hmac(ioif, 1 << 2, 0, buf_a);
	CHECK_RES("hmac", ret, buf_a, HMAC_LEN);

	hmac_sha256(msg, sizeof(msg), key, sizeof(key), buf_e, &hmac_len);

	return memcmp(buf_a, buf_e, HMAC_LEN);
}

static int test_mac(void)
{
	int ret;
	uint8_t nonce_buf[NONCE_SHORT_LEN] = { 0 };

	uint8_t buf_a[MAC_LEN] = { 0 }; /* actual (atsha204a) */
	uint8_t buf_e[MAC_LEN] = { 0 }; /* expected (openssl) */

	uint8_t in_long[NONCE_LONG_NUMIN] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

	uint8_t mac_challenge[32] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

	uint8_t computed_in[] = {
		/* 32 bytes: TempKey[0:31] */
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		/* 32 bytes: Challenge[0:31] */
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		/* 1 byte: Opcode */
		0x08,
		/* 1 byte: Mode */
		0x06,
		/* 2 bytes: Param2[LSB], Param2[MSB] */
		0x00, 0x00,
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

	logd("\n - MAC -\n");
	ret = cmd_get_nonce(ioif, in_long, sizeof(in_long), NONCE_MODE_PASSTHROUGH, nonce_buf, sizeof(nonce_buf));
	CHECK_RES("Nonce for MAC", ret, nonce_buf, sizeof(nonce_buf));

	/*
	 * Mode = 0x06
	 * Bit 0: The 2nd 32 bytes are taken from the input challenge
	 * Bit 1: The 1st 32 bytes are filled with TempKey
	 * Bit 2: Value of TempKey.SourceFlag
	 * Bit 3: MBZ
	 * Bit 4: Don't include OTP[0:10]; fill with zeros
	 * Bit 5: Don't include OTP[0:7]; fill with zeros
	 * Bit 6: Don't include SN[2:3] and SN[4:7]; fill with zeros
	 * Bit 7: MBZ
	 */
	ret = cmd_get_mac(ioif, mac_challenge, sizeof(mac_challenge), 0x06, 0, buf_a, sizeof(buf_a));
	CHECK_RES("MAC", ret, buf_a, MAC_LEN);

	/* Now compute the expected value */
	sha256(computed_in, sizeof(computed_in), buf_e);
	hexdump("expected mac", buf_e, MAC_LEN);

	return memcmp(buf_a, buf_e, MAC_LEN);
}

static int test_checkmac(void)
{
	int ret;

	uint8_t resp;
	uint8_t nonce_buf[NONCE_LONG_LEN] = { 0 };;
	uint8_t mac_buf[MAC_LEN] = { 0 };
	uint8_t in_long[NONCE_LONG_NUMIN] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
	uint8_t mac_challenge[32] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
	uint8_t check_mac_data[77] = { 0 };

	logd("\n - MAC -\n");
	ret = cmd_get_nonce(ioif, in_long, sizeof(in_long), NONCE_MODE_PASSTHROUGH, nonce_buf, 1);
	CHECK_RES("nonce for mac", ret, nonce_buf, 1);
	/*
	 * Mode = 0x06
	 * Bit 0: The 2nd 32 bytes are taken from the input challenge
	 * Bit 1: The 1st 32 bytes are filled with TempKey
	 * Bit 2: Value of TempKey.SourceFlag
	 * Bit 3: MBZ
	 * Bit 4: Don't include OTP[0:10]; fill with zeros
	 * Bit 5: Don't include OTP[0:7]; fill with zeros
	 * Bit 6: Don't include SN[2:3] and SN[4:7]; fill with zeros
	 * Bit 7: MBZ
	 */
	ret = cmd_get_mac(ioif, mac_challenge, sizeof(mac_challenge), 0x06, 0, mac_buf, sizeof(mac_buf));
	CHECK_RES("mac", ret, mac_buf, MAC_LEN);

	logd("\n - CheckMAC -\n");
	/* Data 1 (32 bytes): ClientChal
	 * Data 2 (32 bytes): ClientResp
	 * Data 3 (13 bytes): OtherData
	 */
	memcpy(check_mac_data, mac_challenge, 32);
	memcpy(check_mac_data + 32, mac_buf, 32);
	/* OtherData contains the parameters used for the MAC command */
	check_mac_data[64] = 0x08; /* Opcode */
	check_mac_data[65] = 0x06; /* Mode */
	check_mac_data[66] = 0x00; /* Slot ID MSB */
	check_mac_data[67] = 0x00; /* Slot ID LSB */
	check_mac_data[68] = 0x00; /* OTP[8] or zero */
	check_mac_data[69] = 0x00; /* OTP[9] or zero */
	check_mac_data[70] = 0x00; /* OTP[10] or zero */
	check_mac_data[71] = 0x00; /* SN[4] or zero */
	check_mac_data[72] = 0x00; /* SN[5] or zero */
	check_mac_data[73] = 0x00; /* SN[6] or zero */
	check_mac_data[74] = 0x00; /* SN[7] or zero */
	check_mac_data[75] = 0x00; /* SN[2] or zero */
	check_mac_data[76] = 0x00; /* SN[3] or zero */

	ret = cmd_get_nonce(ioif, in_long, sizeof(in_long), NONCE_MODE_PASSTHROUGH, nonce_buf, 1);
	CHECK_RES("nonce for mac", ret, nonce_buf, 1);

	/* Mode = 0x05
	 * Bit 0: The 2nd 32 bytes are taken from ClientChal
	 * Bit 1: The 1st 32 bytes are filled with TempKey
	 * Bit 2: Value of TempKey.SourceFlag
	 * Bit 3: MBZ
	 * Bit 4: MBZ
	 * Bit 5: 8-bytes of SHA message set to zero
	 * Bit 6: MBZ
	 * Bit 7: MBZ
	 */
	ret = cmd_check_mac(ioif, check_mac_data, sizeof(check_mac_data), 0x06, 0, &resp, 1);
	CHECK_RES("checkmac", ret, &resp, 1);

	return ret;
}

static int test_sha(void)
{
	int ret;

	/* The caller is required to pass the padding and length
	 * bytes of the message (Sect. 13.1)
	 */
	uint8_t sha_in[64] = {
		/* Message */
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		/* Padding */
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* Length */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00
	};
	uint8_t buf_a[SHA_LEN] = { 0 }; /* actual (atsha204a) */
	uint8_t buf_e[SHA_LEN] = { 0 }; /* expected (openssl) */

	logd("\n - SHA \n");
	ret = cmd_sha(ioif, NULL, 0, buf_a, 1);
	CHECK_RES("sha init", ret, buf_a, 1);

	ret = cmd_sha(ioif, sha_in, sizeof(sha_in), buf_a, SHA_LEN);
	CHECK_RES("sha compute", ret, buf_a, SHA_LEN);

	/* Now compute the expected value. We only pass the message
	 * part as the padding is computed by openssl.
	 */
	sha256(sha_in, 32, buf_e);
	hexdump("expected hash", buf_e, SHA_LEN);

	return memcmp(buf_a, buf_e, SHA_LEN);
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
	int ret;
	uint8_t in_long[NONCE_LONG_NUMIN] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
	};
	uint8_t buf[NONCE_SHORT_LEN] = { 0 };
	uint8_t key_e[SLOT_DATA_SIZE] = { 0 };

	uint8_t mac_a[MAC_LEN] = { 0 }; /* actual (atsha204a) */
	uint8_t mac_e[MAC_LEN] = { 0 }; /* expected (openssl) */

	uint8_t sha_in[] = {
		/* 32 bytes: Parent key (ie Key 0) */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* 1 byte: Opcode */
		0x1c,
		/* 1 byte: Param1 */
		0x04,
		/* 2 bytes: Param2[LSB], Param2[MSB] */
		0x06, 0x00,
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
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	};

	uint8_t mac_in[] = {
		/* 32 bytes: Slot6 - Populate with the key */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* 32 bytes: Challenge[0:31] */
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		/* 1 byte: Opcode */
		0x08,
		/* 1 byte: Mode */
		0x00,
		/* 2 bytes: Param2[LSB], Param2[MSB] */
		0x06, 0x00,
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

	logd("\n - Derive Key -\n");
	ret = cmd_get_nonce(ioif, in_long, sizeof(in_long), NONCE_MODE_PASSTHROUGH, buf, 1);
	CHECK_RES("nonce for derive key", ret, buf, 1);

	/* Only test the case where the new key is derived from the parent key
	 * (aka Create). Testing a rolling key not as straightforward, as we can't
	 * verify the expected value unless we know the current key. It would
	 * still be possible if we used UpdateCount to perform as many rolling
	 * operations during the computation of the expected value.
	 */
	ret = cmd_derive_key(ioif, 1 << 2, 0x06, NULL, 0);
	if (ret != STATUS_OK) {
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
	ret = cmd_get_mac(ioif, in_long, sizeof(in_long), 0x00, 0x06, mac_a, sizeof(mac_a));
	CHECK_RES("actual mac", ret, mac_a, sizeof(mac_a));

	sha256(sha_in, sizeof(sha_in), key_e);
	hexdump("key", key_e, sizeof(key_e));

	/* Populate the top 32 bytes with the key */
	memcpy(mac_in, key_e, sizeof(key_e));

	sha256(mac_in, sizeof(mac_in), mac_e);
	hexdump("expected mac", mac_e, MAC_LEN);

out:
	return memcmp(mac_a, mac_e, MAC_LEN);
}

static int test_pause(void)
{
	int ret;
	logd("\n - Pause -\n");
	ret = cmd_pause(ioif, 0xf00);
	if (ret != STATUS_OK) {
		logd("Device paused\n");
	}
	return ret;
}

int main(int argc, char *argv[])
{
	int ret = STATUS_EXEC_ERROR;

	struct atsha204a_testcase tests[] = {
		{"Random", test_random},
		{"DevRev", test_devrev},
		{"Nonce", test_nonce},
		{"GenDig", test_gendig},
		{"HMAC", test_hmac},
		{"MAC", test_mac},
		{"CheckMAC", test_checkmac},
		{"SHA", test_sha},
		{"DeriveKey", test_derivekey},
		{"Pause", test_pause},
		{0, NULL}
	};

	printf("ATSHA204A on %s @ addr 0x%x\n", I2C_DEVICE, ATSHA204A_ADDR);

	ret = register_io_interface(IO_I2C_LINUX, &ioif);
	if (ret != STATUS_OK) {
	    logd("Couldn't register the IO interface\n");
	    goto out;
	}

	ret = at204_open(ioif);

	logd("\n - Wake -\n");
	while (!cmd_wake(ioif)) {};
	logd("ATSHA204A is awake\n");

	for (int i = 0 ; tests[i].func != NULL; i++) {
		ret = tests[i].func();
		printf("%-10s %s\n", tests[i].name,
		       ret ? "\x1B[31m[FAIL]\033[0m" : "\x1B[32m[PASS]\033[0m");
	}
	printf("Done\n");
out:
	ret = at204_close(ioif);
	if (ret != STATUS_OK) {
		ret = STATUS_EXEC_ERROR;
		logd("Couldn't close the device\n");
	}

	return ret;
}
