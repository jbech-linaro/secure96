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

static struct io_interface *ioif;

int main(int argc, char *argv[])
{
	int ret = STATUS_EXEC_ERROR;
	uint8_t buf[32] = { 0 };

	printf("ATSHA204A on %s @ addr 0x%x\n", I2C_DEVICE, ATSHA204A_ADDR);

	ret = register_io_interface(IO_I2C_LINUX, &ioif);
	if (ret != STATUS_OK) {
	    logd("Couldn't register the IO interface\n");
	    goto out;
	}

	ret = at204_open(ioif);

	printf("\n - Wake -\n");
	while (!cmd_wake(ioif)) {};
	printf("ATSHA204A is awake\n");

#ifdef PERSONALIZE
	printf("\n - Personalize -\n");
	ret = atsha204a_personalize(ioif);
	if (ret != STATUS_OK) {
		printf("Failed to personalize the device\n");
	}

	printf("\n - Update Extra -\n");
	ret = cmd_update_extra(ioif, 0, 0xff);
	if (ret != STATUS_OK) {
		printf("Failed to personalize the device\n");
	}

	goto out;
#endif

	printf("\n - Random -\n");
	ret = cmd_get_random(ioif, buf, RANDOM_LEN);
	CHECK_RES("random", ret, buf, RANDOM_LEN);

	printf("\n - Devrev -\n");
	ret = cmd_get_devrev(ioif, buf, DEVREV_LEN);
	CHECK_RES("devrev", ret, buf, DEVREV_LEN);

	printf("\n - Serial number  -\n");
	ret = cmd_get_serialnbr(ioif, buf, SERIALNUM_LEN);
	CHECK_RES("serial number", ret, buf, SERIALNUM_LEN);

	printf("\n - OTP mode -\n");
	ret = cmd_get_otp_mode(ioif, buf);
	CHECK_RES("otp mode", ret, buf, OTP_CONFIG_SIZE);

	{
		int i;
		printf("\n - Slotconfig  -\n");
		for (i = 0; i < 16; i++) {
			printf("\n");
			ret = cmd_get_slot_config(ioif, i, (uint16_t*)buf);
			CHECK_RES("slotconfig", ret, buf, SLOT_CONFIG_SIZE);
		}
	}

	printf("\n - Lock Data -\n");
	ret = cmd_get_lock_data(ioif, buf);
	CHECK_RES("Lock Data", ret, buf, LOCK_DATA_SIZE);

	printf("\n - Lock Config -\n");
	ret = cmd_get_lock_config(ioif, buf);
	CHECK_RES("Lock Config", ret, buf, LOCK_CONFIG_SIZE);
	{
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

		printf("\n - Nonce short -\n");
		ret = cmd_get_nonce(ioif, in_short, sizeof(in_short), NONCE_MODE_UPDATE_SEED, buf, NONCE_LONG_LEN);
		CHECK_RES("nonce", ret, buf, NONCE_LONG_LEN);

		/*
		 * For the passthrough/nonce long we only expect a status
		 * packet, since there is no random number returned back to the
		 * caller.
		 */
		printf("\n - Nonce long -\n");
		ret = cmd_get_nonce(ioif, in_long, sizeof(in_long), NONCE_MODE_PASSTHROUGH, buf, 1);
		CHECK_RES("nonce (long) response code", ret, buf, 1);
	}

	printf("\n - Gendig -\n");
        /*
	 * Use slot 3: This is very much configuration dependent,
         * and it works with the default (factory) settings.
         */
	ret = cmd_gen_dig(ioif, NULL, 0, ZONE_DATA, 3);
	if (ret != STATUS_OK) {
		logd("Could not generate digest\n");
	}

#if 0
	printf("\n - HMAC -\n");
	/* 1 << 2 is to set the TempKey.SourceFlag, since we just above did a
	 * passthrough nonce and therefore we used no internal randomness. */
	ret = cmd_get_hmac(ioif, 1 << 2, 0, buf);
	CHECK_RES("hmac", ret, buf, HMAC_LEN);
#endif

	/* MAC - CheckMAC */
	{
		uint8_t resp;
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

		printf("\n - MAC -\n");
		ret = cmd_get_nonce(ioif, in_long, sizeof(in_long), NONCE_MODE_PASSTHROUGH, buf, 1);
		CHECK_RES("nonce for mac", ret, buf, 1);
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

		printf("\n - CheckMAC -\n");
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

		ret = cmd_get_nonce(ioif, in_long, sizeof(in_long), NONCE_MODE_PASSTHROUGH, buf, 1);
		CHECK_RES("nonce for mac", ret, buf, 1);

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
	}

	printf("\n - SHA \n");
	{
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
		ret = cmd_sha(ioif, NULL, 0, buf, 1);
		CHECK_RES("sha init", ret, buf, 1);

		ret = cmd_sha(ioif, sha_in, sizeof(sha_in), buf, SHA_LEN);
		CHECK_RES("sha compute", ret, buf, SHA_LEN);
	}

	printf("\n - Derive Key -\n");
	{
		uint8_t in_long[NONCE_LONG_NUMIN] = {
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
		};
		ret = cmd_get_nonce(ioif, in_long, sizeof(in_long), NONCE_MODE_PASSTHROUGH, buf, 1);
		CHECK_RES("nonce for derive key", ret, buf, 1);

		ret = cmd_derive_key(ioif, 1 << 2, 4, NULL, 0);
		if (ret != STATUS_OK) {
			loge("Derive Key failed\n");
		}
	}

	printf("\n - Pause -\n");
	ret = cmd_pause(ioif, 0xf00);
	if (ret != STATUS_OK) {
		logd("Device paused\n");
	}

out:
	ret = at204_close(ioif);
	if (ret != STATUS_OK) {
		ret = STATUS_EXEC_ERROR;
		logd("Couldn't close the device\n");
	}

	return ret;
}
