/*
 * Copyright 2017, Linaro Ltd and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <cmd.h>
#include <crc.h>
#include <debug.h>
#include <io.h>
#include <personalize.h>
#include <status.h>

static bool is_configuration_locked(struct io_interface *ioif)
{
	uint8_t lock_config;
	int ret = cmd_get_lock_config(ioif, &lock_config);
	if (ret != STATUS_OK) {
		loge("Couldn't get lock config\n");
		return false;
	}

	return lock_config == LOCK_CONFIG_LOCKED;
}

static bool is_data_zone_locked(struct io_interface *ioif)
{
	uint8_t lock_data;
	int ret = cmd_get_lock_data(ioif, &lock_data);
	if (ret != STATUS_OK) {
		loge("Couldn't get lock data\n");
		return false;
	}

	return lock_data == LOCK_DATA_LOCKED;
}

static int program_data_slots(struct io_interface *ioif, uint16_t *crc)
{
	int i;
	int ret = STATUS_EXEC_ERROR;

	for (i = 0; i < ZONE_DATA_NUM_SLOTS; i++) {
		/*
		 * We must update CRC in each loop to be able to return the CRC
		 * for the entire data area.
		 */
		*crc = calculate_crc16(zone_data + i * SLOT_DATA_SIZE,
				       SLOT_DATA_SIZE, *crc);

		logd("Storing: %d bytes, 0x%02x...0x%02x (running CRC: 0x%04x)\n",
		     SLOT_DATA_SIZE, zone_data[i * SLOT_DATA_SIZE],
		     zone_data[i * SLOT_DATA_SIZE + SLOT_DATA_SIZE - 1], *crc);

		ret = cmd_write(ioif, ZONE_DATA, SLOT_ADDR(i), false,
				zone_data + i * SLOT_DATA_SIZE, SLOT_DATA_SIZE);
		if (ret != STATUS_OK) {
			loge("Failed to program data slot: %d\n", i);
			break;
		}
	}

	return ret;
}

static int program_otp_zone(struct io_interface *ioif, uint16_t *crc)
{
	int i;
	int ret = STATUS_EXEC_ERROR;

	/*
	 * Before Data/OTP zones are locked, only 32-byte values
	 * can be written (section 8.5.18). We therefore need to
	 * program the OTP in terms of blocks, which correspond
	 * to words 0x00 and 0x08.
	 */
	for (i = 0; i < 2; i++) {
		/*
		 * We must update CRC in each loop to be able to return the CRC
		 * for the entire OTP area.
		 */
		*crc = calculate_crc16(zone_otp + i * SLOT_OTP_PROG_SIZE, SLOT_OTP_PROG_SIZE, *crc);

		logd("Storing: %d bytes, 0x%02x...0x%02x (running CRC: 0x%04x)\n",
		     SLOT_OTP_PROG_SIZE, zone_otp[i * SLOT_OTP_PROG_SIZE],
		     zone_otp[i * SLOT_OTP_PROG_SIZE + SLOT_OTP_PROG_SIZE - 1], *crc);

		ret = cmd_write(ioif, ZONE_OTP, i * 0x08, false,
				zone_otp + i * SLOT_OTP_PROG_SIZE, SLOT_OTP_PROG_SIZE);
		if (ret != STATUS_OK) {
			loge("Failed to program OTP address: 0x%02x\n", i * 0x10);
			break;
		}
	}

	return ret;
}

static int program_slot_configs(struct io_interface *ioif)
{
	int i;
	int ret = STATUS_EXEC_ERROR;

	for (i = 0; i < sizeof(slot_configs) / sizeof(struct slot_config); i++) {
		logd("addr: 0x%02x, config[%02d]: 0x%02x 0x%02x, config[%02d]: 0x%02x 0x%02x\n",
		     slot_configs[i].address,
		     2*i, slot_configs[i].value[0], slot_configs[i].value[1],
		     (2*i)+1, slot_configs[i].value[2], slot_configs[i].value[3]);

		ret = cmd_write(ioif, ZONE_CONFIG, slot_configs[i].address, false,
				slot_configs[i].value, sizeof(slot_configs[i].value));

		if (ret != STATUS_OK) {
			loge("Failed to program slot config: %d/%d\n", 2*i, (2*i) + 1);
			break;
		}
	}

	return ret;
}

static int lock_config_zone(struct io_interface *ioif)
{
	uint16_t crc = 0;
	uint8_t config_zone[ZONE_CONFIG_SIZE] = { 0 };
	int ret = STATUS_EXEC_ERROR;

	ret = cmd_get_config_zone(ioif, config_zone, sizeof(config_zone));
	if (ret != STATUS_OK)
		goto out;

	hexdump("config_zone", config_zone, ZONE_CONFIG_SIZE);

	crc = calculate_crc16(config_zone, sizeof(config_zone), crc);

	ret = cmd_lock_zone(ioif, ZONE_CONFIG, &crc);
out:
	return ret;
}

int atsha204a_personalize(struct io_interface *ioif)
{
	int ret = STATUS_OK;

	if (is_configuration_locked(ioif)) {
		logd("Device config already locked\n");
	} else {
		ret = program_slot_configs(ioif);
		if (ret != STATUS_OK)
			goto out;

		ret = lock_config_zone(ioif);
		if (ret != STATUS_OK)
			goto out;
	}

	if (is_data_zone_locked(ioif)) {
		logd("Device data already locked\n");
	} else {
		uint16_t crc = 0;

		ret = program_data_slots(ioif, &crc);
		if (ret != STATUS_OK)
			goto out;

		logd("Intermediate CRC: 0x%04x\n", crc);
		ret = program_otp_zone(ioif, &crc);
		if (ret != STATUS_OK)
			goto out;

		logd("Final CRC: 0x%04x\n", crc);
		ret = cmd_lock_zone(ioif, ZONE_DATA, &crc);
	}
out:
	return ret;
}
