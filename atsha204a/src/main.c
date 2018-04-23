/*
 * Copyright 2017, Linaro Ltd and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmd.h>
#include <crc.h>
#include <debug.h>
#include <device.h>
#include <io.h>
#include <personalize.h>
#include <status.h>

extern struct slot_config slot_configs[8];
extern uint8_t zone_data[ZONE_DATA_SIZE];
extern uint8_t zone_otp[ZONE_OTP_SIZE];

void usage(char *fname)
{
	fprintf(stderr, "Usage: %s <option>\n", fname);
	fprintf(stderr, "\n");
	fprintf(stderr, "Available options:\n");
	fprintf(stderr, "  -i, --info		Display device info\n");
	fprintf(stderr, "  -d, --dump-config	Dump config zone\n");
	fprintf(stderr, "  -p, --personalize	Write config and data\n");
	fprintf(stderr, "  -h, --help		Display this message\n");
	fprintf(stderr, "  -v, --version	Display version\n");
	fprintf(stderr, "\n");
}

int confirm()
{
	char resp[4];
	int confirm = 1;

	do {
		printf("Continue? [yN] ");
		fgets(resp, sizeof(resp), stdin);
		if (resp[0] == 'y' || resp[0] == 'Y') { /* yolo works here too */
			confirm = 0;
			break;
		} else if (resp[0] == 'n' || resp[0] == 'N' || resp[0] == '\n') {
			confirm = 1;
			break;
		}
		printf("Invalid option. ");
	} while(1);

	return confirm;
}

static int get_config_zone(struct io_interface *ioif, uint8_t *buf, size_t size)
{
	int i;
	int ret = STATUS_EXEC_ERROR;

	if (size != ZONE_CONFIG_SIZE || !buf)
		return STATUS_BAD_PARAMETERS;

	/* Read word by word into the buffer */
	for (i = 0; i < ZONE_CONFIG_SIZE / WORD_SIZE; i++) {
		ret = cmd_read(ioif, ZONE_CONFIG, i, 0, WORD_SIZE,
			       buf + (i * WORD_SIZE), WORD_SIZE);
		if (ret != STATUS_OK)
			break;
	}

	return ret;
}

static int get_serialnbr(struct io_interface *ioif, uint8_t *buf, size_t size)
{
	/* Only 9 are used, but we read 4 bytes at a time */
	uint8_t serial_nbr[12] = { 0 };
	int ret = STATUS_EXEC_ERROR;

	if (size != SERIALNUM_LEN || !buf)
		return STATUS_BAD_PARAMETERS;

	ret = cmd_read(ioif, ZONE_CONFIG, SERIALNBR_ADDR0_3,
		       SERIALNBR_OFFSET0_3, WORD_SIZE, serial_nbr,
		       SERIALNBR_SIZE0_3);
	if (ret != STATUS_OK)
		goto err;

	ret = cmd_read(ioif, ZONE_CONFIG, SERIALNBR_ADDR4_7,
		       SERIALNBR_OFFSET4_7, WORD_SIZE, serial_nbr +
		       SERIALNBR_SIZE0_3, SERIALNBR_SIZE4_7);
	if (ret != STATUS_OK)
		goto err;

	ret = cmd_read(ioif, ZONE_CONFIG, SERIALNBR_ADDR8, SERIALNBR_OFFSET8,
		       WORD_SIZE, serial_nbr + SERIALNBR_SIZE0_3 + SERIALNBR_SIZE4_7,
		       SERIALNBR_SIZE8);
err:
	if (ret == STATUS_OK)
		memcpy(buf, serial_nbr, size);
	else
		memset(buf, 0, size);

	return ret;
}

static int get_otp_mode(struct io_interface *ioif, uint8_t *otp_mode)
{
	uint32_t _otp_mode = 0;
	int ret = STATUS_EXEC_ERROR;

	if (!otp_mode)
		return ret;

	ret = cmd_read(ioif, ZONE_CONFIG, OTP_CONFIG_ADDR, OTP_CONFIG_OFFSET,
		       WORD_SIZE, &_otp_mode, OTP_CONFIG_SIZE);

	*otp_mode = _otp_mode & 0xFF;

	return ret;
}

static int get_lock_config(struct io_interface *ioif, uint8_t *lock_config)
{
	uint8_t _lock_config = 0;
	int ret = STATUS_EXEC_ERROR;

	ret = cmd_read(ioif, ZONE_CONFIG, LOCK_CONFIG_ADDR, LOCK_CONFIG_OFFSET,
		       WORD_SIZE, &_lock_config, LOCK_CONFIG_SIZE);

	if (ret == STATUS_OK)
		*lock_config = _lock_config;
	else
		*lock_config = 0;

	return ret;
}

int get_lock_data(struct io_interface *ioif, uint8_t *lock_data)
{
	uint8_t _lock_data = 0;
	int ret = STATUS_EXEC_ERROR;

	ret = cmd_read(ioif, ZONE_CONFIG, LOCK_DATA_ADDR, LOCK_DATA_OFFSET,
		       WORD_SIZE, &_lock_data, LOCK_DATA_SIZE);

	if (ret == STATUS_OK)
		*lock_data = _lock_data;
	else
		*lock_data = 0;

	return ret;
}

bool is_configuration_locked(struct io_interface *ioif)
{
	uint8_t lock_config;
	int ret = get_lock_config(ioif, &lock_config);
	if (ret != STATUS_OK) {
		loge("Couldn't get lock config\n");
		return false;
	}

	return lock_config == LOCK_CONFIG_LOCKED;
}

bool is_data_zone_locked(struct io_interface *ioif)
{
	uint8_t lock_data;
	int ret = get_lock_data(ioif, &lock_data);
	if (ret != STATUS_OK) {
		loge("Couldn't get lock data\n");
		return false;
	}

	return lock_data == LOCK_DATA_LOCKED;
}

int program_data_slots(struct io_interface *ioif, uint16_t *crc)
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

int program_otp_zone(struct io_interface *ioif, uint16_t *crc)
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

int program_slot_configs(struct io_interface *ioif)
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

int lock_config_zone(struct io_interface *ioif)
{
	uint16_t crc = 0;
	uint8_t config_zone[ZONE_CONFIG_SIZE] = { 0 };
	int ret = STATUS_EXEC_ERROR;

	ret = get_config_zone(ioif, config_zone, sizeof(config_zone));
	if (ret != STATUS_OK)
		goto out;

	hexdump("config_zone", config_zone, ZONE_CONFIG_SIZE);

	crc = calculate_crc16(config_zone, sizeof(config_zone), crc);

	ret = cmd_lock_zone(ioif, ZONE_CONFIG, &crc);
out:
	return ret;
}

static int atsha204a_personalize(struct io_interface *ioif)
{
	uint8_t ret = STATUS_EXEC_ERROR;

	if (is_configuration_locked(ioif)) {
		loge("Device config already locked\n");
		goto out;
	} else {
		ret = program_slot_configs(ioif);
		if (ret != STATUS_OK) {
			loge("Could not program config\n");
			goto out;
		}

		ret = lock_config_zone(ioif);
		if (ret != STATUS_OK) {
			loge("Could not lock config\n");
			goto out;
		}
	}

	if (is_data_zone_locked(ioif)) {
		loge("Device data already locked\n");
		goto out;
	} else {
		uint16_t crc = 0;

		ret = program_data_slots(ioif, &crc);
		if (ret != STATUS_OK) {
			loge("Could not program data\n");
			goto out;
		}

		logd("Intermediate CRC: 0x%04x\n", crc);
		ret = program_otp_zone(ioif, &crc);
		if (ret != STATUS_OK) {
			goto out;
			loge("Could not program OTP\n");
		}

		logd("Final CRC: 0x%04x\n", crc);
		ret = cmd_lock_zone(ioif, ZONE_DATA, &crc);
		if (ret != STATUS_OK) {
			loge("Could not lock data");
			goto out;
		}
	}
out:
	return ret;
}

int main(int argc, char *argv[])
{
	int i;
	int ret = STATUS_EXEC_ERROR;
	struct io_interface *ioif;

	uint8_t otp_mode;
	uint8_t lock_config;
	uint8_t lock_data;
	uint8_t devrev[DEVREV_LEN];
	uint8_t sn[SERIALNUM_LEN];
	uint8_t config_zone[ZONE_CONFIG_SIZE] = {0};

	int opt;
	int opt_idx = 0;
	static struct option long_opts[] = {
		{"dump-config",  no_argument, 0, 'd'},
		{"personalize",  no_argument, 0, 'p'},
		{"help",         no_argument, 0, 'h'},
		{"info",         no_argument, 0, 'i'},
		{"version",      no_argument, 0, 'v'},
		{0, 0, 0, 0}
	};

	ret = register_io_interface(IO_I2C_LINUX, &ioif);
	if (ret != STATUS_OK) {
	    fprintf(stderr, "Couldn't register the IO interface\n");
	    goto out;
	}

	ret = at204_open(ioif);

	if (argc == 1) {
		usage(argv[0]);
		return -1;
	}

	while (1) {

		opt_idx = 0;
		opt = getopt_long(argc, argv, "idphv", long_opts, &opt_idx);

		if (opt == -1) /* End of options. */
			break;

		switch (opt) {
		case 'i':

			while (!cmd_wake(ioif)) {};

			ret = cmd_get_devrev(ioif, devrev, sizeof(devrev));
			if (ret != STATUS_OK) {
				fprintf(stderr, "Failed to get DevRev\n");
				goto out;
			}
			ret = get_serialnbr(ioif, sn, sizeof(sn));
			if (ret != STATUS_OK) {
				fprintf(stderr, "Failed to get SN\n");
				goto out;
			}
			ret = get_otp_mode(ioif, &otp_mode);
			if (ret != STATUS_OK) {
				fprintf(stderr, "Failed to get OTP mode\n");
				goto out;
			}
			ret = get_lock_config(ioif, &lock_config);
			if (ret != STATUS_OK) {
				fprintf(stderr, "Failed to get LockConfig\n");
				goto out;
			}
			ret = get_lock_data(ioif, &lock_data);
			if (ret != STATUS_OK) {
				fprintf(stderr, "Failed to get LockData\n");
				goto out;
			}

			printf("ATSHA204A on %s @ addr 0x%x\n", I2C_DEVICE, ATSHA204A_ADDR);
			printf("Device Revision:    %02x%02x%02x%02x\n",
				devrev[0], devrev[1], devrev[2], devrev[3]);
			printf("Serial Number:      %02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
				sn[0], sn[1], sn[2], sn[3], sn[4], sn[5], sn[6], sn[7], sn[8]);
			printf("Config Zone locked: %s\n",
				lock_config == LOCK_CONFIG_UNLOCKED ? "No" : "Yes");
			printf("Data Zone locked:   %s\n",
				lock_data == LOCK_DATA_UNLOCKED ? "No" : "Yes");
			printf("OTP mode:           %s\n", otpmode2str(otp_mode));
			break;
		case 'd':

			while (!cmd_wake(ioif)) {};

			ret = get_config_zone(ioif, config_zone, sizeof(config_zone));
			if (ret != STATUS_OK) {
				fprintf(stderr, "Could not read config\n");
				goto out;
			}
			for (i = 0; i < sizeof(config_zone); i ++) {
				printf("%c", config_zone[i]);
			}
			break;
		case 'p':
			printf("WARNING: Personalizing the device is an one-time operation! ");
			if (confirm())
				goto out;

			while (!cmd_wake(ioif)) {};

			ret = atsha204a_personalize(ioif);
			if (ret != STATUS_OK) {
				fprintf(stderr, "Could not personalize the device\n");
				goto out;
			}
			printf("Done\n");
			break;
		case 'h':
			usage(argv[0]);
			break;
		case 'v':
			printf("Version: %s\n", PROJECT_VERSION);
		default:
			break;
		}
	}

out:
	ret = at204_close(ioif);
	if (ret != STATUS_OK) {
		ret = STATUS_EXEC_ERROR;
		fprintf(stderr, "Couldn't close the device\n");
	}
	return ret;
}
