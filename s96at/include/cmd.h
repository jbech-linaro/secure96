/*
 * Copyright 2017, Linaro Ltd and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __CMD_H
#define __CMD_H
#include <stdint.h>
#include <stdbool.h>

#include <io.h>
#include <s96at_private.h>

/* Zone encoding, this is typically param1 */
enum {
	ZONE_CONFIG = 0,
	ZONE_OTP,
	ZONE_DATA,
	ZONE_END
};

#define ZONE_DATA_NUM_SLOTS    16
#define ZONE_OTP_NUM_WORDS     16

#define LOCK_CONFIG_LOCKED	0x0
#define LOCK_CONFIG_UNLOCKED	0x55
#define LOCK_DATA_LOCKED	0x0
#define LOCK_DATA_UNLOCKED	0x55

#define TEMPKEY_SOURCE_RANDOM	0
#define TEMPKEY_SOURCE_INPUT	1

#define ECC_PUB_LEN		64
#define HMAC_LEN		32
#define RANDOM_LEN		32
#define DEVREV_LEN		4
#define SERIALNUM_LEN		9
#define MAC_LEN			32
#define SHA_LEN			32
#define INFO_LEN		4

#define WORD_SIZE		4
#define MAX_READ_SIZE		32 /* bytes */
#define MAX_WRITE_SIZE		32

#define INFO_MODE_REVISION	0x00
#define INFO_MODE_KEY_VALID	0x01
#define INFO_MODE_STATE		0x02

#define MAC_MODE_TEMPKEY_SOURCE_SHIFT  2
#define MAC_MODE_USE_OTP_88_BITS_SHIFT 4
#define MAC_MODE_USE_OTP_64_BITS_SHIFT 5
#define MAC_MODE_USE_SN_SHIFT          6

#define NONCE_MODE_RANDOM		0
#define NONCE_MODE_RANDOM_NO_SEED	1
#define NONCE_MODE_PASSTHROUGH		3

#define SHA_MODE_INIT		0x00
#define SHA_MODE_COMPUTE	0x01
#define SHA_MODE_END		0x02

/* OP-codes for each command
 *
 * Section 8.5.4 in the ATSHA204A spec
 * Section 9.1.3 in the ATECC508A spec
 */
#define OPCODE_CHECKMAC		0x28
#define OPCODE_COUNTER		0x24 /* ATECC508A */
#define OPCODE_DERIVEKEY	0x1c
#define OPCODE_DEVREV		0x30 /* ATSHA204A */
#define OPCODE_ECDH		0x43 /* ATECC508A */
#define OPCODE_GENDIG		0x15
#define OPCODE_GENKEY		0x40 /* ATECC508A */
#define OPCODE_HMAC		0x11
#define OPCODE_INFO		0x30 /* ATECC508A */
#define OPCODE_LOCK		0x17
#define OPCODE_MAC		0x08
#define OPCODE_NONCE		0x16
#define OPCODE_PAUSE		0x01
#define OPCODE_PRIV_WRITE	0x46 /* ATECC508A */
#define OPCODE_RANDOM		0x1b
#define OPCODE_READ		0x02
#define OPCODE_SHA		0x47
#define OPCODE_SIGN		0x41 /* ATECC508A */
#define OPCODE_UPDATEEXTRA	0x20
#define OPCODE_VERIFY		0x45 /* ATECC508A */
#define OPCODE_WRITE		0x12

/* Addresses etc for the configuration zone. */
#define OTP_CONFIG_ADDR		0x4
#define OTP_CONFIG_OFFSET	0x2
#define OTP_CONFIG_SIZE		0x1

#define SERIALNBR_ADDR0_3	0x0
#define SERIALNBR_OFFSET0_3	0x0
#define SERIALNBR_SIZE0_3	0x4

#define SERIALNBR_ADDR4_7	0x2
#define SERIALNBR_OFFSET4_7	0x0
#define SERIALNBR_SIZE4_7	0x4

#define SERIALNBR_ADDR8		0x3
#define SERIALNBR_OFFSET8	0x0
#define SERIALNBR_SIZE8		0x1

#define LOCK_DATA_ADDR		0x15
#define LOCK_DATA_OFFSET	0x2
#define LOCK_DATA_SIZE		0x1

#define LOCK_CONFIG_ADDR	0x15
#define LOCK_CONFIG_OFFSET	0x3
#define LOCK_CONFIG_SIZE	0x1

/*
 * Base address for slot configuration starts at 0x5. Each word contains slot
 * configuration for two slots.
 */
uint8_t SLOT_CONFIG_ADDR(uint8_t slotnbr);

#define SLOT_DATA_SIZE         32

#define SLOT_ADDR(slot, block, offset) (block << 8 | slot << 3 | offset)
#define SLOT_CONFIG_OFFSET(slotnbr) (slotnbr % 2 ? 2 : 0)
#define SLOT_CONFIG_SIZE 0x2

#define OTP_ADDR(addr) (4 * addr)

uint8_t cmd_check_mac(struct s96at_desc *desc, uint8_t *in, size_t in_size,
		      uint8_t mode, uint16_t slotnbr, uint8_t *out, size_t out_size);

uint8_t cmd_derive_key(struct s96at_desc *desc, uint8_t random, uint8_t slotnbr,
		       uint8_t *buf, size_t size);

uint8_t cmd_devrev(struct s96at_desc *desc, uint8_t *buf, size_t size);

uint8_t cmd_gen_dig(struct s96at_desc *desc, const uint8_t *in, size_t in_size,
		    uint8_t zone, uint16_t slotnbr);

uint8_t cmd_gen_key(struct s96at_desc *desc, uint8_t mode, uint8_t slotnbr,
		    const uint8_t *in, size_t in_size, uint8_t *out, size_t out_len);

uint8_t cmd_hmac(struct s96at_desc *desc, uint8_t mode, uint16_t slotnbr,
		 uint8_t *hmac);

uint8_t cmd_info(struct s96at_desc *desc, uint8_t mode, uint16_t slotnbr,
		 uint8_t *buf, size_t size);

uint8_t cmd_lock(struct s96at_desc *desc, uint8_t zone,
		 const uint16_t *expected_crc);

uint8_t cmd_mac(struct s96at_desc *desc, const uint8_t *in, size_t in_size,
		uint8_t mode, uint16_t slotnbr, uint8_t *out, size_t out_size);

uint8_t cmd_nonce(struct s96at_desc *desc, const uint8_t *in, size_t in_size,
		  uint8_t mode, uint8_t *out, size_t out_size);

uint8_t cmd_pause(struct s96at_desc *desc, uint8_t selector);

uint8_t cmd_random(struct s96at_desc *desc, uint8_t mode, uint8_t *buf, size_t size);

uint8_t cmd_read(struct s96at_desc *desc, uint8_t zone, uint16_t addr,
		 uint8_t offset, size_t size, void *data, size_t data_size);

uint8_t cmd_sha(struct s96at_desc *desc, uint8_t mode, const uint8_t *in,
		size_t in_size, uint8_t *out, size_t out_size);

uint8_t cmd_update_extra(struct s96at_desc *desc, uint8_t mode, uint8_t value);

uint8_t cmd_write(struct s96at_desc *desc, uint8_t zone, uint16_t addr,
		  bool encrypted, const uint8_t *data, size_t size);
#endif
