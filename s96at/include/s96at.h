/*
 * Copyright 2017, Linaro Ltd and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __S96AT_H
#define __S96AT_H

#include <stdint.h>

#include "s96at_private.h"

#define S96AT_VERSION				PROJECT_VERSION

#define S96AT_WORD_SIZE		4
#define S96AT_BLOCK_SIZE	32

#define S96AT_ATECC508A_ZONE_CONFIG_LEN		128
#define S96AT_ATECC508A_ZONE_CONFIG_NUM_BLOCKS	4
#define S96AT_ATECC508A_ZONE_CONFIG_NUM_WORDS	32
#define S96AT_ATECC508A_ZONE_DATA_LEN		1208
#define S96AT_ATECC508A_ZONE_OTP_LEN		64

#define S96AT_ATSHA204A_ZONE_CONFIG_LEN		88
#define S96AT_ATSHA204A_ZONE_CONFIG_NUM_WORDS	22
#define S96AT_ATSHA204A_ZONE_DATA_LEN		512
#define S96AT_ATSHA204A_ZONE_OTP_LEN		64

#define S96AT_STATUS_OK				0x00
#define S96AT_STATUS_CHECKMAC_FAIL		0x01
#define S96AT_STATUS_EXEC_ERROR			0x0f
#define S96AT_STATUS_READY			0x11
#define S96AT_STATUS_PADDING_ERROR		0x98
#define S96AT_STATUS_BAD_PARAMETERS		0x99

#define S96AT_WATCHDOG_TIME			1700 /* msec */

#define S96AT_CHALLENGE_LEN			32
#define S96AT_DEVREV_LEN			4
#define S96AT_ECC_PRIV_LEN			32 /* without padding */
#define S96AT_ECC_PUB_X_LEN			32
#define S96AT_ECC_PUB_Y_LEN			32
#define S96AT_ECDH_SECRET_LEN			32
#define S96AT_ECDSA_R_LEN			32
#define S96AT_ECDSA_S_LEN			32
#define S96AT_GENDIG_INPUT_LEN			4
#define S96AT_HMAC_LEN				32
#define S96AT_KEY_LEN				32
#define S96AT_MAC_LEN				32
#define S96AT_NONCE_INPUT_LEN			20
#define S96AT_RANDOM_LEN			32
#define S96AT_SERIAL_NUMBER_LEN			9
#define S96AT_SHA_LEN				32
#define S96AT_STATE_LEN				2
#define S96AT_ZONE_CONFIG_LEN			88
#define S96AT_ZONE_DATA_LEN			512
#define S96AT_ZONE_OTP_LEN			64

#define S96AT_FLAG_NONE				0x00
#define S96AT_FLAG_TEMPKEY_SOURCE_INPUT		0x01
#define S96AT_FLAG_TEMPKEY_SOURCE_RANDOM	0x02
#define S96AT_FLAG_USE_OTP_64_BITS		0x04
#define S96AT_FLAG_USE_OTP_88_BITS		0x08
#define S96AT_FLAG_USE_SN			0x10
#define S96AT_FLAG_ENCRYPT			0x20
#define S96AT_FLAG_INVALIDATE			0x40

#define S96AT_KEY_INVALID			0x00
#define S96AT_KEY_VALID				0x01

#define	S96AT_ZONE_LOCKED			0x00
#define S96AT_ZONE_UNLOCKED			0x55

#define S96AT_OTP_MODE_LEGACY			0x00
#define S96AT_OTP_MODE_CONSUMPTION		0x55
#define S96AT_OTP_MODE_READONLY			0xAA

/* s96at_get_state() 1st byte */
#define S96AT_STATE_TEMPKEY_KEY_ID_SHIFT	0
#define S96AT_STATE_TEMPKEY_SOURCE_FLAG_SHIFT	4
#define S96AT_STATE_TEMPKEY_GEN_DIG_DATA_SHIFT	5
#define S96AT_STATE_TEMPKEY_GEN_KEY_DATA_SHIFT	6
#define S96AT_STATE_TEMPKEY_NO_MAC_FLAG_SHIFT	7

#define S96AT_STATE_TEMPKEY_KEY_ID_MASK		0x0f
#define S96AT_STATE_TEMPKEY_SOURCE_FLAG_MASK	0x10
#define S96AT_STATE_TEMPKEY_GEN_DIG_DATA_MASK	0x20
#define S96AT_STATE_TEMPKEY_GEN_KEY_DATA_MASK	0x40
#define S96AT_STATE_TEMPKEY_NO_MAC_FLAG_MASK	0x80

/* s96at_get_state() 2nd byte */
#define S96AT_STATE_EEPROM_RNG_SHIFT		0
#define S96AT_STATE_SRAM_RNG_SHIFT		1
#define S96AT_STATE_AUTH_VALID_SHIFT		2
#define S96AT_STATE_AUTH_KEY_ID_SHIFT		3
#define S96AT_STATE_TEMPKEY_VALID_SHIFT		7

#define S96AT_STATE_EEPROM_RNG_MASK		0x01
#define S96AT_STATE_SRAM_RNG_MASK		0x02
#define S96AT_STATE_AUTH_VALID_MASK		0x04
#define S96AT_STATE_AUTH_KEY_ID_MASK		0x78
#define S96AT_STATE_TEMPKEY_VALID_MASK		0x80

enum s96at_device {
	S96AT_ATSHA204A = 1,
	S96AT_ATECC508A
};

enum s96at_io_interface_type {
	S96AT_IO_I2C_LINUX
};

enum s96at_zone {
	S96AT_ZONE_CONFIG,
	S96AT_ZONE_OTP,
	S96AT_ZONE_DATA
};

/* See Table 9.6 in ATECC508A spec */
struct s96at_slot_addr {
	uint8_t slot;
	uint8_t block;
	uint8_t offset;
};

struct s96at_check_mac_data {
	const uint8_t *challenge;
	uint8_t slot;
	uint32_t flags;
	const uint8_t *otp;
	const uint8_t *sn;
};

struct s96at_ecc_pub {
	uint8_t x[S96AT_ECC_PUB_X_LEN];
	uint8_t y[S96AT_ECC_PUB_Y_LEN];
};

struct s96at_ecdsa_sig {
	uint8_t r[S96AT_ECDSA_R_LEN];
	uint8_t s[S96AT_ECDSA_S_LEN];
};

enum s96at_genkey_mode {
	S96AT_GENKEY_MODE_PUB,
	S96AT_GENKEY_MODE_PRIV	  = 0x04,
	S96AT_GENKEY_MODE_DIGEST  = 0x10,
};

enum s96at_mac_mode {
	S96AT_MAC_MODE_0, /* 1st 32 bytes: Slot, 2nd 32 bytes: Input Challenge */
	S96AT_MAC_MODE_1, /* 1st 32 bytes: Slot, 2nd 32 bytes: TempKey */
	S96AT_MAC_MODE_2, /* 1st 32 bytes: TempKey, 2nd 32 bytes: Input Challenge */
	S96AT_MAC_MODE_3  /* 1st 32 bytes: TempKey, 2nd 32 bytes: TempKey */
};

enum s96at_nonce_mode {
	S96AT_NONCE_MODE_RANDOM,
	S96AT_NONCE_MODE_RANDOM_NO_SEED,
	S96AT_NONCE_MODE_PASSTHROUGH = 0x03
};

enum s96at_random_mode {
	S96AT_RANDOM_MODE_UPDATE_SEED,
	S96AT_RANDOM_MODE_UPDATE_NO_SEED
};

enum s96at_sign_mode {
	S96AT_SIGN_MODE_INTERNAL,
	S96AT_SIGN_MODE_EXTERNAL = 0x80
};

enum s96at_verify_key_mode {
	S96AT_VERIFY_KEY_MODE_VALIDATE = 0x03,
	S96AT_VERIFY_KEY_MODE_INVALIDATE = 0x07
};

enum s96at_verify_sig_mode {
	S96AT_VERIFY_SIG_MODE_STORED,
	S96AT_VERIFY_SIG_MODE_EXTERNAL = 0x2
};

enum s96at_update_extra_mode {
	S96AT_UPDATE_EXTRA_MODE_USER,
	S96AT_UPDATE_EXTRA_MODE_SELECTOR,
	S96AT_UPDATE_EXTRA_MODE_LIMIT
};

/* Check a MAC generated by another device
 *
 * Generates a MAC and compares it with the value stored in the mac buffer.
 * This is normally used to verify a MAC generated using s96at_get_mac()
 * during a challenge-response communication between a host and a client,
 * where a host sends a challenge and the client responds with a MAC that
 * is subsequently verified by the host.
 * The s96at_check_mac_data structure contains the parameters used by the
 * client to generate the response. For more information see s96at_get_mac().
 * The slot parameter specifies the slot that contains the key to use by the
 * host when calculating the response. In the flags parameter it is required
 * to specify input source of TempKey.
 *
 * Returns S96AT_STATUS_OK on success. A failed comparison returns
 * S96_STATUS_CHECKMAC_FAIL. Other errors return S96AT_EXECUTION_ERROR.
 */
uint8_t s96at_check_mac(struct s96at_desc *desc, enum s96at_mac_mode mode,
			uint8_t slot, uint32_t flags, struct s96at_check_mac_data *data,
			const uint8_t *mac);

/* Clean up a device descriptor
 *
 * Unregisters the device from the io interface.
 */
uint8_t s96at_cleanup(struct s96at_desc *desc);

/* Calculate a CRC value
 *
 * Calculates the CRC of the data stored in buf, using the same CRC-16
 * polynomial used by the device. If a non-zero value is passed to the
 * current_crc parameter, the algorithm will use that as the initial value.
 * This is useful if the CRC cannot be calculated in one go.
 *
 * Returns the calculated CRC value.
 */
uint16_t s96at_crc(const uint8_t *buf, size_t buf_len, uint16_t current_crc);

/* Derive a key
 *
 * Derives a new key by combining the value stored in a slot with a nonce
 * and storing its SHA256 hash into the target slot. Depending on how the
 * target slot is configured, this function will use the appropriate input
 * key:
 *
 * For slots configured into Create mode, the parent key is used.
 * For slots configured into Rolling mode, the current key is used.
 *
 * If required by the configuration, an authorizing MAC can be sent along,
 * through the mac buffer.
 *
 * The flags parameter must specify the input source of TempKey as defined
 * when executing the Nonce command.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_derive_key(struct s96at_desc *desc, uint8_t slot, uint8_t *mac,
			 uint32_t flags);

/* Performs ECDH
 *
 * This function is only available on ATECC508A.
 *
 * Performs ECDH negotiation with the chip to derive a shared secret. The specified
 * slot must contain an EC private key. If the slot has been configured to output
 * the secret in the clear, the shared secret is written into buf. The buffer length
 * must be S96AT_ECDH_SECRET_LEN. If the slot is configured to store the shared secret
 * into a slot, the buf parameter is ignored.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_ecdh(struct s96at_desc *desc, uint8_t slot, struct s96at_ecc_pub *pub,
		   uint8_t *buf);

/* Read the value of a monotonic counter
 *
 * This function is only available on ATECC508A.
 *
 * Reads the value of the specified counter into the val parameter.
 * Valid values of the counter parameter are 0 and 1, corresponging
 * to the device's Counter<0> and Counter<1>, respectively.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_get_counter(struct s96at_desc *desc, uint8_t counter, uint32_t *val);

/* Get Device Revision
 *
 * Retrieves the device revision and stores it into the buffer pointed by
 * buf. The buffer length must be S96AT_DEVREV_LEN.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_get_devrev(struct s96at_desc *desc, uint8_t *buf);

/* Generate a digest
 *
 * Generate a SHA-256 digest combining the value stored in TempKey with
 * a value stored in the device. The input value is defined by the zone
 * and slot parameters. The value of data must be NULL.
 *
 * For keys configured as CheckOnly, it is possible to generate the
 * digest using the value stored in the data buffer instead of a value
 * stored in the device. This is normally used to generate euphemeral
 * keys. When this operation is required, a pointer must be passed to the
 * data parameter pointing to a buffer that contains the input data. In
 * this case, the zone and slot values are ignored.
 *
 * In both cases, the generated digest is stored in TempKey and it can
 * be used to combine the Nonce with an additional value before executing
 * the MAC / CheckMAC / HMAC commands.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_gen_digest(struct s96at_desc *desc, enum s96at_zone zone,
			 uint8_t slot, uint8_t *data);

/* Generate an ECC key
 *
 * This function is only available on ATECC508A.
 *
 * Mode S96AT_GENKEY_MODE_PRIV generates an ECC keypair and stores the private
 * key into the defined slot. The key slot must be appropriately configured to
 * store an ECC private key. The x and y coordinates of the public key are
 * written into the structure pointed by pub.
 *
 * Mode S96AT_GENKEY_MODE_PUB writes the x and y coordinates of the public key
 * that corresponds to the private key stored into a given slot into the structure
 * pointed to by pub. The public key is also stored in TempKey.
 *
 * Mode S96AT_GENKEY_MODE_DIG generates a digest of the public key stored in
 * the defined slot, and stores it into TempKey. No data are written into the
 * pub structure.
 *
 * Returns S96AT_STATUS_OK on success, or an appropriate error value.
 */
uint8_t s96at_gen_key(struct s96at_desc *desc, enum s96at_genkey_mode mode,
		      uint8_t slot, struct s96at_ecc_pub *pub);

/* Generate an HMAC-SHA256
 *
 * Generates an HMAC. To generate an HMAC, it is first required to load
 * an input challenge into TempKey using Nonce and optionally GenDigest.
 * The value in TempKey is then combined along with the key stored in slot
 * to generate an HMAC.
 *
 * Flags control whether other intput values should be included in
 * the input message. These are:
 *
 * S96AT_FLAG_USE_OTP_64_BITS	Include OTP[0:7]
 * S96AT_FLAG_USE_OTP_88_BITS	Include OTP[0:10]
 * S96AT_FLAG_USE_SN		Include SN[2:3] and SN[4:7]
 *
 * The resulting HMAC is written into the hmac buffer.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_get_hmac(struct s96at_desc *desc, uint8_t slot,
		       uint32_t flags, uint8_t *hmac);

/* Get information on key validity
 *
 * Populates the valid parameter with a value signifying whether the value
 * stored in the specified slot is a valid ECC private or public key. That
 * value can be either S96AT_KEY_VALID or S96AT_KEY_INVALID. This command
 * is only useful for slots configured with KeyType parameter that indicates
 * an ECC key. For public keys, PubInfo must be 1.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_get_key_valid(struct s96at_desc *desc, uint8_t slot, uint8_t *valid);

/* Get the lock status of the Config Zone
 *
 * Reads the lock status of the Config Zone into lock_config.
 * Possible values are:
 *
 *  S96AT_ZONE_LOCKED
 *  S96AT_ZONE_UNLOCKED
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_get_lock_config(struct s96at_desc *desc, uint8_t *lock_config);

/* Get the lock status of the Data / OTP zone
 *
 * Reads the lock status of the Data / OTP zone into lock_data.
 * Possible values are:
 *
 * S96AT_ZONE_LOCKED
 * S96AT_ZONE_UNLOCKED
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_get_lock_data(struct s96at_desc *desc, uint8_t *lock_data);

/* Generate a MAC
 *
 * Generates a MAC. To generate a MAC, it is first required to load
 * an input challenge into TempKey using Nonce and optionally GenDigest.
 * The value in TempKey is then combined along with the key stored in slot
 * to generate a MAC.
 *
 * The mode parameter specifies which fields to use to form the input message:
 *
 * S96AT_MAC_MODE_0	1st 32 bytes from a slot, 2nd 32 bytes from the input challenge
 * S96AT_MAC_MODE_1	1st 32 bytes from a slot, 2nd 32 bytes from TempKey
 * S96AT_MAC_MODE_2	1st 32 bytes from TempKey 2nd 32 bytes from the input challenge
 * S96AT_MAC_MODE_3	1st 32 bytes from TempKey 2nd 32 bytes from TempKey
 *
 * When S96AT_MAC_MODE_2 or S96AT_MAC_MODE_3 is used, the slot parameter is ignored.
 * When S96AT_MAC_MODE_1 or S96AT_MAC_MODE_3 is used, the input challenge parameter
 * is ignored.
 *
 * Flags control whether other intput values should be included in
 * the input message. These are:
 *
 * S96AT_FLAG_USE_OTP_64_BITS	Include OTP[0:7]
 * S96AT_FLAG_USE_OTP_88_BITS	Include OTP[0:10]
 * S96AT_FLAG_USE_SN		Include SN[2:3] and SN[4:7]
 *
 * The resulting MAC is written into the mac buffer.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_get_mac(struct s96at_desc *desc, enum s96at_mac_mode mode, uint8_t slot,
		      const uint8_t *challenge, uint32_t flags, uint8_t *mac);

/* Generate a nonce
 *
 * Generates a nonce. The operation mode is specified by the mode
 * parameter. When operating in Passthrough mode, the input value
 * in the data buffer is stored directly in TempKey.
 * When operating in Random Mode, an input value is combined with
 * a random number and the resulting hash is stored in TempKey.
 *
 * When Random Mode is used, the default behaviour is to update
 * the seed before generating the random number. This behaviour
 * can be overriden when using S96AT_REANDOM_MODE_NO_SEED.
 *
 * The value produced by the RNG is stored into buf.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_gen_nonce(struct s96at_desc *desc, enum s96at_nonce_mode mode,
			uint8_t *data, uint8_t *random);

/* Get the OTP Mode
 *
 * Reads the OTP Mode into otp_mode. Possible values are:
 *
 * S96AT_OTP_MODE_CONSUMPTION
 * S96AT_OTP_MODE_LEGACY
 * S96AT_OTP_MODE_READ_ONLY
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_get_otp_mode(struct s96at_desc *desc, uint8_t *opt_mode);

/* Send the Pause command
 *
 * Upon receiving the Pause command, devices with Selector byte in the
 * configuration that do NOT match the selector parameter, will enter the
 * Idle State. This is useful for avoiding conflicts when multiple devices
 * are used on the same bus.
 *
 * A device that does not enter the idle state returns S96AT_STATUS_OK.
 */
uint8_t s96at_pause(struct s96at_desc *desc, uint8_t selector);

/* Generate a random number
 *
 * Random numbers are generated by combining the output of a hardware RNG
 * with an internally stored seed value. The generated number is stored in
 * the buffer pointed by buf. The length of the buffer must be at least
 * S96AT_RANDOM_LEN.
 *
 * Before generating a new number, the interal seed is updated by default.
 * This can be overriden by using S96AT_RANDOM_MODE_UPDATE_NO_SEED.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_get_random(struct s96at_desc *desc, enum s96at_random_mode mode,
			 uint8_t *buf);

/* Get the device's Serial Number
 *
 * Reads the device's Serial Number into buf. The buffer must be
 * at least S96AT_SERIALNUM_LEN long.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_get_serialnbr(struct s96at_desc *desc, uint8_t *serial);

/* Generate a hash (SHA-256)
 *
 * Generates a SHA-256 hash of the input message contained in buf.
 * The message length is specified in msg_len.
 *
 * In ATECC508A, the minimum message length is 64 Bytes.
 *
 * In ATSHA204A, the input buffer's length must be a multiple of
 * S96AT_SHA_BLOCK_LEN and the buffer is modified in place to contain
 * the SHA padding, as defined in FIPS 180-2. The input buffer is
 * therefore required to have enough room for the padding.
 *
 * The resulting hash is stored in the hash buffer.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_get_sha(struct s96at_desc *desc, uint8_t *buf,
		      size_t buf_len, size_t msg_len, uint8_t *hash);

/* Get dynamic state info (ATECC508A only)
 *
 * Populates buf with dynamic state information. The buffer length is S96AT_STATE_LEN,
 * ie 2 Bytes. The first byte contains the following information:
 * - Byte[7]    TempKey.NoMacFlag
 * - Byte[6]    TempKey.GenKeyData
 * - Byte[5]    TempKey.GenDigData
 * - Byte[4]    TempKey.SourceFlag
 * - Byte[3:0]  TempKey.KeyID
 * The second byte contains the following:
 * - Byte[7]    TempKey.Valid
 * - Byte[6:3]  AuthKeyID
 * - Byte[1]    SRAM RNG
 * - Byte[0]    EEPROM RNG
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_get_state(struct s96at_desc *desc, uint8_t *buf);

/* Increment the value of a monotonic counter
 *
 * This function is only available on ATECC508A.
 *
 * Increments the value of the specified counter. Valid counter values are
 * 0 and 1.
 *
 * Returns S96AT_STATUS_OK on success, or an appropriate error value.
 */
uint8_t s96at_increment_counter(struct s96at_desc *desc, uint8_t counter);

/* Initialize a device descriptor
 *
 * Selects a device and registers with an io interface. Upon successful initialization,
 * the descriptor can be used in subsequent operations.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_init(enum s96at_device device_type, enum s96at_io_interface_type iface,
		   struct s96at_desc *desc);

/* Lock a zone
 *
 * Locks a zone specified by the zone parameter. Device personalization requires
 * the following steps: The configuraton zone is first programmed and locked. After
 * the configuration zone is locked, the Data and OTP areas are programmed.
 * The Data and OTP zones are then locked in a single operation, by setting the zone
 * parameter to S96AT_ZONE_DATA. Specifying S96AT_ZONE_OTP returns an error.
 *
 * Notice that locking a zone is a one-time operation.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_lock_zone(struct s96at_desc *desc, enum s96at_zone zone, uint16_t crc);

/* Read from the Configuration zone
 *
 * In ATECC508A the Configuration zone is organized into 32-byte blocks. The id
 * parameter specifies the block to be read, in the range of 0-3. The block's
 * contents are written into buf, which must have the appropriate size.
 *
 * In ATSHA204A the Config zone is organized into 4-byte words. The id parameter
 * specifies the word to be read, in the range of 0-21. The buffer size must be
 * set accordingly.
 *
 * Reading from the Config zone is always permitted.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_read_config(struct s96at_desc *desc, uint8_t id, uint8_t *buf);

/* Read from the Data zone
 *
 * Reading from a slot is permitted only after the Data zone has been locked,
 * and only if that slot has been configured as such, ie the isSecret bit is
 * zero.
 *
 * In ATSHA204A, the Data zone is organized in 32-byte slots. The slot to be read
 * is defined by the slot element of the addr parameter, in the range of 0-15. The
 * remaining elements of the addr structure must be zero. The default write length
 * is 32 bytes.
 *
 * In ATECC508A, the Data zone slots are of various lengths. Reads are still performed
 * in multiples of 32-byte blocks. The part of the slot to be read is defined by
 * the slot and block elements of the addr parameter. Valid ranges depend on the slot.
 * See Table 9.7 in the ATECC508A specification.
 *
 * Reads from the Data zone can be encrypted if the EncryptedRead bit is set in the
 * slot's configuration. To perform an encrypted read, GenDig must be run before
 * reading data, in order to set the encryption key.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_read_data(struct s96at_desc *desc, struct s96at_slot_addr *addr,
			uint32_t flags, uint8_t *buf, size_t length);

/* Read from the OTP zone
 *
 * The OTP zone is organized in 4-byte words. The id parameter specifies
 * the word to be read in the range of 0 - 15. The buffer length must be
 * 4 bytes. Reading is permitted only once the OTP zone has been locked.
 * If the OTP zone is configured into Legacy mode, reading from words
 * 0 or 1 returns an error.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_read_otp(struct s96at_desc *desc, uint8_t id, uint8_t *buf);

/* Put the device into the sleep state
 *
 * Puts the device in low-power sleep. The device does not respond until the
 * next wakeup is sent. The volatile state of the device is reset.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_sleep(struct s96at_desc *desc);

/* Put the device into the idle state
 *
 * Puts the device into the idle state. The device does not respond until the
 * next wakeup is sent. The contents of RNG seed register and TempKey are
 * retained.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_idle(struct s96at_desc *desc);

/* Reset the address counter
 *
 * Resets the address counter. This allows re-reading the device's output
 * buffer.
 *
 * Returns always S96AT_SUCCESS.
 */
uint8_t s96at_reset(struct s96at_desc *desc);

/* Generate an ECDSA signature
 *
 * This function is only available on ATECC508A.
 *
 * Generates an ECDSA signature using the private key specified by the slot
 * parameter. The resulting signature is stored into buf.
 *
 * Mode S96AT_SIGN_MODE_EXTERNAL signs a message that has been hashed outside
 * the device. The hash must be placed into TempKey using s96at_gen_nonce().
 * The slot that contains the private key must be configured to allow external
 * signatures using SlotConfig.ReadKey.
 *
 * Mode S96AT_SIGN_MODE_INTERNAL signs data generated within the device, and is
 * stored in TempKey either through s96at_gen_dig() or s96at_gen_key(). If the
 * S96AT_FLAG_USE_SN is set, then SN[2:3] and SN[4:7] are included in the hashed
 * message. The slot that contains the private key must be configured to allow
 * internal signatures using SlotConfig.ReadKey.
 *
 * If the resulting sigature is intended to be used to invalidate a key (ie by
 * Verify(Invalidate)), then the S96AT_FLAG_INVALIDATE must be set.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_sign(struct s96at_desc *desc, enum s96at_sign_mode mode, uint8_t slot,
		   uint32_t flags, struct s96at_ecdsa_sig *sig);

/* Update extra configuration bytes
 *
 * Updates the extra configuration bytes. When mode is set to S96AT_UPDATE_EXTRA_MODE_USER,
 * the UserExtra byte in the configuration is updated with the value passed through val.
 * When mode is set to S96AT_UPDATE_EXTRA_MODE_SELECTOR, the Selector byte in the
 * configuration is updated with the value passed through val.
 * When mode is set to S96AT_UPDATE_EXTRA_MODE_LIMIT, the limit use counters of the key
 * defined by val are decremented, if that key has been configured as such.
 * All of the above operations can only be performed after the device has been locked.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_update_extra(struct s96at_desc *desc, enum s96at_update_extra_mode mode,
			   uint8_t val);

/* Validates or Invalidates an EC Public Key
 *
 * This function is only available on ATECC508A.
 *
 * Validates or Invalidates an EC public key. The mode parameter specifies whether to
 * validate or to invalidate the key. The verification message must be stored into the
 * buffer pointed by the buf parameter, and the validation signature is passed through
 * the sig parameter.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_verify_key(struct s96at_desc *desc, enum s96at_verify_key_mode mode,
			 struct s96at_ecdsa_sig *sig, uint8_t slot, const uint8_t *buf);

/* Verify an ECDSA signature
 *
 * This function is only available on ATECC508A.
 *
 * Verifies an ECDSA signature. The signature's R and S components must be stored
 * into the structure specified in the sig parameter. When mode is set to
 * S96AT_VERIFY_SIG_MODE_EXTERNAL, the public key to be used to verify the signature
 * must be passed into the pub parameter. The value of the slot parameter is ignored
 * in this mode. When the mode is set to S96AT_VERIFY_SIG_INTERNAL, the public key
 * to be used is stored into the device and it is specified by the slot parameter.
 * In this mode the pub parameter must be NULL.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_verify_sig(struct s96at_desc *desc, enum s96at_verify_sig_mode mode,
			 struct s96at_ecdsa_sig *sig, uint8_t slot,
			 struct s96at_ecc_pub *pub);

/* Wake up the device
 *
 * Wakes up the device by sending the wake-up sequence. Upon wake up, a watchdog
 * counter is triggered, which keeps the device awake for S96AT_WATCHDOG_TIME.
 * Once the counter reaches zero, the device enters sleep mode, regardless of its
 * current command execution or IO state. It is therefore required that all operations
 * are completed within S96AT_WATCHDOG_TIME.
 *
 * Returns S96AT_STATUS_READY on device wake, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_wake(struct s96at_desc *desc);

/* Write to the Config zone
 *
 * Writes into the Configuration zone are performed in 4-byte words. The id
 * parameter specifies the word to be written. Not all words are writable,
 * and some words can only be updated using the UpdateExtra command. Writing
 * to the Configuration zone is only permitted before the zone is locked.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_write_config(struct s96at_desc *desc, uint8_t id, const uint8_t *buf);

/* Write to the Data zone
 *
 * Programming the Data zone is allowed once the Configuration zone has been locked,
 * and before the Data zone has been locked. Once the Data zone has been locked, writing
 * to a slot depends on the permissions set on the slot's configuration.
 *
 * In ATSHA204A, the Data zone is organized in 32-byte slots. The slot to be written
 * is defined by the slot element of the addr parameter, in the range of 0-15. The
 * remaining elements of the addr structure must be zero. The default write length
 * is 32 bytes.
 *
 * In ATECC508A, the Data zone slots are of various lengths. Writes are still performed
 * in multiples of 32-byte blocks. The part of the slot to be written is defined by
 * the slot and block elements of the addr parameter. Valid ranges depend on the slot.
 * See Table 9.7 in the ATECC508A specification.
 *
 * 4-byte writes allow updating part of a slot. When performing a 4-byte write, the
 * offset element of the addr parameter specifies the required word within the selected
 * slot. 4-byte writes are allowed if the Data zone is locked and the corresponding slot
 * has been configured as:
 * - IsSecret = 0
 * - WriteConfig = ALWAYS
 *
 * Writes to the Data zone can be encrypted if the slot has been configured
 * accordingly and S96AT_FLAG_ENCRYPT is set. Encrypted writes can only be
 * 32-byte long.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_write_data(struct s96at_desc *desc, struct s96at_slot_addr *addr,
			 uint32_t flags, const uint8_t *buf, size_t length);

/* Write to the OTP zone
 *
 * The OTP zone is organized in 4-byte words. The id parameter specifies the
 * word to be written in the range of 0-15. Programming the OTP zone can be
 * performed after the Configuration zone has been locked, and before the Data
 * zone has been locked. At this stage, writing is performed in 32-byte blocks,
 * so the id parameter should only be specified as 0 or 8. Once the Data zone
 * has been locked, writing is only permitted if the zone has been configured in
 * Consumption mode, in which case bits can only be changed from zero to one. At
 * this stage, only 4-byte writes are allowed and id can take any value between
 * 0 and 15.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_write_otp(struct s96at_desc *desc, uint8_t id, const uint8_t *buf,
			size_t length);

/* Write an ECC private key into a slot
 *
 * This function is only available on ATECC508A.
 *
 * Writes the ECC private key generated outside the device pointed to by priv,
 * into the defined slot. The private key must be prepended with 4 zero bytes.
 * The zone must be configured to contain an EC private key. If the Data Zone
 * has been locked, the private key must be encrypted and an authentication MAC
 * is required to be passed along with the encrypted key. Before the Data Zone
 * has been locked, the key can be written unencrypted. In that case the pointer
 * to authorizing mac parameter must be NULL.
 *
 * Returns S96AT_STATUS_OK on success, otherwise S96AT_STATUS_EXEC_ERROR.
 */
uint8_t s96at_write_priv(struct s96at_desc *desc, uint8_t slot, uint8_t *priv,
			 uint8_t *mac);

#endif
