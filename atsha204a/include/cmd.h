#ifndef __CMD_H
#define __CMD_H
#include <stdint.h>
#include <stdbool.h>

#include <io.h>

/* Zone encoding, this is typically param1 */
enum {
	ZONE_CONFIG = 0,
	ZONE_OTP,
	ZONE_DATA,
	ZONE_END
};

#define ZONE_CONFIG_SIZE	88
#define ZONE_OTP_SIZE 		64
#define ZONE_DATA_SIZE		512

#define LOCK_CONFIG_LOCKED	0x0
#define LOCK_CONFIG_UNLOCKED	0x55
#define LOCK_DATA_LOCKED	0x0
#define LOCK_DATA_UNLOCKED	0x55

/* Sizes for out parameter (RandOut) */
#define NONCE_SHORT_LEN		1
#define NONCE_LONG_LEN		32

/* Sizes for in parameter (NumIn) */
#define NONCE_SHORT_NUMIN	20
#define NONCE_LONG_NUMIN	32

#define NONCE_MODE_UPDATE_SEED  0
#define NONCE_MODE_NO_SEED      1
#define NONCE_MODE_PASSTHROUGH  3

#define HMAC_LEN		32
#define RANDOM_LEN		32
#define DEVREV_LEN		4
#define SERIALNUM_LEN		9

#define WORD_SIZE		4
#define MAX_READ_SIZE		32 /* bytes */
#define MAX_WRITE_SIZE		32

/* Word address values */
#define PKT_FUNC_RESET		0x0
#define PKT_FUNC_SLEEP		0x1
#define PKT_FUNC_IDLE		0x2
#define PKT_FUNC_COMMAND	0x3

#define CMD_WAKEUP 0x0

/* OP-codes for each command, see section 8.5.4 in spec */
#define OPCODE_DERIVEKEY	0x1c
#define OPCODE_DEVREV 		0x30
#define OPCODE_GENDIG 		0x15
#define OPCODE_HMAC 		0x11
#define OPCODE_CHECKMAC		0x28
#define OPCODE_LOCK 		0x17
#define OPCODE_MAC 		0x08
#define OPCODE_NONCE 		0x16
#define OPCODE_PAUSE 		0x01
#define OPCODE_RANDOM 		0x1b
#define OPCODE_READ 		0x02
#define OPCODE_SHA 		0x47
#define OPCODE_UPDATEEXTRA 	0x20
#define OPCODE_WRITE 		0x12

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
static uint8_t SLOT_CONFIG_ADDR(slotnbr)
{
	uint8_t addr = 0x5;
	if (slotnbr % 2)
		slotnbr--;
	slotnbr >>= 1;
	return addr + slotnbr;
}

#define SLOT_ADDR(id) (8 * id)

#if FIXME
/* Can one use a macro like this instead of the function above? */
#define SLOT_CONFIG_ADDR(slotnbr) (slotnbr % 2 ? \
	0x5 + (--slotnbr >> 1) : \
	0x5 + (slotnbr >> 1))
#endif

#define SLOT_CONFIG_OFFSET(slotnbr) (slotnbr % 2 ? 2 : 0)
#define SLOT_CONFIG_SIZE 0x2

#define OTP_ADDR(addr) (4 * addr)

bool wake(struct io_interface *ioif);

int cmd_read(struct io_interface *ioif, uint8_t zone, uint8_t addr,
	     uint8_t offset, size_t size, void *data, size_t data_size);

int cmd_get_config_zone(struct io_interface *ioif, uint8_t *buf, size_t size);

int cmd_get_devrev(struct io_interface *ioif, uint8_t *buf, size_t size);

int cmd_get_hmac(struct io_interface *ioif, uint8_t mode, uint16_t slotnbr, uint8_t *hmac);

int cmd_get_lock_config(struct io_interface *ioif, uint8_t *lock_config);

int cmd_get_lock_data(struct io_interface *ioif, uint8_t *lock_data);

int cmd_lock_zone(struct io_interface *ioif, uint8_t zone, uint16_t *expected_crc);

int cmd_get_nonce(struct io_interface *ioif, uint8_t *in, size_t in_size,
		  uint8_t mode, uint8_t *out, size_t out_size);

int cmd_get_otp_mode(struct io_interface *ioif, uint8_t *otp_mode);

int cmd_get_random(struct io_interface *ioif, uint8_t *buf, size_t size);

int cmd_get_serialnbr(struct io_interface *ioif, uint8_t *buf, size_t size);

int cmd_get_slot_config(struct io_interface *ioif, uint8_t slotnbr,
			uint16_t *buf);

int cmd_write(struct io_interface *ioif, uint8_t zone, uint8_t addr,
	      uint8_t *data, size_t size);
#endif
