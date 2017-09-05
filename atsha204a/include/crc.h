#ifndef __CRC_LOCAL_H
#define __CRC_LOCAL_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <cmd.h>

#define CRC_LEN		2 /* In bytes */
#define CRC_POLYNOM 	0x8005

bool crc_valid(const uint8_t *data, uint8_t *crc, size_t data_len);
uint16_t get_packet_crc(struct cmd_packet *p, size_t payload_size);
uint16_t get_serialized_crc(void *p, size_t size);
uint16_t calculate_crc16(const uint8_t *data, size_t size, uint16_t current_crc);

#endif


