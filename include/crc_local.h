#ifndef __CRC_LOCAL_H
#define __CRC_LOCAL_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <cmd.h>

/* FIXME: CRC related functionality needs to go into separate files later on */
#define CRC_LEN 2 /* In bytes */

bool crc_valid(const uint8_t *data, uint8_t *crc, size_t data_len);
uint16_t get_packet_crc(struct cmd_packet *p, size_t payload_size);

#endif


