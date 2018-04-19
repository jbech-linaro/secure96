/*
 * Copyright 2017, Linaro Ltd and contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __PERSONALIZE_H
#define __PERSONALIZE_H

#include <io.h>

/* Generated by ATSHA204A slot config generator */
struct slot_config {
     uint8_t address;
     uint8_t value[4];
};

extern struct slot_config slot_configs[8];
extern uint8_t zone_data[ZONE_DATA_SIZE];
extern uint8_t zone_otp[ZONE_OTP_SIZE];

int atsha204a_personalize(struct io_interface *ioif);

#endif
