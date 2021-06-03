/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2021 NXP
 *
 * brief   PTA I2C RTC Test interface identification.
 */
#ifndef __PTA_I2C_RTC_TEST_H__
#define __PTA_I2C_RTC_TEST_H__

/* PTA UUID generated at http://www.itu.int/ITU-T/asn1/uuid.html */
#define PTA_LS_I2C_RTC_TEST_SUITE_UUID \
	{ \
		0x4daa5ac7, 0xe9d2, 0x498f, \
		{ \
			0xa2, 0x4a, 0x4b, 0x2e, 0xab, 0x7b, 0x4b, 0x01 \
		} \
	}

/*
 * Commands Definition
 */
/* Get RTC time connected to I2C */
#define PTA_CMD_I2C_RTC_RUN_TEST_SUITE 0

#endif /* __PTA_I2C_RTC_TEST_H__ */
