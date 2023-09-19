/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2023 NXP
 */
#ifndef PTA_ELE_TEST_H
#define PTA_ELE_TEST_H

#define PTA_ELE_TEST_UUID                                              \
	{                                                              \
		0x6bd8ac83, 0x592e, 0x4c81,                            \
		{                                                      \
			0x8a, 0xb3, 0x4a, 0x2c, 0x30, 0xc9, 0xf6, 0x27 \
		}                                                      \
	}

/*
 * Test Generation/Deletion of Persistent and volatile keys.
 */
#define PTA_ELE_CMD_TEST_KEY_GENERATE_DELETE 0

#endif /* PTA_ELE_TEST_H */
