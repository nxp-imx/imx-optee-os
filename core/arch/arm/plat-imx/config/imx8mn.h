/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019 NXP
 *
 */

#ifndef CONFIG_IMX8MN_H
#define CONFIG_IMX8MN_H

#define DRAM0_BASE		0x40000000
#define DRAM0_SIZE		CFG_DDR_SIZE

#define DRAM0_NSEC_BASE		DRAM0_BASE
#define DRAM0_NSEC_SIZE		(CFG_TZDRAM_START - DRAM0_NSEC_BASE)

#endif
