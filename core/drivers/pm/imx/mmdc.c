// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2021 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
 */

#include <arm.h>
#include <io.h>
#include <imx.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>

#include "imx_pm.h"

/* i.MX6 */
#define MMDC_MDMISC		0x18
#define MDMISC_DDR_TYPE_MASK	GENMASK_32(4, 3)
#define MDMISC_DDR_TYPE_SHIFT	0x3

/* i.MX7 */
#define DDRC_MSTR		0x0
#define MSTR_DDR3		BIT(0)
#define MSTR_LPDDR2		BIT(2)
#define MSTR_LPDDR3		BIT(3)

int imx_get_ddr_type(void)
{
	uint32_t val = 0;
	uint32_t off = 0;
	bool is_mx7 = soc_is_imx7ds();
	vaddr_t mmdc_base = 0;

	if (is_mx7)
		off = DDRC_MSTR;
	else
		off = MMDC_MDMISC;

	mmdc_base = core_mmu_get_va(MMDC_P0_BASE, MEM_AREA_IO_SEC,
				    off + sizeof(uint32_t));
	val = io_read32(mmdc_base + off);

	if (is_mx7) {
		if (val & MSTR_DDR3)
			return IMX_DDR_TYPE_DDR3;
		else if (val & MSTR_LPDDR2)
			return IMX_DDR_TYPE_LPDDR2;
		else if (val & MSTR_LPDDR3)
			return IMX_DDR_TYPE_LPDDR3;
		else
			return -1;
	}

	return (val & MDMISC_DDR_TYPE_MASK) >> MDMISC_DDR_TYPE_SHIFT;
}
