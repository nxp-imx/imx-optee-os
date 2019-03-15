// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    snvs.c
 *
 * @brief   SNVS Configuration
 */

#include <drivers/imx_snvs.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <platform_config.h>

/* Platform includes */
#include <imx.h>

/**
 * @brief   Set the NPSWA_EN bit.
 *          Allow non-proviledge software to access all SNVS registers
 *          If device is in closed mode, the HAB does not set this bit.
 */
void snvs_set_npswa_en(void)
{
	if (imx_is_device_closed()) {
		vaddr_t snvs_base = core_mmu_get_va(SNVS_BASE, MEM_AREA_IO_SEC);

		io_mask32(snvs_base + SNVS_HPCOMR, BM_SNVS_HPCOMR_NPSWA_EN,
			BM_SNVS_HPCOMR_NPSWA_EN);
	}
}
