// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    imx_ocotp.c
 *
 * @brief   OCOTP module primitives
 */

/* Global includes */
#include <kernel/panic.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>

/* Platform includes */
#include <imx.h>

static uint32_t die_id;

/**
 * @brief   Read device Die Id
 *
 * @param[out] buffer  Output buffer of length \a len
 * @param[in]  len     Length of the output buffer
 *
 * @retval 0 Success
 */
int tee_otp_get_die_id(uint8_t *buffer, size_t len)
{
	vaddr_t va;

	if (die_id == 0) {
		va = core_mmu_get_va(OCOTP_BASE, MEM_AREA_IO_SEC);

		/* Read Fuse shadow register containing the chip DIE ID */
		die_id = read32(va + OCOTP_DIE_ID);
#ifdef CFG_MX7ULP
		/* Read and add part of the Wafer and Lot Number */
		die_id |= (read32(va + OCOTP_WAFER_NO) << 16);
#endif
		IMSG("Device Die ID = 0x%"PRIx32"", die_id);
		if (die_id == 0) {
			if (imx_is_device_closed()) {
				IMSG("Bad Device ID - Stop");
				panic();
			} else
				die_id = 0xDEED0BAD;
		}

	}

	memcpy(buffer, &die_id, MIN(len, sizeof(die_id)));

	return 0;
}

