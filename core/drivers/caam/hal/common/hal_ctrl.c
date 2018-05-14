// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    hal_ctrl.c
 *
 * @brief   CAAM Controller Hardware Abstration Layer.\n
 *          Implementation of primitives to access HW
 */

/* Global includes */
#include <io.h>

#ifdef CFG_CRYPTO_HASH_HW
/* Library i.MX includes */
#include <libimxcrypt_hash.h>
#endif

/* Hal includes */
#include "hal_ctrl.h"

/* Register includes */
#include "version_regs.h"

/**
 * @brief   Returns the number of Job Ring supported
 *
 * @param[in] baseaddr  Controller base address
 *
 * @retval  The number of Job Ring in HW
 */
uint8_t hal_ctrl_jrnum(vaddr_t baseaddr)
{
	uint32_t val;

	val = read32(baseaddr + CHANUM_MS);

	return GET_CHANUM_MS_JRNUM(val);
}

#ifdef CFG_CRYPTO_HASH_HW
/**
 * @brief   Returns the Maximum Hash supported
 *
 * @param[in] baseaddr  Controller base address
 *
 * @retval  Maximum Hash Id supported
 * @retval  (-1) if hash is not supported
 */
int hal_ctrl_hash_limit(vaddr_t baseaddr)
{
	uint32_t val;

	/* Read the number of instance */
	val = read32(baseaddr + CHANUM_LS);

	if (GET_CHANUM_LS_MDNUM(val)) {
		/* Hashing is supported */
		val = read32(baseaddr + CHAVID_LS);
		val &= BM_CHAVID_LS_MDVID;
		if (val == CHAVID_LS_MDVID_LP256)
			return HASH_SHA256;

		return HASH_SHA512;
	}

	return (-1);
}
#endif // CFG_CRYPTO_HASH_HW
