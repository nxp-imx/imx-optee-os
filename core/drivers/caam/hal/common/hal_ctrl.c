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

