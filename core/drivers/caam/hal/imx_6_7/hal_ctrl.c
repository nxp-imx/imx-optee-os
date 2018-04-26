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
#include "ctrl_regs.h"

/**
 * @brief   Initializes the CAAM HW Controller
 *
 * @param[in] baseaddr  Controller base address
 */
void hal_ctrl_init(vaddr_t baseaddr)
{
	/*
	 * Enable DECO watchdogs
	 */
	io_mask32(baseaddr + MCFGR, MCFGR_WDE, MCFGR_WDE);

	/*
	 * ERRATA:  mx6 devices have an issue wherein AXI bus transactions
	 * may not occur in the correct order. This isn't a problem running
	 * single descriptors, but can be if running multiple concurrent
	 * descriptors. Reworking the driver to throttle to single requests
	 * is impractical, thus the workaround is to limit the AXI pipeline
	 * to a depth of 1 (from it's default of 4) to preclude this situation
	 * from occurring.
	 *
	 * mx7 devices, this bit has no effect.
	 */
	io_mask32(baseaddr + MCFGR, MCFGR_AXIPIPE(1), BM_MCFGR_AXIPIPE);
}

