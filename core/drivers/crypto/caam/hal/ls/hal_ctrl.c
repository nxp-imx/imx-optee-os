// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019, 2021 NXP
 *
 * Brief   CAAM Controller Hardware Abstration Layer.
 *         Implementation of primitives to access HW.
 */
#include <caam_hal_ctrl.h>
#include <compiler.h>

void caam_hal_ctrl_init(vaddr_t baseaddr __unused)
{
}

bool is_caam_mpcurve_supported(void)
{
	return true;
}
