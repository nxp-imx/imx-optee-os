// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2017-2018 NXP
 *
 * @file    caam_ctrl.c
 *
 * @brief   CAAM Global Controller.\n
 */

/* Global includes */
#include <initcall.h>
#include <tee_api_types.h>

/* Local includes */
#include "common.h"
#include "caam_jr.h"
#include "caam_rng.h"

/* Utils includes */
#include "utils_mem.h"

/* Hal includes */
#include "hal_cfg.h"
#include "hal_jr.h"
#include "hal_ctrl.h"
#include "hal_clk.h"

#define CTRL_DEBUG
#ifdef CTRL_DEBUG
#define CTRL_TRACE		DRV_TRACE
#else
#define CTRL_TRACE(...)
#endif

/**
 * @brief   CAAM driver initialization function called at TEE boot
 *
 * @retval  TEE_SUCCESS              Success
 * @retval  TEE_ERROR_GENERIC        Generic Error (driver init failure)
 * @retval  TEE_ERROR_NOT_SUPPORTED  CAAM driver not supported
 */
static TEE_Result caam_init(void)
{
	TEE_Result       retresult = TEE_ERROR_GENERIC;
	enum CAAM_Status retstatus;

	struct jr_cfg jr_cfg;

	/* Initialize the Memory Utility */
	retstatus = caam_mem_init();
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}

	/* Enable the CAAM Clock */
	hal_clk_enable(true);

	retstatus = hal_cfg_get_conf(&jr_cfg);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_NOT_SUPPORTED;
		goto exit_init;
	}

	/* Initialize the CAAM Controller */
	hal_ctrl_init(jr_cfg.base);

	hal_cfg_setup_nsjobring(jr_cfg.base);

	/* Initialize the Job Ring to be used */
	retstatus = caam_jr_init(&jr_cfg);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}

	/* Initialize the RNG Module */
	retstatus = caam_rng_init(jr_cfg.base);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}

	retresult = TEE_SUCCESS;

exit_init:
	CTRL_TRACE("CAAM Driver initialization (0x%x)\n", retresult);
	return retresult;
}


driver_init(caam_init);
