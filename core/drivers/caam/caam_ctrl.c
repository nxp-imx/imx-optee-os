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

/* Library i.MX includes */
#include <libimxcrypt.h>

/* Local includes */
#include "common.h"
#include "caam_jr.h"
#include "caam_rng.h"
#ifdef CFG_CRYPTO_CIPHER_HW
#include "caam_cipher.h"
#endif
#ifdef CFG_CRYPTO_HASH_HW
#include "caam_hash.h"
#endif

/* Utils includes */
#include "utils_mem.h"

/* Hal includes */
#include "hal_cfg.h"
#include "hal_clk.h"
#include "hal_ctrl.h"
#include "hal_jr.h"

#define CTRL_DEBUG
#ifdef CTRL_DEBUG
#define CTRL_TRACE		DRV_TRACE
#else
#define CTRL_TRACE(...)
#endif

/**
 * @brief   Crypto driver initialization function called by the Crypto
 *          Library initialization
 *
 * @retval  TEE_SUCCESS              Success
 * @retval  TEE_ERROR_GENERIC        Generic Error (driver init failure)
 * @retval  TEE_ERROR_NOT_SUPPORTED  Driver not supported
 */
TEE_Result crypto_driver_init(void)
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

#ifdef CFG_CRYPTO_HASH_HW
	/* Initialize the Hash Module */
	retstatus = caam_hash_init(jr_cfg.base);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}
#endif // CFG_CRYPTO_HASH_HW

#ifdef CFG_CRYPTO_CIPHER_HW
	/* Initialize the Cipher Module */
	retstatus = caam_cipher_init(jr_cfg.base);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}
#endif // CFG_CRYPTO_CIPHER_HW

	retresult = TEE_SUCCESS;

exit_init:
	CTRL_TRACE("CAAM Driver initialization (0x%x)\n", retresult);
	return retresult;
}

