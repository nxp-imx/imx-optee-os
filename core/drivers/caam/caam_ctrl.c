// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2017-2019 NXP
 *
 * @file    caam_ctrl.c
 *
 * @brief   CAAM Global Controller.\n
 */

/* Global includes */
#include <initcall.h>
#include <tee_api_types.h>

#ifdef CFG_NXPCRYPT
/* Library NXP includes */
#include <libnxpcrypt.h>
#endif

/* Local includes */
#include "common.h"
#include "caam_jr.h"
#include "caam_rng.h"
#include "caam_pwr.h"
#ifdef CFG_CRYPTO_SM_HW
#include "caam_sm.h"
#endif
#ifdef CFG_CRYPTO_PK_HW
#include "caam_acipher.h"
#endif
#ifdef CFG_CRYPTO_CIPHER_HW
#include "caam_cipher.h"
#endif
#ifdef CFG_CRYPTO_HASH_HW
#include "caam_hash.h"
#endif
#ifdef CFG_CRYPTO_MP_HW
#include "caam_mp.h"
#endif
#ifdef CFG_CRYPTO_BLOB_HW
#include "caam_blob.h"
#endif

/* Utils includes */
#include "utils_mem.h"

/* Hal includes */
#include "hal_cfg.h"
#include "hal_clk.h"
#include "hal_ctrl.h"

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
#ifdef CFG_NXPCRYPT
TEE_Result crypto_driver_init(void)
#else
static TEE_Result crypto_driver_init(void)
#endif
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

#ifdef CFG_CRYPTO_SM_HW
	/* Initialize the Secure memory module */
	retstatus = caam_sm_init(&jr_cfg);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}
#endif // CFG_CRYPTO_SM_HW

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

#ifdef CFG_CRYPTO_MP_HW
	/* Initialize the MP Module */
	retstatus = caam_mp_init(jr_cfg.base);

	if ((retstatus != CAAM_NO_ERROR) &&
			(retstatus != CAAM_NOT_SUPPORTED)) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}
#endif // CFG_CRYPTO_MP_HW

#ifdef CFG_CRYPTO_PK_HW
	/* Initialize the MATH Module */
	retstatus = caam_math_init(jr_cfg.base);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}
#endif

	/* Initialize the Asymmetric Cipher Modules */
#ifdef CFG_CRYPTO_RSA_HW
	/* Initialize the RSA Module */
	retstatus = caam_rsa_init(jr_cfg.base);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}
#endif
#ifdef CFG_CRYPTO_ECC_HW
	/* Initialize the ECC Module */
	retstatus = caam_ecc_init(jr_cfg.base);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}
#endif

#ifdef CFG_CRYPTO_BLOB_HW
	/* Initialize the Blob Module */
	retstatus = caam_blob_init(jr_cfg.base);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}
#endif

	/* Everything is OK, register the Power Management handler */
	caam_pwr_init();

	retresult = TEE_SUCCESS;

exit_init:
	/*
	 * Configure Job Rings to NS World
	 * If the Crypto NXP Library is not used (CFG_NXPCRYPT = n)
	 * JR0 is freed to be Non-Secure
	 */
	if (jr_cfg.base)
		hal_cfg_setup_nsjobring(jr_cfg.base);

	CTRL_TRACE("CAAM Driver initialization (0x%x)\n", retresult);
	return retresult;
}

#ifndef CFG_NXPCRYPT
driver_init(crypto_driver_init);
#endif

/**
 * @brief   Crypto driver late initialization function to complete
 *          CAAM operation
 *
 * @retval  TEE_SUCCESS        Success
 * @retval  TEE_ERROR_GENERIC  Generic Error (driver init failure)
 */
static TEE_Result init_caam_late(void)
{
	int ret = 0;

	ret = caam_jr_complete();

	if (ret == 0)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_GENERIC;
}
driver_init_late(init_caam_late);
