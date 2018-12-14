// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    tee_provider.c
 *
 * @brief   Cryptographic library using the i.MX CAAM driver.\n
 *          This library interfaces TEE Internal API by implementing
 *          all crypto_* functions. If an algorithm is not supported,
 *          the default NULL implementations are built and return
 *          TEE_ERROR_NOT_IMPLEMENTED
 */

/* Global includes */
#include <crypto/crypto.h>
#include <initcall.h>
#include <mpalib.h>
#include <trace.h>

/* Library i.MX includes */
#include <libimxcrypt.h>

//#define LIB_DEBUG
#ifdef LIB_DEBUG
#define LIB_TRACE	DMSG
#else
#define LIB_TRACE(...)
#endif

/**
 * @brief   Pointers array to i.MX Cryptographic modules operation
 */
static void *imxcrypt_algo[CRYPTO_MAX_ALGO] = {0};

/**
 * @brief   Cryptographic module registration
 *
 * @param[in] idx  Crypto index in the array
 * @param[in] ops  Reference to the cryptographic module
 *
 * @retval  0   Success
 * @retval (-1) Error
 */
int imxcrypt_register(enum imxcrypt_algo_id idx, void *ops)
{
	if (imxcrypt_algo[idx] == NULL) {
		LIB_TRACE("Registering module id %d with 0x%"PRIxPTR"",
					idx, (uintptr_t)ops);
		imxcrypt_algo[idx] = ops;
		return 0;
	}

	LIB_TRACE("Fail to register module id %d with 0x%"PRIxPTR"",
				idx, (uintptr_t)ops);
	return (-1);
}

/**
 * @brief   Cryptographic module modify registration
 *
 * @param[in] idx  Crypto index in the array
 * @param[in] ops  Reference to the cryptographic module
 */
void imxcrypt_register_change(enum imxcrypt_algo_id idx, void *ops)
{
	LIB_TRACE("Change registered module id %d with 0x%"PRIxPTR"",
					idx, (uintptr_t)ops);
	imxcrypt_algo[idx] = ops;
}

/**
 * @brief   Returns the address of the crypto module structure
 *
 * @param[in] idx  Crypto index in the array
 *
 * retval  address of the crypto module structure
 */
void *imxcrypt_getmod(enum imxcrypt_algo_id idx)
{
	return imxcrypt_algo[idx];
}

/**
 * @brief   Crypto library initialization called by the tee_cryp_init function.
 *          Calls all initialization functions
 *
 * @retval  TEE_SUCCESS              Success
 * @retval  TEE_ERROR_GENERIC        Generic Error
 */
TEE_Result crypto_init(void)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	LIB_TRACE("Initialization of the i.MX Crypto Lib");

	ret = crypto_driver_init();

	if (ret == TEE_SUCCESS) {
		ret = imxcrypt_libsoft_init();
	}

	return ret;
}

