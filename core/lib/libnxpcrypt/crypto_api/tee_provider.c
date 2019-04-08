// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    tee_provider.c
 *
 * @brief   Cryptographic library using the NXP CAAM driver.\n
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

/* Library NXP includes */
#include <libnxpcrypt.h>

//#define LIB_DEBUG
#ifdef LIB_DEBUG
#define LIB_TRACE	DMSG
#else
#define LIB_TRACE(...)
#endif

/**
 * @brief   Pointers array to NXP Cryptographic modules operation
 */
static void *nxpcrypt_algo[CRYPTO_MAX_ALGO] = {0};

/**
 * @brief   Cryptographic module registration
 *
 * @param[in] idx  Crypto index in the array
 * @param[in] ops  Reference to the cryptographic module
 *
 * @retval  0   Success
 * @retval (-1) Error
 */
int nxpcrypt_register(enum nxpcrypt_algo_id idx, void *ops)
{
	if (nxpcrypt_algo[idx] == NULL) {
		LIB_TRACE("Registering module id %d with 0x%"PRIxPTR"",
					idx, (uintptr_t)ops);
		nxpcrypt_algo[idx] = ops;
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
void nxpcrypt_register_change(enum nxpcrypt_algo_id idx, void *ops)
{
	LIB_TRACE("Change registered module id %d with 0x%"PRIxPTR"",
					idx, (uintptr_t)ops);
	nxpcrypt_algo[idx] = ops;
}

/**
 * @brief   Returns the address of the crypto module structure
 *
 * @param[in] idx  Crypto index in the array
 *
 * retval  address of the crypto module structure
 */
void *nxpcrypt_getmod(enum nxpcrypt_algo_id idx)
{
	return nxpcrypt_algo[idx];
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

	LIB_TRACE("Initialization of the NXP Crypto Lib");

	ret = crypto_driver_init();

	if (ret == TEE_SUCCESS) {
		ret = nxpcrypt_libsoft_init();
	}

	return ret;
}

