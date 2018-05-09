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
#include <trace.h>

#define LIB_DEBUG
#ifdef LIB_DEBUG
#define LIB_TRACE	DMSG
#else
#define LIB_TRACE(...)
#endif

/**
 * @brief   Crypto library initialization.
 *          Calls all initialization functions
 *
 * @retval  TEE_SUCCESS              Success
 * @retval  TEE_ERROR_GENERIC        Generic Error
 */
TEE_Result crypto_init(void)
{
	LIB_TRACE("Initialization of the i.MX Crypto Lib");
	return TEE_ERROR_GENERIC;
}

