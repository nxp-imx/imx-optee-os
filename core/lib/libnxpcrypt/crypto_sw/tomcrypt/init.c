// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    init.c
 *
 * @brief   NXP Cryptographic software library initialization.
 */

/* Global includes */
#include <tee_api_types.h>
#include <trace.h>

/* Library NXP includes */
#include <libnxpcrypt.h>

/* Local includes */
#include "local.h"

//#define LIB_DEBUG
#ifdef LIB_DEBUG
#define LIB_TRACE	DMSG
#else
#define LIB_TRACE(...)
#endif

/**
 * @brief   Initialize the Software library. Calls all Software drivers
 *          initialization function ot register then
 *
 * @retval TEE_SUCCESS          Success
 * @retval TEE_ERROR_GENERIC    General failure
 */
TEE_Result nxpcrypt_libsoft_init(void)
{
	int ret = 0;
	int status = 0;

	LIB_TRACE("Initialization of the Software part of NXP Crypto Lib");

	status = libsoft_rng_init();
	LIB_TRACE("libsoft_rng_init ret %d", status);
	ret |= status;

#ifndef CFG_CRYPTO_RSA_HW
	status = libsoft_rsa_init();
	LIB_TRACE("libsoft_rsa_init ret %d", status);
	ret |= status;
#endif

	status = libsoft_dsa_init();
	LIB_TRACE("libsoft_dsa_init ret %d", status);
	ret |= status;

#ifndef CFG_CRYPTO_ECC_HW
	status = libsoft_ecc_init();
	LIB_TRACE("libsoft_ecc_init ret %d", status);
	ret |= status;
#endif

	status = libsoft_dh_init();
	LIB_TRACE("libsoft_dh_init ret %d", status);
	ret |= status;

	status = libsoft_hash_init();
	LIB_TRACE("libsoft_hash_init ret %d", status);
	ret |= status;

	status = libsoft_hash_sw_init();
	LIB_TRACE("libsoft_hash_sw_init ret %d", status);
	ret |= status;

#ifndef CFG_CRYPTO_HMAC_FULL_HW
	status = libsoft_hmac_sw_init();
	LIB_TRACE("libsoft_hmac_init ret %d", status);
	ret |= status;
#endif

	status = libsoft_mpa_init();
	LIB_TRACE("libsoft_mpa_init ret %d", status);
	ret |= status;

	status = libsoft_cipher_init();
	LIB_TRACE("libsoft_cipher_init ret %d", status);
	ret |= status;

	status = libsoft_authenc_init();
	LIB_TRACE("libsoft_authenc_init ret %d", status);
	ret |= status;

	LIB_TRACE("Software part of NXP Crypto Lib ret 0x%"PRIx32"", ret);
	if (ret)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

