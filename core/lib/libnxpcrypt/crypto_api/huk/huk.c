// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    huk.c
 *
 * @brief   Cryptographic library using the NXP CAAM driver.\n
 *          Hardware Unique Key crypto_* interface implementation.
 */

/* Global includes */
#include <crypto/crypto.h>
#include <trace.h>

/* Library NXP includes */
#include <crypto_extension.h>
#include <libnxpcrypt_huk.h>

//#define LIB_DEBUG
#ifdef LIB_DEBUG
#define LIB_TRACE	DMSG
#else
#define LIB_TRACE(...)
#endif

/**
 * @brief   Generation of the Hardware Unique Key (HUK)
 *
 * @param[out] huk  HUK key generated
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 */
TEE_Result crypto_generate_huk(struct nxpcrypt_buf *huk)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct nxpcrypt_huk *hukdrv;

	if (!huk) {
		LIB_TRACE("Input parameters reference error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!huk->data) {
		LIB_TRACE("Input parameters reference error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	hukdrv = nxpcrypt_getmod(CRYPTO_HUK);
	if (hukdrv) {
		if (hukdrv->generate_huk)
			ret = hukdrv->generate_huk(huk);
	}

	LIB_TRACE("Generate HUK returned 0x%"PRIx32"", ret);
	return ret;
}

