// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    rng.c
 *
 * @brief   Cryptographic library using the i.MX CAAM driver.\n
 *          RNG crypto_* interface implementation.
 */

/* Global includes */
#include <crypto/crypto.h>

/* Library i.MX includes */
#include <libimxcrypt.h>
#include <libimxcrypt_rng.h>

/**
 * @brief   Fills input buffer \a buf with \a blen random bytes
 *
 * @param[in] blen  Number of random bytes to read
 *
 * @param[out] buf  Buffer to fill
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 * @retval TEE_ERROR_BAD_STATE       RNG is not in correct state
 * @retval TEE_ERROR_NOT_IMPLEMENTED RNG function is not implemented
 */
TEE_Result crypto_rng_read(void *buf, size_t blen)
{
	struct imxcrypt_rng *rng;

	if ((!buf) || (blen == 0))
		return TEE_ERROR_BAD_PARAMETERS;

	rng = imxcrypt_getmod(CRYPTO_RNG);

	if (rng) {
		if (rng->read)
			return rng->read(buf, blen);
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}



