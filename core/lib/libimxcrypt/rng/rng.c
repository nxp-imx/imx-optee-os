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
#include <assert.h>
#include <crypto/crypto.h>

TEE_Result crypto_rng_read(void *buf __unused, size_t blen __unused)
{
	return TEE_ERROR_BAD_STATE;
}

TEE_Result crypto_rng_add_entropy(const uint8_t *inbuf __unused,
					size_t len __unused)
{
	return TEE_ERROR_BAD_STATE;
}


