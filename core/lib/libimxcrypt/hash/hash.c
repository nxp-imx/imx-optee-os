// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    hash.c
 *
 * @brief   Cryptographic library using the i.MX CAAM driver.\n
 *          Hash crypto_* interface implementation.
 */

/* Global includes */
#include <assert.h>
#include <crypto/crypto.h>

TEE_Result crypto_hash_alloc_ctx(void **ctx __unused, uint32_t algo __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_hash_free_ctx(void *ctx __unused, uint32_t algo __unused)
{
	assert(1);
}

void crypto_hash_copy_state(void *dst_ctx __unused, void *src_ctx __unused,
			    uint32_t algo __unused)
{
	assert(1);
}

TEE_Result crypto_hash_init(void *ctx __unused, uint32_t algo __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
TEE_Result crypto_hash_update(void *ctx __unused, uint32_t algo __unused,
			      const uint8_t *data __unused, size_t len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
TEE_Result crypto_hash_final(void *ctx __unused, uint32_t algo __unused,
			     uint8_t *digest __unused, size_t len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

