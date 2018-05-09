// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    mac.c
 *
 * @brief   Cryptographic library using the i.MX CAAM driver.\n
 *          HMAC crypto_* interface implementation.
 */

/* Global includes */
#include <assert.h>
#include <crypto/crypto.h>

TEE_Result crypto_mac_alloc_ctx(void **ctx __unused, uint32_t algo __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_mac_free_ctx(void *ctx __unused, uint32_t algo __unused)
{
	assert(1);
}

void crypto_mac_copy_state(void *dst_ctx __unused, void *src_ctx __unused,
			   uint32_t algo __unused)
{
	assert(1);
}

TEE_Result crypto_mac_init(void *ctx __unused, uint32_t algo __unused,
			   const uint8_t *key __unused, size_t len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_mac_update(void *ctx __unused, uint32_t algo __unused,
			     const uint8_t *data __unused, size_t len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_mac_final(void *ctx __unused, uint32_t algo __unused,
			    uint8_t *digest __unused,
			    size_t digest_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

