// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    cipher.c
 *
 * @brief   Cryptographic library using the i.MX CAAM driver.\n
 *          Cipher crypto_* interface implementation.
 */

/* Global includes */
#include <assert.h>
#include <crypto/crypto.h>

TEE_Result crypto_cipher_alloc_ctx(void **ctx __unused, uint32_t algo __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_cipher_free_ctx(void *ctx __unused, uint32_t algo __unused)
{
	assert(1);
}

void crypto_cipher_copy_state(void *dst_ctx __unused, void *src_ctx __unused,
			      uint32_t algo __unused)
{
	assert(1);
}

TEE_Result crypto_cipher_init(void *ctx __unused, uint32_t algo __unused,
			      TEE_OperationMode mode __unused,
			      const uint8_t *key1 __unused,
			      size_t key1_len __unused,
			      const uint8_t *key2 __unused,
			      size_t key2_len __unused,
			      const uint8_t *iv __unused,
			      size_t iv_len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_cipher_update(void *ctx __unused, uint32_t algo __unused,
				TEE_OperationMode mode __unused,
				bool last_block __unused,
				const uint8_t *data __unused,
				size_t len __unused, uint8_t *dst __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_cipher_final(void *ctx __unused, uint32_t algo __unused)
{
}

TEE_Result crypto_cipher_get_block_size(uint32_t algo __unused,
					size_t *size __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_aes_expand_enc_key(const void *key __unused,
					size_t key_len __unused,
					void *enc_key __unused,
					unsigned int *rounds __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

void crypto_aes_enc_block(const void *enc_key __unused,
					unsigned int rounds __unused,
					const void *src __unused,
					void *dst __unused)
{
}
