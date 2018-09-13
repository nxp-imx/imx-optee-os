/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    libimxcrypt_hash.h
 *
 * @brief   Cryptographic library using the i.MX CAAM driver.\n
 *          Hash interface library vs CAAM driver.
 */
#ifndef __LIBIMXCRYPT_HASH_H__
#define __LIBIMXCRYPT_HASH_H__

/* Global includes */
#include <tee_api_types.h>

/**
 * @brief   Hash Algorithm enumerate
 */
enum imxcrypt_hash_id {
	HASH_MD5 = 0,       ///< MD5
	HASH_SHA1,          ///< SHA 1
	HASH_SHA224,        ///< SHA 224
	HASH_SHA256,        ///< SHA 256
	HASH_SHA384,        ///< SHA 384
	HASH_SHA512,        ///< SHA 512
	MAX_HASH_SUPPORTED  ///< Maximum Hash supported
};

/**
 * @brief   i.MX Crypto Library Hash driver operations
 *
 */
struct imxcrypt_hash {
	///< Maximum hash supported
	enum imxcrypt_hash_id max_hash;

	///< Allocates of the Software context
	TEE_Result (*alloc_ctx)(void **ctx, enum imxcrypt_hash_id algo);
	///< Free of the Software context
	void (*free_ctx)(void *ctx);
	///< Initialize the hashing operation
	TEE_Result (*init)(void *ctx, enum imxcrypt_hash_id algo);
	///< Update the hashing operation
	TEE_Result (*update)(void *ctx, enum imxcrypt_hash_id algo,
					const uint8_t *data, size_t len);
	///< Finalisze the hashing operation
	TEE_Result (*final)(void *ctx, enum imxcrypt_hash_id algo,
					uint8_t *digest, size_t len);

	///< Copy Hash context
	void (*cpy_state)(void *dst_ctx, void *src_ctx);

	///< HMAC Key computing
	TEE_Result (*compute_key)(void *ctx, const uint8_t *key, size_t len);
};

#endif /* __LIBIMXCRYPT_HASH_H__ */
