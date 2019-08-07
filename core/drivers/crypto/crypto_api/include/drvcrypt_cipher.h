/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   Cipher interface calling the HW crypto driver.
 */
#ifndef __DRVCRYPT_CIPHER_H__
#define __DRVCRYPT_CIPHER_H__

#include <crypto/crypto_impl.h>
#include <tee_api_types.h>

/*
 * Format the CIPHER context to keep the reference to the
 * operation driver
 */
struct crypto_cipher {
	struct crypto_cipher_ctx cipher_ctx; /* Crypto Cipher API context */
	void *ctx;                           /* Cipher Context */
	struct drvcrypt_cipher *op;          /* Reference to the operation */
};

/*
 * Cipher Algorithm initialization data
 */
struct drvcrypt_cipher_init {
	void *ctx;             /* Software Context */
	bool encrypt;          /* Encrypt or decrypt direction */
	struct cryptobuf key1; /* First Key */
	struct cryptobuf key2; /* Second Key */
	struct cryptobuf iv;   /* Initial Vector */
};

/*
 * Cipher Algorithm update data
 */
struct drvcrypt_cipher_update {
	void *ctx;            /* Software Context */
	bool encrypt;         /* Encrypt or decrypt direction */
	bool last;            /* Last block to handle */
	struct cryptobuf src; /* Buffer source (Message or Cipher) */
	struct cryptobuf dst; /* Buffer dest (Message or Cipher) */
};

/*
 * Crypto Library Cipher driver operations
 */
struct drvcrypt_cipher {
	/* Allocates of the Software context */
	TEE_Result (*alloc_ctx)(void **ctx, uint32_t algo);
	/* Free of the Software context */
	void (*free_ctx)(void *ctx);
	/* Initialize the cipher operation */
	TEE_Result (*init)(struct drvcrypt_cipher_init *dinit);
	/* Update the cipher operation */
	TEE_Result (*update)(struct drvcrypt_cipher_update *dupdate);
	/* Finalize the cipher operation */
	void (*final)(void *ctx);
	/* Copy Cipher context */
	void (*copy_state)(void *dst_ctx, void *src_ctx);
};

/*
 * Register a cipher processing driver in the crypto API
 *
 * @ops - Driver operations in the HW layer
 */
static inline TEE_Result drvcrypt_register_cipher(struct drvcrypt_cipher *ops)
{
	return drvcrypt_register(CRYPTO_CIPHER, (void *)ops);
}

#endif /* __DRVCRYPT_CIPHER_H__ */
