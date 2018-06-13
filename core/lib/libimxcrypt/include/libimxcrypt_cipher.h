/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    libimxcrypt_cipher.h
 *
 * @brief   Cryptographic library using the i.MX CAAM driver.\n
 *          Cipher interface library vs CAAM driver.
 */
#ifndef __LIBIMXCRYPT_CIPHER_H__
#define __LIBIMXCRYPT_CIPHER_H__

#include <tee_api_types.h>

/**
 * @brief   Cipher Algorithm enumerate
 */
enum imxcrypt_cipher_id {
	AES_ECB_NOPAD = 0,    ///< AES Algo mode ECB NO PAD
	AES_CBC_NOPAD,        ///< AES Algo mode CBC NO PAD
	AES_CTR,              ///< AES Algo mode CTR
	AES_CTS,              ///< AES Algo mode CTS
	MAX_CIPHER_SUPPORTED, ///< Maximum Cipher supported
};

/**
 * @brief   Cipher Algorithm initialization data
 */
struct imxcrypt_cipher_init {
	void                 *ctx;     ///< Software Context
	enum imxcrypt_cipher_id algo;  ///< Cipher Algorithm id
	bool                 encrypt;  ///< Encrypt or decrypt direction
	struct imxcrypt_buf  key1;     ///< First Key
	struct imxcrypt_buf  key2;     ///< Second Key
	struct imxcrypt_buf  iv;       ///< Initial Vector
};

/**
 * @brief   Cipher Algorithm update data
 */
struct imxcrypt_cipher_update {
	void                    *ctx;     ///< Software Context
	enum imxcrypt_cipher_id algo;     ///< Cipher Algorithm id
	bool                    encrypt;  ///< Encrypt or decrypt direction
	bool                    last;     ///< Last block to handle
	struct imxcrypt_buf     src;      ///< Buffer source (Message or Cipher)
	struct imxcrypt_buf     dst;      ///< Buffer dest (Message or Cipher)
};

/**
 * @brief   i.MX Crypto Library Cipher driver operations
 *
 */
struct imxcrypt_cipher {
	///< Allocates of the Software context
	TEE_Result (*alloc_ctx)(void **ctx, enum imxcrypt_cipher_id algo);
	///< Free of the Software context
	void (*free_ctx)(void *ctx);
	///< Initialize the cipher operation
	TEE_Result (*init)(struct imxcrypt_cipher_init *dinit);
	///< Update the cipher operation
	TEE_Result (*update)(struct imxcrypt_cipher_update *dupdate);
	///< Finalize the cipher operation
	void (*final)(void *ctx, enum imxcrypt_cipher_id algo);
	///< Get Cipher block size
	TEE_Result (*block_size)(enum imxcrypt_cipher_id algo, size_t *size);

	///< Copy Cipher context
	void (*cpy_state)(void *dst_ctx, void *src_ctx);
};

#endif /* __LIBIMXCRYPT_CIPHER_H__ */
