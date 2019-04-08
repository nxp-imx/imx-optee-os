/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 NXP
 *
 * @file    libnxpcrypt_cipher.h
 *
 * @brief   Cryptographic library using the NXP CAAM driver.\n
 *          Cipher interface library vs CAAM driver.
 */
#ifndef __LIBNXPCRYPT_CIPHER_H__
#define __LIBNXPCRYPT_CIPHER_H__

#include <tee_api_types.h>
#include <util.h>

/** @brief  AES Algorithm type id */
#define NXP_AES_ID		BIT32(5)
/** @brief  DES Algorithm type id */
#define NXP_DES_ID		BIT32(6)
/** @brief  Triple-DES Algorithm type id */
#define NXP_DES3_ID		BIT32(7)

/** @brief  Cipher ID mask */
#define NXP_CIPHER_ID_MASK	(NXP_DES3_ID | NXP_DES_ID | NXP_AES_ID)
/** @brief  Return the Cipher algo id */
#define NXP_CIPHER_ID(algo)	(algo & NXP_CIPHER_ID_MASK)

/**
 * @brief   Cipher Algorithm enumerate
 */
enum nxpcrypt_cipher_id {
	AES_ECB_NOPAD = NXP_AES_ID,   ///< AES Algo mode ECB NO PAD
	AES_CBC_NOPAD,                ///< AES Algo mode CBC NO PAD
	AES_CTR,                      ///< AES Algo mode CTR
	AES_CTS,                      ///< AES Algo mode CTS
	AES_XTS,                      ///< AES Algo mode XTS
	AES_CBC_MAC,                  ///< AES Algo mode CBC MAC
	AES_CMAC,                     ///< AES Algo mode CMAC
	MAX_AES_ID,                   ///< Maximum AES ID
	DES_ECB_NOPAD = NXP_DES_ID,   ///< DES Algo mode ECB NO PAD
	DES_CBC_NOPAD,                ///< DES Algo mode CBC NO PAD
	DES_CBC_MAC,                  ///< DES Algo mode CBC MAC
	MAX_DES_ID,                   ///< Maximum DES ID
	DES3_ECB_NOPAD = NXP_DES3_ID, ///< Triple-DES Algo mode ECB NO PAD
	DES3_CBC_NOPAD,               ///< Triple-DES Algo mode CBC NO PAD
	DES3_CBC_MAC,                 ///< Triple-DES Algo mode CBC MAC
	MAX_DES3_ID,                  ///< Maximum Triple-DES ID
};

/** @brief  Maximum AES supported */
#define MAX_AES_SUPPORTED	(MAX_AES_ID - NXP_AES_ID)
/** @brief  Maximum DES supported */
#define MAX_DES_SUPPORTED	(MAX_DES_ID - NXP_DES_ID)
/** @brief  Maximum Triple-DES supported */
#define MAX_DES3_SUPPORTED	(MAX_DES3_ID - NXP_DES3_ID)

/**
 * @brief  Format the CIPHER context to keep the reference to the
 *         operation driver
 */
struct crypto_cipher {
	void                   *ctx; ///< Cipher Context
	struct nxpcrypt_cipher *op;  ///< Reference to the operation
};

/**
 * @brief   Cipher Algorithm initialization data
 */
struct nxpcrypt_cipher_init {
	void                 *ctx;     ///< Software Context
	bool                 encrypt;  ///< Encrypt or decrypt direction
	struct nxpcrypt_buf  key1;     ///< First Key
	struct nxpcrypt_buf  key2;     ///< Second Key
	struct nxpcrypt_buf  iv;       ///< Initial Vector
};

/**
 * @brief   Cipher Algorithm update data
 */
struct nxpcrypt_cipher_update {
	void                *ctx;     ///< Software Context
	bool                encrypt;  ///< Encrypt or decrypt direction
	bool                last;     ///< Last block to handle
	struct nxpcrypt_buf src;      ///< Buffer source (Message or Cipher)
	struct nxpcrypt_buf dst;      ///< Buffer dest (Message or Cipher)
};

/**
 * @brief   NXP Crypto Library Cipher driver operations
 *
 */
struct nxpcrypt_cipher {
	///< Allocates of the Software context
	TEE_Result (*alloc_ctx)(void **ctx, enum nxpcrypt_cipher_id algo);
	///< Free of the Software context
	void (*free_ctx)(void *ctx);
	///< Initialize the cipher operation
	TEE_Result (*init)(struct nxpcrypt_cipher_init *dinit);
	///< Update the cipher operation
	TEE_Result (*update)(struct nxpcrypt_cipher_update *dupdate);
	///< Finalize the cipher operation
	void (*final)(void *ctx);
	///< Get Cipher block size
	TEE_Result (*block_size)(enum nxpcrypt_cipher_id algo, size_t *size);

	///< Copy Cipher context
	void (*cpy_state)(void *dst_ctx, void *src_ctx);
};

#endif /* __LIBNXPCRYPT_CIPHER_H__ */
