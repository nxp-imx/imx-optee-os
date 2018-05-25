/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    libimxcrypt.h
 *
 * @brief   Cryptographic library using the i.MX CAAM driver.\n
 *          Library exported constants and interfaces.
 */
#ifndef __LIBIMXCRYPT_H__
#define __LIBIMXCRYPT_H__

/**
 * @brief   i.MX Crypto Library Algorithm enumeration
 */
enum imxcrypt_algo_id {
	CRYPTO_RNG = 0,      ///< RNG driver
	CRYPTO_HASH,         ///< Hash driver
	CRYPTO_HMAC,         ///< Hmac driver
	CRYPTO_CIPHER,       ///< Cipher driver
	CRYPTO_MAX_ALGO      ///< Maximum numer of algo supported
};

/**
 * @brief   i.MX Cryptographic buffer type
 */
struct imxcrypt_buf {
	uint8_t *data;   ///< Pointer to the data buffer
	size_t  length;  ///< Length in bytes of the data buffer
};

/**
 * @brief   Cryptographic module registration
 *
 * @param[in] idx  Crypto index in the array
 * @param[in] ops  Reference to the cryptographic module
 *
 * @retval  0   Success
 * @retval (-1) Error
 */
int imxcrypt_register(enum imxcrypt_algo_id idx, void *ops);

/**
 * @brief   Returns the address of the crypto module structure
 *
 * @param[in] idx  Crypto index in the array
 *
 * retval  address of the crypto module structure
 */
void *imxcrypt_getmod(enum imxcrypt_algo_id idx);

#endif /* __LIBIMXCRYPT_H__ */
