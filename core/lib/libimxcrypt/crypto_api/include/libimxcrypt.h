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

/* Global includes */
#include <tee_api_types.h>

/**
 * @brief   i.MX Crypto Library Algorithm enumeration
 */
enum imxcrypt_algo_id {
	CRYPTO_HASH = 0,      ///< HASH driver
	CRYPTO_HASH_SW,      ///< HASH SW driver
	CRYPTO_HMAC,         ///< HMAC driver
	CRYPTO_HMAC_SW,      ///< HMAC SW driver
	CRYPTO_CIPHER,       ///< Cipher driver
	CRYPTO_RSA,          ///< Assymetric RSA driver
	CRYPTO_DSA,          ///< Assymetric DSA driver
	CRYPTO_ECC,          ///< Assymetric ECC driver
	CRYPTO_DH,           ///< Assymetric DH driver
	CRYPTO_AUTHENC,      ///< Cipher Authentication driver
	CRYPTO_AUTHENC_SW,   ///< Cipher Authentication SW driver
	CRYPTO_MP,           ///< Manufacturing Protection driver
	CRYPTO_MATH_HW,      ///< Mathematical HW operation driver
	CRYPTO_HUK,          ///< Hardware Unique Key operation driver
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
 * @brief   Cryptographic module modify registration
 *
 * @param[in] idx  Crypto index in the array
 * @param[in] ops  Reference to the cryptographic module
 */
void imxcrypt_register_change(enum imxcrypt_algo_id idx, void *ops);

/**
 * @brief   Returns the address of the crypto module structure
 *
 * @param[in] idx  Crypto index in the array
 *
 * retval  address of the crypto module structure
 */
void *imxcrypt_getmod(enum imxcrypt_algo_id idx);

/**
 * @brief   Initialize the Software library. Calls all Software drivers
 *          initialization function ot register then
 *
 * @retval TEE_SUCCESS          Success
 * @retval TEE_ERROR_GENERIC    General failure
 */
TEE_Result imxcrypt_libsoft_init(void);

/**
 * @brief   Crypto driver initialization function called by the Crypto
 *          Library initialization
 *
 * @retval  TEE_SUCCESS              Success
 * @retval  TEE_ERROR_GENERIC        Generic Error (driver init failure)
 * @retval  TEE_ERROR_NOT_SUPPORTED  Driver not supported
 */
TEE_Result crypto_driver_init(void);

#endif /* __LIBIMXCRYPT_H__ */
