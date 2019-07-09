/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 NXP
 *
 * @file    libnxpcrypt.h
 *
 * @brief   Cryptographic library using the NXP CAAM driver.\n
 *          Library exported constants and interfaces.
 */
#ifndef __LIBNXPCRYPT_H__
#define __LIBNXPCRYPT_H__

/* Global includes */
#include <tee_api_types.h>

/**
 * @brief   NXP Crypto Library Algorithm enumeration
 */
enum nxpcrypt_algo_id {
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
	CRYPTO_BLOB,         ///< Blob Encapsulation operation driver
	CRYPTO_MAX_ALGO      ///< Maximum number of algo supported
};

/**
 * @brief   NXP Cryptographic buffer type
 */
struct nxpcrypt_buf {
	uint8_t *data;   ///< Pointer to the data buffer
	size_t  length;  ///< Length in bytes of the data buffer
};

/**
 * @brief Blob encryption type
 */
enum blob_type {
	RED       = 0,  ///< Red Blob mode   - data in plain text
	BLACK_ECB,      ///< Black Blob mode - data encrypted in AES ECB
	BLACK_CCM,      ///< Black Blod mode - data encrypted in AES CCM
	DEK,            ///< DEK Blob mode   - data encrypted in AES CCM SM
	BLOB_MAX_TYPE   ///< Maximum number of blob type supported
};

/**
 * @brief   Blob Key Modifier size in bytes
 */
#define BLOB_KEY_MODIFIER_SIZE	16
/**
 * @brief   Blob Key (BKEK) size in bytes
 */
#define BLOB_BKEK_SIZE			32
/**
 * @brief   Blob MAC (BMAC) size in bytes
 */
#define BLOB_BMAC_SIZE			16
/**
 * @brief   Blob PAD (BPAD) size in bytes
 */
#define BLOB_BPAD_SIZE			(BLOB_BKEK_SIZE + BLOB_BMAC_SIZE)

/**
 * @brief   Cryptographic module registration
 *
 * @param[in] idx  Crypto index in the array
 * @param[in] ops  Reference to the cryptographic module
 *
 * @retval  0   Success
 * @retval (-1) Error
 */
int nxpcrypt_register(enum nxpcrypt_algo_id idx, void *ops);

/**
 * @brief   Cryptographic module modify registration
 *
 * @param[in] idx  Crypto index in the array
 * @param[in] ops  Reference to the cryptographic module
 */
void nxpcrypt_register_change(enum nxpcrypt_algo_id idx, void *ops);

/**
 * @brief   Returns the address of the crypto module structure
 *
 * @param[in] idx  Crypto index in the array
 *
 * retval  address of the crypto module structure
 */
void *nxpcrypt_getmod(enum nxpcrypt_algo_id idx);

/**
 * @brief   Initialize the Software library. Calls all Software drivers
 *          initialization function ot register then
 *
 * @retval TEE_SUCCESS          Success
 * @retval TEE_ERROR_GENERIC    General failure
 */
TEE_Result nxpcrypt_libsoft_init(void);

/**
 * @brief   Crypto driver initialization function called by the Crypto
 *          Library initialization
 *
 * @retval  TEE_SUCCESS              Success
 * @retval  TEE_ERROR_GENERIC        Generic Error (driver init failure)
 * @retval  TEE_ERROR_NOT_SUPPORTED  Driver not supported
 */
TEE_Result crypto_driver_init(void);

#endif /* __LIBNXPCRYPT_H__ */
