/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2019 NXP
 *
 * @file    libimxcrypt_blob.h
 *
 * @brief   Cryptographic library using the i.MX CAAM driver.\n
 *          Blob data encapsulation interface library vs CAAM driver.
 */
#ifndef __LIBIMXCRYPT_BLOB_H__
#define __LIBIMXCRYPT_BLOB_H__

#include <tee_api_types.h>

/**
 * @brief Blob data structure
 */
struct imxcrypt_blob_data {
	enum blob_type      type;    ///< Blob encryption type
	bool                encaps;  ///< Encryption/Decryption direction
	struct imxcrypt_buf key;     ///< Blob Key modifier
	struct imxcrypt_buf payload; ///< Decrypted Blob data payload
	struct imxcrypt_buf blob;    ///< Encrypted Blob of payload
};

/**
 * @brief   i.MX Crypto Library BLOB driver operations
 */
struct imxcrypt_blob {
	///< Encapsulate/Decapsulate data
	TEE_Result (*operate)(struct imxcrypt_blob_data *blob_data);
};

#endif /* __LIBIMXCRYPT_BLOB_H__ */
