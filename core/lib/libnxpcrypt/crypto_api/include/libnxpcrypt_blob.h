/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2019 NXP
 *
 * @file    libnxpcrypt_blob.h
 *
 * @brief   Cryptographic library using the NXP CAAM driver.\n
 *          Blob data encapsulation interface library vs CAAM driver.
 */
#ifndef __LIBNXPCRYPT_BLOB_H__
#define __LIBNXPCRYPT_BLOB_H__

#include <tee_api_types.h>

/**
 * @brief Blob data structure
 */
struct nxpcrypt_blob_data {
	enum blob_type      type;    ///< Blob encryption type
	bool                encaps;  ///< Encryption/Decryption direction
	struct nxpcrypt_buf key;     ///< Blob Key modifier
	struct nxpcrypt_buf payload; ///< Decrypted Blob data payload
	struct nxpcrypt_buf blob;    ///< Encrypted Blob of payload
};

/**
 * @brief   NXP Crypto Library BLOB driver operations
 */
struct nxpcrypt_blob {
	///< Encapsulate/Decapsulate data
	TEE_Result (*operate)(struct nxpcrypt_blob_data *blob_data);
	///< Encapsulate DEK Blob
	TEE_Result (*dek)(struct nxpcrypt_blob_data *blob_data);
};

#endif /* __LIBNXPCRYPT_BLOB_H__ */
