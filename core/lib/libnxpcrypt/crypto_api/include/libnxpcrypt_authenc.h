/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 NXP\n
 *
 * @file    libnxpcrypt_authenc.h
 *
 * @brief   Cryptographic library using the NXP CAAM driver.\n
 *          Authenticate Encryption interface library vs CAAM driver.
 */
#ifndef __LIBNXPCRYPT_AUTHENC_H__
#define __LIBNXPCRYPT_AUTHENC_H__

#include <tee_api_types.h>

/**
 * @brief   Authenticate Encryption Algorithm enumerate
 */
enum nxpcrypt_authenc_id {
	AES_CCM = 0,           ///< AES Algo mode CCM
	AES_GCM,               ///< AES Algo mode GCM
	MAX_AUTHENC_SUPPORTED, ///< Maximum Authentication Encryption supported
};

/**
 * @brief   Authentication Algorithm initialization data
 */
struct nxpcrypt_authenc_init {
	void                *ctx;        ///< Software Context
	bool                encrypt;     ///< Encrypt or decrypt direction
	struct nxpcrypt_buf key;         ///< Key
	struct nxpcrypt_buf nonce;       ///< Nonce
	size_t              tag_len;     ///< Tag length
	size_t              aad_len;     ///< Additional Data length
	size_t              payload_len; ///< Payload length
};

/**
 * @brief   Authentication Algorithm update Additional Data
 */
struct nxpcrypt_authenc_aad {
	void                *ctx;    ///< Software Context
	struct nxpcrypt_buf aad;     ///< Additonal Data
};

/**
 * @brief   Authentication Algorithm update Payload data
 */
struct nxpcrypt_authenc_data {
	void                *ctx;    ///< Software Context
	bool                encrypt; ///< Encrypt or decrypt direction
	struct nxpcrypt_buf src;     ///< Data Source
	struct nxpcrypt_buf dst;     ///< Data Destination
	struct nxpcrypt_buf tag;     ///< Tag data
};

/**
 * @brief   NXP Crypto Library Authentication driver operations
 *
 */
struct nxpcrypt_authenc {
	///< =True if AES GCM mode supported
	bool aes_gcm;
	///< Allocates of the Software context
	TEE_Result (*alloc_ctx)(void **ctx, enum nxpcrypt_authenc_id algo);
	///< Free of the Software context
	void (*free_ctx)(void *ctx);
	///< Initialize the authentication operation
	TEE_Result (*init)(struct nxpcrypt_authenc_init *dinit);
	///< Update the authentication operation
	TEE_Result (*update)(struct nxpcrypt_authenc_data *dupdate);
	///< Finalize the update authentication operation
	TEE_Result (*update_final)(struct nxpcrypt_authenc_data *dfinal);
	///< Update the authentication additional data
	TEE_Result (*update_aad)(struct nxpcrypt_authenc_aad *daad);
	///< Final the authentication
	void (*final)(void *ctx);

	///< Copy authentication context
	void (*cpy_state)(void *dst_ctx, void *src_ctx);
};

#endif /* __LIBNXPCRYPT_AUTHENC_H__ */
