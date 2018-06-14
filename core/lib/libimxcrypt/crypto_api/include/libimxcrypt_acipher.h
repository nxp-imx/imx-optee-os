/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    libimxcrypt_acipher.h
 *
 * @brief   Cryptographic library using the i.MX CAAM driver.\n
 *          Cipher interface library vs CAAM driver.
 */
#ifndef __LIBIMXCRYPT_ACIPHER_H__
#define __LIBIMXCRYPT_ACIPHER_H__

/* Global includes */
#include <crypto/crypto.h>
#include <tee_api_types.h>

/* Library i.MX includes */
#include <libimxcrypt_hash.h>

/**
 * @brief   Assymetric Cipher RSA Algorithm enumerate
 */
enum imxcrypt_rsa_id {
	RSA_NOPAD = 0,   ///< RSA Algo mode NO PAD
	RSA_OAEP,        ///< RSA Algo mode OAEP
	RSA_PKCS_V1_5,   ///< RSA Algo mode PKCSv1.5
};

/**
 * @brief   RSA Encoded Signature data
 */
struct imxcrypt_rsa_ssa {
	uint32_t              algo;       ///< Operation algorithm
	enum imxcrypt_hash_id hash_id;    ///< HASH Algorithm Id
	void                  *key;       ///< Public or Private Key
	struct imxcrypt_buf   message;    ///< Message to sign or signed
	struct imxcrypt_buf   signature;  ///< Signature of the message
	size_t                salt_len;   ///< Signature Salt length
};

/**
 * @brief   RSA Encrypt/Descript data
 */
struct imxcrypt_rsa_ed {
	enum imxcrypt_rsa_id  rsa_id;  ///< RSA Algorithm Id
	enum imxcrypt_hash_id hash_id; ///< HASH Algorithm Id
	void                  *key;    ///< Public or Private key
	struct imxcrypt_buf   message; ///< Message to encrypt or decrypted
	struct imxcrypt_buf   cipher;  ///< Cipher text encrypted or to decrypt
	struct imxcrypt_buf   label;   ///< Additional Label encryption (RSAES)
};

/**
 * @brief   i.MX Crypto Library RSA driver operations
 *
 */
struct imxcrypt_rsa {
	///< Allocates the RSA keypair
	TEE_Result (*alloc_keypair)(struct rsa_keypair *key, size_t size_bits);
	///< Allocates the RSA public key
	TEE_Result (*alloc_publickey)(struct rsa_public_key *key,
					size_t size_bits);
	///< Free RSA public key
	void (*free_publickey)(struct rsa_public_key *key);
	///< Generates the RSA keypair
	TEE_Result (*gen_keypair)(struct rsa_keypair *key, size_t size_bits);

	///< RSA Encryption
	TEE_Result (*encrypt)(struct imxcrypt_rsa_ed *rsa_data);
	///< RSA Decryption
	TEE_Result (*decrypt)(struct imxcrypt_rsa_ed *rsa_data);

	///< RSA Sign a message and encode the signature
	TEE_Result (*ssa_sign)(struct imxcrypt_rsa_ssa *ssa_data);
	///< RSA Encoded Signature Verification
	TEE_Result (*ssa_verify)(struct imxcrypt_rsa_ssa *ssa_data);
};

#endif /* __LIBIMXCRYPT_ACIPHER_H__ */
