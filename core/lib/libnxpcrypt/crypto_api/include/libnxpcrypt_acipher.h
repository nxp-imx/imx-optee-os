/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 NXP
 *
 * @file    libnxpcrypt_acipher.h
 *
 * @brief   Cryptographic library using the NXP CAAM driver.\n
 *          Cipher interface library vs CAAM driver.
 */
#ifndef __LIBIMXCRYPT_ACIPHER_H__
#define __LIBIMXCRYPT_ACIPHER_H__

/* Global includes */
#include <crypto/crypto.h>
#include <tee_api_types.h>

/* Library NXP includes */
#include <libnxpcrypt_hash.h>

/**
 * @brief   Assymetric Cipher RSA Algorithm enumerate
 */
enum nxpcrypt_rsa_id {
	RSA_NOPAD = 0,   ///< RSA Algo mode NO PAD
	RSA_OAEP,        ///< RSA Algo mode OAEP
	RSA_PKCS_V1_5,   ///< RSA Algo mode PKCSv1.5
	RSA_SIGN,
};

/**
 * @brief   RSA Key object
 */
struct rsakey {
	void   *key;      ///< Public or Private key
	size_t n_size;    ///< Size in bytes of the Modulus N
	bool   isprivate; ///< True if private key
};

/**
 * @brief   RSA Mask Generation data
 */
struct nxpcrypt_rsa_mgf {
	enum nxpcrypt_hash_id hash_id;     ///< HASH Algorithm Id
	size_t                digest_size; ///< Hash Digest Size
	struct nxpcrypt_buf   seed;        ///< Seed to generate mask
	struct nxpcrypt_buf   mask;        ///< Mask generated

};

/**
 * @brief   RSA Encoded Signature data
 */
struct nxpcrypt_rsa_ssa {
	uint32_t              algo;        ///< Operation algorithm
	enum nxpcrypt_hash_id hash_id;     ///< HASH Algorithm Id
	size_t                digest_size; ///< Hash Digest Size
	struct rsakey         key;         ///< Public or Private Key
	struct nxpcrypt_buf   message;     ///< Message to sign or signed
	struct nxpcrypt_buf   signature;   ///< Signature of the message
	size_t                salt_len;    ///< Signature Salt length

	///< RSA Mask Generation function
	TEE_Result (*mgf)(struct nxpcrypt_rsa_mgf *mgf_data);
};

/**
 * @brief   RSA Encrypt/Decript data
 */
struct nxpcrypt_rsa_ed {
	enum nxpcrypt_rsa_id  rsa_id;      ///< RSA Algorithm Id
	enum nxpcrypt_hash_id hash_id;     ///< HASH Algorithm Id
	size_t                digest_size; ///< Hash Digest Size
	struct rsakey         key;         ///< Public or Private key
	struct nxpcrypt_buf   message;     ///< Message to encrypt or decrypted
	struct nxpcrypt_buf   cipher;      ///< Cipher encrypted or to decrypt
	struct nxpcrypt_buf   label;       ///< Additional Label (RSAES)

	///< RSA Mask Generation function
	TEE_Result (*mgf)(struct nxpcrypt_rsa_mgf *mgf_data);
};

/**
 * @brief   NXP Crypto Library RSA driver operations
 *
 */
struct nxpcrypt_rsa {
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
	TEE_Result (*encrypt)(struct nxpcrypt_rsa_ed *rsa_data);
	///< RSA Decryption
	TEE_Result (*decrypt)(struct nxpcrypt_rsa_ed *rsa_data);

	///< RSA Sign a message and encode the signature
	TEE_Result (*ssa_sign)(struct nxpcrypt_rsa_ssa *ssa_data);
	///< RSA Encoded Signature Verification
	TEE_Result (*ssa_verify)(struct nxpcrypt_rsa_ssa *ssa_data);

};

/**
 * @brief   Signature data
 */
struct nxpcrypt_sign_data {
	uint32_t              algo;       ///< Operation algorithm
	void                  *key;       ///< Public or Private Key
	size_t                size_sec;   ///< Security size in bytes
	struct nxpcrypt_buf   message;    ///< Message to sign or signed
	struct nxpcrypt_buf   signature;  ///< Signature of the message
};

/**
 * @brief   Shared Secret data
 */
struct nxpcrypt_secret_data {
	void                  *key_priv;  ///< Private Key
	void                  *key_pub;   ///< Public Key
	size_t                size_sec;   ///< Security size in bytes
	struct nxpcrypt_buf   secret;     ///< Share secret
};

/**
 * @brief   NXP Crypto Library DSA driver operations
 *
 */
struct nxpcrypt_dsa {
	///< Allocates the DSA keypair
	TEE_Result (*alloc_keypair)(struct dsa_keypair *key, size_t size_bits);
	///< Allocates the DSA public key
	TEE_Result (*alloc_publickey)(struct dsa_public_key *key,
					size_t size_bits);
	///< Generates the DSA keypair
	TEE_Result (*gen_keypair)(struct dsa_keypair *key, size_t size_bits);
	///< DSA Sign a message and returns the signature
	TEE_Result (*sign)(struct nxpcrypt_sign_data *sdata);
	///< DSA Verify a message's signature
	TEE_Result (*verify)(struct nxpcrypt_sign_data *sdata);
};

/**
 * @brief   NXP Crypto Library ECC driver operations
 *
 */
struct nxpcrypt_ecc {
	///< Allocates the ECC keypair
	TEE_Result (*alloc_keypair)(struct ecc_keypair *key, size_t size_bits);
	///< Allocates the ECC public key
	TEE_Result (*alloc_publickey)(struct ecc_public_key *key,
					size_t size_bits);
	///< Free ECC public key
	void (*free_publickey)(struct ecc_public_key *key);
	///< Generates the ECC keypair
	TEE_Result (*gen_keypair)(struct ecc_keypair *key, size_t size_bits);
	///< ECC Sign a message and returns the signature
	TEE_Result (*sign)(struct nxpcrypt_sign_data *sdata);
	///< ECC Verify a message's signature
	TEE_Result (*verify)(struct nxpcrypt_sign_data *sdata);
	///< ECC Shared Secret
	TEE_Result (*shared_secret)(struct nxpcrypt_secret_data *sdata);
};

/**
 * @brief   NXP Crypto Library DH driver operations
 *
 */
struct nxpcrypt_dh {
	///< Allocates the DH keypair
	TEE_Result (*alloc_keypair)(struct dh_keypair *key, size_t size_bits);
	///< Generates the DH keypair
	TEE_Result (*gen_keypair)(struct dh_keypair *key, struct bignum *q,
			size_t size_bits);
	///< DH Shared Secret
	TEE_Result (*shared_secret)(struct nxpcrypt_secret_data *sdata);
};

#endif /* __LIBIMXCRYPT_ACIPHER_H__ */
