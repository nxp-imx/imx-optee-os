// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    rsa.c
 *
 * @brief   Cryptographic library using the i.MX CAAM driver.\n
 *          RSA crypto_* interface implementation.
 */
/* Global includes */
#include <crypto/crypto.h>
#include <trace.h>

#define LIB_DEBUG
#ifdef LIB_DEBUG
#define LIB_TRACE	DMSG
#else
#define LIB_TRACE(...)
#endif


TEE_Result crypto_acipher_alloc_rsa_keypair(struct rsa_keypair *s __unused,
					    size_t key_size_bits __unused)
{
	LIB_TRACE("crypto_acipher_alloc_rsa_keypair");
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result
crypto_acipher_alloc_rsa_public_key(struct rsa_public_key *s __unused,
				    size_t key_size_bits __unused)
{
	LIB_TRACE("Bypass crypto_acipher_alloc_rsa_public_key ");
	return TEE_SUCCESS;
}

void crypto_acipher_free_rsa_public_key(struct rsa_public_key *s __unused)
{
	LIB_TRACE("bad");
}

TEE_Result crypto_acipher_gen_rsa_key(struct rsa_keypair *key __unused,
				      size_t key_size __unused)
{
	LIB_TRACE("bad");
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_rsanopad_decrypt(struct rsa_keypair *key __unused,
					   const uint8_t *src __unused,
					   size_t src_len __unused,
					   uint8_t *dst __unused,
					   size_t *dst_len __unused)
{
	LIB_TRACE("bad");
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_rsanopad_encrypt(struct rsa_public_key *key __unused,
					   const uint8_t *src __unused,
					   size_t src_len __unused,
					   uint8_t *dst __unused,
					   size_t *dst_len __unused)
{
	LIB_TRACE("bad");
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_rsaes_decrypt(uint32_t algo __unused,
					struct rsa_keypair *key __unused,
					const uint8_t *label __unused,
					size_t label_len __unused,
					const uint8_t *src __unused,
					size_t src_len __unused,
					uint8_t *dst __unused,
					size_t *dst_len __unused)
{
	LIB_TRACE("bad");
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_rsaes_encrypt(uint32_t algo __unused,
					struct rsa_public_key *key __unused,
					const uint8_t *label __unused,
					size_t label_len __unused,
					const uint8_t *src __unused,
					size_t src_len __unused,
					uint8_t *dst __unused,
					size_t *dst_len __unused)
{
	LIB_TRACE("bad");
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_rsassa_sign(uint32_t algo __unused,
				      struct rsa_keypair *key __unused,
				      int salt_len __unused,
				      const uint8_t *msg __unused,
				      size_t msg_len __unused,
				      uint8_t *sig __unused,
				      size_t *sig_len __unused)
{
	LIB_TRACE("bad");
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result crypto_acipher_rsassa_verify(uint32_t algo __unused,
					struct rsa_public_key *key __unused,
					int salt_len __unused,
					const uint8_t *msg __unused,
					size_t msg_len __unused,
					const uint8_t *sig __unused,
					size_t sig_len __unused)
{
	LIB_TRACE("bypass crypto_acipher_rsassa_verify");
	return TEE_SUCCESS;
}
