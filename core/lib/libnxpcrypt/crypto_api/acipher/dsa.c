// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    dsa.c
 *
 * @brief   Cryptographic library using the NXP CAAM driver.\n
 *          DSA crypto_* interface implementation.
 */
/* Global includes */
#include <crypto/crypto.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>
#include <utee_defines.h>

/* Library NXP includes */
#include <libnxpcrypt.h>
#include <libnxpcrypt_acipher.h>

//#define LIB_DEBUG
#ifdef LIB_DEBUG
#define LIB_TRACE	DMSG
#else
#define LIB_TRACE(...)
#endif

/**
 * @brief   Allocate a DSA keypair
 *
 * @param[in]  key        Keypair
 * @param[in]  size_bits  Key size in bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 */
TEE_Result crypto_acipher_alloc_dsa_keypair(struct dsa_keypair *key,
						size_t size_bits)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct nxpcrypt_dsa *dsa = NULL;

	if ((!key) || (size_bits == 0)) {
		LIB_TRACE("Parameters error (key @0x%"PRIxPTR") (size %d bits)",
				(uintptr_t)key, size_bits);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	dsa = nxpcrypt_getmod(CRYPTO_DSA);
	if (dsa)
		ret = dsa->alloc_keypair(key, size_bits);

	LIB_TRACE("DSA Keypair (%d bits) alloc ret = 0x%"PRIx32"",
						size_bits, ret);
	return ret;
}

/**
 * @brief   Allocate a DSA public key
 *
 * @param[in]  key        Public Key
 * @param[in]  size_bits  Key size in bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 */
TEE_Result crypto_acipher_alloc_dsa_public_key(struct dsa_public_key *key,
						size_t size_bits)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct nxpcrypt_dsa *dsa = NULL;

	if ((!key) || (size_bits == 0)) {
		LIB_TRACE("Parameters error (key @0x%"PRIxPTR") (size %d bits)",
				(uintptr_t)key, size_bits);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	dsa = nxpcrypt_getmod(CRYPTO_DSA);
	if (dsa)
		ret = dsa->alloc_publickey(key, size_bits);

	LIB_TRACE("DSA Public Key (%d bits) alloc ret = 0x%"PRIx32"",
						size_bits, ret);
	return ret;
}

/**
 * @brief   Generates a DSA keypair
 *
 * @param[in]  key        Keypair
 * @param[in]  size_bits  Key size in bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 */
TEE_Result crypto_acipher_gen_dsa_key(struct dsa_keypair *key, size_t size_bits)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct nxpcrypt_dsa *dsa = NULL;

	/* Check input parameters */
	if ((!key) || (size_bits == 0)) {
		LIB_TRACE("Parameters error (key @0x%"PRIxPTR") (size %d bits)",
				(uintptr_t)key, size_bits);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	dsa = nxpcrypt_getmod(CRYPTO_DSA);
	if (dsa)
		ret = dsa->gen_keypair(key, size_bits);

	LIB_TRACE("DSA Keypair (%d bits) generate ret = 0x%"PRIx32"",
						size_bits, ret);

	return ret;
}

/**
 * @brief   Sign the message \a msg.
 *          Message is signed with the DSA Key given by the Keypair \a key
 *
 * @param[in]     algo       DSA algorithm
 * @param[in]     key        DSA Keypair
 * @param[in]     msg        Message to sign
 * @param[in]     msg_len    Length of the message (bytes)
 * @param[out]    sig        Signature
 * @param[in/out] sig_len    Length of the signature (bytes)
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_SHORT_BUFFER      Result buffer too short
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 * @retval TEE_ERROR_SECURITY          Invalid message
 */
TEE_Result crypto_acipher_dsa_sign(uint32_t algo,
					struct dsa_keypair *key,
					const uint8_t *msg, size_t msg_len,
					uint8_t *sig, size_t *sig_len)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;

	struct nxpcrypt_dsa       *dsa = NULL;
	struct nxpcrypt_sign_data sdata;
	size_t                    size_digest;
	size_t                    qorder;

	/* Verify first if the input parameters */
	if ((!key) || (!msg) || (!sig) || (!sig_len)) {
		LIB_TRACE("Input parameters reference error");
		return ret;
	}

	/* Check if the message length is digest hash size */
	ret = tee_hash_get_digest_size(algo, &size_digest);
	if (ret != TEE_SUCCESS)
		return ret;

	qorder = crypto_bignum_num_bytes(key->q);
	if (qorder < size_digest)
		size_digest = qorder;

	if (msg_len != size_digest) {
		LIB_TRACE("Input message length incorrect (%d - expected %d)",
					msg_len, size_digest);
		return TEE_ERROR_SECURITY;
	}

	if (*sig_len < (2 * qorder)) {
		LIB_TRACE("Signature length (%d) too short expected %d bytes",
					*sig_len, qorder);
		*sig_len = 2 * qorder;
		return TEE_ERROR_SHORT_BUFFER;
	}

	dsa = nxpcrypt_getmod(CRYPTO_DSA);
	if (dsa) {
		/*
		 * Prepare the Signature structure data
		 */
		sdata.algo             = algo;
		sdata.key              = key;
		sdata.size_sec         = qorder;
		sdata.message.data     = (uint8_t *)msg;
		sdata.message.length   = msg_len;
		sdata.signature.data   = (uint8_t *)sig;
		sdata.signature.length = *sig_len;

		ret = dsa->sign(&sdata);

		/* Set the signature length */
		*sig_len = sdata.signature.length;
	} else {
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	LIB_TRACE("Sign algo (0x%"PRIx32") returned 0x%"PRIx32"",
		algo, ret);

	return ret;
}

/**
 * @brief   Verify the signature of the message \a msg.
 *          Message is signed with the DSA Key given by the Public Key \a key
 *
 * @param[in]  algo       DSA algorithm
 * @param[in]  key        DSA Public key
 * @param[in]  msg        Message to sign
 * @param[in]  msg_len    Length of the message (bytes)
 * @param[in]  sig        Signature
 * @param[in]  sig_len    Length of the signature (bytes)
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_SIGNATURE_INVALID Signature is not valid
 */
TEE_Result crypto_acipher_dsa_verify(uint32_t algo,
					struct dsa_public_key *key,
					const uint8_t *msg, size_t msg_len,
					const uint8_t *sig, size_t sig_len)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;

	struct nxpcrypt_dsa       *dsa = NULL;
	struct nxpcrypt_sign_data sdata;

	/* Verify first if the input parameters */
	if ((!key) || (!msg) || (!sig)) {
		LIB_TRACE("Input parameters reference error");
		return ret;
	}

	dsa = nxpcrypt_getmod(CRYPTO_DSA);
	if (dsa) {
		/*
		 * Prepare the Signature structure data
		 */
		sdata.algo             = algo;
		sdata.key              = key;
		sdata.size_sec         = crypto_bignum_num_bytes(key->q);
		sdata.message.data     = (uint8_t *)msg;
		sdata.message.length   = msg_len;
		sdata.signature.data   = (uint8_t *)sig;
		sdata.signature.length = sig_len;

		ret = dsa->verify(&sdata);
	} else {
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	LIB_TRACE("Verify algo (0x%"PRIx32") returned 0x%"PRIx32"",
		algo, ret);

	return ret;
}

