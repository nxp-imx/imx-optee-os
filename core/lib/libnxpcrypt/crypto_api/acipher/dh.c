// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    dh.c
 *
 * @brief   Cryptographic library using the NXP CAAM driver.\n
 *          DH crypto_* interface implementation.
 */
/* Global includes */
#include <crypto/crypto.h>
#include <mpalib.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>

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
 * @brief   Allocate an ECC keypair
 *
 * @param[in]  key        Keypair
 * @param[in]  size_bits  Key size in bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 */
TEE_Result crypto_acipher_alloc_dh_keypair(struct dh_keypair *key,
						size_t size_bits)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct nxpcrypt_dh *dh = NULL;

	if ((!key) || (size_bits == 0)) {
		LIB_TRACE("Parameters error (key @0x%"PRIxPTR") (size %d bits)",
				(uintptr_t)key, size_bits);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	dh = nxpcrypt_getmod(CRYPTO_DH);
	if (dh)
		ret = dh->alloc_keypair(key, size_bits);

	LIB_TRACE("DH Keypair (%d bits) alloc ret = 0x%"PRIx32"",
						size_bits, ret);
	return ret;
}

/**
 * @brief   Generates an DH keypair
 *
 * @param[in]  key        Keypair
 * @param[out] q          Subprime
 * @param[in]  size_bits  Key size in bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 */
TEE_Result crypto_acipher_gen_dh_key(struct dh_keypair *key,
		struct bignum *q, size_t key_size)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct nxpcrypt_dh *dh = NULL;

	/* Check input parameters */
	if (!key) {
		LIB_TRACE("Parameters error key is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	dh = nxpcrypt_getmod(CRYPTO_DH);
	if (dh)
		ret = dh->gen_keypair(key, q, key_size);

	LIB_TRACE("DH Keypair (%d bits) generate ret = 0x%"PRIx32"",
						key_size, ret);

	return ret;
}

/**
 * @brief   Compute the shared secret data from DH Private key \a private_key
 *          and Public Key \a public_key
 *
 * @param[in]  private_key  DH Private key
 * @param[in]  public_key   DH Public key
 * @param[in]  secret       Secret
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_SHORT_BUFFER      Result buffer too short
 */
TEE_Result crypto_acipher_dh_shared_secret(
					struct dh_keypair *private_key,
					struct bignum *public_key,
					struct bignum *secret)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;

	struct nxpcrypt_dh          *dh = NULL;
	struct nxpcrypt_secret_data sdata;

	/* Verify first if the input parameters */
	if ((!private_key) || (!public_key) || (!secret)) {
		LIB_TRACE("Input parameters reference error");
		return ret;
	}

	dh = nxpcrypt_getmod(CRYPTO_DH);
	if (dh) {
		/*
		 * Prepare the Secret structure data
		 */
		sdata.key_priv      = private_key;
		sdata.key_pub       = public_key;
		sdata.secret.data   = (void *)secret;

		ret = dh->shared_secret(&sdata);
	} else {
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	LIB_TRACE("Shared Secret returned 0x%"PRIx32"", ret);

	return ret;
}

