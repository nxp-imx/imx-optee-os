// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    dsa.c
 *
 * @brief   Implementation of the DSA pseudo-driver compatible with the
 *          NXP cryptographic library and using the TomCrypt software
 *          driver
 */
/* Global includes */
#include <mpalib.h>
#include <trace.h>

/* Library NXP includes */
#include <libnxpcrypt.h>
#include <libnxpcrypt_acipher.h>

/* Local includes */
#include "local.h"

//#define LIB_DEBUG
#ifdef LIB_DEBUG
#define LIB_TRACE	DMSG
#else
#define LIB_TRACE(...)
#endif

/**
 * @brief   Allocate the maximum bignumber
 *
 * @retval bignumber allocated if success
 * @retval NULL if error
 */
static struct bignum *do_allocate_max_bn(void)
{
	size_t max_size = (mpa_StaticVarSizeInU32(MAX_DSA_SIZE)
						* sizeof(uint32_t) * 8);

	return crypto_bignum_allocate(max_size);
}

/**
 * @brief   Allocate a DSA keypair
 *
 * @param[in]  key        Keypair
 * @param[in]  size_bits  Key size in bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 */
static TEE_Result do_allocate_keypair(struct dsa_keypair *key,
					size_t size_bits __unused)
{
	/* Initialize the key fields to NULL */
	memset(key, 0, sizeof(*key));

	/* Allocate Generator of subgroup */
	key->g = do_allocate_max_bn();
	if (!key->g)
		goto err_alloc_keypair;

	/* Allocate prime p */
	key->p = do_allocate_max_bn();
	if (!key->p)
		goto err_alloc_keypair;

	/* Allocate prime q */
	key->q = do_allocate_max_bn();
	if (!key->q)
		goto err_alloc_keypair;

	/* Allocate Public key */
	key->y = do_allocate_max_bn();
	if (!key->y)
		goto err_alloc_keypair;

	/* Allocate Private key */
	key->x = do_allocate_max_bn();
	if (!key->x)
		goto err_alloc_keypair;

	return TEE_SUCCESS;

err_alloc_keypair:
	LIB_TRACE("Allocation error");

	crypto_bignum_free(key->g);
	crypto_bignum_free(key->p);
	crypto_bignum_free(key->q);
	crypto_bignum_free(key->y);

	return TEE_ERROR_OUT_OF_MEMORY;
}

/**
 * @brief   Allocate a DSA Public Key
 *
 * @param[in]  key        Public Key
 * @param[in]  size_bits  Key size in bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 */
static TEE_Result do_allocate_publickey(struct dsa_public_key *key,
					size_t size_bits __unused)
{
	/* Initialize the key fields to NULL */
	memset(key, 0, sizeof(*key));

	/* Allocate Generator of subgroup */
	key->g = do_allocate_max_bn();
	if (!key->g)
		goto err_alloc_publickey;

	/* Allocate prime p */
	key->p = do_allocate_max_bn();
	if (!key->p)
		goto err_alloc_publickey;

	/* Allocate prime q */
	key->q = do_allocate_max_bn();
	if (!key->q)
		goto err_alloc_publickey;

	/* Allocate Public key */
	key->y = do_allocate_max_bn();
	if (!key->y)
		goto err_alloc_publickey;

	return TEE_SUCCESS;

err_alloc_publickey:
	LIB_TRACE("Allocation error");

	crypto_bignum_free(key->g);
	crypto_bignum_free(key->p);
	crypto_bignum_free(key->q);

	return TEE_ERROR_OUT_OF_MEMORY;
}

/**
 * @brief   Generates a DSA keypair
 *
 * @param[out] key        Keypair
 * @param[in]  key_size   Key size in bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
static TEE_Result do_gen_keypair(struct dsa_keypair *key, size_t key_size)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;

	dsa_key    tmp_key;
	int        ltc_res;
	size_t     modulus = (key_size / 8);
	size_t     group;
	struct ltc_prng *prng = get_ltc_prng();

	LIB_TRACE("Generate key pair");

	if (modulus <= 128)
		group = 20;
	else if (modulus <= 256)
		group = 32;
	else if (modulus <= 384)
		group = 35;
	else
		group = 40;

	/* Generate a temporary DSA key */
	ltc_res = dsa_make_key(&prng->state, prng->index, group, modulus,
							&tmp_key);

	if (ltc_res == CRYPT_OK) {
		if ((size_t)mp_count_bits(tmp_key.p) == key_size) {
			/* Copy the generated key to the output key */
			mp_copy(tmp_key.g,  key->g);
			mp_copy(tmp_key.p,  key->p);
			mp_copy(tmp_key.q,  key->q);
			mp_copy(tmp_key.y,  key->y);
			mp_copy(tmp_key.x,  key->x);

			ret = TEE_SUCCESS;
		}

		/* Free the temporary key */
		dsa_free(&tmp_key);
	}

	return ret;
}

/**
 * @brief   Signature of DSA message
 *
 * @param[in/out]  sdata   DSA data to sign / Signature
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_SHORT_BUFFER      Result buffer too short
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result do_sign(struct nxpcrypt_sign_data *sdata)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct ltc_prng *prng = get_ltc_prng();
	struct dsa_keypair *inkey = sdata->key;
	dsa_key ltc_key = {0};
	int     ltc_res;
	void    *sig_c = NULL;
	void    *sig_d = NULL;

	if ((sdata->algo != TEE_ALG_DSA_SHA1) &&
	    (sdata->algo != TEE_ALG_DSA_SHA224) &&
	    (sdata->algo != TEE_ALG_DSA_SHA256))
		return TEE_ERROR_NOT_IMPLEMENTED;

	/* Convert the input key to LibTomCrypt DSA key */
	ltc_key.type = PK_PRIVATE;
	ltc_key.qord = sdata->size_sec;
	ltc_key.g    = inkey->g;
	ltc_key.p    = inkey->p;
	ltc_key.q    = inkey->q;
	ltc_key.y    = inkey->y;
	ltc_key.x    = inkey->x;

	/* Allocate the signature integer pairs (c, d) */
	ltc_res = mp_init_multi(&sig_c, &sig_d, NULL);
	if (ltc_res != CRYPT_OK) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto end_sign;
	}

	ltc_res = dsa_sign_hash_raw(sdata->message.data, sdata->message.length,
			sig_c, sig_d, &prng->state, prng->index, &ltc_key);

	LIB_TRACE("dsa_sign_hash_raw ret  0x%"PRIx32"", ltc_res);

	if (ltc_res == CRYPT_OK) {
		sdata->signature.length = 2 * sdata->size_sec;

		memset(sdata->signature.data, 0, sdata->signature.length);

		/*
		 * Copy the computed signature to output buffer
		 * Add pad of 0's in the same time
		 */
		mp_to_unsigned_bin(sig_c, sdata->signature.data +
				sdata->size_sec -
				mp_unsigned_bin_size(sig_c));
		mp_to_unsigned_bin(sig_d, sdata->signature.data +
				(2 * sdata->size_sec) -
				mp_unsigned_bin_size(sig_d));
	}

	ret = conv_CRYPT_to_TEE_Result(ltc_res);

end_sign:
	mp_clear_multi(sig_c, sig_d, NULL);

	return ret;
}

/**
 * @brief   Verification of the Signature of DSA message
 *
 * @param[in/out]  sdata   DSA Signature to verify
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_SIGNATURE_INVALID Signature is not valid
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 */
static TEE_Result do_verify(struct nxpcrypt_sign_data *sdata)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct dsa_public_key *inkey = sdata->key;
	dsa_key ltc_key = {0};
	int     ltc_res;
	int     stat;
	void    *sig_c = NULL;
	void    *sig_d = NULL;

	if ((sdata->algo != TEE_ALG_DSA_SHA1) &&
	    (sdata->algo != TEE_ALG_DSA_SHA224) &&
	    (sdata->algo != TEE_ALG_DSA_SHA256))
		return TEE_ERROR_NOT_IMPLEMENTED;

	/* Convert the input key to LibTomCrypt DSA key */
	ltc_key.type = PK_PUBLIC;
	ltc_key.qord = sdata->size_sec;
	ltc_key.g    = inkey->g;
	ltc_key.p    = inkey->p;
	ltc_key.q    = inkey->q;
	ltc_key.y    = inkey->y;

	/* Allocate the signature integer pairs (c, d) */
	ltc_res = mp_init_multi(&sig_c, &sig_d, NULL);
	if (ltc_res != CRYPT_OK) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto end_sign;
	}

	mp_read_unsigned_bin(sig_c, sdata->signature.data,
			sdata->signature.length / 2);
	mp_read_unsigned_bin(sig_d,
			sdata->signature.data + (sdata->signature.length / 2),
			sdata->signature.length / 2);

	ltc_res = dsa_verify_hash_raw(sig_c, sig_d,
			sdata->message.data, sdata->message.length,
			&stat, &ltc_key);

	LIB_TRACE("dsa_verify_hash_raw ret 0x%"PRIx32"", ltc_res);

	if ((ltc_res != CRYPT_OK) || (stat != 1))
		ret = TEE_ERROR_SIGNATURE_INVALID;
	else
		ret = TEE_SUCCESS;

end_sign:
	mp_clear_multi(sig_c, sig_d, NULL);

	return ret;
}

/**
 * @brief   Registration of the RSA Driver
 */
struct nxpcrypt_dsa driver_dsa = {
	.alloc_keypair   = &do_allocate_keypair,
	.alloc_publickey = &do_allocate_publickey,
	.gen_keypair     = &do_gen_keypair,
	.sign            = &do_sign,
	.verify          = &do_verify,
};

/**
 * @brief   Initialize the DSA module
 *
 * @retval  0    Success
 * @retval  (-1) Otherwise
 */
int libsoft_dsa_init(void)
{
	int ret;

	ret = nxpcrypt_register(CRYPTO_DSA, &driver_dsa);

	return ret;
}
