// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    ecc.c
 *
 * @brief   Implementation of the ECC pseudo-driver compatible with the
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

#ifndef CFG_CRYPTO_ECC_HW
/**
 * @brief    Find in the ECC curve constant into the list of the LibTomCrypt
 *           ECC constant array.
 *
 * @param[in]  ltc_key   LibTomCrypt ECC key
 * @param[in]  size_sec  Key size in bytes
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
static TEE_Result find_ecc_param(ecc_key *ltc_key, size_t size_sec)
{
	uint8_t idx;

	if (size_sec > ECC_MAXSIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	for (idx = 0; ((int)size_sec > ltc_ecc_sets[idx].size) &&
			(ltc_ecc_sets[idx].size != 0); idx++)
		;

	if (ltc_ecc_sets[idx].size == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	ltc_key->idx = -1;
	ltc_key->dp  = &ltc_ecc_sets[idx];

	return TEE_SUCCESS;
}

/**
 * @brief   Allocate an ECC keypair
 *
 * @param[in]  key        Keypair
 * @param[in]  size_bits  Key size in bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 */
static TEE_Result do_allocate_keypair(struct ecc_keypair *key,
					size_t size_bits)
{
	/* Initialize the key fields to NULL */
	memset(key, 0, sizeof(*key));

	/* Allocate Secure Scalar */
	key->d = crypto_bignum_allocate(size_bits);
	if (!key->d)
		goto err_alloc_keypair;

	/* Allocate Public coordinate X */
	key->x = crypto_bignum_allocate(size_bits);
	if (!key->x)
		goto err_alloc_keypair;

	/* Allocate Public coordinate Y */
	key->y = crypto_bignum_allocate(size_bits);
	if (!key->y)
		goto err_alloc_keypair;

	return TEE_SUCCESS;

err_alloc_keypair:
	LIB_TRACE("Allocation error");

	crypto_bignum_free(key->d);
	crypto_bignum_free(key->x);

	return TEE_ERROR_OUT_OF_MEMORY;
}

/**
 * @brief   Allocate an ECC Public Key
 *
 * @param[in]  key        Public Key
 * @param[in]  size_bits  Key size in bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 */
static TEE_Result do_allocate_publickey(struct ecc_public_key *key,
					size_t size_bits)
{
	/* Initialize the key fields to NULL */
	memset(key, 0, sizeof(*key));

	/* Allocate Public coordinate X */
	key->x = crypto_bignum_allocate(size_bits);
	if (!key->x)
		goto err_alloc_publickey;

	/* Allocate Public coordinate Y */
	key->y = crypto_bignum_allocate(size_bits);
	if (!key->y)
		goto err_alloc_publickey;

	return TEE_SUCCESS;

err_alloc_publickey:
	LIB_TRACE("Allocation error");

	crypto_bignum_free(key->x);

	return TEE_ERROR_OUT_OF_MEMORY;
}

/**
 * @brief   Free an ECC public key
 *
 * @param[in]  key        Public Key
 */
static void do_free_publickey(struct ecc_public_key *key)
{
	crypto_bignum_free(key->x);
	crypto_bignum_free(key->y);
}

/**
 * @brief   Generates an ECC keypair
 *
 * @param[out] key        Keypair
 * @param[in]  key_size   Key size in bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result do_gen_keypair(struct ecc_keypair *key, size_t key_size)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;

	ecc_key    tmp_key = {0};
	int        ltc_res;
	size_t     size_real;
	struct ltc_prng *prng = get_ltc_prng();

	LIB_TRACE("Generate key pair");

	/* Generate a temporary ECC key */
	ltc_res = ecc_make_key(&prng->state, prng->index, (key_size / 8),
							&tmp_key);
	LIB_TRACE("ecc_make_key ret 0x%"PRIx32"", ltc_res);

	if (ltc_res == CRYPT_OK) {
		/* If the curve is the NIST P521, the real key size is 521 */
		if (key->curve == TEE_ECC_CURVE_NIST_P521)
			size_real = 521;
		else
			size_real = key_size;

		/* Check the size in bits of the keys generated */
		if (((size_t)mp_count_bits(tmp_key.pubkey.x) > size_real) ||
			((size_t)mp_count_bits(tmp_key.pubkey.y) > size_real) ||
			((size_t)mp_count_bits(tmp_key.k) > size_real))
			goto exit_ecc_gen;

		/* Check if coordinate z == 1 to validate the key */
		if (mp_count_bits(tmp_key.pubkey.z) == 1) {
			/* Copy the generated key to the output key */
			mp_copy(tmp_key.pubkey.x, key->x);
			mp_copy(tmp_key.pubkey.y, key->y);
			mp_copy(tmp_key.k, key->d);
		}
	}

	ret = conv_CRYPT_to_TEE_Result(ltc_res);

exit_ecc_gen:
	/* Free the temporary key */
	ecc_free(&tmp_key);
	return ret;
}

/**
 * @brief   Signature of ECC message
 *
 * @param[in/out]  sdata   ECC data to sign / Signature
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result do_sign(struct nxpcrypt_sign_data *sdata)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;

	struct ltc_prng *prng = get_ltc_prng();
	struct ecc_keypair *inkey = sdata->key;
	ecc_key ltc_key = {0};
	int     ltc_res;
	void    *sig_c = NULL;
	void    *sig_d = NULL;

	/* Convert the input key to LibTomCrypt ECC key */
	ltc_key.type = PK_PRIVATE;
	ltc_key.k    = inkey->d;

	ret = find_ecc_param(&ltc_key, sdata->size_sec);
	if (ret != TEE_SUCCESS)
		return ret;

	/* Allocate the signature integer pairs (c, d) */
	ltc_res = mp_init_multi(&sig_c, &sig_d, NULL);
	if (ltc_res != CRYPT_OK) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto end_sign;
	}

	ltc_res = ecc_sign_hash_raw(sdata->message.data, sdata->message.length,
			sig_c, sig_d, &prng->state, prng->index, &ltc_key);

	LIB_TRACE("ecc_sign_hash_raw ret 0x%"PRIx32"", ltc_res);

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
 * @brief   Verification of the Signature of ECC message
 *
 * @param[in/out]  sdata   ECC Signature to verify
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_SIGNATURE_INVALID Signature is not valid
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
static TEE_Result do_verify(struct nxpcrypt_sign_data *sdata)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;

	struct ecc_public_key *inkey = sdata->key;
	ecc_key ltc_key = {0};
	int     ltc_res;
	int     stat;
	void    *sig_c = NULL;
	void    *sig_d = NULL;
	void    *key_z = NULL;
	uint8_t one[1] = { 1 };

	/*
	 * Allocate the signature integer pairs (c, d)
	 * and the key z coordinate
	 */
	ltc_res = mp_init_multi(&key_z, &sig_c, &sig_d, NULL);
	if (ltc_res != CRYPT_OK) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto end_verif;
	}

	mp_read_unsigned_bin(key_z, one, sizeof(one));

	/* Convert the input key to LibTomCrypt ECC key */
	ltc_key.type     = PK_PUBLIC;
	ltc_key.pubkey.x = inkey->x;
	ltc_key.pubkey.y = inkey->y;
	ltc_key.pubkey.z = key_z;

	ret = find_ecc_param(&ltc_key, sdata->size_sec);
	if (ret != TEE_SUCCESS)
		goto end_verif;

	mp_read_unsigned_bin(sig_c, sdata->signature.data,
			sdata->signature.length / 2);
	mp_read_unsigned_bin(sig_d,
			sdata->signature.data + (sdata->signature.length / 2),
			sdata->signature.length / 2);

	ltc_res = ecc_verify_hash_raw(sig_c, sig_d,
			sdata->message.data, sdata->message.length,
			&stat, &ltc_key);

	LIB_TRACE("ecc_verify_hash_raw ret 0x%"PRIx32"", ltc_res);

	if ((ltc_res != CRYPT_OK) || (stat != 1))
		ret = TEE_ERROR_SIGNATURE_INVALID;
	else
		ret = TEE_SUCCESS;

end_verif:
	mp_clear_multi(key_z, sig_c, sig_d, NULL);

	return ret;
}

/**
 * @brief   Compute the shared secret data from ECC Private key \a private_key
 *          and Public Key \a public_key
 *
 * @param[in/out]  sdata   ECC Shared Secret data
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_SHORT_BUFFER      Result buffer too short
 */
static TEE_Result do_shared_secret(struct nxpcrypt_secret_data *sdata)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;

	struct ecc_keypair    *inkey_priv = sdata->key_priv;
	struct ecc_public_key *inkey_pub  = sdata->key_pub;
	ecc_key ltc_key_priv = {0};
	ecc_key ltc_key_pub  = {0};
	int     ltc_res;
	void    *key_z = NULL;
	uint8_t one[1] = { 1 };
	unsigned long secret_len;

	/* Allocate the Public Key z coordinate */
	ltc_res = mp_init(&key_z);
	if (ltc_res != CRYPT_OK) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto end_secret;
	}

	mp_read_unsigned_bin(key_z, one, sizeof(one));

	/* Convert the input public key to LibTomCrypt ECC key */
	ltc_key_pub.type     = PK_PUBLIC;
	ltc_key_pub.pubkey.x = inkey_pub->x;
	ltc_key_pub.pubkey.y = inkey_pub->y;
	ltc_key_pub.pubkey.z = key_z;

	ret = find_ecc_param(&ltc_key_pub, sdata->size_sec);
	if (ret != TEE_SUCCESS)
		goto end_secret;

	/* Convert the input private key to LibTomCrypt ECC key */
	ltc_key_priv.type = PK_PRIVATE;
	ltc_key_priv.k    = inkey_priv->d;
	ltc_key_priv.idx  = ltc_key_pub.idx;
	ltc_key_priv.dp   = ltc_key_pub.dp;

	secret_len = sdata->secret.length;

	ltc_res = ecc_shared_secret(&ltc_key_priv, &ltc_key_pub,
				    sdata->secret.data, &secret_len);
	LIB_TRACE("ecc_shared_secret ret 0x%"PRIx32"", ltc_res);

	sdata->secret.length = secret_len;

	ret = conv_CRYPT_to_TEE_Result(ltc_res);

end_secret:
	mp_clear(key_z);

	return ret;
}

/**
 * @brief   Registration of the ECC Driver
 */
struct nxpcrypt_ecc driver_ecc = {
	.alloc_keypair   = &do_allocate_keypair,
	.alloc_publickey = &do_allocate_publickey,
	.free_publickey  = &do_free_publickey,
	.gen_keypair     = &do_gen_keypair,
	.sign            = &do_sign,
	.verify          = &do_verify,
	.shared_secret   = &do_shared_secret,
};

/**
 * @brief   Initialize the ECC module
 *
 * @retval  0    Success
 * @retval  (-1) Otherwise
 */
int libsoft_ecc_init(void)
{
	int ret;

	ret = nxpcrypt_register(CRYPTO_ECC, &driver_ecc);

	return ret;
}

#endif /* CFG_CRYPTO_ECC_HW */

