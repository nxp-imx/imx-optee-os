// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    dh.c
 *
 * @brief   Implementation of the DH pseudo-driver compatible with the
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
	size_t max_size = (mpa_StaticVarSizeInU32(LTC_MAX_BITS_PER_VARIABLE)
						* sizeof(uint32_t) * 8);

	return crypto_bignum_allocate(max_size);
}

/**
 * @brief   Allocate an DH keypair
 *
 * @param[in]  key        Keypair
 * @param[in]  size_bits  Key size in bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 */
static TEE_Result do_allocate_keypair(struct dh_keypair *key,
					size_t size_bits __unused)
{
	/* Initialize the key fields to NULL */
	memset(key, 0, sizeof(*key));

	/* Generator Point */
	key->g = do_allocate_max_bn();
	if (!key->g)
		goto err_alloc_keypair;

	/* Allocate Prime Number */
	key->p = do_allocate_max_bn();
	if (!key->p)
		goto err_alloc_keypair;

	/* Allocate Private key X */
	key->x = do_allocate_max_bn();
	if (!key->x)
		goto err_alloc_keypair;

	/* Allocate Public key Y */
	key->y = do_allocate_max_bn();
	if (!key->y)
		goto err_alloc_keypair;

	/* Allocate Optional Q subprime */
	key->q = do_allocate_max_bn();
	if (!key->q)
		goto err_alloc_keypair;

	return TEE_SUCCESS;

err_alloc_keypair:
	LIB_TRACE("Allocation error");

	crypto_bignum_free(key->g);
	crypto_bignum_free(key->p);
	crypto_bignum_free(key->x);
	crypto_bignum_free(key->q);

	return TEE_ERROR_OUT_OF_MEMORY;
}

/**
 * @brief   Generates an DH keypair
 *
 * @param[out] key        Keypair
 * @param[out] q          Subprime
 * @param[in]  key_size   Key size in bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result do_gen_keypair(struct dh_keypair *key,
		struct bignum *q, size_t key_size)
{
	dh_key     tmp_key = {0};
	int        ltc_res;
	struct ltc_prng *prng = get_ltc_prng();

	LIB_TRACE("Generate key pair");

	tmp_key.g = key->g;
	tmp_key.p = key->p;

	/* Generate a temporary DH key */
	ltc_res = dh_make_key(&prng->state, prng->index, q, key_size,
							&tmp_key);
	LIB_TRACE("dh_make_key ret 0x%"PRIx32"", ltc_res);

	if (ltc_res == CRYPT_OK) {
		/* Copy the generated key to the output key */
		mp_copy(tmp_key.x,  key->x);
		mp_copy(tmp_key.y,  key->y);
	}

	/* Free the temporary key */
	dh_free(&tmp_key);

	return conv_CRYPT_to_TEE_Result(ltc_res);
}

/**
 * @brief   Compute the shared secret data from DH Private key \a private_key
 *          and Public Key \a public_key
 *
 * @param[in/out]  sdata   DH Shared Secret data
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_SHORT_BUFFER      Result buffer too short
 */
static TEE_Result do_shared_secret(struct nxpcrypt_secret_data *sdata)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;

	struct dh_keypair *inkey_priv = sdata->key_priv;
	dh_key ltc_key_priv;
	int    ltc_res;

	/* Convert the input key private to LibTomCrypt DH key */
	ltc_key_priv.type = PK_PRIVATE,
	ltc_key_priv.g    = inkey_priv->g;
	ltc_key_priv.p    = inkey_priv->p;
	ltc_key_priv.y    = inkey_priv->y;
	ltc_key_priv.x    = inkey_priv->x;


	ltc_res = dh_shared_secret(&ltc_key_priv, sdata->key_pub,
			sdata->secret.data);
	LIB_TRACE("dh_shared_secret ret 0x%"PRIx32"", ltc_res);

	ret = conv_CRYPT_to_TEE_Result(ltc_res);

	return ret;
}

/**
 * @brief   Registration of the DH Driver
 */
struct nxpcrypt_dh driver_dh = {
	.alloc_keypair   = &do_allocate_keypair,
	.gen_keypair     = &do_gen_keypair,
	.shared_secret   = &do_shared_secret,
};

/**
 * @brief   Initialize the DH module
 *
 * @retval  0    Success
 * @retval  (-1) Otherwise
 */
int libsoft_dh_init(void)
{
	int ret;

	ret = nxpcrypt_register(CRYPTO_DH, &driver_dh);

	return ret;
}
