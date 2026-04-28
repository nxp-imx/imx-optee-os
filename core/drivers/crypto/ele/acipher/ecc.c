// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright NXP 2023, 2026
 */

#include <drivers/ele/ele.h>
#include <drivers/ele/key_mgmt.h>
#include <drivers/ele/memutils.h>
#include <drivers/ele/sign_verify.h>
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <ecc.h>
#include <string.h>
#include <config.h>
#include <crypto/crypto_impl.h>
#include <tee/cache.h>
#include <tee_api_defines_extensions.h>
#include <utee_defines.h>
#include <util.h>

/*
 * struct crypto_ecc_keypair_ops, crypto_ecc_public_ops are used for software
 * fallback functions. crypto_ecc_keypair_ops contains generate(), sign()
 * fallback functions.
 * crypto_ecc_public_ops struct contains free(), verify() fallback functions.
 */
static const struct crypto_ecc_keypair_ops *pair_ops;
static const struct crypto_ecc_public_ops *pub_ops;

static TEE_Result curve_to_bits(uint32_t curve, size_t *key_size_bits)
{
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P224:
		*key_size_bits = 224;
		break;
	case TEE_ECC_CURVE_NIST_P256:
		*key_size_bits = 256;
		break;
	case TEE_ECC_CURVE_NIST_P384:
		*key_size_bits = 384;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		*key_size_bits = 521;
		break;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
	return TEE_SUCCESS;
}

/*
 * Get key size (in bits) from curve, translate the TEE algo to ELE algo,
 * and validate that curve/algo/digest_size are mutually consistent.
 *
 * Returns:
 *   TEE_SUCCESS if everything matches, and sets:
 *     - *key_size_bits
 *     - *ele_algo_out
 *   TEE_ERROR_NOT_IMPLEMENTED for unsupported combos.
 */
static TEE_Result get_key_size_and_algo(uint32_t curve, uint32_t tee_algo,
					size_t digest_size,
					size_t *key_size_bits,
					uint32_t *ele_algo_out)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t ele_algo = 0;
	size_t bits = 0;

	res = curve_to_bits(curve, &bits);
	if (res != TEE_SUCCESS)
		return res;

	switch (tee_algo) {
	case TEE_ALG_ECDSA_SHA224:
		ele_algo = ELE_ALGO_ECDSA_SHA224;
		break;
	case TEE_ALG_ECDSA_SHA256:
		ele_algo = ELE_ALGO_ECDSA_SHA256;
		break;
	case TEE_ALG_ECDSA_SHA384:
		ele_algo = ELE_ALGO_ECDSA_SHA384;
		break;
	case TEE_ALG_ECDSA_SHA512:
		ele_algo = ELE_ALGO_ECDSA_SHA512;
		break;
	default:
		DMSG("algorithm %#" PRIx32 " not enabled", tee_algo);
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	switch (ele_algo) {
	case ELE_ALGO_ECDSA_SHA224:
		if (!(bits == 224 && digest_size == TEE_SHA224_HASH_SIZE))
			goto err;
		break;
	case ELE_ALGO_ECDSA_SHA256:
		if (!(bits == 256 && digest_size == TEE_SHA256_HASH_SIZE))
			goto err;
		break;
	case ELE_ALGO_ECDSA_SHA384:
		if (!(bits == 384 && digest_size == TEE_SHA384_HASH_SIZE))
			goto err;
		break;
	case ELE_ALGO_ECDSA_SHA512:
		if (!(bits == 512 && digest_size == TEE_SHA512_HASH_SIZE))
			goto err;
		break;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	*key_size_bits = bits;
	*ele_algo_out  = ele_algo;

	return TEE_SUCCESS;

err:
	DMSG("Unequal key security size & digest size");
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result gen_fallback(struct ecc_keypair *key, size_t len)
{
	if (!IS_ENABLED(CFG_NXP_ELE_ECC_DRV_FALLBACK))
		return TEE_ERROR_NOT_IMPLEMENTED;

	DMSG("ELE: debug: ECC software fallback: KEYGEN");
	return pair_ops->generate(key, len);
}

static TEE_Result sign_fallback(struct drvcrypt_sign_data *sdata)
{
	if (!IS_ENABLED(CFG_NXP_ELE_ECC_DRV_FALLBACK))
		return TEE_ERROR_NOT_IMPLEMENTED;

	DMSG("ELE: debug: ECC software fallback: SIGN");
	return pair_ops->sign(sdata->algo, sdata->key, sdata->message.data,
			      sdata->message.length, sdata->signature.data,
			      &sdata->signature.length);
}

static TEE_Result verify_fallback(struct drvcrypt_sign_data *sdata)
{
	if (!IS_ENABLED(CFG_NXP_ELE_ECC_DRV_FALLBACK))
		return TEE_ERROR_NOT_IMPLEMENTED;

	DMSG("ELE: debug: ECC software fallback: VERIFY");
	return pub_ops->verify(sdata->algo, sdata->key, sdata->message.data,
			       sdata->message.length, sdata->signature.data,
			       sdata->signature.length);
}

static TEE_Result do_gen_keypair(struct ecc_keypair *key,
				 size_t size_bits)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t key_size = 0;
	size_t key_size_bits = 0;
	size_t public_key_size = 0;
	size_t priv_key_size = 0;
	uint8_t *public_key = NULL;
	uint8_t *priv_key = NULL;

	if (!key || !size_bits) {
		EMSG("key is not valid");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = curve_to_bits(key->curve, &key_size_bits);
	if (res)
		return gen_fallback(key, size_bits);

	key_size = ROUNDUP_DIV(key_size_bits, 8);
	public_key_size = key_size * 2;

	public_key = calloc(1, public_key_size);
	if (!public_key) {
		EMSG("Public key allocation failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	priv_key_size = key_size;

	priv_key = calloc(1, priv_key_size);
	if (!priv_key) {
		EMSG("Private key allocation failed");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/*
	 * For plain key generation, passing key management handle, key group,
	 * key lifetime, key usage, permitted algo, MON_INC, SYNC  as 0, as they
	 * are reserved.
	 * Passing Plain key flag as 1 for plain key generation.
	 */
	res = imx_ele_generate_key(0, priv_key, public_key_size, 0, 0, 0,
				   PLAIN_KEY, 0, 0,
				   ELE_KEY_TYPE_ECC_KEY_PAIR_SECP_R1,
				   key_size_bits, 0, 0, priv_key_size,
				   public_key, NULL);

	if (res != TEE_SUCCESS) {
		EMSG("Key generation failed");
		goto out;
	}

	crypto_bignum_bin2bn(public_key, key_size, key->x);
	crypto_bignum_bin2bn(public_key + key_size, key_size, key->y);

	crypto_bignum_bin2bn(priv_key, key_size, key->d);

out:
	free(public_key);
	free(priv_key);

	return res;
}

static TEE_Result do_sign(struct drvcrypt_sign_data *sdata)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t sig_scheme = 0;
	size_t signature_len = 0;
	struct ecc_keypair *key = NULL;
	size_t key_size_bits = 0;
	size_t key_size = 0;
	uint8_t *priv_key = NULL;
	size_t priv_key_size = 0;

	if (!sdata) {
		EMSG("sdata is not valid");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!sdata->key || !sdata->message.data || !sdata->signature.data ||
	    !sdata->message.length) {
		EMSG("Invalid key, message or signature pointer");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	signature_len = sdata->size_sec * 2;
	key = sdata->key;

	res = get_key_size_and_algo(key->curve, sdata->algo,
				    sdata->message.length, &key_size_bits,
				    &sig_scheme);
	if (res)
		return sign_fallback(sdata);

	key_size = ROUNDUP_DIV(key_size_bits, 8);
	priv_key_size = key_size;

	priv_key = calloc(1, priv_key_size);
	if (!priv_key) {
		EMSG("Private key allocation failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	crypto_bignum_bn2bin(key->d, priv_key);

	/*
	 * For plain key, passing signature generation handle and key
	 * id as 0, as they are reserved.
	 */
	res = imx_ele_signature_generate(0, 0, priv_key, priv_key_size,
					 sdata->message.data,
					 sdata->message.length,
					 sdata->signature.data,
					 signature_len, sig_scheme,
					 ELE_SIG_GEN_MSG_TYPE_DIGEST, PLAIN_KEY,
					 ELE_KEY_TYPE_ECC_PUB_KEY_SECP_R1,
					 key_size_bits);

	if (res != TEE_SUCCESS) {
		EMSG("Signature generation failed");
		goto out;
	}

	sdata->signature.length = signature_len;

out:
	free(priv_key);
	return res;
}

static TEE_Result do_verify(struct drvcrypt_sign_data *sdata)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t sig_scheme = 0;
	size_t key_size_bits = 0;
	size_t key_size = 0;
	struct ecc_public_key *key = NULL;
	size_t public_key_size = 0;
	uint8_t *public_key = NULL;

	if (!sdata) {
		EMSG("sdata is not valid");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!sdata->key || !sdata->message.data || !sdata->signature.data ||
	    !sdata->message.length || !sdata->signature.length) {
		EMSG("Invalid key, message or signature pointer");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	key = sdata->key;

	res = get_key_size_and_algo(key->curve, sdata->algo,
				    sdata->message.length, &key_size_bits,
				    &sig_scheme);
	if (res)
		return verify_fallback(sdata);

	key_size = ROUNDUP_DIV(key_size_bits, 8);
	public_key_size = key_size * 2;

	public_key = calloc(1, public_key_size);
	if (!public_key) {
		EMSG("Public key allocation failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	crypto_bignum_bn2bin(key->x, public_key);
	crypto_bignum_bn2bin(key->y, public_key + key_size);

	res = imx_ele_signature_verification(0, public_key,
					     sdata->message.data,
					     sdata->message.length,
					     sdata->signature.data,
					     sdata->signature.length,
					     public_key_size, key_size_bits,
					     ELE_KEY_TYPE_ECC_PUB_KEY_SECP_R1,
					     sig_scheme,
					     ELE_SIG_GEN_MSG_TYPE_DIGEST);

	if (res != TEE_SUCCESS)
		EMSG("Signature verification failed");

	free(public_key);
	return res;
}

static TEE_Result do_allocate_keypair(struct ecc_keypair *key, uint32_t type,
				      size_t size_bits)
{
	switch (type) {
	case TEE_TYPE_SM2_PKE_KEYPAIR:
	case TEE_TYPE_SM2_DSA_KEYPAIR:
	case TEE_TYPE_ECDH_KEYPAIR:
		/* Software fallback */
		return TEE_ERROR_NOT_IMPLEMENTED;
	default:
		break;
	}

	if (!key) {
		EMSG("key is not valid");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Initialize the key fields to NULL */
	memset(key, 0, sizeof(*key));

	/* Allocate Secure Scalar */
	key->d = crypto_bignum_allocate(size_bits);
	if (!key->d)
		goto out;

	/* Allocate Public coordinate X */
	key->x = crypto_bignum_allocate(size_bits);
	if (!key->x)
		goto out;

	/* Allocate Public coordinate Y */
	key->y = crypto_bignum_allocate(size_bits);
	if (!key->y)
		goto out;

	return TEE_SUCCESS;

out:
	crypto_bignum_free(&key->d);
	crypto_bignum_free(&key->x);

	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result do_allocate_publickey(struct ecc_public_key *key,
					uint32_t type, size_t size_bits)
{
	switch (type) {
	case TEE_TYPE_SM2_PKE_PUBLIC_KEY:
	case TEE_TYPE_SM2_DSA_PUBLIC_KEY:
	case TEE_TYPE_ECDH_PUBLIC_KEY:
		/* Software fallback */
		return TEE_ERROR_NOT_IMPLEMENTED;
	default:
		break;
	}

	if (!key) {
		EMSG("key is not valid");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Initialize the key fields to NULL */
	memset(key, 0, sizeof(*key));

	/* Allocate Public coordinate X */
	key->x = crypto_bignum_allocate(size_bits);
	if (!key->x)
		goto out;

	/* Allocate Public coordinate Y */
	key->y = crypto_bignum_allocate(size_bits);
	if (!key->y)
		goto out;

	return TEE_SUCCESS;

out:
	crypto_bignum_free(&key->x);

	return TEE_ERROR_OUT_OF_MEMORY;
}

static void do_free_publickey(struct ecc_public_key *s)
{
	if (!s)
		return;

	crypto_bignum_free(&s->x);
	crypto_bignum_free(&s->y);
}

static struct drvcrypt_ecc driver_ecc = {
	.alloc_keypair = do_allocate_keypair,
	.alloc_publickey = do_allocate_publickey,
	.free_publickey = do_free_publickey,
	.gen_keypair = do_gen_keypair,
	.sign = do_sign,
	.verify = do_verify,
};

TEE_Result imx_ele_ecc_init(void)
{
	pub_ops = crypto_asym_get_ecc_public_ops(TEE_TYPE_ECDSA_PUBLIC_KEY);
	if (!pub_ops)
		return TEE_ERROR_GENERIC;

	pair_ops = crypto_asym_get_ecc_keypair_ops(TEE_TYPE_ECDSA_KEYPAIR);
	if (!pair_ops)
		return TEE_ERROR_GENERIC;

	assert((pub_ops ==
		crypto_asym_get_ecc_public_ops(TEE_TYPE_ECDH_PUBLIC_KEY)) &&
	       (pair_ops ==
		crypto_asym_get_ecc_keypair_ops(TEE_TYPE_ECDH_KEYPAIR)));

	return drvcrypt_register_ecc(&driver_ecc);
}
