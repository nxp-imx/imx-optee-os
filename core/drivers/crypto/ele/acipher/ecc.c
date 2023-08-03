// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright NXP 2023
 */

#include <acipher.h>
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <ele.h>
#include <key_store.h>
#include <string.h>
#include <tee/cache.h>
#include <tee/tee_cryp_utl.h>
#include <tee_api_defines_extensions.h>
#include <utee_defines.h>
#include <util.h>
#include <utils_mem.h>

/* ECC Key types */
#define ELE_KEY_TYPE_ECC_KEY_PAIR_BRAINPOOL_R1	 0x7130
#define ELE_KEY_TYPE_ECC_PUB_KEY_BRAINPOOL_R1 0x4130
#define ELE_KEY_TYPE_ECC_KEY_PAIR_BRAINPOOL_T1	 0x7180
#define ELE_KEY_TYPE_ECC_PUB_KEY_BRAINPOOL_T1 0x4180
#define ELE_KEY_TYPE_ECC_KEY_PAIR_SECP_R1	 0x7112
#define ELE_KEY_TYPE_ECC_PUB_KEY_SECP_R1	 0x4112

/* Key permitted algorithms */
#define ELE_ALGO_ECDSA_SHA224	     0x06000608
#define ELE_ALGO_ECDSA_SHA256	     0x06000609
#define ELE_ALGO_ECDSA_SHA384	     0x0600060A
#define ELE_ALGO_ECDSA_SHA512	     0x0600060B
#define ELE_ALGO_ECDSA_ANY	     0x06000600
#define ELE_ALGO_ECDSA_NOT_SUPPORTED 0x12345678

static uint32_t algo_tee2ele(uint32_t algo)
{
	switch (algo) {
	case TEE_ALG_ECDSA_P224:
		return ELE_ALGO_ECDSA_SHA224;
	case TEE_ALG_ECDSA_P256:
		return ELE_ALGO_ECDSA_SHA256;
	case TEE_ALG_ECDSA_P384:
		return ELE_ALGO_ECDSA_SHA384;
	case TEE_ALG_ECDSA_P521:
		return ELE_ALGO_ECDSA_SHA512;
	default:
		EMSG("algorithm %#" PRIx32 " not enabled", algo);
		return ELE_ALGO_ECDSA_NOT_SUPPORTED;
	}
}

static TEE_Result do_shared_secret(struct drvcrypt_secret_data *sdata __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static TEE_Result get_key_size(uint32_t curve, size_t *key_size_bits)
{
	if (!key_size_bits) {
		EMSG("Key size is not valid");
		return TEE_ERROR_BAD_PARAMETERS;
	}

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
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result get_permitted_algo(uint32_t curve, uint32_t *permitted_algo)
{
	if (!permitted_algo) {
		EMSG("permitted_algo is not valid");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	switch (curve) {
	case TEE_ECC_CURVE_NIST_P224:
		*permitted_algo = ELE_ALGO_ECDSA_SHA224;
		break;
	case TEE_ECC_CURVE_NIST_P256:
		*permitted_algo = ELE_ALGO_ECDSA_SHA256;
		break;
	case TEE_ECC_CURVE_NIST_P384:
		*permitted_algo = ELE_ALGO_ECDSA_SHA384;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		*permitted_algo = ELE_ALGO_ECDSA_SHA512;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result do_gen_keypair(struct ecc_keypair *key,
				 size_t size_bits __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t key_mgmt_handle = 0;
	uint32_t key_id = 0;
	size_t key_size = 0;
	size_t key_size_bits = 0;
	size_t public_key_size = 0;
	uint32_t key_store_handle = 0;
	uint32_t permitted_algo = 0;
	uint8_t *public_key = NULL;

	if (!key) {
		EMSG("key is not valid");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = get_permitted_algo(key->curve, &permitted_algo);
	if (res != TEE_SUCCESS) {
		EMSG("Curve not supported");
		return res;
	}

	res = get_key_size(key->curve, &key_size_bits);
	if (res != TEE_SUCCESS) {
		EMSG("Curve not supported");
		return res;
	}

	key_size = ROUNDUP_DIV(key_size_bits, 8);
	public_key_size = key_size * 2;

	public_key = calloc(1, public_key_size);
	if (!public_key) {
		EMSG("Public key allocation failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	res = imx_ele_get_global_key_store_handle(&key_store_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Getting key store handle failed");
		goto out;
	}

	res = imx_ele_key_mgmt_open(key_store_handle, &key_mgmt_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Key management open failed");
		goto out;
	}

	res = imx_ele_generate_key(key_mgmt_handle, public_key_size,
				   ELE_KEY_GROUP_VOLATILE, false, false,
				   ELE_KEY_LIFETIME_VOLATILE,
				   ELE_KEY_USAGE_SIGN_HASH |
				   ELE_KEY_USAGE_VERIFY_HASH |
				   ELE_KEY_USAGE_SIGN_MSG |
				   ELE_KEY_USAGE_VERIFY_MSG,
				   ELE_KEY_TYPE_ECC_KEY_PAIR_SECP_R1,
				   key_size_bits, permitted_algo,
				   ELE_KEY_LIFECYCLE_DEVICE,
				   public_key, &key_id);

	res |= imx_ele_key_mgmt_close(key_mgmt_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Key generation/Key management close failed");
		goto out;
	}

	crypto_bignum_bin2bn(public_key, key_size, key->x);
	crypto_bignum_bin2bn(public_key + key_size, key_size, key->y);

	crypto_bignum_bin2bn((uint8_t *)&key_id, sizeof(key_id), key->d);

out:
	free(public_key);
	return res;
}

static TEE_Result do_sign(struct drvcrypt_sign_data *sdata)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t key_id = 0;
	uint32_t sig_gen_handle = 0;
	uint32_t sig_scheme = 0;
	size_t signature_len = 0;
	struct ecc_keypair *key = NULL;
	uint32_t key_store_handle = 0;

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
	if (crypto_bignum_num_bytes(key->d) != sizeof(uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	sig_scheme = algo_tee2ele(sdata->algo);
	if (sig_scheme == ELE_ALGO_ECDSA_NOT_SUPPORTED) {
		EMSG("Signature scheme not supported");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	crypto_bignum_bn2bin(key->d, (uint8_t *)&key_id);

	res = imx_ele_get_global_key_store_handle(&key_store_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Getting key store handle failed");
		return res;
	}

	res = imx_ele_sig_gen_open(key_store_handle, &sig_gen_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Signature generation service flow open failed");
		return res;
	}

	res = imx_ele_signature_generate(sig_gen_handle, key_id,
					 sdata->message.data,
					 sdata->message.length,
					 sdata->signature.data,
					 signature_len,
					 sig_scheme,
					 ELE_SIG_GEN_MSG_TYPE_MESSAGE);

	res |= imx_ele_sig_gen_close(sig_gen_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Signature generation/Signature flow close failed");
		goto out;
	}

	sdata->signature.length = signature_len;

out:
	return res;
}

static TEE_Result do_verify(struct drvcrypt_sign_data *sdata)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t sig_verify_handle = 0;
	uint32_t sig_scheme = 0;
	size_t key_size_bits = 0;
	size_t key_size = 0;
	struct ecc_public_key *key = NULL;
	size_t public_key_size = 0;
	uint32_t session_handle = 0;
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

	res = get_key_size(key->curve, &key_size_bits);
	if (res != TEE_SUCCESS) {
		EMSG("Curve not supported");
		return res;
	}

	sig_scheme = algo_tee2ele(sdata->algo);
	if (sig_scheme == ELE_ALGO_ECDSA_NOT_SUPPORTED) {
		EMSG("Signature scheme not supported");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	key_size = ROUNDUP_DIV(key_size_bits, 8);
	public_key_size = key_size * 2;

	public_key = calloc(1, public_key_size);
	if (!public_key) {
		EMSG("Public key allocation failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	crypto_bignum_bn2bin(key->x, public_key);
	crypto_bignum_bn2bin(key->y, public_key + key_size);

	res = imx_ele_get_global_session_handle(&session_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Getting global session handle failed");
		goto out;
	}

	res = imx_ele_sig_verify_open(session_handle, &sig_verify_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Signature verification service flow open failed");
		goto out;
	}

	res = imx_ele_signature_verification(sig_verify_handle,
					     public_key,
					     sdata->message.data,
					     sdata->message.length,
					     sdata->signature.data,
					     sdata->signature.length,
					     public_key_size, key_size_bits,
					     ELE_KEY_TYPE_ECC_PUB_KEY_SECP_R1,
					     sig_scheme,
					     ELE_SIG_GEN_MSG_TYPE_MESSAGE);

	res |= imx_ele_sig_verify_close(sig_verify_handle);
	if (res != TEE_SUCCESS)
		EMSG("Signature verif/Signature verif flow close failed");

out:
	free(public_key);
	return res;
}

static TEE_Result do_allocate_keypair(struct ecc_keypair *key,
				      size_t size_bits)
{
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
	crypto_bignum_free(key->d);
	crypto_bignum_free(key->x);

	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result do_allocate_publickey(struct ecc_public_key *key,
					size_t size_bits)
{
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
	crypto_bignum_free(key->x);

	return TEE_ERROR_OUT_OF_MEMORY;
}

static void do_free_publickey(struct ecc_public_key *s)
{
	if (!s)
		return;

	crypto_bignum_free(s->x);
	crypto_bignum_free(s->y);
}

static struct drvcrypt_ecc driver_ecc = {
	.alloc_keypair = do_allocate_keypair,
	.alloc_publickey = do_allocate_publickey,
	.free_publickey = do_free_publickey,
	.gen_keypair = do_gen_keypair,
	.sign = do_sign,
	.verify = do_verify,
	.shared_secret = do_shared_secret,
};

TEE_Result imx_ele_ecc_init(void)
{
	return drvcrypt_register_ecc(&driver_ecc);
}
