// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2026 NXP
 */

#include <drivers/ele/ele.h>
#include <drivers/ele/key_mgmt.h>
#include <drivers/ele/memutils.h>
#include <drivers/ele/sign_verify.h>
#include <drivers/ele/asym_cipher.h>
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <rsa.h>
#include <string.h>
#include <config.h>
#include <crypto/crypto_impl.h>
#include <tee/cache.h>
#include <tee_api_defines_extensions.h>
#include <utee_defines.h>
#include <util.h>

/* RSA public exponent - ELE only supports 65537 */
#define RSA_PUBLIC_EXPONENT 65537

/*
 * Validate RSA key size - ELE supports specific sizes
 * According to ELE documentation, typical sizes are 2048, 3072, 4096 bits
 */
static TEE_Result validate_rsa_key_size(size_t size_bits)
{
	switch (size_bits) {
	case 2048:
	case 3072:
	case 4096:
		return TEE_SUCCESS;
	default:
		DMSG("RSA key size %zu bits not supported by ELE", size_bits);
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

/*
 * Map TEE algorithm to ELE signature scheme
 */
static TEE_Result tee_algo_to_ele_scheme(uint32_t tee_algo, size_t digest_size,
					 uint32_t *ele_scheme)
{
	switch (tee_algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
		if (digest_size != TEE_SHA224_HASH_SIZE)
			goto err;
		*ele_scheme = ELE_ALGO_RSA_PKCS1_V15_SHA224;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
		if (digest_size != TEE_SHA256_HASH_SIZE)
			goto err;
		*ele_scheme = ELE_ALGO_RSA_PKCS1_V15_SHA256;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
		if (digest_size != TEE_SHA384_HASH_SIZE)
			goto err;
		*ele_scheme = ELE_ALGO_RSA_PKCS1_V15_SHA384;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		if (digest_size != TEE_SHA512_HASH_SIZE)
			goto err;
		*ele_scheme = ELE_ALGO_RSA_PKCS1_V15_SHA512;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
		if (digest_size != TEE_SHA224_HASH_SIZE)
			goto err;
		*ele_scheme = ELE_ALGO_RSA_PKCS1_PSS_MGF1_SHA224;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
		if (digest_size != TEE_SHA256_HASH_SIZE)
			goto err;
		*ele_scheme = ELE_ALGO_RSA_PKCS1_PSS_MGF1_SHA256;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
		if (digest_size != TEE_SHA384_HASH_SIZE)
			goto err;
		*ele_scheme = ELE_ALGO_RSA_PKCS1_PSS_MGF1_SHA384;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		if (digest_size != TEE_SHA512_HASH_SIZE)
			goto err;
		*ele_scheme = ELE_ALGO_RSA_PKCS1_PSS_MGF1_SHA512;
		break;
	default:
		DMSG("RSA algorithm %#" PRIx32 " not supported", tee_algo);
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	return TEE_SUCCESS;

err:
	DMSG("Digest size mismatch for algorithm %#" PRIx32, tee_algo);
	return TEE_ERROR_BAD_PARAMETERS;
}

static uint16_t calculate_salt_len(uint32_t tee_algo)
{
	uint16_t salt_len = 0;

	switch (tee_algo) {
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
		salt_len = TEE_SHA224_HASH_SIZE;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
		salt_len = TEE_SHA256_HASH_SIZE;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
		salt_len = TEE_SHA384_HASH_SIZE;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		salt_len = TEE_SHA512_HASH_SIZE;
		break;
	default:
		salt_len = 0;
		break;
	}

	return salt_len;
}

/*
 * Map TEE RSA encryption algorithm to ELE encryption scheme
 */
static TEE_Result tee_algo_to_ele_enc_scheme(uint32_t tee_algo,
					     uint32_t *ele_scheme)
{
	switch (tee_algo) {
	case TEE_ALG_RSAES_PKCS1_V1_5:
		*ele_scheme = ELE_ALGO_RSA_PKCS1_V15_CRYPT;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
		*ele_scheme = ELE_ALGO_RSA_OAEP_SHA1;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
		*ele_scheme = ELE_ALGO_RSA_OAEP_SHA224;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
		*ele_scheme = ELE_ALGO_RSA_OAEP_SHA256;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
		*ele_scheme = ELE_ALGO_RSA_OAEP_SHA384;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
		*ele_scheme = ELE_ALGO_RSA_OAEP_SHA512;
		break;
	default:
		DMSG("RSA encryption algorithm %#" PRIx32 " not supported",
		     tee_algo);
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result gen_fallback(struct rsa_keypair *key, size_t key_size)
{
	if (!IS_ENABLED(CFG_NXP_ELE_RSA_DRV_FALLBACK))
		return TEE_ERROR_NOT_IMPLEMENTED;

	DMSG("ELE: debug: RSA software fallback: KEYGEN");
	return sw_crypto_acipher_gen_rsa_key(key, key_size);
}

static TEE_Result sign_fallback(struct drvcrypt_rsa_ssa *p)
{
	if (!IS_ENABLED(CFG_NXP_ELE_RSA_DRV_FALLBACK))
		return TEE_ERROR_NOT_IMPLEMENTED;

	DMSG("ELE: debug: RSA software fallback: SIGN");
	return sw_crypto_acipher_rsassa_sign(p->algo, p->key.key, p->salt_len,
					     p->message.data, p->message.length,
					     p->signature.data,
					     &p->signature.length);
}

static TEE_Result verify_fallback(struct drvcrypt_rsa_ssa *p)
{
	if (!IS_ENABLED(CFG_NXP_ELE_RSA_DRV_FALLBACK))
		return TEE_ERROR_NOT_IMPLEMENTED;

	DMSG("ELE: debug: RSA software fallback: VERIFY");
	return sw_crypto_acipher_rsassa_verify(p->algo, p->key.key, p->salt_len,
					       p->message.data,
					       p->message.length,
					       p->signature.data,
					       p->signature.length);
}

static TEE_Result encrypt_fallback(struct drvcrypt_rsa_ed *rsa_data)
{
	if (!IS_ENABLED(CFG_NXP_ELE_RSA_DRV_FALLBACK))
		return TEE_ERROR_NOT_IMPLEMENTED;

	DMSG("ELE: debug: RSA software fallback: ENCRYPT");
	return sw_crypto_acipher_rsaes_encrypt(rsa_data->algo,
					       rsa_data->key.key,
					       rsa_data->label.data,
					       rsa_data->label.length,
					       rsa_data->mgf_algo,
					       rsa_data->message.data,
					       rsa_data->message.length,
					       rsa_data->cipher.data,
					       &rsa_data->cipher.length);
}

static TEE_Result decrypt_fallback(struct drvcrypt_rsa_ed *rsa_data)
{
	if (!IS_ENABLED(CFG_NXP_ELE_RSA_DRV_FALLBACK))
		return TEE_ERROR_NOT_IMPLEMENTED;

	DMSG("ELE: debug: RSA software fallback: DECRYPT");
	return sw_crypto_acipher_rsaes_decrypt(rsa_data->algo,
					       rsa_data->key.key,
					       rsa_data->label.data,
					       rsa_data->label.length,
					       rsa_data->mgf_algo,
					       rsa_data->cipher.data,
					       rsa_data->cipher.length,
					       rsa_data->message.data,
					       &rsa_data->message.length);
}

static TEE_Result alloc_keypair_fallback(struct rsa_keypair *s,
					 size_t size_bits)
{
	if (!IS_ENABLED(CFG_NXP_ELE_RSA_DRV_FALLBACK))
		return TEE_ERROR_NOT_IMPLEMENTED;

	DMSG("ELE: debug: RSA software fallback: KEYPAIR ALLOCATION");
	return sw_crypto_acipher_alloc_rsa_keypair(s, size_bits);
}

/*
 * Generate RSA key pair using ELE
 * ELE only supports public exponent 65537
 */
static TEE_Result do_gen_keypair(struct rsa_keypair *key, size_t size_bits)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t modulus_size = 0;
	size_t priv_exp_size = 0;
	uint8_t *modulus = NULL;
	uint8_t *priv_exp = NULL;
	const uint8_t pub_exp_be[] = { 0x01, 0x00, 0x01 };

	if (!key || !size_bits) {
		EMSG("Invalid key or key size");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/*
	 * RSA 4096, 3072 key generation with ELE takes a lot of
	 * time and sometime leads to issue. So, falling back to
	 * software for RSA 4096,3072 Key Generation only.
	 *
	 * RSA Encryption/Decryption/Signing/Verification is still
	 * offloaded to ELE.
	 */
	if (size_bits == 4096 || size_bits == 3072)
		return gen_fallback(key, size_bits);

	res = validate_rsa_key_size(size_bits);
	if (res)
		return gen_fallback(key, size_bits);

	modulus_size = size_bits / 8;
	priv_exp_size = modulus_size;

	/*
	 * Allocate buffer for modulus (n)
	 */
	modulus = calloc(1, modulus_size);
	if (!modulus) {
		EMSG("Modulus allocation failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Allocate buffer for private exponent (d) */
	priv_exp = calloc(1, priv_exp_size);
	if (!priv_exp) {
		EMSG("Private exponent allocation failed");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/*
	 * Generate RSA key pair using ELE
	 * For plain key generation:
	 * - key_mgmt_hdl = 0 (reserved for plain keys)
	 * - key_group = 0 (reserved)
	 * - key_lifetime = 0 (volatile/plain)
	 * - key_usage = 0 (reserved for plain keys)
	 * - permitted_algo = 0 (reserved)
	 * - flags = PLAIN_KEY
	 * - monotonic_counter = 0 (reserved)
	 * - sync = 0 (reserved)
	 *
	 * Output:
	 * - priv_exp: receives private exponent (d)
	 * - modulus: receives modulus (n)
	 * - Public exponent (e) is always 65537
	 */
	res = imx_ele_generate_key(0, priv_exp, modulus_size, 0, 0, 0,
				   PLAIN_KEY, 0, 0, ELE_KEY_TYPE_RSA_KEY_PAIR,
				   size_bits, 0, 0, priv_exp_size, modulus,
				   NULL);
	if (res != TEE_SUCCESS) {
		EMSG("RSA key generation failed");
		goto out;
	}

	/*
	 * Convert modulus to bignum
	 */
	crypto_bignum_bin2bn(modulus, modulus_size, key->n);

	/*
	 * Convert private exponent to bignum
	 */
	crypto_bignum_bin2bn(priv_exp, priv_exp_size, key->d);

	/*
	 * Convert public exponent to bignum
	 */
	crypto_bignum_bin2bn(pub_exp_be, sizeof(pub_exp_be), key->e);

out:
	free(modulus);
	free(priv_exp);

	return res;
}

/*
 * Sign data using RSA private key
 */
static TEE_Result do_sign(struct drvcrypt_rsa_ssa *sdata)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t sig_scheme = 0;
	struct rsa_keypair *key = NULL;
	size_t key_size_bits = 0;
	size_t modulus_size = 0;
	size_t priv_exp_size = 0;
	uint8_t *priv_key_combined = NULL;
	uint16_t salt_len = 0;

	if (!sdata || !sdata->key.key || !sdata->message.data ||
	    !sdata->signature.data || !sdata->message.length ||
	    !sdata->signature.length) {
		EMSG("Invalid sign data parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	key = (struct rsa_keypair *)sdata->key.key;
	key_size_bits = sdata->key.n_size * 8;

	res = validate_rsa_key_size(key_size_bits);
	if (res)
		return sign_fallback(sdata);

	res = tee_algo_to_ele_scheme(sdata->algo, sdata->message.length,
				     &sig_scheme);
	if (res)
		return sign_fallback(sdata);

	/*
	 * Determine salt length for PSS algorithms
	 */
	salt_len = calculate_salt_len(sdata->algo);

	modulus_size = sdata->key.n_size;
	priv_exp_size = modulus_size;

	/*
	 * For signature generation with plain key:
	 * Private key format: private_exponent || modulus
	 * Total size: priv_exp_size + modulus_size
	 */
	priv_key_combined = calloc(1, priv_exp_size + modulus_size);
	if (!priv_key_combined) {
		EMSG("Combined private key allocation failed");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/*
	 * Convert private exponent and modulus to binary
	 */
	crypto_bignum_bn2bin(key->d, priv_key_combined);
	crypto_bignum_bn2bin(key->n, priv_key_combined + priv_exp_size);

	/*
	 * Generate signature using ELE
	 * For plain key:
	 * - sig_gen_hdl = 0 (reserved)
	 * - key_id = 0 (reserved for plain keys)
	 */
	res = imx_ele_signature_generate(0, 0, priv_key_combined,
					 priv_exp_size + modulus_size,
					 sdata->message.data,
					 sdata->message.length,
					 sdata->signature.data,
					 sdata->signature.length,
					 sig_scheme,
					 ELE_SIG_GEN_MSG_TYPE_DIGEST,
					 PLAIN_KEY,
					 ELE_KEY_TYPE_RSA_KEY_PAIR,
					 key_size_bits, salt_len);
	if (res != TEE_SUCCESS && res != TEE_ERROR_SHORT_BUFFER) {
		EMSG("RSA signature generation failed");
		goto out;
	}

	sdata->signature.length = modulus_size;
out:
	free(priv_key_combined);
	return res;
}

/*
 * Verify RSA signature using public key
 */
static TEE_Result do_verify(struct drvcrypt_rsa_ssa *sdata)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t sig_scheme = 0;
	struct rsa_public_key *key = NULL;
	size_t key_size_bits = 0;
	size_t modulus_size = 0;
	uint8_t *modulus = NULL;
	uint32_t pub_exp = 0;
	uint16_t salt_len = 0;

	if (!sdata || !sdata->key.key || !sdata->message.data ||
	    !sdata->signature.data || !sdata->message.length ||
	    !sdata->signature.length) {
		EMSG("Invalid verify data parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	key = (struct rsa_public_key *)sdata->key.key;
	key_size_bits = sdata->key.n_size * 8;

	res = validate_rsa_key_size(key_size_bits);
	if (res)
		return verify_fallback(sdata);

	res = tee_algo_to_ele_scheme(sdata->algo, sdata->message.length,
				     &sig_scheme);
	if (res)
		return verify_fallback(sdata);

	/*
	 * Determine salt length for PSS algorithms
	 */
	salt_len = calculate_salt_len(sdata->algo);

	/*
	 * Verify public exponent is 65537
	 */
	crypto_bignum_bn2bin(key->e, (uint8_t *)&pub_exp);
	if (pub_exp != RSA_PUBLIC_EXPONENT) {
		DMSG("ELE only supports public exponent 65537, got %u",
		     pub_exp);
		return verify_fallback(sdata);
	}

	modulus_size = sdata->key.n_size;

	modulus = calloc(1, modulus_size);
	if (!modulus) {
		EMSG("Modulus allocation failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/*
	 * Convert modulus to binary
	 */
	crypto_bignum_bn2bin(key->n, modulus);

	/*
	 * Verify signature using ELE
	 * For plain key, sig_verify_hdl = 0 (reserved)
	 */
	res = imx_ele_signature_verification(0, modulus,
					     sdata->message.data,
					     sdata->message.length,
					     sdata->signature.data,
					     sdata->signature.length,
					     modulus_size, key_size_bits,
					     ELE_KEY_TYPE_RSA_PUB_KEY,
					     sig_scheme,
					     ELE_SIG_GEN_MSG_TYPE_DIGEST,
					     salt_len);
	if (res != TEE_SUCCESS)
		EMSG("RSA signature verification failed");

	free(modulus);
	return res;
}

/*
 * Encrypt data using RSA public key
 */
static TEE_Result do_encrypt(struct drvcrypt_rsa_ed *edata)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t enc_scheme = 0;
	struct rsa_public_key *key = NULL;
	size_t key_size_bits = 0;
	size_t modulus_size = 0;
	uint8_t *modulus = NULL;
	uint32_t pub_exp = 0;
	size_t label_len = 0;
	uint8_t *label = NULL;

	if (!edata || !edata->key.key || !edata->message.data ||
	    !edata->cipher.data || !edata->message.length) {
		EMSG("Invalid encrypt data parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (edata->rsa_id == DRVCRYPT_RSA_NOPAD) {
		if (!IS_ENABLED(CFG_NXP_ELE_RSA_DRV_FALLBACK))
			return TEE_ERROR_NOT_IMPLEMENTED;

		DMSG("ELE: RSA NOPAD software fallback");
		return sw_crypto_acipher_rsanopad_encrypt(edata->key.key,
							  edata->message.data,
							  edata->message.length,
							  edata->cipher.data,
							  &edata->cipher.length
							 );
	}

	key = (struct rsa_public_key *)edata->key.key;
	key_size_bits = edata->key.n_size * 8;

	res = validate_rsa_key_size(key_size_bits);
	if (res)
		return encrypt_fallback(edata);

	res = tee_algo_to_ele_enc_scheme(edata->algo, &enc_scheme);
	if (res)
		return encrypt_fallback(edata);

	/*
	 * ELE doesn't support cross digests.
	 * So, performing software fallback when MGF algo is not equal to
	 * the message hash algo.
	 */
	if (edata->mgf_algo != edata->hash_algo)
		return encrypt_fallback(edata);

	/*
	 * Verify public exponent is 65537
	 */
	crypto_bignum_bn2bin(key->e, (uint8_t *)&pub_exp);
	if (pub_exp != RSA_PUBLIC_EXPONENT) {
		DMSG("ELE only supports public exponent 65537, got %u",
		     pub_exp);
		return encrypt_fallback(edata);
	}

	modulus_size = edata->key.n_size;

	/*
	 * Validate output buffer size
	 */
	if (edata->cipher.length < modulus_size) {
		EMSG("Output buffer too small: %zu < %zu", edata->cipher.length,
		     modulus_size);
		edata->cipher.length = modulus_size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	modulus = calloc(1, modulus_size);
	if (!modulus) {
		EMSG("Modulus allocation failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/*
	 * Convert modulus to binary
	 */
	crypto_bignum_bn2bin(key->n, modulus);

	/*
	 * Handle OAEP label if present
	 */
	if (edata->label.data && edata->label.length > 0) {
		label = edata->label.data;
		label_len = edata->label.length;
	}

	/*
	 * Encrypt using ELE
	 * For plain key encryption:
	 * - asym_enc_handle = 0 (reserved for plain keys)
	 * - key = modulus (public key)
	 * - key_type = ELE_KEY_TYPE_RSA_PUB_KEY
	 * - encrypt = true
	 */
	res = imx_ele_asym_operate(0, modulus, modulus_size,
				   edata->message.data, edata->message.length,
				   edata->cipher.data, &edata->cipher.length,
				   label, label_len, enc_scheme, true,
				   ELE_KEY_TYPE_RSA_PUB_KEY, key_size_bits);
	if (res != TEE_SUCCESS) {
		EMSG("RSA encryption failed");
		goto out;
	}
out:
	free(modulus);
	return res;
}

/*
 * Decrypt data using RSA private key
 */
static TEE_Result do_decrypt(struct drvcrypt_rsa_ed *edata)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t enc_scheme = 0;
	struct rsa_keypair *key = NULL;
	size_t key_size_bits = 0;
	size_t modulus_size = 0;
	size_t priv_exp_size = 0;
	uint8_t *priv_key_combined = NULL;
	size_t label_len = 0;
	uint8_t *label = NULL;

	if (!edata || !edata->key.key || !edata->cipher.data ||
	    !edata->message.data || !edata->cipher.length) {
		EMSG("Invalid decrypt data parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/*
	 * Handle RSA NOPAD separately - use software fallback
	 */
	if (edata->rsa_id == DRVCRYPT_RSA_NOPAD) {
		if (!IS_ENABLED(CFG_NXP_ELE_RSA_DRV_FALLBACK))
			return TEE_ERROR_NOT_IMPLEMENTED;

		DMSG("ELE: RSA NOPAD software fallback");
		return sw_crypto_acipher_rsanopad_decrypt(edata->key.key,
							  edata->cipher.data,
							  edata->cipher.length,
							  edata->message.data,
							  &edata->message.length
							 );
	}

	key = (struct rsa_keypair *)edata->key.key;
	key_size_bits = edata->key.n_size * 8;

	res = validate_rsa_key_size(key_size_bits);
	if (res)
		return decrypt_fallback(edata);

	res = tee_algo_to_ele_enc_scheme(edata->algo, &enc_scheme);
	if (res)
		return decrypt_fallback(edata);

	/*
	 * ELE doesn't support cross digests.
	 * So, performing software fallback when MGF hash algo is not equal to
	 * the message hash algo.
	 */
	if (edata->mgf_algo != edata->hash_algo)
		return decrypt_fallback(edata);

	modulus_size = edata->key.n_size;
	priv_exp_size = modulus_size;

	/*
	 * Validate cipher size
	 */
	if (edata->cipher.length != modulus_size) {
		EMSG("Invalid cipher size: %zu != %zu", edata->cipher.length,
		     modulus_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (edata->message.length > modulus_size) {
		edata->message.length = modulus_size;
		DMSG("Setting message.length to modulus_size=%zu",
		     edata->message.length);
	}

	/*
	 * For decryption with plain key:
	 * Private key format: private_exponent || modulus
	 * Total size: priv_exp_size + modulus_size
	 */
	priv_key_combined = calloc(1, priv_exp_size + modulus_size);
	if (!priv_key_combined) {
		EMSG("Combined private key allocation failed");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/*
	 * Convert private exponent and modulus to binary
	 */
	crypto_bignum_bn2bin(key->d, priv_key_combined);
	crypto_bignum_bn2bin(key->n, priv_key_combined + priv_exp_size);

	/*
	 * Handle OAEP label if present
	 */
	if (edata->label.data && edata->label.length > 0) {
		label = edata->label.data;
		label_len = edata->label.length;
	}

	/*
	 * Decrypt using ELE
	 * For plain key decryption:
	 * - asym_enc_handle = 0 (reserved for plain keys)
	 * - key = private_exponent || modulus
	 * - key_type = ELE_KEY_TYPE_RSA
	 * - encrypt = false
	 */
	res = imx_ele_asym_operate(0, priv_key_combined,
				   priv_exp_size + modulus_size,
				   edata->cipher.data, edata->cipher.length,
				   edata->message.data, &edata->message.length,
				   label, label_len, enc_scheme, false,
				   ELE_KEY_TYPE_RSA_KEY_PAIR, key_size_bits);
	if (res != TEE_SUCCESS && res != TEE_ERROR_SHORT_BUFFER) {
		EMSG("RSA decryption failed");
		goto out;
	}

out:
	free(priv_key_combined);
	return res;
}

static TEE_Result do_allocate_keypair(struct rsa_keypair *key, size_t size_bits)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!key) {
		EMSG("Invalid key pointer");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/*
	 * Initialize the key fields to NULL
	 */
	memset(key, 0, sizeof(*key));

	res = validate_rsa_key_size(size_bits);
	if (res)
		return alloc_keypair_fallback(key, size_bits);

	/*
	 * Allocate modulus (n)
	 */
	key->n = crypto_bignum_allocate(size_bits);
	if (!key->n)
		goto err;

	/*
	 * Allocate public exponent (e)
	 */
	key->e = crypto_bignum_allocate(256);
	if (!key->e)
		goto err;

	/*
	 * Allocate private exponent (d)
	 */
	key->d = crypto_bignum_allocate(size_bits);
	if (!key->d)
		goto err;

	/*
	 * Allocate the prime number p
	 */
	key->p = crypto_bignum_allocate(size_bits / 2);
	if (!key->p)
		goto err;

	/*
	 * Allocate the prime number q
	 */
	key->q = crypto_bignum_allocate(size_bits / 2);
	if (!key->q)
		goto err;

	/*
	 * Allocate dp [d mod (p-1)]
	 */
	key->dp = crypto_bignum_allocate(size_bits / 2);
	if (!key->dp)
		goto err;

	/*
	 * Allocate dq [d mod (q-1)]
	 */
	key->dq = crypto_bignum_allocate(size_bits / 2);
	if (!key->dq)
		goto err;

	/*
	 * Allocate qp [1/q mod p]
	 */
	key->qp = crypto_bignum_allocate(size_bits / 2);
	if (!key->qp)
		goto err;

	return TEE_SUCCESS;

err:
	crypto_bignum_free(&key->n);
	crypto_bignum_free(&key->e);
	crypto_bignum_free(&key->d);
	crypto_bignum_free(&key->p);
	crypto_bignum_free(&key->q);
	crypto_bignum_free(&key->dp);
	crypto_bignum_free(&key->dq);
	crypto_bignum_free(&key->qp);

	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result do_allocate_publickey(struct rsa_public_key *key,
					size_t size_bits)
{
	if (!key) {
		EMSG("Invalid key pointer");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/*
	 * Initialize the key fields to NULL
	 */
	memset(key, 0, sizeof(*key));

	/*
	 * Allocate modulus (n)
	 */
	key->n = crypto_bignum_allocate(size_bits);
	if (!key->n)
		goto err;

	/*
	 * Allocate public exponent (e)
	 */
	key->e = crypto_bignum_allocate(256);
	if (!key->e)
		goto err;

	return TEE_SUCCESS;

err:
	crypto_bignum_free(&key->e);
	crypto_bignum_free(&key->n);

	return TEE_ERROR_OUT_OF_MEMORY;
}

static void do_free_keypair(struct rsa_keypair *key)
{
	if (!key)
		return;

	crypto_bignum_free(&key->e);
	crypto_bignum_free(&key->d);
	crypto_bignum_free(&key->n);
	crypto_bignum_free(&key->p);
	crypto_bignum_free(&key->q);
	crypto_bignum_free(&key->qp);
	crypto_bignum_free(&key->dp);
	crypto_bignum_free(&key->dq);
}

static void do_free_publickey(struct rsa_public_key *key)
{
	if (!key)
		return;

	crypto_bignum_free(&key->n);
	crypto_bignum_free(&key->e);
}

static struct drvcrypt_rsa driver_rsa = {
	.alloc_keypair = do_allocate_keypair,
	.alloc_publickey = do_allocate_publickey,
	.free_publickey = do_free_publickey,
	.free_keypair = do_free_keypair,
	.gen_keypair = do_gen_keypair,
	.encrypt = do_encrypt,
	.decrypt = do_decrypt,
	.optional.ssa_sign = do_sign,
	.optional.ssa_verify = do_verify,
};

TEE_Result imx_ele_rsa_init(void)
{
	return drvcrypt_register_rsa(&driver_rsa);
}
