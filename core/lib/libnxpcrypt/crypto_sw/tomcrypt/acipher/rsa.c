// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    rsa.c
 *
 * @brief   Implementation of the RSA pseudo-driver compatible with the
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

#define MAX_BITS_EXP_E	256

#ifndef CFG_CRYPTO_RSA_HW
/**
 * @brief   Allocate a RSA keypair
 *
 * @param[in]  key        Keypair
 * @param[in]  size_bits  Key size in bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 */
static TEE_Result do_allocate_keypair(struct rsa_keypair *key,
					size_t size_bits __unused)
{
	/* Initialize the key fields to NULL */
	memset(key, 0, sizeof(*key));

	/* Allocate Public exponent */
	key->e = crypto_bignum_allocate(MAX_BITS_EXP_E);
	if (!key->e)
		goto err_alloc_keypair;

	/* Allocate Private exponent */
	key->d = crypto_bignum_allocate(size_bits);
	if (!key->d)
		goto err_alloc_keypair;

	/* Allocate modulus */
	key->n = crypto_bignum_allocate(size_bits);
	if (!key->n)
		goto err_alloc_keypair;

	/* Allocate prime p */
	key->p = crypto_bignum_allocate(size_bits / 2);
	if (!key->p)
		goto err_alloc_keypair;

	/* Allocate prime q */
	key->q = crypto_bignum_allocate(size_bits / 2);
	if (!key->q)
		goto err_alloc_keypair;

	/* Allocate qp = 1/q mod p */
	key->qp = crypto_bignum_allocate(size_bits);
	if (!key->qp)
		goto err_alloc_keypair;

	/* Allocate dp = d mod (p - 1) */
	key->dp = crypto_bignum_allocate(size_bits);
	if (!key->dp)
		goto err_alloc_keypair;

	/* Allocate dq = d mod (q - 1) */
	key->dq = crypto_bignum_allocate(size_bits);
	if (!key->dq)
		goto err_alloc_keypair;

	return TEE_SUCCESS;

err_alloc_keypair:
	LIB_TRACE("Allocation error");

	crypto_bignum_free(key->e);
	crypto_bignum_free(key->d);
	crypto_bignum_free(key->n);
	crypto_bignum_free(key->p);
	crypto_bignum_free(key->q);
	crypto_bignum_free(key->qp);
	crypto_bignum_free(key->dp);

	return TEE_ERROR_OUT_OF_MEMORY;
}

/**
 * @brief   Allocate a RSA public key
 *
 * @param[in]  key        Public Key
 * @param[in]  size_bits  Key size in bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 */
static TEE_Result do_allocate_publickey(struct rsa_public_key *key,
					size_t size_bits __unused)
{
	/* Initialize the key fields to NULL */
	memset(key, 0, sizeof(*key));

	/* Allocate Public exponent */
	key->e = crypto_bignum_allocate(MAX_BITS_EXP_E);
	if (!key->e)
		goto err_alloc_publickey;

	/* Allocate modulus */
	key->n = crypto_bignum_allocate(size_bits);
	if (!key->n)
		goto err_alloc_publickey;

	return TEE_SUCCESS;

err_alloc_publickey:
	LIB_TRACE("Allocation error");

	crypto_bignum_free(key->e);
	crypto_bignum_free(key->n);

	return TEE_ERROR_OUT_OF_MEMORY;
}

/**
 * @brief   Free a RSA public key
 *
 * @param[in]  key        Public Key
 */
static void do_free_publickey(struct rsa_public_key *key)
{
	crypto_bignum_free(key->e);
	crypto_bignum_free(key->n);
}

/**
 * @brief   Generates a RSA keypair
 *
 * @param[out] key        Keypair
 * @param[in]  key_size   Key size in bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
static TEE_Result do_gen_keypair(struct rsa_keypair *key, size_t key_size)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;

	rsa_key    tmp_key;
	int        ltc_res;
	long       e;
	struct ltc_prng *prng = get_ltc_prng();

	LIB_TRACE("Generate key pair");

	/* get the public exponent */
	e = mp_get_int(key->e);

	/* Generate a temporary RSA key */
	ltc_res = rsa_make_key(&prng->state, prng->index, (key_size / 8), e,
							&tmp_key);

	if (ltc_res == CRYPT_OK) {
		if ((size_t)mp_count_bits(tmp_key.N) == key_size) {
			/* Copy the generated key to the output key */
			mp_copy(tmp_key.e,  key->e);
			mp_copy(tmp_key.d,  key->d);
			mp_copy(tmp_key.N,  key->n);
			mp_copy(tmp_key.p,  key->p);
			mp_copy(tmp_key.q,  key->q);
			mp_copy(tmp_key.qP, key->qp);
			mp_copy(tmp_key.dP, key->dp);
			mp_copy(tmp_key.dQ, key->dq);

			ret = TEE_SUCCESS;
		}

		/* Free the temporary key */
		rsa_free(&tmp_key);
	}

	return ret;
}

/**
 * @brief  RSA No Pad Encryption/Decryption
 *
 * @param[in]  key  RSA Public or Private key function of the direction
 * @param[in]  src  Data to encrypt/decrypt
 * @param[out] dst  Data result
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_SHORT_BUFFER      Result buffer too short
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result rsa_nopad(rsa_key *ltc_key, const struct nxpcrypt_buf *src,
					struct nxpcrypt_buf *dst)
{
	TEE_Result ret = TEE_SUCCESS;

	uint8_t       *buf = NULL;
	unsigned long blen;
	unsigned long offset = 0;
	int           ltc_res;

	/*
	 * Use a temporary buffer since we don't know exactly how large the
	 * required size of the out buffer without doing a partial decrypt.
	 * We know the upper bound though.
	 */
	blen = (mpa_StaticTempVarSizeInU32(LTC_MAX_BITS_PER_VARIABLE)) *
	       sizeof(uint32_t);
	buf = malloc(blen);
	if (!buf) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto end_rsa_nopad;
	}

	LIB_TRACE("rsa_exptmod");
	ltc_res = rsa_exptmod(src->data, src->length, buf, &blen, ltc_key->type,
			      ltc_key);

	LIB_TRACE("rsa_exptmod returned 0x%"PRIx32"", ltc_res);
	ret = conv_CRYPT_to_TEE_Result(ltc_res);
	if (ret != TEE_SUCCESS)
		goto end_rsa_nopad;

	/* Remove the zero-padding (leave one zero if buff is all zeroes) */
	offset = 0;
	while ((offset < (blen - 1)) && (buf[offset] == 0))
		offset++;

	if (dst->length < (blen - offset)) {
		ret = TEE_ERROR_SHORT_BUFFER;
		goto end_rsa_nopad;
	}

	memcpy(dst->data, (char *)buf + offset, (blen - offset));
	ret = TEE_SUCCESS;

end_rsa_nopad:
	dst->length = blen - offset;

	if (buf)
		free(buf);

	return ret;
}

/**
 * @brief   RSAES encryption
 *
 * @param[in]     ltc_key    RSA LibTomCrypt Key
 * @param[in/out] rsa_data   RSA Data to encrypt / Cipher resulting
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_SHORT_BUFFER      Result buffer too short
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result rsaes_encrypt(rsa_key *ltc_key,
			struct nxpcrypt_rsa_ed *rsa_data)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct ltc_prng *prng = get_ltc_prng();
	int hash_idx = (-1);
	int ltc_rsa_algo;
	int ltc_res;
	unsigned long cipher_len;

	if (rsa_data->rsa_id == RSA_PKCS_V1_5) {
		ltc_rsa_algo = LTC_PKCS_1_V1_5;
	} else {
		/* Get the HASH algorithm index registered in libTomCrypt */
		hash_idx = get_ltc_hashindex(rsa_data->hash_id);

		if (hash_idx == (-1))
			return ret;

		ltc_rsa_algo = LTC_PKCS_1_OAEP;
	}

	LIB_TRACE("rsa_encrypt_key_ex");

	cipher_len = rsa_data->cipher.length;
	ltc_res = rsa_encrypt_key_ex(
			rsa_data->message.data, rsa_data->message.length,
			rsa_data->cipher.data, &cipher_len,
			rsa_data->label.data, rsa_data->label.length,
			&prng->state, prng->index,
			hash_idx, ltc_rsa_algo, ltc_key);

	/* Returns the cipher length generated */
	rsa_data->cipher.length = cipher_len;

	LIB_TRACE("rsa_encrypt_key_ex returned 0x%"PRIx32"", ltc_res);
	ret = conv_CRYPT_to_TEE_Result(ltc_res);

	return ret;
}

/**
 * @brief   RSAES Decryption
 *
 * @param[in]     ltc_key    RSA LibTomCrypt Key
 * @param[in/out] rsa_data   RSA Data to decrypt / Message resulting
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_SHORT_BUFFER      Result buffer too short
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result rsaes_decrypt(rsa_key *ltc_key,
			struct nxpcrypt_rsa_ed *rsa_data)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	int hash_idx = (-1);
	int ltc_rsa_algo;
	int ltc_res;
	int stat;
	unsigned long msglen;
	void *msg = NULL;

	if (rsa_data->rsa_id == RSA_PKCS_V1_5) {
		/*
		 * Use a temporary buffer since we don't know exactly how large
		 * the required size of the out buffer without doing a partial
		 * decrypt. We know the upper bound though.
		 */
		msglen = (crypto_bignum_num_bytes(ltc_key->N) - 11);
		ltc_rsa_algo = LTC_PKCS_1_V1_5;
	} else {
		/* Get the HASH algorithm index registered in libTomCrypt */
		hash_idx = get_ltc_hashindex(rsa_data->hash_id);

		if (hash_idx == (-1))
			return ret;

		/* Decoded message is always shorter than encrypted message */
		ltc_rsa_algo = LTC_PKCS_1_OAEP;
		msglen = rsa_data->cipher.length;
	}

	msg = malloc(msglen);
	if (!msg)
		return TEE_ERROR_OUT_OF_MEMORY;

	LIB_TRACE("rsa_decrypt_key_ex");
	ltc_res = rsa_decrypt_key_ex(
			rsa_data->cipher.data, rsa_data->cipher.length,
			msg, &msglen,
			rsa_data->label.data, rsa_data->label.length,
			hash_idx, ltc_rsa_algo, &stat, ltc_key);

	LIB_TRACE("rsa_decrypt_key_ex returned 0x%"PRIx32"", ltc_res);
	ret = conv_CRYPT_to_TEE_Result(ltc_res);
	if (ret != TEE_SUCCESS)
		goto end_rsaes_decrypt;

	if (stat != 1) {
		ret = TEE_ERROR_GENERIC;
		goto end_rsaes_decrypt;
	}

	rsa_data->message.length = msglen;

	if (rsa_data->message.length >= msglen) {
		memcpy(rsa_data->message.data, msg, msglen);
		ret = TEE_SUCCESS;
	} else {
		ret = TEE_ERROR_SHORT_BUFFER;
	}

end_rsaes_decrypt:
	if (msg)
		free(msg);

	return ret;
}

/**
 * @brief   RSA Encryption
 *
 * @param[in/out] rsa_data   RSA Data to encrypt / Cipher resulting
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_SHORT_BUFFER      Result buffer too short
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result do_encrypt(struct nxpcrypt_rsa_ed *rsa_data)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct rsa_public_key *inkey = rsa_data->key.key;
	rsa_key ltc_key = {0};

	/* Convert the input key to LibTomCrypt RSA key */
	ltc_key.type = PK_PUBLIC;
	ltc_key.e    = inkey->e;
	ltc_key.N    = inkey->n;

	if (rsa_data->rsa_id == RSA_NOPAD)
		ret = rsa_nopad(&ltc_key, &rsa_data->message,
			&rsa_data->cipher);
	else
		ret = rsaes_encrypt(&ltc_key, rsa_data);

	return ret;
}

/**
 * @brief   RSA Decryption
 *
 * @param[in/out] rsa_data   RSA Data to decrypt / Message resulting
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_SHORT_BUFFER      Result buffer too short
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result do_decrypt(struct nxpcrypt_rsa_ed *rsa_data)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct rsa_keypair *inkey = rsa_data->key.key;
	rsa_key ltc_key = {0};

	/* Convert the input key to LibTomCrypt RSA key */
	ltc_key.type = PK_PRIVATE;
	ltc_key.e    = inkey->e;
	ltc_key.N    = inkey->n;
	ltc_key.d    = inkey->d;

	if ((inkey->p) && (crypto_bignum_num_bytes(inkey->p))) {
		ltc_key.p  = inkey->p;
		ltc_key.q  = inkey->q;
		ltc_key.qP = inkey->qp;
		ltc_key.dP = inkey->dp;
		ltc_key.dQ = inkey->dq;
	}

	if (rsa_data->rsa_id == RSA_NOPAD)
		ret = rsa_nopad(&ltc_key, &rsa_data->cipher,
			&rsa_data->message);
	else
		ret = rsaes_decrypt(&ltc_key, rsa_data);

	return ret;
}

/**
 * @brief   PKCS#1 - Signature of RSA message and encodes the signature.
 *
 * @param[in/out]  ssa_data   RSA data to sign / Signature
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_SHORT_BUFFER      Result buffer too short
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result do_ssa_sign(struct nxpcrypt_rsa_ssa *ssa_data)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct rsa_keypair *inkey = ssa_data->key.key;
	struct ltc_prng *prng = get_ltc_prng();
	rsa_key ltc_key = {0};
	int     hash_idx;
	int     ltc_rsa_algo;
	int     ltc_res;
	unsigned long sign_len;

	/* Convert the input key to LibTomCrypt RSA key */
	ltc_key.type = PK_PRIVATE;
	ltc_key.e    = inkey->e;
	ltc_key.N    = inkey->n;
	ltc_key.d    = inkey->d;

	if ((inkey->p) && (crypto_bignum_num_bytes(inkey->p))) {
		ltc_key.p  = inkey->p;
		ltc_key.q  = inkey->q;
		ltc_key.qP = inkey->qp;
		ltc_key.dP = inkey->dp;
		ltc_key.dQ = inkey->dq;
	}

	/* Get the HASH algorithm index registered in libTomCrypt */
	hash_idx = get_ltc_hashindex(ssa_data->hash_id);

	if (hash_idx == (-1))
		return ret;

	/* Get the LibTomCrypt RSA Algorithm */
	switch (ssa_data->algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		ltc_rsa_algo = LTC_PKCS_1_V1_5;
		break;

	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		ltc_rsa_algo = LTC_PKCS_1_PSS;
		break;

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	LIB_TRACE("rsa_sign_hash_ex");

	sign_len = ssa_data->signature.length;
	/* Signature of the message */
	ltc_res = rsa_sign_hash_ex(
			ssa_data->message.data, ssa_data->message.length,
			ssa_data->signature.data, &sign_len,
			ltc_rsa_algo,
			&prng->state, prng->index,
			hash_idx, ssa_data->salt_len, &ltc_key);

	/* Returns the signature length generated */
	ssa_data->signature.length = sign_len;


	LIB_TRACE("rsa_sign_hash_ex return 0x%"PRIx32"", ltc_res);
	ret = conv_CRYPT_to_TEE_Result(ltc_res);

	return ret;
}


/**
 * @brief   PKCS#1 - Verification the encoded signature of RSA message.
 *
 * @param[in]  ssa_data   RSA Encoded signature data
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_SIGNATURE_INVALID Signature invalid
 */
static TEE_Result do_ssa_verify(struct nxpcrypt_rsa_ssa *ssa_data)
{
	struct rsa_public_key *inkey = ssa_data->key.key;
	rsa_key ltc_key = {0};
	int     hash_idx;
	int     ltc_rsa_algo;
	int     ltc_res;
	int     stat;

	/* Convert the input key to LibTomCrypt RSA key */
	ltc_key.type = PK_PUBLIC;
	ltc_key.e    = inkey->e;
	ltc_key.N    = inkey->n;

	/* Get the HASH algorithm index registered in libTomCrypt */
	hash_idx = get_ltc_hashindex(ssa_data->hash_id);

	if (hash_idx == (-1))
		return TEE_ERROR_NOT_IMPLEMENTED;

	/* Get the LibTomCrypt RSA Algorithm */
	switch (ssa_data->algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		ltc_rsa_algo = LTC_PKCS_1_V1_5;
		break;

	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		ltc_rsa_algo = LTC_PKCS_1_PSS;
		break;

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	LIB_TRACE("rsa_verify_hash_ex");
	/* Verification of the signature */
	ltc_res = rsa_verify_hash_ex(
			ssa_data->signature.data, ssa_data->signature.length,
			ssa_data->message.data, ssa_data->message.length,
			ltc_rsa_algo, hash_idx,
			ssa_data->salt_len,
			&stat, &ltc_key);

	LIB_TRACE("rsa_verify_hash_ex return 0x%"PRIx32" with stat=%d",
				ltc_res, stat);
	if ((ltc_res != CRYPT_OK) || (stat != 1))
		return TEE_ERROR_SIGNATURE_INVALID;

	return TEE_SUCCESS;
}

/**
 * @brief   Registration of the RSA Driver
 */
struct nxpcrypt_rsa driver_rsa = {
	.alloc_keypair   = &do_allocate_keypair,
	.alloc_publickey = &do_allocate_publickey,
	.free_publickey  = &do_free_publickey,
	.gen_keypair     = &do_gen_keypair,
	.encrypt         = &do_encrypt,
	.decrypt         = &do_decrypt,
	.ssa_sign        = &do_ssa_sign,
	.ssa_verify      = &do_ssa_verify,
};

/**
 * @brief   Initialize the RSA module
 *
 * @retval  0    Success
 * @retval  (-1) Otherwise
 */
int libsoft_rsa_init(void)
{
	int ret;

	ret = nxpcrypt_register(CRYPTO_RSA, &driver_rsa);

	return ret;
}

#endif /* CFG_CRYPTO_RSA_HW */

