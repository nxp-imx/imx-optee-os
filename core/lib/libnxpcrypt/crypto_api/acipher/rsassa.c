// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    rsassa.c
 *
 * @brief   RSA Signature Software common implementation.\n
 *          Functions preparing and/or verifying the signature
 *          encoded string.
 *          <a href="https://www.ietf.org/rfc/rfc3447.txt">
 *          PKCS #1 v2.1: RSA Cryptography Standard</a>
 */
/* Global includes */
#include <crypto/crypto.h>
#include <malloc.h>
#include <string.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

/* Library NXP includes */
#include <asn1_oid.h>
#include <libnxpcrypt.h>
#include <libnxpcrypt_acipher.h>
#include <libnxpcrypt_hash.h>
#include <libnxpcrypt_math.h>

/* Local include */
#include "local.h"

//#define RSA_DEBUG
#ifdef RSA_DEBUG
#define DUMP_BUF
#define RSA_TRACE	DMSG
#else
#define RSA_TRACE(...)
#endif

#ifdef DUMP_BUF
#define RSA_DUMPBUF(title, buf, len) \
					{RSA_TRACE("%s @ 0x%"PRIxPTR": %d", \
						title, (uintptr_t)buf, len); \
					 dhex_dump(NULL, 0, 0, buf, len); }
#else
#define RSA_DUMPBUF(...)
#endif

/**
 * @brief   Hash operation
 *
 * @param[in]  hash_id   Hash operation identifier
 * @param[in]  data      Data to hash
 * @param[out] digest    Digest result
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result do_hash(enum nxpcrypt_hash_id hash_id,
			const struct nxpcrypt_buf *data,
			struct nxpcrypt_buf *digest)
{
	TEE_Result ret;

	struct nxpcrypt_hash *hash = NULL;

	void *ctx = NULL;

	hash = nxpcrypt_getmod(CRYPTO_HASH);

	/* Verify that the HASH HW implements this algorithm */
	if (hash) {
		if (hash->max_hash < hash_id)
			hash = nxpcrypt_getmod(CRYPTO_HASH_SW);
	} else {
		hash = nxpcrypt_getmod(CRYPTO_HASH_SW);
	}

	if (!hash)
		return TEE_ERROR_NOT_IMPLEMENTED;

	/* Allocate the Hash Context */
	ret = hash->alloc_ctx(&ctx, hash_id);
	if (ret != TEE_SUCCESS)
		goto exit_hash;

	ret = hash->init(ctx);
	if (ret != TEE_SUCCESS)
		goto exit_hash;

	ret = hash->update(ctx, data->data, data->length);
	if (ret != TEE_SUCCESS)
		goto exit_hash;

	ret = hash->final(ctx, digest->data, digest->length);

exit_hash:
	hash->free_ctx(ctx);
	return ret;
}


/**
 * @brief   PKCS#1 V1.5 - Encode the message in Distinguished Encoding Rules
 *          (DER) format.\n
 *          Refer to EMSA-PKCS1-v1_5 chapter of the PKCS#1 v2.1
 *
 * @param[in]  ssa_data  RSA data to encode
 * @param[out] EM        Encoded Message
 *
 */
static void emsa_pkcs1_v1_5_encode(struct nxpcrypt_rsa_ssa *ssa_data,
			struct nxpcrypt_buf *EM)
{
	const struct nxpcrypt_oid *hash_oid;
	size_t  ps_size;
	uint8_t *buf;

	hash_oid = &nxpcrypt_hash_oid[ssa_data->hash_id];

	RSA_DUMPBUF("Hash OID", hash_oid->asn1, hash_oid->asn1_length);

	/*
	 * Calculate the PS size
	 *  EM Size (modulus size) - 3 bytes - DigestInfo DER format size
	 */
	ps_size  = ssa_data->key.n_size - 3;
	ps_size -= ssa_data->digest_size;
	ps_size -= 10 + hash_oid->asn1_length;

	RSA_TRACE("PS size = %d (n %d)", ps_size, ssa_data->key.n_size);

	/*
	 * EM = 0x00 || 0x01 || PS || 0x00 || T
	 *
	 * where T represent the message DigestInfo in DER:
	 *    DigestInfo ::= SEQUENCE {
	 *                digestAlgorithm AlgorithmIdentifier,
	 *                digest OCTET STRING
	 *                }
	 *
	 * T  Length = digest length + oid length
	 * PS Length = 8 bytes
	 * EM Length = T Length + 11
	 */
	buf = EM->data;

	/* Set the EM first byte to 0x00 */
	*buf++ = 0x00;

	/* Set the EM second byte to 0x01 */
	*buf++ = 0x01;

	/* Fill PS with 0xFF */
	memset(buf, 0xFF, ps_size);
	buf += ps_size;

	/* Set the Byte after PS to 0x00 */
	*buf++ = 0x00;

	/*
	 * Create the DigestInfo DER Sequence
	 *
	 *  DigestInfo ::= SEQUENCE {
	 *                digestAlgorithm AlgorithmIdentifier,
	 *                digest OCTET STRING
	 *                }
	 *
	 */
	/* SEQUENCE { */
	*buf++ = ASN1_SEQUENCE | ASN1_CONSTRUCTED;
	*buf++ = (uint8_t)(0x08 + hash_oid->asn1_length +
		ssa_data->digest_size);

		/* digestAlgorithm AlgorithmIdentifier */
		*buf++ = ASN1_SEQUENCE | ASN1_CONSTRUCTED;
		*buf++ = (uint8_t)(0x04 + hash_oid->asn1_length);
		*buf++ = ASN1_OID;
		*buf++ = hash_oid->asn1_length;

		/* digest OCTET STRING */
		memcpy(buf, hash_oid->asn1, hash_oid->asn1_length);
		buf += hash_oid->asn1_length;
		*buf++ = ASN1_NULL;
		*buf++ = 0x00;
		*buf++ = ASN1_OCTET_STRING;
		*buf++ = ssa_data->digest_size;
	/* } */

	memcpy(buf, ssa_data->message.data, ssa_data->digest_size);

	RSA_DUMPBUF("Encoded Message", EM->data, EM->length);
}

/**
 * @brief   Encrypts the RSA message built. This function calls
 *          the RSA decrypt operation (NOPAD without removing the
 *          left 0s).
 *          RSA encrypt/decrypt are doing the same operation except
 *          that decrypt is using the RSA Private key
 *
 * @param[in/out]  ssa_data   RSA data signature
 * @param[in]      msg        RSA Message to encrypt
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result rsa_encrypt(struct nxpcrypt_rsa_ssa *ssa_data,
		struct nxpcrypt_buf *msg)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct nxpcrypt_rsa    *rsa = NULL;
	struct nxpcrypt_rsa_ed rsa_data;

	rsa_data.key.key       = ssa_data->key.key;
	rsa_data.key.isprivate = true;
	rsa_data.key.n_size    = ssa_data->key.n_size;

	rsa = nxpcrypt_getmod(CRYPTO_RSA);
	if (rsa) {
		/* Prepare the decryption data parameters */
		rsa_data.rsa_id         = RSA_SIGN;
		rsa_data.message.data   = ssa_data->signature.data;
		rsa_data.message.length = ssa_data->signature.length;
		rsa_data.cipher.data    = msg->data;
		rsa_data.cipher.length  = msg->length;

		ret = rsa->decrypt(&rsa_data);
	}

	return ret;
}

/**
 * @brief   PKCS#1 V1.5 - Signature of RSA message and encodes the signature.
 *          Refer to RSASSA-PKCS1-v1_5 chapter of the PKCS#1 v2.1
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
static TEE_Result rsassa_pkcs1_v1_5_sign(struct nxpcrypt_rsa_ssa *ssa_data)
{
	TEE_Result ret;

	struct nxpcrypt_buf EM = {0};

	EM.length = ssa_data->key.n_size;
	EM.data   = malloc(EM.length);
	if (!EM.data)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* Encode the Message */
	emsa_pkcs1_v1_5_encode(ssa_data, &EM);

	ret = rsa_encrypt(ssa_data, &EM);

	free(EM.data);

	return ret;
}

/**
 * @brief   PKCS#1 V1.5 - Verification of the RSA message's signature.
 *          Refer to RSASSA-PKCS1-v1_5 chapter of the PKCS#1 v2.1
 *
 * @param[in/out]  ssa_data   RSA data signed and encoded signature
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_SHORT_BUFFER      Result buffer too short
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_SIGNATURE_INVALID Signature invalid
 */
static TEE_Result rsassa_pkcs1_v1_5_verify(struct nxpcrypt_rsa_ssa *ssa_data)
{
	TEE_Result ret;

	struct nxpcrypt_buf EM     = {0};
	struct nxpcrypt_buf EM_gen = {0};

	EM.length = ssa_data->key.n_size;
	EM.data   = malloc(EM.length);

	EM_gen.length = ssa_data->key.n_size;
	EM_gen.data   = malloc(EM.length);

	if ((!EM.data) || (!EM_gen.data)) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto end_verify;
	}

	/*
	 * RSA NO PAD  Encrypt/Decrypt are doing the same operation
	 * expect that the encrypt takes a RSA Public key in parameter
	 */
	ret = crypto_acipher_rsanopad_encrypt(ssa_data->key.key,
						ssa_data->signature.data,
						ssa_data->signature.length,
						EM.data, &EM.length);
	if (ret == TEE_SUCCESS) {
		/* Encode the Message */
		emsa_pkcs1_v1_5_encode(ssa_data, &EM_gen);

		/* Check if EM decrypted and EM re-generated are identical */
		ret = TEE_ERROR_SIGNATURE_INVALID;
		if (EM.length == EM_gen.length) {
			if (memcmp(EM.data, EM_gen.data, EM.length) == 0)
				ret = TEE_SUCCESS;
		}
	}

end_verify:
	free(EM.data);
	free(EM_gen.data);

	return ret;
}

/**
 * @brief   PSS - Encode the message using a Probabilistic Signature
 *          Scheme (PSS)
 *          Refer to EMSA-PSS (encoding) chapter of the PKCS#1 v2.1
 *
 * @param[in]  ssa_data  RSA data to encode
 * @param[in]  emBits    EM size in bits
 * @param[out] EM        Encoded Message
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result emsa_pss_encode(struct nxpcrypt_rsa_ssa *ssa_data,
			size_t emBits, struct nxpcrypt_buf *EM)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	struct nxpcrypt_rsa_mgf mgf_data;
	struct nxpcrypt_buf msg;
	struct nxpcrypt_buf hash;
	struct nxpcrypt_buf dbMask;
	struct nxpcrypt_buf DB;
	size_t db_size;
	size_t ps_size;
	size_t msg_size;
	uint8_t *buf;
	uint8_t *msg_db = NULL;
	uint8_t *salt   = NULL;

	struct nxpcrypt_mod_op mod_op;

	/*
	 * Build EM = maskedDB || H || 0xbc
	 *
	 * where
	 *    maskedDB = DB xor dbMask
	 *       DB     = PS || 0x01 || salt
	 *       dbMask = MGF(H, emLen - hLen - 1)
	 *
	 *    H  = Hash(M')
	 *       M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
	 *
	 * PS size = emLen - sLen - hLen - 2 (may be = 0)
	 */


	/*
	 * Calculate the M' and DB size to allocate a temporary buffer
	 * used for both object
	 */
	ps_size  = EM->length - ssa_data->digest_size - ssa_data->salt_len - 2;
	db_size  = EM->length - ssa_data->digest_size - 1;
	msg_size = 8 + ssa_data->digest_size + ssa_data->salt_len;

	RSA_TRACE("PS Len = %d, DB Len = %d, M' Len = %d",
			ps_size, db_size, msg_size);

	msg_db = malloc(MAX(db_size, msg_size));
	if (!msg_db)
		return TEE_ERROR_OUT_OF_MEMORY;

	if (ssa_data->salt_len) {
		salt = malloc(ssa_data->salt_len);

		if (!salt) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto end_pss_encode;
		}
	}

	/*
	 * Step 4 and 5
	 * Generate the M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
	 *
	 * where
	 *   mHash is the input message (already hash)
	 *   salt is a random number of salt_len (input data) can be empty
	 */
	buf = msg_db;

	memset(buf, 0, 8);
	buf += 8;

	memcpy(buf, ssa_data->message.data, ssa_data->message.length);
	buf += ssa_data->message.length;

	/* Get salt random number if salt length not 0 */
	if (ssa_data->salt_len) {
		ret = crypto_rng_read(salt, ssa_data->salt_len);
		RSA_TRACE("Get salt of %d bytes (ret = 0x%08"PRIx32")",
			ssa_data->salt_len, ret);
		if (ret != TEE_SUCCESS)
			goto end_pss_encode;

		memcpy(buf, salt, ssa_data->salt_len);
	}

	/*
	 * Step 6
	 * Hash the M' generated new message
	 * H = hash(M')
	 */
	msg.data    = msg_db;
	msg.length  = msg_size;

	hash.data   = &EM->data[db_size];
	hash.length = ssa_data->digest_size;

	ret = do_hash(ssa_data->hash_id, &msg, &hash);
	RSA_TRACE("H = hash(M') returned 0x%08"PRIx32"", ret);
	if (ret != TEE_SUCCESS)
		goto end_pss_encode;

	RSA_DUMPBUF("H = hash(M')", hash.data, hash.length);

	/*
	 * Step 7 and 8
	 *   DB = PS || 0x01 || salt
	 */
	buf = msg_db;
	if (ps_size)
		memset(buf, 0, ps_size);
	buf += ps_size;
	*buf++ = 0x01;

	if (ssa_data->salt_len)
		memcpy(buf, salt, ssa_data->salt_len);

	DB.data   = msg_db;
	DB.length = db_size;

	RSA_DUMPBUF("DB", DB.data, DB.length);

	/*
	 * Step 9
	 * Generate a Mask of the seed value
	 * dbMask = MGF(H, emLen - hLen - 1)
	 *
	 * Note: Will use the same buffer for the dbMask and maskedDB
	 *       maskedDB is in the EM output
	 */
	dbMask.data   = EM->data;
	dbMask.length = db_size;

	mgf_data.hash_id     = ssa_data->hash_id;
	mgf_data.digest_size = ssa_data->digest_size;
	mgf_data.seed.data   = hash.data;
	mgf_data.seed.length = hash.length;
	mgf_data.mask.data   = dbMask.data;
	mgf_data.mask.length = dbMask.length;
	ret = ssa_data->mgf(&mgf_data);

	RSA_TRACE("dbMask = MGF(H, emLen - hLen - 1) returned 0x%08"PRIx32"",
		ret);
	if (ret != TEE_SUCCESS)
		goto end_pss_encode;

	RSA_DUMPBUF("dbMask", dbMask.data, dbMask.length);

	/*
	 * Step 10
	 * maskedDB = DB xor dbMask
	 */
	mod_op.N.length      = dbMask.length;
	mod_op.A.data        = DB.data;
	mod_op.A.length      = DB.length;
	mod_op.B.data        = dbMask.data;
	mod_op.B.length      = dbMask.length;
	mod_op.result.data   = dbMask.data;
	mod_op.result.length = dbMask.length;

	ret = libnxpcrypt_xor_mod_n(&mod_op);
	RSA_TRACE("maskedDB = DB xor dbMask returned 0x%08"PRIx32"", ret);
	if (ret != TEE_SUCCESS)
		goto end_pss_encode;

	RSA_DUMPBUF("maskedDB", dbMask.data, dbMask.length);

	/*
	 * Step 11
	 * Set the leftmost 8emLen - emBits of the leftmost octet
	 * in maskedDB to 0'
	 */
	EM->data[0] &= (0xFF >> ((EM->length * 8) - emBits));

	/*
	 * Step 12
	 * EM = maskedDB || H || 0xbc
	 */
	EM->data[EM->length - 1] = 0xbc;

	RSA_DUMPBUF("EM", EM->data, EM->length);

	ret = TEE_SUCCESS;
end_pss_encode:
	free(msg_db);
	free(salt);

	return ret;
}

/**
 * @brief   PSS - Verify the message using a Probabilistic Signature
 *          Scheme (PSS)
 *          Refer to EMSA-PSS (verification) chapter of the PKCS#1 v2.1
 *
 * @param[in]  ssa_data  RSA data to encode
 * @param[in]  emBits    EM size in bits
 * @param[out] EM        Encoded Message
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_SIGNATURE_INVALID Signature invalid
 */
static TEE_Result emsa_pss_verify(struct nxpcrypt_rsa_ssa *ssa_data,
			size_t emBits, struct nxpcrypt_buf *EM)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	struct nxpcrypt_rsa_mgf mgf_data;
	struct nxpcrypt_buf msg;
	struct nxpcrypt_buf hash;
	struct nxpcrypt_buf hash_gen;
	size_t db_size;
	size_t ps_size;
	size_t msg_size;
	uint8_t *msg_db = NULL;
	uint8_t *salt   = NULL;
	uint8_t *buf;

	struct nxpcrypt_mod_op mod_op;

	/*
	 * EM = maskedDB || H || 0xbc
	 *
	 * where
	 *    maskedDB = DB xor dbMask
	 *       DB     = PS || 0x01 || salt
	 *       dbMask = MGF(H, emLen - hLen - 1)
	 *
	 *    H  = Hash(M')
	 *       M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
	 *
	 * PS size = emLen - sLen - hLen - 2 (may be = 0)
	 */

	/*
	 * Calculate the M' and DB size to allocate a temporary buffer
	 * used for both object
	 */
	ps_size  = EM->length - ssa_data->digest_size - ssa_data->salt_len - 2;
	db_size  = EM->length - ssa_data->digest_size - 1;
	msg_size = 8 + ssa_data->digest_size + ssa_data->salt_len;

	RSA_TRACE("PS Len = %d, DB Len = %d, M' Len = %d",
			ps_size, db_size, msg_size);

	msg_db = malloc(MAX(db_size, msg_size));
	if (!msg_db)
		return TEE_ERROR_OUT_OF_MEMORY;

	/*
	 * Step 4
	 * Check if rightmost octet of EM is 0xbc
	 */
	if (EM->data[EM->length - 1] != 0xbc) {
		RSA_TRACE("rigthmost octet != 0xbc (0x%x)",
			EM->data[EM->length - 1]);
		ret = TEE_ERROR_SIGNATURE_INVALID;
		goto end_pss_verify;
	}

	/*
	 * Step 6
	 * Check if the leftmost 8emLen - emBits of the leftmost octet
	 * in maskedDB are 0's
	 */
	if (EM->data[0] & ~(0xFF >> ((EM->length * 8) - emBits))) {
		RSA_TRACE("Error leftmost octet maskedDB not 0's");
		RSA_TRACE("EM[0] = 0x%x - EM Len = %d, emBits = %d",
				EM->data[0], EM->length, emBits);
		ret = TEE_ERROR_SIGNATURE_INVALID;
		goto end_pss_verify;
	}

	hash.data   = &EM->data[db_size];
	hash.length = ssa_data->digest_size;

	/*
	 * Step 7
	 * dbMask = MGF(H, emLen - hLen - 1)
	 *
	 * Note: Will use the same buffer for the dbMask and DB
	 */
	mgf_data.hash_id     = ssa_data->hash_id;
	mgf_data.digest_size = ssa_data->digest_size;
	mgf_data.seed.data   = hash.data;
	mgf_data.seed.length = hash.length;
	mgf_data.mask.data   = msg_db;
	mgf_data.mask.length = db_size;
	ret = ssa_data->mgf(&mgf_data);

	RSA_TRACE("dbMask = MGF(H, emLen - hLen - 1) returned 0x%08"PRIx32"",
			ret);
	if (ret != TEE_SUCCESS)
		goto end_pss_verify;

	RSA_DUMPBUF("dbMask", msg_db, db_size);

	/*
	 * Step 8
	 * DB = maskedDB xor dbMask
	 *
	 *
	 * Note: maskedDB is in the EM input
	 */
	mod_op.N.length      = db_size;
	mod_op.A.data        = EM->data;
	mod_op.A.length      = db_size;
	mod_op.B.data        = msg_db;
	mod_op.B.length      = db_size;
	mod_op.result.data   = msg_db;
	mod_op.result.length = db_size;

	ret = libnxpcrypt_xor_mod_n(&mod_op);
	RSA_TRACE("DB = maskedDB xor dbMask returned 0x%08"PRIx32"", ret);
	if (ret != TEE_SUCCESS)
		goto end_pss_verify;

	/*
	 * Step 9
	 * Set the leftmost 8emLen - emBits of the leftmost octet in
	 * DB to zero
	 */
	*msg_db &= 0xFF >> ((EM->length * 8) - emBits);

	RSA_DUMPBUF("DB", msg_db, db_size);

	/*
	 * Step 10
	 * Expected to have
	 *       DB     = PS || 0x01 || salt
	 *
	 * PS must be 0
	 * PS size = emLen - sLen - hLen - 2 (may be = 0)
	 */
	buf = msg_db;
	while (buf < (msg_db + ps_size)) {
		if (*buf++ != 0) {
			ret = TEE_ERROR_SIGNATURE_INVALID;
			goto end_pss_verify;
		}
	}

	if (*buf++ != 0x01) {
		ret = TEE_ERROR_SIGNATURE_INVALID;
		goto end_pss_verify;
	}

	/*
	 * Step 11
	 * Get the slat value
	 */
	if (ssa_data->salt_len) {
		salt = malloc(ssa_data->salt_len);
		if (!salt) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto end_pss_verify;
		}

		memcpy(salt, buf, ssa_data->salt_len);
	}

	/*
	 * Step 12
	 * Generate the M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
	 *
	 * where
	 *   mHash is the input message (already hash)
	 *   salt is a random number of salt_len (input data) can be empty
	 */
	buf = msg_db;

	memset(buf, 0, 8);
	buf += 8;

	memcpy(buf, ssa_data->message.data, ssa_data->message.length);
	buf += ssa_data->message.length;

	if (ssa_data->salt_len)
		memcpy(buf, salt, ssa_data->salt_len);

	/*
	 * Step 13
	 * Hash the M' generated new message
	 * H' = hash(M')
	 *
	 * Note: reuse the msg_db buffer as Hash result
	 */
	hash_gen.data = msg_db;
	hash_gen.length = ssa_data->digest_size;

	msg.data   = msg_db;
	msg.length = msg_size;

	ret = do_hash(ssa_data->hash_id, &msg, &hash_gen);
	RSA_TRACE("H' = hash(M') returned 0x%08"PRIx32"", ret);
	if (ret != TEE_SUCCESS)
		goto end_pss_verify;

	RSA_DUMPBUF("H' = hash(M')", hash_gen.data, hash_gen.length);

	/*
	 * Step 14
	 * Compare H and H'
	 */
	ret = TEE_ERROR_SIGNATURE_INVALID;
	if (memcmp(hash_gen.data, hash.data, hash_gen.length) == 0)
		ret = TEE_SUCCESS;

end_pss_verify:
	free(msg_db);
	free(salt);

	return ret;
}

/**
 * @brief   PSS - Signature of RSA message and encodes the signature.
 *          Refer to RSASSA-PSS chapter of the PKCS#1 v2.1
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
static TEE_Result rsassa_pss_sign(struct nxpcrypt_rsa_ssa *ssa_data)
{
	TEE_Result ret;

	struct rsa_keypair *key;
	struct nxpcrypt_buf EM = {0};
	size_t modBits;

	key = ssa_data->key.key;

	/* get modulus len in bits */
	modBits = crypto_bignum_num_bits(key->n);
	if (modBits <= 0)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * EM Length = (modBits - 1) / 8
	 * if (modBits - 1) is not divisible by 8, one more byte is needed
	 */
	modBits--;
	EM.length = (modBits / 8) + ((modBits % 8) ? 1 : 0);
	EM.data   = malloc(EM.length);
	if (!EM.data)
		return TEE_ERROR_OUT_OF_MEMORY;

	RSA_TRACE("modBits = %d, hence EM Length = %d",
			(modBits + 1), EM.length);

	/* Encode the Message */
	ret = emsa_pss_encode(ssa_data, modBits, &EM);
	RSA_TRACE("EMSA PSS Encode returned 0x%08"PRIx32"", ret);

	/*
	 * RSA NO PAD  Encrypt/Decrypt are doing the same operation
	 * expect that the decrypt takes a RSA Private key in parameter
	 */
	if (ret == TEE_SUCCESS)
		ret = rsa_encrypt(ssa_data, &EM);

	free(EM.data);

	return ret;
}

/**
 * @brief   PSS - Signature verification of RSA message.
 *          Refer to RSASSA-PSS chapter of the PKCS#1 v2.1
 *
 * @param[in/out]  ssa_data   RSA Signature vs. message to verify
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_SIGNATURE_INVALID Signature invalid
 */
static TEE_Result rsassa_pss_verify(struct nxpcrypt_rsa_ssa *ssa_data)
{
	TEE_Result ret;

	struct rsa_public_key *key;
	struct nxpcrypt_buf EM = {0};
	size_t modBits;
	size_t emLen;

	key = ssa_data->key.key;

	/* get modulus len in bits */
	modBits = crypto_bignum_num_bits(key->n);
	if (modBits <= 0)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * EM Length = (modBits - 1) / 8
	 * if (modBits - 1) is not divisible by 8, one more byte is needed
	 */
	modBits--;
	EM.length = (modBits / 8) + ((modBits % 8) ? 1 : 0);
	EM.data   = malloc(EM.length);
	if (!EM.data)
		return TEE_ERROR_OUT_OF_MEMORY;

	RSA_TRACE("modBits = %d, hence EM Length = %d",
			(modBits + 1), EM.length);

	/*
	 * RSA NO PAD  Encrypt/Decrypt are doing the same operation
	 * expect that the encrypt takes a RSA Public key in parameter
	 */
	emLen = EM.length;
	ret = crypto_acipher_rsanopad_encrypt(key,
						ssa_data->signature.data,
						ssa_data->signature.length,
						EM.data, &emLen);
	if (ret == TEE_SUCCESS) {
		if (emLen != EM.length) {
			RSA_TRACE("EM Length expected %d got %d",
				emLen, EM.length);
		}

		/* Verify the Message */
		ret = emsa_pss_verify(ssa_data, modBits, &EM);
		RSA_TRACE("EMSA PSS Verify returned 0x%08"PRIx32"", ret);
	} else {
		RSA_TRACE("RSA NO PAD returned 0x%08"PRIx32"", ret);
		ret = TEE_ERROR_SIGNATURE_INVALID;
	}

	free(EM.data);

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
TEE_Result rsassa_sign(struct nxpcrypt_rsa_ssa *ssa_data)
{
	switch (ssa_data->algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		return rsassa_pkcs1_v1_5_sign(ssa_data);

	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		return rsassa_pss_sign(ssa_data);

	default:
		break;
	}

	return TEE_ERROR_BAD_PARAMETERS;
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
TEE_Result rsassa_verify(struct nxpcrypt_rsa_ssa *ssa_data)
{
	switch (ssa_data->algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		return rsassa_pkcs1_v1_5_verify(ssa_data);

	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		return rsassa_pss_verify(ssa_data);

	default:
		break;
	}

	return TEE_ERROR_BAD_PARAMETERS;
}

