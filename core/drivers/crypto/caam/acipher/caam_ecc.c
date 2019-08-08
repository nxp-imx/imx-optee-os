// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019 NXP
 *
 * Implementation of ECC functions
 */
#include <caam_acipher.h>
#include <caam_common.h>
#include <caam_hal_ctrl.h>
#include <caam_jr.h>
#include <caam_utils_mem.h>
#include <caam_utils_sgt.h>
#include <caam_utils_status.h>
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

/*
 * Definition of the local ECC Keypair
 *   Public Key format (x, y)
 *   Private Key format (d)
 */
struct caam_ecc_keypair {
	struct caambuf xy; /* Public key - (x, y) ecc point */
	struct caambuf d;  /* Private key - d scalar */
};

/*
 * Free local RSA keypair
 *
 * @key  RSA keypair
 */
static void do_keypair_free(struct caam_ecc_keypair *key)
{
	caam_free_buf(&key->xy);
	caam_free_buf(&key->d);
}

/*
 * Convert Crypto ECC Key to local ECC Public Key
 * Ensure Key is push in physical memory
 *
 * @outkey    [out] Output keypair in local format
 * @inkey     Input key in TEE Crypto format
 * @size_sec  Security size in bytes
 */
static enum caam_status do_keypub_conv(struct caam_ecc_keypair *outkey,
				       const struct ecc_public_key *inkey,
				       size_t size_sec)
{
	enum caam_status retstatus = CAAM_OUT_MEMORY;
	size_t x_size = 0;
	size_t y_size = 0;

	ECC_TRACE("ECC Convert Public Key size %zu bytes", size_sec);

	/* Point (x y) is twice security key size */
	retstatus = caam_calloc_buf(&outkey->xy, 2 * size_sec);
	if (retstatus != CAAM_NO_ERROR)
		return CAAM_OUT_MEMORY;

	/*
	 * Copy x value
	 */
	/* Get the number of bytes of x to pad with 0's */
	x_size = crypto_bignum_num_bytes(inkey->x);
	crypto_bignum_bn2bin(inkey->x, outkey->xy.data + size_sec - x_size);

	/*
	 * Copy y value
	 */
	/* Get the number of bytes of y to pad with 0's */
	y_size = crypto_bignum_num_bytes(inkey->y);
	crypto_bignum_bn2bin(inkey->y, outkey->xy.data + 2 * size_sec - y_size);

	cache_operation(TEE_CACHECLEAN, outkey->xy.data, outkey->xy.length);

	return CAAM_NO_ERROR;
}

/*
 * Convert Crypto ECC Key to local ECC Keypair Key
 * Ensure Key is push in physical memory
 * Don't convert the exponent e not used in decrytion
 *
 * @outkey    [out] Output keypair in local format
 * @inkey     Input key in TEE Crypto format
 * @size_sec  Security size in bytes
 */
static enum caam_status do_keypair_conv(struct caam_ecc_keypair *outkey,
					const struct ecc_keypair *inkey,
					size_t size_sec)
{
	enum caam_status retstatus = CAAM_OUT_MEMORY;
	size_t d_size = 0;

	ECC_TRACE("ECC Convert Keypair size %zu bytes", size_sec);

	/* Private key is only scalar d of sec_size bytes */
	retstatus = caam_calloc_buf(&outkey->d, size_sec);
	if (retstatus != CAAM_NO_ERROR)
		return CAAM_OUT_MEMORY;

	/* Get the number of bytes of d to pad with 0's */
	d_size = crypto_bignum_num_bytes(inkey->d);
	crypto_bignum_bn2bin(inkey->d, outkey->d.data + size_sec - d_size);

	cache_operation(TEE_CACHECLEAN, outkey->d.data, outkey->d.length);

	return CAAM_NO_ERROR;
}

/*
 * Convert TEE ECC Curve to CAAM ECC Curve
 *
 * @tee_curve  TEE ECC Curve
 */
static enum caam_ecc_curve get_caam_curve(uint32_t tee_curve)
{
	enum caam_ecc_curve caam_curve = CAAM_ECC_UNKNOWN;

	if (tee_curve > 0 &&
	    tee_curve < CAAM_ECC_MAX + TEE_ECC_CURVE_NIST_P192) {
		/*
		 * Realign TEE Curve knowing that first in the list is the
		 * NIST_P192
		 */
		caam_curve =
			tee_curve - TEE_ECC_CURVE_NIST_P192 + CAAM_ECC_P192;
	}

	return caam_curve;
}

/*
 * Allocate a ECC keypair
 *
 * @key        Keypair
 * @size_bits  Key size in bits
 */
static TEE_Result do_allocate_keypair(struct ecc_keypair *key, size_t size_bits)
{
	ECC_TRACE("Allocate Keypair of %zu bits", size_bits);

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
	ECC_TRACE("Allocation error");

	crypto_bignum_free(key->d);
	crypto_bignum_free(key->x);

	return TEE_ERROR_OUT_OF_MEMORY;
}

/*
 * Allocate an ECC Public Key
 *
 * @key        Public Key
 * @size_bits  Key size in bits
 */
static TEE_Result do_allocate_publickey(struct ecc_public_key *key,
					size_t size_bits)
{
	ECC_TRACE("Allocate Public Key of %zu bits", size_bits);

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
	ECC_TRACE("Allocation error");

	crypto_bignum_free(key->x);

	return TEE_ERROR_OUT_OF_MEMORY;
}

/*
 * Free an ECC public key
 *
 * @key  Public Key
 */
static void do_free_publickey(struct ecc_public_key *key)
{
	crypto_bignum_free(key->x);
	crypto_bignum_free(key->y);
}

/*
 * Generates an ECC keypair
 *
 * @key        [out] Keypair
 * @key_size   Key size in bits multiple of 8 bits
 */
static TEE_Result do_gen_keypair(struct ecc_keypair *key, size_t key_size)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	enum caam_ecc_curve curve = CAAM_ECC_UNKNOWN;
	struct caambuf d = {};
	struct caambuf xy = {};
	struct caam_jobctx jobctx = {};
	uint32_t *desc = NULL;
	uint32_t desclen = 0;

#ifdef CFG_CAAM_64BIT
#define MAX_DESC_KEY_GEN 8
#else
#define MAX_DESC_KEY_GEN 6
#endif

	ECC_TRACE("Generate Keypair of %zu bits", key_size);

	/* Verify first if the curve is supported */
	curve = get_caam_curve(key->curve);
	if (curve == CAAM_ECC_UNKNOWN)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Allocate the job used to prepare the operation */
	desc = caam_calloc_desc(MAX_DESC_KEY_GEN);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_gen_keypair;
	}

	/*
	 * Allocate secure and public keys in one buffer
	 * Secure key size = key_size align in bytes
	 * Public key size = (key_size * 2) align in bytes
	 */
	retstatus = caam_alloc_align_buf(&d, (key_size / 8) * 3);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_gen_keypair;
	}

	/* Build the xy buffer to simplify the code */
	xy.data = d.data + key_size / 8;
	xy.length = 2 * (key_size / 8);
	xy.paddr = d.paddr + key_size / 8;

	/*
	 * Build the descriptor using Predifined ECC curve
	 */
	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	caam_desc_add_word(desc, PDB_PKGEN_PD1 | PDB_ECC_ECDSEL(curve));
	caam_desc_add_ptr(desc, d.paddr);
	caam_desc_add_ptr(desc, xy.paddr);
	caam_desc_add_word(desc, PK_KEYPAIR_GEN(ECC));

	desclen = caam_desc_get_len(desc);
	caam_desc_update_hdr(desc, DESC_HEADER_IDX(desclen, desclen - 1));

	ECC_DUMPDESC(desc);

	jobctx.desc = desc;
	cache_operation(TEE_CACHEFLUSH, d.data, d.length);
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		cache_operation(TEE_CACHEINVALIDATE, d.data, d.length);

		/* Copy all keypair parameters */
		ret = crypto_bignum_bin2bn(d.data, key_size / 8, key->d);
		if (ret != TEE_SUCCESS)
			goto exit_gen_keypair;

		ret = crypto_bignum_bin2bn(xy.data, xy.length / 2, key->x);
		if (ret != TEE_SUCCESS)
			goto exit_gen_keypair;

		ret = crypto_bignum_bin2bn(xy.data + xy.length / 2,
					   xy.length / 2, key->y);
		if (ret != TEE_SUCCESS)
			goto exit_gen_keypair;

		ECC_DUMPBUF("D", d.data, key_size / 8);
		ECC_DUMPBUF("X", xy.data, xy.length / 2);
		ECC_DUMPBUF("Y", xy.data + xy.length / 2, xy.length / 2);

		ret = TEE_SUCCESS;
	} else {
		ECC_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

exit_gen_keypair:
	caam_free_desc(&desc);
	caam_free_buf(&d);

	return ret;
}

/*
 * Signature of ECC message
 * Note the message to sign is already hashed
 *
 * @sdata   [in/out] ECC data to sign / Signature
 */
static TEE_Result do_sign(struct drvcrypt_sign_data *sdata)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	enum caam_ecc_curve curve = CAAM_ECC_UNKNOWN;
	struct ecc_keypair *inkey = sdata->key;
	struct caam_ecc_keypair ecckey = {};
	struct caam_jobctx jobctx = {};
	uint32_t *desc = NULL;
	uint32_t desclen = 0;
	struct caambuf msg_tmp = {};
	struct caamsgtbuf msg_sgt = { .sgt_type = false };
	paddr_t paddr_msg = 0;
	int realloc = 0;
	size_t sign_len = 0;
	struct caambuf sign_c_tmp = {};
	struct caambuf sign_d_tmp = {};
	struct caamsgtbuf sign_c_sgt = { .sgt_type = false };
	struct caamsgtbuf sign_d_sgt = { .sgt_type = false };
	paddr_t paddr_sign_c = 0;
	paddr_t paddr_sign_d = 0;
	uint32_t pdb_sgt_flags = 0;

#ifdef CFG_CAAM_64BIT
#define MAX_DESC_SIGN 13
#else
#define MAX_DESC_SIGN 9
#endif

	ECC_TRACE("ECC Signature");

	/* Verify first if the curve is supported */
	curve = get_caam_curve(inkey->curve);
	if (curve == CAAM_ECC_UNKNOWN)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Allocate the job descriptor */
	desc = caam_calloc_desc(MAX_DESC_SIGN);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_sign;
	}

	/* Convert the private key to a local key */
	retstatus = do_keypair_conv(&ecckey, inkey, sdata->size_sec);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_sign;
	}

	/* Prepare the input message CAAM Descriptor entry */
	msg_tmp.data = sdata->message.data;
	msg_tmp.length = sdata->message.length;
	msg_tmp.paddr = virt_to_phys(sdata->message.data);
	if (!caam_mem_is_cached_buf(sdata->message.data, sdata->message.length))
		msg_tmp.nocache = 1;

	retstatus = caam_sgt_build_block_data(&msg_sgt, NULL, &msg_tmp);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_GENERIC;
		goto exit_sign;
	}

	if (msg_sgt.sgt_type) {
		pdb_sgt_flags |= PDB_SGT_PKSIGN_MSG;
		paddr_msg = virt_to_phys(msg_sgt.sgt);
		caam_sgt_cache_op(TEE_CACHECLEAN, &msg_sgt);
	} else {
		paddr_msg = msg_sgt.buf->paddr;
		if (!msg_sgt.buf->nocache)
			cache_operation(TEE_CACHECLEAN, msg_sgt.buf->data,
					msg_sgt.length);
	}

	ECC_DUMPBUF("Message", sdata->message.data, sdata->message.length);

	/*
	 * ReAllocate the signature result buffer with a maximum size
	 * of the roundup to 16 bytes of the secure size in bytes if
	 * the signature buffer is not aligned or too short.
	 *
	 *  - 1st Part: size_sec
	 *  - 2nd Part: size_sec roundup to 16 bytes
	 */
	sign_len = ROUNDUP(sdata->size_sec, 16) + sdata->size_sec;

	realloc = caam_set_or_alloc_align_buf(sdata->signature.data,
					      &sign_c_tmp, sign_len);
	if (realloc == -1) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_sign;
	}

	/* Prepare the 1st Part of the signature */
	sign_c_tmp.length = sdata->size_sec;
	retstatus = caam_sgt_build_block_data(&sign_c_sgt, NULL, &sign_c_tmp);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_GENERIC;
		goto exit_sign;
	}

	if (sign_c_sgt.sgt_type) {
		pdb_sgt_flags |= PDB_SGT_PKSIGN_SIGN_C;
		paddr_sign_c = virt_to_phys(sign_c_sgt.sgt);
		caam_sgt_cache_op(TEE_CACHEFLUSH, &sign_c_sgt);
	} else {
		paddr_sign_c = sign_c_sgt.buf->paddr;
		if (!sign_c_sgt.buf->nocache)
			cache_operation(TEE_CACHEFLUSH, sign_c_sgt.buf->data,
					sign_c_sgt.length);
	}

	/* Prepare the 2nd Part of the signature */
	sign_d_tmp.data = sign_c_tmp.data + sdata->size_sec;
	sign_d_tmp.length = ROUNDUP(sdata->size_sec, 16);
	sign_d_tmp.paddr = virt_to_phys(sign_d_tmp.data);
	sign_d_tmp.nocache = sign_c_tmp.nocache;

	retstatus = caam_sgt_build_block_data(&sign_d_sgt, NULL, &sign_d_tmp);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_GENERIC;
		goto exit_sign;
	}

	if (sign_d_sgt.sgt_type) {
		pdb_sgt_flags |= PDB_SGT_PKSIGN_SIGN_D;
		paddr_sign_d = virt_to_phys(sign_d_sgt.sgt);
		caam_sgt_cache_op(TEE_CACHEFLUSH, &sign_d_sgt);
	} else {
		paddr_sign_d = sign_d_sgt.buf->paddr;
		if (!sign_d_sgt.buf->nocache)
			cache_operation(TEE_CACHEFLUSH, sign_d_sgt.buf->data,
					sign_d_sgt.length);
	}

	/*
	 * Build the descriptor using Predifined ECC curve
	 */
	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	caam_desc_add_word(desc, PDB_PKSIGN_PD1 | PDB_ECC_ECDSEL(curve) |
					 pdb_sgt_flags);
	/* Secret key */
	caam_desc_add_ptr(desc, ecckey.d.paddr);
	/* Input message */
	caam_desc_add_ptr(desc, paddr_msg);
	/* Signature 1st part */
	caam_desc_add_ptr(desc, paddr_sign_c);
	/* Signature 2nd part */
	caam_desc_add_ptr(desc, paddr_sign_d);
	/* Message length */
	caam_desc_add_word(desc, sdata->message.length);

	caam_desc_add_word(desc, DSA_SIGN(ECC));

	desclen = caam_desc_get_len(desc);
	caam_desc_update_hdr(desc, DESC_HEADER_IDX(desclen, desclen - 1));

	ECC_DUMPDESC(desc);

	jobctx.desc = desc;

	retstatus = caam_jr_enqueue(&jobctx, NULL);
	if (retstatus == CAAM_NO_ERROR) {
		if (!sign_c_tmp.nocache)
			cache_operation(TEE_CACHEINVALIDATE, sign_c_tmp.data,
					sign_len);

		if (realloc == 1)
			memcpy(sdata->signature.data, sign_c_tmp.data,
			       2 * sdata->size_sec);

		sdata->signature.length = 2 * sdata->size_sec;

		ECC_DUMPBUF("Signature", sdata->signature.data,
			    sdata->signature.length);

		ret = TEE_SUCCESS;
	} else {
		ECC_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

exit_sign:
	caam_free_desc(&desc);
	do_keypair_free(&ecckey);

	if (realloc == 1) {
		sign_c_tmp.length = sign_len;
		caam_free_buf(&sign_c_tmp);
	}

	if (msg_sgt.sgt_type)
		caam_sgtbuf_free(&msg_sgt);

	if (sign_c_sgt.sgt_type)
		caam_sgtbuf_free(&sign_c_sgt);

	if (sign_d_sgt.sgt_type)
		caam_sgtbuf_free(&sign_d_sgt);

	return ret;
}

/*
 * Verification of the Signature of ECC message
 * Note the message is already hashed
 *
 * @sdata   [in/out] ECC Signature to verify
 */
static TEE_Result do_verify(struct drvcrypt_sign_data *sdata)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	enum caam_ecc_curve curve = CAAM_ECC_UNKNOWN;
	struct ecc_public_key *inkey = sdata->key;
	struct caam_ecc_keypair ecckey = {};
	struct caambuf tmp = {};
	struct caam_jobctx jobctx = {};
	uint32_t *desc = NULL;
	uint32_t desclen = 0;
	struct caambuf msg_tmp = {};
	struct caamsgtbuf msg_sgt = { .sgt_type = false };
	paddr_t paddr_msg = 0;
	struct caambuf sign_c_tmp = {};
	struct caambuf sign_d_tmp = {};
	struct caamsgtbuf sign_c_sgt = { .sgt_type = false };
	struct caamsgtbuf sign_d_sgt = { .sgt_type = false };
	paddr_t paddr_sign_c = 0;
	paddr_t paddr_sign_d = 0;
	uint32_t pdb_sgt_flags = 0;

#ifdef CFG_CAAM_64BIT
#define MAX_DESC_VERIFY 15
#else
#define MAX_DESC_VERIFY 10
#endif

	ECC_TRACE("ECC Verify");

	/* Verify first if the curve is supported */
	curve = get_caam_curve(inkey->curve);
	if (curve == CAAM_ECC_UNKNOWN)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Allocate the job descriptor */
	desc = caam_calloc_desc(MAX_DESC_VERIFY);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_verify;
	}

	/* Convert the Public key to local key */
	retstatus = do_keypub_conv(&ecckey, inkey, sdata->size_sec);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_verify;
	}

	/* Prepare the input message CAAM Descriptor entry */
	msg_tmp.data = sdata->message.data;
	msg_tmp.length = sdata->message.length;
	msg_tmp.paddr = virt_to_phys(sdata->message.data);
	if (!caam_mem_is_cached_buf(sdata->message.data, sdata->message.length))
		msg_tmp.nocache = 1;

	retstatus = caam_sgt_build_block_data(&msg_sgt, NULL, &msg_tmp);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_GENERIC;
		goto exit_verify;
	}

	if (msg_sgt.sgt_type) {
		pdb_sgt_flags |= PDB_SGT_PKVERIF_MSG;
		paddr_msg = virt_to_phys(msg_sgt.sgt);
		caam_sgt_cache_op(TEE_CACHECLEAN, &msg_sgt);
	} else {
		paddr_msg = msg_sgt.buf->paddr;
		if (!msg_sgt.buf->nocache)
			cache_operation(TEE_CACHECLEAN, msg_sgt.buf->data,
					msg_sgt.length);
	}

	/* Prepare the 1st Part of the signature */
	sign_c_tmp.data = sdata->signature.data;
	sign_c_tmp.length = sdata->size_sec;
	sign_c_tmp.paddr = virt_to_phys(sign_c_tmp.data);
	if (!caam_mem_is_cached_buf(sdata->signature.data,
				    sdata->signature.length))
		sign_c_tmp.nocache = 1;

	retstatus = caam_sgt_build_block_data(&sign_c_sgt, NULL, &sign_c_tmp);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_GENERIC;
		goto exit_verify;
	}

	if (sign_c_sgt.sgt_type) {
		pdb_sgt_flags |= PDB_SGT_PKVERIF_SIGN_C;
		paddr_sign_c = virt_to_phys(sign_c_sgt.sgt);
		caam_sgt_cache_op(TEE_CACHECLEAN, &sign_c_sgt);
	} else {
		paddr_sign_c = sign_c_sgt.buf->paddr;
		if (!sign_c_sgt.buf->nocache)
			cache_operation(TEE_CACHECLEAN, sign_c_sgt.buf->data,
					sign_c_sgt.length);
	}

	/* Prepare the 2nd Part of the signature */
	sign_d_tmp.data = sdata->signature.data + sdata->size_sec;
	sign_d_tmp.length = sdata->size_sec;
	sign_d_tmp.paddr = virt_to_phys(sign_d_tmp.data);
	sign_d_tmp.nocache = sign_c_tmp.nocache;

	retstatus = caam_sgt_build_block_data(&sign_d_sgt, NULL, &sign_d_tmp);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_GENERIC;
		goto exit_verify;
	}

	if (sign_d_sgt.sgt_type) {
		pdb_sgt_flags |= PDB_SGT_PKVERIF_SIGN_D;
		paddr_sign_d = virt_to_phys(sign_d_sgt.sgt);
		caam_sgt_cache_op(TEE_CACHECLEAN, &sign_d_sgt);
	} else {
		paddr_sign_d = sign_d_sgt.buf->paddr;
		if (!sign_d_sgt.buf->nocache)
			cache_operation(TEE_CACHECLEAN, sign_d_sgt.buf->data,
					sign_d_sgt.length);
	}

	/* Allocate a Temporary buffer used by the CAAM */
	retstatus = caam_alloc_align_buf(&tmp, 2 * sdata->size_sec);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_verify;
	}

	/*
	 * Build the descriptor using Predifined ECC curve
	 */
	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	caam_desc_add_word(desc, PDB_PKVERIFY_PD1 | PDB_ECC_ECDSEL(curve) |
					 pdb_sgt_flags);
	/* Public key */
	caam_desc_add_word(desc, ecckey.xy.paddr);
	/* Input message */
	caam_desc_add_word(desc, paddr_msg);
	/* Signature 1st part */
	caam_desc_add_word(desc, paddr_sign_c);
	/* Signature 2nd part */
	caam_desc_add_word(desc, paddr_sign_d);
	/* Temporary buffer */
	caam_desc_add_word(desc, tmp.paddr);
	/* Message length */
	caam_desc_add_word(desc, sdata->message.length);

	caam_desc_add_word(desc, DSA_VERIFY(ECC));
	desclen = caam_desc_get_len(desc);
	caam_desc_update_hdr(desc, DESC_HEADER_IDX(desclen, desclen - 1));

	ECC_DUMPDESC(desc);

	jobctx.desc = desc;

	cache_operation(TEE_CACHEFLUSH, tmp.data, tmp.length);
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_JOB_STATUS && !jobctx.status) {
		ECC_TRACE("ECC Verify Status 0x%08" PRIx32, jobctx.status);
		ret = TEE_ERROR_SIGNATURE_INVALID;
	} else if (retstatus != CAAM_NO_ERROR) {
		ECC_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	} else {
		ret = TEE_SUCCESS;
	}

exit_verify:
	caam_free_desc(&desc);
	do_keypair_free(&ecckey);
	caam_free_buf(&tmp);

	if (msg_sgt.sgt_type)
		caam_sgtbuf_free(&msg_sgt);

	if (sign_c_sgt.sgt_type)
		caam_sgtbuf_free(&sign_c_sgt);

	if (sign_d_sgt.sgt_type)
		caam_sgtbuf_free(&sign_d_sgt);

	return ret;
}

/*
 * Compute the shared secret data from ECC Private key and Public Key
 *
 * @sdata   [in/out] ECC Shared Secret data
 */
static TEE_Result do_shared_secret(struct drvcrypt_secret_data *sdata)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	enum caam_ecc_curve curve = CAAM_ECC_UNKNOWN;
	struct ecc_keypair *inprivkey = sdata->key_priv;
	struct ecc_public_key *inpubkey = sdata->key_pub;
	struct caam_ecc_keypair ecckey = {};
	struct caam_jobctx jobctx = {};
	uint32_t *desc = NULL;
	uint32_t desclen = 0;
	int realloc = 0;
	struct caambuf secret_tmp = {};
	struct caamsgtbuf secret_sgt = { .sgt_type = false };
	paddr_t paddr_secret = 0;
	uint32_t pdb_sgt_flags = 0;

#ifdef CFG_CAAM_64BIT
#define MAX_DESC_SHARED 10
#else
#define MAX_DESC_SHARED 7
#endif
	ECC_TRACE("ECC Shared Secret");

	/* Verify first if the curve is supported */
	curve = get_caam_curve(inpubkey->curve);
	if (curve == CAAM_ECC_UNKNOWN)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Allocate the job descriptor */
	desc = caam_calloc_desc(MAX_DESC_SHARED);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_shared;
	}

	/* Convert the Private key to local key */
	retstatus = do_keypair_conv(&ecckey, inprivkey, sdata->size_sec);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_shared;
	}

	/* Convert the Public key to local key */
	retstatus = do_keypub_conv(&ecckey, inpubkey, sdata->size_sec);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_shared;
	}

	/*
	 * ReAllocate the secret result buffer with a maximum size
	 * of the secret size if not cache aligned
	 */
	realloc = caam_set_or_alloc_align_buf(sdata->secret.data, &secret_tmp,
					      sdata->size_sec);
	if (realloc == -1) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_shared;
	}

	/* Prepare the Secret output */
	retstatus = caam_sgt_build_block_data(&secret_sgt, NULL, &secret_tmp);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_GENERIC;
		goto exit_shared;
	}

	if (secret_sgt.sgt_type) {
		pdb_sgt_flags |= PDB_SGT_PKDH_SECRET;
		paddr_secret = virt_to_phys(secret_sgt.sgt);
		caam_sgt_cache_op(TEE_CACHEFLUSH, &secret_sgt);
	} else {
		paddr_secret = secret_sgt.buf->paddr;
		if (!secret_sgt.buf->nocache)
			cache_operation(TEE_CACHEFLUSH, secret_sgt.buf->data,
					secret_sgt.length);
	}

	/*
	 * Build the descriptor using Predifined ECC curve
	 */
	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	caam_desc_add_word(desc, PDB_SHARED_SECRET_PD1 | PDB_ECC_ECDSEL(curve) |
					 pdb_sgt_flags);
	/* Public key */
	caam_desc_add_ptr(desc, ecckey.xy.paddr);
	/* Private key */
	caam_desc_add_ptr(desc, ecckey.d.paddr);
	/* Output secret */
	caam_desc_add_ptr(desc, paddr_secret);

	caam_desc_add_word(desc, SHARED_SECRET(ECC));
	desclen = caam_desc_get_len(desc);
	caam_desc_update_hdr(desc, DESC_HEADER_IDX(desclen, desclen - 1));

	ECC_DUMPDESC(desc);

	jobctx.desc = desc;

	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		if (!secret_tmp.nocache)
			cache_operation(TEE_CACHEINVALIDATE, secret_tmp.data,
					secret_tmp.length);
		if (realloc == 1)
			memcpy(sdata->secret.data, secret_tmp.data,
			       secret_tmp.length);

		sdata->secret.length = sdata->size_sec;

		ECC_DUMPBUF("Secret", sdata->secret.data, sdata->secret.length);

		ret = TEE_SUCCESS;
	} else {
		ECC_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

exit_shared:
	caam_free_desc(&desc);
	do_keypair_free(&ecckey);

	if (realloc == 1)
		caam_free_buf(&secret_tmp);

	if (secret_sgt.sgt_type)
		caam_sgtbuf_free(&secret_sgt);

	return ret;
}

/*
 * Registration of the ECC Driver
 */
static struct drvcrypt_ecc driver_ecc = {
	.alloc_keypair = &do_allocate_keypair,
	.alloc_publickey = &do_allocate_publickey,
	.free_publickey = &do_free_publickey,
	.gen_keypair = &do_gen_keypair,
	.sign = &do_sign,
	.verify = &do_verify,
	.shared_secret = &do_shared_secret,
};

enum caam_status caam_ecc_init(vaddr_t ctrl_addr)
{
	enum caam_status retstatus = CAAM_FAILURE;

	if (caam_hal_ctrl_pknum(ctrl_addr))
		if (drvcrypt_register_ecc(&driver_ecc) == TEE_SUCCESS)
			retstatus = CAAM_NO_ERROR;

	return retstatus;
}
