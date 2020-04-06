// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2020 NXP
 *
 * Brief   CAAM RSA manager.
 *         Implementation of RSA functions
 */
#include <caam_acipher.h>
#include <caam_common.h>
#include <caam_hal_ctrl.h>
#include <caam_io.h>
#include <caam_jr.h>
#include <caam_utils_mem.h>
#include <caam_utils_status.h>
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <drvcrypt_math.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>
#include <tee/tee_cryp_utl.h>

#include "local.h"

/*
 * Definition of the maximum bits of Exponent e
 * Refer to sp800-56b
 */
#define MAX_BITS_EXP_E  256

/*
 * Define the maximum number of entries in a descriptor
 * function of the encrypt/decrypt and private key format
 */
#ifdef CFG_CAAM_64BIT
#define MAX_DESC_ENC    (8 + 4)
#define MAX_DESC_DEC_1  (7 + 2 + 4)
#define MAX_DESC_DEC_2  (11 + 2 + 7)
#define MAX_DESC_DEC_3  (13 + 2 + 10)
/* Define the maximum number of entries in the RSA Finish Key descriptor */
#define MAX_DESC_KEY_FINISH  24
#else
#define MAX_DESC_ENC     8
#define MAX_DESC_DEC_1   (7 + 2)
#define MAX_DESC_DEC_2   (11 + 2)
#define MAX_DESC_DEC_3   (13 + 2)
/* Define the maximum number of entries in the RSA Finish Key descriptor */
#define MAX_DESC_KEY_FINISH  15
#endif /* CFG_CAAM_64BIT */

/*
 * Define the RSA Private Key Format used by the CAAM
 *   Format #1: (n, d)
 *   Format #2: (p, q, d)
 *   Format #3: (p, q, dp, dq, qp)
 */
#define RSA_PRIVATE_KEY_FORMAT 3

static TEE_Result do_caam_encrypt(struct drvcrypt_rsa_ed *rsa_data,
				  uint32_t operation);
static TEE_Result do_caam_decrypt(struct drvcrypt_rsa_ed *rsa_data,
				  uint32_t operation);

/*
 * Definition of the local RSA keypair
 *   Public Key Format: (n, e)
 *   Private Key Format #1: (n, d)
 *   Private Key Format #2: (p, q, d)
 *   Private Key Format #3: (p, q, dp, dq, qp)
 */
struct caam_rsa_keypair {
	uint8_t format; /* Define the Private Key Format (1, 2 or 3) */

	struct caambuf n; /* Modulus [n = p * q] */
	struct caambuf e; /* Public Exponent 65537 <= e < 2^256 */
	struct caambuf d; /* Private Exponent [d = 1/e mod LCM(p-1, q-1)] */
#if (RSA_PRIVATE_KEY_FORMAT > 1)
	struct caambuf p; /* Private Prime p */
	struct caambuf q; /* Private Prime q */
#if (RSA_PRIVATE_KEY_FORMAT > 2)
	struct caambuf dp; /* Private [dp = d mod (p-1)] */
	struct caambuf dq; /* Private [dq = d mod (q-1)] */
	struct caambuf qp; /* Private [qp = 1/q mod p] */
#endif /* RSA_PRIVATE_KEY_FORMAT > 1 */
#endif /* RSA_PRIVATE_KEY_FORMAT > 2 */
};

/* CAAM Era version */
static uint8_t caam_era;

/*
 * Free local RSA keypair
 *
 * @key  RSA keypair
 */
static void do_keypair_free(struct caam_rsa_keypair *key)
{
	caam_free_buf(&key->e);
	caam_free_buf(&key->n);
	caam_free_buf(&key->d);

#if (RSA_PRIVATE_KEY_FORMAT > 1)
	if (key->p.data) {
		key->p.length += key->q.length;
		caam_free_buf(&key->p);
	}
#if (RSA_PRIVATE_KEY_FORMAT > 2)
	if (key->dp.data) {
		key->dp.length += key->dq.length + key->qp.length;
		caam_free_buf(&key->dp);
	}
#endif /* RSA_PRIVATE_KEY_FORMAT > 1 */
#endif /* RSA_PRIVATE_KEY_FORMAT > 2 */
}

/*
 * Convert Crypto RSA Key to local RSA Public Key
 * Ensure Key is push in physical memory
 *
 * @outkey   [out] Output keypair in local format
 * @inkey    Input key in TEE Crypto format
 */
static enum caam_status do_keypub_conv(struct caam_rsa_keypair *outkey,
				       const struct rsa_public_key *inkey)
{
	enum caam_status retstatus = CAAM_FAILURE;

	RSA_TRACE("RSA Convert Public Key size N=%zu",
		  crypto_bignum_num_bytes(inkey->n));

	retstatus = caam_calloc_align_buf(&outkey->e,
					  crypto_bignum_num_bytes(inkey->e));
	if (retstatus != CAAM_NO_ERROR)
		goto exit_conv;

	crypto_bignum_bn2bin(inkey->e, outkey->e.data);
	cache_operation(TEE_CACHECLEAN, outkey->e.data, outkey->e.length);

	retstatus = caam_calloc_align_buf(&outkey->n,
					  crypto_bignum_num_bytes(inkey->n));
	if (retstatus != CAAM_NO_ERROR)
		goto exit_conv;

	crypto_bignum_bn2bin(inkey->n, outkey->n.data);
	cache_operation(TEE_CACHECLEAN, outkey->n.data, outkey->n.length);

	return CAAM_NO_ERROR;

exit_conv:
	do_keypair_free(outkey);

	return CAAM_OUT_MEMORY;
}

/*
 * Convert Crypto RSA Key to local RSA Keypair Key
 * Ensure Key is push in physical memory
 * Don't convert the exponent e not used in decrytion
 *
 * @outkey   [out] Output keypair in local format
 * @inkey    Input key in TEE Crypto format
 */
static enum caam_status do_keypair_conv(struct caam_rsa_keypair *outkey,
					const struct rsa_keypair *inkey)
{
	enum caam_status retstatus = CAAM_FAILURE;

#if (RSA_PRIVATE_KEY_FORMAT > 1)
	size_t size_p = 0;
	size_t size_q = 0;
#if (RSA_PRIVATE_KEY_FORMAT > 2)
	size_t size_dp = 0;
	size_t size_dq = 0;
	size_t size_qp = 0;
#endif /* RSA_PRIVATE_KEY_FORMAT > 1 */
#endif /* RSA_PRIVATE_KEY_FORMAT > 2 */

	RSA_TRACE("RSA Convert Keypair size N=%zu",
		  crypto_bignum_num_bytes(inkey->n));

	/* Mandatory fields are n and d => Private Key Format #1 */
	retstatus = caam_calloc_align_buf(&outkey->n,
					  crypto_bignum_num_bytes(inkey->n));
	if (retstatus != CAAM_NO_ERROR)
		goto exit_conv;

	crypto_bignum_bn2bin(inkey->n, outkey->n.data);
	cache_operation(TEE_CACHECLEAN, outkey->n.data, outkey->n.length);

	retstatus = caam_calloc_align_buf(&outkey->d,
					  crypto_bignum_num_bytes(inkey->d));
	if (retstatus != CAAM_NO_ERROR)
		goto exit_conv;

	crypto_bignum_bn2bin(inkey->d, outkey->d.data);
	cache_operation(TEE_CACHECLEAN, outkey->d.data, outkey->d.length);

	outkey->format = 1;

#if (RSA_PRIVATE_KEY_FORMAT > 1)
	/*
	 * Private Key Format #2
	 * Optional fields (p, q)
	 */
	size_p = crypto_bignum_num_bytes(inkey->p);
	size_q = crypto_bignum_num_bytes(inkey->q);

	if (size_p && size_q) {
		/* Allocate one buffer for both */
		retstatus = caam_calloc_align_buf(&outkey->p, size_p + size_q);
		if (retstatus != CAAM_NO_ERROR)
			goto exit_conv;

		/* Field Prime p */
		outkey->p.length = size_p;
		crypto_bignum_bn2bin(inkey->p, outkey->p.data);

		/* Field Prime q */
		outkey->q.data = outkey->p.data + size_p;
		outkey->q.length = size_q;
		outkey->q.paddr = outkey->p.paddr + size_p;

		crypto_bignum_bn2bin(inkey->q, outkey->q.data);

		/* Push fields value to the physical memory */
		cache_operation(TEE_CACHECLEAN, outkey->p.data,
				size_p + size_q);

		outkey->format = 2;
#if (RSA_PRIVATE_KEY_FORMAT > 2)
		/*
		 * Private Key Format #3
		 * Optional fields (dp, dq, qp) in plus of (p, q)
		 */
		size_dp = crypto_bignum_num_bytes(inkey->dp);
		size_dq = crypto_bignum_num_bytes(inkey->dq);
		size_qp = crypto_bignum_num_bytes(inkey->qp);

		/* Check that dp, dq and qp size not exceed p and q size */
		if (size_dp > size_p || size_dq > size_q || size_qp > size_p)
			goto exit_conv;

		if (size_dp && size_dq && size_qp) {
			/*
			 * CAAM is assuming that:
			 *    - dp and dq are same size as p
			 *    - dq same size as q
			 *
			 * Because calculation of dp, dq and qp can be less
			 * than above assumption, force the dp, dq and qp
			 * buffer size.
			 */
			/* Allocate one buffer for the 3 fields */
			retstatus = caam_calloc_align_buf(&outkey->dp,
							  size_p + size_q +
							  size_p);
			if (retstatus != CAAM_NO_ERROR)
				goto exit_conv;

			/* Field dp */
			outkey->dp.length = size_p;

			/*
			 * Ensure buffer is copied starting with 0's
			 * if size_dp != size_p
			 */
			crypto_bignum_bn2bin(inkey->dp,
					     outkey->dp.data + size_p -
					     size_dp);

			/* Field dq */
			outkey->dq.data = outkey->dp.data + size_p;
			outkey->dq.length = size_q;
			outkey->dq.paddr = outkey->dp.paddr + size_p;

			/*
			 * Ensure buffer is copied starting with 0's
			 * if size_dq != size_q
			 */
			crypto_bignum_bn2bin(inkey->dq,
					     outkey->dq.data + size_q -
					     size_dq);

			/* Field qp */
			outkey->qp.data = outkey->dq.data + size_q;
			outkey->qp.length = size_p;
			outkey->qp.paddr = outkey->dq.paddr + size_q;

			/*
			 * Ensure buffer is copied starting with 0's
			 * if size_qp != size_p
			 */
			crypto_bignum_bn2bin(inkey->qp,
					     outkey->qp.data + size_p -
					     size_qp);

			/* Push fields value to the physical memory */
			cache_operation(TEE_CACHECLEAN, outkey->dp.data,
					outkey->dp.length + outkey->dq.length +
						outkey->qp.length);

			outkey->format = 3;
		}
#endif /* RSA_PRIVATE_KEY_FORMAT > 2 */
	}
#endif /* RSA_PRIVATE_KEY_FORMAT > 1 */

	return CAAM_NO_ERROR;

exit_conv:
	do_keypair_free(outkey);

	return CAAM_OUT_MEMORY;
}

/*
 * Allocate a RSA keypair
 *
 * @key        Keypair
 * @size_bits  Key size in bits
 */
static TEE_Result do_allocate_keypair(struct rsa_keypair *key, size_t size_bits)
{
	RSA_TRACE("Allocate Keypair of %zu bits", size_bits);

	/* Initialize all input key fields to 0 */
	memset(key, 0, sizeof(*key));

	/* Allocate the Public Exponent to maximum size */
	key->e = crypto_bignum_allocate(MAX_BITS_EXP_E);
	if (!key->e)
		goto err_alloc_keypair;

	/* Allocate the Private Exponent [d = 1/e mod LCM(p-1, q-1)] */
	key->d = crypto_bignum_allocate(size_bits);
	if (!key->d)
		goto err_alloc_keypair;

	/* Allocate the Modulus (size_bits) [n = p * q] */
	key->n = crypto_bignum_allocate(size_bits);
	if (!key->n)
		goto err_alloc_keypair;

	/* Allocate the prime number p of size (size_bits / 2) */
	key->p = crypto_bignum_allocate(size_bits / 2);
	if (!key->p)
		goto err_alloc_keypair;

	/* Allocate the prime number q of size (size_bits / 2) */
	key->q = crypto_bignum_allocate(size_bits / 2);
	if (!key->q)
		goto err_alloc_keypair;

	/* Allocate dp (size_bits / 2) [d mod (p-1)] */
	key->dp = crypto_bignum_allocate(size_bits / 2);
	if (!key->dp)
		goto err_alloc_keypair;

	/* Allocate dq (size_bits / 2) [d mod (q-1)] */
	key->dq = crypto_bignum_allocate(size_bits / 2);
	if (!key->dq)
		goto err_alloc_keypair;

	/* Allocate qp (size_bits / 2) [1/q mod p] */
	key->qp = crypto_bignum_allocate(size_bits / 2);
	if (!key->qp)
		goto err_alloc_keypair;

	return TEE_SUCCESS;

err_alloc_keypair:
	RSA_TRACE("Allocation error");

	crypto_bignum_free(key->e);
	crypto_bignum_free(key->d);
	crypto_bignum_free(key->n);
	crypto_bignum_free(key->p);
	crypto_bignum_free(key->q);
	crypto_bignum_free(key->dp);
	crypto_bignum_free(key->dq);
	crypto_bignum_free(key->qp);

	return TEE_ERROR_OUT_OF_MEMORY;
}

/*
 * Allocate a RSA public key
 *
 * @key        Public Key
 * @size_bits  Key size in bits
 */
static TEE_Result do_allocate_publickey(struct rsa_public_key *key,
					size_t size_bits)
{
	RSA_TRACE("Allocate Public Key of %zu bits", size_bits);

	/* Initialize all input key fields to 0 */
	memset(key, 0, sizeof(*key));

	/* Allocate the Public Exponent to maximum size */
	key->e = crypto_bignum_allocate(MAX_BITS_EXP_E);
	if (!key->e)
		goto err_alloc_publickey;

	/* Allocate the Modulus (size_bits) [n = p * q] */
	key->n = crypto_bignum_allocate(size_bits);
	if (!key->n)
		goto err_alloc_publickey;

	return TEE_SUCCESS;

err_alloc_publickey:
	RSA_TRACE("Allocation error");

	crypto_bignum_free(key->e);
	crypto_bignum_free(key->n);

	return TEE_ERROR_OUT_OF_MEMORY;
}

/*
 * Free a RSA public key
 *
 * @key        Public Key
 */
static void do_free_publickey(struct rsa_public_key *key)
{
	crypto_bignum_free(key->e);
	crypto_bignum_free(key->n);
}

/*
 * Generates a RSA keypair
 *
 * @key        [out] Keypair
 * @key_size   Key size in bits
 */
static TEE_Result do_gen_keypair(struct rsa_keypair *key, size_t key_size)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct caambuf p = {};
	struct caambuf q = {};
	struct caambuf e = {};
	struct caambuf d_n = {};
#if (RSA_PRIVATE_KEY_FORMAT > 2)
	struct caambuf dp = {};
	struct caambuf dq = {};
	struct caambuf qp = {};
#endif /* RSA_PRIVATE_KEY_FORMAT > 2 */
	size_t size_d = 0;
	size_t size_n = 0;
	size_t size_d_gen = 0;
	struct caam_jobctx jobctx = {};
	uint32_t *desc = 0;
	uint32_t desclen = 0;
	struct prime_rsa prime = {};

	RSA_TRACE("Generate Keypair of %zu bits", key_size);

	/* Allocate the job used to prepare the operation */
	desc = caam_calloc_desc(MAX_DESC_KEY_FINISH);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_gen_keypair;
	}

	/* First allocate primes p and q in one buffer */
	retstatus = caam_calloc_align_buf(&p, key_size / 8);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_gen_keypair;
	}

	/* Prepare q */
	p.length /= 2;
	q.data = p.data + p.length;
	q.length = p.length;
	q.paddr = p.paddr + p.length;

	/* Allocate Public exponent to a caam buffer */
	retstatus = caam_calloc_buf(&e, crypto_bignum_num_bytes(key->e));
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_gen_keypair;
	}

	/*
	 * Allocate d and n in one buffer.
	 * Size of d is (key_size + 1) bits - Add a 32 bits word to
	 * retrieve the length of d generated by CAAM RSA Finalize Key
	 */
	size_d = sizeof(uint32_t) + key_size / 8 + 1;
	size_n = key_size / 8;

	retstatus = caam_calloc_align_buf(&d_n, size_d + size_n);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_gen_keypair;
	}

#if (RSA_PRIVATE_KEY_FORMAT > 2)
	/* Allocate dp, dq and qp in one buffer */
	retstatus = caam_calloc_align_buf(&dp, ((key_size / 8) / 2) * 3);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_gen_keypair;
	}

	dp.length /= 3;
	/* Prepare dq and qp */
	dq.data = dp.data + dp.length;
	dq.length = dp.length;
	dq.paddr = dp.paddr + dp.length;

	qp.data = dq.data + dq.length;
	qp.length = dq.length;
	qp.paddr = dq.paddr + dq.length;
#endif /* RSA_PRIVATE_KEY_FORMAT > 2 */

	crypto_bignum_bn2bin(key->e, e.data);

	prime.era = caam_era;
	prime.key_size = key_size;
	prime.e = &e;
	prime.p = &p;
	prime.q = &q;

	/* Generate prime p and q */
	retstatus = caam_prime_rsa_gen(&prime);
	RSA_TRACE("Generate Prime P and Q returned 0x%" PRIx32, retstatus);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_GENERIC;
		goto exit_gen_keypair;
	}

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));

	caam_desc_add_word(desc, 0);
	caam_desc_add_word(desc, PDB_RSA_KEY_P_SIZE(p.length));
	caam_desc_add_word(desc, PDB_RSA_KEY_N_SIZE(size_n) |
					 PDB_RSA_KEY_E_SIZE(e.length));

	caam_desc_add_ptr(desc, p.paddr);
	caam_desc_add_ptr(desc, q.paddr);
	caam_desc_add_ptr(desc, e.paddr);
	caam_desc_add_ptr(desc, d_n.paddr + size_d);
	caam_desc_add_ptr(desc, d_n.paddr + sizeof(uint32_t));
	caam_desc_add_ptr(desc, d_n.paddr);
#if (RSA_PRIVATE_KEY_FORMAT > 2)
	caam_desc_add_ptr(desc, dp.paddr);
	caam_desc_add_ptr(desc, dq.paddr);
	caam_desc_add_ptr(desc, qp.paddr);
	caam_desc_add_word(desc, RSA_FINAL_KEY(ALL));
#else
	caam_desc_add_word(desc, RSA_FINAL_KEY(N_D));
#endif /* RSA_PRIVATE_KEY_FORMAT > 2 */
	desclen = caam_desc_get_len(desc);
	caam_desc_update_hdr(desc, DESC_HEADER_IDX(desclen, desclen - 1));

	jobctx.desc = desc;
	RSA_DUMPDESC(desc);

	cache_operation(TEE_CACHECLEAN, e.data, e.length);
	cache_operation(TEE_CACHEFLUSH, p.data, p.length + q.length);
	cache_operation(TEE_CACHEFLUSH, d_n.data, size_d + size_n);
#if (RSA_PRIVATE_KEY_FORMAT > 2)
	cache_operation(TEE_CACHEFLUSH, dp.data,
			dp.length + dq.length + qp.length);
#endif /* RSA_PRIVATE_KEY_FORMAT > 2 */

	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		cache_operation(TEE_CACHEINVALIDATE, d_n.data, size_d + size_n);

		size_d_gen = d_n.data[0] + (d_n.data[1] << 8);

		RSA_TRACE("D size %zu", size_d_gen);
		RSA_DUMPBUF("N", d_n.data + size_d, size_n);
		RSA_DUMPBUF("D", d_n.data + sizeof(uint32_t), size_d_gen);

		ret = crypto_bignum_bin2bn(d_n.data + size_d, size_n, key->n);
		if (ret != TEE_SUCCESS)
			goto exit_gen_keypair;

		ret = crypto_bignum_bin2bn(d_n.data + sizeof(uint32_t),
					   size_d_gen, key->d);
		if (ret != TEE_SUCCESS)
			goto exit_gen_keypair;

#if (RSA_PRIVATE_KEY_FORMAT > 1)
		cache_operation(TEE_CACHEINVALIDATE, p.data,
				p.length + q.length);

		ret = crypto_bignum_bin2bn(p.data, p.length, key->p);
		if (ret != TEE_SUCCESS)
			goto exit_gen_keypair;

		ret = crypto_bignum_bin2bn(q.data, q.length, key->q);
		if (ret != TEE_SUCCESS)
			goto exit_gen_keypair;

#if (RSA_PRIVATE_KEY_FORMAT > 2)
		cache_operation(TEE_CACHEINVALIDATE, dp.data,
				dp.length + dq.length + qp.length);

		RSA_DUMPBUF("dp", dp.data, dp.length);
		RSA_DUMPBUF("dq", dq.data, dq.length);
		RSA_DUMPBUF("qp", qp.data, qp.length);

		ret = crypto_bignum_bin2bn(dp.data, dp.length, key->dp);
		if (ret != TEE_SUCCESS)
			goto exit_gen_keypair;

		ret = crypto_bignum_bin2bn(dq.data, dq.length, key->dq);
		if (ret != TEE_SUCCESS)
			goto exit_gen_keypair;

		ret = crypto_bignum_bin2bn(qp.data, qp.length, key->qp);
		if (ret != TEE_SUCCESS)
			goto exit_gen_keypair;

#endif /* RSA_PRIVATE_KEY_FORMAT > 2 */
#endif /* RSA_PRIVATE_KEY_FORMAT > 1 */
		ret = TEE_SUCCESS;
	} else {
		RSA_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

exit_gen_keypair:
	p.length += q.length;
	caam_free_buf(&p);
	caam_free_buf(&e);
	caam_free_buf(&d_n);
#if (RSA_PRIVATE_KEY_FORMAT > 2)
	dp.length += dq.length + qp.length;
	caam_free_buf(&dp);
#endif /* RSA_PRIVATE_KEY_FORMAT > 2 */
	caam_free_desc(&desc);

	return ret;
}

/*
 * RSA EME-OAEP Decoding operation
 * Refer the chapter 7.1.2 Decryption operation of pkcs-1v2-1 specification
 *
 * @rsa_data  [in/out] RSA Data to encode
 */
static TEE_Result do_oaep_decoding(struct drvcrypt_rsa_ed *rsa_data)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct caambuf DB = {};
	struct caambuf lHash = {};
	struct caambuf seed = {};
	struct caambuf dbMask = {};
	struct caambuf maskedDB = {};
	struct caambuf maskedSeed = {};
	struct caambuf EM = {};
	size_t db_size = 0;
	size_t b01_idx = 0;
	struct drvcrypt_rsa_mgf mgf_data = {};
	struct drvcrypt_rsa_ed dec_data = {};
	struct drvcrypt_mod_op mod_op = {};

	RSA_TRACE("RSA OAEP Decoding");

	/*
	 * First Decryption of the Cipher to a EM of modulus size
	 */
	retstatus = caam_calloc_align_buf(&EM, rsa_data->key.n_size);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_oaep_decrypt;
	}

	memcpy(&dec_data, rsa_data, sizeof(dec_data));
	dec_data.message.data = EM.data;
	dec_data.message.length = EM.length;

	ret = do_caam_decrypt(&dec_data, RSA_DECRYPT(NO));

	RSA_DUMPBUF("EM", EM.data, EM.length);

	/*
	 * DB = lHash' || PS || 0x01 || M
	 * DB length = k - hLen - 1
	 *
	 * PS is a 0's buffer of length h - mLen - 2hLen - 2
	 *
	 *  k    is the key modulus length
	 *  hLen is the Hash digest length
	 *  mLen is the input RSA message length
	 */
	/* Calculate the DB size */
	db_size = rsa_data->key.n_size - rsa_data->digest_size - 1;
	RSA_TRACE("DB is %zu bytes", db_size);

	/* Allocate the DB buffer */
	retstatus = caam_calloc_align_buf(&DB, db_size);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_oaep_decrypt;
	}

	/*
	 * Step a
	 * Generate the lHash
	 */
	/* Allocate the lHash buffer */
	retstatus = caam_calloc_align_buf(&lHash, rsa_data->digest_size);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_oaep_decrypt;
	}

	RSA_TRACE("Hash the RSA Label of %zu bytes", rsa_data->label.length);
	ret = tee_hash_createdigest(rsa_data->hash_algo, rsa_data->label.data,
				    rsa_data->label.length, lHash.data,
				    lHash.length);
	RSA_TRACE("Hash the RSA Label returned 0x%08" PRIx32, ret);
	if (ret != TEE_SUCCESS)
		goto exit_oaep_decrypt;

	RSA_DUMPBUF("lHash", lHash.data, lHash.length);

	/* Allocate the seed buffer */
	retstatus = caam_calloc_align_buf(&seed, rsa_data->digest_size);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_oaep_decrypt;
	}

	/* Allocate the dbMask buffer */
	retstatus = caam_calloc_align_buf(&dbMask, db_size);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_oaep_decrypt;
	}

	/*
	 * Step b
	 * Split the EM string
	 * EM = Y || maskedSeed || maskedDB
	 *
	 * Where:
	 *   Y          size = 1 byte
	 *   maskedSeed size = hLen
	 *   maskedDB   size = k - hLen - 1 bytes
	 *
	 *  k    is the key modulus length
	 *  hLen is the Hash digest length
	 *  mLen is the input RSA message length
	 *
	 *  Note Y should have been remove during the
	 */
	maskedSeed.data = &EM.data[1];
	maskedSeed.length = rsa_data->digest_size;
	maskedSeed.paddr = EM.paddr + sizeof(uint8_t);

	maskedDB.data = &EM.data[1 + rsa_data->digest_size];
	maskedDB.length = dbMask.length;
	maskedDB.paddr = EM.paddr + sizeof(uint8_t) + rsa_data->digest_size;

	/*
	 * Step c
	 * Generate a Mask of the maskedDB
	 * seedMask = MGF(maskedDB, k - hLen - 1)
	 *
	 * Note: Use same buffer for seed and seedMask
	 */
	mgf_data.hash_algo = rsa_data->hash_algo;
	mgf_data.digest_size = rsa_data->digest_size;
	mgf_data.seed.data = maskedDB.data;
	mgf_data.seed.length = maskedDB.length;
	mgf_data.mask.data = seed.data;
	mgf_data.mask.length = seed.length;

	ret = rsa_data->mgf(&mgf_data);
	if (ret != TEE_SUCCESS)
		goto exit_oaep_decrypt;

	/*
	 * Step d
	 * seed = maskedSeed xor seedMask
	 *
	 * Note: Use same buffer for seed and seedMask
	 */
	mod_op.n.length = seed.length;
	mod_op.a.data = maskedSeed.data;
	mod_op.a.length = maskedSeed.length;
	mod_op.b.data = seed.data;
	mod_op.b.length = seed.length;
	mod_op.result.data = seed.data;
	mod_op.result.length = seed.length;

	retstatus = drvcrypt_xor_mod_n(&mod_op);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_GENERIC;
		goto exit_oaep_decrypt;
	}

	RSA_DUMPBUF("Seed", seed.data, seed.length);

	/*
	 * Step e
	 * Generate a Mask of the seed value
	 * dbMask = MGF(seed, k - hLen - 1)
	 */
	mgf_data.seed.data = seed.data;
	mgf_data.seed.length = seed.length;
	mgf_data.mask.data = dbMask.data;
	mgf_data.mask.length = dbMask.length;

	ret = rsa_data->mgf(&mgf_data);
	if (ret != TEE_SUCCESS)
		goto exit_oaep_decrypt;

	/*
	 * Step f
	 * DB = maskedDB xor dbMask
	 */
	mod_op.n.length = DB.length;
	mod_op.a.data = maskedDB.data;
	mod_op.a.length = maskedDB.length;
	mod_op.b.data = dbMask.data;
	mod_op.b.length = dbMask.length;
	mod_op.result.data = DB.data;
	mod_op.result.length = DB.length;

	retstatus = drvcrypt_xor_mod_n(&mod_op);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_GENERIC;
		goto exit_oaep_decrypt;
	}

	RSA_DUMPBUF("DB", DB.data, DB.length);

	/*
	 * Step g
	 * Check the DB generated
	 * DB = lHash' || PS || 0x01 || M
	 *
	 * Error if:
	 *   - lHash' != lHash (First step - Hash the Label)
	 *   - byte 0x01 between PS and M is not present
	 */
	/* Check Hash values */
	if (memcmp(DB.data, lHash.data, lHash.length)) {
		RSA_TRACE("Hash error");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto exit_oaep_decrypt;
	}

	/* Find the byte 0x01 separating PS and M */
	for (b01_idx = rsa_data->digest_size;
	     b01_idx < db_size && !DB.data[b01_idx]; b01_idx++)
		;

	if (b01_idx == db_size) {
		RSA_TRACE("byte 0x01 not present");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto exit_oaep_decrypt;
	}

	rsa_data->message.length = DB.length - b01_idx - 1;
	memcpy(rsa_data->message.data, &DB.data[b01_idx + 1],
	       rsa_data->message.length);

	RSA_DUMPBUF("Message decrypted", rsa_data->message.data,
		    rsa_data->message.length);
	ret = TEE_SUCCESS;

exit_oaep_decrypt:
	caam_free_buf(&EM);
	caam_free_buf(&DB);
	caam_free_buf(&seed);
	caam_free_buf(&dbMask);
	caam_free_buf(&lHash);

	return ret;
}

/*
 * RSA EME-OAEP Encoding operation
 * Refer the chapter 7.1.1 Encryption operation of pkcs-1v2-1 specification
 *
 * @rsa_data  [int/out] RSA Data to encode
 */
static TEE_Result do_oaep_encoding(struct drvcrypt_rsa_ed *rsa_data)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus;
	struct caambuf DB = {};
	struct caambuf lHash = {};
	struct caambuf seed = {};
	struct caambuf dbMask = {};
	struct caambuf maskedDB = {};
	struct caambuf maskedSeed = {};
	struct caambuf EM = {};
	size_t db_size = 0;
	size_t ps_size = 0;
	struct drvcrypt_rsa_mgf mgf_data = {};
	struct drvcrypt_rsa_ed enc_data = {};
	struct drvcrypt_mod_op mod_op = {};

	RSA_TRACE("RSA OAEP Encoding");

	/*
	 * DB = lHash || PS || 0x01 || M
	 * DB length = k - hLen - 1
	 *
	 * PS is a 0's buffer of length h - mLen - 2hLen - 2
	 *
	 *  k    is the key modulus length
	 *  hLen is the Hash digest length
	 *  mLen is the input RSA message length
	 */
	/* Calculate the DB size */
	db_size = rsa_data->key.n_size - rsa_data->digest_size - 1;
	RSA_TRACE("DB is %zu bytes", db_size);

	/* Allocate the DB buffer */
	retstatus = caam_calloc_align_buf(&DB, db_size);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_oaep_encrypt;
	}

	/*
	 * Step a
	 * Generate the lHash
	 */
	lHash.length = rsa_data->digest_size;
	lHash.data = DB.data;

	RSA_TRACE("Hash the RSA Label of %zu bytes", rsa_data->label.length);
	ret = tee_hash_createdigest(rsa_data->hash_algo, rsa_data->label.data,
				    rsa_data->label.length, lHash.data,
				    lHash.length);
	RSA_TRACE("Hash the RSA Label returned 0x%08" PRIx32, ret);
	if (ret != TEE_SUCCESS)
		goto exit_oaep_encrypt;
	RSA_DUMPBUF("lHash", lHash.data, lHash.length);

	/*
	 * Step b
	 * Add PS 0's
	 * Note: DB is already filled with 0's at the allocation
	 */
	ps_size = rsa_data->key.n_size - rsa_data->message.length -
		  2 * rsa_data->digest_size - 2;
	RSA_TRACE("PS is %zu bytes", ps_size);

	/*
	 * Step c
	 * Set the value 0x01 after the lHash and the PS
	 * Concatenate result with input message
	 */
	DB.data[lHash.length + ps_size] = 0x01;
	memcpy(&DB.data[lHash.length + ps_size + 1], rsa_data->message.data,
	       rsa_data->message.length);

	RSA_DUMPBUF("DB", DB.data, DB.length);

	/*
	 * Step d
	 * Generate a random seed of hLen
	 */
	/* Allocate the seed buffer */
	retstatus = caam_calloc_align_buf(&seed, rsa_data->digest_size);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_oaep_encrypt;
	}

	/* Allocate the dbMask buffer */
	retstatus = caam_calloc_align_buf(&dbMask, db_size);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_oaep_encrypt;
	}

	ret = crypto_rng_read(seed.data, seed.length);
	RSA_TRACE("Get seed of %zu bytes (ret = 0x%08" PRIx32 ")", seed.length,
		  ret);
	if (ret != TEE_SUCCESS)
		goto exit_oaep_encrypt;

	RSA_DUMPBUF("Seed", seed.data, seed.length);

	/*
	 * Step e
	 * Generate a Mask of the seed value
	 * dbMask = MGF(seed, k - hLen - 1)
	 */
	mgf_data.hash_algo = rsa_data->hash_algo;
	mgf_data.digest_size = rsa_data->digest_size;
	mgf_data.seed.data = seed.data;
	mgf_data.seed.length = seed.length;
	mgf_data.mask.data = dbMask.data;
	mgf_data.mask.length = dbMask.length;

	ret = rsa_data->mgf(&mgf_data);
	if (ret != TEE_SUCCESS)
		goto exit_oaep_encrypt;

	/*
	 * Step f
	 * maskedDB = DB xor dbMask
	 */
	retstatus = caam_calloc_align_buf(&EM, rsa_data->key.n_size);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_oaep_encrypt;
	}

	maskedDB.data = &EM.data[1 + rsa_data->digest_size];
	maskedDB.length = dbMask.length;
	maskedDB.paddr = EM.paddr + sizeof(uint8_t) + rsa_data->digest_size;

	mod_op.n.length = maskedDB.length;
	mod_op.a.data = DB.data;
	mod_op.a.length = DB.length;
	mod_op.b.data = dbMask.data;
	mod_op.b.length = dbMask.length;
	mod_op.result.data = maskedDB.data;
	mod_op.result.length = maskedDB.length;

	ret = drvcrypt_xor_mod_n(&mod_op);
	if (ret != TEE_SUCCESS) {
		ret = TEE_ERROR_GENERIC;
		goto exit_oaep_encrypt;
	}

	/*
	 * Step g
	 * Generate a Mask of the maskedDB
	 * seedMask = MGF(maskedDB, hLen)
	 *
	 * Note: Use same buffer for seedMask and maskedSeed
	 */
	maskedSeed.data = &EM.data[1];
	maskedSeed.length = rsa_data->digest_size;
	maskedSeed.paddr = EM.paddr + sizeof(uint8_t);

	mgf_data.seed.data = maskedDB.data;
	mgf_data.seed.length = maskedDB.length;
	mgf_data.mask.data = maskedSeed.data;
	mgf_data.mask.length = maskedSeed.length;
	ret = rsa_data->mgf(&mgf_data);
	if (ret != TEE_SUCCESS)
		goto exit_oaep_encrypt;

	/*
	 * Step h
	 * maskedSeed = seed xor seedMask
	 */
	mod_op.n.length = maskedSeed.length;
	mod_op.a.data = seed.data;
	mod_op.a.length = seed.length;
	mod_op.b.data = maskedSeed.data;
	mod_op.b.length = maskedSeed.length;
	mod_op.result.data = maskedSeed.data;
	mod_op.result.length = maskedSeed.length;

	ret = drvcrypt_xor_mod_n(&mod_op);
	if (ret != TEE_SUCCESS)
		goto exit_oaep_encrypt;

	RSA_DUMPBUF("EM", EM.data, EM.length);

	/*
	 * Last Encryption of the EM of modulus size to Cipher
	 */
	memcpy(&enc_data, rsa_data, sizeof(enc_data));

	enc_data.message.data = EM.data;
	enc_data.message.length = EM.length;

	ret = do_caam_encrypt(&enc_data, RSA_ENCRYPT(NO));

exit_oaep_encrypt:
	caam_free_buf(&DB);
	caam_free_buf(&seed);
	caam_free_buf(&dbMask);
	caam_free_buf(&EM);

	return ret;
}

/*
 * CAAM RSA Encryption of the input message to a cipher
 *
 * @rsa_data   [in/out] RSA Data to encrypt
 * @operation  CAAM RSA Decryption operation
 */
static TEE_Result do_caam_encrypt(struct drvcrypt_rsa_ed *rsa_data,
				  uint32_t operation)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_rsa_keypair key = {};
	struct caamdmaobj msg = {};
	struct caamdmaobj cipher = {};
	struct caam_jobctx jobctx = {};
	uint32_t *desc = NULL;
	uint32_t desclen = 0;
	uint32_t pdb_sgt_flags = 0;

	RSA_TRACE("RSA Encrypt mode %d", rsa_data->rsa_id);

	/* Allocate the job descriptor */
	desc = caam_calloc_desc(MAX_DESC_ENC);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_encrypt;
	}

	/*
	 * Convert TEE rsa key type to CAAM rsa key type
	 * Push key value to memory
	 */
	retstatus = do_keypub_conv(&key, rsa_data->key.key);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_GENERIC;
		goto exit_encrypt;
	}

	/*
	 * ReAllocate the cipher result buffer with a maximum size
	 * of the Key Modulus's size (N) if not cache aligned
	 */
	ret = caam_dmaobj_init_output(&cipher, rsa_data->cipher.data,
				      rsa_data->cipher.length, key.n.length);
	if (ret)
		goto exit_encrypt;

	if (cipher.sgtbuf.sgt_type)
		pdb_sgt_flags |= PDB_RSA_ENC_SGT_G;

	caam_dmaobj_cache_push(&cipher);

	/* Prepare the input message CAAM descriptor entry */
	ret = caam_dmaobj_init_input(&msg, rsa_data->message.data,
				     rsa_data->message.length);
	if (ret)
		goto exit_encrypt;

	if (msg.sgtbuf.sgt_type)
		pdb_sgt_flags |= PDB_RSA_ENC_SGT_F;

	caam_dmaobj_cache_push(&msg);

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	caam_desc_add_word(desc, PDB_RSA_ENC_E_SIZE(key.e.length) |
					 PDB_RSA_ENC_N_SIZE(key.n.length) |
					 pdb_sgt_flags);
	caam_desc_add_ptr(desc, msg.sgtbuf.paddr);
	caam_desc_add_ptr(desc, cipher.sgtbuf.paddr);
	caam_desc_add_ptr(desc, key.n.paddr);
	caam_desc_add_ptr(desc, key.e.paddr);
	caam_desc_add_word(desc, PDB_RSA_ENC_F_SIZE(rsa_data->message.length));
	caam_desc_add_word(desc, operation);

	/* Set the descriptor Header with length */
	desclen = caam_desc_get_len(desc);
	caam_desc_update_hdr(desc, DESC_HEADER_IDX(desclen, desclen - 1));
	RSA_DUMPDESC(desc);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		caam_dmaobj_copy_to_orig(&cipher);
		rsa_data->cipher.length = key.n.length;

		RSA_DUMPBUF("Output", rsa_data->cipher.data,
			    rsa_data->cipher.length);
		ret = TEE_SUCCESS;
	} else {
		RSA_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

exit_encrypt:
	caam_free_desc(&desc);
	do_keypair_free(&key);
	caam_dmaobj_free(&msg);
	caam_dmaobj_free(&cipher);

	return ret;
}

/*
 * CAAM RSA Decryption of the input cipher to a message
 *
 * @rsa_data   [in/out] RSA Data to decrypt
 * @operation  CAAM RSA Decryption operation
 */
static TEE_Result do_caam_decrypt(struct drvcrypt_rsa_ed *rsa_data,
				  uint32_t operation)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_rsa_keypair key = {};
	struct caamdmaobj cipher = {};
	struct caamdmaobj msg = {};
	struct caam_jobctx jobctx = {};
	uint32_t *desc = NULL;
	uint32_t desclen = 0;
	uint32_t pdb_sgt_flags = 0;
	struct caambuf size_msg = {};
#if RSA_PRIVATE_KEY_FORMAT > 1
	struct caambuf tmp = {};
#endif /* RSA_PRIVATE_KEY_FORMAT */

	RSA_TRACE("RSA Decrypt mode %d", rsa_data->rsa_id);

	/*
	 * Convert TEE rsa key type to CAAM rsa key type
	 * Push key value to memory
	 */
	retstatus = do_keypair_conv(&key, rsa_data->key.key);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_GENERIC;
		goto exit_decrypt;
	}

	/*
	 * Allocate the temporary result buffer with a maximum size
	 * of the Key Modulus's size (N)
	 */
	ret = caam_dmaobj_init_output(&msg, rsa_data->message.data,
				      rsa_data->message.length, key.n.length);
	if (ret)
		goto exit_decrypt;

	if (msg.sgtbuf.sgt_type)
		pdb_sgt_flags |= PDB_RSA_DEC_SGT_F;

	caam_dmaobj_cache_push(&msg);

	/* Allocate the returned computed size when PKCS V1.5 */
	if (operation == RSA_DECRYPT(PKCS_V1_5)) {
		retstatus = caam_alloc_align_buf(&size_msg, 4);
		if (retstatus != CAAM_NO_ERROR)
			goto exit_decrypt;

		cache_operation(TEE_CACHEFLUSH, size_msg.data, size_msg.length);
	}

	/* Prepare the input cipher CAAM descriptor entry */
	ret = caam_dmaobj_init_input(&cipher, rsa_data->cipher.data,
				     rsa_data->cipher.length);

	if (cipher.sgtbuf.sgt_type)
		pdb_sgt_flags |= PDB_RSA_DEC_SGT_G;

	caam_dmaobj_cache_push(&cipher);

	/* Allocate the job descriptor function of the Private key format */
	switch (key.format) {
	case 1:
		desc = caam_calloc_desc(MAX_DESC_DEC_1);
		if (!desc) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_decrypt;
		}
		break;

#if (RSA_PRIVATE_KEY_FORMAT > 1)
	case 2:
	case 3:
		if (key.format == 2)
			desc = caam_calloc_desc(MAX_DESC_DEC_2);
		else
			desc = caam_calloc_desc(MAX_DESC_DEC_3);

		if (!desc) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_decrypt;
		}
		/* Allocate temporary buffers used by the CAAM */
		retstatus =
			caam_alloc_align_buf(&tmp, key.p.length + key.q.length);
		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_decrypt;
		}

		cache_operation(TEE_CACHEFLUSH, tmp.data, tmp.length);
		break;
#endif /* RSA_PRIVATE_KEY_FORMAT > 1 */

	default:
		ret = TEE_ERROR_GENERIC;
		goto exit_decrypt;
	}

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));

	/* Build the descriptor function of the Private Key format */
	switch (key.format) {
	case 1:
		caam_desc_add_word(desc,
				   PDB_RSA_DEC_D_SIZE(key.d.length) |
					   PDB_RSA_DEC_N_SIZE(key.n.length) |
					   pdb_sgt_flags);
		caam_desc_add_ptr(desc, cipher.sgtbuf.paddr);
		caam_desc_add_ptr(desc, msg.sgtbuf.paddr);
		caam_desc_add_ptr(desc, key.n.paddr);
		caam_desc_add_ptr(desc, key.d.paddr);

		break;
#if (RSA_PRIVATE_KEY_FORMAT > 1)
	case 2:
		caam_desc_add_word(desc,
				   PDB_RSA_DEC_D_SIZE(key.d.length) |
					   PDB_RSA_DEC_N_SIZE(key.n.length) |
					   pdb_sgt_flags);
		caam_desc_add_ptr(desc, cipher.sgtbuf.paddr);
		caam_desc_add_ptr(desc, msg.sgtbuf.paddr);
		caam_desc_add_ptr(desc, key.d.paddr);
		caam_desc_add_ptr(desc, key.p.paddr);
		caam_desc_add_ptr(desc, key.q.paddr);
		caam_desc_add_ptr(desc, tmp.paddr);
		caam_desc_add_ptr(desc, tmp.paddr + key.p.length);
		caam_desc_add_word(desc,
				   PDB_RSA_DEC_Q_SIZE(key.q.length) |
					   PDB_RSA_DEC_P_SIZE(key.p.length));
		break;
#endif /* RSA_PRIVATE_KEY_FORMAT > 1 */

#if (RSA_PRIVATE_KEY_FORMAT > 2)
	case 3:
		caam_desc_add_word(desc, PDB_RSA_DEC_N_SIZE(key.n.length) |
						 pdb_sgt_flags);
		caam_desc_add_ptr(desc, cipher.sgtbuf.paddr);
		caam_desc_add_ptr(desc, msg.sgtbuf.paddr);
		caam_desc_add_ptr(desc, key.qp.paddr);
		caam_desc_add_ptr(desc, key.p.paddr);
		caam_desc_add_ptr(desc, key.q.paddr);
		caam_desc_add_ptr(desc, key.dp.paddr);
		caam_desc_add_ptr(desc, key.dq.paddr);
		caam_desc_add_ptr(desc, tmp.paddr);
		caam_desc_add_ptr(desc, tmp.paddr + key.p.length);
		caam_desc_add_word(desc,
				   PDB_RSA_DEC_Q_SIZE(key.q.length) |
					   PDB_RSA_DEC_P_SIZE(key.p.length));
		break;
#endif /* RSA_PRIVATE_KEY_FORMAT > 2 */

	default:
		ret = TEE_ERROR_GENERIC;
		goto exit_decrypt;
	}

	/* Set the Decryption operation type */
	caam_desc_add_word(desc, operation | PROT_RSA_DEC_KEYFORM(key.format));

	if (operation == RSA_DECRYPT(PKCS_V1_5)) {
		/* Get the PPKCS1 v1.5 Message length generated */
		caam_desc_add_word(desc,
				   ST_NOIMM_OFF(CLASS_DECO, REG_MATH0, 4, 4));
		caam_desc_add_ptr(desc, size_msg.paddr);
		/* Set the descriptor Header with length */
		desclen = caam_desc_get_len(desc);
#ifdef CFG_CAAM_64BIT
		caam_desc_update_hdr(desc,
				     DESC_HEADER_IDX(desclen, desclen - 1 - 3));
#else
		caam_desc_update_hdr(desc,
				     DESC_HEADER_IDX(desclen, desclen - 1 - 2));
#endif /* CFG_CAAM_64BIT */
	} else {
		desclen = caam_desc_get_len(desc);
		/* Set the descriptor Header with length */
		caam_desc_update_hdr(desc,
				     DESC_HEADER_IDX(desclen, desclen - 1));
	}

	RSA_DUMPDESC(desc);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		caam_dmaobj_copy_to_orig(&msg);

		if (operation == RSA_DECRYPT(NO) &&
		    rsa_data->rsa_id == RSA_NOPAD) {
			caam_dmaobj_copy_ltrim_to_orig(&msg);
		} else if (operation == RSA_DECRYPT(PKCS_V1_5)) {
			/* PKCS 1 v1.5 */
			cache_operation(TEE_CACHEINVALIDATE, size_msg.data,
					size_msg.length);

			msg.orig.length = caam_read_val32(size_msg.data);
			caam_dmaobj_copy_to_orig(&msg);
		} else {
			caam_dmaobj_copy_to_orig(&msg);
		}

		rsa_data->message.length = msg.orig.length;

		RSA_DUMPBUF("Output", rsa_data->message.data,
			    rsa_data->message.length);
		ret = TEE_SUCCESS;
	} else {
		RSA_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

exit_decrypt:
	caam_free_desc(&desc);
	do_keypair_free(&key);
	caam_free_buf(&size_msg);
	caam_dmaobj_free(&msg);
	caam_dmaobj_free(&cipher);

#if RSA_PRIVATE_KEY_FORMAT > 1
	caam_free_buf(&tmp);
#endif /* RSA_PRIVATE_KEY_FORMAT > 1 */

	return ret;
}

/*
 * RSA Encryption
 *
 * @rsa_data   [in/out] RSA Data to encrypt / Cipher resulting
 */
static TEE_Result do_encrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	switch (rsa_data->rsa_id) {
	case RSA_NOPAD:
	case RSASSA_PKCS_V1_5:
	case RSASSA_PSS:
		ret = do_caam_encrypt(rsa_data, RSA_ENCRYPT(NO));
		break;

	case RSA_PKCS_V1_5:
		ret = do_caam_encrypt(rsa_data, RSA_ENCRYPT(PKCS_V1_5));
		break;

	case RSA_OAEP:
		ret = do_oaep_encoding(rsa_data);
		break;

	default:
		break;
	}

	return ret;
}

/*
 * RSA Decryption
 *
 * @rsa_data   [in/out] RSA Data to decrypt / Message resulting
 */
static TEE_Result do_decrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	switch (rsa_data->rsa_id) {
	case RSA_NOPAD:
	case RSASSA_PKCS_V1_5:
	case RSASSA_PSS:
		ret = do_caam_decrypt(rsa_data, RSA_DECRYPT(NO));
		break;

	case RSA_PKCS_V1_5:
		ret = do_caam_decrypt(rsa_data, RSA_DECRYPT(PKCS_V1_5));
		break;

	case RSA_OAEP:
		ret = do_oaep_decoding(rsa_data);
		break;

	default:
		break;
	}

	return ret;
}

/*
 * Registration of the RSA Driver
 */
static struct drvcrypt_rsa driver_rsa = {
	.alloc_keypair = &do_allocate_keypair,
	.alloc_publickey = &do_allocate_publickey,
	.free_publickey = &do_free_publickey,
	.gen_keypair = &do_gen_keypair,
	.encrypt = &do_encrypt,
	.decrypt = &do_decrypt,
	.ssa_sign = NULL,
	.ssa_verify = NULL,
};

enum caam_status caam_rsa_init(struct caam_jrcfg *caam_jrcfg)
{
	enum caam_status retstatus = CAAM_FAILURE;
	vaddr_t jr_base = caam_jrcfg->base + caam_jrcfg->offset;

	if (caam_hal_ctrl_pknum(jr_base)) {
		caam_era = caam_hal_ctrl_era(jr_base);
		RSA_TRACE("CAAM Era %d", caam_era);

		if (!drvcrypt_register_rsa(&driver_rsa))
			retstatus = CAAM_NO_ERROR;
	}

	return retstatus;
}
