/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019-2020 NXP
 *
 * Brief   CAAM hash/hmac Local header.
 */
#ifndef __LOCAL_H__
#define __LOCAL_H__

#include <caam_common.h>

/*
 * Full hashing/hmac data SW context
 */
struct hashctx {
	uint32_t *descriptor;	   /* Job descriptor */
	struct caamblock blockbuf; /* Temporary Block buffer */
	struct caambuf ctx;	   /* Hash Context used by the CAAM */
	const struct hashalg *alg; /* Reference to the algo constants */
	struct caambuf key;	   /* HMAC split key */
};

/*
 * Hash/hmac Algorithm definition
 */
struct hashalg {
	uint32_t type;	     /* Algo type for operation */
	uint8_t size_digest; /* Digest size */
	uint8_t size_block;  /* Computing block size */
	uint8_t size_ctx;    /* CAAM Context Register size (8 + digest size) */
	uint8_t size_key;    /* HMAC split key size */
};

/* First part CAAM HW Context - message length */
#define HASH_MSG_LEN 8

/*
 * Constants definition of the hash/hmac algorithm
 */
static const struct hashalg hash_alg[] = {
	{
		/* md5 */
		.type = OP_ALGO(MD5),
		.size_digest = TEE_MD5_HASH_SIZE,
		.size_block = TEE_MD5_HASH_SIZE * 4,
		.size_ctx = HASH_MSG_LEN + TEE_MD5_HASH_SIZE,
		.size_key = 32,
	},
	{
		/* sha1 */
		.type = OP_ALGO(SHA1),
		.size_digest = TEE_SHA1_HASH_SIZE,
		.size_block = TEE_MAX_HASH_SIZE,
		.size_ctx = HASH_MSG_LEN + TEE_SHA1_HASH_SIZE,
		.size_key = 40,
	},
	{
		/* sha224 */
		.type = OP_ALGO(SHA224),
		.size_digest = TEE_SHA224_HASH_SIZE,
		.size_block = TEE_MAX_HASH_SIZE,
		.size_ctx = HASH_MSG_LEN + TEE_SHA256_HASH_SIZE,
		.size_key = 64,
	},
	{
		/* sha256 */
		.type = OP_ALGO(SHA256),
		.size_digest = TEE_SHA256_HASH_SIZE,
		.size_block = TEE_MAX_HASH_SIZE,
		.size_ctx = HASH_MSG_LEN + TEE_SHA256_HASH_SIZE,
		.size_key = 64,
	},
	{
		/* sha384 */
		.type = OP_ALGO(SHA384),
		.size_digest = TEE_SHA384_HASH_SIZE,
		.size_block = TEE_MAX_HASH_SIZE * 2,
		.size_ctx = HASH_MSG_LEN + TEE_SHA512_HASH_SIZE,
		.size_key = 128,
	},
	{
		/* sha512 */
		.type = OP_ALGO(SHA512),
		.size_digest = TEE_SHA512_HASH_SIZE,
		.size_block = TEE_MAX_HASH_SIZE * 2,
		.size_ctx = HASH_MSG_LEN + TEE_SHA512_HASH_SIZE,
		.size_key = 128,
	},
};

/*
 * Initialization of the hash/hmac operation
 *
 * @ctx   Operation Software context
 */
TEE_Result caam_hash_hmac_init(struct hashctx *ctx);

/*
 * Update the hash/hmac operation
 *
 * @ctx   Operation Software context
 * @data  Data to hash
 * @len   Data length
 */
TEE_Result caam_hash_hmac_update(struct hashctx *ctx, const uint8_t *data,
				 size_t len);

/*
 * Finalize the hash/hmac operation
 *
 * @ctx     Operation Software context
 * @digest  [out] Hash digest buffer
 * @len     Digest buffer length
 */
TEE_Result caam_hash_hmac_final(struct hashctx *ctx, uint8_t *digest,
				size_t len);

/*
 * Copy Sofware Hashing Context
 *
 * @ctx  [out] Reference the context destination
 * @ctx  Reference the context source
 */
void caam_hash_hmac_copy_state(struct hashctx *dst, struct hashctx *src);

/*
 * Free the SW hashing data context
 *
 * @ctx    [in/out] Caller context variable
 */
void caam_hash_hmac_free(struct hashctx *ctx);

#endif /* __LOCAL_H__ */
