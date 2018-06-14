// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    caam_hash.c
 *
 * @brief   CAAM Hashing manager.\n
 *          Implementation of Hashing functions
 */

/* Standard includes */
#include <string.h>

/* Global includes */
#include <mm/core_memprot.h>
#include <tee/cache.h>
#include <utee_defines.h>

/* Library i.MX includes */
#include <libimxcrypt.h>
#include <libimxcrypt_hash.h>

/* Local includes */
#include "common.h"
#include "caam_hash.h"
#include "caam_jr.h"

/* Utils includes */
#include "utils_mem.h"

/* Hal includes */
#include "hal_ctrl.h"

/*
 * Debug Macros
 */
//#define HASH_DEBUG
#ifdef HASH_DEBUG
#define DUMP_DESC
#define DUMP_BUF
#define HASH_TRACE		DRV_TRACE
#else
#define HASH_TRACE(...)
#endif

#ifdef DUMP_DESC
#define HASH_DUMPDESC(desc)	{HASH_TRACE("HASH Descriptor"); \
							DRV_DUMPDESC(desc); }
#else
#define HASH_DUMPDESC(desc)
#endif

#ifdef DUMP_BUF
#define HASH_DUMPBUF	DRV_DUMPBUF
#else
#define HASH_DUMPBUF(...)
#endif

/**
 * @brief   Hash Algorithm definition
 */
struct hashalg {
	uint32_t type;        ///< Algo type for operation
	uint8_t  size_digest; ///< Digest size
	uint8_t  size_block;  ///< Computing block size
	uint8_t  size_ctx;    ///< CAAM Context Register size (8 + digest size)
	uint8_t  size_key;    ///< HMAC split key size
};

#define HASH_MSG_LEN			8

/**
 * @brief   Constants definition of the Hash algorithm
 */
static const struct hashalg hash_alg[MAX_HASH_SUPPORTED] = {
	{
		/* md5 */
		.type        = OP_ALGO(MD5),
		.size_digest = TEE_MD5_HASH_SIZE,
		.size_block  = TEE_MD5_HASH_SIZE * 4,
		.size_ctx    = HASH_MSG_LEN + TEE_MD5_HASH_SIZE,
		.size_key    = 32,
	},
	{
		/* sha1 */
		.type        = OP_ALGO(SHA1),
		.size_digest = TEE_SHA1_HASH_SIZE,
		.size_block  = TEE_MAX_HASH_SIZE,
		.size_ctx    = HASH_MSG_LEN + TEE_SHA1_HASH_SIZE,
		.size_key    = 40,
	},
	{
		/* sha224 */
		.type        = OP_ALGO(SHA224),
		.size_digest = TEE_SHA224_HASH_SIZE,
		.size_block  = TEE_MAX_HASH_SIZE,
		.size_ctx    = HASH_MSG_LEN + TEE_SHA256_HASH_SIZE,
		.size_key    = 64,
	},
	{
		/* sha256 */
		.type        = OP_ALGO(SHA256),
		.size_digest = TEE_SHA256_HASH_SIZE,
		.size_block  = TEE_MAX_HASH_SIZE,
		.size_ctx    = HASH_MSG_LEN + TEE_SHA256_HASH_SIZE,
		.size_key    = 64,
	},
	{
		/* sha384 */
		.type        = OP_ALGO(SHA384),
		.size_digest = TEE_SHA384_HASH_SIZE,
		.size_block  = TEE_MAX_HASH_SIZE * 2,
		.size_ctx    = HASH_MSG_LEN + TEE_SHA512_HASH_SIZE,
		.size_key    = 96,
	},
	{
		/* sha512 */
		.type        = OP_ALGO(SHA512),
		.size_digest = TEE_SHA512_HASH_SIZE,
		.size_block  = TEE_MAX_HASH_SIZE * 2,
		.size_ctx    = HASH_MSG_LEN + TEE_SHA512_HASH_SIZE,
		.size_key    = 128,
	},
};

/**
 * @brief   Define the number of circular buffers to handle
 */
#define NB_CIRC_BUFFER		2

/**
 * @brief    Maximum number of entry in the descriptor
 */
#define MAX_DESC_ENTRIES	20

/**
 * @brief   Local key type enumerate
 */
enum keytype {
	KEY_EMPTY = 0,  ///< No key
	KEY_PRECOMP,    ///< Precomputed key
};

/**
 * @brief   Full hashing data SW context
 */
struct hashdata {
	descPointer_t descriptor;      ///< Job descriptor

	struct caambuf circbuf[NB_CIRC_BUFFER];  ///< Circular buffers
	uint8_t active_buf;            ///< Current in use circular buffer

	struct caambuf ctx;            ///< Hash Context used by the CAAM

	struct caambuf key;            ///< HMAC split key
	enum keytype   key_type;       ///< HMAC key type

	enum imxcrypt_hash_id algo_id; ///< Hash Algorithm Id
};

static TEE_Result do_update(void *ctx, enum imxcrypt_hash_id algo,
					const uint8_t *data, size_t len);

/**
 * @brief   Reduce key to be a hash algorithm block size maximum
 *
 * @param[in]  alg    Reference to the algorithm definition
 * @param[in]  inkey  Key to be reduced
 * @param[out] outkey key resulting
 *
 * @retval  CAAM_NO_ERROR      Success
 * @retval  CAAM_FAILURE       General error
 * @retval  CAAM_OUT_MEMORY    Out of memory error
 */
static enum CAAM_Status do_reduce_key(const struct hashalg *alg,
				const struct caambuf *inkey,
				struct caambuf *outkey)
{
#define KEY_REDUCE_DESC_ENTRIES	8
	enum CAAM_Status retstatus = CAAM_FAILURE;

	struct jr_jobctx jobctx  = {0};
	descPointer_t desc    = NULL;
	uint8_t       desclen = 1;

	/* Allocate the job descriptor */
	desc = caam_alloc_desc(KEY_REDUCE_DESC_ENTRIES);
	if (!desc) {
		retstatus = CAAM_OUT_MEMORY;
		goto exit_reduce;
	}

	desc[desclen++] = HASH_INITFINAL(alg->type);

	/* Load the input key */
	desc[desclen++] = FIFO_LD_EXT(CLASS_2, MSG, LAST_C2);
	desc[desclen++] = inkey->paddr;
	desc[desclen++] = inkey->length;

	/* Store key reduced */
	desc[desclen++] = ST_NOIMM(CLASS_2, REG_CTX, outkey->length);
	desc[desclen++] = outkey->paddr;

	/* Set the descriptor Header with length */
	desc[0] = DESC_HEADER(desclen);

	HASH_DUMPDESC(desc);

	cache_operation(TEE_CACHECLEAN, inkey->data, inkey->length);
	cache_operation(TEE_CACHEFLUSH, outkey->data, outkey->length);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus != CAAM_NO_ERROR) {
		HASH_TRACE("CAAM Status 0x%08"PRIx32"", jobctx.status);
		retstatus = CAAM_FAILURE;
	} else {
		HASH_DUMPBUF("Reduced Key", outkey->data, outkey->length);
	}

exit_reduce:
	caam_free_desc(&desc);

	return retstatus;
}

/**
 * @brief   Split key of the input key using the CAAM HW HMAC operation
 *
 * @param[in] ctx   Operation Software context
 * @param[in] ikey  Input key to compute
 * @param[in] ilen  Key length
 *
 * @retval  TEE_SUCCESS              Success
 * @retval  TEE_ERROR_GENERIC        General error
 * @retval  TEE_ERROR_OUT_OF_MEMORY  Out of memory error
 */
static TEE_Result do_split_key(void *ctx, const uint8_t *ikey, size_t ilen)
{
#define KEY_COMPUTE_DESC_ENTRIES	8
	TEE_Result    ret = TEE_ERROR_GENERIC;
	enum CAAM_Status retstatus;

	struct hashdata *hashdata = ctx;

	const struct hashalg *alg = &hash_alg[hashdata->algo_id];

	struct caambuf     inkey;
	struct caambuf     key     = {0};
	struct caambuf     hashkey = {0};

	struct jr_jobctx jobctx  = {0};
	descPointer_t    desc     = NULL;
	uint8_t          desclen  = 1;

	HASH_TRACE("split key length %d", ilen);

	inkey.data   = (uint8_t *)ikey;
	inkey.length = ilen;
	inkey.paddr  = virt_to_phys(inkey.data);
	if (!inkey.paddr) {
		ret = TEE_ERROR_GENERIC;
		goto exit_split_key;
	}

	/* Allocate the job descriptor */
	desc = caam_alloc_desc(KEY_REDUCE_DESC_ENTRIES);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_split_key;
	}

	if (hashdata->key.data == NULL) {
		/* Allocate the split key and keep it in the context */
		retstatus = caam_alloc_align_buf(&hashdata->key, alg->size_key);
		if (retstatus != CAAM_NO_ERROR) {
			HASH_TRACE("HMAC key allocation error");
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_split_key;
		}
	}

	hashdata->key.length = alg->size_key;

	if (inkey.length > alg->size_block) {
		HASH_TRACE("Input key must be reduced");

		retstatus = caam_alloc_align_buf(&hashkey, alg->size_digest);
		if (retstatus != CAAM_NO_ERROR) {
			HASH_TRACE("Reduced Key allocation error");
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_split_key;
		}

		key.data   = hashkey.data;
		key.paddr  = hashkey.paddr;
		key.length = alg->size_digest;

		retstatus = do_reduce_key(alg, &inkey, &key);

		if (retstatus != CAAM_NO_ERROR)
			goto exit_split_key;
	} else {
		/* Key size is correct use directly the input key */
		key.data   = inkey.data;
		key.paddr  = inkey.paddr;
		key.length = inkey.length;
	}

	/* Load either input key or the reduced input key into key register */
	desc[desclen++] = LD_KEY_PLAIN(CLASS_2, REG, key.length);
	desc[desclen++] = key.paddr;
	/* Split the key */
	desc[desclen++] = HMAC_INIT_DECRYPT(alg->type);
	desc[desclen++] = FIFO_LD_IMM(CLASS_2, MSG, LAST_C2, 0);
	/* Store the split key */
	desc[desclen++] = FIFO_ST(C2_MDHA_SPLIT_KEY_AES_ECB_JKEK,
					hashdata->key.length);
	desc[desclen++] = hashdata->key.paddr;

	/* Set the descriptor Header with length */
	desc[0] = DESC_HEADER(desclen);

	HASH_DUMPDESC(desc);

	cache_operation(TEE_CACHECLEAN, key.data, key.length);
	cache_operation(TEE_CACHEFLUSH, hashdata->key.data,
			hashdata->key.length);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		HASH_DUMPBUF("Split Key", hashdata->key.data,
			hashdata->key.length);

		hashdata->key_type = KEY_PRECOMP;
		ret = TEE_SUCCESS;
	} else {
		HASH_TRACE("CAAM Status 0x%08"PRIx32"", jobctx.status);
	}

exit_split_key:
	caam_free_buf(&hashkey);
	caam_free_desc(&desc);

	return ret;
}

/**
 * @brief   Free the internal hashing data context
 *
 * @param[in/out]  ctx    Caller context variable
 *
 */
static void do_free_intern(struct hashdata *ctx)
{
	HASH_TRACE("Free Context (0x%"PRIxPTR")", (uintptr_t)ctx);

	if (ctx) {
		/* Free the descriptor */
		caam_free_desc(&ctx->descriptor);
		ctx->descriptor = NULL;

		/* Free the circular buffer */
		caam_free_buf(&ctx->circbuf[0]);

		/* Clear the other circular buffer data address */
		ctx->circbuf[1].data  = NULL;
		ctx->circbuf[1].paddr = 0;

		/* Free the context register */
		caam_free_buf(&ctx->ctx);

		/* Free the HMAC Key */
		caam_free_buf(&ctx->key);
		ctx->key_type   = KEY_EMPTY;
	}
}

/**
 * @brief   Allocate the internal hashing data context
 *
 * @param[in/out]  ctx    Caller context variable
 *
 * @retval CAAM_NO_ERROR       Success
 * @retval CAAM_FAILURE        Generic error
 * @retval CAAM_OUT_MEMORY     Out of memory
 */
static enum CAAM_Status do_allocate_intern(struct hashdata *ctx)
{
	TEE_Result ret = CAAM_OUT_MEMORY;

	struct caambuf  buf;

	HASH_TRACE("Allocate Context (0x%"PRIxPTR")", (uintptr_t)ctx);

	/* Allocate the descriptor */
	ctx->descriptor = caam_alloc_desc(MAX_DESC_ENTRIES);
	if (!ctx->descriptor) {
		HASH_TRACE("Allocation descriptor error");
		goto exit_alloc;
	}

	/* Allocate the Circular buffers - size = 2x blocks */
	ret = caam_alloc_align_buf(&buf, 2 * hash_alg[ctx->algo_id].size_block);
	if (ret != CAAM_NO_ERROR) {
		HASH_TRACE("Allocation circular buffer error");
		goto exit_alloc;
	}

	ctx->circbuf[0].data   = buf.data;
	ctx->circbuf[0].paddr  = buf.paddr;
	/* Ensure buffer length is 0 */
	ctx->circbuf[0].length = 0;
	ctx->circbuf[1].data   = ctx->circbuf[0].data +
					hash_alg[ctx->algo_id].size_block;
	ctx->circbuf[1].paddr  = ctx->circbuf[0].paddr +
					hash_alg[ctx->algo_id].size_block;
	/* Ensure buffer length is 0 */
	ctx->circbuf[1].length = 0;

	/* Allocate the CAAM Context register */
	ret = caam_alloc_align_buf(&ctx->ctx, hash_alg[ctx->algo_id].size_ctx);
#ifdef HASH_DEBUG
	if (ret != CAAM_NO_ERROR)
		HASH_TRACE("Allocation context register error");
#endif

	/* Ensure buffer length is 0 */
	ctx->ctx.length = 0;

exit_alloc:
	if (ret != CAAM_NO_ERROR) {
		/* Free all data allocated */
		do_free_intern(ctx);
	}

	return ret;
}

/**
 * @brief   Free the SW hashing data context
 *
 * @param[in/out]  ctx    Caller context variable
 *
 */
static void do_free(void *ctx)
{
	HASH_TRACE("Free Context (0x%"PRIxPTR")", (uintptr_t)ctx);

	if (ctx) {
		do_free_intern(ctx);
		caam_free(&ctx);
	}
}

/**
 * @brief   Allocate the internal hashing data context
 *
 * @param[in/out]  ctx    Caller context variable
 * @param[in]      algo   Algorithm ID of the context
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 */
static TEE_Result do_allocate(void **ctx, enum imxcrypt_hash_id algo)
{
	struct hashdata *hashdata;

	HASH_TRACE("Allocate Context (0x%"PRIxPTR")", (uintptr_t)ctx);

	hashdata = caam_alloc(sizeof(struct hashdata));
	if (!hashdata) {
		HASH_TRACE("Allocation Hash data error");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	HASH_TRACE("Allocated Context (0x%"PRIxPTR")", (uintptr_t)hashdata);

	hashdata->algo_id = algo;

	*ctx = hashdata;

	return TEE_SUCCESS;
}

/**
 * @brief   Initialization of the Hash operation
 *
 * @param[in] ctx   Operation Software context
 * @param[in] algo  Algorithm ID of the context
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 */
static TEE_Result do_init(void *ctx, enum imxcrypt_hash_id algo)
{
	struct hashdata *hashdata = ctx;

	/* Check if the algorithm is equal to the context one's */
	if (hashdata->algo_id == algo) {
		/* Reset the software context */
		hashdata->active_buf = 0;
		hashdata->circbuf[0].length = 0;
		hashdata->circbuf[1].length = 0;
		hashdata->ctx.length = 0;

		hashdata->key.length = 0;
		hashdata->key_type   = KEY_EMPTY;

		return TEE_SUCCESS;
	}

	return TEE_ERROR_BAD_PARAMETERS;
}

/**
 * @brief   Update the Hash operation
 *
 * @param[in] ctx   Operation Software context
 * @param[in] algo  Algorithm ID of the context
 * @param[in] data  Data to hash
 * @param[in] len   Data length
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY   Out of memory
 */
static TEE_Result do_update(void *ctx, enum imxcrypt_hash_id algo,
					const uint8_t *data, size_t len)
{
	TEE_Result    ret = TEE_ERROR_GENERIC;
	enum CAAM_Status retstatus;

	struct hashdata      *hashdata = ctx;
	struct caambuf       *circbuf;
	const struct hashalg *alg = &hash_alg[algo];

	struct jr_jobctx jobctx = {0};
	descPointer_t    desc;
	uint8_t          desclen = 1;

	uint8_t       next_active_buf;
	paddr_t       paddr_data;
	size_t        size_todo;
	size_t        size_topost;
	const uint8_t *in_topost  = data;

	if (hashdata->algo_id != algo) {
		HASH_TRACE("Context algo is %d and asked for %d",
					hashdata->algo_id, algo);
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto exit_update;
	}

	paddr_data = virt_to_phys((void *)data);
	if (!paddr_data) {
		HASH_TRACE("Bad input data physical address");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto exit_update;
	}

	if (!hashdata->ctx.data) {
		retstatus = do_allocate_intern(hashdata);
		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_update;
		}
	}

	HASH_TRACE("Update Algo %d - Input @0x%08"PRIxPTR"-%d",
				algo, (uintptr_t)data, len);

	/* Set next active buffer to current active buffer */
	next_active_buf = hashdata->active_buf;
	circbuf = &hashdata->circbuf[hashdata->active_buf];

	/* Check if there are data postponed */
	if (circbuf->length) {
		/*
		 * Calculate the maximum size of data that can be done
		 * function of the postponed data and the blocksize
		 */
		HASH_TRACE("Add Data to circbuf %d - %d",
					hashdata->active_buf, circbuf->length);

		size_todo   = len + circbuf->length;
		size_topost = size_todo % alg->size_block;
		size_todo  -= size_topost;

		/* If size_todo is null, complete the circular buffer */
		if (size_todo == 0) {
			HASH_TRACE("Complete Circular with %d", len);

			memcpy((circbuf->data + circbuf->length), data, len);
			circbuf->length += len;
			size_topost = 0;
		}
	} else {
		size_todo   = len;
		size_topost = len % alg->size_block;
		size_todo  -= size_topost;
	}

	HASH_TRACE("Data size to do %d - Postpone %d", size_todo, size_topost);

	if (size_topost) {
		next_active_buf += 1;
		next_active_buf %= NB_CIRC_BUFFER;

		/* Calculate the input pointer for the postponed data */
		if (size_todo > 0)
			in_topost += (len - size_topost);

		/* Some data to be saved for the next block size to update */
		memcpy(hashdata->circbuf[next_active_buf].data,
			in_topost, size_topost);

		hashdata->circbuf[next_active_buf].length = size_topost;

		HASH_TRACE("Save postponed data to buffer #%d",
			next_active_buf);
		HASH_DUMPBUF("Cirbuf", hashdata->circbuf[next_active_buf].data,
			hashdata->circbuf[next_active_buf].length)
	}

	if (size_todo) {
		desc = hashdata->descriptor;

		/* There are blocks to hash - Create the Descriptor */
		if (hashdata->ctx.length) {
			HASH_TRACE("Update Operation");
			/* Algo Operation - Update */
			desc[desclen++] = HASH_UPDATE(alg->type);
			/* Running context to restore */
			desc[desclen++] = LD_NOIMM(CLASS_2, REG_CTX,
					hashdata->ctx.length);
			desc[desclen++] = hashdata->ctx.paddr;
		} else {
			HASH_TRACE("Init Operation");

			/* Check if there is a key to load it */
			if (hashdata->key_type == KEY_PRECOMP) {
				HASH_TRACE("Insert Key");
				desc[desclen++] = LD_KEY_SPLIT(
					hashdata->key.length);
				desc[desclen++] = hashdata->key.paddr;

				/* Algo Operation - HMAC Init */
				desc[desclen++] = HMAC_INIT_PRECOMP(alg->type);

				/* Clean the Split key */
				cache_operation(TEE_CACHECLEAN,
					hashdata->key.data,
					hashdata->key.length);

			} else {
				/* Algo Operation - Init */
				desc[desclen++] = HASH_INIT(alg->type);
			}

			hashdata->ctx.length = alg->size_ctx;
		}
			/* Data to be hashed */
		if (circbuf->length) {
			size_todo -= circbuf->length;

			/* Add the saved data in the circular buffer */
			if (size_todo) {
				desc[desclen++] = FIFO_LD_EXT(CLASS_2, MSG,
						NOACTION);
			} else {
				desc[desclen++] = FIFO_LD_EXT(CLASS_2, MSG,
						LAST_C2);
			}
			desc[desclen++] = circbuf->paddr;
			desc[desclen++] = circbuf->length;

			/* Clean the circular buffer data to be loaded */
			cache_operation(TEE_CACHECLEAN, circbuf->data,
					circbuf->length);

			circbuf->length = 0;
		}

		/* Add the input data multiple of blocksize */
		if (size_todo) {
			desc[desclen++] = FIFO_LD_EXT(CLASS_2, MSG, LAST_C2);
			desc[desclen++] = paddr_data;
			desc[desclen++] = size_todo;

			/* Clean the input data to be loaded */
			cache_operation(TEE_CACHECLEAN, (void *)data,
					size_todo);
		}

		/* Save the running context */
		desc[desclen++] = ST_NOIMM(CLASS_2, REG_CTX,
					hashdata->ctx.length);
		desc[desclen++] = hashdata->ctx.paddr;

		/* Set the descriptor Header with length */
		desc[0] = DESC_HEADER(desclen);

		HASH_DUMPDESC(desc);

		/* Invalidate Context register */
		cache_operation(TEE_CACHEINVALIDATE, hashdata->ctx.data,
						hashdata->ctx.length);

		jobctx.desc = desc;
		retstatus = caam_jr_enqueue(&jobctx, NULL);

		if (retstatus == CAAM_NO_ERROR) {
			ret = TEE_SUCCESS;
			HASH_DUMPBUF("CTX", hashdata->ctx.data,
				hashdata->ctx.length);
		} else {
			HASH_TRACE("CAAM Status 0x%08"PRIx32"", jobctx.status);
			ret = TEE_ERROR_GENERIC;
		}
	} else {
		/* Return success, all data postponed */
		ret = TEE_SUCCESS;
	}

	hashdata->active_buf = next_active_buf;

exit_update:
	if (ret != TEE_SUCCESS)
		do_free_intern(hashdata);

	return ret;
}

/**
 * @brief   Finalize the Hash operation
 *
 * @param[in] ctx   Operation Software context
 * @param[in] algo  Algorithm ID of the context
 * @param[in] len   Digest buffer length
 *
 * @param[out] digest  Hash digest buffer
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 * @retval TEE_ERROR_SHORT_BUFFER    Digest buffer too short
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 */
static TEE_Result do_final(void *ctx, enum imxcrypt_hash_id algo,
					uint8_t *digest, size_t len)
{
	TEE_Result    ret = TEE_ERROR_GENERIC;
	enum CAAM_Status retstatus;

	struct hashdata      *hashdata = ctx;
	struct caambuf       *circbuf;
	const struct hashalg *alg = &hash_alg[algo];

	struct jr_jobctx jobctx = {0};
	descPointer_t    desc;
	uint8_t          desclen = 1;

	paddr_t       paddr_digest;

	if (!hashdata->ctx.data) {
		HASH_TRACE("Bad context");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (hashdata->algo_id != algo) {
		HASH_TRACE("Context algo is %d and asked for %d",
					hashdata->algo_id, algo);
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto exit_final;
	}

	if (alg->size_digest > len) {
		HASH_TRACE("Digest buffer size %d too short (%d)",
					alg->size_digest, len);
		ret = TEE_ERROR_SHORT_BUFFER;
		goto exit_final;
	}

	paddr_digest = virt_to_phys((void *)digest);
	if (!paddr_digest) {
		HASH_TRACE("Bad digest physical address");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto exit_final;
	}

	HASH_TRACE("Final Algo %d - Digest @0x%08"PRIxPTR"-%d",
				algo, (uintptr_t)digest, len);

	circbuf = &hashdata->circbuf[hashdata->active_buf];
	desc = hashdata->descriptor;

	/* Check if there is a key to load it */
	if (hashdata->key_type == KEY_PRECOMP) {
		HASH_TRACE("Load key");
		desc[desclen++] = LD_KEY_SPLIT(hashdata->key.length);
		desc[desclen++] = hashdata->key.paddr;

		/* Clean Split key */
		cache_operation(TEE_CACHECLEAN, hashdata->key.data,
						hashdata->key.length);
	}

	if (hashdata->ctx.length) {
		HASH_TRACE("Final Operation");

		if (hashdata->key_type == KEY_PRECOMP)
			desc[desclen++] = HMAC_FINAL_PRECOMP(alg->type);
		else
			desc[desclen++] = HASH_FINAL(alg->type);

		/* Running context to restore */
		desc[desclen++] = LD_NOIMM(CLASS_2, REG_CTX,
					hashdata->ctx.length);
		desc[desclen++] = hashdata->ctx.paddr;

		cache_operation(TEE_CACHEINVALIDATE, hashdata->ctx.data,
						hashdata->ctx.length);
		HASH_DUMPBUF("CTX", hashdata->ctx.data, hashdata->ctx.length);
	} else {
		HASH_TRACE("Init/Final Operation");
		if (hashdata->key_type == KEY_PRECOMP)
			desc[desclen++] = HMAC_INITFINAL_PRECOMP(alg->type);
		else
			desc[desclen++] = HASH_INITFINAL(alg->type);
	}

	HASH_DUMPBUF("Cirbuf", circbuf->data, circbuf->length);
	desc[desclen++] = FIFO_LD_EXT(CLASS_2, MSG, LAST_C2);
	desc[desclen++] = circbuf->paddr;
	desc[desclen++] = circbuf->length;
	cache_operation(TEE_CACHECLEAN, circbuf->data, circbuf->length);

	/* Save the final digest */
	desc[desclen++] = ST_NOIMM(CLASS_2, REG_CTX, alg->size_digest);
	desc[desclen++] = paddr_digest;

	/* Set the descriptor Header with length */
	desc[0] = DESC_HEADER(desclen);

	HASH_DUMPDESC(desc);

	jobctx.desc = desc;
	cache_operation(TEE_CACHEFLUSH, digest, len);

	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		ret = TEE_SUCCESS;
		HASH_DUMPBUF("Digest", digest, alg->size_digest);
	} else {
		HASH_TRACE("CAAM Status 0x%08"PRIx32"", jobctx.status);
		ret = TEE_ERROR_GENERIC;
	}

exit_final:
	do_free_intern(hashdata);
	return ret;
}

/**
 * @brief   Copy Sofware Hashing Context
 *
 * @param[in] src_ctx  Reference the context source
 *
 * @param[out] dst_ctx  Reference the context destination
 *
 */
static void do_cpy_state(void *dst_ctx, void *src_ctx)
{
	uint8_t idx;
	struct hashdata *dst = dst_ctx;
	struct hashdata *src = src_ctx;

	HASH_TRACE("Copy State context (0x%"PRIxPTR") to (0x%"PRIxPTR")",
			 (uintptr_t)src_ctx, (uintptr_t)dst_ctx);

	if (!dst->ctx.data)
		do_allocate_intern(dst_ctx);

	dst->active_buf = src->active_buf;
	dst->algo_id    = src->algo_id;

	memcpy(dst->ctx.data, src->ctx.data, src->ctx.length);
	dst->ctx.length = src->ctx.length;
	cache_operation(TEE_CACHECLEAN, dst->ctx.data, dst->ctx.length);

	for (idx = 0; idx < NB_CIRC_BUFFER; idx++) {
		dst->circbuf[idx].length = src->circbuf[idx].length;
		if (src->circbuf[idx].length != 0) {
			memcpy(dst->circbuf[idx].data, src->circbuf[idx].data,
						src->circbuf[idx].length);
		}
	}

	dst->key_type   = src->key_type;
	if (src->key.length) {
		if (caam_alloc_align_buf(&dst->key,
					hash_alg[src->algo_id].size_key) ==
			CAAM_NO_ERROR) {
			memcpy(dst->key.data, src->key.data, src->key.length);
		}
	}
}

/**
 * @brief   Registration of the HASH Driver
 */
struct imxcrypt_hash driver_hash = {
	.alloc_ctx  = &do_allocate,
	.free_ctx   = &do_free,
	.init       = &do_init,
	.update     = &do_update,
	.final      = &do_final,
	.cpy_state  = &do_cpy_state,
	.compute_key = NULL,
};

/**
 * @brief   Registration of the HMAC Driver
 */
struct imxcrypt_hash driver_hmac = {
	.alloc_ctx   = &do_allocate,
	.free_ctx    = &do_free,
	.init        = &do_init,
	.update      = &do_update,
	.final       = &do_final,
	.cpy_state   = &do_cpy_state,
	.compute_key = &do_split_key,
};


/**
 * @brief   Initialize the Hash module
 *
 * @param[in] ctrl_addr   Controller base address
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 * @retval  CAAM_OUT_MEMORY  Out of memory
 */
enum CAAM_Status caam_hash_init(vaddr_t ctrl_addr)
{
	enum CAAM_Status retstatus = CAAM_FAILURE;
	int hash_limit;

	hash_limit = hal_ctrl_hash_limit(ctrl_addr);

	if (hash_limit > 0) {
		driver_hash.max_hash = hash_limit;
		driver_hmac.max_hash = hash_limit;

		if ((imxcrypt_register(CRYPTO_HASH, &driver_hash) == 0) &&
			(imxcrypt_register(CRYPTO_HMAC, &driver_hmac) == 0))
			retstatus = CAAM_NO_ERROR;
	}

	return retstatus;
}
