// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2020 NXP
 *
 * Implementation of Cipher functions
 */
#include <caam_cipher.h>
#include <caam_common.h>
#include <caam_io.h>
#include <caam_jr.h>
#include <caam_utils_mem.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>
#include <tee/tee_cryp_utl.h>
#include <utee_defines.h>

#include "local.h"

/*
 * Max Cipher Buffer to encrypt/decrypt at each operation
 */
#define MAX_CIPHER_BUFFER (8 * 1024)

/* Local Function declaration */
static TEE_Result do_update_streaming(struct drvcrypt_cipher_update *dupdate);
static TEE_Result do_update_cipher(struct drvcrypt_cipher_update *dupdate);
static TEE_Result do_update_cts(struct drvcrypt_cipher_update *dupdate);

/*
 * Constants definition of the AES algorithm
 */
static const struct cipheralg aes_alg[] = {
	{
		/* AES ECB No Pad */
		.type = OP_ALGO(AES) | ALGO_AAI(AES_ECB),
		.size_block = TEE_AES_BLOCK_SIZE,
		.size_ctx = 0,
		.ctx_offset = 0,
		.require_key = NEED_KEY1,
		.def_key = { .min = 16, .max = 32, .mod = 8 },
		.update = do_update_cipher,
	},
	{
		/* AES CBC No Pad */
		.type = OP_ALGO(AES) | ALGO_AAI(AES_CBC),
		.size_block = TEE_AES_BLOCK_SIZE,
		.size_ctx = 2 * sizeof(uint64_t),
		.ctx_offset = 0,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key = { .min = 16, .max = 32, .mod = 8 },
		.update = do_update_cipher,
	},
	{
		/* AES CTR */
		.type = OP_ALGO(AES) | ALGO_AAI(AES_CTR_MOD128),
		.size_block = TEE_AES_BLOCK_SIZE,
		.size_ctx = 2 * sizeof(uint64_t),
		.ctx_offset = 16,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key = { .min = 16, .max = 32, .mod = 8 },
		.update = do_update_streaming,
	},
	{
		/* AES CTS, combinaison of CBC and ECB mode */
		.type = 0,
		.size_block = TEE_AES_BLOCK_SIZE,
		.size_ctx = 2 * sizeof(uint64_t),
		.ctx_offset = 0,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key = { .min = 16, .max = 32, .mod = 8 },
		.update = do_update_cts,
	},
	{
		/* AES XTS, tweakable ECB cipher block */
		.type = OP_ALGO(AES) | ALGO_AAI(AES_ECB),
		.size_block = TEE_AES_BLOCK_SIZE,
		.size_ctx = 0,
		.ctx_offset = 0,
		.require_key = NEED_KEY1 | NEED_KEY2 | NEED_TWEAK,
		.def_key = { .min = 16, .max = 32, .mod = 8 },
		.update = caam_cipher_update_xts,
	},
};

/*
 * Constants definition of the DES algorithm
 */
static const struct cipheralg des_alg[] = {
	{
		/* DES ECB No Pad */
		.type = OP_ALGO(DES) | ALGO_AAI(DES_ECB),
		.size_block = TEE_DES_BLOCK_SIZE,
		.size_ctx = 0,
		.ctx_offset = 0,
		.require_key = NEED_KEY1,
		.def_key = { .min = 8, .max = 8, .mod = 8 },
		.update = do_update_cipher,
	},
	{
		/* DES CBC No Pad */
		.type = OP_ALGO(DES) | ALGO_AAI(DES_CBC),
		.size_block = TEE_DES_BLOCK_SIZE,
		.size_ctx = sizeof(uint64_t),
		.ctx_offset = 0,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key = { .min = 8, .max = 8, .mod = 8 },
		.update = do_update_cipher,
	},
};

/*
 * Constants definition of the DES3 algorithm
 */
static const struct cipheralg des3_alg[] = {
	{
		/* Triple-DES ECB No Pad */
		.type = OP_ALGO(3DES) | ALGO_AAI(DES_ECB),
		.size_block = TEE_DES_BLOCK_SIZE,
		.size_ctx = 0,
		.ctx_offset = 0,
		.require_key = NEED_KEY1,
		.def_key = { .min = 16, .max = 24, .mod = 8 },
		.update = do_update_cipher,
	},
	{
		/* Triple-DES CBC No Pad */
		.type = OP_ALGO(3DES) | ALGO_AAI(DES_CBC),
		.size_block = TEE_DES_BLOCK_SIZE,
		.size_ctx = sizeof(uint64_t),
		.ctx_offset = 0,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key = { .min = 16, .max = 24, .mod = 8 },
		.update = do_update_cipher,
	},
};

/*
 * Allocate context data and copy input data into
 *
 * @dst  [out] Destination data to allocate and fill
 * @src  Source of data to copy
 */
static enum caam_status copy_ctx_data(struct caambuf *dst,
				      struct cryptobuf *src)
{
	enum caam_status ret = CAAM_OUT_MEMORY;

	if (!dst->data) {
		/* Allocate the destination buffer */
		ret = caam_alloc_align_buf(dst, src->length);
		if (ret != CAAM_NO_ERROR)
			return CAAM_OUT_MEMORY;
	}

	/* Do the copy */
	memcpy(dst->data, src->data, dst->length);

	/* Push data to physical memory */
	cache_operation(TEE_CACHEFLUSH, dst->data, dst->length);

	return CAAM_NO_ERROR;
}

/*
 * Verify the input key size with the requirements
 *
 * @def  Key requirements
 * @size Key size to verify
 */
static enum caam_status do_check_keysize(const struct caamdefkey *def,
					 size_t size)
{
	if (size >= def->min && size <= def->max) {
		if (!(size % def->mod))
			return CAAM_NO_ERROR;
	}

	return CAAM_BAD_PARAM;
}

enum caam_status caam_cipher_block(struct cipherdata *ctx, bool savectx,
				   uint8_t keyid, bool encrypt,
				   struct caamdmaobj *src,
				   struct caamdmaobj *dst)
{
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_jobctx jobctx = {};
	uint32_t *desc = ctx->descriptor;

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));

	if (keyid == NEED_KEY1) {
		/* Build the descriptor */
		caam_desc_add_word(desc, LD_KEY_PLAIN(CLASS_1, REG,
						      ctx->key1.length));
		caam_desc_add_ptr(desc, ctx->key1.paddr);
	} else if (keyid == NEED_KEY2) {
		/* Build the descriptor */
		caam_desc_add_word(desc, LD_KEY_PLAIN(CLASS_1, REG,
						      ctx->key2.length));
		caam_desc_add_ptr(desc, ctx->key2.paddr);
	}

	/* If there is a context register load it */
	if (ctx->ctx.length && ctx->alg->size_ctx) {
		caam_desc_add_word(desc, LD_NOIMM_OFF(CLASS_1, REG_CTX,
						      ctx->ctx.length,
						      ctx->alg->ctx_offset));
		caam_desc_add_ptr(desc, ctx->ctx.paddr);
		/* Operation with the direction */
		caam_desc_add_word(desc, CIPHER_INIT(ctx->alg->type, encrypt));
	} else {
		/* Operation with the direction */
		caam_desc_add_word(desc,
				   CIPHER_INITFINAL(ctx->alg->type, encrypt));
	}

	/* Load the source data if any */
	if (src) {
		caam_desc_fifo_load(desc, src, CLASS_1, MSG, LAST_C1);
		caam_dmaobj_cache_push(src);
	}

	/* Store the output data if any */
	if (dst) {
		caam_desc_fifo_store(desc, dst, MSG_DATA);
		caam_dmaobj_cache_push(dst);
	}

	if (ctx->ctx.length && ctx->alg->size_ctx) {
		if (savectx) {
			/* Store the context */
			caam_desc_add_word(desc,
					   ST_NOIMM_OFF(CLASS_1, REG_CTX,
							ctx->ctx.length,
							ctx->alg->ctx_offset));
			caam_desc_add_ptr(desc, ctx->ctx.paddr);
		}

		/* Ensure Context register data are not in cache */
		cache_operation(TEE_CACHEINVALIDATE, ctx->ctx.data,
				ctx->ctx.length);
	}

	CIPHER_DUMPDESC(desc);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus != CAAM_NO_ERROR) {
		CIPHER_TRACE("CAAM return 0x%08x Status 0x%08" PRIx32,
			     retstatus, jobctx.status);
		retstatus = CAAM_FAILURE;
	}

	return retstatus;
}

/*
 * Checks if the algorithm @algo is supported and returns the
 * local algorithm entry in the corresponding cipher array
 */
static const struct cipheralg *get_cipheralgo(uint32_t algo)
{
	unsigned int algo_id = 0;
	unsigned int algo_md = 0;

	/* Extract the algorithms fields */
	algo_id = TEE_ALG_GET_MAIN_ALG(algo);
	algo_md = TEE_ALG_GET_CHAIN_MODE(algo);

	CIPHER_TRACE("Algo id:%" PRId32 " md:%" PRId32, algo_id, algo_md);

	switch (algo_id) {
	case TEE_MAIN_ALGO_AES:
		if (algo_md < ARRAY_SIZE(aes_alg))
			return &aes_alg[algo_md];
		break;

	case TEE_MAIN_ALGO_DES:
		if (algo_md < ARRAY_SIZE(des_alg))
			return &des_alg[algo_md];
		break;

	case TEE_MAIN_ALGO_DES3:
		if (algo_md < ARRAY_SIZE(des3_alg))
			return &des3_alg[algo_md];
		break;

	default:
		break;
	}

	return NULL;
}

/*
 * Allocate the SW cipher data context
 *
 * @algo  Algorithm ID of the context
 * @ctx   [out] Caller context variable
 */
static TEE_Result do_allocate(void **ctx, uint32_t algo)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct cipherdata *cipherdata = NULL;
	const struct cipheralg *alg = NULL;

	CIPHER_TRACE("Allocate Algo 0x%" PRIX32 " Context (%p)", algo, ctx);

	alg = get_cipheralgo(algo);
	if (!alg) {
		CIPHER_TRACE("Algorithm not supported");
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	cipherdata = caam_calloc(sizeof(*cipherdata));
	if (!cipherdata) {
		CIPHER_TRACE("Allocation Cipher data error");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Allocate the descriptor */
	cipherdata->descriptor = caam_calloc_desc(MAX_DESC_ENTRIES);
	if (!cipherdata->descriptor) {
		CIPHER_TRACE("Allocation descriptor error");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto err_allocate;
	}

	/* Setup the Algorithm pointer */
	cipherdata->alg = alg;

	/* Initialize the block buffer */
	cipherdata->blockbuf.max = cipherdata->alg->size_block;

	*ctx = cipherdata;

	return TEE_SUCCESS;

err_allocate:
	caam_free_desc(&cipherdata->descriptor);
	caam_free(cipherdata);

	return ret;
}

/*
 * Free the internal cipher data context
 *
 * @ctx    Caller context variable
 */
static void do_free_intern(struct cipherdata *ctx)
{
	CIPHER_TRACE("Free Context (%p)", ctx);

	if (ctx) {
		/* Free the descriptor */
		caam_free_desc(&ctx->descriptor);

		/* Free the Key 1  */
		caam_free_buf(&ctx->key1);

		/* Free the Key 2  */
		caam_free_buf(&ctx->key2);

		/* Free the Tweak */
		caam_free_buf(&ctx->tweak);

		/* Free the Context Register */
		caam_free_buf(&ctx->ctx);

		/* Free Temporary buffer */
		caam_free_buf(&ctx->blockbuf.buf);
	}
}

void caam_cipher_free(void *ctx)
{
	CIPHER_TRACE("Free Context (%p)", ctx);

	if (ctx) {
		do_free_intern(ctx);
		caam_free(ctx);
	}
}

void caam_cipher_copy_state(void *dst_ctx, void *src_ctx)
{
	struct cipherdata *dst = dst_ctx;
	struct cipherdata *src = src_ctx;

	CIPHER_TRACE("Copy State context (%p) to (%p)", src_ctx, dst_ctx);

	dst->alg = src->alg;
	dst->encrypt = src->encrypt;

	if (src->blockbuf.filled) {
		struct caambuf srcdata = {
			.data = src->blockbuf.buf.data,
			.length = src->blockbuf.filled };
		caam_cpy_block_src(&dst->blockbuf, &srcdata, 0);
	}

	if (src->key1.length) {
		struct cryptobuf key1 = {
			.data = src->key1.data,
			.length = src->key1.length };
		copy_ctx_data(&dst->key1, &key1);
	}

	if (src->key2.length) {
		struct cryptobuf key2 = {
			.data = src->key2.data,
			.length = src->key2.length };
		copy_ctx_data(&dst->key2, &key2);
	}

	if (src->ctx.length) {
		struct cryptobuf ctx = {
			.data = src->ctx.data,
			.length = src->ctx.length };
		copy_ctx_data(&dst->ctx, &ctx);
	}

	if (src->tweak.length) {
		struct cryptobuf tweak = {
			.data = src->tweak.data,
			.length = src->tweak.length };
		copy_ctx_data(&dst->tweak, &tweak);
	}
}

TEE_Result caam_cipher_initialize(struct drvcrypt_cipher_init *dinit)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;
	enum caam_status retstatus = CAAM_FAILURE;
	struct cipherdata *cipherdata = dinit->ctx;
	const struct cipheralg *alg = NULL;

	CIPHER_TRACE("Action %s", dinit->encrypt ? "Encrypt" : "Decrypt");

	if (!cipherdata)
		return ret;

	alg = cipherdata->alg;

	/* Check if all required keys are defined */
	if (alg->require_key & NEED_KEY1) {
		if (!dinit->key1.data || !dinit->key1.length)
			goto exit_init;

		retstatus = do_check_keysize(&alg->def_key, dinit->key1.length);
		if (retstatus != CAAM_NO_ERROR) {
			CIPHER_TRACE("Bad Key 1 size");
			goto exit_init;
		}

		/* Copy the key 1 */
		retstatus = copy_ctx_data(&cipherdata->key1, &dinit->key1);
		CIPHER_TRACE("Copy Key 1 returned 0x%" PRIx32, retstatus);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_init;
		}
	}

	if (alg->require_key & NEED_KEY2) {
		if (!dinit->key2.data || !dinit->key2.length)
			goto exit_init;

		retstatus = do_check_keysize(&alg->def_key, dinit->key2.length);
		if (retstatus != CAAM_NO_ERROR) {
			CIPHER_TRACE("Bad Key 2 size");
			goto exit_init;
		}

		/* Copy the key 2 */
		retstatus = copy_ctx_data(&cipherdata->key2, &dinit->key2);
		CIPHER_TRACE("Copy Key 2 returned 0x%" PRIx32, retstatus);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_init;
		}
	}

	if (alg->require_key & NEED_IV) {
		if (!dinit->iv.data || !dinit->iv.length)
			goto exit_init;

		if (dinit->iv.length != alg->size_ctx) {
			CIPHER_TRACE("Bad IV size %zu (expected %" PRId32 ")",
				     dinit->iv.length, alg->size_ctx);
			goto exit_init;
		}

		CIPHER_TRACE("Allocate CAAM Context Register (%" PRId32
			     " bytes)",
			     alg->size_ctx);

		/* Copy the IV into the context register */
		retstatus = copy_ctx_data(&cipherdata->ctx, &dinit->iv);
		CIPHER_TRACE("Copy IV returned 0x%" PRIx32, retstatus);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_init;
		}
	}

	if (alg->require_key & NEED_TWEAK) {
		/* This is accepted to start with a NULL Tweak */
		if (dinit->iv.length) {
			if (dinit->iv.length != alg->size_block) {
				CIPHER_TRACE("Bad tweak 2 size");
				goto exit_init;
			}

			/* Copy the tweak */
			retstatus = copy_ctx_data(&cipherdata->tweak,
						  &dinit->iv);
			CIPHER_TRACE("Copy Tweak returned 0x%" PRIx32,
				     retstatus);

			if (retstatus != CAAM_NO_ERROR) {
				ret = TEE_ERROR_OUT_OF_MEMORY;
				goto exit_init;
			}
		} else {
			/* Create tweak 0's */
			if (!cipherdata->tweak.data) {
				/*
				 * Allocate the destination buffer and
				 * fill it with 0's
				 */
				ret = caam_calloc_align_buf(&cipherdata->tweak,
							    alg->size_block);
				if (ret != CAAM_NO_ERROR)
					return ret;
			} else {
				/* Fill it with 0's */
				memset(cipherdata->tweak.data, 0,
				       cipherdata->tweak.length);

				/* Push data to physical memory */
				cache_operation(TEE_CACHEFLUSH,
						cipherdata->tweak.data,
						cipherdata->tweak.length);
			}
		}
	}

	/* Save the operation direction */
	cipherdata->encrypt = dinit->encrypt;
	cipherdata->blockbuf.filled = 0;

	ret = TEE_SUCCESS;

exit_init:
	/* Free the internal context in case of error */
	if (ret != TEE_SUCCESS)
		do_free_intern(cipherdata);

	return ret;
}

/*
 * Update of the cipher operation in streaming mode, meaning
 * doing partial intermediate block.
 * If there is a context, the context is saved only when a
 * full block is done.
 * The partial block (if not the last block) is encrypted or
 * decrypted to return the result and it's saved to be concatened
 * to next data to rebuild a full block.
 *
 * @dupdate  Data update object
 */
static TEE_Result do_update_streaming(struct drvcrypt_cipher_update *dupdate)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct cipherdata *ctx = dupdate->ctx;
	struct caamdmaobj *src = NULL;
	struct caamdmaobj *dst = NULL;
	struct caamdmaobj insrc = {};
	struct caamdmaobj indst = {};
	struct caamdmaobj srcblock = {};
	struct caamdmaobj dstblock = {};
	size_t fullSize = 0;
	size_t size_topost = 0;
	size_t size_todo = 0;
	size_t size_indone = 0;

	CIPHER_TRACE("Length=%zu - %s", dupdate->src.length,
		     ctx->encrypt ? "Encrypt" : "Decrypt");

	/* Calculate the total data to be handled */
	fullSize = ctx->blockbuf.filled + dupdate->src.length;
	if (fullSize < ctx->alg->size_block) {
		size_topost = dupdate->src.length;
	} else {
		size_topost = fullSize % ctx->alg->size_block;
		/* Total size that is a cipher block multiple */
		size_todo = fullSize - size_topost;
	}

	CIPHER_TRACE("FullSize %zu - posted %zu - todo %zu", fullSize,
		     size_topost, size_todo);

	/* If there is full block to do, do them first */
	if (size_todo) {
		size_indone = size_todo - ctx->blockbuf.filled;
		ret = caam_dmaobj_init_input(&insrc, dupdate->src.data,
					     size_indone);
		if (ret)
			goto end_streaming;

		ret = caam_dmaobj_init_output(&indst, dupdate->dst.data,
					      size_indone, size_indone);
		if (ret)
			goto end_streaming;

		/*
		 * If there are data saved in the temporary buffer,
		 * redo it to generate and increment cipher context.
		 */
		if (ctx->blockbuf.filled) {
			ret = caam_dmaobj_add_first_block(&srcblock,
							  &ctx->blockbuf,
							  &insrc);
			if (ret)
				goto end_streaming;

			ret = caam_dmaobj_add_first_block(&dstblock,
							  &ctx->blockbuf,
							  &indst);
			if (ret)
				goto end_streaming;

			ctx->blockbuf.filled = 0;

			src = &srcblock;
			dst = &dstblock;
		} else {
			src = &insrc;
			dst = &indst;
		}

		retstatus = caam_cipher_block(ctx, true, NEED_KEY1,
					      ctx->encrypt, src, dst);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto end_streaming;
		}

		/*
		 * Copy only the output corresponding to the
		 * encryption/decryption of the input data.
		 * Additional block is used to ensure that a complete
		 * cipher block is done.
		 */
		caam_dmaobj_copy_to_orig(&indst);
		caam_dmaobj_free(&insrc);
		caam_dmaobj_free(&indst);

		CIPHER_DUMPBUF("Source", dupdate->src.data,
			       dupdate->src.length - size_topost);
		CIPHER_DUMPBUF("Result", dupdate->dst.data,
			       dupdate->dst.length - size_topost);
	}

	if (size_topost) {
		CIPHER_TRACE("Save input data %zu bytes (done %zu)",
			     size_topost, size_indone);
		struct caambuf cpysrc = { .data = dupdate->src.data,
					  .length = dupdate->src.length };

		retstatus = caam_cpy_block_src(&ctx->blockbuf, &cpysrc,
					       size_indone);
		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto end_streaming;
		}

		ret = caam_dmaobj_init_input(&insrc,
					     dupdate->src.data + size_indone,
					     dupdate->src.length - size_indone);
		if (ret)
			goto end_streaming;

		ret = caam_dmaobj_init_output(&indst,
					      dupdate->dst.data + size_indone,
					      ctx->blockbuf.filled,
					      ctx->blockbuf.filled);
		if (ret)
			goto end_streaming;

		retstatus = caam_cipher_block(ctx, false, NEED_KEY1,
					      ctx->encrypt, &insrc, &indst);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto end_streaming;
		}

		caam_dmaobj_copy_to_orig(&indst);

		CIPHER_DUMPBUF("Source", ctx->blockbuf.buf.data,
			       ctx->blockbuf.filled);
		CIPHER_DUMPBUF("Result", dupdate->dst.data + size_indone,
			       ctx->blockbuf.filled);
	}

	ret = TEE_SUCCESS;

end_streaming:
	caam_dmaobj_free(&insrc);
	caam_dmaobj_free(&indst);
	caam_dmaobj_free(&srcblock);
	caam_dmaobj_free(&dstblock);

	return ret;
}

/*
 * Update of the cipher operation with complete block except
 * if last block. Last block can be partial block.
 *
 * @dupdate  Data update object
 */
static TEE_Result do_update_cipher(struct drvcrypt_cipher_update *dupdate)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct cipherdata *ctx = dupdate->ctx;
	struct caamdmaobj src = {};
	struct caamdmaobj dst = {};
	unsigned int nb_buf = 0;
	size_t offset = 0;

	CIPHER_TRACE("Length=%zu - %s", dupdate->src.length,
		     (ctx->encrypt ? "Encrypt" : "Decrypt"));

	/*
	 * Check the length of the payload/cipher to be at least
	 * one or n cipher block.
	 */
	if (dupdate->src.length < ctx->alg->size_block ||
	    dupdate->src.length % ctx->alg->size_block) {
		CIPHER_TRACE("Bad payload/cipher size %zu bytes",
			     dupdate->src.length);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	nb_buf = dupdate->dst.length / MAX_CIPHER_BUFFER;
	for (; nb_buf; nb_buf--) {
		ret = caam_dmaobj_init_input(&src, dupdate->src.data + offset,
					     MAX_CIPHER_BUFFER);
		if (ret)
			goto end_cipher;

		ret = caam_dmaobj_init_output(&dst, dupdate->dst.data + offset,
					      dupdate->dst.length - offset,
					      MAX_CIPHER_BUFFER);
		if (ret)
			goto end_cipher;

		CIPHER_TRACE("Do nb_buf=%" PRId32 ", offset %zu", nb_buf,
			     offset);
		retstatus = caam_cipher_block(ctx, true, NEED_KEY1,
					      ctx->encrypt, &src, &dst);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto end_cipher;
		}

		caam_dmaobj_copy_to_orig(&dst);

		offset += MAX_CIPHER_BUFFER;

		caam_dmaobj_free(&src);
		caam_dmaobj_free(&dst);
	}

	/*
	 * After doing all maximum block, finalize operation
	 * with the remaining data
	 */
	if (dupdate->src.length - offset > 0) {
		CIPHER_TRACE("Do Last %zu offset %zu",
			     dupdate->src.length - offset, offset);
		ret = caam_dmaobj_init_input(&src, dupdate->src.data + offset,
					     dupdate->src.length - offset);
		if (ret)
			goto end_cipher;

		ret = caam_dmaobj_init_output(&dst, dupdate->dst.data + offset,
					      dupdate->dst.length - offset,
					      dupdate->dst.length - offset);
		if (ret)
			goto end_cipher;

		retstatus = caam_cipher_block(ctx, true, NEED_KEY1,
					      ctx->encrypt, &src, &dst);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto end_cipher;
		}

		caam_dmaobj_copy_to_orig(&dst);
	}

	ret = TEE_SUCCESS;

end_cipher:
	caam_dmaobj_free(&src);
	caam_dmaobj_free(&dst);

	return ret;
}

/*
 * Update of the cipher operation for AES CTS mode.
 * Call the tee_aes_cbc_cts_update function that will either
 * call AES ECB/CBC algorithm.
 *
 * @dupdate  Data update object
 */
static TEE_Result do_update_cts(struct drvcrypt_cipher_update *dupdate)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct crypto_cipher *cipher_ctx = NULL;
	void *cipher_cbc = NULL;
	void *cipher_ecb = NULL;
	struct cipherdata *in_ctx = dupdate->ctx;
	struct cipherdata *ctx_cbc = NULL;
	struct cipherdata *ctx_ecb = NULL;

	CIPHER_TRACE("Algo AES CTS length=%zu - %s", dupdate->src.length,
		     (in_ctx->encrypt ? "Encrypt" : "Decrypt"));

	ret = crypto_cipher_alloc_ctx(&cipher_cbc, TEE_ALG_AES_CBC_NOPAD);
	if (ret != TEE_SUCCESS)
		goto end_update_cts;

	cipher_ctx = container_of(cipher_cbc, struct crypto_cipher, cipher_ctx);
	ctx_cbc = cipher_ctx->ctx;

	ret = crypto_cipher_alloc_ctx(&cipher_ecb, TEE_ALG_AES_ECB_NOPAD);
	if (ret != TEE_SUCCESS)
		goto end_update_cts;

	cipher_ctx = container_of(cipher_ecb, struct crypto_cipher, cipher_ctx);
	ctx_ecb = cipher_ctx->ctx;

	ctx_cbc->key1.data = in_ctx->key1.data;
	ctx_cbc->key1.length = in_ctx->key1.length;
	ctx_cbc->key1.paddr = in_ctx->key1.paddr;
	ctx_cbc->key1.nocache = in_ctx->key1.nocache;

	ctx_cbc->ctx.data = in_ctx->ctx.data;
	ctx_cbc->ctx.length = in_ctx->ctx.length;
	ctx_cbc->ctx.paddr = in_ctx->ctx.paddr;
	ctx_cbc->ctx.nocache = in_ctx->ctx.nocache;

	ctx_ecb->key1.data = in_ctx->key1.data;
	ctx_ecb->key1.length = in_ctx->key1.length;
	ctx_ecb->key1.paddr = in_ctx->key1.paddr;
	ctx_ecb->key1.nocache = in_ctx->key1.nocache;

	ctx_cbc->encrypt = in_ctx->encrypt;
	ctx_cbc->blockbuf.filled = 0;
	ctx_ecb->encrypt = in_ctx->encrypt;
	ctx_ecb->blockbuf.filled = 0;

	ret = tee_aes_cbc_cts_update(cipher_cbc, cipher_ecb,
				     in_ctx->encrypt ? TEE_MODE_ENCRYPT :
						       TEE_MODE_DECRYPT,
				     dupdate->last, dupdate->src.data,
				     dupdate->src.length, dupdate->dst.data);

	ctx_cbc->key1.data = NULL;
	ctx_cbc->key1.length = 0;
	ctx_cbc->ctx.data = NULL;
	ctx_cbc->ctx.length = 0;
	ctx_ecb->key1.data = NULL;
	ctx_ecb->key1.length = 0;

end_update_cts:
	crypto_cipher_free_ctx(cipher_cbc, TEE_ALG_AES_CBC_NOPAD);
	crypto_cipher_free_ctx(cipher_ecb, TEE_ALG_AES_ECB_NOPAD);

	return ret;
}

/*
 * Update of the cipher operation. Call the algorithm update
 * function associated.
 *
 * @dupdate  Data update object
 */
static TEE_Result do_update(struct drvcrypt_cipher_update *dupdate)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct cipherdata *cipherdata = dupdate->ctx;

	ret = cipherdata->alg->update(dupdate);

	return ret;
}

/*
 * Finalize of the cipher operation
 *
 * @ctx    Caller context variable
 */
static void do_final(void *ctx __unused)
{
}

/*
 * Registration of the Cipher Driver
 */
static struct drvcrypt_cipher driver_cipher = {
	.alloc_ctx = do_allocate,
	.free_ctx = caam_cipher_free,
	.init = caam_cipher_initialize,
	.update = do_update,
	.final = do_final,
	.copy_state = caam_cipher_copy_state,
};

/*
 * Initialize the Cipher module
 *
 * @ctrl_addr   Controller base address
 */
enum caam_status caam_cipher_init(vaddr_t ctrl_addr __unused)
{
	enum caam_status retstatus = CAAM_FAILURE;

	if (drvcrypt_register_cipher(&driver_cipher) == TEE_SUCCESS)
		retstatus = CAAM_NO_ERROR;

	return retstatus;
}
