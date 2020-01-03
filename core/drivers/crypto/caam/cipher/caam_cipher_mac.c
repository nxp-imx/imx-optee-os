// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2020 NXP
 *
 * Brief   CAAM Cipher manager.
 *         Implementation of Cipher MAC functions
 */
#include <caam_cipher.h>
#include <caam_common.h>
#include <caam_jr.h>
#include <caam_utils_mem.h>
#include <caam_utils_sgt.h>
#include <caam_utils_status.h>
#include <drvcrypt_mac.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>
#include <utee_defines.h>

#include "local.h"

static TEE_Result do_update_mac(struct drvcrypt_cipher_update *dupdate);
static TEE_Result do_update_cmac(struct drvcrypt_cipher_update *dupdate);

/*
 * Constants definition of the AES MAC algorithm
 */
static const struct cipheralg aes_mac_alg[] = {
	{
		/* AES CBC MAC */
		.type = OP_ALGO(AES) | ALGO_AAI(AES_CBC),
		.size_block = TEE_AES_BLOCK_SIZE,
		.size_ctx = 2 * sizeof(uint64_t),
		.ctx_offset = 0,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key = { .min = 16, .max = 32, .mod = 8 },
		.update = do_update_mac,
	},
	{
		/* AES CMAC */
		.type = OP_ALGO(AES) | ALGO_AAI(AES_CMAC),
		.size_block = TEE_AES_BLOCK_SIZE,
		.size_ctx = 4 * sizeof(uint64_t),
		.ctx_offset = 0,
		.require_key = NEED_KEY1,
		.def_key = { .min = 16, .max = 32, .mod = 8 },
		.update = do_update_cmac,
	},
};

/*
 * Constants definition of the DES MAC algorithm
 */
static const struct cipheralg des_mac_alg[] = {
	{
		/* DES CBC MAC */
		.type = OP_ALGO(DES) | ALGO_AAI(DES_CBC),
		.size_block = TEE_DES_BLOCK_SIZE,
		.size_ctx = sizeof(uint64_t),
		.ctx_offset = 0,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key = { .min = 8, .max = 8, .mod = 8 },
		.update = do_update_mac,
	},
};

/*
 * Constants definition of the DES3 MAC algorithm
 */
static const struct cipheralg des3_mac_alg[] = {
	{
		/* Triple-DES CBC MAC */
		.type = OP_ALGO(3DES) | ALGO_AAI(DES_CBC),
		.size_block = TEE_DES_BLOCK_SIZE,
		.size_ctx = sizeof(uint64_t),
		.ctx_offset = 0,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key = { .min = 16, .max = 24, .mod = 8 },
		.update = do_update_mac,
	},
};

static const struct crypto_mac_ops cmac_ops;

/*
 * Format the mac context to keep the reference to the
 * operation driver
 */
struct crypto_mac {
	struct crypto_mac_ctx mac_ctx; /* Crypto mac API context */
	struct cipherdata *ctx;	       /* Cmac Context */
};

/*
 * Returns the reference to the driver context
 *
 * @ctx  API Context
 */
static struct crypto_mac *to_mac_ctx(struct crypto_mac_ctx *ctx)
{
	assert(ctx && ctx->ops == &cmac_ops);

	return container_of(ctx, struct crypto_mac, mac_ctx);
}

/*
 * Checks if the algorithm @algo is supported and returns the
 * local algorithm entry in the corresponding cipher array
 *
 * @algo  Algorithm ID
 */
static const struct cipheralg *get_macalgo(uint32_t algo)
{
	unsigned int algo_id = TEE_ALG_GET_MAIN_ALG(algo);
	unsigned int algo_md = TEE_ALG_GET_CHAIN_MODE(algo);
	const struct cipheralg *alg = NULL;

	switch (algo_id) {
	case TEE_MAIN_ALGO_AES:
		alg = aes_mac_alg;
		if (algo_md == TEE_CHAIN_MODE_CMAC)
			return &alg[1];
		break;

	case TEE_MAIN_ALGO_DES:
		alg = des_mac_alg;
		break;

	case TEE_MAIN_ALGO_DES3:
		alg = des3_mac_alg;
		break;

	default:
		return NULL;
	}

	if (algo_md != TEE_CHAIN_MODE_CBC_NOPAD &&
	    algo_md != TEE_CHAIN_MODE_CBC_MAC_PKCS5) {
		CIPHER_TRACE("ALGO MD=%d", algo_md);
		alg = NULL;
	}

	return alg;
}

/*
 * Increment the buffer of @inc value.
 * Check if the next data is crossing a small page to get the
 * physical address of the next data with the virt_to_phys function.
 * Otherwise increment the buffer's physical address of @inc value.
 *
 * @buf   Buffer to increment
 * @inc   Increment
 */
static inline void inc_mac_buffer(struct caambuf *buf, size_t inc)
{
	vaddr_t prev = (vaddr_t)buf->data;
	vaddr_t next = prev + inc;

	buf->data += inc;

	if ((prev & SMALL_PAGE_MASK) > (next & SMALL_PAGE_MASK))
		buf->paddr = virt_to_phys(buf->data);
	else
		buf->paddr += inc;
}

/*
 * MAC update of the cipher operation of complete block except
 * if last block. Last block can be partial block.
 *
 * @dupdate  Data update object
 */
static TEE_Result do_update_mac(struct drvcrypt_cipher_update *dupdate)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;
	enum caam_status retstatus = CAAM_FAILURE;
	struct cipherdata *ctx = dupdate->ctx;
	struct caambuf srcbuf = {};
	struct caambuf dst_align = {};
	size_t fullSize = 0;
	size_t size_topost = 0;
	size_t size_todo = 0;
	int realloc = 0;

	CIPHER_TRACE("Length=%zu - %s", dupdate->src.length,
		     ctx->encrypt ? "Encrypt" : " Decrypt");

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

	if (dupdate->src.length) {
		srcbuf.data = dupdate->src.data;
		srcbuf.paddr = virt_to_phys(dupdate->src.data);

		if (!srcbuf.paddr) {
			CIPHER_TRACE("Bad src address");
			return TEE_ERROR_GENERIC;
		}

		if (!caam_mem_is_cached_buf(dupdate->src.data,
					    dupdate->src.length))
			srcbuf.nocache = 1;
	}

	if (!size_todo) {
		/*
		 * There is no complete block to do:
		 *   - either input size + already saved data < block size
		 *   - or no input data and this is the last block
		 */
		if (dupdate->last)
			memcpy(dupdate->dst.data, ctx->ctx.data,
			       MIN(dupdate->dst.length, ctx->alg->size_ctx));

		goto final_mac_update;
	}

	if (dupdate->last) {
		realloc = caam_set_or_alloc_align_buf(dupdate->dst.data,
						      &dst_align,
						      ctx->alg->size_ctx);
		if (realloc == -1) {
			CIPHER_TRACE("Dest buffer reallocation error");
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto end_mac;
		}
	}

	/*
	 * Check first if there is some data saved to complete the
	 * buffer.
	 */
	if (ctx->blockbuf.filled) {
		srcbuf.length = ctx->alg->size_block - ctx->blockbuf.filled;

		if (dupdate->last)
			retstatus = caam_cipher_block(ctx, true, NEED_KEY1,
						      true, &srcbuf, &dst_align,
						      CIPHER_BLOCK_IN);
		else
			retstatus = caam_cipher_block(ctx, true, NEED_KEY1,
						      true, &srcbuf, NULL,
						      CIPHER_BLOCK_IN);

		ctx->blockbuf.filled = 0;
		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto end_mac;
		}

		size_todo -= ctx->alg->size_block;

		if (size_todo || size_topost)
			inc_mac_buffer(&srcbuf, srcbuf.length);
	}

	srcbuf.length = ctx->alg->size_block;

	while (size_todo) {
		if (dupdate->last)
			retstatus = caam_cipher_block(ctx, true, NEED_KEY1,
						      true, &srcbuf, &dst_align,
						      CIPHER_BLOCK_NONE);
		else
			retstatus = caam_cipher_block(ctx, true, NEED_KEY1,
						      true, &srcbuf, NULL,
						      CIPHER_BLOCK_NONE);
		if (retstatus != CAAM_NO_ERROR)
			return TEE_ERROR_GENERIC;

		size_todo -= ctx->alg->size_block;

		if (size_todo || size_topost)
			inc_mac_buffer(&srcbuf, srcbuf.length);
	};

	if (dst_align.data) {
		if (!dst_align.nocache)
			cache_operation(TEE_CACHEINVALIDATE, dst_align.data,
					dst_align.length);

		if (realloc)
			memcpy(dupdate->dst.data, dst_align.data,
			       MIN(dupdate->dst.length, dst_align.length));
	}

final_mac_update:
	ret = TEE_SUCCESS;

	if (size_topost) {
		CIPHER_TRACE("Save input data %zu bytes of %zu", size_topost,
			     dupdate->src.length);

		struct caambuf cpysrc = { .data = srcbuf.data,
					  .length = size_topost };

		retstatus = caam_cpy_block_src(&ctx->blockbuf, &cpysrc, 0);
		if (retstatus != CAAM_NO_ERROR)
			ret = TEE_ERROR_GENERIC;
	}

end_mac:
	if (realloc == 1)
		caam_free_buf(&dst_align);

	return ret;
}

/*
 * Build and run the Cipher MAC descriptor (AES only)
 *
 * @ctx     Cipher Data context
 * @srcbuf  Input data
 * @dstbuf  [out] Output data if last block
 * @last    Last block flag
 */
static TEE_Result run_cmac_desc(struct cipherdata *ctx, struct caambuf *srcbuf,
				struct caambuf *dstbuf, bool last)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_jobctx jobctx = {};
	uint32_t *desc = NULL;
	struct caamsgtbuf src_sgt = { .sgt_type = false };
	struct caamsgtbuf dst_sgt = { .sgt_type = false };

	desc = ctx->descriptor;
	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));

	if (last) {
		retstatus = caam_sgt_build_block_data(&dst_sgt, NULL, dstbuf);
		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto end_run_cmac;
		}
	}

	if (ctx->alg->require_key & NEED_KEY1) {
		/* Build the descriptor */
		caam_desc_add_word(desc, LD_KEY_PLAIN(CLASS_1, REG,
						      ctx->key1.length));
		caam_desc_add_ptr(desc, ctx->key1.paddr);
	}

	/* If context already allocated, this is an update */
	if (ctx->ctx.length) {
		CIPHER_TRACE("%s Operation", last ? "Final" : "Update");
		caam_desc_add_word(desc, LD_NOIMM_OFF(CLASS_1, REG_CTX,
						      ctx->ctx.length,
						      ctx->alg->ctx_offset));
		caam_desc_add_ptr(desc, ctx->ctx.paddr);
		if (last)
			caam_desc_add_word(desc,
					   CIPHER_FINAL(ctx->alg->type, true));
		else
			caam_desc_add_word(desc,
					   CIPHER_UPDATE(ctx->alg->type, true));
	} else if (last) {
		CIPHER_TRACE("Init/Final Operation");

		caam_desc_add_word(desc,
				   CIPHER_INITFINAL(ctx->alg->type, true));
	} else {
		CIPHER_TRACE("Init Operation");

		caam_desc_add_word(desc, CIPHER_INIT(ctx->alg->type, true));
		if (!ctx->ctx.data) {
			retstatus = caam_alloc_align_buf(&ctx->ctx,
							 ctx->alg->size_ctx);
			if (retstatus != CAAM_NO_ERROR) {
				ret = TEE_ERROR_OUT_OF_MEMORY;
				goto end_run_cmac;
			}
		}
	}

	/*
	 * Check first if there is some data saved to complete the
	 * buffer.
	 */
	if (ctx->blockbuf.filled) {
		/* Add the temporary buffer */
		if (srcbuf->length)
			caam_desc_add_word(desc,
					   FIFO_LD_EXT(CLASS_1, MSG, NOACTION));
		else
			caam_desc_add_word(desc,
					   FIFO_LD_EXT(CLASS_1, MSG, LAST_C1));

		caam_desc_add_ptr(desc, ctx->blockbuf.buf.paddr);
		caam_desc_add_word(desc, ctx->blockbuf.filled);

		/* Clean the circular buffer data to be loaded */
		cache_operation(TEE_CACHECLEAN, ctx->blockbuf.buf.data,
				ctx->blockbuf.filled);
	}

	if (srcbuf->length) {
		retstatus = caam_sgt_build_block_data(&src_sgt, NULL, srcbuf);
		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_GENERIC;
			goto end_run_cmac;
		}

		if (src_sgt.sgt_type) {
			/* Add the input data multiple of blocksize */
			caam_desc_add_word(desc, FIFO_LD_SGT_EXT(CLASS_1, MSG,
								 LAST_C1));
			caam_desc_add_ptr(desc, virt_to_phys(src_sgt.sgt));
			caam_desc_add_word(desc, srcbuf->length);

			caam_sgt_cache_op(TEE_CACHECLEAN, &src_sgt);
		} else {
			/* Add the input data multiple of blocksize */
			caam_desc_add_word(desc,
					   FIFO_LD_EXT(CLASS_1, MSG, LAST_C1));
			caam_desc_add_ptr(desc, srcbuf->paddr);
			caam_desc_add_word(desc, srcbuf->length);

			cache_operation(TEE_CACHECLEAN, srcbuf->data,
					srcbuf->length);
		}
	} else {
		if (last && !ctx->blockbuf.filled) {
			/*
			 * Add the input data of 0 bytes to start
			 * algorithm by setting the input data size
			 */
			caam_desc_add_word(desc,
					   FIFO_LD(CLASS_1, MSG, LAST_C1, 0));
			caam_desc_add_ptr(desc, 0);
		}
	}

	ctx->blockbuf.filled = 0;

	if (last) {
		if (dst_sgt.sgt_type) {
			caam_desc_add_word(desc, ST_SGT_NOIMM(CLASS_1, REG_CTX,
							      dst_sgt.length));
			caam_desc_add_ptr(desc, virt_to_phys(dst_sgt.sgt));

			caam_sgt_cache_op(TEE_CACHEFLUSH, &dst_sgt);
		} else {
			caam_desc_add_word(desc, ST_NOIMM(CLASS_1, REG_CTX,
							  dst_sgt.length));
			caam_desc_add_ptr(desc, dst_sgt.buf->paddr);

			if (!dst_sgt.buf->nocache)
				cache_operation(TEE_CACHEFLUSH,
						dst_sgt.buf->data,
						dst_sgt.length);
		}
	} else {
		/* Store the context */
		caam_desc_add_word(desc, ST_NOIMM_OFF(CLASS_1, REG_CTX,
						      ctx->ctx.length,
						      ctx->alg->ctx_offset));
		caam_desc_add_ptr(desc, ctx->ctx.paddr);
	}

	CIPHER_DUMPDESC(desc);

	/* Invalidate Context register */
	if (ctx->ctx.length)
		cache_operation(TEE_CACHEINVALIDATE, ctx->ctx.data,
				ctx->ctx.length);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		ret = TEE_SUCCESS;

		if (!dstbuf->nocache)
			cache_operation(TEE_CACHEINVALIDATE, dstbuf->data,
					dstbuf->length);
	} else {
		CIPHER_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

end_run_cmac:
	if (src_sgt.sgt_type)
		caam_sgtbuf_free(&src_sgt);

	if (dst_sgt.sgt_type)
		caam_sgtbuf_free(&dst_sgt);

	return ret;
}

/*
 * Update of the cipher CMAC operation of complete block except
 * if last block. Last block can be partial block.
 *
 * @dupdate  Data update object
 */
static TEE_Result do_update_cmac(struct drvcrypt_cipher_update *dupdate)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;
	struct cipherdata *ctx = dupdate->ctx;
	size_t fullSize = 0;
	size_t size_topost = 0;
	size_t size_todo = 0;
	size_t size_inmade = 0;
	struct caambuf srcbuf = {};
	int realloc = 0;
	struct caambuf dst_align = {};

	CIPHER_TRACE("Length=%zu - %s", dupdate->src.length,
		     dupdate->encrypt ? "Encrypt" : " Decrypt");

	if (dupdate->src.length) {
		srcbuf.data = dupdate->src.data;
		srcbuf.length = dupdate->src.length;
		srcbuf.paddr = virt_to_phys(dupdate->src.data);

		if (!srcbuf.paddr) {
			CIPHER_TRACE("Bad Src address");
			return TEE_ERROR_GENERIC;
		}

		if (!caam_mem_is_cached_buf(dupdate->src.data,
					    dupdate->src.length))
			srcbuf.nocache = 1;
	}

	if (dupdate->last) {
		realloc = caam_set_or_alloc_align_buf(dupdate->dst.data,
						      &dst_align,
						      dupdate->dst.length);
		if (realloc == -1) {
			CIPHER_TRACE("Destination buffer reallocation error");
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto end_cmac;
		}
	}

	/* Calculate the total data to be handled */
	fullSize = ctx->blockbuf.filled + srcbuf.length;
	if (!dupdate->last) {
		if (fullSize < ctx->alg->size_block) {
			size_topost = srcbuf.length;
		} else {
			size_topost = fullSize % ctx->alg->size_block;

			/*
			 * In case there is no data to save and because it's
			 * not the final operation, ensure that a block of data
			 * is kept for the final operation.
			 */
			if (!size_topost)
				size_topost = ctx->alg->size_block;

			/* Total size that is a cipher block multiple */
			size_todo = fullSize - size_topost;
		}
	}

	CIPHER_TRACE("FullSize %zu - posted %zu - todo %zu", fullSize,
		     size_topost, size_todo);

	if (size_todo || dupdate->last) {
		size_inmade = srcbuf.length - size_topost;
		srcbuf.length = size_inmade;

		ret = run_cmac_desc(ctx, &srcbuf, &dst_align, dupdate->last);

		srcbuf.length = dupdate->src.length;

		if (ret == TEE_SUCCESS && dupdate->last && realloc)
			memcpy(dupdate->dst.data, dst_align.data,
			       dupdate->dst.length);
	} else {
		ret = TEE_SUCCESS;
	}

	if (size_topost) {
		CIPHER_TRACE("Post %zu of input len %zu made %zu", size_topost,
			     srcbuf.length, size_inmade);
		if (caam_cpy_block_src(&ctx->blockbuf, &srcbuf, size_inmade) !=
		    CAAM_NO_ERROR)
			ret = TEE_ERROR_GENERIC;
	}

end_cmac:
	if (realloc == 1)
		caam_free_buf(&dst_align);

	return ret;
}

/*
 * Initialization of the Cipher MAC operation.
 *
 * @ctx  Operation Software context
 * @key  Input key to compute
 * @len  Key length
 */
static TEE_Result do_cmac_init(struct crypto_mac_ctx *ctx, const uint8_t *key,
			       size_t len)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	uint8_t *iv_tmp = NULL;
	struct drvcrypt_cipher_init dinit = {};
	struct crypto_mac *mac = to_mac_ctx(ctx);
	struct cipherdata *macdata = mac->ctx;

	if (macdata->mode != TEE_CHAIN_MODE_CMAC) {
		/* Allocate temporary IV initialize with 0's */
		iv_tmp = caam_calloc(macdata->alg->size_ctx);
		if (!iv_tmp)
			return TEE_ERROR_OUT_OF_MEMORY;
	} else {
		/*
		 * Check if the context registers is allocated to free it,
		 * because in case of CMAC mode, the context registers
		 * is allocated during do_update_cmac operation if
		 * necessary.
		 */
		if (macdata->ctx.data)
			caam_free_buf(&macdata->ctx);
	}

	macdata->countdata = 0;

	/* Prepare the initialization data */
	dinit.ctx = macdata;
	dinit.encrypt = true;
	dinit.key1.data = (uint8_t *)key;
	dinit.key1.length = len;
	dinit.key2.data = NULL;
	dinit.key2.length = 0;
	dinit.iv.data = iv_tmp;
	dinit.iv.length = macdata->alg->size_ctx;
	ret = caam_cipher_initialize(&dinit);

	caam_free(iv_tmp);

	return ret;
}

/*
 * Update of the cipher MAC operation.
 *
 * @ctx   Operation Software context
 * @data  Data to encrypt
 * @len   Data length
 */
static TEE_Result do_cmac_update(struct crypto_mac_ctx *ctx,
				 const uint8_t *data, size_t len)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct crypto_mac *mac = to_mac_ctx(ctx);
	struct cipherdata *macdata = mac->ctx;
	struct drvcrypt_cipher_update dupdate = {};

	/* Prepare the update data */
	dupdate.ctx = macdata;
	dupdate.encrypt = true;
	dupdate.last = false;
	dupdate.src.data = (uint8_t *)data;
	dupdate.src.length = len;
	dupdate.dst.data = NULL;
	dupdate.dst.length = 0;

	ret = macdata->alg->update(&dupdate);

	if (ret == TEE_SUCCESS &&
	    macdata->mode == TEE_CHAIN_MODE_CBC_MAC_PKCS5) {
		macdata->countdata += len;
	}

	return ret;
}

/*
 * Finalize the MAC operation
 *
 * @ctx     Operation Software context
 * @len     Digest buffer length
 * @digest  [out] Digest buffer
 */
static TEE_Result do_cmac_final(struct crypto_mac_ctx *ctx, uint8_t *digest,
				size_t len)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	uint8_t *pad_src = NULL;
	size_t pad_size = 0;
	struct crypto_mac *mac = to_mac_ctx(ctx);
	struct cipherdata *macdata = mac->ctx;
	struct drvcrypt_cipher_update dupdate = {};

	/* Check if the digest size is big enough */
	if (len < macdata->alg->size_block)
		return TEE_ERROR_SHORT_BUFFER;

	if (macdata->mode == TEE_CHAIN_MODE_CBC_MAC_PKCS5) {
		/* Calculate the last block PAD Size */
		pad_size = macdata->alg->size_block;
		pad_size -= macdata->countdata % macdata->alg->size_block;
		CIPHER_TRACE("Pad size = %zu", pad_size);

		if (pad_size) {
			/* Need to pad the last block */
			pad_src = caam_calloc(pad_size);

			if (!pad_src) {
				CIPHER_TRACE("Pad src allocation error");
				return TEE_ERROR_OUT_OF_MEMORY;
			}

			memset(pad_src, pad_size, pad_size);
		}
	}

	/* Prepare the update data */
	dupdate.ctx = macdata;
	dupdate.encrypt = true;
	dupdate.last = true;
	dupdate.src.data = pad_src;
	dupdate.src.length = pad_size;
	dupdate.dst.data = digest;
	dupdate.dst.length = len;

	ret = macdata->alg->update(&dupdate);

	if (pad_src)
		caam_free(pad_src);

	return ret;
}

/*
 * Free the SW hashing data context
 * Call common free operation between cipher and cmac
 *
 * @ctx    [in/out] Caller context variable
 */
static void do_cmac_free(struct crypto_mac_ctx *ctx)
{
	struct crypto_mac *mac = to_mac_ctx(ctx);

	caam_cipher_free(mac->ctx);

	free(mac);
}

/*
 * Copy Software Cipher MAC Context
 *
 * @src_ctx  Reference the context source
 * @dst_ctx  [out] Reference the context destination
 */
static void do_cmac_copy_state(struct crypto_mac_ctx *dst_ctx,
			       struct crypto_mac_ctx *src_ctx)
{
	struct crypto_mac *mac_src = to_mac_ctx(src_ctx);
	struct crypto_mac *mac_dst = to_mac_ctx(dst_ctx);
	struct cipherdata *macdata_dst = mac_dst->ctx;
	struct cipherdata *macdata_src = mac_src->ctx;

	caam_cipher_copy_state(macdata_dst, macdata_src);

	macdata_dst->countdata = macdata_src->countdata;
	macdata_dst->mode = macdata_src->mode;
}

/*
 * Registration of the cmac Driver
 */
static const struct crypto_mac_ops cmac_ops = {
	.init = do_cmac_init,
	.update = do_cmac_update,
	.final = do_cmac_final,
	.free_ctx = do_cmac_free,
	.copy_state = do_cmac_copy_state,
};

/*
 * Allocate the SW cipher data context
 *
 * @ctx      [out] Caller context variable
 * @algo_id  Algorithm ID of the context
 * @algo_md  MAC Mode of the context
 */
static TEE_Result caam_cmac_allocate(struct crypto_mac_ctx **ctx, uint32_t algo)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct crypto_mac *mac = NULL;
	const struct cipheralg *alg = NULL;
	struct cipherdata *macdata = NULL;

	CIPHER_TRACE("Allocate Context (%p) algo %" PRIx32, ctx, algo);

	alg = get_macalgo(algo);
	if (!alg) {
		CIPHER_TRACE("Algorithm not supported");
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	mac = calloc(1, sizeof(*mac));
	if (!mac)
		return TEE_ERROR_OUT_OF_MEMORY;

	macdata = caam_calloc(sizeof(*macdata));
	if (!macdata) {
		CIPHER_TRACE("Allocation mac data error");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto err_allocate;
	}

	/* Allocate the descriptor */
	macdata->descriptor = caam_calloc_desc(MAX_DESC_ENTRIES);
	if (!macdata->descriptor) {
		CIPHER_TRACE("Allocation descriptor error");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto err_allocate;
	}

	/* Setup the Algorithm pointer */
	macdata->alg = alg;

	/* Initialize the block buffer */
	macdata->blockbuf.max = alg->size_block;

	/* Keep the MAC mode */
	macdata->mode = TEE_ALG_GET_CHAIN_MODE(algo);

	mac->mac_ctx.ops = &cmac_ops;
	mac->ctx = macdata;

	*ctx = &mac->mac_ctx;

	return TEE_SUCCESS;

err_allocate:
	if (macdata)
		caam_free_desc(&macdata->descriptor);

	caam_free(macdata);
	free(mac);

	return ret;
}

/*
 * Initialize the Cipher MAC module
 *
 * Inputs:
 * ctrl_addr   Controller base address
 */
enum caam_status caam_cmac_init(vaddr_t ctrl_addr __unused)
{
	enum caam_status retstatus = CAAM_FAILURE;

	if (drvcrypt_register(CRYPTO_CMAC, &caam_cmac_allocate) == 0)
		retstatus = CAAM_NO_ERROR;

	return retstatus;
}
