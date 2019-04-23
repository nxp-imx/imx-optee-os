// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    caam_cipher_cmac.c
 *
 * @brief   CAAM Cipher CMAC algorithm.\n
 *          Implementation of Cipher CMAC functions
 */

/* Standard includes */
#include <string.h>

/* Global includes */
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <tee/cache.h>

/* Local includes */
#include "common.h"
#include "caam_jr.h"
#include "local.h"

/* Utils includes */
#include "utils_mem.h"
#include "utils_status.h"

/**
 * @brief   Update of the cipher CMAC operation of complete block except
 *          if last block. Last block can be partial block.
 *
 * @param[in] dupdate  Data update object
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad Parameters
 * @retval TEE_ERROR_SHORT_BUFFER    Output buffer too short
 * @retval TEE_ERROR_OUT_OF_MEMORY   Out of memory
 */
TEE_Result do_update_cmac(struct nxpcrypt_cipher_update *dupdate)
{
	TEE_Result       ret = TEE_ERROR_BAD_PARAMETERS;
	enum CAAM_Status retstatus;

	struct cipherdata *ctx = dupdate->ctx;

	struct jr_jobctx jobctx = {0};
	descPointer_t    desc;
	uint8_t          desclen = 0;

	size_t fullSize;
	size_t size_topost;
	size_t size_todo;
	size_t size_inmade;

	paddr_t psrc = 0;

	int realloc = 0;
	struct caambuf dst_align = {0};

	CIPHER_TRACE("Algo %d length=%d - %s", ctx->algo_id,
				dupdate->src.length,
				(dupdate->encrypt ? "Encrypt" : " Decrypt"));

	if ((dupdate->src.length) && (!dupdate->src.data))
		return ret;

	if (dupdate->src.length) {
		psrc = virt_to_phys(dupdate->src.data);
		if (!psrc) {
			CIPHER_TRACE("Bad Src address");
			return TEE_ERROR_GENERIC;
		}
	}

	if (dupdate->last) {
		if (!dupdate->dst.data)
			return ret;

		/* Check if the digest size is big enough */
		if (dupdate->dst.length < ctx->alg->size_block)
			return TEE_ERROR_SHORT_BUFFER;

		realloc = caam_realloc_align(dupdate->dst.data, &dst_align,
				dupdate->dst.length);
		if (realloc == (-1)) {
			CIPHER_TRACE("Destination buffer reallocation error");
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto end_cmac;
		}
	}

	/* Calculate the total data to be handled */
	fullSize = ctx->blockbuf.filled + dupdate->src.length;

	if (dupdate->last) {
		size_topost = 0;
	} else {
		size_topost = fullSize % ctx->alg->size_block;
		if (size_topost == 0)
			size_topost = ctx->alg->size_block;
	}

	/* Total size that is a cipher block multiple */
	size_todo   = fullSize - size_topost;
	size_inmade = dupdate->src.length - size_topost;

	CIPHER_TRACE("FullSize %d - posted %d - todo %d",
			fullSize, size_topost, size_todo);

	if ((size_todo) || (dupdate->last)) {
		desc = ctx->descriptor;
		desc_init(desc);
		desc_add_word(desc, DESC_HEADER(0));

		if (ctx->alg->require_key & NEED_KEY1) {
			/* Build the descriptor */
			desc_add_word(desc, LD_KEY_PLAIN(CLASS_1, REG,
				ctx->key1.length));
			desc_add_ptr(desc, ctx->key1.paddr);
		}

		/* If context already allocated, this is an update */
		if (ctx->ctx.length) {
			CIPHER_TRACE("%s Operation",
					(dupdate->last ? "Final" : "Update"));
			desc_add_word(desc, LD_NOIMM_OFF(CLASS_1, REG_CTX,
				ctx->ctx.length, ctx->alg->ctx_offset));
			desc_add_ptr(desc, ctx->ctx.paddr);
			if (dupdate->last)
				desc_add_word(desc, CIPHER_FINAL(ctx->alg->type,
					true));
			else
				desc_add_word(desc, CIPHER_UPDATE(ctx->alg->type,
					true));
		} else {
			CIPHER_TRACE("%s Operation",
					(dupdate->last ? "Init/Final" : "Init"));
			/* Allocate the CAAM Context register */
			retstatus = caam_alloc_align_buf(&ctx->ctx,
				ctx->alg->size_ctx);
			if (retstatus != CAAM_NO_ERROR) {
				CIPHER_TRACE("Allocation context error");
				return TEE_ERROR_GENERIC;
			}

			if (dupdate->last) {
				desc_add_word(desc, CIPHER_INITFINAL(
					ctx->alg->type, true));
			} else {
				desc_add_word(desc, CIPHER_INIT(ctx->alg->type,
					true));
			}
		}

		/*
		 * Check first if there is some data saved to complete the
		 * buffer.
		 */
		if (ctx->blockbuf.filled != 0) {
			/* Add the temporary buffer */
			if (size_inmade) {
				desc_add_word(desc, FIFO_LD_EXT(CLASS_1, MSG,
					NOACTION));
			} else {
				desc_add_word(desc, FIFO_LD_EXT(CLASS_1, MSG,
					LAST_C1));
			}

			desc_add_ptr(desc, ctx->blockbuf.buf.paddr);
			desc_add_word(desc, ctx->blockbuf.filled);

			/* Clean the circular buffer data to be loaded */
			cache_operation(TEE_CACHECLEAN,
					ctx->blockbuf.buf.data,
					ctx->blockbuf.filled);
		}

		if (size_inmade) {
			/* Add the input data multiple of blocksize */
			desc_add_word(desc, FIFO_LD_EXT(CLASS_1, MSG, LAST_C1));
			desc_add_ptr(desc, psrc);
			desc_add_word(desc, size_inmade);
			if (dupdate->src.length) {
				/* Clean the input data to be loaded */
				cache_operation(TEE_CACHECLEAN,
					(void *)dupdate->src.data,
					size_inmade);
			}
		} else {
			if ((dupdate->last) && (ctx->blockbuf.filled == 0)) {
				/*
				 * Add the input data of 0 bytes to start
				 * algorithm by setting the input data size
				 */
				desc_add_word(desc, FIFO_LD(CLASS_1, MSG,
					LAST_C1, 0));
				desc_add_ptr(desc, 0);
			}
		}

		ctx->blockbuf.filled = 0;
		if (dupdate->last) {
			desc_add_word(desc, ST_NOIMM_OFF(CLASS_1, REG_CTX,
						dupdate->dst.length, 0));
			desc_add_ptr(desc, dst_align.paddr);
		} else {
			/* Store the context */
			desc_add_word(desc, ST_NOIMM_OFF(CLASS_1, REG_CTX,
						ctx->ctx.length,
						ctx->alg->ctx_offset));
			desc_add_ptr(desc, ctx->ctx.paddr);
		}

		desclen = desc_get_len(desc);
		if (desclen > MAX_DESC_ENTRIES)	{
			CIPHER_TRACE("Descriptor Size too short (%d vs %d)",
						desclen, MAX_DESC_ENTRIES);
			panic();
		}

		CIPHER_DUMPDESC(desc);

		if (dupdate->last) {
			/* Flush the destination register */
			if (dst_align.nocache == 0)
				cache_operation(TEE_CACHEFLUSH, dst_align.data,
							dupdate->dst.length);
		}

		if (ctx->ctx.length) {
			/* Invalidate Context register */
			cache_operation(TEE_CACHEINVALIDATE, ctx->ctx.data,
							ctx->ctx.length);
		}

		jobctx.desc = desc;
		retstatus = caam_jr_enqueue(&jobctx, NULL);

		if (retstatus == CAAM_NO_ERROR) {
			ret = TEE_SUCCESS;

			if (dupdate->last) {
				if (dst_align.nocache == 0)
					cache_operation(TEE_CACHEINVALIDATE,
							dst_align.data,
							dupdate->dst.length);

				if (realloc)
					memcpy(dupdate->dst.data,
						dst_align.data,
						dupdate->dst.length);

				CIPHER_DUMPBUF("DST", dupdate->dst.data,
					dupdate->dst.length);
			} else {
				CIPHER_DUMPBUF("CTX", ctx->ctx.data,
					ctx->ctx.length);
			}
		} else {
			CIPHER_TRACE("CAAM Status 0x%08"PRIx32"",
				jobctx.status);
			ret = job_status_to_tee_result(jobctx.status);
		}

	} else {
		ret = TEE_SUCCESS;

		if (size_topost) {
			/* All input data must be saved */
			size_inmade = 0;
		}
	}

	if (size_topost) {
		struct nxpcrypt_buf indata = {
			.data   = (uint8_t *)dupdate->src.data,
			.length = dupdate->src.length};

		CIPHER_TRACE("Post %d of input len %d made %d",
				size_topost, dupdate->src.length, size_inmade);
		retstatus = caam_cpy_block_src(&ctx->blockbuf, &indata,
				size_inmade);

		if (retstatus != CAAM_NO_ERROR)
			ret = TEE_ERROR_GENERIC;
	}

end_cmac:
	if (realloc == 1)
		caam_free_buf(&dst_align);

	return ret;
}

