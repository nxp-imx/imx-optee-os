// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    caam_cipher.c
 *
 * @brief   CAAM Cipher manager.\n
 *          Implementation of Cipher functions
 */

/* Standard includes */
#include <string.h>

/* Global includes */
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <tee/cache.h>
#include <tee/tee_cryp_utl.h>
#include <utee_defines.h>

/* Library i.MX includes */
#include <libimxcrypt.h>
#include <libimxcrypt_cipher.h>

/* Local includes */
#include "common.h"
#include "caam_cipher.h"
#include "caam_jr.h"

/* Utils includes */
#include "utils_mem.h"

/*
 * Debug Macros
 */
//#define CIPHER_DEBUG
#ifdef CIPHER_DEBUG
#define DUMP_DESC
#define DUMP_BUF
#define CIPHER_TRACE			DRV_TRACE
#else
#define CIPHER_TRACE(...)
#endif

#ifdef DUMP_DESC
#define CIPHER_DUMPDESC(desc)	{CIPHER_TRACE("Descriptor"); \
							DRV_DUMPDESC(desc); }
#else
#define CIPHER_DUMPDESC(desc)
#endif

#ifdef DUMP_BUF
#define CIPHER_DUMPBUF			DRV_DUMPBUF
#else
#define CIPHER_DUMPBUF(...)
#endif

/**
 * @brief    Maximum number of entry in the descriptor
 */
#define MAX_DESC_ENTRIES	14

/**
 * @brief   Definition of flags tagging which key(s) is required
 */
#define NEED_KEY1	BIT(0)
#define NEED_KEY2	BIT(1)
#define NEED_IV		BIT(2)

/* Local Function declaration */
static TEE_Result do_update_streaming(struct imxcrypt_cipher_update *dupdate);
static TEE_Result do_update_block(struct imxcrypt_cipher_update *dupdate);
static TEE_Result do_update_cts(struct imxcrypt_cipher_update *dupdate);

/**
 * @brief   Cipher Algorithm definition
 */
struct cipheralg {
	uint32_t type;        ///< Algo type for operation
	uint8_t  size_block;  ///< Computing block size
	uint8_t  size_ctx;    ///< CAAM Context Register size
	uint8_t  ctx_offset;  ///< CAAM Context Register offset
	uint8_t  require_key; ///< Tag defining key(s) required

	struct defkey def_key;     ///< Key size accepted

	TEE_Result (*update)(struct imxcrypt_cipher_update *dupdate);
};

/**
 * @brief   Full Cipher data SW context
 */
struct cipherdata {
	descPointer_t descriptor;        ///< Job descriptor

	struct caambuf key1;             ///< First Key
	struct caambuf key2;             ///< Second Key

	struct caambuf ctx;              ///< CAAM Context Register

	struct caamblock blockbuf;       ///< Temporary Block buffer

	enum imxcrypt_cipher_id algo_id; ///< Cipher Algorithm Id
};

/**
 * @brief   Constants definition of the Hash algorithm
 */
static const struct cipheralg cipher_alg[MAX_CIPHER_SUPPORTED] = {
	{
		/* AES ECB No Pad */
		.type        = OP_ALGO(AES) | ALGO_AAI(AES_ECB),
		.size_block  = TEE_AES_BLOCK_SIZE,
		.size_ctx    = 0,
		.ctx_offset  = 0,
		.require_key = NEED_KEY1,
		.def_key     = {.min = 16, .max = 32, .mod = 8},
		.update      = do_update_block,
	},
	{
		/* AES CBC No Pad */
		.type        = OP_ALGO(AES) | ALGO_AAI(AES_CBC),
		.size_block  = TEE_AES_BLOCK_SIZE,
		.size_ctx    = 2 * sizeof(uint64_t),
		.ctx_offset  = 0,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key     = {.min = 16, .max = 32, .mod = 8},
		.update      = do_update_block,
	},
	{
		/* AES CTR */
		.type        = OP_ALGO(AES) | ALGO_AAI(AES_CTR_MOD128),
		.size_block  = TEE_AES_BLOCK_SIZE,
		.size_ctx    = 2 * sizeof(uint64_t),
		.ctx_offset  = 16,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key     = {.min = 16, .max = 32, .mod = 8},
		.update      = do_update_streaming,
	},
	{
		/* AES CTS, combinaison of CBC and ECB mode */
		.type        = 0,
		.size_block  = TEE_AES_BLOCK_SIZE,
		.size_ctx    = 2 * sizeof(uint64_t),
		.ctx_offset  = 0,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key     = {.min = 16, .max = 32, .mod = 8},
		.update      = do_update_cts,
	},

};

/**
 * @brief   Allocate context data and copy input data into
 *
 * @param[in]  src  Source of data to copy
 * @param[out] dst  Destination data to allocate and fill
 *
 * @retval  CAAM_NO_ERROR   Success
 * @retval  CAAM_OUT_MEMORY Allocation error
 */
static enum CAAM_Status copy_ctx_data(struct caambuf *dst,
			struct imxcrypt_buf *src)
{
	enum CAAM_Status ret;

	/* Allocate the destination buffer */
	ret = caam_alloc_align_buf(dst, src->length);
	if (ret != CAAM_NO_ERROR)
		return ret;

	/* Do the copy */
	memcpy(dst->data, src->data, dst->length);

	/* Push data to physical memory */
	cache_operation(TEE_CACHEFLUSH, dst->data, dst->length);

	return CAAM_NO_ERROR;
}

/**
 * @brief  Verifies the input key size with the requirements
 *
 * @param[in] def  Key requirements
 * @param[in] size Key size to verify
 *
 * @retval CAAM_NO_ERROR   Success
 * @retval CAAM_BAD_PARAM  Bad parameters
 */
static enum CAAM_Status do_check_keysize(const struct defkey *def, size_t size)
{
	if ((size >= def->min) && (size <= def->max)) {
		if ((size % def->mod) == 0)
			return CAAM_NO_ERROR;
	}

	return CAAM_BAD_PARAM;
}

/**
 * @brief   Allocate the SW cipher data context
 *
 * @param[in/out]  ctx    Caller context variable
 * @param[in]      algo   Algorithm ID of the context
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 */
static TEE_Result do_allocate(void **ctx, enum imxcrypt_cipher_id algo)
{
	struct cipherdata *cipherdata = NULL;

	CIPHER_TRACE("Allocate Context (0x%"PRIxPTR")", (uintptr_t)ctx);

	cipherdata = caam_alloc(sizeof(struct cipherdata));
	if (!cipherdata) {
		CIPHER_TRACE("Allocation Cipher data error");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Allocate the descriptor */
	cipherdata->descriptor = caam_alloc_desc(MAX_DESC_ENTRIES);
	if (!cipherdata->descriptor) {
		CIPHER_TRACE("Allocation descriptor error");
		goto err_allocate;
	}

	/* Setup the algorithm id */
	cipherdata->algo_id = algo;

	/* Initialize the block buffer */
	cipherdata->blockbuf.filled = 0;

	*ctx = cipherdata;

	return TEE_SUCCESS;

err_allocate:
	caam_free_desc(&cipherdata->descriptor);
	caam_free((void **)&cipherdata);

	return TEE_ERROR_OUT_OF_MEMORY;
}

/**
 * @brief   Free the internal cipher data context
 *
 * @param[in/out]  ctx    Caller context variable
 *
 */
static void do_free_intern(struct cipherdata *ctx)
{
	CIPHER_TRACE("Free Context (0x%"PRIxPTR")", (uintptr_t)ctx);

	if (ctx) {
		/* Free the descriptor */
		caam_free_desc(&ctx->descriptor);

		/* Free the Key 1  */
		caam_free_buf(&ctx->key1);

		/* Free the Key 2  */
		caam_free_buf(&ctx->key2);

		/* Free the Context Register */
		caam_free_buf(&ctx->ctx);

		/* Free Temporary buffer */
		caam_free_buf(&ctx->blockbuf.buf);
	}
}

/**
 * @brief   Free the SW Cipher data context
 *
 * @param[in] ctx    Caller context variable
 *
 */
static void do_free(void *ctx)
{
	CIPHER_TRACE("Free Context (0x%"PRIxPTR")", (uintptr_t)ctx);

	if (ctx) {
		do_free_intern(ctx);
		caam_free(&ctx);
	}
}

/**
 * @brief   Copy Software Cipher Context
 *
 * @param[in]  src_ctx  Reference the context source
 * @param[out] dst_ctx  Reference the context destination
 *
 */
static void do_cpy_state(void *dst_ctx, void *src_ctx)
{
	struct cipherdata *dst = dst_ctx;
	struct cipherdata *src = src_ctx;

	CIPHER_TRACE("Copy State context (0x%"PRIxPTR") to (0x%"PRIxPTR")",
			 (uintptr_t)src_ctx, (uintptr_t)dst_ctx);

	dst->algo_id = src->algo_id;
}

/**
 * @brief   Get the algorithm block size
 *
 * @param[in]  algo  Algorithm ID
 * @param[out] size  Block size of the algorithm
 *
 * @retval TEE_SUCCESS                 Success
 */
static TEE_Result do_get_blocksize(enum imxcrypt_cipher_id algo, size_t *size)
{
	*size = cipher_alg[algo].size_block;

	return TEE_SUCCESS;
}

/**
 * @brief   Copy source data into the block buffer
 *
 * @param[in/out] ctx    Cipher data context
 * @param[in]     src    Source to copy
 * @param[in]     offset Source offset to start
 *
 * @retval CAAM_NO_ERROR       Success
 * @retval CAAM_OUT_MEMORY     Out of memory
 */
static enum CAAM_Status do_cpy_block_src(struct cipherdata *ctx,
				struct imxcrypt_buf *src,
				size_t offset)
{
	enum CAAM_Status ret;

	struct caamblock       *block = &ctx->blockbuf;
	const struct cipheralg *alg   = &cipher_alg[ctx->algo_id];

	size_t cpy_size;

	/* Check if the temporary buffer is allocted, else allocate it */
	if (!block->buf.data) {
		ret = caam_alloc_align_buf(&block->buf, alg->size_block);
		if (ret != CAAM_NO_ERROR) {
			CIPHER_TRACE("Allocation Block buffer error");
			goto end_cpy;
		}
	}

	/* Calculate the number of bytes to copy in the block buffer */
	CIPHER_TRACE("Current buffer is %d (%d) bytes",
					block->filled, alg->size_block);

	cpy_size = alg->size_block - block->filled;
	cpy_size = MIN(cpy_size, (src->length - offset));

	CIPHER_TRACE("Copy %d of src %d bytes", cpy_size, src->length);

	memcpy(&block->buf.data[block->filled], &src->data[offset], cpy_size);

	block->filled += cpy_size;

	ret = CAAM_NO_ERROR;

end_cpy:
	return ret;
}

/**
 * @brief   Initialization of the cipher operation
 *
 * @param[in] dinit  Data initialization object
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
static TEE_Result do_init(struct imxcrypt_cipher_init *dinit)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;

	enum CAAM_Status retstatus;
	struct cipherdata      *cipherdata = dinit->ctx;
	const struct cipheralg *alg;

	if (cipherdata->algo_id != dinit->algo)
		return ret;

	CIPHER_TRACE("Algo %d - %s", cipherdata->algo_id,
				(dinit->encrypt ? "Encrypt" : " Decrypt"));

	alg = &cipher_alg[cipherdata->algo_id];

	/* Check if all required keys are defined */
	if (alg->require_key & NEED_KEY1) {
		if ((!dinit->key1.data) || (dinit->key1.length == 0))
			goto exit_init;

		if (do_check_keysize(&alg->def_key, dinit->key1.length) !=
			CAAM_NO_ERROR) {
			CIPHER_TRACE("Bad Key 1 size");
			goto exit_init;
		}

		/* Copy the key 1 */
		retstatus = copy_ctx_data(&cipherdata->key1, &dinit->key1);
		CIPHER_TRACE("Copy Key 1 returned %d", retstatus);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_init;
		}
	}

	if (alg->require_key & NEED_KEY2) {
		if ((!dinit->key2.data) || (dinit->key2.length == 0))
			goto exit_init;

		if (do_check_keysize(&alg->def_key, dinit->key2.length) !=
			CAAM_NO_ERROR) {
			CIPHER_TRACE("Bad Key 2 size");
			goto exit_init;
		}

		/* Copy the key 2 */
		retstatus = copy_ctx_data(&cipherdata->key2, &dinit->key2);
		CIPHER_TRACE("Copy Key 2 returned %d", retstatus);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_init;
		}
	}

	if (alg->require_key & NEED_IV) {
		if (((!dinit->iv.data) || (dinit->iv.length == 0)) &&
			(alg->size_ctx != 0))
			goto exit_init;

		if (dinit->iv.length != alg->size_ctx) {
			CIPHER_TRACE("Bad IV size %d (expected %d)",
					dinit->iv.length, alg->size_ctx);
			goto exit_init;
		}

		CIPHER_TRACE("Allocate CAAM Context Register (%d bytes)",
					alg->size_ctx);

		/* Copy the IV into the context register */
		retstatus = copy_ctx_data(&cipherdata->ctx, &dinit->iv);
		CIPHER_TRACE("Copy IV returned %d", retstatus);

		if (retstatus != CAAM_NO_ERROR) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_init;
		}
	}

	ret = TEE_SUCCESS;

exit_init:
	if (ret != TEE_SUCCESS) {
		/* Free the internal context in case of error */
		do_free_intern(cipherdata);
	}

	return ret;
}

/**
 * @brief   Update of the cipher operation in streaming mode, meaning
 *          doing partial intermediate block.\n
 *          If there is a context, the context is saved only when a
 *          full block is done.\n
 *          The partial block (if not the last block) is encrypted or
 *          decrypted to return the result and it's saved to be concatened
 *          to next data to rebuild a full block.
 *
 * @param[in] dupdate  Data update object
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 */
static TEE_Result do_update_streaming(struct imxcrypt_cipher_update *dupdate)
{
	TEE_Result    ret = TEE_ERROR_GENERIC;
	enum CAAM_Status retstatus;

	struct cipherdata      *cipherdata = dupdate->ctx;
	const struct cipheralg *alg;

	struct jr_jobctx   jobctx = {0};
	descPointer_t desc    = cipherdata->descriptor;
	uint8_t       desclen = 1;
	paddr_t       psrc;
	paddr_t       pdst;

	struct sgt    dst_sgt[2]  = { {0} };
	bool          use_dst_sgt = false;
	bool          noctxbackup = false;
	size_t        fullSize;
	size_t        srcSizeRest = 0;

	CIPHER_TRACE("Algo %d length=%d - %s", cipherdata->algo_id,
				dupdate->src.length,
				(dupdate->encrypt ? "Encrypt" : " Decrypt"));

	alg = &cipher_alg[cipherdata->algo_id];

	/* Get and check the payload/cipher physical addresses */
	psrc = virt_to_phys(dupdate->src.data);
	pdst = virt_to_phys(dupdate->dst.data);

	if ((!psrc) || (!pdst)) {
		CIPHER_TRACE("Bad Addr (src 0x%"PRIxPA") (dst 0x%"PRIxPA")",
				psrc, pdst);
		ret = TEE_ERROR_GENERIC;
		return ret;
	}

	if (alg->require_key & NEED_KEY1) {
		/* Build the descriptor */
		desc[desclen++] = LD_KEY_PLAIN(CLASS_1, REG,
				cipherdata->key1.length);
		desc[desclen++] = cipherdata->key1.paddr;
	}

	/* If there is a context register load it */
	if ((cipherdata->ctx.length) && (alg->size_ctx)) {
		desc[desclen++] = LD_NOIMM_OFF(CLASS_1, REG_CTX,
					cipherdata->ctx.length,
					alg->ctx_offset);
		desc[desclen++] = cipherdata->ctx.paddr;

		/* Operation with the direction */
		desc[desclen++] = CIPHER_INIT(alg->type, dupdate->encrypt);
	} else {
		/* Operation with the direction */
		desc[desclen++] = CIPHER_INITFINAL(alg->type, dupdate->encrypt);
	}

	fullSize = cipherdata->blockbuf.filled + dupdate->src.length;
	/* Load the Block buffer if present and filled */
	if (cipherdata->blockbuf.filled != 0) {
		desc[desclen++] = FIFO_LD(CLASS_1, MSG, NOACTION,
					cipherdata->blockbuf.filled);
		desc[desclen++] = cipherdata->blockbuf.buf.paddr;

		/* Ensure Context Block buffer data are in memory */
		cache_operation(TEE_CACHECLEAN, cipherdata->blockbuf.buf.data,
					cipherdata->blockbuf.filled);

#ifndef ARM64
		dst_sgt[0].ptr_ls = cipherdata->blockbuf.buf.paddr;
		dst_sgt[0].length = cipherdata->blockbuf.filled;
		dst_sgt[1].ptr_ls = pdst;
		dst_sgt[1].length = dupdate->dst.length;
		dst_sgt[1].final  = 1;
#else
		dst_sgt[0].ptr_ls = (uint32_t)(cipherdata->blockbuf.buf.paddr);
		dst_sgt[0].ptr_ms = (uint32_t)(cipherdata->blockbuf.buf.paddr
						>> 32);
		dst_sgt[0].length = cipherdata->blockbuf.filled;
		dst_sgt[1].ptr_ls = (uint32_t)(pdst);
		dst_sgt[1].ptr_ms = (uint32_t)(pdst >> 32);
		dst_sgt[1].length = dupdate->dst.length;
		dst_sgt[1].final  = 1;
#endif
		cipherdata->blockbuf.filled = 0;
		use_dst_sgt = true;

		cache_operation(TEE_CACHECLEAN, dst_sgt, sizeof(dst_sgt));
	}

	if (!dupdate->last) {
		/*
		 * Check if the length of the source data and the length of the
		 * context block buffer is less than a block size.
		 * If this is not the last block, store the input data into the
		 * context block buffer
		 */
		CIPHER_TRACE("Context block %d bytes",
			cipherdata->blockbuf.filled);

		if (fullSize < alg->size_block) {
			CIPHER_TRACE("Copy input into context block buffer");
			retstatus = do_cpy_block_src(cipherdata,
						&dupdate->src, 0);

			noctxbackup = true;
			if (retstatus != CAAM_NO_ERROR) {
				ret = TEE_ERROR_GENERIC;
				return ret;
			}
		} else if (fullSize % alg->size_block) {
			/*
			 * Calculate the size of the input length to
			 * operate based on the block size
			 */
			srcSizeRest = fullSize % alg->size_block;
			CIPHER_TRACE("Operate data src %d bytes, rest %d bytes",
					dupdate->src.length, srcSizeRest);
		}
	}

	/* Load the source data */
	desc[desclen++] = FIFO_LD(CLASS_1, MSG, LAST_C1,
				(dupdate->src.length - srcSizeRest));
	desc[desclen++] = psrc;

	if (use_dst_sgt) {
		/* Store the destination data */
		desc[desclen++] = FIFO_ST_SGT(MSG_DATA,
					(fullSize - srcSizeRest));
		desc[desclen++] = virt_to_phys(dst_sgt);
	} else {
		/* Store the destination data */
		desc[desclen++] = FIFO_ST(MSG_DATA, (fullSize - srcSizeRest));
		desc[desclen++] = pdst;
	}

	if ((cipherdata->ctx.length) && (alg->size_ctx) &&
		(noctxbackup == false)) {
		/* Store the context */
		desc[desclen++] = ST_NOIMM_OFF(CLASS_1, REG_CTX,
				cipherdata->ctx.length, alg->ctx_offset);
		desc[desclen++] = cipherdata->ctx.paddr;

		/* Ensure Context register data are not in cache */
		cache_operation(TEE_CACHEINVALIDATE, cipherdata->ctx.data,
					cipherdata->ctx.length);
	}

	/* Set the descriptor Header with length */
	desc[0] = DESC_HEADER(desclen);
	if (desclen > MAX_DESC_ENTRIES)	{
		CIPHER_TRACE("Descriptor Size too short (%d vs %d)",
					desclen, MAX_DESC_ENTRIES);
		panic();
	}

	CIPHER_DUMPDESC(desc);

	CIPHER_DUMPBUF("Input", dupdate->src.data, dupdate->src.length);
	cache_operation(TEE_CACHECLEAN, dupdate->src.data, dupdate->src.length);
	cache_operation(TEE_CACHEFLUSH, dupdate->dst.data, dupdate->dst.length);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		CIPHER_DUMPBUF("Result", dupdate->dst.data,
					dupdate->dst.length);

		/*
		 * If there is source data remaining representing a partial
		 * block, compute it to get the result. Save it and don't
		 * update the context register
		 */
		if (srcSizeRest) {
			dupdate->src.data += (dupdate->src.length -
						srcSizeRest);
			dupdate->src.length = srcSizeRest;
			dupdate->dst.data += (dupdate->dst.length -
						srcSizeRest);
			dupdate->dst.length = srcSizeRest;
			ret = do_update_streaming(dupdate);
		} else {
			ret = TEE_SUCCESS;
		}
	} else {
		CIPHER_TRACE("CAAM Status 0x%08"PRIx32"", jobctx.status);
		ret = TEE_ERROR_GENERIC;
	}

	return ret;
}


/**
 * @brief   Update of the cipher operation of complete block except
 *          if last block. Last block can be partial block.
 *
 * @param[in] dupdate  Data update object
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad Parameters
 */
static TEE_Result do_update_block(struct imxcrypt_cipher_update *dupdate)
{
	TEE_Result    ret = TEE_ERROR_BAD_PARAMETERS;
	enum CAAM_Status retstatus;

	struct cipherdata      *cipherdata = dupdate->ctx;
	const struct cipheralg *alg;

	struct jr_jobctx   jobctx = {0};
	descPointer_t desc    = cipherdata->descriptor;
	uint8_t       desclen = 1;
	paddr_t       psrc;
	paddr_t       pdst;

	CIPHER_TRACE("Algo %d length=%d - %s", cipherdata->algo_id,
				dupdate->src.length,
				(dupdate->encrypt ? "Encrypt" : " Decrypt"));

	alg = &cipher_alg[cipherdata->algo_id];

	/* Check the length of the payload/cipher */
	if ((dupdate->src.length < alg->size_block) ||
		(dupdate->src.length % alg->size_block)) {
		CIPHER_TRACE("Bad payload/cipher size %d bytes",
					dupdate->src.length);
		return ret;
	}

	/* Get and check the payload/cipher physical addresses */
	psrc = virt_to_phys(dupdate->src.data);
	pdst = virt_to_phys(dupdate->dst.data);

	if ((!psrc) || (!pdst)) {
		CIPHER_TRACE("Bad Addr (src 0x%"PRIxPA") (dst 0x%"PRIxPA")",
			psrc, pdst);
		ret = TEE_ERROR_GENERIC;
		return ret;
	}

	if (alg->require_key & NEED_KEY1) {
		/* Build the descriptor */
		desc[desclen++] = LD_KEY_PLAIN(CLASS_1, REG,
				cipherdata->key1.length);
		desc[desclen++] = cipherdata->key1.paddr;
	}

	/* If there is a context register load it */
	if ((cipherdata->ctx.length) && (alg->size_ctx)) {
		desc[desclen++] = LD_NOIMM_OFF(CLASS_1, REG_CTX,
				cipherdata->ctx.length, alg->ctx_offset);
		desc[desclen++] = cipherdata->ctx.paddr;

		/* Operation with the direction */
		desc[desclen++] = CIPHER_INIT(alg->type, dupdate->encrypt);
	} else {
		/* Operation with the direction */
		desc[desclen++] = CIPHER_INITFINAL(alg->type, dupdate->encrypt);
	}

	/* Load the source data */
	desc[desclen++] = FIFO_LD(CLASS_1, MSG, LAST_C1, dupdate->src.length);
	desc[desclen++] = psrc;

	/* Store the destination data */
	desc[desclen++] = FIFO_ST(MSG_DATA, dupdate->dst.length);
	desc[desclen++] = pdst;

	if ((cipherdata->ctx.length) && (alg->size_ctx)) {
		/* Store the context */
		desc[desclen++] = ST_NOIMM_OFF(CLASS_1, REG_CTX,
				cipherdata->ctx.length, alg->ctx_offset);
		desc[desclen++] = cipherdata->ctx.paddr;

		/* Ensure Context register data are not in cache */
		cache_operation(TEE_CACHEINVALIDATE, cipherdata->ctx.data,
					cipherdata->ctx.length);
	}

	/* Set the descriptor Header with length */
	desc[0] = DESC_HEADER(desclen);
	if (desclen > MAX_DESC_ENTRIES)	{
		CIPHER_TRACE("Descriptor Size too short (%d vs %d)",
					desclen, MAX_DESC_ENTRIES);
		panic();
	}

	CIPHER_DUMPDESC(desc);

	CIPHER_DUMPBUF("Input", dupdate->src.data, dupdate->src.length);
	cache_operation(TEE_CACHECLEAN, dupdate->src.data, dupdate->src.length);
	cache_operation(TEE_CACHEFLUSH, dupdate->dst.data, dupdate->dst.length);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		CIPHER_DUMPBUF("Result", dupdate->dst.data,
				dupdate->dst.length);
		ret = TEE_SUCCESS;
	} else {
		CIPHER_TRACE("CAAM Status 0x%08"PRIx32"", jobctx.status);
		ret = TEE_ERROR_GENERIC;
	}

	return ret;
}
/**
 * @brief   Update of the cipher operation for AES CTS mode.
 *          Call the tee_aes_cbc_cts_update function that will either
 *          call AES ECB/CBC algorithm.
 *
 * @param[in] dupdate  Data update object
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad Parameters
 * @retval TEE_ERROR_BAD_STATE       Data length error
 */
static TEE_Result do_update_cts(struct imxcrypt_cipher_update *dupdate)
{
	CIPHER_TRACE("Algo AES CTS length=%d - %s",
				dupdate->src.length,
				(dupdate->encrypt ? "Encrypt" : " Decrypt"));

	return tee_aes_cbc_cts_update(dupdate->ctx, dupdate->ctx,
		(dupdate->encrypt ? TEE_MODE_ENCRYPT : TEE_MODE_DECRYPT),
		dupdate->last, dupdate->src.data, dupdate->src.length,
		dupdate->dst.data);
}

/**
 * @brief   Update of the cipher operation. Call the algorithm update
 *          function associated.
 *
 * @param[in] dupdate  Data update object
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 */
static TEE_Result do_update(struct imxcrypt_cipher_update *dupdate)
{
	TEE_Result  ret;

	struct cipherdata *cipherdata = dupdate->ctx;
	const struct cipheralg *alg;

	enum imxcrypt_cipher_id orialgo;

	orialgo = cipherdata->algo_id;

	switch (cipherdata->algo_id) {
	case AES_CTS:
		/* For this case, check if input algo is AES ECB/CBC */
		if ((dupdate->algo != AES_ECB_NOPAD) &&
			(dupdate->algo != AES_CBC_NOPAD) &&
			(dupdate->algo != AES_CTS))
			return TEE_ERROR_BAD_PARAMETERS;

		/* Change context algo to be able update operation */
		cipherdata->algo_id = dupdate->algo;
		break;

	default:
		if (cipherdata->algo_id != dupdate->algo)
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	}

	alg = &cipher_alg[cipherdata->algo_id];

	ret = alg->update(dupdate);

	/* Restore the original algorithm in the context */
	cipherdata->algo_id = orialgo;

	return ret;
}

/**
 * @brief   Finalize of the cipher operation
 *
 * @param[in] ctx    Caller context variable
 * @param[in] algo   Algorithm ID of the context
 */
static void do_final(void *ctx __unused, enum imxcrypt_cipher_id algo __unused)
{
}

/**
 * @brief   Registration of the Cipher Driver
 */
struct imxcrypt_cipher driver_cipher = {
	.alloc_ctx  = &do_allocate,
	.free_ctx   = &do_free,
	.init       = &do_init,
	.update     = &do_update,
	.final      = &do_final,
	.block_size = &do_get_blocksize,
	.cpy_state  = &do_cpy_state,
};

/**
 * @brief   Initialize the Cipher module
 *
 * @param[in] ctrl_addr   Controller base address
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 * @retval  CAAM_OUT_MEMORY  Out of memory
 */
enum CAAM_Status caam_cipher_init(vaddr_t ctrl_addr __unused)
{
	enum CAAM_Status retstatus = CAAM_FAILURE;

	if (imxcrypt_register(CRYPTO_CIPHER, &driver_cipher) == 0)
		retstatus = CAAM_NO_ERROR;

	return retstatus;
}
