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
#include <utee_defines.h>
#include <mm/core_memprot.h>
#include <tee/cache.h>

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
#define MAX_DESC_ENTRIES	(10)

/**
 * @brief   Definition of flags tagging which key(s) is required
 */
#define NEED_KEY1	BIT(0)
#define NEED_KEY2	BIT(1)
#define NEED_IV		BIT(2)

/**
 * @brief   Cipher Algorithm definition
 */
struct cipheralg {
	uint32_t type;        ///< Algo type for operation
	uint8_t  size_block;  ///< Computing block size
	uint8_t  require_key; ///< Tag defining key(s) required
	struct defkey def_key;     ///< Key size accepted
};

/**
 * @brief   Full Cipher data SW context
 */
struct cipherdata {
	descPointer_t descriptor;     ///< Job descriptor

	struct caambuf     key1;      ///< First Key
	struct caambuf     key2;      ///< Second Key
	struct caambuf     iv;        ///< Initial Vector

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
		.require_key = NEED_KEY1,
		.def_key     = {.min = 16, .max = 32, .mod = 8},
	},
};

/**
 * @brief   Allocate context data and copy input data into
 *
 * @param[in]  src  Source of data to copy
 * @param[out] dst  Destination data to allocate and fill
 *
 * @retval  CAAM_NO_ERROR   Success
 * @retval  CAAM_FAILURE    Other error
 * @retval  CAAM_OUT_MEMORY Allocation error
 */
static enum CAAM_Status copy_ctx_data(struct caambuf *dst,
			struct imxcrypt_buf *src)
{
	/* Allocate the destination buffer */
	dst->data = caam_alloc_align(src->length);
	if (!dst->data)
		return CAAM_OUT_MEMORY;

	dst->length = src->length;

	/* Get the physical address of the buffer */
	dst->paddr = virt_to_phys(dst->data);
	if (!dst->paddr)
		return CAAM_FAILURE;

	/* Do the copy */
	memcpy(dst->data, src->data, dst->length);

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

	cipherdata->algo_id = algo;
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
		caam_free((void **)&ctx->key1.data);
		ctx->key1.length = 0;
		ctx->key1.paddr  = 0;

		/* Free the Key 2  */
		caam_free((void **)&ctx->key2.data);
		ctx->key2.length = 0;
		ctx->key2.paddr  = 0;

		/* Free the IV  */
		caam_free((void **)&ctx->iv.data);
		ctx->iv.length = 0;
		ctx->iv.paddr  = 0;
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
		if ((!dinit->iv.data) || (dinit->iv.length == 0))
			goto exit_init;

		if (do_check_keysize(&alg->def_key, dinit->iv.length) !=
			CAAM_NO_ERROR) {
			CIPHER_TRACE("Bad IV size");
			goto exit_init;
		}

		/* Copy the IV */
		retstatus = copy_ctx_data(&cipherdata->iv, &dinit->iv);
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
 * @brief   Update of the cipher operation
 *
 * @param[in] dupdate  Data update object
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 */
static TEE_Result do_update(struct imxcrypt_cipher_update *dupdate)
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

	if (cipherdata->algo_id != dupdate->algo)
		return ret;

	CIPHER_TRACE("Algo %d - %s", cipherdata->algo_id,
				(dupdate->encrypt ? "Encrypt" : " Decrypt"));

	alg = &cipher_alg[cipherdata->algo_id];

	/* Check the length of the payload/cipher */
	if ((dupdate->src.length < alg->size_block) ||
		(dupdate->src.length % alg->size_block)) {
		CIPHER_TRACE("Bad payload/cipher size %d bytes",
					dupdate->payload.length);
		return ret;
	}

	/* Get and check the payload/cipher physical addresses */
	psrc = virt_to_phys(dupdate->src.data);
	pdst  = virt_to_phys(dupdate->dst.data);

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
		cache_operation(TEE_CACHECLEAN, cipherdata->key1.data,
						cipherdata->key1.length);
	}

	/* Operation with the direction */
	desc[desclen++] = CIPHER_INITFINAL(alg->type, dupdate->encrypt);

	/* Load the source data */
	desc[desclen++] = FIFO_LD(CLASS_1, MSG, LAST_C1, dupdate->src.length);
	desc[desclen++] = psrc;

	/* Store the destination data */
	desc[desclen++] = FIFO_ST(MSG_DATA, dupdate->dst.length);
	desc[desclen++] = pdst;

	/* Set the descriptor Header with length */
	desc[0] = DESC_HEADER(desclen);

	CIPHER_DUMPDESC(desc);

	cache_operation(TEE_CACHECLEAN, dupdate->src.data, dupdate->src.length);
	cache_operation(TEE_CACHEFLUSH, dupdate->dst.data, dupdate->dst.length);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		cache_operation(TEE_CACHEINVALIDATE, dupdate->dst.data,
						dupdate->dst.length);
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
