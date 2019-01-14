// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    caam_blob.c
 *
 * @brief   CAAM Blob manager.\n
 *          Implementation of Blob functions
 */
/* Standard includes */
#include <string.h>

/* Global includes */
#include <mm/core_memprot.h>
#include <tee/cache.h>
#include <utee_defines.h>

/* Platform includes */
#include <imx.h>

/* Library i.MX includes */
#include <libimxcrypt.h>
#include <libimxcrypt_huk.h>

/* Local includes */
#include "common.h"
#include "caam_blob.h"
#include "caam_jr.h"

/* Utils includes */
#include "utils_mem.h"

/*
 * Debug Macros
 */
//#define BLOB_DEBUG
#ifdef BLOB_DEBUG
#define DUMP_DESC
#define DUMP_BUF
#define BLOB_TRACE		DRV_TRACE
#else
#define BLOB_TRACE(...)
#endif

#ifdef DUMP_DESC
#define BLOB_DUMPDESC(desc)	{BLOB_TRACE("BLOB Descriptor"); \
							DRV_DUMPDESC(desc); }
#else
#define BLOB_DUMPDESC(desc)
#endif

#ifdef DUMP_BUF
#define BLOB_DUMPBUF	DRV_DUMPBUF
#else
#define BLOB_DUMPBUF(...)
#endif

/* Number of entries in descriptor */
#define BLOB_MASTER_KEY_VERIF	7

/**
 * @brief   Verify Master Key (derives a BKEK from the secret master key).
 *          This BKEK is not the same used during normal blob encapsulation.
 *
 * @param[out] outkey  Output key generated
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result caam_master_key_verif(struct imxcrypt_buf *outkey)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum CAAM_Status retstatus;

	paddr_t paddr_keymod;
	uint8_t keymod_buf[BLOB_KEY_MODIFIER_SIZE] = {0};

	struct caambuf outkey_align = {0};
	int            realloc = 0;

	struct jr_jobctx jobctx = {0};
	descPointer_t    desc;
	uint8_t          desclen = 1;

	/* Check if parameters are correct */
	if (!outkey)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!outkey->data)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Get the physical address of the key modifier */
	paddr_keymod = virt_to_phys(keymod_buf);
	if (!paddr_keymod)
		return TEE_ERROR_GENERIC;

	/* Realloc the outkey if not aligned or too small */
	realloc = caam_realloc_align(outkey->data, &outkey_align,
				BLOB_BKEK_SIZE);
	if (realloc == (-1)) {
		BLOB_TRACE("Output key reallocation error");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Allocate the job descriptor */
	desc = caam_alloc_desc(BLOB_MASTER_KEY_VERIF);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_masterkey;
	}

	/*
	 * Create the Master Key Verification descriptor
	 */
	/* Load the key modifier */
	desc[desclen++] = LD_NOIMM(CLASS_2, REG_KEY, BLOB_KEY_MODIFIER_SIZE);
	desc[desclen++] = paddr_keymod;

	/* Output key storage */
	desc[desclen++] = SEQ_OUT_PTR(BLOB_BKEK_SIZE);
	desc[desclen++] = outkey_align.paddr;

	/* Blob Master key verification operation */
	desc[desclen++] = BLOB_MSTR_KEY;

	/* Descriptor Header */
	desc[0] = DESC_HEADER(desclen);

	BLOB_DUMPDESC(desc);

	cache_operation(TEE_CACHECLEAN, keymod_buf, BLOB_KEY_MODIFIER_SIZE);
	cache_operation(TEE_CACHEFLUSH, outkey_align.data, outkey_align.length);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		cache_operation(TEE_CACHEINVALIDATE, outkey_align.data,
				outkey_align.length);
		BLOB_DUMPBUF("Master Key", outkey_align.data,
				outkey_align.length);

		if (realloc == 1)
			memcpy(outkey->data, outkey_align.data,
				MIN(outkey_align.length, outkey->length));

		ret = TEE_SUCCESS;
	} else {
		BLOB_TRACE("CAAM Status 0x%08"PRIx32"", jobctx.status);
		ret = TEE_ERROR_GENERIC;
	}

exit_masterkey:
	caam_free_desc(&desc);
	if (realloc == 1)
		caam_free_buf(&outkey_align);

	return ret;
}

/**
 * @brief   Registration of the HUK Driver
 */
struct imxcrypt_huk driver_huk = {
	.generate_huk = &caam_master_key_verif,
};

/**
 * @brief   Initialize the Blob module
 *
 * @param[in] ctrl_addr   Controller base address
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 */
enum CAAM_Status caam_blob_init(vaddr_t ctrl_addr __unused)
{
	enum CAAM_Status retstatus = CAAM_FAILURE;

	/* Register the HUK Driver */
	if (imxcrypt_register(CRYPTO_HUK, &driver_huk) == 0)
		retstatus = CAAM_NO_ERROR;

	return retstatus;
}
