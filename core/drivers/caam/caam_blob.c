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

/* Library NXP includes */
#include <libnxpcrypt.h>
#include <libnxpcrypt_huk.h>
#include <libnxpcrypt_blob.h>

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
//#define DUMP_DESC
//#define DUMP_BUF
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
static TEE_Result caam_master_key_verif(struct nxpcrypt_buf *outkey)
{
#ifdef CFG_PHYS_64BIT
#define BLOB_MASTER_KEY_VERIF	9
#else
#define BLOB_MASTER_KEY_VERIF	7
#endif

	TEE_Result ret = TEE_ERROR_GENERIC;
	enum CAAM_Status retstatus;

	paddr_t paddr_keymod;
	uint8_t keymod_buf[BLOB_KEY_MODIFIER_SIZE] = {0};

	struct caambuf outkey_align = {0};
	int            realloc = 0;

	struct jr_jobctx jobctx = {0};
	descPointer_t    desc;

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
	desc_init(desc);
	desc_add_word(desc, DESC_HEADER(0));

	/* Load the key modifier */
	desc_add_word(desc, LD_NOIMM(CLASS_2, REG_KEY, BLOB_KEY_MODIFIER_SIZE));
	desc_add_ptr(desc, paddr_keymod);

	/* Output key storage */
	desc_add_word(desc, SEQ_OUT_PTR(BLOB_BKEK_SIZE));
	desc_add_ptr(desc, outkey_align.paddr);

	/* Blob Master key verification operation */
	desc_add_word(desc, BLOB_MSTR_KEY);

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
struct nxpcrypt_huk driver_huk = {
	.generate_huk = &caam_master_key_verif,
};

/**
 * @brief
 *   - Encapsulates input data to RED or BLACK blob.\n
 *   - Decapsulates the input blob to provide the encapsulated data.\n
 *   \n
 *   If resulting blob is black, the data must be black as well.\n
 *   If resulting blob is red, the data are plain text.\n
 *   \n
 *   Output data length is:\n
 *      - encapsulation = inLen + BLOB_BPAD_SIZE\n
 *      - decapsulation = inLen - BLOB_BPAD_SIZE\n
 *   \n
 * @param[in/out] blob_data    Blob data to encapsulate/decapsulate
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_OUT_OF_MEMORY   Not enough memory
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 * @retval TEE_ERROR_GENERIC         Any other error
 */
static TEE_Result do_operate(struct nxpcrypt_blob_data *blob_data)
{
#ifdef CFG_PHYS_64BIT
#define BLOB_OPERATE_DESC_ENTRIES	12
#else
#define BLOB_OPERATE_DESC_ENTRIES	9
#endif

	TEE_Result ret = TEE_ERROR_GENERIC;
	enum CAAM_Status retstatus = CAAM_FAILURE;

	struct jr_jobctx jobctx = {0};
	descPointer_t desc = NULL;

	paddr_t paddr_input = 0;
	paddr_t paddr_key = 0;

	struct caambuf out_buf = {0};
	size_t insize, rinsize;
	size_t outsize, routsize;

	uint32_t opflag   = 0;
	int retS = 0;

	BLOB_TRACE("Blob %s - Type %d - Payload %d bytes - Blob %d bytes",
			(blob_data->encaps) ? "Encaps" : "Decaps",
			blob_data->type,
			blob_data->payload.length,
			blob_data->blob.length);

	paddr_key = virt_to_phys(blob_data->key.data);
	if (!paddr_key)
		goto exit_operate;

	if (blob_data->encaps) {
		retS = caam_realloc_align(blob_data->blob.data, &out_buf,
				blob_data->blob.length);
		if (retS == (-1)) {
			BLOB_TRACE("Signature reallocation error");
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_operate;
		}

		insize  = blob_data->payload.length;
		outsize = blob_data->blob.length;

		paddr_input = virt_to_phys(blob_data->payload.data);
		if (!paddr_input)
			goto exit_operate;

		BLOB_DUMPBUF("Input",
			blob_data->payload.data, blob_data->payload.length);
	} else {
		retS = caam_realloc_align(blob_data->payload.data, &out_buf,
		blob_data->payload.length);
		if (retS == (-1)) {
			BLOB_TRACE("Signature reallocation error");
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_operate;
		}
		insize  = blob_data->blob.length;
		outsize = blob_data->payload.length;

		paddr_input = virt_to_phys(blob_data->blob.data);
		if (!paddr_input)
			goto exit_operate;

		BLOB_DUMPBUF("Input",
			blob_data->blob.data, blob_data->blob.length);
	}

	rinsize  = insize;
	routsize = outsize;

	switch (blob_data->type) {
	case BLACK_CCM:
		opflag = PROT_BLOB_TYPE(BLACK_KEY) | PROT_BLOB_INFO(CCM);
		/*
		 * Round up the size of buffer to clean/flush real buffer
		 * which contains more data
		 */
		if (blob_data->encaps)
			rinsize = BLACK_KEY_CCM_SIZE(insize);
		else
			routsize = ROUNDUP(BLACK_KEY_CCM_SIZE(outsize), 16);
		break;

	case BLACK_ECB:
		opflag = PROT_BLOB_TYPE(BLACK_KEY) | PROT_BLOB_INFO(ECB);
		/*
		 * Round up the size of buffer to clean/flush real buffer
		 * which contains more data
		 */
		if (blob_data->encaps)
			rinsize = BLACK_KEY_CCM_SIZE(insize);
		else
			routsize = ROUNDUP(BLACK_KEY_ECB_SIZE(outsize), 16);
		break;

	case RED:
		break;

	default:
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto exit_operate;
	}

	/* Allocate the descriptor */
	desc = caam_alloc_desc(BLOB_OPERATE_DESC_ENTRIES);
	if (!desc) {
		BLOB_TRACE("CAAM Context Descriptor Allocation error");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_operate;
	}

	/*
	 * Create the Blob encapsulation/decapsulation descriptor
	 */
	desc_init(desc);
	desc_add_word(desc, DESC_HEADER(0));

	/* Load the key modifier */
	desc_add_word(desc, LD_NOIMM(CLASS_2, REG_KEY, blob_data->key.length));
	desc_add_ptr(desc, paddr_key);

	/* Define the Input data sequence */
	desc_add_word(desc, SEQ_IN_PTR(insize));
	desc_add_ptr(desc, paddr_input);

	/* Define the Output data sequence */
	desc_add_word(desc, SEQ_OUT_PTR(outsize));
	desc_add_ptr(desc, out_buf.paddr);

	if (blob_data->encaps) {
		/* Define the encapsulation operation */
		desc_add_word(desc, BLOB_ENCAPS | opflag);
	} else {
		/* Define the decapsulation operation */
		desc_add_word(desc, BLOB_DECAPS | opflag);
	}

	BLOB_DUMPDESC(desc);

	cache_operation(TEE_CACHECLEAN, blob_data->key.data,
		blob_data->key.length);

	if (blob_data->encaps)
		cache_operation(TEE_CACHECLEAN, blob_data->payload.data,
			rinsize);
	else
		cache_operation(TEE_CACHECLEAN, blob_data->blob.data,
			rinsize);

	if (out_buf.nocache == 0)
		cache_operation(TEE_CACHEFLUSH, out_buf.data, out_buf.length);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		BLOB_TRACE("Done CAAM BLOB %s",
				blob_data->encaps ? "Encaps" : "Decaps");

		if (out_buf.nocache == 0)
			cache_operation(TEE_CACHEINVALIDATE, out_buf.data,
				out_buf.length);

		BLOB_DUMPBUF("Output", out_buf.data, routsize);

		if (retS == 1) {
			/*
			 * Copy the result data in the correct output
			 * buffer function of the operation direction
			 */
			if (blob_data->encaps)
				memcpy(blob_data->blob.data,
					out_buf.data, routsize);
			else
				memcpy(blob_data->payload.data,
					out_buf.data, routsize);

			ret = TEE_SUCCESS;
		}

		if (blob_data->encaps)
			blob_data->blob.length = routsize;
		else
			blob_data->payload.length = routsize;
	} else {
		BLOB_TRACE("CAAM Status 0x%08"PRIx32"", jobctx.status);
		ret = TEE_ERROR_GENERIC;
	}

exit_operate:
	if (retS == 1)
		caam_free_buf(&out_buf);

	caam_free_desc(&desc);
	return ret;
}

/**
 * @brief   Registration of the Blob Driver
 */
struct nxpcrypt_blob driver_blob = {
	.operate = &do_operate,
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
	if (nxpcrypt_register(CRYPTO_HUK, &driver_huk) == 0) {
		if (nxpcrypt_register(CRYPTO_BLOB, &driver_blob) == 0)
			retstatus = CAAM_NO_ERROR;
	}

	return retstatus;
}
