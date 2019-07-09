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
#ifdef CFG_CRYPTO_SM_HW
#include "caam_sm.h"
#endif

/* Utils includes */
#include "utils_mem.h"
#include "utils_status.h"

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
		ret = job_status_to_tee_result(jobctx.status);
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

#ifdef CFG_PHYS_64BIT
#define BLOB_OPERATE_DESC_ENTRIES	12
#else
#define BLOB_OPERATE_DESC_ENTRIES	9
#endif

#ifdef CFG_CRYPTO_SM_HW
/**
 * @brief      Encapsulate DEK blob for HAB encrypted boot. DEK blob
 *             generation requires the encapsulation to be done from a
 *             partition of the CAAM secure memory. The BKEK for secure
 *             memory blobs is generated in a manner that it binds the access
 *             permissions of the partition to the blob. Any attempt to
 *             decapsulate a secure memory blob into a partition with different
 *             access permission would fail when checking MAC tag.
 *
 *             Secure memory blobs does not have to be decapsulate from the same
 *             partition. However both partition (for encap and decap) must be
 *             owned by the same Job ring.
 *
 *             The BKEK here, is derived from the master key and a 128 bits key
 *             modifier within the blob descriptor that includes a constant
 *             specific to secure memory blobs and the values of the partition
 *             access permission.
 *
 * @param      blob_data  The blob data
 *
 *   Output data length is: inLen + BLOB_BPAD_SIZE
 *
 * @param[in/out] blob_data    DEK Blob data to encapsulate
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_OUT_OF_MEMORY   Not enough memory
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 * @retval TEE_ERROR_GENERIC         Any other error
 */
static TEE_Result do_dek(struct nxpcrypt_blob_data *blob_data)
{
	TEE_Result retstatus = TEE_ERROR_GENERIC;
	paddr_t paddr_input = 0;
	paddr_t paddr_key = 0;
	descPointer_t desc = NULL;
	struct caambuf out_buf = {0};
	struct sm_data *sm = NULL;
	int ret_input = 0;
	int ret_output = 0;
	size_t insize, rinsize;
	size_t outsize, routsize;
	struct jr_jobctx jobctx = {0};

	if (blob_data->type != DEK || blob_data->encaps != true)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Get key paddr */
	paddr_key = virt_to_phys(blob_data->key.data);
	if (!paddr_key)
		goto exit_operate;

	/* Re-allocate output buffer if alignment needed */
	ret_input = caam_realloc_align(blob_data->blob.data, &out_buf,
				       blob_data->blob.length);
	if (ret_input < 0) {
		BLOB_TRACE("Signature reallocation error");
		retstatus = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_operate;
	}

	/**
	 * Allocate secure memory. By default, we use partition 1 and one page
	 * to generate the DEK blob.
	 */
	ret_output	= caam_sm_alloc(&sm, PARTITION_1, PAGE_2);
	if (ret_output) {
		retstatus = TEE_ERROR_OUT_OF_MEMORY;
		BLOB_TRACE("Secure memory allocation error");
		goto exit_operate;
	}

	insize   = blob_data->payload.length;
	outsize  = blob_data->blob.length;
	rinsize  = blob_data->payload.length;
	routsize = blob_data->blob.length;

	/* Copy DEK in secure memory */
	memcpy((void *)sm->sm_va, blob_data->payload.data,
		blob_data->payload.length);

	BLOB_DUMPBUF("Secure Mem", sm->sm_va, blob_data->payload.length);

	/* Set payload address DMA secure memory */
	paddr_input = sm->sm_dma_addr;

	/**
	 * Set partition access rights
	 * SMAPR_CSP: page will be zeroized after de-allocation or
	 * after security alarm.
	 * SMAPR_SMAP_LOCK: lock SMAP register until de-allocation.
	 * SMAPG_SMAP_LOCK: lock SMAG register until de-allocation.
	 * SMAPR_G1_SMBLOB: allow importing/exporting secure memory
	 * blob from group 1.
	 */
	caam_sm_set_access_perm(sm, SMAPR_CSP | SMAPR_SMAP_LOCK |
					    SMAPR_SMAG_LOCK | SMAPR_G1_SMBLOB);

	/* Allocate the descriptor */
	desc = caam_alloc_desc(BLOB_OPERATE_DESC_ENTRIES);
	if (!desc) {
		BLOB_TRACE("CAAM Context Descriptor Allocation error");
		retstatus = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_operate;
	}

	/*
	 * Create the Blob encapsulation descriptor
	 */
	desc_init(desc);
	desc_add_word(desc, DESC_HEADER(0));

	/**
	 * Command Protocol
	 *
	 * LD_IMM_OFF:
	 *	- LOAD command
	 *	- IMM Immediate flag, data follows as part of descriptor
	 *	- CLASS 2: object in CCB
	 *	- DST(REG_KEY): Class 2 Key register
	 *	- 0x08: length of the data
	 *	- 0x0c: offset of the data
	 */
	desc_add_word(desc, LD_IMM_OFF(CLASS_2, REG_KEY, 0x08, 0x0c));

	/**
	 * Additional authenticated data
	 *
	 * AAD_ALG_SIZE: key length
	 * AES CCM
	 */
	desc_add_word(desc, AAD_ALG_SIZE(blob_data->payload.length)
			| AAD_AES_SRC | AAD_CCM_MODE);

	/**
	 * Additional authenticated data
	 */
	desc_add_word(desc, 0x0);

	/* Define the Input data sequence */
	desc_add_word(desc, SEQ_IN_PTR(insize));
	desc_add_ptr(desc, paddr_input);

	/* Define the Output data sequence */
	desc_add_word(desc, SEQ_OUT_PTR(outsize));
	desc_add_ptr(desc, out_buf.paddr);

	/* Define the encapsulation operation */
	desc_add_word(desc, BLOB_ENCAPS | PROT_BLOB_SEC_MEM);

	BLOB_DUMPDESC(desc);

	cache_operation(TEE_CACHECLEAN, blob_data->key.data,
			blob_data->key.length);

	cache_operation(TEE_CACHECLEAN, blob_data->payload.data,
		rinsize);

	if (out_buf.nocache == 0)
		cache_operation(TEE_CACHEFLUSH, out_buf.data, out_buf.length);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		BLOB_TRACE("Done CAAM DEK BLOB encaps");

		if (out_buf.nocache == 0)
			cache_operation(TEE_CACHEINVALIDATE, out_buf.data,
				out_buf.length);

		BLOB_DUMPBUF("Output", out_buf.data, routsize);

		if (ret_input == 1)
			/*
			 * Copy the result data in the correct output
			 * buffer function of the operation direction
			 */
			memcpy(blob_data->blob.data, out_buf.data, routsize);

		blob_data->blob.length = routsize;

		retstatus = TEE_SUCCESS;
	} else {
		BLOB_TRACE("CAAM Status 0x%08"PRIx32"", jobctx.status);
		retstatus = TEE_ERROR_GENERIC;
	}

exit_operate:
	if (ret_input == 1)
		caam_free_buf(&out_buf);

	if (ret_output == 0)
		caam_sm_free(sm);

	caam_free_desc(&desc);

	return retstatus;
}

#else /* CFG_CRYPTO_SM_HW */
static inline TEE_Result do_dek(struct nxpcrypt_blob_data
						*blob_data __maybe_unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif /* CFG_CRYPTO_SM_HW */

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

		}

		if (blob_data->encaps)
			blob_data->blob.length = routsize;
		else
			blob_data->payload.length = routsize;

		ret = TEE_SUCCESS;
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
	.dek = &do_dek,
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
