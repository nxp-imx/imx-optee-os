// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019-2021 NXP
 *
 * Brief   CAAM Generation of an encapsulated DEK blob
 *         Use the CAAM Blob encapsulation from CAAM Secure Memory
 */
#include <caam_common.h>
#include <caam_sm.h>
#include <caam_utils_mem.h>
#include <caam_utils_sgt.h>
#include <drivers/caam/crypto_extension.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

#ifdef CFG_PHYS_64BIT
#define BLOB_OPERATE_DESC_ENTRIES 12
#else
#define BLOB_OPERATE_DESC_ENTRIES 10
#endif

TEE_Result caam_blob_sm_encapsulate(struct crypto_blob *blob,
				    struct crypto_sm_page *sm_page)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct sm_page_addr sm_addr = {};
	bool realloc = false;
	struct caambuf blob_align = {};
	struct caamsgtbuf sgtblob = { .sgt_type = false };
	paddr_t paddr_blob = 0;
	unsigned int opflags = 0;
	size_t outsize = 0;
	struct caam_jobctx jobctx = {};
	uint32_t *desc = NULL;

	if (!blob->payload.data || !blob->blob.data)
		return TEE_ERROR_BAD_PARAMETERS;

	outsize = blob->payload.length + BLOB_PAD_SIZE;

	switch (blob->type) {
	case BLOB_BLACK_CCM:
		opflags = PROT_BLOB_TYPE(BLACK_KEY) | PROT_BLOB_INFO(CCM);
		outsize = ROUNDUP(BLACK_KEY_CCM_SIZE(outsize), 16);
		break;

	case BLOB_BLACK_ECB:
		opflags = PROT_BLOB_TYPE(BLACK_KEY) | PROT_BLOB_INFO(ECB);
		outsize = ROUNDUP(BLACK_KEY_ECB_SIZE(outsize), 16);
		break;

	case BLOB_RED:
		break;

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (blob->blob.length < outsize) {
		BLOB_TRACE("Blob buffer too short expected %zu bytes", outsize);
		blob->blob.length = outsize;
		return TEE_ERROR_SHORT_BUFFER;
	}

	/* Re-allocate output buffer if alignment needed */
	retstatus = caam_set_or_alloc_align_buf(blob->blob.data, &blob_align,
					      outsize, &realloc);
	if (retstatus != CAAM_NO_ERROR) {
		BLOB_TRACE("Blob reallocation error");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	retstatus = caam_sgt_build_block_data(&sgtblob, NULL, &blob_align);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_GENERIC;
		goto exit_operate;
	}

	if (sgtblob.sgt_type) {
		paddr_blob = virt_to_phys(sgtblob.sgt);
		caam_sgt_cache_op(TEE_CACHEFLUSH, &sgtblob);
	} else {
		paddr_blob = sgtblob.buf->paddr;
		if (!sgtblob.buf->nocache)
			cache_operation(TEE_CACHEFLUSH, sgtblob.buf->data,
					sgtblob.length);
	}

	/* Allocate page(s) in one Secure Memory partition */
	ret = caam_sm_alloc(sm_page, &sm_addr);
	if (ret != CAAM_NO_ERROR) {
		BLOB_TRACE("Secure memory allocation error 0x%" PRIx32, ret);
		goto exit_operate;
	}

	/*
	 * Set the partition access rights for the group #1 to be
	 * a blob export/import
	 */
	/* Copy input data to encapsulate in Secure Memory allocated */
	memcpy((void *)sm_addr.vaddr, blob->payload.data, blob->payload.length);

	BLOB_DUMPBUF("Secure Memory", (void *)sm_addr.vaddr,
		     blob->payload.length);

	caam_sm_set_access_perm(sm_page, SM_GRP_BLOB, 0);

	/* Allocate the descriptor */
	desc = caam_calloc_desc(BLOB_OPERATE_DESC_ENTRIES);
	if (!desc) {
		BLOB_TRACE("CAAM Context Descriptor Allocation error");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_operate;
	}

	/*
	 * Create the Blob encapsulation descriptor
	 */
	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));

	/*
	 * Command Protocol - The Key Modifier used when payload is
	 * in Secure Memory is only 64 bits and it's loaded in the
	 * Class 2 Key register at offset 12.
	 *
	 * Use the load immediata key value because key is small.
	 */
	caam_desc_add_word(desc, LD_IMM_OFF(CLASS_2, REG_KEY, 8, 12));
	caam_desc_add_word(desc, blob->key[0]);
	caam_desc_add_word(desc, blob->key[1]);

	/* Define the Input data sequence */
	caam_desc_add_word(desc, SEQ_IN_PTR(blob->payload.length));
	caam_desc_add_ptr(desc, sm_addr.paddr);

	/* Define the Output data sequence */
	if (sgtblob.sgt_type)
		caam_desc_add_word(desc, SEQ_OUT_PTR(sgtblob.length));
	else
		caam_desc_add_word(desc, SEQ_OUT_PTR(sgtblob.length));
	caam_desc_add_ptr(desc, paddr_blob);

	/* Define the encapsulation operation */
	caam_desc_add_word(desc, BLOB_ENCAPS | PROT_BLOB_SEC_MEM | opflags);

	BLOB_DUMPDESC(desc);

	cache_operation(TEE_CACHECLEAN, blob->payload.data,
			blob->payload.length);
	caam_dmaobj_cache_push(&resblob);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		BLOB_TRACE("Done CAAM BLOB from Secure Memory encaps");

		if (!blob_align.nocache)
			cache_operation(TEE_CACHEINVALIDATE, blob_align.data,
					blob_align.length);

		BLOB_DUMPBUF("Blob Output", blob_align.data, blob_align.length);

		blob->blob.length = blob_align.length;

		if (realloc)
			memcpy(blob->blob.data, blob_align.data,
			       blob->blob.length);

		ret = TEE_SUCCESS;
	} else {
		BLOB_TRACE("CAAM Status 0x%08" PRIx32 "", jobctx.status);
		ret = TEE_ERROR_GENERIC;
	}

exit_operate:
	if (realloc)
		caam_free_buf(&blob_align);

	caam_sm_free_page(sm_page);
	caam_free_desc(&desc);

	if (sgtblob.sgt_type)
		caam_sgtbuf_free(&sgtblob);

	return ret;
}
