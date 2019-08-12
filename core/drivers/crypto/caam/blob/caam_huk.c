// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 NXP
 *
 * Brief   CAAM Generation of a Hardware Unique Key.
 *         Use the CAAM Blob Verify Master Key operation
 */
#include <caam_common.h>
#include <caam_huk.h>
#include <caam_jr.h>
#include <caam_utils_mem.h>
#include <caam_utils_status.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <tee/cache.h>
#include <utee_defines.h>
#include <string.h>

/* Blob Key Modifier size in bytes */
#define BLOB_KEY_MODIFIER_SIZE 16

/* Blob Key (BKEK) size in bytes */
#define BLOB_BKEK_SIZE 32

/*
 * HUK State
 */
enum huk_state {
	CAAM_HUK_EMPTY,     /* Initialized but not generated */
	CAAM_HUK_GENERATED, /* Generated */
	CAAM_HUK_ERROR      /* Error can not be generated */
};

/*
 * HUK module private data
 */
struct huk_privdata {
	enum huk_state state;  /* HUK state flag */
	struct caambuf huk;    /* HUK buffer */
};

static struct huk_privdata *huk_privdata;

/*
 * Verify Master Key (derives a BKEK from the secret master key).
 * This BKEK is not the same used during normal blob encapsulation.
 *
 * @outkey  [out] Output key generated
 */
static TEE_Result caam_master_key_verif(struct caambuf *outkey)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	paddr_t paddr_keymod = 0;
	uint8_t keymod_buf[BLOB_KEY_MODIFIER_SIZE] = {};
	struct caam_jobctx jobctx = {};
	uint32_t *desc = NULL;

#ifdef CFG_CAAM_64BIT
#define BLOB_MASTER_KEY_VERIF 9
#else
#define BLOB_MASTER_KEY_VERIF 7
#endif
	/* Check if parameters are correct */
	if (!outkey)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!outkey->data)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Get the physical address of the key modifier */
	paddr_keymod = virt_to_phys(keymod_buf);
	if (!paddr_keymod)
		return TEE_ERROR_GENERIC;

	/* Allocate the job descriptor */
	desc = caam_calloc_desc(BLOB_MASTER_KEY_VERIF);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_masterkey;
	}

	/*
	 * Create the Master Key Verification descriptor
	 */
	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));

	/* Load the key modifier */
	caam_desc_add_word(desc,
			   LD_NOIMM(CLASS_2, REG_KEY, BLOB_KEY_MODIFIER_SIZE));
	caam_desc_add_ptr(desc, paddr_keymod);

	/* Output key storage */
	caam_desc_add_word(desc, SEQ_OUT_PTR(BLOB_BKEK_SIZE));
	caam_desc_add_ptr(desc, outkey->paddr);

	/* Blob Master key verification operation */
	caam_desc_add_word(desc, BLOB_MSTR_KEY);

	BLOB_DUMPDESC(desc);

	cache_operation(TEE_CACHECLEAN, keymod_buf, BLOB_KEY_MODIFIER_SIZE);
	cache_operation(TEE_CACHEFLUSH, outkey->data, outkey->length);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		cache_operation(TEE_CACHEINVALIDATE, outkey->data,
				outkey->length);
		BLOB_DUMPBUF("Master Key", outkey->data, outkey->length);

		ret = TEE_SUCCESS;
	} else {
		BLOB_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

exit_masterkey:
	caam_free_desc(&desc);

	return ret;
}

/*
 * Return a HW unique key value.
 * On i.MX device, return a derivation of the Master Key
 * by calling the CAAM Blob master key verification
 * operation using a key modifier corresponding of the
 * first 16 bytes of the Die ID
 *
 * @hwhuk  [out] HW Unique key
 */
TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwhuk)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	/* Initialize the HUK value */
	memset(hwhuk->data, 0, sizeof(hwhuk->data));

	if (!huk_privdata)
		return ret;

	if (huk_privdata->state == CAAM_HUK_EMPTY) {
		ret = caam_master_key_verif(&huk_privdata->huk);
		if (ret == TEE_SUCCESS)
			huk_privdata->state = CAAM_HUK_GENERATED;
	}

	if (huk_privdata->state == CAAM_HUK_GENERATED) {
		memcpy(hwhuk->data, huk_privdata->huk.data,
		       MIN(sizeof(hwhuk->data), huk_privdata->huk.length));
	}

	/*
	 * TODO Add check if device type
	 * If there is an error during the Master key derivation,
	 * let the device booting with a 0's key
	 */
	if (ret != TEE_SUCCESS)
		ret = TEE_SUCCESS;

	return ret;
}

/*
 * Initialize the HUK module
 *
 * @ctrl_addr   Controller base address
 */
enum caam_status caam_huk_init(vaddr_t ctrl_addr __unused)
{
	enum caam_status ret = CAAM_FAILURE;

	/* Allocate the Private data */
	huk_privdata = caam_calloc(sizeof(struct huk_privdata));
	if (!huk_privdata)
		return CAAM_OUT_MEMORY;

	/* Allocate the HUK buffer */
	ret = caam_calloc_align_buf(&huk_privdata->huk, BLOB_BKEK_SIZE);
	if (ret == CAAM_NO_ERROR)
		huk_privdata->state = CAAM_HUK_EMPTY;
	else
		huk_privdata->state = CAAM_HUK_ERROR;

	return ret;
}
