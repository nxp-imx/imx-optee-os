// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    caam_mp.c
 *
 * @brief   CAAM Manufacturing Protection.
 */

/* Standard includes */
#include <string.h>

/* Global includes */
#include <mm/core_memprot.h>
#include <tee/cache.h>

/* Library i.MX includes */
#include <libimxcrypt.h>
#include <libimxcrypt_mp.h>
#include <libimxcrypt_hash.h>

/* Utils includes */
#include "utils_mem.h"

/* Local includes */
#include "common.h"
#include "caam_jr.h"
#include "caam_mp.h"

/* Library libutee includes */
#include <utee_defines.h>

/* Hal includes */
#include "hal_ctrl.h"

/*
 * Debug Macros
 */
#define MP_DEBUG
#ifdef MP_DEBUG
#define DUMP_DESC
//#define DUMP_BUF
#define MP_TRACE		DRV_TRACE
#else
#define MP_TRACE(...)
#endif

#ifdef DUMP_DESC
#define MP_DUMPDESC(desc)	{MP_TRACE("MP Descriptor"); \
							DRV_DUMPDESC(desc); }
#else
#define MP_DUMPDESC(desc)
#endif

#ifdef DUMP_BUF
#define MP_DUMPBUF	DRV_DUMPBUF
#else
#define MP_DUMPBUF(...)
#endif

/**
 * @brief   MP module private data
 *
 */
struct mp_privdata {
	uint8_t curve_sel;          ///< PDB curve selection
	uint8_t sec_key_size;       ///< Security key size in bytes
	uint8_t *val_mpmr;
};

/**
 * @brief   MP module private data reference
 */
static struct mp_privdata mp_privdata;

/**
 * @brief   MPPrivK-generation function.\n
 *          The ECDSA private key is securely stored in the MPPKR.\n
 *          This register is locked to prevent reading or writing.\n
 *
 * @param[in] passphrase         Passphrase
 * @param[in] len                Passphrase's length
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     General failure
 * @retval  CAAM_OUT_MEMORY  Out of memory
 */
static enum CAAM_Status do_mppriv_gen(const uint8_t *passphrase, size_t len,
					uint32_t curve)
{
#define MP_PRIV_DESC_ENTRIES	6
	enum CAAM_Status ret = CAAM_FAILURE;
	struct jr_jobctx jobctx = {0};
	descPointer_t desc = NULL;
	paddr_t paddr = 0;
	uint8_t desclen = 1;

	MP_TRACE("MPPriv generation function\n");

	/* We assume that the passphrase could be null */
	if (passphrase && (len == 0))
		goto exit_mppriv;

	paddr = virt_to_phys((void *)passphrase);
	if (!paddr)
		goto exit_mppriv;

	cache_operation(TEE_CACHECLEAN, (void *)passphrase, len);

	/* Allocate the job descriptor */
	desc = caam_alloc_desc(MP_PRIV_DESC_ENTRIES);
	if (!desc) {
		ret = CAAM_OUT_MEMORY;
		goto exit_mppriv;
	}

	/* Load the input message */
	desc[desclen++] = curve;
	desc[desclen++] = paddr;
	desc[desclen++] = len;

	/* MPPrivK Operation */
	desc[desclen++] = MPPRIVK;

	/* Set the descriptor Header with length and index */
	desc[0] = DESC_HEADER_IDX(desclen, (desclen - 1));

	MP_DUMPDESC(desc);

	jobctx.desc = desc;
	ret = caam_jr_enqueue(&jobctx, NULL);

	if (ret != CAAM_NO_ERROR) {
		MP_TRACE("CAAM Status 0x%08"PRIx32"", jobctx.status);
	} else {
		MP_TRACE("Do Mppriv gen CAAM");
		ret = CAAM_NO_ERROR;
	}

exit_mppriv:
	caam_free_desc(&desc);
	return ret;
}

/**
 * @brief   Export the MPMR content.\n
 *          We assume that it is filled with message given in parameter.\n
 *          It contains 32 registers of 8 bits (32 bytes).
 *
 * @param[out] mpmr_reg                MPMR register
 *
 * @retval  TEE_SUCCESS                Success
 * @retval  TEE_ERROR_BAD_PARAMETERS   Bad parameters
 */
static TEE_Result do_mpmr(struct imxcrypt_buf *mpmr_reg)
{
	MP_TRACE("Get MPMR content");
	/* check the size of the MPMR register */
	if (mpmr_reg->length != hal_ctrl_get_mpmr_size())
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(mpmr_reg->data, mp_privdata.val_mpmr, mpmr_reg->length);

	return TEE_SUCCESS;
}

/**
 * @brief   Export the MPPub Key.\n
 *          This function uses the private key stored in the MPPKR.
 *
 * @param[out] pubkey          MP Public key structure
 *
 * @retval  TEE_SUCCESS                Success
 * @retval  TEE_ERROR_GENERIC          General error
 * @retval  TEE_ERROR_BAD_PARAMETERS   Bad parameters
 * @retval  TEE_ERROR_OUT_OF_MEMORY    Out of memory
 */
static TEE_Result do_mppub(struct imxcrypt_buf *pubkey)
{
#define MP_PUB_DESC_ENTRIES	6
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum CAAM_Status retstatus = CAAM_FAILURE;
	struct jr_jobctx jobctx = {0};
	descPointer_t desc = NULL;
	uint8_t desclen = 1;
	int retP = 0;
	struct caambuf key = {0};

	/* check the public key size in function of the curve */
	if (pubkey->length < (2 * mp_privdata.sec_key_size))
		goto exit_mppub;

	retP = caam_realloc_align(pubkey->data, &key, pubkey->length);

	if (retP == (-1)) {
		MP_TRACE("Key reallocation error");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_mppub;
	}

	/* Allocate the job descriptor */
	desc = caam_alloc_desc(MP_PUB_DESC_ENTRIES);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_mppub;
	}

	/* Load the input message */
	desc[desclen++] = SHIFT_U32((mp_privdata.curve_sel & 0xFF), 17);

	/* Output message */
	desc[desclen++] = key.paddr;
	desc[desclen++] = pubkey->length;

	/* MPPrivK Operation */
	desc[desclen++] = MPPUBK;

	/* Set the descriptor Header with length and index */
	desc[0] = DESC_HEADER_IDX(desclen, (desclen - 1));

	MP_DUMPDESC(desc);

	if (key.nocache == 0)
		cache_operation(TEE_CACHEFLUSH, key.data, pubkey->length);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		MP_TRACE("Do Mppub gen CAAM");
		if (key.nocache == 0)
			cache_operation(TEE_CACHEINVALIDATE, key.data,
				pubkey->length);

		if (retP == 1)
			memcpy(pubkey->data, key.data, pubkey->length);

		ret = TEE_SUCCESS;
	} else {
		MP_TRACE("CAAM Status 0x%08"PRIx32"", jobctx.status);
	}

exit_mppub:
	if (retP == 1)
		caam_free_buf(&key);

	caam_free_desc(&desc);
	return ret;
}

/**
 * @brief   MPSign function.\n
 *          This function takes the value in the MPMR if it exists\n
 *          and concatenates any additional data (certificate).\n
 *          The signature over the message is done with the private key.
 *
 * @param[in/out]  sdata          MP Signature structure
 *
 * @retval  TEE_SUCCESS                Success
 * @retval  TEE_ERROR_GENERIC          General error
 * @retval  TEE_ERROR_BAD_PARAMETERS   Bad parameters
 */
static TEE_Result do_mpsign(struct imxcrypt_mp_sign *sdata)
{
#define MP_SIGN_DESC_ENTRIES	9
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum CAAM_Status retstatus = CAAM_FAILURE;
	struct jr_jobctx jobctx = {0};
	descPointer_t desc = NULL;
	paddr_t paddr_m = 0;

	struct caambuf sig = {0};
	struct caambuf h   = {0};
	size_t len_hash = TEE_MAX_HASH_SIZE;
	int retS = 0;
	uint8_t desclen = 1;

	/* check the signature size in function of the curve */
	if (sdata->signature.length < 2*mp_privdata.sec_key_size)
		goto exit_mpsign;

	/* Reallocate the signature to be cache alogned */
	retS = caam_realloc_align(sdata->signature.data, &sig,
		sdata->signature.length);
	if (retS == (-1)) {
		MP_TRACE("Signature reallocation error");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_mpsign;
	}

	/*
	 * Allocate the hash buffer of the Message + MPMR payload
	 * Note: Hash is not retrieve, hence no need to do cache
	 * maintenance
	 */
	retstatus = caam_alloc_align_buf(&h, len_hash);
	if (retstatus != CAAM_NO_ERROR) {
		MP_TRACE("Hash allocation error");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_mpsign;
	}

	/* convert address virt to phys for message */
	paddr_m = virt_to_phys(sdata->message.data);
	if (!paddr_m)
		goto exit_mpsign;

	/* Allocate the job descriptor */
	desc = caam_alloc_desc(MP_SIGN_DESC_ENTRIES);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_mpsign;
	}

	/* Load the input message */
	desc[desclen++] = SHIFT_U32((mp_privdata.curve_sel & 0xFF), 17);
	desc[desclen++] = paddr_m;

	/* Hash of message + MPMR result - Not used */
	desc[desclen++] = h.paddr;
	/* Signature in the format (c, d) */
	desc[desclen++] = sig.paddr;
	desc[desclen++] = sig.paddr +
		(mp_privdata.sec_key_size * sizeof(uint8_t));
	/* Message Length */
	desc[desclen++] = sdata->message.length;

	/* MPPrivK Operation */
	desc[desclen++] = MPSIGN_OP;

	/* Set the descriptor Header with length and index */
	desc[0] = DESC_HEADER_IDX(desclen, (desclen - 1));

	MP_DUMPDESC(desc);

	cache_operation(TEE_CACHECLEAN, sdata->message.data,
		sdata->message.length);

	if (sig.nocache == 0)
		cache_operation(TEE_CACHEFLUSH, sig.data,
			sdata->signature.length);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		MP_TRACE("Do Mpsign gen CAAM");
		if (sig.nocache == 0)
			cache_operation(TEE_CACHEINVALIDATE, sig.data,
				sdata->signature.length);

		if (retS == 1)
			memcpy(sdata->signature.data, sig.data,
				sdata->signature.length);

		ret = TEE_SUCCESS;
	} else {
		MP_TRACE("CAAM Status 0x%08"PRIx32"", jobctx.status);
	}

exit_mpsign:
	if (retS == 1)
		caam_free_buf(&sig);

	caam_free_buf(&h);
	caam_free_desc(&desc);
	return ret;
}

/**
 * @brief   Registration of the MP Driver
 */
struct imxcrypt_mp driver_mp = {
	.export_pubkey = &do_mppub,
	.export_mpmr = &do_mpmr,
	.sign = &do_mpsign,
};

/**
 * @brief   Initialize the MP module and generate the private key
 *
 * @param[in] ctrl_addr   Controller base address
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 * @retval  CAAM_OUT_MEMORY  Out of memory
 */
enum CAAM_Status caam_mp_init(vaddr_t ctrl_addr)
{
	enum CAAM_Status retstatus = CAAM_FAILURE;
	int hash_limit;
	const char *passphrase = "manufacturing protection";
	struct imxcrypt_buf msg_mpmr;
	const char *mpmr_data = "value to fill the MPMR content";

	msg_mpmr.data = (uint8_t *)mpmr_data;
	msg_mpmr.length = strlen(mpmr_data);

	/* store the ctrl_addr in the private data */
	hash_limit = hal_ctrl_hash_limit(ctrl_addr);

	switch (hash_limit) {
	/* store the curve selection in the private data */
	case HASH_SHA256:
		mp_privdata.curve_sel = PDB_MP_CSEL_P256;
		mp_privdata.sec_key_size = 32; break;
	case HASH_SHA384:
		mp_privdata.curve_sel = PDB_MP_CSEL_P384;
		mp_privdata.sec_key_size = 48; break;
	case HASH_SHA512:
		mp_privdata.curve_sel = PDB_MP_CSEL_P521;
		mp_privdata.sec_key_size = 66; break;

	default:
		MP_TRACE("This curve doesn't exist"); return retstatus;
	}

	if (!hal_ctrl_is_mpcurve(ctrl_addr)) {
		MP_TRACE("MP Private key has not been generated .\n");
		retstatus = do_mppriv_gen((const uint8_t *)passphrase,
                            strlen(passphrase),
			SHIFT_U32((PDB_MP_CSEL_P256 & 0xFF), 17));
		if (retstatus != CAAM_NO_ERROR) {
			MP_TRACE("do_mppriv_gen failed!");
			return retstatus;
		}
	}

	mp_privdata.val_mpmr = malloc(hal_ctrl_get_mpmr_size());
	if (!mp_privdata.val_mpmr) {
		EMSG("malloc failed\n");
		return CAAM_FAILURE;
	}

	/* fill the MPMR content then lock it */
	hal_ctrl_fill_mpmr(ctrl_addr, &msg_mpmr);

	/* see the MPMR content (32 registers of 8 bits) */
	hal_ctrl_get_mpmr(ctrl_addr, mp_privdata.val_mpmr);

	if (imxcrypt_register(CRYPTO_MP, &driver_mp) == 0)
		retstatus = CAAM_NO_ERROR;
	else
		retstatus = CAAM_FAILURE;

	return retstatus;
}
