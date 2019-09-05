// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   CAAM Manufacturing Protection.
 */
#include <caam_common.h>
#include <caam_hal_ctrl.h>
#include <caam_jr.h>
#include <caam_mp.h>
#include <caam_utils_mem.h>
#include <caam_utils_sgt.h>
#include <caam_utils_status.h>
#include <drivers/caam/crypto_extension.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>
#include <utee_defines.h>

/*
 * MP module private data
 * We know that curve is 4 bits and the Security key size will not
 * exceed 66 bytes.
 */
struct mp_privdata {
	uint8_t curve;     /* PDB curve selection */
	uint8_t sec_size;  /* Security key size in bytes */
	vaddr_t ctrl_addr; /* Base address of the controller */
};

/*
 * MP module private data reference
 */
static struct mp_privdata mp_privdata;

/*
 * MPPrivK-generation function.
 * The ECDSA private key is securely stored in the MPPKR.
 * This register is locked to prevent reading or writing.
 *
 * @passphrase  Passphrase
 * @len         Passphrase's length
 */
static enum caam_status do_mppriv_gen(const char *passphrase, size_t len)
{
	enum caam_status ret = CAAM_FAILURE;
	struct caam_jobctx jobctx = {};
	uint32_t *desc = NULL;
	paddr_t paddr = 0;
	uint32_t desclen = 0;

#ifdef CFG_PHYS_64BIT
#define MP_PRIV_DESC_ENTRIES 7
#else
#define MP_PRIV_DESC_ENTRIES 6
#endif

	MP_TRACE("MPPriv generation function");

	/* We assume that the passphrase could be null */
	if (passphrase && !len)
		goto exit_mppriv;

	paddr = virt_to_phys((void *)passphrase);
	if (!paddr)
		goto exit_mppriv;

	cache_operation(TEE_CACHECLEAN, (void *)passphrase, len);

	/* Allocate the job descriptor */
	desc = caam_calloc_desc(MP_PRIV_DESC_ENTRIES);
	if (!desc) {
		ret = CAAM_OUT_MEMORY;
		goto exit_mppriv;
	}

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	/* MP Curve PDB */
	caam_desc_add_word(desc, PROT_MP_CURVE(mp_privdata.curve));

	/* Load the input message */
	caam_desc_add_ptr(desc, paddr);
	caam_desc_add_word(desc, len);

	/* MPPrivK Operation */
	caam_desc_add_word(desc, MPPRIVK);

	/* Set the descriptor Header with length and index */
	desclen = caam_desc_get_len(desc);
	caam_desc_update_hdr(desc, DESC_HEADER_IDX(desclen, desclen - 1));

	MP_DUMPDESC(desc);

	jobctx.desc = desc;
	ret = caam_jr_enqueue(&jobctx, NULL);

	if (ret != CAAM_NO_ERROR) {
		MP_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = CAAM_NOT_SUPPORTED;
	} else {
		MP_TRACE("Do Mppriv gen CAAM");
		ret = CAAM_NO_ERROR;
	}

exit_mppriv:
	caam_free_desc(&desc);
	return ret;
}

TEE_Result crypto_mp_export_mpmr(struct cryptobuf *mpmr)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct caambuf caam_mpmr = { .data = mpmr->data,
				     .length = mpmr->length,
				     .paddr = 0 };

	MP_TRACE("Get MPMR content");

	/* Read the MPMR content */
	ret = caam_hal_ctrl_read_mpmr(mp_privdata.ctrl_addr, &caam_mpmr);
	mpmr->length = caam_mpmr.length;

	return ret;
}

TEE_Result crypto_mp_export_publickey(struct cryptobuf *pubkey)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_jobctx jobctx = {};
	uint32_t *desc = NULL;
	uint32_t desclen = 0;
	bool realloc = false;
	struct caambuf key_align = {};

#ifdef CFG_PHYS_64BIT
#define MP_PUB_DESC_ENTRIES 7
#else
#define MP_PUB_DESC_ENTRIES 6
#endif
	if (!pubkey->data) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto exit_mppub;
	}

	/* Check the public key size (ECC) that is twice secure size */
	if (pubkey->length < 2 * mp_privdata.sec_size) {
		pubkey->length = 2 * mp_privdata.sec_size;
		ret = TEE_ERROR_SHORT_BUFFER;
		goto exit_mppub;
	}

	retstatus = caam_set_or_alloc_align_buf(pubkey->data, &key_align,
					      pubkey->length, &realloc);

	if (retstatus != CAAM_NO_ERROR) {
		MP_TRACE("Key reallocation error");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_mppub;
	}

	/* Allocate the job descriptor */
	desc = caam_calloc_desc(MP_PUB_DESC_ENTRIES);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_mppub;
	}

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));

	/* MP Curve PDB */
	caam_desc_add_word(desc, PROT_MP_CURVE(mp_privdata.curve));

	/* Output message */
	caam_desc_add_ptr(desc, key_align.paddr);
	caam_desc_add_word(desc, pubkey->length);

	/* MPPrivK Operation */
	caam_desc_add_word(desc, MPPUBK);

	/* Set the descriptor Header with length and index */
	desclen = caam_desc_get_len(desc);
	caam_desc_update_hdr(desc, DESC_HEADER_IDX(desclen, desclen - 1));

	MP_DUMPDESC(desc);

	if (!key_align.nocache)
		cache_operation(TEE_CACHEFLUSH, key_align.data,
				key_align.length);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		MP_TRACE("MP Public Key generated");
		if (!key_align.nocache)
			cache_operation(TEE_CACHEINVALIDATE, key_align.data,
					key_align.length);

		pubkey->length = 2 * mp_privdata.sec_size;

		if (realloc)
			memcpy(pubkey->data, key_align.data, pubkey->length);

		MP_DUMPBUF("MP PubKey", pubkey->data, pubkey->length);
		ret = TEE_SUCCESS;
	} else {
		MP_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

exit_mppub:
	if (realloc)
		caam_free_buf(&key_align);

	caam_free_desc(&desc);
	return ret;
}

TEE_Result crypto_mp_sign(struct crypto_mp_sign *sdata)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_jobctx jobctx = {};
	uint32_t *desc = NULL;
	paddr_t paddr_msg = 0;
	struct caambuf msg_tmp = {};
	struct caamsgtbuf sgtmsg = { .sgt_type = false };
	struct caambuf hash = {};
	uint32_t desclen = 0;
	uint32_t pdb_sgt_flags = 0;
	bool realloc = false;
	size_t sign_len = 0;
	struct caambuf sign_c_tmp = {};
	struct caambuf sign_d_tmp = {};
	struct caamsgtbuf sgtsign_c = { .sgt_type = false };
	struct caamsgtbuf sgtsign_d = { .sgt_type = false };
	paddr_t paddr_sign_c = 0;
	paddr_t paddr_sign_d = 0;

#ifdef CFG_PHYS_64BIT
#define MP_SIGN_DESC_ENTRIES 13
#else
#define MP_SIGN_DESC_ENTRIES 9
#endif

	if (!sdata->signature.data) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto exit_mpsign;
	}

	if (sdata->signature.length < 2 * mp_privdata.sec_size) {
		sdata->signature.length = 2 * mp_privdata.sec_size;
		ret = TEE_ERROR_SHORT_BUFFER;
		goto exit_mpsign;
	}

	/*
	 * Allocate the hash buffer of the Message + MPMR payload
	 * Note: Hash is not retrieve, hence no need to do cache
	 * maintenance
	 */
	retstatus = caam_alloc_align_buf(&hash, TEE_MAX_HASH_SIZE);
	if (retstatus != CAAM_NO_ERROR) {
		MP_TRACE("Hash allocation error");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_mpsign;
	}

	/*
	 * ReAllocate the signature result buffer with a maximum size
	 * of the roundup to 16 bytes of the secure size in bytes if
	 * the signature buffer is not aligned or too short.
	 *
	 *  - 1st Part: size_sec
	 *  - 2nd Part: size_sec roundup to 16 bytes
	 */
	sign_len = ROUNDUP(mp_privdata.sec_size, 16) + mp_privdata.sec_size;

	retstatus = caam_set_or_alloc_align_buf(sdata->signature.data,
					      &sign_c_tmp, sign_len,
					      &realloc);
	if (retstatus != CAAM_NO_ERROR) {
		MP_TRACE("Signature reallocation error");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_mpsign;
	}

	/* Prepare the 1st Part of the signature */
	sign_c_tmp.length = mp_privdata.sec_size;
	retstatus = caam_sgt_build_block_data(&sgtsign_c, NULL, &sign_c_tmp);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_GENERIC;
		goto exit_mpsign;
	}

	if (sgtsign_c.sgt_type) {
		pdb_sgt_flags |= PDB_SGT_MP_SIGN_C;
		paddr_sign_c = virt_to_phys(sgtsign_c.sgt);
		caam_sgt_cache_op(TEE_CACHEFLUSH, &sgtsign_c);
	} else {
		paddr_sign_c = sgtsign_c.buf->paddr;
		if (!sgtsign_c.buf->nocache)
			cache_operation(TEE_CACHEFLUSH, sgtsign_c.buf->data,
					sgtsign_c.length);
	}

	/* Prepare the 2nd Part of the signature */
	sign_d_tmp.data = sign_c_tmp.data + mp_privdata.sec_size;
	sign_d_tmp.length = ROUNDUP(mp_privdata.sec_size, 16);
	sign_d_tmp.paddr = virt_to_phys(sign_d_tmp.data);
	sign_d_tmp.nocache = sign_c_tmp.nocache;

	retstatus = caam_sgt_build_block_data(&sgtsign_d, NULL, &sign_d_tmp);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_GENERIC;
		goto exit_mpsign;
	}

	if (sgtsign_d.sgt_type) {
		pdb_sgt_flags |= PDB_SGT_MP_SIGN_D;
		paddr_sign_d = virt_to_phys(sgtsign_d.sgt);
		caam_sgt_cache_op(TEE_CACHEFLUSH, &sgtsign_d);
	} else {
		paddr_sign_d = sgtsign_d.buf->paddr;
		if (!sgtsign_d.buf->nocache)
			cache_operation(TEE_CACHEFLUSH, sgtsign_d.buf->data,
					sgtsign_d.length);
	}

	/* Prepare the input message CAAM descriptor entry */
	msg_tmp.data = sdata->message.data;
	msg_tmp.length = sdata->message.length;
	msg_tmp.paddr = virt_to_phys(sdata->message.data);
	if (!caam_mem_is_cached_buf(sdata->message.data,
				    sdata->message.length))
		msg_tmp.nocache = 1;

	retstatus = caam_sgt_build_block_data(&sgtmsg, NULL, &msg_tmp);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_GENERIC;
		goto exit_mpsign;
	}

	if (sgtmsg.sgt_type) {
		pdb_sgt_flags |= PDB_SGT_MP_SIGN_MSG;
		paddr_msg = virt_to_phys(sgtmsg.sgt);
		caam_sgt_cache_op(TEE_CACHECLEAN, &sgtmsg);
	} else {
		paddr_msg = sgtmsg.buf->paddr;
		if (!sgtmsg.buf->nocache)
			cache_operation(TEE_CACHECLEAN, sgtmsg.buf->data,
					sgtmsg.length);
	}

	/* Allocate the job descriptor */
	desc = caam_calloc_desc(MP_SIGN_DESC_ENTRIES);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_mpsign;
	}

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));

	/* MP Curve PDB */
	caam_desc_add_word(desc,
			   PROT_MP_CURVE(mp_privdata.curve) | pdb_sgt_flags);

	/* Load the input message */
	caam_desc_add_ptr(desc, paddr_msg);

	/* Hash of message + MPMR result - Not used */
	caam_desc_add_ptr(desc, hash.paddr);
	/* Signature in the format (c, d) */
	caam_desc_add_ptr(desc, paddr_sign_c);
	caam_desc_add_ptr(desc, paddr_sign_d);
	/* Message Length */
	caam_desc_add_word(desc, sdata->message.length);

	/* MPPrivK Operation */
	caam_desc_add_word(desc, MPSIGN_OP);

	/* Set the descriptor Header with length and index */
	desclen = caam_desc_get_len(desc);
	caam_desc_update_hdr(desc, DESC_HEADER_IDX(desclen, desclen - 1));

	MP_DUMPDESC(desc);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		MP_TRACE("Do Mpsign gen CAAM");
		if (!sign_c_tmp.nocache)
			cache_operation(TEE_CACHEINVALIDATE, sign_c_tmp.data,
					sign_len);

		sdata->signature.length = 2 * mp_privdata.sec_size;

		if (realloc)
			memcpy(sdata->signature.data, sign_c_tmp.data,
			       sdata->signature.length);

		MP_DUMPBUF("MP Signature", sdata->signature.data,
			   sdata->signature.length);
		ret = TEE_SUCCESS;
	} else {
		MP_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

exit_mpsign:
	if (realloc)
		caam_free_buf(&sign_c_tmp);

	caam_free_buf(&hash);
	caam_free_desc(&desc);

	if (sgtmsg.sgt_type)
		caam_sgtbuf_free(&sgtmsg);

	if (sgtsign_c.sgt_type)
		caam_sgtbuf_free(&sgtsign_c);

	if (sgtsign_d.sgt_type)
		caam_sgtbuf_free(&sgtsign_d);

	return ret;
}

enum caam_status caam_mp_init(vaddr_t ctrl_addr)
{
	enum caam_status retstatus = CAAM_FAILURE;
	uint8_t curve = 0;
	uint8_t hash_limit = 0;
	const char *passphrase = "manufacturing protection";
	const char *mpmr_data = "value to fill the MPMR content";
	struct caambuf msg_mpmr = { .data = (uint8_t *)mpmr_data,
				    .length = strlen(mpmr_data) };

	curve = caam_hal_ctrl_get_mpcurve(ctrl_addr);

	if (curve == UINT8_MAX) {
		EMSG("*************************************");
		EMSG("* Warning: Manufacturing protection *");
		EMSG("*          is not supported         *");
		EMSG("*************************************");
		/*
		 * Don't register the driver and return
		 * no error to not stop the boot. Because
		 * Driver is not registered, the MP will not
		 * be used.
		 */
		return CAAM_NOT_SUPPORTED;
	}

	if (!curve) {
		/*
		 * Get the device HASH Limit to select the
		 * MP Curve to be used
		 */
		hash_limit = caam_hal_ctrl_hash_limit(ctrl_addr);

		switch (hash_limit) {
		case TEE_MAIN_ALGO_SHA256:
			mp_privdata.curve = PDB_MP_CSEL_P256;
			mp_privdata.sec_size = 32;
			break;

		case TEE_MAIN_ALGO_SHA512:
			mp_privdata.curve = PDB_MP_CSEL_P521;
			mp_privdata.sec_size = 66;
			break;

		default:
			MP_TRACE("This curve doesn't exist");
			return CAAM_FAILURE;
		}

		MP_TRACE("MP Private key has not been generated");
		retstatus = do_mppriv_gen(passphrase, strlen(passphrase));

		if (retstatus != CAAM_NO_ERROR) {
			MP_TRACE("do_mppriv_gen failed!");
			EMSG("*************************************");
			EMSG("* Warning: Manufacturing protection *");
			EMSG("*          is not supported         *");
			EMSG("*************************************");
			return retstatus;
		}
	} else {
		/*
		 * MP Curve is already programmed
		 * Set the Secure Key size corresponding
		 */
		mp_privdata.curve = curve;

		switch (curve) {
		case PDB_MP_CSEL_P256:
			mp_privdata.sec_size = 32;
			break;

		case PDB_MP_CSEL_P384:
			mp_privdata.sec_size = 48;
			break;

		case PDB_MP_CSEL_P521:
			mp_privdata.sec_size = 66;
			break;

		default:
			MP_TRACE("This curve is not supported");
			return retstatus;
		}
	}

	/* Fill the MPMR content then lock it */
	caam_hal_ctrl_fill_mpmr(ctrl_addr, &msg_mpmr);

	/* Keep the CAAM controller base address */
	mp_privdata.ctrl_addr = ctrl_addr;

	return CAAM_NO_ERROR;
}
