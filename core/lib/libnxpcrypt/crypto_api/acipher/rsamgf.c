// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    rsamgf.c
 *
 * @brief   RSA Mask Generation function implementation.
 */

/* Global includes */
#include <malloc.h>
#include <string.h>
#include <trace.h>
#include <utee_defines.h>

/* Library NXP includes */
#include <libnxpcrypt.h>
#include <libnxpcrypt_acipher.h>

/* Local includes */
#include "local.h"

/*
 * Debug Macros
 */
//#define RSA_DEBUG
#ifdef RSA_DEBUG
#define DUMP_DESC
#define DUMP_BUF
#define RSA_TRACE		DMSG
#else
#define RSA_TRACE(...)
#endif

#ifdef DUMP_BUF
#define RSA_DUMPBUF(title, buf, len) \
					{RSA_TRACE("%s @ 0x%"PRIxPTR": %d", \
						title, (uintptr_t)buf, len); \
					 dhex_dump(NULL, 0, 0, buf, len); }
#else
#define RSA_DUMPBUF(...)
#endif

/**
 * @brief   Mask Generation function. Use a Hash operation
 *          to generate an output \a mask from a input \a seed
 *
 * @param[in/out] mgf_data  MGF data
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 */
TEE_Result rsa_mgf1(struct nxpcrypt_rsa_mgf *mgf_data)
{
	TEE_Result ret;

	enum nxpcrypt_hash_id hash_id = mgf_data->hash_id;
	struct nxpcrypt_hash *hash = NULL;
	void     *ctx = NULL;
	size_t   lastBlock_size;
	size_t   nbBlock = 0;
	uint32_t counter = 0;
	uint32_t swapcount;
	uint8_t  *cur_mask = mgf_data->mask.data;
	uint8_t  *tmpdigest = NULL;


	RSA_TRACE("Generate Mask (%d bytes) with seed of %d bytes",
			mgf_data->mask.length, mgf_data->seed.length);

	hash = nxpcrypt_getmod(CRYPTO_HASH);

	/* Verify that the HASH HW implements this algorithm */
	if (hash) {
		if (hash->max_hash < hash_id)
			hash = nxpcrypt_getmod(CRYPTO_HASH_SW);
	} else {
		hash = nxpcrypt_getmod(CRYPTO_HASH_SW);
	}

	if (!hash)
		return TEE_ERROR_NOT_IMPLEMENTED;

	/* Calculate the number of complet hash digest*/
	lastBlock_size = mgf_data->mask.length % mgf_data->digest_size;
	if (lastBlock_size) {
		/* Allocate a digest buffer for the last block */
		tmpdigest = malloc(mgf_data->digest_size);
		if (!tmpdigest)
			return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Allocate the Hash Context */
	ret = hash->alloc_ctx(&ctx, hash_id);
	if (ret != TEE_SUCCESS)
		goto exit_mgf;

	nbBlock = (mgf_data->mask.length - lastBlock_size) /
	    mgf_data->digest_size;

	RSA_TRACE("Nb Loop (%d bytes) = %d, last Block = %d byes",
		mgf_data->digest_size, nbBlock, lastBlock_size);

	for (counter = 0; counter < nbBlock; counter++,
		cur_mask += mgf_data->digest_size) {

		swapcount = TEE_U32_TO_BIG_ENDIAN(counter);

		ret = hash->init(ctx);
		if (ret != TEE_SUCCESS)
			goto exit_mgf;

		ret = hash->update(ctx, mgf_data->seed.data,
			mgf_data->seed.length);
		if (ret != TEE_SUCCESS)
			goto exit_mgf;

		ret = hash->update(ctx, (uint8_t *)&swapcount,
				sizeof(swapcount));
		if (ret != TEE_SUCCESS)
			goto exit_mgf;

		ret = hash->final(ctx, cur_mask, mgf_data->digest_size);
		if (ret != TEE_SUCCESS)
			goto exit_mgf;
	}

	if (lastBlock_size) {
		RSA_TRACE("Last Block = %d bytes", lastBlock_size);

		swapcount = TEE_U32_TO_BIG_ENDIAN(counter);

		ret = hash->init(ctx);
		if (ret != TEE_SUCCESS)
			goto exit_mgf;

		ret = hash->update(ctx, mgf_data->seed.data,
			mgf_data->seed.length);
		if (ret != TEE_SUCCESS)
			goto exit_mgf;

		ret = hash->update(ctx, (uint8_t *)&swapcount,
				sizeof(swapcount));
		if (ret != TEE_SUCCESS)
			goto exit_mgf;

		ret = hash->final(ctx, tmpdigest, mgf_data->digest_size);
		if (ret != TEE_SUCCESS)
			goto exit_mgf;

		memcpy(cur_mask, tmpdigest, lastBlock_size);
	}

	RSA_DUMPBUF("MGF1 Input", mgf_data->seed.data, mgf_data->seed.length);
	RSA_DUMPBUF("MGF1 Mask", mgf_data->mask.data, mgf_data->mask.length);

	ret = TEE_SUCCESS;

exit_mgf:
	hash->free_ctx(ctx);
	free(tmpdigest);

	RSA_TRACE("ret 0x%08"PRIx32"", ret);
	return ret;
}


