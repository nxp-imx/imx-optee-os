// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP\n
 *
 * @file    authenc.c
 *
 * @brief   Cryptographic library using the NXP CAAM driver.\n
 *          Authentication common function implementation.
 */

/* Global includes */
#include <crypto/crypto.h>
#include <malloc.h>
#include <trace.h>

/* Library NXP includes */
#include <libnxpcrypt.h>
#include <libnxpcrypt_authenc.h>

/* Local include */
#include "local.h"

//#define LIB_DEBUG
#ifdef LIB_DEBUG
#define LIB_TRACE	DMSG
#else
#define LIB_TRACE(...)
#endif

/**
 * @brief  Format the Authentication Encryption context to keep
 *         the reference to the operation driver
 */
struct crypto_authenc {
	void                    *ctx; ///< Context
	struct nxpcrypt_authenc *op;  ///< Reference to the operation
};


/**
 * @brief   Checks and returns reference to the driver operations
 *
 * @param[in]  algo        Algorithm
 * @param[out] authenc_id  Authentication Encryption Algorithm internal ID
 *
 * @retval  Reference to the driver operations
 */
static struct nxpcrypt_authenc *do_check_algo(uint32_t algo,
	enum nxpcrypt_authenc_id *authenc_id)
{
	struct nxpcrypt_authenc *authenc = NULL;

	LIB_TRACE("Check Authentication algo %x", algo);

	authenc = nxpcrypt_getmod(CRYPTO_AUTHENC);
	if (!authenc)
		authenc = nxpcrypt_getmod(CRYPTO_AUTHENC_SW);

	if (!authenc)
		return NULL;

	switch (algo) {
	case TEE_ALG_AES_CCM:
		*authenc_id = AES_CCM;
		break;

	case TEE_ALG_AES_GCM:
		*authenc_id = AES_GCM;
		if (!authenc->aes_gcm)
			authenc = nxpcrypt_getmod(CRYPTO_AUTHENC_SW);
		break;

	default:
		authenc = NULL;
		break;
	}

	LIB_TRACE("Check Authentication id: %d ret 0x%"PRIxPTR"",
				*authenc_id, (uintptr_t)authenc);

	return authenc;
}

/**
 * @brief   Allocates the Software Authentication Encryption Context
 *          function of the algorithm
 *
 * @param[in/out] ctx    Reference the context pointer
 * @param[in]     algo   Algorithm
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
TEE_Result authenc_alloc_ctx(void **ctx, uint32_t algo)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct crypto_authenc    *authenc   = NULL;
	enum nxpcrypt_authenc_id authenc_id = 0;

	/* Check the parameters */
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	authenc = calloc(1, sizeof(*authenc));
	if (!authenc)
		return TEE_ERROR_OUT_OF_MEMORY;

	authenc->op = do_check_algo(algo, &authenc_id);
	if (authenc->op) {
		if (authenc->op->alloc_ctx)
			ret = authenc->op->alloc_ctx(&authenc->ctx, authenc_id);
	} else {
		free(authenc);
		authenc = NULL;
	}

	*ctx = authenc;

	return ret;
}

/**
 * @brief   Free the Software Authentication Encryption Context
 *          function of the algorithm
 *
 * @param[in/out] ctx    Reference the context pointer
 * @param[in]     algo   Algorithm
 */
void authenc_free_ctx(void *ctx, uint32_t algo __unused)
{
	struct crypto_authenc *authenc = ctx;

	/* Check the parameters */
	if (ctx) {
		if (authenc->op) {
			if (authenc->op->free_ctx)
				authenc->op->free_ctx(authenc->ctx);
		}
		free(authenc);
	}
}

/**
 * @brief   Copy Software Authentication Encryption Context
 *
 * @param[in]  src_ctx  Reference the context source
 * @param[in]  algo     Algorithm
 * @param[out] dst_ctx  Reference the context destination
 */
void authenc_copy_state(void *dst_ctx, void *src_ctx,
		uint32_t algo __unused)
{
	struct crypto_authenc *authenc_src = src_ctx;
	struct crypto_authenc *authenc_dst = dst_ctx;

	if ((!dst_ctx) || (!src_ctx))
		return;

	if (authenc_src->op) {
		if (authenc_src->op->cpy_state)
			authenc_src->op->cpy_state(authenc_dst->ctx,
				authenc_src->ctx);
	}
}

/**
 * @brief  Initialization of the Authentication Encryption operation
 *
 * @param[in] ctx          Reference the context pointer
 * @param[in] algo         Algorithm
 * @param[in] mode         Operation mode
 * @param[in] key          Key
 * @param[in] key_len      Length of the key
 * @param[in] nonce        Nonce
 * @param[in] nonce_len    Length of the Nonce
 * @param[in] tag_len      Length of the tag
 * @param[in] aad_len      Length of the Associated Data
 * @param[in] payload_len  Length of the payload
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
TEE_Result authenc_init(void *ctx, uint32_t algo __unused,
			TEE_OperationMode mode,
			const uint8_t *key, size_t key_len,
			const uint8_t *nonce, size_t nonce_len,
			size_t tag_len, size_t aad_len,	size_t payload_len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct crypto_authenc *authenc = ctx;
	struct nxpcrypt_authenc_init dinit;

	/* Check the parameters */
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check the mode */
	if ((mode != TEE_MODE_DECRYPT) && (mode != TEE_MODE_ENCRYPT)) {
		LIB_TRACE("Bad Authentication mode request %d", mode);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check the keys vs. length */
	if (((!key) && (key_len != 0)) ||
		((!nonce) && (nonce_len != 0))) {
		LIB_TRACE("One of the key is bad");
		LIB_TRACE("key   @0x%08"PRIxPTR"-%d",
			(uintptr_t)key, key_len);
		LIB_TRACE("nonce @0x%08"PRIxPTR"-%d",
			(uintptr_t)nonce, nonce_len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (authenc->op) {
		if (authenc->op->init) {
			/* Prepare the initialization data */
			dinit.ctx          = authenc->ctx;
			dinit.encrypt      = ((mode == TEE_MODE_ENCRYPT) ?
				true : false);
			dinit.key.data     = (uint8_t *)key;
			dinit.key.length   = key_len;
			dinit.nonce.data   = (uint8_t *)nonce;
			dinit.nonce.length = nonce_len;
			dinit.tag_len      = tag_len;
			dinit.aad_len      = aad_len;
			dinit.payload_len  = payload_len;
			ret = authenc->op->init(&dinit);
		}
	}

	return ret;
}

/**
 * @brief  Update the Authentication Associated Data
 *
 * @param[in] ctx          Reference the context pointer
 * @param[in] algo         Algorithm
 * @param[in] data         Data to add
 * @param[in] len          Length of the data
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_GENERIC           Generic Error
 */
TEE_Result authenc_update_aad(void *ctx, uint32_t algo __unused,
				const uint8_t *data, size_t len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct crypto_authenc *authenc = ctx;
	struct nxpcrypt_authenc_aad daad;

	/* Check the parameters */
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check the data vs. length */
	if ((!data) && (len != 0)) {
		LIB_TRACE("Bad data  @0x%08"PRIxPTR"-%d",
			(uintptr_t)data, len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (authenc->op) {
		if (authenc->op->update_aad) {
			/* Prepare the aad data */
			daad.ctx        = authenc->ctx;
			daad.aad.data   = (uint8_t *)data;
			daad.aad.length = len;
			ret = authenc->op->update_aad(&daad);
		}
	}

	return ret;
}

/**
 * @brief  Update Authentication data and returns result
 *
 * @param[in] ctx          Reference the context pointer
 * @param[in] algo         Algorithm
 * @param[in] mode         Operation mode
 * @param[in] src_data     Source
 * @param[in] src_len      Length of the source
 *
 * @param[out] dst_data    Destination
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_GENERIC           Other Error
 */
TEE_Result authenc_update_payload(void *ctx, uint32_t algo __unused,
				TEE_OperationMode mode,
				const uint8_t *src_data, size_t src_len,
				uint8_t *dst_data)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct crypto_authenc *authenc = ctx;
	struct nxpcrypt_authenc_data dpayload;

	/* Check the parameters */
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check the mode */
	if ((mode != TEE_MODE_DECRYPT) && (mode != TEE_MODE_ENCRYPT)) {
		LIB_TRACE("Bad Authentication mode request %d", mode);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check the data vs. length */
	if (((!src_data) && (src_len != 0)) ||
	    (!dst_data)) {
		LIB_TRACE("Bad data src/dst");
		LIB_TRACE("Src @0x%08"PRIxPTR"-%d",
			(uintptr_t)src_data, src_len);
		LIB_TRACE("Dst @0x%08"PRIxPTR"",
			(uintptr_t)dst_data);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (authenc->op) {
		if (authenc->op->update) {
			/* Prepare the update data */
			dpayload.ctx        = authenc->ctx;
			dpayload.encrypt    = ((mode == TEE_MODE_ENCRYPT) ?
				true : false);
			dpayload.src.data   = (uint8_t *)src_data;
			dpayload.src.length = src_len;
			dpayload.dst.data   = (uint8_t *)dst_data;
			dpayload.dst.length = src_len;
			ret = authenc->op->update(&dpayload);
		}
	}

	return ret;
}

/**
 * @brief  Finalize the Authentication update data operation
 *
 * @param[in]     ctx       Reference the context pointer
 * @param[in]     algo      Algorithm
 * @param[in]     mode      Operation mode
 * @param[in]     src_data  Source
 * @param[in]     src_len   Length of the source
 * @param[out]    dst_data  Destination
 * @param[in/out] tag       Destination tag
 * @param[in/out] tag_len   Length of the destination tag
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_GENERIC           Other Error
 * @retval TEE_ERROR_SHORT_BUFFER      Tag Length is too short
 * @retval TEE_ERROR_MAC_INVALID       MAC is invalid
 */
TEE_Result authenc_update_final(void *ctx, uint32_t algo __unused,
				TEE_OperationMode mode,
				const uint8_t *src_data, size_t src_len,
				uint8_t *dst_data,
				uint8_t *tag_data, size_t *tag_len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct crypto_authenc *authenc = ctx;
	struct nxpcrypt_authenc_data dfinal;

	/* Check the parameters */
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check the data vs. length */
	if (((!src_data) && (src_len != 0)) ||
	    (!dst_data) ||
	    ((!tag_data) && (*tag_len != 0))) {
		LIB_TRACE("Bad data src/dst");
		LIB_TRACE("Src @0x%08"PRIxPTR"-%d",
			(uintptr_t)src_data, src_len);
		LIB_TRACE("Dst @0x%08"PRIxPTR"",
			(uintptr_t)dst_data);
		LIB_TRACE("Tag @0x%08"PRIxPTR"-%d",
			(uintptr_t)tag_data, *tag_len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (authenc->op) {
		if (authenc->op->update_final) {
			/* Prepare the final data */
			dfinal.ctx        = authenc->ctx;
			dfinal.encrypt    = ((mode == TEE_MODE_ENCRYPT) ?
				true : false);
			dfinal.src.data   = (uint8_t *)src_data;
			dfinal.src.length = src_len;
			dfinal.dst.data   = (uint8_t *)dst_data;
			dfinal.dst.length = src_len;
			dfinal.tag.data   = (uint8_t *)tag_data;
			dfinal.tag.length = *tag_len;
			ret = authenc->op->update_final(&dfinal);

			if (ret == TEE_SUCCESS) {
				if (dfinal.encrypt)
					*tag_len = dfinal.tag.length;
			}
		}
	}

	return ret;
}

/**
 * @brief  Finalize the Authentication operation
 *
 * @param[in] ctx   Reference the context pointer
 * @param[in] algo  Algorithm
 */
void authenc_final(void *ctx, uint32_t algo __unused)
{
	struct crypto_authenc *authenc = ctx;

	if (!ctx)
		return;

	if (authenc->op) {
		if (authenc->op->final)
			authenc->op->final(authenc->ctx);
	}
}
