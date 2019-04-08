// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP\n
 *
 * @file    authenc.c
 *
 * @brief   Implementation of the Authentication pseudo-driver compatible with
 *          the NXP cryptographic library. LibTomCrypt's descriptor wrapper
 *          to use the HW module.
 */

/* Global includes */
#include <crypto/crypto.h>
#include <utee_defines.h>

/* Library NXP includes */
#include <libnxpcrypt.h>
#include <libnxpcrypt_authenc.h>

/* Local includes */
#include "local.h"

//#define LIB_DEBUG
#ifdef LIB_DEBUG
#define LIB_TRACE	DMSG
#else
#define LIB_TRACE(...)
#endif

/**
 * @brief  AES CCM SW Context using the LibTomCrypt context
 */
struct authenc_data {
	enum nxpcrypt_authenc_id algo;
	union {
#ifdef LTC_CCM_MODE
		ccm_state ccm_ctx;  ///< CCM State defined by LTC
#endif
#ifdef LTC_GCM_MODE
		gcm_state gcm_ctx;  ///< GCM State defined by LTC
#endif
	} ltc_ctx;
	size_t tag_len;     ///< Tag Length
};

#define TAG_MAX_LENGTH	16

/**
 * @brief   Check if the algorithm is enabled in the LibTomCrypt
 *
 * @param[in]      algo   Algorithm ID of the context
 *
 * @retval  true if supported
 * @retval  false otherwise
 */
static bool algo_isvalid(enum nxpcrypt_authenc_id algo)
{
	bool isvalid = false;

	switch (algo) {
#ifdef LTC_CCM_MODE
	case AES_CCM:
		isvalid = true;
		break;
#endif
#ifdef LTC_GCM_MODE
	case AES_GCM:
		isvalid = true;
		break;
#endif
	default:
		break;
	}

	return isvalid;
}

/**
 * @brief   Allocate the SW authentication data context
 *
 * @param[in/out]  ctx    Caller context variable
 * @param[in]      algo   Algorithm ID of the context
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 */
static TEE_Result do_allocate(void **ctx, enum nxpcrypt_authenc_id algo)
{
	TEE_Result ret = TEE_ERROR_OUT_OF_MEMORY;
	struct authenc_data *auth_ctx = NULL;

	if (algo_isvalid(algo)) {
		auth_ctx = calloc(1, sizeof(struct authenc_data));
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	if (auth_ctx) {
		/* Set the algorithm in the context */
		auth_ctx->algo = algo;
		ret = TEE_SUCCESS;
	}

	*ctx = auth_ctx;
	return ret;
}

/**
 * @brief   Free the SW Authentication data context
 *
 * @param[in] ctx    Caller context variable
 *
 */
static void do_free(void *ctx)
{
	free(ctx);
}

/**
 * @brief   Copy Software Authentication Context
 *
 * @param[in]  src_ctx  Reference the context source
 * @param[out] dst_ctx  Reference the context destination
 *
 */
static void do_cpy_state(void *dst_ctx, void *src_ctx)
{
	LIB_TRACE("Copy State");
	memcpy(dst_ctx, src_ctx, sizeof(struct authenc_data));
}

/**
 * @brief   Initialization of the Authentication operation
 *
 * @param[in] dinit  Data initialization object
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 */
static TEE_Result do_init(struct nxpcrypt_authenc_init *dinit)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct authenc_data *ctx = dinit->ctx;
	int cipher_idx;
	int ltc_res;

	LIB_TRACE("SW Init aglo %d", ctx->algo);

	cipher_idx = get_ltc_cipherindex(AES_ECB_NOPAD);
	if (cipher_idx == (-1))
		return ret;

	memset(ctx, 0, sizeof(struct authenc_data));
	ctx->tag_len = dinit->tag_len;

	switch (ctx->algo) {
#ifdef LTC_CCM_MODE
	case AES_CCM:
		/* Check Nonce Length */
		if (dinit->nonce.length > 13)
			return TEE_ERROR_BAD_PARAMETERS;

		/* Check Tag Length */
		if ((dinit->tag_len < 4) || (dinit->tag_len > TAG_MAX_LENGTH) ||
				((dinit->tag_len % 2) != 0))
			return TEE_ERROR_BAD_PARAMETERS;

		ltc_res = ccm_init(&ctx->ltc_ctx.ccm_ctx, cipher_idx,
				dinit->key.data, dinit->key.length,
				dinit->payload_len, dinit->tag_len,
				dinit->aad_len);
		LIB_TRACE("ccm_init ret %x", ltc_res);

		if (ltc_res == CRYPT_OK) {
			ltc_res = ccm_add_nonce(&ctx->ltc_ctx.ccm_ctx,
					dinit->nonce.data, dinit->nonce.length);
			LIB_TRACE("ccm_add_nonce ret %x", ltc_res);
		}
		ret = conv_CRYPT_to_TEE_Result(ltc_res);
		break;
#endif
#ifdef LTC_GCM_MODE
	case AES_GCM:
		ltc_res = gcm_init(&ctx->ltc_ctx.gcm_ctx, cipher_idx,
				dinit->key.data, dinit->key.length);

		LIB_TRACE("gcm_init ret %x", ltc_res);

		if (ltc_res == CRYPT_OK) {
			ltc_res = gcm_add_iv(&ctx->ltc_ctx.gcm_ctx,
					dinit->nonce.data, dinit->nonce.length);
			LIB_TRACE("gcm_add_iv ret %x", ltc_res);
		}
		ret = conv_CRYPT_to_TEE_Result(ltc_res);

		break;
#endif

	default:
		break;
	}

	return ret;
}

/**
 * @brief   Update of the Authentication data operation
 *
 * @param[in] dupdate  Data update object
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_GENERIC           Other Error
 */
static TEE_Result do_update(struct nxpcrypt_authenc_data *dupdate)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct authenc_data *ctx = dupdate->ctx;
	int ltc_res;

	LIB_TRACE("SW Update algo %d", ctx->algo);

	switch (ctx->algo) {
#ifdef LTC_CCM_MODE
	case AES_CCM:
		if (dupdate->encrypt) {
			ltc_res = ccm_process(&ctx->ltc_ctx.ccm_ctx,
					dupdate->src.data, dupdate->src.length,
					dupdate->dst.data, CCM_ENCRYPT);
		} else {
			ltc_res = ccm_process(&ctx->ltc_ctx.ccm_ctx,
					dupdate->dst.data, dupdate->dst.length,
					dupdate->src.data, CCM_DECRYPT);
		}
		LIB_TRACE("ccm_process %s ret %x",
			(dupdate->encrypt) ? "ENCRYPT" : "DECRYPT", ltc_res);

		ret = conv_CRYPT_to_TEE_Result(ltc_res);
		break;
#endif
#ifdef LTC_GCM_MODE
	case AES_GCM:
		if (ctx->ltc_ctx.gcm_ctx.mode == LTC_GCM_MODE_IV) {
			ltc_res = gcm_add_aad(&ctx->ltc_ctx.gcm_ctx,
					NULL, 0);
			LIB_TRACE("gcm_add_aad ret %x", ltc_res);
			if (ltc_res != CRYPT_OK)
				return conv_CRYPT_to_TEE_Result(ltc_res);
		}

		if (dupdate->encrypt) {
			ltc_res = gcm_process(&ctx->ltc_ctx.gcm_ctx,
					dupdate->src.data, dupdate->src.length,
					dupdate->dst.data, GCM_ENCRYPT);
		} else {
			ltc_res = gcm_process(&ctx->ltc_ctx.gcm_ctx,
					dupdate->dst.data, dupdate->dst.length,
					dupdate->src.data, GCM_DECRYPT);
		}
		LIB_TRACE("gcm_process %s ret %x",
			(dupdate->encrypt) ? "ENCRYPT" : "DECRYPT", ltc_res);

		ret = conv_CRYPT_to_TEE_Result(ltc_res);
		break;
#endif

	default:
		break;
	}

	return ret;
}

/**
 * @brief   Finalize of the Authentication update data operation
 *
 * @param[in] dfinal  Data final object
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_GENERIC           Other Error
 * @retval TEE_ERROR_SHORT_BUFFER      Tag Length is too short
 * @retval TEE_ERROR_MAC_INVALID       MAC is invalid
 */
static TEE_Result do_update_final(struct nxpcrypt_authenc_data *dfinal)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

#ifdef LTC_GCM_MODE
	struct nxpcrypt_authenc_data dupdate;
#endif
	struct authenc_data *ctx = dfinal->ctx;
	int           ltc_res;
	uint8_t       tag[TAG_MAX_LENGTH];
	unsigned long tag_len;

	LIB_TRACE("SW Update final algo %d", ctx->algo);

	switch (ctx->algo) {
#ifdef LTC_CCM_MODE
	case AES_CCM:
		if (dfinal->encrypt) {
			ltc_res = ccm_process(&ctx->ltc_ctx.ccm_ctx,
					dfinal->src.data, dfinal->src.length,
					dfinal->dst.data, CCM_ENCRYPT);
			LIB_TRACE("ccm_process ENCRYPT ret %x", ltc_res);

			if (ltc_res == CRYPT_OK) {
				if (dfinal->tag.length < ctx->tag_len) {
					dfinal->tag.length = ctx->tag_len;
					return TEE_ERROR_SHORT_BUFFER;
				}

				tag_len = ctx->tag_len;

				ltc_res = ccm_done(&ctx->ltc_ctx.ccm_ctx,
						dfinal->tag.data, &tag_len);
				LIB_TRACE("ccm_done ret %x", ltc_res);

				dfinal->tag.length = tag_len;
			}
		} else {
			if (dfinal->tag.length == 0)
				return TEE_ERROR_SHORT_BUFFER;

			if (dfinal->tag.length > TAG_MAX_LENGTH)
				return TEE_ERROR_BAD_PARAMETERS;

			ltc_res = ccm_process(&ctx->ltc_ctx.ccm_ctx,
					dfinal->dst.data, dfinal->dst.length,
					dfinal->src.data, CCM_DECRYPT);
			LIB_TRACE("ccm_process DECRYPT ret %x", ltc_res);

			tag_len = dfinal->tag.length;

			if (ltc_res == CRYPT_OK) {
				ltc_res = ccm_done(&ctx->ltc_ctx.ccm_ctx,
						tag, &tag_len);
				LIB_TRACE("ccm_done ret %x", ltc_res);
			}
			if (ltc_res == CRYPT_OK) {
				if (buf_compare_ct(tag, dfinal->tag.data,
					    tag_len) != 0)
					return TEE_ERROR_MAC_INVALID;
				else
					return TEE_SUCCESS;
			}
		}

		ret = conv_CRYPT_to_TEE_Result(ltc_res);
		break;
#endif

#ifdef LTC_GCM_MODE
	case AES_GCM:
		/* Prepare the update data */
		dupdate.ctx     = dfinal->ctx;
		dupdate.algo    = dfinal->algo;
		dupdate.encrypt = dfinal->encrypt;
		dupdate.src     = dfinal->src;
		dupdate.dst     = dfinal->dst;

		if (dfinal->encrypt) {
			ret = do_update(&dupdate);

			if (ret != TEE_SUCCESS)
				return ret;

			if (dfinal->tag.length < ctx->tag_len) {
				dfinal->tag.length = ctx->tag_len;
				return TEE_ERROR_SHORT_BUFFER;
			}

			tag_len = ctx->tag_len;

			ltc_res = gcm_done(&ctx->ltc_ctx.gcm_ctx,
					dfinal->tag.data, &tag_len);
			LIB_TRACE("gcm_done ret %x", ltc_res);

			dfinal->tag.length = tag_len;
		} else {
			if (dfinal->tag.length == 0)
				return TEE_ERROR_SHORT_BUFFER;

			if (dfinal->tag.length > TAG_MAX_LENGTH)
				return TEE_ERROR_BAD_PARAMETERS;

			ret = do_update(&dupdate);
			tag_len = dfinal->tag.length;

			if (ret != TEE_SUCCESS)
				return ret;

			ltc_res = gcm_done(&ctx->ltc_ctx.gcm_ctx,
					tag, &tag_len);
			LIB_TRACE("gcm_done ret %x", ltc_res);

			if (ltc_res == CRYPT_OK) {
				if (buf_compare_ct(tag, dfinal->tag.data,
					    tag_len) != 0)
					return TEE_ERROR_MAC_INVALID;
				else
					return TEE_SUCCESS;
			}
		}

		ret = conv_CRYPT_to_TEE_Result(ltc_res);
		break;
#endif

	default:
		break;
	}

	return ret;
}

/**
 * @brief   Update of the Authentication Additional Data
 *
 * @param[in] daad  Additional Data object
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_GENERIC           Generic Error
 */
static TEE_Result do_update_aad(struct nxpcrypt_authenc_aad *daad)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct authenc_data *ctx = daad->ctx;
	int ltc_res;

	LIB_TRACE("SW Update aad algo %d", ctx->algo);

	switch (ctx->algo) {
#ifdef LTC_CCM_MODE
	case AES_CCM:
		ltc_res = ccm_add_aad(&ctx->ltc_ctx.ccm_ctx,
				daad->aad.data, daad->aad.length);
		LIB_TRACE("ccm_add_aad ret %x", ltc_res);
		ret = conv_CRYPT_to_TEE_Result(ltc_res);
		break;
#endif
#ifdef LTC_GCM_MODE
	case AES_GCM:
		ltc_res = gcm_add_aad(&ctx->ltc_ctx.gcm_ctx,
				daad->aad.data, daad->aad.length);
		LIB_TRACE("gcm_add_aad ret %x", ltc_res);
		ret = conv_CRYPT_to_TEE_Result(ltc_res);
		break;
#endif
	default:
		break;
	}

	return ret;
}

/**
 * @brief  Finalize the Authentication operation
 *
 * @param[in] ctx   Reference the context pointer
 */
static void do_final(void *ctx)
{
	struct authenc_data *auth_ctx = ctx;

	LIB_TRACE("SW Final algo %d", auth_ctx->algo);

	switch (auth_ctx->algo) {
#ifdef LTC_CCM_MODE
	case AES_CCM:
		ccm_reset(&auth_ctx->ltc_ctx.ccm_ctx);
		break;
#endif

#ifdef LTC_GCM_MODE
	case AES_GCM:
		gcm_reset(&auth_ctx->ltc_ctx.gcm_ctx);
		break;
#endif
	default:
		break;
	}
}

/**
 * @brief   Registration of the Authentication Driver
 */
struct nxpcrypt_authenc driver_authenc_sw = {
#ifdef LTC_GCM_MODE
	.aes_gcm      = true,
#else
	.aes_gcm      = false,
#endif
	.alloc_ctx    = &do_allocate,
	.free_ctx     = &do_free,
	.init         = &do_init,
	.update       = &do_update,
	.update_final = &do_update_final,
	.update_aad   = &do_update_aad,
	.final        = &do_final,
	.cpy_state    = &do_cpy_state,
};

/**
 * @brief   Initialize the Authentication module
 *
 * @retval  0    Success
 * @retval  (-1) Otherwise
 */
int libsoft_authenc_init(void)
{
#if defined(LTC_CCM_MODE) || defined(LTC_GCM_MODE)
	return nxpcrypt_register(CRYPTO_AUTHENC_SW, (void *)&driver_authenc_sw);
#endif
	return 0;
}

