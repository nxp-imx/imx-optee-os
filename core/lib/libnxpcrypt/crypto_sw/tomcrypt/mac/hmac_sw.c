// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    hmac_sw.c
 *
 * @brief   Implementation of the hmac pseudo-driver compatible with the
 *          NXP cryptographic library. Call LibTomCrypt's algorithm instead
 *          of using the HW module.
 */

/* Global includes */
#include <trace.h>
#include <utee_defines.h>

/* Library NXP includes */
#include <libnxpcrypt.h>
#include <libnxpcrypt_hash.h>

/* Local includes */
#include "local.h"

//#define LIB_DEBUG
#ifdef LIB_DEBUG
#define LIB_TRACE	DMSG
#else
#define LIB_TRACE(...)
#endif

#ifndef CFG_CRYPTO_HMAC_FULL_HW

/**
 * @brief   Allocate the SW hmac data context
 *
 * @param[in/out]  ctx    Caller context variable
 * @param[in]      algo   Algorithm ID of the context
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 */
static TEE_Result do_allocate(void **ctx, enum nxpcrypt_hash_id algo)
{
	hmac_state *hmac_ctx;
	int index;

	LIB_TRACE("HMAC_SW: Allocate Context (0x%"PRIxPTR")", (uintptr_t)ctx);

	index = get_ltc_hashindex(algo);
	if (index == (-1))
		return TEE_ERROR_NOT_IMPLEMENTED;

	hmac_ctx = calloc(1, sizeof(hmac_state));
	if (!hmac_ctx) {
		LIB_TRACE("HMAC_SW: Allocation Hash data error");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Set the HASH Id in the context for operation */
	hmac_ctx->hash = index;

	*ctx = hmac_ctx;

	return TEE_SUCCESS;
}

/**
 * @brief   Free the SW hmac data context
 *
 * @param[in/out]  ctx    Caller context variable
 *
 */
static void do_free(void *ctx)
{
	LIB_TRACE("HMAC_SW: Free Context (0x%"PRIxPTR")", (uintptr_t)ctx);

	if (ctx)
		free(ctx);
}

/**
 * @brief   Initialization of the HMAC operation.
 *
 * @param[in] ctx   Operation Software context
 *
 * @retval TEE_SUCCESS               Success
 */
static TEE_Result do_init(void *ctx __maybe_unused)
{

	LIB_TRACE("HMAC_SW: Init - Context @0x%08"PRIxPTR"",
				(uintptr_t)ctx);

	return TEE_SUCCESS;
}

/**
 * @brief   Initialization of the HMAC operation and Compute the key
 *
 * @param[in] ctx   Operation Software context
 * @param[in] key   HMAC Key
 * @param[in] len   Length of the HMAC Key
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED Algorithm not implemented
 */
static TEE_Result do_compute_key(void *ctx, const uint8_t *key, size_t len)
{
	int ret;
	hmac_state *hmac = ctx;

	LIB_TRACE("HMAC_SW: Init and Compute Key Context @0x%08"PRIxPTR"",
				(uintptr_t)ctx);

	ret = hmac_init(hmac, hmac->hash, key, len);

	return conv_CRYPT_to_TEE_Result(ret);
}

/**
 * @brief   Update the HMAC operation
 *
 * @param[in] ctx   Operation Software context
 * @param[in] data  Data to hash
 * @param[in] len   Data length
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY   Out of memory
 */
static TEE_Result do_update(void *ctx, const uint8_t *data, size_t len)
{
	int ret;

	LIB_TRACE("HMAC_SW: Update - Input @0x%08"PRIxPTR"-%d",
				(uintptr_t)data, len);

	if ((!data) || (!len))
		return TEE_SUCCESS;

	ret = hmac_process(ctx, data, len);

	return conv_CRYPT_to_TEE_Result(ret);
}

/**
 * @brief   Finalize the HMAC operation
 *
 * @param[in] ctx   Operation Software context
 * @param[in] len   Digest buffer length
 *
 * @param[out] digest  HMAC digest buffer
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 * @retval TEE_ERROR_SHORT_BUFFER    Digest buffer too short
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 */
static TEE_Result do_final(void *ctx, uint8_t *digest, size_t len)
{
	hmac_state *hmac = ctx;
	int ret;
	unsigned long dig_len = len;

	LIB_TRACE("HMAC_SW: Final - Digest @0x%08"PRIxPTR"-%d",
				(uintptr_t)digest, len);

	/* Check the length of the digest */
	if (hash_descriptor[hmac->hash]->hashsize > len)
		return TEE_ERROR_SHORT_BUFFER;

	ret = hmac_done(ctx, digest, &dig_len);

	return conv_CRYPT_to_TEE_Result(ret);
}

/**
 * @brief   Copy Sofware HMAC Context
 *
 * @param[in] src_ctx  Reference the context source
 *
 * @param[out] dst_ctx  Reference the context destination
 *
 */
static void do_cpy_state(void *dst_ctx, void *src_ctx)
{
	LIB_TRACE("HMAC_SW: Copy State (0x%"PRIxPTR") to (0x%"PRIxPTR")",
			 (uintptr_t)src_ctx, (uintptr_t)dst_ctx);

	memcpy(dst_ctx, src_ctx, sizeof(hmac_state));
}

/**
 * @brief   Registration of the HMAC SW Driver
 */
const struct nxpcrypt_hash driver_hmac_sw = {
	.alloc_ctx   = &do_allocate,
	.free_ctx    = &do_free,
	.init        = &do_init,
	.update      = &do_update,
	.final       = &do_final,
	.cpy_state   = &do_cpy_state,
	.compute_key = &do_compute_key,
};

/**
 * @brief   Initialize the HMAC SW module
 *
 * @retval  0    Success
 * @retval  (-1) Otherwise
 */
int libsoft_hmac_sw_init(void)
{
	return nxpcrypt_register(CRYPTO_HMAC_SW, (void *)&driver_hmac_sw);
}
#endif /* CFG_CRYPTO_HMAC_FULL_HW */
