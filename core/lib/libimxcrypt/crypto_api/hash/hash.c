// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    hash.c
 *
 * @brief   Cryptographic library using the i.MX CAAM driver.\n
 *          Hash crypto_* interface implementation.
 */

/* Global includes */
#include <crypto/crypto.h>
#include <trace.h>
#include <utee_defines.h>

/* Library i.MX includes */
#include <libimxcrypt.h>
#include <libimxcrypt_hash.h>

//#define LIB_DEBUG
#ifdef LIB_DEBUG
#define LIB_TRACE	DMSG
#else
#define LIB_TRACE(...)
#endif

/**
 * @brief   Checks and returns reference to the driver operations
 *
 * @param[in]  algo     Algorithm
 * @param[out] hash_id  Hash Algorithm internal ID
 *
 * @retval  Reference to the driver operations
 */
static struct imxcrypt_hash *do_check_algo(uint32_t algo,
						enum imxcrypt_hash_id *hash_id)
{
	struct imxcrypt_hash *hash = NULL;
	uint8_t algo_op;
	uint8_t algo_id;

	/* Extract the algorithms fields */
	algo_op = TEE_ALG_GET_CLASS(algo);
	algo_id = TEE_ALG_GET_MAIN_ALG(algo);

	if ((algo_op == TEE_OPERATION_DIGEST) &&
		((algo_id >= TEE_MAIN_ALGO_MD5) &&
		 (algo_id <= TEE_MAIN_ALGO_SHA512))) {

		*hash_id = algo_id - 1;

		hash = imxcrypt_getmod(CRYPTO_HASH);

		/* Verify that the HASH HW implements this algorithm */
		if (hash) {
			if (hash->max_hash < *hash_id)
				hash = imxcrypt_getmod(CRYPTO_HASH_SW);
		} else {
			hash = imxcrypt_getmod(CRYPTO_HASH_SW);
		}
	}

	LIB_TRACE("Check Hash algo %d ret 0x%"PRIxPTR"",
		algo_id, (uintptr_t)hash);

	return hash;
}

/**
 * @brief   Allocates the Software Hashing Context function of the algorithm
 *
 * @param[in/out] ctx    Reference the context pointer
 * @param[in]     algo   Algorithm
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
TEE_Result crypto_hash_alloc_ctx(void **ctx, uint32_t algo)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct imxcrypt_hash  *hash;
	enum imxcrypt_hash_id hash_id;

	/* Check the parameters */
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	hash = do_check_algo(algo, &hash_id);
	if (hash) {
		if (hash->alloc_ctx)
			ret = hash->alloc_ctx(ctx, hash_id);
	}

	return ret;
}

/**
 * @brief   Free the Software Hashing Context function of the algorithm
 *
 * @param[in/out] ctx    Reference the context pointer
 * @param[in]     algo   Algorithm
 *
 */
void crypto_hash_free_ctx(void *ctx, uint32_t algo)
{
	struct imxcrypt_hash  *hash;
	enum imxcrypt_hash_id hash_id;

	/* Check the parameters */
	if (ctx) {
		hash = do_check_algo(algo, &hash_id);
		if (hash) {
			if (hash->free_ctx)
				hash->free_ctx(ctx);
		}
	}
}

/**
 * @brief   Copy Software Hashing Context
 *
 * @param[in] src_ctx  Reference the context source
 * @param[in] algo     Algorithm
 *
 * @param[out] dst_ctx  Reference the context destination
 *
 */
void crypto_hash_copy_state(void *dst_ctx, void *src_ctx, uint32_t algo)
{
	struct imxcrypt_hash  *hash;
	enum imxcrypt_hash_id hash_id;

	if ((!dst_ctx) || (!src_ctx))
		return;

	hash = do_check_algo(algo, &hash_id);
	if (hash) {
		if (hash->cpy_state)
			hash->cpy_state(dst_ctx, src_ctx);
	}
}

/**
 * @brief   Initialization of the Hash operation
 *
 * @param[in] ctx    Reference the context pointer
 * @param[in] algo   Algorithm
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED Algorithm is not implemented
 */
TEE_Result crypto_hash_init(void *ctx, uint32_t algo)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct imxcrypt_hash *hash;
	enum imxcrypt_hash_id hash_id;

	/* Check the parameters */
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	hash = do_check_algo(algo, &hash_id);
	if (hash) {
		if (hash->init)
			ret = hash->init(ctx, hash_id);
	}

	return ret;
}

/**
 * @brief   Update the Hash operation
 *
 * @param[in] ctx   Operation Software context
 * @param[in] algo  Algorithm ID of the context
 * @param[in] data  Data to hash
 * @param[in] len   Data length
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED Algorithm is not implemented
 */
TEE_Result crypto_hash_update(void *ctx, uint32_t algo,
					const uint8_t *data, size_t len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct imxcrypt_hash  *hash;
	enum imxcrypt_hash_id hash_id;

	/* Check the parameters */
	if ((!ctx) || ((!data) && (len != 0)))
		return TEE_ERROR_BAD_PARAMETERS;

	hash = do_check_algo(algo, &hash_id);
	if (hash) {
		if (hash->update)
			ret = hash->update(ctx, hash_id, data, len);
	}

	return ret;
}

/**
 * @brief   Finalize the Hash operation
 *
 * @param[in] ctx   Operation Software context
 * @param[in] algo  Algorithm ID of the context
 * @param[in] len   Digest buffer length
 *
 * @param[out] digest  Hash digest buffer
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED Algorithm is not implemented
 * @retval TEE_ERROR_OUT_OF_MEMORY   Out of memory
 */
TEE_Result crypto_hash_final(void *ctx, uint32_t algo,
					uint8_t *digest, size_t len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct imxcrypt_hash  *hash;
	enum imxcrypt_hash_id hash_id;

	/* Check the parameters */
	if ((!ctx) || (!digest) || (!len))
		return TEE_ERROR_BAD_PARAMETERS;

	hash = do_check_algo(algo, &hash_id);
	if (hash) {
		if (hash->final)
			ret = hash->final(ctx, hash_id, digest, len);
	}

	return ret;
}

