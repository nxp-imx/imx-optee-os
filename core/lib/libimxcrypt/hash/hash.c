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
#include <assert.h>
#include <crypto/crypto.h>
#include <utee_defines.h>
#include <trace.h>

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
 * @param[in] algo   Algorithm
 *
 * @retval  Reference to the driver operations
 */
static struct imxcrypt_hash *do_check_algo(uint32_t algo)
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
		hash = imxcrypt_getmod(CRYPTO_HASH);
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
	struct imxcrypt_hash *hash;
	uint8_t algo_id;

	/* Check the parameters */
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	hash = do_check_algo(algo);
	if (hash) {
		if (hash->alloc_ctx) {
			algo_id = TEE_ALG_GET_MAIN_ALG(algo);
			ret = hash->alloc_ctx(ctx, (algo_id - 1));
		}
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
	struct imxcrypt_hash *hash;

	/* Check the parameters */
	if (ctx) {
		hash = do_check_algo(algo);
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
	struct imxcrypt_hash *hash;

	if ((!dst_ctx) || (!src_ctx))
		return;

	hash = do_check_algo(algo);
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
	uint8_t algo_id;

	/* Check the parameters */
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	hash = do_check_algo(algo);
	if (hash) {
		if (hash->init) {
			algo_id = TEE_ALG_GET_MAIN_ALG(algo);
			ret = hash->init(ctx, (algo_id - 1));
		}
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
	struct imxcrypt_hash *hash;
	uint8_t algo_id;

	/* Check the parameters */
	if ((!ctx) || (!data) || (!len))
		return TEE_ERROR_BAD_PARAMETERS;

	hash = do_check_algo(algo);
	if (hash) {
		if (hash->update) {
			algo_id = TEE_ALG_GET_MAIN_ALG(algo);
			ret = hash->update(ctx, (algo_id - 1), data, len);
		}
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
 * @retval TEE_ERROR_SHORT_BUFFER    Digest buffer too short
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED Algorithm is not implemented
 */
TEE_Result crypto_hash_final(void *ctx, uint32_t algo,
					uint8_t *digest, size_t len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct imxcrypt_hash *hash;
	uint8_t algo_id;

	/* Check the parameters */
	if ((!ctx) || (!digest) || (!len))
		return TEE_ERROR_BAD_PARAMETERS;

	hash = do_check_algo(algo);
	if (hash) {
		if (hash->final) {
			algo_id = TEE_ALG_GET_MAIN_ALG(algo);
			ret = hash->final(ctx, (algo_id - 1), digest, len);
		}
	}

	return ret;
}

