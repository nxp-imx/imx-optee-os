// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    hash.c
 *
 * @brief   Cryptographic library using the NXP CAAM driver.\n
 *          Hash crypto_* interface implementation.
 */
/* Standard includes */
#include <stdlib.h>

/* Global includes */
#include <crypto/crypto.h>
#include <trace.h>
#include <utee_defines.h>

/* Library NXP includes */
#include <libnxpcrypt.h>
#include <libnxpcrypt_hash.h>

//#define LIB_DEBUG
#ifdef LIB_DEBUG
#define LIB_TRACE	DMSG
#else
#define LIB_TRACE(...)
#endif

/**
 * @brief  Format the HASH context to keep the reference to the
 *         operation driver
 */
struct crypto_hash {
	void                 *ctx; ///< Hash Context
	struct nxpcrypt_hash *op;  ///< Reference to the operation
};

/**
 * @brief   Checks and returns reference to the driver operations
 *
 * @param[in]  algo  Algorithm
 * @param[out] id    Hash Algorithm internal ID
 *
 * @retval  Reference to the driver operations
 */
static struct nxpcrypt_hash *do_check_algo(uint32_t algo,
						enum nxpcrypt_hash_id *id)
{
	struct nxpcrypt_hash *hash = NULL;
	uint8_t algo_op;
	uint8_t algo_id;
	enum nxpcrypt_hash_id hash_id;

	/* Extract the algorithms fields */
	algo_op = TEE_ALG_GET_CLASS(algo);
	algo_id = TEE_ALG_GET_MAIN_ALG(algo);

	if ((algo_op == TEE_OPERATION_DIGEST) &&
		((algo_id >= TEE_MAIN_ALGO_MD5) &&
		 (algo_id <= TEE_MAIN_ALGO_SHA512))) {

		hash_id = algo_id - 1;

		hash = nxpcrypt_getmod(CRYPTO_HASH);

		/* Verify that the HASH HW implements this algorithm */
		if (hash) {
			if (hash->max_hash < hash_id)
				hash = nxpcrypt_getmod(CRYPTO_HASH_SW);
		} else {
			hash = nxpcrypt_getmod(CRYPTO_HASH_SW);
		}

		if (id)
			*id = hash_id;
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
	struct crypto_hash   *hash = NULL;
	enum nxpcrypt_hash_id hash_id;

	/* Check the parameters */
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	hash = calloc(1, sizeof(*hash));
	if (!hash)
		return TEE_ERROR_OUT_OF_MEMORY;

	hash->op = do_check_algo(algo, &hash_id);
	if (hash->op) {
		if (hash->op->alloc_ctx)
			ret = hash->op->alloc_ctx(&hash->ctx, hash_id);
	} else {
		free(hash);
		hash = NULL;
	}

	*ctx = hash;

	return ret;
}

/**
 * @brief   Free the Software Hashing Context function of the algorithm
 *
 * @param[in/out] ctx    Reference the context pointer
 * @param[in]     algo   Algorithm
 *
 */
void crypto_hash_free_ctx(void *ctx, uint32_t algo __unused)
{
	struct crypto_hash *hash = ctx;

	/* Check the parameters */
	if (ctx) {
		if (hash->op) {
			if (hash->op->free_ctx)
				hash->op->free_ctx(hash->ctx);
		}
		free(hash);
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
void crypto_hash_copy_state(void *dst_ctx, void *src_ctx,
		uint32_t algo __unused)
{
	struct crypto_hash *hash_src = src_ctx;
	struct crypto_hash *hash_dst = dst_ctx;

	if ((!dst_ctx) || (!src_ctx))
		return;

	if (hash_src->op) {
		if (hash_src->op->cpy_state)
			hash_src->op->cpy_state(hash_dst->ctx, hash_src->ctx);
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
TEE_Result crypto_hash_init(void *ctx, uint32_t algo __unused)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct crypto_hash *hash = ctx;

	/* Check the parameters */
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	if (hash->op) {
		if (hash->op->init)
			ret = hash->op->init(hash->ctx);
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
TEE_Result crypto_hash_update(void *ctx, uint32_t algo __unused,
					const uint8_t *data, size_t len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct crypto_hash *hash = ctx;

	/* Check the parameters */
	if ((!ctx) || ((!data) && (len != 0)))
		return TEE_ERROR_BAD_PARAMETERS;

	if (hash->op) {
		if (hash->op->update)
			ret = hash->op->update(hash->ctx, data, len);
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
TEE_Result crypto_hash_final(void *ctx, uint32_t algo __unused,
					uint8_t *digest, size_t len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct crypto_hash *hash = ctx;

	/* Check the parameters */
	if ((!ctx) || (!digest) || (!len))
		return TEE_ERROR_BAD_PARAMETERS;

	if (hash->op) {
		if (hash->op->final)
			ret = hash->op->final(hash->ctx, digest, len);
	}

	return ret;
}

