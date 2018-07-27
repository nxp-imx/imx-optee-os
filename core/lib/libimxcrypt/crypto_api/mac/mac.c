// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    mac.c
 *
 * @brief   Cryptographic library using the i.MX CAAM driver.\n
 *          HMAC crypto_* interface implementation.
 */
/* Global includes */
#include <crypto/crypto.h>
#include <malloc.h>
#include <string.h>
#include <trace.h>
#include <utee_defines.h>

/* Library i.MX includes */
#include <libimxcrypt.h>
#include <libimxcrypt_hash.h>
#include <libimxcrypt_cipher.h>

//#define LIB_DEBUG
#ifdef LIB_DEBUG
#define LIB_TRACE	DMSG
#else
#define LIB_TRACE(...)
#endif

/**
 * @brief   CBC-MAC mode context
 */
struct cbc_ctx {
	void   *ctx;      ///< Cipher context allocated by the driver
	size_t countdata; ///< Number of input data done
	size_t sizeblock; ///< Cipher Block size
};

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

	if ((algo_op == TEE_OPERATION_MAC) &&
		((algo_id >= TEE_MAIN_ALGO_MD5) &&
		 (algo_id <= TEE_MAIN_ALGO_SHA512))) {

		*hash_id = algo_id - 1;

		hash = imxcrypt_getmod(CRYPTO_HMAC);

		/* Verify that the HASH HW implements this algorithm */
		if (hash) {
			if (hash->max_hash < *hash_id)
				hash = imxcrypt_getmod(CRYPTO_HMAC_SW);
		} else {
			hash = imxcrypt_getmod(CRYPTO_HMAC_SW);
		}
	}

	LIB_TRACE("Check HMAC algo %d ret 0x%"PRIxPTR"",
		algo_id, (uintptr_t)hash);

	return hash;
}

/**
 * @brief   Checks and returns reference to the driver operations
 *          to do cipher mac
 *
 * @param[in]  algo       Algorithm
 * @param[out] cipher_id  Cipher Algorithm internal ID
 *
 * @retval  Reference to the driver operations
 */
static struct imxcrypt_cipher *do_check_algo_cipher(uint32_t algo,
					enum imxcrypt_cipher_id *cipher_id)
{
	struct imxcrypt_cipher *cipher = NULL;
	uint8_t algo_op;
	uint8_t algo_id;
	uint8_t algo_md;

	/* Extract the algorithms fields */
	algo_op = TEE_ALG_GET_CLASS(algo);
	algo_id = TEE_ALG_GET_MAIN_ALG(algo);
	algo_md = TEE_ALG_GET_CHAIN_MODE(algo);

	LIB_TRACE("Algo op:%d id:%d md:%d", algo_op, algo_id, algo_md);

	if ((algo_op != TEE_OPERATION_MAC) &&
		((algo_md != TEE_CHAIN_MODE_CBC_NOPAD) &&
		(algo_md != TEE_CHAIN_MODE_CBC_MAC_PKCS5) &&
		(algo_md != TEE_CHAIN_MODE_CMAC)))
		goto end_check_cipher;

	cipher = imxcrypt_getmod(CRYPTO_CIPHER);

	switch (algo_id) {
	case TEE_MAIN_ALGO_AES:
		if (algo_md == TEE_CHAIN_MODE_CMAC)
			*cipher_id = AES_CMAC;
		else
			*cipher_id = AES_CBC_MAC;
		break;

	case TEE_MAIN_ALGO_DES:
		*cipher_id = DES_CBC_MAC;
		break;

	case TEE_MAIN_ALGO_DES3:
		*cipher_id = DES3_CBC_MAC;
		break;

	default:
		cipher = NULL;
		break;
	}

end_check_cipher:
	LIB_TRACE("Check Cipher MAC id: %d ret 0x%"PRIxPTR"",
				*cipher_id, (uintptr_t)cipher);

	return cipher;
}


/**
 * @brief   Allocates the Software Hmac Context function of the algorithm
 *
 * @param[in/out] ctx    Reference the context pointer
 * @param[in]     algo   Algorithm
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
TEE_Result crypto_mac_alloc_ctx(void **ctx, uint32_t algo)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	/* HMAC Algorithm */
	struct imxcrypt_hash    *hash;
	enum imxcrypt_hash_id   hash_id;

	/* Cipher Mac Algorthm */
	struct cbc_ctx          *cbc_ctx;
	struct imxcrypt_cipher  *cipher;
	enum imxcrypt_cipher_id cipher_id;

	/* Check the parameters */
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (algo) {
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		cipher = do_check_algo_cipher(algo, &cipher_id);
		if (!cipher)
			return ret;

		/* Allocate specific context for the CBC-MAC */
		*ctx = malloc(sizeof(struct cbc_ctx));

		if (*ctx) {
			cbc_ctx = *ctx;
			if (cipher->alloc_ctx) {
				ret = cipher->alloc_ctx(&cbc_ctx->ctx,
					cipher_id);

				if (ret != TEE_SUCCESS) {
					/* Free the CBC-MAC context */
					free(*ctx);
					*ctx = NULL;
					return ret;
				}
			}
		}
		break;

	case TEE_ALG_AES_CMAC:
		cipher = do_check_algo_cipher(algo, &cipher_id);
		if (!cipher)
			return ret;

		if (cipher->alloc_ctx)
			ret = cipher->alloc_ctx(ctx, cipher_id);
		break;

	default:
		hash = do_check_algo(algo, &hash_id);
		if (hash) {
			if (hash->alloc_ctx)
				ret = hash->alloc_ctx(ctx, hash_id);
		}
		break;
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
void crypto_mac_free_ctx(void *ctx, uint32_t algo)
{
	/* HMAC Algorithm */
	struct imxcrypt_hash    *hash;
	enum imxcrypt_hash_id   hash_id;

	/* Cipher Mac Algorthm */
	struct cbc_ctx          *cbc_ctx;
	struct imxcrypt_cipher  *cipher;
	enum imxcrypt_cipher_id cipher_id;

	/* Check the parameters */
	if (ctx) {
		switch (algo) {
		case TEE_ALG_AES_CBC_MAC_NOPAD:
		case TEE_ALG_DES_CBC_MAC_NOPAD:
		case TEE_ALG_DES3_CBC_MAC_NOPAD:
		case TEE_ALG_AES_CBC_MAC_PKCS5:
		case TEE_ALG_DES_CBC_MAC_PKCS5:
		case TEE_ALG_DES3_CBC_MAC_PKCS5:
			cipher = do_check_algo_cipher(algo, &cipher_id);
			if (!cipher)
				return;

			cbc_ctx = ctx;

			/* Free the Cipher Algorithm context */
			if (cipher->free_ctx)
				cipher->free_ctx(cbc_ctx->ctx);

			free(ctx);
			break;

		case TEE_ALG_AES_CMAC:
			cipher = do_check_algo_cipher(algo, &cipher_id);
			if (!cipher)
				return;

			/* Free the Cipher Algorithm context */
			if (cipher->free_ctx)
				cipher->free_ctx(ctx);
			break;

		default:
			hash = do_check_algo(algo, &hash_id);
			if (hash) {
				if (hash->free_ctx)
					hash->free_ctx(ctx);
			}
			break;
		}
	}
}

/**
 * @brief   Copy Sofware Hashing Context
 *
 * @param[in] src_ctx  Reference the context source
 * @param[in] algo     Algorithm
 *
 * @param[out] dst_ctx  Reference the context destination
 *
 */
void crypto_mac_copy_state(void *dst_ctx, void *src_ctx, uint32_t algo)
{
	/* HMAC Algorithm */
	struct imxcrypt_hash    *hash;
	enum imxcrypt_hash_id   hash_id;

	/* Cipher Mac Algorthm */
	struct cbc_ctx          *cbc_dst_ctx;
	struct cbc_ctx          *cbc_src_ctx;
	struct imxcrypt_cipher  *cipher;
	enum imxcrypt_cipher_id cipher_id;

	if ((!dst_ctx) || (!src_ctx))
		return;

	switch (algo) {
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		cipher = do_check_algo_cipher(algo, &cipher_id);
		if (!cipher)
			return;

		cbc_dst_ctx = dst_ctx;
		cbc_src_ctx = src_ctx;

		/* Copy just the Cipher context no the intermediate cipher */
		if (cipher->cpy_state)
			cipher->cpy_state(cbc_dst_ctx->ctx, cbc_src_ctx->ctx);

		cbc_dst_ctx->countdata = cbc_src_ctx->countdata;
		cbc_dst_ctx->sizeblock = cbc_src_ctx->sizeblock;
		break;

	case TEE_ALG_AES_CMAC:
		cipher = do_check_algo_cipher(algo, &cipher_id);
		if (!cipher)
			return;

		/* Free the Cipher Algorithm context */
		if (cipher->cpy_state)
			cipher->cpy_state(dst_ctx, src_ctx);
		break;

	default:
		hash = do_check_algo(algo, &hash_id);
		if (hash) {
			if (hash->cpy_state)
				hash->cpy_state(dst_ctx, src_ctx);
		}
		break;
	}
}

/**
 * @brief   Initialization of the HMAC operation
 *
 * @param[in] ctx      Reference the context pointer
 * @param[in] algo     Algorithm
 * @param[in] key      HMAC Key
 * @param[in] key_len  Length of the HMAC Key
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED Algorithm is not implemented
 * @retval TEE_ERROR_OUT_OF_MEMORY   Out of memory
 */
TEE_Result crypto_mac_init(void *ctx, uint32_t algo,
				const uint8_t *key, size_t key_len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	/* HMAC Algorithm */
	struct imxcrypt_hash    *hash;
	enum imxcrypt_hash_id   hash_id;

	/* Cipher Mac Algorthm */
	struct cbc_ctx          *cbc_ctx;
	uint8_t                 *iv_tmp;
	struct imxcrypt_cipher  *cipher;
	enum imxcrypt_cipher_id cipher_id;
	struct imxcrypt_cipher_init dinit;

	LIB_TRACE("mac init keylen %d", key_len);

	/* Check the parameters */
	if ((!ctx) || (!key) || (key_len == 0))
		return TEE_ERROR_BAD_PARAMETERS;

	switch (algo) {
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		cipher = do_check_algo_cipher(algo, &cipher_id);
		if (!cipher)
			return ret;

		cbc_ctx = ctx;

		if ((!cipher->init) || (!cipher->block_size))
			return ret;

		ret = cipher->block_size(cipher_id, &cbc_ctx->sizeblock);

		if (ret != TEE_SUCCESS)
			return ret;

		/* Allocate temporary IV initialize with 0's */
		iv_tmp = malloc(cbc_ctx->sizeblock);
		if (!iv_tmp)
			return TEE_ERROR_OUT_OF_MEMORY;

		memset(iv_tmp, 0, cbc_ctx->sizeblock);
		cbc_ctx->countdata = 0;

		/* Prepare the initialization data */
		dinit.ctx         = cbc_ctx->ctx;
		dinit.algo        = cipher_id;
		dinit.encrypt     = true;
		dinit.key1.data   = (uint8_t *)key;
		dinit.key1.length = key_len;
		dinit.key2.data   = NULL;
		dinit.key2.length = 0;
		dinit.iv.data     = iv_tmp;
		dinit.iv.length   = cbc_ctx->sizeblock;
		ret = cipher->init(&dinit);

		free(iv_tmp);
		break;

	case TEE_ALG_AES_CMAC:
		cipher = do_check_algo_cipher(algo, &cipher_id);
		if (!cipher)
			return ret;

		if (cipher->init) {
			/* Prepare the initialization data */
			dinit.ctx         = ctx;
			dinit.algo        = cipher_id;
			dinit.encrypt     = true;
			dinit.key1.data   = (uint8_t *)key;
			dinit.key1.length = key_len;
			dinit.key2.data   = NULL;
			dinit.key2.length = 0;
			dinit.iv.data     = NULL;
			dinit.iv.length   = 0;
			ret = cipher->init(&dinit);
		}
		break;

	default:
		hash = do_check_algo(algo, &hash_id);
		if (hash) {
			if ((hash->init) && (hash->compute_key)) {
				ret = hash->init(ctx, hash_id);

				if (ret == TEE_SUCCESS) {
					if (hash->compute_key)
						ret = hash->compute_key(ctx,
							key, key_len);
				}
			}
		}
		break;
	}

	return ret;
}

/**
 * @brief   Update the HMAC operation
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
TEE_Result crypto_mac_update(void *ctx, uint32_t algo,
					const uint8_t *data, size_t len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	/* HMAC Algorithm */
	struct imxcrypt_hash    *hash;
	enum imxcrypt_hash_id   hash_id;

	/* Cipher Mac Algorthm */
	struct cbc_ctx          *cbc_ctx;
	struct imxcrypt_cipher  *cipher;
	enum imxcrypt_cipher_id cipher_id;
	struct imxcrypt_cipher_update dupdate;

	LIB_TRACE("mac update len %d", len);

	/* Check the parameters */
	if ((!ctx) || ((!data) && (len != 0)))
		return TEE_ERROR_BAD_PARAMETERS;

	switch (algo) {
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		cipher = do_check_algo_cipher(algo, &cipher_id);
		if (!cipher)
			return ret;

		cbc_ctx = ctx;

		if (cipher->update) {
			/* Prepare the update data */
			dupdate.ctx         = cbc_ctx->ctx;
			dupdate.algo        = cipher_id;
			dupdate.encrypt     = true;
			dupdate.last        = false;
			dupdate.src.data    = (uint8_t *)data;
			dupdate.src.length  = len;
			dupdate.dst.data    = NULL;
			dupdate.dst.length  = 0;

			ret = cipher->update(&dupdate);
		}

		if (ret == TEE_SUCCESS)
			cbc_ctx->countdata += len;

		break;

	case TEE_ALG_AES_CMAC:
		cipher = do_check_algo_cipher(algo, &cipher_id);
		if (!cipher)
			return ret;

		if (cipher->update) {
			/* Prepare the update data */
			dupdate.ctx         = ctx;
			dupdate.algo        = cipher_id;
			dupdate.encrypt     = true;
			dupdate.last        = false;
			dupdate.src.data    = (uint8_t *)data;
			dupdate.src.length  = len;
			dupdate.dst.data    = NULL;
			dupdate.dst.length  = 0;

			ret = cipher->update(&dupdate);
		}
		break;

	default:
		hash = do_check_algo(algo, &hash_id);
		if (hash) {
			if (hash->update)
				ret = hash->update(ctx, hash_id, data, len);
		}
		break;
	}

	return ret;
}

/**
 * @brief   Finalize the HMAC operation
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
 * @retval TEE_ERROR_OUT_OF_MEMORY   Out of memory
 */
TEE_Result crypto_mac_final(void *ctx, uint32_t algo,
					uint8_t *digest, size_t len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	/* HMAC Algorithm */
	struct imxcrypt_hash    *hash;
	enum imxcrypt_hash_id   hash_id;

	/* Cipher Mac Algorthm */
	struct cbc_ctx          *cbc_ctx;
	struct imxcrypt_cipher  *cipher;
	enum imxcrypt_cipher_id cipher_id;
	struct imxcrypt_cipher_update dupdate;
	uint8_t *pad_src = NULL;
	size_t  pad_size = 0;

	LIB_TRACE("mac final len %d", len);

	/* Check the parameters */
	if ((!ctx) || (!digest) || (!len))
		return TEE_ERROR_BAD_PARAMETERS;

	switch (algo) {
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		cbc_ctx = ctx;
		/* Calculate the last block PAD Size */
		pad_size  = cbc_ctx->sizeblock;
		pad_size -= (cbc_ctx->countdata % cbc_ctx->sizeblock);
		LIB_TRACE("Pad size = %d", pad_size);

		/* fallthrough */

	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
		cipher = do_check_algo_cipher(algo, &cipher_id);
		if (!cipher)
			return ret;

		if ((!cipher->update) || (!cipher->final))
			return ret;

		cbc_ctx = ctx;

		if (pad_size) {
			/* Need to pad the last block */
			pad_src = malloc(pad_size);

			if (!pad_src) {
				LIB_TRACE("Pad src allocation error");
				return TEE_ERROR_OUT_OF_MEMORY;
			}

			memset(pad_src, pad_size, pad_size);
		}

		/* Prepare the update data */
		dupdate.ctx         = cbc_ctx->ctx;
		dupdate.algo        = cipher_id;
		dupdate.encrypt     = true;
		dupdate.last        = true;
		dupdate.src.data    = pad_src;
		dupdate.src.length  = pad_size;
		dupdate.dst.data    = digest;
		dupdate.dst.length  = len;

		ret = cipher->update(&dupdate);

		cipher->final(ctx, cipher_id);
		break;

	case TEE_ALG_AES_CMAC:
		cipher = do_check_algo_cipher(algo, &cipher_id);
		if (!cipher)
			return ret;

		if (cipher->update) {
			/* Prepare the update data */
			dupdate.ctx         = ctx;
			dupdate.algo        = cipher_id;
			dupdate.encrypt     = true;
			dupdate.last        = true;
			dupdate.src.data    = NULL;
			dupdate.src.length  = 0;
			dupdate.dst.data    = digest;
			dupdate.dst.length  = len;

			ret = cipher->update(&dupdate);
		}
		cipher->final(ctx, cipher_id);
		break;

	default:
		hash = do_check_algo(algo, &hash_id);
		if (hash) {
			if (hash->final)
				ret = hash->final(ctx, hash_id, digest, len);
		}
		break;
	}

	if (pad_src)
		free(pad_src);

	return ret;
}

