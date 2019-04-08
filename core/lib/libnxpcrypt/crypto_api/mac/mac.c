// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    mac.c
 *
 * @brief   Cryptographic library using the NXP CAAM driver.\n
 *          HMAC crypto_* interface implementation.
 */
/* Global includes */
#include <crypto/crypto.h>
#include <malloc.h>
#include <string.h>
#include <trace.h>
#include <utee_defines.h>

/* Library NXP includes */
#include <libnxpcrypt.h>
#include <libnxpcrypt_hash.h>
#include <libnxpcrypt_cipher.h>

//#define LIB_DEBUG
#ifdef LIB_DEBUG
#define LIB_TRACE	DMSG
#else
#define LIB_TRACE(...)
#endif

/**
 * @brief  Format the MAC context to keep the reference to the
 *         operation driver
 */
struct crypto_mac {
	void *ctx; ///< Context of the operation

	enum mac_type {
		TYPE_HMAC = 0,      ///< Hash MAC operation
		TYPE_CMAC,          ///< Cipher MAC operation
		TYPE_CBCMAC_NOPAD,  ///< Cipher CBC MAC NOPAD operation
		TYPE_CBCMAC_PKCS5,  ///< Cipher CBC MAC PKCS5 operation
	} type; ///< Define the type of MAC

	/* CBC Mac specific context */
	size_t countdata; ///< Number of input data done
	size_t sizeblock; ///< Cipher Block size

	union {
		struct nxpcrypt_hash   *hash;   ///< Hash operations
		struct nxpcrypt_cipher *cipher; ///< Cipher operations
	} op;
};


/**
 * @brief   Checks and returns reference to the driver operations
 *
 * @param[in]  algo     Algorithm
 * @param[out] hash_id  Hash Algorithm internal ID
 *
 * @retval  Reference to the driver operations
 */
static struct nxpcrypt_hash *do_check_algo(uint32_t algo,
					enum nxpcrypt_hash_id *hash_id)
{
	struct nxpcrypt_hash *hash = NULL;
	uint8_t algo_op;
	uint8_t algo_id;

	/* Extract the algorithms fields */
	algo_op = TEE_ALG_GET_CLASS(algo);
	algo_id = TEE_ALG_GET_MAIN_ALG(algo);

	if ((algo_op == TEE_OPERATION_MAC) &&
		((algo_id >= TEE_MAIN_ALGO_MD5) &&
		 (algo_id <= TEE_MAIN_ALGO_SHA512))) {

		*hash_id = algo_id - 1;

		hash = nxpcrypt_getmod(CRYPTO_HMAC);

		/* Verify that the HASH HW implements this algorithm */
		if (hash) {
			if (hash->max_hash < *hash_id)
				hash = nxpcrypt_getmod(CRYPTO_HMAC_SW);
		} else {
			hash = nxpcrypt_getmod(CRYPTO_HMAC_SW);
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
static struct nxpcrypt_cipher *do_check_algo_cipher(uint32_t algo,
					enum nxpcrypt_cipher_id *cipher_id)
{
	struct nxpcrypt_cipher *cipher = NULL;
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

	cipher = nxpcrypt_getmod(CRYPTO_CIPHER);

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

	struct crypto_mac       *mac = NULL;
	enum nxpcrypt_hash_id   hash_id = 0;
	enum nxpcrypt_cipher_id cipher_id = 0;

	/* Check the parameters */
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	LIB_TRACE("mac allocate 0x%"PRIx32"", algo);

	mac = calloc(1, sizeof(*mac));
	if (!mac)
		return TEE_ERROR_OUT_OF_MEMORY;

	switch (algo) {
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		if (TEE_ALG_GET_CHAIN_MODE(algo) == TEE_CHAIN_MODE_CBC_NOPAD)
			mac->type = TYPE_CBCMAC_NOPAD;
		else
			mac->type = TYPE_CBCMAC_PKCS5;

		mac->op.cipher = do_check_algo_cipher(algo, &cipher_id);

		if (mac->op.cipher) {
			if (mac->op.cipher->alloc_ctx)
				ret = mac->op.cipher->alloc_ctx(&mac->ctx,
					cipher_id);
		}
		break;

	case TEE_ALG_AES_CMAC:
		mac->type = TYPE_CMAC;
		mac->op.cipher = do_check_algo_cipher(algo, &cipher_id);

		if (mac->op.cipher) {
			if (mac->op.cipher->alloc_ctx)
				ret = mac->op.cipher->alloc_ctx(&mac->ctx,
					cipher_id);
		}
		break;

	default:
		mac->type = TYPE_HMAC;
		mac->op.hash = do_check_algo(algo, &hash_id);

		if (mac->op.hash) {
			if (mac->op.hash->alloc_ctx)
				ret = mac->op.hash->alloc_ctx(&mac->ctx,
					hash_id);
		}
		break;
	}

	if (ret != TEE_SUCCESS) {
		free(mac);
		mac = NULL;
	}

	*ctx = mac;

	return ret;
}

/**
 * @brief   Free the Software Hashing Context function of the algorithm
 *
 * @param[in/out] ctx    Reference the context pointer
 * @param[in]     algo   Algorithm
 *
 */
void crypto_mac_free_ctx(void *ctx, uint32_t algo __unused)
{
	struct crypto_mac *mac = ctx;

	/* Check the parameters */
	if (!ctx)
		return;

	switch (mac->type) {
	case TYPE_CBCMAC_NOPAD:
	case TYPE_CBCMAC_PKCS5:
	case TYPE_CMAC:
		/* Free the Cipher Algorithm context */
		if (mac->op.cipher) {
			if (mac->op.cipher->free_ctx)
				mac->op.cipher->free_ctx(mac->ctx);

			free(mac);
		}
		break;

	default:
		if (mac->op.hash) {
			if (mac->op.hash->free_ctx)
				mac->op.hash->free_ctx(mac->ctx);

			free(mac);
		}
		break;
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
void crypto_mac_copy_state(void *dst_ctx, void *src_ctx,
		uint32_t algo __unused)
{
	struct crypto_mac *mac_src = src_ctx;
	struct crypto_mac *mac_dst = dst_ctx;

	if ((!dst_ctx) || (!src_ctx))
		return;

	switch (mac_src->type) {
	case TYPE_CBCMAC_NOPAD:
	case TYPE_CBCMAC_PKCS5:
	case TYPE_CMAC:
		/* Copy just the Cipher context no the intermediate cipher */
		if (mac_src->op.cipher) {
			if (mac_src->op.cipher->cpy_state) {
				mac_src->op.cipher->cpy_state(mac_dst->ctx,
					mac_src->ctx);

				if (mac_src->type != TYPE_CMAC) {
					mac_dst->countdata = mac_src->countdata;
					mac_dst->sizeblock = mac_src->sizeblock;
				}
			}
		}
		break;

	default:
		if (mac_src->op.hash) {
			if (mac_src->op.hash->cpy_state)
				mac_src->op.hash->cpy_state(mac_dst->ctx,
					mac_src->ctx);
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

	struct crypto_mac *mac = ctx;

	uint8_t                 *iv_tmp;
	struct nxpcrypt_cipher_init dinit;

	enum nxpcrypt_cipher_id cipher_id;
	LIB_TRACE("mac init keylen %d", key_len);

	/* Check the parameters */
	if ((!ctx) || (!key) || (key_len == 0))
		return TEE_ERROR_BAD_PARAMETERS;

	switch (mac->type) {
	case TYPE_CBCMAC_NOPAD:
	case TYPE_CBCMAC_PKCS5:
		if (!mac->op.cipher)
			return ret;
		if ((!mac->op.cipher->init) || (!mac->op.cipher->block_size))
			return ret;

		do_check_algo_cipher(algo, &cipher_id);
		ret = mac->op.cipher->block_size(cipher_id, &mac->sizeblock);

		if (ret != TEE_SUCCESS)
			return ret;

		/* Allocate temporary IV initialize with 0's */
		iv_tmp = malloc(mac->sizeblock);
		if (!iv_tmp)
			return TEE_ERROR_OUT_OF_MEMORY;

		memset(iv_tmp, 0, mac->sizeblock);
		mac->countdata = 0;

		/* Prepare the initialization data */
		dinit.ctx         = mac->ctx;
		dinit.encrypt     = true;
		dinit.key1.data   = (uint8_t *)key;
		dinit.key1.length = key_len;
		dinit.key2.data   = NULL;
		dinit.key2.length = 0;
		dinit.iv.data     = iv_tmp;
		dinit.iv.length   = mac->sizeblock;
		ret = mac->op.cipher->init(&dinit);

		free(iv_tmp);
		break;

	case TYPE_CMAC:
		if (!mac->op.cipher)
			return ret;
		if (!mac->op.cipher->init)
			return ret;

		/* Prepare the initialization data */
		dinit.ctx         = mac->ctx;
		dinit.encrypt     = true;
		dinit.key1.data   = (uint8_t *)key;
		dinit.key1.length = key_len;
		dinit.key2.data   = NULL;
		dinit.key2.length = 0;
		dinit.iv.data     = NULL;
		dinit.iv.length   = 0;

		ret = mac->op.cipher->init(&dinit);
		break;

	default:
		if (!mac->op.hash)
			return ret;
		if (!mac->op.hash->init)
			return ret;

		ret = mac->op.hash->init(mac->ctx);

		if ((ret == TEE_SUCCESS) &&	(mac->op.hash->compute_key))
			ret = mac->op.hash->compute_key(mac->ctx, key, key_len);
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
TEE_Result crypto_mac_update(void *ctx, uint32_t algo __unused,
					const uint8_t *data, size_t len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct crypto_mac *mac = ctx;

	struct nxpcrypt_cipher_update dupdate;

	LIB_TRACE("mac update len %d", len);

	/* Check the parameters */
	if ((!ctx) || ((!data) && (len != 0)))
		return TEE_ERROR_BAD_PARAMETERS;

	switch (mac->type) {
	case TYPE_CBCMAC_NOPAD:
	case TYPE_CBCMAC_PKCS5:
	case TYPE_CMAC:
		if (mac->op.cipher) {
			if (mac->op.cipher->update) {
				/* Prepare the update data */
				dupdate.ctx         = mac->ctx;
				dupdate.encrypt     = true;
				dupdate.last        = false;
				dupdate.src.data    = (uint8_t *)data;
				dupdate.src.length  = len;
				dupdate.dst.data    = NULL;
				dupdate.dst.length  = 0;

				ret = mac->op.cipher->update(&dupdate);
			}

			if ((ret == TEE_SUCCESS) && (mac->type != TYPE_CMAC))
				mac->countdata += len;
		}
		break;

	default:
		if (mac->op.hash) {
			if (mac->op.hash->update)
				ret = mac->op.hash->update(mac->ctx, data, len);
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
TEE_Result crypto_mac_final(void *ctx, uint32_t algo __unused,
					uint8_t *digest, size_t len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct crypto_mac *mac = ctx;

	struct nxpcrypt_cipher_update dupdate;
	uint8_t *pad_src = NULL;
	size_t  pad_size = 0;

	LIB_TRACE("mac final len %d", len);

	/* Check the parameters */
	if ((!ctx) || (!digest) || (!len))
		return TEE_ERROR_BAD_PARAMETERS;

	switch (mac->type) {
	case TYPE_CBCMAC_PKCS5:
		/* Calculate the last block PAD Size */
		pad_size  = mac->sizeblock;
		pad_size -= (mac->countdata % mac->sizeblock);
		LIB_TRACE("Pad size = %d", pad_size);

		/* fallthrough */

	case TYPE_CBCMAC_NOPAD:
	case TYPE_CMAC:
		if (!mac->op.cipher)
			return ret;

		if ((!mac->op.cipher->update) || (!mac->op.cipher->final))
			return ret;

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
		dupdate.ctx         = mac->ctx;
		dupdate.encrypt     = true;
		dupdate.last        = true;
		dupdate.src.data    = pad_src;
		dupdate.src.length  = pad_size;
		dupdate.dst.data    = digest;
		dupdate.dst.length  = len;

		ret = mac->op.cipher->update(&dupdate);

		mac->op.cipher->final(ctx);
		break;

	default:
		if (mac->op.hash) {
			if (mac->op.hash->final)
				ret = mac->op.hash->final(mac->ctx, digest,
					len);
		}
		break;
	}

	if (pad_src)
		free(pad_src);

	return ret;
}

