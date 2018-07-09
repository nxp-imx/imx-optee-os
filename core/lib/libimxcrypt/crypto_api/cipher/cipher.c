// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    cipher.c
 *
 * @brief   Cryptographic library using the i.MX CAAM driver.\n
 *          Cipher crypto_* interface implementation.
 */

/* Global includes */
#include <crypto/crypto.h>
#include <kernel/panic.h>
#include <string.h>
#include <trace.h>
#include <utee_defines.h>

/* Library i.MX includes */
#include <libimxcrypt.h>
#include <libimxcrypt_cipher.h>

#ifndef CFG_CRYPTO_GCM_HW
#include <tomcrypt.h>
#endif

//#define LIB_DEBUG
#ifdef LIB_DEBUG
#define LIB_TRACE	DMSG
#else
#define LIB_TRACE(...)
#endif

/**
 * @brief   Checks and returns reference to the driver operations
 *
 * @param[in]  algo       Algorithm
 * @param[out] cipher_id  Cipher Algorithm internal ID
 *
 * @retval  Reference to the driver operations
 */
static struct imxcrypt_cipher *do_check_algo(uint32_t algo,
					enum imxcrypt_cipher_id *cipher_id)
{
	struct imxcrypt_cipher *cipher = NULL;
	uint8_t algo_op;
	uint8_t algo_id;
	uint8_t algo_md;
	uint8_t min_id;
	uint8_t max_id;
	enum imxcrypt_cipher_id cipher_algo = 0;

	/* Extract the algorithms fields */
	algo_op = TEE_ALG_GET_CLASS(algo);
	algo_id = TEE_ALG_GET_MAIN_ALG(algo);
	algo_md = TEE_ALG_GET_CHAIN_MODE(algo);

	LIB_TRACE("Algo op:%d id:%d md:%d",	algo_op, algo_id, algo_md);

	if (algo_op == TEE_OPERATION_CIPHER) {
		switch (algo_id) {
		case TEE_MAIN_ALGO_AES:
			min_id = IMX_AES_ID;
			max_id = AES_CBC_MAC;
			break;

		case TEE_MAIN_ALGO_DES:
			min_id = IMX_DES_ID;
			max_id = MAX_DES_ID;
			break;

		case TEE_MAIN_ALGO_DES3:
			min_id = IMX_DES3_ID;
			max_id = MAX_DES3_ID;
			break;

		default:
			return NULL;
		}

		cipher_algo = min_id + algo_md;

		if (cipher_algo < max_id) {
			cipher     = imxcrypt_getmod(CRYPTO_CIPHER);
			*cipher_id = cipher_algo;
		}
	}

	LIB_TRACE("Check Cipher id: %d ret 0x%"PRIxPTR"",
				cipher_algo, (uintptr_t)cipher);

	return cipher;
}

/**
 * @brief   Allocates the Software Cipher Context function of the algorithm
 *
 * @param[in/out] ctx    Reference the context pointer
 * @param[in]     algo   Algorithm
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
TEE_Result crypto_cipher_alloc_ctx(void **ctx, uint32_t algo)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct imxcrypt_cipher  *cipher   = NULL;
	enum imxcrypt_cipher_id cipher_id = 0;

	/* Check the parameters */
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	cipher = do_check_algo(algo, &cipher_id);
	if (cipher) {
		if (cipher->alloc_ctx)
			ret = cipher->alloc_ctx(ctx, cipher_id);
	}

	return ret;
}

/**
 * @brief   Free the Software Cipher Context function of the algorithm
 *
 * @param[in/out] ctx    Reference the context pointer
 * @param[in]     algo   Algorithm
 *
 */
void crypto_cipher_free_ctx(void *ctx, uint32_t algo)
{
	struct imxcrypt_cipher  *cipher   = NULL;
	enum imxcrypt_cipher_id cipher_id = 0;

	/* Check the parameters */
	if (ctx) {
		cipher = do_check_algo(algo, &cipher_id);
		if (cipher) {
			if (cipher->free_ctx)
				cipher->free_ctx(ctx);
		}
	}
}

/**
 * @brief   Copy Software Cipher Context
 *
 * @param[in] src_ctx  Reference the context source
 * @param[in] algo     Algorithm
 *
 * @param[out] dst_ctx  Reference the context destination
 *
 */
void crypto_cipher_copy_state(void *dst_ctx, void *src_ctx, uint32_t algo)
{
	struct imxcrypt_cipher  *cipher   = NULL;
	enum imxcrypt_cipher_id cipher_id = 0;

	if ((!dst_ctx) || (!src_ctx))
		return;

	/* Check the parameters */
	cipher = do_check_algo(algo, &cipher_id);
	if (cipher) {
		if (cipher->cpy_state)
			cipher->cpy_state(dst_ctx, src_ctx);
	}
}

/**
 * @brief  Initialization of the Cipher operation
 *
 * @param[in] ctx      Reference the context pointer
 * @param[in] algo     Algorithm
 * @param[in] mode     Operation mode
 * @param[in] key1     First Key
 * @param[in] key1_len Length of the first key
 * @param[in] key2     Second Key
 * @param[in] key2_len Length of the second key
 * @param[in] iv       Initial Vector
 * @param[in] iv_len   Length of the IV
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
TEE_Result crypto_cipher_init(void *ctx, uint32_t algo,
					TEE_OperationMode mode,
					const uint8_t *key1, size_t key1_len,
					const uint8_t *key2, size_t key2_len,
					const uint8_t *iv, size_t iv_len)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct imxcrypt_cipher   *cipher   = NULL;
	enum imxcrypt_cipher_id  cipher_id = 0;
	struct imxcrypt_cipher_init dinit;

	/* Check the parameters */
	if (!ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check the mode */
	if ((mode != TEE_MODE_DECRYPT) && (mode != TEE_MODE_ENCRYPT)) {
		LIB_TRACE("Bad Cipher mode request %d", mode);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check the keys vs. length */
	if (((!key1) && (key1_len != 0)) ||
		((!key2) && (key2_len != 0)) ||
		((!iv) && (iv_len != 0))) {
		LIB_TRACE("One of the key is bad");
		LIB_TRACE("key1 @0x%08"PRIxPTR"-%d)",
			(uintptr_t)key1, key1_len);
		LIB_TRACE("key2 @0x%08"PRIxPTR"-%d)",
			(uintptr_t)key1, key1_len);
		LIB_TRACE("iv   @0x%08"PRIxPTR"-%d)",
			(uintptr_t)iv, iv_len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cipher = do_check_algo(algo, &cipher_id);
	if (cipher) {
		if (cipher->init) {
			/* Prepare the initialization data */
			dinit.ctx         = ctx;
			dinit.algo        = cipher_id;
			dinit.encrypt     = ((mode == TEE_MODE_ENCRYPT) ?
						true : false);
			dinit.key1.data   = (uint8_t *)key1;
			dinit.key1.length = key1_len;
			dinit.key2.data   = (uint8_t *)key2;
			dinit.key2.length = key2_len;
			dinit.iv.data     = (uint8_t *)iv;
			dinit.iv.length   = iv_len;
			ret = cipher->init(&dinit);
		}
	}

	return ret;
}

/**
 * @brief  Update of the Cipher operation
 *
 * @param[in]  ctx        Reference the context pointer
 * @param[in]  algo       Algorithm
 * @param[in]  mode       Operation mode
 * @param[in]  last_block True if last block to handle
 * @param[in]  data       Data to encrypt/decrypt
 * @param[in]  len        Length of the input data and output result
 * @param[out] dst        Result block of the operation
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_GENERIC           Other Error
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
TEE_Result crypto_cipher_update(void *ctx, uint32_t algo,
				TEE_OperationMode mode,	bool last_block,
				const uint8_t *data, size_t len,
				uint8_t *dst)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct imxcrypt_cipher   *cipher   = NULL;
	enum imxcrypt_cipher_id  cipher_id = 0;
	struct imxcrypt_cipher_update dupdate;

	/* Check the parameters */
	if ((!ctx) || (!dst)) {
		LIB_TRACE("Bad ctx @0x%08"PRIxPTR" or dst @0x%08"PRIxPTR"",
					(uintptr_t)ctx, (uintptr_t)dst);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check the mode */
	if ((mode != TEE_MODE_DECRYPT) && (mode != TEE_MODE_ENCRYPT)) {
		LIB_TRACE("Bad Cipher mode request %d", mode);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check the data vs. length */
	if ((!data) && (len != 0)) {
		LIB_TRACE("Bad data data @0x%08"PRIxPTR"-%d)",
				(uintptr_t)data, len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cipher = do_check_algo(algo, &cipher_id);
	if (cipher) {
		if (cipher->update) {
			/* Prepare the update data */
			dupdate.ctx         = ctx;
			dupdate.algo        = cipher_id;
			dupdate.last        = last_block;
			dupdate.src.data    = (uint8_t *)data;
			dupdate.src.length  = len;
			dupdate.dst.data    = dst;
			dupdate.dst.length  = len;

			if (mode == TEE_MODE_ENCRYPT)
				dupdate.encrypt = true;
			else
				dupdate.encrypt = false;

			ret = cipher->update(&dupdate);
		}
	}

	return ret;
}

/**
 * @brief  Finalize the Cipher operation
 *
 * @param[in]  ctx        Reference the context pointer
 * @param[in]  algo       Algorithm
 *
 */
void crypto_cipher_final(void *ctx, uint32_t algo)
{
	struct imxcrypt_cipher  *cipher   = NULL;
	enum imxcrypt_cipher_id cipher_id = 0;

	/* Check the parameters */
	if (ctx) {
		cipher = do_check_algo(algo, &cipher_id);
		if (cipher) {
			if (cipher->final)
				cipher->final(ctx, cipher_id);
		}
	}
}

/**
 * @brief  Gets the algorithm block size
 *
 * @param[in]  algo       Algorithm
 * @param[out] size       Block size of the algorithm
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
TEE_Result crypto_cipher_get_block_size(uint32_t algo, size_t *size)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	struct imxcrypt_cipher  *cipher   = NULL;
	enum imxcrypt_cipher_id cipher_id = 0;

	/* Check the parameters */
	if (!size)
		return TEE_ERROR_BAD_PARAMETERS;

	cipher = do_check_algo(algo, &cipher_id);
	if (cipher) {
		if (cipher->block_size)
			ret = cipher->block_size(cipher_id, size);
	}

	return ret;
}

#ifndef CFG_CRYPTO_GCM_HW

/**
 * @brief  AES Expansion key
 *
 * @param[in]  key       Input key of \a key_len bytes size
 * @param[in]  key_len   Key size in bytes
 *
 * @param[out] enc_key   Key resulting of the operation
 * @param[out] rounds    Number of encryption rounds to do
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
TEE_Result crypto_aes_expand_enc_key(const void *key, size_t key_len,
				void *enc_key, unsigned int *rounds)
{
	symmetric_key skey;

	if (aes_setup(key, key_len, 0, &skey))
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(enc_key, skey.rijndael.eK, sizeof(skey.rijndael.eK));
	*rounds = skey.rijndael.Nr;
	return TEE_SUCCESS;
}

/**
 * @brief  AES encryption block
 *
 * @param[in]  enc_key   Encryption key
 * @param[in]  rounds    Rounds number
 * @param[in]  src       Data to encrypt
 *
 * @param[out] dst       Cipher result
 */
void crypto_aes_enc_block(const void *enc_key, unsigned int rounds,
			const void *src, void *dst)
{
	symmetric_key skey;

	memcpy(skey.rijndael.eK, enc_key, sizeof(skey.rijndael.eK));
	skey.rijndael.Nr = rounds;
	if (aes_ecb_encrypt(src, dst, &skey))
		panic();
}

#else

/**
 * @brief  AES Expansion key
 *
 * @param[in]  key       Input key of \a key_len bytes size
 * @param[in]  key_len   Key size in bytes
 *
 * @param[out] enc_key   Key resulting of the operation
 * @param[out] rounds    Number of encryption rounds to do
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
TEE_Result crypto_aes_expand_enc_key(const void *key __unused,
					size_t key_len __unused,
					void *enc_key __unused,
					unsigned int *rounds __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

/**
 * @brief  AES encryption block
 *
 * @param[in]  enc_key   Encryption key
 * @param[in]  rounds    Rounds number
 * @param[in]  src       Data to encrypt
 *
 * @param[out] dst       Cipher result
 */
void __noreturn crypto_aes_enc_block(const void *enc_key __unused,
					unsigned int rounds __unused,
					const void *src __unused,
					void *dst __unused)
{
	panic();
}

#endif // CFG_CRYPTO_GCM_HW
