// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP\n
 *
 * @file    aes_ccm.c
 *
 * @brief   Cryptographic library using the NXP CAAM driver.\n
 *          AES CCM crypto_* interface implementation.
 */

/* Global includes */
#include <crypto/aes-ccm.h>
#include <crypto/crypto.h>

/* Local include */
#include "local.h"

/**
 * @brief   Allocates the Software Authentication Encryption Context
 *          function of the algorithm
 *
 * @param[in/out] ctx    Reference the context pointer
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
TEE_Result crypto_aes_ccm_alloc_ctx(void **ctx)
{
	return authenc_alloc_ctx(ctx, TEE_ALG_AES_CCM);
}

/**
 * @brief   Free the Software Authentication Encryption Context
 *          function of the algorithm
 *
 * @param[in/out] ctx    Reference the context pointer
 */
void crypto_aes_ccm_free_ctx(void *ctx)
{
	authenc_free_ctx(ctx, TEE_ALG_AES_CCM);
}

/**
 * @brief   Copy Software Authentication Encryption Context
 *
 * @param[in]  src_ctx  Reference the context source
 * @param[out] dst_ctx  Reference the context destination
 */
void crypto_aes_ccm_copy_state(void *dst_ctx, void *src_ctx)
{
	authenc_copy_state(dst_ctx, src_ctx, TEE_ALG_AES_CCM);
}

/**
 * @brief  Initialization of the Authentication Encryption operation
 *
 * @param[in] ctx          Reference the context pointer
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
TEE_Result crypto_aes_ccm_init(void *ctx,
			TEE_OperationMode mode,
			const uint8_t *key, size_t key_len,
			const uint8_t *nonce, size_t nonce_len,
			size_t tag_len, size_t aad_len, size_t payload_len)
{
	return authenc_init(ctx, TEE_ALG_AES_CCM, mode,
			key, key_len, nonce, nonce_len,
			tag_len, aad_len, payload_len);
}

/**
 * @brief  Update the Authentication Associated Data
 *
 * @param[in] ctx        Reference the context pointer
 * @param[in] data       Data to add
 * @param[in] len        Length of the data
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_GENERIC           Other Error
 */
TEE_Result crypto_aes_ccm_update_aad(void *ctx,
				const uint8_t *data, size_t len)
{
	return authenc_update_aad(ctx, TEE_ALG_AES_CCM, data, len);
}

/**
 * @brief  Update Authentication data and returns result
 *
 * @param[in]  ctx         Reference the context pointer
 * @param[in]  mode        Operation mode
 * @param[in]  src_data    Source
 * @param[in]  src_len     Length of the source
 * @param[out] dst_data    Destination
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_GENERIC           Other Error
 */
TEE_Result crypto_aes_ccm_update_payload(void *ctx,
				TEE_OperationMode mode,
				const uint8_t *src_data, size_t src_len,
				uint8_t *dst_data)
{
	return authenc_update_payload(ctx, TEE_ALG_AES_CCM, mode,
			src_data, src_len, dst_data);
}

/**
 * @brief  Finalize the Authentication data encryption
 *
 * @param[in]     ctx          Reference the context pointer
 * @param[in]     mode         Operation mode
 * @param[in]     src_data     Source
 * @param[in]     src_len      Length of the source
 * @param[out]    dst_data     Destination
 * @param[out]    dst_tag      Destination tag
 * @param[in/out] dst_tag_len  Length of the destination tag
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_GENERIC           Other Error
 * @retval TEE_ERROR_SHORT_BUFFER      Tag Length is too short
 * @retval TEE_ERROR_MAC_INVALID       MAC is invalid
 */
TEE_Result crypto_aes_ccm_enc_final(void *ctx,
			const uint8_t *src_data, size_t src_len,
			uint8_t *dst_data,
			uint8_t *dst_tag, size_t *dst_tag_len)
{
	return authenc_update_final(ctx, TEE_ALG_AES_CCM, TEE_MODE_ENCRYPT,
				src_data, src_len, dst_data,
				dst_tag, dst_tag_len);
}
/**
 * @brief  Finalize the Authentication data decryption
 *
 * @param[in]  ctx        Reference the context pointer
 * @param[in]  mode       Operation mode
 * @param[in]  src_data   Source
 * @param[in]  src_len    Length of the source
 * @param[in]  tag        Destination tag
 * @param[in]  tag_len    Length of the destination tag
 * @param[out] dst_data   Destination
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_GENERIC           Other Error
 * @retval TEE_ERROR_SHORT_BUFFER      Tag Length is too short
 * @retval TEE_ERROR_MAC_INVALID       MAC is invalid
 */
TEE_Result crypto_aes_ccm_dec_final(void *ctx,
				const uint8_t *src_data, size_t src_len,
				uint8_t *dst_data,
				const uint8_t *tag, size_t tag_len)
{
	return authenc_update_final(ctx, TEE_ALG_AES_CCM, TEE_MODE_DECRYPT,
				src_data, src_len, dst_data,
				(uint8_t *)tag, &tag_len);
}

/**
 * @brief  Finalize the Authentication data operation
 *
 * @param[in] ctx Reference the context pointer
 */
void crypto_aes_ccm_final(void *ctx)
{
	authenc_final(ctx, TEE_ALG_AES_CCM);
}
