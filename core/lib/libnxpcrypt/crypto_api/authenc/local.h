/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP\n
 *
 * @file    local.h
 *
 * @brief   Authenticate Encryption local header.
 */
#ifndef __LOCAL_H__
#define __LOCAL_H__

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
TEE_Result authenc_alloc_ctx(void **ctx, uint32_t algo);

/**
 * @brief   Free the Software Authentication Encryption Context
 *          function of the algorithm
 *
 * @param[in/out] ctx    Reference the context pointer
 * @param[in]     algo   Algorithm
 */
void authenc_free_ctx(void *ctx, uint32_t algo);

/**
 * @brief   Copy Software Authentication Encryption Context
 *
 * @param[in]  src_ctx  Reference the context source
 * @param[in]  algo     Algorithm
 * @param[out] dst_ctx  Reference the context destination
 */
void authenc_copy_state(void *dst_ctx, void *src_ctx, uint32_t algo);

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
TEE_Result authenc_init(void *ctx, uint32_t algo,
			TEE_OperationMode mode,
			const uint8_t *key, size_t key_len,
			const uint8_t *nonce, size_t nonce_len,
			size_t tag_len, size_t aad_len,	size_t payload_len);

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
TEE_Result authenc_update_aad(void *ctx, uint32_t algo,
				const uint8_t *data, size_t len);

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
TEE_Result authenc_update_payload(void *ctx, uint32_t algo,
				TEE_OperationMode mode,
				const uint8_t *src_data, size_t src_len,
				uint8_t *dst_data);

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
TEE_Result authenc_update_final(void *ctx, uint32_t algo,
				TEE_OperationMode mode,
				const uint8_t *src_data, size_t src_len,
				uint8_t *dst_data,
				uint8_t *tag_data, size_t *tag_len);

/**
 * @brief  Finalize the Authentication data operation
 *
 * @param[in] ctx   Reference the context pointer
 * @param[in] algo  Algorithm
 */
void authenc_final(void *ctx, uint32_t algo);

#endif
