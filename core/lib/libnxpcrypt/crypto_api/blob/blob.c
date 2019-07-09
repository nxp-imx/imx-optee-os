// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    blob.c
 *
 * @brief   Cryptographic library using the NXP CAAM driver.\n
 *          Blob crypto_* interface implementation.
 */

/* Global includes */
#include <crypto/crypto.h>
#include <trace.h>

/* Library NXP includes */
#include <crypto_extension.h>
#include <libnxpcrypt_blob.h>

//#define LIB_DEBUG
#ifdef LIB_DEBUG
#define LIB_TRACE	DMSG
#else
#define LIB_TRACE(...)
#endif

/**
 * @brief Encapsulates input data.
 *  Resulting blob is the input length + 48 bytes
 *
 * @param[in] type       Type of blob
 * @param[in] key        Key derivation (must be 128 bits length)
 * @param[in] payload    Data to encapsulate
 *
 * @param[in/out] blob   Resulting blob. The maximum length of the blob
 *                       buffer in bytes must be given as input
 *                       (blob length >= payload length + 48 bytes)
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_SHORT_BUFFER      Output buffer too short
 * @retval TEE_ERROR_GENERIC           Generic error
 */
TEE_Result blob_encapsulate(enum blob_type type,
		const uint8_t *key,
		const struct nxpcrypt_buf *payload,
		struct nxpcrypt_buf *blob)
{
	TEE_Result ret;
	struct nxpcrypt_blob_data blob_data = {0};
	struct nxpcrypt_blob *blobdrv = NULL;

	blobdrv = nxpcrypt_getmod(CRYPTO_BLOB);
	if (!blobdrv) {
		LIB_TRACE("Blob is not supported");
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	/* Check input parameters */
	if ((!key) || (!payload) || (!blob)) {
		LIB_TRACE("One of the input data is not defined");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check payload data is defined */
	if (!payload->data) {
		LIB_TRACE("Payload buffer error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check blob data is defined and big enough */
	if (!blob->data) {
		LIB_TRACE("Blob buffer error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if ((blob->length - BLOB_BPAD_SIZE) < payload->length) {
		LIB_TRACE("Blob length too short");
		return TEE_ERROR_SHORT_BUFFER;
	}

	/* Check Blob Type */
	if (type > BLOB_MAX_TYPE) {
		LIB_TRACE("Blob type is not correct");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	blob_data.type           = type;
	blob_data.encaps         = true;
	blob_data.key.data       = (uint8_t *)key;
	blob_data.key.length     = BLOB_KEY_MODIFIER_SIZE;
	blob_data.payload.data   = payload->data;
	blob_data.payload.length = payload->length;
	blob_data.blob.data      = blob->data;
	blob_data.blob.length    = blob->length;

	if (type == DEK)
		ret = blobdrv->dek(&blob_data);
	else
		ret = blobdrv->operate(&blob_data);

	/* Return the size of the encapsulated blob */
	blob->length = blob_data.blob.length;

	return ret;
}

/**
 * @brief Decapsulates input blob.
 *  Resulting data is the blob length - 48 bytes
 *
 * @param[in] type         Type of blob
 * @param[in] key          Key derivation (must be 128 bits length)
 * @param[in] blob         Resulting blob.
 *
 * @param[in/out] payload  Data to decapsulate. The maximum length of the
 *                         buffer in bytes must be given as input
 *                         (payload length >= blob length - 48 bytes)
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_SHORT_BUFFER      Output buffer too short
 * @retval TEE_ERROR_GENERIC           Generic error
 */
TEE_Result blob_decapsulate(enum blob_type type,
		const uint8_t *key,
		struct nxpcrypt_buf *payload,
		const struct nxpcrypt_buf *blob)
{
	TEE_Result ret;

	struct nxpcrypt_blob_data blob_data = {0};
	struct nxpcrypt_blob *blobdrv = NULL;

	blobdrv = nxpcrypt_getmod(CRYPTO_BLOB);
	if (!blobdrv) {
		LIB_TRACE("Blob is not supported");
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	/* Check input parameters */
	if ((!key) || (!payload) || (!blob)) {
		LIB_TRACE("One of the input data is not defined");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check payload data is defined */
	if (!payload->data) {
		LIB_TRACE("Payload buffer error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check blob data is defined and big enough */
	if (!blob->data) {
		LIB_TRACE("Blob buffer error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (blob->length > (payload->length + BLOB_BPAD_SIZE)) {
		LIB_TRACE("Payload length too short");
		return TEE_ERROR_SHORT_BUFFER;
	}

	/* Check Blob Type */
	if (type > BLOB_MAX_TYPE) {
		LIB_TRACE("Blob type is not correct");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	blob_data.type           = type;
	blob_data.encaps         = false;
	blob_data.key.data       = (uint8_t *)key;
	blob_data.key.length     = BLOB_KEY_MODIFIER_SIZE;
	blob_data.payload.data   = payload->data;
	blob_data.payload.length = payload->length;
	blob_data.blob.data      = blob->data;
	blob_data.blob.length    = blob->length;

	ret = blobdrv->operate(&blob_data);
	/* Return the size of the decapsulated data */
	payload->length = blob_data.payload.length;

	return ret;
}

