// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    pta_blob_mx.c
 *
 * @brief   Pseudo Trusted Application.\n
 *			Blob Encapsulation/Decapsulation functionality
 */

/* Standard includes */
#include <stdlib.h>
#include <string.h>

/* Library kernel includes */
#include <kernel/pseudo_ta.h>

/* Library libutee includes */
#include <pta_blob.h>

/* Library tee includes */
#include <tee_api_types.h>

/* Library crypto includes */
#include <crypto_extension.h>
#include <libnxpcrypt_blob.h>

/* Library crypto includes */
#include <crypto/crypto.h>

/* Global includes */
#include <tee_api_defines.h>

/** @brief    PTA name */
#define BLOB_PTA_NAME "blob.pta"

/**
 * @brief   Call the Crytographic Extension API to encapsulate
 *          the given input data in the requested blob type.
 *
 *  Params are:
 *    Inputs:
 *     params[0].value.a = blob Type (enum PTA_BLOB_TYPE)
 *     params[1].memref  = Key derivation of 128 bits length
 *     params[2].memref  = Data to encapsulate
 *
 *    Output:
 *     params[3].memref  = Blob resulting
 *                         (size >= data length + 48 bytes)
 *
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_SHORT_BUFFER      Output buffer too short
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result encapsulate(uint32_t param_types,
		TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t exp_param_types;
	struct nxpcrypt_buf payload;
	struct nxpcrypt_buf blob;

	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_OUTPUT);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check the Key derivation */
	if (params[1].memref.size != BLOB_KEY_MODIFIER_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Convert the payload to nxpcrypt_buf object */
	payload.data   = params[2].memref.buffer;
	payload.length = params[2].memref.size;

	/* Convert the blob to nxpcrypt_buf object */
	blob.data   = params[3].memref.buffer;
	blob.length = params[3].memref.size;

	res = blob_encapsulate(params[0].value.a,
			params[1].memref.buffer,
			&payload, &blob);

	if (res == TEE_SUCCESS)
		params[3].memref.size = blob.length;

	return res;
}

/**
 * @brief   Call the Crytographic Extension API to decapsulate
 *          the given input blob in the requested blob type.
 *
 *  Params are:
 *    Inputs:
 *     params[0].value.a = blob Type (enum PTA_BLOB_TYPE)
 *     params[1].memref  = Key derivation of 128 bits length
 *     params[2].memref  = Blob to decapsulate
 *
 *    Output:
 *     params[3].memref  = Data resulting
 *                         (size >= blob length - 48 bytes)
 *
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_SHORT_BUFFER      Output buffer too short
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result decapsulate(uint32_t param_types,
		TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t exp_param_types;
	struct nxpcrypt_buf payload;
	struct nxpcrypt_buf blob;

	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_OUTPUT);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check the Key derivation */
	if (params[1].memref.size != BLOB_KEY_MODIFIER_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Convert the payload to nxpcrypt_buf object */
	payload.data   = params[3].memref.buffer;
	payload.length = params[3].memref.size;

	/* Convert the blob to nxpcrypt_buf object */
	blob.data   = params[2].memref.buffer;
	blob.length = params[2].memref.size;

	res = blob_decapsulate(params[0].value.a,
			params[1].memref.buffer,
			&payload, &blob);

	if (res == TEE_SUCCESS)
		params[3].memref.size = payload.length;

	return res;
}

/**
 * @brief   Called when a pseudo TA is invoked.
 *
 * @param[in]  sess_ctx       Session Identifier
 * @param[in]  cmd_id         Command ID
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_SHORT_BUFFER      Output buffer too short
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result invokeCommandEntryPoint(void *sess_ctx __unused,
		uint32_t cmd_id, uint32_t param_types,
		TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_BLOB_CMD_ENCAPS:
		return encapsulate(param_types, params);
	case PTA_BLOB_CMD_DECAPS:
		return decapsulate(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

/**
 * @brief   Open Session function verifying that only a TA opened
 *          the current PTA
 *
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 * @param[in]  sess_ctx       Session Identifier
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_ACCESS_DENIED     PTA access is denied
 */
static TEE_Result open_session(uint32_t param_types __unused,
			TEE_Param pParams[TEE_NUM_PARAMS] __unused,
			void **sess_ctx)
{
	struct tee_ta_session *sess;

	/* Check if the session is opened by a TA */
	sess = tee_ta_get_calling_session();
	if (!sess)
		return TEE_ERROR_ACCESS_DENIED;

	*sess_ctx = (void *)(vaddr_t)sess->ctx->ops->get_instance_id(sess->ctx);

	return TEE_SUCCESS;
}

pseudo_ta_register(
		.uuid = PTA_BLOB_PTA_UUID,
		.name = BLOB_PTA_NAME,
		.flags = PTA_DEFAULT_FLAGS,
		.open_session_entry_point = open_session,
		.invoke_command_entry_point = invokeCommandEntryPoint);
