// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    status.c
 *
 * @brief   Implementation of utilities function to manage LibTomCrypt
 *          status conversion to TEE Result and opposite.
 */

/* Local includes */
#include "local.h"

/**
 * @brief   Convert a TEE_Result code to a LibTomCrypt error code
 *
 * @param[in] code  TEE_Result code
 *
 * @retval  CRYPT_xxx code
 */
int conv_TEE_Result_to_CRYPT(TEE_Result code)
{
	int ret = CRYPT_ERROR;

	switch (code) {
	case TEE_SUCCESS:
		ret = CRYPT_OK;
		break;

	case TEE_ERROR_OUT_OF_MEMORY:
		ret = CRYPT_MEM;
		break;

	case TEE_ERROR_NOT_IMPLEMENTED:
		ret = CRYPT_NOP;
		break;

	case TEE_ERROR_BAD_PARAMETERS:
		ret = CRYPT_INVALID_ARG;
		break;

	default:
		break;
	}

	return ret;
}

/**
 * @brief   Convert a LibTomCrypt error code to TEE_Result
 *
 * @param[in] code  CRYPT_xxx code
 *
 * @retval  TEE_Result code
 */
TEE_Result conv_CRYPT_to_TEE_Result(int code)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	switch (code) {
	case CRYPT_OK:
		ret = TEE_SUCCESS;
		break;

	case CRYPT_MEM:
		ret = TEE_ERROR_OUT_OF_MEMORY;
		break;

	case CRYPT_NOP:
	case CRYPT_INVALID_CIPHER:
		ret = TEE_ERROR_NOT_IMPLEMENTED;
		break;

	case CRYPT_PK_NOT_PRIVATE:
	case CRYPT_PK_INVALID_TYPE:
	case CRYPT_PK_INVALID_SIZE:
	case CRYPT_INVALID_PACKET:
	case CRYPT_PK_INVALID_PADDING:
	case CRYPT_INVALID_ARG:
	case CRYPT_PK_TYPE_MISMATCH:
	case CRYPT_INVALID_KEYSIZE:
		ret = TEE_ERROR_BAD_PARAMETERS;
		break;

	case CRYPT_BUFFER_OVERFLOW:
		ret = TEE_ERROR_SHORT_BUFFER;
		break;

	default:
		break;
	}

	return ret;
}
