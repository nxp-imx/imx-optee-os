// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    pta_manufact_protec_mx.c
 *
 * @brief   Pseudo Trusted Application.\n
 *			Manufacturing Protection functionality (i.MX7D platform)
 */

/* Standard includes */
#include <stdlib.h>
#include <string.h>

/* Library kernel includes */
#include <kernel/pseudo_ta.h>

/* Library libutee includes */
#include <pta_manufact_protec_mx.h>

/* Library tee includes */
#include <tee_api_types.h>

/* Library crypto includes */
#include <crypto_extension.h>
#include <libnxpcrypt_hash.h>

/* Library crypto includes */
#include <crypto/crypto.h>

/* Global includes */
#include <tee_api_defines.h>

/** @brief    PTA name */
#define MANUFACT_PROTEC_PTA_NAME "manuf_protec.pta"

/** @brief  Size signature MPSign in bytes
 *          This field must be updated on platform supporting other curve
 */
#define SIGNATURE_SIZE	(2*32)


/**
 * @brief   Create the Manufacturing protection public key
 *
 * @param[out] mppub_key    MP Public key
 *
 * @retval TEE_SUCCESS			Success
 * @retval TEE_ERROR_GENERIC           General error
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad Parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY	   Out of memory
 */
static TEE_Result mppub_gen(struct nxpcrypt_buf *pubkey)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	DMSG("MPPub generation function\n");
	/* public key gen */
	res = crypto_mp_export_pubkey(pubkey);
	if (res != TEE_SUCCESS)
		EMSG("crypto_mp_export_pubkey failed with code 0x%x\n", res);

	return res;
}

/**
 * @brief   Create the Manufacturing protection signature\n
 *          over the certificate.
 *
 * @param[in/out]   cert    Certificate
 * @param[in]       len     Length of the certificate
 *
 * @retval TEE_SUCCESS			Success
 * @retval TEE_ERROR_GENERIC           General error
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad Parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY	   Out of memory
 */
static TEE_Result mpsign(void *cert, size_t len, size_t len_sig)
{
	struct nxpcrypt_mp_sign sdata;
	TEE_Result res = TEE_ERROR_GENERIC;

	DMSG("MPSign function\n");

	/* MP Signature structure */
	sdata.message.data = (uint8_t *)cert;
	sdata.message.length = len;
	sdata.signature.length = SIGNATURE_SIZE;

	if (len_sig > len)
		return TEE_ERROR_BAD_PARAMETERS;

	sdata.signature.data = malloc(sdata.signature.length);
	if (!sdata.signature.data) {
		EMSG("malloc failed\n");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	memset(sdata.signature.data, 0, sdata.signature.length);

	/* mpsign */
	res = crypto_mp_sign(&sdata);
	if (res != TEE_SUCCESS) {
		EMSG("crypto_mp_sign failed with code 0x%x\n", res);
		goto out;
	}

	memset(cert, 0, sdata.message.length);
	memcpy(cert, sdata.signature.data, sdata.signature.length);

out:
	free(sdata.signature.data);
	return res;
}

/**
 * @brief   Get MPMR content\n
 *          (Manufacturing Protection message register)\n
 *          It comes from the ROM resident boot firmware data\n
 *          such as the SOC's part number, SRK hash...\n
 *
 * @param[out] mpmr_reg                MPMR register
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_GENERIC           General error
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad Parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY	   Out of memory
 */
static TEE_Result mpmr_content(struct nxpcrypt_buf *mpmr_reg)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	/* Get MPMR content */
	res = crypto_mp_export_mpmr(mpmr_reg);
	if (res != TEE_SUCCESS)
		EMSG("crypto_mp_export_mpmr failed with code 0x%x\n", res);

	return res;
}


/**
 * @brief   Public issuer key exchange.
 *
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 *
 * @retval TEE_SUCCESS                Success
 * @retval TEE_ERROR_BAD_PARAMETERS	  Bad parameters
 * @retval TEE_ERROR_GENERIC          General error
 * @retval TEE_ERROR_OUT_OF_MEMORY	  Out of memory
 */
static TEE_Result pub_issuer_key(uint32_t type,
	TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct nxpcrypt_buf pubkey;
	uint32_t exp_param_types;

	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE);

	if (type != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	pubkey.data = params[0].memref.buffer;
	pubkey.length = params[0].memref.size;

	/* mppub generation */
	res = mppub_gen(&pubkey);
	if (res != TEE_SUCCESS)
		EMSG("mppub_gen failed with code 0x%x\n", res);

	return res;
}

/**
 * @brief   Receive the cerificate to be signed and write the signature in it.
 *          Then get the MPMR content and send both registers to the TA.\n
 *
 * @param[in]  param_types    TEE parameters
 * @param[in]  params         Buffer parameters
 *
 * @retval TEE_SUCCESS                Success
 * @retval TEE_ERROR_BAD_PARAMETERS	  Bad parameters
 * @retval TEE_ERROR_GENERIC          General error
 * @retval TEE_ERROR_OUT_OF_MEMORY	  Out of memory
 */
static TEE_Result certificate_signature(uint32_t type,
	TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct nxpcrypt_buf mpmr_reg;
	uint32_t exp_param_types;

	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_OUTPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE);

	if (type != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* mpsign */
	res = mpsign(params[0].memref.buffer, params[0].memref.size,
		SIGNATURE_SIZE);
	if (res != TEE_SUCCESS) {
		EMSG("mpsign failed with code 0x%x\n", res);
		return res;
	}

	/* mpmr content */
	mpmr_reg.data = params[1].memref.buffer;
	mpmr_reg.length = params[1].memref.size;

	res = mpmr_content(&mpmr_reg);
	if (res != TEE_SUCCESS) {
		EMSG("mpmr_content failed with code 0x%x\n", res);
		return res;
	}

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
 * @retval TEE_ERROR_BAD_PARAMETERS   Bad parameters
 */
static TEE_Result invokeCommandEntryPoint(void *sess_ctx __unused,
	uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_MANUFACT_PROTEC_CMD_CERT:
		return certificate_signature(param_types, params);
	case PTA_MANUFACT_PROTEC_CMD_PUBKEY:
		return pub_issuer_key(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

pseudo_ta_register(.uuid = PTA_MANUFACT_PROTEC_PTA_UUID,
	.name = MANUFACT_PROTEC_PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invokeCommandEntryPoint);
