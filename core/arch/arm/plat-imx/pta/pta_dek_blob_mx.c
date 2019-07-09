// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file	pta_dek_blob_mx.c
 *
 * @brief	Pseudo Trusted Application.
 *		DEK Blob encapsulation.
 */

/* Standard includes */
#include <stdlib.h>
#include <string.h>
#include <trace.h>

/* Library kernel includes */
#include <kernel/cache_helpers.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>

/* Library libutee includes */
#include <pta_dek_blob.h>

/* Library tee includes */
#include <tee_api_defines.h>
#include <tee_api_types.h>

/* Library crypto includes */
#include <crypto/crypto.h>
#include <crypto_extension.h>
#include <libnxpcrypt_blob.h>

/* Platform includes */
#include <imx.h>

#define DEK_BLOB_PTA_NAME "dek_blob.pta"

/**
 * @brief	Generate DEK blob for encrypted boot
 *
 * @param	src_va	Device encryption key (DEK) virtual address.
 * @param	dst_va	Device encryption key blob virtual address.
 * @param	key_len	Device encryption key length.
 *
 * @return	TEE_ERROR_BAD_PARAMETERS
 *		TEE_ERROR_OUT_OF_MEMORY
 *		TEE_SUCCESS
 */
static TEE_Result generate_dek_blob_pta(vaddr_t src_va, vaddr_t dst_va,
					size_t src_size, size_t dst_size,
					size_t key_len)
{
	TEE_Result res;
	struct nxpcrypt_buf payload, blob;
	struct tee_hw_unique_key otpmk;
	struct dek_blob_header hdr;

	if (!(src_va & dst_va)) {
		EMSG("src_addr or dst_addr are invalid");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check input AES key size */
	if (!((key_len == 16) | (key_len == 24) | (key_len == 32))) {
		EMSG("Invalid DEK size. Valid sizes are 128, 192 and 256 bits");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check input size buffer */
	if (src_size < key_len) {
		EMSG("Invalid input size buffer");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check output size buffer */
	if (dst_size < (key_len + BLOB_BPAD_SIZE)) {
		EMSG("Invalid output size buffer");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Get the OTP Master Key */
	tee_otp_get_hw_unique_key(&otpmk);

	/* Build payload and blob structures */
	payload.length = key_len;
	payload.data = (uint8_t *)src_va;
	blob.length = key_len + BLOB_BPAD_SIZE;
	blob.data = (uint8_t *)malloc(blob.length);

	if (!blob.data)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* Clear blob structure */
	memset((void *)blob.data, 0x0, sizeof(blob.data));

	/* Generate the RED blob */
	res = blob_encapsulate(DEK, otpmk.data, &payload, &blob);
	if (res != TEE_SUCCESS) {
		EMSG("Error in Encapsulation 0x%08" PRIx32 "", res);
		goto error;
	}

	/* Build DEK blob header */
	hdr.tag = HAB_HDR_TAG;
	hdr.len_msb = 0x00;
	hdr.len_lsb = key_len + BLOB_BPAD_SIZE + sizeof(hdr);
	hdr.par = HAB_HDR_V4;
	hdr.mode = HAB_HDR_MODE_CCM;
	hdr.alg = HAB_HDR_ALG_AES;
	hdr.size = key_len;
	hdr.flg = 0x00;

	/* Copy header to destination */
	memcpy((void *)dst_va, (void *)&hdr, sizeof(struct dek_blob_header));

	/* Copy the blob */
	memcpy((void *)(dst_va + sizeof(struct dek_blob_header)),
	       (void *)blob.data, blob.length);

	DMSG("DEK Blob size = 0x%X", hdr.len_lsb);
	dhex_dump(NULL, 0, TRACE_DEBUG, (void *)dst_va, hdr.len_lsb);

error:
	free(blob.data);

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
					  uint32_t cmd_id __unused,
					  uint32_t param_types,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types;
	vaddr_t buf_input, buf_output;
	uint32_t in_size, out_size;
	TEE_Result res;

	exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	buf_input = (vaddr_t)params[0].memref.buffer;
	in_size = params[0].memref.size;
	buf_output = (vaddr_t)params[1].memref.buffer;
	out_size = params[1].memref.size;

	res = generate_dek_blob_pta(buf_input, buf_output, in_size, out_size,
				    in_size);
	if (res)
		EMSG("Error generating DEK blob 0x%X", res);

	return res;
}

pseudo_ta_register(
		.uuid = PTA_DEK_BLOB_PTA_UUID,
		.name = DEK_BLOB_PTA_NAME,
		.flags = PTA_DEFAULT_FLAGS,
		.invoke_command_entry_point = invokeCommandEntryPoint);
