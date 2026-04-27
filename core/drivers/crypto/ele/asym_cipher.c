// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2026 NXP
 */

#include <drivers/ele/ele.h>
#include <drivers/ele/memutils.h>
#include <drivers/ele/asym_cipher.h>
#include <string.h>

#define ELE_CMD_ASYM_OPERATE 0x92

TEE_Result imx_ele_asym_operate(uint32_t asym_enc_handle, const uint8_t *key,
				size_t key_size, const uint8_t *input,
				size_t input_size, uint8_t *output,
				size_t *output_size, const uint8_t *label,
				size_t label_size, uint32_t asym_operate_scheme,
				bool encrypt, uint16_t key_type,
				size_t key_security_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct imx_ele_buf input_buf = {};
	struct imx_ele_buf output_buf = {};
	struct imx_ele_buf key_buf = {};
	struct imx_ele_buf label_buf = {};
	struct imx_mu_msg mu_msg = {};

	struct asym_operate_msg_cmd {
		uint32_t asym_enc_handle;
		uint32_t key_addr;
		uint32_t plaintext_addr;
		uint32_t ciphertext_addr;
		uint32_t label_addr;
		uint32_t plaintext_size;
		uint32_t ciphertext_size;
		uint32_t label_size;
		uint8_t flags;
		uint8_t rsvd[3];
		uint32_t algorithm;
		uint32_t input_plaintext_key_size;
		uint16_t input_plaintext_key_type;
		uint16_t input_plaintext_key_security_size;
		uint32_t rsvd2;
		uint32_t crc;
	} __packed cmd = {};

	struct asym_operate_msg_rsp {
		uint32_t rsp_code;
		uint32_t output_size;
	} rsp = {};

	if (!key || !input || !output || !key_size || !input_size ||
	    !output_size || !key_security_size)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Allocate buffer for plaintext key
	 */
	res = imx_ele_buf_alloc(&key_buf, key, key_size);
	if (res != TEE_SUCCESS) {
		EMSG("Key memory allocation failed");
		return res;
	}

	/*
	 * Allocate buffer for input data (plaintext for encrypt,
	 * ciphertext for decrypt)
	 */
	res = imx_ele_buf_alloc(&input_buf, input, input_size);
	if (res != TEE_SUCCESS) {
		EMSG("Input memory allocation failed");
		goto out;
	}

	/*
	 * Allocate buffer for output data (ciphertext for encrypt,
	 * plaintext for decrypt)
	 */
	if (*output_size) {
		res = imx_ele_buf_alloc(&output_buf, NULL, *output_size);
		if (res != TEE_SUCCESS) {
			EMSG("Output memory allocation failed");
			goto out;
		}
	}

	/*
	 * Allocate buffer for label if provided (for RSA OAEP)
	 */
	if (label && label_size) {
		res = imx_ele_buf_alloc(&label_buf, label, label_size);
		if (res != TEE_SUCCESS) {
			EMSG("Label memory allocation failed");
			goto out;
		}
	}

	cmd.asym_enc_handle = asym_enc_handle;
	cmd.key_addr = key_buf.paddr_lsb;

	/*
	 * For encryption: input is plaintext, output is ciphertext
	 * For decryption: input is ciphertext, output is plaintext
	 */
	if (encrypt) {
		cmd.plaintext_addr = input_buf.paddr_lsb;
		cmd.ciphertext_addr = output_buf.paddr_lsb;
		cmd.plaintext_size = (uint32_t)input_buf.size;
		cmd.ciphertext_size = (uint32_t)output_buf.size;
	} else {
		if (*output_size) {
			cmd.plaintext_addr = output_buf.paddr_lsb;
			cmd.plaintext_size = (uint32_t)output_buf.size;
		} else {
			cmd.plaintext_addr = 0;
			cmd.plaintext_size = 0;
		}
		cmd.ciphertext_addr = input_buf.paddr_lsb;
		cmd.ciphertext_size = (uint32_t)input_buf.size;
	}

	cmd.label_addr = label_buf.paddr_lsb;
	cmd.label_size = (uint32_t)label_buf.size;

	/*
	 * Flags: Bit 0 = operation mode, Bit 3 = plaintext key
	 */
	cmd.flags = IMX_ELE_FLAG_PLAINTEXT_KEY |
		    (encrypt ? IMX_ELE_FLAG_ENCRYPT : IMX_ELE_FLAG_DECRYPT);

	cmd.algorithm = asym_operate_scheme;
	cmd.input_plaintext_key_size = (uint32_t)key_buf.size;
	cmd.input_plaintext_key_type = key_type;
	cmd.input_plaintext_key_security_size = (uint16_t)key_security_size;
	cmd.crc = 0;

	/*
	 * Prepare MU message
	 */
	mu_msg.header.version = ELE_VERSION_HSM;
	mu_msg.header.size = SIZE_MSG_32(cmd);
	mu_msg.header.tag = ELE_REQUEST_TAG;
	mu_msg.header.command = ELE_CMD_ASYM_OPERATE;

	memcpy(mu_msg.data.u8, &cmd, sizeof(cmd));
	update_crc(&mu_msg);

	res = imx_ele_call(&mu_msg);
	if (res != TEE_SUCCESS && res != TEE_ERROR_SHORT_BUFFER) {
		EMSG("Failed to perform asymmetric %s with plain key res = %"
		     PRIx32, encrypt ? "encryption" : "decryption", res);
		goto out;
	}

	/*
	 * Parse response
	 */
	memcpy(&rsp, mu_msg.data.u8, sizeof(rsp));

	/*
	 * Update output size with actual size from ELE
	 */
	*output_size = rsp.output_size;

	if (res == TEE_ERROR_SHORT_BUFFER)
		goto out;

	/*
	 * Copy output data back to caller
	 */
	res = imx_ele_buf_copy(&output_buf, output, *output_size);
	if (res != TEE_SUCCESS)
		EMSG("Output copy failed");
out:
	if (label && label_size)
		imx_ele_buf_free(&label_buf);
	imx_ele_buf_free(&key_buf);
	imx_ele_buf_free(&input_buf);
	imx_ele_buf_free(&output_buf);

	return res;
}
