// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2023 NXP
 */
#include <ele.h>
#include <sign_verify.h>
#include <string.h>
#include <utils_mem.h>

#define ELE_CMD_SIG_GEN_OPEN	 0x70
#define ELE_CMD_SIG_GEN_CLOSE	 0x71
#define ELE_CMD_SIG_GENERATE	 0x72
#define ELE_CMD_SIG_VERIFY_OPEN	 0x80
#define ELE_CMD_SIG_VERIFY_CLOSE 0x81
#define ELE_CMD_SIG_VERIFICATION 0x82

TEE_Result imx_ele_sig_gen_open(uint32_t key_store_handle,
				uint32_t *sig_gen_handle)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	struct sig_gen_open_msg_cmd {
		uint32_t key_store_handle;
		uint32_t msbi;
		uint32_t msbo;
		uint8_t flags;
		uint8_t rsvd[3];
		uint32_t crc;
	} __packed cmd = {
		.key_store_handle = key_store_handle,
		.msbi = 0,
		.msbo = 0,
		.flags = 0,
		.rsvd = {},
		.crc = 0,
	};

	struct sig_gen_open_msg_rsp {
		uint32_t rsp_code;
		uint32_t sig_gen_handle;
	} rsp = {};

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_HSM,
		.header.size = SIZE_MSG_32(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_SIG_GEN_OPEN,
	};

	if (!sig_gen_handle)
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(msg.data.u8, &cmd, sizeof(cmd));
	update_crc(&msg);

	res = imx_ele_call(&msg);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to open signature generation res = %" PRIx32, res);
		return res;
	}

	memcpy(&rsp, msg.data.u8, sizeof(rsp));

	*sig_gen_handle = rsp.sig_gen_handle;

	return TEE_SUCCESS;
}

TEE_Result imx_ele_sig_gen_close(uint32_t sig_gen_handle)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	struct sig_gen_close_msg_cmd {
		uint32_t sig_gen_handle;
	} __packed cmd = {
		.sig_gen_handle = sig_gen_handle,
	};

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_HSM,
		.header.size = SIZE_MSG_32(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_SIG_GEN_CLOSE,
	};

	memcpy(msg.data.u8, &cmd, sizeof(cmd));

	res = imx_ele_call(&msg);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to close signature gen flow res = %" PRIx32, res);
		return res;
	}

	return TEE_SUCCESS;
}

TEE_Result imx_ele_signature_generate(uint32_t sig_gen_handle,
				      uint32_t key_identifier,
				      const uint8_t *message,
				      size_t message_size, uint8_t *signature,
				      size_t signature_size,
				      uint32_t signature_scheme,
				      uint8_t message_type)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct imx_ele_buf msg = {};
	struct imx_ele_buf sig = {};
	struct imx_mu_msg mu_msg = {};

	struct signature_generate_msg_cmd {
		uint32_t sig_gen_handle;
		uint32_t key_identifier;
		uint32_t message;
		uint32_t signature;
		uint32_t message_size;
		uint16_t signature_size;
		uint8_t flags;
		uint8_t rsvd;
		uint32_t signature_scheme;
		uint32_t crc;
	} __packed cmd = {};

	if (!message || !signature || !message_size || !signature_size)
		return TEE_ERROR_BAD_PARAMETERS;

	res = imx_ele_buf_alloc(&msg, message, message_size);
	if (res != TEE_SUCCESS) {
		EMSG("Message memory allocation failed");
		return res;
	}

	res = imx_ele_buf_alloc(&sig, NULL, signature_size);
	if (res != TEE_SUCCESS) {
		EMSG("Signature memory allocation failed");
		goto out;
	}

	cmd.sig_gen_handle = sig_gen_handle;
	cmd.key_identifier = key_identifier;
	cmd.message = msg.paddr;
	cmd.signature = sig.paddr;
	cmd.message_size = (uint16_t)msg.size;
	cmd.signature_size = (uint16_t)sig.size;
	cmd.flags = message_type;
	cmd.rsvd = 0;
	cmd.signature_scheme = signature_scheme;
	cmd.crc = 0;

	mu_msg.header.version = ELE_VERSION_HSM;
	mu_msg.header.size = SIZE_MSG_32(cmd);
	mu_msg.header.tag = ELE_REQUEST_TAG;
	mu_msg.header.command = ELE_CMD_SIG_GENERATE;

	memcpy(mu_msg.data.u8, &cmd, sizeof(cmd));
	update_crc(&mu_msg);

	res = imx_ele_call(&mu_msg);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to generate signature res = %" PRIx32, res);
		return res;
	}

	res = imx_ele_buf_copy(&sig, signature, signature_size);
	if (res != TEE_SUCCESS)
		EMSG("Signature copy failed");

out:
	imx_ele_buf_free(&msg);
	imx_ele_buf_free(&sig);
	return TEE_SUCCESS;
}

TEE_Result imx_ele_sig_verify_open(uint32_t session_handle,
				   uint32_t *sig_verify_handle)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	struct sig_verif_open_msg_cmd {
		uint32_t session_handle;
		uint32_t msbi;
		uint32_t msbo;
		uint8_t flags;
		uint8_t rsvd[3];
		uint32_t crc;
	} __packed cmd = {
		.session_handle = session_handle,
		.msbi = 0,
		.msbo = 0,
		.flags = 0,
		.rsvd = {},
		.crc = 0,
	};

	struct sig_verif_open_msg_rsp {
		uint32_t rsp_code;
		uint32_t sig_verify_handle;
	} rsp = {};

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_HSM,
		.header.size = SIZE_MSG_32(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_SIG_VERIFY_OPEN,
	};

	if (!sig_verify_handle)
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(msg.data.u8, &cmd, sizeof(cmd));
	update_crc(&msg);

	res = imx_ele_call(&msg);
	if (res != TEE_SUCCESS) {
		EMSG("failed to open signature verif flow res = %" PRIx32, res);
		return res;
	}

	memcpy(&rsp, msg.data.u8, sizeof(rsp));

	*sig_verify_handle = rsp.sig_verify_handle;

	return TEE_SUCCESS;
}

TEE_Result imx_ele_sig_verify_close(uint32_t sig_verify_handle)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	struct sig_verif_close_msg_cmd {
		uint32_t sig_verify_handle;
	} __packed cmd = {
		.sig_verify_handle = sig_verify_handle,
	};

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_HSM,
		.header.size = SIZE_MSG_32(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_SIG_VERIFY_CLOSE,
	};

	memcpy(msg.data.u8, &cmd, sizeof(cmd));

	res = imx_ele_call(&msg);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to close signature verif res = %" PRIx32, res);
		return res;
	}

	return TEE_SUCCESS;
}

/*
 * This function will return SUCCESS or FAILURE based on Signature
 * Verification status coming from ELE.
 *
 * @verification_status: Signature Verification status
 */
static TEE_Result imx_ele_sig_verify_status(uint32_t verification_status)
{
	switch (verification_status) {
	case ELE_SIG_VERIFICATION_SUCCESS:
		return TEE_SUCCESS;
	case ELE_SIG_VERIFICATION_FAILURE:
		return TEE_ERROR_SIGNATURE_INVALID;
	default:
		return TEE_ERROR_GENERIC;
	}
}

TEE_Result imx_ele_signature_verification(uint32_t sig_verify_handle,
					  const uint8_t *key,
					  const uint8_t *message,
					  size_t message_size,
					  const uint8_t *signature,
					  size_t signature_size,
					  size_t key_size,
					  size_t key_security_size,
					  uint16_t key_type,
					  uint32_t signature_scheme,
					  uint8_t message_type)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct imx_mu_msg mu_msg = {};
	struct imx_ele_buf public_key = {};
	struct imx_ele_buf msg = {};
	struct imx_ele_buf sig = {};

	struct signature_verification_msg_cmd {
		uint32_t sig_verify_handle;
		uint32_t key;
		uint32_t message;
		uint32_t signature;
		uint32_t message_size;
		uint16_t signature_size;
		uint16_t key_size;
		uint16_t key_security_size;
		uint16_t key_type;
		uint8_t flags;
		uint8_t rsvd[3];
		uint32_t signature_scheme;
		uint32_t crc;
	} __packed cmd = {};

	struct signature_verification_msg_rsp {
		uint32_t rsp_code;
		uint32_t verification_status;
	} rsp = {};

	if (!key || !message || !signature || !key_size ||
	    !message_size || !signature_size || !key_security_size)
		return TEE_ERROR_BAD_PARAMETERS;

	res = imx_ele_buf_alloc(&public_key, key, key_size);
	if (res != TEE_SUCCESS) {
		EMSG("Public key memory allocation failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	res = imx_ele_buf_alloc(&msg, message, message_size);
	if (res != TEE_SUCCESS) {
		EMSG("Message memory allocation failed");
		goto out;
	}

	res = imx_ele_buf_alloc(&sig, signature, signature_size);
	if (res != TEE_SUCCESS) {
		EMSG("Signature memory allocation failed");
		goto out;
	}

	cmd.sig_verify_handle = sig_verify_handle;
	cmd.key = public_key.paddr;
	cmd.message = msg.paddr;
	cmd.signature = sig.paddr;
	cmd.message_size = (uint32_t)msg.size;
	cmd.signature_size = (uint16_t)sig.size;
	cmd.key_size = (uint16_t)public_key.size;
	cmd.key_security_size = (uint16_t)key_security_size;
	cmd.key_type = key_type;
	cmd.flags = message_type;
	cmd.signature_scheme = signature_scheme;
	cmd.crc = 0;

	mu_msg.header.version = ELE_VERSION_HSM;
	mu_msg.header.size = SIZE_MSG_32(cmd);
	mu_msg.header.tag = ELE_REQUEST_TAG;
	mu_msg.header.command = ELE_CMD_SIG_VERIFICATION;

	memcpy(mu_msg.data.u8, &cmd, sizeof(cmd));
	update_crc(&mu_msg);

	res = imx_ele_call(&mu_msg);
	if (res != TEE_SUCCESS) {
		EMSG("Failure in signature verificaction res = %" PRIx32, res);
		goto out;
	}

	memcpy(&rsp, mu_msg.data.u8, sizeof(rsp));

	res = imx_ele_sig_verify_status(rsp.verification_status);
	if (res != TEE_SUCCESS)
		EMSG("Signature Verification failed");

out:
	imx_ele_buf_free(&public_key);
	imx_ele_buf_free(&msg);
	imx_ele_buf_free(&sig);

	return res;
}
