// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2023 NXP
 */
#include <ele.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <utils_mem.h>

#define ELE_CMD_KEY_MGMT_OPEN  0x40
#define ELE_CMD_KEY_MGMT_CLOSE 0x41
#define ELE_CMD_GENERATE_KEY   0x42
#define ELE_CMD_DELETE_KEY     0x4E

/*
 * Open a key management session with EdgeLock Enclave.
 *
 * @key_store_handle: EdgeLock Enclave key store handle
 * @key_mgmt_handle: EdgeLock Enclave Key management handle
 */
TEE_Result imx_ele_key_mgmt_open(uint32_t key_store_handle,
				 uint32_t *key_mgmt_handle)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct key_mgmt_open_cmd {
		uint32_t key_store_handle;
		uint32_t msbi;
		uint32_t msbo;
		uint8_t flags;
		uint8_t reserved[3];
		uint32_t crc;
	} __packed cmd = {
		.key_store_handle = key_store_handle,
		.msbi = 0,
		.msbo = 0,
		.flags = 0,
		.reserved = {},
		.crc = 0,
	};

	struct key_mgmt_open_msg_rsp {
		uint32_t rsp_code;
		uint32_t key_mgmt_handle;
	} rsp = {};

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_HSM,
		.header.size = SIZE_MSG_32(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_KEY_MGMT_OPEN,
	};

	if (!key_mgmt_handle)
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(msg.data.u8, &cmd, sizeof(cmd));
	update_crc(&msg);

	res = imx_ele_call(&msg);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to open key management service flow");
		return res;
	}

	memcpy(&rsp, msg.data.u8, sizeof(rsp));

	*key_mgmt_handle = rsp.key_mgmt_handle;

	return TEE_SUCCESS;
}

TEE_Result imx_ele_key_mgmt_close(uint32_t key_mgmt_handle)
{
	struct key_mgmt_close_cmd {
		uint32_t key_mgmt_handle;
	} cmd = {
		.key_mgmt_handle = key_mgmt_handle,
	};

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_HSM,
		.header.size = SIZE_MSG_32(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_KEY_MGMT_CLOSE,
	};

	memcpy(msg.data.u8, &cmd, sizeof(cmd));

	return imx_ele_call(&msg);
}

TEE_Result imx_ele_generate_key(uint32_t key_mgmt_handle,
				size_t public_key_size, uint16_t key_group,
				bool sync, bool mon_inc, uint32_t key_lifetime,
				uint32_t key_usage, uint16_t key_type,
				size_t key_size, uint32_t permitted_algo,
				uint32_t key_lifecycle,
				uint8_t *public_key_addr,
				uint32_t *key_identifier)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	struct imx_mu_msg msg = {};
	struct imx_ele_buf public_key = {};
	struct gen_key_msg_cmd {
		uint32_t key_mgmt_handle;
		uint32_t key_id;
		uint16_t public_key_size;
		uint16_t key_group;
		uint16_t key_type;
		uint16_t key_size;
		uint32_t key_lifetime;
		uint32_t key_usage;
		uint32_t permitted_algo;
		uint32_t key_lifecycle;
		uint8_t flags;
		uint8_t reserved[3];
		uint32_t public_key_addr;
		uint32_t crc;
	} __packed cmd = {};

	struct gen_key_msg_rsp {
		uint32_t rsp_code;
		uint32_t key_identifier;
		uint16_t pub_key_size;
		uint16_t reserved;
	} rsp = {};

	if (!key_identifier || !public_key_addr)
		return TEE_ERROR_BAD_PARAMETERS;

	/* MONOTONIC counter increment flag can only be set with SYNC flag */
	if (mon_inc && !sync)
		return TEE_ERROR_BAD_PARAMETERS;

	res = imx_ele_buf_alloc(&public_key, NULL, public_key_size);
	if (res != TEE_SUCCESS) {
		EMSG("Public key memory allocation failed");
		return res;
	}

	cmd.key_mgmt_handle = key_mgmt_handle;
	cmd.key_id = 0;
	cmd.public_key_size = (uint16_t)public_key.size;
	cmd.key_group = key_group;
	cmd.key_type = key_type;
	cmd.key_size = (uint16_t)key_size;
	cmd.key_lifetime = key_lifetime;
	cmd.key_usage = key_usage;
	cmd.permitted_algo = permitted_algo;
	cmd.key_lifecycle = key_lifecycle;
	cmd.flags = (mon_inc ? IMX_ELE_FLAG_MON_INC : 0) |
		    (sync ? IMX_ELE_FLAG_SYNC : 0),
	cmd.public_key_addr = public_key.paddr;
	cmd.crc = 0;

	msg.header.version = ELE_VERSION_HSM;
	msg.header.size = SIZE_MSG_32(cmd);
	msg.header.tag = ELE_REQUEST_TAG;
	msg.header.command = ELE_CMD_GENERATE_KEY;

	memcpy(msg.data.u8, &cmd, sizeof(cmd));
	update_crc(&msg);

	res = imx_ele_call(&msg);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to generate key res = %" PRIx32, res);
		goto out;
	}

	imx_ele_buf_cache_op(TEE_CACHEINVALIDATE, &public_key);

	res = imx_ele_buf_copy(&public_key, public_key_addr, public_key_size);
	if (res != TEE_SUCCESS) {
		EMSG("Public key copy failed");
		goto out;
	}

	memcpy(&rsp, msg.data.u8, sizeof(rsp));

	*key_identifier = rsp.key_identifier;

out:
	imx_ele_buf_free(&public_key);
	return res;
}

TEE_Result imx_ele_delete_key(uint32_t key_mgmt_handle, uint32_t key_identifier)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	struct delete_key_msg_cmd {
		uint32_t key_mgmt_handle;
		uint32_t key_identifier;
		uint16_t rsvd1;
		uint8_t flags;
		uint8_t rsvd2;
	} __packed cmd = {
		.key_mgmt_handle = key_mgmt_handle,
		.key_identifier = key_identifier,
		.rsvd1 = 0,
		.flags = 0,
		.rsvd2 = 0,
	};

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_HSM,
		.header.size = SIZE_MSG_32(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_DELETE_KEY,
	};

	memcpy(msg.data.u8, &cmd, sizeof(cmd));
	update_crc(&msg);

	res = imx_ele_call(&msg);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to delete key res = %" PRIx32, res);
		return res;
	}

	return TEE_SUCCESS;
}
