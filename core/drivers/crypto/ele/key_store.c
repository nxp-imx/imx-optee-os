// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022-2023 NXP
 */
#include <ele.h>
#include <key_store.h>
#include <string.h>

#define ELE_CMD_KEY_STORE_OPEN	    0x30
#define ELE_CMD_KEY_STORE_CLOSE	    0x31

#define IMX_ELE_GLOBAL_KEY_STORE_ID 0x1234
#define IMX_ELE_KEY_STORE_AUTH_NONCE  0x1234
#define IMX_ELE_KEY_STORE_MAX_UPDATES 100

#define IMX_ELE_KEY_STORE_FLAG_CREATE 0x01

/*
 * Open a Keystore session with EdgeLock Enclave.
 *
 * @session_handle: EdgeLock Enclave session handle
 * @key_store_id: User defined word identifying the key store
 * @auth_nonce: Nonce used as authentication proof for accessing
 *		the key store.
 * @create: Whether to create the key store or load it.
 * @mon_inc: Whether to increment the monotonic counter or not.
 * @sync: Whether to push persistent keys in the NVM(Non Volatile Memory).
 *        Without it, even if the key attribute is set as persistent
 *        at the key creation (generation, importation), the key will
 *        not be stored in the NVM.
 * @key_store_handle: EdgeLock Enclave Key store handle.
 */
static TEE_Result imx_ele_key_store_open(uint32_t session_handle,
					 uint32_t key_store_id,
					 uint32_t auth_nonce, bool create,
					 bool mon_inc, bool sync,
					 uint32_t *key_store_handle)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct key_store_open_cmd {
		uint32_t session_handle;
		uint32_t key_store_id;
		uint32_t auth_nonce;
		uint16_t rsvd1;
		uint8_t flags;
		uint8_t rsvd2;
		uint32_t crc;
	} __packed cmd = {
		.session_handle = session_handle,
		.key_store_id = key_store_id,
		.auth_nonce = auth_nonce,
		.rsvd1 = 0,
		.flags = (create ? IMX_ELE_KEY_STORE_FLAG_CREATE : 0) |
			 (mon_inc ? IMX_ELE_FLAG_MON_INC : 0) |
			 (sync ? IMX_ELE_FLAG_SYNC : 0),
		.rsvd2 = 0,
		.crc = 0,
	};

	struct key_store_open_msg_rsp {
		uint32_t rsp_code;
		uint32_t key_store_handle;
	} rsp = {};

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_HSM,
		.header.size = SIZE_MSG_32(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_KEY_STORE_OPEN,
	};

	if (!key_store_handle)
		return TEE_ERROR_BAD_PARAMETERS;

	/* SYNC flag can only be set with CREATE flag */
	/* MONOTONIC counter increment flag can only be set with SYNC flag */
	if ((sync && !create) || (mon_inc && !sync))
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(msg.data.u8, &cmd, sizeof(cmd));
	update_crc(&msg);

	res = imx_ele_call(&msg);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to open key store");
		return res;
	}

	memcpy(&rsp, msg.data.u8, sizeof(rsp));

	*key_store_handle = rsp.key_store_handle;

	return TEE_SUCCESS;
}

/*
 * Close Key store with EdgeLock Enclave.
 *
 * @key_store_handle: EdgeLock Enclave key store handle
 * @strict: Whether to push persistent keys in the NVM.
 */
static TEE_Result __maybe_unused
imx_ele_key_store_close(uint32_t key_store_handle)
{
	struct key_store_close_cmd {
		uint32_t key_store_handle;
	} cmd = {
		.key_store_handle = key_store_handle,
	};

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION_HSM,
		.header.size = SIZE_MSG_32(cmd),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_KEY_STORE_CLOSE,
	};

	memcpy(msg.data.u8, &cmd, sizeof(cmd));

	return imx_ele_call(&msg);
}

TEE_Result imx_ele_get_global_key_store_handle(uint32_t *key_store_handle)
{
	static uint32_t imx_ele_key_store_handle;
	uint32_t imx_ele_session_handle = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!key_store_handle)
		return TEE_ERROR_BAD_PARAMETERS;

	if (imx_ele_key_store_handle) {
		res = TEE_SUCCESS;
		goto out;
	}

	res = imx_ele_get_global_session_handle(&imx_ele_session_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get global session handle");
		return res;
	}

	res = imx_ele_key_store_open(imx_ele_session_handle,
				     IMX_ELE_GLOBAL_KEY_STORE_ID,
				     IMX_ELE_KEY_STORE_AUTH_NONCE, true, false,
				     false, &imx_ele_key_store_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to open key store handle");
		return res;
	}

out:
	*key_store_handle = imx_ele_key_store_handle;
	return res;
}
