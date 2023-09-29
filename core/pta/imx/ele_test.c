// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2023 NXP
 */

#include <drivers/ele/ele.h>
#include <drivers/ele/key_store.h>
#include <drivers/ele/key_mgmt.h>
#include <drivers/ele/sign_verify.h>
#include <kernel/pseudo_ta.h>
#include <kernel/user_ta.h>
#include <pta_ele_test.h>
#include <stdint.h>
#include <string.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>

#define PTA_NAME "ele_test.pta"

#define PTA_ELE_KEY_STORE_ID 0x1234
#define PTA_ELE_KEY_STORE_AUTH_NONCE 0x1234

#define PTA_ELE_KEY_GROUP_VOLATILE 0x1
#define PTA_ELE_KEY_GROUP_PERSISTENT 0x2

#define PTA_ELE_ECC_KEY_USAGE                               \
	(ELE_KEY_USAGE_SIGN_MSG | ELE_KEY_USAGE_SIGN_HASH | \
	 ELE_KEY_USAGE_VERIFY_MSG | ELE_KEY_USAGE_VERIFY_HASH)

#define GEN_KEY_TC(_sz, _psz, _key_gp, _key_type, _key_lt, _perm_alg, _sync)   \
	{                                                                      \
		.key_size = (_sz), .public_key_size = (_psz),                  \
		.key_group = (_key_gp), .key_type = (_key_type),               \
		.key_lifetime = (_key_lt), .permitted_algorithm = (_perm_alg), \
		.sync = (_sync),                                               \
	}

struct gen_key_test_case {
	size_t key_size;
	size_t public_key_size;
	uint32_t key_group;
	uint32_t key_type;
	uint32_t key_lifetime;
	uint32_t permitted_algorithm;
	uint32_t sync;
};

static const struct gen_key_test_case gen_key_tc[] = {
	GEN_KEY_TC(224, 56, PTA_ELE_KEY_GROUP_VOLATILE,
		   ELE_KEY_TYPE_ECC_KEY_PAIR_SECP_R1, ELE_KEY_LIFETIME_VOLATILE,
		   ELE_ALGO_ECDSA_SHA224, 0),
	GEN_KEY_TC(256, 64, PTA_ELE_KEY_GROUP_VOLATILE,
		   ELE_KEY_TYPE_ECC_KEY_PAIR_SECP_R1, ELE_KEY_LIFETIME_VOLATILE,
		   ELE_ALGO_ECDSA_SHA256, 0),
	GEN_KEY_TC(384, 96, PTA_ELE_KEY_GROUP_VOLATILE,
		   ELE_KEY_TYPE_ECC_KEY_PAIR_SECP_R1, ELE_KEY_LIFETIME_VOLATILE,
		   ELE_ALGO_ECDSA_SHA384, 0),
	GEN_KEY_TC(521, 132, PTA_ELE_KEY_GROUP_VOLATILE,
		   ELE_KEY_TYPE_ECC_KEY_PAIR_SECP_R1, ELE_KEY_LIFETIME_VOLATILE,
		   ELE_ALGO_ECDSA_SHA512, 0),
	GEN_KEY_TC(224, 56, PTA_ELE_KEY_GROUP_PERSISTENT,
		   ELE_KEY_TYPE_ECC_KEY_PAIR_SECP_R1,
		   ELE_KEY_LIFETIME_PERSISTENT, ELE_ALGO_ECDSA_SHA224, 1),
	GEN_KEY_TC(256, 64, PTA_ELE_KEY_GROUP_PERSISTENT,
		   ELE_KEY_TYPE_ECC_KEY_PAIR_SECP_R1,
		   ELE_KEY_LIFETIME_PERSISTENT, ELE_ALGO_ECDSA_SHA256, 1),
	GEN_KEY_TC(384, 96, PTA_ELE_KEY_GROUP_PERSISTENT,
		   ELE_KEY_TYPE_ECC_KEY_PAIR_SECP_R1,
		   ELE_KEY_LIFETIME_PERSISTENT, ELE_ALGO_ECDSA_SHA384, 1),
	GEN_KEY_TC(521, 132, PTA_ELE_KEY_GROUP_PERSISTENT,
		   ELE_KEY_TYPE_ECC_KEY_PAIR_SECP_R1,
		   ELE_KEY_LIFETIME_PERSISTENT, ELE_ALGO_ECDSA_SHA512, 1),
};

static TEE_Result get_key_store_handle(uint32_t session_handle,
				       uint32_t *key_store_handle)
{
	uint32_t ele_key_store_handle = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!key_store_handle)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Since we have now enabled the NVM manager, we will first try to
	 * open then Key store because there may be the case that same key
	 * store is imported from master blob.
	 * If there is no Key store with the same credentials then, we will
	 * create a key store.
	 */
	res = imx_ele_key_store_open(session_handle, PTA_ELE_KEY_STORE_ID,
				     PTA_ELE_KEY_STORE_AUTH_NONCE, false, false,
				     false, &ele_key_store_handle);
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		res = imx_ele_key_store_open(session_handle,
					     PTA_ELE_KEY_STORE_ID,
					     PTA_ELE_KEY_STORE_AUTH_NONCE, true,
					     false, false,
					     &ele_key_store_handle);
	}
	if (res != TEE_SUCCESS)
		return res;

	*key_store_handle = ele_key_store_handle;
	return res;
}

static TEE_Result ele_generate_delete(const struct gen_key_test_case *tc,
				      uint32_t key_mgmt_handle)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *public_key = NULL;
	uint32_t key_identifier = 0;

	public_key = calloc(1, tc->public_key_size);
	if (!public_key) {
		EMSG("Public key memory allocation failed");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = imx_ele_generate_key(key_mgmt_handle, tc->public_key_size,
				   tc->key_group, tc->sync, false,
				   tc->key_lifetime, PTA_ELE_ECC_KEY_USAGE,
				   tc->key_type, tc->key_size,
				   tc->permitted_algorithm,
				   ELE_KEY_LIFECYCLE_DEVICE, public_key,
				   &key_identifier);
	if (res != TEE_SUCCESS) {
		EMSG("Key generation failed");
		goto out;
	}

	res = imx_ele_delete_key(key_mgmt_handle, key_identifier, tc->sync,
				 false);
	if (res != TEE_SUCCESS)
		EMSG("Key deletion failed");

out:
	free(public_key);
	return res;
}

static TEE_Result
pta_ele_test_key_generate_delete(uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t session_handle = 0;
	uint32_t key_store_handle = 0;
	uint32_t key_mgmt_handle = 0;
	unsigned int i = 0;
	unsigned int error = 0;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = imx_ele_session_open(&session_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Session open failed");
		goto out;
	}

	res = get_key_store_handle(session_handle, &key_store_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Key store open failed");
		goto session_close;
	}

	res = imx_ele_key_mgmt_open(key_store_handle, &key_mgmt_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Key management open failed");
		goto key_store_close;
	}

	for (i = 0; i < ARRAY_SIZE(gen_key_tc); i++) {
		res = ele_generate_delete(&gen_key_tc[i], key_mgmt_handle);
		if (res != TEE_SUCCESS) {
			EMSG("ELE Generate/Delete failed");
			error = 1;
			break;
		}
	}

	res = imx_ele_key_mgmt_close(key_mgmt_handle);
	if (res != TEE_SUCCESS)
		EMSG("Key Mgmt Close failed");

key_store_close:
	res = imx_ele_key_store_close(key_store_handle);
	if (res != TEE_SUCCESS)
		EMSG("Key Store Close failed");

session_close:
	res = imx_ele_session_close(session_handle);
	if (res != TEE_SUCCESS)
		EMSG("Session Close failed");

out:
	if (error)
		res = TEE_ERROR_GENERIC;
	return res;
}

/* Data for test */
static const char test_data[] = "The quick brown fox jumps over the lazy dog";

static TEE_Result ele_sign_verify(uint32_t session_handle,
				  uint32_t key_store_handle,
				  uint32_t key_identifier, uint8_t *public_key,
				  size_t public_key_size, size_t key_size_bits,
				  uint32_t key_type, uint32_t sig_scheme)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t sig_gen_handle = 0;
	uint32_t sig_verify_handle = 0;
	uint8_t *signature = NULL;
	uint8_t *data = (uint8_t *)test_data;
	unsigned int data_size = sizeof(test_data) - 1;

	/*
	 * Public key size and signature size is same for ECC key type
	 */
	size_t signature_size = public_key_size;

	signature = calloc(1, signature_size);
	if (!signature) {
		EMSG("Signature  memory allocation failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	res = imx_ele_sig_gen_open(key_store_handle, &sig_gen_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Signature generation service flow open failed");
		goto out;
	}

	res = imx_ele_signature_generate(sig_gen_handle, key_identifier, data,
					 data_size, signature, signature_size,
					 sig_scheme,
					 ELE_SIG_GEN_MSG_TYPE_MESSAGE);
	if (res != TEE_SUCCESS)
		EMSG("Signature generation failed");

	res |= imx_ele_sig_gen_close(sig_gen_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Signature generation flow close failed");
		goto out;
	}

	res = imx_ele_sig_verify_open(session_handle, &sig_verify_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Signature verification service flow open failed");
		goto out;
	}

	res = imx_ele_signature_verification(sig_verify_handle,
					     public_key, data,
					     data_size, signature,
					     signature_size, public_key_size,
					     key_size_bits, key_type,
					     sig_scheme,
					     ELE_SIG_GEN_MSG_TYPE_MESSAGE);
	if (res != TEE_SUCCESS)
		EMSG("Signature verification failed");

	res |= imx_ele_sig_verify_close(sig_verify_handle);
	if (res != TEE_SUCCESS)
		EMSG("Signature verification flow close failed");

out:
	free(signature);
	return res;
}

static TEE_Result ele_gen_del_sign_verify(const struct gen_key_test_case *tc,
					  uint32_t key_mgmt_handle,
					  uint32_t session_handle,
					  uint32_t key_store_handle)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *public_key = NULL;
	uint32_t key_identifier = 0;
	unsigned int error = 0;

	public_key = calloc(1, tc->public_key_size);
	if (!public_key) {
		EMSG("Public key memory allocation failed");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = imx_ele_generate_key(key_mgmt_handle, tc->public_key_size,
				   tc->key_group, tc->sync, false,
				   tc->key_lifetime, PTA_ELE_ECC_KEY_USAGE,
				   tc->key_type, tc->key_size,
				   tc->permitted_algorithm,
				   ELE_KEY_LIFECYCLE_DEVICE, public_key,
				   &key_identifier);
	if (res != TEE_SUCCESS) {
		EMSG("Key generation failed");
		goto out;
	}

	res = ele_sign_verify(session_handle, key_store_handle, key_identifier,
			      public_key, tc->public_key_size, tc->key_size,
			      ELE_KEY_TYPE_ECC_PUB_KEY_SECP_R1,
			      tc->permitted_algorithm);
	if (res != TEE_SUCCESS) {
		EMSG("Sign Verify test failed");
		error = 1;
	}

	res = imx_ele_delete_key(key_mgmt_handle, key_identifier, tc->sync,
				 false);
	if (res != TEE_SUCCESS)
		EMSG("Key deletion failed");

out:
	free(public_key);
	if (error && !res)
		res = TEE_ERROR_GENERIC;
	return res;
}

static TEE_Result
pta_ele_test_sign_verify(uint32_t param_types,
			 TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t session_handle = 0;
	uint32_t key_store_handle = 0;
	uint32_t key_mgmt_handle = 0;
	unsigned int i = 0;
	unsigned int error = 0;

	uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = imx_ele_session_open(&session_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Session open failed");
		goto out;
	}

	res = get_key_store_handle(session_handle, &key_store_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Key store open failed");
		goto session_close;
	}

	res = imx_ele_key_mgmt_open(key_store_handle, &key_mgmt_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Key management open failed");
		goto key_store_close;
	}

	for (i = 0; i < ARRAY_SIZE(gen_key_tc); i++) {
		res = ele_gen_del_sign_verify(&gen_key_tc[i], key_mgmt_handle,
					      session_handle, key_store_handle);
		if (res != TEE_SUCCESS) {
			EMSG("ELE Gen delete with sign/verify failed");
			error = 1;
			break;
		}
	}

	res = imx_ele_key_mgmt_close(key_mgmt_handle);
	if (res != TEE_SUCCESS)
		EMSG("Key Mgmt Close failed");

key_store_close:
	res = imx_ele_key_store_close(key_store_handle);
	if (res != TEE_SUCCESS)
		EMSG("Key Store Close failed");

session_close:
	res = imx_ele_session_close(session_handle);
	if (res != TEE_SUCCESS)
		EMSG("Session Close failed");

out:
	if (error)
		res = TEE_ERROR_GENERIC;
	return res;
}

static TEE_Result pta_ele_test_invoke_cmd(void *sess_ctx __unused,
					  uint32_t cmd_id, uint32_t param_types,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_ELE_CMD_TEST_KEY_GENERATE_DELETE:
		return pta_ele_test_key_generate_delete(param_types, params);
	case PTA_ELE_CMD_TEST_SIGN_VERIFY:
		return pta_ele_test_sign_verify(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

pseudo_ta_register(.uuid = PTA_ELE_TEST_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = pta_ele_test_invoke_cmd);
