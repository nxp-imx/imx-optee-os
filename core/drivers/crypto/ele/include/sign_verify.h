/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2023 NXP
 */
#ifndef __ACIPHER_H__
#define __ACIPHER_H__

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <utils_mem.h>

#define ELE_KEY_USAGE_SIGN_MSG	  0x00000400
#define ELE_KEY_USAGE_VERIFY_MSG  0x00000800
#define ELE_KEY_USAGE_SIGN_HASH	  0x00001000
#define ELE_KEY_USAGE_VERIFY_HASH 0x00002000
#define ELE_KEY_USAGE_DERIVE	  0x00004000

/* Signature generation message type */
#define ELE_SIG_GEN_MSG_TYPE_MESSAGE 0x1
#define ELE_SIG_GEN_MSG_TYPE_DIGEST  0x0

#define ELE_SIG_VERIFICATION_SUCCESS 0x5A3CC3A5
#define ELE_SIG_VERIFICATION_FAILURE 0x2B4DD4B2

/*
 * Open a Signature Generation Flow
 *
 * @key_store_handle: EdgeLock Enclave key store handle
 * @sig_gen_handle: Signature Generation handle returned by ELE
 */
TEE_Result imx_ele_sig_gen_open(uint32_t key_store_handle,
				uint32_t *sig_gen_handle);

/*
 * Close a signature generation flow
 *
 * @sig_gen_handle: signature generation handle to be closed
 */
TEE_Result imx_ele_sig_gen_close(uint32_t sig_gen_handle);

/*
 * Signature generate operation
 *
 * @sig_gen_handle: edgelock enclave signature generation handle
 * @key_identifier: identifier of key to be used for operation
 * @message: data on which signature will be generated
 * @message_size: message size
 * @signature: generated signature
 * @signature_size: signature size
 * @signature_scheme: signature scheme to be used for signature generation
 * @message_type: whethere passed message is digest or actual message
 *		  (ELE_SIG_GEN_MSG_TYPE_MESSAGE/ELE_SIG_GEN_MSG_TYPE_HASH)
 */
TEE_Result imx_ele_signature_generate(uint32_t sig_gen_handle,
				      uint32_t key_identifier,
				      const uint8_t *message,
				      size_t message_size, uint8_t *signature,
				      size_t signature_size,
				      uint32_t signature_scheme,
				      uint8_t message_type);

/*
 * Open a signature verification flow
 *
 * @session_handle: edgelock enclave session handle
 * @sig_verify_handle: signature verification handle returned by ele
 */
TEE_Result imx_ele_sig_verify_open(uint32_t session_handle,
				   uint32_t *sig_verify_handle);

/*
 * Close a signature verification flow
 *
 * @sig_verify_handle: signature verif handle to be closed
 */
TEE_Result imx_ele_sig_verify_close(uint32_t sig_verify_handle);

/*
 * Signature verification operation
 *
 * @sig_verify_handle: edgelock enclave signature generation handle
 * @key: public key to be used for operation
 * @message: data on which signature was generated
 * @message_size: message size
 * @signature: generated signature
 * @signature_size: signature size
 * @key_size: key size
 * @key_security_size: key security size
 * @key_type: key type
 * @signature_scheme: signature scheme to be used for signature generation
 * @message_type: whether passed message is digest or actual message
 *		  (ELE_SIG_GEN_MSG_TYPE_MESSAGE/ELE_SIG_GEN_MSG_TYPE_HASH)
 */
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
					  uint8_t message_type);

#endif /* __ACIPHER_H__ */
