/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright NXP 2023
 */

#ifndef __ELE_H_
#define __ELE_H_

#include <drivers/imx_mu.h>
#include <utils_mem.h>
#include <tee_api_types.h>
#include <trace.h>

/* Definitions for communication protocol */
#define ELE_VERSION_HSM 0x07
#define ELE_REQUEST_TAG 0x17
#define ELE_RESPONSE_TAG 0xe1
#define ELE_VERSION_BASELINE 0x06

/* Definitions for Key Lifetime attribute */
#define ELE_KEY_LIFETIME_VOLATILE	      0x00000000
#define ELE_KEY_LIFETIME_PERSISTENT	      0x00000001
#define ELE_KEY_LIFETIME_VOLATILE_PERMANENT   0x00000080
#define ELE_KEY_LIFETIME_PERSISTENT_PERMANENT 0x00000081

/* Definitions for Key Usage attribute */
#define ELE_KEY_USAGE_EXPORT 0x00000001

/* Key store information */
#define ELE_KEY_STORE_AUTH_NONCE  0x1234
#define ELE_KEY_STORE_MAX_UPDATES 100

/* Key groups for grouping keys */
#define ELE_KEY_GROUP_VOLATILE	 0
#define ELE_KEY_GROUP_PERSISTENT 1

/* Key Store and Key Gen Flags */
#define IMX_ELE_FLAG_SYNC 0x80
#define IMX_ELE_FLAG_MON_INC 0x20

/* Key Lifecycle */
#define ELE_KEY_LIFECYCLE_DEVICE 0x00
#define ELE_KEY_LIFECYCLE_OPEN 0x01
#define ELE_KEY_LIFECYCLE_CLOSED 0x02
#define ELE_KEY_LIFECYCLE_CLOSED_LOCKED 0x04

/*
 * ELE response code
 */
struct response_code {
	uint8_t status;
	uint8_t rating;
	uint16_t rating_extension;
} __packed;

static inline size_t size_msg(size_t cmd)
{
	size_t words = ROUNDUP(cmd, sizeof(uint32_t)) / sizeof(uint32_t);

	/* Add the header size */
	words = words + 1;

	return words;
}

#define SIZE_MSG_32(_msg) size_msg(sizeof(_msg))

/*
 * Extract response codes from the given word
 *
 * @word 32 bits word MU response
 */
struct response_code get_response_code(uint32_t word);

/*
 * The CRC is the last word of the message
 *
 * msg: MU message to hash
 */
void update_crc(struct imx_mu_msg *msg);

/*
 * Initiate a communication with the EdgeLock Enclave. It sends a message
 * and expects an answer.
 *
 * @msg MU message
 */
TEE_Result imx_ele_call(struct imx_mu_msg *msg);
TEE_Result imx_ele_get_global_session_handle(uint32_t *session_handle);

/*
 * Open a Key Management session with EdgeLock Enclave.
 *
 * @key_store_handle: EdgeLock Enclave key store handle
 * @key_mgmt_handle: EdgeLock Enclave Key management handle
 */
TEE_Result imx_ele_key_mgmt_open(uint32_t key_store_handle,
				 uint32_t *key_mgmt_handle);

/*
 * Close Key management with EdgeLock Enclave.
 *
 * @key_mgmt_handle: EdgeLock Enclave key management handle
 */
TEE_Result imx_ele_key_mgmt_close(uint32_t key_mgmt_handle);

/*
 * Generate a Key be it Asymmetric or Symmetric
 *
 * @key_mgmt_handle: EdgeLock Enclave key management handle
 * @public_key_size: Size in bytes of the output where to store the generated
 *		     Key. It must be 0 if a symmetric key is generated.
 *		     If the size is different than 0, EdgeLock Enclave will
 *		     attempt to copy the public key for asymmetric algorithm.
 * @key_group: Indicates the generated key group.
 * @sync: Whether to push persistent keys in the NVM(Non Volatile Memory).
 *        Without it, even if the key attribute is set as persistent
 *        at the key creation (generation, importation), the key will
 *        not be stored in the NVM.
 * @mon_inc: Whether to increment the monotonic counter or not.
 * @key_lifetime: Lifetime of the key (Volatile or Persistent)
 * @key_usage: Defines cryptographic operations that key can execute.
 * @key_type: Defines Key type
 * @key_size: Key Size in bits
 * @permitted_algo: Defines algorithms in which key can be used.
 * @key_lifecycle: Defines in which device lifecycle the key is usable
 *		   OPEN, CLOSED, CLOSED and LOCKED
 * @public_key_addr: In case of Asymmetric Key, address to where Edgelock
 *		Enclave will copy the Public Key.
 * @key_identifier: Identifier of the generated key
 */
TEE_Result imx_ele_generate_key(uint32_t key_mgmt_handle,
				size_t public_key_size, uint16_t key_group,
				bool sync, bool mon_inc, uint32_t key_lifetime,
				uint32_t key_usage, uint16_t key_type,
				size_t key_size, uint32_t permitted_algo,
				uint32_t key_lifecycle,
				uint8_t *public_key_addr,
				uint32_t *key_identifier);

/*
 * Delete a Key
 *
 * @key_mgmt_handle: EdgeLock Enclave key management handle
 * @key_identifier: Identifier of key to be deleted
 */
TEE_Result imx_ele_delete_key(uint32_t key_mgmt_handle,
			      uint32_t key_identifier);

#endif /* __ELE_H_ */
