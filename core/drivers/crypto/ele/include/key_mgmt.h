/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright NXP 2023
 */

#ifndef __KEY_MGMT_H__
#define __KEY_MGMT_H__

#include <tee_api_types.h>

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

#endif /* __KEY_MGMT_H_ */
