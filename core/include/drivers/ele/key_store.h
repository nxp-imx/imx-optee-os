/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2023 NXP
 */
#ifndef __KEY_STORE_H_
#define __KEY_STORE_H_

#include <tee_api_types.h>

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
TEE_Result imx_ele_key_store_open(uint32_t session_handle,
				  uint32_t key_store_id, uint32_t auth_nonce,
				  bool create, bool mon_inc, bool sync,
				  uint32_t *key_store_handle);

/*
 * Close Key store with EdgeLock Enclave.
 *
 * @key_store_handle: EdgeLock Enclave key store handle
 * @strict: Whether to push persistent keys in the NVM.
 */
TEE_Result imx_ele_key_store_close(uint32_t key_store_handle);
/*
 * Get global Key store handle.
 *
 * @key_store_handle: EdgeLock Enclave key store handle
 */
TEE_Result imx_ele_get_global_key_store_handle(uint32_t *key_store_handle);

#endif /* __KEY_STORE_H_ */
