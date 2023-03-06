/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2023 NXP
 */
#ifndef __KEY_STORE_H_
#define __KEY_STORE_H_

#include <tee_api_types.h>

/*
 * Get global Key store handle.
 *
 * @key_store_handle: EdgeLock Enclave key store handle
 */
TEE_Result imx_ele_get_global_key_store_handle(uint32_t *key_store_handle);

#endif /* __KEY_STORE_H_ */
