/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2023 NXP
 */
#ifndef __ELE_EXTENSION_H__
#define __ELE_EXTENSION_H__

#include <tee_api_types.h>
#include <types_ext.h>

/*
 * Derive a subkey from the ELE unique key.
 * Given the same input the same subkey is returned each time.
 * @ctx:		Constant data to generate different subkey with
 *			the same usage
 * @ctx_size:		Length of constant data
 * @key:		Generated subkey virtual address
 *			that must map an aligned physical address
 * @key_size:		Required size of the subkey, must be 16 or 32.
 *
 * Returns a subkey.
 */
TEE_Result imx_ele_derive_key(const uint8_t *ctx, size_t ctx_size, uint8_t *key,
			      size_t key_size);

#endif /* __ELE_EXTENSION_H__ */
