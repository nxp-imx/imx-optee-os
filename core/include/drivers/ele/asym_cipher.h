/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __ASYM_CIPHER_H
#define __ASYM_CIPHER_H

#include <tee_api_types.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * RSA Encryption Algorithms
 */
#define ELE_ALGO_RSA_PKCS1_V15_CRYPT 0x07000200
#define ELE_ALGO_RSA_OAEP_SHA1 0x07000305
#define ELE_ALGO_RSA_OAEP_SHA224 0x07000308
#define ELE_ALGO_RSA_OAEP_SHA256 0x07000309
#define ELE_ALGO_RSA_OAEP_SHA384 0x0700030A
#define ELE_ALGO_RSA_OAEP_SHA512 0x0700030B
#define ELE_ALGO_RSA_OAEP_ANY_HASH 0x070003FF
#define ELE_ALGO_RSA_PKCS1_CRYPT_ALL 0x8700FF00

/*
 * Perform asymmetric encryption or decryption using ELE with plain key
 *
 * @asym_enc_handle: Asymmetric encryption handle (0 for plain key)
 * @key: Key buffer (modulus for public key, priv_exp||modulus for private key)
 * @key_size: Size of key buffer in bytes
 * @input: Input data buffer
 * @input_size: Size of input data
 * @output: Output data buffer
 * @output_size: Pointer to output buffer size (in/out)
 * @label: Optional label for OAEP (can be NULL)
 * @label_size: Size of label (0 if no label)
 * @asym_operate_scheme: Encryption scheme (ELE_ALGO_RSA_*)
 * @encrypt: true for encryption, false for decryption
 * @key_type: Key type (ELE_KEY_TYPE_RSA or ELE_KEY_TYPE_RSA_PUB_KEY)
 * @key_security_size: Key security size in bits
 *
 * Return: TEE_SUCCESS on success, error code otherwise
 */
TEE_Result imx_ele_asym_operate(uint32_t asym_enc_handle, const uint8_t *key,
				size_t key_size, const uint8_t *input,
				size_t input_size, uint8_t *output,
				size_t *output_size, const uint8_t *label,
				size_t label_size, uint32_t asym_operate_scheme,
				bool encrypt, uint16_t key_type,
				size_t key_security_size);

#endif /* __ASYM_CIPHER_H */
