/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    libimxcrypt_math.h
 *
 * @brief   Cryptographic library using the i.MX CAAM driver.\n
 *          Mathematical operation using CAAM driver if available.
 */
#ifndef __LIBIMXCRYPT_MATH_H__
#define __LIBIMXCRYPT_MATH_H__

/**
 * @brief   Binary Modular operation data
 */
struct imxcrypt_mod_op {
	struct imxcrypt_buf N;      ///< Modulus N
	struct imxcrypt_buf A;      ///< Operand A
	struct imxcrypt_buf B;      ///< Operand B
	struct imxcrypt_buf result; ///< Result of operation
};

/**
 * @brief   operation (A xor B) mod N
 *
 * @param[in/out] data   input/output data operation
 *
 * @retval TEE_SUCCESS               Operation success
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad parameters
 * @retval TEE_ERROR_GENERIC         Operation failed
 */
TEE_Result libimxcrypt_xor_mod_n(struct imxcrypt_mod_op *data);

/**
 * @brief   i.MX Crypto Library Binaries Modular driver operations
 *
 */
struct imxcrypt_math {
	///< (A xor B) mod N
	TEE_Result (*xor_mod_n)(struct imxcrypt_mod_op *op_data);
};

#endif /* __LIBIMXCRYPT_MATH_H__ */
