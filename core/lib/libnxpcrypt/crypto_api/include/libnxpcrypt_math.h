/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 NXP
 *
 * @file    libnxpcrypt_math.h
 *
 * @brief   Cryptographic library using the NXP CAAM driver.\n
 *          Mathematical operation using CAAM driver if available.
 */
#ifndef __LIBNXPCRYPT_MATH_H__
#define __LIBNXPCRYPT_MATH_H__

/**
 * @brief   Binary Modular operation data
 */
struct nxpcrypt_mod_op {
	struct nxpcrypt_buf N;      ///< Modulus N
	struct nxpcrypt_buf A;      ///< Operand A
	struct nxpcrypt_buf B;      ///< Operand B
	struct nxpcrypt_buf result; ///< Result of operation
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
TEE_Result libnxpcrypt_xor_mod_n(struct nxpcrypt_mod_op *data);

/**
 * @brief   NXP Crypto Library Binaries Modular driver operations
 *
 */
struct nxpcrypt_math {
	///< (A xor B) mod N
	TEE_Result (*xor_mod_n)(struct nxpcrypt_mod_op *op_data);
};

#endif /* __LIBNXPCRYPT_MATH_H__ */
