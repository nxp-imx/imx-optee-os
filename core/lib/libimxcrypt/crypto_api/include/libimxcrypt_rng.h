/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    libimxcrypt_rng.h
 *
 * @brief   Cryptographic library using the i.MX CAAM driver.\n
 *          RNG interface library vs CAAM driver.
 */
#ifndef __LIBIMXCRYPT_RNG_H__
#define __LIBIMXCRYPT_RNG_H__

/**
 * @brief   i.MX Crypto Library Random Data driver operations
 *
 */
struct imxcrypt_rng {
	///< Read a Random Data Buffer
	TEE_Result (*read)(uint8_t *buf, size_t len);
	///< Add entropy to next Random Data Generation
	TEE_Result (*add_entropy)(const uint8_t *inbuf,	size_t len);
};

#endif /* __LIBIMXCRYPT_RNG_H__ */
