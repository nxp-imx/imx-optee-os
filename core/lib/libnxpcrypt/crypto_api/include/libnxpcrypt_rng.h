/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 NXP
 *
 * @file    libnxpcrypt_rng.h
 *
 * @brief   Cryptographic library using the NXP CAAM driver.\n
 *          RNG interface library vs CAAM driver.
 */
#ifndef __LIBNXPCRYPT_RNG_H__
#define __LIBNXPCRYPT_RNG_H__

/**
 * @brief   NXP Crypto Library Random Data driver operations
 *
 */
struct nxpcrypt_rng {
	///< Read a Random Data Buffer
	TEE_Result (*read)(uint8_t *buf, size_t len);
	///< Add entropy to next Random Data Generation
	TEE_Result (*add_entropy)(const uint8_t *inbuf,	size_t len);
};

#endif /* __LIBNXPCRYPT_RNG_H__ */
