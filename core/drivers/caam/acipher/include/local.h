/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    local.h
 *
 * @brief   CAAM Cipher Local header.
 */
#ifndef __LOCAL_H__
#define __LOCAL_H__

/* Global includes */
#include <mpalib.h>

/* Local includes */
#include "common.h"

/**
 * @brief   Definition of the maximum bits of Exponent e
 *          Refer to sp800-56b
 */
#define MAX_BITS_EXP_E	256

/**
 * @brief   Prime generator structure
 */
struct caam_prime_data {
	uint8_t        era;      ///< CAAM Era version
	size_t         key_size; ///< Key size in bits
	struct caambuf *e;       ///< Key exponent e
	struct caambuf *p;       ///< Prime p
	struct caambuf *q;       ///< Prime q (can be NULL of only p asked)
};

/**
 * @brief   Generate a Prime Number
 *          Algorithm based on the Chapter B.3.3 of the FIPS.184-6
 *          specification
 *
 * @param[in/out] data  Prime generation data
 *
 * @retval  CAAM_NO_ERROR   No Error
 * @retval  CAAM_FAILURE    General failure
 * @retval  CAAM_OUT_MEMORY Out of memory error
 */
enum CAAM_Status caam_prime_gen(struct caam_prime_data *data);

#endif /* __LOCAL_H__ */
