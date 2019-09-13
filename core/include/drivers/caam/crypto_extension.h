/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   CAAM Cryptographic APIs extension not available thru standard TEE
 *         Cryptographic APIs.
 */
#ifndef __CRYPTO_EXTENSTION_H__
#define __CRYPTO_EXTENSTION_H__

#include <tee_api_types.h>

/*
 * Definition of a crypto buffer type
 */
struct cryptobuf {
	uint8_t *data;
	size_t length;
};

#ifdef CFG_CRYPTO_DRV_MP
struct crypto_mp_sign {
	struct cryptobuf message;   /* Message to sign */
	struct cryptobuf signature; /* Message's Signature */
};

/*
 * Export the MPMR content.
 * We assume that it is filled with message given in parameter.
 * It contains 32 registers of 8 bits (32 bytes).
 *
 * @mpmr  [out] MPMR buffer read
 */
TEE_Result crypto_mp_export_mpmr(struct cryptobuf *mpmr);

/*
 * Export the Manufacturing Protection Public Key.
 *
 * @pubkey  [out] Public key read
 */
TEE_Result crypto_mp_export_publickey(struct cryptobuf *pubkey);

/*
 * MPSign function.
 * This function takes the value in the MPMR if it exists
 * and concatenates any additional data (certificate).
 * The signature over the message is done with the private key.
 *
 * @sdata   [in/out] MP Signature structure
 */
TEE_Result crypto_mp_sign(struct crypto_mp_sign *sdata);
#endif /* CFG_CRYPTO_DRV_MP */

#ifdef CFG_CRYPTO_DRV_SM
/*
 * Free a full Secure Memory partition and its pages
 *
 * @partition  Secure Memory partition
 */
TEE_Result caam_sm_free_partition(unsigned int partition);

/*
 * Secure Memory Page(s)/Partition definition
 */
struct crypto_sm_page {
	unsigned int partition;    /* Partition number */
	unsigned int page;         /* Page number */
	unsigned int nb_pages;     /* Number of pages used */
};
#endif /* CFG_CRYPTO_DRV_SM */
#endif /* __CRYPTO_EXTENSTION_H__ */
