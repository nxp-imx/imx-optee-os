/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2023 NXP
 */
#ifndef __DRIVERS_CAAM_EXTENSION_H__
#define __DRIVERS_CAAM_EXTENSION_H__

#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <types_ext.h>

#ifdef CFG_NXP_CAAM_MP_DRV
/*
 * Export the MPMR content.
 * We assume that it is filled with message given in parameter.
 * It contains 32 registers of 8 bits (32 bytes).
 *
 * @mpmr  [out] MPMR buffer read
 * @size  [in/out] MPMR buffer size exported
 */
TEE_Result caam_mp_export_mpmr(uint8_t *mpmr, size_t *size);

/*
 * Export the Manufacturing Protection Public Key.
 *
 * @pubkey [out] Public key read
 * @size   [in/out] Public key size exported
 */
TEE_Result caam_mp_export_publickey(uint8_t *pubkey, size_t *size);

/*
 * MPSign function.
 * This function takes the value in the MPMR if it exists
 * and concatenates any additional data (certificate).
 * The signature over the message is done with the private key.
 *
 * @data	[in] Data to sign
 * @data_size	[in] Data size to sign
 * @sig		[out] Signature
 * @sig_size	[in/out] Signature size
 */
TEE_Result caam_mp_sign(uint8_t *data, size_t *data_size, uint8_t *sig,
			size_t *sig_size);
#endif /* CFG_NXP_CAAM_MP_DRV */

#ifdef CFG_NXP_CAAM_SM_DRV
/*
 * Definition of a crypto buffer type
 */
struct cryptobuf {
	uint8_t *data;
	size_t length;
};

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

/*
 * Blob size padding in bytes
 */
#define BLOB_BKEK_SIZE	32
#define BLOB_MAC_SIZE	16
#define BLOB_PAD_SIZE	(BLOB_BKEK_SIZE + BLOB_MAC_SIZE)

/*
 * Blob Key modifier is 128 bits
 */
#define BLOB_KEY_MODIFIER_BITS	128

/*
 * Blob encryption/decryption type
 */
enum crypto_blob_type {
	BLOB_RED = 0,   /* Red Blob mode   - data in plain text */
	BLOB_BLACK_ECB, /* Black Blob mode - data encrypted in AES ECB */
	BLOB_BLACK_CCM, /* Black Blod mode - data encrypted in AES CCM */
};

/*
 * Blob data structure where
 * if encapsulation:
 *       - payload is the input
 *       - blob is the output
 * if decapsulation:
 *       - blob is the input
 *       - payload is the output
 */
struct crypto_blob {
	enum crypto_blob_type type;                /* Blob Type */
	uint32_t key[BLOB_KEY_MODIFIER_BITS / 32]; /* Blob Key modifier */
	struct cryptobuf payload;                  /* Payload */
	struct cryptobuf blob;                     /* Blob */
};

/*
 * Blob encapsulation using CAAM Secure Memory.
 *
 * @blob_data  [in/out] Blob data
 */
TEE_Result caam_blob_sm_encapsulate(struct crypto_blob *blob,
				    struct crypto_sm_page *sm_page);
#endif /* CFG_NXP_CAAM_SM_DRV */
#endif /* __CAAM_EXTENSION_H__ */
