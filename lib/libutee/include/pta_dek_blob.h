/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019, 2021 NXP
 *
 * brief   PTA DEK Blob interface identification.
 */
#ifndef __PTA_DEK_BLOB_H__
#define __PTA_DEK_BLOB_H__

/* PTA UUID generated at http://www.itu.int/ITU-T/asn1/uuid.html */
#define PTA_DEK_BLOB_UUID {0xef477737, 0x0db1, 0x4a9d,                         \
		{0x84, 0x37, 0xf2, 0xf5, 0x35, 0xc0, 0xbd, 0x92} }

/*
 * HAB Blob header values
 */
#define HAB_HDR_TAG		0x81
#define HAB_HDR_V4		0x43
#define HAB_HDR_MODE_CCM	0x66
#define HAB_HDR_ALG_AES		0x55

/*
 * DEK blobs are stored by the HAB in a secret key blob data structure. Notice
 * that the HAB supports a set of encryption algorithms, but the encrypted boot
 * protocol expects AES. The key length is a variable; it can be 128-bit,
 * 192-bit, or 256-bit
 *
 * For more info, see NXP application note AN12056
 */
struct hab_dek_blob_header {
	uint8_t tag;		/* Constant identifying HAB struct: 0x81 */
	uint8_t len_msb;	/* Struct length in 8-bit msb */
	uint8_t len_lsb;	/* Struct length in 8-bit lsb */
	uint8_t par;		/* Constant value, HAB version: 0x43 */
	uint8_t mode;		/* AES encryption CCM mode: 0x66 */
	uint8_t alg;		/* AES encryption alg: 0x55 */
	uint8_t	size;		/* Unwrapped key value size in bytes */
	uint8_t flg;		/* Key flags */
} __aligned(8);

/*
 * Commands Definition
 */

/*
 * HAB DEK Blob encapsulation
 * old interface:
 * params[0].memref Data to place in the DEK blob
 * params[1].memref DEK blob created: header and data
 *
 * new interface:
 * params[0].memref Data to place in the DEK blob
 * params[1].memref DEK blob created: header and data
 * params[2].value.a First Secure Memory page to use
 * params[2].value.b Additional pages to allocate
 * params[3].value.a Secure Memory partition where the pages must be allocated
 */
#define PTA_DEK_CMD_BLOB_ENCAPSULATE	0

/*
 * Free a Secure Memory partition
 *
 * params[0].value.a Index of the Secure Memory partition to free
 */
#define PTA_DEK_CMD_FREE_PARTITION	1

#endif /* __PTA_DEK_BLOB_H__ */
