/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2019 NXP
 *
 * @file    pta_blob.h
 *
 * @brief   PTA Blob interface identification.
 */
#ifndef __PTA_BLOB_H__
#define __PTA_BLOB_H__

/**
 * @brief   PTA UUID generated at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define PTA_BLOB_PTA_UUID { \
	0x229b29a9, 0x520, 0x4018, \
	{0x87, 0xa9, 0xdf, 0xa0, 0xcb, 0x8b, 0x26, 0xd6} }

/**
 * @brief   PTA Command IDs
 */
enum PTA_BLOB_CMD {
	PTA_BLOB_CMD_ENCAPS = 0, ///< Encapsulation
	PTA_BLOB_CMD_DECAPS,     ///< Decapsulation
};

/**
 * @brief   PTA Blob Type
 *          Enumerate must be the same as the blob_Type defined in the
 *          crypto_extension.h
 */
enum PTA_BLOB_TYPE {
	PTA_BLOB_RED = 0,   ///< Red Blob mode   - data in plain text
	PTA_BLOB_BLACK_ECB, ///< Black Blob mode - data encrypted in AES ECB
	PTA_BLOB_BLACK_CCM, ///< Black Blod mode - data encrypted in AES CCM
};

/**
 * @brief   Blob Key Modifier size in bytes
 */
#define PTA_BLOB_KEY_SIZE	16

/**
 * @brief   Blob PAD size in bytes (padding added to store recovering
 *          blob key (32 bytes) and a blob MAC (16 bytes)
 */
#define PTA_BLOB_PAD_SIZE	 48

#endif /* __PTA_BLOB_H__ */
