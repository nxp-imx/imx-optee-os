/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright NXP 2025
 */

#ifndef __ELE_H_
#define __ELE_H_

#include <drivers/ele/memutils.h>
#include <drivers/imx_mu.h>
#include <tee_api_types.h>
#include <trace.h>

/* Definitions for communication protocol */
#define ELE_VERSION_HSM 0x07
#define ELE_REQUEST_TAG 0x17
#define ELE_RESPONSE_TAG 0xe1
#define ELE_VERSION_BASELINE 0x06

/* Definitions for Key Lifetime attribute */
#define ELE_KEY_LIFETIME_VOLATILE	      0x00000000
#define ELE_KEY_LIFETIME_PERSISTENT	      0x00000001
#define ELE_KEY_LIFETIME_VOLATILE_PERMANENT   0x00000080
#define ELE_KEY_LIFETIME_PERSISTENT_PERMANENT 0x00000081

/* Definitions for Key Usage attribute */
#define ELE_KEY_USAGE_EXPORT 0x00000001

/* Key store information */
#define ELE_KEY_STORE_AUTH_NONCE  0x1234
#define ELE_KEY_STORE_MAX_UPDATES 100

/* Key groups for grouping keys */
#define ELE_KEY_GROUP_VOLATILE	 0
#define ELE_KEY_GROUP_PERSISTENT 1

/* Key Store and Key Gen Flags */
#define IMX_ELE_FLAG_SYNC 0x80
#define IMX_ELE_FLAG_MON_INC 0x20

/* Key Lifecycle */
#define ELE_KEY_LIFECYCLE_DEVICE 0x00
#define ELE_KEY_LIFECYCLE_OPEN 0x01
#define ELE_KEY_LIFECYCLE_CLOSED 0x02
#define ELE_KEY_LIFECYCLE_CLOSED_LOCKED 0x04

/* SoC Lifecycle */
#define SOC_LIFECYCLE_CLOSED 0x40UL
#define SOC_LIFECYCLE_OPEN 0x10UL

#define CRC_WORD_LIMIT 0x4
/*
 * ELE response code
 */
struct response_code {
	uint8_t status;
	uint8_t indication;
	uint16_t abort_code;
} __packed;

/*
 * ELE GET INFO response
 */
struct get_info_rsp {
	uint32_t rsp_code;
	uint16_t soc_id;
	uint16_t soc_rev;
	uint16_t lifecycle;
	uint8_t sssm_state;
	uint8_t attest_api_version;
	uint32_t uid[4];
	uint32_t sha256_rom_patch[8];
	uint32_t sha256_firmware[8];
	uint32_t oem_srkh[16];
	uint8_t trng_state;
	uint8_t csal_state;
#if defined(CFG_MX95) || defined(CFG_MX943)
	uint8_t reserved[2];
	uint32_t oem_pqc_srkh[16];
	uint32_t rsvd[8];
#else
	uint8_t imem_state;
	uint8_t unused_2;
#endif
} __packed;

static inline size_t size_msg(size_t cmd)
{
	size_t words = ROUNDUP(cmd, sizeof(uint32_t)) / sizeof(uint32_t);

	/* Add the header size */
	words = words + 1;

	return words;
}

#define SIZE_MSG_32(_msg) size_msg(sizeof(_msg))

/*
 * Extract response codes from the given word
 *
 * @word 32 bits word MU response
 */
struct response_code get_response_code(uint32_t word);

/*
 * The CRC for the message is computed xor-ing all the words of the message:
 * the header and all the words except the word storing the CRC.
 *
 * @msg MU message to hash
 */
uint32_t compute_crc(struct imx_mu_msg *msg);

/*
 * The CRC is the last word of the message
 *
 * msg: MU message to hash
 */
void update_crc(struct imx_mu_msg *msg);

/*
 * Open a session with EdgeLock Enclave. It returns a session handle.
 *
 * @session_handle EdgeLock Enclave session handle
 */
TEE_Result imx_ele_session_open(uint32_t *session_handle);

/*
 * Close a session with EdgeLock Enclave.
 *
 * @session_handle EdgeLock Enclave session handle
 */
TEE_Result imx_ele_session_close(uint32_t session_handle);
/*
 * Initiate a communication with the EdgeLock Enclave. It sends a message
 * and expects an answer.
 *
 * @msg MU message
 */
TEE_Result imx_ele_call(struct imx_mu_msg *msg);
TEE_Result imx_ele_get_global_session_handle(uint32_t *session_handle);

/*
 * Get device related info from EdgeLock Enclave.
 *
 * @rsp GET_INFO returned data get filled in rsp.
 */
TEE_Result imx_ele_get_device_info(struct get_info_rsp *rsp);

#endif /* __ELE_H_ */
