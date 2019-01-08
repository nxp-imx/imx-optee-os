/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2019 NXP
 *
 * @file    caam_blob.h
 *
 * @brief   CAAM Blob manager header
 */
#ifndef __CAAM_BLOB_H__
#define __CAAM_BLOB_H__

/* Global includes */
#include <tee_api_types.h>

/**
 * @brief   Initialize the Blob module
 *
 * @param[in] ctrl_addr   Controller base address
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 */
enum CAAM_Status caam_blob_init(vaddr_t ctrl_addr);

#endif /* __CAAM_BLOB_H__ */
