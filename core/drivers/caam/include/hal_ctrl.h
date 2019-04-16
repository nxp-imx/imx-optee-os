/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 NXP
 *
 * @file    hal_ctrl.h
 *
 * @brief   CAAM Controller Hardware Abstration Layer header.
 */
#ifndef __HAL_CTRL_H__
#define __HAL_CTRL_H__

#ifdef CFG_NXPCRYPT
/* Library NXP includes */
#include <libnxpcrypt.h>
#endif

/**
 * @brief   Initializes the CAAM HW Controller
 *
 * @param[in] baseaddr  Controller base address
 */
void hal_ctrl_init(vaddr_t baseaddr);

#ifdef CFG_CRYPTO_MP_HW
/**
 * @brief   Get the size in bytes of the MPMR\n
 *          knowing that MPMR reigster is 8 bits.
 *
 * @retval MPMR_NB_REG   Size in bytes of the MPMR
 */
size_t hal_ctrl_get_mpmr_size(void);

/**
 * @brief   Get the SCFGR content and check the MPCURVE fields
 *
 * @param[in] ctrl_addr  Controller base address
 *
 * @retval MPCurve Value read if device closed
 * @retval 0                  if not programmed
 * @retval (-1)               if not supported
 */
int8_t hal_ctrl_is_mpcurve(vaddr_t ctrl_addr);

/**
 * @brief   Get the MPMR content
 *
 * @param[in] ctrl_addr  Controller base address
 * @param[out] val_scfgr Value of the MPMR
 */
void hal_ctrl_get_mpmr(vaddr_t ctrl_addr, uint8_t *val_scfgr);

/**
 * @brief   Fill the MPMR content then lock the register
 *
 * @param[in] ctrl_addr  Controller base address
 * @param[in] msg_mpmr   Buffer with the message and length
 *                       to fill the MPMR content
 */
void hal_ctrl_fill_mpmr(vaddr_t ctrl_addr, struct nxpcrypt_buf *msg_mpmr);
#endif

/**
 * @brief   Returns the number of Job Ring supported
 *
 * @param[in] baseaddr  Controller base address
 *
 * @retval  The number of Job Ring in HW
 */
uint8_t hal_ctrl_jrnum(vaddr_t baseaddr);

/**
 * @brief   Returns the Maximum Hash supported
 *
 * @param[in] baseaddr  Controller base address
 *
 * @retval  Maximum Hash Id supported
 * @retval  (-1) if hash is not supported
 */
int hal_ctrl_hash_limit(vaddr_t baseaddr);

/**
 * @brief   Returns if the HW support the split key operation.
 *          Split key is supported if CAAM Version is > 3
 *
 * @param[in] baseaddr  Controller base address
 *
 * @retval  true  if split key is supported
 * @retval  false otherwise
 */
bool hal_ctrl_splitkey(vaddr_t baseaddr);

/**
 * @brief   Returns the CAAM Era
 *
 * @param[in] baseaddr  Controller base address
 *
 * @retval  Era version
 */
uint8_t hal_ctrl_caam_era(vaddr_t baseaddr);

#endif /* __HAL_CTRL_H__ */
