// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    hal_ctrl.c
 *
 * @brief   CAAM Controller Hardware Abstration Layer.\n
 *          Implementation of primitives to access HW
 */
#ifndef CFG_LS
/* Platform includes */
#include <imx.h>
#endif

/* Local includes */
#include "caam_io.h"

#ifdef CFG_CRYPTO_HASH_HW
/* Library NXP includes */
#include <libnxpcrypt_hash.h>
#endif

/* Hal includes */
#include "hal_ctrl.h"

/* Register includes */
#include "ctrl_regs.h"

/* Register includes */
#include "version_regs.h"

#include <trace.h>

/**
 * @brief   Returns the number of Job Ring supported
 *
 * @param[in] baseaddr  Controller base address
 *
 * @retval  The number of Job Ring in HW
 */
uint8_t hal_ctrl_jrnum(vaddr_t baseaddr)
{
	uint32_t val;

	val = get32(baseaddr + CHANUM_MS);

	return GET_CHANUM_MS_JRNUM(val);
}

#ifdef CFG_CRYPTO_HASH_HW
/**
 * @brief   Returns the Maximum Hash supported
 *
 * @param[in] baseaddr  Controller base address
 *
 * @retval  Maximum Hash Id supported
 * @retval  (-1) if hash is not supported
 */
int hal_ctrl_hash_limit(vaddr_t baseaddr)
{
	uint32_t val;

	/* Read the number of instance */
	val = get32(baseaddr + CHANUM_LS);

	if (GET_CHANUM_LS_MDNUM(val)) {
		/* Hashing is supported */
		val = get32(baseaddr + CHAVID_LS);
		val &= BM_CHAVID_LS_MDVID;
		if (val == CHAVID_LS_MDVID_LP256)
			return HASH_SHA256;

		return HASH_SHA512;
	}

	return (-1);
}

/**
 * @brief   Returns if the HW support the split key operation.
 *          Split key is supported if CAAM Version is > 3
 *
 * @param[in] baseaddr  Controller base address
 *
 * @retval  true  if split key is supported
 * @retval  false otherwise
 */
bool hal_ctrl_splitkey(vaddr_t baseaddr)
{
	uint32_t val;

	/* Read the number of instance */
	val = get32(baseaddr + CAAMVID_MS);

	if (GET_CAAMVID_MS_MAJ_REV(val) < 3) {
		return false;
	}

	return true;
}
#endif // CFG_CRYPTO_HASH_HW

#ifdef CFG_CRYPTO_PK_HW
/**
 * @brief   Returns the CAAM Era
 *
 * @param[in] baseaddr  Controller base address
 *
 * @retval  Era version
 */
uint8_t hal_ctrl_caam_era(vaddr_t baseaddr)
{
	uint32_t val;

	/* Read the number of instance */
	val = get32(baseaddr + CCBVID);

	return GET_CCBVID_CAAM_ERA(val);
}
#endif

#ifdef CFG_CRYPTO_MP_HW

/**
 * @brief   Get the size in bytes of the MPMR\n
 *          knowing that MPMR reigster is 8 bits.
 *
 * @retval MPMR_NB_REG   Size in bytes of the MPMR
 */
size_t hal_ctrl_get_mpmr_size(void)
{
	return MPMR_NB_REG;
}

/**
 * @brief   Get the SCFGR content and check the MPCURVE fields
 *
 * @param[in] ctrl_addr  Controller base address
 *
 * @retval MPCurve Value read if device closed
 * @retval 0                  if not programmed
 * @retval (-1)               if not supported
 */
int8_t hal_ctrl_is_mpcurve(vaddr_t ctrl_addr)
{
	uint32_t val_scfgr = 0;

	/*
	 * On i.MX8MQ B0, the MP is not usable, hence
	 * return (-1)
	 */
	if (soc_is_imx8mq_b0_layer())
		return (-1);

	/*
	 * Verify if the device is closed or not
	 * If device is closed, check get the MPCurve
	 */
	if (imx_is_device_closed()) {
		/* Get the SCFGR content */
		val_scfgr = get32(ctrl_addr + SCFGR);
		DMSG("val_scfgr = 0x%x", val_scfgr);

		/* Get the MPCurve field value */
		val_scfgr = (val_scfgr & BM_SCFGR_MPCURVE) >> BS_SCFGR_MPCURVE;

		/*
		 * If the device is closed and the MPCurve field is 0
		 * return (-1) indicating that there is a problem and the
		 * MP can not be supported.
		 */
		if (val_scfgr == 0)
			return (-1);
	}

	return val_scfgr;
}

/**
 * @brief   Get the MPMR content
 *
 * @param[in] ctrl_addr  Controller base address
 * @param[out] val_scfgr Value of the MPMR
 */
void hal_ctrl_get_mpmr(vaddr_t ctrl_addr, uint8_t *val_scfgr)
{
	int i;
	uint32_t val;
	/*
     * get the SCFGR content
     * Note that the MPMR endianess is reverted between write and read
     */
	for (i = 0; i < MPMR_NB_REG; i += 4) {
		val = get32(ctrl_addr + MPMR + i);
		val_scfgr[i]     = (uint8_t)((val >> 24) & 0xFF);
		val_scfgr[i + 1] = (uint8_t)((val >> 16) & 0xFF);
		val_scfgr[i + 2] = (uint8_t)((val >> 8) & 0xFF);
		val_scfgr[i + 3] = (uint8_t)(val & 0xFF);
	}

}

/**
 * @brief   Fill the MPMR content then lock the register
 *
 * @param[in] ctrl_addr  Controller base address
 * @param[in] msg_mpmr   Buffer with the message and length
 *                       to fill the MPMR content
 */
void hal_ctrl_fill_mpmr(vaddr_t ctrl_addr, struct nxpcrypt_buf *msg_mpmr)
{
	int i;
	vaddr_t reg = ctrl_addr + MPMR;
	bool is_filled = false;
	uint32_t val = 0;
	uint16_t min, remain;

	/* check if the MPMR is filled */
	if (get32(ctrl_addr + SCFGR) & BM_SCFGR_MPMRL)
		is_filled = true;

	DMSG("is_filled = %s", is_filled?"true":"false");

	/* if the MPMR is not filled */
	if (!is_filled) {
		/*
		 * find the min between the message length
		 * and the MPMR_NB_REG
		 */
		min = MIN(msg_mpmr->length, (uint8_t)MPMR_NB_REG);
		remain = min % 4;

		/* fill the MPMR with the first entiere 32 bits value */
		for (i = 0; i < (min-remain); i += 4, reg += 4) {
			val = (msg_mpmr->data[i] |
					(msg_mpmr->data[i + 1] << 8) |
					(msg_mpmr->data[i + 2] << 16) |
					(msg_mpmr->data[i + 3] << 24));
			put32(reg, val);
		}

		if (remain) {
			val = 0;
			/*
			 * fill the MPMR with the 8 bits values
			 * until the end of the message length
			 */
			for (i = 0; i < remain; i++)
				val |= (msg_mpmr->data[i] << (i*8));
			put32(reg, val);
			reg += 4;
		}
		/* fill the remain of the MPMR with 0 */
		remain = MPMR_NB_REG - ROUNDUP(msg_mpmr->length, 4);
		for (i = 0; i < (remain / 4); i++, reg += 4)
			put32(reg, 0x0);

		/*
		 * locks the MPMR for writing
		 * remains locked until the next power-on session
		 * set the MPMRL bit of SCFRG to 1
		 */
		put32(ctrl_addr + SCFGR,
			(get32(ctrl_addr + SCFGR) | BM_SCFGR_MPMRL));

		DMSG("val_scfgr = 0x%x", get32(ctrl_addr + SCFGR));
	}
}
#endif // CFG_CRYPTO_MP_HW
