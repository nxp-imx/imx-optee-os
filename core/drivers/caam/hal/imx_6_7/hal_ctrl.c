// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    hal_ctrl.c
 *
 * @brief   CAAM Controller Hardware Abstration Layer.\n
 *          Implementation of primitives to access HW
 */

/* Global includes */
#include <io.h>
#include <trace.h>

/* Local includes */
#include "caam_pwr.h"

/* Hal includes */
#include "hal_ctrl.h"

/* Register includes */
#include "ctrl_regs.h"

/*
 * List of control registers to save/restore
 */
const struct reglist ctrl_backup[] = {
	{MCFGR, 1, 0, 0},
#ifdef CFG_CRYPTO_MP_HW
	{SCFGR, 1, BM_SCFGR_MPMRL | BM_SCFGR_MPCURVE, 0},
#else
	/* For device not supporting MP (bits not defined) */
	{SCFGR, 1, 0, 0},
#endif
};

/**
 * @brief   Initializes the CAAM HW Controller
 *
 * @param[in] baseaddr  Controller base address
 */
void hal_ctrl_init(vaddr_t baseaddr)
{
	/*
	 * Enable DECO watchdogs
	 */
	io_mask32(baseaddr + MCFGR, MCFGR_WDE, MCFGR_WDE);

	/*
	 * ERRATA:  mx6 devices have an issue wherein AXI bus transactions
	 * may not occur in the correct order. This isn't a problem running
	 * single descriptors, but can be if running multiple concurrent
	 * descriptors. Reworking the driver to throttle to single requests
	 * is impractical, thus the workaround is to limit the AXI pipeline
	 * to a depth of 1 (from it's default of 4) to preclude this situation
	 * from occurring.
	 *
	 * mx7 devices, this bit has no effect.
	 */
	io_mask32(baseaddr + MCFGR, MCFGR_AXIPIPE(1), BM_MCFGR_AXIPIPE);

	caam_pwr_add_backup(baseaddr, ctrl_backup, ARRAY_SIZE(ctrl_backup));
}

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
 * @retval true       Success
 * @retval false      Failure
 */
bool hal_ctrl_is_mpcurve(vaddr_t ctrl_addr __maybe_unused)
{
#ifdef CHECK_MPPRIVK
	uint32_t val_scfgr;

	/* get the SCFGR content */
	val_scfgr = read32(ctrl_addr + SCFGR);
	DMSG("val_scfgr = 0x%x", val_scfgr);

	/**
	 * check if the MPCURVE field value is 0
	 * which means that the MP Private key has not been generated
	 */
	if (val_scfgr & BM_SCFGR_MPCURVE)
		return true;

#endif

	/*
	 * always return false to generate private key
	 * even if the MPCURVE field is not clear
	 */
	return false;
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
		val = read32(ctrl_addr + MPMR + i);
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
void hal_ctrl_fill_mpmr(vaddr_t ctrl_addr, struct imxcrypt_buf *msg_mpmr)
{
	int i;
	vaddr_t reg = ctrl_addr + MPMR;
	bool is_filled = false;
	uint32_t val = 0;
	uint16_t min, remain;

	/* check if the MPMR is filled */
	if (read32(ctrl_addr + SCFGR) & BM_SCFGR_MPMRL)
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
			write32(val, reg);
		}

		if (remain) {
			val = 0;
			/*
			 * fill the MPMR with the 8 bits values
			 * until the end of the message length
			 */
			for (i = 0; i < remain; i++)
				val |= (msg_mpmr->data[i] << (i*8));
			write32(val, reg);
			reg += 4;
		}
		/* fill the remain of the MPMR with 0 */
		remain = MPMR_NB_REG - ROUNDUP(msg_mpmr->length, 4);
		for (i = 0; i < (remain / 4); i++, reg += 4)
			write32(0x0, reg);

		/*
		 * locks the MPMR for writing
		 * remains locked until the next power-on session
		 * set the MPMRL bit of SCFRG to 1
		 */
		write32((read32(ctrl_addr + SCFGR) | BM_SCFGR_MPMRL),
			ctrl_addr + SCFGR);

		DMSG("val_scfgr = 0x%x", read32(ctrl_addr + SCFGR));
	}
}
#endif // CFG_CRYPTO_MP_HW
