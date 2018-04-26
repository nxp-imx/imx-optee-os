/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2017-2018 NXP
 *
 * @file    version_regs.h
 *
 * @brief   Version Registers.\n
 */
#ifndef __VERSION_REGS_H__
#define __VERSION_REGS_H__

/* Global includes */
#include <util.h>

/* Compile Time Parameters */
#define CTPR_MS						0x0FA8
#define BM_CTPR_MS_RNG_I			SHIFT_U32(0x7, 8)
#define GET_CTPR_MS_RNG_I(val)		((val & BM_CTPR_MS_RNG_I) >> 8)

/* CHA Version ID */
#define CHAVID_LS					0x0FEC
#define BM_CHAVID_LS_RNGVID			SHIFT_U32(0xF, 16)
#define GET_CHAVID_LS_RNGVID(val)	((val & BM_CHAVID_LS_RNGVID) >> 16)

/* CHA Number */
#define CHANUM_MS					0x0FF0
#define BM_CHANUM_MS_JRNUM			SHIFT_U32(0xF, 28)
#define GET_CHANUM_MS_JRNUM(val)	((val & BM_CHANUM_MS_JRNUM) >> 28)

#endif /* __VERSION_REGS_H__ */

