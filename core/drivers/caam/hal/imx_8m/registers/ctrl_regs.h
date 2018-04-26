/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2017-2018 NXP
 *
 * @file    ctrl_regs.h
 *
 * @brief   Control Registers.
 */
#ifndef __CTRL_REGS_H__
#define __CTRL_REGS_H__

/* Global includes */
#include <util.h>

/* Master Configuration */
#define MCFGR					0x0004
#define MCFGR_WDE				BIT32(30)

/* Job Ring x MID */
#define JRxDID_SIZE				0x8
#define JR0DID_MS				0x0010
#define JR0DID_LS				0x0014
#define JRxDID_MS(idx)			(JR0DID_MS + (idx * JRxDID_SIZE))
#define JRxDID_LS(idx)			(JR0DID_LS + (idx * JRxDID_SIZE))

#define JRxDID_MS_LDID				BIT32(31)
#define JRxDID_MS_PRIM_ICID(val)	SHIFT_U32((val & 0x3FF), 19)
#define JRxDID_MS_LAMTD				BIT32(17)
#define JRxDID_MS_AMTD				BIT32(16)
#define JRxDID_MS_TZ_OWN			BIT32(15)
#define JRxDID_MS_PRIM_TZ			BIT32(4)
#define JRxDID_MS_PRIM_DID(val)		SHIFT_U32((val & 0xF), 0)

#endif /* __CTRL_REGS_H__ */

