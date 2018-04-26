/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    jr_regs.h
 *
 * @brief   Job Ring Registers.\n
 */
#ifndef __JR_REGS_H__
#define __JR_REGS_H__

/* Global includes */
#include <util.h>

/* Job Ring Block Register Size */
#define JRx_BLOCK_SIZE		0x1000
#define JRx_IDX(offset)		((offset - JRx_BLOCK_SIZE) / JRx_BLOCK_SIZE)

/*
 * Input Ring
 */
/* Base Address */
#define JRx_IRBAR					0x0000
/* Size */
#define JRx_IRSR					0x000C
/* Slots Available */
#define JRx_IRSAR					0x0014
/* Jobs Added */
#define JRx_IRJAR					0x001C

/*
 * Output Ring
 */
/* Base Address */
#define JRx_ORBAR					0x0020
/* Size */
#define JRx_ORSR					0x002C
/* Jobs Removed */
#define JRx_ORJRR					0x0034
/* Slots Full */
#define JRx_ORSFR					0x003C

/* Interrupt Status */
#define JRx_JRINTR					0x004C
#define BM_JRx_JRINTR_HALT			SHIFT_U32(0x3, 2)
#define JRINTR_HALT_ONGOING			SHIFT_U32(0x1, 2)
#define JRINTR_HALT_DONE			SHIFT_U32(0x2, 2)
#define JRx_JRINTR_JRI				BIT32(0)

/* Configuration */
#define JRx_JRCFGR_LS				0x0054
#define JRx_JRCFGR_LS_ICTT(val)		SHIFT_U32((val & 0xFFFF), 16)
#define JRx_JRCFGR_LS_ICDCT(val)	SHIFT_U32((val & 0xFF), 8)
#define JRx_JRCFGR_LS_ICEN			BIT32(1)
#define JRx_JRCFGR_LS_IMSK			BIT32(0)

/* Command */
#define JRx_JRCR					0x006C
#define JRx_JRCR_RESET				BIT32(0)

#endif /* __JR_REGS_H__ */
