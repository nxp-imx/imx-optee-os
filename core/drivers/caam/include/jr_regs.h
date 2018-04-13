/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018 NXP
 *
 */
#ifndef __JR_REGS_H__
#define __JR_REGS_H__

/* Job Ring Block Register Size */
#define JRx_BLOCK_SIZE	(0x1000)

/*
 * Input Ring
 */
/* Base Address */
#define JRx_IRBAR		(0x0000)
/* Size */
#define JRx_IRSR		(0x000C)
/* Slots Available */
#define JRx_IRSAR		(0x0014)
/* Jobs Added */
#define JRx_IRJAR		(0x001C)

/*
 * Output Ring
 */
/* Base Address */
#define JRx_ORBAR		(0x0020)
/* Size */
#define JRx_ORSR		(0x002C)
/* Jobs Removed */
#define JRx_ORJRR		(0x0034)
/* Slots Full */
#define JRx_ORSFR		(0x003C)

/* Interrupt Status */
#define JRx_JRINTR		(0x004C)
#define BS_JRx_JRINTR_HALT			(2)
#define BM_JRx_JRINTR_HALT			(0x3 << BS_JRx_JRINTR_HALT)
#define JRINTR_HALT_ONGOING	(0x1 << BS_JRx_JRINTR_HALT)
#define JRINTR_HALT_DONE	(0x2 << BS_JRx_JRINTR_HALT)
#define BS_JRx_JRINTR_JRI			(0)
#define BM_JRx_JRINTR_JRI			(0x1 << BS_JRx_JRINTR_JRI)

/* Configuration */
#define JRx_JRCFGR_LS	(0x0054)

#define BS_JRx_JRCFGR_LS_ICTT			(16)
#define BM_JRx_JRCFGR_LS_ICTT			(0xFFFF << BS_JRx_JRCFGR_LS_ICTT)
#define BS_JRx_JRCFGR_LS_ICDCT			(8)
#define BM_JRx_JRCFGR_LS_ICDCT			(0xFF << BS_JRx_JRCFGR_LS_ICDCT)
#define BS_JRx_JRCFGR_LS_ICEN			(1)
#define BM_JRx_JRCFGR_LS_ICEN			(0x1 << BS_JRx_JRCFGR_LS_ICEN)
#define BS_JRx_JRCFGR_LS_IMSK			(0)
#define BM_JRx_JRCFGR_LS_IMSK			(0x1 << BS_JRx_JRCFGR_LS_IMSK)

/* Input Ring Read Index */
#define JRx_IRRIR		(0x005C)
/* Output Ring Write Index */
#define JRx_ORWIR		(0x0064)
/* Command */
#define JRx_JRCR		(0x006C)
#define BS_JRx_JRCR_RESET	(0)
#define BM_JRx_JRCR_RESET	(0x1 << BS_JRx_JRCR_RESET)

#endif /* __JR_REGS_H__ */
