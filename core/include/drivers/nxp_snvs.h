/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020 Pengutronix
 * Rouven Czerwinski <entwicklung@pengutronix.de>
 * Copyright 2021 NXP
 */
#ifndef __DRIVERS_NXP_SNVS_H
#define __DRIVERS_NXP_SNVS_H

#include <tee_api_types.h>

/*
 * SNVS HP Registers
 */
#define SNVS_HPLR	    0x00
#define BM_SNVS_HPLR_MKS_SL BIT32(9)

#define SNVS_HPCOMR		0x04
#define BM_SNVS_HPCOMR_MKS_EN	BIT32(13)
#define BM_SNVS_HPCOMR_NPSWA_EN BIT32(31)

#define SNVS_HPSR		 0x14
#define BM_SNVS_HPSR_OTPMK_ZERO	 BIT32(27)
#define BM_SNVS_HPSR_OTPMK_SYND	 SHIFT_U32(0x1FF, 16)
#define BM_SNVS_HPSR_SYS_SEC_CFG SHIFT_U32(0x7, 12)
#define SNVS_HPSR_CLOSED	 BIT32(13)
#define SNVS_HPSR_BAD		 BIT32(14)

/*
 * SNVS LP Registers
 */
#define SNVS_LPLR	    0x34
#define BM_SNVS_LPLR_MKS_HL BIT32(9)

#define SNVS_LPCR	      0x38
#define BM_SNVS_LPCR_TOP      BIT32(6)
#define BM_SNVS_LPCR_DP_EN    BIT32(5)
#define BM_SNVS_LPCR_SRTC_ENV BIT32(0)

#define SNVS_LPMKCR		0x3C
#define BM_SNVS_LP_MKCR_MKS_SEL SHIFT_U32(0x3, 0)

#define SNVS_LPSVCR    0x40
#define SNVS_LPTGFCR   0x44
#define SNVS_LPTDCR    0x48
#define SNVS_LPSR      0x4C
#define SNVS_LPSRTCMR  0x50
#define SNVS_LPSRTCLR  0x54
#define SNVS_LPTAR     0x58
#define SNVS_LPSMCMR   0x5C
#define SNVS_LPSMCLR   0x60
#define SNVS_LPPGDR    0x64
#define SNVS_LPGPR0_A  0x68
#define SNVS_LPZMKR0   0x6C
#define SNVS_LPCGR0_30 0x90
#define SNVS_LPCGR0_31 0x94
#define SNVS_LPCGR0_32 0x98
#define SNVS_LPCGR0_33 0x9C
#define SNVS_LPTDC2R   0xA0
#define SNVS_LPTDSR    0xA4
#define SNVS_LPTGF1CR  0xA8
#define SNVS_LPTGF2CR  0xAC
#define SNVS_LPAT1CR   0xC0
#define SNVS_LPAT2CR   0xC4
#define SNVS_LPAT3CR   0xC8
#define SNVS_LPAT4CR   0xCC
#define SNVS_LPAT5CR   0xD0
#define SNVS_LPATCTLR  0xE0
#define SNVS_LPATCLKR  0xE4
#define SNVS_LPATRC1R  0xE8
#define SNVS_LPATRC2R  0xEC

#define HPSR_SSM_ST_MASK  GENMASK_32(11, 8)
#define HPSR_SSM_ST_SHIFT 8

#define SNVS_HPSR_SYS_SECURITY_BAD    BIT(14)
#define SNVS_HPSR_SYS_SECURITY_CLOSED BIT(13)
#define SNVS_HPSR_SYS_SECURITY_OPEN   BIT(12)

enum snvs_ssm_mode {
	SNVS_SSM_MODE_INIT,
	SNVS_SSM_MODE_HARD_FAIL,
	SNVS_SSM_MODE_SOFT_FAIL = 3,
	SNVS_SSM_MODE_INIT_INTERMEDIATE = 8,
	SNVS_SSM_MODE_CHECK,
	SNVS_SSM_MODE_NON_SECURE = 11,
	SNVS_SSM_MODE_TRUSTED = 13,
	SNVS_SSM_MODE_SECURE,
};

enum snvs_security_cfg {
	SNVS_SECURITY_CFG_FAB,
	SNVS_SECURITY_CFG_OPEN,
	SNVS_SECURITY_CFG_CLOSED,
	SNVS_SECURITY_CFG_FIELD_RETURN,
};

enum snvs_ssm_mode snvs_get_ssm_mode(void);

enum snvs_security_cfg snvs_get_security_cfg(void);

/**
 * @brief   Set the OTPMK Key as Master key.
 *          If device is a closed device and OTMPK can not be set
 *          system stop in panic.
 *          If device is NOT a closed device and OTPMK can not be
 *          set, continue anyway.
 */
void snvs_set_master_otpmk(void);

/**
 * @brief   Set the NPSWA_EN bit.
 *          Allow non-proviledge software to access all SNVS registers
 *          If device is in closed mode, the HAB does not set this bit.
 */
void snvs_set_npswa_en(void);

/**
 * @brief   Indication on the security state of the hardware.
 *          Indicate if the device is in a state call closed meaning it can
 *          only boot signed code.
 */
bool snvs_is_device_closed(void);
#endif /* __DRIVERS_NXP_SNVS_H */
