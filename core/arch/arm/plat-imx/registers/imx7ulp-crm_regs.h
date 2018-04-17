/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017 NXP
 *
 */

#ifndef __MX7ULP_CCM_REGS_H__
#define __MX7ULP_CCM_REGS_H__

#define PCC_CGC_BIT_SHIFT 30

#define PCC_ENABLE_CLOCK (1 << PCC_CGC_BIT_SHIFT)
#define PCC_DISABLE_CLOCK (0 << PCC_CGC_BIT_SHIFT)

#define PCC_CAAM 0x90

#endif
