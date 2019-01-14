/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019 NXP
 *
 */
#ifndef __OCOTP_REGS_H__
#define __OCOTP_REGS_H__

#ifdef CFG_MX7ULP
#define OCOTP_WAFER_NO	0x04D0
#define OCOTP_DIE_ID	0x04E0
#else
#define OCOTP_DIE_ID	0x0420
#endif

#endif /* __OCOTP_REGS_H__ */
