/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2018 NXP
 *
 */

#ifndef __IMX_WDOG_H
#define __IMX_WDOG_H

/* i.MX6/7D */
#define WDT_WCR		0x00
#define WDT_WCR_WDA	BIT(5)
#define WDT_WCR_SRS	BIT(4)
#define WDT_WCR_WRE	BIT(3)
#define WDT_WCR_WDE	BIT(2)
#define WDT_WCR_WDZST	BIT(0)

#define WDT_WSR		0x02
#define WDT_SEQ1	0x5555
#define WDT_SEQ2	0xAAAA

/* 7ULP */
#define WDOG_CNT	0x4
#define WDOG_TOVAL	0x8

#define REFRESH_SEQ0	0xA602
#define REFRESH_SEQ1	0xB480
#define REFRESH		((REFRESH_SEQ1 << 16) | (REFRESH_SEQ0))

#define UNLOCK_SEQ0	0xC520
#define UNLOCK_SEQ1	0xD928
#define UNLOCK		((UNLOCK_SEQ1 << 16) | (UNLOCK_SEQ0))

#define WDOG_CS			0x0
#define WDOG_CS_CMD32EN		BIT(13)
#define WDOG_CS_ULK		BIT(11)
#define WDOG_CS_RCS		BIT(10)
#define WDOG_CS_EN		BIT(7)
#define WDOG_CS_UPDATE		BIT(5)

/* Exposed for psci reset */
void imx_wdog_restart(void);
#endif
