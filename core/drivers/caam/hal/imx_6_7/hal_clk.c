// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    hal_clk.c
 *
 * @brief   CAAM Clock functions.
 */

/* Global includes */
#include <io.h>
#include <mm/core_memprot.h>

/* Platform includes */
#include <imx.h>

/* Hal includes */
#include "hal_clk.h"

/**
 * @brief  Enable/disable the CAAM clocks
 *
 * @param[in] enable  Enable the clock if true
 */
void hal_clk_enable(bool enable)
{
#if !defined(CFG_MX7ULP)
	vaddr_t  ccm_base = (vaddr_t)phys_to_virt(CCM_BASE, MEM_AREA_IO_SEC);
#else
	vaddr_t  pcc2_base = (vaddr_t)phys_to_virt(PCC2_BASE, MEM_AREA_IO_SEC);
#endif

#if defined(CFG_MX6) || defined(CFG_MX6UL)
	uint32_t reg;
	uint32_t mask;

	reg = read32(ccm_base + CCM_CCGR0);

	mask = (BM_CCM_CCGR0_CAAM_WRAPPER_IPG  |
			BM_CCM_CCGR0_CAAM_WRAPPER_ACLK |
			BM_CCM_CCGR0_CAAM_SECURE_MEM);

	if (enable)
		reg |= mask;
	else
		reg &= ~mask;

	write32(reg, (ccm_base + CCM_CCGR0));

	if (!soc_is_imx6ul()) {
		/* EMI slow clk */
		reg  = read32(ccm_base + CCM_CCGR6);
		mask = BM_CCM_CCGR6_EMI_SLOW;

		if (enable)
			reg |= mask;
		else
			reg &= ~mask;

		write32(reg, (ccm_base + CCM_CCGR6));
	}

#elif defined(CFG_MX7)
	if (enable) {
		write32(CCM_CCGRx_ALWAYS_ON(0),
			ccm_base + CCM_CCGRx_SET(CCM_CLOCK_DOMAIN_CAAM));
	} else {
		write32(CCM_CCGRx_ALWAYS_ON(0),
			ccm_base + CCM_CCGRx_CLR(CCM_CLOCK_DOMAIN_CAAM));
	}
#elif defined(CFG_MX7ULP)
	if (enable)
		write32(PCC_ENABLE_CLOCK, pcc2_base + PCC_CAAM);
	else
		write32(PCC_DISABLE_CLOCK, pcc2_base + PCC_CAAM);
#endif
}

