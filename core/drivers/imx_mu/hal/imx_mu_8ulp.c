// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */
#include <drivers/imx_mu.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <local.h>
#include <mm/core_memprot.h>

#define MU_TCR		  0x120
#define MU_TSR		  0x124
#define MU_RCR		  0x128
#define MU_RSR		  0x12C
#define MU_TRn(n)	  (0x200 + 0x4 * (n))
#define MU_RRn(n)	  (0x280 + 0x4 * (n))
#define MU_TSR_TEn(n)	  SHIFT_U32(0x1, (n))
#define MU_RSR_RFn(n)	  SHIFT_U32(0x1, (n))
#define MU_MAX_RX_CHANNEL 4
#define MU_MAX_TX_CHANNEL 8

static TEE_Result mu_wait_for(vaddr_t addr, uint32_t mask)
{
	uint64_t timeout = timeout_init_us(1000);

	while (!(io_read32(addr) & mask)) {
		if (timeout_elapsed(timeout))
			return TEE_ERROR_BUSY;
	}

	return TEE_SUCCESS;
}

unsigned int imx_mu_hal_get_rx_channel(void)
{
	return MU_MAX_RX_CHANNEL;
}

unsigned int imx_mu_hal_get_tx_channel(void)
{
	return MU_MAX_TX_CHANNEL;
}

TEE_Result imx_mu_hal_send(vaddr_t base, unsigned int index, uint32_t msg)
{
	assert(index < MU_MAX_TX_CHANNEL);

	/* Wait TX register to be empty */
	if (mu_wait_for(base + MU_TSR, MU_TSR_TEn(index)))
		return TEE_ERROR_BUSY;

	io_write32(base + MU_TRn(index), msg);

	return TEE_SUCCESS;
}

TEE_Result imx_mu_hal_receive(vaddr_t base, unsigned int index, uint32_t *msg)
{
	assert(index < MU_MAX_RX_CHANNEL);

	/* Wait RX register to be full */
	if (mu_wait_for(base + MU_RSR, MU_RSR_RFn(index)))
		return TEE_ERROR_BUSY;

	*msg = io_read32(base + MU_RRn(index));

	return TEE_SUCCESS;
}

void imx_mu_hal_init(vaddr_t base)
{
	/* Reset status registers */
	io_write32(base + MU_TCR, 0x0);
	io_write32(base + MU_RCR, 0x0);
}
