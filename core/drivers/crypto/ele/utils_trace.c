// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2023, 2026 NXP
 */
#include <assert.h>
#include <drivers/ele/ele.h>
#include <drivers/imx_mu.h>
#include <stdint.h>
#include <utils_trace.h>

void ele_trace_print_msg(struct imx_mu_msg msg)
{
	size_t dump_size = 0;
	unsigned int i = 0;

	if (msg.header.tag == ELE_RESPONSE_TAG)
		DMSG("Response:");
	else
		DMSG("Request:");

	DMSG("Header version %#" PRIx8 " size %#" PRIx8 " tag %#" PRIx8
	     " command %#" PRIx8,
	     msg.header.version, msg.header.size, msg.header.tag,
	     msg.header.command);

	dump_size = (size_t)msg.header.size - 1;
	for (i = 0; i < dump_size; i++)
		DMSG("\t[%u] %#010" PRIx32, i, msg.data.u32[i]);
}
