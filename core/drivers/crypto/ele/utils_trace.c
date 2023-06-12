// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2023 NXP
 */
#include <assert.h>
#include <drivers/imx_mu.h>
#include <ele.h>
#include <stdint.h>
#include <utils_trace.h>

void ele_trace_print_msg(struct imx_mu_msg msg)
{
	unsigned int i = 0;

	DMSG("Header version %#" PRIx8 " size %#" PRIx8 " tag %#" PRIx8
	     " command %#" PRIx8,
	     msg.header.version, msg.header.size, msg.header.tag,
	     msg.header.command);

	/*
	 * If the given message is response message, the first 4 bytes of the
	 * message are status codes.
	 */
	if (msg.header.tag == ELE_RESPONSE_TAG) {
		struct response_code rsp __maybe_unused =
			get_response_code(msg.data.u32[0]);

		DMSG("Response status: %#" PRIx8 " rating: %#" PRIx8
		     " rating extension %#" PRIx8,
		     rsp.status, rsp.rating, rsp.rating_extension);
	} else {
		DMSG("Request:");
	}

	for (i = 0; i < msg.header.size; i++)
		DMSG("\t[%u] %#010" PRIx32, i, msg.data.u32[i]);
}
