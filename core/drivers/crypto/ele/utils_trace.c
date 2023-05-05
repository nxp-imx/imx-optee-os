// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2023 NXP
 */
#include <assert.h>
#include <drivers/imx_mu.h>
#include <ele.h>
#include <stdint.h>
#include <utils_trace.h>

struct response_code {
	uint8_t status;
	uint8_t rating;
	uint16_t rating_extension;
} __packed;

/*
 * Extract response codes from the given word
 *
 * @word 32 bits word MU response
 */
static struct response_code get_response_code(uint32_t word)
{
	struct response_code rsp = {
		.rating_extension = (word & GENMASK_32(31, 16)) >> 16,
		.rating = (word & GENMASK_32(15, 8)) >> 8,
		.status = (word & GENMASK_32(7, 0)) >> 0,
	};

	return rsp;
}

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
