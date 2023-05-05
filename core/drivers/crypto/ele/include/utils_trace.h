/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2023 NXP
 */
#ifndef __UTILS_TRACE_H_
#define __UTILS_TRACE_H_

#include <drivers/imx_mu.h>
#include <stddef.h>

/*
 * Dump ELE request/response message
 *
 * @msg ELE MU message
 */
void ele_trace_print_msg(struct imx_mu_msg msg);

#endif /* __UTILS_TRACE_H_ */
