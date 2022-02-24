// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */
#include <assert.h>
#include <drivers/imx_mu.h>
#include <kernel/mutex.h>
#include <local.h>
#include <string.h>
#include <trace.h>

static struct mutex imx_mu_mutex = MUTEX_INITIALIZER;

__weak void imx_mu_hal_init(vaddr_t base __unused)
{
}

__weak TEE_Result imx_mu_hal_send(vaddr_t base __unused,
				  unsigned int index __unused,
				  uint32_t msg __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

__weak TEE_Result imx_mu_hal_receive(vaddr_t base __unused,
				     unsigned int index __unused,
				     uint32_t *msg __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

/*
 * Receive a message via the MU
 *
 * @base: virtual base address of the MU controller
 * @[out]msg: message received
 */
static TEE_Result imx_mu_receive_msg(vaddr_t base, struct imx_mu_msg *msg)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned int count = 0;
	uint32_t response = 0;
	unsigned int nb_channel = 0;

	assert(base && msg);

	res = imx_mu_hal_receive(base, 0, &response);
	if (res)
		return res;

	memcpy(&msg->header, &response, sizeof(response));

	/* Check the size of the message to receive */
	if (msg->header.size > IMX_MU_MSG_SIZE) {
		EMSG("Size of the message is > than IMX_MU_MSG_SIZE");
		return TEE_ERROR_BAD_FORMAT;
	}

	nb_channel = imx_mu_hal_get_rx_channel();

	for (count = 1; count < msg->header.size; count++) {
		res = imx_mu_hal_receive(base, count % nb_channel,
					 &msg->data.u32[count - 1]);
		if (res)
			return res;
	}

	return TEE_SUCCESS;
}

/*
 * Send a message via the MU
 *
 * @base: virtual base address of the MU controller
 * @[in]msg: message to send
 */
static TEE_Result imx_mu_send_msg(vaddr_t base, struct imx_mu_msg *msg)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned int count = 0;
	unsigned int nb_channel = 0;

	assert(base && msg);

	if (msg->header.size > IMX_MU_MSG_SIZE) {
		EMSG("msg->size is > than IMX_MU_MSG_SIZE");
		return TEE_ERROR_BAD_FORMAT;
	}

	res = imx_mu_hal_send(base, 0, *(uint32_t *)msg);
	if (res)
		return res;

	nb_channel = imx_mu_hal_get_tx_channel();

	for (count = 1; count < msg->header.size; count++) {
		res = imx_mu_hal_send(base, count % nb_channel,
				      msg->data.u32[count - 1]);
		if (res)
			return res;
	}

	return TEE_SUCCESS;
}

void imx_mu_init(vaddr_t base)
{
	if (!base) {
		EMSG("Bad MU base address");
		return;
	}

	mutex_lock(&imx_mu_mutex);
	imx_mu_hal_init(base);
	mutex_unlock(&imx_mu_mutex);
}

TEE_Result imx_mu_call(vaddr_t base, struct imx_mu_msg *msg,
		       bool wait_for_answer)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!base || !msg)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&imx_mu_mutex);

	res = imx_mu_send_msg(base, msg);
	if (res == TEE_SUCCESS && wait_for_answer)
		res = imx_mu_receive_msg(base, msg);

	mutex_unlock(&imx_mu_mutex);

	return res;
}
