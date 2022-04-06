// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */
#include <drivers/imx_mu.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>

/* Definitions for communication protocol */
#define ELE_VERSION	    0x07
#define ELE_COMMAND_SUCCEED 0x00
#define ELE_COMMAND_FAILED  0x29
#define ELE_REQUEST_TAG	    0x17
#define ELE_RESPONSE_TAG    0xe1

/* Definitions for get_device_id API */
#define ELE_CMD_READ_FUSE	    0x97
#define ELE_CMD_READ_FUSE_DEVICE_ID 0x01
#define ELE_CMD_SUCCESS		    0xD6

#define UID_SIZE (4 * sizeof(uint32_t))

register_phys_mem_pgdir(MEM_AREA_IO_SEC, MU_BASE, MU_SIZE);

struct response_code {
	uint8_t status;
	uint8_t rating;
	uint16_t rating_extension;
} __packed;

static vaddr_t imx_ele_va;

static void print_rsp_code(const struct response_code rsp __maybe_unused)
{
	IMSG("Response status 0x%" PRIx8 ", rating 0x%" PRIx8 " (ext 0x%" PRIx16
	     ")",
	     rsp.status, rsp.rating, rsp.rating_extension);
}

static void print_msg_header(const struct imx_mu_msg_header hdr __maybe_unused)
{
	IMSG("Header vers 0x%" PRIx8 ", size %" PRId8 ", tag 0x%" PRIx8
	     ", cmd 0x%" PRIx8,
	     hdr.version, hdr.size, hdr.tag, hdr.command);
}

static void dump_message(const struct imx_mu_msg *msg __maybe_unused)
{
	size_t i = 0;
	size_t size = msg->header.size;
	uint32_t *data __maybe_unused = (uint32_t *)msg;

	DMSG("Dump of message %p(%" PRIu64 ")", data, size);
	for (i = 0; i < size; i++)
		DMSG("word %" PRIu64 ": %" PRIx32, i, data[i]);
}

static TEE_Result imx_ele_init(void)
{
	vaddr_t va = 0;

	va = core_mmu_get_va(MU_BASE, MEM_AREA_IO_SEC, MU_SIZE);
	if (!va) {
		EMSG("Failed to map ele mu address");
		return TEE_ERROR_GENERIC;
	}

	imx_mu_init(va);

	imx_ele_va = va;

	return TEE_SUCCESS;
}

static struct response_code get_response_code(uint32_t word)
{
	struct response_code rsp = {};

	rsp.rating_extension = (word & GENMASK_32(31, 16)) >> 16;
	rsp.rating = (word & GENMASK_32(15, 8)) >> 8;
	rsp.status = (word & GENMASK_32(7, 0)) >> 0;

	return rsp;
}

static TEE_Result imx_ele_call(struct imx_mu_msg *msg)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct response_code rsp = {};

	if (msg->header.tag != ELE_REQUEST_TAG) {
		EMSG("Request has invalid tag: %" PRIx8 " instead of %" PRIx8,
		     msg->header.tag, ELE_REQUEST_TAG);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = imx_mu_call(imx_ele_va, msg, true);
	if (res) {
		EMSG("Failed to transmit message: %" PRIx32, res);
		print_msg_header(msg->header);
		dump_message(msg);
		return res;
	}

	rsp = get_response_code(msg->data.u32[0]);

	if (msg->header.tag != ELE_RESPONSE_TAG) {
		EMSG("Response has invalid tag: %" PRIx8 " instead of %" PRIx8,
		     msg->header.tag, ELE_RESPONSE_TAG);
		print_msg_header(msg->header);
		return TEE_ERROR_GENERIC;
	}

	if (rsp.status == ELE_COMMAND_FAILED) {
		EMSG("Command has failed");
		print_rsp_code(rsp);
		return TEE_ERROR_GENERIC;
	}

	/* The rating can be different in success and failing case */
	if (rsp.rating != 0) {
		EMSG("Command has invalid rating: %" PRIx8, rsp.rating);
		print_rsp_code(rsp);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

static TEE_Result imx_ele_get_device_id(uint32_t uid[])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct imx_mu_msg msg = {
		.header.version = 0x06,
		.header.size = 2,
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_READ_FUSE,
		.data.u32[0] = ELE_CMD_READ_FUSE_DEVICE_ID,
	};

	res = imx_mu_call(imx_ele_va, &msg, true);
	if (res)
		return res;

	if (msg.header.command == ELE_CMD_READ_FUSE && msg.header.size == 0x7 &&
	    msg.data.u32[0] == ELE_CMD_SUCCESS) {
		uid[0] = msg.data.u32[1];
		uid[1] = msg.data.u32[2];
		uid[2] = msg.data.u32[3];
		uid[3] = msg.data.u32[4];

		return TEE_SUCCESS;
	}

	return TEE_ERROR_COMMUNICATION;
}

int tee_otp_get_die_id(uint8_t *buffer, size_t len)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t uid[UID_SIZE / sizeof(uint32_t)] = {};

	res = imx_ele_get_device_id(uid);
	if (res) {
		EMSG("Error while getting die ID");
		return -1;
	}

	memcpy(buffer, uid, MIN(UID_SIZE, len));

	return 0;
}

static TEE_Result imx_ele_mu_init(void)
{
	return imx_ele_init();
}

service_init(imx_ele_mu_init);
