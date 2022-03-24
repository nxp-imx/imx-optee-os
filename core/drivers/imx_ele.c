// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */
#include <drivers/imx_mu.h>
#include <initcall.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/panic.h>
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

/* Definitions for ELE API */
#define ELE_CMD_SESSION_OPEN  0x10
#define ELE_CMD_SESSION_CLOSE 0x11

#define ELE_CMD_RNG_OPEN  0x20
#define ELE_CMD_RNG_CLOSE 0x21
#define ELE_CMD_RNG_GET	  0x22

#define ELE_MU_ID  0x2
#define ELE_MU_IRQ 0x0
#define ELE_MU_DID 0x7

#define CRC_TO_COMPUTE 0xdeadbeef

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

static TEE_Result open_session(uint32_t *session_handle)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct open_session_msg_cmd {
		uint8_t mu_id;
		uint8_t interrupt_num;
		uint8_t tz;
		uint8_t did;
		uint8_t priority;
		uint8_t op_mode;
		uint16_t reserved;
	} __packed open_cmd = {
		.mu_id = ELE_MU_ID,
		.interrupt_num = ELE_MU_IRQ,
		.tz = 0,
		.did = ELE_MU_DID,
		.priority = 0,
		.op_mode = 0,
		.reserved = 0,
	};

	struct open_session_msg_rsp {
		uint32_t rsp_code;
		uint32_t session_handle;
	} *open_rsp = NULL;

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION,
		.header.size = 1 + (sizeof(open_cmd) / sizeof(uint32_t)),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_SESSION_OPEN,
	};

	memcpy(msg.data.u8, &open_cmd, sizeof(open_cmd));

	res = imx_ele_call(&msg);
	if (res) {
		EMSG("Failed to get open session");
		return res;
	}

	open_rsp = (void *)msg.data.u32;

	if (session_handle)
		*session_handle = open_rsp->session_handle;

	return TEE_SUCCESS;
}

static TEE_Result close_session(uint32_t session_handle)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct close_session_msg_cmd {
		uint32_t session_handle;
	} close_cmd = {
		.session_handle = session_handle,
	};

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION,
		.header.size = 1 + (sizeof(close_cmd) / sizeof(uint32_t)),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_SESSION_CLOSE,
	};

	memcpy(msg.data.u8, &close_cmd, sizeof(close_cmd));

	res = imx_ele_call(&msg);
	if (res) {
		EMSG("Failed to get close session");
		return res;
	}

	return TEE_SUCCESS;
}

/*
 * The CRC for the message is computed xor-ing all the words of the message:
 * the header and all the words except the word storing the crc
 */
static uint32_t compute_crc(const struct imx_mu_msg *msg)
{
	uint32_t crc = 0;
	size_t i = 0;
	/* The CRC is included in the size */
	size_t size = msg->header.size - 1;
	uint32_t *payload = (uint32_t *)msg;

	for (i = 0; i < size; i++)
		crc ^= payload[i];

	return crc;
}

/*
 * The CRC is the last word of the message
 */
static void update_crc(struct imx_mu_msg *msg)
{
	msg->data.u32[msg->header.size - 2] = compute_crc(msg);
}

static TEE_Result open_service_rng(uint32_t session_handle, paddr_t buffer,
				   uint32_t *rng_handle)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rng_open_msg_cmd {
		uint32_t session_handle;
		uint32_t msbi;
		uint32_t msbo;
		uint8_t flags;
		uint8_t rsv[3];
		uint32_t crc;
	} __packed open_rng_cmd = {
		.session_handle = session_handle,
		.msbi = 0,
		.msbo = ((uint64_t)buffer) >> 32,
		.flags = 0,
		.rsv = {},
		.crc = CRC_TO_COMPUTE,
	};

	struct rng_open_msg_rsp {
		uint32_t rsp_code;
		uint32_t rng_handle;
	} *open_rng_rsp = NULL;

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION,
		.header.size = 1 + (sizeof(open_rng_cmd) / sizeof(uint32_t)),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_RNG_OPEN,
	};

	memcpy(msg.data.u8, &open_rng_cmd, sizeof(open_rng_cmd));
	update_crc(&msg);

	res = imx_ele_call(&msg);
	if (res) {
		EMSG("Failed to get open rng session");
		return res;
	}

	open_rng_rsp = (void *)msg.data.u32;

	if (rng_handle)
		*rng_handle = open_rng_rsp->rng_handle;

	return TEE_SUCCESS;
}

static TEE_Result close_service_rng(uint32_t rng_handle)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rng_close_msg_cmd {
		uint32_t rng_handle;
	} close_rng_cmd = {
		.rng_handle = rng_handle,
	};

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION,
		.header.size = 1 + (sizeof(close_rng_cmd) / sizeof(uint32_t)),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_RNG_CLOSE,
	};

	memcpy(msg.data.u8, &close_rng_cmd, sizeof(close_rng_cmd));

	res = imx_ele_call(&msg);
	if (res) {
		EMSG("Failed to get close rng session");
		return res;
	}

	return TEE_SUCCESS;
}

static TEE_Result service_rng_get_random(uint32_t rng_handle, paddr_t buffer,
					 uint32_t buf_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct rng_get_rnd_msg_cmd {
		uint32_t rng_handle;
		uint32_t out_addr;
		uint32_t out_size;
		uint32_t crc;
	} get_random_cmd = {
		.rng_handle = rng_handle,
		.out_addr = ((uint64_t)buffer) & GENMASK_32(31, 0),
		.out_size = buf_size,
		.crc = CRC_TO_COMPUTE,
	};

	struct imx_mu_msg msg = {
		.header.version = ELE_VERSION,
		.header.size = 1 + (sizeof(get_random_cmd) / sizeof(uint32_t)),
		.header.tag = ELE_REQUEST_TAG,
		.header.command = ELE_CMD_RNG_GET,
	};

	memcpy(msg.data.u8, &get_random_cmd, sizeof(get_random_cmd));
	update_crc(&msg);

	res = imx_ele_call(&msg);
	if (res) {
		EMSG("Failed to get random");
		return res;
	}

	return TEE_SUCCESS;
}

static TEE_Result imx_ele_get_rng(paddr_t buffer, size_t nb_byte_req)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t session_handle = 0;
	uint32_t rng_handle = 0;

	res = open_session(&session_handle);
	if (res)
		goto exit;

	res = open_service_rng(session_handle, buffer, &rng_handle);
	if (res)
		goto close_session;

	res = service_rng_get_random(rng_handle, buffer, nb_byte_req);
	if (res)
		goto close_rng;

close_rng:
	if (close_service_rng(rng_handle))
		return TEE_ERROR_GENERIC;

close_session:
	if (close_session(session_handle))
		return TEE_ERROR_GENERIC;

exit:
	return res;
}

unsigned long plat_get_aslr_seed(void)
{
	unsigned long aslr = 0;

	if (imx_ele_init())
		panic("Failed to init");

	if (imx_ele_get_rng((paddr_t)&aslr, sizeof(aslr)))
		panic("Failed to get RNG");

	return aslr;
}

static TEE_Result imx_ele_mu_init(void)
{
	return imx_ele_init();
}

service_init(imx_ele_mu_init);
