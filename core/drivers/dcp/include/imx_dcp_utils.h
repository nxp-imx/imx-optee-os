/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 NXP
 */
#ifndef __IMX_DCP_UTILS_H__
#define __IMX_DCP_UTILS_H__

/* Adjust index value for writing in register */
#define SRAM_KEY_INDEX(idx) SHIFT_U32(idx, 4)

/* Calculate context switching buffer offset */
#define CONTEXT_SW_OFFSET(chann) (((DCP_NB_CHANNELS) - (1) - (chann)) * (52))

/*
 * Allocate internal driver buffer aligned with a cache line and initialize it
 * with 0s
 *
 * @buf   [out] Buffer to allocate
 * @size  Size in bytes of the memory to allocate
 */
TEE_Result dcp_calloc_align_buf(struct align_buf *buf, size_t size);

/*
 * Free allocated memory
 *
 * @ptr  reference to the object to free
 */
void dcp_free(void *ptr);

/*
 * Left shifting a multi bytes buffer by one bit
 *
 * @result       [out] Buffer containing the result of the operation
 * @input        Input buffer for the operation
 * @buffer_size  Size of the buffer in bytes
 */
void left_shift_buffer(uint8_t *result, uint8_t *input, size_t buffer_size);

/*
 * Wait given microsecond
 *
 * @time   Time in microsecond
 */
void dcp_udelay(uint32_t time);

#endif /* __IMX_DCP_UTILS_H__ */
