// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    hal_jr.c
 *
 * @brief   CAAM Job Rings Hardware Abstration Layer.\n
 *          Implementation of primitives to access HW
 */

/* Global includes */
#include <io.h>

/* Local includes */
#include "common.h"
#include "caam_pwr.h"

/* Hal includes */
#include "hal_jr.h"

/* Utils includes */
#include "utils_delay.h"

/* Registers includes */
#include "ctrl_regs.h"
#include "jr_regs.h"

//#define HAL_DEBUG
#ifdef HAL_DEBUG
#define HAL_TRACE		DRV_TRACE
#else
#define HAL_TRACE(...)
#endif

/*
 * List of common JR registers to save/restore
 */
const struct reglist jr_backup[] = {
	{JRx_IRBAR, 2, 0, 0},
	{JRx_IRSR, 1, 0, 0},
	{JRx_ORBAR, 2, 0, 0},
	{JRx_ORSR, 1, 0, 0},
	{JRx_JRCFGR_LS, 1, 0, 0},
};


/**
 * @brief   Resets the Job Ring to ensure that all pending job completed
 *          and no other will be executed
 *
 * @param[in] baseaddr   Job Ring Base address
 *
 * @retval   CAAM_NO_ERROR   Success
 * @retval   CAAM_FAILURE    An error occurred
 *
 */
enum CAAM_Status hal_jr_reset(vaddr_t baseaddr)
{
	/*
	 * Reset is done in 2 steps:
	 *  - Flush all pending jobs (Set RESET bit)
	 *  - Reset the Job Ring (Set RESET bit second time)
	 */
	uint16_t timeout = 10000;
	uint32_t reg_val;

	/* Mask interrupts to poll for reset completion status */
	io_mask32(baseaddr + JRx_JRCFGR_LS, JRx_JRCFGR_LS_IMSK,
			JRx_JRCFGR_LS_IMSK);

	/* Initiate flush (required prior to reset) */
	write32(JRx_JRCR_RESET, baseaddr + JRx_JRCR);
	do {
		caam_udelay(100);
		reg_val = read32(baseaddr + JRx_JRINTR);
		reg_val &= BM_JRx_JRINTR_HALT;
	} while ((reg_val == JRINTR_HALT_ONGOING) && --timeout);

	if ((!timeout)  || (reg_val != JRINTR_HALT_DONE)) {
		EMSG("Failed to flush job ring\n");
		return CAAM_FAILURE;
	}

	/* Initiate reset */
	timeout = 100;
	write32(JRx_JRCR_RESET, baseaddr + JRx_JRCR);
	do {
		caam_udelay(100);
		reg_val = read32(baseaddr + JRx_JRCR);
	} while ((reg_val & JRx_JRCR_RESET) && --timeout);

	if (!timeout) {
		EMSG("Failed to reset job ring\n");
		return CAAM_FAILURE;
	}

	return CAAM_NO_ERROR;
}

/**
 * @brief Configures the Job Ring HW queues.
 *
 * @param[in] baseaddr   Job Ring Base Address
 * @param[in] nbJobs     Number of job rings supported
 * @param[in] inrings    physical address of the JR input queue
 * @param[in] outrings   physical address of the JR output queue
 *
 */
void hal_jr_config(vaddr_t baseaddr, uint8_t nbJobs,
					uint64_t inrings, uint64_t outrings)
{
	uint32_t value;

	/* Setup the JR input queue */
	write32(((inrings >> 32) & 0xFFFFFFFF), baseaddr + JRx_IRBAR);
	write32((inrings & 0xFFFFFFFF), baseaddr + JRx_IRBAR + 4);
	write32(nbJobs, baseaddr + JRx_IRSR);

	/* Setup the JR output queue */
	write32(((outrings >> 32) & 0xFFFFFFFF), baseaddr + JRx_ORBAR);
	write32((outrings & 0xFFFFFFFF), baseaddr + JRx_ORBAR + 4);
	write32(nbJobs, baseaddr + JRx_ORSR);

	/* Disable the JR interrupt */
	hal_jr_disableIT(baseaddr);

	/*
	 * Configure interrupts but disable it:
	 * Optimization to generate an interrupt either when there are
	 *   half of the job done
	 *   or when there is a job done and 10 clock cycles elapse without new
	 *      job complete
	 */
	value = JRx_JRCFGR_LS_ICTT(10);
	value |= JRx_JRCFGR_LS_ICDCT((nbJobs / 2));
	value |= JRx_JRCFGR_LS_ICEN;
	value |= JRx_JRCFGR_LS_IMSK;
	write32(value, baseaddr + JRx_JRCFGR_LS);

#ifdef CFG_IMXCRYPT
	caam_pwr_add_backup(baseaddr, jr_backup, ARRAY_SIZE(jr_backup));
#endif
}

/**
 * @brief   Returns the number of slots available in the input job ring
 *
 * @param[in] baseaddr   Job Ring Base address
 *
 * @retval   Number of slot available
 *
 */
uint32_t hal_jr_read_nbSlotAvailable(vaddr_t baseaddr)
{
	return read32(baseaddr + JRx_IRSAR);
}

/**
 * @brief  Indicates to HW that a new job is available
 *
 * @param[in] baseaddr   Job Ring Base Address
 *
 */
void hal_jr_add_newjob(vaddr_t baseaddr)
{
	write32(1, baseaddr + JRx_IRJAR);
}

/**
 * @brief   Returns the output ring slots full register value
 *
 * @param[in] baseaddr   Job Ring Base Address
 *
 * @retval Number of jobs complete
 */
uint32_t hal_jr_get_nbJobDone(vaddr_t baseaddr)
{
	return read32(baseaddr + JRx_ORSFR);
}

/**
 * @brief   Removes a job from the job ring output queue
 *
 * @param[in] baseaddr   Job Ring Base Address
 *
 */
void hal_jr_del_job(vaddr_t baseaddr)
{
	write32(1, baseaddr + JRx_ORJRR);
}

/**
 * @brief   Disable and acknwoledge the Job Ring interrupt
 *
 * @param[in] baseaddr   Jobr Ring Base Address
 *
 */
void hal_jr_disableIT(vaddr_t baseaddr)
{
	io_mask32(baseaddr + JRx_JRCFGR_LS,	JRx_JRCFGR_LS_IMSK,
			JRx_JRCFGR_LS_IMSK);
	io_mask32(baseaddr + JRx_JRINTR, JRx_JRINTR_JRI, JRx_JRINTR_JRI);
}

/**
 * @brief   Enable the Job Ring interrupt
 *
 * @param[in] baseaddr   Jobr Ring Base Address
 *
 */
void hal_jr_enableIT(vaddr_t baseaddr)
{
	io_mask32(baseaddr + JRx_JRCFGR_LS,	~JRx_JRCFGR_LS_IMSK,
				JRx_JRCFGR_LS_IMSK);
}

/**
 * @brief   Pool and acknwoledge the Job Ring interrupt
 *
 * @param[in] baseaddr   Jobr Ring Base Address
 *
 * @retval  true    If interrupt occurred
 * @retval  false   Not interrupt occurred
 */
bool hal_jr_poolackIT(vaddr_t baseaddr)
{
	uint32_t val;

	val = read32(baseaddr + JRx_JRINTR);

	if ((val & JRx_JRINTR_JRI) == JRx_JRINTR_JRI) {
		/* Acknowledge interrupt */
		io_mask32(baseaddr + JRx_JRINTR, JRx_JRINTR_JRI,
				JRx_JRINTR_JRI);
		return true;
	}

	return false;
}

/**
 * @brief   Halt the Job Ring processing. Stop fetching input
 *          queue and wait all running jobs normal completion.
 *
 * @param[in] baseaddr   Jobr Ring Base Address
 *
 * @retval 0    Job Ring is halted
 * @retval (-1) Error occurred
 */
int hal_jr_halt(vaddr_t baseaddr)
{
	uint16_t timeout = 10000;
	uint32_t val;

	/* Mask interrupts to poll for completion status */
	io_mask32(baseaddr + JRx_JRCFGR_LS, JRx_JRCFGR_LS_IMSK,
			JRx_JRCFGR_LS_IMSK);

	/* Request Job ring halt */
	write32(JRx_JRCR_PARK, baseaddr + JRx_JRCR);

	/* Check if there is a job running */
	val = read32(baseaddr + JRx_IRSR);
	if ((hal_jr_read_nbSlotAvailable(baseaddr) == val)
			&& (read32(baseaddr + JRx_CSTA) != JRx_CSTA_BSY))
		return 0;

	/* Wait until all jobs complete */
	do {
		caam_udelay(10);
		val = read32(baseaddr + JRx_JRINTR);
		val &= BM_JRx_JRINTR_HALT;
	} while ((val != JRINTR_HALT_DONE) && --timeout);

	if (!timeout)
		return (-1);

	return 0;
}

/**
 * @brief   Wait all Input queue Job Ring processing.
 *
 * @param[in] baseaddr   Jobr Ring Base Address
 *
 * @retval 0    Job Ring is halted
 * @retval (-1) Error occurred
 */
int hal_jr_flush(vaddr_t baseaddr)
{
	uint16_t timeout = 10000;
	uint32_t val;

	/* Mask interrupts to poll for completion status */
	io_mask32(baseaddr + JRx_JRCFGR_LS, JRx_JRCFGR_LS_IMSK,
			JRx_JRCFGR_LS_IMSK);

	/* Request Job ring to flush input queue */
	write32(JRx_JRCR_RESET, baseaddr + JRx_JRCR);

	/* Check if there is a job running */
	val = read32(baseaddr + JRx_IRSR);
	if ((hal_jr_read_nbSlotAvailable(baseaddr) == val)
			&& (read32(baseaddr + JRx_CSTA) != JRx_CSTA_BSY))
		return 0;

	/* Wait until all jobs complete */
	do {
		caam_udelay(10);
		val = read32(baseaddr + JRx_JRINTR);
		val &= BM_JRx_JRINTR_HALT;
	} while ((val == JRINTR_HALT_DONE) && --timeout);

	if (!timeout)
		return (-1);

	return 0;
}

/**
 * @brief   Resume the Job Ring processing.
 *
 * @param[in] baseaddr   Jobr Ring Base Address
 */
void hal_jr_resume(vaddr_t baseaddr)
{
	write32(JRINTR_HALT_RESUME, baseaddr + JRx_JRINTR);

	hal_jr_enableIT(baseaddr);
}

/**
 * @brief   Get the current JR input queue index of the next job to read.
 *          The HW increments register by 4. Convert it to a software
 *          index number
 *
 * @param[in] baseaddr   CAAM JR Base Address
 *
 * @retval index of the next entry in the queue
 */
uint8_t hal_jr_input_index(vaddr_t baseaddr)
{
	uint32_t index;

	index = read32(baseaddr + JRx_IRRIR);
	return index >> 2;
}

/**
 * @brief   Get the current JR output index of the next job completion.
 *          The HW increments register by 8. Convert it to a software
 *          index number
 *
 * @param[in] baseaddr   CAAM JR Base Address
 *
 * @retval index of the next entry in the queue
 */
uint8_t hal_jr_output_index(vaddr_t baseaddr)
{
	uint32_t index;

	index = read32(baseaddr + JRx_ORWIR);
	return index >> 3;
}

