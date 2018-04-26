/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    hal_jr.h
 *
 * @brief   CAAM Job Rings Hardware Abstration Layer header.
 */
#ifndef __HAL_JR_H__
#define __HAL_JR_H__

/**
 * @brief   Configures the Job Ring Owner and lock it.\n
 *          If the configuration is already locked, checks if the configuration
 *          set and returns an error if value is not corresponding to the
 *          expected value.
 *
 * @param[in] ctrl_base  Base address of the controller
 * @param[in] jr_offset  Job Ring offset to configure
 * @param[in] owner      Onwer ID to configure
 *
 * @retval   CAAM_NO_ERROR  Success
 * @retval   CAAM_FAILURE   An error occurred
 *
 */
enum CAAM_Status hal_jr_setowner(vaddr_t ctrl_base, paddr_t jr_offset,
						enum jr_owner owner);
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
enum CAAM_Status hal_jr_reset(vaddr_t baseaddr);

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
					uint64_t inrings, uint64_t outrings);

/**
 * @brief   Returns the number of slots available in the input job ring
 *
 * @param[in] baseaddr   Job Ring Base address
 *
 * @retval   Number of slot available
 *
 */
uint32_t hal_jr_read_nbSlotAvailable(vaddr_t baseaddr);

/**
 * @brief  Indicates to HW that a new job is available
 *
 * @param[in] baseaddr   Job Ring Base Address
 *
 */
void hal_jr_add_newjob(vaddr_t baseaddr);

/**
 * @brief   Returns the output ring slots full register value
 *
 * @param[in] baseaddr   Job Ring Base Address
 *
 * @retval Number of jobs complete
 */
uint32_t hal_jr_get_nbJobDone(vaddr_t baseaddr);

/**
 * @brief   Removes a job from the job ring output queue
 *
 * @param[in] baseaddr   Job Ring Base Address
 *
 */
void hal_jr_del_job(vaddr_t baseaddr);

/**
 * @brief   Disable and acknwoledge the Job Ring interrupt
 *
 * @param[in] baseaddr   Jobr Ring Base Address
 *
 */
void hal_jr_disableIT(vaddr_t baseaddr);

/**
 * @brief   Enable the Job Ring interrupt
 *
 * @param[in] baseaddr   Jobr Ring Base Address
 *
 */
void hal_jr_enableIT(vaddr_t baseaddr);

/**
 * @brief   Pool and acknwoledge the Job Ring interrupt
 *
 * @param[in] baseaddr   Jobr Ring Base Address
 *
 * @retval  true    If interrupt occurred
 * @retval  false   Not interrupt occurred
 */
bool hal_jr_poolackIT(vaddr_t baseaddr);

#endif /* __HAL_JR_H__ */

