// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 NXP
 * PTA for I2C Testing on LayerScape Boards
 */

#include <drivers/ls_i2c.h>
#include <initcall.h>
#include <kernel/delay.h>
#include <kernel/pseudo_ta.h>
#include <mm/core_memprot.h>
#include <pta_i2c_rtc_test.h>
#include <tee_api_types.h>

#define PTA_NAME "i2c_rtc_test.pta"

#define PCF2129_CTRL3_BIT_BLF BIT(2) /* Battery Low Flag*/
#define PCF2129_SLAVE_ADDRESS 0x51

/*
 * Control registers are combination of multiple bits.
 * Please check their description from following link:
 * https://www.nxp.com/docs/en/data-sheet/PCF2129.pdf [Sec 8.2]
 */
struct pcf2129_regs {
	uint8_t control[3];
	uint8_t seconds;
	uint8_t minutes;
	uint8_t hours;
	uint8_t days;
	uint8_t weekdays;
	uint8_t months;
	uint8_t years;
	uint8_t second_alarm;
	uint8_t minute_alarm;
	uint8_t hour_alarm;
	uint8_t day_alarm;
	uint8_t weekday_alarm;
} __packed;

#if defined(PLATFORM_FLAVOR_lx2160ardb)
/* I2c clock based on 750Mhz platform clock */
#define I2C_CLOCK      93750000
#define I2C_SPEED      100000
#define I2C_CONTROLLER 4
#endif

/*
 * RTC outputs time in BCD format and now we need to do
 * calculation on seconds field, we need to convert it to decimal.
 * For more information please check section 8.8 in this pdf
 * https://www.nxp.com/docs/en/data-sheet/PCF2129.pdf
 */
static inline int bcd_to_decimal(uint8_t bcd)
{
	int dec = ((bcd & 0xF0) >> 4) * 10 + (bcd & 0x0F);
	return dec;
}

static TEE_Result i2c_rtc_get_second(vaddr_t base, uint8_t *sec)
{
	struct i2c_operation operation = {};
	unsigned int operation_count = 0;
	uint8_t rtc_reg_adr = 0;
	static struct pcf2129_regs pcf_regs = {};
	uint8_t __maybe_unused days = 0;
	uint8_t __maybe_unused hours = 0;
	uint8_t __maybe_unused minutes = 0;
	uint8_t seconds = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	rtc_reg_adr = offsetof(struct pcf2129_regs, control[2]);

	operation_count = 1;
	operation.flags = I2C_FLAG_WRITE;
	operation.length_in_bytes = sizeof(rtc_reg_adr);
	operation.buffer = &rtc_reg_adr;

	res = i2c_bus_xfer(base, PCF2129_SLAVE_ADDRESS, &operation,
			   operation_count);
	if (res) {
		EMSG("RTC write error at Addr, Status = %x", res);
		goto exit;
	}

	operation_count = 1;
	operation.flags = I2C_FLAG_READ;
	operation.length_in_bytes = offsetof(struct pcf2129_regs,
					     second_alarm) -
				    offsetof(struct pcf2129_regs, control[2]);
	operation.buffer = &pcf_regs.control[2];

	res = i2c_bus_xfer(base, PCF2129_SLAVE_ADDRESS, &operation,
			   operation_count);
	if (res) {
		EMSG("RTC read error at Addr, Status = %x", res);
		goto exit;
	}

	days = bcd_to_decimal(pcf_regs.days);
	hours = bcd_to_decimal(pcf_regs.hours);
	minutes = bcd_to_decimal(pcf_regs.minutes);
	seconds = bcd_to_decimal(pcf_regs.seconds);

	DMSG("Days = %u, Hours = %u, Minutes = %u, Second = %u", days, hours,
	     minutes, seconds);

	if (pcf_regs.control[2] & PCF2129_CTRL3_BIT_BLF)
		EMSG("RTC battery res low, check RTC battery");

	*sec = seconds;

exit:
	return res;
}

static TEE_Result i2c_test_suite(void)
{
	uint8_t curr_sec = 0, prev_sec = 0;
	uint8_t num_times = 0;
	struct ls_i2c_data i2c_data = {};
	TEE_Result res = TEE_ERROR_GENERIC;

	DMSG("I2C RTC TEST: will get time from RTC 5 times after 2 secs");

	/* set slave info */
	i2c_data.i2c_controller = I2C_CONTROLLER;
	i2c_data.i2c_bus_clock = I2C_CLOCK;
	i2c_data.speed = I2C_SPEED;

	/* Initialise I2C driver */
	res = i2c_init(&i2c_data);
	if (res) {
		EMSG("Unable to init I2C driver");
		goto exit;
	}

	while (num_times < 5) {
		res = i2c_rtc_get_second(i2c_data.base, &curr_sec);
		if (res)
			goto exit;
		/*
		 * Will skip first time for saving prev_sec to
		 * compare with current second value received
		 * from RTC.
		 * Also Skipping the test when minute changes.
		 */
		if (num_times > 0 && curr_sec > 1) {
			/*
			 * Comparing diff with 2 seconds.
			 * Also taking into difference of 3 seconds
			 * because of boundary condition and delay
			 * due to calculation.
			 */
			if ((curr_sec - prev_sec) != 2 &&
			    (curr_sec - prev_sec) != 3) {
				EMSG("Seconds mismatch by = %u sec\n",
				     curr_sec - prev_sec);
				res = TEE_ERROR_GENERIC;
				goto exit;
			}
		}
		prev_sec = curr_sec;
		/* Add delay of 2 secs and then again get time from RTC */
		mdelay(2000);
		num_times++;
	}
exit:
	return res;
}

/*
 * Called when a pseudo TA is invoked.
 *
 * sess_ctx       Session Identifier
 * cmd_id         Command ID
 * param_types    TEE parameters
 * params         Buffer parameters
 */
static TEE_Result
invokeCommandEntryPoint(void *sess_ctx __unused, uint32_t cmd_id,
			uint32_t param_types __unused,
			TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	switch (cmd_id) {
	case PTA_CMD_I2C_RTC_RUN_TEST_SUITE:
		return i2c_test_suite();
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

pseudo_ta_register(.uuid = PTA_LS_I2C_RTC_TEST_SUITE_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invokeCommandEntryPoint);
