// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2018 NXP
 *
 */
#include <io.h>
#include <string.h>
#include <trace.h>
#include <util.h>
#include <tee_api_types.h>

#include "intern.h"
#include "ctrl_regs.h"
#include "rng_regs.h"
#include "version_regs.h"

#include <mm/core_memprot.h>
#include <tee/cache.h>
#include "jr_regs.h"

//#define RNG_DEBUG
//#define DRV_DEBUG
#ifdef DRV_DEBUG
#define DRV_TRACE(...)	trace_printf(__func__, __LINE__, 0, false, __VA_ARGS__)
#else
#define DRV_TRACE(...)
#endif

static void dump_error(vaddr_t ctrl_base __maybe_unused)
{
	DRV_TRACE("Dump CAAM Error");
	DRV_TRACE("MCFGR 0x%08X", read32(ctrl_base + MCFGR));
	DRV_TRACE("FAR  0x%08X%08X", read32(ctrl_base + FAR),
							  read32(ctrl_base + FAR + 4));
	DRV_TRACE("FAMR 0x%08X", read32(ctrl_base + FAMR));
	DRV_TRACE("FADR 0x%08X", read32(ctrl_base + FADR));
	DRV_TRACE("CSTA 0x%08X", read32(ctrl_base + CSTA));
}

static inline void do_sw_delay(void)
{
	volatile uint16_t delay = 0xFFFF;

	/*
	 * Implementation of a small delay loop because udelay kernel
	 * function is not available on all cortex
	 */
	while (delay--);
}

static void kick_trng(vaddr_t ctrl_base, uint32_t ent_delay)
{
	uint32_t val;

	/* Put RNG in program mode */
	io_mask32(ctrl_base + TRNG_MCTL, BM_TRNG_MCTL_PRGM,
				BM_TRNG_MCTL_PRGM);

	/* Configure the RNG Entropy Delay
	 * Performance-wise, it does not make sense to
	 * set the delay to a value that is lower
	 * than the last one that worked (i.e. the state handles
	 * were instantiated properly. Thus, instead of wasting
	 * time trying to set the values controlling the sample
	 * frequency, the function simply returns.
	 */
	val = read32(ctrl_base + TRNG_SDCTL);
	val &= BM_TRNG_SDCTL_ENT_DLY;
	val >>= BS_TRNG_SDCTL_ENT_DLY;

	if (ent_delay < val) {
		/*
		 * In some case, the other register are not setup correctly
		 * hence to the configuration anyway.
		 */
		ent_delay = val;
	}

	val = read32(ctrl_base + TRNG_SDCTL);
	val &= ~BM_TRNG_SDCTL_ENT_DLY;
	val |= ent_delay << BS_TRNG_SDCTL_ENT_DLY;
	write32(val, ctrl_base + TRNG_SDCTL);

	/* min. freq. count, equal to 1/4 of the entropy sample length */
	write32(ent_delay >> 2, ctrl_base + TRNG_FRQMIN);

	/* max. freq. count, equal to 16 times the entropy sample length */
	write32(ent_delay << 4, ctrl_base + TRNG_FRQMAX);

	val = read32(ctrl_base + TRNG_MCTL);
	/*
	 * Select raw sampling in both entropy shifter
	 * and statistical checker
	 */
	val &= ~BM_TRNG_MCTL_SAMP_MODE;
	val |= TRNG_MCTL_SAMP_MODE_RAW_ES_SC;
	/* Put RNG4 into run mode */
	val &= ~BM_TRNG_MCTL_PRGM;
	write32(val, ctrl_base + TRNG_MCTL);

	/* Clear the ERR bit in RTMCTL if set. The TRNG error can occur when the
	 * RNG clock is not within 1/2x to 8x the system clock.
	 * This error is possible if ROM code does not initialize the system PLLs
	 * immediately after PoR.
	 */
	val = read32(ctrl_base + TRNG_MCTL) | BM_TRNG_MCTL_ERR;
	write32(val, ctrl_base + TRNG_MCTL);

}

#define CAAM_HDR_CTYPE				(0x16u << 27)
#define CAAM_HDR_ONE				(0x1 << 23)
#define CAAM_HDR_START_INDEX(x)		(((x) & 0x3F) << 16)
#define CAAM_HDR_DESCLEN(x)			((x) & 0x3F)
#define CAAM_PROTOP_CTYPE			(0x10u << 27)

/* State Handle */
#define BS_ALGO_RNG_SH				(4)
#define BM_ALGO_RNG_SH				(0x3 << BS_ALGO_RNG_SH)
#define ALGO_RNG_SH(id)				((id << BS_ALGO_RNG_SH) & BM_ALGO_RNG_SH)

/* Secure Key */
#define BS_ALGO_RNG_SK				(12)
#define BM_ALGO_RNG_SK				(0x1 << BS_ALGO_RNG_SK)

/* State */
#define BS_ALGO_RNG_AS				(2)
#define BM_ALGO_RNG_AS				(0x3 << BS_ALGO_RNG_AS)
#define ALGO_RNG_GENERATE			(0x0 << BS_ALGO_RNG_AS)
#define ALGO_RNG_INSTANTIATE		(0x1 << BS_ALGO_RNG_AS)

#define CAAM_C1_RNG					((0x50 << 16) | (2 << 24))

#define BS_JUMP_LOCAL_OFFSET		(0)
#define BM_JUMP_LOCAL_OFFSET		(0xFF << BS_JUMP_LOCAL_OFFSET)

#define CAAM_C1_JUMP				((0x14u << 27) | (1 << 25))
#define CAAM_JUMP_LOCAL				(0 << 20)
#define CAAM_JUMP_TST_ALL_COND_TRUE (0 << 16)
#define CAAM_JUMP_OFFSET(off)		((off << BS_JUMP_LOCAL_OFFSET) & BM_JUMP_LOCAL_OFFSET)

#define CAAM_C0_LOAD_IMM			((0x2 << 27) | (1 << 23))
#define CAAM_DST_CLEAR_WRITTEN		(0x8 << 16)

/*
 * Descriptors to instantiate SH0, SH1, load the keys
 */
static const uint32_t rng_inst_sh0_desc[] = {
	/* Header, don't setup the size */
	CAAM_HDR_CTYPE | CAAM_HDR_ONE | CAAM_HDR_START_INDEX(0),
	/* Operation instantiation (sh0) */
	CAAM_PROTOP_CTYPE | CAAM_C1_RNG | ALGO_RNG_SH(0) | ALGO_RNG_INSTANTIATE,
};

static const uint32_t rng_inst_sh1_desc[] = {
	/* wait for done - Jump to next entry */
	CAAM_C1_JUMP | CAAM_JUMP_LOCAL | CAAM_JUMP_TST_ALL_COND_TRUE | CAAM_JUMP_OFFSET(1),
	/* Clear written register (write 1) */
	CAAM_C0_LOAD_IMM | CAAM_DST_CLEAR_WRITTEN | sizeof(uint32_t),
	0x00000001,
	/* Operation instantiation (sh1) */
	CAAM_PROTOP_CTYPE | CAAM_C1_RNG | ALGO_RNG_SH(1) | ALGO_RNG_INSTANTIATE,
};

static const uint32_t rng_inst_load_keys[] = {
	/* wait for done - Jump to next entry */
	CAAM_C1_JUMP | CAAM_JUMP_LOCAL | CAAM_JUMP_TST_ALL_COND_TRUE | CAAM_JUMP_OFFSET(1),
	/* Clear written register (write 1) */
	CAAM_C0_LOAD_IMM | CAAM_DST_CLEAR_WRITTEN | sizeof(uint32_t),
	0x00000001,
	/* Generate the Key */
	CAAM_PROTOP_CTYPE | CAAM_C1_RNG | BM_ALGO_RNG_SK | ALGO_RNG_GENERATE,
};

#define RNG_DESC_SH0_SIZE	(ARRAY_SIZE(rng_inst_sh0_desc))
#define RNG_DESC_SH1_SIZE	(ARRAY_SIZE(rng_inst_sh1_desc))
#define RNG_DESC_KEYS_SIZE	(ARRAY_SIZE(rng_inst_load_keys))
#define RNG_DESC_MAX_SIZE	(RNG_DESC_SH0_SIZE + \
								RNG_DESC_SH1_SIZE + \
								RNG_DESC_KEYS_SIZE)

static void do_inst_desc(uint32_t *desc, uint32_t status)
{
	uint32_t *pdesc = desc;
	uint8_t  desc_size;
	bool     add_sh0   = false;
	bool     add_sh1   = false;
	bool     load_keys = false;

	/*
	 * Modify the the descriptor to remove if necessary:
	 *  - The key loading
	 *  - One of the SH already instantiated
	 */
	desc_size = RNG_DESC_SH0_SIZE;
	if ((status & BM_RNG_STA_IF0) != BM_RNG_STA_IF0) {
		add_sh0 = true;
	}

	if ((status & BM_RNG_STA_IF1) != BM_RNG_STA_IF1) {
		add_sh1 = true;

		if (add_sh0) {
			desc_size += RNG_DESC_SH1_SIZE;
		}
	}

	if ((status & BM_RNG_STA_SKVN) != BM_RNG_STA_SKVN) {
		load_keys = true;

		desc_size += RNG_DESC_KEYS_SIZE;
	}

	/* Copy the SH0 descriptor anyway */
	memcpy(pdesc, rng_inst_sh0_desc, sizeof(rng_inst_sh0_desc));
	pdesc += RNG_DESC_SH0_SIZE;

	if (load_keys) {
		DRV_TRACE("RNG - Load keys");
		memcpy(pdesc, rng_inst_load_keys, sizeof(rng_inst_load_keys));
		pdesc += RNG_DESC_KEYS_SIZE;
	}

	if (add_sh1) {
		if (add_sh0) {
			DRV_TRACE("RNG - Instantiation of SH0 and SH1");
			/* Add the sh1 descriptor */
			memcpy(pdesc, rng_inst_sh1_desc, sizeof(rng_inst_sh1_desc));
		}
		else {
			DRV_TRACE("RNG - Instantiation of SH1 only");
			/* Modify the SH0 descriptor to instantiate only SH1 */
			desc[1] &= ~BM_ALGO_RNG_SH;
			desc[1] |= ALGO_RNG_SH(1);
		}
	}

	/* Setup the descriptor size */
	desc[0] &= ~(0x3F);
	desc[0] |=	CAAM_HDR_DESCLEN(desc_size);

#ifdef RNG_DEBUG
	for (uint32_t i = 0; i < (desc[0] & 0x3F); i++) {
		DRV_TRACE("desc 0x%08x \n", ((uint32_t *)desc)[i]);
	}
#endif
}

static inline void write64(uint64_t val, vaddr_t addr)
{
	write32(((val >> 32) & 0xFFFFFFFF), addr);
	write32((val & 0xFFFFFFFF), addr + 4);
}

static int jr_reset(vaddr_t jr_base)
{
	/*
	 * Function reset the Job Ring HW
	 * Reset is done in 2 steps:
	 *  - Flush all pending jobs (Set RESET bit)
	 *  - Reset the Job Ring (Set RESET bit second time)
	 */
	uint16_t timeout = 10000;
	uint32_t reg_val;

	/* Mask interrupts to poll for reset completion status */
	io_mask32(jr_base + JRx_JRCFGR_LS, BM_JRx_JRCFGR_LS_IMSK,
				BM_JRx_JRCFGR_LS_IMSK);

	/* Initiate flush (required prior to reset) */
	write32(BM_JRx_JRCR_RESET, jr_base + JRx_JRCR);
	do {
		do_sw_delay();
		reg_val = read32(jr_base + JRx_JRINTR);
		reg_val &= BM_JRx_JRINTR_HALT;
	} while ((reg_val == JRINTR_HALT_ONGOING) && --timeout);

	if ((!timeout)  || (reg_val != JRINTR_HALT_DONE)) {
		EMSG("Failed to flush job ring\n");
		return (-1);
	}

	/* Initiate reset */
	timeout = 100;
	write32(BM_JRx_JRCR_RESET, jr_base + JRx_JRCR);
	do {
		do_sw_delay();
		reg_val = read32(jr_base + JRx_JRCR);
	} while ((reg_val & BM_JRx_JRCR_RESET) && --timeout);

	if (!timeout) {
		EMSG("Failed to reset job ring\n");
		return (-1);
	}

	return 0;
}

/*
 * Definition of input ring object
 */
typedef struct inring_entry {
	uint32_t desc; /* Pointer to input descriptor */
} inring_entry_t;

/*
 * Definition of output ring object
 */
typedef struct outring_entry {
	uint32_t desc;   /* Pointer to output descriptor */
	uint32_t status; /* Status of the Job Ring       */
} outring_entry_t;

typedef struct {
	vaddr_t         jr_base;
	size_t          desc_align;
	inring_entry_t  *inrings;
	outring_entry_t *outrings;
} jr_data_t;

static uint32_t do_job(jr_data_t *jr_data, uint32_t *desc)
{
	paddr_t pdesc;

	while (read32(jr_data->jr_base + JRx_IRSAR) == 0) {
		do_sw_delay();
	};

	pdesc = virt_to_phys(desc);

	jr_data->inrings[0].desc = pdesc;

	cache_operation(TEE_CACHECLEAN, desc,
					(CAAM_HDR_DESCLEN(desc[0]) * sizeof(uint32_t)));
	cache_operation(TEE_CACHECLEAN, jr_data->inrings, sizeof(inring_entry_t));

	/* Inform HW that a new JR is available */
	write32(1, jr_data->jr_base + JRx_IRJAR);

	while (read32(jr_data->jr_base + JRx_ORSFR) == 0) {
		do_sw_delay();
	}

	/* Acknowledge interrupt */
	io_mask32(jr_data->jr_base + JRx_JRINTR,
				BM_JRx_JRINTR_JRI, BM_JRx_JRINTR_JRI);

	cache_operation(TEE_CACHEINVALIDATE, jr_data->outrings,
						sizeof(outring_entry_t));

	/* Remove the JR from the output list even if no JR caller found */
	write32(1, jr_data->jr_base + JRx_ORJRR);

	if (pdesc == jr_data->outrings[0].desc) {
		return jr_data->outrings[0].status;
	}

	return (-1);
}

static int do_cfg_jrqueue(jr_data_t *jr_data)
{
	uint32_t value = 0;
	paddr_t  phys_addr;

	uint16_t cacheline_size;

#ifdef ARM64
	asm volatile("mrs %0, ctr_el0" : "=r" (value));	\

	cacheline_size = 4 << ((value >> CTR_DMINLINE_SHIFT) & 0xF);
#else
	asm volatile ("mrc	p15, 1, %[val], c0, c0, 0" : [val] "=r" (value));
	cacheline_size = 4 << ((value & 0x7) + 2);
#endif

	jr_data->inrings  = memalign(cacheline_size,
						ROUNDUP(sizeof(inring_entry_t), cacheline_size));
	jr_data->outrings = memalign(cacheline_size,
						ROUNDUP(sizeof(outring_entry_t), cacheline_size));

	if ((!jr_data->inrings) || (!jr_data->outrings)) {
		return (-1);
	}

	/* Fill the input and output stack with 0 */
	memset(jr_data->inrings, 0, sizeof(inring_entry_t));
	memset(jr_data->outrings, 0, sizeof(outring_entry_t));
	cache_operation(TEE_CACHEFLUSH, (void *)jr_data->inrings,
					sizeof(inring_entry_t));
	cache_operation(TEE_CACHEFLUSH, (void *)jr_data->outrings,
					sizeof(outring_entry_t));

	/* Configure the HW Job Rings */
	phys_addr = virt_to_phys(jr_data->inrings);
	write64(phys_addr, jr_data->jr_base + JRx_IRBAR);
	write32(1, jr_data->jr_base + JRx_IRSR);

	phys_addr = virt_to_phys(jr_data->outrings);
	write64(phys_addr, jr_data->jr_base + JRx_ORBAR);
	write32(1, jr_data->jr_base + JRx_ORSR);

	io_mask32(jr_data->jr_base + JRx_JRINTR,
					BM_JRx_JRINTR_JRI, BM_JRx_JRINTR_JRI);

	/*
	 * Configure interrupts but disable it:
	 * Optimization to generate an interrupt either when there are
	 *   half of the job done
	 *   or when there is a job done and 10 clock cycles elapse without new
	 *      job complete
	 */
	value = 10 << BS_JRx_JRCFGR_LS_ICTT;
	value |= (1 << BS_JRx_JRCFGR_LS_ICDCT) & BM_JRx_JRCFGR_LS_ICDCT;
	value |= BM_JRx_JRCFGR_LS_ICEN;
	value |= BM_JRx_JRCFGR_LS_IMSK;
	write32(value, jr_data->jr_base + JRx_JRCFGR_LS);

	return 0;

}

static void do_clear_rng_error(vaddr_t ctrl_base)
{
	uint32_t val;

	val = read32(ctrl_base + TRNG_MCTL);

	DRV_TRACE("RNG RTMCTL 0x%x", val);

	if (val & (BM_TRNG_MCTL_ERR | BM_TRNG_MCTL_FCT_FAIL)) {
		io_mask32(ctrl_base + TRNG_MCTL, BM_TRNG_MCTL_ERR, BM_TRNG_MCTL_ERR);
		val = read32(ctrl_base + TRNG_MCTL);

		DRV_TRACE("RNG RTMCTL 0x%x", val);
	}
}

static int do_instantiation(vaddr_t ctrl_base, jr_data_t *jr_data)
{
	int      ret = (-1);

	uint32_t cha_vid_ls;
	uint32_t *desc = NULL;
	uint32_t ent_delay;
	uint32_t status;

	desc = memalign(jr_data->desc_align, RNG_DESC_MAX_SIZE * sizeof(uint32_t));

	if (!desc) {
		EMSG("CAAM Descriptor allocation error");
		return (-1);
	}

	cha_vid_ls = read32(ctrl_base + CHAVID_LS);

	/*
	 * If SEC has RNG version >= 4 and RNG state handle has not been
	 * already instantiated, do RNG instantiation
	 */
	if (((cha_vid_ls & BM_CHAVID_LS_RNGVID) >> BS_CHAVID_LS_RNGVID) < 4) {
		DRV_TRACE("RNG already instantiated");
		return 0;
	}

	ent_delay = TRNG_SDCTL_ENT_DLY_MIN;

	do {
		/* Read the CAAM RNG status */
		status = read32(ctrl_base + RNG_STA);

		DRV_TRACE("RNG Status 0x%x", status);

		if ((status & BM_RNG_STA_IF0) != BM_RNG_STA_IF0) {
			/* Configure the RNG entropy delay */
			kick_trng(ctrl_base, ent_delay);
			ent_delay += 400;
		}

		do_clear_rng_error(ctrl_base);

		if ((status & (BM_RNG_STA_IF0 | BM_RNG_STA_IF1)) !=
			(BM_RNG_STA_IF0 | BM_RNG_STA_IF1)) {

			/* Prepare the instantiation descriptor */
			do_inst_desc(desc, status);

			/* Run Job */
			ret = do_job(jr_data, desc);
			DRV_TRACE("RNG Instantiation DECO returned 0x%x", ret);

			if (ret == (-1)) {
				/* CAAM DECO failure ends here */
				EMSG("RNG Instantiation DECO error");
				dump_error(ctrl_base);
				goto end_instantation;
			}
		} else {
			ret = 0;
			EMSG("RNG Instantation Done");
			goto end_instantation;
		}
	} while (ent_delay < TRNG_SDCTL_ENT_DLY_MAX);

	EMSG("RNG Instantation Failure - Entropy delay");
	ret = (-1);

end_instantation:
	if (desc) {
		free(desc);
	}

	return ret;
}

TEE_Result rng_init(vaddr_t ctrl_base)
{
	TEE_Result status = TEE_ERROR_GENERIC;
	int  ret;

	jr_data_t jr_data = {0};

	jr_data.jr_base = ctrl_base + JRx_BLOCK_SIZE;

#ifdef ARM64
	jr_data.desc_align = 64 / 8;
#else
	jr_data.desc_align = 32 / 8;
#endif

	ret = do_cfg_jrqueue(&jr_data);

	if (ret != 0) {
		EMSG("Error CAAM JR initialization");
		goto end_rng_init;
	}

	ret = jr_reset(jr_data.jr_base);
	if (ret != 0) {
		EMSG("Error CAAM JR reset");
		goto end_rng_reset;
	}

	ret = do_instantiation(ctrl_base, &jr_data);

	if (ret == 0) {
		status = TEE_SUCCESS;
	}

end_rng_reset:
	jr_reset(jr_data.jr_base);

end_rng_init:
	if (jr_data.inrings) {
		free(jr_data.inrings);
	}
	if (jr_data.outrings) {
		free(jr_data.outrings);
	}

	return status;
}

