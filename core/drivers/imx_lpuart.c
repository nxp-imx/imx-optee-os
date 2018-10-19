// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2018 NXP
 *
 */

#include <assert.h>
#include <drivers/imx_lpuart.h>
#include <io.h>
#include <keep.h>
#include <util.h>
#include <kernel/dt.h>

#define STAT		0x14
#define DATA		0x1C
#define STAT_TDRE	BIT(23)
#define STAT_RDRF	BIT(21)
#define STAT_OR		BIT(19)

static vaddr_t chip_to_base(struct serial_chip *chip)
{
	struct imx_lpuart_data *pd =
		container_of(chip, struct imx_lpuart_data, chip);

	return io_pa_or_va(&pd->base);
}

static void imx_lpuart_flush(struct serial_chip *chip __unused)
{

}

static int imx_lpuart_getchar(struct serial_chip *chip)
{
	int ch;
	vaddr_t base = chip_to_base(chip);

	while (read32(base + STAT) & STAT_RDRF)
		;

	ch = (read32(base + DATA) & 0x3ff);

	if (read32(base + STAT) & STAT_OR)
		write32(base + STAT, STAT_OR);

	return ch;
}

static void imx_lpuart_putc(struct serial_chip *chip, int ch)
{
	vaddr_t base = chip_to_base(chip);

	while (!(read32(base + STAT) & STAT_TDRE))
		__asm__ __volatile__("" : : : "memory");
	write32(ch, base + DATA);
}

static const struct serial_ops imx_lpuart_ops = {
	.flush = imx_lpuart_flush,
	.getchar = imx_lpuart_getchar,
	.putc = imx_lpuart_putc,
};
KEEP_PAGER(imx_lpuart_ops);

void imx_lpuart_init(struct imx_lpuart_data *pd, paddr_t base)
{
	pd->base.pa = base;
	pd->base.va = 0;
	pd->chip.ops = &imx_lpuart_ops;

	/*
	 * Do nothing, debug uart(sc lpuart) share with normal world,
	 * everything for uart0 intialization is done in scfw.
	 */
}

#ifdef CFG_DT

static struct serial_chip *imx_lpuart_dev_alloc(void)
{
	struct imx_lpuart_data *pd = malloc(sizeof(*pd));

	if (!pd)
		return NULL;
	return &pd->chip;
}

static int imx_lpuart_dev_init(struct serial_chip *chip,
			       const void *fdt,
			       int offs,
			       const char *parms)
{
	struct imx_lpuart_data *pd =
		container_of(chip, struct imx_lpuart_data, chip);
	vaddr_t vbase;
	paddr_t pbase;
	size_t size;

	if (parms && parms[0])
		IMSG("imx_lpuart: device parameters ignored (%s)", parms);

	if (dt_map_dev(fdt, offs, &vbase, &size) < 0)
		return -1;

	pbase = virt_to_phys((void *)vbase);
	imx_lpuart_init(pd, pbase);

	return 0;
}

static void imx_lpuart_dev_free(struct serial_chip *chip)
{
	struct imx_lpuart_data *pd =
	  container_of(chip,  struct imx_lpuart_data, chip);

	free(pd);
}

static const struct serial_driver imx_lpuart_driver = {
	.dev_alloc = imx_lpuart_dev_alloc,
	.dev_init = imx_lpuart_dev_init,
	.dev_free = imx_lpuart_dev_free,
};

static const struct dt_device_match imx_match_table[] = {
	{ .compatible = "fsl,imx7ulp-lpuart" },
	{ .compatible = "fsl,imx8qm-lpuart" },
	{ 0 }
};

const struct dt_driver imx_dt_driver __dt_driver = {
	.name = "imx_lpuart",
	.match_table = imx_match_table,
	.driver = &imx_lpuart_driver,
};

#endif /* CFG_DT */
