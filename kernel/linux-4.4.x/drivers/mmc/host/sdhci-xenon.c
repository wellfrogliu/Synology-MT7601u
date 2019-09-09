#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#if defined(MY_DEF_HERE)
/*
#if defined(MY_DEF_HERE)
 * Driver for Marvell Xenon SDHC as a platform device
#else  // MY_DEF_HERE
 * Driver for Marvell SOCP Xenon SDHC as a platform device
#endif // MY_DEF_HERE
 *
 * Copyright (C) 2016 Marvell, All Rights Reserved.
 *
 * Author:	Hu Ziji <huziji@marvell.com>
#if defined(MY_DEF_HERE)
 * Date:	2016-8-24
#else  // MY_DEF_HERE
 * Date:	2016-7-30
#endif // MY_DEF_HERE
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * Inspired by Jisheng Zhang <jszhang@marvell.com>
 * Special thanks to Video BG4 project team.
 */

#include <linux/delay.h>
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
#include <linux/err.h>
#include <linux/io.h>
#include <linux/mmc/host.h>
#include <linux/mmc/mmc.h>
#include <linux/mmc/sdio.h>
#include <linux/mmc/card.h>
#include <linux/mmc/host.h>
#endif /* MY_DEF_HERE */
#include <linux/module.h>
#include <linux/of.h>

#include "sdhci-pltfm.h"
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
#include "sdhci.h"
#endif /* MY_DEF_HERE */
#include "sdhci-xenon.h"

#if defined(MY_DEF_HERE)
static int enable_xenon_internal_clk(struct sdhci_host *host)
#else /* MY_DEF_HERE */
/*
 * Xenon Specific Initialization Operations
 */
static inline void xenon_set_tuning_count(struct sdhci_host *host,
				unsigned int count)
#endif /* MY_DEF_HERE */
{
#if defined(MY_DEF_HERE)
	u32 reg;
	u8 timeout;

	reg = sdhci_readl(host, SDHCI_CLOCK_CONTROL);
	reg |= SDHCI_CLOCK_INT_EN;
	sdhci_writel(host, reg, SDHCI_CLOCK_CONTROL);
	/* Wait max 20 ms */
	timeout = 20;
	while (!((reg = sdhci_readw(host, SDHCI_CLOCK_CONTROL))
			& SDHCI_CLOCK_INT_STABLE)) {
		if (timeout == 0) {
			pr_err("%s: Internal clock never stabilised.\n",
			       mmc_hostname(host->mmc));
			return -ETIMEDOUT;
		}
		timeout--;
		mdelay(1);
	}
#else /* MY_DEF_HERE */
	/* A valid count value */
	host->tuning_count = 1 << (count - 1);
}
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	return 0;
#else /* MY_DEF_HERE */
/*
 * Current driver can only support Tuning Mode 1.
 * Tuning timer is only setup only tuning_mode == Tuning Mode 1.
 * Thus host->tuning_mode has to be forced as Tuning Mode 1.
 */
static inline void xenon_set_tuning_mode(struct sdhci_host *host)
{
	host->tuning_mode = SDHCI_TUNING_MODE_1;
#endif /* MY_DEF_HERE */
}

/* Set SDCLK-off-while-idle */
static void xenon_set_sdclk_off_idle(struct sdhci_host *host,
#if defined(MY_DEF_HERE)
				     unsigned char sdhc_id, bool enable)
#else /* MY_DEF_HERE */
			unsigned char slot_idx, bool enable)
#endif /* MY_DEF_HERE */
{
	u32 reg;
	u32 mask;

#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
	reg = sdhci_readl(host, XENON_SYS_OP_CTRL);
#else /* MY_DEF_HERE */
	reg = sdhci_readl(host, SDHCI_SYS_OP_CTRL);
#endif /* MY_DEF_HERE */
	/* Get the bit shift basing on the SDHC index */
#if defined(MY_DEF_HERE)
	mask = (0x1 << (XENON_SDCLK_IDLEOFF_ENABLE_SHIFT + sdhc_id));
#else /* MY_DEF_HERE */
	mask = (0x1 << (SDHCI_SDCLK_IDLEOFF_ENABLE_SHIFT + sdhc_id));
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
	reg = sdhci_readl(host, SDHC_SYS_OP_CTRL);
	/* Get the bit shift basing on the slot index */
	mask = (0x1 << (SDCLK_IDLEOFF_ENABLE_SHIFT + slot_idx));
#endif /* MY_DEF_HERE */
	if (enable)
		reg |= mask;
	else
		reg &= ~mask;

#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
	sdhci_writel(host, reg, XENON_SYS_OP_CTRL);
#else /* MY_DEF_HERE */
	sdhci_writel(host, reg, SDHCI_SYS_OP_CTRL);
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
	sdhci_writel(host, reg, SDHC_SYS_OP_CTRL);
#endif /* MY_DEF_HERE */
}

/* Enable/Disable the Auto Clock Gating function */
static void xenon_set_acg(struct sdhci_host *host, bool enable)
{
	u32 reg;

#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
	reg = sdhci_readl(host, XENON_SYS_OP_CTRL);
#else /* MY_DEF_HERE */
	reg = sdhci_readl(host, SDHCI_SYS_OP_CTRL);
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
	reg = sdhci_readl(host, SDHC_SYS_OP_CTRL);
#endif /* MY_DEF_HERE */
	if (enable)
#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
		reg &= ~XENON_AUTO_CLKGATE_DISABLE_MASK;
#else /* MY_DEF_HERE */
		reg &= ~SDHCI_AUTO_CLKGATE_DISABLE_MASK;
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
		reg &= ~AUTO_CLKGATE_DISABLE_MASK;
#endif /* MY_DEF_HERE */
	else
#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
		reg |= XENON_AUTO_CLKGATE_DISABLE_MASK;
	sdhci_writel(host, reg, XENON_SYS_OP_CTRL);
#else /* MY_DEF_HERE */
		reg |= SDHCI_AUTO_CLKGATE_DISABLE_MASK;
	sdhci_writel(host, reg, SDHCI_SYS_OP_CTRL);
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
		reg |= AUTO_CLKGATE_DISABLE_MASK;
	sdhci_writel(host, reg, SDHC_SYS_OP_CTRL);
#endif /* MY_DEF_HERE */
}

#if defined(MY_DEF_HERE)
/* Enable this SDHC */
static void xenon_enable_sdhc(struct sdhci_host *host,
			      unsigned char sdhc_id)
#else /* MY_DEF_HERE */
/* Enable this slot */
static void xenon_enable_slot(struct sdhci_host *host,
			unsigned char slot_idx)
#endif /* MY_DEF_HERE */
{
	u32 reg;

#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
	reg = sdhci_readl(host, XENON_SYS_OP_CTRL);
	reg |= (BIT(sdhc_id) << XENON_SLOT_ENABLE_SHIFT);
	sdhci_writel(host, reg, XENON_SYS_OP_CTRL);
#else /* MY_DEF_HERE */
	reg = sdhci_readl(host, SDHCI_SYS_OP_CTRL);
	reg |= (BIT(sdhc_id) << SDHCI_SLOT_ENABLE_SHIFT);
	sdhci_writel(host, reg, SDHCI_SYS_OP_CTRL);
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
	reg = sdhci_readl(host, SDHC_SYS_OP_CTRL);
	reg |= ((0x1 << slot_idx) << SLOT_ENABLE_SHIFT);
	sdhci_writel(host, reg, SDHC_SYS_OP_CTRL);
#endif /* MY_DEF_HERE */

	/*
#if defined(MY_DEF_HERE)
	 * Manually set the flag which all the card types require,
#else  // MY_DEF_HERE
	 * Manually set the flag which all the slots require,
#endif // MY_DEF_HERE
	 * including SD, eMMC, SDIO
	 */
	host->mmc->caps |= MMC_CAP_WAIT_WHILE_BUSY;
}

#if defined(MY_DEF_HERE)
/* Disable this SDHC */
static void xenon_disable_sdhc(struct sdhci_host *host,
			       unsigned char sdhc_id)
#else /* MY_DEF_HERE */
/* Disable this slot */
static void xenon_disable_slot(struct sdhci_host *host,
			unsigned char slot_idx)
#endif /* MY_DEF_HERE */
{
	u32 reg;

#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
	reg = sdhci_readl(host, XENON_SYS_OP_CTRL);
	reg &= ~(BIT(sdhc_id) << XENON_SLOT_ENABLE_SHIFT);
	sdhci_writel(host, reg, XENON_SYS_OP_CTRL);
#else /* MY_DEF_HERE */
	reg = sdhci_readl(host, SDHCI_SYS_OP_CTRL);
	reg &= ~(BIT(sdhc_id) << SDHCI_SLOT_ENABLE_SHIFT);
	sdhci_writel(host, reg, SDHCI_SYS_OP_CTRL);
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
	reg = sdhci_readl(host, SDHC_SYS_OP_CTRL);
	reg &= ~((0x1 << slot_idx) << SLOT_ENABLE_SHIFT);
	sdhci_writel(host, reg, SDHC_SYS_OP_CTRL);
#endif /* MY_DEF_HERE */
}

/* Enable Parallel Transfer Mode */
#if defined(MY_DEF_HERE)
static void xenon_enable_sdhc_parallel_tran(struct sdhci_host *host,
					    unsigned char sdhc_id)
#else /* MY_DEF_HERE */
static void xenon_enable_slot_parallel_tran(struct sdhci_host *host,
			unsigned char slot_idx)
#endif /* MY_DEF_HERE */
{
	u32 reg;

#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
	reg = sdhci_readl(host, XENON_SYS_EXT_OP_CTRL);
#else /* MY_DEF_HERE */
	reg = sdhci_readl(host, SDHCI_SYS_EXT_OP_CTRL);
#endif /* MY_DEF_HERE */
	reg |= BIT(sdhc_id);
#if defined(MY_DEF_HERE)
	sdhci_writel(host, reg, XENON_SYS_EXT_OP_CTRL);
#else /* MY_DEF_HERE */
	sdhci_writel(host, reg, SDHCI_SYS_EXT_OP_CTRL);
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
	reg = sdhci_readl(host, SDHC_SYS_EXT_OP_CTRL);
	reg |= (0x1 << slot_idx);
	sdhci_writel(host, reg, SDHC_SYS_EXT_OP_CTRL);
#endif /* MY_DEF_HERE */
}

#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
/* Mask command conflict error */
static void xenon_mask_cmd_conflict_err(struct sdhci_host *host)
{
	u32  reg;

	reg = sdhci_readl(host, XENON_SYS_EXT_OP_CTRL);
	reg |= XENON_MASK_CMD_CONFLICT_ERR;
	sdhci_writel(host, reg, XENON_SYS_EXT_OP_CTRL);
}

static void xenon_sdhc_retune_setup(struct sdhci_host *host)
#else /* MY_DEF_HERE */
static void xenon_sdhc_tuning_setup(struct sdhci_host *host)
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
static void xenon_slot_tuning_setup(struct sdhci_host *host)
#endif /* MY_DEF_HERE */
{
#if defined(MY_DEF_HERE)
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_xenon_priv *priv = sdhci_pltfm_priv(pltfm_host);
#endif /* MY_DEF_HERE */
	u32 reg;

	/* Disable the Re-Tuning Request functionality */
#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
	reg = sdhci_readl(host, XENON_SLOT_RETUNING_REQ_CTRL);
	reg &= ~XENON_RETUNING_COMPATIBLE;
	sdhci_writel(host, reg, XENON_SLOT_RETUNING_REQ_CTRL);
#else /* MY_DEF_HERE */
	reg = sdhci_readl(host, SDHCI_SLOT_RETUNING_REQ_CTRL);
	reg &= ~SDHCI_RETUNING_COMPATIBLE;
	sdhci_writel(host, reg, SDHCI_SLOT_RETUNING_REQ_CTRL);
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
	reg = sdhci_readl(host, SDHC_SLOT_RETUNING_REQ_CTRL);
	reg &= ~RETUNING_COMPATIBLE;
	sdhci_writel(host, reg, SDHC_SLOT_RETUNING_REQ_CTRL);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	/* Disable the Re-tuning Interrupt */
#else /* MY_DEF_HERE */
	/* Disable the Re-tuning Event Signal Enable */
#endif /* MY_DEF_HERE */
	reg = sdhci_readl(host, SDHCI_SIGNAL_ENABLE);
	reg &= ~SDHCI_INT_RETUNE;
	sdhci_writel(host, reg, SDHCI_SIGNAL_ENABLE);
#if defined(MY_DEF_HERE)
	reg = sdhci_readl(host, SDHCI_INT_ENABLE);
	reg &= ~SDHCI_INT_RETUNE;
	sdhci_writel(host, reg, SDHCI_INT_ENABLE);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	/* Force to use Tuning Mode 1 */
	host->tuning_mode = SDHCI_TUNING_MODE_1;
	/* Set re-tuning period */
	host->tuning_count = 1 << (priv->tuning_count - 1);
#else /* MY_DEF_HERE */
	/* Disable Auto-retuning */
	reg = sdhci_readl(host, SDHC_SLOT_AUTO_RETUNING_CTRL);
	reg &= ~ENABLE_AUTO_RETUNING;
	sdhci_writel(host, reg, SDHC_SLOT_AUTO_RETUNING_CTRL);
#endif /* MY_DEF_HERE */
}

/*
 * Operations inside struct sdhci_ops
 */
/* Recover the Register Setting cleared during SOFTWARE_RESET_ALL */
static void sdhci_xenon_reset_exit(struct sdhci_host *host,
#if defined(MY_DEF_HERE)
				   unsigned char sdhc_id, u8 mask)
#else /* MY_DEF_HERE */
					unsigned char slot_idx, u8 mask)
#endif /* MY_DEF_HERE */
{
	/* Only SOFTWARE RESET ALL will clear the register setting */
	if (!(mask & SDHCI_RESET_ALL))
		return;

#if defined(MY_DEF_HERE)
	/* Disable tuning request and auto-retuning again */
#if defined(MY_DEF_HERE)
	xenon_sdhc_retune_setup(host);
#else /* MY_DEF_HERE */
	xenon_sdhc_tuning_setup(host);
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
	/* Disable tuning request and auto-retuing again */
	xenon_slot_tuning_setup(host);
#endif /* MY_DEF_HERE */

	xenon_set_acg(host, true);

#if defined(MY_DEF_HERE)
	xenon_set_sdclk_off_idle(host, sdhc_id, false);
#else /* MY_DEF_HERE */
	xenon_set_sdclk_off_idle(host, slot_idx, false);
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)

	xenon_mask_cmd_conflict_err(host);
#endif /* MY_DEF_HERE */
}

static void sdhci_xenon_reset(struct sdhci_host *host, u8 mask)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_xenon_priv *priv = sdhci_pltfm_priv(pltfm_host);

	sdhci_reset(host, mask);
#if defined(MY_DEF_HERE)
	sdhci_xenon_reset_exit(host, priv->sdhc_id, mask);
#else /* MY_DEF_HERE */
	sdhci_xenon_reset_exit(host, priv->slot_idx, mask);
}

static void xenon_platform_init(struct sdhci_host *host)
{
	xenon_set_acg(host, false);
#endif /* MY_DEF_HERE */
}

/*
#if defined(MY_DEF_HERE)
 * Xenon defines different values for HS200 and HS400
#else  // MY_DEF_HERE
 * Xenon defines different values for HS200 and SDR104
#endif // MY_DEF_HERE
 * in Host_Control_2
 */
static void xenon_set_uhs_signaling(struct sdhci_host *host,
				unsigned int timing)
{
	u16 ctrl_2;

	ctrl_2 = sdhci_readw(host, SDHCI_HOST_CONTROL2);
	/* Select Bus Speed Mode for host */
	ctrl_2 &= ~SDHCI_CTRL_UHS_MASK;
	if (timing == MMC_TIMING_MMC_HS200)
#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
		ctrl_2 |= XENON_CTRL_HS200;
#else /* MY_DEF_HERE */
		ctrl_2 |= SDHCI_XENON_CTRL_HS200;
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
		ctrl_2 |= XENON_SDHCI_CTRL_HS200;
#endif /* MY_DEF_HERE */
	else if (timing == MMC_TIMING_UHS_SDR104)
		ctrl_2 |= SDHCI_CTRL_UHS_SDR104;
	else if (timing == MMC_TIMING_UHS_SDR12)
		ctrl_2 |= SDHCI_CTRL_UHS_SDR12;
	else if (timing == MMC_TIMING_UHS_SDR25)
		ctrl_2 |= SDHCI_CTRL_UHS_SDR25;
	else if (timing == MMC_TIMING_UHS_SDR50)
		ctrl_2 |= SDHCI_CTRL_UHS_SDR50;
	else if ((timing == MMC_TIMING_UHS_DDR50) ||
		 (timing == MMC_TIMING_MMC_DDR52))
		ctrl_2 |= SDHCI_CTRL_UHS_DDR50;
	else if (timing == MMC_TIMING_MMC_HS400)
#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
		ctrl_2 |= XENON_CTRL_HS400;
#else /* MY_DEF_HERE */
		ctrl_2 |= SDHCI_XENON_CTRL_HS400;
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
		ctrl_2 |= XENON_SDHCI_CTRL_HS400;
#endif /* MY_DEF_HERE */
	sdhci_writew(host, ctrl_2, SDHCI_HOST_CONTROL2);
}

static const struct sdhci_ops sdhci_xenon_ops = {
	.set_clock		= sdhci_set_clock,
	.set_bus_width		= sdhci_set_bus_width,
	.reset			= sdhci_xenon_reset,
	.set_uhs_signaling	= xenon_set_uhs_signaling,
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	.platform_init		= xenon_platform_init,
#endif /* MY_DEF_HERE */
	.get_max_clock		= sdhci_pltfm_clk_get_max_clock,
};

static const struct sdhci_pltfm_data sdhci_xenon_pdata = {
	.ops = &sdhci_xenon_ops,
	.quirks = SDHCI_QUIRK_NO_ENDATTR_IN_NOPDESC |
#if defined(MY_DEF_HERE)
// do nothing
#else /* MY_DEF_HERE */
			SDHCI_QUIRK_MULTIBLOCK_READ_ACMD12 |
#endif /* MY_DEF_HERE */
			SDHCI_QUIRK_NO_SIMULT_VDD_AND_POWER |
			SDHCI_QUIRK_CAP_CLOCK_BASE_BROKEN,
#if defined(MY_DEF_HERE)
// do nothing
#else /* MY_DEF_HERE */
	/*
	 * Add SOC specific quirks in the above .quirks, .quirks2
	 * fields.
	 */
#endif /* MY_DEF_HERE */
};

/*
 * Xenon Specific Operations in mmc_host_ops
 */
static void xenon_set_ios(struct mmc_host *mmc, struct mmc_ios *ios)
{
	struct sdhci_host *host = mmc_priv(mmc);
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_xenon_priv *priv = sdhci_pltfm_priv(pltfm_host);
	unsigned long flags;
#if defined(MY_DEF_HERE)
	u32 reg;
#endif /* MY_DEF_HERE */

	/*
	 * HS400/HS200/eMMC HS doesn't have Preset Value register.
	 * However, sdhci_set_ios will read HS400/HS200 Preset register.
	 * Disable Preset Value register for HS400/HS200.
	 * eMMC HS with preset_enabled set will trigger a bug in
	 * get_preset_value().
	 */
	spin_lock_irqsave(&host->lock, flags);
	if ((ios->timing == MMC_TIMING_MMC_HS400) ||
		(ios->timing == MMC_TIMING_MMC_HS200) ||
		(ios->timing == MMC_TIMING_MMC_HS)) {
		host->preset_enabled = false;
		host->quirks2 |= SDHCI_QUIRK2_PRESET_VALUE_BROKEN;
#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
		host->flags &= ~SDHCI_PV_ENABLED;
#endif /* MY_DEF_HERE */

		reg = sdhci_readw(host, SDHCI_HOST_CONTROL2);
		reg &= ~SDHCI_CTRL_PRESET_VAL_ENABLE;
		sdhci_writew(host, reg, SDHCI_HOST_CONTROL2);
	} else {
#else /* MY_DEF_HERE */
	} else
#endif /* MY_DEF_HERE */
		host->quirks2 &= ~SDHCI_QUIRK2_PRESET_VALUE_BROKEN;
#if defined(MY_DEF_HERE)
	}
#endif /* MY_DEF_HERE */
	spin_unlock_irqrestore(&host->lock, flags);

	sdhci_set_ios(mmc, ios);
	xenon_phy_adj(host, ios);

#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
	if (host->clock > XENON_DEFAULT_SDCLK_FREQ) {
#else /* MY_DEF_HERE */
	if (host->clock > SDHCI_DEFAULT_SDCLK_FREQ) {
#endif /* MY_DEF_HERE */
		spin_lock_irqsave(&host->lock, flags);
		xenon_set_sdclk_off_idle(host, priv->sdhc_id, true);
		spin_unlock_irqrestore(&host->lock, flags);
	}
#else /* MY_DEF_HERE */
	if (host->clock > DEFAULT_SDCLK_FREQ)
		xenon_set_sdclk_off_idle(host, priv->slot_idx, true);
#endif /* MY_DEF_HERE */
}

#if defined(MY_DEF_HERE)
static int xenon_emmc_signal_voltage_switch(struct mmc_host *mmc,
					    struct mmc_ios *ios)
#else /* MY_DEF_HERE */
static int __emmc_signal_voltage_switch(struct mmc_host *mmc,
				const unsigned char signal_voltage)
#endif /* MY_DEF_HERE */
{
#if defined(MY_DEF_HERE)
	unsigned char voltage = ios->signal_voltage;
#else /* MY_DEF_HERE */
	u32 ctrl;
	unsigned char voltage_code;
#endif /* MY_DEF_HERE */
	struct sdhci_host *host = mmc_priv(mmc);
#if defined(MY_DEF_HERE)
	unsigned char voltage_code;
	u32 ctrl;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	if ((voltage == MMC_SIGNAL_VOLTAGE_330) ||
	    (voltage == MMC_SIGNAL_VOLTAGE_180)) {
		if (voltage == MMC_SIGNAL_VOLTAGE_330)
#if defined(MY_DEF_HERE)
			voltage_code = XENON_EMMC_VCCQ_3_3V;
#else /* MY_DEF_HERE */
			voltage_code = SDHCI_EMMC_VCCQ_3_3V;
#endif /* MY_DEF_HERE */
		else if (voltage == MMC_SIGNAL_VOLTAGE_180)
#if defined(MY_DEF_HERE)
			voltage_code = XENON_EMMC_VCCQ_1_8V;
#else /* MY_DEF_HERE */
			voltage_code = SDHCI_EMMC_VCCQ_1_8V;
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
	if (signal_voltage == MMC_SIGNAL_VOLTAGE_330)
		voltage_code = eMMC_VCCQ_3_3V;
	else if (signal_voltage == MMC_SIGNAL_VOLTAGE_180)
		voltage_code = eMMC_VCCQ_1_8V;
	else
		return -EINVAL;
#endif /* MY_DEF_HERE */

	/*
	 * This host is for eMMC, XENON self-defined
#if defined(MY_DEF_HERE)
	 * eMMC control register should be accessed
#else  // MY_DEF_HERE
	 * eMMC slot control register should be accessed
#endif // MY_DEF_HERE
	 * instead of Host Control 2
	 */
#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
		ctrl = sdhci_readl(host, XENON_SLOT_EMMC_CTRL);
		ctrl &= ~XENON_EMMC_VCCQ_MASK;
#else /* MY_DEF_HERE */
		ctrl = sdhci_readl(host, SDHCI_SLOT_EMMC_CTRL);
		ctrl &= ~SDHCI_EMMC_VCCQ_MASK;
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
	ctrl = sdhci_readl(host, SDHC_SLOT_eMMC_CTRL);
	ctrl &= ~eMMC_VCCQ_MASK;
#endif /* MY_DEF_HERE */
	ctrl |= voltage_code;
#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
		sdhci_writel(host, ctrl, XENON_SLOT_EMMC_CTRL);
#else /* MY_DEF_HERE */
		sdhci_writel(host, ctrl, SDHCI_SLOT_EMMC_CTRL);
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
	sdhci_writel(host, ctrl, SDHC_SLOT_eMMC_CTRL);
#endif /* MY_DEF_HERE */

	/* There is no standard to determine this waiting period */
	usleep_range(1000, 2000);

	/* Check whether io voltage switch is done */
#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
		ctrl = sdhci_readl(host, XENON_SLOT_EMMC_CTRL);
		ctrl &= XENON_EMMC_VCCQ_MASK;
#else /* MY_DEF_HERE */
		ctrl = sdhci_readl(host, SDHCI_SLOT_EMMC_CTRL);
		ctrl &= SDHCI_EMMC_VCCQ_MASK;
#endif /* MY_DEF_HERE */
		/*
		 * This bit is set only when regulator feeds back
		 * the voltage switch results to Xenon SDHC.
		 * However, in actaul implementation, regulator might not
		 * provide this feedback.
		 * Thus we shall not rely on this bit to determine
		 * if switch failed.
		 * If the bit is not set, just throw a message.
		 * Besides, error code should not be returned.
		 */
#else /* MY_DEF_HERE */
	ctrl = sdhci_readl(host, SDHC_SLOT_eMMC_CTRL);
	ctrl &= eMMC_VCCQ_MASK;
	/*
	 * This bit is set only when regulator feedbacks the voltage switch
	 * results to Xenon SDHC.
	 * However, in actaul implementation, regulator might not provide
	 * this feedback.
	 * Thus we shall not rely on this bit to determine if switch failed.
	 * If the bit is not set, just throw a warning.
	 * Besides, error code should neither be returned.
	 */
#endif /* MY_DEF_HERE */
	if (ctrl != voltage_code)
#if defined(MY_DEF_HERE)
			dev_info(mmc_dev(mmc), "fail to detect eMMC signal voltage stable\n");
#else /* MY_DEF_HERE */
		pr_info("%s: Xenon fail to detect eMMC signal voltage stable\n",
					mmc_hostname(mmc));
#endif /* MY_DEF_HERE */
	return 0;
#if defined(MY_DEF_HERE)
	}
#else /* MY_DEF_HERE */
}

static int xenon_emmc_signal_voltage_switch(struct mmc_host *mmc,
					struct mmc_ios *ios)
{
	unsigned char voltage = ios->signal_voltage;

	if ((voltage == MMC_SIGNAL_VOLTAGE_330) ||
		(voltage == MMC_SIGNAL_VOLTAGE_180))
		return __emmc_signal_voltage_switch(mmc, voltage);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	dev_err(mmc_dev(mmc), "Unsupported signal voltage: %d\n", voltage);
#else /* MY_DEF_HERE */
	pr_err("%s: Xenon Unsupported signal voltage: %d\n",
				mmc_hostname(mmc), voltage);
#endif /* MY_DEF_HERE */
	return -EINVAL;
}

static int xenon_start_signal_voltage_switch(struct mmc_host *mmc,
					     struct mmc_ios *ios)
{
	struct sdhci_host *host = mmc_priv(mmc);
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_xenon_priv *priv = sdhci_pltfm_priv(pltfm_host);

	/*
	 * Before SD/SDIO set signal voltage, SD bus clock should be
	 * disabled. However, sdhci_set_clock will also disable the Internal
	 * clock in mmc_set_signal_voltage().
	 * If Internal clock is disabled, the 3.3V/1.8V bit can not be updated.
	 * Thus here manually enable internal clock.
	 *
#if defined(MY_DEF_HERE)
	 * After switch completes, it is unnecessary to disable internal clock,
#else /* MY_DEF_HERE */
	 * After switch completes, it is unnessary to disable internal clock,
#endif /* MY_DEF_HERE */
	 * since keeping internal clock active obeys SD spec.
	 */
	enable_xenon_internal_clk(host);

#if defined(MY_DEF_HERE)
// do nothing
#else /* MY_DEF_HERE */
	if (priv->card_candidate) {
		if (mmc_card_mmc(priv->card_candidate)) {
			/* Set SoC PAD register for MMC PHY voltage */
#endif /* MY_DEF_HERE */
			xenon_soc_pad_ctrl(host, ios->signal_voltage);

#if defined(MY_DEF_HERE)
	if (priv->init_card_type == MMC_TYPE_MMC)
#endif /* MY_DEF_HERE */
			return xenon_emmc_signal_voltage_switch(mmc, ios);
#if defined(MY_DEF_HERE)
// do nothing
#else /* MY_DEF_HERE */
		}
	}
#endif /* MY_DEF_HERE */

	return sdhci_start_signal_voltage_switch(mmc, ios);
}

/*
#if defined(MY_DEF_HERE)
 * Update card type.
 * priv->init_card_type will be used in PHY timing adjustment.
#else  // MY_DEF_HERE
 * After determining the slot is used for SDIO,
 * some addtional task is required.
#endif // MY_DEF_HERE
 */
static void xenon_init_card(struct mmc_host *mmc, struct mmc_card *card)
{
	struct sdhci_host *host = mmc_priv(mmc);
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	u32 reg;
	u8 slot_idx;
#endif /* MY_DEF_HERE */
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_xenon_priv *priv = sdhci_pltfm_priv(pltfm_host);

#if defined(MY_DEF_HERE)
	/* Update card type*/
	priv->init_card_type = card->type;
}

static int xenon_execute_tuning(struct mmc_host *mmc, u32 opcode)
{
	struct sdhci_host *host = mmc_priv(mmc);

	if (host->timing == MMC_TIMING_UHS_DDR50)
		return 0;

#if defined(MY_DEF_HERE)
	/*
	 * Currently force Xenon driver back to support mode 1 only,
	 * even though Xenon might claim to support mode 2 or mode 3.
	 * It requires more time to test mode 2/mode 3 on more platforms.
	 */
	if (host->tuning_mode != SDHCI_TUNING_MODE_1)
		xenon_sdhc_retune_setup(host);

#endif /* MY_DEF_HERE */
	return sdhci_execute_tuning(mmc, opcode);
}
#else /* MY_DEF_HERE */
	/* Link the card for delay adjustment */
	priv->card_candidate = card;
	/* Set Xenon tuning */
	xenon_set_tuning_mode(host);
	xenon_set_tuning_count(host, priv->tuning_count);

	slot_idx = priv->slot_idx;
	if (!mmc_card_sdio(card)) {
		/* Re-enable the Auto-CMD12 cap flag. */
		host->quirks |= SDHCI_QUIRK_MULTIBLOCK_READ_ACMD12;
		host->flags |= SDHCI_AUTO_CMD12;

		/* Clear SDIO Card Insterted indication */
		reg = sdhci_readl(host, SDHC_SYS_CFG_INFO);
		reg &= ~(1 << (slot_idx + SLOT_TYPE_SDIO_SHIFT));
		sdhci_writel(host, reg, SDHC_SYS_CFG_INFO);

		if (mmc_card_mmc(card)) {
			mmc->caps |= MMC_CAP_NONREMOVABLE | MMC_CAP_1_8V_DDR;
			/*
			 * Force to clear BUS_TEST to
			 * skip bus_test_pre and bus_test_post
			 */
			mmc->caps &= ~MMC_CAP_BUS_WIDTH_TEST;
			mmc->caps2 |= MMC_CAP2_HS400_1_8V |
				MMC_CAP2_HC_ERASE_SZ | MMC_CAP2_PACKED_CMD;
		}
		/* Xenon SD doesn't support DDR50 tuning.*/
		if (mmc_card_sd(card))
			mmc->caps2 |= MMC_CAP2_NO_DDR50_TUNING;
	} else {
		/*
		 * Delete the Auto-CMD12 cap flag.
		 * Otherwise, when sending multi-block CMD53,
		 * Driver will set Transfer Mode Register to enable Auto CMD12.
		 * However, SDIO device cannot recognize CMD12.
		 * Thus SDHC will time-out for waiting for CMD12 response.
		 */
		host->quirks &= ~SDHCI_QUIRK_MULTIBLOCK_READ_ACMD12;
		host->flags &= ~SDHCI_AUTO_CMD12;
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
static void xenon_enable_sdio_irq(struct mmc_host *mmc, int enable)
{
	struct sdhci_host *host = mmc_priv(mmc);
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_xenon_priv *priv = sdhci_pltfm_priv(pltfm_host);
	u32 reg;
	u8 sdhc_id = priv->sdhc_id;

	sdhci_enable_sdio_irq(mmc, enable);

	if (enable) {
#endif /* MY_DEF_HERE */
		/*
#if defined(MY_DEF_HERE)
		 * Set SDIO Card Inserted indication
		 * to enable detecting SDIO async irq.
#else  // MY_DEF_HERE
		 * Set SDIO Card Insterted indication
		 * to inform that the current slot is for SDIO
#endif // MY_DEF_HERE
		 */
#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
		reg = sdhci_readl(host, XENON_SYS_CFG_INFO);
		reg |= (1 << (sdhc_id + XENON_SLOT_TYPE_SDIO_SHIFT));
		sdhci_writel(host, reg, XENON_SYS_CFG_INFO);
#else /* MY_DEF_HERE */
		reg = sdhci_readl(host, SDHCI_SYS_CFG_INFO);
		reg |= (1 << (sdhc_id + SDHCI_SLOT_TYPE_SDIO_SHIFT));
		sdhci_writel(host, reg, SDHCI_SYS_CFG_INFO);
#endif /* MY_DEF_HERE */
	} else {
		/* Clear SDIO Card Inserted indication */
#if defined(MY_DEF_HERE)
		reg = sdhci_readl(host, XENON_SYS_CFG_INFO);
		reg &= ~(1 << (sdhc_id + XENON_SLOT_TYPE_SDIO_SHIFT));
		sdhci_writel(host, reg, XENON_SYS_CFG_INFO);
#else /* MY_DEF_HERE */
		reg = sdhci_readl(host, SDHCI_SYS_CFG_INFO);
		reg &= ~(1 << (sdhc_id + SDHCI_SLOT_TYPE_SDIO_SHIFT));
		sdhci_writel(host, reg, SDHCI_SYS_CFG_INFO);
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
		reg = sdhci_readl(host, SDHC_SYS_CFG_INFO);
		reg |= (1 << (slot_idx + SLOT_TYPE_SDIO_SHIFT));
		sdhci_writel(host, reg, SDHC_SYS_CFG_INFO);
#endif /* MY_DEF_HERE */
	}
}

static void xenon_replace_mmc_host_ops(struct sdhci_host *host)
{
	host->mmc_host_ops.set_ios = xenon_set_ios;
	host->mmc_host_ops.start_signal_voltage_switch =
			xenon_start_signal_voltage_switch;
	host->mmc_host_ops.init_card = xenon_init_card;
#if defined(MY_DEF_HERE)
	host->mmc_host_ops.execute_tuning = xenon_execute_tuning;
	host->mmc_host_ops.enable_sdio_irq = xenon_enable_sdio_irq;
}

/*
#if defined(MY_DEF_HERE)
 * Parse Xenon specific DT properties:
 * init_card_type: check whether this SDHC is for eMMC
 * sdhc-id: the index of current SDHC.
 *	    Refer to XENON_SYS_CFG_INFO register
 * tun-count: the interval between re-tuning
#else /* MY_DEF_HERE */
 * Parse child node in Xenon DT.
 * Search for the following item(s):
 * - eMMC card type
#endif /* MY_DEF_HERE */
 */
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
static int xenon_child_node_of_parse(struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;
	struct sdhci_host *host = platform_get_drvdata(pdev);
	struct mmc_host *mmc = host->mmc;
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_xenon_priv *priv = sdhci_pltfm_priv(pltfm_host);
	struct device_node *child;
	int nr_child;

	priv->init_card_type = SDHCI_CARD_TYPE_UNKNOWN;

	nr_child = of_get_child_count(np);
	if (!nr_child)
		return 0;

	for_each_child_of_node(np, child) {
		if (of_device_is_compatible(child, "mmc-card"))	{
			priv->init_card_type = MMC_TYPE_MMC;
			mmc->caps |= MMC_CAP_NONREMOVABLE;

			/*
			 * Force to clear BUS_TEST to
			 * skip bus_test_pre and bus_test_post
			 */
			mmc->caps &= ~MMC_CAP_BUS_WIDTH_TEST;
			mmc->caps2 |= MMC_CAP2_HC_ERASE_SZ |
				      MMC_CAP2_PACKED_CMD |
				      MMC_CAP2_NO_SD |
				      MMC_CAP2_NO_SDIO;
		}
	}

	return 0;
#endif /* MY_DEF_HERE */
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
}

#endif /* MY_DEF_HERE */
static int xenon_probe_dt(struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;
	struct sdhci_host *host = platform_get_drvdata(pdev);
	struct mmc_host *mmc = host->mmc;
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_xenon_priv *priv = sdhci_pltfm_priv(pltfm_host);
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	int err;
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
	u32 sdhc_id, nr_sdhc;
#else /* MY_DEF_HERE */
	u32 slot_idx;
#endif /* MY_DEF_HERE */
	u32 tuning_count;

#if defined(MY_DEF_HERE)
	/* Disable HS200 on Armada AP806 */
	if (of_device_is_compatible(np, "marvell,armada-ap806-sdhci"))
		host->quirks2 |= SDHCI_QUIRK2_BROKEN_HS200;
#else /* MY_DEF_HERE */
	/* Standard MMC property */
	err = mmc_of_parse(mmc);
	if (err)
		return err;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	priv->init_card_type = XENON_CARD_TYPE_UNKNOWN;
	/* Check if mmc-card sub-node exists */
	if (mmc_of_parse_mmc_card(mmc)) {
		priv->init_card_type = MMC_TYPE_MMC;
		/*
		 * Force to clear BUS_TEST to
		 * skip bus_test_pre and bus_test_post
		 */
		mmc->caps &= ~MMC_CAP_BUS_WIDTH_TEST;
	}
#else /* MY_DEF_HERE */
	/* Standard SDHCI property */
	sdhci_get_of_property(pdev);

	/*
	 * Xenon Specific property:
#if defined(MY_DEF_HERE)
	 * init_card_type: check whether this SDHC is for eMMC
	 * sdhc-id: the index of current SDHC.
	 *	    Refer to SDHCI_SYS_CFG_INFO register
	 * tun-count: the interval between re-tuning
#else  // MY_DEF_HERE
	 * slotno: the index of slot. Refer to SDHC_SYS_CFG_INFO register
	 * tuning-count: the interval between re-tuning
	 * PHY type: "sdhc phy", "emmc phy 5.0" or "emmc phy 5.1"
#endif // MY_DEF_HERE
	 */
#if defined(MY_DEF_HERE)
	/* Parse child node, including checking emmc type */
	err = xenon_child_node_of_parse(pdev);
	if (err)
		return err;
#endif /* MY_DEF_HERE */

	priv->sdhc_id = 0x0;
	if (!of_property_read_u32(np, "marvell,xenon-sdhc-id", &sdhc_id)) {
#if defined(MY_DEF_HERE)
		nr_sdhc = sdhci_readl(host, XENON_SYS_CFG_INFO);
		nr_sdhc &= XENON_NR_SUPPORTED_SLOT_MASK;
#else /* MY_DEF_HERE */
		nr_sdhc = sdhci_readl(host, SDHCI_SYS_CFG_INFO);
		nr_sdhc &= SDHCI_NR_SUPPORTED_SLOT_MASK;
#endif /* MY_DEF_HERE */
		if (unlikely(sdhc_id > nr_sdhc)) {
			dev_err(mmc_dev(mmc), "SDHC Index %d exceeds Number of SDHCs %d\n",
				sdhc_id, nr_sdhc);
			return -EINVAL;
		}
	}
#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
	tuning_count = XENON_DEF_TUNING_COUNT;
#else /* MY_DEF_HERE */
	tuning_count = SDHCI_DEF_TUNING_COUNT;
#endif /* MY_DEF_HERE */
	if (!of_property_read_u32(np, "marvell,xenon-tun-count",
				  &tuning_count)) {
#if defined(MY_DEF_HERE)
		if (unlikely(tuning_count >= XENON_TMR_RETUN_NO_PRESENT)) {
#else /* MY_DEF_HERE */
		if (unlikely(tuning_count >= SDHCI_TMR_RETUN_NO_PRESENT)) {
#endif /* MY_DEF_HERE */
			dev_err(mmc_dev(mmc), "Wrong Re-tuning Count. Set default value %d\n",
#if defined(MY_DEF_HERE)
				XENON_DEF_TUNING_COUNT);
			tuning_count = XENON_DEF_TUNING_COUNT;
#else /* MY_DEF_HERE */
				SDHCI_DEF_TUNING_COUNT);
			tuning_count = SDHCI_DEF_TUNING_COUNT;
#endif /* MY_DEF_HERE */
		}
#else /* MY_DEF_HERE */
	if (!of_property_read_u32(np, "xenon,slotno", &slot_idx))
		priv->slot_idx = slot_idx & 0xff;
	else
		priv->slot_idx = 0x0;

	if (!of_property_read_u32(np, "xenon,tuning-count", &tuning_count)) {
		if (unlikely(tuning_count >= TMR_RETUN_NO_PRESENT)) {
			pr_err("%s: Wrong Re-tuning Count. Set default value %d\n",
				mmc_hostname(mmc), DEF_TUNING_COUNT);
			tuning_count = DEF_TUNING_COUNT;
#endif /* MY_DEF_HERE */
		}
#if defined(MY_DEF_HERE)
	priv->tuning_count = tuning_count;
#else /* MY_DEF_HERE */
		priv->tuning_count = tuning_count & 0xf;
	} else
		priv->tuning_count = DEF_TUNING_COUNT;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	return xenon_phy_parse_dt(np, host);
#else /* MY_DEF_HERE */
	err = xenon_phy_parse_dt(np, priv);
	return err;
#endif /* MY_DEF_HERE */
}

#if defined(MY_DEF_HERE)
static int xenon_sdhc_probe(struct sdhci_host *host)
#else /* MY_DEF_HERE */
static int xenon_slot_probe(struct sdhci_host *host)
#endif /* MY_DEF_HERE */
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_xenon_priv *priv = sdhci_pltfm_priv(pltfm_host);
#if defined(MY_DEF_HERE)
	u8 sdhc_id = priv->sdhc_id;
#else /* MY_DEF_HERE */
	u8 slot_idx = priv->slot_idx;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	/* Enable SDHC */
	xenon_enable_sdhc(host, sdhc_id);
#else /* MY_DEF_HERE */
	/* Enable slot */
	xenon_enable_slot(host, slot_idx);
#endif /* MY_DEF_HERE */

	/* Enable ACG */
	xenon_set_acg(host, true);

	/* Enable Parallel Transfer Mode */
#if defined(MY_DEF_HERE)
	xenon_enable_sdhc_parallel_tran(host, sdhc_id);
#else /* MY_DEF_HERE */
	xenon_enable_slot_parallel_tran(host, slot_idx);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
	xenon_mask_cmd_conflict_err(host);
#else /* MY_DEF_HERE */
	/* Set tuning functionality of this SDHC */
	xenon_sdhc_tuning_setup(host);
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
	priv->timing = MMC_TIMING_FAKE;
#endif /* MY_DEF_HERE */

	return 0;
}

#if defined(MY_DEF_HERE)
static void xenon_sdhc_remove(struct sdhci_host *host)
#else /* MY_DEF_HERE */
static void xenon_slot_remove(struct sdhci_host *host)
#endif /* MY_DEF_HERE */
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_xenon_priv *priv = sdhci_pltfm_priv(pltfm_host);
#if defined(MY_DEF_HERE)
	u8 sdhc_id = priv->sdhc_id;
#else /* MY_DEF_HERE */
	u8 slot_idx = priv->slot_idx;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	/* disable SDHC */
	xenon_disable_sdhc(host, sdhc_id);
#else /* MY_DEF_HERE */
	/* disable slot */
	xenon_disable_slot(host, slot_idx);
#endif /* MY_DEF_HERE */
}

static int sdhci_xenon_probe(struct platform_device *pdev)
{
	struct sdhci_pltfm_host *pltfm_host;
	struct sdhci_host *host;
	struct sdhci_xenon_priv *priv;
	int err;

	host = sdhci_pltfm_init(pdev, &sdhci_xenon_pdata,
		sizeof(struct sdhci_xenon_priv));
	if (IS_ERR(host))
		return PTR_ERR(host);

	pltfm_host = sdhci_priv(host);
	priv = sdhci_pltfm_priv(pltfm_host);

#if defined(MY_DEF_HERE)
	xenon_set_acg(host, false);

#endif /* MY_DEF_HERE */
	/*
	 * Link Xenon specific mmc_host_ops function,
	 * to replace standard ones in sdhci_ops.
	 */
	xenon_replace_mmc_host_ops(host);

	pltfm_host->clk = devm_clk_get(&pdev->dev, "core");
#if defined(MY_DEF_HERE)
	if (IS_ERR(pltfm_host->clk)) {
#else /* MY_DEF_HERE */
	if (!IS_ERR(pltfm_host->clk)) {
		err = clk_prepare_enable(pltfm_host->clk);
		if (err)
			goto free_pltfm;
	} else if (PTR_ERR(pltfm_host->clk) == -EPROBE_DEFER) {
		err = -EPROBE_DEFER;
		goto free_pltfm;
	} else {
		pr_err("%s: Failed to setup input clk.\n",
			mmc_hostname(host->mmc));
#endif /* MY_DEF_HERE */
		err = PTR_ERR(pltfm_host->clk);
#if defined(MY_DEF_HERE)
		dev_err(&pdev->dev, "Failed to setup input clk: %d\n", err);
#endif /* MY_DEF_HERE */
		goto free_pltfm;
	}
#if defined(MY_DEF_HERE)
	err = clk_prepare_enable(pltfm_host->clk);
#else /* MY_DEF_HERE */

	/*
	 * Some SOCs require additional clock to
	 * manage AXI bus clock.
	 * It is optional.
	 */
	priv->axi_clk = devm_clk_get(&pdev->dev, "axi");
	if (!IS_ERR(priv->axi_clk)) {
		err = clk_prepare_enable(priv->axi_clk);
#endif /* MY_DEF_HERE */
		if (err)
#if defined(MY_DEF_HERE)
		goto free_pltfm;
#else /* MY_DEF_HERE */
			goto err_clk;
	}
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	err = mmc_of_parse(host->mmc);
	if (err)
		goto err_clk;

	sdhci_get_of_property(pdev);

	/* Xenon specific dt parse */
#endif /* MY_DEF_HERE */
	err = xenon_probe_dt(pdev);
	if (err)
		goto err_clk;

#if defined(MY_DEF_HERE)
	err = xenon_sdhc_probe(host);
#else /* MY_DEF_HERE */
	err = xenon_slot_probe(host);
#endif /* MY_DEF_HERE */
	if (err)
		goto err_clk;

	err = sdhci_add_host(host);
	if (err)
#if defined(MY_DEF_HERE)
		goto remove_sdhc;
#else /* MY_DEF_HERE */
		goto remove_slot;

	/* Set tuning functionality of this slot */
	xenon_slot_tuning_setup(host);

	/* Initialize SoC PAD register for MMC PHY voltage
	 * For eMMC, it is set to 1.8V
	 * For SD/SDIO, it is set to 3.3V
	 */
	xenon_soc_pad_ctrl(host, MMC_SIGNAL_VOLTAGE_330);
#endif /* MY_DEF_HERE */

	return 0;

#if defined(MY_DEF_HERE)
remove_sdhc:
	xenon_sdhc_remove(host);
#else /* MY_DEF_HERE */
remove_slot:
	xenon_slot_remove(host);
#endif /* MY_DEF_HERE */
err_clk:
#if defined(MY_DEF_HERE)
// do nothing
#else /* MY_DEF_HERE */
	if (!IS_ERR(pltfm_host->clk))
#endif /* MY_DEF_HERE */
		clk_disable_unprepare(pltfm_host->clk);
#if defined(MY_DEF_HERE)
// do nothing
#else /* MY_DEF_HERE */
	if (!IS_ERR(priv->axi_clk))
		clk_disable_unprepare(priv->axi_clk);
#endif /* MY_DEF_HERE */
free_pltfm:
	sdhci_pltfm_free(pdev);
	return err;
}

static int sdhci_xenon_remove(struct platform_device *pdev)
{
	struct sdhci_host *host = platform_get_drvdata(pdev);
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	int dead = (readl(host->ioaddr + SDHCI_INT_STATUS) == 0xFFFFFFFF);
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
	struct sdhci_xenon_priv *priv = sdhci_pltfm_priv(pltfm_host);
	int dead = (readl(host->ioaddr + SDHCI_INT_STATUS) == 0xffffffff);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	xenon_sdhc_remove(host);
#else /* MY_DEF_HERE */
	xenon_slot_remove(host);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	sdhci_remove_host(host, 0);
#else /* MY_DEF_HERE */
	sdhci_remove_host(host, dead);
#endif /* MY_DEF_HERE */

	clk_disable_unprepare(pltfm_host->clk);
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	clk_disable_unprepare(priv->axi_clk);
#endif /* MY_DEF_HERE */

	sdhci_pltfm_free(pdev);

	return 0;
}

#if defined(MY_DEF_HERE)
#ifdef CONFIG_PM
static int sdhci_xenon_suspend(struct device *dev)
{
	int ret;
	struct sdhci_host *host = dev_get_drvdata(dev);
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);

	ret = sdhci_suspend_host(host);

	if (pltfm_host->clk)
		clk_disable_unprepare(pltfm_host->clk);

	return ret;
}

static int sdhci_xenon_resume(struct device *dev)
{
	int ret;
	struct sdhci_host *host = dev_get_drvdata(dev);
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);

	if (pltfm_host->clk)
		ret = clk_prepare_enable(pltfm_host->clk);

	ret = xenon_sdhc_probe(host);

	/* Initialize SoC PAD register for MMC PHY voltage
	 * For eMMC, it is set to 1.8V
	 * For SD/SDIO, it is set to 3.3V
	 */
	xenon_soc_pad_ctrl(host, MMC_SIGNAL_VOLTAGE_330);

	ret = sdhci_resume_host(host);

	return ret;
}

static const struct dev_pm_ops sdhci_xenon_pmops = {
	SET_SYSTEM_SLEEP_PM_OPS(sdhci_xenon_suspend, sdhci_xenon_resume)
};
#endif

#endif /* MY_DEF_HERE */
static const struct of_device_id sdhci_xenon_dt_ids[] = {
#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
	{ .compatible = "marvell,armada-ap806-sdhci",},
	{ .compatible = "marvell,armada-cp110-sdhci",},
#else /* MY_DEF_HERE */
	{ .compatible = "marvell,armada8k-sdhci",},
#endif /* MY_DEF_HERE */
	{ .compatible = "marvell,armada-3700-sdhci",},
#else /* MY_DEF_HERE */
	{ .compatible = "marvell,xenon-sdhci",},
#endif /* MY_DEF_HERE */
	{}
};
MODULE_DEVICE_TABLE(of, sdhci_xenon_dt_ids);

static struct platform_driver sdhci_xenon_driver = {
	.driver	= {
#if defined(MY_DEF_HERE)
		.name	= "xenon-sdhci",
#else /* MY_DEF_HERE */
		.name	= "mv-xenon-sdhci",
#endif /* MY_DEF_HERE */
		.of_match_table = sdhci_xenon_dt_ids,
#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
#ifdef CONFIG_PM
		.pm = &sdhci_xenon_pmops,
#endif
#else /* MY_DEF_HERE */
		.pm = &sdhci_pltfm_pmops,
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
		.pm = SDHCI_PLTFM_PMOPS,
#endif /* MY_DEF_HERE */
	},
	.probe	= sdhci_xenon_probe,
	.remove	= sdhci_xenon_remove,
};

module_platform_driver(sdhci_xenon_driver);

MODULE_DESCRIPTION("SDHCI platform driver for Marvell Xenon SDHC");
MODULE_AUTHOR("Hu Ziji <huziji@marvell.com>");
MODULE_LICENSE("GPL v2");
#endif /* MY_DEF_HERE */
