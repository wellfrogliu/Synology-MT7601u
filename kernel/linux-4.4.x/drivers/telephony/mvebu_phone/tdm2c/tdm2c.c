#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#if defined(MY_DEF_HERE)
/*******************************************************************************
 * Copyright (C) 2016 Marvell International Ltd.
 *
 * This software file (the "File") is owned and distributed by Marvell
 * International Ltd. and/or its affiliates ("Marvell") under the following
 * alternative licensing terms.  Once you have made an election to distribute the
 * File under one of the following license alternatives, please (i) delete this
 * introductory statement regarding license alternatives, (ii) delete the three
 * license alternatives that you have not elected to use and (iii) preserve the
 * Marvell copyright notice above.
 *
 * ********************************************************************************
 * Marvell Commercial License Option
 *
 * If you received this File from Marvell and you have entered into a commercial
 * license agreement (a "Commercial License") with Marvell, the File is licensed
 * to you under the terms of the applicable Commercial License.
 *
 * ********************************************************************************
 * Marvell GPL License Option
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 2 of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * ********************************************************************************
 * Marvell GNU General Public License FreeRTOS Exception
 *
 * If you received this File from Marvell, you may opt to use, redistribute and/or
 * modify this File in accordance with the terms and conditions of the Lesser
 * General Public License Version 2.1 plus the following FreeRTOS exception.
 * An independent module is a module which is not derived from or based on
 * FreeRTOS.
 * Clause 1:
 * Linking FreeRTOS statically or dynamically with other modules is making a
 * combined work based on FreeRTOS. Thus, the terms and conditions of the GNU
 * General Public License cover the whole combination.
 * As a special exception, the copyright holder of FreeRTOS gives you permission
 * to link FreeRTOS with independent modules that communicate with FreeRTOS solely
 * through the FreeRTOS API interface, regardless of the license terms of these
 * independent modules, and to copy and distribute the resulting combined work
 * under terms of your choice, provided that:
 * 1. Every copy of the combined work is accompanied by a written statement that
 * details to the recipient the version of FreeRTOS used and an offer by yourself
 * to provide the FreeRTOS source code (including any modifications you may have
 * made) should the recipient request it.
 * 2. The combined work is not itself an RTOS, scheduler, kernel or related
 * product.
 * 3. The independent modules add significant and primary functionality to
 * FreeRTOS and do not merely extend the existing functionality already present in
 * FreeRTOS.
 * Clause 2:
 * FreeRTOS may not be used for any competitive or comparative purpose, including
 * the publication of any form of run time or compile time metric, without the
 * express permission of Real Time Engineers Ltd. (this is the norm within the
 * industry and is intended to ensure information accuracy).
 *
 * ********************************************************************************
 * Marvell BSD License Option
 *
 * If you received this File from Marvell, you may opt to use, redistribute and/or
 * modify this File under the following licensing terms.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 *	* Redistributions of source code must retain the above copyright notice,
 *	  this list of conditions and the following disclaimer.
 *
 *	* Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in the
 *	  documentation and/or other materials provided with the distribution.
 *
 *	* Neither the name of Marvell nor the names of its contributors may be
 *	  used to endorse or promote products derived from this software without
 *	  specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "mv_phone.h"

#if defined(MY_DEF_HERE)
/* Main TDM structure definition */
struct tdm2c_dev {
	/* Resources */
	void __iomem *regs;
	struct device *dev;

	/* Buffers */
	u8 *rx_aggr_buff_virt;
	u8 *tx_aggr_buff_virt;

	/* Flags and counters */
	u16 rx_full;
	u16 tx_empty;
	u8 rx_int;
	u8 tx_int;
	bool enable;
	bool int_lock;
	int chan_stop_count;

	/* Parameters */
	u8 factor;
	enum mv_phone_pcm_format pcm_format;
	enum mv_phone_band_mode band_mode;

	/* Channels' data */
	struct tdm2c_ch_info *ch_info[MV_TDM2C_TOTAL_CHANNELS];

	/* Statistics */
	u32 int_rx_count;
	u32 int_tx_count;
	u32 int_rx0_count;
	u32 int_tx0_count;
	u32 int_rx1_count;
	u32 int_tx1_count;
	u32 int_rx0_miss;
	u32 int_tx0_miss;
	u32 int_rx1_miss;
	u32 int_tx1_miss;
	u32 pcm_restart_count;
#else /* MY_DEF_HERE */
/* Defines */
#define INT_SAMPLE			2
#define BUFF_IS_FULL			1
#define BUFF_IS_EMPTY			0
#define FIRST_INT			1
#define TOTAL_BUFFERS			2
#define MV_TDM_NEXT_BUFFER(buf)		((buf + 1) % TOTAL_BUFFERS)
#define MV_TDM_PREV_BUFFER(buf, step)	((TOTAL_BUFFERS + buf - step) % TOTAL_BUFFERS)
#define MV_TDM_CS			0
#define BUFF_INVALID			-1

/* TDM channel info structure */
struct tdm2c_ch_info {
	u8 ch;
	u8 *rxBuffVirt[TOTAL_BUFFERS], *txBuffVirt[TOTAL_BUFFERS];
	dma_addr_t rxBuffPhys[TOTAL_BUFFERS], txBuffPhys[TOTAL_BUFFERS];
	u8 rxBuffFull[TOTAL_BUFFERS], txBuffFull[TOTAL_BUFFERS];
	u8 rxCurrBuff, txCurrBuff;
	u8 rxFirst;
#endif /* MY_DEF_HERE */
};

#if defined(MY_DEF_HERE)
struct tdm2c_dev *tdm2c;
#else /* MY_DEF_HERE */
/* Globals */
static u8 *rx_aggr_buff_virt, *tx_aggr_buff_virt;
static u8 rx_int, tx_int;
static u16 rx_full, tx_empty;
static u8 tdm_enable;
static u8 spi_mode;
static u8 factor;
static enum mv_phone_pcm_format pcm_format;
static enum mv_phone_band_mode tdm_band_mode;
static struct tdm2c_ch_info *tdm_ch_info[MV_TDM2C_TOTAL_CHANNELS] = { NULL, NULL };
static u8 chan_stop_count;
static u8 int_lock;
static struct device *pdev;
static void __iomem *regs;

/* Stats */
static u32 int_rx_count;
static u32 int_tx_count;
static u32 int_rx0_count;
static u32 int_tx0_count;
static u32 int_rx1_count;
static u32 int_tx1_count;
static u32 int_rx0_miss;
static u32 int_tx0_miss;
static u32 int_rx1_miss;
static u32 int_tx1_miss;
static u32 pcm_restart_count;
#endif /* MY_DEF_HERE */

static void tdm2c_daisy_chain_mode_set(void)
{
#if defined(MY_DEF_HERE)
	while ((readl(tdm2c->regs + SPI_CTRL_REG) & SPI_STAT_MASK) == SPI_ACTIVE)
#else /* MY_DEF_HERE */
	while ((readl(regs + SPI_CTRL_REG) & SPI_STAT_MASK) == SPI_ACTIVE)
#endif /* MY_DEF_HERE */
		continue;
#if defined(MY_DEF_HERE)
	writel((0x80 << 8) | 0, tdm2c->regs + SPI_CODEC_CMD_LO_REG);
	writel(TRANSFER_BYTES(2) | ENDIANNESS_MSB_MODE | WR_MODE | CLK_SPEED_LO_DIV,
	       tdm2c->regs + SPI_CODEC_CTRL_REG);
	writel(readl(tdm2c->regs + SPI_CTRL_REG) | SPI_ACTIVE, tdm2c->regs + SPI_CTRL_REG);
#else /* MY_DEF_HERE */
	writel((0x80 << 8) | 0, regs + SPI_CODEC_CMD_LO_REG);
	writel(TRANSFER_BYTES(2) | ENDIANNESS_MSB_MODE | WR_MODE | CLK_SPEED_LO_DIV, regs + SPI_CODEC_CTRL_REG);
	writel(readl(regs + SPI_CTRL_REG) | SPI_ACTIVE, regs + SPI_CTRL_REG);
#endif /* MY_DEF_HERE */
	/* Poll for ready indication */
#if defined(MY_DEF_HERE)
	while ((readl(tdm2c->regs + SPI_CTRL_REG) & SPI_STAT_MASK) == SPI_ACTIVE)
#else /* MY_DEF_HERE */
	while ((readl(regs + SPI_CTRL_REG) & SPI_STAT_MASK) == SPI_ACTIVE)
#endif /* MY_DEF_HERE */
		continue;

#if defined(MY_DEF_HERE)
	dev_dbg(tdm2c->dev, "%s: Exit\n", __func__);
#else /* MY_DEF_HERE */
	dev_dbg(pdev, "%s: Exit\n", __func__);
#endif /* MY_DEF_HERE */
}

static int tdm2c_ch_init(u8 ch)
{
	struct tdm2c_ch_info *ch_info;
	u32 buff;

#if defined(MY_DEF_HERE)
	dev_dbg(tdm2c->dev, "%s: Enter, ch%d\n", __func__, ch);
#else /* MY_DEF_HERE */
	dev_dbg(pdev, "%s: Enter, ch%d\n", __func__, ch);
#endif /* MY_DEF_HERE */

	if (ch >= MV_TDM2C_TOTAL_CHANNELS) {
#if defined(MY_DEF_HERE)
		dev_err(tdm2c->dev, "%s: error, channel(%d) exceeds maximum(%d)\n",
#else /* MY_DEF_HERE */
		dev_err(pdev, "%s: error, channel(%d) exceeds maximum(%d)\n",
#endif /* MY_DEF_HERE */
			__func__, ch, MV_TDM2C_TOTAL_CHANNELS);
		return -EINVAL;
	}

#if defined(MY_DEF_HERE)
	tdm2c->ch_info[ch] = kmalloc(sizeof(struct tdm2c_ch_info), GFP_ATOMIC);
	if (!tdm2c->ch_info) {
		dev_err(tdm2c->dev, "%s: error malloc failed\n", __func__);
#else /* MY_DEF_HERE */
	tdm_ch_info[ch] = ch_info = kmalloc(sizeof(struct tdm2c_ch_info),
					    GFP_ATOMIC);
	if (!ch_info) {
		dev_err(pdev, "%s: error malloc failed\n", __func__);
#endif /* MY_DEF_HERE */
		return -ENOMEM;
	}

#if defined(MY_DEF_HERE)
	ch_info = tdm2c->ch_info[ch];
#endif /* MY_DEF_HERE */
	ch_info->ch = ch;

	/* Per channel TDM init */
	/* Disable channel (enable in pcm start) */
#if defined(MY_DEF_HERE)
	writel(CH_DISABLE, tdm2c->regs + CH_ENABLE_REG(ch));
#else /* MY_DEF_HERE */
	writel(CH_DISABLE, regs + CH_ENABLE_REG(ch));
#endif /* MY_DEF_HERE */
	/* Set total samples and int sample */
#if defined(MY_DEF_HERE)
	writel(CONFIG_CH_SAMPLE(tdm2c->band_mode, tdm2c->factor), tdm2c->regs + CH_SAMPLE_REG(ch));
#else /* MY_DEF_HERE */
	writel(CONFIG_CH_SAMPLE(tdm_band_mode, factor), regs + CH_SAMPLE_REG(ch));
#endif /* MY_DEF_HERE */

	for (buff = 0; buff < TOTAL_BUFFERS; buff++) {
		/* Buffers must be 32B aligned */
#if defined(MY_DEF_HERE)
		ch_info->rx_buff_virt[buff] = dma_alloc_coherent(tdm2c->dev,
				MV_TDM_CH_BUFF_SIZE(tdm2c->pcm_format, tdm2c->band_mode, tdm2c->factor),
				&(ch_info->rx_buff_phys[buff]), GFP_KERNEL);
		ch_info->rx_buff_full[buff] = BUFF_IS_EMPTY;

		ch_info->tx_buff_virt[buff] = dma_alloc_coherent(tdm2c->dev,
				MV_TDM_CH_BUFF_SIZE(tdm2c->pcm_format, tdm2c->band_mode, tdm2c->factor),
				&(ch_info->tx_buff_phys[buff]), GFP_KERNEL);
		ch_info->tx_buff_empty[buff] = BUFF_IS_FULL;

		memset(ch_info->tx_buff_virt[buff], 0,
				MV_TDM_CH_BUFF_SIZE(tdm2c->pcm_format, tdm2c->band_mode, tdm2c->factor));

		if (((ulong) ch_info->rx_buff_virt[buff] | ch_info->rx_buff_phys[buff] |
		     (ulong) ch_info->tx_buff_virt[buff] | ch_info->tx_buff_phys[buff]) & 0x1f) {
			dev_err(tdm2c->dev, "%s: error, unaligned buffer allocation\n", __func__);
#else /* MY_DEF_HERE */
		ch_info->rxBuffVirt[buff] = dma_alloc_coherent(pdev,
							      MV_TDM_CH_BUFF_SIZE(pcm_format, tdm_band_mode, factor),
							      &(ch_info->rxBuffPhys[buff]), GFP_KERNEL);
		ch_info->rxBuffFull[buff] = BUFF_IS_EMPTY;

		ch_info->txBuffVirt[buff] = dma_alloc_coherent(pdev,
							      MV_TDM_CH_BUFF_SIZE(pcm_format, tdm_band_mode, factor),
							      &(ch_info->txBuffPhys[buff]), GFP_KERNEL);
		ch_info->txBuffFull[buff] = BUFF_IS_FULL;

		memset(ch_info->txBuffVirt[buff], 0, MV_TDM_CH_BUFF_SIZE(pcm_format, tdm_band_mode, factor));

		if (((ulong) ch_info->rxBuffVirt[buff] | ch_info->rxBuffPhys[buff] |
		     (ulong) ch_info->txBuffVirt[buff] | ch_info->txBuffPhys[buff]) & 0x1f) {
			dev_err(pdev, "%s: error, unaligned buffer allocation\n", __func__);
#endif /* MY_DEF_HERE */
		}
	}

	return 0;
}

static inline int tdm2c_ch_tx_low(u8 ch)
{
	u32 max_poll = 0;
#if defined(MY_DEF_HERE)
	struct tdm2c_ch_info *ch_info = tdm2c->ch_info[ch];
#else /* MY_DEF_HERE */
	struct tdm2c_ch_info *ch_info = tdm_ch_info[ch];
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	dev_dbg(tdm2c->dev, "%s: Enter, ch%d\n", __func__, ch);
#else /* MY_DEF_HERE */
	dev_dbg(pdev, "%s: Enter, ch%d\n", __func__, ch);
#endif /* MY_DEF_HERE */

	/* Count tx interrupts */
#if defined(MY_DEF_HERE)
	tdm2c->tx_int++;
#else /* MY_DEF_HERE */
	tx_int++;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	if (ch_info->tx_buff_empty[ch_info->tx_curr_buff] == BUFF_IS_FULL)
		dev_dbg(tdm2c->dev, "curr buff full for hw [MMP ok]\n");
#else /* MY_DEF_HERE */
	if (ch_info->txBuffFull[ch_info->txCurrBuff] == BUFF_IS_FULL)
		dev_dbg(pdev, "curr buff full for hw [MMP ok]\n");
#endif /* MY_DEF_HERE */
	else
#if defined(MY_DEF_HERE)
		dev_warn(tdm2c->dev, "curr buf is empty [MMP miss write]\n");
#else /* MY_DEF_HERE */
		dev_warn(pdev, "curr buf is empty [MMP miss write]\n");
#endif /* MY_DEF_HERE */

	/* Change buffers */
#if defined(MY_DEF_HERE)
	ch_info->tx_curr_buff = MV_TDM_NEXT_BUFFER(ch_info->tx_curr_buff);
#else /* MY_DEF_HERE */
	ch_info->txCurrBuff = MV_TDM_NEXT_BUFFER(ch_info->txCurrBuff);
#endif /* MY_DEF_HERE */

	/*
	 * Mark next buff to be transmitted by HW as empty. Give it to the HW
	 * for next frame. The app need to write the data before HW takes it.
	 */
#if defined(MY_DEF_HERE)
	ch_info->tx_buff_empty[ch_info->tx_curr_buff] = BUFF_IS_EMPTY;
	dev_dbg(tdm2c->dev, "->%s clear buf(%d) for channel(%d)\n", __func__, ch_info->tx_curr_buff, ch);
#else /* MY_DEF_HERE */
	ch_info->txBuffFull[ch_info->txCurrBuff] = BUFF_IS_EMPTY;
	dev_dbg(pdev, "->%s clear buf(%d) for channel(%d)\n", __func__, ch_info->txCurrBuff, ch);
#endif /* MY_DEF_HERE */

	/* Poll on SW ownership (single check) */
#if defined(MY_DEF_HERE)
	dev_dbg(tdm2c->dev, "start poll for SW ownership\n");
	while (((readb(tdm2c->regs + CH_BUFF_OWN_REG(ch_info->ch) + TX_OWN_BYTE_OFFS) & OWNER_MASK) == OWN_BY_HW)
#else /* MY_DEF_HERE */
	dev_dbg(pdev, "start poll for SW ownership\n");
	while (((readb(regs + CH_BUFF_OWN_REG(ch_info->ch) + TX_OWN_BYTE_OFFS) & OWNER_MASK) == OWN_BY_HW)
#endif /* MY_DEF_HERE */
	       && (max_poll < 2000)) {
		udelay(1);
		max_poll++;
	}
	if (max_poll == 2000) {
#if defined(MY_DEF_HERE)
		dev_err(tdm2c->dev, "poll timeout (~2ms)\n");
#else /* MY_DEF_HERE */
		dev_err(pdev, "poll timeout (~2ms)\n");
#endif /* MY_DEF_HERE */
		return -ETIME;
	}

#if defined(MY_DEF_HERE)
	dev_dbg(tdm2c->dev, "ch%d, start tx buff %d\n", ch, ch_info->tx_curr_buff);
#else /* MY_DEF_HERE */
	dev_dbg(pdev, "ch%d, start tx buff %d\n", ch, ch_info->txCurrBuff);
#endif /* MY_DEF_HERE */

	/* Set TX buff address (must be 32 byte aligned) */
#if defined(MY_DEF_HERE)
	writel(ch_info->tx_buff_phys[ch_info->tx_curr_buff], tdm2c->regs + CH_TX_ADDR_REG(ch_info->ch));
#else /* MY_DEF_HERE */
	writel(ch_info->txBuffPhys[ch_info->txCurrBuff], regs + CH_TX_ADDR_REG(ch_info->ch));
#endif /* MY_DEF_HERE */

	/* Set HW ownership */
#if defined(MY_DEF_HERE)
	writeb(OWN_BY_HW, tdm2c->regs + CH_BUFF_OWN_REG(ch_info->ch) + TX_OWN_BYTE_OFFS);
#else /* MY_DEF_HERE */
	writeb(OWN_BY_HW, regs + CH_BUFF_OWN_REG(ch_info->ch) + TX_OWN_BYTE_OFFS);
#endif /* MY_DEF_HERE */

	/* Enable Tx */
#if defined(MY_DEF_HERE)
	writeb(CH_ENABLE, tdm2c->regs + CH_ENABLE_REG(ch_info->ch) + TX_ENABLE_BYTE_OFFS);
#else /* MY_DEF_HERE */
	writeb(CH_ENABLE, regs + CH_ENABLE_REG(ch_info->ch) + TX_ENABLE_BYTE_OFFS);
#endif /* MY_DEF_HERE */

	/* Did we get the required amount of irqs for Tx wakeup ? */
#if defined(MY_DEF_HERE)
	if (tdm2c->tx_int < MV_TDM_INT_COUNTER)
#else /* MY_DEF_HERE */
	if (tx_int < MV_TDM_INT_COUNTER)
#endif /* MY_DEF_HERE */
		return -EBUSY;

#if defined(MY_DEF_HERE)
	tdm2c->tx_int = 0;
	tdm2c->tx_empty = ch_info->tx_curr_buff;
#else /* MY_DEF_HERE */
	tx_int = 0;
	tx_empty = ch_info->txCurrBuff;
#endif /* MY_DEF_HERE */

	return 0;
}

static inline int tdm2c_ch_rx_low(u8 ch)
{
	u32 max_poll = 0;
#if defined(MY_DEF_HERE)
	struct tdm2c_ch_info *ch_info = tdm2c->ch_info[ch];
#else /* MY_DEF_HERE */
	struct tdm2c_ch_info *ch_info = tdm_ch_info[ch];
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	dev_dbg(tdm2c->dev, "%s: Enter, ch%d\n", __func__, ch);
#else /* MY_DEF_HERE */
	dev_dbg(pdev, "%s: Enter, ch%d\n", __func__, ch);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	if (ch_info->rx_first)
		ch_info->rx_first = !FIRST_INT;
#else /* MY_DEF_HERE */
	if (ch_info->rxFirst)
		ch_info->rxFirst = !FIRST_INT;
#endif /* MY_DEF_HERE */
	else
#if defined(MY_DEF_HERE)
		tdm2c->rx_int++;
#else /* MY_DEF_HERE */
		rx_int++;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	if (ch_info->rx_buff_full[ch_info->rx_curr_buff] == BUFF_IS_EMPTY)
		dev_dbg(tdm2c->dev, "curr buff empty for hw [MMP ok]\n");
#else /* MY_DEF_HERE */
	if (ch_info->rxBuffFull[ch_info->rxCurrBuff] == BUFF_IS_EMPTY)
		dev_dbg(pdev, "curr buff empty for hw [MMP ok]\n");
#endif /* MY_DEF_HERE */
	else
#if defined(MY_DEF_HERE)
		dev_warn(tdm2c->dev, "curr buf is full [MMP miss read]\n");
#else /* MY_DEF_HERE */
		dev_warn(pdev, "curr buf is full [MMP miss read]\n");
#endif /* MY_DEF_HERE */

	/*
	 * Mark last buff that was received by HW as full. Give next buff to HW for
	 * next frame. The app need to read the data before next irq
	 */
#if defined(MY_DEF_HERE)
	ch_info->rx_buff_full[ch_info->rx_curr_buff] = BUFF_IS_FULL;
#else /* MY_DEF_HERE */
	ch_info->rxBuffFull[ch_info->rxCurrBuff] = BUFF_IS_FULL;
#endif /* MY_DEF_HERE */

	/* Change buffers */
#if defined(MY_DEF_HERE)
	ch_info->rx_curr_buff = MV_TDM_NEXT_BUFFER(ch_info->rx_curr_buff);
#else /* MY_DEF_HERE */
	ch_info->rxCurrBuff = MV_TDM_NEXT_BUFFER(ch_info->rxCurrBuff);
#endif /* MY_DEF_HERE */

	/* Poll on SW ownership (single check) */
#if defined(MY_DEF_HERE)
	dev_dbg(tdm2c->dev, "start poll for ownership\n");
	while (((readb(tdm2c->regs + CH_BUFF_OWN_REG(ch_info->ch) + RX_OWN_BYTE_OFFS) & OWNER_MASK) == OWN_BY_HW)
#else /* MY_DEF_HERE */
	dev_dbg(pdev, "start poll for ownership\n");
	while (((readb(regs + CH_BUFF_OWN_REG(ch_info->ch) + RX_OWN_BYTE_OFFS) & OWNER_MASK) == OWN_BY_HW)
#endif /* MY_DEF_HERE */
	       && (max_poll < 2000)) {
		udelay(1);
		max_poll++;
	}

	if (max_poll == 2000) {
#if defined(MY_DEF_HERE)
		dev_err(tdm2c->dev, "poll timeout (~2ms)\n");
#else /* MY_DEF_HERE */
		dev_err(pdev, "poll timeout (~2ms)\n");
#endif /* MY_DEF_HERE */
		return -ETIME;
	}

#if defined(MY_DEF_HERE)
	dev_dbg(tdm2c->dev, "ch%d, start rx buff %d\n", ch, ch_info->rx_curr_buff);
#else /* MY_DEF_HERE */
	dev_dbg(pdev, "ch%d, start rx buff %d\n", ch, ch_info->rxCurrBuff);
#endif /* MY_DEF_HERE */

	/* Set RX buff address (must be 32 byte aligned) */
#if defined(MY_DEF_HERE)
	writel(ch_info->rx_buff_phys[ch_info->rx_curr_buff], tdm2c->regs + CH_RX_ADDR_REG(ch_info->ch));
#else /* MY_DEF_HERE */
	writel(ch_info->rxBuffPhys[ch_info->rxCurrBuff], regs + CH_RX_ADDR_REG(ch_info->ch));
#endif /* MY_DEF_HERE */

	/* Set HW ownership */
#if defined(MY_DEF_HERE)
	writeb(OWN_BY_HW, tdm2c->regs + CH_BUFF_OWN_REG(ch_info->ch) + RX_OWN_BYTE_OFFS);
#else /* MY_DEF_HERE */
	writeb(OWN_BY_HW, regs + CH_BUFF_OWN_REG(ch_info->ch) + RX_OWN_BYTE_OFFS);
#endif /* MY_DEF_HERE */

	/* Enable Rx */
#if defined(MY_DEF_HERE)
	writeb(CH_ENABLE, tdm2c->regs + CH_ENABLE_REG(ch_info->ch) + RX_ENABLE_BYTE_OFFS);
#else /* MY_DEF_HERE */
	writeb(CH_ENABLE, regs + CH_ENABLE_REG(ch_info->ch) + RX_ENABLE_BYTE_OFFS);
#endif /* MY_DEF_HERE */

	/* Did we get the required amount of irqs for Rx wakeup ? */
#if defined(MY_DEF_HERE)
	if (tdm2c->rx_int < MV_TDM_INT_COUNTER)
#else /* MY_DEF_HERE */
	if (rx_int < MV_TDM_INT_COUNTER)
#endif /* MY_DEF_HERE */
		return -EBUSY;

#if defined(MY_DEF_HERE)
	tdm2c->rx_int = 0;
	tdm2c->rx_full = MV_TDM_PREV_BUFFER(ch_info->rx_curr_buff, 2);
	dev_dbg(tdm2c->dev, "buff %d is FULL for ch0/1\n", tdm2c->rx_full);
#else /* MY_DEF_HERE */
	rx_int = 0;
	rx_full = MV_TDM_PREV_BUFFER(ch_info->rxCurrBuff, 2);
	dev_dbg(pdev, "buff %d is FULL for ch0/1\n", rx_full);
#endif /* MY_DEF_HERE */

	return 0;
}

static int tdm2c_ch_remove(u8 ch)
{
	struct tdm2c_ch_info *ch_info;
	u8 buff;

#if defined(MY_DEF_HERE)
	dev_dbg(tdm2c->dev, "%s: Enter, ch%d\n", __func__, ch);
#else /* MY_DEF_HERE */
	dev_dbg(pdev, "%s: Enter, ch%d\n", __func__, ch);
#endif /* MY_DEF_HERE */

	if (ch >= MV_TDM2C_TOTAL_CHANNELS) {
#if defined(MY_DEF_HERE)
		dev_err(tdm2c->dev, "%s: error, channel(%d) exceeds maximum(%d)\n",
#else /* MY_DEF_HERE */
		dev_err(pdev, "%s: error, channel(%d) exceeds maximum(%d)\n",
#endif /* MY_DEF_HERE */
			__func__, ch, MV_TDM2C_TOTAL_CHANNELS);
		return -EINVAL;
	}

#if defined(MY_DEF_HERE)
	ch_info = tdm2c->ch_info[ch];
#else /* MY_DEF_HERE */
	ch_info = tdm_ch_info[ch];
#endif /* MY_DEF_HERE */

	for (buff = 0; buff < TOTAL_BUFFERS; buff++) {
#if defined(MY_DEF_HERE)
		dma_free_coherent(tdm2c->dev, MV_TDM_CH_BUFF_SIZE(tdm2c->pcm_format, tdm2c->band_mode, tdm2c->factor),
				  ch_info->rx_buff_virt[buff], (dma_addr_t)ch_info->rx_buff_phys[buff]);
		dma_free_coherent(tdm2c->dev, MV_TDM_CH_BUFF_SIZE(tdm2c->pcm_format, tdm2c->band_mode, tdm2c->factor),
				  ch_info->tx_buff_virt[buff], (dma_addr_t)ch_info->tx_buff_phys[buff]);
#else /* MY_DEF_HERE */
		dma_free_coherent(pdev, MV_TDM_CH_BUFF_SIZE(pcm_format, tdm_band_mode, factor),
				  ch_info->rxBuffVirt[buff], (dma_addr_t)ch_info->rxBuffPhys[buff]);
		dma_free_coherent(pdev, MV_TDM_CH_BUFF_SIZE(pcm_format, tdm_band_mode, factor),
				  ch_info->txBuffVirt[buff], (dma_addr_t)ch_info->txBuffPhys[buff]);
#endif /* MY_DEF_HERE */
	}

	kfree(ch_info);

	return 0;
}

static void tdm2c_reset(void)
{
	struct tdm2c_ch_info *ch_info;
	u8 buff, ch;

#if defined(MY_DEF_HERE)
	dev_dbg(tdm2c->dev, "%s: Enter, ch%d\n", __func__, ch);
#else /* MY_DEF_HERE */
	dev_dbg(pdev, "%s: Enter, ch%d\n", __func__, ch);
#endif /* MY_DEF_HERE */

	/* Reset globals */
#if defined(MY_DEF_HERE)
	tdm2c->rx_int = 0;
	tdm2c->tx_int = 0;
	tdm2c->rx_full = BUFF_INVALID;
	tdm2c->tx_empty = BUFF_INVALID;
#else /* MY_DEF_HERE */
	rx_int = tx_int = 0;
	rx_full = tx_empty = BUFF_INVALID;
#endif /* MY_DEF_HERE */

	for (ch = 0; ch < MV_TDM2C_TOTAL_CHANNELS; ch++) {
#if defined(MY_DEF_HERE)
		ch_info = tdm2c->ch_info[ch];
		ch_info->rx_first = FIRST_INT;
		ch_info->tx_curr_buff = ch_info->rx_curr_buff = 0;
#else /* MY_DEF_HERE */
		ch_info = tdm_ch_info[ch];
		ch_info->rxFirst = FIRST_INT;
		ch_info->txCurrBuff = ch_info->rxCurrBuff = 0;
#endif /* MY_DEF_HERE */
		for (buff = 0; buff < TOTAL_BUFFERS; buff++) {
#if defined(MY_DEF_HERE)
			ch_info->rx_buff_full[buff] = BUFF_IS_EMPTY;
			ch_info->tx_buff_empty[buff] = BUFF_IS_FULL;
#else /* MY_DEF_HERE */
			ch_info->rxBuffFull[buff] = BUFF_IS_EMPTY;
			ch_info->txBuffFull[buff] = BUFF_IS_FULL;
#endif /* MY_DEF_HERE */

		}
	}
}

#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
void __iomem *get_tdm_base(void)
{
	return regs;
}

#endif /* MY_DEF_HERE */
int tdm2c_init(void __iomem *base, struct device *dev,
#if defined(MY_DEF_HERE)
	       struct mv_phone_params *tdm_params, enum mv_phone_frame_ts frame_ts,
	       enum mv_phone_spi_mode spi_mode, bool use_pclk_external)
#else /* MY_DEF_HERE */
	       struct mv_phone_params *tdmParams, struct mv_phone_data *halData)
#endif /* MY_DEF_HERE */
{
	u8 ch;
	u32 pcm_ctrl_reg, nb_delay = 0, wb_delay = 0;
	u32 ch_delay[4] = { 0, 0, 0, 0 };
	int ret;

#if defined(MY_DEF_HERE)
	/* Initialize or reset main structure */
	if (!tdm2c) {
		tdm2c = devm_kzalloc(dev, sizeof(struct tdm2c_dev), GFP_KERNEL);
		if (!tdm2c)
			return -ENOMEM;
	} else {
		memset(tdm2c, 0,  sizeof(struct tdm2c_dev));
	}

	/* Initialize remaining parameters */
	tdm2c->regs = base;
	tdm2c->pcm_format = tdm_params->pcm_format;
	tdm2c->rx_full = BUFF_INVALID;
	tdm2c->tx_empty = BUFF_INVALID;
	tdm2c->dev = dev;

#else /* MY_DEF_HERE */
	regs = base;
#endif /* MY_DEF_HERE */
	dev_info(dev, "TDM dual channel device rev 0x%x\n",
#if defined(MY_DEF_HERE)
		 readl(tdm2c->regs + TDM_REV_REG));

	if (tdm_params->sampling_period > MV_TDM_MAX_SAMPLING_PERIOD)
#else /* MY_DEF_HERE */
		 readl(regs + TDM_REV_REG));

	/* Init globals */
	rx_int = tx_int = 0;
	rx_full = tx_empty = BUFF_INVALID;
	tdm_enable = 0, int_lock = 0;
	spi_mode = halData->spi_mode;
	pcm_format = tdmParams->pcm_format;
	int_rx_count = 0, int_tx_count = 0;
	int_rx0_count = 0, int_tx0_count = 0;
	int_rx1_count = 0, int_tx1_count = 0;
	int_rx0_miss = 0, int_tx0_miss = 0;
	int_rx1_miss = 0, int_tx1_miss = 0;
	pcm_restart_count = 0;
	pdev = dev;

	if (tdmParams->sampling_period > MV_TDM_MAX_SAMPLING_PERIOD)
#endif /* MY_DEF_HERE */
		/* Use base sample period(10ms) */
#if defined(MY_DEF_HERE)
		tdm2c->factor = 1;
#else /* MY_DEF_HERE */
		factor = 1;
#endif /* MY_DEF_HERE */
	else
#if defined(MY_DEF_HERE)
		tdm2c->factor = (tdm_params->sampling_period / MV_TDM_BASE_SAMPLING_PERIOD);
#else /* MY_DEF_HERE */
		factor = (tdmParams->sampling_period / MV_TDM_BASE_SAMPLING_PERIOD);
#endif /* MY_DEF_HERE */

	/* Extract pcm format & band mode */
#if defined(MY_DEF_HERE)
	if (tdm2c->pcm_format == MV_PCM_FORMAT_4BYTES) {
		tdm2c->pcm_format = MV_PCM_FORMAT_2BYTES;
		tdm2c->band_mode = MV_WIDE_BAND;
#else /* MY_DEF_HERE */
	if (pcm_format == MV_PCM_FORMAT_4BYTES) {
		pcm_format = MV_PCM_FORMAT_2BYTES;
		tdm_band_mode = MV_WIDE_BAND;
#endif /* MY_DEF_HERE */
	} else {
#if defined(MY_DEF_HERE)
		tdm2c->band_mode = MV_NARROW_BAND;
#else /* MY_DEF_HERE */
		tdm_band_mode = MV_NARROW_BAND;
#endif /* MY_DEF_HERE */
	}

	/* Allocate aggregated buffers for data transport */
#if defined(MY_DEF_HERE)
	dev_dbg(tdm2c->dev, "allocate %d bytes for aggregated buffer\n",
		MV_TDM_AGGR_BUFF_SIZE(tdm2c->pcm_format, tdm2c->band_mode, tdm2c->factor));
	tdm2c->rx_aggr_buff_virt = alloc_pages_exact(
			MV_TDM_AGGR_BUFF_SIZE(tdm2c->pcm_format, tdm2c->band_mode, tdm2c->factor),
			GFP_KERNEL);
	tdm2c->tx_aggr_buff_virt = alloc_pages_exact(
			MV_TDM_AGGR_BUFF_SIZE(tdm2c->pcm_format, tdm2c->band_mode, tdm2c->factor),
			GFP_KERNEL);
	if (!tdm2c->rx_aggr_buff_virt || !tdm2c->tx_aggr_buff_virt) {
		dev_err(tdm2c->dev, "%s: Error malloc failed\n", __func__);
#else /* MY_DEF_HERE */
	dev_dbg(pdev, "allocate %d bytes for aggregated buffer\n",
		MV_TDM_AGGR_BUFF_SIZE(pcm_format, tdm_band_mode, factor));
	rx_aggr_buff_virt = alloc_pages_exact(MV_TDM_AGGR_BUFF_SIZE(pcm_format, tdm_band_mode, factor), GFP_KERNEL);
	tx_aggr_buff_virt = alloc_pages_exact(MV_TDM_AGGR_BUFF_SIZE(pcm_format, tdm_band_mode, factor), GFP_KERNEL);
	if (!rx_aggr_buff_virt || !tx_aggr_buff_virt) {
		dev_err(pdev, "%s: Error malloc failed\n", __func__);
#endif /* MY_DEF_HERE */
		return -ENOMEM;
	}

	/* Clear buffers */
#if defined(MY_DEF_HERE)
	memset(tdm2c->rx_aggr_buff_virt, 0,
	       MV_TDM_AGGR_BUFF_SIZE(tdm2c->pcm_format, tdm2c->band_mode, tdm2c->factor));
	memset(tdm2c->tx_aggr_buff_virt, 0,
	       MV_TDM_AGGR_BUFF_SIZE(tdm2c->pcm_format, tdm2c->band_mode, tdm2c->factor));
#else /* MY_DEF_HERE */
	memset(rx_aggr_buff_virt, 0, MV_TDM_AGGR_BUFF_SIZE(pcm_format, tdm_band_mode, factor));
	memset(tx_aggr_buff_virt, 0, MV_TDM_AGGR_BUFF_SIZE(pcm_format, tdm_band_mode, factor));
#endif /* MY_DEF_HERE */

	/* Calculate CH(0/1) Delay Control for narrow/wideband modes */
	for (ch = 0; ch < MV_TDM2C_TOTAL_CHANNELS; ch++) {
#if defined(MY_DEF_HERE)
		nb_delay = ((tdm_params->pcm_slot[ch] * PCM_SLOT_PCLK) + 1);
#else /* MY_DEF_HERE */
		nb_delay = ((tdmParams->pcm_slot[ch] * PCM_SLOT_PCLK) + 1);
#endif /* MY_DEF_HERE */
		/* Offset required by ZARLINK VE880 SLIC */
#if defined(MY_DEF_HERE)
		wb_delay = (nb_delay + ((frame_ts / 2) * PCM_SLOT_PCLK));
#else /* MY_DEF_HERE */
		wb_delay = (nb_delay + ((halData->frame_ts / 2) * PCM_SLOT_PCLK));
#endif /* MY_DEF_HERE */
		ch_delay[ch] = ((nb_delay << CH_RX_DELAY_OFFS) | (nb_delay << CH_TX_DELAY_OFFS));
		ch_delay[(ch + 2)] = ((wb_delay << CH_RX_DELAY_OFFS) | (wb_delay << CH_TX_DELAY_OFFS));
	}

	/* Enable TDM/SPI interface */
#if defined(MY_DEF_HERE)
	mv_phone_reset_bit(tdm2c->regs + TDM_SPI_MUX_REG, 0x00000001);
#else /* MY_DEF_HERE */
	mv_phone_reset_bit(regs + TDM_SPI_MUX_REG, 0x00000001);
#endif /* MY_DEF_HERE */
	/* Interrupt cause is not clear on read */
#if defined(MY_DEF_HERE)
	writel(CLEAR_ON_ZERO, tdm2c->regs + INT_RESET_SELECT_REG);
#else /* MY_DEF_HERE */
	writel(CLEAR_ON_ZERO, regs + INT_RESET_SELECT_REG);
#endif /* MY_DEF_HERE */
	/* All interrupt bits latched in status */
#if defined(MY_DEF_HERE)
	writel(0x3ffff, tdm2c->regs + INT_EVENT_MASK_REG);
#else /* MY_DEF_HERE */
	writel(0x3ffff, regs + INT_EVENT_MASK_REG);
#endif /* MY_DEF_HERE */
	/* Disable interrupts */
#if defined(MY_DEF_HERE)
	writel(0, tdm2c->regs + INT_STATUS_MASK_REG);
#else /* MY_DEF_HERE */
	writel(0, regs + INT_STATUS_MASK_REG);
#endif /* MY_DEF_HERE */
	/* Clear int status register */
#if defined(MY_DEF_HERE)
	writel(0, tdm2c->regs + INT_STATUS_REG);
#else /* MY_DEF_HERE */
	writel(0, regs + INT_STATUS_REG);
#endif /* MY_DEF_HERE */

	/* Bypass clock divider - PCM PCLK freq */
#if defined(MY_DEF_HERE)
	writel(PCM_DIV_PASS, tdm2c->regs + PCM_CLK_RATE_DIV_REG);
#else /* MY_DEF_HERE */
	writel(PCM_DIV_PASS, regs + PCM_CLK_RATE_DIV_REG);
#endif /* MY_DEF_HERE */

	/* Padding on Rx completion */
#if defined(MY_DEF_HERE)
	writel(0, tdm2c->regs + DUMMY_RX_WRITE_DATA_REG);
	writeb(readl(tdm2c->regs + SPI_GLOBAL_CTRL_REG) | SPI_GLOBAL_ENABLE,
	       tdm2c->regs + SPI_GLOBAL_CTRL_REG);
#else /* MY_DEF_HERE */
	writel(0, regs + DUMMY_RX_WRITE_DATA_REG);
	writeb(readl(regs + SPI_GLOBAL_CTRL_REG) | SPI_GLOBAL_ENABLE, regs + SPI_GLOBAL_CTRL_REG);
#endif /* MY_DEF_HERE */
	/* SPI SCLK freq */
#if defined(MY_DEF_HERE)
	writel(SPI_CLK_2MHZ, tdm2c->regs + SPI_CLK_PRESCALAR_REG);
#else /* MY_DEF_HERE */
	writel(SPI_CLK_2MHZ, regs + SPI_CLK_PRESCALAR_REG);
#endif /* MY_DEF_HERE */
	/* Number of timeslots (PCLK) */
#if defined(MY_DEF_HERE)
	writel((u32)frame_ts, tdm2c->regs + FRAME_TIMESLOT_REG);
#else /* MY_DEF_HERE */
	writel((u32)halData->frame_ts, regs + FRAME_TIMESLOT_REG);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	if (tdm2c->band_mode == MV_NARROW_BAND) {
		pcm_ctrl_reg = (CONFIG_PCM_CRTL | (((u8)tdm2c->pcm_format - 1) << PCM_SAMPLE_SIZE_OFFS));
#else /* MY_DEF_HERE */
	if (tdm_band_mode == MV_NARROW_BAND) {
		pcm_ctrl_reg = (CONFIG_PCM_CRTL | (((u8)pcm_format - 1) << PCM_SAMPLE_SIZE_OFFS));
#endif /* MY_DEF_HERE */

		if (use_pclk_external)
			pcm_ctrl_reg |= MASTER_PCLK_EXTERNAL;

		/* PCM configuration */
#if defined(MY_DEF_HERE)
		writel(pcm_ctrl_reg, tdm2c->regs + PCM_CTRL_REG);
#else /* MY_DEF_HERE */
		writel(pcm_ctrl_reg, regs + PCM_CTRL_REG);
#endif /* MY_DEF_HERE */
		/* CH0 delay control register */
#if defined(MY_DEF_HERE)
		writel(ch_delay[0], tdm2c->regs + CH_DELAY_CTRL_REG(0));
#else /* MY_DEF_HERE */
		writel(ch_delay[0], regs + CH_DELAY_CTRL_REG(0));
#endif /* MY_DEF_HERE */
		/* CH1 delay control register */
#if defined(MY_DEF_HERE)
		writel(ch_delay[1], tdm2c->regs + CH_DELAY_CTRL_REG(1));
#else /* MY_DEF_HERE */
		writel(ch_delay[1], regs + CH_DELAY_CTRL_REG(1));
#endif /* MY_DEF_HERE */
	} else {		/* MV_WIDE_BAND */

#if defined(MY_DEF_HERE)
		pcm_ctrl_reg = (CONFIG_WB_PCM_CRTL | (((u8)tdm2c->pcm_format - 1) << PCM_SAMPLE_SIZE_OFFS));
#else /* MY_DEF_HERE */
		pcm_ctrl_reg = (CONFIG_WB_PCM_CRTL | (((u8)pcm_format - 1) << PCM_SAMPLE_SIZE_OFFS));
#endif /* MY_DEF_HERE */

		if (use_pclk_external)
			pcm_ctrl_reg |= MASTER_PCLK_EXTERNAL;

		/* PCM configuration - WB support */
#if defined(MY_DEF_HERE)
		writel(pcm_ctrl_reg, tdm2c->regs + PCM_CTRL_REG);
#else /* MY_DEF_HERE */
		writel(pcm_ctrl_reg, regs + PCM_CTRL_REG);
#endif /* MY_DEF_HERE */
		/* CH0 delay control register */
#if defined(MY_DEF_HERE)
		writel(ch_delay[0], tdm2c->regs + CH_DELAY_CTRL_REG(0));
#else /* MY_DEF_HERE */
		writel(ch_delay[0], regs + CH_DELAY_CTRL_REG(0));
#endif /* MY_DEF_HERE */
		/* CH1 delay control register */
#if defined(MY_DEF_HERE)
		writel(ch_delay[1], tdm2c->regs + CH_DELAY_CTRL_REG(1));
#else /* MY_DEF_HERE */
		writel(ch_delay[1], regs + CH_DELAY_CTRL_REG(1));
#endif /* MY_DEF_HERE */
		/* CH0 WB delay control register */
#if defined(MY_DEF_HERE)
		writel(ch_delay[2], tdm2c->regs + CH_WB_DELAY_CTRL_REG(0));
#else /* MY_DEF_HERE */
		writel(ch_delay[2], regs + CH_WB_DELAY_CTRL_REG(0));
#endif /* MY_DEF_HERE */
		/* CH1 WB delay control register */
#if defined(MY_DEF_HERE)
		writel(ch_delay[3], tdm2c->regs + CH_WB_DELAY_CTRL_REG(1));
#else /* MY_DEF_HERE */
		writel(ch_delay[3], regs + CH_WB_DELAY_CTRL_REG(1));
#endif /* MY_DEF_HERE */
	}

	/* Issue reset to codec(s) */
#if defined(MY_DEF_HERE)
	dev_dbg(tdm2c->dev, "resetting voice unit(s)\n");
	writel(0, tdm2c->regs + MISC_CTRL_REG);
#else /* MY_DEF_HERE */
	dev_dbg(pdev, "resetting voice unit(s)\n");
	writel(0, regs + MISC_CTRL_REG);
#endif /* MY_DEF_HERE */
	mdelay(1);
#if defined(MY_DEF_HERE)
	writel(1, tdm2c->regs + MISC_CTRL_REG);
#else /* MY_DEF_HERE */
	writel(1, regs + MISC_CTRL_REG);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	if (spi_mode == MV_SPI_MODE_DAISY_CHAIN) {
#else /* MY_DEF_HERE */
	if (spi_mode) {
#endif /* MY_DEF_HERE */
		/* Configure TDM to work in daisy chain mode */
		tdm2c_daisy_chain_mode_set();
	}

	/* Initialize all HW units */
	for (ch = 0; ch < MV_TDM2C_TOTAL_CHANNELS; ch++) {
		ret = tdm2c_ch_init(ch);
		if (ret) {
#if defined(MY_DEF_HERE)
			dev_err(tdm2c->dev, "tdm2c_ch_init(%d) failed !\n", ch);
#else /* MY_DEF_HERE */
			dev_err(pdev, "tdm2c_ch_init(%d) failed !\n", ch);
#endif /* MY_DEF_HERE */
			return ret;
		}
	}

	/* Enable SLIC/DAA interrupt detection(before pcm is active) */
#if defined(MY_DEF_HERE)
	writel((readl(tdm2c->regs + INT_STATUS_MASK_REG) | TDM_INT_SLIC), tdm2c->regs + INT_STATUS_MASK_REG);
#else /* MY_DEF_HERE */
	writel((readl(regs + INT_STATUS_MASK_REG) | TDM_INT_SLIC), regs + INT_STATUS_MASK_REG);
#endif /* MY_DEF_HERE */

	return 0;
}

void tdm2c_release(void)
{
	u8 ch;

	/* Free Rx/Tx aggregated buffers */
#if defined(MY_DEF_HERE)
	free_pages_exact(tdm2c->rx_aggr_buff_virt,
			 MV_TDM_AGGR_BUFF_SIZE(tdm2c->pcm_format, tdm2c->band_mode, tdm2c->factor));
	free_pages_exact(tdm2c->tx_aggr_buff_virt,
			 MV_TDM_AGGR_BUFF_SIZE(tdm2c->pcm_format, tdm2c->band_mode, tdm2c->factor));
#else /* MY_DEF_HERE */
	free_pages_exact(rx_aggr_buff_virt, MV_TDM_AGGR_BUFF_SIZE(pcm_format, tdm_band_mode, factor));
	free_pages_exact(tx_aggr_buff_virt, MV_TDM_AGGR_BUFF_SIZE(pcm_format, tdm_band_mode, factor));
#endif /* MY_DEF_HERE */

	/* Release HW channel resources */
	for (ch = 0; ch < MV_TDM2C_TOTAL_CHANNELS; ch++)
		tdm2c_ch_remove(ch);

	/* Disable TDM/SPI interface */
#if defined(MY_DEF_HERE)
	mv_phone_set_bit(tdm2c->regs + TDM_SPI_MUX_REG, 0x00000001);
#else /* MY_DEF_HERE */
	mv_phone_set_bit(regs + TDM_SPI_MUX_REG, 0x00000001);
#endif /* MY_DEF_HERE */
}

void tdm2c_pcm_start(void)
{
	struct tdm2c_ch_info *ch_info;
	u8 ch;

	/* TDM is enabled */
#if defined(MY_DEF_HERE)
	tdm2c->enable = true;
	tdm2c->int_lock = false;
	tdm2c->chan_stop_count = 0;
#else /* MY_DEF_HERE */
	tdm_enable = 1;
	int_lock = 0;
	chan_stop_count = 0;
#endif /* MY_DEF_HERE */
	tdm2c_reset();

	for (ch = 0; ch < MV_TDM2C_TOTAL_CHANNELS; ch++) {
#if defined(MY_DEF_HERE)
		ch_info = tdm2c->ch_info[ch];
#else /* MY_DEF_HERE */
		ch_info = tdm_ch_info[ch];
#endif /* MY_DEF_HERE */

		/* Set Tx buff */
#if defined(MY_DEF_HERE)
		writel(ch_info->tx_buff_phys[ch_info->tx_curr_buff], tdm2c->regs + CH_TX_ADDR_REG(ch));
		writeb(OWN_BY_HW, tdm2c->regs + CH_BUFF_OWN_REG(ch) + TX_OWN_BYTE_OFFS);
#else /* MY_DEF_HERE */
		writel(ch_info->txBuffPhys[ch_info->txCurrBuff], regs + CH_TX_ADDR_REG(ch));
		writeb(OWN_BY_HW, regs + CH_BUFF_OWN_REG(ch) + TX_OWN_BYTE_OFFS);
#endif /* MY_DEF_HERE */

		/* Set Rx buff */
#if defined(MY_DEF_HERE)
		writel(ch_info->rx_buff_phys[ch_info->rx_curr_buff], tdm2c->regs + CH_RX_ADDR_REG(ch));
		writeb(OWN_BY_HW, tdm2c->regs + CH_BUFF_OWN_REG(ch) + RX_OWN_BYTE_OFFS);
#else /* MY_DEF_HERE */
		writel(ch_info->rxBuffPhys[ch_info->rxCurrBuff], regs + CH_RX_ADDR_REG(ch));
		writeb(OWN_BY_HW, regs + CH_BUFF_OWN_REG(ch) + RX_OWN_BYTE_OFFS);
#endif /* MY_DEF_HERE */

	}

	/* Enable Tx */
#if defined(MY_DEF_HERE)
	writeb(CH_ENABLE, tdm2c->regs + CH_ENABLE_REG(0) + TX_ENABLE_BYTE_OFFS);
	writeb(CH_ENABLE, tdm2c->regs + CH_ENABLE_REG(1) + TX_ENABLE_BYTE_OFFS);
#else /* MY_DEF_HERE */
	writeb(CH_ENABLE, regs + CH_ENABLE_REG(0) + TX_ENABLE_BYTE_OFFS);
	writeb(CH_ENABLE, regs + CH_ENABLE_REG(1) + TX_ENABLE_BYTE_OFFS);
#endif /* MY_DEF_HERE */

	/* Enable Rx */
#if defined(MY_DEF_HERE)
	writeb(CH_ENABLE, tdm2c->regs + CH_ENABLE_REG(0) + RX_ENABLE_BYTE_OFFS);
	writeb(CH_ENABLE, tdm2c->regs + CH_ENABLE_REG(1) + RX_ENABLE_BYTE_OFFS);
#else /* MY_DEF_HERE */
	writeb(CH_ENABLE, regs + CH_ENABLE_REG(0) + RX_ENABLE_BYTE_OFFS);
	writeb(CH_ENABLE, regs + CH_ENABLE_REG(1) + RX_ENABLE_BYTE_OFFS);
#endif /* MY_DEF_HERE */

	/* Enable Tx interrupts */
#if defined(MY_DEF_HERE)
	writel(readl(tdm2c->regs + INT_STATUS_REG) & (~(TDM_INT_TX(0) | TDM_INT_TX(1))),
	       tdm2c->regs + INT_STATUS_REG);
	writel((readl(tdm2c->regs + INT_STATUS_MASK_REG) | TDM_INT_TX(0) | TDM_INT_TX(1)),
	       tdm2c->regs + INT_STATUS_MASK_REG);
#else /* MY_DEF_HERE */
	writel(readl(regs + INT_STATUS_REG) & (~(TDM_INT_TX(0) | TDM_INT_TX(1))), regs + INT_STATUS_REG);
	writel((readl(regs + INT_STATUS_MASK_REG) | TDM_INT_TX(0) | TDM_INT_TX(1)), regs + INT_STATUS_MASK_REG);
#endif /* MY_DEF_HERE */

	/* Enable Rx interrupts */
#if defined(MY_DEF_HERE)
	writel((readl(tdm2c->regs + INT_STATUS_REG) & (~(TDM_INT_RX(0) | TDM_INT_RX(1)))),
	       tdm2c->regs + INT_STATUS_REG);
	writel((readl(tdm2c->regs + INT_STATUS_MASK_REG) | TDM_INT_RX(0) | TDM_INT_RX(1)),
	       tdm2c->regs + INT_STATUS_MASK_REG);
#else /* MY_DEF_HERE */
	writel((readl(regs + INT_STATUS_REG) & (~(TDM_INT_RX(0) | TDM_INT_RX(1)))), regs + INT_STATUS_REG);
	writel((readl(regs + INT_STATUS_MASK_REG) | TDM_INT_RX(0) | TDM_INT_RX(1)), regs + INT_STATUS_MASK_REG);
#endif /* MY_DEF_HERE */
}

void tdm2c_pcm_stop(void)
{
#if defined(MY_DEF_HERE)
	tdm2c->enable = false;
#else /* MY_DEF_HERE */
	tdm_enable = 0;
#endif /* MY_DEF_HERE */

	tdm2c_reset();
}

int tdm2c_tx(u8 *tdm_tx_buff)
{
	struct tdm2c_ch_info *ch_info;
	u8 ch;
	u8 *tx_buff;

	/* Sanity check */
#if defined(MY_DEF_HERE)
	if (tdm_tx_buff != tdm2c->tx_aggr_buff_virt) {
		dev_err(tdm2c->dev, "%s: Error, invalid Tx buffer !!!\n", __func__);
#else /* MY_DEF_HERE */
	if (tdm_tx_buff != tx_aggr_buff_virt) {
		dev_err(pdev, "%s: Error, invalid Tx buffer !!!\n", __func__);
#endif /* MY_DEF_HERE */
		return -EINVAL;
	}

#if defined(MY_DEF_HERE)
	if (!tdm2c->enable) {
		dev_err(tdm2c->dev, "%s: Error, no active Tx channels are available\n", __func__);
#else /* MY_DEF_HERE */
	if (!tdm_enable) {
		dev_err(pdev, "%s: Error, no active Tx channels are available\n", __func__);
#endif /* MY_DEF_HERE */
		return -EINVAL;
	}

#if defined(MY_DEF_HERE)
	if (tdm2c->tx_empty == BUFF_INVALID) {
		dev_err(tdm2c->dev, "%s: Tx not ready\n", __func__);
#else /* MY_DEF_HERE */
	if (tx_empty == BUFF_INVALID) {
		dev_err(pdev, "%s: Tx not ready\n", __func__);
#endif /* MY_DEF_HERE */
		return -EINVAL;
	}

	for (ch = 0; ch < MV_TDM2C_TOTAL_CHANNELS; ch++) {
#if defined(MY_DEF_HERE)
		ch_info = tdm2c->ch_info[ch];
		dev_dbg(tdm2c->dev, "ch%d: fill buf %d with %d bytes\n",
			ch, tdm2c->tx_empty,
			MV_TDM_CH_BUFF_SIZE(tdm2c->pcm_format, tdm2c->band_mode, tdm2c->factor));
		ch_info->tx_buff_empty[tdm2c->tx_empty] = BUFF_IS_FULL;
		tx_buff = tdm_tx_buff +
			  (ch * MV_TDM_CH_BUFF_SIZE(tdm2c->pcm_format, tdm2c->band_mode, tdm2c->factor));
#else /* MY_DEF_HERE */
		ch_info = tdm_ch_info[ch];
		dev_dbg(pdev, "ch%d: fill buf %d with %d bytes\n",
			ch, tx_empty,
			MV_TDM_CH_BUFF_SIZE(pcm_format, tdm_band_mode, factor));
		ch_info->txBuffFull[tx_empty] = BUFF_IS_FULL;
		tx_buff = tdm_tx_buff + (ch * MV_TDM_CH_BUFF_SIZE(pcm_format, tdm_band_mode, factor));
#endif /* MY_DEF_HERE */

		/* Copy data from voice engine buffer to DMA */
#if defined(MY_DEF_HERE)
		memcpy(ch_info->tx_buff_virt[tdm2c->tx_empty], tx_buff,
		       MV_TDM_CH_BUFF_SIZE(tdm2c->pcm_format, tdm2c->band_mode, tdm2c->factor));
#else /* MY_DEF_HERE */
		memcpy(ch_info->txBuffVirt[tx_empty], tx_buff,
		       MV_TDM_CH_BUFF_SIZE(pcm_format, tdm_band_mode, factor));
#endif /* MY_DEF_HERE */
	}

#if defined(MY_DEF_HERE)
	tdm2c->tx_empty = BUFF_INVALID;
#else /* MY_DEF_HERE */
	tx_empty = BUFF_INVALID;
#endif /* MY_DEF_HERE */

	return 0;
}

int tdm2c_rx(u8 *tdm_rx_buff)
{
	struct tdm2c_ch_info *ch_info;
	u8 ch;
	u8 *rx_buff;

	/* Sanity check */
#if defined(MY_DEF_HERE)
	if (tdm_rx_buff != tdm2c->rx_aggr_buff_virt) {
		dev_err(tdm2c->dev, "%s: invalid Rx buffer !!!\n", __func__);
#else /* MY_DEF_HERE */
	if (tdm_rx_buff != rx_aggr_buff_virt) {
		dev_err(pdev, "%s: invalid Rx buffer !!!\n", __func__);
#endif /* MY_DEF_HERE */
		return -EINVAL;
	}

#if defined(MY_DEF_HERE)
	if (!tdm2c->enable) {
		dev_err(tdm2c->dev, "%s: Error, no active Rx channels are available\n", __func__);
#else /* MY_DEF_HERE */
	if (!tdm_enable) {
		dev_err(pdev, "%s: Error, no active Rx channels are available\n", __func__);
#endif /* MY_DEF_HERE */
		return -EINVAL;
	}

#if defined(MY_DEF_HERE)
	if (tdm2c->rx_full == BUFF_INVALID) {
		dev_err(tdm2c->dev, "%s: Rx not ready\n", __func__);
#else /* MY_DEF_HERE */
	if (rx_full == BUFF_INVALID) {
		dev_err(pdev, "%s: Rx not ready\n", __func__);
#endif /* MY_DEF_HERE */
		return -EINVAL;
	}

	for (ch = 0; ch < MV_TDM2C_TOTAL_CHANNELS; ch++) {
#if defined(MY_DEF_HERE)
		ch_info = tdm2c->ch_info[ch];
		ch_info->rx_buff_full[tdm2c->rx_full] = BUFF_IS_EMPTY;
		dev_dbg(tdm2c->dev, "%s get Rx buffer(%d) for channel(%d)\n",
			__func__, tdm2c->rx_full, ch);
		rx_buff = tdm_rx_buff +
			  (ch * MV_TDM_CH_BUFF_SIZE(tdm2c->pcm_format, tdm2c->band_mode, tdm2c->factor));
#else /* MY_DEF_HERE */
		ch_info = tdm_ch_info[ch];
		ch_info->rxBuffFull[rx_full] = BUFF_IS_EMPTY;
		dev_dbg(pdev, "%s get Rx buffer(%d) for channel(%d)\n",
			__func__, rx_full, ch);
		rx_buff = tdm_rx_buff + (ch * MV_TDM_CH_BUFF_SIZE(pcm_format, tdm_band_mode, factor));
#endif /* MY_DEF_HERE */

		/* Copy data from DMA to voice engine buffer */
#if defined(MY_DEF_HERE)
		memcpy(rx_buff, ch_info->rx_buff_virt[tdm2c->rx_full],
		       MV_TDM_CH_BUFF_SIZE(tdm2c->pcm_format, tdm2c->band_mode, tdm2c->factor));
#else /* MY_DEF_HERE */
		memcpy(rx_buff, ch_info->rxBuffVirt[rx_full],
		       MV_TDM_CH_BUFF_SIZE(pcm_format, tdm_band_mode, factor));
#endif /* MY_DEF_HERE */
	}

#if defined(MY_DEF_HERE)
	tdm2c->rx_full = BUFF_INVALID;
#else /* MY_DEF_HERE */
	rx_full = BUFF_INVALID;
#endif /* MY_DEF_HERE */

	return 0;
}

int tdm2c_pcm_stop_int_miss(void)
{
	u32 status_reg, mask_reg, status_stop_int, status_mask = 0, int_mask = 0;

#if defined(MY_DEF_HERE)
	status_reg = readl(tdm2c->regs + INT_STATUS_REG);
	mask_reg = readl(tdm2c->regs + INT_STATUS_MASK_REG);
#else /* MY_DEF_HERE */
	status_reg = readl(regs + INT_STATUS_REG);
	mask_reg = readl(regs + INT_STATUS_MASK_REG);
#endif /* MY_DEF_HERE */

	/* Refer only to unmasked bits */
	status_stop_int = status_reg & mask_reg;

	if (status_stop_int & TX_UNDERFLOW_BIT(1)) {
		status_mask |= TX_UNDERFLOW_BIT(1);
		int_mask |= TDM_INT_TX(1);
	}

	if (status_stop_int & TX_UNDERFLOW_BIT(0)) {
		status_mask |= TX_UNDERFLOW_BIT(0);
		int_mask |= TDM_INT_TX(0);
	}

	if (status_stop_int & RX_OVERFLOW_BIT(1)) {
		status_mask |= RX_OVERFLOW_BIT(1);
		int_mask |= TDM_INT_RX(1);
	}

	if (status_stop_int & RX_OVERFLOW_BIT(0)) {
		status_mask |= TX_UNDERFLOW_BIT(0);
		int_mask |= TDM_INT_RX(0);
	}

	if (int_mask != 0) {
#if defined(MY_DEF_HERE)
		dev_err(tdm2c->dev, "Stop Interrupt missing found STATUS=%x, MASK=%x\n", status_reg, mask_reg);
		writel(~(status_mask), tdm2c->regs + INT_STATUS_REG);
		writel(readl(tdm2c->regs + INT_STATUS_MASK_REG) & (~(int_mask)),
		       tdm2c->regs + INT_STATUS_MASK_REG);
#else /* MY_DEF_HERE */
		dev_err(pdev, "Stop Interrupt missing found STATUS=%x, MASK=%x\n", status_reg, mask_reg);
		writel(~(status_mask), regs + INT_STATUS_REG);
		writel(readl(regs + INT_STATUS_MASK_REG) & (~(int_mask)),
		       regs + INT_STATUS_MASK_REG);
#endif /* MY_DEF_HERE */

		return -EINVAL;
	}

	return 0;
}

/* Low level TDM interrupt service routine */
int tdm2c_intr_low(struct mv_phone_intr_info *tdm_intr_info)
{
	u32 status_reg, mask_reg, status_and_mask;
	int ret = 0;
	int int_tx_miss = -1;
	int int_rx_miss = -1;
	u8 ch;

	/* Read Status & mask registers */
#if defined(MY_DEF_HERE)
	status_reg = readl(tdm2c->regs + INT_STATUS_REG);
	mask_reg = readl(tdm2c->regs + INT_STATUS_MASK_REG);
	dev_dbg(tdm2c->dev, "CAUSE(0x%x), MASK(0x%x)\n", status_reg, mask_reg);
#else /* MY_DEF_HERE */
	status_reg = readl(regs + INT_STATUS_REG);
	mask_reg = readl(regs + INT_STATUS_MASK_REG);
	dev_dbg(pdev, "CAUSE(0x%x), MASK(0x%x)\n", status_reg, mask_reg);
#endif /* MY_DEF_HERE */

	/* Refer only to unmasked bits */
	status_and_mask = status_reg & mask_reg;

	/* Reset params */
	tdm_intr_info->tdm_rx_buff = NULL;
	tdm_intr_info->tdm_tx_buff = NULL;
	tdm_intr_info->int_type = MV_EMPTY_INT;
	tdm_intr_info->cs = MV_TDM_CS;

	/* Handle SLIC/DAA int */
	if (status_and_mask & SLIC_INT_BIT) {
#if defined(MY_DEF_HERE)
		dev_dbg(tdm2c->dev, "Phone interrupt !!!\n");
#else /* MY_DEF_HERE */
		dev_dbg(pdev, "Phone interrupt !!!\n");
#endif /* MY_DEF_HERE */
		tdm_intr_info->int_type |= MV_PHONE_INT;
	}

	if (status_and_mask & DMA_ABORT_BIT) {
#if defined(MY_DEF_HERE)
		dev_err(tdm2c->dev, "DMA data abort. Address: 0x%08x, Info: 0x%08x\n",
			readl(tdm2c->regs + DMA_ABORT_ADDR_REG),
			readl(tdm2c->regs + DMA_ABORT_INFO_REG));
#else /* MY_DEF_HERE */
		dev_err(pdev, "DMA data abort. Address: 0x%08x, Info: 0x%08x\n",
			readl(regs + DMA_ABORT_ADDR_REG),
			readl(regs + DMA_ABORT_INFO_REG));
#endif /* MY_DEF_HERE */
		tdm_intr_info->int_type |= MV_DMA_ERROR_INT;
	}

	for (ch = 0; ch < MV_TDM2C_TOTAL_CHANNELS; ch++) {

		/* Give next buff to TDM and set curr buff as empty */
#if defined(MY_DEF_HERE)
		if ((status_and_mask & TX_BIT(ch)) && tdm2c->enable && !tdm2c->int_lock) {
			dev_dbg(tdm2c->dev, "Tx interrupt(ch%d)\n", ch);
#else /* MY_DEF_HERE */
		if ((status_and_mask & TX_BIT(ch)) && tdm_enable && !int_lock) {
			dev_dbg(pdev, "Tx interrupt(ch%d)\n", ch);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
			tdm2c->int_tx_count++;
#else /* MY_DEF_HERE */
			int_tx_count++;
#endif /* MY_DEF_HERE */
			if (ch == 0) {
#if defined(MY_DEF_HERE)
				tdm2c->int_tx0_count++;
				if (tdm2c->int_tx0_count <= tdm2c->int_tx1_count) {
#else /* MY_DEF_HERE */
				int_tx0_count++;
				if (int_tx0_count <= int_tx1_count) {
#endif /* MY_DEF_HERE */
					int_tx_miss = 0;
#if defined(MY_DEF_HERE)
					tdm2c->int_tx0_miss++;
#else /* MY_DEF_HERE */
					int_tx0_miss++;
#endif /* MY_DEF_HERE */
				}
			} else {
#if defined(MY_DEF_HERE)
				tdm2c->int_tx1_count++;
				if (tdm2c->int_tx1_count < tdm2c->int_tx0_count) {
#else /* MY_DEF_HERE */
				int_tx1_count++;
				if (int_tx1_count < int_tx0_count) {
#endif /* MY_DEF_HERE */
					int_tx_miss = 1;
#if defined(MY_DEF_HERE)
					tdm2c->int_tx1_miss++;
#else /* MY_DEF_HERE */
					int_tx1_miss++;
#endif /* MY_DEF_HERE */
				}
			}

			/* 0 -> Tx is done for both channels */
			if (tdm2c_ch_tx_low(ch) == 0) {
#if defined(MY_DEF_HERE)
				dev_dbg(tdm2c->dev, "Assign Tx aggregate buffer for further processing\n");
				tdm_intr_info->tdm_tx_buff = tdm2c->tx_aggr_buff_virt;
#else /* MY_DEF_HERE */
				dev_dbg(pdev, "Assign Tx aggregate buffer for further processing\n");
				tdm_intr_info->tdm_tx_buff = tx_aggr_buff_virt;
#endif /* MY_DEF_HERE */
				tdm_intr_info->int_type |= MV_TX_INT;
			}
		}
	}

	for (ch = 0; ch < MV_TDM2C_TOTAL_CHANNELS; ch++) {

#if defined(MY_DEF_HERE)
		if ((status_and_mask & RX_BIT(ch)) && tdm2c->enable && !tdm2c->int_lock) {
			dev_dbg(tdm2c->dev, "Rx interrupt(ch%d)\n", ch);
#else /* MY_DEF_HERE */
		if ((status_and_mask & RX_BIT(ch)) && tdm_enable && !int_lock) {
			dev_dbg(pdev, "Rx interrupt(ch%d)\n", ch);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
			tdm2c->int_rx_count++;
#else /* MY_DEF_HERE */
			int_rx_count++;
#endif /* MY_DEF_HERE */
			if (ch == 0) {
#if defined(MY_DEF_HERE)
				tdm2c->int_rx0_count++;
				if (tdm2c->int_rx0_count <= tdm2c->int_rx1_count) {
#else /* MY_DEF_HERE */
				int_rx0_count++;
				if (int_rx0_count <= int_rx1_count) {
#endif /* MY_DEF_HERE */
					int_rx_miss = 0;
#if defined(MY_DEF_HERE)
					tdm2c->int_rx0_miss++;
#else /* MY_DEF_HERE */
					int_rx0_miss++;
#endif /* MY_DEF_HERE */
				}
			} else {
#if defined(MY_DEF_HERE)
				tdm2c->int_rx1_count++;
				if (tdm2c->int_rx1_count < tdm2c->int_rx0_count) {
#else /* MY_DEF_HERE */
				int_rx1_count++;
				if (int_rx1_count < int_rx0_count) {
#endif /* MY_DEF_HERE */
					int_rx_miss = 1;
#if defined(MY_DEF_HERE)
					tdm2c->int_rx1_miss++;
#else /* MY_DEF_HERE */
					int_rx1_miss++;
#endif /* MY_DEF_HERE */
				}
			}

			/* 0 -> Rx is done for both channels */
			if (tdm2c_ch_rx_low(ch) == 0) {
#if defined(MY_DEF_HERE)
				dev_dbg(tdm2c->dev, "Assign Rx aggregate buffer for further processing\n");
				tdm_intr_info->tdm_rx_buff = tdm2c->rx_aggr_buff_virt;
#else /* MY_DEF_HERE */
				dev_dbg(pdev, "Assign Rx aggregate buffer for further processing\n");
				tdm_intr_info->tdm_rx_buff = rx_aggr_buff_virt;
#endif /* MY_DEF_HERE */
				tdm_intr_info->int_type |= MV_RX_INT;
			}
		}
	}

	for (ch = 0; ch < MV_TDM2C_TOTAL_CHANNELS; ch++) {

		if (status_and_mask & TX_UNDERFLOW_BIT(ch)) {

#if defined(MY_DEF_HERE)
			dev_dbg(tdm2c->dev, "Tx underflow(ch%d) - checking for root cause...\n",
#else /* MY_DEF_HERE */
			dev_dbg(pdev, "Tx underflow(ch%d) - checking for root cause...\n",
#endif /* MY_DEF_HERE */
				    ch);
#if defined(MY_DEF_HERE)
			if (tdm2c->enable) {
				dev_dbg(tdm2c->dev, "Tx underflow ERROR\n");
#else /* MY_DEF_HERE */
			if (tdm_enable) {
				dev_dbg(pdev, "Tx underflow ERROR\n");
#endif /* MY_DEF_HERE */
				tdm_intr_info->int_type |= MV_TX_ERROR_INT;
				if (!(status_and_mask & TX_BIT(ch))) {
					ret = -1;
					/* 0 -> Tx is done for both channels */
					if (tdm2c_ch_tx_low(ch) == 0) {
#if defined(MY_DEF_HERE)
						dev_dbg(tdm2c->dev, "Assign Tx aggregate buffer for further processing\n");
						tdm_intr_info->tdm_tx_buff = tdm2c->tx_aggr_buff_virt;
#else /* MY_DEF_HERE */
						dev_dbg(pdev, "Assign Tx aggregate buffer for further processing\n");
						tdm_intr_info->tdm_tx_buff = tx_aggr_buff_virt;
#endif /* MY_DEF_HERE */
						tdm_intr_info->int_type |= MV_TX_INT;
					}
				}
			} else {
#if defined(MY_DEF_HERE)
				dev_dbg(tdm2c->dev, "Expected Tx underflow(not an error)\n");
#else /* MY_DEF_HERE */
				dev_dbg(pdev, "Expected Tx underflow(not an error)\n");
#endif /* MY_DEF_HERE */
				tdm_intr_info->int_type |= MV_CHAN_STOP_INT;
				/* Update number of channels already stopped */
#if defined(MY_DEF_HERE)
				tdm_intr_info->data = ++tdm2c->chan_stop_count;
				writel(readl(tdm2c->regs + INT_STATUS_MASK_REG) & (~(TDM_INT_TX(ch))),
				       tdm2c->regs + INT_STATUS_MASK_REG);
#else /* MY_DEF_HERE */
				tdm_intr_info->data = ++chan_stop_count;
				writel(readl(regs + INT_STATUS_MASK_REG) & (~(TDM_INT_TX(ch))),
				       regs + INT_STATUS_MASK_REG);
#endif /* MY_DEF_HERE */
			}
		}

		if (status_and_mask & RX_OVERFLOW_BIT(ch)) {
#if defined(MY_DEF_HERE)
			dev_dbg(tdm2c->dev, "Rx overflow(ch%d) - checking for root cause...\n", ch);
			if (tdm2c->enable) {
				dev_dbg(tdm2c->dev, "Rx overflow ERROR\n");
#else /* MY_DEF_HERE */
			dev_dbg(pdev, "Rx overflow(ch%d) - checking for root cause...\n", ch);
			if (tdm_enable) {
				dev_dbg(pdev, "Rx overflow ERROR\n");
#endif /* MY_DEF_HERE */
				tdm_intr_info->int_type |= MV_RX_ERROR_INT;
				if (!(status_and_mask & RX_BIT(ch))) {
					ret = -1;
					/* 0 -> Rx is done for both channels */
					if (tdm2c_ch_rx_low(ch) == 0) {
#if defined(MY_DEF_HERE)
						dev_dbg(tdm2c->dev, "Assign Rx aggregate buffer for further processing\n");
						tdm_intr_info->tdm_rx_buff = tdm2c->rx_aggr_buff_virt;
#else /* MY_DEF_HERE */
						dev_dbg(pdev, "Assign Rx aggregate buffer for further processing\n");
						tdm_intr_info->tdm_rx_buff = rx_aggr_buff_virt;
#endif /* MY_DEF_HERE */
						tdm_intr_info->int_type |= MV_RX_INT;
					}
				}
			} else {
#if defined(MY_DEF_HERE)
				dev_dbg(tdm2c->dev, "Expected Rx overflow(not an error)\n");
#else /* MY_DEF_HERE */
				dev_dbg(pdev, "Expected Rx overflow(not an error)\n");
#endif /* MY_DEF_HERE */
				tdm_intr_info->int_type |= MV_CHAN_STOP_INT;
#if defined(MY_DEF_HERE)
				/* Update number of channels already stopped */
				tdm_intr_info->data = ++tdm2c->chan_stop_count;
				writel(readl(tdm2c->regs + INT_STATUS_MASK_REG) & (~(TDM_INT_RX(ch))),
				       tdm2c->regs + INT_STATUS_MASK_REG);
#else /* MY_DEF_HERE */
				tdm_intr_info->data = ++chan_stop_count; /* Update number of channels already stopped */
				writel(readl(regs + INT_STATUS_MASK_REG) & (~(TDM_INT_RX(ch))),
				       regs + INT_STATUS_MASK_REG);
#endif /* MY_DEF_HERE */
			}
		}
	}

	/* clear TDM interrupts */
#if defined(MY_DEF_HERE)
	writel(~status_reg, tdm2c->regs + INT_STATUS_REG);
#else /* MY_DEF_HERE */
	writel(~status_reg, regs + INT_STATUS_REG);
#endif /* MY_DEF_HERE */

	/* Check if interrupt was missed -> restart */
	if  (int_tx_miss != -1)  {
#if defined(MY_DEF_HERE)
		dev_err(tdm2c->dev, "Missing Tx Interrupt Detected ch%d!!!\n", int_tx_miss);
#else /* MY_DEF_HERE */
		dev_err(pdev, "Missing Tx Interrupt Detected ch%d!!!\n", int_tx_miss);
#endif /* MY_DEF_HERE */
		if (int_tx_miss)
#if defined(MY_DEF_HERE)
			tdm2c->int_tx1_count = tdm2c->int_tx0_count;
#else /* MY_DEF_HERE */
			int_tx1_count = int_tx0_count;
#endif /* MY_DEF_HERE */
		else
#if defined(MY_DEF_HERE)
			tdm2c->int_tx0_count  = (tdm2c->int_tx1_count + 1);
#else /* MY_DEF_HERE */
			int_tx0_count  = (int_tx1_count + 1);
#endif /* MY_DEF_HERE */
		ret = -1;
	}

	if  (int_rx_miss != -1)  {
#if defined(MY_DEF_HERE)
		dev_err(tdm2c->dev, "Missing Rx Interrupt Detected ch%d!!!\n", int_rx_miss);
#else /* MY_DEF_HERE */
		dev_err(pdev, "Missing Rx Interrupt Detected ch%d!!!\n", int_rx_miss);
#endif /* MY_DEF_HERE */
		if (int_rx_miss)
#if defined(MY_DEF_HERE)
			tdm2c->int_rx1_count = tdm2c->int_rx0_count;
#else /* MY_DEF_HERE */
			int_rx1_count = int_rx0_count;
#endif /* MY_DEF_HERE */
		else
#if defined(MY_DEF_HERE)
			tdm2c->int_rx0_count  = (tdm2c->int_rx1_count + 1);
#else /* MY_DEF_HERE */
			int_rx0_count  = (int_rx1_count + 1);
#endif /* MY_DEF_HERE */
		ret = -1;
	}

	if (ret == -1) {
#if defined(MY_DEF_HERE)
		tdm2c->int_lock = true;
		tdm2c->pcm_restart_count++;
#else /* MY_DEF_HERE */
		int_lock = 1;
		pcm_restart_count++;
#endif /* MY_DEF_HERE */
	}

	return ret;
}

void tdm2c_intr_enable(void)
{
#if defined(MY_DEF_HERE)
	writel((readl(tdm2c->regs + INT_STATUS_MASK_REG) | TDM_INT_SLIC),
	       tdm2c->regs + INT_STATUS_MASK_REG);
#else /* MY_DEF_HERE */
	writel((readl(regs + INT_STATUS_MASK_REG) | TDM_INT_SLIC),
	       regs + INT_STATUS_MASK_REG);
#endif /* MY_DEF_HERE */
}

void tdm2c_intr_disable(void)
{
	u32 val = ~TDM_INT_SLIC;

#if defined(MY_DEF_HERE)
	writel((readl(tdm2c->regs + INT_STATUS_MASK_REG) & val),
	       tdm2c->regs + INT_STATUS_MASK_REG);
#else /* MY_DEF_HERE */
	writel((readl(regs + INT_STATUS_MASK_REG) & val),
	       regs + INT_STATUS_MASK_REG);
#endif /* MY_DEF_HERE */
}

void tdm2c_pcm_if_reset(void)
{
	/* SW PCM reset assert */
#if defined(MY_DEF_HERE)
	mv_phone_reset_bit(tdm2c->regs + TDM_MISC_REG, 0x00000001);
#else /* MY_DEF_HERE */
	mv_phone_reset_bit(regs + TDM_MISC_REG, 0x00000001);
#endif /* MY_DEF_HERE */

	mdelay(10);

	/* SW PCM reset de-assert */
#if defined(MY_DEF_HERE)
	mv_phone_set_bit(tdm2c->regs + TDM_MISC_REG, 0x00000001);
#else /* MY_DEF_HERE */
	mv_phone_set_bit(regs + TDM_MISC_REG, 0x00000001);
#endif /* MY_DEF_HERE */

	/* Wait a bit more - might be fine tuned */
	mdelay(50);

#if defined(MY_DEF_HERE)
	dev_dbg(tdm2c->dev, "%s: Exit\n", __func__);
#else /* MY_DEF_HERE */
	dev_dbg(pdev, "%s: Exit\n", __func__);
#endif /* MY_DEF_HERE */
}

/* Debug routines */
void tdm2c_reg_dump(u32 offset)
{
#if defined(MY_DEF_HERE)
	dev_info(tdm2c->dev, "0x%05x: %08x\n", offset, readl(tdm2c->regs + offset));
#else /* MY_DEF_HERE */
	dev_info(pdev, "0x%05x: %08x\n", offset, readl(regs + offset));
#endif /* MY_DEF_HERE */
}

void tdm2c_regs_dump(void)
{
	u8 i;
	struct tdm2c_ch_info *ch_info;

#if defined(MY_DEF_HERE)
	dev_info(tdm2c->dev, "TDM Control:\n");
#else /* MY_DEF_HERE */
	dev_info(pdev, "TDM Control:\n");
#endif /* MY_DEF_HERE */
	tdm2c_reg_dump(TDM_SPI_MUX_REG);
	tdm2c_reg_dump(INT_RESET_SELECT_REG);
	tdm2c_reg_dump(INT_STATUS_MASK_REG);
	tdm2c_reg_dump(INT_STATUS_REG);
	tdm2c_reg_dump(INT_EVENT_MASK_REG);
	tdm2c_reg_dump(PCM_CTRL_REG);
	tdm2c_reg_dump(TIMESLOT_CTRL_REG);
	tdm2c_reg_dump(PCM_CLK_RATE_DIV_REG);
	tdm2c_reg_dump(FRAME_TIMESLOT_REG);
	tdm2c_reg_dump(DUMMY_RX_WRITE_DATA_REG);
	tdm2c_reg_dump(MISC_CTRL_REG);
#if defined(MY_DEF_HERE)
	dev_info(tdm2c->dev, "TDM Channel Control:\n");
#else /* MY_DEF_HERE */
	dev_info(pdev, "TDM Channel Control:\n");
#endif /* MY_DEF_HERE */
	for (i = 0; i < MV_TDM2C_TOTAL_CHANNELS; i++) {
		tdm2c_reg_dump(CH_DELAY_CTRL_REG(i));
		tdm2c_reg_dump(CH_SAMPLE_REG(i));
		tdm2c_reg_dump(CH_DBG_REG(i));
		tdm2c_reg_dump(CH_TX_CUR_ADDR_REG(i));
		tdm2c_reg_dump(CH_RX_CUR_ADDR_REG(i));
		tdm2c_reg_dump(CH_ENABLE_REG(i));
		tdm2c_reg_dump(CH_BUFF_OWN_REG(i));
		tdm2c_reg_dump(CH_TX_ADDR_REG(i));
		tdm2c_reg_dump(CH_RX_ADDR_REG(i));
	}
#if defined(MY_DEF_HERE)
	dev_info(tdm2c->dev, "TDM interrupts:\n");
#else /* MY_DEF_HERE */
	dev_info(pdev, "TDM interrupts:\n");
#endif /* MY_DEF_HERE */
	tdm2c_reg_dump(INT_EVENT_MASK_REG);
	tdm2c_reg_dump(INT_STATUS_MASK_REG);
	tdm2c_reg_dump(INT_STATUS_REG);
	for (i = 0; i < MV_TDM2C_TOTAL_CHANNELS; i++) {
#if defined(MY_DEF_HERE)
		dev_info(tdm2c->dev, "ch%d info:\n", i);
		ch_info = tdm2c->ch_info[i];
		dev_info(tdm2c->dev, "RX buffs:\n");
		dev_info(tdm2c->dev, "buff0: virt=%p phys=%p\n",
			 ch_info->rx_buff_virt[0], (u32 *) (ch_info->rx_buff_phys[0]));
		dev_info(tdm2c->dev, "buff1: virt=%p phys=%p\n",
			 ch_info->rx_buff_virt[1], (u32 *) (ch_info->rx_buff_phys[1]));
		dev_info(tdm2c->dev, "TX buffs:\n");
		dev_info(tdm2c->dev, "buff0: virt=%p phys=%p\n",
			 ch_info->tx_buff_virt[0], (u32 *) (ch_info->tx_buff_phys[0]));
		dev_info(tdm2c->dev, "buff1: virt=%p phys=%p\n",
			 ch_info->tx_buff_virt[1], (u32 *) (ch_info->tx_buff_phys[1]));
#else /* MY_DEF_HERE */
		dev_info(pdev, "ch%d info:\n", i);
		ch_info = tdm_ch_info[i];
		dev_info(pdev, "RX buffs:\n");
		dev_info(pdev, "buff0: virt=%p phys=%p\n",
			 ch_info->rxBuffVirt[0], (u32 *) (ch_info->rxBuffPhys[0]));
		dev_info(pdev, "buff1: virt=%p phys=%p\n",
			 ch_info->rxBuffVirt[1], (u32 *) (ch_info->rxBuffPhys[1]));
		dev_info(pdev, "TX buffs:\n");
		dev_info(pdev, "buff0: virt=%p phys=%p\n",
			 ch_info->txBuffVirt[0], (u32 *) (ch_info->txBuffPhys[0]));
		dev_info(pdev, "buff1: virt=%p phys=%p\n",
			 ch_info->txBuffVirt[1], (u32 *) (ch_info->txBuffPhys[1]));
#endif /* MY_DEF_HERE */
	}
}

#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
void tdm2c_ext_stats_get(struct mv_phone_extended_stats *tdm_ext_stats)
#else /* MY_DEF_HERE */
void tdm2c_ext_stats_get(struct mv_phone_extended_stats *tdmExtStats)
#endif /* MY_DEF_HERE */
{
#if defined(MY_DEF_HERE)
	tdm_ext_stats->int_rx_count = tdm2c->int_rx_count;
	tdm_ext_stats->int_tx_count = tdm2c->int_tx_count;
	tdm_ext_stats->int_rx0_count = tdm2c->int_rx0_count;
	tdm_ext_stats->int_tx0_count = tdm2c->int_tx0_count;
	tdm_ext_stats->int_rx1_count = tdm2c->int_rx1_count;
	tdm_ext_stats->int_tx1_count = tdm2c->int_tx1_count;
	tdm_ext_stats->int_rx0_miss = tdm2c->int_rx0_miss;
	tdm_ext_stats->int_tx0_miss = tdm2c->int_tx0_miss;
	tdm_ext_stats->int_rx1_miss = tdm2c->int_rx1_miss;
	tdm_ext_stats->int_tx1_miss = tdm2c->int_tx1_miss;
	tdm_ext_stats->pcm_restart_count = tdm2c->pcm_restart_count;
#else /* MY_DEF_HERE */
	tdmExtStats->int_rx_count = int_rx_count;
	tdmExtStats->int_tx_count = int_tx_count;
	tdmExtStats->int_rx0_count = int_rx0_count;
	tdmExtStats->int_tx0_count = int_tx0_count;
	tdmExtStats->int_rx1_count = int_rx1_count;
	tdmExtStats->int_tx1_count = int_tx1_count;
	tdmExtStats->int_rx0_miss = int_rx0_miss;
	tdmExtStats->int_tx0_miss = int_tx0_miss;
	tdmExtStats->int_rx1_miss = int_rx1_miss;
	tdmExtStats->int_tx1_miss = int_tx1_miss;
	tdmExtStats->pcm_restart_count = pcm_restart_count;
#endif /* MY_DEF_HERE */
}
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
#endif
#endif /* MY_DEF_HERE */
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)

/* Initialize decoding windows */
int tdm2c_set_mbus_windows(struct device *dev, void __iomem *regs,
			   const struct mbus_dram_target_info *dram)
{
	int i;

	if (!dram) {
		dev_err(dev, "no mbus dram info\n");
		return -EINVAL;
	}

	for (i = 0; i < TDM_MBUS_MAX_WIN; i++) {
		writel(0, regs + TDM_WIN_CTRL_REG(i));
		writel(0, regs + TDM_WIN_BASE_REG(i));
	}

	for (i = 0; i < dram->num_cs; i++) {
		const struct mbus_dram_window *cs = dram->cs + i;

		/* Write size, attributes and target id to control register */
		writel(((cs->size - 1) & 0xffff0000) |
			(cs->mbus_attr << 8) |
			(dram->mbus_dram_target_id << 4) | 1,
			regs + TDM_WIN_CTRL_REG(i));
		/* Write base address to base register */
		writel(cs->base, regs + TDM_WIN_BASE_REG(i));
	}

	return 0;
}
#endif /* MY_DEF_HERE */
