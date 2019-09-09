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
/* Globals */
#else /* MY_DEF_HERE */
#undef	MV_COMM_UNIT_DEBUG
#define	MV_COMM_UNIT_RPT_SUPPORT /* Repeat mode must be set */
#undef	MV_COMM_UNIT_TEST_SUPPORT

/* defines */
#define TOTAL_CHAINS		2
#define CONFIG_RBSZ		16
#define NEXT_BUFF(buff)		((buff + 1) % TOTAL_CHAINS)
#define PREV_BUFF(buff)		(buff == 0 ? (TOTAL_CHAINS-1) : (buff-1))
#define MAX_POLL_USEC		100000	/* 100ms */
#define COMM_UNIT_SW_RST	(1 << 5)
#define OLD_INT_WA_BIT		(1 << 15)
#define MV_TDM_PCM_CLK_8MHZ	1

/* globals */
static int tdm_enable;
static int pcm_enable;
static u8 sample_size;
static u8 sampling_coeff;
static u16 total_channels;
static u8 prev_rx_buff, next_tx_buff;
static u8 *rx_buff_virt[TOTAL_CHAINS], *tx_buff_virt[TOTAL_CHAINS];
static dma_addr_t rx_buff_phys[TOTAL_CHAINS], tx_buff_phys[TOTAL_CHAINS];
static struct tdmmc_mcdma_rx_desc *mcdma_rx_desc_ptr[TOTAL_CHAINS];
static struct tdmmc_mcdma_tx_desc *mcdma_tx_desc_ptr[TOTAL_CHAINS];
static dma_addr_t mcdma_rx_desc_phys[TOTAL_CHAINS], mcdma_tx_desc_phys[TOTAL_CHAINS];
#endif /* MY_DEF_HERE */
static struct tdmmc_dram_entry def_dpram_entry = { 0, 0, 0x1, 0x1, 0, 0, 0x1, 0, 0, 0, 0 };
#if defined(MY_DEF_HERE)
static struct tdmmc_dev *tdmmc;
#else /* MY_DEF_HERE */
static u32 ctrl_family_id;
static struct device *pdev;
static void __iomem *regs;

static enum tdmmc_ip_version tdmmc_ip_ver_get(u32 ctrl_family_id)
{
	switch (ctrl_family_id) {
	case MV_65XX_DEV_ID:
		return MV_COMMUNIT_IP_VER_ORIGIN;
	case MV_78XX0:
	case MV_88F66X0:
	case MV_88F67X0:
		return MV_COMMUNIT_IP_VER_REVISE_1;
	default:
		return MV_COMMUNIT_IP_VER_REVISE_1;
	}
}
#endif /* MY_DEF_HERE */

static void tdmmc_desc_chain_build(void)
{
	u32 chan, index, buff_size;

	/* Calculate single Rx/Tx buffer size */
#if defined(MY_DEF_HERE)
	buff_size = (tdmmc->sample_size * MV_TDM_TOTAL_CH_SAMPLES * tdmmc->sampling_coeff);
#else /* MY_DEF_HERE */
	buff_size = (sample_size * MV_TDM_TOTAL_CH_SAMPLES * sampling_coeff);
#endif /* MY_DEF_HERE */

	/* Initialize descriptors fields */
#if defined(MY_DEF_HERE)
	for (chan = 0; chan < tdmmc->total_channels; chan++) {
#else /* MY_DEF_HERE */
	for (chan = 0; chan < total_channels; chan++) {
#endif /* MY_DEF_HERE */
		for (index = 0; index < TOTAL_CHAINS; index++) {
			/* Associate data buffers to descriptors physBuffPtr */
#if defined(MY_DEF_HERE)
			((struct tdmmc_mcdma_rx_desc *) (tdmmc->rx_desc_virt[index] + chan))->phys_buff_ptr =
			    (u32) (tdmmc->rx_buff_phys[index] + (chan * buff_size));
			((struct tdmmc_mcdma_tx_desc *) (tdmmc->tx_desc_virt[index] + chan))->phys_buff_ptr =
			    (u32) (tdmmc->tx_buff_phys[index] + (chan * buff_size));
#else /* MY_DEF_HERE */
			((struct tdmmc_mcdma_rx_desc *) (mcdma_rx_desc_ptr[index] + chan))->phys_buff_ptr =
			    (u32) (rx_buff_phys[index] + (chan * buff_size));
			((struct tdmmc_mcdma_tx_desc *) (mcdma_tx_desc_ptr[index] + chan))->phys_buff_ptr =
			    (u32) (tx_buff_phys[index] + (chan * buff_size));
#endif /* MY_DEF_HERE */

			/* Build cyclic descriptors chain for each channel */
#if defined(MY_DEF_HERE)
			((struct tdmmc_mcdma_rx_desc *) (tdmmc->rx_desc_virt[index] + chan))->phys_next_desc_ptr =
			    (u32) (tdmmc->rx_desc_phys[((index + 1) % TOTAL_CHAINS)] +
#else /* MY_DEF_HERE */
			((struct tdmmc_mcdma_rx_desc *) (mcdma_rx_desc_ptr[index] + chan))->phys_next_desc_ptr =
			    (u32) (mcdma_rx_desc_phys[((index + 1) % TOTAL_CHAINS)] +
#endif /* MY_DEF_HERE */
				      (chan * sizeof(struct tdmmc_mcdma_rx_desc)));

#if defined(MY_DEF_HERE)
			((struct tdmmc_mcdma_tx_desc *) (tdmmc->tx_desc_virt[index] + chan))->phys_next_desc_ptr =
			    (u32) (tdmmc->tx_desc_phys[((index + 1) % TOTAL_CHAINS)] +
#else /* MY_DEF_HERE */
			((struct tdmmc_mcdma_tx_desc *) (mcdma_tx_desc_ptr[index] + chan))->phys_next_desc_ptr =
			    (u32) (mcdma_tx_desc_phys[((index + 1) % TOTAL_CHAINS)] +
#endif /* MY_DEF_HERE */
				      (chan * sizeof(struct tdmmc_mcdma_tx_desc)));

			/* Set Byte_Count/Buffer_Size Rx descriptor fields */
#if defined(MY_DEF_HERE)
			((struct tdmmc_mcdma_rx_desc *) (tdmmc->rx_desc_virt[index] + chan))->byte_cnt = 0;
			((struct tdmmc_mcdma_rx_desc *) (tdmmc->rx_desc_virt[index] + chan))->buff_size = buff_size;
#else /* MY_DEF_HERE */
			((struct tdmmc_mcdma_rx_desc *) (mcdma_rx_desc_ptr[index] + chan))->byte_cnt = 0;
			((struct tdmmc_mcdma_rx_desc *) (mcdma_rx_desc_ptr[index] + chan))->buff_size = buff_size;
#endif /* MY_DEF_HERE */

			/* Set Shadow_Byte_Count/Byte_Count Tx descriptor fields */
#if defined(MY_DEF_HERE)
			((struct tdmmc_mcdma_tx_desc *) (tdmmc->tx_desc_virt[index] + chan))->shadow_byte_cnt =
													 buff_size;
			((struct tdmmc_mcdma_tx_desc *) (tdmmc->tx_desc_virt[index] + chan))->byte_cnt = buff_size;
#else /* MY_DEF_HERE */
			((struct tdmmc_mcdma_tx_desc *) (mcdma_tx_desc_ptr[index] + chan))->shadow_byte_cnt = buff_size;
			((struct tdmmc_mcdma_tx_desc *) (mcdma_tx_desc_ptr[index] + chan))->byte_cnt = buff_size;
#endif /* MY_DEF_HERE */

			/* Set Command/Status Rx/Tx descriptor fields */
#if defined(MY_DEF_HERE)
			((struct tdmmc_mcdma_rx_desc *) (tdmmc->rx_desc_virt[index] + chan))->cmd_status =
#else /* MY_DEF_HERE */
			((struct tdmmc_mcdma_rx_desc *) (mcdma_rx_desc_ptr[index] + chan))->cmd_status =
#endif /* MY_DEF_HERE */
			    (CONFIG_MCDMA_DESC_CMD_STATUS);
#if defined(MY_DEF_HERE)
			((struct tdmmc_mcdma_tx_desc *) (tdmmc->tx_desc_virt[index] + chan))->cmd_status =
#else /* MY_DEF_HERE */
			((struct tdmmc_mcdma_tx_desc *) (mcdma_tx_desc_ptr[index] + chan))->cmd_status =
#endif /* MY_DEF_HERE */
			    (CONFIG_MCDMA_DESC_CMD_STATUS);
		}
	}
}

static void tdmmc_mcdma_mcsc_start(void)
{
	u32 chan;
	dma_addr_t rx_desc_phys_addr, tx_desc_phys_addr;

	tdmmc_desc_chain_build();

	/* Set current Rx/Tx descriptors  */
#if defined(MY_DEF_HERE)
	for (chan = 0; chan < tdmmc->total_channels; chan++) {
		rx_desc_phys_addr = tdmmc->rx_desc_phys[0] + (chan * sizeof(struct tdmmc_mcdma_rx_desc));
		tx_desc_phys_addr = tdmmc->tx_desc_phys[0] + (chan * sizeof(struct tdmmc_mcdma_tx_desc));
		writel(rx_desc_phys_addr, tdmmc->regs + MCDMA_CURRENT_RECEIVE_DESC_PTR_REG(chan));
		writel(tx_desc_phys_addr, tdmmc->regs + MCDMA_CURRENT_TRANSMIT_DESC_PTR_REG(chan));
#else /* MY_DEF_HERE */
	for (chan = 0; chan < total_channels; chan++) {
		rx_desc_phys_addr = mcdma_rx_desc_phys[0] + (chan * sizeof(struct tdmmc_mcdma_rx_desc));
		tx_desc_phys_addr = mcdma_tx_desc_phys[0] + (chan * sizeof(struct tdmmc_mcdma_tx_desc));
		writel(rx_desc_phys_addr, regs + MCDMA_CURRENT_RECEIVE_DESC_PTR_REG(chan));
		writel(tx_desc_phys_addr, regs + MCDMA_CURRENT_TRANSMIT_DESC_PTR_REG(chan));
#endif /* MY_DEF_HERE */
	}

	/* Restore MCDMA Rx/Tx control registers */
#if defined(MY_DEF_HERE)
	for (chan = 0; chan < tdmmc->total_channels; chan++) {
#else /* MY_DEF_HERE */
	for (chan = 0; chan < total_channels; chan++) {
#endif /* MY_DEF_HERE */
		/* Set RMCCx */
#if defined(MY_DEF_HERE)
		writel(CONFIG_RMCCx, tdmmc->regs + MCDMA_RECEIVE_CONTROL_REG(chan));
#else /* MY_DEF_HERE */
		writel(CONFIG_RMCCx, regs + MCDMA_RECEIVE_CONTROL_REG(chan));
#endif /* MY_DEF_HERE */

		/* Set TMCCx */
#if defined(MY_DEF_HERE)
		writel(CONFIG_TMCCx, tdmmc->regs + MCDMA_TRANSMIT_CONTROL_REG(chan));
#else /* MY_DEF_HERE */
		writel(CONFIG_TMCCx, regs + MCDMA_TRANSMIT_CONTROL_REG(chan));
#endif /* MY_DEF_HERE */
	}

	/* Set Rx/Tx periodical interrupts */
#if defined(MY_DEF_HERE)
	if (tdmmc->ip_ver == TDMMC_REV0)
#else /* MY_DEF_HERE */
	if (tdmmc_ip_ver_get(ctrl_family_id) == MV_COMMUNIT_IP_VER_ORIGIN)
#endif /* MY_DEF_HERE */
		writel(CONFIG_VOICE_PERIODICAL_INT_CONTROL_WA,
#if defined(MY_DEF_HERE)
		       tdmmc->regs + VOICE_PERIODICAL_INT_CONTROL_REG);
#else /* MY_DEF_HERE */
		       regs + VOICE_PERIODICAL_INT_CONTROL_REG);
#endif /* MY_DEF_HERE */
	else
		writel(CONFIG_VOICE_PERIODICAL_INT_CONTROL,
#if defined(MY_DEF_HERE)
		       tdmmc->regs + VOICE_PERIODICAL_INT_CONTROL_REG);
#else /* MY_DEF_HERE */
		       regs + VOICE_PERIODICAL_INT_CONTROL_REG);
#endif /* MY_DEF_HERE */

	/* MCSC Global Tx Enable */
#if defined(MY_DEF_HERE)
	if (!tdmmc->tdm_enable)
		mv_phone_set_bit(tdmmc->regs + MCSC_GLOBAL_CONFIG_REG, MCSC_GLOBAL_CONFIG_TXEN_MASK);
#else /* MY_DEF_HERE */
	if (!tdm_enable)
		mv_phone_set_bit(regs + MCSC_GLOBAL_CONFIG_REG, MCSC_GLOBAL_CONFIG_TXEN_MASK);
#endif /* MY_DEF_HERE */

	/* Enable MCSC-Tx & MCDMA-Rx */
#if defined(MY_DEF_HERE)
	for (chan = 0; chan < tdmmc->total_channels; chan++) {
#else /* MY_DEF_HERE */
	for (chan = 0; chan < total_channels; chan++) {
#endif /* MY_DEF_HERE */
		/* Enable Tx in TMCCx */
#if defined(MY_DEF_HERE)
		if (!tdmmc->tdm_enable)
			mv_phone_set_bit(tdmmc->regs + MCSC_CHx_TRANSMIT_CONFIG_REG(chan), MTCRx_ET_MASK);
#else /* MY_DEF_HERE */
		if (!tdm_enable)
			mv_phone_set_bit(regs + MCSC_CHx_TRANSMIT_CONFIG_REG(chan), MTCRx_ET_MASK);
#endif /* MY_DEF_HERE */

		/* Enable Rx in: MCRDPx */
#if defined(MY_DEF_HERE)
		mv_phone_set_bit(tdmmc->regs + MCDMA_RECEIVE_CONTROL_REG(chan), MCDMA_ERD_MASK);
#else /* MY_DEF_HERE */
		mv_phone_set_bit(regs + MCDMA_RECEIVE_CONTROL_REG(chan), MCDMA_ERD_MASK);
#endif /* MY_DEF_HERE */
	}

	/* MCSC Global Rx Enable */
#if defined(MY_DEF_HERE)
	if (!tdmmc->tdm_enable)
		mv_phone_set_bit(tdmmc->regs + MCSC_GLOBAL_CONFIG_REG, MCSC_GLOBAL_CONFIG_RXEN_MASK);
#else /* MY_DEF_HERE */
	if (!tdm_enable)
		mv_phone_set_bit(regs + MCSC_GLOBAL_CONFIG_REG, MCSC_GLOBAL_CONFIG_RXEN_MASK);
#endif /* MY_DEF_HERE */

	/* Enable MCSC-Rx & MCDMA-Tx */
#if defined(MY_DEF_HERE)
	for (chan = 0; chan < tdmmc->total_channels; chan++) {
#else /* MY_DEF_HERE */
	for (chan = 0; chan < total_channels; chan++) {
#endif /* MY_DEF_HERE */
		/* Enable Rx in RMCCx */
#if defined(MY_DEF_HERE)
		if (!tdmmc->tdm_enable)
			mv_phone_set_bit(tdmmc->regs + MCSC_CHx_RECEIVE_CONFIG_REG(chan), MRCRx_ER_MASK);
#else /* MY_DEF_HERE */
		if (!tdm_enable)
			mv_phone_set_bit(regs + MCSC_CHx_RECEIVE_CONFIG_REG(chan), MRCRx_ER_MASK);
#endif /* MY_DEF_HERE */

		/* Enable Tx in MCTDPx */
#if defined(MY_DEF_HERE)
		mv_phone_set_bit(tdmmc->regs + MCDMA_TRANSMIT_CONTROL_REG(chan), MCDMA_TXD_MASK);
#else /* MY_DEF_HERE */
		mv_phone_set_bit(regs + MCDMA_TRANSMIT_CONTROL_REG(chan), MCDMA_TXD_MASK);
#endif /* MY_DEF_HERE */
	}

	/* Disable Rx/Tx return to half */
#if defined(MY_DEF_HERE)
	mv_phone_reset_bit(tdmmc->regs + FLEX_TDM_CONFIG_REG, (TDM_RR2HALF_MASK | TDM_TR2HALF_MASK));
#else /* MY_DEF_HERE */
	mv_phone_reset_bit(regs + FLEX_TDM_CONFIG_REG, (TDM_RR2HALF_MASK | TDM_TR2HALF_MASK));
#endif /* MY_DEF_HERE */
	/* Wait at least 1 frame */
	udelay(200);
}

static void tdmmc_mcdma_mcsc_abort(void)
{
	u32 chan;

	/* Abort MCSC/MCDMA in case we got here from tdmmc_release() */
#if defined(MY_DEF_HERE)
	if (!tdmmc->tdm_enable) {
#else /* MY_DEF_HERE */
	if (!tdm_enable) {
#endif /* MY_DEF_HERE */
		/* Clear MCSC Rx/Tx channel enable */
#if defined(MY_DEF_HERE)
		for (chan = 0; chan < tdmmc->total_channels; chan++) {
			mv_phone_reset_bit(tdmmc->regs + MCSC_CHx_RECEIVE_CONFIG_REG(chan), MRCRx_ER_MASK);
			mv_phone_reset_bit(tdmmc->regs + MCSC_CHx_TRANSMIT_CONFIG_REG(chan), MTCRx_ET_MASK);
#else /* MY_DEF_HERE */
		for (chan = 0; chan < total_channels; chan++) {
			mv_phone_reset_bit(regs + MCSC_CHx_RECEIVE_CONFIG_REG(chan), MRCRx_ER_MASK);
			mv_phone_reset_bit(regs + MCSC_CHx_TRANSMIT_CONFIG_REG(chan), MTCRx_ET_MASK);
#endif /* MY_DEF_HERE */
		}

		/* MCSC Global Rx/Tx Disable */
#if defined(MY_DEF_HERE)
		mv_phone_reset_bit(tdmmc->regs + MCSC_GLOBAL_CONFIG_REG, MCSC_GLOBAL_CONFIG_RXEN_MASK);
		mv_phone_reset_bit(tdmmc->regs + MCSC_GLOBAL_CONFIG_REG, MCSC_GLOBAL_CONFIG_TXEN_MASK);
#else /* MY_DEF_HERE */
		mv_phone_reset_bit(regs + MCSC_GLOBAL_CONFIG_REG, MCSC_GLOBAL_CONFIG_RXEN_MASK);
		mv_phone_reset_bit(regs + MCSC_GLOBAL_CONFIG_REG, MCSC_GLOBAL_CONFIG_TXEN_MASK);
#endif /* MY_DEF_HERE */
	}
}

static void tdmmc_mcdma_stop(void)
{
	u32 index, chan, max_poll;
	u32 curr_rx_desc, curr_tx_desc, next_tx_buff = 0, next_rx_buff = 0;

	/***************************/
	/*    Stop MCDMA - Rx/Tx   */
	/***************************/
#if defined(MY_DEF_HERE)
	for (chan = 0; chan < tdmmc->total_channels; chan++) {
		curr_rx_desc = readl(tdmmc->regs + MCDMA_CURRENT_RECEIVE_DESC_PTR_REG(chan));
#else /* MY_DEF_HERE */
	for (chan = 0; chan < total_channels; chan++) {
		curr_rx_desc = readl(regs + MCDMA_CURRENT_RECEIVE_DESC_PTR_REG(chan));
#endif /* MY_DEF_HERE */
		for (index = 0; index < TOTAL_CHAINS; index++) {
#if defined(MY_DEF_HERE)
			if (curr_rx_desc == (tdmmc->rx_desc_phys[index] +
			    (chan * (sizeof(struct tdmmc_mcdma_rx_desc))))) {
#else /* MY_DEF_HERE */
			if (curr_rx_desc == (mcdma_rx_desc_phys[index] + (chan*(sizeof(struct tdmmc_mcdma_rx_desc))))) {
#endif /* MY_DEF_HERE */
				next_rx_buff = NEXT_BUFF(index);
				break;
			}
		}

		if (index == TOTAL_CHAINS) {
#if defined(MY_DEF_HERE)
			dev_err(tdmmc->dev, "%s: ERROR, couldn't Rx descriptor match for chan(%d)\n",
#else /* MY_DEF_HERE */
			dev_err(pdev, "%s: ERROR, couldn't Rx descriptor match for chan(%d)\n",
#endif /* MY_DEF_HERE */
				__func__, chan);
			break;
		}

		((struct tdmmc_mcdma_rx_desc *)
#if defined(MY_DEF_HERE)
			(tdmmc->rx_desc_virt[next_rx_buff] + chan))->phys_next_desc_ptr = 0;
#else /* MY_DEF_HERE */
			(mcdma_rx_desc_ptr[next_rx_buff] + chan))->phys_next_desc_ptr = 0;
#endif /* MY_DEF_HERE */
		((struct tdmmc_mcdma_rx_desc *)
#if defined(MY_DEF_HERE)
			(tdmmc->rx_desc_virt[next_rx_buff] + chan))->cmd_status = (LAST_BIT | OWNER);
#else /* MY_DEF_HERE */
			(mcdma_rx_desc_ptr[next_rx_buff] + chan))->cmd_status = (LAST_BIT | OWNER);
#endif /* MY_DEF_HERE */
	}

#if defined(MY_DEF_HERE)
	for (chan = 0; chan < tdmmc->total_channels; chan++) {
		curr_tx_desc = readl(tdmmc->regs + MCDMA_CURRENT_TRANSMIT_DESC_PTR_REG(chan));
#else /* MY_DEF_HERE */
	for (chan = 0; chan < total_channels; chan++) {
		curr_tx_desc = readl(regs + MCDMA_CURRENT_TRANSMIT_DESC_PTR_REG(chan));
#endif /* MY_DEF_HERE */
		for (index = 0; index < TOTAL_CHAINS; index++) {
#if defined(MY_DEF_HERE)
			if (curr_tx_desc == (tdmmc->tx_desc_phys[index] +
			    (chan * (sizeof(struct tdmmc_mcdma_tx_desc))))) {
#else /* MY_DEF_HERE */
			if (curr_tx_desc == (mcdma_tx_desc_phys[index] + (chan*(sizeof(struct tdmmc_mcdma_tx_desc))))) {
#endif /* MY_DEF_HERE */
				next_tx_buff = NEXT_BUFF(index);
				break;
			}
		}

		if (index == TOTAL_CHAINS) {
#if defined(MY_DEF_HERE)
			dev_err(tdmmc->dev, "%s: ERROR, couldn't Tx descriptor match for chan(%d)\n",
#else /* MY_DEF_HERE */
			dev_err(pdev, "%s: ERROR, couldn't Tx descriptor match for chan(%d)\n",
#endif /* MY_DEF_HERE */
				__func__, chan);
			return;
		}

		((struct tdmmc_mcdma_tx_desc *)
#if defined(MY_DEF_HERE)
			(tdmmc->tx_desc_virt[next_tx_buff] + chan))->phys_next_desc_ptr = 0;
#else /* MY_DEF_HERE */
			(mcdma_tx_desc_ptr[next_tx_buff] + chan))->phys_next_desc_ptr = 0;
#endif /* MY_DEF_HERE */
		((struct tdmmc_mcdma_tx_desc *)
#if defined(MY_DEF_HERE)
			(tdmmc->tx_desc_virt[next_tx_buff] + chan))->cmd_status = (LAST_BIT | OWNER);
#else /* MY_DEF_HERE */
			(mcdma_tx_desc_ptr[next_tx_buff] + chan))->cmd_status = (LAST_BIT | OWNER);
#endif /* MY_DEF_HERE */
	}

#if defined(MY_DEF_HERE)
	for (chan = 0; chan < tdmmc->total_channels; chan++) {
#else /* MY_DEF_HERE */
	for (chan = 0; chan < total_channels; chan++) {
#endif /* MY_DEF_HERE */
		max_poll = 0;
		while ((max_poll < MAX_POLL_USEC) &&
#if defined(MY_DEF_HERE)
			(readl(tdmmc->regs + MCDMA_TRANSMIT_CONTROL_REG(chan)) & MCDMA_TXD_MASK)) {
#else /* MY_DEF_HERE */
			(readl(regs + MCDMA_TRANSMIT_CONTROL_REG(chan)) & MCDMA_TXD_MASK)) {
#endif /* MY_DEF_HERE */
			udelay(1);
			max_poll++;
		}

		if (max_poll >= MAX_POLL_USEC) {
#if defined(MY_DEF_HERE)
			dev_err(tdmmc->dev, "%s: Error, MCDMA TXD polling timeout(ch%d)\n", __func__, chan);
#else /* MY_DEF_HERE */
			dev_err(pdev, "%s: Error, MCDMA TXD polling timeout(ch%d)\n", __func__, chan);
#endif /* MY_DEF_HERE */
			return;
		}

		max_poll = 0;
		while ((max_poll < MAX_POLL_USEC) &&
#if defined(MY_DEF_HERE)
			(readl(tdmmc->regs + MCDMA_RECEIVE_CONTROL_REG(chan)) & MCDMA_ERD_MASK)) {
#else /* MY_DEF_HERE */
			(readl(regs + MCDMA_RECEIVE_CONTROL_REG(chan)) & MCDMA_ERD_MASK)) {
#endif /* MY_DEF_HERE */
			udelay(1);
			max_poll++;
		}

		if (max_poll >= MAX_POLL_USEC) {
#if defined(MY_DEF_HERE)
			dev_err(tdmmc->dev, "%s: Error, MCDMA ERD polling timeout(ch%d)\n", __func__, chan);
#else /* MY_DEF_HERE */
			dev_err(pdev, "%s: Error, MCDMA ERD polling timeout(ch%d)\n", __func__, chan);
#endif /* MY_DEF_HERE */
			return;
		}
	}

	/* Disable Rx/Tx periodical interrupts */
#if defined(MY_DEF_HERE)
	writel(0xffffffff, tdmmc->regs + VOICE_PERIODICAL_INT_CONTROL_REG);
#else /* MY_DEF_HERE */
	writel(0xffffffff, regs + VOICE_PERIODICAL_INT_CONTROL_REG);
#endif /* MY_DEF_HERE */

	/* Enable Rx/Tx return to half */
#if defined(MY_DEF_HERE)
	mv_phone_set_bit(tdmmc->regs + FLEX_TDM_CONFIG_REG, (TDM_RR2HALF_MASK | TDM_TR2HALF_MASK));
#else /* MY_DEF_HERE */
	mv_phone_set_bit(regs + FLEX_TDM_CONFIG_REG, (TDM_RR2HALF_MASK | TDM_TR2HALF_MASK));
#endif /* MY_DEF_HERE */
	/* Wait at least 1 frame */
	udelay(200);

	/* Manual reset to channel-balancing mechanism */
#if defined(MY_DEF_HERE)
	mv_phone_set_bit(tdmmc->regs + MCSC_GLOBAL_CONFIG_REG, MCSC_GLOBAL_CONFIG_MAI_MASK);
#else /* MY_DEF_HERE */
	mv_phone_set_bit(regs + MCSC_GLOBAL_CONFIG_REG, MCSC_GLOBAL_CONFIG_MAI_MASK);
#endif /* MY_DEF_HERE */
	udelay(1);
}

void tdmmc_intr_enable(u8 device_id)
{
}

void tdmmc_intr_disable(u8 device_id)
{
}

void tdmmc_show(void)
{
	u32 index;

	/* Dump data buffers & descriptors addresses */
	for (index = 0; index < TOTAL_CHAINS; index++) {
#if defined(MY_DEF_HERE)
		dev_dbg(tdmmc->dev, "Rx Buff(%d): virt = 0x%lx, phys = 0x%lx\n",
			index, (ulong)tdmmc->rx_buff_virt[index],
			(ulong)tdmmc->rx_buff_phys[index]);
		dev_dbg(tdmmc->dev, "Tx Buff(%d): virt = 0x%lx, phys = 0x%lx\n",
			index, (ulong)tdmmc->tx_buff_virt[index],
			(ulong)tdmmc->tx_buff_phys[index]);
		dev_dbg(tdmmc->dev, "Rx Desc(%d): virt = 0x%lx, phys = 0x%lx\n",
			index, (ulong)tdmmc->rx_desc_virt[index],
			(ulong) tdmmc->rx_desc_phys[index]);
		dev_dbg(tdmmc->dev, "Tx Desc(%d): virt = 0x%lx, phys = 0x%lx\n",
			index, (ulong)tdmmc->tx_desc_virt[index],
			(ulong)tdmmc->tx_desc_phys[index]);
#else /* MY_DEF_HERE */
		dev_info(pdev, "Rx Buff(%d): virt = 0x%lx, phys = 0x%lx\n",
			 index, (ulong)rx_buff_virt[index],
			 (ulong)rx_buff_phys[index]);
		dev_info(pdev, "Tx Buff(%d): virt = 0x%lx, phys = 0x%lx\n",
			 index, (ulong)tx_buff_virt[index],
			 (ulong)tx_buff_phys[index]);
		dev_info(pdev, "Rx Desc(%d): virt = 0x%lx, phys = 0x%lx\n",
			 index, (ulong)mcdma_rx_desc_ptr[index],
			 (ulong) mcdma_rx_desc_phys[index]);
		dev_info(pdev, "Tx Desc(%d): virt = 0x%lx, phys = 0x%lx\n",
			 index, (ulong)mcdma_tx_desc_ptr[index],
			 (ulong)mcdma_tx_desc_phys[index]);
#endif /* MY_DEF_HERE */
	}
}

int tdmmc_init(void __iomem *base, struct device *dev,
#if defined(MY_DEF_HERE)
	       struct mv_phone_params *tdm_params, enum mv_phone_frame_ts frame_ts,
	       enum tdmmc_ip_version tdmmc_ip_ver)
#else /* MY_DEF_HERE */
	       struct mv_phone_params *tdm_params, struct mv_phone_data *hal_data)
#endif /* MY_DEF_HERE */
{
	u16 pcm_slot, index;
	u32 buff_size, chan, total_rx_desc_size, total_tx_desc_size;
	u32 max_poll, clk_sync_ctrl_reg, count;
	struct tdmmc_dram_entry *act_dpram_entry;
#if defined(MY_DEF_HERE)
	int ret;

	/* Initialize or reset main structure */
	if (!tdmmc) {
		tdmmc = devm_kzalloc(dev, sizeof(struct tdmmc_dev), GFP_KERNEL);
		if (!tdmmc)
			return -ENOMEM;
	} else {
		memset(tdmmc, 0,  sizeof(struct tdmmc_dev));
	}
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	/* Initialize remaining parameters */
	tdmmc->regs = base;
	tdmmc->tdm_enable = false;
	tdmmc->pcm_enable = false;
	tdmmc->total_channels = tdm_params->total_channels;
	tdmmc->prev_rx = 0;
	tdmmc->next_tx = 0;
	tdmmc->ip_ver = tdmmc_ip_ver;
	tdmmc->dev = dev;
#else /* MY_DEF_HERE */
	regs = base;
	/* Initialize driver resources */
	tdm_enable = 0;
	pcm_enable = 0;
	total_channels = tdm_params->total_channels;
	prev_rx_buff = 0;
	next_tx_buff = 0;
	ctrl_family_id = hal_data->family_id;
	pdev = dev;
#endif /* MY_DEF_HERE */

	/* Check parameters */
	if ((tdm_params->total_channels > MV_TDMMC_TOTAL_CHANNELS) ||
	    (tdm_params->sampling_period > MV_TDM_MAX_SAMPLING_PERIOD)) {
#if defined(MY_DEF_HERE)
		dev_err(tdmmc->dev, "%s: Error, bad parameters\n", __func__);
#else /* MY_DEF_HERE */
		dev_err(pdev, "%s: Error, bad parameters\n", __func__);
#endif /* MY_DEF_HERE */
		return -EINVAL;
	}

	/* Extract sampling period coefficient */
#if defined(MY_DEF_HERE)
	tdmmc->sampling_coeff = (tdm_params->sampling_period / MV_TDM_BASE_SAMPLING_PERIOD);
#else /* MY_DEF_HERE */
	sampling_coeff = (tdm_params->sampling_period / MV_TDM_BASE_SAMPLING_PERIOD);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	tdmmc->sample_size = tdm_params->pcm_format;
#else /* MY_DEF_HERE */
	sample_size = tdm_params->pcm_format;
#endif /* MY_DEF_HERE */

	/* Calculate single Rx/Tx buffer size */
#if defined(MY_DEF_HERE)
	buff_size = (tdmmc->sample_size * MV_TDM_TOTAL_CH_SAMPLES * tdmmc->sampling_coeff);
#else /* MY_DEF_HERE */
	buff_size = (sample_size * MV_TDM_TOTAL_CH_SAMPLES * sampling_coeff);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	/* Allocate non-cached data buffers for all channels */
	dev_dbg(tdmmc->dev, "%s: allocate 0x%x for data buffers total channels = %d\n",
		__func__, (buff_size * tdmmc->total_channels), tdmmc->total_channels);
#else /* MY_DEF_HERE */
	/* Allocate cached data buffers for all channels */
	dev_dbg(pdev, "%s: allocate 0x%x for data buffers total_channels = %d\n",
		__func__, (buff_size * total_channels), total_channels);
#endif /* MY_DEF_HERE */

	for (index = 0; index < TOTAL_CHAINS; index++) {
#if defined(MY_DEF_HERE)
		tdmmc->rx_buff_virt[index] = dma_alloc_coherent(tdmmc->dev, buff_size * tdmmc->total_channels,
						       &tdmmc->rx_buff_phys[index], GFP_KERNEL);
		tdmmc->tx_buff_virt[index] = dma_alloc_coherent(tdmmc->dev, buff_size * tdmmc->total_channels,
						       &tdmmc->tx_buff_phys[index], GFP_KERNEL);

		if (!tdmmc->rx_buff_virt[index] || !tdmmc->tx_buff_virt[index]) {
			ret = -ENOMEM;
			goto err_buff_virt;
#else /* MY_DEF_HERE */
		rx_buff_virt[index] = dma_alloc_coherent(pdev, buff_size * total_channels,
						       &rx_buff_phys[index], GFP_KERNEL);
		tx_buff_virt[index] = dma_alloc_coherent(pdev, buff_size * total_channels,
						       &tx_buff_phys[index], GFP_KERNEL);
#ifdef MV_COMM_UNIT_TEST_SUPPORT
	/* Fill Tx buffers with incremental pattern */
		{
			int i, j;

			for (j = 0; j < total_channels; j++) {
				for (i = 0; i < buffSize; i++)
					*(u8 *) (tx_buff_virt[index]+i+(j*buffSize)) = (u8)(i+1);
			}
#endif /* MY_DEF_HERE */
		}
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
#endif
#endif /* MY_DEF_HERE */
	}

	/* Allocate non-cached MCDMA Rx/Tx descriptors */
#if defined(MY_DEF_HERE)
	total_rx_desc_size = tdmmc->total_channels * sizeof(struct tdmmc_mcdma_rx_desc);
	total_tx_desc_size = tdmmc->total_channels * sizeof(struct tdmmc_mcdma_tx_desc);
#else /* MY_DEF_HERE */
	total_rx_desc_size = total_channels * sizeof(struct tdmmc_mcdma_rx_desc);
	total_tx_desc_size = total_channels * sizeof(struct tdmmc_mcdma_tx_desc);
#endif /* MY_DEF_HERE */

	dev_dbg(dev, "%s: allocate %dB for Rx/Tx descriptors\n",
		__func__, total_tx_desc_size);
	for (index = 0; index < TOTAL_CHAINS; index++) {
#if defined(MY_DEF_HERE)
		tdmmc->rx_desc_virt[index] = dma_alloc_coherent(tdmmc->dev, total_rx_desc_size,
							   &tdmmc->rx_desc_phys[index], GFP_KERNEL);
		tdmmc->tx_desc_virt[index] = dma_alloc_coherent(tdmmc->dev, total_tx_desc_size,
							   &tdmmc->tx_desc_phys[index], GFP_KERNEL);

		if (!tdmmc->rx_desc_virt[index] || !tdmmc->tx_desc_virt[index]) {
			ret = -ENOMEM;
			goto err_mcdma_desc;
		}
#else /* MY_DEF_HERE */
		mcdma_rx_desc_ptr[index] = dma_alloc_coherent(pdev, total_rx_desc_size,
							   &mcdma_rx_desc_phys[index], GFP_KERNEL);
		mcdma_tx_desc_ptr[index] = dma_alloc_coherent(pdev, total_tx_desc_size,
							   &mcdma_tx_desc_phys[index], GFP_KERNEL);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
		/* XXX Add BUG() */
#endif /* MY_DEF_HERE */
		/* Check descriptors alignment */
#if defined(MY_DEF_HERE)
		if (((ulong) tdmmc->rx_desc_virt[index] | (ulong)tdmmc->tx_desc_virt[index]) &
#else /* MY_DEF_HERE */
		if (((ulong) mcdma_rx_desc_ptr[index] | (ulong)mcdma_tx_desc_ptr[index]) &
#endif /* MY_DEF_HERE */
		    (sizeof(struct tdmmc_mcdma_rx_desc) - 1)) {
#if defined(MY_DEF_HERE)
			dev_err(tdmmc->dev, "%s: Error, unaligned MCDMA Rx/Tx descriptors\n", __func__);
			ret = -ENOMEM;
			goto err_mcdma_desc;
#else /* MY_DEF_HERE */
			dev_err(pdev, "%s: Error, unaligned MCDMA Rx/Tx descriptors\n", __func__);
			return -ENOMEM;
#endif /* MY_DEF_HERE */
		}
	}

	/* Poll MCDMA for reset completion */
	max_poll = 0;
#if defined(MY_DEF_HERE)
	while ((max_poll < MAX_POLL_USEC) && !(readl(tdmmc->regs + MCDMA_GLOBAL_CONTROL_REG) & MCDMA_RID_MASK)) {
#else /* MY_DEF_HERE */
	while ((max_poll < MAX_POLL_USEC) && !(readl(regs + MCDMA_GLOBAL_CONTROL_REG) & MCDMA_RID_MASK)) {
#endif /* MY_DEF_HERE */
		udelay(1);
		max_poll++;
	}

	if (max_poll >= MAX_POLL_USEC) {
#if defined(MY_DEF_HERE)
		dev_err(tdmmc->dev, "Error, MCDMA reset completion timout\n");
		ret = -ETIME;
		goto err_mcdma_desc;
#else /* MY_DEF_HERE */
		dev_err(pdev, "Error, MCDMA reset completion timout\n");
		return -ETIME;
#endif /* MY_DEF_HERE */
	}

	/* Poll MCSC for RAM initialization done */
#if defined(MY_DEF_HERE)
	if (!(readl(tdmmc->regs + MCSC_GLOBAL_INT_CAUSE_REG) & MCSC_GLOBAL_INT_CAUSE_INIT_DONE_MASK)) {
#else /* MY_DEF_HERE */
	if (!(readl(regs + MCSC_GLOBAL_INT_CAUSE_REG) & MCSC_GLOBAL_INT_CAUSE_INIT_DONE_MASK)) {
#endif /* MY_DEF_HERE */
		max_poll = 0;
		while ((max_poll < MAX_POLL_USEC) &&
#if defined(MY_DEF_HERE)
		       !(readl(tdmmc->regs + MCSC_GLOBAL_INT_CAUSE_REG) & MCSC_GLOBAL_INT_CAUSE_INIT_DONE_MASK)) {
#else /* MY_DEF_HERE */
		       !(readl(regs + MCSC_GLOBAL_INT_CAUSE_REG) & MCSC_GLOBAL_INT_CAUSE_INIT_DONE_MASK)) {
#endif /* MY_DEF_HERE */
			udelay(1);
			max_poll++;
		}

		if (max_poll >= MAX_POLL_USEC) {
#if defined(MY_DEF_HERE)
			dev_err(tdmmc->dev, "Error, MCDMA RAM initialization timout\n");
			ret = -ETIME;
			goto err_mcdma_desc;
#else /* MY_DEF_HERE */
			dev_err(pdev, "Error, MCDMA RAM initialization timout\n");
			return -ETIME;
#endif /* MY_DEF_HERE */
		}
	}

	/***************************************************************/
	/* MCDMA Configuration(use default MCDMA linked-list settings) */
	/***************************************************************/
	/* Set Rx Service Queue Arbiter Weight Register */
#if defined(MY_DEF_HERE)
	writel((readl(tdmmc->regs + RX_SERVICE_QUEUE_ARBITER_WEIGHT_REG) & ~(0x1f << 24)),
	       tdmmc->regs + RX_SERVICE_QUEUE_ARBITER_WEIGHT_REG);
#else /* MY_DEF_HERE */
	writel((readl(regs + RX_SERVICE_QUEUE_ARBITER_WEIGHT_REG) & ~(0x1f << 24)), /*| MCDMA_RSQW_MASK));*/
	       regs + RX_SERVICE_QUEUE_ARBITER_WEIGHT_REG);
#endif /* MY_DEF_HERE */

	/* Set Tx Service Queue Arbiter Weight Register */
#if defined(MY_DEF_HERE)
	writel((readl(tdmmc->regs + TX_SERVICE_QUEUE_ARBITER_WEIGHT_REG) & ~(0x1f << 24)),
	       tdmmc->regs + TX_SERVICE_QUEUE_ARBITER_WEIGHT_REG);
#else /* MY_DEF_HERE */
	writel((readl(regs + TX_SERVICE_QUEUE_ARBITER_WEIGHT_REG) & ~(0x1f << 24)), /*| MCDMA_TSQW_MASK));*/
	       regs + TX_SERVICE_QUEUE_ARBITER_WEIGHT_REG);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	for (chan = 0; chan < tdmmc->total_channels; chan++) {
#else /* MY_DEF_HERE */
	for (chan = 0; chan < total_channels; chan++) {
#endif /* MY_DEF_HERE */
		/* Set RMCCx */
#if defined(MY_DEF_HERE)
		writel(CONFIG_RMCCx, tdmmc->regs + MCDMA_RECEIVE_CONTROL_REG(chan));
#else /* MY_DEF_HERE */
		writel(CONFIG_RMCCx, regs + MCDMA_RECEIVE_CONTROL_REG(chan));
#endif /* MY_DEF_HERE */

		/* Set TMCCx */
#if defined(MY_DEF_HERE)
		writel(CONFIG_TMCCx, tdmmc->regs + MCDMA_TRANSMIT_CONTROL_REG(chan));
#else /* MY_DEF_HERE */
		writel(CONFIG_TMCCx, regs + MCDMA_TRANSMIT_CONTROL_REG(chan));
#endif /* MY_DEF_HERE */
	}

	/**********************/
	/* MCSC Configuration */
	/**********************/
	/* Disable Rx/Tx channel balancing & Linear mode fix */
#if defined(MY_DEF_HERE)
	mv_phone_set_bit(tdmmc->regs + MCSC_GLOBAL_CONFIG_REG, MCSC_GLOBAL_CONFIG_TCBD_MASK);
#else /* MY_DEF_HERE */
	mv_phone_set_bit(regs + MCSC_GLOBAL_CONFIG_REG, MCSC_GLOBAL_CONFIG_TCBD_MASK);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	for (chan = 0; chan < tdmmc->total_channels; chan++) {
		writel(CONFIG_MRCRx, tdmmc->regs + MCSC_CHx_RECEIVE_CONFIG_REG(chan));
		writel(CONFIG_MTCRx, tdmmc->regs + MCSC_CHx_TRANSMIT_CONFIG_REG(chan));
#else /* MY_DEF_HERE */
	for (chan = 0; chan < total_channels; chan++) {
		writel(CONFIG_MRCRx, regs + MCSC_CHx_RECEIVE_CONFIG_REG(chan));
		writel(CONFIG_MTCRx, regs + MCSC_CHx_TRANSMIT_CONFIG_REG(chan));
#endif /* MY_DEF_HERE */
	}

	/* Enable RX/TX linear byte swap, only in linear mode */
	if (tdm_params->pcm_format == MV_PCM_FORMAT_1BYTE)
#if defined(MY_DEF_HERE)
		writel((readl(tdmmc->regs + MCSC_GLOBAL_CONFIG_EXTENDED_REG) & (~CONFIG_LINEAR_BYTE_SWAP)),
		       tdmmc->regs + MCSC_GLOBAL_CONFIG_EXTENDED_REG);
#else /* MY_DEF_HERE */
		writel((readl(regs + MCSC_GLOBAL_CONFIG_EXTENDED_REG) & (~CONFIG_LINEAR_BYTE_SWAP)),
		       regs + MCSC_GLOBAL_CONFIG_EXTENDED_REG);
#endif /* MY_DEF_HERE */
	else
#if defined(MY_DEF_HERE)
		writel((readl(tdmmc->regs + MCSC_GLOBAL_CONFIG_EXTENDED_REG) | CONFIG_LINEAR_BYTE_SWAP),
		       tdmmc->regs + MCSC_GLOBAL_CONFIG_EXTENDED_REG);
#else /* MY_DEF_HERE */
		writel((readl(regs + MCSC_GLOBAL_CONFIG_EXTENDED_REG) | CONFIG_LINEAR_BYTE_SWAP),
		       regs + MCSC_GLOBAL_CONFIG_EXTENDED_REG);
#endif /* MY_DEF_HERE */

	/***********************************************/
	/* Shared Bus to Crossbar Bridge Configuration */
	/***********************************************/
	/* Set Timeout Counter Register */
#if defined(MY_DEF_HERE)
	writel((readl(tdmmc->regs + TIME_OUT_COUNTER_REG) | TIME_OUT_THRESHOLD_COUNT_MASK),
	       tdmmc->regs + TIME_OUT_COUNTER_REG);
#else /* MY_DEF_HERE */
	writel((readl(regs + TIME_OUT_COUNTER_REG) | TIME_OUT_THRESHOLD_COUNT_MASK), regs + TIME_OUT_COUNTER_REG);
#endif /* MY_DEF_HERE */

	/*************************************************/
	/* Time Division Multiplexing(TDM) Configuration */
	/*************************************************/
	act_dpram_entry = kmalloc(sizeof(struct tdmmc_dram_entry), GFP_KERNEL);
#if defined(MY_DEF_HERE)
	if (!act_dpram_entry) {
		ret = -EINVAL;
		goto err_mcdma_desc;
	}
#else /* MY_DEF_HERE */
	if (!act_dpram_entry)
		return -EINVAL;
#endif /* MY_DEF_HERE */

	memcpy(act_dpram_entry, &def_dpram_entry, sizeof(struct tdmmc_dram_entry));
#if defined(MY_DEF_HERE)
	/* Set repeat mode bits for (tdmmc->sample_size > 1) */
	act_dpram_entry->rpt = ((tdmmc->sample_size == MV_PCM_FORMAT_1BYTE) ? 0 : 1);
#else /* MY_DEF_HERE */
	/* Set repeat mode bits for (sample_size > 1) */
	act_dpram_entry->rpt = ((sample_size == MV_PCM_FORMAT_1BYTE) ? 0 : 1);
#endif /* MY_DEF_HERE */

	/* Reset all Rx/Tx DPRAM entries to default value */
	for (index = 0; index < (2 * MV_TDM_MAX_HALF_DPRAM_ENTRIES); index++) {
#if defined(MY_DEF_HERE)
		writel(*((u32 *) act_dpram_entry), tdmmc->regs + FLEX_TDM_RDPR_REG(index));
		writel(*((u32 *) act_dpram_entry), tdmmc->regs + FLEX_TDM_TDPR_REG(index));
#else /* MY_DEF_HERE */
		writel(*((u32 *) act_dpram_entry), regs + FLEX_TDM_RDPR_REG(index));
		writel(*((u32 *) act_dpram_entry), regs + FLEX_TDM_TDPR_REG(index));
#endif /* MY_DEF_HERE */
	}

	/* Set active Rx/Tx DPRAM entries */
#if defined(MY_DEF_HERE)
	for (chan = 0; chan < tdmmc->total_channels; chan++) {
#else /* MY_DEF_HERE */
	for (chan = 0; chan < total_channels; chan++) {
#endif /* MY_DEF_HERE */
		/* Same time slot number for both Rx & Tx */
		pcm_slot = tdm_params->pcm_slot[chan];

		/* Verify time slot is within frame boundries */
#if defined(MY_DEF_HERE)
		if (pcm_slot >= frame_ts) {
			dev_err(tdmmc->dev, "Error, time slot(%d) exceeded maximum(%d)\n",
				pcm_slot, frame_ts);
			ret = -ETIME;
			goto err_dpram;
#else /* MY_DEF_HERE */
		if (pcm_slot >= hal_data->frame_ts) {
			dev_err(pdev, "Error, time slot(%d) exceeded maximum(%d)\n",
				pcm_slot, hal_data->frame_ts);
			goto err;
#endif /* MY_DEF_HERE */
		}

		/* Verify time slot is aligned to sample size */
#if defined(MY_DEF_HERE)
		if ((tdmmc->sample_size > MV_PCM_FORMAT_1BYTE) && (pcm_slot & 1)) {
			dev_err(tdmmc->dev, "Error, time slot(%d) not aligned to Linear PCM sample size\n",
#else /* MY_DEF_HERE */
		if ((sample_size > MV_PCM_FORMAT_1BYTE) && (pcm_slot & 1)) {
			dev_err(pdev, "Error, time slot(%d) not aligned to Linear PCM sample size\n",
#endif /* MY_DEF_HERE */
				pcm_slot);
#if defined(MY_DEF_HERE)
			ret = -EINVAL;
			goto err_dpram;
#else /* MY_DEF_HERE */
			goto err;
#endif /* MY_DEF_HERE */
		}

		/* Update relevant DPRAM fields */
		act_dpram_entry->ch = chan;
		act_dpram_entry->mask = 0xff;

		/* Extract physical DPRAM entry id */
#if defined(MY_DEF_HERE)
		index = ((tdmmc->sample_size == MV_PCM_FORMAT_1BYTE) ? pcm_slot : (pcm_slot / 2));
#else /* MY_DEF_HERE */
		index = ((sample_size == MV_PCM_FORMAT_1BYTE) ? pcm_slot : (pcm_slot / 2));
#endif /* MY_DEF_HERE */

		/* DPRAM low half */
#if defined(MY_DEF_HERE)
		writel(*((u32 *) act_dpram_entry), tdmmc->regs + FLEX_TDM_RDPR_REG(index));
		writel(*((u32 *) act_dpram_entry), tdmmc->regs + FLEX_TDM_TDPR_REG(index));
#else /* MY_DEF_HERE */
		writel(*((u32 *) act_dpram_entry), regs + FLEX_TDM_RDPR_REG(index));
		writel(*((u32 *) act_dpram_entry), regs + FLEX_TDM_TDPR_REG(index));
#endif /* MY_DEF_HERE */

		/* DPRAM high half(mirroring DPRAM low half) */
		act_dpram_entry->mask = 0;
		writel(*((u32 *) act_dpram_entry),
#if defined(MY_DEF_HERE)
		       tdmmc->regs + FLEX_TDM_RDPR_REG((MV_TDM_MAX_HALF_DPRAM_ENTRIES + index)));
#else /* MY_DEF_HERE */
		       regs + FLEX_TDM_RDPR_REG((MV_TDM_MAX_HALF_DPRAM_ENTRIES + index)));
#endif /* MY_DEF_HERE */
		writel(*((u32 *) act_dpram_entry),
#if defined(MY_DEF_HERE)
		       tdmmc->regs + FLEX_TDM_TDPR_REG((MV_TDM_MAX_HALF_DPRAM_ENTRIES + index)));
#else /* MY_DEF_HERE */
		       regs + FLEX_TDM_TDPR_REG((MV_TDM_MAX_HALF_DPRAM_ENTRIES + index)));
#endif /* MY_DEF_HERE */

		/* WideBand mode */
#if defined(MY_DEF_HERE)
		if (tdmmc->sample_size == MV_PCM_FORMAT_4BYTES) {
			index = (index + (frame_ts / tdmmc->sample_size));
#else /* MY_DEF_HERE */
		if (sample_size == MV_PCM_FORMAT_4BYTES) {
			index = (index + (hal_data->frame_ts / sample_size));
#endif /* MY_DEF_HERE */
			/* DPRAM low half */
			act_dpram_entry->mask = 0xff;
#if defined(MY_DEF_HERE)
			writel(*((u32 *) act_dpram_entry), tdmmc->regs + FLEX_TDM_RDPR_REG(index));
			writel(*((u32 *) act_dpram_entry), tdmmc->regs + FLEX_TDM_TDPR_REG(index));
#else /* MY_DEF_HERE */
			writel(*((u32 *) act_dpram_entry), regs + FLEX_TDM_RDPR_REG(index));
			writel(*((u32 *) act_dpram_entry), regs + FLEX_TDM_TDPR_REG(index));
#endif /* MY_DEF_HERE */

			/* DPRAM high half(mirroring DPRAM low half) */
			act_dpram_entry->mask = 0;
			writel(*((u32 *) act_dpram_entry),
#if defined(MY_DEF_HERE)
			       tdmmc->regs + FLEX_TDM_RDPR_REG((MV_TDM_MAX_HALF_DPRAM_ENTRIES + index)));
#else /* MY_DEF_HERE */
			       regs + FLEX_TDM_RDPR_REG((MV_TDM_MAX_HALF_DPRAM_ENTRIES + index)));
#endif /* MY_DEF_HERE */
			writel(*((u32 *) act_dpram_entry),
#if defined(MY_DEF_HERE)
			       tdmmc->regs + FLEX_TDM_TDPR_REG((MV_TDM_MAX_HALF_DPRAM_ENTRIES + index)));
#else /* MY_DEF_HERE */
			       regs + FLEX_TDM_TDPR_REG((MV_TDM_MAX_HALF_DPRAM_ENTRIES + index)));
#endif /* MY_DEF_HERE */
		}
	}

	/* Fill last Tx/Rx DPRAM entry('LAST'=1) */
	act_dpram_entry->mask = 0;
	act_dpram_entry->ch = 0;
	act_dpram_entry->last = 1;

	/* Index for last entry */
#if defined(MY_DEF_HERE)
	if (tdmmc->sample_size == MV_PCM_FORMAT_1BYTE)
		index = (frame_ts - 1);
#else /* MY_DEF_HERE */
	if (sample_size == MV_PCM_FORMAT_1BYTE)
		index = (hal_data->frame_ts - 1);
#endif /* MY_DEF_HERE */
	else
#if defined(MY_DEF_HERE)
		index = ((frame_ts / 2) - 1);
#else /* MY_DEF_HERE */
		index = ((hal_data->frame_ts / 2) - 1);
#endif /* MY_DEF_HERE */

	/* Low half */
#if defined(MY_DEF_HERE)
	writel(*((u32 *) act_dpram_entry), tdmmc->regs + FLEX_TDM_TDPR_REG(index));
	writel(*((u32 *) act_dpram_entry), tdmmc->regs + FLEX_TDM_RDPR_REG(index));
#else /* MY_DEF_HERE */
	writel(*((u32 *) act_dpram_entry), regs + FLEX_TDM_TDPR_REG(index));
	writel(*((u32 *) act_dpram_entry), regs + FLEX_TDM_RDPR_REG(index));
#endif /* MY_DEF_HERE */
	/* High half */
#if defined(MY_DEF_HERE)
	writel(*((u32 *) act_dpram_entry),
	       tdmmc->regs + FLEX_TDM_TDPR_REG((MV_TDM_MAX_HALF_DPRAM_ENTRIES + index)));
	writel(*((u32 *) act_dpram_entry),
	       tdmmc->regs + FLEX_TDM_RDPR_REG((MV_TDM_MAX_HALF_DPRAM_ENTRIES + index)));
#else /* MY_DEF_HERE */
	writel(*((u32 *) act_dpram_entry), regs + FLEX_TDM_TDPR_REG((MV_TDM_MAX_HALF_DPRAM_ENTRIES + index)));
	writel(*((u32 *) act_dpram_entry), regs + FLEX_TDM_RDPR_REG((MV_TDM_MAX_HALF_DPRAM_ENTRIES + index)));
#endif /* MY_DEF_HERE */

	/* Set TDM_CLK_AND_SYNC_CONTROL register */
#if defined(MY_DEF_HERE)
	clk_sync_ctrl_reg = readl(tdmmc->regs + TDM_CLK_AND_SYNC_CONTROL_REG);
#else /* MY_DEF_HERE */
	clk_sync_ctrl_reg = readl(regs + TDM_CLK_AND_SYNC_CONTROL_REG);
#endif /* MY_DEF_HERE */
	clk_sync_ctrl_reg &= ~(TDM_TX_FSYNC_OUT_ENABLE_MASK | TDM_RX_FSYNC_OUT_ENABLE_MASK |
			TDM_TX_CLK_OUT_ENABLE_MASK | TDM_RX_CLK_OUT_ENABLE_MASK);
	clk_sync_ctrl_reg |= CONFIG_TDM_CLK_AND_SYNC_CONTROL;
#if defined(MY_DEF_HERE)
	writel(clk_sync_ctrl_reg, tdmmc->regs + TDM_CLK_AND_SYNC_CONTROL_REG);
#else /* MY_DEF_HERE */
	writel(clk_sync_ctrl_reg, regs + TDM_CLK_AND_SYNC_CONTROL_REG);
#endif /* MY_DEF_HERE */

	/* Set TDM TCR register */
#if defined(MY_DEF_HERE)
	writel((readl(tdmmc->regs + FLEX_TDM_CONFIG_REG) | CONFIG_FLEX_TDM_CONFIG),
	       tdmmc->regs + FLEX_TDM_CONFIG_REG);
#else /* MY_DEF_HERE */
	writel((readl(regs + FLEX_TDM_CONFIG_REG) | CONFIG_FLEX_TDM_CONFIG), regs + FLEX_TDM_CONFIG_REG);
#endif /* MY_DEF_HERE */

	/**********************************************************************/
	/* Time Division Multiplexing(TDM) Interrupt Controller Configuration */
	/**********************************************************************/
	/* Clear TDM cause and mask registers */
#if defined(MY_DEF_HERE)
	writel(0, tdmmc->regs + COMM_UNIT_TOP_MASK_REG);
	writel(0, tdmmc->regs + TDM_MASK_REG);
	writel(0, tdmmc->regs + COMM_UNIT_TOP_CAUSE_REG);
	writel(0, tdmmc->regs + TDM_CAUSE_REG);
#else /* MY_DEF_HERE */
	writel(0, regs + COMM_UNIT_TOP_MASK_REG);
	writel(0, regs + TDM_MASK_REG);
	writel(0, regs + COMM_UNIT_TOP_CAUSE_REG);
	writel(0, regs + TDM_CAUSE_REG);
#endif /* MY_DEF_HERE */

	/* Clear MCSC cause and mask registers(except InitDone bit) */
#if defined(MY_DEF_HERE)
	writel(0, tdmmc->regs + MCSC_GLOBAL_INT_MASK_REG);
	writel(0, tdmmc->regs + MCSC_EXTENDED_INT_MASK_REG);
	writel(MCSC_GLOBAL_INT_CAUSE_INIT_DONE_MASK, tdmmc->regs + MCSC_GLOBAL_INT_CAUSE_REG);
	writel(0, tdmmc->regs + MCSC_EXTENDED_INT_CAUSE_REG);
#else /* MY_DEF_HERE */
	writel(0, regs + MCSC_GLOBAL_INT_MASK_REG);
	writel(0, regs + MCSC_EXTENDED_INT_MASK_REG);
	writel(MCSC_GLOBAL_INT_CAUSE_INIT_DONE_MASK, regs + MCSC_GLOBAL_INT_CAUSE_REG);
	writel(0, regs + MCSC_EXTENDED_INT_CAUSE_REG);
#endif /* MY_DEF_HERE */

	/* Set output sync counter bits for FS */
#if defined(MY_DEF_HERE)
	count = frame_ts * 8;
#else /* MY_DEF_HERE */
#if defined(MV_TDM_PCM_CLK_8MHZ)
	count = MV_FRAME_128TS * 8;
#elif defined(MV_TDM_PCM_CLK_4MHZ)
	count = MV_FRAME_64TS * 8;
#else /* MV_TDM_PCM_CLK_2MHZ */
	count = MV_FRAME_32TS * 8;
#endif
#endif /* MY_DEF_HERE */
	writel(((count << TDM_SYNC_BIT_RX_OFFS) & TDM_SYNC_BIT_RX_MASK) | (count & TDM_SYNC_BIT_TX_MASK),
#if defined(MY_DEF_HERE)
	       tdmmc->regs + TDM_OUTPUT_SYNC_BIT_COUNT_REG);
#else /* MY_DEF_HERE */
	       regs + TDM_OUTPUT_SYNC_BIT_COUNT_REG);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	tdmmc_show();
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
#endif
#endif /* MY_DEF_HERE */

	/* Enable PCM */
	tdmmc_pcm_start();

	/* Mark TDM I/F as enabled */
#if defined(MY_DEF_HERE)
	tdmmc->tdm_enable = true;
#else /* MY_DEF_HERE */
	tdm_enable = 1;
#endif /* MY_DEF_HERE */

	/* Enable PCLK */
#if defined(MY_DEF_HERE)
	writel((readl(tdmmc->regs + TDM_DATA_DELAY_AND_CLK_CTRL_REG) | CONFIG_TDM_DATA_DELAY_AND_CLK_CTRL),
	       tdmmc->regs + TDM_DATA_DELAY_AND_CLK_CTRL_REG);
#else /* MY_DEF_HERE */
	writel((readl(regs + TDM_DATA_DELAY_AND_CLK_CTRL_REG) | CONFIG_TDM_DATA_DELAY_AND_CLK_CTRL),
	       regs + TDM_DATA_DELAY_AND_CLK_CTRL_REG);
#endif /* MY_DEF_HERE */

	/* Keep the software workaround to enable TEN while set Fsync for none-ALP chips */
	/* Enable TDM */
#if defined(MY_DEF_HERE)
	if (tdmmc->ip_ver == TDMMC_REV0)
		mv_phone_set_bit(tdmmc->regs + FLEX_TDM_CONFIG_REG, TDM_TEN_MASK);
#else /* MY_DEF_HERE */
	if (tdmmc_ip_ver_get(ctrl_family_id) == MV_COMMUNIT_IP_VER_ORIGIN)
		mv_phone_set_bit(regs + FLEX_TDM_CONFIG_REG, TDM_TEN_MASK);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	dev_dbg(tdmmc->dev, "%s: Exit\n", __func__);
#else /* MY_DEF_HERE */
	dev_dbg(pdev, "%s: Exit\n", __func__);
#endif /* MY_DEF_HERE */

	kfree(act_dpram_entry);
	return 0;
#if defined(MY_DEF_HERE)

err_dpram:
#else /* MY_DEF_HERE */
err:
#endif /* MY_DEF_HERE */
	kfree(act_dpram_entry);
#if defined(MY_DEF_HERE)
err_mcdma_desc:
	for (index = 0; index < TOTAL_CHAINS; index++) {
		if (tdmmc->rx_desc_virt[index])
			dma_free_coherent(tdmmc->dev, total_rx_desc_size,
					  tdmmc->rx_desc_virt[index], tdmmc->rx_desc_phys[index]);
		if (tdmmc->tx_desc_virt[index])
			dma_free_coherent(tdmmc->dev, total_tx_desc_size,
					  tdmmc->tx_desc_virt[index], tdmmc->tx_desc_phys[index]);
	}
err_buff_virt:
	for (index = 0; index < TOTAL_CHAINS; index++) {
		if (tdmmc->rx_buff_phys[index])
			dma_free_coherent(tdmmc->dev, buff_size, tdmmc->rx_buff_virt[index],
					  tdmmc->rx_buff_phys[index]);
		if (tdmmc->tx_buff_phys[index])
			dma_free_coherent(tdmmc->dev, buff_size, tdmmc->tx_buff_virt[index],
					  tdmmc->tx_buff_phys[index]);
	}

	return ret;
#else /* MY_DEF_HERE */
	return -EINVAL;
#endif /* MY_DEF_HERE */
}

void tdmmc_release(void)
{
	u32 buff_size, total_rx_desc_size, total_tx_desc_size, index;

#if defined(MY_DEF_HERE)
	if (tdmmc->tdm_enable) {
#else /* MY_DEF_HERE */
	if (tdm_enable) {
#endif /* MY_DEF_HERE */

		/* Mark TDM I/F as disabled */
#if defined(MY_DEF_HERE)
		tdmmc->tdm_enable = false;
#else /* MY_DEF_HERE */
		tdm_enable = 0;
#endif /* MY_DEF_HERE */

		tdmmc_pcm_stop();

		tdmmc_mcdma_mcsc_abort();

		udelay(10);
#if defined(MY_DEF_HERE)
		mv_phone_reset_bit(tdmmc->regs + MCSC_GLOBAL_CONFIG_REG, MCSC_GLOBAL_CONFIG_MAI_MASK);
#else /* MY_DEF_HERE */
		mv_phone_reset_bit(regs + MCSC_GLOBAL_CONFIG_REG, MCSC_GLOBAL_CONFIG_MAI_MASK);
#endif /* MY_DEF_HERE */

		/* Disable TDM */
#if defined(MY_DEF_HERE)
		if (tdmmc->ip_ver == TDMMC_REV0)
			mv_phone_reset_bit(tdmmc->regs + FLEX_TDM_CONFIG_REG, TDM_TEN_MASK);
#else /* MY_DEF_HERE */
		if (tdmmc_ip_ver_get(ctrl_family_id) == MV_COMMUNIT_IP_VER_ORIGIN)
			mv_phone_reset_bit(regs + FLEX_TDM_CONFIG_REG, TDM_TEN_MASK);
#endif /* MY_DEF_HERE */

		/* Disable PCLK */
#if defined(MY_DEF_HERE)
		mv_phone_reset_bit(tdmmc->regs + TDM_DATA_DELAY_AND_CLK_CTRL_REG,
#else /* MY_DEF_HERE */
		mv_phone_reset_bit(regs + TDM_DATA_DELAY_AND_CLK_CTRL_REG,
#endif /* MY_DEF_HERE */
				   (TX_CLK_OUT_ENABLE_MASK |
				    RX_CLK_OUT_ENABLE_MASK));

		/* Calculate total Rx/Tx buffer size */
#if defined(MY_DEF_HERE)
		buff_size = (tdmmc->sample_size * MV_TDM_TOTAL_CH_SAMPLES *
			     tdmmc->sampling_coeff * tdmmc->total_channels);
#else /* MY_DEF_HERE */
		buff_size = (sample_size * MV_TDM_TOTAL_CH_SAMPLES * sampling_coeff * total_channels);
#endif /* MY_DEF_HERE */

		/* Calculate total MCDMA Rx/Tx descriptors chain size */
#if defined(MY_DEF_HERE)
		total_rx_desc_size = tdmmc->total_channels * sizeof(struct tdmmc_mcdma_rx_desc);
		total_tx_desc_size = tdmmc->total_channels * sizeof(struct tdmmc_mcdma_tx_desc);
#else /* MY_DEF_HERE */
		total_rx_desc_size = total_channels * sizeof(struct tdmmc_mcdma_rx_desc);
		total_tx_desc_size = total_channels * sizeof(struct tdmmc_mcdma_tx_desc);
#endif /* MY_DEF_HERE */

		for (index = 0; index < TOTAL_CHAINS; index++) {
			/* Release Rx/Tx data buffers */
#if defined(MY_DEF_HERE)
			dma_free_coherent(tdmmc->dev, buff_size, tdmmc->rx_buff_virt[index],
					  tdmmc->rx_buff_phys[index]);
			dma_free_coherent(tdmmc->dev, buff_size, tdmmc->tx_buff_virt[index],
					  tdmmc->tx_buff_phys[index]);
#else /* MY_DEF_HERE */
			dma_free_coherent(pdev, buff_size, rx_buff_virt[index],
					  rx_buff_phys[index]);
			dma_free_coherent(pdev, buff_size, tx_buff_virt[index],
					  tx_buff_phys[index]);
#endif /* MY_DEF_HERE */

			/* Release MCDMA Rx/Tx descriptors */
#if defined(MY_DEF_HERE)
			dma_free_coherent(tdmmc->dev, total_rx_desc_size,
					  tdmmc->rx_desc_virt[index], tdmmc->rx_desc_phys[index]);
			dma_free_coherent(tdmmc->dev, total_tx_desc_size,
					  tdmmc->tx_desc_virt[index], tdmmc->tx_desc_phys[index]);
#else /* MY_DEF_HERE */
			dma_free_coherent(pdev, total_rx_desc_size,
					  mcdma_rx_desc_ptr[index], mcdma_rx_desc_phys[index]);
			dma_free_coherent(pdev, total_tx_desc_size,
					  mcdma_tx_desc_ptr[index], mcdma_tx_desc_phys[index]);
#endif /* MY_DEF_HERE */
		}
	}
}

void tdmmc_pcm_start(void)
{
	u32 mask_reg;

#if defined(MY_DEF_HERE)
	if (!tdmmc->pcm_enable) {
#else /* MY_DEF_HERE */
	if (!pcm_enable) {
#endif /* MY_DEF_HERE */

		/* Mark PCM I/F as enabled  */
#if defined(MY_DEF_HERE)
		tdmmc->pcm_enable = true;
#else /* MY_DEF_HERE */
		pcm_enable = 1;
#endif /* MY_DEF_HERE */

		tdmmc_mcdma_mcsc_start();

		/* Clear TDM cause and mask registers */
#if defined(MY_DEF_HERE)
		writel(0, tdmmc->regs + COMM_UNIT_TOP_MASK_REG);
		writel(0, tdmmc->regs + TDM_MASK_REG);
		writel(0, tdmmc->regs + COMM_UNIT_TOP_CAUSE_REG);
		writel(0, tdmmc->regs + TDM_CAUSE_REG);
#else /* MY_DEF_HERE */
		writel(0, regs + COMM_UNIT_TOP_MASK_REG);
		writel(0, regs + TDM_MASK_REG);
		writel(0, regs + COMM_UNIT_TOP_CAUSE_REG);
		writel(0, regs + TDM_CAUSE_REG);
#endif /* MY_DEF_HERE */

		/* Clear MCSC cause and mask registers(except InitDone bit) */
#if defined(MY_DEF_HERE)
		writel(0, tdmmc->regs + MCSC_GLOBAL_INT_MASK_REG);
		writel(0, tdmmc->regs + MCSC_EXTENDED_INT_MASK_REG);
		writel(MCSC_GLOBAL_INT_CAUSE_INIT_DONE_MASK, tdmmc->regs + MCSC_GLOBAL_INT_CAUSE_REG);
		writel(0, tdmmc->regs + MCSC_EXTENDED_INT_CAUSE_REG);
#else /* MY_DEF_HERE */
		writel(0, regs + MCSC_GLOBAL_INT_MASK_REG);
		writel(0, regs + MCSC_EXTENDED_INT_MASK_REG);
		writel(MCSC_GLOBAL_INT_CAUSE_INIT_DONE_MASK, regs + MCSC_GLOBAL_INT_CAUSE_REG);
		writel(0, regs + MCSC_EXTENDED_INT_CAUSE_REG);
#endif /* MY_DEF_HERE */

		/* Enable unit interrupts */
#if defined(MY_DEF_HERE)
		mask_reg = readl(tdmmc->regs + TDM_MASK_REG);
		writel(mask_reg | CONFIG_TDM_CAUSE, tdmmc->regs + TDM_MASK_REG);
		writel(CONFIG_COMM_UNIT_TOP_MASK, tdmmc->regs + COMM_UNIT_TOP_MASK_REG);
#else /* MY_DEF_HERE */
		mask_reg = readl(regs + TDM_MASK_REG);
		writel(mask_reg | CONFIG_TDM_CAUSE, regs + TDM_MASK_REG);
		writel(CONFIG_COMM_UNIT_TOP_MASK, regs + COMM_UNIT_TOP_MASK_REG);
#endif /* MY_DEF_HERE */

		/* Enable TDM */
#if defined(MY_DEF_HERE)
		if (tdmmc->ip_ver == TDMMC_REV1)
			mv_phone_set_bit(tdmmc->regs + FLEX_TDM_CONFIG_REG, TDM_TEN_MASK);
#else /* MY_DEF_HERE */
		if (tdmmc_ip_ver_get(ctrl_family_id) == MV_COMMUNIT_IP_VER_REVISE_1)
			mv_phone_set_bit(regs + FLEX_TDM_CONFIG_REG, TDM_TEN_MASK);
#endif /* MY_DEF_HERE */
	}
}

void tdmmc_pcm_stop(void)
{
	u32 buff_size, index;

#if defined(MY_DEF_HERE)
	if (tdmmc->pcm_enable) {
#else /* MY_DEF_HERE */
	if (pcm_enable) {
#endif /* MY_DEF_HERE */
		/* Mark PCM I/F as disabled  */
#if defined(MY_DEF_HERE)
		tdmmc->pcm_enable = false;
#else /* MY_DEF_HERE */
		pcm_enable = 0;
#endif /* MY_DEF_HERE */

		/* Clear TDM cause and mask registers */
#if defined(MY_DEF_HERE)
		writel(0, tdmmc->regs + COMM_UNIT_TOP_MASK_REG);
		writel(0, tdmmc->regs + TDM_MASK_REG);
		writel(0, tdmmc->regs + COMM_UNIT_TOP_CAUSE_REG);
		writel(0, tdmmc->regs + TDM_CAUSE_REG);
#else /* MY_DEF_HERE */
		writel(0, regs + COMM_UNIT_TOP_MASK_REG);
		writel(0, regs + TDM_MASK_REG);
		writel(0, regs + COMM_UNIT_TOP_CAUSE_REG);
		writel(0, regs + TDM_CAUSE_REG);
#endif /* MY_DEF_HERE */

		/* Clear MCSC cause and mask registers(except InitDone bit) */
#if defined(MY_DEF_HERE)
		writel(0, tdmmc->regs + MCSC_GLOBAL_INT_MASK_REG);
		writel(0, tdmmc->regs + MCSC_EXTENDED_INT_MASK_REG);
		writel(MCSC_GLOBAL_INT_CAUSE_INIT_DONE_MASK, tdmmc->regs + MCSC_GLOBAL_INT_CAUSE_REG);
		writel(0, tdmmc->regs + MCSC_EXTENDED_INT_CAUSE_REG);
#else /* MY_DEF_HERE */
		writel(0, regs + MCSC_GLOBAL_INT_MASK_REG);
		writel(0, regs + MCSC_EXTENDED_INT_MASK_REG);
		writel(MCSC_GLOBAL_INT_CAUSE_INIT_DONE_MASK, regs + MCSC_GLOBAL_INT_CAUSE_REG);
		writel(0, regs + MCSC_EXTENDED_INT_CAUSE_REG);
#endif /* MY_DEF_HERE */

		tdmmc_mcdma_stop();

		/* Calculate total Rx/Tx buffer size */
#if defined(MY_DEF_HERE)
		buff_size = (tdmmc->sample_size * MV_TDM_TOTAL_CH_SAMPLES *
			     tdmmc->sampling_coeff * tdmmc->total_channels);
#else /* MY_DEF_HERE */
		buff_size = (sample_size * MV_TDM_TOTAL_CH_SAMPLES * sampling_coeff * total_channels);
#endif /* MY_DEF_HERE */

		/* Clear Rx buffers */
		for (index = 0; index < TOTAL_CHAINS; index++)
#if defined(MY_DEF_HERE)
			memset(tdmmc->rx_buff_virt[index], 0, buff_size);
#else /* MY_DEF_HERE */
			memset(rx_buff_virt[index], 0, buff_size);
#endif /* MY_DEF_HERE */

		/* Disable TDM */
#if defined(MY_DEF_HERE)
		if (tdmmc->ip_ver == TDMMC_REV1)
			mv_phone_reset_bit(tdmmc->regs + FLEX_TDM_CONFIG_REG, TDM_TEN_MASK);
#else /* MY_DEF_HERE */
		if (tdmmc_ip_ver_get(ctrl_family_id) == MV_COMMUNIT_IP_VER_REVISE_1)
			mv_phone_reset_bit(regs + FLEX_TDM_CONFIG_REG, TDM_TEN_MASK);
#endif /* MY_DEF_HERE */
	}
}

int tdmmc_tx(u8 *tdm_tx_buff)
{
	u32 buff_size, index;
	u8 tmp;

	/* Calculate total Tx buffer size */
#if defined(MY_DEF_HERE)
	buff_size = (tdmmc->sample_size * MV_TDM_TOTAL_CH_SAMPLES *
		     tdmmc->sampling_coeff * tdmmc->total_channels);
#else /* MY_DEF_HERE */
	buff_size = (sample_size * MV_TDM_TOTAL_CH_SAMPLES * sampling_coeff * total_channels);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	if (tdmmc->ip_ver == TDMMC_REV0) {
		if (tdmmc->sample_size > MV_PCM_FORMAT_1BYTE) {
			dev_dbg(tdmmc->dev, "Linear mode (Tx): swapping bytes\n");
#else /* MY_DEF_HERE */
	if (tdmmc_ip_ver_get(ctrl_family_id) == MV_COMMUNIT_IP_VER_ORIGIN) {
		if (sample_size > MV_PCM_FORMAT_1BYTE) {
			dev_dbg(pdev, "Linear mode (Tx): swapping bytes\n");
#endif /* MY_DEF_HERE */
			for (index = 0; index < buff_size; index += 2) {
				tmp = tdm_tx_buff[index];
				tdm_tx_buff[index] = tdm_tx_buff[index+1];
				tdm_tx_buff[index+1] = tmp;
			}
#if defined(MY_DEF_HERE)
			dev_dbg(tdmmc->dev, "Linear mode (Tx): swapping bytes...done.\n");
#else /* MY_DEF_HERE */
			dev_dbg(pdev, "Linear mode (Tx): swapping bytes...done.\n");
#endif /* MY_DEF_HERE */
		}
	}

	return 0;
}

int tdmmc_rx(u8 *tdm_rx_buff)
{
	u32 buff_size, index;
	u8 tmp;

	/* Calculate total Rx buffer size */
#if defined(MY_DEF_HERE)
	buff_size = (tdmmc->sample_size * MV_TDM_TOTAL_CH_SAMPLES *
		     tdmmc->sampling_coeff * tdmmc->total_channels);
#else /* MY_DEF_HERE */
	buff_size = (sample_size * MV_TDM_TOTAL_CH_SAMPLES * sampling_coeff * total_channels);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	if (tdmmc->ip_ver == TDMMC_REV0) {
		if (tdmmc->sample_size > MV_PCM_FORMAT_1BYTE) {
			dev_dbg(tdmmc->dev, "Linear mode (Rx): swapping bytes\n");
#else /* MY_DEF_HERE */
	if (tdmmc_ip_ver_get(ctrl_family_id) == MV_COMMUNIT_IP_VER_ORIGIN) {
		if (sample_size > MV_PCM_FORMAT_1BYTE) {
			dev_dbg(pdev, "Linear mode (Rx): swapping bytes\n");
#endif /* MY_DEF_HERE */
			for (index = 0; index < buff_size; index += 2) {
				tmp = tdm_rx_buff[index];
				tdm_rx_buff[index] = tdm_rx_buff[index+1];
				tdm_rx_buff[index+1] = tmp;
			}
#if defined(MY_DEF_HERE)
			dev_dbg(tdmmc->dev, "Linear mode (Rx): swapping bytes...done.\n");
#else /* MY_DEF_HERE */
			dev_dbg(pdev, "Linear mode (Rx): swapping bytes...done.\n");
#endif /* MY_DEF_HERE */
		}
	}

	return 0;
}

/* Low level TDM interrupt service routine */
int tdmmc_intr_low(struct mv_phone_intr_info *tdm_intr_info)
{
	u32 cause_reg, mask_reg, cause_and_mask, curr_desc, int_ack_bits = 0;
	u8 index;

	/* Read TDM cause & mask registers */
#if defined(MY_DEF_HERE)
	cause_reg = readl(tdmmc->regs + TDM_CAUSE_REG);
	mask_reg = readl(tdmmc->regs + TDM_MASK_REG);
#else /* MY_DEF_HERE */
	cause_reg = readl(regs + TDM_CAUSE_REG);
	mask_reg = readl(regs + TDM_MASK_REG);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	dev_dbg(tdmmc->dev, "%s: Cause register = 0x%x, Mask register = 0x%x\n",
#else /* MY_DEF_HERE */
	dev_dbg(pdev, "%s: Cause register = 0x%x, Mask register = 0x%x\n",
#endif /* MY_DEF_HERE */
		__func__, cause_reg, mask_reg);

	/* Refer only to unmasked bits */
	cause_and_mask = cause_reg & mask_reg;

	/* Reset ISR params */
	tdm_intr_info->tdm_rx_buff = NULL;
	tdm_intr_info->tdm_tx_buff = NULL;
	tdm_intr_info->int_type = MV_EMPTY_INT;

	/* Return in case TDM is disabled */
#if defined(MY_DEF_HERE)
	if (!tdmmc->tdm_enable) {
		dev_dbg(tdmmc->dev, "%s: TDM is disabled - quit low lever ISR\n", __func__);
		writel(~int_ack_bits, tdmmc->regs + TDM_CAUSE_REG);
#else /* MY_DEF_HERE */
	if (!tdm_enable) {
		dev_dbg(pdev, "%s: TDM is disabled - quit low lever ISR\n", __func__);
		writel(~int_ack_bits, regs + TDM_CAUSE_REG);
#endif /* MY_DEF_HERE */
		return 0;
	}

	/* Handle TDM Error/s */
	if (cause_and_mask & TDM_ERROR_INT) {
#if defined(MY_DEF_HERE)
		dev_err(tdmmc->dev, "TDM Error: TDM_CAUSE_REG = 0x%x\n", cause_reg);
#else /* MY_DEF_HERE */
		dev_err(pdev, "TDM Error: TDM_CAUSE_REG = 0x%x\n", cause_reg);
#endif /* MY_DEF_HERE */
		int_ack_bits |= (int_ack_bits & TDM_ERROR_INT);
	}

	if (cause_and_mask & (TDM_TX_INT | TDM_RX_INT)) {
		/* MCDMA current Tx desc. pointer is unreliable, thus, checking Rx desc. pointer only */
#if defined(MY_DEF_HERE)
		curr_desc = readl(tdmmc->regs + MCDMA_CURRENT_RECEIVE_DESC_PTR_REG(0));
		dev_dbg(tdmmc->dev, "%s: current descriptor = 0x%x\n", __func__, curr_desc);
#else /* MY_DEF_HERE */
		curr_desc = readl(regs + MCDMA_CURRENT_RECEIVE_DESC_PTR_REG(0));
		dev_dbg(pdev, "%s: current descriptor = 0x%x\n", __func__, curr_desc);
#endif /* MY_DEF_HERE */

		/* Handle Tx */
		if (cause_and_mask & TDM_TX_INT) {
			for (index = 0; index < TOTAL_CHAINS; index++) {
#if defined(MY_DEF_HERE)
				if (curr_desc == tdmmc->rx_desc_phys[index]) {
					tdmmc->next_tx = NEXT_BUFF(index);
#else /* MY_DEF_HERE */
				if (curr_desc == mcdma_rx_desc_phys[index]) {
					next_tx_buff = NEXT_BUFF(index);
#endif /* MY_DEF_HERE */
					break;
				}
			}
#if defined(MY_DEF_HERE)
			dev_dbg(tdmmc->dev, "%s: TX interrupt (next_tx_buff = %d\n",
				__func__, tdmmc->next_tx);
			tdm_intr_info->tdm_tx_buff = tdmmc->tx_buff_virt[tdmmc->next_tx];
#else /* MY_DEF_HERE */
			dev_dbg(pdev, "%s: TX interrupt (next_tx_buff = %d\n",
				__func__, next_tx_buff);
			tdm_intr_info->tdm_tx_buff = tx_buff_virt[next_tx_buff];
#endif /* MY_DEF_HERE */
			tdm_intr_info->int_type |= MV_TX_INT;
			int_ack_bits |= TDM_TX_INT;
		}

		/* Handle Rx */
		if (cause_and_mask & TDM_RX_INT) {
			for (index = 0; index < TOTAL_CHAINS; index++) {
#if defined(MY_DEF_HERE)
				if (curr_desc == tdmmc->rx_desc_phys[index]) {
					tdmmc->prev_rx = PREV_BUFF(index);
#else /* MY_DEF_HERE */
				if (curr_desc == mcdma_rx_desc_phys[index]) {
					prev_rx_buff = PREV_BUFF(index);
#endif /* MY_DEF_HERE */
					break;
				}
			}
#if defined(MY_DEF_HERE)
			dev_dbg(tdmmc->dev, "%s: RX interrupt (prev_rx_buff = %d)\n",
				__func__, tdmmc->prev_rx);
			tdm_intr_info->tdm_rx_buff = tdmmc->rx_buff_virt[tdmmc->prev_rx];
#else /* MY_DEF_HERE */
			dev_dbg(pdev, "%s: RX interrupt (prev_rx_buff = %d)\n",
				__func__, prev_rx_buff);
			tdm_intr_info->tdm_rx_buff = rx_buff_virt[prev_rx_buff];
#endif /* MY_DEF_HERE */
			tdm_intr_info->int_type |= MV_RX_INT;
			int_ack_bits |= TDM_RX_INT;
		}
	}

	/* Clear TDM interrupts */
#if defined(MY_DEF_HERE)
	writel(~int_ack_bits, tdmmc->regs + TDM_CAUSE_REG);
#else /* MY_DEF_HERE */
	writel(~int_ack_bits, regs + TDM_CAUSE_REG);
#endif /* MY_DEF_HERE */

	return 0;
}

int tdmmc_reset_slic(void)
{
	/* Enable SLIC reset */
#if defined(MY_DEF_HERE)
	mv_phone_reset_bit(tdmmc->regs + TDM_CLK_AND_SYNC_CONTROL_REG, TDM_PROG_TDM_SLIC_RESET_MASK);
#else /* MY_DEF_HERE */
	mv_phone_reset_bit(regs + TDM_CLK_AND_SYNC_CONTROL_REG, TDM_PROG_TDM_SLIC_RESET_MASK);
#endif /* MY_DEF_HERE */

	udelay(60);

	/* Release SLIC reset */
#if defined(MY_DEF_HERE)
	mv_phone_set_bit(tdmmc->regs + TDM_CLK_AND_SYNC_CONTROL_REG, TDM_PROG_TDM_SLIC_RESET_MASK);
#else /* MY_DEF_HERE */
	mv_phone_set_bit(regs + TDM_CLK_AND_SYNC_CONTROL_REG, TDM_PROG_TDM_SLIC_RESET_MASK);
#endif /* MY_DEF_HERE */

	return 0;
}

/* Initialize decoding windows */
int tdmmc_set_mbus_windows(struct device *dev, void __iomem *regs)
{
	const struct mbus_dram_target_info *dram = mv_mbus_dram_info();
	u32 win_protect, win_enable;
	int i;

	if (!dram) {
		dev_err(dev, "no mbus dram info\n");
		return -EINVAL;
	}

	for (i = 0; i < COMM_UNIT_MBUS_MAX_WIN; i++) {
		writel(0, regs + COMM_UNIT_WIN_CTRL_REG(i));
		writel(0, regs + COMM_UNIT_WIN_SIZE_REG(i));
		writel(0, regs + COMM_UNIT_WIN_ENABLE_REG(i));
	}

	win_enable = 0xff;
	win_protect = 0;

	for (i = 0; i < dram->num_cs; i++) {
		const struct mbus_dram_window *cs = dram->cs + i;

		writel((cs->base & 0xffff0000) |
		       (cs->mbus_attr << 8) |
		       dram->mbus_dram_target_id,
		       regs + COMM_UNIT_WIN_CTRL_REG(i));

		writel((cs->size - 1) & 0xffff0000,
		       regs + COMM_UNIT_WIN_SIZE_REG(i));

		writel(win_enable, regs + COMM_UNIT_WIN_ENABLE_REG(i));
		win_protect |= 3 << (2 * i);
	}

	/* Configure an extra window for PCIE0 */
	writel(0x8000e804, regs + COMM_UNIT_WIN_CTRL_REG(i));
	writel(0x1fff0000, regs + COMM_UNIT_WIN_SIZE_REG(i));
	writel(win_enable, regs + COMM_UNIT_WIN_ENABLE_REG(i));
	win_protect |= 3 << (2 * i);

	writel(win_protect, regs + COMM_UNIT_WINDOWS_ACCESS_PROTECT_REG);

	return 0;
}

#if defined(MY_DEF_HERE)

/* Initialize decoding windows for Armada 8k SoC */
int tdmmc_set_a8k_windows(struct device *dev, void __iomem *regs)
{
	int i;

	for (i = 0; i < COMM_UNIT_MBUS_MAX_WIN; i++) {
		writel(0xce00, regs + COMM_UNIT_WIN_CTRL_REG(i));
		writel(0xffff0000, regs + COMM_UNIT_WIN_SIZE_REG(i));
		if (i > 0)
			writel(0x0, regs + COMM_UNIT_WIN_ENABLE_REG(i));
	}

	return 0;
}
#endif /* MY_DEF_HERE */
#endif /* MY_DEF_HERE */
