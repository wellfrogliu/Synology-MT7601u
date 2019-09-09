/*
 * AHCI SATA platform driver
 *
 * Copyright 2004-2005  Red Hat, Inc.
 *   Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2010  MontaVista Software, LLC.
 *   Anton Vorontsov <avorontsov@ru.mvista.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/pm.h>
#include <linux/device.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/libata.h>
#include <linux/ahci_platform.h>
#include "ahci.h"
#include <linux/delay.h>

//#include <linux/switch.h>
#include <linux/of_address.h>
#include <linux/reset-helper.h> // rstc_get
#include <linux/reset.h>
#include <linux/of_gpio.h>
#include <linux/suspend.h>

#include <scsi/scsi_device.h>
#include "libata.h"

#define DRV_NAME_RTK "ahci_rtk"
#define HPC 0
#define HPC_PLUS 1
#define IC_PROCESS HPC_PLUS
#define CHK_STAT_FREQ 200    //ms

#define MAX_PORT 2
#define RESET_NUM 3
struct reset_control *rstc[MAX_PORT][RESET_NUM];

void __iomem *base = NULL;
void __iomem *ukbase = NULL;

struct task_struct *rtk_sata_dev_task = NULL;
int RTK_SATA_DEV_FLAG = 0;

static u32 blink_gpio_0 = 0;
static u32 blink_gpio_1 = 0;

enum {
	status_init = 0,
	status_start,
	status_finish,
	status_done,
};

struct ahci_port_data {
	unsigned int dev_detect;
	unsigned int speed;
	unsigned int phy_status;
	struct reset_control *rstc[RESET_NUM];
	void __iomem *port_reg;
};

struct rtk_ahci_dev {
	struct device *dev;
	void __iomem *base;
	void __iomem *ukbase;

	unsigned int port_num;
	struct ahci_port_data *port[MAX_PORT];

	unsigned char swname[MAX_PORT][20];
	int present_io[MAX_PORT];
//	struct switch_dev sw[MAX_PORT];

	unsigned int speed_limit;
	unsigned int spread_spectrum;
	unsigned int hotplug_en;
	unsigned int rx_sensitivity;
	unsigned int tx_driving;
	unsigned int host_en;
	unsigned int link_status;
	struct task_struct * task;

	struct ahci_host_priv *hpriv;
};

struct rtk_ahci_dev *ahci_dev = NULL;

static ssize_t ahci_rtk_transmit_led_message(struct ata_port *ap, u32 state,
					    ssize_t size);
static void ahci_rtk_postreset(struct ata_link *link, unsigned int *class);
static void ahci_rtk_host_stop(struct ata_host *host);

void ahci_handle_port_interrupt(struct ata_port *ap, void __iomem *port_mmio, u32 status);
void ahci_error_intr(struct ata_port *ap, u32 irq_stat);

void ahci_rtk_issue_intr(int port_num)
{
	struct ata_host *host = dev_get_drvdata(ahci_dev->dev);
	struct ata_port *ap;

	spin_lock(&host->lock);
	ap = host->ports[port_num];
	ahci_error_intr(ap, 0x00400000);
	spin_unlock(&host->lock);
}
EXPORT_SYMBOL_GPL(ahci_rtk_issue_intr);

void ahci_rtk_reset_mac(int port_num)
{
	struct ata_host *host = dev_get_drvdata(ahci_dev->dev);
	void __iomem *port_mmio;
	struct ata_port *ap;

	spin_lock(&host->lock);
	ap = host->ports[port_num];
	port_mmio = ahci_port_base(ap);

	/* set port reg 0x18 to 0x4016*/
	writel(0x4016, port_mmio + 0x18);

	/* clear port reg 0x2c bit0*/
	writel(readl(port_mmio + 0x2c) & (~0x1), port_mmio + 0x2c);

	/* set port reg 0x2c bit0*/
	writel(readl(port_mmio + 0x2c) | 0x1, port_mmio + 0x2c);

	/* clear port reg 0x2c bit0*/
	writel(readl(port_mmio + 0x2c) & (~0x1), port_mmio + 0x2c);

	spin_unlock(&host->lock);
}
EXPORT_SYMBOL_GPL(ahci_rtk_reset_mac);

static void ahci_rtk_host_stop(struct ata_host *host)
{
	struct ahci_host_priv *hpriv = host->private_data;

	ahci_platform_disable_resources(hpriv);
}

static void ahci_rtk_postreset(struct ata_link *link, unsigned int *class)
{
	struct ata_port *ap = link->ap;

	if (ap->port_no == 0 && gpio_is_valid(blink_gpio_0))
		ata_link_online(link) ? gpio_set_value(blink_gpio_0, 1) : gpio_set_value(blink_gpio_0, 0);

	if (ap->port_no == 1 && gpio_is_valid(blink_gpio_1))
		ata_link_online(link) ? gpio_set_value(blink_gpio_1, 1) : gpio_set_value(blink_gpio_1, 0);

	return ahci_ops.postreset(link, class);
}

static ssize_t ahci_rtk_transmit_led_message(struct ata_port *ap, u32 state,
					     ssize_t size)
{
	if (ap->port_no == 0 && gpio_is_valid(blink_gpio_0))
		(state & EM_MSG_LED_VALUE_ON) ? gpio_set_value(blink_gpio_0, 0) : gpio_set_value(blink_gpio_0, 1);

	if (ap->port_no == 1 && gpio_is_valid(blink_gpio_1))
		(state & EM_MSG_LED_VALUE_ON) ? gpio_set_value(blink_gpio_1, 0) : gpio_set_value(blink_gpio_1, 1);

	return ahci_ops.transmit_led_message(ap, state, size);
}

struct ata_port_operations ahci_rtk_ops = {
	.inherits	= &ahci_ops,
	.host_stop	= ahci_rtk_host_stop,
	.postreset	= ahci_rtk_postreset,
	.transmit_led_message = ahci_rtk_transmit_led_message,
};

static const struct ata_port_info ahci_port_info = {
	.flags		= AHCI_FLAG_COMMON | ATA_FLAG_EM | ATA_FLAG_SW_ACTIVITY,
	.pio_mask	= ATA_PIO4,
	.udma_mask	= ATA_UDMA6,
	.port_ops	= &ahci_rtk_ops,
};

static struct scsi_host_template ahci_platform_sht = {
	AHCI_SHT(DRV_NAME_RTK),
};

static const char *rst_name[MAX_PORT][20] = {
	{
//		"sata_func_exist_0",
//		"rstn_sata_phy_pow_0",
		"rstn_sata_0",
		"rstn_sata_phy_0",
		"rstn_sata_phy_pow_0",
	},
	{
//		"sata_func_exist_1",
//		"rstn_sata_phy_pow_1",
		"rstn_sata_1",
		"rstn_sata_phy_1",
		"rstn_sata_phy_pow_1",
	},
};

static void writel_delay(unsigned int value, void __iomem *address)
{
	writel(value, address);
	mdelay(1);
}

static void config_sata_phy(unsigned int port)
{
	void __iomem *base = ahci_dev->base;

	writel_delay(port, base + 0xF64);

	writel_delay(0x00001111, base + 0xF60);
	writel_delay(0x00005111, base + 0xF60);
	writel_delay(0x00009111, base + 0xF60);
#if IC_PROCESS == HPC
	writel_delay(0x538E0411, base + 0xF60);
	writel_delay(0x538E4411, base + 0xF60);
	writel_delay(0x538E8411, base + 0xF60);

	writel_delay(0x3b6a0511, base + 0xF60);
	writel_delay(0x3b6a4511, base + 0xF60);
	writel_delay(0x3b6a8511, base + 0xF60);

	writel_delay(0xE0500111, base + 0xF60);
	writel_delay(0xE0504111, base + 0xF60);
	writel_delay(0xE04C8111, base + 0xF60);

	writel_delay(0x00110611, base + 0xF60);
	writel_delay(0x00114611, base + 0xF60);
	writel_delay(0x00118611, base + 0xF60);

	writel_delay(0xA6000A11, base + 0xF60);
	writel_delay(0xA6004A11, base + 0xF60);
	writel_delay(0xA6008A11, base + 0xF60);

	writel_delay(0x27FD8211, base + 0xF60);
	writel_delay(0xA6408A11, base + 0xF60);
	writel_delay(0x041BA611, base + 0xF60);
#else
	if(ahci_dev->spread_spectrum==0) {
		printk("[SATA] spread-spectrum disable\n");
		writel_delay(0x538E0411, base + 0xF60);
		writel_delay(0x538E4411, base + 0xF60);
		writel_delay(0x538E8411, base + 0xF60);
	} else {
		printk("[SATA] spread-spectrum enable\n");
		writel_delay(0x738E0411, base + 0xF60);
		writel_delay(0x738E4411, base + 0xF60);
		writel_delay(0x738E8411, base + 0xF60);

		writel_delay(0x35910811, base + 0xF60);
		writel_delay(0x35914811, base + 0xF60);
		writel_delay(0x35918811 , base + 0xF60);

		writel_delay(0x02342711, base + 0xF60);
		writel_delay(0x02346711, base + 0xF60);
		writel_delay(0x0234a711, base + 0xF60);
	}
	writel_delay(0x336a0511, base + 0xF60);
	writel_delay(0x336a4511, base + 0xF60);
	writel_delay(0x336a8511, base + 0xF60);

	writel_delay(0xE0700111, base + 0xF60);
	writel_delay(0xE05C4111, base + 0xF60);
	writel_delay(0xE04A8111, base + 0xF60);

	writel_delay(0x00150611, base + 0xF60);
	writel_delay(0x00154611, base + 0xF60);
	writel_delay(0x00158611, base + 0xF60);

	writel_delay(0xC6000A11, base + 0xF60);
	writel_delay(0xC6004A11, base + 0xF60);
	writel_delay(0xC6008A11, base + 0xF60);

	writel_delay(0x70000211, base + 0xF60);
	writel_delay(0x70004211, base + 0xF60);
	writel_delay(0x70008211, base + 0xF60);

	writel_delay(0xC6600A11, base + 0xF60);
	writel_delay(0xC6604A11, base + 0xF60);
	writel_delay(0xC6608A11, base + 0xF60);

	writel_delay(0x20041911, base + 0xF60);
	writel_delay(0x20045911, base + 0xF60);
	writel_delay(0x20049911, base + 0xF60);

	writel_delay(0x94aa2011, base + 0xF60);
	writel_delay(0x94aa6011, base + 0xF60);
	writel_delay(0x94aaa011, base + 0xF60);
#endif

	writel_delay(0x17171511, base + 0xF60);
	writel_delay(0x17175511, base + 0xF60);
	writel_delay(0x17179511, base + 0xF60);

	writel_delay(0x07701611, base + 0xF60);
	writel_delay(0x07705611, base + 0xF60);
	writel_delay(0x07709611, base + 0xF60);

// for rx sensitivity
	writel_delay(0x72100911, base + 0xF60);
	writel_delay(0x72104911, base + 0xF60);
	writel_delay(0x72108911, base + 0xF60);
/*	if(ahci_dev->port[port]->phy_status==0) {
		writel_delay(0x27640311, base + 0xF60);
		writel_delay(0x27644311, base + 0xF60);
		writel_delay(0x27648311, base + 0xF60);
	} else if(ahci_dev->port[port]->phy_status==2) {
		writel_delay(0x27710311, base + 0xF60);
		writel_delay(0x27714311, base + 0xF60);
		writel_delay(0x27718311, base + 0xF60);
	}*/
	writel_delay(0x27710311, base + 0xF60);
	writel_delay(0x27684311, base + 0xF60);
	writel_delay(0x27688311, base + 0xF60);

	writel_delay(0x29001011, base + 0xF60);
	writel_delay(0x29005011, base + 0xF60);
	writel_delay(0x29009011, base + 0xF60);

	if(ahci_dev->tx_driving==2) {
		printk("[SATA] set tx-driving to L (level 2)\n");
		writel_delay(0x94a72011, base + 0xF60);
		writel_delay(0x94a76011, base + 0xF60);
		writel_delay(0x94a7a011, base + 0xF60);
		writel_delay(0x587a2111, base + 0xF60);
		writel_delay(0x587a6111, base + 0xF60);
		writel_delay(0x587aa111, base + 0xF60);
	} else if(ahci_dev->tx_driving == 8) { // for DS418j
		printk("[SATA] set tx-driving to L (level 8)\n");
		if(port==0) {
			writel_delay(0x94a82011, base + 0xF60);
			writel_delay(0x94a86011, base + 0xF60);
			writel_delay(0x94a8a011, base + 0xF60);
			writel_delay(0x588a2111, base + 0xF60);
			writel_delay(0x588a6111, base + 0xF60);
			writel_delay(0x588aa111, base + 0xF60);
		} else if(port==1) {
			writel_delay(0x94a82011, base + 0xF60);
			writel_delay(0x94a86011, base + 0xF60);
			writel_delay(0x94a8a011, base + 0xF60);
			writel_delay(0x58da2111, base + 0xF60);
			writel_delay(0x58da6111, base + 0xF60);
			writel_delay(0x58daa111, base + 0xF60);
		}
	} else if(ahci_dev->tx_driving == 6) { // for DS418
		printk("[SATA] set tx-driving to L (level 6)\n");
		if(port==0) {
			writel_delay(0x94aa2011, base + 0xF60);
			writel_delay(0x94aa6011, base + 0xF60);
			writel_delay(0x94aaa011, base + 0xF60);
			writel_delay(0xa86a2111, base + 0xF60);
			writel_delay(0xa86a6111, base + 0xF60);
			writel_delay(0xa86aa111, base + 0xF60);
		} else if(port==1) {
			writel_delay(0x94a42011, base + 0xF60);
			writel_delay(0x94a46011, base + 0xF60);
			writel_delay(0x94a4a011, base + 0xF60);
			writel_delay(0x68ca2111, base + 0xF60);
			writel_delay(0x68ca6111, base + 0xF60);
			writel_delay(0x68caa111, base + 0xF60);
		}
	} else if(ahci_dev->tx_driving == 4) { // for DS218play
		printk("[SATA] set tx-driving to L (level 4)\n");
		if(port==0) {
			writel_delay(0x94a72011, base + 0xF60);
			writel_delay(0x94a76011, base + 0xF60);
			writel_delay(0x94a7a011, base + 0xF60);
			writel_delay(0x587a2111, base + 0xF60);
			writel_delay(0x587a6111, base + 0xF60);
			writel_delay(0x587aa111, base + 0xF60);
		} else if(port==1) {
			writel_delay(0x94a72011, base + 0xF60);
			writel_delay(0x94a76011, base + 0xF60);
			writel_delay(0x94a7a011, base + 0xF60);
			writel_delay(0x587a2111, base + 0xF60);
			writel_delay(0x587a6111, base + 0xF60);
			writel_delay(0x587aa111, base + 0xF60);
		}
	} else if(ahci_dev->tx_driving == 10) { // for DS118
		printk("[SATA] set tx-driving to L (level 10)\n");
		if(port==0) {
			writel_delay(0x94a72011, base + 0xF60);
			writel_delay(0x94a76011, base + 0xF60);
			writel_delay(0x94a7a011, base + 0xF60);
			writel_delay(0x383a2111, base + 0xF60);
			writel_delay(0x383a6111, base + 0xF60);
			writel_delay(0x383aa111, base + 0xF60);
		}
	} else if(ahci_dev->tx_driving == 9) { // for DS218
		printk("[SATA] set tx-driving to L (level 9)\n");
		if(port==0) {
			writel_delay(0x94a32011, base + 0xF60);
			writel_delay(0x94a36011, base + 0xF60);
			writel_delay(0x94a3a011, base + 0xF60);
			writel_delay(0x385a2111, base + 0xF60);
			writel_delay(0x385a6111, base + 0xF60);
			writel_delay(0x385aa111, base + 0xF60);
		} else if(port==1) {
			writel_delay(0x94a72011, base + 0xF60);
			writel_delay(0x94a76011, base + 0xF60);
			writel_delay(0x94a7a011, base + 0xF60);
			writel_delay(0x383a2111, base + 0xF60);
			writel_delay(0x383a6111, base + 0xF60);
			writel_delay(0x383aa111, base + 0xF60);
		}
	}
	// RX power saving off
	writel_delay(0x40000C11, base + 0xF60);
	writel_delay(0x40004C11, base + 0xF60);
	writel_delay(0x40008C11, base + 0xF60);

	writel_delay(0x00271711, base + 0xF60);
	writel_delay(0x00275711, base + 0xF60);
	writel_delay(0x00279711, base + 0xF60);
}

static void config_sata_mac(unsigned int port)
{
	unsigned int val;
	void __iomem *base, *port_base;

	base = ahci_dev->base;
	port_base = ahci_dev->port[port]->port_reg;

	writel_delay(port, base + 0xF64);
	/* SATA MAC */
//	writel_delay(0x2, port_base + 0x144);
	writel_delay(0x6726ff81, base);
	val = readl(base);
	writel_delay(0x6737ff81, base);
	val = readl(base);

//	writel_delay(0x83090c15, base + 0xbc);
//	writel_delay(0x83090c15, base + 0xbc);

	writel_delay(0x80000001, base + 0x4);
	writel_delay(0x80000002, base + 0x4);

	val = readl(base + 0x14);
	writel_delay((val & ~0x1), base + 0x14);
	val = readl(base + 0xC);
	writel_delay((val | 0x3), base + 0xC);
	val = readl(base + 0x18);
	val |= port << 1;
	writel_delay(val, base + 0x18);

	writel_delay(0xffffffff, port_base + 0x114);
//	writel_delay(0x05040000, port_base + 0x100);
//	writel_delay(0x05040400, port_base + 0x108);

	val = readl(port_base + 0x170);
	writel_delay(0x88, port_base + 0x170);
	val = readl(port_base + 0x118);
	writel_delay(0x10, port_base + 0x118);
	val = readl(port_base + 0x118);
	writel_delay(0x4016, port_base + 0x118);
	val = readl(port_base + 0x140);
	writel_delay(0xf000, port_base + 0x140);

	writel_delay(0x3c300, base + 0xf20);

	writel_delay(0x700, base + 0xA4);
	//Set to Auto mode
	if(ahci_dev->port[port]->speed == 0)
		writel_delay(0xA, base + 0xF68);
	else if(ahci_dev->port[port]->speed == 2)
		writel_delay(0x5, base + 0xF68);
	else if(ahci_dev->port[port]->speed == 1)
		writel_delay(0x0, base + 0xF68);

//	while(1) {
//		val = readl(port_base + 0x128);
//		printk(KERN_ERR "%s: reg base+0x128 = 0x%x\n", __func__, val);
//		msleep(200);
//	}
}

static int send_oob(unsigned int port)
{
	unsigned int val=0;

	if(port==0) {
		val = readl(ahci_dev->ukbase + 0x80);
		val |= 0x115;
	} else if(port==1) {
		val = readl(ahci_dev->ukbase + 0x80);
		val |= 0x12A;
	}
	writel(val, ahci_dev->ukbase + 0x80);

	return 0;
}

void set_rx_sensitivity(unsigned int port, unsigned int rx_sens)
{
	void __iomem *base, *port_base;
	unsigned int val;

	base = ahci_dev->base;
	port_base = ahci_dev->port[port]->port_reg;

	writel_delay(port, base + 0xF64);

	val = readl(port_base + 0x12C);
	val = val & ~0x1;
	writel_delay(val, port_base + 0x12c);

	if(rx_sens==0) {
		printk("[SATA] change rx_sensitivy to %d\n", rx_sens);
		writel_delay(0x27640311, base + 0xF60);
		writel_delay(0x27644311, base + 0xF60);
		writel_delay(0x27648311, base + 0xF60);
	} else if(rx_sens==2) {
		printk("[SATA] change rx_sensitivy to %d\n", rx_sens);
		writel_delay(0x27710311, base + 0xF60);
		writel_delay(0x27714311, base + 0xF60);
		writel_delay(0x27718311, base + 0xF60);
	}
	val = val | 0x1;
	writel_delay(val, port_base + 0x12c);
	val = val & ~0x1;
	writel_delay(val, port_base + 0x12c);

	val = val | 0x4;
	writel_delay(val, port_base + 0x12c);
	val = val & ~0x4;
	writel_delay(val, port_base + 0x12c);
}

int change_rx_sensitivity(unsigned int id)
{
	unsigned int port;
	if(id > ahci_dev->port_num) {
		printk("[SATA] this port is larger than port number");
		return -1;
	}

	port = id - 1;
	if(ahci_dev->port[port]->phy_status==0)
		ahci_dev->port[port]->phy_status = 2;
	else
		ahci_dev->port[port]->phy_status = 0;

	set_rx_sensitivity(port, ahci_dev->port[port]->phy_status);
	return 0;
}
EXPORT_SYMBOL_GPL(change_rx_sensitivity);
#if 0
static void set_speed_limit(unsigned int port, unsigned int speed)
{
	void __iomem *base, *port_base;
	base = ahci_dev->base;
	port_base = ahci_dev->port[port]->port_reg;

	writel_delay(port, base + 0xF64);
	if(speed == 2) {
		writel_delay(0x5, base + 0xF68);
		writel_delay(0x20, port_base + 0x12c);
		writel_delay(0x21, port_base + 0x12c);
		writel_delay(0x20, port_base + 0x12c);
	} else if(speed == 1) {
		writel_delay(0x0, base + 0xF68);
		writel_delay(0x10, port_base + 0x12c);
		writel_delay(0x11, port_base + 0x12c);
		writel_delay(0x10, port_base + 0x12c);
	} else {
		writel_delay(0xA, base + 0xF68);
		writel_delay(0x00, port_base + 0x12c);
		writel_delay(0x01, port_base + 0x12c);
		writel_delay(0x00, port_base + 0x12c);
	}
}

static int thread_status_check(void *data)
{
	int i, cnt=0;
	void __iomem *base, *port_base;
	struct platform_device *pdev = data;
	struct device *dev = &pdev->dev;
	struct ahci_host_priv *hpriv = ahci_dev->hpriv;
	int readynum=0, rc;
	unsigned int reg_link=0, reg_err=0, have_try[MAX_PORT];
	struct ata_host *host;

	set_current_state(TASK_INTERRUPTIBLE);

	while(!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		base = ahci_dev->base;
		msleep(CHK_STAT_FREQ);
		if(ahci_dev->link_status==status_init) {
			readynum = cnt = 0;
			for(i=0; i<ahci_dev->port_num; i++) {
				ahci_dev->port[i]->dev_detect = 0;
				ahci_dev->port[i]->speed = ahci_dev->speed_limit;
				have_try[i] = 0;
			}
			ahci_dev->link_status = status_start;
		}
		if(ahci_dev->link_status == status_start) {
			printk("[SATA] Start to check link status\n");
			for(i=0; i<ahci_dev->port_num; i++) {
				port_base = ahci_dev->port[i]->port_reg;
				if(ahci_dev->port[i]->dev_detect != 1) {
					reg_link = readl(port_base + 0x128);
					reg_err = readl(port_base + 0x130);
					if((reg_link&0xF)==0x3 && reg_err==0x04050002) {
						printk("[SATA] Port%d Link OK, status = 0x%x, rx_en=%d, speed=%d\n", i, reg_link, ahci_dev->port[i]->phy_status, ahci_dev->port[i]->speed);
						ahci_dev->port[i]->dev_detect = 1;
						readynum++;
					} else {
						printk("[SATA] Port%d link fail, rx_en=%d, speed=%d\n", i, ahci_dev->port[i]->phy_status, ahci_dev->port[i]->speed);
						if(!have_try[i]) {
							if(ahci_dev->port[i]->phy_status==0) {
								ahci_dev->port[i]->phy_status=1;
								set_rx_sensitivity(i, ahci_dev->port[i]->phy_status, ahci_dev->port[i]->speed);
							} else if(ahci_dev->port[i]->phy_status==1) {
								ahci_dev->port[i]->phy_status=0;
								set_rx_sensitivity(i, ahci_dev->port[i]->phy_status, ahci_dev->port[i]->speed);
							}
							have_try[i] = 1;
						} else {
							have_try[i] = 0;
							if(ahci_dev->port[i]->speed==0) {
								ahci_dev->port[i]->speed = 2;
								ahci_dev->port[i]->phy_status = ahci_dev->rx_sensitivity;
								set_rx_sensitivity(i, ahci_dev->port[i]->phy_status, ahci_dev->port[i]->speed);
		//						set_speed_limit(i, ahci_dev->port[i]->speed);
							} else
								readynum++;

		//					else if(ahci_dev->port[i]->speed==2) {
		//						ahci_dev->port[i]->speed = 1;
		//						ahci_dev->port[i]->phy_status = ahci_dev->rx_sensitivity;
		//						set_rx_sensitivity(i, ahci_dev->port[i]->phy_status, ahci_dev->port[i]->speed);
		//						set_speed_limit(i, ahci_dev->port[i]->speed);
		//					} else
		//						readynum++;
						}
					}
				}
			}
			if(readynum == ahci_dev->port_num) {
				printk("[SATA] Phy link finish\n");
				ahci_dev->link_status = status_finish;
			}
		}
		if(ahci_dev->link_status == status_finish) {
			printk("[SATA] Link finish\n");
			host = dev_get_drvdata(ahci_dev->dev);
			if(host == NULL) {
				printk("[SATA] No host!! start initial\n");
				ahci_platform_init_host(pdev, hpriv, &ahci_port_info, &ahci_platform_sht);
			} else {
				printk("[SATA] Have host!! resume host\n");
				rc = ahci_platform_resume_host(dev);
				if (rc)
					printk(KERN_ERR "[SATA] Can't resume host\n");
			}
			ahci_dev->link_status = status_done;
		}
	}
	return 0;
}
#endif
static int rtk_sata_dev_fun(void *data)
{
	struct ata_host *host;
	int rc, cnt;
	set_current_state(TASK_INTERRUPTIBLE);
	while(!kthread_should_stop()){
		schedule();
		host = dev_get_drvdata(ahci_dev->dev);
		if(host != NULL) {
			if(RTK_SATA_DEV_FLAG==2) {
				printk("[SATA] state=%d\n", host->ports[0]->scsi_host->shost_state);
				if(host->ports[0]->scsi_host->shost_state == SHOST_RUNNING ) {
					printk("[SATA] scsi_remove_device start\n");
					if(host->ports[0]->link.device[0].sdev != NULL)
						scsi_remove_device(host->ports[0]->link.device[0].sdev);
				}
			} else if(RTK_SATA_DEV_FLAG==1){
				cnt = 0;
				printk("[SATA] ata_scsi_user_scan, state=%d\n", host->ports[0]->scsi_host->shost_state);
				while(1) {
					if(host->ports[0]->scsi_host->shost_state == SHOST_RUNNING )
						break;
					if(cnt<=5) {
						cnt++;
						msleep(200);
					} else
						break;
				}
				rc = ata_scsi_user_scan(host->ports[0]->scsi_host, 0, 0, 0);
				printk("[SATA] ata_scsi_user_scan, state=%d, cnt=%d, rc=%d\n", host->ports[0]->scsi_host->shost_state, cnt, rc);
			}
		}
		set_current_state(TASK_INTERRUPTIBLE);
	}

	return 0;
}

#if 0
static ssize_t switch_present_print_state(struct switch_dev *sdev, char *buffer)
{
	int ret = 0;
	if(!strcmp(sdev->name, "SATA0_present")) {
		if(ahci_dev->present_io[0]>=0) {
			ret = gpio_get_value(ahci_dev->present_io[0]);
			switch_set_state(sdev, ret);
		}
	}
	if(!strcmp(sdev->name, "SATA1_present")) {
		if(ahci_dev->present_io[1]>=0) {
			ret = gpio_get_value(ahci_dev->present_io[1]);
			switch_set_state(sdev, ret);
		}
	}
	return sprintf(buffer, "%d\n", ret);
}
#endif

static int ahci_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct ahci_host_priv *hpriv;
	struct ahci_port_data *port_data;
	int ret, i, j;
	int gpio;

	ahci_dev = devm_kzalloc(dev, sizeof(struct rtk_ahci_dev), GFP_KERNEL);
	if(!ahci_dev) {
		dev_err(dev, "can't allocate struct ahci_dev\n");
		return -ENOMEM;
	}
	RTK_SATA_DEV_FLAG = 0;
	ahci_dev->dev = &pdev->dev;

	ahci_dev->base = of_iomap(pdev->dev.of_node, 0);
	if (!ahci_dev->base) {
		dev_err(dev, "no mmio space(SATA host)\n");
		return -EINVAL;
	}

	ahci_dev->ukbase = of_iomap(pdev->dev.of_node, 1);
	if (!ahci_dev->ukbase) {
		dev_err(dev, "no mmio space(ukbase)\n");
		return -EINVAL;
	}

	//Get port number from device tree
	ahci_dev->port_num = of_get_child_count(dev->of_node);
	if(!ahci_dev->port_num)
		ahci_dev->port_num = 1;
	else if(ahci_dev->port_num > MAX_PORT)
		ahci_dev->port_num = MAX_PORT;

	for(i=0; i<ahci_dev->port_num; i++) {
		gpio = of_get_gpio(dev->of_node, i);
		if(gpio<0) {
			dev_err(dev, "can't find gpio to enable sata power\n");
			return -EINVAL;
		}
		gpio_request(gpio, dev->of_node->name);
		gpio_set_value(gpio, 1);
		gpio_free(gpio);
	}

	blink_gpio_0 = of_get_named_gpio_flags(dev->of_node, "blink-gpios", 0, NULL);
	if (gpio_is_valid(blink_gpio_0))
		gpio_request(blink_gpio_0, "blink-gpios(0)");

	blink_gpio_1 = of_get_named_gpio_flags(dev->of_node, "blink-gpios", 1, NULL);
	if (gpio_is_valid(blink_gpio_1))
		gpio_request(blink_gpio_1, "blink-gpios(1)");

	//Get reset information
	for(i=0; i<ahci_dev->port_num; i++) {
		port_data = devm_kzalloc(dev, sizeof(struct ahci_port_data), GFP_KERNEL);
		if(!port_data) {
			dev_err(dev, "can't allocate struct ahci_port_data\n");
			return -ENOMEM;
		}
		for(j=0; j<RESET_NUM; j++) {
			port_data->rstc[j] = rstc_get(rst_name[i][j]);
			if(!port_data->rstc[j]) {
				dev_err(dev, "can't not get reset\n");
				return -EINVAL;
			}
		}
		ahci_dev->port[i] = port_data;
		ahci_dev->port[i]->port_reg = ahci_dev->base + i*0x80;
	}
	for(i=0; i<ahci_dev->port_num; i++) {
		ahci_dev->present_io[i] = of_get_gpio(dev->of_node, i+ahci_dev->port_num);
		if(ahci_dev->present_io[i]<0)
			continue;
		gpio_request(ahci_dev->present_io[i], dev->of_node->name);
		gpio_direction_input(ahci_dev->present_io[i]);

#if 0
		sprintf(ahci_dev->swname[i], "SATA%d_present", i);
		ahci_dev->sw[i].name = ahci_dev->swname[i];
		ahci_dev->sw[i].print_state = switch_present_print_state;
		switch_dev_register(&ahci_dev->sw[i]);
#endif
	}

	ahci_dev->spread_spectrum = 0;
	ahci_dev->rx_sensitivity = 0;
	ahci_dev->speed_limit = 0;
	ahci_dev->tx_driving = 3;
//	of_property_read_u32(dev->of_node, "hotplug-en", &ahci_dev->hotplug_en);
	of_property_read_u32(dev->of_node, "rx-sensitivity", &ahci_dev->rx_sensitivity);
	of_property_read_u32(dev->of_node, "spread-spectrum", &ahci_dev->spread_spectrum);
	of_property_read_u32(dev->of_node, "speed-limit", &ahci_dev->speed_limit);
	of_property_read_u32(dev->of_node, "tx-driving", &ahci_dev->tx_driving);

	hpriv = ahci_platform_get_resources(pdev);
	if (IS_ERR(hpriv))
		return PTR_ERR(hpriv);

	ahci_dev->hpriv = hpriv;
	ret = ahci_platform_enable_resources(hpriv);
	if (ret)
		return ret;

	for(i=0; i<ahci_dev->port_num; i++) {
		reset_control_deassert(ahci_dev->port[i]->rstc[0]);
		reset_control_deassert(ahci_dev->port[i]->rstc[1]);
	}

	for(i=0; i<ahci_dev->port_num; i++) {
		ahci_dev->port[i]->phy_status = ahci_dev->rx_sensitivity;
		ahci_dev->port[i]->speed = ahci_dev->speed_limit;
		config_sata_mac(i);
		config_sata_phy(i);
		reset_control_deassert(ahci_dev->port[i]->rstc[2]);
		send_oob(i);
	}

//	if (of_device_is_compatible(dev->of_node, "Realtek,ahci-sata"))
//		hpriv->flags |= AHCI_HFLAG_NO_FBS | AHCI_HFLAG_NO_NCQ;
//	ahci_dev->link_status = status_init;
//	ahci_dev->task = kthread_run(thread_status_check, pdev, "sata_status_check");
	ahci_platform_init_host(pdev, hpriv, &ahci_port_info, &ahci_platform_sht);

	rtk_sata_dev_task = kthread_run(rtk_sata_dev_fun, &pdev, "rtk_sata_dev_handler");
	if (IS_ERR(rtk_sata_dev_task)) {
		ret = PTR_ERR(rtk_sata_dev_task);
		rtk_sata_dev_task = NULL;
		return -1;
	}

	return 0;
}

#ifdef CONFIG_PM
static int rtk_ahci_suspend(struct device *dev)
{
	struct ata_host *host;
	struct ahci_host_priv *hpriv;
	int rc, i, j;

	printk("[SATA] enter %s\n", __FUNCTION__);

//	if(!ahci_dev->host_en)
//		goto exit_suspend;
//	if(ahci_dev->link_status != status_done)
//		ahci_dev->link_status = status_done;

	host = dev_get_drvdata(dev);
	hpriv = host->private_data;

	rc = ahci_platform_suspend_host(dev);
	if (rc)
		return rc;
	if(RTK_PM_STATE == PM_SUSPEND_STANDBY) {
		ahci_platform_disable_clks(hpriv);
	} else {
		ahci_platform_disable_resources(hpriv);
		for(i=0; i<ahci_dev->port_num; i++)
			for(j=0; j<RESET_NUM; j++)
				reset_control_assert(ahci_dev->port[i]->rstc[j]);
	}

	printk("[SATA] exit %s\n", __FUNCTION__);
	return 0;
}

static int rtk_ahci_resume(struct device *dev)
{
	struct ata_host *host;
	struct ahci_host_priv *hpriv;
	int rc, i, gpio;

	printk("[ATA] enter %s\n", __FUNCTION__);

//	if(!ahci_dev->host_en)
//		goto exit_resume;

	host = dev_get_drvdata(dev);
	hpriv = host->private_data;

	RTK_SATA_DEV_FLAG = 1;

	for(i=0; i<ahci_dev->port_num; i++) {
		gpio = of_get_gpio(dev->of_node, i);
		gpio_request(gpio, dev->of_node->name);
		gpio_set_value(gpio, 1);
		gpio_free(gpio);
	}
	if(RTK_PM_STATE == PM_SUSPEND_STANDBY) {
		ahci_platform_enable_clks(hpriv);
	} else {
		rc = ahci_platform_enable_resources(hpriv);
		if (rc)
			return rc;

		for(i=0; i<ahci_dev->port_num; i++) {
			reset_control_deassert(ahci_dev->port[i]->rstc[0]);
			reset_control_deassert(ahci_dev->port[i]->rstc[1]);
		}

		for(i=0; i<ahci_dev->port_num; i++) {
			config_sata_mac(i);
			config_sata_phy(i);
			reset_control_deassert(ahci_dev->port[i]->rstc[2]);
			send_oob(i);
		}
	}
//	ahci_dev->link_status = status_init;

	rc = ahci_platform_resume_host(dev);
	if (rc)
		goto disable_resources;

	/* We resumed so update PM runtime state */
	pm_runtime_disable(dev);
	pm_runtime_set_active(dev);
	pm_runtime_enable(dev);

	printk("[ATA] exit %s\n", __FUNCTION__);
	return 0;

disable_resources:
	ahci_platform_disable_resources(hpriv);

	return rc;
}
//static SIMPLE_DEV_PM_OPS(ahci_pm_ops, ahci_platform_suspend, ahci_platform_resume);
static SIMPLE_DEV_PM_OPS(ahci_pm_ops, rtk_ahci_suspend, rtk_ahci_resume);
#endif

static const struct of_device_id ahci_of_match[] = {
	{ .compatible = "Realtek,ahci-sata", },
	{},
};
MODULE_DEVICE_TABLE(of, ahci_of_match);

static struct platform_driver ahci_driver = {
	.probe = ahci_probe,
	.remove = ata_platform_remove_one,
	.driver = {
		.name = DRV_NAME_RTK,
		.of_match_table = ahci_of_match,
#ifdef CONFIG_PM
		.pm = &ahci_pm_ops,
#endif
	},
};
module_platform_driver(ahci_driver);

MODULE_DESCRIPTION("AHCI SATA platform driver");
MODULE_AUTHOR("Anton Vorontsov <avorontsov@ru.mvista.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:ahci");
