/*
 * xHCI host controller driver PCI Bus Glue.
 *
 * Copyright (C) 2008 Intel Corp.
 *
 * Author: Sarah Sharp
 * Some code borrowed from the Linux EHCI driver.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/pci.h>

#include "etxhci.h"

static struct table_item cfg_s1_items_v00660[] = {
		{0x9b, 0xa1},
		{0x9c, 0x18},
		{0xec, 0x04},
		{0xf5, 0x40},
};
#define CFG_S1_ITEMS_V00660	((int)(sizeof(cfg_s1_items_v00660)/sizeof(cfg_s1_items_v00660[0])))

static struct table_item cfg_s2_items_v00660[] = {
		{0x44, 0x00000003},
		{0x2c, 0x70231b6f},
		{0x68, 0x19c001c1},
		{0x68, 0x18005000},
		{0x68, 0x198001d0},
		{0x68, 0x18005000},
		{0x68, 0x199001d1},
		{0x68, 0x18005000},
		{0x68, 0x19eb5003},
		{0x68, 0x19305004},
		{0x68, 0x19005005},
		{0x68, 0x19045007},
		{0x68, 0x19f05022},
		{0x68, 0x190000ec},
		{0x44, 0x00000000},
};
#define CFG_S2_ITEMS_V00660	((int)(sizeof(cfg_s2_items_v00660)/sizeof(cfg_s2_items_v00660[0])))

static struct table_item mmio_items_v00660[] = {
		{0x1811, 0x60},
		{0x4000, 0x60},
		{0x4001, 0x06},
		{0x4002, 0x50},
		{0x4003, 0x21},
		{0x0008, 0xff},
		{0x0010, 0xa5},
		{0x0011, 0x40},
		{0x4022, 0x10},
		{0x4059, 0x80},
		{0x405f, 0x04},
		{0x4063, 0x01},
		{0x4071, 0x23},
		{0x4072, 0x76},
		{0x4075, 0x80},
		{0x4079, 0x02},
		{0x407d, 0x20},
		{0x407e, 0x80},
		{0x4090, 0x00},
		{0x4091, 0x30},
		{0x40ac, 0xa8},
		{0x40ad, 0x61},
		{0x40bc, 0xa8},
		{0x40bd, 0x61},
		{0x40a4, 0x05},
		{0x40b4, 0x05},
		{0x4200, 0x08},
		{0x4300, 0x08},
		{0x4202, 0x58},
		{0x4302, 0x58},
		{0x40c0, 0x0e},
		{0x40f4, 0x03},
		{0x1811, 0x61},
};

#define MMIO_ITEMS_V00660	((int)(sizeof(mmio_items_v00660)/sizeof(mmio_items_v00660[0])))

void xhci_init_ej168_v00660(struct xhci_hcd *xhci)
{
	int i, error_flag = 0;
	struct usb_hcd *hcd = xhci_to_hcd(xhci);
	struct pci_dev *pdev = to_pci_dev(hcd->self.controller);
	u8 reg8 = 0;

	for (i = 0; i < CFG_S1_ITEMS_V00660; i++) {
		pci_write_config_byte(pdev, cfg_s1_items_v00660[i].offset,
			(u8)cfg_s1_items_v00660[i].value);
	}

	for (i = 0; i < CFG_S2_ITEMS_V00660; i++) {
		pci_write_config_dword(pdev, cfg_s2_items_v00660[i].offset,
			cfg_s2_items_v00660[i].value);
		if (cfg_s2_items_v00660[i].offset == 0x68 &&
			cfg_s2_items_v00660[i].value != 0x18005000)
			mdelay(1);
	}

	for (i = 0; i < MMIO_ITEMS_V00660; i++) {
		xhci_writeb(xhci, mmio_items_v00660[i].value,
			mmio_items_v00660[i].offset);
	}

	for (i = 0; i < MMIO_ITEMS_V00660; i++) {
		if ((0x1811 != mmio_items_v00660[i].offset) && (0 == error_flag)) {
			reg8 = xhci_readb(xhci, mmio_items_v00660[i].offset);
			if (reg8 != (u8)mmio_items_v00660[i].value)
				error_flag = 1;
		}
	}

	if (error_flag) {
		for (i = 0; i < MMIO_ITEMS_V00660; i++) {
			if (0x1811 != mmio_items_v00660[i].offset) {
				reg8 = xhci_readb(xhci, mmio_items_v00660[i].offset);
				xhci_err(xhci, "%s - @%04x %02x\n",
					__func__, mmio_items_v00660[i].offset, reg8);
			}
		}
	}
}
