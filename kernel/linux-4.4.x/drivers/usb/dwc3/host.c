#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
/**
 * host.c - DesignWare USB3 DRD Controller Host Glue
 *
 * Copyright (C) 2011 Texas Instruments Incorporated - http://www.ti.com
 *
 * Authors: Felipe Balbi <balbi@ti.com>,
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2  of
 * the License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/platform_device.h>
#include <linux/usb/xhci_pdriver.h>

#include "core.h"

int dwc3_host_init(struct dwc3 *dwc)
{
	struct platform_device	*xhci;
	struct usb_xhci_pdata	pdata;
	int			ret;

#if defined(CONFIG_USB_RTK_DWC3_DRD_MODE) && defined(MY_DEF_HERE)
	dev_info(dwc->dev, "%s\n", __func__);
#endif /* defined(CONFIG_USB_RTK_DWC3_DRD_MODE) && defined(MY_DEF_HERE) */

	xhci = platform_device_alloc("xhci-hcd", PLATFORM_DEVID_AUTO);
	if (!xhci) {
		dev_err(dwc->dev, "couldn't allocate xHCI device\n");
		return -ENOMEM;
	}

	dma_set_coherent_mask(&xhci->dev, dwc->dev->coherent_dma_mask);

	xhci->dev.parent	= dwc->dev;
	xhci->dev.dma_mask	= dwc->dev->dma_mask;
	xhci->dev.dma_parms	= dwc->dev->dma_parms;

	dwc->xhci = xhci;
#if defined(CONFIG_USB_RTK_DWC3_DRD_MODE) && defined(MY_DEF_HERE)
	dwc->has_xhci = true;
#endif /* defined(CONFIG_USB_RTK_DWC3_DRD_MODE) && defined(MY_DEF_HERE) */

	ret = platform_device_add_resources(xhci, dwc->xhci_resources,
						DWC3_XHCI_RESOURCES_NUM);
	if (ret) {
		dev_err(dwc->dev, "couldn't add resources to xHCI device\n");
		goto err1;
	}

	memset(&pdata, 0, sizeof(pdata));

	pdata.usb3_lpm_capable = dwc->usb3_lpm_capable;

	ret = platform_device_add_data(xhci, &pdata, sizeof(pdata));
	if (ret) {
		dev_err(dwc->dev, "couldn't add platform data to xHCI device\n");
		goto err1;
	}

	phy_create_lookup(dwc->usb2_generic_phy, "usb2-phy",
			  dev_name(&xhci->dev));
	phy_create_lookup(dwc->usb3_generic_phy, "usb3-phy",
			  dev_name(&xhci->dev));

	ret = platform_device_add(xhci);
	if (ret) {
		dev_err(dwc->dev, "failed to register xHCI device\n");
		goto err2;
	}

	return 0;
err2:
	phy_remove_lookup(dwc->usb2_generic_phy, "usb2-phy",
			  dev_name(&xhci->dev));
	phy_remove_lookup(dwc->usb3_generic_phy, "usb3-phy",
			  dev_name(&xhci->dev));
err1:
	platform_device_put(xhci);
	return ret;
}
#ifdef MY_DEF_HERE
EXPORT_SYMBOL_GPL(dwc3_host_init);
#endif

void dwc3_host_exit(struct dwc3 *dwc)
{
	phy_remove_lookup(dwc->usb2_generic_phy, "usb2-phy",
			  dev_name(&dwc->xhci->dev));
	phy_remove_lookup(dwc->usb3_generic_phy, "usb3-phy",
			  dev_name(&dwc->xhci->dev));
#if defined(CONFIG_USB_RTK_DWC3_DRD_MODE) && defined(MY_DEF_HERE)
	dwc->has_xhci = false;
#endif /* defined(CONFIG_USB_RTK_DWC3_DRD_MODE) && defined(MY_DEF_HERE) */
	platform_device_unregister(dwc->xhci);
}
#ifdef MY_DEF_HERE
EXPORT_SYMBOL_GPL(dwc3_host_exit);
#endif
