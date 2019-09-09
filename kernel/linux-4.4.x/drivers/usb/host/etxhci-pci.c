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
#include <linux/slab.h>
#include <linux/module.h>

#include "etxhci.h"

/* Device for a quirk */
#define PCI_VENDOR_ID_ETRON		0x1b6f
#define PCI_DEVICE_ID_ETRON_EJ168	0x7023
#define PCI_DEVICE_ID_ETRON_EJ188	0x7052

static const char hcd_name[] = "etxhci_hcd-170202";

/* called after powerup, by probe or system-pm "wakeup" */
static int xhci_pci_reinit(struct xhci_hcd *xhci, struct pci_dev *pdev)
{
	/*
	 * TODO: Implement finding debug ports later.
	 * TODO: see if there are any quirks that need to be added to handle
	 * new extended capabilities.
	 */

	/* PCI Memory-Write-Invalidate cycle support is optional (uncommon) */
	if (!pci_set_mwi(pdev))
		xhci_dbg(xhci, "MWI active\n");

	xhci_dbg(xhci, "Finished xhci_pci_reinit\n");
	return 0;
}

static void xhci_pci_quirks(struct device *dev, struct xhci_hcd *xhci)
{
	struct pci_dev		*pdev = to_pci_dev(dev);
	struct usb_hcd		*hcd = xhci_to_hcd(xhci);

	/* Look for vendor-specific quirks */
	hcd->chip_id = HCD_CHIP_ID_UNKNOWN;
	if (pdev->vendor == PCI_VENDOR_ID_ETRON) {
		pci_read_config_dword(pdev, 0x58, &xhci->hcc_params1);
		xhci->hcc_params1 &= 0xffff;
		xhci_init_ejxxx(xhci);

		if (pdev->device == PCI_DEVICE_ID_ETRON_EJ168)
			hcd->chip_id = HCD_CHIP_ID_ETRON_EJ168;
		else if (pdev->device == PCI_DEVICE_ID_ETRON_EJ188) {
			hcd->chip_id = HCD_CHIP_ID_ETRON_EJ188;
			xhci->quirks |= XHCI_BULK_XFER_QUIRK;
		}

		xhci_dbg(xhci, "Etron chip ID %02x\n", hcd->chip_id);
		xhci->quirks |= XHCI_SPURIOUS_SUCCESS;
		xhci->quirks |= XHCI_HUB_INFO_QUIRK;
		xhci->quirks |= XHCI_RESET_ON_RESUME;
		xhci_dbg(xhci, "QUIRK: Resetting on resume\n");
	}

	if (((xhci->hcc_params1 & 0xff) == 0x30) ||
		((xhci->hcc_params1 & 0xff) == 0x40)) {
		xhci->quirks |= XHCI_EP_INFO_QUIRK;
	}
}

/* called during probe() after chip reset completes */
static int xhci_pci_setup(struct usb_hcd *hcd)
{
	struct xhci_hcd		*xhci;
	struct pci_dev		*pdev = to_pci_dev(hcd->self.controller);
	int			retval;

	retval = etxhci_gen_setup(hcd, xhci_pci_quirks);
	if (retval)
		return retval;

	xhci = hcd_to_xhci(hcd);
	if (!usb_hcd_is_primary_hcd(hcd))
		return 0;

	pci_read_config_byte(pdev, XHCI_SBRN_OFFSET, &xhci->sbrn);
	xhci_dbg(xhci, "Got SBRN %u\n", (unsigned int) xhci->sbrn);

	/* Find any debug ports */
	retval = xhci_pci_reinit(xhci, pdev);
	if (!retval)
		return retval;

	kfree(xhci);
	return retval;
}

/*
 * We need to register our own PCI probe function (instead of the USB core's
 * function) in order to create a second roothub under xHCI.
 */
static int xhci_pci_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	int retval;
	struct xhci_hcd *xhci;
	struct hc_driver *driver;
	struct usb_hcd *hcd;
	char name[16];

	if (dev->vendor != PCI_VENDOR_ID_ETRON)
		return -ENODEV;

	driver = (struct hc_driver *)id->driver_data;

	/* Prevent runtime suspending between USB-2 and USB-3 initialization */
	pm_runtime_get_noresume(&dev->dev);

	/* Register the USB 2.0 roothub.
	 * FIXME: USB core must know to register the USB 2.0 roothub first.
	 * This is sort of silly, because we could just set the HCD driver flags
	 * to say USB 2.0, but I'm not sure what the implications would be in
	 * the other parts of the HCD code.
	 */
	retval = usb_hcd_pci_probe(dev, id);

	if (retval)
		goto put_runtime_pm;

	/* USB 2.0 roothub is stored in the PCI device now. */
	hcd = dev_get_drvdata(&dev->dev);
	xhci = hcd_to_xhci(hcd);
	xhci->shared_hcd = usb_create_shared_hcd(driver, &dev->dev,
				pci_name(dev), hcd);
	if (!xhci->shared_hcd) {
		retval = -ENOMEM;
		goto dealloc_usb2_hcd;
	}

	/* Set the xHCI pointer before xhci_pci_setup() (aka hcd_driver.reset)
	 * is called by usb_add_hcd().
	 */
	*((struct xhci_hcd **) xhci->shared_hcd->hcd_priv) = xhci;

	retval = usb_add_hcd(xhci->shared_hcd, dev->irq,
			IRQF_SHARED);
	if (retval)
		goto put_usb3_hcd;
	/* Roothub already marked as USB 3.0 speed */

	snprintf(name, sizeof(name), "etxhci_wq%d", hcd->self.busnum);
	xhci->bulk_xfer_wq = create_singlethread_workqueue(name);
	if (!xhci->bulk_xfer_wq) {
		retval = -ENOMEM;
		goto put_usb3_hcd;
	}

	INIT_WORK(&xhci->bulk_xfer_work, xhci_bulk_xfer_work);
	INIT_LIST_HEAD(&xhci->bulk_xfer_list);
	xhci->bulk_xfer_count = 0;

	/* USB-2 and USB-3 roothubs initialized, allow runtime pm suspend */
	pm_runtime_put_noidle(&dev->dev);

	return 0;

put_usb3_hcd:
	usb_put_hcd(xhci->shared_hcd);
dealloc_usb2_hcd:
	usb_hcd_pci_remove(dev);
put_runtime_pm:
	pm_runtime_put_noidle(&dev->dev);
	return retval;
}

static void xhci_pci_remove(struct pci_dev *dev)
{
	struct xhci_hcd *xhci;

	xhci = hcd_to_xhci(pci_get_drvdata(dev));
	if (xhci->shared_hcd) {
		usb_remove_hcd(xhci->shared_hcd);
		usb_put_hcd(xhci->shared_hcd);
	}
	usb_hcd_pci_remove(dev);
	if (xhci->bulk_xfer_wq)
		destroy_workqueue(xhci->bulk_xfer_wq);

	kfree(xhci);
}

#ifdef CONFIG_PM
static int xhci_pci_suspend(struct usb_hcd *hcd, bool do_wakeup)
{
	struct xhci_hcd	*xhci = hcd_to_xhci(hcd);
	int	retval = 0;

	if (hcd->state != HC_STATE_SUSPENDED ||
			xhci->shared_hcd->state != HC_STATE_SUSPENDED)
		return -EINVAL;

	retval = etxhci_suspend(xhci);

	return retval;
}

static int xhci_pci_resume(struct usb_hcd *hcd, bool hibernated)
{
	struct xhci_hcd		*xhci = hcd_to_xhci(hcd);
	int			retval = 0;

	retval = etxhci_resume(xhci, hibernated);

	return retval;
}
#endif /* CONFIG_PM */

static const struct hc_driver xhci_pci_hc_driver = {
	.description =		hcd_name,
	.product_desc =		"Etron xHCI Host Controller",
	.hcd_priv_size =	sizeof(struct xhci_hcd *),

	/*
	 * generic hardware linkage
	 */
	.irq =			etxhci_irq,
	.flags =		HCD_MEMORY | HCD_USB3 | HCD_SHARED,

	/*
	 * basic lifecycle operations
	 */
	.reset =		xhci_pci_setup,
	.start =		etxhci_run,
#ifdef CONFIG_PM
	.pci_suspend =          xhci_pci_suspend,
	.pci_resume =           xhci_pci_resume,
#endif
	.stop =			etxhci_stop,
	.shutdown =		etxhci_shutdown,

	/*
	 * managing i/o requests and associated device resources
	 */
	.urb_enqueue =		etxhci_urb_enqueue,
	.urb_dequeue =		etxhci_urb_dequeue,
	.alloc_dev =		etxhci_alloc_dev,
	.free_dev =		etxhci_free_dev,
	.alloc_streams =	etxhci_alloc_streams,
	.free_streams =		etxhci_free_streams,
	.add_endpoint =		etxhci_add_endpoint,
	.drop_endpoint =	etxhci_drop_endpoint,
	.stop_endpoint =	etxhci_stop_endpoint,
	.endpoint_reset =	etxhci_endpoint_reset,
	.check_bandwidth =	etxhci_check_bandwidth,
	.reset_bandwidth =	etxhci_reset_bandwidth,
	.address_device =	etxhci_address_device,
	.update_hub_device =	etxhci_update_hub_device,
	.reset_device =		etxhci_discover_or_reset_device,
	.update_uas_device = etxhci_update_uas_device,

	/*
	 * scheduling support
	 */
	.get_frame_number =	etxhci_get_frame,

	/* Root hub support */
	.hub_control =		etxhci_hub_control,
	.hub_status_data =	etxhci_hub_status_data,
	.bus_suspend =		etxhci_bus_suspend,
	.bus_resume =		etxhci_bus_resume,
};

/*-------------------------------------------------------------------------*/

/* PCI driver selection metadata; PCI hotplugging uses this */
static const struct pci_device_id pci_ids[] = { {
	/* handle any USB 3.0 xHCI controller */
	PCI_DEVICE_CLASS(PCI_CLASS_SERIAL_USB_XHCI, ~0),
	.driver_data =	(unsigned long) &xhci_pci_hc_driver,
	},
	{ /* end: all zeroes */ }
};
MODULE_DEVICE_TABLE(pci, pci_ids);

/* pci driver glue; this is a "new style" PCI driver module */
static struct pci_driver xhci_pci_driver = {
	.name =		(char *) hcd_name,
	.id_table =	pci_ids,

	.probe =	xhci_pci_probe,
	.remove =	xhci_pci_remove,
	/* suspend and resume implemented later */

	.shutdown = 	usb_hcd_pci_shutdown,
#ifdef CONFIG_PM
	.driver = {
		.pm = &usb_hcd_pci_pm_ops
	},
#endif
};

int __init etxhci_register_pci(void)
{
	return pci_register_driver(&xhci_pci_driver);
}

void etxhci_unregister_pci(void)
{
	pci_unregister_driver(&xhci_pci_driver);
}
