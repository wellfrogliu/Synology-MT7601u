/*
 * OHCI HCD (Host Controller Driver) for USB.
 *
 * Bus Glue for Rtk Dmp chips
 *
 * Based on "ohci-au1xxx.c" by Matt Porter <mporter@kernel.crashing.org>
 *
 * Modified for Rtk Dmp chips
 *
 * This file is licenced under the GPL.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/mbus.h>
#include <linux/clk.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/of_address.h>
#include <linux/usb.h>
#include <linux/usb/hcd.h>
#include <linux/io.h>
#include <linux/dma-mapping.h>

#define RTK_OHCI_HCD_NAME "rtk-ohci"

extern int usb_disabled(void);

static int ohci_rtk_dmp_start(struct usb_hcd *hcd)
{
    struct ohci_hcd	*ohci = hcd_to_ohci(hcd);
    int ret;

    ohci_dbg(ohci, "ohci_rtk_dmp_start, ohci:%p", ohci);

    if ((ret = ohci_init(ohci)) < 0)
        return ret;

    if ((ret = ohci_run(ohci)) < 0) {
        printk ("can't start %s", hcd->self.bus_name);
        ohci_stop(hcd);
        return ret;
    }

    return 0;
}

static const struct hc_driver ohci_rtk_dmp_hc_driver = {
    .description =		hcd_name,
    .product_desc =		"Rtk Dmp OHCI",
    .hcd_priv_size =	sizeof(struct ohci_hcd),

    /*
     * generic hardware linkage
     */
    .irq =			ohci_irq,
    .flags =		HCD_USB11 | HCD_MEMORY,

    /*
     * basic lifecycle operations
     */
    .start =		ohci_rtk_dmp_start,
    .stop =			ohci_stop,
    .shutdown =		ohci_shutdown,

    /*
     * managing i/o requests and associated device resources
     */
    .urb_enqueue =		ohci_urb_enqueue,
    .urb_dequeue =		ohci_urb_dequeue,
    .endpoint_disable =	ohci_endpoint_disable,

    /*
     * scheduling support
     */
    .get_frame_number =	ohci_get_frame,

    /*
     * root hub support
     */
    .hub_status_data =	ohci_hub_status_data,
    .hub_control =		ohci_hub_control,
#ifdef	CONFIG_PM
    .bus_suspend =		ohci_bus_suspend,
    .bus_resume =		ohci_bus_resume,
#endif
    .start_port_reset =	ohci_start_port_reset,
};

struct ohci_rtk {
    struct device *dev;
    struct ohci_hcd *ohci;
    int irq;
};

extern void rtk_usb_init_power_on(struct device *dev);

static int ohci_rtk_drv_probe(struct platform_device *pdev)
{
    struct usb_hcd *hcd;
    struct ohci_hcd *ohci;
    void *reg_base;
    struct resource res;
    int irq;
    int ret;
    struct usb_phy *phy;
    unsigned long probe_time = jiffies;

    if (usb_disabled())
        return -ENODEV;

    dev_info(&pdev->dev, "Probe Realtek-SoC USB OHCI Host Controller\n");

    //phy = devm_usb_get_phy(&pdev->dev, USB_PHY_TYPE_USB2);
    phy = devm_usb_get_phy_by_phandle(&pdev->dev, "usb-phy", 0);
    if (IS_ERR(phy)) {
        dev_err(&pdev->dev, "No usb phy found\n");
        return -ENODEV;
    } else {
        usb_phy_init(phy);
    }

    irq = irq_of_parse_and_map(pdev->dev.of_node, 0);
    if (irq <= 0) {
        dev_err(&pdev->dev,
                "Found HC with no IRQ. Check %s setup!\n",
                dev_name(&pdev->dev));
        return -ENODEV;
    }

    if (of_address_to_resource(pdev->dev.of_node, 0, &res)) {
        dev_err(&pdev->dev,
                "Found HC with no register addr. Check %s setup!\n",
                dev_name(&pdev->dev));
        return -ENODEV;
    }

    /*
     * Right now device-tree probed devices don't get dma_mask
     * set. Since shared usb code relies on it, set it here for
     * now. Once we have dma capability bindings this can go away.
     */
    if (!pdev->dev.dma_mask)
        pdev->dev.dma_mask = &pdev->dev.coherent_dma_mask;
    if (!pdev->dev.coherent_dma_mask)
        pdev->dev.coherent_dma_mask = DMA_BIT_MASK(32);

    hcd = usb_create_hcd(&ohci_rtk_dmp_hc_driver, &pdev->dev, dev_name(&pdev->dev));
    if (!hcd)
        return -ENOMEM;

    hcd->rsrc_start = res.start;
    hcd->rsrc_len = resource_size(&res);

    reg_base = of_iomap(pdev->dev.of_node, 0);
    if (!reg_base) {
        dev_err(&pdev->dev, "ioremap failed\n");
        ret = -ENOMEM;
        goto err2;
    }

    hcd->regs = reg_base;

    ohci = hcd_to_ohci(hcd);

    ohci_hcd_init(ohci);

    ret = usb_add_hcd(hcd, irq, IRQF_SHARED);
    if (ret) {
        dev_err(&pdev->dev, "failed to add hcd with err %d\n", ret);
        goto err2;
    }

    rtk_usb_init_power_on(&pdev->dev);

    platform_set_drvdata(pdev, hcd);

    dev_info(&pdev->dev, "%s OK (take %d ms)\n", __func__, jiffies_to_msecs(jiffies - probe_time));
    return 0;

err2:
    irq_dispose_mapping(irq);
//err1:
    usb_put_hcd(hcd);
    return ret;
}

static int ohci_rtk_drv_remove(struct platform_device *pdev)
{
    struct usb_hcd *hcd = platform_get_drvdata(pdev);

    usb_remove_hcd(hcd);

    iounmap(hcd->regs);

    release_mem_region(hcd->rsrc_start, hcd->rsrc_len);
    usb_put_hcd(hcd);

    platform_set_drvdata(pdev, NULL);

    return 0;
}

static const struct of_device_id ohci_rtk_dt_ids[] = {
    { .compatible = "Realtek,rtk119x-ohci", },
    { .compatible = "Realtek,rtd129x-ohci", },
    {},
};
MODULE_DEVICE_TABLE(of, ohci_rtk_dt_ids);

static struct platform_driver ohci_rtk_driver = {
    .probe		= ohci_rtk_drv_probe,
    .remove		= ohci_rtk_drv_remove,
    .shutdown	= usb_hcd_platform_shutdown,
    .driver		= {
        .name	= RTK_OHCI_HCD_NAME,
        .owner	= THIS_MODULE,
        .of_match_table = of_match_ptr(ohci_rtk_dt_ids),
    },
};

MODULE_ALIAS("platform:" RTK_OHCI_HCD_NAME);
