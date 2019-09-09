#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/clk.h>
#include <linux/dma-mapping.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/usb/phy.h>
#include <linux/slab.h>
#include <linux/usb/xhci_pdriver.h>
#include <linux/acpi.h>

#include "xhci.h"
#include "xhci-mvebu.h"
#include "xhci-rcar.h"
#if defined(MY_DEF_HERE)
#include <linux/usb/otg.h>
#endif  

static struct hc_driver __read_mostly xhci_plat_hc_driver;

static int xhci_plat_setup(struct usb_hcd *hcd);
static int xhci_plat_start(struct usb_hcd *hcd);

static const struct xhci_driver_overrides xhci_plat_overrides __initconst = {
	.extra_priv_size = sizeof(struct xhci_hcd),
	.reset = xhci_plat_setup,
	.start = xhci_plat_start,
};

static void xhci_plat_quirks(struct device *dev, struct xhci_hcd *xhci)
{
	 
	xhci->quirks |= XHCI_PLAT;
#if defined(MY_DEF_HERE)

	if (of_property_read_bool(dev->of_node, "needs-reset-on-resume"))
		xhci->quirks |= XHCI_RESET_ON_RESUME;
#endif  
}

static int xhci_plat_setup(struct usb_hcd *hcd)
{
	struct device_node *of_node = hcd->self.controller->of_node;
	int ret;

	if (of_device_is_compatible(of_node, "renesas,xhci-r8a7790") ||
	    of_device_is_compatible(of_node, "renesas,xhci-r8a7791")) {
		ret = xhci_rcar_init_quirk(hcd);
		if (ret)
			return ret;
	}

	return xhci_gen_setup(hcd, xhci_plat_quirks);
}

static int xhci_plat_start(struct usb_hcd *hcd)
{
	struct device_node *of_node = hcd->self.controller->of_node;

	if (of_device_is_compatible(of_node, "renesas,xhci-r8a7790") ||
	    of_device_is_compatible(of_node, "renesas,xhci-r8a7791"))
		xhci_rcar_start(hcd);

	return xhci_run(hcd);
}

#if defined(MY_DEF_HERE)
 
int xhci_phy_init(struct usb_hcd *hcd, const char *phy_name)
{
	struct phy *phy = NULL;
	int ret = 0;

	phy = phy_get(hcd->self.controller, phy_name);

	if (IS_ERR(phy)) {
		ret = PTR_ERR(phy);
	} else {
		ret = phy_init(phy);
		if (ret) {
			phy_put(phy);
			return ret;
		}
		ret = phy_power_on(phy);
		if (ret) {
			phy_exit(phy);
			phy_put(phy);
			return ret;
		}
		hcd->phy = phy;
	}

	return ret;
}

#endif  
static int xhci_plat_probe(struct platform_device *pdev)
{
#if defined (MY_ABC_HERE)
	u32 vbus_gpio_pin = 0;
#endif  
	struct device_node	*node = pdev->dev.of_node;
	struct usb_xhci_pdata	*pdata = dev_get_platdata(&pdev->dev);
	const struct hc_driver	*driver;
	struct xhci_hcd		*xhci;
	struct resource         *res;
	struct usb_hcd		*hcd;
	struct clk              *clk;
	int			ret;
	int			irq;

	if (usb_disabled())
		return -ENODEV;

	driver = &xhci_plat_hc_driver;

	irq = platform_get_irq(pdev, 0);
	if (irq < 0)
		return -ENODEV;

	if (WARN_ON(!pdev->dev.dma_mask))
		 
		ret = dma_coerce_mask_and_coherent(&pdev->dev,
						   DMA_BIT_MASK(64));
	else
		ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));

	if (ret) {
		ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
		if (ret)
			return ret;
	}

	hcd = usb_create_hcd(driver, &pdev->dev, dev_name(&pdev->dev));
	if (!hcd)
		return -ENOMEM;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	hcd->regs = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(hcd->regs)) {
		ret = PTR_ERR(hcd->regs);
		goto put_hcd;
	}

	hcd->rsrc_start = res->start;
	hcd->rsrc_len = resource_size(res);

	clk = devm_clk_get(&pdev->dev, NULL);
	if (!IS_ERR(clk)) {
		ret = clk_prepare_enable(clk);
		if (ret)
			goto put_hcd;
	} else if (PTR_ERR(clk) == -EPROBE_DEFER) {
		ret = -EPROBE_DEFER;
		goto put_hcd;
	}

	if (of_device_is_compatible(pdev->dev.of_node,
				    "marvell,armada-375-xhci") ||
	    of_device_is_compatible(pdev->dev.of_node,
				    "marvell,armada-380-xhci")) {
		ret = xhci_mvebu_mbus_init_quirk(pdev);
		if (ret)
			goto disable_clk;
	}

	device_wakeup_enable(hcd->self.controller);

	xhci = hcd_to_xhci(hcd);
	xhci->clk = clk;
	xhci->main_hcd = hcd;
	xhci->shared_hcd = usb_create_shared_hcd(driver, &pdev->dev,
			dev_name(&pdev->dev), hcd);
	if (!xhci->shared_hcd) {
		ret = -ENOMEM;
		goto disable_clk;
	}

	if ((node && of_property_read_bool(node, "usb3-lpm-capable")) ||
			(pdata && pdata->usb3_lpm_capable))
		xhci->quirks |= XHCI_LPM_SUPPORT;

	hcd->usb_phy = devm_usb_get_phy_by_phandle(&pdev->dev, "usb-phy", 0);
	if (IS_ERR(hcd->usb_phy)) {
		ret = PTR_ERR(hcd->usb_phy);
		if (ret == -EPROBE_DEFER)
			goto put_usb3_hcd;
		hcd->usb_phy = NULL;
	} else {
		ret = usb_phy_init(hcd->usb_phy);
		if (ret)
			goto put_usb3_hcd;
	}

#if defined (MY_ABC_HERE)
	if (node) {
		if (of_property_read_bool(node, "power-control-capable")) {
			hcd->power_control_support = 1;
		} else {
			hcd->power_control_support = 0;
		}
		if (of_property_read_bool(node, "vbus-gpio")) {
			of_property_read_u32(node, "vbus-gpio", &vbus_gpio_pin);
			 
			hcd->vbus_gpio_pin = vbus_gpio_pin;
		} else {
			hcd->vbus_gpio_pin = -1;
			dev_warn(&pdev->dev, "failed to get Vbus gpio\n");
		}
	}
	dev_info(&pdev->dev, "USB2 Vbus gpio %d\n", hcd->vbus_gpio_pin);
	dev_info(&pdev->dev, "power control %s\n", hcd->power_control_support ?
			"enabled" : "disabled");
#endif  

#if defined(MY_DEF_HERE)
	if (of_device_is_compatible(pdev->dev.of_node,
#if defined(MY_DEF_HERE)
				    "marvell,armada-3700-xhci")) {
#else  
				    "marvell,armada-3700-xhci-otg")) {
#endif  
		 
		if (hcd->usb_phy == NULL) {
			dev_err(&pdev->dev, "unable to find OTG PHY\n");
			goto disable_usb_phy;
		}

		hcd->irq = irq;

#if defined(MY_DEF_HERE)
		 
		if (of_property_read_bool(pdev->dev.of_node, "separated-phys-for-usb2-usb3")) {
			if (xhci_phy_init(hcd, "usb2")) {
				dev_err(&pdev->dev, "unable to init and power on USB2 PHY\n");
				goto disable_usb_phy;
			}
			if (xhci_phy_init(xhci->shared_hcd, "usb3")) {
				dev_err(&pdev->dev, "unable to init and power on USB3 PHY\n");
				goto disable_usb_phy;
			}
		}

#endif  
		ret = otg_set_host(hcd->usb_phy->otg, &hcd->self);
		if (ret) {
			dev_err(&pdev->dev, "unable to register with OTG PHY\n");
			goto disable_usb_phy;
		}
	} else {
#if defined(MY_DEF_HERE)
		 
		if (of_property_read_bool(pdev->dev.of_node, "separated-phys-for-usb2-usb3")) {
			ret = usb_add_hcd_with_phy_name(hcd, irq, IRQF_SHARED, "usb2");
			if (ret)
				goto disable_usb_phy;

			ret = usb_add_hcd_with_phy_name(xhci->shared_hcd, irq, IRQF_SHARED, "usb3");
			if (ret)
				goto dealloc_usb2_hcd;
		} else {
			ret = usb_add_hcd(hcd, irq, IRQF_SHARED);
			if (ret)
				goto disable_usb_phy;

			ret = usb_add_hcd(xhci->shared_hcd, irq, IRQF_SHARED);
			if (ret)
				goto dealloc_usb2_hcd;
		}
#else  
		ret = usb_add_hcd(hcd, irq, IRQF_SHARED);
		if (ret)
			goto disable_usb_phy;
#endif  

#if defined (MY_ABC_HERE)
		xhci->shared_hcd->vbus_gpio_pin = hcd->vbus_gpio_pin;
		xhci->shared_hcd->power_control_support = hcd->power_control_support;
		dev_info(&pdev->dev, "USB3 Vbus gpio %d\n",
				xhci->shared_hcd->vbus_gpio_pin);
		dev_info(&pdev->dev, "power control %s\n", hcd->power_control_support ?
				"enabled" : "disabled");
#endif  

		if (HCC_MAX_PSA(xhci->hcc_params) >= 4)
			xhci->shared_hcd->can_do_streams = 1;

#if defined(MY_DEF_HERE)
 
#else  
		ret = usb_add_hcd(xhci->shared_hcd, irq, IRQF_SHARED);
		if (ret)
			goto dealloc_usb2_hcd;
#endif  
	}
#else  
	ret = usb_add_hcd(hcd, irq, IRQF_SHARED);
	if (ret)
		goto disable_usb_phy;

#if defined (MY_ABC_HERE)
	xhci->shared_hcd->vbus_gpio_pin = hcd->vbus_gpio_pin;
	xhci->shared_hcd->power_control_support = hcd->power_control_support;
	dev_info(&pdev->dev, "USB3 Vbus gpio %d\n",
			xhci->shared_hcd->vbus_gpio_pin);
	dev_info(&pdev->dev, "power control %s\n", hcd->power_control_support ?
			"enabled" : "disabled");
#endif  

	if (HCC_MAX_PSA(xhci->hcc_params) >= 4)
		xhci->shared_hcd->can_do_streams = 1;

	ret = usb_add_hcd(xhci->shared_hcd, irq, IRQF_SHARED);
	if (ret)
		goto dealloc_usb2_hcd;
#endif  

	return 0;

dealloc_usb2_hcd:
	usb_remove_hcd(hcd);

disable_usb_phy:
	usb_phy_shutdown(hcd->usb_phy);

put_usb3_hcd:
	usb_put_hcd(xhci->shared_hcd);

disable_clk:
	if (!IS_ERR(clk))
		clk_disable_unprepare(clk);

put_hcd:
	usb_put_hcd(hcd);

	return ret;
}

static int xhci_plat_remove(struct platform_device *dev)
{
	struct usb_hcd	*hcd = platform_get_drvdata(dev);
	struct xhci_hcd	*xhci = hcd_to_xhci(hcd);
	struct clk *clk = xhci->clk;

	xhci->xhc_state |= XHCI_STATE_REMOVING;

#if defined(MY_DEF_HERE)
	if (of_device_is_compatible(dev->dev.of_node,
#if defined(MY_DEF_HERE)
				    "marvell,armada-3700-xhci")) {
#else  
				    "marvell,armada-3700-xhci-otg")) {
#endif  
		otg_set_host(hcd->usb_phy->otg, NULL);
	} else {
		usb_remove_hcd(xhci->shared_hcd);
		usb_phy_shutdown(hcd->usb_phy);

		usb_remove_hcd(hcd);
	}
#else  
	usb_remove_hcd(xhci->shared_hcd);
	usb_phy_shutdown(hcd->usb_phy);

	usb_remove_hcd(hcd);
#endif  

	usb_put_hcd(xhci->shared_hcd);

	if (!IS_ERR(clk))
		clk_disable_unprepare(clk);
	usb_put_hcd(hcd);

	return 0;
}

#if defined(MY_DEF_HERE)
void xhci_plat_shutdown(struct platform_device *dev)
{
	xhci_plat_remove(dev);
}
#endif  

#ifdef CONFIG_PM_SLEEP
static int xhci_plat_suspend(struct device *dev)
{
	struct usb_hcd	*hcd = dev_get_drvdata(dev);
	struct xhci_hcd	*xhci = hcd_to_xhci(hcd);
#if defined(MY_DEF_HERE)
	int ret;
#endif  

#if defined(MY_DEF_HERE)
	ret = xhci_suspend(xhci, device_may_wakeup(dev));
	if (ret) {
		dev_err(dev, "unable to suspend xhci\n");
		return ret;
	}

	phy_power_off(hcd->phy);
	phy_exit(hcd->phy);

	if (of_property_read_bool(dev->of_node, "separated-phys-for-usb2-usb3")) {
		phy_power_off(xhci->shared_hcd->phy);
		phy_exit(xhci->shared_hcd->phy);
	}

	return 0;
#else  
	return xhci_suspend(xhci, device_may_wakeup(dev));
#endif  
}

static int xhci_plat_resume(struct device *dev)
{
	struct usb_hcd	*hcd = dev_get_drvdata(dev);
	struct xhci_hcd	*xhci = hcd_to_xhci(hcd);
#if defined(MY_DEF_HERE)
	int ret;

	ret = phy_init(hcd->phy);
	if (ret)
		return ret;

	ret = phy_power_on(hcd->phy);
	if (ret) {
		phy_exit(hcd->phy);
		return ret;
	}

	if (of_property_read_bool(dev->of_node, "separated-phys-for-usb2-usb3")) {
		ret = phy_init(xhci->shared_hcd->phy);
		if (ret)
			return ret;

		ret = phy_power_on(xhci->shared_hcd->phy);
		if (ret) {
			phy_exit(xhci->shared_hcd->phy);
			 
			phy_power_off(hcd->phy);
			phy_exit(hcd->phy);
			return ret;
		}
	}
#endif  

	return xhci_resume(xhci, 0);
}

static const struct dev_pm_ops xhci_plat_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(xhci_plat_suspend, xhci_plat_resume)
};
#define DEV_PM_OPS	(&xhci_plat_pm_ops)
#else
#define DEV_PM_OPS	NULL
#endif  

#ifdef CONFIG_OF
static const struct of_device_id usb_xhci_of_match[] = {
	{ .compatible = "generic-xhci" },
	{ .compatible = "xhci-platform" },
	{ .compatible = "marvell,armada-375-xhci"},
	{ .compatible = "marvell,armada-380-xhci"},
	{ .compatible = "renesas,xhci-r8a7790"},
	{ .compatible = "renesas,xhci-r8a7791"},
#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
	{ .compatible = "marvell,armada-3700-xhci"},
#else  
	{ .compatible = "marvell,armada-3700-xhci-otg"},
#endif  
#endif  
	{ },
};
MODULE_DEVICE_TABLE(of, usb_xhci_of_match);
#endif

static const struct acpi_device_id usb_xhci_acpi_match[] = {
	 
	{ "PNP0D10", },
	{ }
};
MODULE_DEVICE_TABLE(acpi, usb_xhci_acpi_match);

static struct platform_driver usb_xhci_driver = {
#if defined(MY_DEF_HERE)
	.probe		= xhci_plat_probe,
	.remove		= xhci_plat_remove,
	.shutdown	= xhci_plat_shutdown,
#else  
	.probe	= xhci_plat_probe,
	.remove	= xhci_plat_remove,
#endif  
	.driver	= {
		.name = "xhci-hcd",
		.pm = DEV_PM_OPS,
		.of_match_table = of_match_ptr(usb_xhci_of_match),
		.acpi_match_table = ACPI_PTR(usb_xhci_acpi_match),
	},
};
MODULE_ALIAS("platform:xhci-hcd");

static int __init xhci_plat_init(void)
{
	xhci_init_driver(&xhci_plat_hc_driver, &xhci_plat_overrides);
	return platform_driver_register(&usb_xhci_driver);
}
module_init(xhci_plat_init);

static void __exit xhci_plat_exit(void)
{
	platform_driver_unregister(&usb_xhci_driver);
}
module_exit(xhci_plat_exit);

MODULE_DESCRIPTION("xHCI Platform Host Controller Driver");
MODULE_LICENSE("GPL");
