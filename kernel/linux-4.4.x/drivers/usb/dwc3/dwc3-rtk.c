/**
 * dwc3-rtk.c - Realtek DWC3 Specific Glue layer
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <linux/clk.h>
#include <linux/usb/otg.h>
#include <linux/usb/usb_phy_generic.h>
#include <linux/usb/of.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/suspend.h>

#ifdef CONFIG_ARCH_RTD129X
#include <soc/realtek/rtd129x_cpu.h>
#endif

#define WRAP_CTR_reg  0x0
#define USB_TMP_reg   0x50
#define USB_TMP_reg_1 0x54
#define USB_TMP_reg_2 0x58
#define USB_TMP_reg_3 0x5c
#define USB2_PHY_reg  0x70
#define USB_TYPEC_CTRL_CC1_0 0x14c //0x9801334c

#define EN_SWITCH BIT(29)
#define DISABLE_MULTI_REQ BIT(1)

struct dwc3_rtk {
	struct platform_device	*usb2_phy;
	struct platform_device	*usb3_phy;
	struct device		*dev;

	void __iomem 		*regs;
	size_t      		regs_size;

	struct clk		*clk;
	int dr_mode;
};

static int dwc3_rtk_register_phys(struct dwc3_rtk *rtk)
{
	struct usb_phy_generic_platform_data pdata;
	struct platform_device	*pdev;
	int			ret;

	memset(&pdata, 0x00, sizeof(pdata));

	pdev = platform_device_alloc("usb_phy_generic", PLATFORM_DEVID_AUTO);
	if (!pdev)
		return -ENOMEM;

	rtk->usb2_phy = pdev;
	pdata.type = USB_PHY_TYPE_USB2;

	ret = platform_device_add_data(rtk->usb2_phy, &pdata, sizeof(pdata));
	if (ret)
		goto err1;

	pdev = platform_device_alloc("usb_phy_generic", PLATFORM_DEVID_AUTO);
	if (!pdev) {
		ret = -ENOMEM;
		goto err1;
	}

	rtk->usb3_phy = pdev;
	pdata.type = USB_PHY_TYPE_USB3;

	ret = platform_device_add_data(rtk->usb3_phy, &pdata, sizeof(pdata));
	if (ret)
		goto err2;

	ret = platform_device_add(rtk->usb2_phy);
	if (ret)
		goto err2;

	ret = platform_device_add(rtk->usb3_phy);
	if (ret)
		goto err3;

	return 0;

err3:
	platform_device_del(rtk->usb2_phy);

err2:
	platform_device_put(rtk->usb3_phy);

err1:
	platform_device_put(rtk->usb2_phy);

	return ret;
}

static int dwc3_rtk_remove_child(struct device *dev, void *unused)
{
	struct platform_device *pdev = to_platform_device(dev);

	platform_device_unregister(pdev);

	return 0;
}

static void dwc3_rtk_int_dr_mode(struct dwc3_rtk *rtk, int dr_mode) {
	
	switch (dr_mode) {
		case USB_DR_MODE_PERIPHERAL:
			writel(0x0, rtk->regs + USB_TMP_reg_2);//writel(0x0, IOMEM(0xfe013258));         // in wrapper
			writel(0x0, rtk->regs + USB2_PHY_reg);//writel(0x0, IOMEM(0xfe013270));         // set Dpm 1'b0
		break;
		case USB_DR_MODE_HOST:
			writel(0x7, rtk->regs + USB_TMP_reg_2);//writel(0x7, IOMEM(0xfe013258));         // in wrapper
			writel(0x606, rtk->regs + USB2_PHY_reg);//writel(0x606, IOMEM(0xfe013270));       // set Dpm 1'b1
		break;
		case USB_DR_MODE_OTG:
			writel(BIT(11), rtk->regs + USB2_PHY_reg);
			dev_info(rtk->dev, "%s: USB_DR_MODE_OTG USB_TMP_reg_2=BIT(11)\n", __func__);
		break;
	}
}

static int dwc3_rtk_init(struct dwc3_rtk *rtk) {
	struct device		*dev = rtk->dev;
	void __iomem		*regs = rtk->regs;

#ifdef CONFIG_ARCH_RTD129X
	if (get_rtd129x_cpu_revision() == RTD129x_CHIP_REVISION_A00) {
		writel(DISABLE_MULTI_REQ | readl(regs + WRAP_CTR_reg),
				regs + WRAP_CTR_reg);
		dev_info(dev, "[bug fixed] 1295 A00: add workaround to disable multiple request for D-Bus");
	}
#endif

	return 0;
}

extern void rtk_usb_init_power_on(struct device *dev);

static int dwc3_rtk_probe_dwc3core(struct dwc3_rtk *rtk) {
	struct device		*dev = rtk->dev;
	struct device_node	*node = dev->of_node;
	struct device_node	*next_node;
	int    ret = 0;

	dwc3_rtk_init(rtk);

	if (node) {
		ret = of_platform_populate(node, NULL, NULL, dev);
		if (ret) {
			dev_err(dev, "failed to add dwc3 core\n");
			return ret;
		}

		/* hcy adde below */
		//node =  of_find_compatible_node(NULL, NULL, "synopsys,dwc3");

		next_node = of_get_next_child(node, NULL);
		if (next_node != NULL) {
			int dr_mode;
			dr_mode = of_usb_get_dr_mode(next_node);
			dwc3_rtk_int_dr_mode(rtk, dr_mode);
			rtk->dr_mode = dr_mode;
		}
	}

	rtk_usb_init_power_on(dev);

	return ret;
}

static int dwc3_rtk_probe(struct platform_device *pdev)
{
	struct dwc3_rtk	*rtk;
	struct device		*dev = &pdev->dev;
	struct device_node	*node = dev->of_node;

	struct resource         *res;
	void __iomem            *regs;

	int			ret = -ENOMEM;
	unsigned long probe_time = jiffies;

	dev_info(&pdev->dev, "Probe Realtek-SoC USB DWC3 Host Controller\n");

	rtk = devm_kzalloc(dev, sizeof(*rtk), GFP_KERNEL);
	if (!rtk) {
		dev_err(dev, "not enough memory\n");
		goto err1;
	}

	/*
	 * Right now device-tree probed devices don't get dma_mask set.
	 * Since shared usb code relies on it, set it here for now.
	 * Once we move to full device tree support this will vanish off.
	 */
	if (!dev->dma_mask)
		dev->dma_mask = &dev->coherent_dma_mask;
	if (!dev->coherent_dma_mask)
		dev->coherent_dma_mask = DMA_BIT_MASK(32);

	platform_set_drvdata(pdev, rtk);

	ret = dwc3_rtk_register_phys(rtk);
	if (ret) {
		dev_err(dev, "couldn't register PHYs\n");
		goto err1;
	}

	rtk->dev	= dev;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(dev, "missing memory resource\n");
		return -ENODEV;
	}

	regs = devm_ioremap_resource(dev, res);
	if (IS_ERR(regs)) {
		ret = PTR_ERR(regs);
		goto err1;
	}

	rtk->regs = regs;
	rtk->regs_size = resource_size(res);

	if (node) {
		ret = dwc3_rtk_probe_dwc3core(rtk);
		if (ret) {
			dev_err(dev, "%s failed to add dwc3 core\n", __func__);
			goto err2;
		}
	} else {
		dev_err(dev, "no device node, failed to add dwc3 core\n");
		ret = -ENODEV;
		goto err2;
	}
	dev_info(dev, "dwc3_rtk_probe ok! (take %d ms)\n", jiffies_to_msecs(jiffies - probe_time));

	return 0;

err2:
#if 0
	clk_disable_unprepare(clk);
#endif
err1:
	return ret;
}

static int dwc3_rtk_remove(struct platform_device *pdev)
{
	struct dwc3_rtk	*rtk = platform_get_drvdata(pdev);

	of_platform_depopulate(rtk->dev);

	device_for_each_child(&pdev->dev, NULL, dwc3_rtk_remove_child);
	platform_device_unregister(rtk->usb2_phy);
	platform_device_unregister(rtk->usb3_phy);

	pm_runtime_put_sync(&pdev->dev);
	pm_runtime_disable(&pdev->dev);

	return 0;
}

#ifdef CONFIG_OF
static const struct of_device_id rtk_dwc3_match[] = {
	{ .compatible = "Realtek,rtk119x-dwc3" },
	{ .compatible = "Realtek,rtd129x-dwc3-drd" },
	{ .compatible = "Realtek,rtd129x-dwc3-u2h" },
	{ .compatible = "Realtek,rtd129x-dwc3-u3h" },
	{},
};
MODULE_DEVICE_TABLE(of, rtk_dwc3_match);
#endif

#ifdef CONFIG_PM_SLEEP
extern struct dwc3 *dwc_substance ; //hcy added

static int dwc3_rtk_suspend(struct device *dev)
{
	dev_info(dev, "[USB] Enter %s", __func__);
	if (RTK_PM_STATE == PM_SUSPEND_STANDBY){
		//For idle mode
		dev_info(dev, "[USB] %s Idle mode\n", __func__);
		goto out;
	}
	//For suspend mode
	dev_info(dev,  "[USB] %s Suspend mode\n", __func__);

//hcy removed	clk_disable(rtk->clk);

#if 0
	/* reset usb3 */
	writel(readl(IOMEM(0xfe000000)) & ~(BIT(2)|BIT(4)), IOMEM(0xfe000000));
#endif
out:
	dev_info(dev, "[USB] Exit %s", __func__);
	return 0;
}

static int dwc3_rtk_resume(struct device *dev)
{
	struct dwc3_rtk *rtk = dev_get_drvdata(dev);
	
	dev_info(dev, "[USB] Enter %s", __func__);
	if (RTK_PM_STATE == PM_SUSPEND_STANDBY){
		//For idle mode
		dev_info(dev, "[USB] %s Idle mode\n", __func__);
		goto out;
	}
	//For suspend mode
	dev_info(dev,  "[USB] %s Suspend mode\n", __func__);

	dwc3_rtk_init(rtk);

#if 0
	/* release rst of usb3 */
	writel(readl(IOMEM(0xfe000000)) | (BIT(2)|BIT(4)), IOMEM(0xfe000000));
	mdelay(5);
#endif

	dwc3_rtk_int_dr_mode(rtk, rtk->dr_mode);

	/* runtime set active to reflect active state. */
	pm_runtime_disable(dev);
	pm_runtime_set_active(dev);
	pm_runtime_enable(dev);

out:
	dev_info(dev, "[USB] Exit %s", __func__);
	return 0;
}

static const struct dev_pm_ops dwc3_rtk_dev_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(dwc3_rtk_suspend, dwc3_rtk_resume)
};

#define DEV_PM_OPS	(&dwc3_rtk_dev_pm_ops)
#else
#define DEV_PM_OPS	NULL
#endif /* CONFIG_PM_SLEEP */

static struct platform_driver dwc3_rtk_driver = {
	.probe		= dwc3_rtk_probe,
	.remove		= dwc3_rtk_remove,
	.driver		= {
		.name	= "rtk-dwc3",
		.of_match_table = of_match_ptr(rtk_dwc3_match),
		.pm	= DEV_PM_OPS,
	},
};

module_platform_driver(dwc3_rtk_driver);

MODULE_ALIAS("platform:rtk-dwc3");
MODULE_LICENSE("GPL");
