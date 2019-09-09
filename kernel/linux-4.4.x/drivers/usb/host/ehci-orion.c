#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/mbus.h>
#include <linux/clk.h>
#include <linux/platform_data/usb-ehci-orion.h>
#include <linux/of.h>
#include <linux/phy/phy.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/usb.h>
#include <linux/usb/hcd.h>
#include <linux/io.h>
#include <linux/dma-mapping.h>

#include "ehci.h"

#define rdl(off)	readl_relaxed(hcd->regs + (off))
#define wrl(off, val)	writel_relaxed((val), hcd->regs + (off))

#define USB_CMD			0x140
#define   USB_CMD_RUN		BIT(0)
#define   USB_CMD_RESET		BIT(1)
#define USB_MODE		0x1a8
#define   USB_MODE_MASK		GENMASK(1, 0)
#define   USB_MODE_DEVICE	0x2
#define   USB_MODE_HOST		0x3
#define   USB_MODE_SDIS		BIT(4)
#define USB_CAUSE		0x310
#define USB_MASK		0x314
#define USB_WINDOW_CTRL(i)	(0x320 + ((i) << 4))
#define USB_WINDOW_BASE(i)	(0x324 + ((i) << 4))
#define USB_IPG			0x360
#define USB_PHY_PWR_CTRL	0x400
#define USB_PHY_TX_CTRL		0x420
#define USB_PHY_RX_CTRL		0x430
#define USB_PHY_IVREF_CTRL	0x440
#define USB_PHY_TST_GRP_CTRL	0x450

#if defined(MY_DEF_HERE)
#define USB_SBUSCFG		0x90
#define USB_SBUSCFG_BAWR_OFF	0x6
#define USB_SBUSCFG_BARD_OFF	0x3
#define USB_SBUSCFG_AHBBRST_OFF	0x0

#define USB_SBUSCFG_BAWR_ALIGN_128B	0x3
#define USB_SBUSCFG_BARD_ALIGN_128B	0x3
#define USB_SBUSCFG_AHBBRST_INCR16	0x3

#define USB_SBUSCFG_DEF_VAL	((USB_SBUSCFG_BAWR_ALIGN_128B << USB_SBUSCFG_BAWR_OFF) \
				| (USB_SBUSCFG_BARD_ALIGN_128B << USB_SBUSCFG_BARD_OFF) \
				| (USB_SBUSCFG_AHBBRST_INCR16 << USB_SBUSCFG_AHBBRST_OFF))
#endif  

#define DRIVER_DESC "EHCI orion driver"

#define hcd_to_orion_priv(h) ((struct orion_ehci_hcd *)hcd_to_ehci(h)->priv)

struct orion_ehci_hcd {
	struct clk *clk;
	struct phy *phy;
#if defined(MY_DEF_HERE)
	bool reset_on_resume;
#endif  
};

static const char hcd_name[] = "ehci-orion";

static struct hc_driver __read_mostly ehci_orion_hc_driver;

#if defined(MY_DEF_HERE)
static u32 usb_save[(USB_IPG - USB_CAUSE) +
		    (USB_PHY_TST_GRP_CTRL - USB_PHY_PWR_CTRL)];
#endif  

static void orion_usb_phy_v1_setup(struct usb_hcd *hcd)
{
	 
	wrl(USB_CAUSE, 0);
	wrl(USB_MASK, 0);

	wrl(USB_CMD, rdl(USB_CMD) | USB_CMD_RESET);
	while (rdl(USB_CMD) & USB_CMD_RESET);

	wrl(USB_IPG, (rdl(USB_IPG) & ~0x7f00) | 0xc00);

	wrl(USB_PHY_PWR_CTRL, (rdl(USB_PHY_PWR_CTRL) & ~0xc0)| 0x40);

	wrl(USB_PHY_TX_CTRL, (rdl(USB_PHY_TX_CTRL) & ~0x78) | 0x202040);

	wrl(USB_PHY_RX_CTRL, (rdl(USB_PHY_RX_CTRL) & ~0xc2003f0) | 0xc0000010);

	wrl(USB_PHY_IVREF_CTRL, (rdl(USB_PHY_IVREF_CTRL) & ~0x80003 ) | 0x32);

	wrl(USB_PHY_TST_GRP_CTRL, rdl(USB_PHY_TST_GRP_CTRL) & ~0x8000);

	wrl(USB_CMD, rdl(USB_CMD) & ~USB_CMD_RUN);
	wrl(USB_CMD, rdl(USB_CMD) | USB_CMD_RESET);
	while (rdl(USB_CMD) & USB_CMD_RESET);

	wrl(USB_MODE, USB_MODE_SDIS | USB_MODE_HOST);
}

static void
ehci_orion_conf_mbus_windows(struct usb_hcd *hcd,
			     const struct mbus_dram_target_info *dram)
{
	int i;

	for (i = 0; i < 4; i++) {
		wrl(USB_WINDOW_CTRL(i), 0);
		wrl(USB_WINDOW_BASE(i), 0);
	}

	for (i = 0; i < dram->num_cs; i++) {
		const struct mbus_dram_window *cs = dram->cs + i;

		wrl(USB_WINDOW_CTRL(i), ((cs->size - 1) & 0xffff0000) |
					(cs->mbus_attr << 8) |
					(dram->mbus_dram_target_id << 4) | 1);
		wrl(USB_WINDOW_BASE(i), cs->base);
	}
}

#if defined(MY_DEF_HERE)
static int ehci_orion_drv_reset(struct usb_hcd *hcd)
{
	struct device *dev = hcd->self.controller;
	int retval;

	retval = ehci_setup(hcd);
	if (retval)
		dev_err(dev, "ehci_setup failed %d\n", retval);

	if (of_device_is_compatible(dev->of_node, "marvell,armada-3700-ehci"))
		wrl(USB_SBUSCFG, USB_SBUSCFG_DEF_VAL);

	return retval;
}
#endif  

static const struct ehci_driver_overrides orion_overrides __initconst = {
	.extra_priv_size =	sizeof(struct orion_ehci_hcd),
#if defined(MY_DEF_HERE)
	.reset = ehci_orion_drv_reset,
#endif  
};

static int ehci_orion_drv_probe(struct platform_device *pdev)
{
	struct orion_ehci_data *pd = dev_get_platdata(&pdev->dev);
	const struct mbus_dram_target_info *dram;
	struct resource *res;
	struct usb_hcd *hcd;
	struct ehci_hcd *ehci;
	void __iomem *regs;
	int irq, err;
	enum orion_ehci_phy_ver phy_version;
	struct orion_ehci_hcd *priv;
#if defined (MY_ABC_HERE)
	struct device_node	*node = pdev->dev.of_node;
	u32 vbus_gpio_pin = 0;
#endif  

	if (usb_disabled())
		return -ENODEV;

	pr_debug("Initializing Orion-SoC USB Host Controller\n");

	irq = platform_get_irq(pdev, 0);
	if (irq <= 0) {
		dev_err(&pdev->dev,
			"Found HC with no IRQ. Check %s setup!\n",
			dev_name(&pdev->dev));
		err = -ENODEV;
		goto err;
	}

	err = dma_coerce_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
	if (err)
		goto err;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	regs = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(regs)) {
		err = PTR_ERR(regs);
		goto err;
	}

	hcd = usb_create_hcd(&ehci_orion_hc_driver,
			&pdev->dev, dev_name(&pdev->dev));
	if (!hcd) {
		err = -ENOMEM;
		goto err;
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
#endif  

	hcd->rsrc_start = res->start;
	hcd->rsrc_len = resource_size(res);
	hcd->regs = regs;

	ehci = hcd_to_ehci(hcd);
	ehci->caps = hcd->regs + 0x100;
	hcd->has_tt = 1;

	priv = hcd_to_orion_priv(hcd);
	 
	priv->clk = devm_clk_get(&pdev->dev, NULL);
	if (!IS_ERR(priv->clk))
		clk_prepare_enable(priv->clk);

#if defined(MY_DEF_HERE)
	if (of_property_read_bool(pdev->dev.of_node, "needs-reset-on-resume"))
		priv->reset_on_resume = true;
	else
		priv->reset_on_resume = false;

#endif  
	priv->phy = devm_phy_optional_get(&pdev->dev, "usb");
	if (IS_ERR(priv->phy)) {
		err = PTR_ERR(priv->phy);
		if (err != -ENOSYS)
			goto err_phy_get;
	} else {
		err = phy_init(priv->phy);
		if (err)
			goto err_phy_init;

		err = phy_power_on(priv->phy);
		if (err)
			goto err_phy_power_on;
	}

	dram = mv_mbus_dram_info();
	if (dram)
		ehci_orion_conf_mbus_windows(hcd, dram);

	if (pdev->dev.of_node)
		phy_version = EHCI_PHY_NA;
	else
		phy_version = pd->phy_version;

	switch (phy_version) {
	case EHCI_PHY_NA:	 
		break;
	case EHCI_PHY_ORION:
		orion_usb_phy_v1_setup(hcd);
		break;
	case EHCI_PHY_DD:
	case EHCI_PHY_KW:
	default:
		dev_warn(&pdev->dev, "USB phy version isn't supported.\n");
	}

#if defined (MY_ABC_HERE)
	dev_info(&pdev->dev, "USB2 Vbus gpio %d\n", hcd->vbus_gpio_pin);
	dev_info(&pdev->dev, "power control %s\n", hcd->power_control_support ?
			"enabled" : "disabled");
#endif  
	err = usb_add_hcd(hcd, irq, IRQF_SHARED);
	if (err)
		goto err_add_hcd;

	device_wakeup_enable(hcd->self.controller);
	return 0;

err_add_hcd:
	if (!IS_ERR(priv->phy))
		phy_power_off(priv->phy);
err_phy_power_on:
	if (!IS_ERR(priv->phy))
		phy_exit(priv->phy);
err_phy_init:
err_phy_get:
	if (!IS_ERR(priv->clk))
		clk_disable_unprepare(priv->clk);
	usb_put_hcd(hcd);
err:
	dev_err(&pdev->dev, "init %s fail, %d\n",
		dev_name(&pdev->dev), err);

	return err;
}

static int ehci_orion_drv_remove(struct platform_device *pdev)
{
	struct usb_hcd *hcd = platform_get_drvdata(pdev);
	struct orion_ehci_hcd *priv = hcd_to_orion_priv(hcd);

	usb_remove_hcd(hcd);

	if (!IS_ERR(priv->phy)) {
		phy_power_off(priv->phy);
		phy_exit(priv->phy);
	}

	if (!IS_ERR(priv->clk))
		clk_disable_unprepare(priv->clk);

	usb_put_hcd(hcd);

	return 0;
}

#if defined(MY_DEF_HERE)
static int ehci_orion_drv_suspend(struct platform_device *pdev,
				  pm_message_t state)
{
	struct usb_hcd *hcd = platform_get_drvdata(pdev);
#if defined(MY_DEF_HERE)
	bool do_wakeup = device_may_wakeup(&pdev->dev);
	int addr, i, rc;
#else  

	int addr, i;
#endif  

	for (addr = USB_CAUSE, i = 0; addr <= USB_IPG; addr += 0x4, i++)
		usb_save[i] = readl_relaxed(hcd->regs + addr);

	for (addr = USB_PHY_PWR_CTRL; addr <= USB_PHY_TST_GRP_CTRL;
	     addr += 0x4, i++)
		usb_save[i] = readl_relaxed(hcd->regs + addr);

#if defined(MY_DEF_HERE)
	rc = ehci_suspend(hcd, do_wakeup);
	if (rc)
		return rc;

	phy_power_off(hcd->phy);
	phy_exit(hcd->phy);

#endif  
	return 0;
}

#define MV_USB_CORE_CMD_RESET_BIT           1
#define MV_USB_CORE_CMD_RESET_MASK          (1 << MV_USB_CORE_CMD_RESET_BIT)
#define MV_USB_CORE_MODE_OFFSET                 0
#define MV_USB_CORE_MODE_MASK                   (3 << MV_USB_CORE_MODE_OFFSET)
#define MV_USB_CORE_MODE_HOST                   (3 << MV_USB_CORE_MODE_OFFSET)
#define MV_USB_CORE_MODE_DEVICE                 (2 << MV_USB_CORE_MODE_OFFSET)
#define MV_USB_CORE_CMD_RUN_BIT             0
#define MV_USB_CORE_CMD_RUN_MASK            (1 << MV_USB_CORE_CMD_RUN_BIT)

static int ehci_orion_drv_resume(struct platform_device *pdev)
{
	struct usb_hcd *hcd = platform_get_drvdata(pdev);
#if defined(MY_DEF_HERE)
	struct orion_ehci_hcd *priv = hcd_to_orion_priv(hcd);
	int addr, regVal, i, rc;

	rc = phy_init(hcd->phy);
	if (rc)
		return rc;

	rc = phy_power_on(hcd->phy);
	if (rc) {
		phy_exit(hcd->phy);
		return rc;
	}
#else  
	int addr, regVal, i;
#endif  

	for (addr = USB_CAUSE, i = 0; addr <= USB_IPG; addr += 0x4, i++)
		writel_relaxed(usb_save[i], hcd->regs + addr);

	for (addr = USB_PHY_PWR_CTRL; addr <= USB_PHY_TST_GRP_CTRL;
	     addr += 0x4, i++)
		writel_relaxed(usb_save[i], hcd->regs + addr);

	writel_relaxed(0, hcd->regs + 0x310);
	writel_relaxed(0, hcd->regs + 0x314);

	regVal = readl_relaxed(hcd->regs + 0x140);
	writel_relaxed(regVal | MV_USB_CORE_CMD_RESET_MASK, hcd->regs + 0x140);
	while (readl_relaxed(hcd->regs + 0x140) & MV_USB_CORE_CMD_RESET_MASK)
		;

	regVal = readl_relaxed(hcd->regs + 0x140);
	regVal &= ~MV_USB_CORE_CMD_RUN_MASK;
	writel_relaxed(regVal, hcd->regs + 0x140);

	regVal = readl_relaxed(hcd->regs + 0x140);
	regVal |= MV_USB_CORE_CMD_RESET_MASK;
	writel_relaxed(regVal, hcd->regs + 0x140);

	do {
		regVal = readl_relaxed(hcd->regs + 0x140);
	} while (regVal & MV_USB_CORE_CMD_RESET_MASK);

	regVal = MV_USB_CORE_MODE_HOST;
	writel_relaxed(regVal, hcd->regs + 0x1A8);

#if defined(MY_DEF_HERE)
	ehci_resume(hcd, priv->reset_on_resume);

#endif  
	return 0;
}

static void ehci_orion_drv_shutdown(struct platform_device *pdev)
{
	struct usb_hcd *hcd = platform_get_drvdata(pdev);
	static void __iomem *usb_pwr_ctrl_base;
	struct clk *clk;

	usb_hcd_platform_shutdown(pdev);

	usb_pwr_ctrl_base = hcd->regs + USB_PHY_PWR_CTRL;
	BUG_ON(!usb_pwr_ctrl_base);
	 
	writel((readl(usb_pwr_ctrl_base) & ~(BIT(0) | BIT(1))),
	       usb_pwr_ctrl_base);

	clk = clk_get(&pdev->dev, NULL);
	if (!IS_ERR(clk)) {
		clk_disable_unprepare(clk);
		clk_put(clk);
	}

}
#endif  

static const struct of_device_id ehci_orion_dt_ids[] = {
	{ .compatible = "marvell,orion-ehci", },
#if defined(MY_DEF_HERE)
	{ .compatible = "marvell,armada-3700-ehci", },
#endif  
	{},
};
MODULE_DEVICE_TABLE(of, ehci_orion_dt_ids);

static struct platform_driver ehci_orion_driver = {
	.probe		= ehci_orion_drv_probe,
	.remove		= ehci_orion_drv_remove,
#if defined(MY_DEF_HERE)
#ifdef CONFIG_PM
	.suspend        = ehci_orion_drv_suspend,
	.resume         = ehci_orion_drv_resume,
#endif
	.shutdown	= ehci_orion_drv_shutdown,
#else  
	.shutdown	= usb_hcd_platform_shutdown,
#endif  
	.driver = {
		.name	= "orion-ehci",
		.of_match_table = ehci_orion_dt_ids,
	},
};

static int __init ehci_orion_init(void)
{
	if (usb_disabled())
		return -ENODEV;

	pr_info("%s: " DRIVER_DESC "\n", hcd_name);

	ehci_init_driver(&ehci_orion_hc_driver, &orion_overrides);
	return platform_driver_register(&ehci_orion_driver);
}
module_init(ehci_orion_init);

static void __exit ehci_orion_cleanup(void)
{
	platform_driver_unregister(&ehci_orion_driver);
}
module_exit(ehci_orion_cleanup);

MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_ALIAS("platform:orion-ehci");
MODULE_AUTHOR("Tzachi Perelstein");
MODULE_LICENSE("GPL v2");
