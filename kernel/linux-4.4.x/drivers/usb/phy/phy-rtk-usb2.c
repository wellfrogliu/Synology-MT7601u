#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/usb/otg.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/of_address.h>

#include "phy-rtk-usb.h"

#define RTK_USB2PHY_NAME "rtk-usb2phy"

#define WAIT_VBUSY_RETRY	3

#define OFFEST_PHY_READ	0x20

#ifdef MY_DEF_HERE
#define RX_SENSITIVITY_MODE_ADDR		0xF7
#define RX_SENSITIVITY_MODE_OLD_MODE	0x02
#endif /* MY_DEF_HERE */

#define USB_ST_BUSY		BIT(23)
#define phy_write(addr, val)	do { smp_wmb(); __raw_writel(val, addr); } while(0)
#define phy_read(addr)			__raw_readl(addr)

struct reg_addr {
    void __iomem *REG_WRAP_VStatusOut2;
    void __iomem *REG_GUSB2PHYACC0;
};

struct phy_data {
    int page0_size;
    struct rtk_usb_phy_data_s *page0;
    int page1_size;
    struct rtk_usb_phy_data_s *page1;

    int pre_state;
};

int utmi_wait_register(void __iomem *reg, u32 mask, u32 result);

static char rtk_usb_phy_read(struct rtk_usb_phy_s *rtk_phy, char addr)
{
    volatile unsigned int regVal;
    struct reg_addr *regAddr = rtk_phy->reg_addr;
    void __iomem *REG_GUSB2PHYACC0 = regAddr->REG_GUSB2PHYACC0;

    // polling until VBusy == 0
    utmi_wait_register(REG_GUSB2PHYACC0, USB_ST_BUSY, 0);

    // VCtrl = low nibble of addr, VLoadM = 1
    regVal = BIT(25) | 	// Port num
             ((addr & 0x0f) << 8);	// vcontrol
    phy_write(REG_GUSB2PHYACC0, regVal);
    utmi_wait_register(REG_GUSB2PHYACC0, USB_ST_BUSY, 0);

    // VCtrl = high nibble of addr, VLoadM = 1
    regVal = BIT(25) | 	// Port num
             ((addr & 0xf0) << 4);	// vcontrol
    phy_write(REG_GUSB2PHYACC0, regVal);
    utmi_wait_register(REG_GUSB2PHYACC0, USB_ST_BUSY, 0);

    smp_rmb();
    regVal = phy_read(REG_GUSB2PHYACC0);

    return (char) (regVal & 0xff);
}
static int rtk_usb_phy_write(struct rtk_usb_phy_s *rtk_phy, char addr, char data)
{
    volatile unsigned int regVal;
    struct reg_addr *regAddr = rtk_phy->reg_addr;
    void __iomem *REG_WRAP_VStatusOut2 = regAddr->REG_WRAP_VStatusOut2;
    void __iomem *REG_GUSB2PHYACC0 = regAddr->REG_GUSB2PHYACC0;
    int shift_bits = rtk_phy->portN*8;

    //write data to VStatusOut2 (data output to phy)
    phy_write(REG_WRAP_VStatusOut2, (u32)data<<shift_bits);
    utmi_wait_register(REG_GUSB2PHYACC0, USB_ST_BUSY, 0);

    // VCtrl = low nibble of addr, VLoadM = 1
    regVal = BIT(25) |
             ((addr & 0x0f) << 8);

    phy_write(REG_GUSB2PHYACC0, regVal);
    utmi_wait_register(REG_GUSB2PHYACC0, USB_ST_BUSY, 0);

    // VCtrl = high nibble of addr, VLoadM = 1
    regVal = BIT(25) |
             ((addr & 0xf0) << 4);

    phy_write(REG_GUSB2PHYACC0, regVal);
    utmi_wait_register(REG_GUSB2PHYACC0, USB_ST_BUSY, 0);

    return 0;
}

static int rtk_usb_phy_set_page(struct rtk_usb_phy_s *rtk_phy, int page)
{
    return rtk_usb_phy_write(rtk_phy, 0xf4, page == 0 ? 0x9b : 0xbb);
}

static void rtk_usb2_phy_shutdown(struct usb_phy *phy)
{
    /* Todo */
}

static int rtk_usb2_phy_init(struct usb_phy *phy)
{
    int i;
    struct rtk_usb_phy_s *rtk_phy = (struct rtk_usb_phy_s*) phy;
    struct phy_data *phy_data = rtk_phy->phy_data;
    struct rtk_usb_phy_data_s *phy_page0_default_setting = phy_data->page0;
    struct rtk_usb_phy_data_s *phy_page1_default_setting = phy_data->page1;
#ifdef MY_DEF_HERE
    bool rx_sensitivity_mode_is_set = false;
#endif /* MY_DEF_HERE */

    dev_info(phy->dev, "%s Init RTK USB 2.0 PHY\n", __FILE__);

    /* Set page 0 */
    rtk_usb_phy_set_page(rtk_phy, 0);

    for (i=0; i<phy_data->page0_size; i++) {
        if (rtk_usb_phy_write(rtk_phy, (phy_page0_default_setting + i)->addr, (phy_page0_default_setting + i)->data)) {
            dev_err(phy->dev, "[%s:%d], page0 Error : addr = 0x%x, value = 0x%x\n",
                    __FUNCTION__, __LINE__,
                    (phy_page0_default_setting + i)->addr,
                    (phy_page0_default_setting + i)->data);
            return -1;
        } else {
            dev_dbg(phy->dev, "[%s:%d], page0 Good : addr = 0x%x, value = 0x%x\n",
                    __FUNCTION__, __LINE__,
                    (phy_page0_default_setting + i)->addr,
                    rtk_usb_phy_read(rtk_phy, (phy_page0_default_setting + i)->addr - OFFEST_PHY_READ));

#ifdef MY_DEF_HERE
            if((phy_page0_default_setting + i)->addr == RX_SENSITIVITY_MODE_ADDR) {
                rx_sensitivity_mode_is_set = true;
            }
#endif /* MY_DEF_HERE */
        }
    }

#ifdef MY_DEF_HERE
    if(!rx_sensitivity_mode_is_set) {
        if (rtk_usb_phy_write(rtk_phy, RX_SENSITIVITY_MODE_ADDR, RX_SENSITIVITY_MODE_OLD_MODE)) {
            dev_err(phy->dev, "[%s:%d], page0 Error : addr = 0x%x, value = 0x%x\n",
                    __FUNCTION__, __LINE__,
                    RX_SENSITIVITY_MODE_ADDR,
                    RX_SENSITIVITY_MODE_OLD_MODE);
            return -1;
        } else {
            dev_dbg(phy->dev, "[%s:%d], page0 Good : addr = 0x%x, value = 0x%x\n",
                    __FUNCTION__, __LINE__,
                    RX_SENSITIVITY_MODE_ADDR,
                    rtk_usb_phy_read(rtk_phy, RX_SENSITIVITY_MODE_ADDR - OFFEST_PHY_READ));
        }
    }
#endif /* MY_DEF_HERE */

    /* Set page 1 */
    rtk_usb_phy_set_page(rtk_phy, 1);

    for (i=0; i<phy_data->page1_size; i++) {
        if (rtk_usb_phy_write(rtk_phy, (phy_page1_default_setting + i)->addr, (phy_page1_default_setting + i)->data)) {
            dev_err(phy->dev, "[%s:%d], page1 Error : addr = 0x%x, value = 0x%x\n",
                    __FUNCTION__, __LINE__,
                    (phy_page1_default_setting + i)->addr,
                    (phy_page1_default_setting + i)->data);
            return -1;
        } else {
            dev_dbg(phy->dev, "[%s:%d], page1 Good : addr = 0x%x, value = 0x%x\n",
                    __FUNCTION__, __LINE__,
                    (phy_page1_default_setting + i)->addr,
                    rtk_usb_phy_read(rtk_phy, (phy_page1_default_setting + i)->addr - OFFEST_PHY_READ));
        }
    }

    dev_info(phy->dev, "%s Initialized RTK USB 2.0 PHY\n", __FILE__);
    return 0;
}

void rtk_usb2_phy_state(u32 state)
{
    struct device_node *node = NULL;
    struct device_node *prev_node = NULL;
    struct platform_device *pdev;
    struct rtk_usb_phy_s *rtk_phy = NULL;
    struct phy_data *phy_data;

    pr_info("%s: Not enable %s~", __FILE__, __func__);
    return;

    do {
        node = of_find_compatible_node(prev_node, NULL, "Realtek,rtk119x-usb2phy");
        if (node == NULL)
            break;
        pdev = of_find_device_by_node(node);
        if (pdev != NULL)
            rtk_phy = platform_get_drvdata(pdev);

        if (rtk_phy == NULL) {
            pr_err("%s %s ERROR! NO this device", __FILE__, __func__);
            break;
        }

        phy_data = rtk_phy->phy_data;
        if (state == 1) {
            dev_err(rtk_phy->dev, "%s prepare to U0\n", __func__);
            rtk_usb_phy_write(rtk_phy, 0xF0, 0xbc);
            rtk_usb_phy_write(rtk_phy, 0xF2, 0xBE);
            phy_data->pre_state = 1;
        } else if (phy_data->pre_state == 1) {
            dev_err(rtk_phy->dev, "%s U0\n",__func__);
            rtk_usb_phy_write(rtk_phy, 0xF2, 0x00);
            rtk_usb_phy_write(rtk_phy, 0xF0, 0xfc);
            phy_data->pre_state = 0;
        }

        rtk_phy = NULL;
        prev_node = node;
    } while (prev_node != NULL);
}
EXPORT_SYMBOL(rtk_usb2_phy_state);

static int rtk_usb2phy_probe(struct platform_device *pdev)
{
    struct rtk_usb_phy_s *rtk_usb_phy;
    struct device *dev = &pdev->dev;
    struct reg_addr *addr;
    int ret = 0;
    struct phy_data *phy_data;
    int phy_data_page0_size, phy_data_page1_size;
    rtk_usb_phy = devm_kzalloc(dev, sizeof(*rtk_usb_phy), GFP_KERNEL);
    if (!rtk_usb_phy)
        return -ENOMEM;

    rtk_usb_phy->dev			= &pdev->dev;
    rtk_usb_phy->phy.dev		= rtk_usb_phy->dev;
    rtk_usb_phy->phy.label		= RTK_USB2PHY_NAME;
    rtk_usb_phy->phy.init		= rtk_usb2_phy_init;
    rtk_usb_phy->phy.shutdown	= rtk_usb2_phy_shutdown;

    if (dev->of_node) {
        ret = of_property_read_u32_index(dev->of_node, "portN", 0, &rtk_usb_phy->portN);
        if (ret) goto err;
        dev_dbg(dev, "%s %s portN=%d\n", __FILE__, __func__, rtk_usb_phy->portN);
        addr = devm_kzalloc(dev, sizeof(*addr), GFP_KERNEL);
        if (!addr) return -ENOMEM;

        addr->REG_GUSB2PHYACC0     = of_iomap(dev->of_node, 0);
        addr->REG_WRAP_VStatusOut2 = of_iomap(dev->of_node, 1);
        rtk_usb_phy->reg_addr = addr;

        dev_dbg(dev, "%s %s REG_WRAP_VStatusOut2=%p\n", __FILE__, __func__, addr->REG_WRAP_VStatusOut2);
        dev_dbg(dev, "%s %s REG_GUSB2PHYACC0=%p\n", __FILE__, __func__, addr->REG_GUSB2PHYACC0);
        ret = of_property_read_u32_index(dev->of_node, "phy_data_page0_size", 0, &phy_data_page0_size);
        if (ret) goto err;
        ret = of_property_read_u32_index(dev->of_node, "phy_data_page1_size", 0, &phy_data_page1_size);
        if (ret) goto err;

        dev_dbg(dev, "%s %s phy_data_page0_size=%d, phy_data_page1_size=%d\n", __FILE__, __func__,
                phy_data_page0_size, phy_data_page1_size);
    }

    phy_data = devm_kzalloc(dev, sizeof(*phy_data), GFP_KERNEL);
    if (!phy_data)
        return -ENOMEM;
    phy_data->page0_size = phy_data_page0_size;
    phy_data->page0 = devm_kzalloc(dev, sizeof(struct rtk_usb_phy_data_s)*phy_data_page0_size, GFP_KERNEL);
    if (!phy_data->page0)
        return -ENOMEM;
    phy_data->page1_size = phy_data_page1_size;
    phy_data->page1 = devm_kzalloc(dev, sizeof(struct rtk_usb_phy_data_s)*phy_data_page1_size, GFP_KERNEL);
    if (!phy_data->page1)
        return -ENOMEM;
    phy_data->pre_state = 0;

    if (dev->of_node) {
        char tmp_addr[phy_data_page0_size];
        char tmp_data[phy_data_page0_size];
        int i = 0;
        ret = of_property_read_u8_array(dev->of_node, "phy_data_page0_addr", tmp_addr, phy_data_page0_size);
        if (ret) goto err;
        ret = of_property_read_u8_array(dev->of_node, "phy_data_page0_data", tmp_data, phy_data_page0_size);
        if (ret) goto err;
        for (i = 0; i < phy_data_page0_size; i++) {
            struct rtk_usb_phy_data_s *phy_data_page0 = (phy_data->page0 + i);
            phy_data_page0->addr = tmp_addr[i];
            phy_data_page0->data = tmp_data[i];
        }
        ret = of_property_read_u8_array(dev->of_node, "phy_data_page1_addr", tmp_addr, phy_data_page1_size);
        if (ret) goto err;
        ret = of_property_read_u8_array(dev->of_node, "phy_data_page1_data", tmp_data, phy_data_page1_size);
        if (ret) goto err;
        for (i = 0; i < phy_data_page1_size; i++) {
            struct rtk_usb_phy_data_s *phy_data_page1 = (phy_data->page1 + i);
            phy_data_page1->addr = tmp_addr[i];
            phy_data_page1->data = tmp_data[i];
        }
        rtk_usb_phy->phy_data = phy_data;
    }

    platform_set_drvdata(pdev, rtk_usb_phy);

    //ret = usb_add_phy(&rtk_usb_phy->phy, USB_PHY_TYPE_USB2);
    //if (ret)
    //	goto err;

    dev_info(&pdev->dev, "%s Probe RTK USB 2.0 PHY\n", __FILE__);
err:
    return ret;
}

static int rtk_usb2phy_remove(struct platform_device *pdev)
{
    //struct rtk_usb_phy_s *rtk_usb_phy = platform_get_drvdata(pdev);

    //usb_remove_phy(&rtk_usb_phy->phy);

    return 0;
}

#ifdef CONFIG_OF
static const struct of_device_id usbphy_rtk_dt_match[] = {
    { .compatible = "Realtek,rtk119x-usb2phy", },
    { .compatible = "Realtek,rtd129x-usb2phy", },
    {},
};
MODULE_DEVICE_TABLE(of, usbphy_rtk_dt_match);
#endif

static struct platform_driver rtk_usb2phy_driver = {
    .probe		= rtk_usb2phy_probe,
    .remove		= rtk_usb2phy_remove,
    .driver		= {
        .name	= RTK_USB2PHY_NAME,
        .owner	= THIS_MODULE,
        .of_match_table = of_match_ptr(usbphy_rtk_dt_match),
    },
};

module_platform_driver(rtk_usb2phy_driver);
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:" RTK_USB2PHY_NAME);
