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
#include <linux/usb/ch11.h>

#include "phy-rtk-usb.h"

#define RTK_USB3PHY_NAME "rtk-usb3phy"

struct reg_addr {
    void __iomem *REG_MDIO_CTL;
};

struct phy_data {
    int size;
    u8 *addr;
    u16 *data;

    u16 saved_trim_value;//=0xFFFF;
    u8 connected;//=0;
};

#define WAIT_VBUSY_RETRY	3
#define USB_ST_BUSY		BIT(7)

int utmi_wait_register(void __iomem *reg, u32 mask, u32 result);

static int rtk_usb_phy3_wait_vbusy(struct reg_addr *regAddr)
{
    return utmi_wait_register(regAddr->REG_MDIO_CTL, BIT(7), 0);
}

static u32 rtk_usb_phy_read(struct rtk_usb_phy_s *rtk_phy, char addr)
{
    volatile unsigned int regVal;
    struct reg_addr * regAddr = rtk_phy->reg_addr;

    regVal = (addr << 8);

    writel(regVal, regAddr->REG_MDIO_CTL);

    rtk_usb_phy3_wait_vbusy(regAddr);

    return readl(regAddr->REG_MDIO_CTL);
}

static int rtk_usb_phy_write(struct rtk_usb_phy_s *rtk_phy, char addr, u16 data)
{
    volatile unsigned int regVal;
    struct reg_addr * regAddr = rtk_phy->reg_addr;

    regVal = BIT(0)     |
             (addr << 8) |
             (data <<16);

    writel(regVal, regAddr->REG_MDIO_CTL);

    rtk_usb_phy3_wait_vbusy(regAddr);

    return 0;
}

static void rtk_usb_phy_shutdown(struct usb_phy *phy)
{
    /* Todo */
}

static int rtk_usb_phy_init(struct usb_phy *phy)
{
    struct rtk_usb_phy_s *rtk_phy = (struct rtk_usb_phy_s*) phy;
    int index = 0;
    struct phy_data *phy_data = rtk_phy->phy_data;
    u8 *addr = phy_data->addr;
    u16 *data = phy_data->data;

    dev_info(phy->dev, "%s Init RTK USB 3.0 PHY\n", __FILE__);

#if 1 // Move init data to device tree
    for (index = 0; index < phy_data->size; index++) {
        rtk_usb_phy_write(rtk_phy, *(addr + index), *(data + index));
    }
#else
    rtk_usb_phy_write(rtk_phy, 0x00, 0x4008);
    rtk_usb_phy_write(rtk_phy, 0x01, 0xA878);
    rtk_usb_phy_write(rtk_phy, 0x02, 0x6046);
    rtk_usb_phy_write(rtk_phy, 0x03, 0x2771);
    rtk_usb_phy_write(rtk_phy, 0x04, 0xB2F5);
    rtk_usb_phy_write(rtk_phy, 0x05, 0x2AD7);
    rtk_usb_phy_write(rtk_phy, 0x06, 0x0001);
    rtk_usb_phy_write(rtk_phy, 0x07, 0x3200);
    if (soc_is_rtk1195() && (realtek_rev() == RTK1195_REV_A)) {
        rtk_usb_phy_write(rtk_phy, 0x08, 0x3590);
        rtk_usb_phy_write(rtk_phy, 0x09, 0x325C);
        rtk_usb_phy_write(rtk_phy, 0x0A, 0xD643);
        rtk_usb_phy_write(rtk_phy, 0x0B, 0xE909);
    }
    else {	// REV_B
        rtk_usb_phy_write(rtk_phy, 0x08, 0x3592);
        rtk_usb_phy_write(rtk_phy, 0x09, 0x325C);
        rtk_usb_phy_write(rtk_phy, 0x0A, 0xD643);
        rtk_usb_phy_write(rtk_phy, 0x0B, 0xA909);
    }
    rtk_usb_phy_write(rtk_phy, 0x0C, 0xC008);
    rtk_usb_phy_write(rtk_phy, 0x0D, 0xFF28);
    rtk_usb_phy_write(rtk_phy, 0x0E, 0x2010);
    rtk_usb_phy_write(rtk_phy, 0x0F, 0x8000);
    rtk_usb_phy_write(rtk_phy, 0x10, 0x000C);
    rtk_usb_phy_write(rtk_phy, 0x11, 0x4C00);
    rtk_usb_phy_write(rtk_phy, 0x12, 0xFC00);
    rtk_usb_phy_write(rtk_phy, 0x13, 0x0C81);
    rtk_usb_phy_write(rtk_phy, 0x14, 0xDE01);
    rtk_usb_phy_write(rtk_phy, 0x15, 0x0000);
    rtk_usb_phy_write(rtk_phy, 0x16, 0x0000);
    rtk_usb_phy_write(rtk_phy, 0x17, 0x0000);
    rtk_usb_phy_write(rtk_phy, 0x18, 0x0000);
    if (soc_is_rtk1195() && (realtek_rev() == RTK1195_REV_A)) {
        rtk_usb_phy_write(rtk_phy, 0x19, 0x7004);
    }
    else {	// REV_B ...
        rtk_usb_phy_write(rtk_phy, 0x19, 0x3804);
    }
    rtk_usb_phy_write(rtk_phy, 0x1A, 0x1260);
    rtk_usb_phy_write(rtk_phy, 0x1B, 0xFF0C);
    rtk_usb_phy_write(rtk_phy, 0x1C, 0xCB1C);
    rtk_usb_phy_write(rtk_phy, 0x1D, 0xA03F);
    rtk_usb_phy_write(rtk_phy, 0x1E, 0xC200);
    rtk_usb_phy_write(rtk_phy, 0x1F, 0x9000);
    if (soc_is_rtk1195() && (realtek_rev() < RTK1195_REV_C)) {
        rtk_usb_phy_write(rtk_phy, 0x20, 0xD4FF);
    }
    else { //REV_C ...
        rtk_usb_phy_write(rtk_phy, 0x20, 0x94FF);

    }
    rtk_usb_phy_write(rtk_phy, 0x21, 0xAAFF);
    rtk_usb_phy_write(rtk_phy, 0x22, 0x0051);
    rtk_usb_phy_write(rtk_phy, 0x23, 0xDB60);
    rtk_usb_phy_write(rtk_phy, 0x24, 0x0800);
    rtk_usb_phy_write(rtk_phy, 0x25, 0x0000);
    rtk_usb_phy_write(rtk_phy, 0x26, 0x0004);
    rtk_usb_phy_write(rtk_phy, 0x27, 0x01D6);
    if (soc_is_rtk1195() && (realtek_rev() == RTK1195_REV_A)) {
        rtk_usb_phy_write(rtk_phy, 0x28, 0xF882);
    }
    else {	// REV_B ...
        //	rtk_usb_phy_write(0x28, 0xF842);
        rtk_usb_phy_write(rtk_phy, 0x28, 0xF840);
    }
    rtk_usb_phy_write(rtk_phy, 0x29, 0x3080);
    rtk_usb_phy_write(rtk_phy, 0x2A, 0x3083);
    rtk_usb_phy_write(rtk_phy, 0x2B, 0x2038);
    rtk_usb_phy_write(rtk_phy, 0x2C, 0xFFFF);
    rtk_usb_phy_write(rtk_phy, 0x2D, 0xFFFF);
    rtk_usb_phy_write(rtk_phy, 0x2E, 0x0000);
    rtk_usb_phy_write(rtk_phy, 0x2F, 0x0040);
    rtk_usb_phy_write(rtk_phy, 0x09, 0x325C);
    rtk_usb_phy_write(rtk_phy, 0x09, 0x305C);
    rtk_usb_phy_write(rtk_phy, 0x09, 0x325C);
#endif

    {
        int i=0;
        for (i=0; i<0x30; i++)
            dev_dbg(phy->dev, "[USB3_PHY], addr = 0x%02x, data =  %08x\n", i, rtk_usb_phy_read(rtk_phy, i));
    }

    dev_info(phy->dev, "%s Initialized RTK USB 3.0 PHY\n", __FILE__);
    return 0;
}

void rtk_usb3_phy_state(u32 state)
{
    struct device_node *node = NULL;
    struct device_node *prev_node = NULL;
    struct platform_device *pdev;
    struct rtk_usb_phy_s *rtk_phy = NULL;
    struct phy_data *phy_data;

    pr_info("%s: Not enable %s~", __FILE__, __func__);
    return;

    do {
        node = of_find_compatible_node(prev_node, NULL, "Realtek,rtk119x-usb3phy");
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

        //Note TODO Check if add to 1295 soc
        if (true)
            pr_err("%s %s TODO check if add to 1295!!!", __FILE__, __func__);
        else //if (soc_is_rtk1195() && (realtek_rev() < RTK1195_REV_C))
        {
            if ((state & USB_PORT_STAT_CONNECTION) && (phy_data->connected == 0)) {
                dev_info(rtk_phy->dev, "%s ------ USB3 connected\n", __func__);
                phy_data->connected = 1;
                rtk_usb_phy_write(rtk_phy, 0x1D, 0xA03E);
            } else if (!(state & USB_PORT_STAT_CONNECTION) && (phy_data->connected == 1)) {
                dev_info(rtk_phy->dev, "%s ------ USB3 disconnected\n", __func__);
                phy_data->connected = 0;
                phy_data->saved_trim_value = 0xFFFF;	// reset to init phase
                rtk_usb_phy_write(rtk_phy, 0x1D, 0xA03F);
            }
        }

        rtk_phy = NULL;
        prev_node = node;
    } while (prev_node != NULL);
}
EXPORT_SYMBOL(rtk_usb3_phy_state);

unsigned int grayToBinary(unsigned int num)
{
    unsigned int mask;
    for (mask = num >> 1; mask != 0; mask = mask >> 1)
    {
        num = num ^ mask;
    }
    return num;
}

void rtk_usb3_phy_trim(u16 state)
{
    struct device_node *node = NULL;
    struct device_node *prev_node = NULL;
    struct platform_device *pdev;
    struct rtk_usb_phy_s *rtk_phy = NULL;
    struct phy_data *phy_data;
    u16 tmp = 0;

    pr_info("%s: Not enable %s~", __FILE__, __func__);
    return;

    do {
        node = of_find_compatible_node(prev_node, NULL, "Realtek,rtk119x-usb3phy");
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
        switch (state) {
        case USB_SS_PORT_LS_U0:
            if ((phy_data->connected == 1) && (phy_data->saved_trim_value == 0xFFFF)) {
                phy_data->saved_trim_value = rtk_usb_phy_read(rtk_phy, 0x1f)>>27;
                dev_info(rtk_phy->dev, "%s ------ get usb3 phy: %04x\n", __func__, phy_data->saved_trim_value);
            }
            break;
        case USB_SS_PORT_LS_U3:
            if (phy_data->saved_trim_value != 0xFFFF) {
                tmp = rtk_usb_phy_read(rtk_phy, 0x19)>>16;
                tmp &= ~(0xfe00);
                rtk_usb_phy_write(rtk_phy, 0x19, tmp | grayToBinary(phy_data->saved_trim_value)<<11);
                dev_info(rtk_phy->dev, "%s ------ rewrite [0x19]:%04x\n", __func__, rtk_usb_phy_read(rtk_phy, 0x19)>>16);
            }
            break;
        default:
            break;
        }

        rtk_phy = NULL;
        prev_node = node;
    } while (prev_node != NULL);

}
EXPORT_SYMBOL(rtk_usb3_phy_trim);

static int rtk_usb3phy_probe(struct platform_device *pdev)
{
    struct rtk_usb_phy_s *rtk_usb_phy;
    struct device *dev = &pdev->dev;
    struct reg_addr *addr;
    struct phy_data *phy_data;
    int	ret = 0;

    rtk_usb_phy = devm_kzalloc(dev, sizeof(*rtk_usb_phy), GFP_KERNEL);
    if (!rtk_usb_phy)
        return -ENOMEM;

    rtk_usb_phy->dev			= &pdev->dev;
    rtk_usb_phy->phy.dev		= rtk_usb_phy->dev;
    rtk_usb_phy->phy.label		= RTK_USB3PHY_NAME;
    rtk_usb_phy->phy.init		= rtk_usb_phy_init;
    rtk_usb_phy->phy.shutdown	= rtk_usb_phy_shutdown;

    addr = devm_kzalloc(dev, sizeof(*addr), GFP_KERNEL);
    if (!addr)
        return -ENOMEM;
    addr->REG_MDIO_CTL = of_iomap(dev->of_node, 0);
    rtk_usb_phy->reg_addr = addr;
    dev_dbg(dev, "%s %s REG_MDIO_CTL=%p\n", __FILE__, __func__, addr->REG_MDIO_CTL);

    phy_data = devm_kzalloc(dev, sizeof(*phy_data), GFP_KERNEL);
    if (!phy_data)
        return -ENOMEM;
    phy_data->saved_trim_value = 0xFFFF;
    phy_data->connected = 0;

    if (dev->of_node) {
        ret = of_property_read_u32_index(dev->of_node, "phy_data_size", 0, &phy_data->size);
        if (ret)
            goto err;
        phy_data->addr = devm_kzalloc(dev, sizeof(u8)*phy_data->size, GFP_KERNEL);
        if (!phy_data->addr)
            return -ENOMEM;
        phy_data->data = devm_kzalloc(dev, sizeof(u16)*phy_data->size, GFP_KERNEL);
        if (!phy_data->data)
            return -ENOMEM;
        ret = of_property_read_u8_array(dev->of_node, "phy_data_addr", phy_data->addr, phy_data->size);
        if (ret)
            goto err;
        ret = of_property_read_u16_array(dev->of_node, "phy_data_revA", phy_data->data, phy_data->size);
        if (ret)
            goto err;
    }
    rtk_usb_phy->phy_data = phy_data;

    platform_set_drvdata(pdev, rtk_usb_phy);

    //ret = usb_add_phy(&rtk_usb_phy->phy, USB_PHY_TYPE_USB3);
    //if (ret)
    //	goto err;

    dev_info(&pdev->dev, "%s Probe RTK USB 3.0 PHY\n", __FILE__);
err:
    return ret;
}

static int rtk_usb3phy_remove(struct platform_device *pdev)
{
    //struct rtk_usb_phy_s *rtk_usb_phy = platform_get_drvdata(pdev);

    //usb_remove_phy(&rtk_usb_phy->phy);

    return 0;
}

#ifdef CONFIG_OF
static const struct of_device_id usbphy_rtk_dt_match[] = {
    { .compatible = "Realtek,rtk119x-usb3phy", },
    { .compatible = "Realtek,rtd129x-usb3phy", },
    {},
};
MODULE_DEVICE_TABLE(of, usbphy_rtk_dt_match);
#endif

static struct platform_driver rtk_usb3phy_driver = {
    .probe		= rtk_usb3phy_probe,
    .remove		= rtk_usb3phy_remove,
    .driver		= {
        .name	= RTK_USB3PHY_NAME,
        .owner	= THIS_MODULE,
        .of_match_table = of_match_ptr(usbphy_rtk_dt_match),
    },
};

module_platform_driver(rtk_usb3phy_driver);
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:" RTK_USB3PHY_NAME);
