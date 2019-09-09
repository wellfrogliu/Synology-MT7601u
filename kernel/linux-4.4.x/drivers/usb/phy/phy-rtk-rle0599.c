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

#define RTK_USB_RLE0599_PHY_NAME "rtk-usb-phy-rle0599"

struct reg_addr {
    void __iomem *REG_WRAP_VStatusOut2;
    void __iomem *REG_EHCI_INSNREG05;
    void __iomem *REG_EFUSE71cc;
};

struct phy_data {
    int page0_size;
    struct rtk_usb_phy_data_s *page0;
    int page1_size;
    struct rtk_usb_phy_data_s *page1;
};

#define WAIT_VBUSY_RETRY	3

#define OFFEST_PHY_READ 0x20

#ifdef MY_DEF_HERE
#define RX_SENSITIVITY_MODE_ADDR		0xF7
#define RX_SENSITIVITY_MODE_OLD_MODE	0x02
#endif /* MY_DEF_HERE */

#define USB_ST_BUSY		BIT(17)

static DEFINE_SPINLOCK(rtk_phy_lock);

#define phy_read(addr)			__raw_readl(addr)
#define phy_write(addr, val)	do { smp_wmb(); __raw_writel(val, addr); } while(0)
#define PHY_IO_TIMEOUT_MSEC		(50)

char  efuse_mapping[16] = {

    0xa1, 0x85, 0x89, 0x8d, 0x91, 0x95, 0x99, 0x9d, 0xa1, 0xa5, 0xa9, 0xad, 0xb1, 0xb5, 0xb9, 0xbd,

};

int utmi_wait_register(void __iomem *reg, u32 mask, u32 result)
{
    unsigned long timeout = jiffies + msecs_to_jiffies(PHY_IO_TIMEOUT_MSEC);
    while (time_before(jiffies, timeout)) {
        smp_rmb();
        if ((phy_read(reg) & mask) == result)
            return 0;
        udelay(100);
    }
    pr_err("\033[0;32;31m can't program USB phy \033[m\n");
    return -1;
}
EXPORT_SYMBOL_GPL(utmi_wait_register);

static char rtk_usb_phy_read(struct rtk_usb_phy_s *rtk_phy, char addr)
{
    volatile unsigned int regVal;
    struct reg_addr *regAddr = rtk_phy->reg_addr;
    void __iomem *REG_EHCI_INSNREG05 = regAddr->REG_EHCI_INSNREG05;

    utmi_wait_register(REG_EHCI_INSNREG05, USB_ST_BUSY, 0);

    // VCtrl = low nibble of addr, VLoadM = 1
    regVal = (1 << 13) | 	// Port num
             (1 << 12) |	// vload
             ((addr & 0x0f) << 8);	// vcontrol
    phy_write(REG_EHCI_INSNREG05, regVal);
    utmi_wait_register(REG_EHCI_INSNREG05, USB_ST_BUSY, 0);

    // VCtrl = low nibble of addr, VLoadM = 0
    regVal &= ~(1 << 12);
    phy_write(REG_EHCI_INSNREG05, regVal);
    utmi_wait_register(REG_EHCI_INSNREG05, USB_ST_BUSY, 0);

    // VCtrl = high nibble of addr, VLoadM = 1
    regVal = (1 << 13) | 	// Port num
             (1 << 12) |	// vload
             ((addr & 0xf0) << 4);	// vcontrol
    phy_write(REG_EHCI_INSNREG05, regVal);
    utmi_wait_register(REG_EHCI_INSNREG05, USB_ST_BUSY, 0);

    // VCtrl = high nibble of addr, VLoadM = 0
    regVal &= ~(1 << 12);
    phy_write(REG_EHCI_INSNREG05, regVal);
    utmi_wait_register(REG_EHCI_INSNREG05, USB_ST_BUSY, 0);

    smp_rmb();
    regVal = phy_read(REG_EHCI_INSNREG05);

    return (char) (regVal & 0xff);
}

static int rtk_usb_phy_write(struct rtk_usb_phy_s *rtk_phy, char addr, char data)
{
    volatile unsigned int regVal;
    struct reg_addr *regAddr = rtk_phy->reg_addr;
    void __iomem *REG_WRAP_VStatusOut2 = regAddr->REG_WRAP_VStatusOut2;
    void __iomem *REG_EHCI_INSNREG05 = regAddr->REG_EHCI_INSNREG05;
    int shift_bits = rtk_phy->portN*8;

    //printk("[%s:%d], addr = 0x%x, data = 0x%x\n", __FUNCTION__, __LINE__, addr, data);

    //write data to VStatusOut2 (data output to phy)
    phy_write(REG_WRAP_VStatusOut2, (u32) data<<shift_bits);
    utmi_wait_register(REG_EHCI_INSNREG05, USB_ST_BUSY, 0);

    // VCtrl = low nibble of addr, VLoadM = 1
    regVal = (1 << 13) | 	// Port num
             (1 << 12) |	// vload
             ((addr & 0x0f) << 8);	// vcontrol
    phy_write(REG_EHCI_INSNREG05, regVal);
    utmi_wait_register(REG_EHCI_INSNREG05, USB_ST_BUSY, 0);

    // VCtrl = low nibble of addr, VLoadM = 0
    regVal &= ~(1 << 12);
    phy_write(REG_EHCI_INSNREG05, regVal);
    utmi_wait_register(REG_EHCI_INSNREG05, USB_ST_BUSY, 0);

    // VCtrl = high nibble of addr, VLoadM = 1
    regVal = (1 << 13) | 	// Port num
             (1 << 12) |	// vload
             ((addr & 0xf0) << 4);	// vcontrol
    phy_write(REG_EHCI_INSNREG05, regVal);
    utmi_wait_register(REG_EHCI_INSNREG05, USB_ST_BUSY, 0);

    // VCtrl = high nibble of addr, VLoadM = 0
    regVal &= ~(1 << 12);
    phy_write(REG_EHCI_INSNREG05, regVal);
    utmi_wait_register(REG_EHCI_INSNREG05, USB_ST_BUSY, 0);

    return 0;
}

static int rtk_usb_phy_set_page(struct rtk_usb_phy_s *rtk_phy, int page)
{
    return rtk_usb_phy_write(rtk_phy, 0xf4, page == 0 ? 0x9b : 0xbb);
}

static int initialized=0;
void rtk_usb_phy_shutdown(struct usb_phy *phy)
{
    /* Todo */
    initialized = 0;
}

int rtk_usb_phy_init(struct usb_phy* phy)
{
    int i;
    int ret=0;
    unsigned long flags;

    struct rtk_usb_phy_s *rtk_phy = (struct rtk_usb_phy_s*) phy;
    struct phy_data *phy_data = rtk_phy->phy_data;
    struct rtk_usb_phy_data_s *phy_page0_default_setting = phy_data->page0;
    struct rtk_usb_phy_data_s *phy_page1_default_setting = phy_data->page1;
#ifdef MY_DEF_HERE
    bool rx_sensitivity_mode_is_set = false;
#endif /* MY_DEF_HERE */

    spin_lock_irqsave(&rtk_phy_lock, flags);

    if (initialized) goto out;

    dev_info(phy->dev, "Init RTK USB phy-rle0599\n");

    /* Set page 0 */
    //printk("[%s:%d], Set page 0\n", __FUNCTION__, __LINE__);
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
        /* TODO check efuse_mapping
			if (phy_page0_default_setting[i].addr == 0xe0) {
				volatile unsigned int jj = 0;
				jj = (phy_read(REG_EFUSE71cc) >> 6) & 0xf ;
				if (rtk_usb_phy_write(phy_page0_default_setting[i].addr, efuse_mapping[jj])){
					dev_err(phy->dev, "[%s:%d], Error : addr = 0x%x, value = 0x%x\n",
						__FUNCTION__, __LINE__,
						phy_page0_default_setting[i].addr,
						efuse_mapping[jj]);
						return -1;
				}
				dev_info(phy->dev, "[%s:%d], Good : addr = 0x%x, value = 0x%x\n",
					__FUNCTION__, __LINE__,
					phy_page0_default_setting[i].addr,
					efuse_mapping[jj]);
			}
        */
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
    //printk("[%s:%d], Set page 1\n", __FUNCTION__, __LINE__);
    rtk_usb_phy_set_page(rtk_phy, 1);

    for (i = 0; i < phy_data->page1_size; i++) {
        if (rtk_usb_phy_write(rtk_phy, (phy_page1_default_setting + i)->addr, (phy_page1_default_setting + i)->data)) {
            dev_err(phy->dev, "[%s:%d], page1 Error : addr = 0x%x, value = 0x%x\n",
                    __FUNCTION__, __LINE__,
                    (phy_page1_default_setting + i)->addr,
                    (phy_page1_default_setting + i)->data);
            ret = -1;
            goto out;
        } else {
            dev_dbg(phy->dev, "[%s:%d], page1 Good : addr = 0x%x, value = 0x%x\n",
                    __FUNCTION__, __LINE__,
                    (phy_page1_default_setting + i)->addr,
                    rtk_usb_phy_read(rtk_phy, (phy_page1_default_setting + i)->addr - OFFEST_PHY_READ));
        }
    }

    initialized = 1;

    dev_info(phy->dev, "%s Initialized RTK USB PHY rle0599\n", __FILE__);
out:
    spin_unlock_irqrestore(&rtk_phy_lock, flags);
    return ret;
}

static int rtk_usb_rle0599_phy_probe(struct platform_device *pdev)
{
    struct rtk_usb_phy_s *rtk_usb_phy;
    struct device *dev = &pdev->dev;
    int	ret = 0;
    struct reg_addr *addr;
    struct phy_data *phy_data;
    int phy_data_page0_size, phy_data_page1_size;

    rtk_usb_phy = devm_kzalloc(dev, sizeof(*rtk_usb_phy), GFP_KERNEL);
    if (!rtk_usb_phy)
        return -ENOMEM;

    rtk_usb_phy->dev			= &pdev->dev;
    rtk_usb_phy->phy.dev		= rtk_usb_phy->dev;
    rtk_usb_phy->phy.label		= RTK_USB_RLE0599_PHY_NAME;
    rtk_usb_phy->phy.init		= rtk_usb_phy_init;
    rtk_usb_phy->phy.shutdown	= rtk_usb_phy_shutdown;

    if (dev->of_node) {
        ret = of_property_read_u32_index(dev->of_node, "portN", 0, &rtk_usb_phy->portN);
        if (ret) goto err;
        dev_dbg(dev, "%s %s portN=%d\n", __FILE__, __func__, rtk_usb_phy->portN);
        addr = devm_kzalloc(dev, sizeof(*addr), GFP_KERNEL);
        if (!addr) return -ENOMEM;

        addr->REG_WRAP_VStatusOut2 = of_iomap(dev->of_node, 0);
        addr->REG_EHCI_INSNREG05   = of_iomap(dev->of_node, 1);
        addr->REG_EFUSE71cc = of_iomap(dev->of_node, 2);

        rtk_usb_phy->reg_addr = addr;

        dev_dbg(dev, "%s %s REG_WRAP_VStatusOut2=%p\n", __FILE__, __func__, addr->REG_WRAP_VStatusOut2);
        dev_dbg(dev, "%s %s REG_EHCI_INSNREG05=%p\n", __FILE__, __func__, addr->REG_EHCI_INSNREG05);
        ret = of_property_read_u32_index(dev->of_node, "phy_data_page0_size", 0, &phy_data_page0_size);
        if (ret) goto err;
        ret = of_property_read_u32_index(dev->of_node, "phy_data_page1_size", 0, &phy_data_page1_size);
        if (ret) goto err;

        dev_dbg(dev, "%s %s phy_data_page0_size=%d, phy_data_page1_size=%d\n",
                __FILE__, __func__, phy_data_page0_size, phy_data_page1_size);
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

#if 0
    /* Due to usb_add_phy only support one USB2_phy and one USB3_phy
     * DWC3 use USB2_phy and USB3_phy, EHCI don't add it
     */
    ret = usb_add_phy(&rtk_usb_phy->phy, USB_PHY_TYPE_USB2);
    if (ret)
        goto err;
#endif

    platform_set_drvdata(pdev, rtk_usb_phy);

    dev_info(&pdev->dev, "Probe RTK USB 2.0 RLE0599 PHY\n");

err:
    return ret;
}

static int rtk_usb_rle0599_phy_remove(struct platform_device *pdev)
{
//	struct rtk_usb_phy_s *rtk_usb_phy = platform_get_drvdata(pdev);

#if 0
    /* Due to usb_add_phy only support one USB2_phy and one USB3_phy
     * DWC3 use USB2_phy and USB3_phy, EHCI don't add it
     */
    usb_remove_phy(&rtk_usb_phy->phy);
#endif

    return 0;
}

static const struct of_device_id usb_phy_rle0599_rtk_dt_ids[] = {
    { .compatible = "Realtek,rtk119x-usb_phy_rle0599", },
    { .compatible = "Realtek,rtd129x-usb_phy_rle0599", },
    {},
};
MODULE_DEVICE_TABLE(of, usb_phy_rle0599_rtk_dt_ids);

static struct platform_driver rtk_usb_rle0599_phy_driver = {
    .probe		= rtk_usb_rle0599_phy_probe,
    .remove		= rtk_usb_rle0599_phy_remove,
    .driver		= {
        .name	= RTK_USB_RLE0599_PHY_NAME,
        .owner	= THIS_MODULE,
        .of_match_table = of_match_ptr(usb_phy_rle0599_rtk_dt_ids),
    },
};

module_platform_driver(rtk_usb_rle0599_phy_driver);
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:" RTK_USB_RLE0599_PHY_NAME);
