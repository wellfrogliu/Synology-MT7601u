#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
/*
 *  RTK Host Power Control Driver for All USB.
 *
 * This file is licensed under the GPL.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/usb.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_gpio.h>
#include <linux/of_platform.h>
#include <linux/reset-helper.h> // rstc_get
#include <linux/reset.h>
#include <linux/clkdev.h>   // clk_get
#include <linux/clk.h>   // clk_get
#include <linux/clk-provider.h>
#include <linux/power-control.h>
#include <linux/suspend.h>
#include <linux/regulator/consumer.h>
#include <soc/realtek/rtd129x_cpu.h>

#define CRT_SOFT_RESET1 	0x0
#define CRT_SOFT_RESET2 	0x4
#define CRT_CLOCK_ENABLE1 	0xc

struct manager_data {
    int rtd129x_cpu_id;
    void __iomem *crt_base;
    void __iomem *reg_charger;
    void __iomem *usb_typec_ctrl_cc1_0;
    void __iomem *reg_usb_ctrl;

    struct device *dev;

    /*GPIO*/
    unsigned int type_c_pow_gpio;
    unsigned int u2host_pow_gpio;
    unsigned int u3host_pow_gpio;

    int port0;
    int port1;
    int port2;
    int port3;
    bool disable_usb;

    struct device_node *drd_node;
    struct device_node *u2host_node;
    struct device_node *ehci_node;
    struct device_node *ohci_node;
    struct device_node *u3host_node;
};

static inline void __power_control_set_power(const char *name, bool power_on)
{
    struct power_control * pctrl = power_control_get(name);
    if (!pctrl) {
        pr_debug("%s: Failed to get power_control %s\n",  __func__, name);
        return;
    }

    if (power_on)
        power_control_power_on(pctrl);
    else
        power_control_power_off(pctrl);
}

/* enable hw_pm (L4 ICG)
 *   The hw_pm function will be reset after doing soft_reset, so
 *   only enable is provided.
 */
static __maybe_unused void __rtk_usb_set_hw_pm_enable(struct manager_data *data)
{
    struct device *dev = data->dev;

    dev_dbg(dev, "set usb_hw_pm\n");

    /* for hw_pm, enable is equal to power_off */
    if (data->port0)
        __power_control_set_power("pctrl_l4_icg_usb_p0", false);
    if (data->port1)
        __power_control_set_power("pctrl_l4_icg_usb_p1", false);
    if (data->port2)
        __power_control_set_power("pctrl_l4_icg_usb_p2", false);
    if (data->port3)
        __power_control_set_power("pctrl_l4_icg_usb_p3", false);
}

/* set usb charger power */
static __maybe_unused void __rtk_usb_set_charger_power(struct manager_data *data, bool power_on)
{
    struct device *dev = data->dev;
    void __iomem *reg_charger  = data->reg_charger;
    unsigned int val = 0;

    if (power_on) {
        val |= data->port0 << 0;
        val |= data->port1 << 1;
        val |= data->port2 << 2;
        val |= data->port3 << 3;
    }

    dev_dbg(dev, "set usb_charger to 0x%08x\n", val);

    writel(val, reg_charger);
}

/* set usb power domain */
static void __rtk_usb_set_pd_power(struct manager_data* data, bool power_on)
{
    struct device *dev = data->dev;

    if (power_on && (data->port0 || data->port1 || data->port2 || data->port3)) {

        dev_dbg(dev, "set usb_power_domain/p0 on\n");
        __power_control_set_power("pctrl_usb_p0_mac", 1);
        __power_control_set_power("pctrl_usb_p0_phy", 1);

        dev_info(dev, "set usb_power_domain/p3 on\n");
        __power_control_set_power("pctrl_usb_p3_phy", data->port3);
        __power_control_set_power("pctrl_usb_p3_mac", data->port3);

    } else {
        void __iomem *reg_usb_ctrl = data->reg_usb_ctrl;

        dev_dbg(dev, "set power_domain off\n");
        writel(0x00000000, reg_usb_ctrl);
    }
}

static int __rtk_usb_host_reset(struct manager_data* data) {
    struct device *dev = data->dev;
    void __iomem *crt_reg = data->crt_base;
    /* GET clock */
    struct clk *clk_usb = clk_get(NULL, "clk_en_usb");

    /* GET reset controller */
    struct reset_control *reset_phy0 = rstc_get("rstn_usb_phy0");
    struct reset_control *reset_phy1 = rstc_get("rstn_usb_phy1");
    struct reset_control *reset_phy2 = rstc_get("rstn_usb_phy2");
    struct reset_control *reset_phy3 = rstc_get("rstn_usb_phy3");
    struct reset_control *reset_u3_phy0 = rstc_get("rstn_usb3_phy0_pow");
    struct reset_control *reset_u3_phy1 = rstc_get("rstn_usb3_phy1_pow");
    struct reset_control *reset_u3_phy0_mdio = rstc_get("rstn_usb3_p0_mdio");
    struct reset_control *reset_u3_phy1_mdio = rstc_get("rstn_usb3_p1_mdio");
    struct reset_control *reset_usb = rstc_get("rstn_usb");
    struct reset_control *reset_usb_apply = rstc_get("rstn_usb_apply");

    dev_dbg(dev, "Realtek USB init CRT_SOFT_RESET1=%x, CRT_SOFT_RESET2=%x, CRT_CLOCK_ENABLE1=%x\n",
            (uint32_t)(readl(crt_reg + CRT_SOFT_RESET1)),
            (uint32_t)(readl(crt_reg + CRT_SOFT_RESET2)),
            (uint32_t)(readl(crt_reg + CRT_CLOCK_ENABLE1)));

    reset_control_assert(reset_phy0);
    reset_control_assert(reset_phy1);
    reset_control_assert(reset_phy2);
    reset_control_assert(reset_phy3);
    reset_control_assert(reset_u3_phy0);
    reset_control_assert(reset_u3_phy1);
    reset_control_assert(reset_u3_phy0_mdio);
    reset_control_assert(reset_u3_phy1_mdio);
    reset_control_assert(reset_usb);
    wmb();

    dev_dbg(dev, "Realtek USB init 0/5 CRT_SOFT_RESET1=%x, CRT_SOFT_RESET2=%x, CRT_CLOCK_ENABLE1=%x\n",
            (uint32_t)(readl(crt_reg + CRT_SOFT_RESET1)),
            (uint32_t)(readl(crt_reg + CRT_SOFT_RESET2)),
            (uint32_t)(readl(crt_reg + CRT_CLOCK_ENABLE1)));

#if 0 //Directly use write register to reset u2phy pll, due to port0 to port2 must reset Simultaneously.
// CRT_SOFT_RESET1 usb part
#define rstn_phy1          BIT(9)
#define rstn_phy0          BIT(8)
#define rstn_u3_phy0 BIT(2)
// CRT_SOFT_RESET2 usb part
#define rstn_u3_phy1 BIT(4)
#define rstn_phy2 BIT(3)
#define rstn_phy3 BIT(2)

    {
        int reset1_pll_flag = 0;
        int reset2_pll_flag = 0;

        // Enable usb phy reset
        if (data->port0)
            reset1_pll_flag |= rstn_phy0 | rstn_u3_phy0;

        if (data->port1)
            reset1_pll_flag |= rstn_phy1;

        if (data->port2)
            reset2_pll_flag |= rstn_phy2;

        if (data->port3)
            reset2_pll_flag |= rstn_phy3 | rstn_u3_phy1;

        writel(reset1_pll_flag | readl(crt_reg + CRT_SOFT_RESET1), crt_reg + CRT_SOFT_RESET1);
        writel(reset2_pll_flag | readl(crt_reg + CRT_SOFT_RESET2), crt_reg + CRT_SOFT_RESET2);
    }
#else
    // Enable usb phy reset
    /* DEASSERT: set rstn bit to 1 */
    if (data->port0) {
        reset_control_deassert(reset_phy0);
        reset_control_deassert(reset_u3_phy0);
    }
    if (data->port1) {
        reset_control_deassert(reset_phy1);
    }
    if (data->port2) {
        reset_control_deassert(reset_phy2);
    }
    if (data->port3) {
        reset_control_deassert(reset_phy3);
        reset_control_deassert(reset_u3_phy1);
    }
    reset_control_deassert(reset_usb_apply);
#endif

    mdelay(2);
    dev_dbg(dev,"Realtek USB init 1/5 Enable PLL (CRT_SOFT_RESET1=%x, CRT_SOFT_RESET2=%x, CRT_CLOCK_ENABLE1=%x)\n",
            (uint32_t)(readl(crt_reg + CRT_SOFT_RESET1)),
            (uint32_t)(readl(crt_reg + CRT_SOFT_RESET2)),
            (uint32_t)(readl(crt_reg + CRT_CLOCK_ENABLE1)));

    // Trigger USB clk (enable -> disable)
    clk_prepare_enable(clk_usb); // = clk_prepare + clk_enable
    dev_dbg(dev, "Realtek USB init 2/5 enable usb clk (CRT_SOFT_RESET1=%x, CRT_SOFT_RESET2=%x, CRT_CLOCK_ENABLE1=%x)\n",
            (uint32_t)(readl(crt_reg + CRT_SOFT_RESET1)),
            (uint32_t)(readl(crt_reg + CRT_SOFT_RESET2)),
            (uint32_t)(readl(crt_reg + CRT_CLOCK_ENABLE1)));

    clk_disable_unprepare(clk_usb); // = clk_disable + clk_unprepare
    mdelay(1);

    dev_dbg(dev, "Realtek USB init 3/5 disable usb clk (CRT_SOFT_RESET1=%x, CRT_SOFT_RESET2=%x, CRT_CLOCK_ENABLE1=%x)\n",
            (uint32_t)(readl(crt_reg + CRT_SOFT_RESET1)),
            (uint32_t)(readl(crt_reg + CRT_SOFT_RESET2)),
            (uint32_t)(readl(crt_reg + CRT_CLOCK_ENABLE1)));

    // Enable USB reset
    if (data->port0) {
        reset_control_deassert(reset_u3_phy0_mdio);
    }
    if (data->port3) {
        reset_control_deassert(reset_u3_phy1_mdio);
    }
    reset_control_deassert(reset_usb_apply);

    reset_control_deassert(reset_usb);
    mdelay(1);
    dev_dbg(dev, "Realtek USB init 4/5 Turn on RSTN_USB (CRT_SOFT_RESET1=%x, CRT_SOFT_RESET2=%x, CRT_CLOCK_ENABLE1=%x)\n",
            (uint32_t)(readl(crt_reg + CRT_SOFT_RESET1)),
            (uint32_t)(readl(crt_reg + CRT_SOFT_RESET2)),
            (uint32_t)(readl(crt_reg + CRT_CLOCK_ENABLE1)));

    // Enable USB clk
    clk_prepare_enable(clk_usb); // = clk_prepare + clk_enable
    mdelay(2);

    dev_info(dev, "Realtek USB init 5/5 OK (CRT_SOFT_RESET1=%x, CRT_SOFT_RESET2=%x, CRT_CLOCK_ENABLE1=%x)\n",
             (uint32_t)(readl(crt_reg + CRT_SOFT_RESET1)),
             (uint32_t)(readl(crt_reg + CRT_SOFT_RESET2)),
             (uint32_t)(readl(crt_reg + CRT_CLOCK_ENABLE1)));

    clk_put(clk_usb);

    return 0;
}

static int rtk_usb_drd_gpio_power_on_off(struct manager_data *data, bool on) {
    struct device *dev = data->dev;
    int gpio = data->type_c_pow_gpio;
    void __iomem *usb_typec_ctrl_cc1_0 = data->usb_typec_ctrl_cc1_0;

    writel(BIT(29), usb_typec_ctrl_cc1_0);
    if (gpio_is_valid(gpio)) {
        if (gpio_direction_output(gpio, on))
            dev_err(dev, "%s ERROR set gpio fail\n", __func__);
        else dev_info(dev, "%s 1294 type c power %s by gpio (id=%d) OK\n",
                              __func__, on?"on":"off", gpio);
    }

    return 0;
}

static int rtk_usb_u2host_gpio_power_on_off(struct manager_data *data, bool on) {
    struct device *dev = data->dev;
    int u2host_pow_gpio = data->u2host_pow_gpio;

    if (gpio_is_valid(u2host_pow_gpio)) {
        if (gpio_request(u2host_pow_gpio, "u2host_pow_gpio"))         //request gpio
            dev_err(dev, "%s ERROR Request u2host_pow_gpio (id=%d) fail\n",__func__, u2host_pow_gpio);
        else if (u2host_pow_gpio != -1) {
            if (gpio_direction_output(u2host_pow_gpio, on))
                dev_err(dev, "%s ERROR u2host power %s fail\n", __func__, on?"on":"off");
            gpio_free(u2host_pow_gpio);
            dev_dbg(dev, "%s to set u2host power %s gpio (id=%d) OK\n", __func__, on?"on":"off", u2host_pow_gpio);
        }
    }
    return 0;
}

static int rtk_usb_u3host_gpio_power_on_off(struct manager_data *data, bool on) {
    struct device *dev = data->dev;
    int u3host_pow_gpio = data->u3host_pow_gpio;

    if (gpio_is_valid(u3host_pow_gpio)) {
        if (gpio_request(u3host_pow_gpio, "u3host_pow_gpio"))         //request gpio
            dev_err(dev, "%s ERROR Request u3host_pow_gpio (id=%d) fail\n",__func__, u3host_pow_gpio);
        else if (u3host_pow_gpio != -1) {
            if (gpio_direction_output(u3host_pow_gpio, on))
                dev_err(dev, "%s ERROR u3host power %s fail\n", __func__, on?"on":"off");
            gpio_free(u3host_pow_gpio);
            dev_dbg(dev, "%s to set u3host power %s gpio (id=%d) OK\n", __func__, on?"on":"off", u3host_pow_gpio);
        }
    }

#if 0
    // add workaround to enable QA board u2host power
    if (data->rtd129x_cpu_id == RTK1296_CPU_ID) {
        int qa_borad_gpio19 = 19;
        if (gpio_is_valid(qa_borad_gpio19)) {
            if (gpio_request(qa_borad_gpio19, "qa_u2host_pow_gpio"))         //request gpio
                dev_err(dev, "%s ERROR Request QA u2host_pow_gpio (id=%d) fail\n",__func__, qa_borad_gpio19);
            else if (qa_borad_gpio19 != -1) {
                if (gpio_direction_output(qa_borad_gpio19, on))
                    dev_err(dev, "%s ERROR QA u2host power %s fail\n", __func__, on?"on":"off");
                gpio_free(qa_borad_gpio19);
                dev_info(dev, "%s [Workaround] to set QA board u2host power %s gpio (id=%d) OK\n",
                         __func__, on?"on":"off", qa_borad_gpio19);
            }
        }
    }
#endif

    return 0;
}

static int rtk_usb_resume_power_on(struct manager_data *data) {
    struct device *dev = data->dev;
    bool on = true;

    dev_info(dev, "%s", __func__);
    if (data->port0) {
        rtk_usb_drd_gpio_power_on_off(data, on);
    }
    if (data->port1 || data->port2) {
        rtk_usb_u2host_gpio_power_on_off(data, on);
    }
    if (data->port3) {
        rtk_usb_u3host_gpio_power_on_off(data, on);
    }
    return 0;
}

int rtk_usb_init_power_on(struct device *usb_dev) {

#ifdef CONFIG_ARCH_RTD129X
    struct device_node *usb_node = usb_dev->of_node;
    struct device_node *node = of_find_compatible_node(NULL, NULL, "Realtek,rtd129x-usb-power-manager");
    struct platform_device *pdev = NULL;
    struct manager_data *data = NULL;
    bool on = true;

    if (node != NULL)
        pdev = of_find_device_by_node(node);
    if (pdev != NULL) {
        data = platform_get_drvdata(pdev);
    }
    if (data == NULL) {
        dev_err(data->dev, "%s ERROR no manager_data", __func__);
        return -ENODEV;
    }

    dev_info(data->dev, "%s for %s", __func__, dev_name(usb_dev));
    if (data->port0 && (data->drd_node->phandle == usb_node->phandle)) {
        dev_dbg(data->dev, "%s %s power on port 0", __func__, dev_name(usb_dev));
        rtk_usb_drd_gpio_power_on_off(data, on);
    }
    if (data->port1 || data->port2) {
        static int count = 0;
        if ((data->u2host_node->phandle == usb_node->phandle) ||
                (data->ehci_node->phandle == usb_node->phandle) ||
                (data->ohci_node->phandle == usb_node->phandle)) {
            count++;
        }
        if (count == (data->port1 + data->port2)) {
            dev_dbg(data->dev, "%s %s power on port 1 and port 2", __func__, dev_name(usb_dev));
            rtk_usb_u2host_gpio_power_on_off(data, on);
            count = 0;
        }
    }
    if (data->port3 && (data->u3host_node->phandle == usb_node->phandle)) {
        dev_dbg(data->dev, "%s %s power on port 3", __func__, dev_name(usb_dev));
        rtk_usb_u3host_gpio_power_on_off(data, on);
    }
#endif

    return 0;
}
EXPORT_SYMBOL_GPL(rtk_usb_init_power_on);

static int rtk_usb_gpio_init(struct manager_data *data) {
    struct device *dev = data->dev;
    int type_c_pow_gpio = data->type_c_pow_gpio;
    int u2host_pow_gpio = data->u2host_pow_gpio;
    int u3host_pow_gpio = data->u3host_pow_gpio;

    // drd Type C
    if (gpio_is_valid(type_c_pow_gpio)) {
        if (gpio_direction_output(type_c_pow_gpio, 0))
            dev_err(dev, "%s ERROR type_c-power-gpio fail\n", __func__);
        else dev_dbg(dev, "%s first to close type c power by gpio (id=%d) OK\n", __func__, type_c_pow_gpio);
    }

    // u2host and ehci
    if (gpio_is_valid(u2host_pow_gpio)) {
        if (gpio_request(u2host_pow_gpio, "u2host_pow_gpio"))         //request gpio
            dev_err(dev, "%s ERROR Request u2host_pow_gpio (id=%d) fail\n",__func__, u2host_pow_gpio);
        else if (u2host_pow_gpio != -1) {
            if (gpio_direction_output(u2host_pow_gpio, 0))
                dev_err(dev, "%s ERROR disable u2host power fail\n", __func__);
            gpio_free(u2host_pow_gpio);
            dev_dbg(dev, "%s to disable u2host power gpio (id=%d) OK\n", __func__, u2host_pow_gpio);
        }
    }

    // u3host
    if (gpio_is_valid(u3host_pow_gpio)) {
        if (gpio_request(u3host_pow_gpio, "u3host_pow_gpio"))         //request gpio
            dev_err(dev, "%s ERROR Request u3host_pow_gpio (id=%d) fail\n",__func__, u3host_pow_gpio);
        else if (u3host_pow_gpio != -1) {
            if (gpio_direction_output(u3host_pow_gpio, 0))
                dev_err(dev, "%s ERROR disable u3host power fail\n", __func__);
            gpio_free(u3host_pow_gpio);
            dev_dbg(dev, "%s to disable u3host power gpio (id=%d) OK\n", __func__, u3host_pow_gpio);
        }
    }
    return 0;
}

static int rtk_usb_init(struct manager_data *data) {
    struct device *dev = data->dev;

    dev_dbg(dev, "Realtek USB init ....\n");

    if (data->disable_usb) {
        dev_err(dev, "Realtek USB No any usb be enabled ....\n");
        return 0;
    }

    __rtk_usb_set_pd_power(data, 1);

    __rtk_usb_host_reset(data);

    rtk_usb_gpio_init(data);

    dev_dbg(dev, "Realtek USB init Done\n");

    return 0;
}

static int rtk_usb_power_manager_probe(struct platform_device *pdev) {
    struct device		*dev = &pdev->dev;
    struct device_node	*node = dev->of_node;
    struct manager_data 	*data;
    unsigned int gpio;
    int ret = 0;
    unsigned long probe_time = jiffies;

    dev_info(dev, "ENTER %s", __func__);
    data = devm_kzalloc(dev, sizeof(*data), GFP_KERNEL);
    if (!data)
        return -ENOMEM;

    data->crt_base = of_iomap(pdev->dev.of_node, 0);
    if (data->crt_base == NULL) {
        dev_err(&pdev->dev, "error mapping memory for crt_base\n");
        ret = -EFAULT;
        goto err1;
    }

    data->reg_charger  = ioremap(0x98007044, 0x4);
    if (data->reg_charger == NULL) {
        dev_err(&pdev->dev, "error mapping memory for reg_charger\n");
        ret = -EFAULT;
        goto err1;
    }

    data->usb_typec_ctrl_cc1_0 = ioremap(0x9801334c, 0x4);
    if (data->usb_typec_ctrl_cc1_0 == NULL) {
        dev_err(&pdev->dev, "error mapping memory for usb_typec_ctrl_cc1_0\n");
        ret = -EFAULT;
        goto err1;
    }

    data->reg_usb_ctrl = ioremap(0x98007fb0, 0x4);
    if (data->reg_usb_ctrl == NULL) {
        dev_err(&pdev->dev, "error mapping memory for reg_usb_ctrl\n");
        ret = -EFAULT;
        goto err1;
    }

    data->rtd129x_cpu_id = get_rtd129x_cpu_id();

    data->dev = dev;

    if (node && of_device_is_available(node)) {
        gpio = of_get_named_gpio(node, "realtek,type_c-power-gpio", 0);

        if (gpio_is_valid(gpio)) {
            data->type_c_pow_gpio = gpio;
            dev_dbg(dev, "%s get type_c-power-gpio (id=%d) OK\n", __func__, gpio);
        } else {
            data->type_c_pow_gpio = -1;
            dev_err(dev, "Error type_c-power-gpio no found");
        }

        gpio = of_get_named_gpio(node, "realtek,u2host-power-gpio", 0);
        if (gpio_is_valid(gpio)) {
            data->u2host_pow_gpio = gpio;
            dev_dbg(dev, "%s get u2host-power-gpio (id=%d) OK\n", __func__, gpio);
        } else {
            data->u2host_pow_gpio = -1;
            dev_err(dev, "Error u2host-power-gpio no found");
        }
        gpio = of_get_named_gpio(node, "realtek,u3host-power-gpio", 0);
        if (gpio_is_valid(gpio)) {
            data->u3host_pow_gpio = gpio;
            dev_dbg(dev, "%s get u3host-power-gpio (id=%d) OK\n", __func__, gpio);
        } else {
            data->u3host_pow_gpio = -1;
            dev_dbg(dev, " u3host-power-gpio no found");
        }
#ifdef MY_DEF_HERE
        /*
         * remove rtk power enable on USB device
         * because synology power enable is earlier
         * than RTK. so the USB power enable on RTK
         * is redundant
         */
        data->type_c_pow_gpio = -1;
        data->u2host_pow_gpio = -1;
        data->u3host_pow_gpio = -1;
#endif /* MY_DEF_HERE */
    }

    if (node && of_device_is_available(node)) {
        data->drd_node = of_parse_phandle(node, "port0", 0);
        data->u2host_node = of_parse_phandle(node, "port1", 0);
        data->ehci_node = of_parse_phandle(node, "port2", 0);
        data->ohci_node = of_parse_phandle(node, "port2", 1);
        data->u3host_node = of_parse_phandle(node, "port3", 0);

        data->disable_usb = true;
        data->port0 = 0;
        if (data->drd_node && of_device_is_available(data->drd_node)) {
            dev_info(dev, "%s status is okay", data->drd_node->name);
            data->port0++;
        }

        data->port1 = 0;
        if (data->u2host_node && of_device_is_available(data->u2host_node)) {
            dev_err(dev, "%s status is okay", data->u2host_node->name);
            data->port1++;
        }

        data->port2 = 0;
        if (data->ehci_node && of_device_is_available(data->ehci_node)) {
            dev_err(dev, "%s status is okay", data->ehci_node->name);
            data->port2++;
        }
        if (data->ohci_node && of_device_is_available(data->ohci_node)) {
            dev_err(dev, "%s status is okay", data->ohci_node->name);
            data->port2++;
        }

        data->port3 = 0;
        if (data->u3host_node && of_device_is_available(data->u3host_node)) {
            dev_err(dev, "%s status is okay", data->u3host_node->name);
            data->port3++;
        }
        if (data->port0 || data->port1 || data->port2 || data->port3) {
            data->disable_usb = false;
        }
    }

    rtk_usb_init(data);

    platform_set_drvdata(pdev, data);

    dev_info(&pdev->dev, "%s OK (take %d ms)\n", __func__, jiffies_to_msecs(jiffies - probe_time));
    return 0;

err1:
    dev_err(&pdev->dev, "%s: Probe fail, %d\n", __func__, ret);

    return ret;
}

static int rtk_usb_power_manager_remove(struct platform_device *pdev) {
    dev_info(&pdev->dev, "%s\n", __func__);
    return 0;
}

#ifdef CONFIG_OF
static const struct of_device_id rtk_usb_power_manager_match[] = {
    { .compatible = "Realtek,rtd129x-usb-power-manager" },
    {},
};
MODULE_DEVICE_TABLE(of, rtk_usb_power_manager_match);
#endif

#ifdef CONFIG_PM_SLEEP
static int rtk_usb_power_manager_suspend(struct device *dev) {
    struct manager_data *data = dev_get_drvdata(dev);

    dev_info(dev, "[USB] Enter %s\n", __func__);
    if (RTK_PM_STATE == PM_SUSPEND_STANDBY) {
        //For idle mode
        dev_info(dev, "[USB] %s Idle mode\n", __func__);
    } else {
        //For suspend mode
        dev_info(dev,  "[USB] %s Suspend mode\n", __func__);
        __rtk_usb_set_pd_power(data, 0);
    }
    dev_info(dev, "[USB] Exit %s\n", __func__);
    return 0;
}

static int rtk_usb_power_manager_resume(struct device *dev) {
    struct manager_data *data = dev_get_drvdata(dev);
    struct clk *clk_usb = clk_get(NULL, "clk_en_usb");

    dev_info(dev, "[USB] Enter %s\n", __func__);
    if (RTK_PM_STATE == PM_SUSPEND_STANDBY) {
        //For idle mode
        dev_info(dev, "[USB] %s Idle mode\n", __func__);
    } else {
        //For suspend mode
        dev_info(dev, "[USB] %s Suspend mode\n", __func__);
        clk_disable_unprepare(clk_usb); // = clk_disable + clk_unprepare
        __rtk_usb_set_pd_power(data, 1);
        __rtk_usb_host_reset(data);
        rtk_usb_gpio_init(data);
        rtk_usb_resume_power_on(data);
    }
    dev_info(dev, "[USB] Exit %s\n", __func__);
    return 0;
}

static const struct dev_pm_ops rtk_usb_power_manager_pm_ops = {
    SET_LATE_SYSTEM_SLEEP_PM_OPS(rtk_usb_power_manager_suspend, rtk_usb_power_manager_resume)
};

#define DEV_PM_OPS	(&rtk_usb_power_manager_pm_ops)
#else
#define DEV_PM_OPS	NULL
#endif /* CONFIG_PM_SLEEP */

static struct platform_driver rtk_usb_power_manager_driver = {
    .probe		= rtk_usb_power_manager_probe,
    .remove		= rtk_usb_power_manager_remove,
    .driver		= {
        .name	= "rtk-usb-power-manager",
        .of_match_table = of_match_ptr(rtk_usb_power_manager_match),
        .pm = DEV_PM_OPS,
    },
};

static int __init rtk_usb_power_manager_driver_init(void) {
    return platform_driver_register(&(rtk_usb_power_manager_driver));
}
subsys_initcall(rtk_usb_power_manager_driver_init);
//module_init(rtk_usb_power_manager_driver_init);

static void __exit rtk_usb_power_manager_driver_exit(void) {
    platform_driver_unregister(&(rtk_usb_power_manager_driver));
}
//module_exit(rtk_usb_power_manager_driver_exit);

MODULE_ALIAS("platform:rtk-usb-power-manager");
MODULE_LICENSE("GPL");
