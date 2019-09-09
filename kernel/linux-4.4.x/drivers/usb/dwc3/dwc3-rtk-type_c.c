/**
 *  * dwc3-rtk-type_c.c - Realtek DWC3 Type C driver
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#undef DEBUG

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_gpio.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/usb/otg.h>
#include <linux/syscalls.h>
#include <linux/suspend.h>

#include "core.h"
#include "dwc3-rtk-drd.h"

struct type_c_data {
	void __iomem *wrap_base;
	struct device *dev;

	/*GPIO*/
	unsigned int pow_gpio;
	unsigned int rd_ctrl_gpio;

	/*Parameters*/
	u32 cc1_rp;
	u32 cc1_rp_code;
	u32 cc1_rd;
	u32 cc1_rd_code;
	u32 cc1_vref_ufp;
	u32 cc1_vref_dfp_usb;
	u32 cc1_vref_dfp_1_5;
	u32 cc1_vref_dfp_3_0;
	u32 cc2_rp;
	u32 cc2_rp_code;
	u32 cc2_rd;
	u32 cc2_rd_code;
	u32 cc2_vref_ufp;
	u32 cc2_vref_dfp_usb;
	u32 cc2_vref_dfp_1_5;
	u32 cc2_vref_dfp_3_0;
	u32 debounce_val;// 1b,1us 7f,4.7us

	struct dwc3 *dwc;
	int dwc3_mode;
	int cur_mode;
	bool is_drd_mode;

	// type_c state
	int connect_change;
#define CONNECT_CHANGE 1
#define CONNECT_NO_CHANGE 0
	int in_host_mode;
#define IN_HOST_MODE 1
#define IN_DEVICE_MODE 0
	int is_attach;
#define IN_ATTACH 1
#define TO_ATTACH 1
#define IN_DETACH 0
#define TO_DETACH 0
	int at_cc1;
#define AT_CC1 1
#define AT_CC2 0

	u32 int_status;
	u32 cc_status;
	spinlock_t		lock;
	struct delayed_work   delayed_work;

	bool debug;
};

// Wrapper register address begin from 0x98013200
// register USB2 PHY
#define USB_TMP_reg   0x50
#define USB_TMP_reg_1 0x54
#define USB_TMP_reg_2 0x58
#define USB_TMP_reg_3 0x5c
#define USB2_PHY_reg  0x70
// register type c
#define USB_TYPEC_CTRL_CC1_0 0x14c //0x9801334c
#define USB_TYPEC_CTRL_CC1_1 0x150 //0x98013350
#define USB_TYPEC_CTRL_CC2_0 0x154 //0x98013354
#define USB_TYPEC_CTRL_CC2_1 0x158 //0x98013358
#define USB_TYPEC_STS        0x15c //0x9801335c
#define USB_TYPEC_CTRL       0x160 //0x98013360
#define USB_DBUS_PWR_CTRL    0x164 //0x98013364

// USB_TYPEC_CTRL_CC1_0 USB_TYPEC_CTRL_CC2_0
#define EN_SWITCH BIT(29)
#define Txout_sel BIT(28)
#define Rxin_sel BIT(27)
#define SWITCH_MASK (EN_SWITCH | Txout_sel | Rxin_sel)
#define enable_cc1 EN_SWITCH
#define enable_cc2 (EN_SWITCH | Txout_sel | Rxin_sel)
#define rp4pk_code(val) (val << 22)
#define rp36k_code(val) (val << 17)
#define rp12k_code(val) (val << 12)
#define rd_code(val) (val << 7)
#define cc_mode(val) (val << 5)
#define En_rp4p7k BIT(4)
#define En_rp36k BIT(3)
#define En_rp12k BIT(2)
#define En_rd BIT(1)
#define En_cc_det BIT(0)

#define CC_MODE_UFP 0x0
#define CC_MODE_DFP_USB 0x1
#define CC_MODE_DFP_1_5 0x2
#define CC_MODE_DFP_3_0 0x3

// USB_TYPEC_CTRL_CC1_1 USB_TYPEC_CTRL_CC2_1
#define vref_2p6v(val) (val << 26)
#define vref_1p23v(val) (val << 22)
#define vref_0p8v(val) (val << 18)
#define vref_0p66v(val) (val << 14)
#define vref_0p4v(val) (val << 11)
#define vref_0p2v(val) (val << 8)
#define vref_1_1p6v(val) (val << 4)
#define vref_0_1p6v(val) (val << 0)

// USB_TYPEC_STS
#define det_sts 0x7
#define cc1_det_sts (det_sts)
#define cc2_det_sts (det_sts << 3)
#define det_sts_ra 0x1
#define det_sts_rd 0x3
#define cc1_det_sts_ra (det_sts_ra)
#define cc1_det_sts_rd (det_sts_rd)
#define cc2_det_sts_ra (det_sts_ra << 3)
#define cc2_det_sts_rd (det_sts_rd << 3)

//USB_TYPEC_CTRL
#define cc2_int_en BIT(11)
#define cc1_int_en BIT(10)
#define cc2_int_sts BIT(9)
#define cc1_int_sts BIT(8)
#define debounce_time_MASK 0xff
#define ENABLE_TYPE_C_DETECT (cc1_int_en | cc2_int_en)
#define all_cc_int_sts (cc1_int_sts | cc2_int_sts)

//Parameter
#define DETECT_TIME 50 //ms

static void enable_writel(int value, void __iomem* addr) {
	writel(value | readl(addr),  addr);
}

static void disable_writel(int value, void __iomem* addr) {
	writel(~value & readl(addr),  addr);
}

#if 0
void dbg_dump(struct type_c_data * type_c) {
	struct device		*dev = type_c->dev;
	void __iomem 		*wrap_base = type_c->wrap_base;

//	dev_err(dev, "CC1 Rp=0x%x code=0x%x\n", type_c->cc1_rp, type_c->cc1_rp_code);
//	dev_err(dev, "CC1 Rd=0x%x code=0x%x\n", type_c->cc1_rd, type_c->cc1_rd_code);
//	dev_err(dev, "CC2 Rp=0x%x code=0x%x\n", type_c->cc2_rp, type_c->cc2_rp_code);
//	dev_err(dev, "CC2 Rd=0x%x code=0x%x\n", type_c->cc2_rd, type_c->cc1_rd_code);

//	dev_err(dev, "USB_TYPEC_CTRL_CC1_0=0x%x\n", readl(wrap_base + USB_TYPEC_CTRL_CC1_0));
//	dev_err(dev, "USB_TYPEC_CTRL_CC1_1=0x%x\n", readl(wrap_base + USB_TYPEC_CTRL_CC1_1));
//	dev_err(dev, "USB_TYPEC_CTRL_CC2_0=0x%x\n", readl(wrap_base + USB_TYPEC_CTRL_CC2_0));
//	dev_err(dev, "USB_TYPEC_CTRL_CC2_1=0x%x\n", readl(wrap_base + USB_TYPEC_CTRL_CC2_1));
	dev_err(dev, "USB_TYPEC_STS=0x%x\n", readl(wrap_base + USB_TYPEC_STS));
	dev_err(dev, "USB_TYPEC_CTRL=0x%x", readl(type_c->wrap_base + USB_TYPEC_CTRL));
}

#endif

static void switch_dwc3_mode(struct type_c_data *type_c, int dr_mode) {

	if (!type_c->is_drd_mode) {
		dr_mode = type_c->dwc3_mode;
	}

	type_c->cur_mode = dr_mode;

	switch (dr_mode) {
		case USB_DR_MODE_PERIPHERAL:
			dev_info(type_c->dev, "%s dr_mode=USB_DR_MODE_PERIPHERAL\n", __func__);
#ifdef CONFIG_USB_RTK_DWC3_DRD_MODE
			dwc3_drd_to_device(type_c->dwc);
#else
			dev_err(type_c->dev, "NO add config CONFIG_USB_RTK_DWC3_DRD_MODE");
#endif
			mdelay(10);
			writel(0x0, type_c->wrap_base + USB2_PHY_reg);
		break;
		case USB_DR_MODE_HOST:
			dev_info(type_c->dev, "%s dr_mode=USB_DR_MODE_HOST\n", __func__);
#ifdef CONFIG_USB_RTK_DWC3_DRD_MODE
			dwc3_drd_to_host(type_c->dwc);
#else
			dev_err(type_c->dev, "NO add config CONFIG_USB_RTK_DWC3_DRD_MODE");
#endif
			mdelay(10);
			writel(0x606, type_c->wrap_base + USB2_PHY_reg);
		break;
		default:
			dev_info(type_c->dev, "%s dr_mode=%d\n", __func__, dr_mode);
			//mdelay(10);
#ifdef CONFIG_USB_RTK_DWC3_DRD_MODE
			dwc3_drd_to_stop_all(type_c->dwc);
#else
			dev_err(type_c->dev, "NO add config CONFIG_USB_RTK_DWC3_DRD_MODE");
#endif
	}
}

/* device attached / detached */
int device_attached(struct type_c_data *type_c, u32 enable_cc) {
	struct device		*dev = type_c->dev;
	unsigned int gpio = type_c->pow_gpio;

	cancel_delayed_work(&type_c->delayed_work);

	switch_dwc3_mode(type_c, USB_DR_MODE_HOST);

	enable_writel(enable_cc, type_c->wrap_base + USB_TYPEC_CTRL_CC1_0);

	dev_info(dev,"%s to enable power\n", __func__);
	if (gpio != -1 && gpio_is_valid(gpio)) {
		if (gpio_direction_output(gpio, 1))
			dev_err(dev, "%s ERROR type_c power=1 fail\n", __func__);
		else dev_dbg(dev, "%s to enable type c power gpio (id=%d) OK\n", __func__, gpio);
	}

	enable_writel(ENABLE_TYPE_C_DETECT, type_c->wrap_base + USB_TYPEC_CTRL);
	return 0;
}

int device_detached(struct type_c_data *type_c) {
	struct device		*dev = type_c->dev;
	unsigned int gpio = type_c->pow_gpio;

	dev_info(dev,"%s to disable power\n", __func__);
	if (gpio != -1 && gpio_is_valid(gpio)) {
		if (gpio_direction_output(gpio, 0))
			dev_err(dev, "%s ERROR type_c power=0 fail\n", __func__);
		else dev_dbg(dev, "%s to disable type c power gpio (id=%d) OK\n", __func__, gpio);
	}

	disable_writel(SWITCH_MASK, type_c->wrap_base + USB_TYPEC_CTRL_CC1_0);

	switch_dwc3_mode(type_c, 0);
	schedule_delayed_work(&type_c->delayed_work, msecs_to_jiffies(DETECT_TIME));

	disable_writel(ENABLE_TYPE_C_DETECT, type_c->wrap_base + USB_TYPEC_CTRL);
	return 0;
}

/* host connect /disconnect*/
int host_connected(struct type_c_data *type_c, u32 enable_cc) {
	struct device		*dev = type_c->dev;

	dev_info(dev,"%s: a Host connect\n", __func__);

	cancel_delayed_work(&type_c->delayed_work);

	switch_dwc3_mode(type_c, USB_DR_MODE_PERIPHERAL);

	enable_writel(enable_cc, type_c->wrap_base + USB_TYPEC_CTRL_CC1_0);

	enable_writel(ENABLE_TYPE_C_DETECT, type_c->wrap_base + USB_TYPEC_CTRL);
	return 0;
}

int host_disconnected(struct type_c_data *type_c) {
	struct device		*dev = type_c->dev;
	dev_info(dev,"%s: a Host disconnect\n", __func__);

	disable_writel(SWITCH_MASK, type_c->wrap_base + USB_TYPEC_CTRL_CC1_0);

	switch_dwc3_mode(type_c, 0);

	schedule_delayed_work(&type_c->delayed_work, msecs_to_jiffies(DETECT_TIME));

	disable_writel(ENABLE_TYPE_C_DETECT, type_c->wrap_base + USB_TYPEC_CTRL);

	return 0;
}

/* detect host device switch */
static int detect_device(struct type_c_data *type_c) {
	struct device		*dev = type_c->dev;
	void __iomem 		*wrap_base = type_c->wrap_base;
	unsigned int gpio = type_c->rd_ctrl_gpio;
	u32 cc1_config, cc2_config, default_ctrl;
	int cc_mode_sel = CC_MODE_DFP_3_0;

	default_ctrl = readl(wrap_base + USB_TYPEC_CTRL) & debounce_time_MASK;
	writel(default_ctrl, wrap_base + USB_TYPEC_CTRL);

	disable_writel(En_cc_det, wrap_base + USB_TYPEC_CTRL_CC1_0);
	disable_writel(En_cc_det, wrap_base + USB_TYPEC_CTRL_CC2_0);

	if (gpio != -1 && gpio_is_valid(gpio)) {
		if (gpio_direction_output(gpio, 1))
			dev_err(dev, "%s ERROR rd_ctrl_gpio=1 fail\n", __func__);
	}

	switch (cc_mode_sel) {
		case CC_MODE_DFP_USB:
		writel(type_c->cc1_vref_dfp_usb, wrap_base + USB_TYPEC_CTRL_CC1_1);
		writel(type_c->cc2_vref_dfp_usb, wrap_base + USB_TYPEC_CTRL_CC2_1);
		break;
		case CC_MODE_DFP_1_5:
		writel(type_c->cc1_vref_dfp_1_5, wrap_base + USB_TYPEC_CTRL_CC1_1);
		writel(type_c->cc2_vref_dfp_1_5, wrap_base + USB_TYPEC_CTRL_CC2_1);
		break;
		case CC_MODE_DFP_3_0:
		writel(type_c->cc1_vref_dfp_3_0, wrap_base + USB_TYPEC_CTRL_CC1_1);
		writel(type_c->cc2_vref_dfp_3_0, wrap_base + USB_TYPEC_CTRL_CC2_1);
		break;
		default:
		dev_err(dev, "%s ERROR cc_mode_sel=%d\n", __func__, cc_mode_sel);
		break;
	}
	cc1_config = type_c->cc1_rp | type_c->cc1_rp_code | cc_mode(cc_mode_sel);
	cc2_config = type_c->cc2_rp | type_c->cc2_rp_code | cc_mode(cc_mode_sel);

	writel(cc1_config, wrap_base + USB_TYPEC_CTRL_CC1_0);
	writel(cc2_config, wrap_base + USB_TYPEC_CTRL_CC2_0);

	wmb();

	mdelay(1);
	enable_writel(En_cc_det, wrap_base + USB_TYPEC_CTRL_CC1_0);
	enable_writel(En_cc_det, wrap_base + USB_TYPEC_CTRL_CC2_0);

	return 0;
}

static int detect_host(struct type_c_data *type_c) {
	struct device		*dev = type_c->dev;
	void __iomem 		*wrap_base = type_c->wrap_base;
	unsigned int gpio = type_c->rd_ctrl_gpio;
	u32 cc1_config, cc2_config, default_ctrl;

	default_ctrl = readl(wrap_base + USB_TYPEC_CTRL) & debounce_time_MASK;
	writel(default_ctrl, wrap_base + USB_TYPEC_CTRL);

	disable_writel(En_cc_det, wrap_base + USB_TYPEC_CTRL_CC1_0);
	disable_writel(En_cc_det, wrap_base + USB_TYPEC_CTRL_CC2_0);

	writel(type_c->cc1_vref_ufp, wrap_base + USB_TYPEC_CTRL_CC1_1);
	writel(type_c->cc2_vref_ufp, wrap_base + USB_TYPEC_CTRL_CC2_1);

	cc1_config = type_c->cc1_rd | type_c->cc1_rd_code | cc_mode(CC_MODE_UFP);
	cc2_config = type_c->cc2_rd | type_c->cc2_rd_code | cc_mode(CC_MODE_UFP);

	writel(cc1_config, wrap_base + USB_TYPEC_CTRL_CC1_0);
	writel(cc2_config, wrap_base + USB_TYPEC_CTRL_CC2_0);

	//if ((type_c->cc1_rd & type_c->cc2_rd) && gpio != -1 && gpio_is_valid(gpio)) {
	// Add workaround to force use internal Rd plus external Rd
	if (false && (type_c->cc1_rd & type_c->cc2_rd)
			&& gpio != -1 && gpio_is_valid(gpio)) {
		// use internal Rd
		if (gpio_direction_output(gpio, 1))
			dev_err(dev, "%s ERROR rd_ctrl_gpio=1 fail\n", __func__);
	} else if (gpio != -1 && gpio_is_valid(gpio)) {
		// use external Rd
		if (gpio_direction_output(gpio, 0))
			dev_err(dev, "%s ERROR rd_ctrl_gpio=0 fail\n", __func__);
	}
	wmb();

	mdelay(1);
	enable_writel(En_cc_det, wrap_base + USB_TYPEC_CTRL_CC1_0);
	mdelay(2); // add a delay to avoid error cc2 interrupt on cc_status=0x0
	enable_writel(En_cc_det, wrap_base + USB_TYPEC_CTRL_CC2_0);
	mdelay(1); // add a delay to avoid error cc2 interrupt on cc_status=0x0

	return 0;
}

int host_device_switch_detection(struct type_c_data * type_c) {
	struct device		*dev = type_c->dev;
	int ret = 0;

	dev_dbg(dev, "ENTER  %s", __func__);
	if (type_c->in_host_mode) {
		type_c->in_host_mode = IN_DEVICE_MODE;
		detect_host(type_c);
		dev_dbg(dev, "Now device mode $$$$$$$$$$$$$$$$$$$$$$$");
	} else {
		type_c->in_host_mode = IN_HOST_MODE;
		detect_device(type_c);
		dev_dbg(dev, "Now host mode   #######################");
	}

	return ret;
}

int detect_type_c_state(struct type_c_data *type_c) {
	struct device *dev = type_c->dev;
	u32 int_status, cc_status;

	int_status = readl(type_c->wrap_base + USB_TYPEC_CTRL);
	cc_status = readl(type_c->wrap_base + USB_TYPEC_STS);

	type_c->connect_change = CONNECT_NO_CHANGE;

	switch (type_c->in_host_mode) {
	case IN_HOST_MODE:
		switch (type_c->is_attach) {
		case IN_ATTACH:
			if (((cc_status & cc1_det_sts) == cc1_det_sts) && (type_c->at_cc1 == AT_CC1)) {
				dev_dbg(dev,"IN host mode and cc1 device detach");
				type_c->is_attach = TO_DETACH;
				type_c->connect_change = CONNECT_CHANGE;
			} else if (((cc_status & cc2_det_sts) == cc2_det_sts) && (type_c->at_cc1 == AT_CC2)) {
				dev_dbg(dev,"IN host mode and cc2 device detach");
				type_c->is_attach = TO_DETACH;
				type_c->connect_change = CONNECT_CHANGE;
			}
		break;
		case IN_DETACH:
			if ((cc_status & cc1_det_sts) == cc1_det_sts_rd) {
				dev_dbg(dev,"IN host mode and cc1 device attach");
				type_c->is_attach = TO_ATTACH;
				type_c->at_cc1 = AT_CC1;
				type_c->connect_change = CONNECT_CHANGE;
			} else if ((cc_status & cc2_det_sts) == cc2_det_sts_rd) {
				dev_dbg(dev,"In host mode and cc2 device attach");
				type_c->is_attach = TO_ATTACH;
				type_c->at_cc1 = AT_CC2;
				type_c->connect_change = CONNECT_CHANGE;
			}
		break;
		default:
			dev_err(dev,"IN host_mode and error attach state (is_attach=%d)", type_c->is_attach);
		}
	break;
	case IN_DEVICE_MODE:
		switch (type_c->is_attach) {
		case IN_ATTACH:
			if ((cc_status & cc1_det_sts) == 0x0 && type_c->at_cc1 == AT_CC1) {
				dev_dbg(dev,"IN device mode and cc1 host disconnect");
				type_c->is_attach = TO_DETACH;
				type_c->connect_change = CONNECT_CHANGE;
			} else if ((cc_status & cc2_det_sts) == 0x0 && type_c->at_cc1 == AT_CC2) {
				dev_dbg(dev,"IN device mode and cc2 host connect");
				type_c->is_attach = TO_DETACH;
				type_c->connect_change = CONNECT_CHANGE;
			}
		break;
		case IN_DETACH:
			if ((cc_status & cc1_det_sts) != 0x0) {
				dev_dbg(dev,"IN device mode and cc1 host connect");
				type_c->at_cc1 = AT_CC1;
				type_c->is_attach = TO_ATTACH;
				type_c->connect_change = CONNECT_CHANGE;
			} else if ((cc_status & cc2_det_sts) != 0) {
				dev_dbg(dev,"IN device mode and cc2 host connect");
				type_c->at_cc1 = AT_CC2;
				type_c->is_attach = TO_ATTACH;
				type_c->connect_change = CONNECT_CHANGE;
			}
		break;
		default:
			dev_err(dev,"IN device_mode and error attach state (is_attach=%d)", type_c->is_attach);
		}
	break;
	default:
		dev_err(dev,"error host or device mode (in_host_mode=%d)", type_c->in_host_mode);
	}
	type_c->int_status = int_status;
	type_c->cc_status = cc_status;
	return 0;
}

void host_device_switch(struct work_struct *work) {
	struct type_c_data *type_c = container_of(work, struct type_c_data, delayed_work.work);
	struct device		*dev = type_c->dev;
	unsigned long		flags;
	int connect_change = 0;
	int in_host_mode = 0;
	int is_attach = 0;
	int at_cc1 = 0;

	dev_dbg(type_c->dev, "ENTER %s", __func__);

	spin_lock_irqsave(&type_c->lock, flags);

	if (type_c->is_attach == IN_DETACH && !type_c->connect_change) {
		if (type_c->is_drd_mode)
			host_device_switch_detection(type_c);
		detect_type_c_state(type_c);
	}

	if (type_c->connect_change) {
		connect_change = type_c->connect_change;
		in_host_mode = type_c->in_host_mode;
		is_attach = type_c->is_attach;
		at_cc1 = type_c->at_cc1;
		type_c->connect_change = CONNECT_NO_CHANGE;
	} else {
		schedule_delayed_work(&type_c->delayed_work, msecs_to_jiffies(DETECT_TIME));
	}

	spin_unlock_irqrestore(&type_c->lock, flags);

	if (connect_change) {
		dev_info(dev, "%s: usb cable connection change\n", __func__);
		if (in_host_mode) {
			if (is_attach && at_cc1)
				device_attached(type_c, enable_cc1);
			else if (is_attach && !at_cc1)
				device_attached(type_c, enable_cc2);
			else
				device_detached(type_c);
		} else {
			if (is_attach && at_cc1)
				host_connected(type_c, enable_cc1);
			else if (is_attach && !at_cc1)
				host_connected(type_c, enable_cc2);
			else
				host_disconnected(type_c);
		}
		dev_err(dev, "Connection change: IN %s mode to %s %s at %s",
				in_host_mode?"host":"device",
				in_host_mode?
					(is_attach?"attach":"detach"):
					(is_attach?"connect":"disconnect"),
				in_host_mode?"device":"host", at_cc1?"cc1":"cc2");

	}

	/* For special case, some boards use type c power and need use host mode.
	 * After 30s, We switch to host mode if in device mode but no host connect.
	 */
	if (type_c->is_drd_mode) {
		static bool check_at_boot = true;
		if (check_at_boot && connect_change &&
			(in_host_mode == IN_DEVICE_MODE) && is_attach) {
			int no_host_connect = 0;
			int no_run_gadget = 0;
			u32 enable_cc = at_cc1?enable_cc1:enable_cc2;
			void __iomem *dwc3_dsts_addr = ioremap(0x9802870c, 0x4);
			void __iomem *dwc3_dctl_addr = ioremap(0x98028704, 0x4);
			dev_info(dev, "%s: In Device mode check connection at boot time\n", __func__);
			msleep(30000);
			dev_info(dev, "%s: Device mode check DSTS=%x DCTL=%x\n", __func__,
					readl(dwc3_dsts_addr), readl(dwc3_dctl_addr));
			no_host_connect = (readl(dwc3_dsts_addr) & 0x0003FFF8) == BIT(17);
			no_run_gadget = (readl(dwc3_dctl_addr) & BIT(31)) == 0x0;
			if (no_host_connect || no_run_gadget) {
				disable_writel(SWITCH_MASK, type_c->wrap_base + USB_TYPEC_CTRL_CC1_0);
				mdelay(100);
				dev_info(dev, "%s: In Device mode, NO host connect at boot time, switch to Host mode\n", __func__);
				switch_dwc3_mode(type_c, USB_DR_MODE_HOST);
				enable_writel(enable_cc, type_c->wrap_base + USB_TYPEC_CTRL_CC1_0);
			}
			__iounmap(dwc3_dsts_addr);;
			__iounmap(dwc3_dctl_addr);;
		}
		check_at_boot = false;
	}
}

irqreturn_t type_c_detect_irq(int irq, void *__data) {
	struct type_c_data 	*type_c = (struct type_c_data *) __data;
	struct device 		*dev = type_c->dev;
	unsigned long		flags;

	spin_lock_irqsave(&type_c->lock, flags);

	detect_type_c_state(type_c);

	if (type_c->connect_change) {
		dev_info(dev, "%s: IN %s mode to %s %s (at %s interrupt) int_status=0x%x, cc_status=0x%x",
			__func__,
			type_c->in_host_mode?"host":"device",
			type_c->in_host_mode?
				(type_c->is_attach?"attach":"detach"):
				(type_c->is_attach?"connect":"disconnect"),
			type_c->in_host_mode?"device":"host",
			type_c->at_cc1?"cc1":"cc2", type_c->int_status, type_c->cc_status);

		//clear interrupt status
		disable_writel(all_cc_int_sts, type_c->wrap_base + USB_TYPEC_CTRL);

		cancel_delayed_work(&type_c->delayed_work);
		schedule_delayed_work(&type_c->delayed_work, msecs_to_jiffies(0));
	}

	spin_unlock_irqrestore(&type_c->lock, flags);

	return IRQ_HANDLED;
}

/* Init and probe */
static int dwc3_rtk_type_c_init(struct type_c_data *type_c)
{
	struct device		*dev = type_c->dev;
	u32 debounce_val = type_c->debounce_val;// 1b,1us 7f,4.7us

	enable_writel(debounce_val<<1, type_c->wrap_base + USB_TYPEC_CTRL);
	dev_info(dev, "%s set debounce = 0x%x (check--> 0x%x)\n",
				__func__, debounce_val, readl(type_c->wrap_base + USB_TYPEC_CTRL));

	if ((type_c->rd_ctrl_gpio != -1) && gpio_request(type_c->rd_ctrl_gpio, dev->of_node->name))
		dev_err(dev, "%s ERROR Request rd_ctrl_gpio  (id=%d) fail\n",__func__, type_c->rd_ctrl_gpio);

	if (type_c->dwc3_mode == USB_DR_MODE_HOST) {
		unsigned long		flags;

		spin_lock_irqsave(&type_c->lock, flags);

		dev_info(dev, "DWC3_DRD run in USB_DR_MODE_HOST");
		type_c->in_host_mode = IN_HOST_MODE;
		type_c->is_attach = IN_DETACH;
		type_c->connect_change = CONNECT_NO_CHANGE;
		type_c->cur_mode = USB_DR_MODE_HOST;

		detect_device(type_c);
		detect_type_c_state(type_c);

		spin_unlock_irqrestore(&type_c->lock, flags);

		schedule_delayed_work(&type_c->delayed_work, msecs_to_jiffies(0));
	} else if (type_c->dwc3_mode == USB_DR_MODE_PERIPHERAL) {
		unsigned long		flags;

		spin_lock_irqsave(&type_c->lock, flags);

		dev_info(dev, "DWC3_DRD run in USB_DR_MODE_PERIPHERAL%s",
				type_c->is_drd_mode?" at DRD mode":"");
		type_c->in_host_mode = IN_DEVICE_MODE;
		type_c->is_attach = IN_DETACH;
		type_c->connect_change = CONNECT_NO_CHANGE;
		type_c->cur_mode = USB_DR_MODE_PERIPHERAL;

		detect_host(type_c);
		detect_type_c_state(type_c);

		spin_unlock_irqrestore(&type_c->lock, flags);

		schedule_delayed_work(&type_c->delayed_work, msecs_to_jiffies(0));
	} else {
		dev_err(dev, "DWC3_DRD is USB_DR_MODE_UNKNOWN");
	}
	return 0;
}

static int dwc3_rtk_type_c_probe(struct platform_device *pdev) {
	struct device		*dev = &pdev->dev;
	struct device_node	*node = dev->of_node;
	struct type_c_data 	*type_c;
	unsigned int gpio;
	int irq;
	int ret = 0;
	unsigned long probe_time = jiffies;

	dev_info(dev, "ENTER %s", __func__);
	type_c = devm_kzalloc(dev, sizeof(*type_c), GFP_KERNEL);
	if (!type_c)
		return -ENOMEM;

	type_c->wrap_base = of_iomap(pdev->dev.of_node, 0);
	if (type_c->wrap_base == NULL) {
		dev_err(&pdev->dev, "error mapping memory for wrap_base\n");
		ret = -EFAULT;
		goto err1;
	}
	type_c->dev = dev;

	irq = irq_of_parse_and_map(pdev->dev.of_node, 0);
	if (irq <= 0) {
		dev_err(&pdev->dev, "Type C driver with no IRQ. Check %s setup!\n",
				dev_name(&pdev->dev));
		ret = -ENODEV;
		goto err1;
	}

	ret = request_irq(irq, type_c_detect_irq,
			IRQF_SHARED, "type_c_detect", type_c);

	if (node && of_device_is_available(node)) {
		gpio = of_get_named_gpio(node, "realtek,rd_ctrl-gpio", 0);

		if (gpio_is_valid(gpio)) {
			type_c->rd_ctrl_gpio = gpio;
			dev_info(dev, "%s get rd_ctrl-gpio (id=%d) OK\n", __func__, gpio);
		} else {
			dev_err(dev, "Error rd_ctrl-gpio no found");
			type_c->rd_ctrl_gpio = -1;
		}

		gpio = of_get_named_gpio(node, "realtek,type_c-power-gpio", 0);
		if (gpio_is_valid(gpio)) {
			type_c->pow_gpio = gpio;
			dev_info(dev, "%s get type_c power-gpio (id=%d) OK\n", __func__, gpio);
			if (gpio_direction_output(gpio, 0))
				dev_err(dev, "%s ERROR type_c power=0 fail\n", __func__);
			else dev_info(dev, "%s first to close type c power by gpio (id=%d) OK\n", __func__, gpio);
		 } else {
			dev_err(dev, "Error type_c-power-gpio no found");
			type_c->pow_gpio = -1;
		}
	}

	if (node && of_device_is_available(node)) {
		const char *str;
		u32 val;
		char array_vals[3];
		//cc1 parameters
		ret = of_property_read_string(node, "cc1_rp", &str);
		if (ret) {
			dev_err(&pdev->dev, "%s: cc1_rp error(%d)\n", __func__, ret);
			goto err1;
		}
		ret = of_property_read_u32(node, "cc1_rp_code", &val);
		if (ret) {
			dev_err(&pdev->dev, "%s: cc1_rp error(%d)\n", __func__, ret);
			goto err1;
		}
		if (!strcmp(str, "rp4p7k")) {
			type_c->cc1_rp = En_rp4p7k;
			type_c->cc1_rp_code = rp4pk_code(val);
		} else if (!strcmp(str, "rp36k")) {
			type_c->cc1_rp = En_rp36k;
			type_c->cc1_rp_code = rp36k_code(val);
		} else if (!strcmp(str, "rp12k")) {
			type_c->cc1_rp = En_rp12k;
			type_c->cc1_rp_code = rp12k_code(val);
		} else {
			dev_err(&pdev->dev, "%s: unknown cc1_rp %s, code=%d\n", __func__, str, val);
		}
		ret = of_property_read_string(node, "cc1_rd", &str);
		if (ret) {
			dev_err(&pdev->dev, "%s: cc1_rd error(%d)\n", __func__, ret);
			goto err1;
		}
		ret = of_property_read_u32(node, "cc1_rd_code", &val);
		if (ret) {
			dev_err(&pdev->dev, "%s: cc1_rd error(%d)\n", __func__, ret);
			goto err1;
		}
		if (!strcmp(str, "internal")) {
			type_c->cc1_rd = En_rd;
			type_c->cc1_rd_code = rd_code(val);
		} else if (!strcmp(str, "external")) {
			type_c->cc1_rd = 0x0;
			type_c->cc1_rd_code = 0x0;
		} else {
			dev_err(&pdev->dev, "%s: unknown cc1_rd %s, code=%d\n", __func__, str, val);
		}
		ret = of_property_read_u8_array(node, "cc1_vref_ufp", array_vals, 3);
		if (ret) {
			dev_err(&pdev->dev, "%s: cc1_vref_ufp error(%d)\n", __func__, ret);
			goto err1;
		}
		type_c->cc1_vref_ufp = vref_1p23v(array_vals[0]) | vref_0p66v(array_vals[1]) | vref_0p2v(array_vals[2]);

		ret = of_property_read_u8_array(node, "cc1_vref_dfp_usb", array_vals, 3);
		if (ret) {
			dev_err(&pdev->dev, "%s: cc1_vref_dfp_usb error(%d)\n", __func__, ret);
			goto err1;
		}
		type_c->cc1_vref_dfp_usb = vref_0_1p6v(array_vals[0]) | vref_0p2v(array_vals[1]);

		ret = of_property_read_u8_array(node, "cc1_vref_dfp_1_5", array_vals, 3);
		if (ret) {
			dev_err(&pdev->dev, "%s: cc1_vref_dfp_1_5 error(%d)\n", __func__, ret);
			goto err1;
		}
		type_c->cc1_vref_dfp_1_5 = vref_1_1p6v(array_vals[0]) | vref_0p4v(array_vals[1]) | vref_0p2v(array_vals[2]);

		ret = of_property_read_u8_array(node, "cc1_vref_dfp_3_0", array_vals, 3);
		if (ret) {
			dev_err(&pdev->dev, "%s: cc1_vref_dfp_3_0 error(%d)\n", __func__, ret);
			goto err1;
		}
		type_c->cc1_vref_dfp_3_0 = vref_2p6v(array_vals[0]) | vref_0p8v(array_vals[1]) | vref_0p2v(array_vals[2]);

		//cc2 parameters
		ret = of_property_read_string(node, "cc2_rp", &str);
		if (ret) {
			dev_err(&pdev->dev, "%s: cc2_rp error(%d)\n", __func__, ret);
			goto err1;
		}
		ret = of_property_read_u32(node, "cc2_rp_code", &val);
		if (ret) {
			dev_err(&pdev->dev, "%s: cc2_rp error(%d)\n", __func__, ret);
			goto err1;
		}
		if (!strcmp(str, "rp4p7k")) {
			type_c->cc2_rp = En_rp4p7k;
			type_c->cc2_rp_code = rp4pk_code(val);
		} else if (!strcmp(str, "rp36k")) {
			type_c->cc2_rp = En_rp36k;
			type_c->cc2_rp_code = rp36k_code(val);
		} else if (!strcmp(str, "rp12k")) {
			type_c->cc2_rp = En_rp12k;
			type_c->cc2_rp_code = rp12k_code(val);
		} else {
			dev_err(&pdev->dev, "%s: unknown cc2_rp %s, code=%d\n", __func__, str, val);
		}
		ret = of_property_read_string(node, "cc2_rd", &str);
		if (ret) {
			dev_err(&pdev->dev, "%s: cc2_rd error(%d)\n", __func__, ret);
			goto err1;
		}
		ret = of_property_read_u32(node, "cc2_rd_code", &val);
		if (ret) {
			dev_err(&pdev->dev, "%s: cc2_rd_code error(%d)\n", __func__, ret);
			goto err1;
		}
		if (!strcmp(str, "internal")) {
			type_c->cc2_rd = En_rd;
			type_c->cc2_rd_code = rd_code(val);
		} else if (!strcmp(str, "external")) {
			type_c->cc2_rd = 0x0;
			type_c->cc2_rd_code = 0x0;
		} else {
			dev_err(&pdev->dev, "%s: unknown cc2_rd %s, code=%d\n", __func__, str, val);
		}

		ret = of_property_read_u8_array(node, "cc2_vref_ufp", array_vals, 3);
		if (ret) {
			dev_err(&pdev->dev, "%s: cc2_vref_ufp error(%d)\n", __func__, ret);
			goto err1;
		}
		type_c->cc2_vref_ufp = vref_1p23v(array_vals[0]) | vref_0p66v(array_vals[1]) | vref_0p2v(array_vals[2]);

		ret = of_property_read_u8_array(node, "cc2_vref_dfp_usb", array_vals, 3);
		if (ret) {
			dev_err(&pdev->dev, "%s: cc2_vref_dfp_usb error(%d)\n", __func__, ret);
			goto err1;
		}
		type_c->cc2_vref_dfp_usb = vref_0_1p6v(array_vals[0]) | vref_0p2v(array_vals[1]);

		ret = of_property_read_u8_array(node, "cc2_vref_dfp_1_5", array_vals, 3);
		if (ret) {
			dev_err(&pdev->dev, "%s: cc2_vref_dfp_1_5 error(%d)\n", __func__, ret);
			goto err1;
		}
		type_c->cc2_vref_dfp_1_5 = vref_1_1p6v(array_vals[0]) | vref_0p4v(array_vals[1]) | vref_0p2v(array_vals[2]);

		ret = of_property_read_u8_array(node, "cc2_vref_dfp_3_0", array_vals, 3);
		if (ret) {
			dev_err(&pdev->dev, "%s: cc2_vref_dfp_3_0 error(%d)\n", __func__, ret);
			goto err1;
		}
		type_c->cc2_vref_dfp_3_0 = vref_2p6v(array_vals[0]) | vref_0p8v(array_vals[1]) | vref_0p2v(array_vals[2]);

		type_c->debounce_val = 0x7f;// 1b,1us 7f,4.7us
	}

	if (true) {
		struct device_node	*_node;
		struct device_node	*next_node;

		_node =  of_find_compatible_node(NULL, NULL, "Realtek,rtd129x-dwc3-drd");
		next_node = of_get_next_child(_node, NULL);
		if (next_node != NULL) {
			type_c->dwc = platform_get_drvdata(of_find_device_by_node(next_node));
		} else {
			dev_err(dev, "No find rtd129x-dwc-drd");
			ret = -ENODEV;
			goto err1;
		}

		type_c->dwc3_mode = type_c->dwc->dr_mode;
	}

	type_c->is_attach = IN_DETACH;
	type_c->is_drd_mode = false;
	if (of_property_read_bool(node, "drd_mode")) {
		if (type_c->dwc3_mode == USB_DR_MODE_PERIPHERAL) {
			type_c->is_drd_mode = true;
			dev_info(dev, "DWC3_DRD is DRD mode");
		} else {
			dev_info(dev, "DWC3_DRD is not DRD mode, due to dwc3_mode=USB_DR_MODE_HOST");
		}
	} else {
		dev_dbg(dev, "DWC3_DRD is no drd_mode, and dwc3_mode=%d", type_c->dwc3_mode);
	}

	if (of_property_read_bool(node, "debug")) {
		dev_info(&pdev->dev, "%s device tree set debug flag\n", __func__);
		type_c->debug = true;
	} else {
		type_c->debug = false;
	}

	INIT_DELAYED_WORK(&type_c->delayed_work, host_device_switch);

	dwc3_rtk_type_c_init(type_c);

	platform_set_drvdata(pdev, type_c);

	dev_info(&pdev->dev, "Exit %s OK (take %d ms)\n", __func__, jiffies_to_msecs(jiffies - probe_time));
	return 0;

err1:
	dev_err(&pdev->dev, "%s: Probe fail, %d\n", __func__, ret);

	return ret;
}

static int dwc3_rtk_type_c_remove(struct platform_device *pdev) {
	dev_info(&pdev->dev, "%s\n", __func__);
	return 0;
}

#ifdef CONFIG_OF
static const struct of_device_id rtk_dwc3_type_c_match[] = {
	{ .compatible = "Realtek,rtd1295-dwc3-type_c" },
	{ .compatible = "Realtek,rtd1296-dwc3-type_c" },
	{},
};
MODULE_DEVICE_TABLE(of, rtk_dwc3_type_c_match);
#endif

#ifdef CONFIG_PM_SLEEP
static int dwc3_rtk_type_c_suspend(struct device *dev) {
	struct type_c_data *type_c = dev_get_drvdata(dev);
	u32 default_ctrl;
	unsigned long		flags;
	dev_info(dev, "[USB] Enter %s", __func__);

	cancel_delayed_work_sync(&type_c->delayed_work);

	flush_delayed_work(&type_c->delayed_work);

	BUG_ON(delayed_work_pending(&type_c->delayed_work));

	spin_lock_irqsave(&type_c->lock, flags);
	//disable interrupt
	default_ctrl = readl(type_c->wrap_base + USB_TYPEC_CTRL) & debounce_time_MASK;
	writel(default_ctrl, type_c->wrap_base + USB_TYPEC_CTRL);

	spin_unlock_irqrestore(&type_c->lock, flags);

	if (RTK_PM_STATE == PM_SUSPEND_STANDBY){
		//For idle mode
		dev_info(dev, "[USB] %s Idle mode\n", __func__);
		goto out;
	}
	//For suspend mode
	dev_info(dev,  "[USB] %s Suspend mode\n", __func__);

	if (type_c->rd_ctrl_gpio != -1)
		gpio_free(type_c->rd_ctrl_gpio);

out:
	dev_info(dev, "[USB] Exit %s\n", __func__);
	return 0;
}

static int dwc3_rtk_type_c_resume(struct device *dev) {
	struct type_c_data *type_c = dev_get_drvdata(dev);
	unsigned long		flags;
	dev_info(dev, "[USB] Enter %s", __func__);

	if (RTK_PM_STATE == PM_SUSPEND_STANDBY){
		//For idle mode
		dev_info(dev, "[USB] %s Idle mode\n", __func__);
		spin_lock_irqsave(&type_c->lock, flags);
		schedule_delayed_work(&type_c->delayed_work, msecs_to_jiffies(1));
		spin_unlock_irqrestore(&type_c->lock, flags);
		goto out;
	}
	//For suspend mode
	dev_info(dev,  "[USB] %s Suspend mode\n", __func__);

	dwc3_rtk_type_c_init(type_c);

out:
	dev_info(dev, "[USB] Exit %s\n", __func__);
	return 0;
}

static const struct dev_pm_ops dwc3_rtk_type_c_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(dwc3_rtk_type_c_suspend, dwc3_rtk_type_c_resume)
};

#define DEV_PM_OPS	(&dwc3_rtk_type_c_pm_ops)
#else
#define DEV_PM_OPS	NULL
#endif /* CONFIG_PM_SLEEP */

static struct platform_driver dwc3_rtk_type_c_driver = {
	.probe		= dwc3_rtk_type_c_probe,
	.remove		= dwc3_rtk_type_c_remove,
	.driver		= {
		.name	= "rtk-dwc3-type_c",
		.of_match_table = of_match_ptr(rtk_dwc3_type_c_match),
		.pm = DEV_PM_OPS,
	},
};

//module_platform_driver(dwc3_rtk_type_c_driver);
static int __init dwc3_rtk_type_c_driver_init(void) {
	void __iomem *efuse_addr = ioremap(0x980171d8, 0x4);
	int val = readl(efuse_addr) & 0x3;
	int ret = 0;
	if (val != 0x1) {
		ret =  platform_driver_register(&(dwc3_rtk_type_c_driver));
	}
	__iounmap(efuse_addr);
	return ret;
}
module_init(dwc3_rtk_type_c_driver_init);

static void __exit dwc3_rtk_type_c_driver_exit(void) {
	platform_driver_unregister(&(dwc3_rtk_type_c_driver));
}
module_exit(dwc3_rtk_type_c_driver_exit);

MODULE_ALIAS("platform:rtk-dwc3-type_c");
MODULE_LICENSE("GPL");
