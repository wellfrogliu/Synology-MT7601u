#define pr_fmt(fmt) "pctrl-rtk: " fmt

#include <linux/slab.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/power-control.h>
#include <linux/reset-controller.h>
#include <linux/reset.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/cpu_pm.h>
#include <linux/suspend.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include "soc/realtek/rtd129x_cpu.h"

#define DELAY_TIME_SEC 20

static inline int of_powerctrl_is_l4_icg(struct device_node *np);

enum {
    NONE = 0,
    L4_ICG,
    ANALOG,
    SRAM,
    GPU_CORE,
    USB_PHY
};

enum {
    IGNORE = -1,
    SYSTEM_DEFAULT = -1,
    POWER_OFF = 0,
    POWER_ON = 1,
    DRIVER_CONTROLLED = 10,
    PC_MANAGED = 11,
};

struct managed_pctrl {
    struct list_head list;
    struct power_control * pctrl;
};

static LIST_HEAD(managed_pctrl_list);
static struct workqueue_struct *rtk_powerctrl_workqueue;
const char * power_on_str[]  =  { "POWER_ON", "DISABLE_HW_PM" };
const char * power_off_str[] =  { "POWER_OFF", "ENABLE_HW_PM" };
static DEFINE_MUTEX(rtk_powerctrl_mutex);

static inline void rtk_powerctrl_lock(void)
{
    mutex_lock(&rtk_powerctrl_mutex);
}

static inline void rtk_powerctrl_unlock(void)
{
    mutex_unlock(&rtk_powerctrl_mutex);
}

#ifdef CONFIG_POWER_CONTROL_RTD129X_DEBUGFS

static struct dentry *power_control_root;

static int rtk_power_control_show(struct seq_file *s, void *data)
{
    struct power_control *pctrl = s->private;
    seq_printf(s, "%d\n", power_control_is_powered_on(pctrl));
    return 0;
}

static int rtk_power_control_open(struct inode *inode, struct file *file)
{
    return single_open(file, rtk_power_control_show, inode->i_private);
}

static ssize_t rtk_power_control_write(struct file *filp, const char __user *user_buf, size_t count, loff_t *f_pos)
{
    char buf[32];
    int buf_size;
    struct power_control *pctrl = filp->f_inode->i_private;
    bool val;

    buf_size = count < sizeof(buf) - 1 ? count : sizeof(buf) - 1;
    if (copy_from_user(buf, user_buf, buf_size))
        return -EFAULT;

    if (strtobool(buf, &val))
        return -EINVAL;

    if (val == 1)
        power_control_power_on(pctrl);
    else
        power_control_power_off(pctrl);

    return count;
}

static struct file_operations rtk_power_control_debugfs_ops = {
    .owner   = THIS_MODULE,
    .open    = rtk_power_control_open,
    .read    = seq_read,
    .write   = rtk_power_control_write,
    .release = single_release,
};

#endif /* CONFIG_POWER_CONTROL_RTD129X_DEBUGFS */

#ifdef CONFIG_PM

struct pm_priv_data {
    struct list_head list;
    struct power_control *pctrl;
    int    state;
};

static LIST_HEAD(pm_data_list);

void inline rtk_powerctrl_pm_config(struct power_control *pctrl)
{
    struct pm_priv_data *data = kzalloc(sizeof(*data), GFP_KERNEL);
    if (data) {
        data->pctrl = pctrl;
        list_add(&data->list, &pm_data_list);
    }
}

static inline int rtk_powerctrl_pm_store(void)
{
    struct list_head * it = NULL;

#ifdef CONFIG_SUSPEND
    if (RTK_PM_STATE == PM_SUSPEND_STANDBY)
        return 0;
#endif

    list_for_each(it, &pm_data_list) {
        struct pm_priv_data *data = list_entry(it, struct pm_priv_data, list);
        data->state = power_control_is_powered_on(data->pctrl);
    }

    return 0;
}

static inline int rtk_powerctrl_pm_restore(void)
{
    struct list_head * it = NULL;
    int ret;

#ifdef CONFIG_SUSPEND
    if (RTK_PM_STATE == PM_SUSPEND_STANDBY)
        return 0;
#endif

    list_for_each_prev(it, &pm_data_list) {
        struct pm_priv_data *data = list_entry(it, struct pm_priv_data, list);
        struct power_control *pctrl = data->pctrl;
        int pon = power_control_is_powered_on(pctrl);
        int is_l4_icg = of_powerctrl_is_l4_icg(pctrl->of_node);

        if (data->state == 1 && pon != 1) {
            ret = power_control_power_on(pctrl);
            pr_info("restore %s: %s, ret = %d\n", pctrl->name,
                    power_off_str[is_l4_icg], ret);

        }
        else if (data->state == 0 && pon != 0) {
            ret = power_control_power_off(pctrl);
            pr_info("restore %s: %s, ret = %d\n", pctrl->name,
                    power_off_str[is_l4_icg], ret);
        }
    }
    return 0;
}

static int rtk_powerctrl_pm_notify(struct notifier_block *notify_block, unsigned long mode, void *unused)
{
    switch (mode) {
    case CPU_CLUSTER_PM_ENTER:
        printk(KERN_INFO "[POWERCTRL] Enter %s, act = CPU_CLUSTER_PM_ENTER\n", __func__);
        rtk_powerctrl_pm_store();
        printk(KERN_INFO "[POWERCTRL] Exit %s,  act = CPU_CLUSTER_PM_ENTER\n", __func__);
        break;
    case CPU_CLUSTER_PM_EXIT:
        printk(KERN_INFO "[POWERCTRL] Enter %s, act = CPU_CLUSTER_PM_EXIT\n", __func__);
        rtk_powerctrl_pm_restore();
        printk(KERN_INFO "[POWERCTRL] Exit %s,  act = CPU_CLUSTER_PM_EXIT\n", __func__);
        break;
    default:
        break;
    }
    return NOTIFY_OK;
}

static struct notifier_block pm_notifier_block = {
    .notifier_call = rtk_powerctrl_pm_notify,
};

#else

void inline rtk_powerctrl_pm_config(struct power_control *pctrl)
{
}

#endif /* CONFIG_PM */

static int of_get_power_state(struct device_node *np)
{
    int power_on = SYSTEM_DEFAULT;
    const char *power_state_str;

    if (!of_property_read_u32(np, "power-on", &power_on)) {
        pr_warning("%s: property is replace by power-state.\n", np->name);
    }

    if (!of_property_read_string(np, "power-state", &power_state_str))  {

        if (!strcmp(power_state_str, "off"))
            power_on = POWER_OFF;
        else if (!strcmp(power_state_str, "on"))
            power_on = POWER_ON;
        else if (!strcmp(power_state_str, "driver-controlled"))
            power_on = DRIVER_CONTROLLED;
        else if (!strcmp(power_state_str, "managed"))
            power_on = PC_MANAGED;
        else {
            // default
        }
    }

    return power_on;
}

static inline int of_powerctrl_is_l4_icg(struct device_node *np)
{
    if (of_find_property(np, "is-l4-icg", NULL))
        return 1;
    return 0;
}

static inline int of_powerctrl_is_analog(struct device_node *np)
{
    if (of_find_property(np, "is-analog", NULL))
        return 1;
    return 0;
}

static inline int of_check_revision(struct device_node *np, int rev_val)
{
    const u32 *prop;
    int i;
    int size;
    bool exclusive_mode = false;

    prop = of_get_property(np, "rev,inclusive", &size);
    if (prop)
        goto start;

    exclusive_mode = true;
    prop = of_get_property(np, "rev,exclusive", &size);
    if (prop)
        goto start;

    return 1;
start:

    size /= sizeof(u32);
    for (i = 0; i < size; i++) {
        u32 val = of_read_number(prop++, 1);

        if (val == rev_val)
            return exclusive_mode ? 0 : 1;
    }

    return exclusive_mode ? 1 : 0;
}

/**
 *  count_status_from_reference_devices - count available reference devices
 *  @np:    device node from which the property value is to be read
 *
 *  Return value is less than 0, if there is no reference device.
 */
static int of_count_available_reference_devices(struct device_node *np)
{
    int ret = 0;
    int n_name, n_comp, i;
    const char * str;
    struct device_node *ref_np;

    n_name = of_property_count_strings(np, "ref-status,by-name");
    for (i = 0; i < n_name; i++) {
        of_property_read_string_index(np, "ref-status,by-name", i, &str);

        ref_np = of_find_node_by_name(NULL, str);
        if (ref_np) {
            if (of_device_is_available(ref_np))
                ret ++;
            of_node_put(ref_np);
        }
    }

    n_comp = of_property_count_strings(np, "ref-status,by-compatible");
    for (i = 0; i < n_comp; i++) {
        of_property_read_string_index(np, "ref-status,by-compatible", i, &str);

        ref_np = of_find_compatible_node(NULL, NULL, str);
        if (ref_np) {
            if (of_device_is_available(ref_np))
                ret ++;
            of_node_put(ref_np);
        }
    }

    if (n_name <= 0 && n_comp <= 0)
        ret = -EINVAL;

    return ret;
}

static int rtk_powerctrl_generic_config(struct device_node * np, struct power_control * pctrl)
{
    int power_on = of_get_power_state(np);
    int is_l4_icg = of_powerctrl_is_l4_icg(np);
    int ret;

    switch(power_on)
    {
    case POWER_OFF:
        ret = power_control_power_off(pctrl);
        pr_info("%s::%s, ret = %d\n", pctrl->name,
                power_off_str[is_l4_icg], ret);
        break;

    case POWER_ON:
        ret = power_control_power_on(pctrl);
        pr_info("%s::%s, ret = %d\n", pctrl->name,
                power_on_str[is_l4_icg], ret);
        break;

    case PC_MANAGED: {
        struct managed_pctrl *data = kzalloc(sizeof(*data), GFP_KERNEL);
        data->pctrl = pctrl;
        list_add_tail(&data->list, &managed_pctrl_list);
        break;

    } /* case PC_MANAGED */
    default:
        break;
    }

#ifdef CONFIG_POWER_CONTROL_RTD129X_DEBUGFS
    do {
        struct dentry *dir = debugfs_create_dir(pctrl->name, power_control_root);
        debugfs_create_file("power", 0444, dir, pctrl, &rtk_power_control_debugfs_ops);
    } while (0);
#endif

    return 0;
}

/********************************************************************************
 * rtk_powerctrl
 ********************************************************************************/
struct rtk_powerctrl_config {
    void * __iomem reg;
    u32 shift;
    u32 width;
    u32 off_value;
    u32 off_value_st;
    u32 on_value;
    u32 on_value_st;
};

struct rtk_powerctrl {
    struct power_control pctrl;
    int    type;
    struct clk *ref_clk;
    struct reset_control *ref_rstc;
    struct power_control *ref_pctrl;

    int size;
    /* LAST MEMBER  */
    struct rtk_powerctrl_config config[0];
};

#define to_rtk_powerctrl(_p) container_of((_p), struct rtk_powerctrl, pctrl)

static int __rtk_powerctrl_check_reference(struct rtk_powerctrl *ctrl)
{
    if (ctrl->ref_rstc && reset_control_status(ctrl->ref_rstc) > 0)
        return -EPERM;

    if (ctrl->ref_clk && __clk_is_enabled(ctrl->ref_clk) == 0)
        return -EPERM;

    if (ctrl->ref_pctrl && power_control_is_powered_on(ctrl->ref_pctrl) != 1)
        return -EPERM;

    return 0;
}

struct __ref_state {
    int ref_clk_st;
    int ref_rstc_st;
};

static int __rtk_powerctrl_enable_reference(struct rtk_powerctrl *ctrl,
        struct __ref_state *st)
{
    if (ctrl->type != ANALOG)
        return -EINVAL;

    if (ctrl->ref_pctrl && power_control_is_powered_on(ctrl->ref_pctrl) != 1)
        return -EPERM;

    st->ref_rstc_st = 0;
    if (ctrl->ref_rstc && reset_control_status(ctrl->ref_rstc) > 0) {
        reset_control_deassert(ctrl->ref_rstc);
        st->ref_rstc_st = 1;
    }

    st->ref_clk_st = 0;
    if (ctrl->ref_clk && __clk_is_enabled(ctrl->ref_clk) == 0) {
        clk_prepare_enable(ctrl->ref_clk);
        st->ref_clk_st = 1;
    }

    return 0;
}

static int __rtk_powerctrl_restore_reference(struct rtk_powerctrl *ctrl,
        struct __ref_state *st)
{
    if (st->ref_rstc_st)
        reset_control_assert(ctrl->ref_rstc);
    if (st->ref_clk_st)
        clk_disable_unprepare(ctrl->ref_clk);

    return 0;
}

static int rtk_power_on(struct power_control *pctrl)
{
    struct rtk_powerctrl *ctrl = to_rtk_powerctrl(pctrl);
    u32 val, mask, data;
    int i;
    int ret;
    struct __ref_state st;

    switch (ctrl->type) {
    default:
        ret = __rtk_powerctrl_check_reference(ctrl);
        if (ret)
            return ret;
        break;
    case ANALOG:
        ret = __rtk_powerctrl_enable_reference(ctrl, &st);
        if (ret)
            return ret;
        break;
    }

    rtk_powerctrl_lock();

    for (i = 0; i < ctrl->size; i++)
    {
        struct rtk_powerctrl_config *config = &ctrl->config[i];

        mask = (BIT(config->width) - 1) << config->shift;
        data = config->on_value << config->shift;

        val = readl(config->reg);
        val &= ~mask;
        val |= data & mask;
        writel(val, config->reg);
    }

    rtk_powerctrl_unlock();

    if (ctrl->type == ANALOG)
        __rtk_powerctrl_restore_reference(ctrl, &st);

    return 0;
}

static int rtk_power_off(struct power_control *pctrl)
{
    struct rtk_powerctrl * ctrl = to_rtk_powerctrl(pctrl);
    u32 val, mask, data;
    int i;

    int ret;
    struct __ref_state st;

    switch (ctrl->type) {
    default:
        ret = __rtk_powerctrl_check_reference(ctrl);
        if (ret)
            return ret;
        break;
    case ANALOG:
        ret = __rtk_powerctrl_enable_reference(ctrl, &st);
        if (ret)
            return ret;
        break;
    }

    rtk_powerctrl_lock();

    for (i = ctrl->size-1; i >= 0; i--)
    {
        struct rtk_powerctrl_config *config = &ctrl->config[i];

        mask = (BIT(config->width) - 1) << config->shift;
        data = config->off_value << config->shift;

        val = readl(config->reg);
        val &= ~mask;
        val |= data & mask;
        writel(val, config->reg);
    }

    rtk_powerctrl_unlock();

    if (ctrl->type == ANALOG)
        __rtk_powerctrl_restore_reference(ctrl, &st);

    return 0;
}

static int rtk_is_powered_on(struct power_control *pctrl)
{
    struct rtk_powerctrl * ctrl = to_rtk_powerctrl(pctrl);
    int on = 0, off = 0, i;
    u32 val;
    int ret;

    ret = __rtk_powerctrl_check_reference(ctrl);
    if (ret)
        return ret;

    rtk_powerctrl_lock();

    for (i = 0; i < ctrl->size; i++) {
        const struct rtk_powerctrl_config *config = &ctrl->config[i];

        val = readl(config->reg);
        if (val != 0xdeadbeef)
        {
            val = (val >> config->shift) & (BIT(config->width) - 1);
            if (val == config->on_value_st)
                on ++;
            if (val == config->off_value_st)
                off ++;
        }
    }

    rtk_powerctrl_unlock();

    if (on == i)
        return 1;

    if (off == i)
        return 0;

    return -EINVAL;
}

static struct power_control_ops rtk_power_control_ops = {
    .power_on = rtk_power_on,
    .power_off = rtk_power_off,
    .is_powered_on = rtk_is_powered_on,
};

static void __rtk_powerctrl_reinit_clk(struct power_control *pctrl)
{
    struct rtk_powerctrl * ctrl = to_rtk_powerctrl(pctrl);
    struct device_node *np = pctrl->of_node;

    WARN_ON(ctrl->ref_clk);

    /* reference clock */
    ctrl->ref_clk = of_clk_get(np, 0);
    if (IS_ERR(ctrl->ref_clk))
        ctrl->ref_clk = NULL;
}

static int __init init_rtk_powerctrl_simple(struct device_node *np)
{
    struct rtk_powerctrl *ctrl;
    int size, i, ret;
    u32 temp[20];

    /* get size of array */
    size = of_property_count_u32_elems(np, "width");

    ctrl = kzalloc(sizeof(*ctrl) + sizeof(struct rtk_powerctrl_config) * size, GFP_KERNEL);
    if (!ctrl)
        return -ENOMEM;

    ctrl->size = size;
    ctrl->pctrl.ops   = &rtk_power_control_ops;
    ctrl->pctrl.name  = np->name;
    ctrl->pctrl.of_node = np;

    /* read propertise */
    for (i = 0 ; i < ctrl->size; i++)
        ctrl->config[i].reg = of_iomap(np, i);

    ret = of_property_read_u32_array(np, "width", temp, size);
    if (ret)
        goto err;
    for (i = 0 ; i < ctrl->size; i++)
        ctrl->config[i].width = temp[i];

    ret = of_property_read_u32_array(np, "shift", temp, size);
    if (ret)
        goto err;
    for (i = 0 ; i < ctrl->size; i++)
        ctrl->config[i].shift = temp[i];

    ret = of_property_read_u32_array(np, "on-value", temp, size);
    for (i = 0 ; i < ctrl->size; i++)
        ctrl->config[i].on_value = ret ? BIT(ctrl->config[i].width) - 1 : temp[i];

    ret = of_property_read_u32_array(np, "off-value", temp, size);
    for (i = 0 ; i < ctrl->size; i++)
        ctrl->config[i].off_value = ret ? 0 : temp[i];

    ret = of_property_read_u32_array(np, "state,on-value", temp, size);
    for (i = 0 ; i < ctrl->size; i++)
        ctrl->config[i].on_value_st = ret ? ctrl->config[i].on_value : temp[i];

    ret = of_property_read_u32_array(np, "state,off-value", temp, size);
    for (i = 0 ; i < ctrl->size; i++)
        ctrl->config[i].off_value_st = ret ? ctrl->config[i].off_value : temp[i];

    if (of_find_property(np, "is-l4-icg", NULL))
        ctrl->type = L4_ICG;
    else if (of_find_property(np, "is-analog", NULL))
        ctrl->type = ANALOG;

    /* reference clock */
    ctrl->ref_clk = of_clk_get(np, 0);
    if (IS_ERR(ctrl->ref_clk))
        ctrl->ref_clk = NULL;

    /* reference reset control */
    ctrl->ref_rstc = of_reset_control_get(np, NULL);
    if (IS_ERR(ctrl->ref_rstc))
        ctrl->ref_rstc = NULL;

    /* reference power control */
    ctrl->ref_pctrl = of_power_control_get(np, NULL);
    if (IS_ERR(ctrl->ref_pctrl))
        ctrl->ref_pctrl = NULL;

    /* use pctrl-name as name instead of node name*/
    if (of_property_read_string(np, "pctrl-name", &ctrl->pctrl.name)) {
        ctrl->pctrl.name  = np->name;
    }

    /* register */
    power_control_register(&ctrl->pctrl);

    /* set power state */
    rtk_powerctrl_generic_config(np, &ctrl->pctrl);

    /* save info for pm */
    rtk_powerctrl_pm_config(&ctrl->pctrl);

    return 0;
err:
    kfree(ctrl);
    return -EINVAL;
}

/********************************************************************************
 * rtk_powerctrl sram
 ********************************************************************************/
#define SRAM_MAX_RSTC 2

struct rtk_powerctrl_sram {
    struct power_control pctrl;
    void __iomem * addr_iso_cell;
    void __iomem * addr_sram_pwr3;
    void __iomem * addr_sram_pwr4;

    u32  sram_pwr4_on_value;
    u32  sram_pwr4_off_value;
    u32  iso_cell_shift;

    u32  rstc_num;
    struct reset_control *rstc[SRAM_MAX_RSTC];
};

#define to_rtk_powerctrl_sram(_p) container_of((_p), struct rtk_powerctrl_sram, pctrl)

static int rtk_sram_power_on(struct power_control *pctrl)
{
    struct rtk_powerctrl_sram * ctrl = to_rtk_powerctrl_sram(pctrl);
    u32 val;
    int i;

    rtk_powerctrl_lock();

    /* trigger power on */
    writel(ctrl->sram_pwr4_on_value, ctrl->addr_sram_pwr4);

    /* reset logic modules */
    for (i = 0; i < ctrl->rstc_num; i++)
        reset_control_assert(ctrl->rstc[i]);
    for (i = 0; i < ctrl->rstc_num; i++)
        reset_control_deassert(ctrl->rstc[i]);

    /* disable isolation cell */
    if (ctrl->addr_iso_cell) {
        val = readl(ctrl->addr_iso_cell);
        val &= ~BIT(ctrl->iso_cell_shift);
        writel(val, ctrl->addr_iso_cell);
    }

    rtk_powerctrl_unlock();

    return 0;
}

static int rtk_sram_power_off(struct power_control *pctrl)
{
    struct rtk_powerctrl_sram *ctrl = to_rtk_powerctrl_sram(pctrl);
    u32 val;

    rtk_powerctrl_lock();

    /* enable isolation cell */
    if (ctrl->addr_iso_cell) {
        val = readl(ctrl->addr_iso_cell);
        val |= BIT(ctrl->iso_cell_shift);
        writel(val, ctrl->addr_iso_cell);
    }

    /* set power-off auto mode */
    val = readl(ctrl->addr_sram_pwr3);
    val &= ~1;
    writel(val, ctrl->addr_sram_pwr3);

    /* trigger power-off */
    writel(ctrl->sram_pwr4_off_value, ctrl->addr_sram_pwr4);

    rtk_powerctrl_unlock();

    return 0;
}

static int rtk_sram_is_powered_on(struct power_control *pctrl)
{
    struct rtk_powerctrl_sram *ctrl = to_rtk_powerctrl_sram(pctrl);
    u32 val;
    int ret = -EINVAL;

    rtk_powerctrl_lock();

    val = readl(ctrl->addr_sram_pwr4);
    if ((val & 0x1) == (ctrl->sram_pwr4_off_value & 0x1))
        ret = 0;
    else if ((val & 0x1) == (ctrl->sram_pwr4_on_value & 0x1))
        ret = 1;

    rtk_powerctrl_unlock();

    return ret;
}

static struct power_control_ops rtk_power_control_sram_ops = {
    .power_on = rtk_sram_power_on,
    .power_off = rtk_sram_power_off,
    .is_powered_on = rtk_sram_is_powered_on,
};

static int __init init_rtk_powerctrl_sram(struct device_node *np)
{
    struct rtk_powerctrl_sram *ctrl;
    int i, num_of_names;

    /* get rtsc num */
    num_of_names = of_property_count_strings(np, "reset-names");
    if (num_of_names < 0) {
        num_of_names = 0;
    }
    BUG_ON(num_of_names > SRAM_MAX_RSTC);

    ctrl = kzalloc(sizeof(*ctrl), GFP_KERNEL);
    if (!ctrl)
        return -ENOMEM;

    ctrl->addr_iso_cell  = of_iomap(np, 0);
    ctrl->addr_sram_pwr3 = of_iomap(np, 1);
    ctrl->addr_sram_pwr4 = of_iomap(np, 2);
    ctrl->pctrl.ops   = &rtk_power_control_sram_ops;
    ctrl->pctrl.of_node = np;
    ctrl->rstc_num    = num_of_names;

    /* get properties */
    if (ctrl->addr_iso_cell && of_property_read_u32(np, "iso-cell-shift", &ctrl->iso_cell_shift))
        goto err;

    if (of_property_read_string(np, "pctrl-name", &ctrl->pctrl.name)) {
        ctrl->pctrl.name  = np->name;
    }

    if (of_property_read_u32(np, "sram-pwr4-on-value", &ctrl->sram_pwr4_on_value) ||
            of_property_read_u32(np, "sram-pwr4-off-value", &ctrl->sram_pwr4_off_value)) {
        ctrl->sram_pwr4_on_value = 0x00000f00;
        ctrl->sram_pwr4_off_value = 0x00000f01;
    }

    /* get reset control list */
    for (i = 0; i < num_of_names; i++) {
        const char * reset_name;
        if (!of_property_read_string_index(np, "reset-names", i, &reset_name)) {
            ctrl->rstc[i] = of_reset_control_get(np, reset_name);
            if (IS_ERR(ctrl->rstc)) {
                ctrl->rstc_num = i; // set current index for free mem
                pr_err("%s: get rstc failed, name = %s, index = %d\n", np->name, reset_name, i);
                goto err;
            }
        }
    }

    power_control_register(&ctrl->pctrl);

    /* set power state */
    rtk_powerctrl_generic_config(np, &ctrl->pctrl);

    /* save info for pm */
    rtk_powerctrl_pm_config(&ctrl->pctrl);
    return 0;

err:
    for (i = 0; i < ctrl->rstc_num; i++)
        kfree(ctrl->rstc[i]);
    kfree(ctrl);
    return -EINVAL;
}

/********************************************************************************
 * rtk_powerctrl gpu_core
 ********************************************************************************/
struct rtk_powerctrl_gpu_core {
    struct power_control pctrl;
    void __iomem * on_addr;
    void __iomem * off_addr;

    int last_call;

    u32  on_shift;
    u32  off_shift;
};

#define to_rtk_powerctrl_gpu_core(_p) container_of((_p), struct rtk_powerctrl_gpu_core, pctrl)

static int rtk_gpu_core_power_on(struct power_control * pctrl)
{
    struct rtk_powerctrl_gpu_core * ctrl = to_rtk_powerctrl_gpu_core(pctrl);
    u32 val;

    rtk_powerctrl_lock();

    ctrl->last_call = 1;

    val = readl(ctrl->on_addr);
    val |= 1 << ctrl->on_shift;
    writel(val, ctrl->on_addr);

    rtk_powerctrl_unlock();

    return 0;
}

static int rtk_gpu_core_power_off(struct power_control * pctrl)
{
    struct rtk_powerctrl_gpu_core * ctrl = to_rtk_powerctrl_gpu_core(pctrl);
    u32 val;

    rtk_powerctrl_lock();

    ctrl->last_call = 0;

    val = readl(ctrl->off_addr);
    val |= 1 << ctrl->off_shift;
    writel(val, ctrl->off_addr);

    rtk_powerctrl_unlock();

    return 0;
}

static int rtk_gpu_core_is_powered_on(struct power_control * pctrl)
{
    struct rtk_powerctrl_gpu_core * ctrl = to_rtk_powerctrl_gpu_core(pctrl);
    int ret;

    rtk_powerctrl_lock();
    ret = ctrl->last_call;
    rtk_powerctrl_unlock();

    return ret;
}

static struct power_control_ops rtk_power_control_gpu_core_ops = {
    .power_on = rtk_gpu_core_power_on,
    .power_off = rtk_gpu_core_power_off,
    .is_powered_on = rtk_gpu_core_is_powered_on,
};

static int __init init_rtk_powerctrl_gpu_core(struct device_node *np)
{
    struct rtk_powerctrl_gpu_core *ctrl;

    ctrl = kzalloc(sizeof(*ctrl), GFP_KERNEL);

    ctrl->on_addr     = of_iomap(np, 0);
    ctrl->off_addr    = of_iomap(np, 1);
    ctrl->pctrl.of_node = np;
    ctrl->pctrl.ops   = &rtk_power_control_gpu_core_ops;

    /* get properties */
    if (of_property_read_u32(np, "on-shift", &ctrl->on_shift) ||
            of_property_read_u32(np, "off-shift", &ctrl->off_shift))
        goto err;

    if (of_property_read_string(np, "pctrl-name", &ctrl->pctrl.name)) {
        ctrl->pctrl.name  = np->name;
    }

    power_control_register(&ctrl->pctrl);

    /* set power state */
    rtk_powerctrl_generic_config(np, &ctrl->pctrl);

    /* save info for pm */
    rtk_powerctrl_pm_config(&ctrl->pctrl);
    return 0;
err:
    kfree(ctrl);
    return -EINVAL;
}

/********************************************************************************
 * rtk_powerctrl set_on_boot
 ********************************************************************************/
/**
 * power off the devices that are already using reset controller & common
 *   clk framework in their drivers. this is a one-time thing, so there is
 *   no powerctrl created.
 */
static __init int init_rtk_powerctrl_once(struct device_node *np)
{
    void __iomem * reg = of_iomap(np, 0);
    int ret = 0;
    u32 mask;
    u32 val, old_val;

    if (of_property_read_u32(np, "mask", &mask)) {
        pr_err("can't read mask for node %s\n", np->name);
        ret = -EINVAL;
        goto out;
    }

    if (of_get_power_state(np) == POWER_OFF) {
        val = readl(reg);
        old_val = val;
        val &= ~mask; // clean bits
        writel(val, reg);

        pr_info("addr: 0x%08x [0x%08x -> 0x%08x], bit-diff = 0x%08x, mask = 0x%08x\n",
                (u32)(long)reg, old_val, val, old_val ^ val, mask);
    }

out:
    of_node_put(np);
    return ret;
}

static void rtk_powerctrl_manager(struct work_struct *work)
{
    int ret;
    struct list_head * it = NULL;

    pr_info("%s: begin\n", __func__);

    list_for_each(it, &managed_pctrl_list) {
        struct power_control *pctrl = list_entry(it, struct managed_pctrl, list)->pctrl;
        int target = IGNORE;
        int ref_cnt = of_count_available_reference_devices(pctrl->of_node);
        int is_l4_icg = 0;

        if (of_device_is_compatible(pctrl->of_node, "realtek,powerctrl-simple")) {
            int is_analog = of_powerctrl_is_analog(pctrl->of_node);
            is_l4_icg = of_powerctrl_is_l4_icg(pctrl->of_node);

            /* get clk again*/
            __rtk_powerctrl_reinit_clk(pctrl);

            /* ref_cnt < 0:
             *     no reference device_node is set
             *     => try to ENABLE_HW_PM
             *
             * ref_cnt > 0:
             *     reference device_node is available
             *     => ENABLE_HW_PM
             */
            if (is_l4_icg) {
                if (ref_cnt == 0)
                    continue;
                else
                    target = POWER_OFF;
            } else if (is_analog) {
                if (ref_cnt > 0)
                    continue;

                if (__rtk_powerctrl_check_reference(to_rtk_powerctrl(pctrl)))
                    target = POWER_OFF;
            }
        } else {
            /* ref_cnt == 0:
             *     no reference device_node is available
             *     => POWER_OFF
             */
            if (ref_cnt == 0)
                target = POWER_OFF;
        }

        if (target == POWER_OFF && power_control_is_powered_on(pctrl) != 0) {
            ret = power_control_power_off(pctrl);
            pr_info("%s::%s, ret = %d\n", pctrl->name, power_off_str[is_l4_icg], ret);
        }

        mdelay(5);
    }

    pr_info("%s: done\n", __func__);
}

static DECLARE_DELAYED_WORK(rtk_powercontrol_manager_work, rtk_powerctrl_manager);

static const struct of_device_id rtk_powerctrl_match[] = {
    {.compatible = "realtek,powerctrl-once",      .data = init_rtk_powerctrl_once},
    {.compatible = "realtek,powerctrl-simple",    .data = init_rtk_powerctrl_simple},
    {.compatible = "realtek,powerctrl-sram",      .data = init_rtk_powerctrl_sram},
    {.compatible = "realtek,powerctrl-gpu-core",  .data = init_rtk_powerctrl_gpu_core},
#ifdef CONFIG_RTK_POWERCTRL_TIMER
    {.compatible = "realtek,powerctrl-timer", .data = init_rtk_powerctrl_timer},
#endif
    {}
};

static int __init rtk_init_powerctrl(void)
{
    struct device_node *np;
    const struct of_device_id *match;
    int ret = 0;
    int chip_rev = get_rtd129x_cpu_revision() >> 16;

#ifdef CONFIG_POWER_CONTROL_RTD129X_DEBUGFS
    power_control_root = debugfs_create_dir("rtk_power_control", NULL);
#endif

    for_each_matching_node_and_match(np, rtk_powerctrl_match, &match) {
        int (*func)(struct device_node *) = match->data;

        if (!of_device_is_available(np))
            continue;

        if (!of_check_revision(np, chip_rev)) {
            pr_info("%s: rev not match\n", np->name);
            continue;
        }

        BUG_ON(!func);
        ret = func(np);
        if (ret)
            pr_err("Failed to init %s, ret = %d\n", np->name, ret);
    }

    rtk_powerctrl_workqueue = create_workqueue("powerctrl");
    queue_delayed_work(rtk_powerctrl_workqueue,
                       &rtk_powercontrol_manager_work, DELAY_TIME_SEC * HZ);

#ifdef CONFIG_PM
    cpu_pm_register_notifier(&pm_notifier_block);
#endif

    return 0;
}
early_initcall(rtk_init_powerctrl);
