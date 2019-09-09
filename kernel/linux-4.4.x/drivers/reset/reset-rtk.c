#define pr_fmt(fmt) "reset-rtk: " fmt

#include <linux/reset-controller.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/reset.h>
#include <linux/reset-helper.h>

//#include <asm-generic/io.h>
#include <asm/io.h>    //use asm/io.h instead

#include <linux/cpu_pm.h>
#include <linux/suspend.h>

#ifdef CONFIG_PM

struct pm_priv_data {
    struct list_head list;
    void __iomem * reg;
    u32 mask;
    u32 value;
};

static LIST_HEAD(pm_data_list);

static inline int rtk_rstn_pm_config(void __iomem *reg, u32  mask)
{
    struct pm_priv_data *saved_rstn = kzalloc(sizeof(*saved_rstn), GFP_KERNEL);

    if (!saved_rstn)
        return -EINVAL;

    saved_rstn->reg  = reg;
    saved_rstn->mask = mask;
    list_add(&saved_rstn->list, &pm_data_list);
    return 0;
}

static inline int rtk_rstn_pm_store(void)
{
    struct list_head * it = NULL;

    if (RTK_PM_STATE == PM_SUSPEND_STANDBY)
        return 0;

    list_for_each(it, &pm_data_list) {
        struct pm_priv_data *saved_rstn =
            list_entry(it, struct pm_priv_data, list);
        saved_rstn->value = readl(saved_rstn->reg);
        pr_debug("a = 0x%08x v = 0x%08x\n", (u32)(unsigned long)saved_rstn->reg, saved_rstn->value);
    }

    return 0;
}

static inline int rtk_rstn_pm_restore(void)
{
    struct list_head * it = NULL;

    if (RTK_PM_STATE == PM_SUSPEND_STANDBY)
        return 0;

    list_for_each_prev(it, &pm_data_list) {
        struct pm_priv_data *saved_rstn =
            list_entry(it, struct pm_priv_data, list);
        u32 val = readl(saved_rstn->reg);
        u32 val_o = val;

        val &= ~saved_rstn->mask;
        val |= saved_rstn->mask & saved_rstn->value;
        writel(val, saved_rstn->reg);
        pr_debug("a = 0x%08x d = 0x%08x -> 0x%08x | v = 0x%08x, m = 0x%08x\n",
                 (u32)(unsigned long)saved_rstn->reg, val_o, val, saved_rstn->value, saved_rstn->mask
                );
    }
    return 0;
}

static int rtk_rstn_pm_notify(struct notifier_block *notify_block, unsigned long mode, void *unused)
{
    switch (mode) {
    case CPU_CLUSTER_PM_ENTER:
        printk(KERN_INFO "[RESET] Enter %s, act = CPU_CLUSTER_PM_ENTER\n", __func__);
        rtk_rstn_pm_store();
        printk(KERN_INFO "[RESET] Exit %s,  act = CPU_CLUSTER_PM_ENTER\n", __func__);
        break;
    case CPU_CLUSTER_PM_EXIT:
        printk(KERN_INFO "[RESET] Enter %s, act = CPU_CLUSTER_PM_EXIT\n", __func__);
        rtk_rstn_pm_restore();
        printk(KERN_INFO "[RESET] Exit %s,  act = CPU_CLUSTER_PM_EXIT\n", __func__);
        break;
    default:
        break;
    }
    return NOTIFY_OK;
}
static struct notifier_block pm_notifier_block = {
    .notifier_call = rtk_rstn_pm_notify,
};

#endif /* CONFIG_PM */

DEFINE_MUTEX(rtk_rstc_mutex);

#define USB_APPLY_NUM 0x100

enum {RESET_GENERAL = 0, RESET_GROUPED, RESET_USB };

struct reset_data {
    void __iomem *reg;
    struct reset_controller_dev rcdev;
    u32 type;
    u32 data[2];
};

#define to_reset_data(_p) container_of((_p), struct reset_data, rcdev)

static int rtk_reset_assert(struct reset_controller_dev *rcdev,
                            unsigned long id)
{
    struct reset_data *data = to_reset_data(rcdev);
    u32 val, val_old, mask;
    void __iomem *reg = data->reg;

    switch (data->type) {
    case RESET_USB:
        if (id == USB_APPLY_NUM)
            return -EINVAL;

        if (id >= 32) {
            reg += (id / 32) * 4;
            id %= 32;
        }
    case RESET_GENERAL:
    case RESET_GROUPED:
        mask = data->type == RESET_GROUPED ? id : BIT(id);

        mutex_lock(&rtk_rstc_mutex);
        val_old = val = readl(reg);
        val &= ~mask;
        writel(val, reg);
        mutex_unlock(&rtk_rstc_mutex);

        pr_info("ASSERT      0x%08x [0x%08x -> 0x%08x] D 0x%08x, M 0x%08x\n",
                (u32)(long)reg, val_old, val, val_old ^ val, mask);
        break;
    } /* switch (data->type) */

    return 0;
}

static int rtk_reset_deassert(struct reset_controller_dev *rcdev,
                              unsigned long id)
{
    struct reset_data *data = to_reset_data(rcdev);
    u32 val, val_old, mask;
    void __iomem *reg = data->reg;

    switch (data->type) {
    case RESET_GENERAL:
    case RESET_GROUPED:
        mask = data->type == RESET_GROUPED ? id : BIT(id);

        mutex_lock(&rtk_rstc_mutex);
        val_old = val = readl(reg);
        val |= mask;
        writel(val, reg);
        mutex_unlock(&rtk_rstc_mutex);

        pr_info("DEASSERT    0x%08x [0x%08x -> 0x%08x] D 0x%08x, M 0x%08x\n",
                (u32)(long)reg, val_old, val, val_old ^ val, mask);
        break;

    case RESET_USB:
        mutex_lock(&rtk_rstc_mutex);

        /* when id is 0xffffffff, write to memory */
        if (id == USB_APPLY_NUM) {
            int i;
            for (i = 0; i < 2; i++) {
                mask = data->data[i];

                if (mask) {
                    val_old = val = readl(reg);
                    val |= mask;
                    writel(val, reg);
                }

                reg += 4;
            }

            data->data[0] = data->data[1] = 0;
        } else {
            data->data[id / 32] |= BIT(id % 32);
        }

        mutex_unlock(&rtk_rstc_mutex);
        break;
    } /* switch (data->type) */

    return 0;
}

static int rtk_reset_reset(struct reset_controller_dev *rcdev,
                           unsigned long id)
{
    int ret;

    ret = rtk_reset_assert(rcdev, id);
    if (ret)
        return ret;

    return rtk_reset_deassert(rcdev, id);
}

static int rtk_reset_status(struct reset_controller_dev *rcdev,
                            unsigned long id)
{
    struct reset_data *data = to_reset_data(rcdev);
    u32 val;
    void __iomem * reg = data->reg;

    if (id >= 64)
        return -EINVAL;

    if (id >= 32) {
        id -= 32;
        reg += 4;
    }

    mutex_lock(&rtk_rstc_mutex);
    val = readl(reg);
    mutex_unlock(&rtk_rstc_mutex);

    if (data->type == RESET_GROUPED) {
        if ((val & id) == id)
            return 0;
        else if ((val & id) == 0)
            return 1;
        else
            return -EINVAL;
    }
    else
        return !(val & BIT(id));
}

static struct reset_control_ops rtk_reset_ops = {
    .assert     = rtk_reset_assert,
    .deassert   = rtk_reset_deassert,
    .reset      = rtk_reset_reset,
    .status     = rtk_reset_status,
};

static int rtl_reset_of_xlate(struct reset_controller_dev *rcdev,
                              const struct of_phandle_args *reset_spec)
{
    struct reset_data __maybe_unused *data = to_reset_data(rcdev);
    int id;

    if (reset_spec->args_count != 1)
        return -EINVAL;

    id = (int)reset_spec->args[0];
    return id;
}

static int __init init_rtk_reset_controller(struct device_node *np)
{
    struct reset_data * data;

    data = kzalloc(sizeof(struct reset_data), GFP_KERNEL);
    if (!data)
        return -ENOMEM;

    data->reg = of_iomap(np, 0);
    data->rcdev.owner = THIS_MODULE;
    data->rcdev.ops   = &rtk_reset_ops;
    data->rcdev.of_node = np;
    data->rcdev.of_reset_n_cells = 2;
    data->rcdev.of_xlate = rtl_reset_of_xlate;

    if (of_find_property(np, "is-grouped", NULL))
        data->type = RESET_GROUPED;
    else if (of_find_property(np, "is-usb", NULL))
        data->type = RESET_USB;
    else
        data->type = RESET_GENERAL;

    reset_controller_register(&data->rcdev);

#ifdef CONFIG_PM
    if (!of_find_property(np, "ignore-in-pm", NULL))
        rtk_rstn_pm_config(data->reg, 0xffffffff);
#endif

    return 0;
}

static int __init init_rtk_reset_control(struct device_node *node)
{
    int num_of_names = of_property_count_strings(node, "reset-names");
    int i;

    for (i = 0; i < num_of_names; ++i) {
        const char * reset_name;
        if (!of_property_read_string_index(node, "reset-names", i, &reset_name))
        {
            struct reset_control * rstc = of_reset_control_get(node, reset_name);
            if (!IS_ERR(rstc))
            {
                int ret = rstc_add(rstc, reset_name);
                if (ret)
                    reset_control_put(rstc);
            }
        }
    }

    return 0;
}

static const struct of_device_id rtk_reset_match[] = {
    {.compatible = "realtek,129x-soft-reset",},
    {}
};

static const struct of_device_id rtk_rtsc_init_match[] = {
    {.compatible = "realtek,129x-rstc-init",},
    {}
};

static int __init rtk_init_reset(void)
{
    struct device_node *np;

    for_each_matching_node(np, rtk_reset_match) {
        init_rtk_reset_controller(np);
    }

    for_each_matching_node(np, rtk_rtsc_init_match) {
        init_rtk_reset_control(np);
    }

#ifdef CONFIG_PM
    cpu_pm_register_notifier(&pm_notifier_block);
#endif

    return 0;
}
early_initcall(rtk_init_reset);
