/*
 * clk-rtd129x.c - Common clock framework implementation for RTD-129x
 *
 * Copyright (C) 2016, Realtek Semiconductor Corporation
 *
 * Author: Cheng-Yu Lee <cylee12@realtek.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#define pr_fmt(fmt) "clk-rtk: " fmt

#include <linux/slab.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/clk.h>
#include <linux/clkdev.h>
#include <linux/clk-provider.h>
#include <linux/delay.h>
#include <linux/cpu_pm.h>
#include <linux/suspend.h>
#include <linux/list.h>
#include <linux/bitops.h>
#include <linux/debugfs.h>
#include <asm/uaccess.h>
#include "clk-generic.h"

#define CLK_IS_RAW         BIT(0)
#define CLK_HAS_MUX        BIT(1)
#define CLK_HAS_RATE       BIT(2)
#define CLK_HAS_RATE_RW    BIT(3)
#define CLK_HAS_GATE       BIT(4)
#define CLK_IS_COMPOSITE   BIT(5)
#define CLK_NO_PARENT      BIT(6)

struct pll_scpu_extension {
    struct clk_factor clk_f;
    struct clk_factor_config oc_en;
    struct clk_factor_config oc_done;
    const int *tr_table;
    const int *tr_point;
};

#define to_pll_scpu_extension(_p) container_of(_p, struct pll_scpu_extension, clk_f)

#define SCPU_FACTOR_TO_DATA(_n, _f, _d, _data) \
    _data = ((((_n) & 0xff) << 24) | (((_f) & 0xffff) << 8) | ((_d) & 0xff))

#define SCPU_DATA_TRANSLATE(_data, _p) \
    _data = (_data) ^ *((_p) + 1);

#define SCPU_DATA_TO_FACTOR(_data, _n, _f, _d) \
    do { \
        _d = (_data) & 0xff; \
        _f = ((_data) >> 8) & 0xffff;\
        _n = ((_data) >> 24); \
    } while (0);

struct pll_gpu_extension {
    struct clk_factor clk_f;
    struct clk_factor_config oc_en;
};

#define to_pll_gpu_extension(_p) container_of(_p, struct pll_gpu_extension, clk_f)

#define to_clk_composite(_hw) container_of(_hw, struct clk_composite, hw)
#define to_clk_mux(_hw) container_of(_hw, struct clk_mux, hw)
#define to_clk_gate(_hw) container_of(_hw, struct clk_gate, hw)
#define to_clk_fixed_factor(_hw) container_of(_hw, struct clk_fixed_factor, hw)
#define to_clk_fixed_rate(_hw) container_of(_hw, struct clk_fixed_rate, hw)

static DEFINE_SPINLOCK(clk_lock);

#ifdef CONFIG_PM

struct clk_pm_generic {
    struct list_head list;
    unsigned int type;
};

struct clk_pm_raw {
    struct clk_pm_generic generic;
    void __iomem * reg;
    u32 mask;
    u32 value;
};

struct clk_pm_data {
    struct clk_pm_generic generic;
    struct clk *clk;
    struct clk *parent;
    unsigned long rate;
    bool enable;
};

static LIST_HEAD(pm_data_list);

static inline void rtk_clk_pm_config_raw(void __iomem *reg, u32 mask)
{
    struct clk_pm_raw *priv = kzalloc(sizeof(*priv), GFP_KERNEL);
    if (priv) {
        priv->generic.type = CLK_IS_RAW;
        list_add(&priv->generic.list, &pm_data_list);
        priv->reg  = reg;
        priv->mask = mask;
    }
}

static inline void rtk_clk_pm_config_data(struct clk *clk, u32 type)
{
    struct clk_pm_data *priv = kzalloc(sizeof(*priv), GFP_KERNEL);
    if (priv) {
        priv->generic.type = type;
        list_add(&priv->generic.list, &pm_data_list);
        priv->clk = clk;
    }
}

static inline int rtk_clk_pm_store(void)
{
    struct list_head * it = NULL;
#ifdef CONFIG_SUSPEND
    if (RTK_PM_STATE == PM_SUSPEND_STANDBY)
        return 0;
#endif
    list_for_each(it, &pm_data_list) {
        struct clk_pm_generic *generic =
            list_entry(it, struct clk_pm_generic, list);

        if ((generic->type & CLK_IS_RAW) != CLK_IS_RAW) {
            struct clk_pm_data *priv =
                container_of(generic, struct clk_pm_data, generic);

            if ((generic->type & CLK_HAS_MUX) == CLK_HAS_MUX)
                priv->parent = clk_get_parent(priv->clk);

            if ((generic->type & CLK_HAS_RATE_RW) == CLK_HAS_RATE_RW)
                priv->rate = clk_get_rate(priv->clk);

            if ((generic->type & CLK_HAS_GATE) == CLK_HAS_GATE)
                priv->enable = __clk_is_enabled(priv->clk);
        } else {
            struct clk_pm_raw *priv =
                container_of(generic, struct clk_pm_raw, generic);

            spin_lock(&clk_lock);
            priv->value = readl(priv->reg);
            spin_unlock(&clk_lock);

            pr_debug("A 0x%08x V 0x%08x\n",
                     (u32)(unsigned long)priv->reg, priv->value);
        }
    }

    return 0;
}

static inline int rtk_clk_pm_restore(void)
{
    struct list_head * it = NULL;
#ifdef CONFIG_SUSPEND
    if (RTK_PM_STATE == PM_SUSPEND_STANDBY)
        return 0;
#endif
    list_for_each_prev(it, &pm_data_list) {
        struct clk_pm_generic *generic =
            list_entry(it, struct clk_pm_generic, list);

        if ((generic->type & CLK_IS_RAW) != CLK_IS_RAW) {
            struct clk_pm_data *priv =
                container_of(generic, struct clk_pm_data, generic);

            if ((generic->type & CLK_HAS_MUX) == CLK_HAS_MUX)
                clk_set_parent(priv->clk, priv->parent);

            if ((generic->type & CLK_HAS_RATE_RW) == CLK_HAS_RATE_RW)
                clk_set_rate(priv->clk, priv->rate);

            if ((generic->type & CLK_HAS_GATE) == CLK_HAS_GATE) {
                struct clk_hw *hw = __clk_get_hw(priv->clk);
                struct clk_gate *clk_g;
                u32 val;

                /* for clk_composite */
                if ((generic->type & CLK_IS_COMPOSITE) == CLK_IS_COMPOSITE)
                    hw = ((struct clk_composite *)to_clk_composite(hw))->gate_hw;

                clk_g = to_clk_gate(hw);

                spin_lock(&clk_lock);
                val = readl(clk_g->reg);
                val &= ~(1 << clk_g->bit_idx);
                val |= priv->enable << clk_g->bit_idx;
                writel(val, clk_g->reg);
                spin_unlock(&clk_lock);
            }

        } else {
            struct clk_pm_raw *priv =
                container_of(generic, struct clk_pm_raw, generic);
            u32 val, _val;

            spin_lock(&clk_lock);
            _val = val= readl(priv->reg);
            val &= ~priv->mask;
            val |= priv->value & priv->mask;
            writel(val, priv->reg);
            spin_unlock(&clk_lock);

            pr_debug("A 0x%08x V 0x%08x -> 0x%08x | S 0x%08x, M 0x%08x\n",
                     (u32)(unsigned long)priv->reg, _val, val, priv->value, priv->mask);
        }
    }
    return 0;
}

static int rtk_clk_pm_notify(struct notifier_block *notify_block, unsigned long mode, void *unused)
{
    switch (mode) {
    case CPU_CLUSTER_PM_ENTER:
        printk(KERN_INFO "[CLK] Enter %s, act = CPU_CLUSTER_IS_ENTER\n", __func__);
        rtk_clk_pm_store();
        printk(KERN_INFO "[CLK] Exit %s,  act = CPU_CLUSTER_IS_ENTER\n", __func__);
        break;
    case CPU_CLUSTER_PM_EXIT:
        printk(KERN_INFO "[CLK] Enter %s, act = CPU_CLUSTER_IS_EXIT\n", __func__);
        rtk_clk_pm_restore();
        printk(KERN_INFO "[CLK] Exit %s,  act = CPU_CLUSTER_IS_EXIT\n", __func__);
        break;
    default:
        break;
    }
    return NOTIFY_OK;
}

static struct notifier_block pm_notifier_block = {
    .notifier_call = rtk_clk_pm_notify,
};

#endif /* CONFIG_PM */

#ifdef CONFIG_COMMON_CLK_RTD129X_DEBUGFS

/*
 * To simplify the debugfs code for RTD1x9x clocks, a struct is defined to
 * identify which file is accessed. It helps to implement to the files of debugfs
 * with only a single file operation. But the allocated memory is only bind in
 * the file of debugfs. Therefore, it should be handled if the file is removable.
 * Each struct member carries an enum to identify which debugfs file is accessed
 * and help to get the source clock structure.
 */
enum clk_debugfs_id {
    CLK_DEBUGFS_NAME,
    CLK_DEBUGFS_RATE,
    CLK_DEBUGFS_PARENT,
    CLK_DEBUGFS_ENABLE,
};

struct clk_debugfs {
    struct clk *clk;
    int name;
    int rate;
    int parent;
    int enable;
};

#define name_to_clk(_p)     container_of(_p, struct clk_debugfs, name)->clk
#define rate_to_clk(_p)     container_of(_p, struct clk_debugfs, rate)->clk
#define parent_to_clk(_p)   container_of(_p, struct clk_debugfs, parent)->clk
#define enable_to_clk(_p)   container_of(_p, struct clk_debugfs, enable)->clk

static int clk_debugfs_show(struct seq_file *s, void *v)
{
    int *code = (int *)s->private;
    struct clk *clk;

    switch(*code) {
    case CLK_DEBUGFS_NAME:
        clk = name_to_clk(code);
        seq_printf(s, "%s\n", __clk_get_name(clk));
        break;

    case CLK_DEBUGFS_RATE:
        clk = rate_to_clk(code);
        seq_printf(s, "%lu\n", clk_get_rate(clk));
        break;

    case CLK_DEBUGFS_PARENT:
        clk = parent_to_clk(code);
        clk = clk_get_parent(clk);
        seq_printf(s, "%s\n", clk == NULL ? "(no parent)" : __clk_get_name(clk));
        break;

    case CLK_DEBUGFS_ENABLE:
        clk = enable_to_clk(code);
        seq_printf(s, "%d\n", __clk_is_enabled(clk));
        break;
    }

    return 0;
}

static int clk_debugfs_open(struct inode *inode, struct file *filp)
{
    return single_open(filp, clk_debugfs_show, inode->i_private);
}

static ssize_t clk_debugfs_write(struct file *filp, const char __user *buf,
                                 size_t count, loff_t *f_pos)
{
    int *code = filp->f_inode->i_private;
    struct clk *clk;
    char kbuf[40];
    int ret;

    bool enable;
    struct clk *parent;
    unsigned long rate;
    char *endp;

    if (count > 40)
        return -EINVAL;

    ret = copy_from_user(kbuf, buf, count);
    if (ret)
        goto error;

    switch(*code) {
    default:
    case CLK_DEBUGFS_NAME:
        ret = -EINVAL;
        goto error;

    case CLK_DEBUGFS_RATE:
        clk = rate_to_clk(code);
        rate = simple_strtoul(kbuf, &endp, 10);
        clk_set_rate(clk, rate);
        break;

    case CLK_DEBUGFS_PARENT:
        clk = parent_to_clk(code);
        parent = clk_get(NULL, kbuf);
        if (parent) {
            clk_set_parent(clk, parent);
            clk_put(parent);
        }
        break;

    case CLK_DEBUGFS_ENABLE:
        clk = enable_to_clk(code);
        ret = strtobool(kbuf, &enable);
        if (ret)
            goto error;

        if (enable)
            clk_prepare_enable(clk);
        else
            clk_disable_unprepare(clk);

        break;
    }

    return count;
error:
    return ret;
}

const struct file_operations clk_debugfs_fops = {
    .owner   = THIS_MODULE,
    .open    = clk_debugfs_open,
    .read    = seq_read,
    .write   = clk_debugfs_write,
    .release = single_release,
};

static int clk_debugfs_create_files(struct clk *clk, struct dentry *parent,
                                    unsigned long clk_type)
{
    if (clk_type) {
        struct clk_debugfs *clk_d = kmalloc(sizeof(*clk_d), GFP_KERNEL);

        clk_d->clk = clk;
        clk_d->name = CLK_DEBUGFS_NAME;
        clk_d->rate = CLK_DEBUGFS_RATE;
        clk_d->parent = CLK_DEBUGFS_PARENT;
        clk_d->enable = CLK_DEBUGFS_ENABLE;

        debugfs_create_file("clk_name", 0444, parent, &clk_d->name,
                            &clk_debugfs_fops);

        if ((clk_type & CLK_NO_PARENT) != CLK_NO_PARENT) {
            debugfs_create_file("clk_parent",
                                (clk_type & CLK_HAS_MUX) == CLK_HAS_MUX ? 0644 : 0444,
                                parent, &clk_d->parent, &clk_debugfs_fops);
        }

        if ((clk_type & CLK_NO_PARENT) != CLK_NO_PARENT ||
                (clk_type & CLK_HAS_RATE) == CLK_HAS_RATE) {
            debugfs_create_file("clk_rate",
                                (clk_type & CLK_HAS_RATE_RW) == CLK_HAS_RATE_RW ? 0644 : 0444,
                                parent, &clk_d->rate, &clk_debugfs_fops);
        }

        if ((clk_type & CLK_HAS_GATE) == CLK_HAS_GATE) {
            debugfs_create_file("clk_enable", 0644, parent, &clk_d->enable,
                                &clk_debugfs_fops);
        }
    }

    return 0;
}

static struct dentry *clk_debugfs_root;

#endif

static int generic_read_factors(struct clk_factor *clk_f)
{
    int i;
    for (i = 0; i < clk_f->n_factors; i++) {
        clk_f->factors[i].cur = clk_factor_read_factor(&clk_f->factors[i]);
    }
    return 0;
}

static int generic_write_factors(struct clk_factor *clk_f)
{
    int i;
    for (i = 0; i < clk_f->n_factors; i++) {
        clk_factor_write_factor(&clk_f->factors[i], clk_f->factors[i].cur);
    }
    return 0;
}

static int generic_nf_calc_rate(struct clk_factor *clk_f,
                                unsigned long *rate, unsigned long parent_rate)
{
    struct clk_factor_config *n = &clk_f->factors[0];
    struct clk_factor_config *f = &clk_f->factors[1];

    *rate = (n->cur + 3) * parent_rate + parent_rate * f->cur / 2048;

    pr_debug("%s: n=%d,f=%d,rate=%lu\n", __func__,
             n->cur, f->cur, *rate);

    return 0;
}

/**
 *  generic_nf_recalc_factors
 *
 *    Target = parent_rate * (N + 3 + F / 2048)
 */
static int generic_nf_recalc_factors(struct clk_factor *clk_f,
                                     unsigned long *rate, unsigned long parent_rate)
{
    struct clk_factor_config *n = &clk_f->factors[0];
    struct clk_factor_config *f = &clk_f->factors[1];

    clk_factor_verify_target_rate(clk_f, rate);

    n->cur = *rate / parent_rate - 3;
    f->cur = (*rate % parent_rate) * 2048 / parent_rate;

    pr_debug("%s:\n", __func__);
    generic_nf_calc_rate(clk_f, rate, parent_rate);

    return 0;
}

const struct clk_factor_ops realtek_129x_pll_nf_ops = {
    .calc_rate      = generic_nf_calc_rate,
    .recalc_factors = generic_nf_recalc_factors,
    .read_factors   = generic_read_factors,
    .write_factors  = generic_write_factors,
};

static int generic_mno_calc_rate(struct clk_factor *clk_f,
                                 unsigned long *rate, unsigned long parent_rate)
{
    struct clk_factor_config *m = &clk_f->factors[0];
    struct clk_factor_config *n = &clk_f->factors[1];
    struct clk_factor_config *o = &clk_f->factors[2];

    *rate = parent_rate * (m->cur + 2) / (n->cur + 1) / (o->cur + 1);

    pr_debug("%s: m=%d,n=%d,o=%d,rate=%lu\n", __func__,
             m->cur, n->cur, o->cur, *rate);

    return 0;
}

/**
 *  generic_mno_recalc_factors
 *
 *    Target = parent_rate * (M+2) / (N+1) / (O+1)
 */
static int generic_mno_recalc_factors(struct clk_factor *clk_f,
                                      unsigned long *rate, unsigned long parent_rate)
{
    struct clk_factor_config *m = &clk_f->factors[0];
    struct clk_factor_config *n = &clk_f->factors[1];
    struct clk_factor_config *o = &clk_f->factors[2];
    int i, j, k;

    unsigned long best = 0, curr;

    clk_factor_verify_target_rate(clk_f, rate);

    for (i = o->min; i <= o->max; i++)
        for (j = n->min; j <= n->max; j++)
            for (k = m->min; k <= m->max; k++) {
                curr = parent_rate * (k+2) / (j+1) / (i+1);

                if (curr <= *rate && (*rate - curr) < (*rate - best)) {
                    best = curr;
                    m->cur = k;
                    n->cur = j;
                    o->cur = i;

                    if (best == *rate)
                        goto done;
                }

                if (curr > *rate)
                    break;
            }
done:
    *rate = best;

    return 0;
}

const struct clk_factor_ops realtek_129x_pll_mno_ops = {
    .calc_rate      = generic_mno_calc_rate,
    .recalc_factors = generic_mno_recalc_factors,
    .read_factors   = generic_read_factors,
    .write_factors  = generic_write_factors,
};

static int realtek_129x_pll_scpu_calc_rate(struct clk_factor *clk_f,
        unsigned long *rate, unsigned long parent_rate)
{
    struct pll_scpu_extension *scpu = to_pll_scpu_extension(clk_f);
    struct clk_factor_config *n = &clk_f->factors[0];
    struct clk_factor_config *f = &clk_f->factors[1];
    struct clk_factor_config *d = &clk_f->factors[2];
    int div;
    unsigned int data;

    SCPU_FACTOR_TO_DATA(n->cur, f->cur, d->cur, data);

    if (scpu->tr_table && scpu->tr_point) {
        unsigned int tr_data = data;

        SCPU_DATA_TRANSLATE(tr_data, scpu->tr_point);
        SCPU_DATA_TO_FACTOR(tr_data, n->cur, f->cur, d->cur);
    }

    div = d->cur == 3 ? 4 : (d->cur == 2 ? 2 : 1);
    *rate = ((n->cur + 3) * parent_rate + parent_rate * f->cur / 2048) / div;

    SCPU_DATA_TO_FACTOR(data, n->cur, f->cur, d->cur);

    return 0;
}

static int realtek_129x_pll_scpu_recalc_factors(struct clk_factor *clk_f,
        unsigned long *rate, unsigned long parent_rate)
{
    struct pll_scpu_extension *scpu = to_pll_scpu_extension(clk_f);
    struct clk_factor_config *n = &clk_f->factors[0];
    struct clk_factor_config *f = &clk_f->factors[1];
    struct clk_factor_config *d = &clk_f->factors[2];
    unsigned long target = *rate;

    clk_factor_verify_target_rate(clk_f, &target);

    if (target >= 1000000000) {
        d->cur = 1;
    } else if (target >= 500000000) {
        d->cur = 2;
        target *= 2;
    } else {
        d->cur = 3;
        target *= 4;
    }

    n->cur = target / parent_rate - 3;
    target %= parent_rate;
    f->cur = (target * 2048) / parent_rate;

    // check for safety
    if (scpu->tr_table) {
        unsigned int data;
        const int *p = scpu->tr_table;

        SCPU_FACTOR_TO_DATA(n->cur, f->cur, d->cur, data);
        scpu->tr_point = NULL;
        while (*p != 0) {
            if (*p == data) {
                scpu->tr_point = p;
                SCPU_DATA_TRANSLATE(data, p);
                SCPU_DATA_TO_FACTOR(data, n->cur, f->cur, d->cur);
                break;
            }
            p += 2;
        }
    }

    realtek_129x_pll_scpu_calc_rate(clk_f, rate, parent_rate);

    pr_debug("%s: n=%d,f=%d,d=%d,rate=%lu\n", __func__,
             n->cur, f->cur, d->cur, *rate);

    return 0;
}

static inline void realtek_129x_pll_scpu_write_pll(struct clk_factor *clk_f,
        int target_n, int target_f)
{
    struct pll_scpu_extension *priv = to_pll_scpu_extension(clk_f);
    struct clk_factor_config *n = &clk_f->factors[0];
    struct clk_factor_config *f = &clk_f->factors[1];

    /* set OC_EN to 0 */
    clk_factor_write_factor(&priv->oc_en, 0);

    /* set PLL */
    clk_factor_write_factor_merged(n, target_n, f, target_f);

    /* set OC_EN to 1 */
    clk_factor_write_factor(&priv->oc_en, 1);

    /*wait until OC_DONE is 1 */
    while (!clk_factor_read_factor(&priv->oc_done));

    udelay(100);
}

static int realtek_129x_pll_scpu_write_factors(struct clk_factor *clk_f)
{
    struct clk_factor_config *n = &clk_f->factors[0];
    struct clk_factor_config *f = &clk_f->factors[1];
    struct clk_factor_config *d = &clk_f->factors[2];
    int d_old = clk_factor_read_factor(d);

    /* for fixing a timing issue to prevent glitch when switch scpu_freq_sel
     * Condition:
     *   1. switching scpu_freq_sel aka factor d is required
     *   2. target rate of PLL is over than 1 GHz
     *
     * Flow:
     *   a. set PLL to 1GHz
     *   b. set target scpu_freq_sel
     *   c. set PLL to target
     */
    if (d->cur != d_old && d->cur == 1) {

        /* set PLL rate to 1 GHz */
        realtek_129x_pll_scpu_write_pll(clk_f, 37, 45);

        clk_factor_write_factor(d, d->cur);
        d_old = d->cur;
    }

    if (d->cur > d_old) {
        clk_factor_write_factor(d, d->cur);
    }

    /* set PLL */
    realtek_129x_pll_scpu_write_pll(clk_f, n->cur, f->cur);

    if (d->cur < d_old) {
        clk_factor_write_factor(d, d->cur);
    }

    return 0;
}

const struct clk_factor_ops realtek_129x_pll_scpu_ops = {
    .calc_rate      = realtek_129x_pll_scpu_calc_rate,
    .recalc_factors = realtek_129x_pll_scpu_recalc_factors,
    .read_factors   = generic_read_factors,
    .write_factors  = realtek_129x_pll_scpu_write_factors,
};

static int realtek_129x_pll_gpu_write_factors(struct clk_factor *clk_f)
{
    struct pll_gpu_extension *priv = to_pll_gpu_extension(clk_f);
    struct clk_factor_config *n = &clk_f->factors[0];
    struct clk_factor_config *f = &clk_f->factors[1];

    clk_factor_write_factor(&priv->oc_en, 0x8);

    clk_factor_write_factor_merged(n, n->cur, f, f->cur);

    clk_factor_write_factor(&priv->oc_en, 0xd);

    return 0;
}

const struct clk_factor_ops realtek_129x_pll_gpu_ops = {
    .calc_rate      = generic_nf_calc_rate,
    .recalc_factors = generic_nf_recalc_factors,
    .read_factors   = generic_read_factors,
    .write_factors  = realtek_129x_pll_gpu_write_factors,
};

const struct clk_factor_ops *realtek_clk_factor_ops_list[] = {
    &realtek_129x_pll_nf_ops,
    &realtek_129x_pll_mno_ops,
    &realtek_129x_pll_scpu_ops,
    &realtek_129x_pll_gpu_ops,
};

enum realtek_clk_factor_type {
    CLK_FACTOR_NF   = 0,
    CLK_FACTOR_MNO  = 1,
    CLK_FACTOR_SCPU = 2,
    CLK_FACTOR_GPU  = 3,
};

static inline int realtek_clk_factor_type_code(const char *type)
{
    if (!strcmp(type, "nf"))
        return CLK_FACTOR_NF;

    if (!strcmp(type, "mno"))
        return CLK_FACTOR_MNO;

    if (!strcmp(type, "scpu"))
        return CLK_FACTOR_SCPU;

    if (!strcmp(type, "gpu"))
        return CLK_FACTOR_GPU;

    return -EINVAL;
}

static int __init init_clk_factor(struct device_node *np)
{
    struct clk_factor *clk_f;
    struct clk *clk;
    const char *type;
    const char *name;
    const char *parent_name;
    int ret;
    int type_code;

    if (of_property_read_string(np, "factor,type", &type))
        return -EINVAL;

    type_code = realtek_clk_factor_type_code(type);
    if (type_code < 0)
        return -EINVAL;

    if (type_code == CLK_FACTOR_SCPU) {
        const u32 *prop;
        int size, i;
        struct pll_scpu_extension *priv = kzalloc(sizeof(*priv), GFP_KERNEL);
        if (!priv)
            return -ENOMEM;

        of_clk_factor_read_factor_by_index(np, 3, &priv->oc_en);
        of_clk_factor_read_factor_by_index(np, 4, &priv->oc_done);

        prop = of_get_property(np, "scpu,pll,workaround", &size);
        size /= sizeof(u32);
        if (prop && (size % 2) == 0) {
            u32 *table;
            priv->tr_table = table = kzalloc(sizeof(u32) * (size + 2) , GFP_KERNEL);
            for (i = 0; i < size; i++) {
                table[i] = of_read_number(prop++, 1);
                pr_info("scpu,pll,workaround %08x\n", table[i]);
            }
        }

        clk_f = &priv->clk_f;
    } else if (type_code == CLK_FACTOR_GPU) {
        struct pll_gpu_extension *priv = kzalloc(sizeof(*priv), GFP_KERNEL);
        if (!priv)
            return -ENOMEM;

        of_clk_factor_read_factor_by_index(np, 2, &priv->oc_en);

        clk_f = &priv->clk_f;
    } else  {
        clk_f = kzalloc(sizeof(*clk_f), GFP_KERNEL);
        if (!clk_f)
            return -ENOMEM;
    }

    clk_f->ops = realtek_clk_factor_ops_list[type_code];

    ret = of_config_clk_factor(np, clk_f);
    if (ret) {
        pr_err("Failed to configure clk_factor from DT %s.\n", np->name);
        goto error;
    }

    name = np->name;
    parent_name = of_clk_get_parent_name(np, 0);

    clk = clk_register_factor(NULL, name, parent_name,
                              clk_f, CLK_GET_RATE_NOCACHE);
    if (!clk) {
        ret = -EINVAL;
        goto error;
    }

    of_clk_add_provider(np, of_clk_src_simple_get, clk);

    clk_register_clkdev(clk, name, NULL);

#ifdef CONFIG_PM
    rtk_clk_pm_config_data(clk, CLK_HAS_RATE);
#endif

#ifdef CONFIG_COMMON_CLK_RTD129X_DEBUGFS
    do {
        struct dentry *dir = debugfs_create_dir(np->name,
                                                clk_debugfs_root);
        switch (type_code) {
        case CLK_FACTOR_NF:
            debugfs_create_u32("factor.n", 0644, dir, &clk_f->factors[0].cur);
            debugfs_create_u32("factor.f", 0644, dir, &clk_f->factors[1].cur);
            break;
        case CLK_FACTOR_MNO:
            debugfs_create_u32("factor.m", 0644, dir, &clk_f->factors[0].cur);
            debugfs_create_u32("factor.n", 0644, dir, &clk_f->factors[1].cur);
            debugfs_create_u32("factor.o", 0644, dir, &clk_f->factors[2].cur);
            break;
        case CLK_FACTOR_SCPU:
            debugfs_create_u32("factor.n", 0644, dir, &clk_f->factors[0].cur);
            debugfs_create_u32("factor.f", 0644, dir, &clk_f->factors[1].cur);
            debugfs_create_u32("factor.d", 0644, dir, &clk_f->factors[2].cur);
            break;
        case CLK_FACTOR_GPU:
            debugfs_create_u32("factor.n", 0644, dir, &clk_f->factors[0].cur);
            debugfs_create_u32("factor.f", 0644, dir, &clk_f->factors[1].cur);
            break;
        }
        clk_debugfs_create_files(clk, dir, CLK_HAS_RATE);
    } while (0);
#endif

    return 0;
error:
    if (type_code == CLK_FACTOR_GPU)
        kfree(to_pll_gpu_extension(clk_f));
    else if (type_code == CLK_FACTOR_SCPU) {
        struct pll_scpu_extension *priv = to_pll_scpu_extension(clk_f);
        if (priv->tr_table)
            kfree(priv->tr_table);
        kfree(priv);
    } else
        kfree(clk_f);

    return ret;
}

static int __init init_clk_composite(struct device_node *np)
{
#define DEFINE_AND_INIT_CLK(_type_name, _name)          \
    struct _type_name *_name =                          \
        kzalloc(sizeof(*_name), GFP_KERNEL);            \
    if (!_name) {                                       \
        ret = -ENOMEM;                                  \
        goto error;                                     \
    }                                                   \
                                                        \
    ret = of_config_ ## _type_name(np, _name);          \
    if (ret) {                                          \
        pr_err("Failed to configure %s from DT %s\n",   \
             #_type_name, np->name);                    \
        kfree(_name);                                   \
        goto error;                                     \
    }

#define CLK_MAX_PARENTS 4

    void *p_clk_rate = NULL;
    struct clk_hw  *mux_hw = NULL, *rate_hw = NULL, *gate_hw = NULL;
    const struct clk_ops *mux_op = NULL, *rate_op = NULL, *gate_op = NULL;
    int ret = 0;
    unsigned long flags = CLK_SET_RATE_PARENT | CLK_IGNORE_UNUSED | CLK_GET_RATE_NOCACHE;
    struct clk *clk;
    const char *clk_name;
    const char *parent_names[CLK_MAX_PARENTS];
    int n_parents;
    int i;
    unsigned int __maybe_unused clk_type = CLK_IS_COMPOSITE;

    if (of_find_property(np, "has-clk-mux", NULL)) {
        DEFINE_AND_INIT_CLK(clk_mux, clk_m);

        mux_hw = &clk_m->hw;
        mux_op = &clk_mux_ops;

        clk_type |= CLK_HAS_MUX;
    }

    if (of_find_property(np, "has-clk-gate", NULL)) {
        DEFINE_AND_INIT_CLK(clk_gate, clk_g);

        gate_hw = &clk_g->hw;
        gate_op = &clk_gate_ops;

        clk_g->lock = &clk_lock;

        clk_type |= CLK_HAS_GATE;
    }

    /*
     * Steps to add a new clk with clk_rate:
     *  1. define the 'of_config_' function to obtain config by
     *      DEFINE_AND_INIT_CLK.
     *  2. set the point p_clk_rate to free memory in the ERROR
     *     handling code
     */
    if (of_find_property(np, "has-clk-rate", NULL)) {
        if (!of_property_match_string(np, "has-clk-rate", "fixed-rate")) {
            DEFINE_AND_INIT_CLK(clk_fixed_rate, clk_f);

            p_clk_rate = clk_f;

            rate_hw = &clk_f->hw;
            rate_op = &clk_fixed_rate_ops;
        } else if (!of_property_match_string(np, "has-clk-rate", "fixed-factor")) {
            DEFINE_AND_INIT_CLK(clk_fixed_factor, clk_f);

            p_clk_rate = clk_f;

            rate_hw = &clk_f->hw;
            rate_op = &clk_fixed_factor_ops;
        } else if (!of_property_match_string(np, "has-clk-rate", "factor")) {
            const char *type;
            int type_code;
            DEFINE_AND_INIT_CLK(clk_factor, clk_f);

            p_clk_rate = clk_f;

            if (of_property_read_string(np, "factor,type", &type)) {
                ret = -EINVAL;
                goto error;
            }

            type_code = realtek_clk_factor_type_code(type);
            if (type_code != CLK_FACTOR_NF && type_code != CLK_FACTOR_MNO) {
                ret = -EINVAL;
                goto error;
            }

            clk_f->ops = realtek_clk_factor_ops_list[type_code];

            rate_hw = &clk_f->hw;
            rate_op = &clk_factor_ops;

            clk_type |= CLK_HAS_RATE_RW;
        } else {
            pr_err("Failed to init a CLK_RATE type in DT %s\n", np->name);
            goto error;
        }

        clk_type |= CLK_HAS_RATE;
    }

    /* name */
    clk_name = np->name;

    /* parent(s) */
    if (mux_hw) {
        n_parents = of_property_count_strings(np, "clock-names");
        if (n_parents > 0) {
            BUG_ON(n_parents > CLK_MAX_PARENTS);
            for (i = 0; i < n_parents; i++)
                parent_names[i] = of_clk_get_parent_name(np, i);
        } else
            n_parents = 0;

        WARN_ON(n_parents == 0);
    } else {
        parent_names[0] = of_clk_get_parent_name(np, 0);
        n_parents = parent_names[0] ? 1 : 0;
    }

    if (n_parents == 0) {
        flags |= CLK_IS_ROOT;
        clk_type |= CLK_NO_PARENT;
    }

    clk = clk_register_composite(NULL, clk_name,
                                 n_parents == 0 ? NULL : parent_names, n_parents,
                                 mux_hw, mux_op, rate_hw, rate_op, gate_hw, gate_op, flags);
    if (IS_ERR_OR_NULL(clk))
        goto error;

    of_clk_add_provider(np, of_clk_src_simple_get, clk);

    clk_register_clkdev(clk, clk_name, NULL);

#ifdef CONFIG_PM
    rtk_clk_pm_config_data(clk, clk_type);
#endif

#ifdef CONFIG_COMMON_CLK_RTD129X_DEBUGFS
    do {
        struct dentry *dir = debugfs_create_dir(np->name,
                                                clk_debugfs_root);

        clk_debugfs_create_files(clk, dir, clk_type);
    } while (0);
#endif

    return 0;
error:
    if (mux_hw)
        kfree(to_clk_mux(mux_hw));

    if (gate_hw)
        kfree(to_clk_gate(gate_hw));

    if (p_clk_rate)
        kfree(p_clk_rate);

    return ret;
}

static int __init init_clk_gates(struct device_node *np)
{
#define RTK_GATES_MAX_SIZE  32

    struct clk_onecell_data *clk_data;
    const char *clk_parent;
    void __iomem *reg;
    unsigned long flags = CLK_IGNORE_UNUSED;
    unsigned long mask[1];
    u32 t;
    int i, j;
    int ret;
    int last_bit;
    struct dentry __maybe_unused *dir;

#ifdef CONFIG_COMMON_CLK_RTD129X_DEBUGFS
    do {
        const char *str = strrchr(np->full_name, '/');
        if (!str)
            str = np->name;
        else
            str += 1;

        dir = debugfs_create_dir(str, clk_debugfs_root);
    } while (0);
#endif

    reg = of_iomap(np, 0);

    clk_parent = of_clk_get_parent_name(np, 0);

    if (of_property_read_u32(np, "mask", &t))
        return -EINVAL;

    mask[0] = t;
    last_bit = find_last_bit(mask, RTK_GATES_MAX_SIZE);

    clk_data = kzalloc(sizeof(*clk_data), GFP_KERNEL);
    if (!clk_data) {
        ret = -ENOMEM;
        goto error;
    }

    clk_data->clks = kzalloc(sizeof(struct clk *) * (last_bit+1), GFP_KERNEL);
    if (!clk_data->clks) {
        ret = -ENOMEM;
        goto error;
    }

    j = 0;
    for_each_set_bit(i, mask, RTK_GATES_MAX_SIZE) {
        const char *clk_name;

        if (of_property_read_string_index(np, "clock-output-names", j, &clk_name)) {
            ret = -EINVAL;
            goto error;
        }

        clk_data->clks[i] = clk_register_gate(NULL, clk_name,
                                              clk_parent, flags, reg, i, 0, &clk_lock);
        if (IS_ERR_OR_NULL(clk_data->clks[i])) {
            ret = -EINVAL;
            goto error;
        }

        clk_register_clkdev(clk_data->clks[i], clk_name, NULL);

#ifdef CONFIG_COMMON_CLK_RTD129X_DEBUGFS
        do {
            char buf[30];
            struct dentry *sub_dir;
            sprintf(buf, "%02d.%s", i, clk_name);
            sub_dir = debugfs_create_dir(buf, dir);
            clk_debugfs_create_files(clk_data->clks[i], sub_dir,
                                     (clk_parent ? 0 : CLK_NO_PARENT) | CLK_HAS_GATE);
        } while (0);
#endif

        j++;
    }

    clk_data->clk_num = i;

    of_clk_add_provider(np, of_clk_src_onecell_get, clk_data);

#ifdef CONFIG_PM
    rtk_clk_pm_config_raw(reg, mask[0]);
#endif

    return 0;

error:
    if (clk_data && clk_data->clks)
        kfree(clk_data->clks);

    if (clk_data)
        kfree(clk_data);

    return ret;
}

static const __initconst struct of_device_id clk_match[] = {
    {.compatible = "realtek,129x-pll-generic",   .data = init_clk_factor},
    {.compatible = "realtek,129x-clk-composite", .data = init_clk_composite},
    {.compatible = "realtek,129x-clk-gates",     .data = init_clk_gates},
    {}
};

static int __init rtk_init_clk(void)
{
    struct device_node *np;
    const struct of_device_id *match;

#ifdef CONFIG_COMMON_CLK_RTD129X_DEBUGFS
    clk_debugfs_root = debugfs_create_dir("rtk_clk", NULL);
#endif

    for_each_matching_node_and_match(np, clk_match, &match) {
        int (*func)(struct device_node*) = match->data;
        int ret;

        if (!of_device_is_available(np))
            continue;

        if (func != NULL) {
            ret = func(np);
            if (ret)
                pr_err("Failed to init %s, ret = %d\n", np->name, ret);
        }
    }

#if CONFIG_PM
    cpu_pm_register_notifier(&pm_notifier_block);
#endif

    return 0;
}
pure_initcall(rtk_init_clk);
