/*
 * clk-generic.c - Generic helper functions for clock implementation
 *
 * Copyright (C) 2016 Realtek Semiconductor Corporation
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
#define pr_fmt(fmt) "clk-generic: " fmt
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/clk-provider.h>
#include "clk-generic.h"

/**
 * of_config_clk_gate: of help function to config clk_gate
 *   @np: device node
 *   @clk_g: clk_gate
 *
 * Returns 0 on success, -EINVAL if the required properity is not read
 */
int of_config_clk_gate(struct device_node *np, struct clk_gate *clk_g)
{
    u32 index, shift;

    if (of_property_read_u32(np, "gate,reg-index", &index))
        return -EINVAL;

    if (of_property_read_u32(np, "gate,shift", &shift))
        return -EINVAL;

    clk_g->reg     = of_iomap(np, index);
    clk_g->bit_idx = shift;

    return 0;
}

/**
 * of_config_clk_mux: of help function to config clk_mux
 *   @np: device node
 *   @clk_m: clk_mux
 *
 * Returns 0 on success, -EINVAL if the required properity is not read
 */
int of_config_clk_mux(struct device_node *np, struct clk_mux *clk_m)
{
    u32 index, shift, width;

    if (of_property_read_u32(np, "mux,reg-index", &index))
        return -EINVAL;

    if (of_property_read_u32(np, "mux,shift", &shift))
        return -EINVAL;

    if (of_property_read_u32(np, "mux,width", &width))
        return -EINVAL;

    clk_m->reg   = of_iomap(np, index);
    clk_m->shift = shift;
    clk_m->mask  = BIT(width) - 1;

    return 0;
}

/**
 * of_config_clk_fixed_rate: of help function to config clk_fixed_rate
 *   @np: device node
 *   @clk_f: clk_fixed_rate
 *
 * Returns 0 on success, -EINVAL if the required properity is not read
 */
int of_config_clk_fixed_rate(struct device_node *np, struct clk_fixed_rate *clk_f)
{
    u32 rate;
    if (of_property_read_u32(np, "fixed-rate,rate", &rate))
        return -EINVAL;

    clk_f->fixed_rate = rate;

    return 0;
}

/**
 * of_config_clk_fixed_factor: of help function to config clk_fixed_factor
 *   @np: device node
 *   @clk_f: clk_fixed_factor
 *
 * Returns 0 on success, -EINVAL if the required properity is not read
 */
int of_config_clk_fixed_factor(struct device_node *np, struct clk_fixed_factor *clk_f)
{
    u32 div, mult;

    if (of_property_read_u32(np, "fixed-factor,div", &div))
        div = 1;
    if (of_property_read_u32(np, "fixed-factor,mult", &mult))
        mult = 1;

    clk_f->div = div;
    clk_f->mult = mult;

    return 0;
}

/**
 * of_clk_factor_read_factor_by_index - of help to read clk_factor_config
 *   @np: device node
 *   #index: index of clk_factor_config in properties
 *   @f_out: clk_factor_config to be written
 *
 * Returns 0 on success, -EINVAL if the required properity is not read
 */
int of_clk_factor_read_factor_by_index(struct device_node *np, int index,
                                       struct clk_factor_config *f_out)
{
    f_out->reg = of_iomap(np, index);

    if (of_property_read_u32_index(np, "factor,shift", index, &f_out->shift) ||
            of_property_read_u32_index(np, "factor,width", index, &f_out->width))
        return -EINVAL;

    if (of_property_read_u32_index(np, "factor,min", index, &f_out->min))
        f_out->min = 0;
    if (of_property_read_u32_index(np, "factor,max", index, &f_out->max))
        f_out->max = BIT(f_out->width) - 1;

    return 0;
}

/**
 * of_config_clk_factor: of help function to config clk_factor
 *   @np: device node
 *   @clk_f: clk_factor
 *
 * Returns 0 on success, -EINVAL if the required properity is not read
 */
int of_config_clk_factor(struct device_node *np, struct clk_factor *clk_f)
{
    int i;

    if (of_property_read_u32(np, "factor,num", &clk_f->n_factors))
        return -EINVAL;

    if (of_property_read_u32(np, "factor,max-rate", &clk_f->max_rate))
        return -EINVAL;

    if (of_property_read_u32(np, "factor,min-rate", &clk_f->min_rate))
        return -EINVAL;

    for (i = 0; i < clk_f->n_factors; i++) {
        if (of_clk_factor_read_factor_by_index(np, i, &clk_f->factors[i])) {
            return -EINVAL;
        }
    }

    return 0;
}

static unsigned long clk_factor_recalc_rate(struct clk_hw *hw,
        unsigned long parent_rate)
{
    struct clk_factor *clk_f = to_clk_factor(hw);
    unsigned long rate = 0;

    if (clk_f->ops) {
        clk_f->ops->read_factors(clk_f);
        clk_f->ops->calc_rate(clk_f, &rate, parent_rate);
    }

    return rate;
}

static long clk_factor_round_rate(struct clk_hw *hw, unsigned long rate,
                                  unsigned long *parent_rate)
{
    struct clk_factor __maybe_unused *clk_f = to_clk_factor(hw);

#if 0
    /* NOTE: unnecessary, round will be done in set_rate  */
    if (clk_f->ops)
        clk_f->ops->recalc_factors(clk_f, &rate, *parent_rate);

    pr_err("%s: rate = %lu, parent_rate = %lu\n", __func__, rate, *parent_rate);
#endif
    return rate;
}

static int clk_factor_set_rate(struct clk_hw *hw, unsigned long rate,
                               unsigned long parent_rate)
{
    struct clk_factor *clk_f = to_clk_factor(hw);

    if (clk_f->ops) {
        clk_f->ops->recalc_factors(clk_f, &rate, parent_rate);
        clk_f->ops->write_factors(clk_f);
    }

    return 0;
}

const struct clk_ops clk_factor_ops = {
    .recalc_rate = clk_factor_recalc_rate,
    .round_rate  = clk_factor_round_rate,
    .set_rate    = clk_factor_set_rate,
};

/**
 * clk_register_factor - register a clk_factor
 *   @dev:
 *   @name: clk name
 *   @parent_name: parent name of clk
 *   @clk_f: preconfigured clk_factor, the ops will be checked if ops is set
 *   @flags: clk flags
 *
 * Returns a clk on success
 */
struct clk * clk_register_factor(struct device *dev, const char *name,
                                 const char *parent_name, struct clk_factor * clk_f, unsigned long flags)
{
    struct clk *clk;
    struct clk_init_data init;

    init.name = name;
    init.ops = &clk_factor_ops;
    init.flags = flags;
    init.parent_names = parent_name ? &parent_name : NULL;
    init.num_parents = parent_name ? 1 : 0;

    if (clk_f->ops) {
        BUG_ON(!clk_f->ops->recalc_factors ||
               !clk_f->ops->calc_rate ||
               !clk_f->ops->write_factors ||
               !clk_f->ops->read_factors);
    }

    clk_f->hw.init = &init;

    clk = clk_register(dev, &clk_f->hw);

    return clk;

}
