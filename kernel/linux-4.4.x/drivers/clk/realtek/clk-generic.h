/*
 * clk-generic.h - Generic helper functions for clock implementation
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
#ifndef __CLK_GENERIC_H_
#define __CLK_GENERIC_H_

#include <asm-generic/io.h>

struct clk_hw;

struct clk_factor_config {
    void __iomem * reg;
    int shift;
    int width;
    int min;
    int max;    
    int cur;
};

/**
 * clk_factor_read_factor - read a factor form register
 */
static inline u32 clk_factor_read_factor(struct clk_factor_config *f)
{
    u32 val = readl(f->reg);
    val >>= f->shift;
    val &= BIT(f->width) - 1;
    return val;
}

/**
 * clk_factor_write_factor - write a factor from register
 */
static inline void clk_factor_write_factor(struct clk_factor_config *f, u32 f_val)
{
    u32 val = readl(f->reg);
    u32 mask = (BIT(f->width) - 1) << f->shift;
    
    val = (val & ~mask) | ((f_val << f->shift) & mask);
    writel(val, f->reg);
}

/**
 * clk_factor_write_factor_merged - write to factor in the same address
 *   @f_0: first factor to write, the register is used as the target address
 *   @f_1: sencond factor to write
 */
static inline void clk_factor_write_factor_merged(struct clk_factor_config *f_0, u32 f_val_0,
    struct clk_factor_config *f_1, u32 f_val_1)
{
    u32 val = readl(f_0->reg);
    u32 mask;

    mask = (BIT(f_0->width) - 1) << f_0->shift;
    val = (val & ~mask) | ((f_val_0 << f_0->shift) & mask);

    mask = (BIT(f_1->width) - 1) << f_1->shift;
    val = (val & ~mask) | ((f_val_1 << f_1->shift) & mask);

    writel(val, f_0->reg);    
}

struct clk_factor_ops;

struct clk_factor {
    struct clk_hw hw;
    const struct clk_factor_ops *ops;    

    int max_rate;
    int min_rate;

    int n_factors;
    struct clk_factor_config factors[3];
};

#define to_clk_factor(_hw) container_of(_hw, struct clk_factor, hw)

/**
 * clk_factor_verify_target_rate - set the target rate within the limiatation
 *   @clk_f: clk_factor
 *   @target_rate: target rate
 */
static inline void clk_factor_verify_target_rate(struct clk_factor *clk_f, unsigned long *target_rate)
{
    if (*target_rate < clk_f->min_rate)
        *target_rate = clk_f->min_rate;
    if (*target_rate > clk_f->max_rate)
        *target_rate = clk_f->max_rate;
}

/**
 * struct clk_factor_ops - callback functions, all are required for a clk_factor
 *
 * @calc_rate:      Calcuate the rate from the clk_factor_config.
 *
 * @recalc_factors: Find the new factor based on rate and parent_rate.The rate is an 
 *                  input/output parameter, passing the target rate and returning the 
 *                  found rate with the factors. The new factor should be saved in 
 *                  member cur in struct clk_factor_config.
 *
 * @read_factors:   Read factors from register(s)
 *
 * @write_factors:  Write factors to register(s)
 *
 */
struct clk_factor_ops {
    int (*calc_rate)(struct clk_factor *clk_f, unsigned long *rate, unsigned long parent_rate);
    int (*recalc_factors)(struct clk_factor *clk_f, unsigned long *rate, unsigned long parent_rate);
    int (*read_factors)(struct clk_factor *clk_f);
    int (*write_factors)(struct clk_factor *clk_f);
};

extern const struct clk_ops clk_factor_ops;

int of_config_clk_gate(struct device_node *np, struct clk_gate *clk_g);
int of_config_clk_mux(struct device_node *np, struct clk_mux *clk_m);
int of_config_clk_fixed_rate(struct device_node *np, struct clk_fixed_rate *clk_f);
int of_config_clk_fixed_factor(struct device_node *np, struct clk_fixed_factor *clk_f);
int of_config_clk_factor(struct device_node *np, struct clk_factor *clk_f);
int of_clk_factor_read_factor_by_index(struct device_node *np, int index,
    struct clk_factor_config *f_out);
struct clk * clk_register_factor(struct device *dev, const char *name,
    const char *parent_name, struct clk_factor * clk_f, unsigned long flags);

#endif
