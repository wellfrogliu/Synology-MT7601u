#include <linux/err.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/syscore_ops.h>
#include <linux/slab.h>
#include <linux/irqdomain.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/irqchip.h>
#include <asm/hardirq.h>

#include <asm/exception.h>
#include <asm/irq.h>

//#include "drivers/irqchip/irqchip.h"

#define NONE			"\033[m"
#define RED				"\033[0;32;31m"
#define LIGHT_RED		"\033[1;31m"
#define GREEN			"\033[0;32;32m"
#define LIGHT_GREEN		"\033[1;32m"
#define BLUE			"\033[0;32;34m"
#define LIGHT_BLUE		"\033[1;34m"
#define DARY_GRAY		"\033[1;30m"
#define CYAN			"\033[0;36m"
#define LIGHT_CYAN		"\033[1;36m"
#define PURPLE			"\033[0;35m"
#define LIGHT_PURPLE	"\033[1;35m"
#define BROWN			"\033[0;33m"
#define YELLOW			"\033[1;33m"
#define LIGHT_GRAY		"\033[0;37m"
#define WHITE			"\033[1;37m"

#define ATTR_OFF		"\033[0m"
#define BOLD			"\033[1m"
#define UNDERSCORE		"\033[4m"
#define BLINK			"\033[5m"
#define REVERSE			"\033[7m"
#define CONCEALED		"\033[8m"

#define dbg_fmt(fmt) fmt

#define dbg_err(fmt, ...) \
	printk(KERN_ERR RED dbg_fmt(fmt) NONE"\n", ##__VA_ARGS__)

#define dbg_emerg(fmt, ...) \
	printk(KERN_EMERG RED dbg_fmt(fmt) NONE"\n", ##__VA_ARGS__)

#define dbg_alert(fmt, ...) \
	printk(KERN_ALERT RED dbg_fmt(fmt) NONE"\n", ##__VA_ARGS__)

#define dbg_crit(fmt, ...) \
	printk(KERN_CRIT RED dbg_fmt(fmt) NONE"\n", ##__VA_ARGS__)

#define dbg_warning(fmt, ...) \
	printk(KERN_WARNING RED dbg_fmt(fmt) NONE"\n", ##__VA_ARGS__)

#define dbg_warn dbg_warning

#define dbg_info(fmt, ...) \
	printk(KERN_INFO CYAN dbg_fmt(fmt) NONE"\n", ##__VA_ARGS__)

#define dbg_notice(fmt, ...) \
	printk(KERN_NOTICE CYAN dbg_fmt(fmt) NONE"\n", ##__VA_ARGS__)

#define dbg_cont(fmt, ...) \
	printk(KERN_CONT CYAN fmt NONE"\n", ##__VA_ARGS__)

#define IRQ_INMUX		32

#define rtd_outl(offset, val)		__raw_writel(val, offset)
#define rtd_setbits(offset, Mask)	__raw_writel(((__raw_readl(offset) | Mask)), offset)
#define rtd_clearbits(offset, Mask)	__raw_writel(((__raw_readl(offset) & ~Mask)), offset)

enum misc_int_en {
    MISC_INT_FAIL           = 0xFF,
    MISC_INT_RVD            = 0xFE,
    MISC_INT_EN_FAN         = 29,
    MISC_INT_EN_I2C3        = 28,
    MISC_INT_EN_GSPI        = 27,
    MISC_INT_EN_I2C2        = 26,
    MISC_INT_EN_SC0         = 24,
    MISC_INT_EN_LSADC1      = 22,
    MISC_INT_EN_LSADC0      = 21,
    MISC_INT_EN_GPIODA      = 20,
    MISC_INT_EN_GPIOA       = 19,
    MISC_INT_EN_I2C4        = 15,
    MISC_INT_EN_I2C5        = 14,
    MISC_INT_EN_RTC_DATA    = 12,
    MISC_INT_EN_RTC_HOUR    = 11,
    MISC_INT_EN_RTC_MIN     = 10,
    MISC_INT_EN_UR2         = 7,
    MISC_INT_EN_UR2_TO      = 6,
    MISC_INT_EN_UR1_TO      = 5,
    MISC_INT_EN_UR1         = 3,
};

enum iso_int_en {
    ISO_INT_FAIL            = 0xFF,
    ISO_INT_RVD             = 0xFE,
    ISO_INT_EN_I2C1_REQ     = 31,
    ISO_INT_EN_GPHY_AV      = 30,
    ISO_INT_EN_GPHY_DV      = 29,
    ISO_INT_EN_GPIODA       = 20,
    ISO_INT_EN_GPIOA        = 19,
    ISO_INT_EN_RTC_ALARM    = 13,
    ISO_INT_EN_RTC_HSEC     = 12,
    ISO_INT_EN_I2C1         = 11,
    ISO_INT_EN_I2C0         = 8,
    ISO_INT_EN_IRDA         = 5,
    ISO_INT_EN_UR0          = 2,
};

unsigned char irq_map_tab[2][IRQ_INMUX] = {
    {
        MISC_INT_FAIL,          /* Bit0 */
        MISC_INT_FAIL,          /* Bit1 */
        MISC_INT_RVD,           /* Bit2 */
        MISC_INT_EN_UR1,        /* Bit3 */
        MISC_INT_FAIL,          /* Bit4 */
        MISC_INT_EN_UR1_TO, /* Bit5 */
        MISC_INT_RVD,           /* Bit6 */
        MISC_INT_RVD,           /* Bit7 */
        MISC_INT_EN_UR2,        /* Bit8 */
        MISC_INT_RVD,           /* Bit9 */
        MISC_INT_EN_RTC_MIN, /* Bit10 */
        MISC_INT_EN_RTC_HOUR,/* Bit11 */
        MISC_INT_EN_RTC_DATA,/* Bit12 */
        MISC_INT_EN_UR2_TO,     /* Bit13 */
        MISC_INT_EN_I2C5,       /* Bit14 */
        MISC_INT_EN_I2C4,       /* Bit15 */
        MISC_INT_FAIL,          /* Bit16 */
        MISC_INT_FAIL,          /* Bit17 */
        MISC_INT_FAIL,          /* Bit18 */
        MISC_INT_EN_GPIOA,      /* Bit19 */
        MISC_INT_EN_GPIODA,     /* Bit20 */
        MISC_INT_EN_LSADC0,     /* Bit21 */
        MISC_INT_EN_LSADC1,     /* Bit22 */
        MISC_INT_EN_I2C3,       /* Bit23 */
        MISC_INT_EN_SC0,        /* Bit24 */
        MISC_INT_FAIL,          /* Bit25 */
        MISC_INT_EN_I2C2,       /* Bit26 */
        MISC_INT_EN_GSPI,       /* Bit27 */
        MISC_INT_FAIL,          /* Bit28 */
        MISC_INT_EN_FAN,        /* Bit29 */
        MISC_INT_FAIL,          /* Bit30 */
        MISC_INT_FAIL,          /* Bit31 */
    },
    {
        ISO_INT_FAIL,           /* Bit0 */
        ISO_INT_RVD,            /* Bit1 */
        ISO_INT_EN_UR0,         /* Bit2 */
        ISO_INT_FAIL,           /* Bit3 */
        ISO_INT_FAIL,           /* Bit4 */
        ISO_INT_EN_IRDA,        /* Bit5 */
        ISO_INT_FAIL,           /* Bit6 */
        ISO_INT_RVD,            /* Bit7 */
        ISO_INT_EN_I2C0,        /* Bit8 */
        ISO_INT_RVD,            /* Bit9 */
        ISO_INT_FAIL,           /* Bit10 */
        ISO_INT_EN_I2C1,        /* Bit11 */
        ISO_INT_EN_RTC_HSEC,/* Bit12 */
        ISO_INT_EN_RTC_ALARM,/* Bit13 */
        ISO_INT_FAIL,           /* Bit14 */
        ISO_INT_FAIL,           /* Bit15 */
        ISO_INT_FAIL,           /* Bit16 */
        ISO_INT_FAIL,           /* Bit17 */
        ISO_INT_FAIL,           /* Bit18 */
        ISO_INT_EN_GPIOA,       /* Bit19 */
        ISO_INT_EN_GPIODA,      /* Bit20 */
        ISO_INT_RVD,            /* Bit21 */
        ISO_INT_RVD,            /* Bit22 */
        ISO_INT_RVD,            /* Bit23 */
        ISO_INT_RVD,            /* Bit24 */
        ISO_INT_FAIL,           /* Bit25 */
        ISO_INT_FAIL,           /* Bit26 */
        ISO_INT_FAIL,           /* Bit27 */
        ISO_INT_FAIL,           /* Bit28 */
        ISO_INT_EN_GPHY_DV,     /* Bit29 */
        ISO_INT_EN_GPHY_AV,     /* Bit30 */
        ISO_INT_EN_I2C1_REQ,/* Bit31 */
    }
};

static DEFINE_SPINLOCK(irq_mux_lock);

struct irq_mux_data {
    void __iomem		*base;
    unsigned char           index;
    unsigned int		irq;
    unsigned int		irq_offset;
    u32					intr_status;
    u32					intr_en;
};

static struct irq_domain *irq_mux_domain;

static void mux_mask_irq(struct irq_data *data)
{
    struct irq_mux_data *mux_data = irq_data_get_irq_chip_data(data);
    void __iomem *base;
    u32 reg_st;

    mux_data += (data->hwirq / IRQ_INMUX);
    base = mux_data->base;
    reg_st = mux_data->intr_status;

    rtd_outl(base+reg_st, BIT(data->hwirq % IRQ_INMUX));
}

static void mux_unmask_irq(struct irq_data *data)
{
    struct irq_mux_data *mux_data = irq_data_get_irq_chip_data(data);
    void __iomem *base;
    u32 reg_en;
    u8 en_offset;

    mux_data += (data->hwirq / IRQ_INMUX);
    base = mux_data->base;
    reg_en = mux_data->intr_en;
    en_offset = irq_map_tab[mux_data->index][data->hwirq % IRQ_INMUX];

    if((en_offset!=MISC_INT_RVD)&&(en_offset!=MISC_INT_FAIL))
        rtd_setbits(base+reg_en, BIT(en_offset));
    else if(en_offset==MISC_INT_FAIL)
        pr_err("[IRQ MUX] Enable irq(%lu) fail\n",data->hwirq);

}

static void mux_disable_irq(struct irq_data *data)
{
    struct irq_mux_data *mux_data = irq_data_get_irq_chip_data(data);
    void __iomem *base;
    u32 reg_en;
    u8 en_offset;

    mux_data += (data->hwirq / IRQ_INMUX);
    base = mux_data->base;
    reg_en = mux_data->intr_en;
    en_offset = irq_map_tab[mux_data->index][data->hwirq % IRQ_INMUX];

    if((en_offset!=MISC_INT_RVD)&&(en_offset!=MISC_INT_FAIL))
        rtd_clearbits(base+reg_en, BIT(en_offset));
    else if(en_offset==MISC_INT_FAIL)
        pr_err("[IRQ MUX] Disable irq(%lu) fail\n",data->hwirq);

}

#ifdef CONFIG_SMP
__maybe_unused static int mux_set_affinity(struct irq_data *d,
        const struct cpumask *mask_val, bool force)
{
    struct irq_mux_data *mux_data = irq_data_get_irq_chip_data(d);
    struct irq_chip *chip = irq_get_chip(mux_data->irq);
    struct irq_data *data = irq_get_irq_data(mux_data->irq);

    if (chip && chip->irq_set_affinity)
        return chip->irq_set_affinity(data, mask_val, force);
    else
        return -EINVAL;
}
#endif

static struct irq_chip mux_chip = {
    .name		= "IRQMUX",
    .irq_mask	= mux_mask_irq,
    .irq_unmask	= mux_unmask_irq,
    .irq_disable= mux_disable_irq,
#ifdef CONFIG_SMP
    .irq_set_affinity	= mux_set_affinity,
#endif
};

static void mux_irq_handle(struct irq_desc *desc)
{
    struct irq_mux_data *mux_data = irq_desc_get_handler_data(desc);
    struct irq_chip *chip = irq_desc_get_chip(desc);
    unsigned int irq = irq_desc_get_irq(desc);
    static u32 count = 0;
    int ret, i;
    unsigned int mux_irq;
    unsigned int status, check_status;
    unsigned int enable;
    u8 en_offset;
    u32 reg_st = mux_data->intr_status;
    u32 reg_en = mux_data->intr_en;

    chained_irq_enter(chip, desc);

    spin_lock(&irq_mux_lock);
    enable = __raw_readl(mux_data->base+reg_en);
    status = __raw_readl(mux_data->base+reg_st);
    spin_unlock(&irq_mux_lock);

    for(i=0; i<IRQ_INMUX; i++) // Check every interrupt flag
    {
        if(status & BIT(i))
        {
            en_offset = irq_map_tab[mux_data->index][i];
            mux_irq = mux_data->irq_offset + i;
            if(en_offset<IRQ_INMUX)
            {
                if(enable & BIT(en_offset))
                {
                    ret = generic_handle_irq(irq_find_mapping(irq_mux_domain, mux_irq));
                    if (ret != 0)
                        pr_err("[IRQ MUX Err] mux_irq(%u) desc is not found. (st:0x%08x en:0x%08x)\n", mux_irq, status, enable);
                }
            }
            else if(en_offset==MISC_INT_RVD)
            {
                ret = generic_handle_irq(irq_find_mapping(irq_mux_domain, mux_irq));
                if (ret != 0)
                    pr_err("[IRQ MUX Err] mux_irq(%u) desc is not found. (st:0x%08x en:0x%08x)\n", mux_irq, status, enable);
            }
            else
                pr_err("[IRQ MUX Err] mux_irq(%u) should not happen (st:0x%08x en:0x%08x)\n", mux_irq, status, enable);
        }
    }

    spin_lock(&irq_mux_lock);
    check_status = __raw_readl(mux_data->base+reg_st);
    spin_unlock(&irq_mux_lock);

    if (check_status == status) {
        if(count > 1)
            printk(KERN_ERR "[IRQ MUX] (%u) %s irq status is not change. clear it! (st:0x%08x en:0x%08x)\n", irq, mux_data->index?"ISO":"MISC", status, enable);

        else
            count++;

        spin_lock(&irq_mux_lock);
        rtd_outl(mux_data->base+reg_st, BIT(__ffs(status)));
        spin_unlock(&irq_mux_lock);
    }
    else
    {
        count = 0;
    }

    chained_irq_exit(chip, desc);
}

__maybe_unused static int mux_irq_domain_xlate(struct irq_domain *d,
        struct device_node *controller,
        const u32 *intspec, unsigned int intsize,
        unsigned long *out_hwirq,
        unsigned int *out_type)
{
    if (controller != irq_domain_get_of_node(d))
        return -EINVAL;

    if (intsize < 2)
        return -EINVAL;

    *out_hwirq = intspec[0]*IRQ_INMUX + intspec[1];
    *out_type = 0;

    return 0;
}

static int mux_irq_domain_map(struct irq_domain *d,
                              unsigned int irq, irq_hw_number_t hw)
{
    struct irq_mux_data *data = d->host_data;

    irq_set_chip_and_handler(irq, &mux_chip, handle_level_irq);
    irq_set_chip_data(irq, data);
    irq_set_probe(irq);

    return 0;
}

static const struct irq_domain_ops mux_irq_domain_ops = {
    .xlate	= mux_irq_domain_xlate,
    .map	= mux_irq_domain_map,
};

static void __init mux_init_each(struct irq_mux_data *mux_data, void __iomem *base,
                                 u32 irq, u32 status, u32 enable, int nr)
{
    mux_data->base = base;
    mux_data->index = nr;
    mux_data->irq = irq;
    mux_data->irq_offset = nr*IRQ_INMUX;
    mux_data->intr_status = status;
    mux_data->intr_en = enable;

    rtd_clearbits(base+enable, BIT(2));
    rtd_outl(base+status, BIT(2));

    irq_set_chained_handler_and_data(irq, mux_irq_handle,mux_data);

}

#ifdef CONFIG_OF
static int __init mux_of_init(struct device_node *np,
                              struct device_node *parent)
{
    int i;
    u32 nr_irq=1;
    struct irq_mux_data *mux_data;
    void __iomem *base;
    u32 irq;
    u32 status, enable;

    if (WARN_ON(!np))
        return -ENODEV;

    if (of_property_read_u32(np, "Realtek,mux-nr", &nr_irq)) {
        dbg_err("%s can not specified mux number.", __func__);
    }

    mux_data = kcalloc(nr_irq, sizeof(*mux_data), GFP_KERNEL);
    WARN(!mux_data,"could not allocate MUX IRQ data");

    /*TODO : tempary define the first irq number in this mux is 160, end in 160+64*/
    irq_mux_domain = irq_domain_add_simple(np, (nr_irq*IRQ_INMUX), 160,
                                           &mux_irq_domain_ops, mux_data);
    WARN(!irq_mux_domain, "IRQ domain init failed\n");

    for (i=0; i < nr_irq; i++) {
        base = of_iomap(np, i);

        WARN(!(base), "unable to map IRQ base registers\n");

        irq = irq_of_parse_and_map(np, i);

        WARN(!(irq), "can not map IRQ.\n");

        of_property_read_u32_index(np, "intr-status", i, &status);
        of_property_read_u32_index(np, "intr-en", i, &enable);

        mux_init_each(mux_data, base, irq, status, enable, i);

        mux_data++;
    }

    //register_syscore_ops(&mux_irq_domain_ops);

    return 0;
}

IRQCHIP_DECLARE(rtk_irq_mux, "Realtek,rtk-irq-mux", mux_of_init);
#endif
