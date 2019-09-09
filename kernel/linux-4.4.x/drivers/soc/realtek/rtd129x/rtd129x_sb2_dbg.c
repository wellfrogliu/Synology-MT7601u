#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/printk.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

#include <asm/system_misc.h>

#include "include/reg_sb2.h"

static void __iomem *iobase;

irqreturn_t isr_sb2_dbg(int irq, void *pdev)
{
	struct pt_regs *regs;
	u32 intr = readl(SB2_DBG_INT);

	regs = get_irq_regs();

	if (intr & ((1 << 4) | (1 << 10) | (1<<6) | (1<<12))) {
		u32 cause, addr, s_a_cpu;
		char buf[128];
		pr_err("[SB2 DBG] sb2 get int 0x%08x from SB2_DBG_INT\n", intr);

		writel((1 << 9) | (1 << 7) | 1, SB2_DBG_INT);

		s_a_cpu = (intr & (1<<10)) ? 1 : 2;	/* SCPU:1, ACPU:2 */
		addr = (s_a_cpu == 1) ? readl(SB2_DBG_ADDR_SYSTEM) : readl(SB2_DBG_ADDR_AUDIO);
		cause = readl(SB2_DBG_ADDR1);
		cause = (s_a_cpu == 1) ? (cause >> 2) : (cause >> 4);

		sprintf(buf, "Memory 0x%08x trashed by %sCPU with %s %s\n", addr,
				(s_a_cpu == 1) ? "S" : "A",
				(cause & 1) ? "D" : "I",
				(cause & 2) ? "W" : "R");

		die(buf, regs, 0);

		return IRQ_HANDLED;
	}

	intr = readl(SB2_INV_INTSTAT);

	if (intr & (SWCIVA_INT | ACIVA_INT | SCIVA_INT)) {

		pr_err("[SB2 DBG] sb2 get int 0x%08x from SB2_INV_INTSTAT\n", intr);

		writel( SWCIVA_INT | ACIVA_INT | SCIVA_INT | WRITE_DATA_0, SB2_INV_INTSTAT);

		if (intr & SWCIVA_INT)
			pr_err("\033[0;31m[SB2 DBG] Invalid access issued by SCPU security world\033[m\n") ;

		if (intr & ACIVA_INT)
			pr_err("\033[0;31m[SB2 DBG] Invalid access issued by Audio\033[m\n") ;

		if (intr & SCIVA_INT)
			pr_err("\033[0;31m[SB2 DBG] Invalid access issued by SCPU\033[m\n") ;

		pr_err("\033[0;31m[SB2 DBG] Invalid address is 0x%x \033[m\n", readl(SB2_INV_ADDR));
		pr_err("[SB2 DBG] Timeout threshold(0x%08x)\n", readl(SB2_DEBUG_REG));
		//show_regs(regs);

		return IRQ_HANDLED;

	}
	return IRQ_NONE;
}

void sb2_dbg_scpu_monitor(int which, u32 start, u32 end, u32 d_i, u32 r_w);
void sb2_dbg_acpu_monitor(int which, u32 start, u32 end, u32 d_i, u32 r_w);

static int sb2_dbg_init(struct platform_device *pdev)
{
	struct device_node *np;
	int sb2_irq;

	if (WARN_ON(!(pdev->dev.of_node))) {
		pr_err("[SB2 DBG] Error: No node\n");
		return -ENODEV;
	}

	np = pdev->dev.of_node;

	iobase = of_iomap(np, 0);
	//pr_info("[SB2 DBG][%s] base(0x%08x)\n", __FUNCTION__, iobase);

	sb2_irq = irq_of_parse_and_map(np, 0);

	if (!sb2_irq) {
		pr_err("[SB2 DBG][%s] irq parse fail\n", __FUNCTION__);
		return -ENXIO;
	}
	//pr_info("[SB2 DBG][%s] irq(%u)\n",__FUNCTION__,sb2_irq);

	if (request_irq(sb2_irq, isr_sb2_dbg, IRQF_SHARED, "sb2_dbg", pdev) != 0) {
		pr_err("[SB2 DBG][%s] irq request fail\n", __FUNCTION__);
		return -ENXIO;
	}

	pr_info("[SB2 DBG][%s] memory monitor 0x98013b00 - 0x98013c00\n", __FUNCTION__);
	sb2_dbg_acpu_monitor(0, 0x98013b00, 0x98013c00, SB2_DBG_MONITOR_DATA|SB2_DBG_MONITOR_INST, SB2_DBG_MONITOR_READ|SB2_DBG_MONITOR_WRITE);

	//Enable SB2 interrupt
	writel(SB2_ACPU_INT_EN | SB2_SCPU_INT_EN | WRITE_DATA_1, SB2_DBG_INT);
	writel(SWCIVA_INT | ACIVA_INT | SCIVA_INT | WRITE_DATA_0, SB2_INV_INTSTAT);
	writel(SWCIVAIRQ_EN | ACIVAIRQ_EN | SCIVAIRQ_EN | WRITE_DATA_1 | readl(SB2_INV_INTEN), SB2_INV_INTEN);

	pr_info("[SB2 DBG][%s] initialized\n", __FUNCTION__);

	return 0;
}

static int sb2_dbg_exit(struct platform_device *pdev)
{
	struct device_node *np;
	int sb2_irq;

	pr_info("[SB2 DBG][%s]\n", __FUNCTION__);

	np = pdev->dev.of_node;
	sb2_irq = irq_of_parse_and_map(np, 0);

	//Disable  SB2 interrupt
	writel(0x0, SB2_DBG_INT);

	free_irq(sb2_irq, NULL);

	return 0;
}

int sb2_dbg_suspend(struct device *dev)
{
	pr_info("[SB2 DBG] Enter %s\n", __FUNCTION__);
	//Disable  SB2 interrupt
	writel(0x0, SB2_DBG_INT);

	pr_info("[SB2 DBG] Exit %s\n", __FUNCTION__);

	return 0;
}

int sb2_dbg_resume(struct device *dev)
{
	pr_info("[SB2 DBG] Enter %s\n", __FUNCTION__);

	//Enable SB2 interrupt
	writel(SB2_ACPU_INT_EN | SB2_SCPU_INT_EN | WRITE_DATA_1, SB2_DBG_INT);
	writel(SWCIVA_INT | ACIVA_INT | SCIVA_INT | WRITE_DATA_0, SB2_INV_INTSTAT);
	writel(SWCIVAIRQ_EN | ACIVAIRQ_EN | SCIVAIRQ_EN | WRITE_DATA_1 | readl(SB2_INV_INTEN), SB2_INV_INTEN);

	pr_info("[SB2 DBG] Exit %s\n",__FUNCTION__);

	return 0;
}

void sb2_dbg_disable_mem_monitor(int which)
{
	u32 *reg_ctrl = (u32 *) SB2_DBG_CTRL_REG0;
	reg_ctrl += which;

	writel((1 << 13) | (1 << 9) | (1 << 1), reg_ctrl);
}
EXPORT_SYMBOL(sb2_dbg_disable_mem_monitor);

static void sb2_dbg_set_mem_monitor(int which, u32 start, u32 end, u32 flags)
{
	u32 *reg_start, *reg_end, *reg_ctrl;

	/* disable this set first */
	sb2_dbg_disable_mem_monitor(which);

	reg_start = ((u32 *) SB2_DBG_START_REG0) + which;
	reg_end = ((u32 *) SB2_DBG_END_REG0) + which;
	reg_ctrl = ((u32 *) SB2_DBG_CTRL_REG0) + which;

	writel(start, reg_start);
	writel(end, reg_end);
	writel(flags, reg_ctrl);

	/*
	pr_info("sb2 0x%08x=0x%08x\n", (u32)reg_ctrl, readl(reg_ctrl));
	pr_info("sb2 0x%08x=0x%08x\n", (u32)reg_start, readl(reg_start));
	pr_info("sb2 0x%08x=0x%08x\n", (u32)reg_end, readl(reg_end));
	pr_info("sb2 0x%08x=0x%08x\n", (u32)SB2_DBG_INT, readl(SB2_DBG_INT));
	*/
}

/*
 * which: 0~7, which register set
 * d_i: SB2_DBG_MONITOR_DATA|SB2_DBG_MONITOR_INST
 * r_w: SB2_DBG_MONITOR_READ|SB2_DBG_MONITOR_WRITE
 */
void sb2_dbg_scpu_monitor(int which, u32 start, u32 end, u32 d_i, u32 r_w)
{
	sb2_dbg_set_mem_monitor(which, start, end, (1 << 13) | (3 << 8) | d_i | r_w | 3);
}
EXPORT_SYMBOL(sb2_dbg_scpu_monitor);

void sb2_dbg_acpu_monitor(int which, u32 start, u32 end, u32 d_i, u32 r_w)
{
	sb2_dbg_set_mem_monitor(which, start, end, (3 << 12) | (1 << 9) | d_i | r_w | 3);
}
EXPORT_SYMBOL(sb2_dbg_acpu_monitor);

static struct dev_pm_ops sb2_pm_ops = {
	.suspend_noirq = sb2_dbg_suspend,
	.resume_noirq = sb2_dbg_resume,
};

static const struct of_device_id rtk_sb2_match[] = {
	{.compatible = "Realtek,rtk-sb2"},
	{},
};

static struct platform_driver rtk129x_sb2_driver = {
	.probe = sb2_dbg_init,
	.remove = sb2_dbg_exit,
	.driver = {
		.name = "rtk129x-sb2",
		.owner = THIS_MODULE,
		.pm = &sb2_pm_ops,
		.of_match_table = of_match_ptr(rtk_sb2_match),
	},
};
module_platform_driver(rtk129x_sb2_driver);

MODULE_DESCRIPTION("Realtek SB2 driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:rtk119x-sb2");
