#define pr_fmt(fmt) "cpuidle-rtk-cm: " fmt

#include <linux/slab.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/cpu.h>
#include <linux/device.h>
#include <linux/cpumask.h>
#include <linux/bitmap.h>
#include <linux/fs.h>
#include <linux/cpufreq.h>
#include <asm/uaccess.h>
#include <linux/delay.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/debugfs.h>
#include <linux/cpu_pm.h>
#include <linux/pm.h>
#include <linux/suspend.h>
#include <linux/proc_fs.h>

/********************************************************************************
 *  rtk_cpuidle_init
 ********************************************************************************/
void disable_cpuidle(void);

static int  __init rtk_cpuidle_init(void)
{
    /* disable original cpuidle functions */
    disable_cpuidle();

    return 0;
}
early_initcall(rtk_cpuidle_init);
