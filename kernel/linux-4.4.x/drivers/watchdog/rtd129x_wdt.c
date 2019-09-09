#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/platform_device.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/uaccess.h>
#include <asm/mutex.h>
#include <asm/io.h>
#include <linux/suspend.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>

static void __iomem *ISO_WATCH_BASE;

#define ISO_WDT_CTL					0x0
#define ISO_WDT_CLR					0x4
#define ISO_WDT_NMI        			0x8
#define ISO_WDT_OVERFLOW			0xC

#define ISO_WDT_CLK					(27000000)	// 27MHz
#define ISO_WDT_1MS_CNT				(27000)

#define IOMEM(x)        ((void __force __iomem *)(x))

static char * rtk_watchdog_buffer_read;
static char * rtk_watchdog_buffer_write;

struct proc_dir_entry * rtk_watchdog_dir = NULL;
struct proc_dir_entry * rtk_watchdog_entry = NULL;

#define MAX_LINE_SIZE 128

enum {
    STATE_DISABLE = 0,
    STATE_ENABLE,
    STATE_NONE,
};
static int watchdog_state = STATE_DISABLE;
static int watchdog_suspend_state = STATE_NONE;
struct mutex watchdog_mutex;
unsigned int kick_ignore;

#define ENABLE_RTK_WATCHDOG

int rtk_watchdog_kick( unsigned int msec )
{
    mutex_lock(&watchdog_mutex);

    if( msec == 0xdeadbeef ) {
        printk("kick watchdog threshold (%d ms)\n", msec);
        writel(1, ISO_WATCH_BASE + ISO_WDT_CLR);
        writel(0x0080beef, ISO_WATCH_BASE + ISO_WDT_OVERFLOW);
        writel(0xff, ISO_WATCH_BASE + ISO_WDT_CTL);
        kick_ignore = 1;
    }
    else {
        if( !kick_ignore ) {
            printk("kick watchdog threshold (%d ms)\n", msec);
            writel(1, ISO_WATCH_BASE + ISO_WDT_CLR);
            writel((msec*ISO_WDT_1MS_CNT), ISO_WATCH_BASE + ISO_WDT_OVERFLOW);
            writel(0xff, ISO_WATCH_BASE + ISO_WDT_CTL);
        }
    }

    mutex_unlock(&watchdog_mutex);

    return 0;
}
EXPORT_SYMBOL(rtk_watchdog_kick);

static int rtk_watchdog_enable( void )
{
    if (watchdog_suspend_state != STATE_NONE) {
        printk("Invalid setting! suspend state is %d\n",watchdog_suspend_state);
        return 0;
    }
    mutex_lock(&watchdog_mutex);
    printk("enable watchdog reset\n");
    writel(0xFF, ISO_WATCH_BASE + ISO_WDT_CTL);
    kick_ignore = 0;
    watchdog_state = STATE_ENABLE;
    mutex_unlock(&watchdog_mutex);
    return 0;
}

static int rtk_watchdog_disable( void )
{
    mutex_lock(&watchdog_mutex);
    printk("disable watchdog reset\n");
    writel(0xA5, ISO_WATCH_BASE + ISO_WDT_CTL);
    kick_ignore = 1;
    watchdog_state = STATE_DISABLE;
    mutex_unlock(&watchdog_mutex);
    return 0;
}

static int rtk_watchdog_suspend(void)
{
    if (watchdog_suspend_state != STATE_NONE)
        return 0;

    watchdog_suspend_state = watchdog_state;

    if (watchdog_suspend_state == STATE_ENABLE)
        return rtk_watchdog_disable();
    else
        return 0;
}

static int rtk_watchdog_resume(void)
{
    int ret = 0;
    if (watchdog_suspend_state == STATE_ENABLE) {
        watchdog_suspend_state = STATE_NONE;
        ret =  rtk_watchdog_enable();
    }

    watchdog_suspend_state = STATE_NONE;
    return ret;
}

static int rtk_watchdog_notifier_event(struct notifier_block *this,
                                       unsigned long event, void *ptr)
{
    switch (event) {
    case PM_SUSPEND_PREPARE:
    {
        rtk_watchdog_suspend();
        break;
    }
    case PM_POST_RESTORE:
    case PM_POST_SUSPEND:
    {
        rtk_watchdog_resume();
        break;
    }
    default:
        break;
    }

    return NOTIFY_OK;
}

static struct notifier_block rtk_watchdog_notifier = {
    .notifier_call = rtk_watchdog_notifier_event,
};

static int rtk_watchdog_proc_open(struct inode *inode, struct file *file)
{
    //printk("OPEN proc/watchdog...\n");
    return single_open(file, NULL, inode->i_private);
}

static ssize_t rtk_watchdog_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    int total_len;
    int len2;
    int ret;

#if 1
    char * pBuf = rtk_watchdog_buffer_read;
    memset( pBuf,0,MAX_LINE_SIZE );

    len2 = sprintf( pBuf, "WD overflow reg = 0x%08x\n", readl(ISO_WATCH_BASE + ISO_WDT_OVERFLOW) );
    total_len = len2;

    len2 = sprintf( pBuf+total_len, "WD control reg = 0x%08x\n", readl(ISO_WATCH_BASE + ISO_WDT_CTL) );
    total_len += len2;

    ret = copy_to_user(buf, pBuf, total_len);
#else
    char * pBuf = "Hello World!\n";
    total_len = strlen(pBuf);
    ret = copy_to_user(buf, pBuf, total_len);
#endif

    if (ret) {
        printk("copy_to_user failed!\n");
        return 0;//-EFAULT;
    }
    if (*ppos == 0) {
        *ppos += total_len;
    }
    else {
        total_len = 0;
    }
    return total_len;
}

static ssize_t rtk_watchdog_proc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    char str[MAX_LINE_SIZE];
    int ret;
    if (count > PAGE_SIZE) { //procfs write and read has PAGE_SIZE limit
        count = MAX_LINE_SIZE;
    }

    ret = copy_from_user(str, buf, count);
    if (ret)
    {
        printk("copy_from_user failed!\n");
        return -EFAULT;
    }

    if( strncmp( str, "kick", 4 ) == 0 ) {
        //rtk_watchdog_kick(5000); // 5000ms
        //rtk_watchdog_kick(10000); // 10000ms
        rtk_watchdog_kick(20000); // 20000ms 20000*27000=0x202fbf00
    }
    if( strncmp( str, "disable", 7 ) == 0 ) {
        rtk_watchdog_disable();
    }
    if( strncmp( str, "enable", 6 ) == 0 ) {
        rtk_watchdog_enable();
    }

    str[count-1] = '\0';
    //printk("Your enter :\n%s\n", str);

    return count;
}

static const struct file_operations rtk_watchdog_proc_fops = {
    .owner = THIS_MODULE,
    .open  = rtk_watchdog_proc_open,
    .read  = rtk_watchdog_proc_read,
    .write = rtk_watchdog_proc_write,
    .release = single_release,
};

static int rtk_watchdog_probe(struct platform_device *pdev)
{
    rtk_watchdog_buffer_read = NULL;
    rtk_watchdog_buffer_write = NULL;
    kick_ignore = 0;

    printk(KERN_INFO "%s: rtk watchdog driver init\n", __func__);

    ISO_WATCH_BASE = of_iomap(pdev->dev.of_node, 0);
    printk(KERN_INFO "%s: RTK Watchdog base address 0x%08llx\n", __func__, (u64)ISO_WATCH_BASE);

    mutex_init(&watchdog_mutex);

    // set watchdog timeout value ( base: ms )
    rtk_watchdog_kick(120000); // 120000*27000=0xC11E_7A00

    // disable watchdog
#ifdef CONFIG_RTK_WATCHDOG_ENABLE_TIMER
    rtk_watchdog_enable();
#else
    rtk_watchdog_disable();
#endif

    // create proc/watchdog entry
    rtk_watchdog_buffer_read = kzalloc( MAX_LINE_SIZE, GFP_KERNEL);
    rtk_watchdog_buffer_write = kzalloc( MAX_LINE_SIZE, GFP_KERNEL);
    if (!rtk_watchdog_buffer_read || !rtk_watchdog_buffer_write) {
        printk("no mem\n");

        if( !rtk_watchdog_buffer_read ) {
            kfree(rtk_watchdog_buffer_read);
        }
        if( !rtk_watchdog_buffer_write ) {
            kfree(rtk_watchdog_buffer_write);
        }

        return -ENOMEM;
    }

    /* create a procfs entry for read-only */
#ifdef CONFIG_PROC_FS
    //rtk_watchdog_dir = proc_mkdir(dir_name, NULL);
    //if (!rtk_watchdog_dir)
    //{
    //	printk("Create directory \"%s\" failed.\n", dir_name);
    //	return -1;
    //}

    rtk_watchdog_entry = proc_create("watchdog", 0x0644, NULL, &rtk_watchdog_proc_fops);
    if (!rtk_watchdog_entry) {
        printk("create proc failed\n");

        if( !rtk_watchdog_buffer_read ) {
            kfree(rtk_watchdog_buffer_read);
        }
        if( !rtk_watchdog_buffer_write ) {
            kfree(rtk_watchdog_buffer_write);
        }

        return -1;
    }
#else
    printk("This module requests the kernel to support procfs,need set CONFIG_PROC_FS configure Y\n");
#endif

    register_pm_notifier(&rtk_watchdog_notifier);

    return 0;
}

static int rtk_watchdog_remove(struct platform_device *pdev)
{
    printk(KERN_INFO "rtk watchdog driver exit\n");

    // remove proc/watchdog entry
#ifdef CONFIG_PROC_FS
    //proc_remove(rtk_watchdog_entry);
    proc_remove(rtk_watchdog_dir);
#endif

    // free resource
    if( !rtk_watchdog_buffer_read ) {
        kfree(rtk_watchdog_buffer_read);
    }
    if( !rtk_watchdog_buffer_write ) {
        kfree(rtk_watchdog_buffer_write);
    }

    unregister_pm_notifier(&rtk_watchdog_notifier);

    return 0;
}

static const struct of_device_id rtd1295_watchdog_match[] = {
    { .compatible = "Realtek,rtk-watchdog" },
    {},
};
MODULE_DEVICE_TABLE(of, rtd1295_watchdog_match);

static struct platform_driver rtd1295_watchdog_driver = {
    .probe = rtk_watchdog_probe,
    .remove = rtk_watchdog_remove,
    //.shutdown	= rtk_watchdog_shutdown,
    .driver = {
        .name = KBUILD_MODNAME,
        .of_match_table	= rtd1295_watchdog_match,
    },
};

module_platform_driver(rtd1295_watchdog_driver);
