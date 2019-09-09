#include <linux/slab.h>
#include <linux/power-control.h>
#include <linux/mutex.h>
#include "powerctrl.h"
#include <linux/debugfs.h>

static struct dentry *power_control_root;

#define DEFINE_OPEN(open_func_name, show_func_name) \
static int open_func_name(struct inode *inode, struct file *file) \
{ \
    return single_open(file, show_func_name, inode->i_private); \
}

static int power_control_summary_show(struct seq_file *s, void *data)
{
    struct power_control *pctrl;
    struct power_control_priv *priv;
    struct list_head *it = NULL;
    int is_powered_on;

    seq_printf(s, "%-28s %-9s %-9s %3s = %8s - %8s\n",
               "POWER_CONTROL_NAME", "STATE", "LAST_CALL",
               "X", "CNT_ON", "CNT_OFF");

    mutex_lock(&power_control_list_mutex);
    list_for_each(it, &power_control_list) {
        pctrl = to_power_control(it);
        priv = (struct power_control_priv *)pctrl->owner;

        is_powered_on = power_control_is_powered_on(pctrl);
        seq_printf(s, "%-28s %-9s %-9s %3d   %8d   %8d\n",
                   pctrl->name,
                   is_powered_on == -EINVAL ?  "INVAL" :
                   is_powered_on == -EPERM ? "NOT_PERM" :
                   is_powered_on == 0 ? "OFF" : "ON",
                   priv->last_call == PC_NONE ? "NONE" :
                   priv->last_call == PC_ON ? "POWER_ON" : "POWER_OFF",
                   priv->count_x,
                   priv->count_on,
                   priv->count_off
                  );

    }
    mutex_unlock(&power_control_list_mutex);
    return 0;

}

DEFINE_OPEN(power_control_summary_open, power_control_summary_show);

static struct file_operations power_control_summary_ops = {
    .owner   = THIS_MODULE,
    .open    = power_control_summary_open,
    .read    = seq_read,
    .release = single_release,
};

static int __init power_control_debugfs_init(void)
{
    power_control_root = debugfs_create_dir("power_control", NULL);
    debugfs_create_file("power_control_summary", 0444,
                        power_control_root, NULL, &power_control_summary_ops);
    return 0;
}
late_initcall(power_control_debugfs_init);
