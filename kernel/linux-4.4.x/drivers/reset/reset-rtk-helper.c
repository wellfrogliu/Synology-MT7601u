#define pr_fmt(fmt) "reset-rtk: " fmt

#include <linux/list.h>
#include <linux/reset.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/reset.h>

#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>

static int dfs_read(struct seq_file *s, void *v)
{
    struct reset_control * rstc = (struct reset_control *)s->private;
    seq_printf(s, "%d\n", reset_control_status(rstc));
    return 0;
}

static int dfs_open(struct inode *inode, struct file *filp)
{
    return single_open(filp, dfs_read, inode->i_private);
}

static ssize_t dfs_write_assert(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
    struct reset_control * rstc = (struct reset_control *)filp->f_inode->i_private;
    reset_control_assert(rstc);
    return count;
}

static ssize_t dfs_write_deassert(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
    struct reset_control * rstc = (struct reset_control *)filp->f_inode->i_private;
    reset_control_deassert(rstc);
    return count;
}

const struct file_operations rtk_rst_debugfs_assert_fops = {
    .owner   = THIS_MODULE,
    .open    = dfs_open,
    .read    = seq_read,
    .write   = dfs_write_assert,
    .release = single_release,
};

const struct file_operations rtk_rst_debugfs_deassert_fops = {
    .owner   = THIS_MODULE,
    .open    = dfs_open,
    .read    = seq_read,
    .write   = dfs_write_deassert,
    .release = single_release,
};

struct reset_control_lookup {
    struct list_head      node;
    const char           *name;
    struct reset_control *rstc;
};

static struct dentry * rtk_dfs_root = NULL;

static LIST_HEAD(rstc_list);

static DEFINE_MUTEX(rstc_mutex);

#define to_reset_control_lookup(_p) container_of((_p), struct reset_control_lookup, node)

struct reset_control * rstc_get(const char * name)
{
    struct reset_control_lookup *data;
    struct list_head * it = NULL;
    struct reset_control *rstc = NULL;

    if (!name)
        goto err;

    mutex_lock(&rstc_mutex);
    list_for_each(it, &rstc_list) {
        data = to_reset_control_lookup(it);
        if (!strcmp(data->name, name))
        {
            rstc = data->rstc;
            break;
        }

    }
    mutex_unlock(&rstc_mutex);

    return rstc;
err:
    return NULL;
}
EXPORT_SYMBOL(rstc_get);

int rstc_add(struct reset_control *rstc, const char * name)
{
    struct reset_control_lookup *data;

    if (!name || rstc_get(name))
        goto err;

    data = kzalloc(sizeof(*data), GFP_KERNEL);
    data->name = name;
    data->rstc = rstc;

    mutex_lock(&rstc_mutex);
    list_add(&data->node, &rstc_list);
    mutex_unlock(&rstc_mutex);

    //pr_info(" %s is added\n", name);

#ifdef CONFIG_DEBUG_FS
    if (!rtk_dfs_root)
        rtk_dfs_root = debugfs_create_dir("rtk_rst", NULL);

    {
        struct dentry * cur = debugfs_create_dir(name, rtk_dfs_root);
        debugfs_create_file("rst_assert", S_IRUGO, cur, rstc, &rtk_rst_debugfs_assert_fops);
        debugfs_create_file("rst_deassert", S_IRUGO, cur, rstc, &rtk_rst_debugfs_deassert_fops);
    }
#endif

    return 0;
err:
    pr_info(" %s is already in the list\n", name);
    return -EINVAL;
}
EXPORT_SYMBOL(rstc_add);
