#include <linux/slab.h>
#include <linux/power-control.h>
#include <linux/of.h>
#include "powerctrl.h"

DEFINE_MUTEX(power_control_list_mutex);

LIST_HEAD(power_control_list);

#define to_power_control(_p) container_of((_p), struct power_control, list)

int power_control_power_on(struct power_control *pctrl)
{
    int ret = 0;
    struct power_control_priv *priv;

    if (!pctrl)
        return -EINVAL;

    priv = (struct power_control_priv *)pctrl->owner;
    priv->count_on ++;
    priv->count_x ++;
    priv->last_call = PC_ON;

    if (pctrl->ops->power_on)
        ret = pctrl->ops->power_on(pctrl);

    return ret;
}
EXPORT_SYMBOL(power_control_power_on);

int power_control_power_off(struct power_control *pctrl)
{
    int ret = 0;
    struct power_control_priv *priv;

    if (!pctrl)
        return -EINVAL;

    priv = (struct power_control_priv *)pctrl->owner;
    priv->count_off ++;
    priv->count_x --;
    priv->last_call = PC_OFF;

    if (pctrl->ops->power_off);
    ret = pctrl->ops->power_off(pctrl);

    return ret;
}
EXPORT_SYMBOL(power_control_power_off);

int power_control_is_powered_on(struct power_control *pctrl)
{
    if (!pctrl)
        return -EINVAL;

    if (pctrl->ops->is_powered_on)
        return pctrl->ops->is_powered_on(pctrl);

    return -EINVAL;
}
EXPORT_SYMBOL(power_control_is_powered_on);

struct power_control *power_control_get(const char * name)
{
    struct power_control *pctrl, *rctrl = NULL;
    struct list_head * it = NULL;

    mutex_lock(&power_control_list_mutex);
    list_for_each(it, &power_control_list) {
        pctrl = to_power_control(it);
        if (!strcmp(pctrl->name, name))
        {
            rctrl = pctrl;
            break;
        }
    }
    mutex_unlock(&power_control_list_mutex);

    return rctrl;
}
EXPORT_SYMBOL(power_control_get);

struct power_control *of_power_control_get(struct device_node *node,
        const char *id)
{
    struct power_control *ctrl = NULL, *r;
    struct of_phandle_args args;
    int index = 0;
    int ret;

    if (id)
        index = of_property_match_string(node,
                                         "powerctrl-names", id);
    ret = of_parse_phandle_with_args(node, "powerctrls", "#powerctrl-cells",
                                     index, &args);
    if (ret)
        return ERR_PTR(ret);

    mutex_lock(&power_control_list_mutex);
    list_for_each_entry(r, &power_control_list, list) {
        if (args.np == r->of_node) {
            ctrl = r;
            break;
        }
    }
    mutex_unlock(&power_control_list_mutex);

    return ctrl;
}
EXPORT_SYMBOL(of_power_control_get);

int power_control_register(struct power_control *pctrl)
{
    struct power_control_priv *priv = kzalloc(sizeof(struct power_control_priv), GFP_KERNEL);

    if (!priv)
        return -ENOMEM;
    pctrl->owner = (struct module *)priv;
    priv->count_on  = 0;
    priv->count_off = 0;
    priv->count_x   = 0;
    priv->last_call = PC_NONE;

    mutex_lock(&power_control_list_mutex);
    list_add(&pctrl->list, &power_control_list);
    mutex_unlock(&power_control_list_mutex);
    return 0;
}
EXPORT_SYMBOL(power_control_register);

void power_control_unregister(struct power_control *pctrl)
{
    mutex_lock(&power_control_list_mutex);
    list_del(&pctrl->list);
    mutex_unlock(&power_control_list_mutex);

    kfree(pctrl->owner);
}
EXPORT_SYMBOL(power_control_unregister);
