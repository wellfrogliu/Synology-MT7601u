#ifndef _LINUX_POWER_CONTROL_H_
#define _LINUX_POWER_CONTROL_H_

struct power_control;

struct device_node;

struct power_control_ops {
    int (*power_on)(struct power_control *);
    int (*power_off)(struct power_control *);
    int (*is_powered_on)(struct power_control *);
};

struct power_control {
    struct list_head list;
    const char *name;
    struct power_control_ops *ops;
    struct module *owner; // never access this
    struct device_node *of_node;
};

#ifdef CONFIG_POWER_CONTROL
int power_control_power_on(struct power_control *pctrl);
int power_control_power_off(struct power_control *pctrl);
int power_control_is_powered_on(struct power_control *pctrl);
struct power_control *power_control_get(const char *name);
struct power_control *of_power_control_get(struct device_node *node,
                       const char *id);
int power_control_register(struct power_control *pctrl);
void power_control_unregister(struct power_control *pctrl);

#else

inline static int power_control_power_on(struct power_control *pctrl)
{
    WARN_ON(1);
    return 0;
}

inline static int power_control_power_off(struct power_control *pctrl)
{
    WARN_ON(1);
    return 0;
}

inline static int power_control_is_powered_on(struct power_control *pctrl)
{
    WARN_ON(1);
    return -EINVAL;
}

inline static struct power_control *power_control_get(const char *name)
{
    WARN_ON(1);
    return NULL;
}

inline static struct power_control *of_power_control_get(struct device_node *node,
                       const char *id)
{
    WARN_ON(1);
    return NULL;
}

inline static int power_control_register(struct power_control *pctrl)
{
    WARN_ON(1);
    return 0;
}

inline static void power_control_unregister(struct power_control *pctrl)
{
    WARN_ON(1);
}

#endif

inline static int power_control_enable_hw_pm(struct power_control *pctrl)
{
    return power_control_power_off(pctrl);
}

inline static int power_control_disable_hw_pm(struct power_control *pctrl)
{
    return power_control_power_on(pctrl);
}

#endif
