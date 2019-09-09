#define pr_fmt(fmt) "corectrl: " fmt

#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/device.h>
#include <linux/kthread.h>
#include <linux/cpumask.h>
#include <linux/bitmap.h>
#include <linux/cpufreq.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/of.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/platform_device.h>
#include <linux/sysfs.h>
#include <linux/pm.h>
#include <linux/suspend.h>
#include <linux/core_control.h>
#include <linux/string.h>

#define ENABLE_RTK_CORE_CONTROL_TESTING 0

#define CORE_CONTROL_NAME_LENGTH 20

struct core_controller {
    char name[CORE_CONTROL_NAME_LENGTH];
    struct list_head list;
};

enum core_control_state {
    CORE_CONTROL_NONE,
    CORE_CONTROL_HOTPLUG,
    CORE_CONTROL_HOTPLUG_DONE,
};

enum core_control_act {
    CORE_CONTROL_CPU_ONLINE,
    CORE_CONTROL_CPU_OFFLINE,
};

static int core_control_enabled;
static int core_control_suspend;
static struct kobject *core_control_kobj;
static struct completion hotplug_notify_complete;
static struct task_struct *hotplug_task;
static int force_online = 0;
static DEFINE_MUTEX(core_control_mutex);
static volatile enum core_control_state task_state;
static struct cpumask available_cpus;
static struct cpumask cpus_to_online;
static struct cpumask cpus_to_offline;
static struct cpumask offlined_cpus;
static BLOCKING_NOTIFIER_HEAD(core_control_chain_head);
static struct core_controller *current_controller;
static LIST_HEAD(controller_list);
static DEFINE_MUTEX(controller_list_mutex);

static inline int core_control_notification(unsigned long val, void *data)
{
    int ret = blocking_notifier_call_chain(&core_control_chain_head, val, data);
    return notifier_to_errno(ret);
}

static inline bool core_control_is_current_controller(struct core_controller *cc)
{
    bool ret;
    mutex_lock(&controller_list_mutex);
    ret = cc == current_controller;
    mutex_unlock(&controller_list_mutex);
    return ret;
}

/*
 * core control APIs
 *
 */
/**
 *  of_core_control_read_cpumask - read cpumask from a CPU phandle list
 *  @np: device node
 *  @prop_name: property name
 *  @out: cpumask to be read to, changed only if function call is successs
 *
 *  This is an example,
 *    in device tree:
 *      node {
 *        ...
 *        cpu-list = <&A53_1>,<&A53_2>, <&A53_3>;
 *        ...
 *      };
 *
 *    in c code:
 *      of_core_control_read_cpumask(np, "cpu-list", &mask);
 *
 *   which returns a mask with 1-3.
 *
 *  Returns 0 if success, or %-EINVAL if property not exist
 */
int of_core_control_read_cpumask(struct device_node *np,
    const char *prop_name, struct cpumask *out)
{
    struct cpumask mask;
    int list_size;
    int i;

    cpumask_clear(&mask);

    if (!of_get_property(np, prop_name, &list_size) || list_size <= 0) {
        pr_err("Failed to read CPU-list %s\n", prop_name);
        return -EINVAL;
    }

    list_size /= sizeof(__be32);
    for (i = 0; i < list_size; i++) {
        int cpu;
        struct device_node *cpu_phandle =
            of_parse_phandle(np, prop_name, i);

        if (!cpu_phandle)
            break;

        for_each_possible_cpu(cpu) {
            if (of_get_cpu_node(cpu, NULL) == cpu_phandle) {
                cpumask_set_cpu(cpu, &mask);
                break;
            }
        }
    }

    if (i != list_size) {
        pr_warning("CPU List size(%d) != Read count (%d)\n", list_size, i);
    }

    cpumask_copy(out, &mask);

    return 0;
}
EXPORT_SYMBOL_GPL(of_core_control_read_cpumask);

/**
 *  core_control_is_enabled - return core_control is enabled or not
 *
 *  Returns true if enabled, false if disabled.
 */
bool core_control_is_enabled(void)
{
    return core_control_enabled == 1;
}
EXPORT_SYMBOL_GPL(core_control_is_enabled);

/**
 *  core_control_get_available_cpus - get available_cpus
 *  @out: available_cpus to be put
 *
 *  Returns 1 on success, 0 if core_control is not valid
 */
int core_control_get_available_cpus(struct cpumask *out)
{
    if (core_control_suspend)
        return -EINVAL;

    if (!core_control_enabled)
        return -EINVAL;

    mutex_lock(&core_control_mutex);
    cpumask_copy(out, &available_cpus);
    mutex_unlock(&core_control_mutex);

    return 0;
}
EXPORT_SYMBOL_GPL(core_control_get_available_cpus);

static bool __is_cpu_available(int cpu)
{
    return cpumask_test_cpu(cpu, &available_cpus);
}

/**
 *  core_control_is_cpu_available - test CPU is in available_cpus or not
 *  @cpu: CPU to be tested
 *
 *  Returns true if CPU is in the available_cpus, false if not
 */
bool core_control_is_cpu_available(int cpu)
{
    bool ret;
    mutex_lock(&core_control_mutex);
    ret = __is_cpu_available(cpu);
    mutex_unlock(&core_control_mutex);
    return ret;
}
EXPORT_SYMBOL_GPL(core_control_is_cpu_available);

static int __set_cpu_offline(int cpu)
{
    int ret = 0;

    if (core_control_suspend)
        return -EINVAL;

    if (!core_control_enabled)
        return -EINVAL;

    if (!__is_cpu_available(cpu)) {
        ret = -EINVAL;
    } else if (!cpumask_test_cpu(cpu, cpu_online_mask)) {
        ret = -EPERM;
    } else {
        cpumask_set_cpu(cpu, &cpus_to_offline);
        if (hotplug_task)
            complete(&hotplug_notify_complete);
        else
            ret = -ESRCH;
    }

    return ret;
}

/**
 *  core_control_set_cpu_offline - offline a specific CPU
 *  @cc: core_controller
 *  @cpu: CPU to be offline
 *
 *  Only the core_controller with token can change the core state
 *
 *  Returns 0 on successs, %-EINVAL if core_controller not the token owner,
 *   or core_control is not valid, or CPU is not in available_cpus, %-EPERM
 *   if the CPU is already offlined, %-ESRCH if the worker thread in not
 *   valid.
 */
int core_control_set_cpu_offline(struct core_controller *cc, int cpu)
{
    int ret;

    if(!core_control_is_current_controller(cc))
        return -EINVAL;

    mutex_lock(&core_control_mutex);
    ret = __set_cpu_offline(cpu);
    mutex_unlock(&core_control_mutex);

    return ret;
}
EXPORT_SYMBOL_GPL(core_control_set_cpu_offline);

/**
 *  core_control_set_any_cpu_offline - offline any CPU in available_cpus
 *  @cc: core_controller
 *
 *  Only the core_controller with token can change the core state
 *
 *  Returns 0 on successs, %-EINVAL if core_controller not the token owner,
 *   or core_control is not valid, or CPU is not in available_cpus, %-EPERM
 *   if the CPU is already offlined, %-ESRCH if the worker thread in not
 *   valid.
 */
int core_control_set_any_cpu_offline(struct core_controller *cc)
{
    struct cpumask cpu_list;
    int cpu;
    int ret = -EINVAL;

    if(!core_control_is_current_controller(cc))
        return -EINVAL;

    mutex_lock(&core_control_mutex);

    cpumask_and(&cpu_list, &available_cpus, cpu_online_mask);

    cpu = cpumask_first(&cpu_list);
    if (cpu < nr_cpu_ids)
       ret = __set_cpu_offline(cpu);

    mutex_unlock(&core_control_mutex);

    return ret;
}
EXPORT_SYMBOL_GPL(core_control_set_any_cpu_offline);

static int __set_cpu_online(int cpu)
{
    int ret = 0;

    if (core_control_suspend)
        return -EINVAL;

    if (!core_control_enabled)
        return -EINVAL;

    if (!__is_cpu_available(cpu)) {
        ret = -EINVAL;
    } else if (cpumask_test_cpu(cpu, cpu_online_mask)) {
        ret = -EPERM;
    } else {
        cpumask_set_cpu(cpu, &cpus_to_online);
        if (hotplug_task)
            complete(&hotplug_notify_complete);
        else
           ret = -ESRCH;
    }

    return ret;
}

/**
 *  core_control_set_cpu_online - online a specific CPU
 *  @cc: core_controller
 *  @cpu: CPU to be online
 *
 *  Only the core_controller with token can change the core state
 *
 *  Returns 0 on successs, %-EINVAL if core_controller not the token owner,
 *   or core_control is not valid, or CPU is not in available_cpus, %-EPERM
 *   if the CPU is already onlined, %-ESRCH if the worker thread in not
 *   valid.
 */
int core_control_set_cpu_online(struct core_controller *cc, int cpu)
{
    int ret;

    if(!core_control_is_current_controller(cc))
        return -EINVAL;

    mutex_lock(&core_control_mutex);
    ret = __set_cpu_online(cpu);
    mutex_unlock(&core_control_mutex);

    return ret;
}
EXPORT_SYMBOL_GPL(core_control_set_cpu_online);

/**
 *  core_control_set_any_cpu_online - online any CPU in available_cpus
 *  @cc: core_controller
 *
 *  Only the core_controller with token can change the core state
 *
 *  Returns 0 on successs, %-EINVAL if core_controller not the token owner,
 *   or core_control is not valid, or CPU is not in available_cpus, %-EPERM
 *   if the CPU is already onlined, %-ESRCH if the worker thread in not
 *   valid.
 */
int core_control_set_any_cpu_online(struct core_controller *cc)
{
    struct cpumask cpu_list;
    int cpu;
    int ret = -EINVAL;

    if(!core_control_is_current_controller(cc))
        return -EINVAL;

    mutex_lock(&core_control_mutex);

    cpumask_andnot(&cpu_list, &available_cpus, cpu_online_mask);

    cpu = cpumask_first(&cpu_list);
    if (cpu < nr_cpu_ids)
        ret = __set_cpu_online(cpu);

    mutex_unlock(&core_control_mutex);

    return ret;
}
EXPORT_SYMBOL_GPL(core_control_set_any_cpu_online);

/**
 *  register_core_control_notifier - register core_control notifier
 *  @nb: notifier block
 */
int register_core_control_notifier(struct notifier_block *nb)
{
    return blocking_notifier_chain_register(&core_control_chain_head, nb);
}
EXPORT_SYMBOL_GPL(register_core_control_notifier);

/**
 *  unregister_core_control_notifier - unregister core_control notifier
 *  @nb: notifier block
 */
int unregister_core_control_notifier(struct notifier_block *nb)
{
     return blocking_notifier_chain_unregister(&core_control_chain_head, nb);
}
EXPORT_SYMBOL_GPL(unregister_core_control_notifier);

/**
 *  core_control_register_controller - register a core_controller
 *  @name: core_controller name
 *
 *  Register a core_controller. Only core_controller with token can change
 *   the state of CPUs
 *
 *  Returns core_controller on success, NULL if NOMEM
 */
struct core_controller *core_control_register_controller(const char *name)
{
    struct core_controller *cc = kzalloc(sizeof(*cc), GFP_KERNEL);
    if (!cc)
        return NULL;

    strncpy(cc->name, name, CORE_CONTROL_NAME_LENGTH);

    mutex_lock(&controller_list_mutex);
    list_add(&cc->list, &controller_list);
    mutex_unlock(&controller_list_mutex);

    return cc;
}
EXPORT_SYMBOL_GPL(core_control_register_controller);

/**
 *  core_control_unregister_controller - unregister a core_controller
 *  @cc: core_controller
 *
 *  Returns 0 if success
 */
int core_control_unregister_controller(struct core_controller *cc)
{
    mutex_lock(&controller_list_mutex);
    list_del(&cc->list);
    mutex_unlock(&controller_list_mutex);

    kfree(cc);
    return 0;
}
EXPORT_SYMBOL_GPL(core_control_unregister_controller);

/**
 *  core_control_set_token_owner - set the token to core_controller
 *  @cc: core_controller to own the token
 *
 *  Only core_controller with token can change the state of CPUs.
 */
int core_control_set_token_owner(struct core_controller *cc)
{
    mutex_lock(&controller_list_mutex);
    pr_info("token_owenr %s -> %s\n",
        current_controller == NULL ? "X" : current_controller->name,
        cc == NULL ? "X" : cc->name);

    current_controller = cc;
    mutex_unlock(&controller_list_mutex);

    return 0;
}
EXPORT_SYMBOL_GPL(core_control_set_token_owner);

/**
 * core_control_get_token_owner - get the core_controller with the token
 *
 * Returns the core_controller with the token
 */
struct core_controller *core_control_get_token_owner(void)
{
    struct core_controller *cc ;
    mutex_lock(&controller_list_mutex);
    cc = current_controller;
    mutex_unlock(&controller_list_mutex);
    return cc;
}
EXPORT_SYMBOL_GPL(core_control_get_token_owner);

/*
 * Core functions
 *
 */
static inline void set_cpu_state(int cpu_id, int act)
{
    struct device *dev = get_cpu_device(cpu_id);
    struct cpu *cpu = container_of(dev, struct cpu, dev);

    if (act == CORE_CONTROL_CPU_ONLINE) {
        device_online(&cpu->dev);
        pr_info("CPU %d is online\n", cpu_id);
    } else if (act == CORE_CONTROL_CPU_OFFLINE) {
        device_offline(&cpu->dev);
        pr_info("CPU %d is offline\n", cpu_id);
    }
}

static int do_hotplug(void *data)
{
    int n_off, n_on;
    struct cpumask mask;
    int cpu;
    struct sched_param param = {.sched_priority = MAX_RT_PRIO-2};

    sched_setscheduler(current, SCHED_FIFO, &param);
    while (!kthread_should_stop()) {
        while (wait_for_completion_interruptible(&hotplug_notify_complete) != 0);

        reinit_completion(&hotplug_notify_complete);

        mutex_lock(&core_control_mutex);

        cpumask_and(&mask, &cpus_to_online, &cpus_to_offline);
        cpumask_xor(&cpus_to_online, &cpus_to_online, &mask);
        cpumask_xor(&cpus_to_offline, &cpus_to_offline, &mask);

        n_on  = cpumask_weight(&cpus_to_online);
        n_off = cpumask_weight(&cpus_to_offline);

        if (n_on == n_off) {
            cpumask_clear(&cpus_to_offline);
            cpumask_clear(&cpus_to_online);
            goto done;
        }

        task_state = CORE_CONTROL_HOTPLUG;
        cpufreq_update_policy(0); // FIXME: per cluster
        msleep(500);

        if (n_on > n_off) {
            if (force_online)
                cpu = cpumask_first(&cpus_to_online);
            else
                cpu = cpumask_first_and(&cpus_to_online, &offlined_cpus);

            if (cpu < nr_cpu_ids) {
                BUG_ON(cpumask_test_cpu(cpu, cpu_online_mask));

                set_cpu_state(cpu, CORE_CONTROL_CPU_ONLINE);

                cpumask_clear_cpu(cpu, &cpus_to_online);
                cpumask_clear_cpu(cpu, &offlined_cpus);
            }
        } else if (n_on < n_off) {
            cpu = cpumask_first(&cpus_to_offline);

            if (cpu < nr_cpu_ids) {
                BUG_ON(!cpumask_test_cpu(cpu, cpu_online_mask));

                set_cpu_state(cpu, CORE_CONTROL_CPU_OFFLINE);

                cpumask_clear_cpu(cpu, &cpus_to_offline);
                cpumask_set_cpu(cpu, &offlined_cpus);
            }
        }

        task_state = CORE_CONTROL_HOTPLUG_DONE;
        cpufreq_update_policy(0); // FIXME: per cluster
        msleep(500);

done:
        task_state = CORE_CONTROL_NONE;
        mutex_unlock(&core_control_mutex);

        sysfs_notify(core_control_kobj, NULL, "online_cpus");
    }

    return 0;
}

/*
 * SysFS
 *
 */
static ssize_t enable_show(struct kobject *kobj, struct kobj_attribute *attr,
    char *buf)
{
    return sprintf(buf, "%u\n", core_control_enabled == 1);
}

static ssize_t enable_store(struct kobject *kobj, struct kobj_attribute *attr,
    const char *buf, size_t count)
{
    int ret;
    bool val;

    ret = strtobool(buf, &val);
    if (ret < 0)
        return ret;

    if (val && !core_control_enabled) {
        core_control_enabled = 1;
        core_control_notification(CORE_CONTROL_ENABLE, NULL);
    } else if (!val && core_control_enabled) {
        core_control_enabled = 0;
        core_control_notification(CORE_CONTROL_DISABLE, NULL);
    }

    return count;
}

static struct kobj_attribute enable_attr =  __ATTR_RW(enable);

static ssize_t available_cpus_show(struct kobject *kobj, struct kobj_attribute *attr,
    char *buf)
{
    return cpumap_print_to_pagebuf(true, buf, &available_cpus);
}

static ssize_t available_cpus_store(struct kobject *kobj, struct kobj_attribute *attr,
    const char *buf, size_t count)
{
    int ret;
    struct cpumask mask;
    struct cpumask diff;

    ret = cpulist_parse(buf, &mask);
    if (ret)
        return ret;

    if (cpumask_test_cpu(0, &mask)) {
        return -EINVAL;
    }

    mutex_lock(&core_control_mutex);
    cpumask_xor(&diff, &available_cpus, &mask);
    cpumask_copy(&available_cpus, &mask);
    mutex_unlock(&core_control_mutex);

    if (cpumask_weight(&diff) != 0)
        core_control_notification(CORE_CONTROL_AVAILABLE_CPUS_CHANGE, NULL);

    return count;
}

static struct kobj_attribute available_cpus_attr =  __ATTR_RW(available_cpus);

#define DEFINE_SYSFS_CPUMASK_ATTR(_name, _maskp) \
    static ssize_t _name##_show(struct kobject *kobj, \
       struct kobj_attribute *attr, char *buf) \
    { \
        return cpumap_print_to_pagebuf(true, buf, (_maskp)); \
    } \
    static struct kobj_attribute _name##_attr = \
        __ATTR_RO(_name);
DEFINE_SYSFS_CPUMASK_ATTR(online_cpus,     cpu_online_mask);
DEFINE_SYSFS_CPUMASK_ATTR(cpus_to_online,  &cpus_to_online);
DEFINE_SYSFS_CPUMASK_ATTR(cpus_to_offline, &cpus_to_offline);

static struct attribute *core_control_attrs[] = {
    &online_cpus_attr.attr,
    &available_cpus_attr.attr,
    &cpus_to_online_attr.attr,
    &cpus_to_offline_attr.attr,
    &enable_attr.attr,
    NULL
};

static struct attribute_group core_control_attr_group = {
    .attrs = core_control_attrs,
};

static __init int core_control_add_sysfs_nodes(void)
{
    int ret = 0;

    core_control_kobj = kobject_create_and_add("core_control", kernel_kobj);
    if (!core_control_kobj) {
        pr_err("cannot create core control kobj\n");
        ret = -ENOMEM;
        goto error;
    }

    ret = sysfs_create_group(core_control_kobj, &core_control_attr_group);
    if (ret) {
        pr_err("cannot create sysfs group. err:%d\n", ret);
        goto error;
    }
    return 0;

error:
    if (core_control_kobj)
        kobject_del(core_control_kobj);
    return ret;
}

/*
 * PM Notifier
 *
 */
#ifdef CONFIG_PM
static int core_control_pm_notifier(struct notifier_block *nb,
    unsigned long event, void *data)
{
    switch (event) {
    case PM_HIBERNATION_PREPARE:
    case PM_SUSPEND_PREPARE:
        //while (task_state == CORE_CONTROL_HOTPLUG);
        core_control_suspend = 1;
        break;

    case PM_POST_HIBERNATION:
    case PM_POST_SUSPEND:
        core_control_suspend = 0;
        break;
    default:
        return NOTIFY_DONE;
    }

    return NOTIFY_OK;
}

static struct notifier_block pm_notifier_block = {
    .notifier_call = core_control_pm_notifier,
};
#endif

/*
 *  CPUFreq Notifier
 *
 */
static int core_control_cpufreq_notifier(struct notifier_block *nb,
    unsigned long event, void *data)
{
    struct cpufreq_policy *policy = data;

    if (event != CPUFREQ_ADJUST)
        return NOTIFY_DONE;

    switch (task_state) {
    case CORE_CONTROL_HOTPLUG:
        cpufreq_verify_within_limits(policy, policy->cur, policy->cur);
        return NOTIFY_STOP;

    case CORE_CONTROL_HOTPLUG_DONE:
        cpufreq_verify_within_limits(policy,
            policy->cpuinfo.min_freq, policy->cpuinfo.max_freq);
        break;
    default:
        return NOTIFY_DONE;
    }

    return NOTIFY_OK;
}

static struct notifier_block cpufreq_notifier_block = {
    .notifier_call = core_control_cpufreq_notifier,
};

/*
 * Init
 *
 */
static __init int core_control_late_init(void)
{
    init_completion(&hotplug_notify_complete);

    hotplug_task = kthread_create(do_hotplug, NULL, "hotplug");
    if (IS_ERR(hotplug_task)) {
        pr_err("task hotplug not init\n");
        return -EINVAL;
    }

    kthread_bind(hotplug_task, 0);
    wake_up_process(hotplug_task);

    core_control_add_sysfs_nodes();

    cpufreq_register_notifier(&cpufreq_notifier_block, CPUFREQ_POLICY_NOTIFIER);

#ifdef CONFIG_PM
    register_pm_notifier(&pm_notifier_block);
#endif

    return 0;
}
late_initcall(core_control_late_init);

/*
 * RTK platform driver
 *
 */
static int rtk_core_control_probe(struct platform_device *pdev)
{
    int ret;
    mutex_lock(&core_control_mutex);

    cpumask_clear(&available_cpus);
    ret = of_core_control_read_cpumask(pdev->dev.of_node, "cpu-list", &available_cpus);
    pr_info("CPU List = [ %*pbl ]\n", cpumask_pr_args(&available_cpus));

    mutex_unlock(&core_control_mutex);

    if (ret)
       core_control_notification(CORE_CONTROL_AVAILABLE_CPUS_CHANGE, NULL);

    return 0;
}

static struct of_device_id rtk_core_control_macth_table[] = {
#ifdef CONFIG_HOTPLUG_CPU
    {.compatible = "Realtek,core-control"},
#endif
    {}
};

static struct platform_driver rtk_core_control_platdrv = {
    .probe = rtk_core_control_probe,
    .driver = {
        .name = "rtk-core-control",
        .owner = THIS_MODULE,
        .of_match_table = rtk_core_control_macth_table,
    },
};
module_platform_driver_probe(rtk_core_control_platdrv, rtk_core_control_probe);

/*
 * TESTING
 *
 */
#if ENABLE_RTK_CORE_CONTROL_TESTING
static struct workqueue_struct *rtk_core_control_q;
static struct delayed_work rtk_core_control_delayed_work;
static int rtk_testing_online;
struct core_controller *rtk_testing_cc

static void rtk_core_control_testing_func(struct work_struct *work)
{
    int ret;

    if (!rtk_testing_online)
        ret = core_control_set_any_cpu_offline(rtk_testing_cc);
    else
        ret = core_control_set_any_cpu_online(rtk_testing_cc);

    if (!ret)
        printk(KERN_INFO "Core Control Testing set a CPU %s\n",
            rtk_testing_online ? "online" : "offline");

    if (ret < 0)
        rtk_testing_online = !rtk_testing_online;

    if (core_control_is_enabled())
        mod_delayed_work_on(0, rtk_core_control_q, &rtk_core_control_delayed_work, HZ);
}

static int core_control_testing_notifier(struct notifier_block *nb,
    unsigned long event, void *data)
{
    if (event == CORE_CONTROL_ENABLE) {
        mod_delayed_work_on(0, rtk_core_control_q, &rtk_core_control_delayed_work, HZ);
        return NOTIFY_OK;
    }

    return NOTIFY_DONE;
}

static struct notifier_block testing_notifier_block = {
    .notifier_call = core_control_testing_notifier,
};

static __init int rtk_core_control_testing_init(void)
{
    rtk_core_control_q  = create_workqueue("rtk_core_control_test");
    INIT_DELAYED_WORK(&rtk_core_control_delayed_work, rtk_core_control_testing_func);
    register_core_control_notifier(&testing_notifier_block);
    rtk_testing_cc = core_controller_register("testing");

    return 0;
}
late_initcall(rtk_core_control_testing_init);
#endif
