#include <linux/slab.h>
#include <linux/power-control.h>
#include <linux/workqueue.h>
#include <linux/core_control.h>
#include <linux/cpufreq.h>

#define SECOND_TO_COUNT(_sec, _delay) ((_sec) * HZ / (_delay) + 1)

#ifdef CONFIG_REALTEK_CPUFREQ_CORE_CONTROL_HELPER
static DEFINE_PER_CPU(u64, prev_idle);
static DEFINE_PER_CPU(u64, prev_time);

static int get_cpu_load(int cpu)
{
    int load;
    u64 time, idle, d_idle, d_time;

    idle = get_cpu_idle_time(cpu, &time, 1);

    d_idle = idle - per_cpu(prev_idle, cpu);
    d_time = time - per_cpu(prev_time, cpu);

    if (d_time <= d_idle)
        load = 0;
    else
        load = div64_u64(100 * (d_time - d_idle), d_time);

    per_cpu(prev_idle, cpu) = idle;
    per_cpu(prev_time, cpu) = time;

    return load;
}

struct cpufreq_cc_data {
    struct delayed_work dwork;
    int    polling_delay;

    int cnt_high;
    int cnt_low;
    struct core_controller *cctrl;
    struct notifier_block nb;
};

static void rtk_cpufreq_cc_load_checker(struct work_struct *work)
{
    struct cpufreq_cc_data *priv = container_of(work, struct cpufreq_cc_data, dwork.work);

    int cpu;
    int load, load_sum = 0, n_cpus = 0;
    int ret;

    for_each_online_cpu(cpu) {
        load_sum += get_cpu_load(cpu);
        n_cpus += 1;
    }

    load = load_sum / n_cpus;

    if (load <= 4) {
        priv->cnt_low ++;
        priv->cnt_high = 0;
    } else if (load > 95) {
        priv->cnt_low = 0;
        priv->cnt_high += 5;
    } else if (load > 70) {
        priv->cnt_low = 0;
        priv->cnt_high ++;
    }

    if (priv->cnt_low >= 10) {
        ret = core_control_set_any_cpu_offline(priv->cctrl);
        printk(KERN_DEBUG "CPU Loading monitor set a CPU offline: %d\n", ret);
        priv->cnt_low = 0;
    }

    if (priv->cnt_high >= 5) {
        ret = core_control_set_any_cpu_online(priv->cctrl);
        printk(KERN_DEBUG  "CPU Loading monitor set a CPU online: %d\n", ret);
        priv->cnt_high = 0;
    }

    if (core_control_is_enabled())
        mod_delayed_work(system_freezable_wq, &priv->dwork, priv->polling_delay);
}

static int rtk_cpufreq_cc_load_notifier(struct notifier_block *nb,
                                        unsigned long event, void *data)
{
    if (event == CORE_CONTROL_ENABLE) {
        struct cpufreq_cc_data *priv = container_of(nb, struct cpufreq_cc_data, nb);
        mod_delayed_work(system_freezable_wq, &priv->dwork, priv->polling_delay);
        return NOTIFY_OK;
    }
    return NOTIFY_DONE;
}

static int __init init_rtk_cpufreq_cc_load_checker(void)
{
    struct cpufreq_cc_data *priv = kzalloc(sizeof(*priv), GFP_KERNEL);
    if (!priv)
        return -ENOMEM;

    INIT_DELAYED_WORK(&priv->dwork, rtk_cpufreq_cc_load_checker);

    priv->polling_delay = HZ;
    priv->cctrl = core_control_register_controller("cpufreq");
    if (priv->cctrl)
        core_control_set_token_owner(priv->cctrl);

    priv->nb.notifier_call = rtk_cpufreq_cc_load_notifier;
    register_core_control_notifier(&priv->nb);

    return 0;
}
late_initcall(init_rtk_cpufreq_cc_load_checker);
#endif

#ifdef CONFIG_REALTEL_CPUFREQ_GPU_HELPER
struct cpufreq_gpu_data {
    struct delayed_work dwork;
    int    polling_delay;

    struct power_control *pctrl_gpu;
    unsigned long min_freq;
    unsigned int up_weight;
    unsigned int up_time;
    struct notifier_block nb;
};

static void rtk_cpufreq_gpu_checker(struct work_struct *work)
{
    struct cpufreq_gpu_data *priv = container_of(work, struct cpufreq_gpu_data, dwork.work);
    unsigned int up_time_old = priv->up_time;

    priv->up_weight = priv->up_weight * 4 / 10;

    if (power_control_is_powered_on(priv->pctrl_gpu) == 1) {
        priv->up_weight += 10;
        if (priv->up_weight >= 16) {
            priv->up_time = SECOND_TO_COUNT(10, priv->polling_delay);
            if (up_time_old != (priv->up_time - 1))
                cpufreq_update_policy(0);
        }
    }

    if (priv->up_time) {
        priv->up_time --;
        if (!priv->up_time)
            cpufreq_update_policy(0);
    }

    mod_delayed_work(system_freezable_wq, &priv->dwork, priv->polling_delay);
}

static int rtk_cpufreq_gpu_notifier(struct notifier_block *nb,
                                    unsigned long event, void *data)
{
    struct cpufreq_policy *policy = data;
    struct cpufreq_gpu_data *priv = container_of(nb, struct cpufreq_gpu_data, nb);

    if (event != CPUFREQ_ADJUST)
        return NOTIFY_DONE;

    if (priv->up_time != 0 && policy->min != priv->min_freq) {
        pr_debug("set to 500 MHz\n");
        cpufreq_verify_within_limits(policy, priv->min_freq, policy->max);

    } else if (priv->up_time == 0 && policy->cpuinfo.min_freq != priv->min_freq) {
        pr_debug("reset\n");
        cpufreq_verify_within_limits(policy, policy->cpuinfo.min_freq, policy->max);
    }

    return NOTIFY_OK;
}

static int __init init_rtk_cpufreq_gpu_checker(void)
{
    int ret;
    struct cpufreq_gpu_data *priv = kzalloc(sizeof(*priv), GFP_KERNEL);
    if (!priv)
        return -ENOMEM;

    priv->pctrl_gpu = power_control_get("pctrl_gpu");
    if (IS_ERR_OR_NULL(priv->pctrl_gpu)) {
        ret = PTR_ERR(priv->pctrl_gpu);
        goto error;
    }

    priv->min_freq = 500000;
    priv->polling_delay = HZ / 3;
    priv->nb.notifier_call = rtk_cpufreq_gpu_notifier;
    cpufreq_register_notifier(&priv->nb, CPUFREQ_POLICY_NOTIFIER);

    INIT_DELAYED_WORK(&priv->dwork, rtk_cpufreq_gpu_checker);
    queue_delayed_work(system_freezable_wq, &priv->dwork, 30 * HZ);
    return 0;
error:
    if (priv)
        kfree(priv);
    return ret;
}
late_initcall(init_rtk_cpufreq_gpu_checker);
#endif
