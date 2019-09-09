#include <linux/core_control.h>
#include <linux/cpumask.h>
#include <linux/thermal.h>
#include <linux/slab.h>
#include <linux/delay.h>

struct cpu_core_cooling_priv {
    int id;
    struct cpumask available_cpus;
    struct thermal_cooling_device *cdev;
    struct core_controller *cc;
    struct core_controller *last_cc;
    unsigned long state;
};

#define cdev_to_priv(_cdev) ((_cdev)->devdata)

static DEFINE_MUTEX(cpu_core_cooling_mutex);
static int gid = 0;

static int cpu_core_cooling_get_cur_state(struct thermal_cooling_device *cdev,
        unsigned long *state)
{
    struct cpu_core_cooling_priv *priv = cdev_to_priv(cdev);
    struct cpumask curr;
    cpumask_andnot(&curr, &priv->available_cpus, cpu_online_mask);
    *state = cpumask_weight(&curr);
    return 0;
}

static int cpu_core_cooling_set_cur_state(struct thermal_cooling_device *cdev,
        unsigned long state)
{
    struct cpu_core_cooling_priv *priv = cdev_to_priv(cdev);
    struct cpumask curr;
    unsigned long curr_state;
    int cpu;
    int ret = 0;

    cpu_core_cooling_get_cur_state(cdev, &curr_state);
    priv->state = state;

    if (state != 0) {
        struct core_controller *ccc = core_control_get_token_owner();
        if (ccc != priv->cc) {
            priv->last_cc = ccc;
            core_control_set_token_owner(priv->cc);
        }
    }

    pr_info("cpu_core_cooling: state %d -> %d\n", (int)curr_state, (int)state);
    if (state > curr_state) {
        while (state != curr_state) {
            cpumask_and(&curr, &priv->available_cpus, cpu_online_mask);
            cpu = cpumask_first(&curr);

            ret = core_control_set_cpu_offline(priv->cc, cpu);
            if (ret)
                break;

            usleep_range(1, 2);
            cpu_core_cooling_get_cur_state(cdev, &curr_state);
        }
    } else if (state < curr_state) {
        while (state != curr_state) {
            cpumask_andnot(&curr, &priv->available_cpus, cpu_online_mask);
            cpu = cpumask_first(&curr);

            ret = core_control_set_cpu_online(priv->cc, cpu);
            if (ret)
                break;

            usleep_range(1, 2);

            cpu_core_cooling_get_cur_state(cdev, &curr_state);
        }
    }

    if (state == 0) {
        if (priv->last_cc != NULL)
            core_control_set_token_owner(priv->last_cc);
    }

    return ret;
}

static int cpu_core_cooling_get_max_state(struct thermal_cooling_device *cdev,
        unsigned long *state)
{
    struct cpu_core_cooling_priv *priv = cdev_to_priv(cdev);
    *state = (unsigned long)cpumask_weight(&priv->available_cpus);
    return 0;
}

static struct thermal_cooling_device_ops cdev_ops = {
    .get_max_state = cpu_core_cooling_get_max_state,
    .get_cur_state = cpu_core_cooling_get_cur_state,
    .set_cur_state = cpu_core_cooling_set_cur_state,
};

struct thermal_cooling_device *cpu_core_cooling_register(struct cpumask *cpus)
{
    char dev_name[THERMAL_NAME_LENGTH];
    struct cpu_core_cooling_priv *priv = kzalloc(sizeof(*priv), GFP_KERNEL);

    if (!priv)
        return NULL;

    mutex_lock(&cpu_core_cooling_mutex);
    priv->id = gid ++;
    mutex_unlock(&cpu_core_cooling_mutex);

    cpumask_copy(&priv->available_cpus, cpus);

    snprintf(dev_name, sizeof(dev_name), "thermal-cpu-core-%d", priv->id);

    priv->last_cc = NULL;
    priv->cc   = core_control_register_controller("thermal");
    priv->cdev = thermal_cooling_device_register(dev_name, priv, &cdev_ops);
    return priv->cdev;
}

int cpu_core_cooling_unregister(struct thermal_cooling_device *cdev)
{
    struct cpu_core_cooling_priv *priv = cdev_to_priv(cdev);
    thermal_cooling_device_unregister(cdev);
    core_control_unregister_controller(priv->cc);
    kfree(priv);
    return 0;
}
