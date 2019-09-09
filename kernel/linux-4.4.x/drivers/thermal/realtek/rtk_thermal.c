#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#include <linux/device.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/platform_device.h>
#include <linux/of_device.h>
#include <linux/thermal.h>
#include <linux/cpufreq.h>
#include <linux/cpumask.h>
#include <linux/cpu_cooling.h>
#include <linux/slab.h>
#include <linux/core_control.h>

#include "rtk_thermal.h"
#include "sc_wrap_dvfs_reg.h"

#if defined(MY_DEF_HERE)
static struct thermal_zone_device* g_syno_tz = NULL;
#endif /* MY_DEF_HERE */

static void rtk_thermal_error_check(struct thermal_zone_device *thermal)
{
    struct rtk_thermal_priv *priv = thermal->devdata;
    unsigned int u_out_val;
    unsigned int t_out_val;

    u_out_val = rd_reg(priv->reg_base+SC_WRAP_DVFS_TM_SENSOR_STATUS2);
    t_out_val = rd_reg(priv->reg_base+SC_WRAP_DVFS_TM_SENSOR_STATUS1);

    /*
     * if temp > 150 || temp < -30
     *  0x25800 / 150 <-> 0x3FFFF /  262
     *  0x78AD0 / -30 <-> 0x40000 / -262
     */
    if((u_out_val==0x0)||(u_out_val==0x3FFFFF) ||
            (0x25800 <= t_out_val && t_out_val <= 0x78AD0))
    {
        // Check again
        u_out_val = rd_reg(priv->reg_base+SC_WRAP_DVFS_TM_SENSOR_STATUS2);
        t_out_val = rd_reg(priv->reg_base+SC_WRAP_DVFS_TM_SENSOR_STATUS1);

        if((u_out_val==0x0)||(u_out_val==0x3FFFFF) ||
                (0x25800 <= t_out_val && t_out_val <= 0x78AD0))
        {
            dev_info(&thermal->device, "Thermal sensor toggle power\n");

            //HW bug, do power toggle
            wr_reg((priv->reg_base+SC_WRAP_DVFS_TM_SENSOR_CTRL2), 0x01904001);
            wr_reg((priv->reg_base+SC_WRAP_DVFS_TM_SENSOR_CTRL2), 0x01924001);
            usleep_range(25000,26000);//delay 25 ms
        }
    }
}

static int rtk_thermal_get_temp(struct thermal_zone_device *thermal, unsigned long *temp)
{
    struct rtk_thermal_priv *priv = thermal->devdata;
    int temperature = 0;
    *temp = 0;

    THERMAL_DEBUG("[%s]",__FUNCTION__);

    wr_reg((priv->reg_base+SC_WRAP_DVFS_TM_SENSOR_CTRL2), 0x01924001);

    usleep_range(5000,6000);

    rtk_thermal_error_check(thermal);// SW workaround

    /* return 18-bits signed value */
    temperature = rd_reg(priv->reg_base+SC_WRAP_DVFS_TM_SENSOR_STATUS1);

    if (BIT(18) & temperature) {
        dev_info(&thermal->device, "TM_SENSOR_STATUS1 = 0x%08x\n", temperature);
    }

    /* sign extension */
    temperature = (int)(((unsigned int)0 - (BIT(18) & temperature)) | temperature);

    temperature = temperature*1000/1024;

    /* NOTE: the current thermal_zone_device tz use type 'int' to store
     * the value from (*get_temp) in temperature and last_temperature.
     *
     * The existing call flows are as following:
     *
     *   temp_show ------------\
     *                          |-------> thermal_zone_get_temp --|
     *   update_temperature ---/                                  |
     *                                            (*get_temp) <---|
     *
     * In both function temp_show and update_temperature use a type 'long'
     * value as the second paramter of function thermal_zone_get_temp,
     * which is defined as unsigned long pointer. So it is simple to fix
     * the unsupported problem of nagative temperature value, just do sign
     * extension and force the output unsigned long pointer as a long type
     * pointer.
     */
    *(long *)temp = temperature;

    return 0;
}

static int rtk_thermal_get_trip_type(struct thermal_zone_device *thermal,
                                     int trip, enum thermal_trip_type *type)
{
    struct rtk_thermal_priv *priv = thermal->devdata;

    if (trip >= priv->n_trips)
        return -EINVAL;
    *type = priv->trips[trip].type;

    return 0;
}

static int rtk_thermal_get_trip_temp(struct thermal_zone_device *thermal,
                                     int trip, unsigned long *temp)
{
    struct rtk_thermal_priv *priv = thermal->devdata;

    if (trip >= priv->n_trips)
        return -EINVAL;

    *temp = priv->trips[trip].temp;

    return 0;
}

static int rtk_thermal_set_trip_temp(struct thermal_zone_device *thermal,
                                     int trip, unsigned long temp)
{
    struct rtk_thermal_priv *priv = thermal->devdata;

    if (trip >= priv->n_trips)
        return -EINVAL;

    priv->trips[trip].temp = (int)temp;
    return 0;
}

static int rtk_thermal_get_trip_hyst(struct thermal_zone_device *thermal,
                                     int trip, unsigned long *hyst)
{
    struct rtk_thermal_priv *priv = thermal->devdata;

    if (trip >= priv->n_trips)
        return -EINVAL;

    *hyst = priv->trips[trip].hyst;

    return 0;
}

static int rtk_thermal_set_trip_hyst(struct thermal_zone_device *thermal,
                                     int trip, unsigned long hyst)
{
    struct rtk_thermal_priv *priv = thermal->devdata;

    if (trip >= priv->n_trips)
        return -EINVAL;

    priv->trips[trip].hyst = (int)hyst;
    return 0;
}

static int rtk_thermal_get_trend(struct thermal_zone_device *thermal,
                                 int trip, enum thermal_trend *trend)
{
    struct rtk_thermal_priv *priv = thermal->devdata;
    unsigned long trip_temp;
    int ret;

    ret = rtk_thermal_get_trip_temp(thermal, trip, &trip_temp);
    if (ret < 0)
        return ret;

    if (thermal->temperature >= trip_temp)
        if (priv->flags & TREND_URGENT)
            *trend = THERMAL_TREND_RAISE_FULL;
        else
            *trend = THERMAL_TREND_RAISING;
    else if (priv->flags & TREND_URGENT)
        *trend = THERMAL_TREND_DROP_FULL;
    else
        *trend = THERMAL_TREND_DROPPING;

    if (thermal->temperature >= trip_temp) {
        dev_info(&thermal->device, "temperature(%d C) tripTemp(%lu C) \n",
                 thermal->temperature/1000, trip_temp/1000);
        dev_info(&thermal->device, "thermal->temperature = %8d (0x%08x)\n",
                 thermal->temperature, thermal->temperature);
        dev_info(&thermal->device, "TM_SENSOR_STATUS1 = 0x%08x\n",
                 rd_reg(priv->reg_base+SC_WRAP_DVFS_TM_SENSOR_STATUS1));
        dev_info(&thermal->device, "TM_SENSOR_STATUS2 = 0x%08x\n",
                 rd_reg(priv->reg_base+SC_WRAP_DVFS_TM_SENSOR_STATUS2));
    }

    return 0;
}

static enum rtk_cdev_id rtk_thermal_get_cdev_id(struct thermal_cooling_device *cdev)
{
    if (!strncmp(cdev->type, "thermal-cpufreq", 15))
        return CDEV_CPUFREQ;

    if (!strncmp(cdev->type, "thermal-cpu-core", 16))
        return CDEV_CPU_CORE_CTRL;

    return CDEV_INVALID;
}

static int rtk_thermal_bind(struct thermal_zone_device *thermal,
                            struct thermal_cooling_device *cdev)
{
    struct rtk_thermal_priv *priv = thermal->devdata;
    unsigned long upper, lower;
    int ret = 0;
    int i;
    enum rtk_cdev_id cdev_id;

    cdev_id = rtk_thermal_get_cdev_id(cdev);

    for (i = 0; i < priv->n_trips; i++) {
        if (priv->trips[i].cdev_id != cdev_id)
            continue;

        switch (cdev_id) {
        case CDEV_CPUFREQ:
            lower = priv->freqs[priv->trips[i].cdev_idx * 2].lv;
            upper = priv->freqs[priv->trips[i].cdev_idx * 2+1].lv;
            break;
        case CDEV_CPU_CORE_CTRL:
            lower = 1;
            cdev->ops->get_max_state(cdev, &upper);
            break;
        default:
            upper = lower = THERMAL_NO_LIMIT;
        }

        ret = thermal_zone_bind_cooling_device(thermal, i, cdev,
                                               upper, lower, THERMAL_WEIGHT_DEFAULT);
        dev_info(&cdev->device, "%s bind to TP%d: %lu -> %lu, ret = %d\n", cdev->type, i,
                 lower, upper, ret);
    }

    return ret;
}

static int rtk_thermal_unbind(struct thermal_zone_device *thermal,
                              struct thermal_cooling_device *cdev)
{
    struct rtk_thermal_priv *priv = thermal->devdata;
    int ret = 0;
    int i;
    enum rtk_cdev_id cdev_id;

    cdev_id = rtk_thermal_get_cdev_id(cdev);

    for (i = 0; i < priv->n_trips; i++) {
        if (priv->trips[i].cdev_id != cdev_id)
            continue;

        ret = thermal_zone_unbind_cooling_device(thermal, i, cdev);
        if (ret)
            pr_err("Failed unbind_cooling_device of TP:%d to cdev: %s\n",
                   i, cdev->type);
    }

    return ret;
}

static int rtk_thermal_get_mode(struct thermal_zone_device *thermal,
                                enum thermal_device_mode *mode)
{
    struct rtk_thermal_priv *priv = thermal->devdata;

    if (priv)
        *mode = priv->mode;

    return 0;
}

static int rtk_thermal_set_mode(struct thermal_zone_device *thermal,
                                enum thermal_device_mode mode)
{
    struct rtk_thermal_priv *priv = thermal->devdata;

    if (!priv->tz_dev) {
        dev_notice(&thermal->device, "thermal zone not registered\n");
        return 0;
    }

    mutex_lock(&priv->tz_dev->lock);

    if (mode == THERMAL_DEVICE_ENABLED)
        priv->tz_dev->polling_delay = priv->monitoringRateMs;
    else
        priv->tz_dev->polling_delay = 0;

    mutex_unlock(&priv->tz_dev->lock);

    priv->mode = mode;

    thermal_zone_device_update(priv->tz_dev);
    dev_info(&thermal->device, "thermal polling set for duration=%d msec\n",
             priv->tz_dev->polling_delay);

    return 0;
}

static int rtk_thermal_get_crit_temp(struct thermal_zone_device *thermal,
                                     unsigned long *temp)
{
    struct rtk_thermal_priv *priv = thermal->devdata;

    /* shutdown zone */
    return rtk_thermal_get_trip_temp(thermal, priv->n_trips - 1, temp);
}

static struct thermal_zone_device_ops rtk_tz_ops = {
    .get_temp       = rtk_thermal_get_temp,
    .get_trend      = rtk_thermal_get_trend,
    .bind           = rtk_thermal_bind,
    .unbind         = rtk_thermal_unbind,
    .get_mode       = rtk_thermal_get_mode,
    .set_mode       = rtk_thermal_set_mode,
    .get_trip_type  = rtk_thermal_get_trip_type,
    .get_trip_temp  = rtk_thermal_get_trip_temp,
    .set_trip_temp  = rtk_thermal_set_trip_temp,
    .get_trip_hyst  = rtk_thermal_get_trip_hyst,
    .set_trip_hyst  = rtk_thermal_set_trip_hyst,
    .get_crit_temp  = rtk_thermal_get_crit_temp,
};

void modifyFlags(struct rtk_thermal_priv *priv, unsigned int value, enum FlagMode mode)
{
    switch (mode) {
    case SET:
            priv->flags |= value;
        break;
    case CLEAR:
        priv->flags &= ~value;
        break;
    case ASSIGN:
        priv->flags = value;
        break;
    default:
        THERMAL_ERROR("[%s] value = 0x%x, mode = %d",__FUNCTION__,value,mode);
    }
}

static int rtk_thermal_probe_of(struct rtk_thermal_priv *priv, struct platform_device *pdev)
{
    struct device_node *node = pdev->dev.of_node;
    const u32 *prop;
    int size;
    int i;
    int ret;

#define TRIP_POINT_COLUMN 4
    prop = of_get_property(node, "trip-points", &size);
    size /= sizeof(u32);
    if (prop && (size % TRIP_POINT_COLUMN) == 0) {
        priv->n_trips = size / TRIP_POINT_COLUMN;
        priv->crit_idx = -1;
        priv->trips = devm_kzalloc(&pdev->dev, sizeof(struct rtk_trip_point) * priv->n_trips, GFP_KERNEL);
        for (i = 0; i < priv->n_trips; i++) {
            priv->trips[i].temp     = of_read_number(prop++, 1) * 1000;
            priv->trips[i].hyst     = of_read_number(prop++, 1) * 1000;
            priv->trips[i].cdev_id  = (enum rtk_cdev_id)of_read_number(prop++, 1);
            priv->trips[i].cdev_idx = of_read_number(prop++, 1);
            priv->trips[i].type     = priv->trips[i].cdev_id == CDEV_SHUTDOWN ?
                                      THERMAL_TRIP_CRITICAL : THERMAL_TRIP_PASSIVE;

            if (priv->trips[i].type == THERMAL_TRIP_CRITICAL)
                priv->crit_idx = i;
        }

        if (priv->crit_idx == -1)
            priv->crit_idx = i - 1;
    } else {
        priv->n_trips = 0;
        dev_err(&pdev->dev, "[%s] thermal-table ERROR! array_size = %d \n", __func__, size);
        return -EINVAL;
    }
#undef TRIP_POINT_COLUMN

    /* cpufreq cooling */
    prop = of_get_property(node, "cpufreq,freqs", &size);
    size /= sizeof(u32);
    if (size) {
        struct cpufreq_policy * policy = cpufreq_cpu_get(0);
        int max_lv;

        if (policy) {
            max_lv = cpufreq_frequency_table_get_index(policy, policy->cpuinfo.max_freq);
            priv->n_freqs = size;
            priv->freqs = devm_kzalloc(&pdev->dev, sizeof(struct rtk_freq) * priv->n_freqs, GFP_KERNEL);

            for (i = 0; i < priv->n_freqs; i++) {
                priv->freqs[i].freq = of_read_number(prop++, 1);
                priv->freqs[i].lv = max_lv - cpufreq_frequency_table_get_index(policy, priv->freqs[i].freq);
            }

            cpufreq_cpu_put(policy);
        }
    }

    /* cpu core cooling */
    ret = of_core_control_read_cpumask(pdev->dev.of_node,
                                       "cpu-core,cpu-list", &priv->core_control_mask);
    if (!ret)
        core_control_get_available_cpus(&priv->core_control_mask);

    prop = of_get_property(node, "thermal-trip-shutdown", &size);
    if (prop) {
        unsigned int temp = of_read_number(prop,1);
        if (temp)
            modifyFlags(priv, TRIP_SHUTDOWN, SET);
    }

    prop = of_get_property(node, "thermal-polling-ms", &size);
    if (prop) {
        unsigned int temp = of_read_number(prop,1);
        priv->monitoringRateMs = temp;
    }
    else
        priv->monitoringRateMs = 500;

    prop = of_get_property(node, "thermal-trend-urgent", &size);
    if (prop) {
        unsigned int temp = of_read_number(prop,1);
        if (temp)
            modifyFlags(priv, TREND_URGENT, SET);
    }

    THERMAL_DEBUG("[%s] thermal flags is 0x%lx",__func__,priv->flags);

    return 0;
}

static int rtk_thermal_core_control_notifier(struct notifier_block *nb,
        unsigned long event, void *data)
{
    struct rtk_thermal_priv *priv = container_of(nb, struct rtk_thermal_priv, cc_nb);

    if (event == CORE_CONTROL_ENABLE) {
        if (priv->cdev[CDEV_CPU_CORE_CTRL] != NULL) {
            pr_warning("CDEV_CPU_CORE_CTRL is already registered.\n");
            return NOTIFY_OK;
        }

        priv->cdev[CDEV_CPU_CORE_CTRL] = cpu_core_cooling_register(&priv->core_control_mask);
        if (IS_ERR_OR_NULL(priv->cdev[CDEV_CPU_CORE_CTRL])) {
            pr_err("Failed to register CDEV_CPU_CORE_CTRL.\n");
            priv->cdev[CDEV_CPU_CORE_CTRL] = NULL;
        }
    } else if (event == CORE_CONTROL_DISABLE) {
        if (priv->cdev[CDEV_CPU_CORE_CTRL] == NULL) {
            pr_warning("CDEV_CPU_CORE_CTRL is already unregister.\n");
            return NOTIFY_OK;
        }

        cpu_core_cooling_unregister(priv->cdev[CDEV_CPU_CORE_CTRL]);
        priv->cdev[CDEV_CPU_CORE_CTRL] = NULL;
    }
    return NOTIFY_DONE;
}

static int rtk_thermal_probe(struct platform_device *pdev)
{
    struct device_node *node = NULL;
    struct rtk_thermal_priv *priv;
    int ret;

    dev_dbg(&pdev->dev, "%s", __func__);
    node = pdev->dev.of_node;
    if (!node) {
        return -ENODEV;
    }

    priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL);
    if (!priv) {
        return -ENOMEM;
    }

    priv->reg_base = of_iomap(node, 0);

    ret = rtk_thermal_probe_of(priv, pdev);
    if (ret < 0) {
        dev_err(&pdev->dev, "Fail to parse device tree node.\n");
        return ret;
    }

    priv->tz_dev = thermal_zone_device_register("rtk_thermal", priv->n_trips, 0,
                   priv, &rtk_tz_ops, NULL, priv->monitoringRateMs, priv->monitoringRateMs);
    if (IS_ERR(priv->tz_dev)) {
        ret = PTR_ERR(priv->tz_dev);
        dev_err(&pdev->dev, "Failed to register thermal_zone device: %d\n", ret);
        return ret;
    }

    /* cpufreq cooling */
    if (priv->freqs) {
        struct cpumask cpufreq_mask;

        cpumask_setall(&cpufreq_mask);
        priv->cdev[CDEV_CPUFREQ] = cpufreq_cooling_register(&cpufreq_mask);
        if (IS_ERR_OR_NULL(priv->cdev[CDEV_CPUFREQ])) {
            dev_err(&pdev->dev, "Failed to register CDEV_CPUFREQ.\n");
            priv->cdev[CDEV_CPUFREQ] = NULL;
        }
    }

    /* cpu core cooling */
    if (core_control_is_enabled()) {
        priv->cdev[CDEV_CPU_CORE_CTRL] = cpu_core_cooling_register(&priv->core_control_mask);
        if (IS_ERR_OR_NULL(priv->cdev[CDEV_CPU_CORE_CTRL])) {
            dev_err(&pdev->dev, "Failed to register CDEV_CPU_CORE_CTRL.\n");
            priv->cdev[CDEV_CPU_CORE_CTRL] = NULL;
        }
    }

    priv->cc_nb.notifier_call = rtk_thermal_core_control_notifier;
    register_core_control_notifier(&priv->cc_nb);

    if (!priv->cdev[CDEV_CPUFREQ] && !priv->cdev[CDEV_CPU_CORE_CTRL]) {
        dev_warn(&pdev->dev, "No cooling device registered.\n");
    }

    priv->tz_dev->polling_delay = priv->monitoringRateMs;

    priv->mode = THERMAL_DEVICE_ENABLED;

#if defined(MY_DEF_HERE)
	g_syno_tz = priv->tz_dev;
#endif /* MY_DEF_HERE */

    platform_set_drvdata(pdev, priv->tz_dev);

    dev_dbg(&pdev->dev, "%s done", __func__);
    return 0;
}

static int rtk_thermal_remove(struct platform_device *pdev)
{
    struct thermal_zone_device *rtk_thermal = platform_get_drvdata(pdev);
    struct rtk_thermal_priv *priv = rtk_thermal->devdata;

    if (priv->cdev[CDEV_CPUFREQ])
        cpufreq_cooling_unregister(priv->cdev[CDEV_CPUFREQ]);

    unregister_core_control_notifier(&priv->cc_nb);

    if (priv->cdev[CDEV_CPU_CORE_CTRL])
        cpu_core_cooling_unregister(priv->cdev[CDEV_CPU_CORE_CTRL]);

    thermal_zone_device_unregister(priv->tz_dev);

    platform_set_drvdata(pdev, NULL);
    return 0;
}

static const struct of_device_id rtk_thermal_of_match[] = {
    {.compatible = "Realtek,rtd1295-thermal",},
    { /* Sentinel */ },
};

static struct platform_driver rtk_thermal_driver = {
    .probe	= rtk_thermal_probe,
    .remove	= rtk_thermal_remove,
    .driver = {
        .name	= "realtek_thermal",
        .owner	= THIS_MODULE,
        .of_match_table = of_match_ptr(rtk_thermal_of_match),
    },
};

static int __init rtk_thermal_probe_init(void)
{
    return platform_driver_probe(&rtk_thermal_driver, rtk_thermal_probe);
}

#if defined(MY_DEF_HERE)

int syno_rtd_get_temperature(void)
{
	int iRet = -1;
	unsigned long int ulTemp = 0;

	if (NULL == g_syno_tz) {
		printk(KERN_ERR "syno: thermal device not found\n");
		goto out;
	}

	// rtk thermal will return degree * 1000, we need to change unit
	rtk_thermal_get_temp(g_syno_tz, &ulTemp);
	iRet = (int)ulTemp/1000;

out:
	return iRet;
}

EXPORT_SYMBOL(syno_rtd_get_temperature);
#endif /* MY_DEF_HERE */
late_initcall(rtk_thermal_probe_init);
