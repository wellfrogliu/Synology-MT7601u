
#define __RTK_THERMAL_DEBUG__	0

#if __RTK_THERMAL_DEBUG__
#define THERMAL_DEBUG(format, ...) printk("[THERMAL DBG]" format "\n", ## __VA_ARGS__)
#else
#define THERMAL_DEBUG(format, ...)
#endif

#define THERMAL_ERROR(format, ...) printk(KERN_ERR "[THERMAL ERR]" format "\n", ## __VA_ARGS__)
#define THERMAL_INFO(format, ...) printk(KERN_WARNING "[THERMAL]" format "\n", ## __VA_ARGS__)

#define wr_reg(x,y)                     writel(y,(volatile unsigned int*)(x))
#define rd_reg(x)                       readl((volatile unsigned int*)(x))

#define THERMAL_MASK (THERMAL_0_EN | THERMAL_1_EN)

enum FlagMode {
	SET,
	CLEAR,
	ASSIGN
};

enum rtk_thermal_flags_t {
	TREND_URGENT			= 0x1U << 0,
	TRIP_SHUTDOWN			= 0x1U << 1,
	THERMAL_0_EN			= 0x1U << 2,
	THERMAL_1_EN			= 0x1U << 3,
};

#define THERMAL_CDEV_NUM 4

enum rtk_cdev_id {
    CDEV_CPUFREQ = 0,
    CDEV_CPU_CORE_CTRL = 1,
    CDEV_FAN_CTRL = 2,
    CDEV_SHUTDOWN = 3,

    /* INVALID */
    CDEV_INVALID = -1
};

struct rtk_trip_point {
    int temp;
    int hyst;
    enum thermal_trip_type type;
    enum rtk_cdev_id  cdev_id;
    int cdev_idx;
};

struct rtk_freq {
    int freq;
    int lv;
};

struct rtk_thermal_priv {
	struct thermal_zone_device      *tz_dev;

    struct thermal_cooling_device *cdev[THERMAL_CDEV_NUM];
    int crit_idx;
    int n_trips;
    struct rtk_trip_point *trips;
    /* use by cpufreq cdev */
    int n_freqs;
    struct rtk_freq *freqs;
    /* use by cpu core cdev */
    struct cpumask core_control_mask;

	enum thermal_device_mode mode;
	unsigned int  compareDelayUs;
	int	          monitoringRateMs;
	unsigned long flags;

	void __iomem	*reg_base;
    struct notifier_block cc_nb;
};

#ifdef CONFIG_RTK_THERMAL_CPU_CORE_COOLING
struct thermal_cooling_device *cpu_core_cooling_register(struct cpumask *cpus);
int cpu_core_cooling_unregister(struct thermal_cooling_device *cdev);
#else
static inline struct thermal_cooling_device *cpu_core_cooling_register(struct cpumask *cpus)
{
    return NULL;
}

static inline int cpu_core_cooling_unregister(struct thermal_cooling_device *cdev)
{
    return 0;
}
#endif /* CONFIG_RTK_THERMAL_CPU_CORE_COOLING */
