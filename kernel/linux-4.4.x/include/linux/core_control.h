#ifndef _LINUX_CORE_CONTROL_H
#define _LINUX_CORE_CONTROL_H

#define CORE_CONTROL_DISABLE                  0x01
#define CORE_CONTROL_ENABLE                   0x02
#define CORE_CONTROL_AVAILABLE_CPUS_CHANGE    0x03

/* umimplement */
#define CORE_CONTROL_CPU_ONLINE_DONE          0x04
#define CORE_CONTROL_CPU_ONLINE_PREPARE       0x05
#define CORE_COTTROL_CPU_OFFLINE_DONE         0x06
#define CORE_COTTROL_CPU_OFFLINE_PREPARE      0x07

#include <linux/types.h>
struct device_node;
struct cpumask;
struct notifier_block;
struct core_controller;

struct core_control_notification_args {
    int abort;
};

#ifdef CONFIG_HOTPLUG_CPU

int of_core_control_read_cpumask(struct device_node *np,
    const char *prop_name, struct cpumask *out);
bool core_control_is_enabled(void);
int core_control_get_available_cpus(struct cpumask *out);
bool core_control_is_cpu_available(int cpu);
int core_control_set_cpu_offline(struct core_controller *cc, int cpu);
int core_control_set_any_cpu_offline(struct core_controller *cc);
int core_control_set_cpu_online(struct core_controller *cc, int cpu);
int core_control_set_any_cpu_online(struct core_controller *cc);
struct core_controller *core_control_register_controller(const char *name);
int core_control_unregister_controller(struct core_controller *cc);
int core_control_set_token_owner(struct core_controller *cc);
struct core_controller *core_control_get_token_owner(void);
int register_core_control_notifier(struct notifier_block *nb);
int unregister_core_control_notifier(struct notifier_block *nb);

#endif /* CONFIG_HOTPLUG_CPU */

#endif /* _LINUX_CORE_CONTROL_H */
