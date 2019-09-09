#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#define pr_fmt(fmt) "NMI watchdog: " fmt

#include <linux/mm.h>
#include <linux/cpu.h>
#include <linux/nmi.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/smpboot.h>
#include <linux/sched/rt.h>
#include <linux/tick.h>

#include <asm/irq_regs.h>
#include <linux/kvm_para.h>
#include <linux/perf_event.h>
#include <linux/kthread.h>

#define NMI_WATCHDOG_ENABLED_BIT   0
#define SOFT_WATCHDOG_ENABLED_BIT  1
#define NMI_WATCHDOG_ENABLED      (1 << NMI_WATCHDOG_ENABLED_BIT)
#define SOFT_WATCHDOG_ENABLED     (1 << SOFT_WATCHDOG_ENABLED_BIT)

static DEFINE_MUTEX(watchdog_proc_mutex);

#ifdef CONFIG_HARDLOCKUP_DETECTOR
static unsigned long __read_mostly watchdog_enabled = SOFT_WATCHDOG_ENABLED|NMI_WATCHDOG_ENABLED;
#else
static unsigned long __read_mostly watchdog_enabled = SOFT_WATCHDOG_ENABLED;
#endif
int __read_mostly nmi_watchdog_enabled;
int __read_mostly soft_watchdog_enabled;
int __read_mostly watchdog_user_enabled;
int __read_mostly watchdog_thresh = 10;

#ifdef CONFIG_SMP
int __read_mostly sysctl_softlockup_all_cpu_backtrace;
int __read_mostly sysctl_hardlockup_all_cpu_backtrace;
#else
#define sysctl_softlockup_all_cpu_backtrace 0
#define sysctl_hardlockup_all_cpu_backtrace 0
#endif
static struct cpumask watchdog_cpumask __read_mostly;
unsigned long *watchdog_cpumask_bits = cpumask_bits(&watchdog_cpumask);

#define for_each_watchdog_cpu(cpu) \
	for_each_cpu_and((cpu), cpu_online_mask, &watchdog_cpumask)

static int __read_mostly watchdog_running;
 
static int __read_mostly watchdog_suspended;

static u64 __read_mostly sample_period;

static DEFINE_PER_CPU(unsigned long, watchdog_touch_ts);
static DEFINE_PER_CPU(struct task_struct *, softlockup_watchdog);
static DEFINE_PER_CPU(struct hrtimer, watchdog_hrtimer);
static DEFINE_PER_CPU(bool, softlockup_touch_sync);
static DEFINE_PER_CPU(bool, soft_watchdog_warn);
static DEFINE_PER_CPU(unsigned long, hrtimer_interrupts);
static DEFINE_PER_CPU(unsigned long, soft_lockup_hrtimer_cnt);
static DEFINE_PER_CPU(struct task_struct *, softlockup_task_ptr_saved);
#ifdef CONFIG_HARDLOCKUP_DETECTOR
static DEFINE_PER_CPU(bool, hard_watchdog_warn);
static DEFINE_PER_CPU(bool, watchdog_nmi_touch);
static DEFINE_PER_CPU(unsigned long, hrtimer_interrupts_saved);
static DEFINE_PER_CPU(struct perf_event *, watchdog_ev);
#endif
#ifdef MY_ABC_HERE
static DEFINE_PER_CPU(unsigned long, softlockup_counter);
#endif  
static unsigned long soft_lockup_nmi_warn;

#ifdef CONFIG_HARDLOCKUP_DETECTOR
unsigned int __read_mostly hardlockup_panic =
			CONFIG_BOOTPARAM_HARDLOCKUP_PANIC_VALUE;
static unsigned long hardlockup_allcpu_dumped;
 
void hardlockup_detector_disable(void)
{
	watchdog_enabled &= ~NMI_WATCHDOG_ENABLED;
}

static int __init hardlockup_panic_setup(char *str)
{
	if (!strncmp(str, "panic", 5))
		hardlockup_panic = 1;
	else if (!strncmp(str, "nopanic", 7))
		hardlockup_panic = 0;
	else if (!strncmp(str, "0", 1))
		watchdog_enabled &= ~NMI_WATCHDOG_ENABLED;
	else if (!strncmp(str, "1", 1))
		watchdog_enabled |= NMI_WATCHDOG_ENABLED;
	return 1;
}
__setup("nmi_watchdog=", hardlockup_panic_setup);
#endif

unsigned int __read_mostly softlockup_panic =
			CONFIG_BOOTPARAM_SOFTLOCKUP_PANIC_VALUE;

static int __init softlockup_panic_setup(char *str)
{
	softlockup_panic = simple_strtoul(str, NULL, 0);

	return 1;
}
__setup("softlockup_panic=", softlockup_panic_setup);

static int __init nowatchdog_setup(char *str)
{
	watchdog_enabled = 0;
	return 1;
}
__setup("nowatchdog", nowatchdog_setup);

static int __init nosoftlockup_setup(char *str)
{
	watchdog_enabled &= ~SOFT_WATCHDOG_ENABLED;
	return 1;
}
__setup("nosoftlockup", nosoftlockup_setup);

#ifdef CONFIG_SMP
static int __init softlockup_all_cpu_backtrace_setup(char *str)
{
	sysctl_softlockup_all_cpu_backtrace =
		!!simple_strtol(str, NULL, 0);
	return 1;
}
__setup("softlockup_all_cpu_backtrace=", softlockup_all_cpu_backtrace_setup);
static int __init hardlockup_all_cpu_backtrace_setup(char *str)
{
	sysctl_hardlockup_all_cpu_backtrace =
		!!simple_strtol(str, NULL, 0);
	return 1;
}
__setup("hardlockup_all_cpu_backtrace=", hardlockup_all_cpu_backtrace_setup);
#endif

static int get_softlockup_thresh(void)
{
#ifdef MY_ABC_HERE
	return watchdog_thresh * 4;
#else  
	return watchdog_thresh * 2;
#endif  
}

static unsigned long get_timestamp(void)
{
	return running_clock() >> 30LL;   
}

static void set_sample_period(void)
{
	 
#ifdef MY_ABC_HERE
	sample_period = (get_softlockup_thresh() / 2) * ((u64)NSEC_PER_SEC / 5);
#else  
	sample_period = get_softlockup_thresh() * ((u64)NSEC_PER_SEC / 5);
#endif  
}

static void __touch_watchdog(void)
{
	__this_cpu_write(watchdog_touch_ts, get_timestamp());
}

void touch_softlockup_watchdog(void)
{
	 
	raw_cpu_write(watchdog_touch_ts, 0);
}
EXPORT_SYMBOL(touch_softlockup_watchdog);

void touch_all_softlockup_watchdogs(void)
{
	int cpu;

	for_each_watchdog_cpu(cpu)
		per_cpu(watchdog_touch_ts, cpu) = 0;
}

#ifdef CONFIG_HARDLOCKUP_DETECTOR
void touch_nmi_watchdog(void)
{
	 
	raw_cpu_write(watchdog_nmi_touch, true);
	touch_softlockup_watchdog();
}
EXPORT_SYMBOL(touch_nmi_watchdog);

#endif

void touch_softlockup_watchdog_sync(void)
{
	__this_cpu_write(softlockup_touch_sync, true);
	__this_cpu_write(watchdog_touch_ts, 0);
}

#ifdef CONFIG_HARDLOCKUP_DETECTOR
 
static bool is_hardlockup(void)
{
	unsigned long hrint = __this_cpu_read(hrtimer_interrupts);

	if (__this_cpu_read(hrtimer_interrupts_saved) == hrint)
		return true;

	__this_cpu_write(hrtimer_interrupts_saved, hrint);
	return false;
}
#endif

static int is_softlockup(unsigned long touch_ts)
{
	unsigned long now = get_timestamp();

	if ((watchdog_enabled & SOFT_WATCHDOG_ENABLED) && watchdog_thresh){
		 
		if (time_after(now, touch_ts + get_softlockup_thresh()))
			return now - touch_ts;
	}
	return 0;
}

#ifdef CONFIG_HARDLOCKUP_DETECTOR

static struct perf_event_attr wd_hw_attr = {
	.type		= PERF_TYPE_HARDWARE,
	.config		= PERF_COUNT_HW_CPU_CYCLES,
	.size		= sizeof(struct perf_event_attr),
	.pinned		= 1,
	.disabled	= 1,
};

static void watchdog_overflow_callback(struct perf_event *event,
		 struct perf_sample_data *data,
		 struct pt_regs *regs)
{
	 
	event->hw.interrupts = 0;

	if (__this_cpu_read(watchdog_nmi_touch) == true) {
		__this_cpu_write(watchdog_nmi_touch, false);
		return;
	}

	if (is_hardlockup()) {
		int this_cpu = smp_processor_id();

		if (__this_cpu_read(hard_watchdog_warn) == true)
			return;

		pr_emerg("Watchdog detected hard LOCKUP on cpu %d", this_cpu);
		print_modules();
		print_irqtrace_events(current);
		if (regs)
			show_regs(regs);
		else
			dump_stack();

		if (sysctl_hardlockup_all_cpu_backtrace &&
				!test_and_set_bit(0, &hardlockup_allcpu_dumped))
			trigger_allbutself_cpu_backtrace();

		if (hardlockup_panic)
			panic("Hard LOCKUP");

		__this_cpu_write(hard_watchdog_warn, true);
		return;
	}

	__this_cpu_write(hard_watchdog_warn, false);
	return;
}
#endif  

static void watchdog_interrupt_count(void)
{
	__this_cpu_inc(hrtimer_interrupts);
}

static int watchdog_nmi_enable(unsigned int cpu);
static void watchdog_nmi_disable(unsigned int cpu);

static int watchdog_enable_all_cpus(void);
static void watchdog_disable_all_cpus(void);

static enum hrtimer_restart watchdog_timer_fn(struct hrtimer *hrtimer)
{
	unsigned long touch_ts = __this_cpu_read(watchdog_touch_ts);
	struct pt_regs *regs = get_irq_regs();
	int duration;
	int softlockup_all_cpu_backtrace = sysctl_softlockup_all_cpu_backtrace;

	watchdog_interrupt_count();

	wake_up_process(__this_cpu_read(softlockup_watchdog));

	hrtimer_forward_now(hrtimer, ns_to_ktime(sample_period));

	if (touch_ts == 0) {
		if (unlikely(__this_cpu_read(softlockup_touch_sync))) {
			 
			__this_cpu_write(softlockup_touch_sync, false);
			sched_clock_tick();
		}

		kvm_check_and_clear_guest_paused();
		__touch_watchdog();
		return HRTIMER_RESTART;
	}

	duration = is_softlockup(touch_ts);
	if (unlikely(duration)) {
		 
		if (kvm_check_and_clear_guest_paused())
			return HRTIMER_RESTART;

		if (__this_cpu_read(soft_watchdog_warn) == true) {
			 
			if (__this_cpu_read(softlockup_task_ptr_saved) !=
			    current) {
				__this_cpu_write(soft_watchdog_warn, false);
				__touch_watchdog();
			}
			return HRTIMER_RESTART;
		}

		if (softlockup_all_cpu_backtrace) {
			 
			if (test_and_set_bit(0, &soft_lockup_nmi_warn)) {
				 
				__this_cpu_write(soft_watchdog_warn, true);
				return HRTIMER_RESTART;
			}
		}

#ifdef MY_ABC_HERE
		if (__this_cpu_read(softlockup_counter) >= CONFIG_SYNO_SOFTLOCKUP_COUNTER_MAX) {
			__this_cpu_write(soft_watchdog_warn, false);
			return HRTIMER_RESTART;
		} else {
			__this_cpu_inc(softlockup_counter);
		}
#endif  

		pr_emerg("BUG: soft lockup - CPU#%d stuck for %us! [%s:%d]\n",
			smp_processor_id(), duration,
			current->comm, task_pid_nr(current));
		__this_cpu_write(softlockup_task_ptr_saved, current);
		print_modules();
		print_irqtrace_events(current);
		if (regs)
			show_regs(regs);
		else
			dump_stack();

		if (softlockup_all_cpu_backtrace) {
			 
			trigger_allbutself_cpu_backtrace();

			clear_bit(0, &soft_lockup_nmi_warn);
			 
			smp_mb__after_atomic();
		}

		add_taint(TAINT_SOFTLOCKUP, LOCKDEP_STILL_OK);
		if (softlockup_panic)
			panic("softlockup: hung tasks");
		__this_cpu_write(soft_watchdog_warn, true);
	} else
		__this_cpu_write(soft_watchdog_warn, false);

	return HRTIMER_RESTART;
}

static void watchdog_set_prio(unsigned int policy, unsigned int prio)
{
	struct sched_param param = { .sched_priority = prio };

	sched_setscheduler(current, policy, &param);
}

static void watchdog_enable(unsigned int cpu)
{
	struct hrtimer *hrtimer = raw_cpu_ptr(&watchdog_hrtimer);

	hrtimer_init(hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	hrtimer->function = watchdog_timer_fn;

	watchdog_nmi_enable(cpu);

	hrtimer_start(hrtimer, ns_to_ktime(sample_period),
		      HRTIMER_MODE_REL_PINNED);

	watchdog_set_prio(SCHED_FIFO, MAX_RT_PRIO - 1);
	__touch_watchdog();
}

static void watchdog_disable(unsigned int cpu)
{
	struct hrtimer *hrtimer = raw_cpu_ptr(&watchdog_hrtimer);

	watchdog_set_prio(SCHED_NORMAL, 0);
	hrtimer_cancel(hrtimer);
	 
	watchdog_nmi_disable(cpu);
}

static void watchdog_cleanup(unsigned int cpu, bool online)
{
	watchdog_disable(cpu);
}

static int watchdog_should_run(unsigned int cpu)
{
	return __this_cpu_read(hrtimer_interrupts) !=
		__this_cpu_read(soft_lockup_hrtimer_cnt);
}

static void watchdog(unsigned int cpu)
{
	__this_cpu_write(soft_lockup_hrtimer_cnt,
			 __this_cpu_read(hrtimer_interrupts));
	__touch_watchdog();

	if (!(watchdog_enabled & NMI_WATCHDOG_ENABLED))
		watchdog_nmi_disable(cpu);
}

#ifdef CONFIG_HARDLOCKUP_DETECTOR
 
static unsigned long cpu0_err;

static int watchdog_nmi_enable(unsigned int cpu)
{
	struct perf_event_attr *wd_attr;
	struct perf_event *event = per_cpu(watchdog_ev, cpu);

	if (!(watchdog_enabled & NMI_WATCHDOG_ENABLED))
		goto out;

	if (event && event->state > PERF_EVENT_STATE_OFF)
		goto out;

	if (event != NULL)
		goto out_enable;

	wd_attr = &wd_hw_attr;
	wd_attr->sample_period = hw_nmi_get_sample_period(watchdog_thresh);

	event = perf_event_create_kernel_counter(wd_attr, cpu, NULL, watchdog_overflow_callback, NULL);

	if (cpu == 0 && IS_ERR(event))
		cpu0_err = PTR_ERR(event);

	if (!IS_ERR(event)) {
		 
		if (cpu == 0 || cpu0_err)
			pr_info("enabled on all CPUs, permanently consumes one hw-PMU counter.\n");
		goto out_save;
	}

	smp_mb__before_atomic();
	clear_bit(NMI_WATCHDOG_ENABLED_BIT, &watchdog_enabled);
	smp_mb__after_atomic();

	if (cpu > 0 && (PTR_ERR(event) == cpu0_err))
		return PTR_ERR(event);

	if (PTR_ERR(event) == -EOPNOTSUPP)
		pr_info("disabled (cpu%i): not supported (no LAPIC?)\n", cpu);
	else if (PTR_ERR(event) == -ENOENT)
		pr_warn("disabled (cpu%i): hardware events not enabled\n",
			 cpu);
	else
		pr_err("disabled (cpu%i): unable to create perf event: %ld\n",
			cpu, PTR_ERR(event));

	pr_info("Shutting down hard lockup detector on all cpus\n");

	return PTR_ERR(event);

out_save:
	per_cpu(watchdog_ev, cpu) = event;
out_enable:
	perf_event_enable(per_cpu(watchdog_ev, cpu));
out:
	return 0;
}

static void watchdog_nmi_disable(unsigned int cpu)
{
	struct perf_event *event = per_cpu(watchdog_ev, cpu);

	if (event) {
		perf_event_disable(event);
		per_cpu(watchdog_ev, cpu) = NULL;

		perf_event_release_kernel(event);
	}
	if (cpu == 0) {
		 
		cpu0_err = 0;
	}
}

#else
static int watchdog_nmi_enable(unsigned int cpu) { return 0; }
static void watchdog_nmi_disable(unsigned int cpu) { return; }
#endif  

static struct smp_hotplug_thread watchdog_threads = {
	.store			= &softlockup_watchdog,
	.thread_should_run	= watchdog_should_run,
	.thread_fn		= watchdog,
	.thread_comm		= "watchdog/%u",
	.setup			= watchdog_enable,
	.cleanup		= watchdog_cleanup,
	.park			= watchdog_disable,
	.unpark			= watchdog_enable,
};

static int watchdog_park_threads(void)
{
	int cpu, ret = 0;

	for_each_watchdog_cpu(cpu) {
		ret = kthread_park(per_cpu(softlockup_watchdog, cpu));
		if (ret)
			break;
	}

	return ret;
}

static void watchdog_unpark_threads(void)
{
	int cpu;

	for_each_watchdog_cpu(cpu)
		kthread_unpark(per_cpu(softlockup_watchdog, cpu));
}

int lockup_detector_suspend(void)
{
	int ret = 0;

	get_online_cpus();
	mutex_lock(&watchdog_proc_mutex);
	 
	if (watchdog_running && !watchdog_suspended)
		ret = watchdog_park_threads();

	if (ret == 0)
		watchdog_suspended++;
	else {
		watchdog_disable_all_cpus();
		pr_err("Failed to suspend lockup detectors, disabled\n");
		watchdog_enabled = 0;
	}

	mutex_unlock(&watchdog_proc_mutex);

	return ret;
}

void lockup_detector_resume(void)
{
	mutex_lock(&watchdog_proc_mutex);

	watchdog_suspended--;
	 
	if (watchdog_running && !watchdog_suspended)
		watchdog_unpark_threads();

	mutex_unlock(&watchdog_proc_mutex);
	put_online_cpus();
}

static int update_watchdog_all_cpus(void)
{
	int ret;

	ret = watchdog_park_threads();
	if (ret)
		return ret;

	watchdog_unpark_threads();

	return 0;
}

static int watchdog_enable_all_cpus(void)
{
	int err = 0;

	if (!watchdog_running) {
		err = smpboot_register_percpu_thread_cpumask(&watchdog_threads,
							     &watchdog_cpumask);
		if (err)
			pr_err("Failed to create watchdog threads, disabled\n");
		else
			watchdog_running = 1;
	} else {
		 
		err = update_watchdog_all_cpus();

		if (err) {
			watchdog_disable_all_cpus();
			pr_err("Failed to update lockup detectors, disabled\n");
		}
	}

	if (err)
		watchdog_enabled = 0;

	return err;
}

static void watchdog_disable_all_cpus(void)
{
	if (watchdog_running) {
		watchdog_running = 0;
		smpboot_unregister_percpu_thread(&watchdog_threads);
	}
}

#ifdef CONFIG_SYSCTL

static int proc_watchdog_update(void)
{
	int err = 0;

	if (watchdog_enabled && watchdog_thresh)
		err = watchdog_enable_all_cpus();
	else
		watchdog_disable_all_cpus();

	return err;

}

static int proc_watchdog_common(int which, struct ctl_table *table, int write,
				void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int err, old, new;
	int *watchdog_param = (int *)table->data;

	get_online_cpus();
	mutex_lock(&watchdog_proc_mutex);

	if (watchdog_suspended) {
		 
		err = -EAGAIN;
		goto out;
	}

	if (!write) {
		*watchdog_param = (watchdog_enabled & which) != 0;
		err = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	} else {
		err = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
		if (err)
			goto out;

		do {
			old = watchdog_enabled;
			 
			if (*watchdog_param)
				new = old | which;
			else
				new = old & ~which;
		} while (cmpxchg(&watchdog_enabled, old, new) != old);

		if (old == new)
			goto out;

		err = proc_watchdog_update();
	}
out:
	mutex_unlock(&watchdog_proc_mutex);
	put_online_cpus();
	return err;
}

int proc_watchdog(struct ctl_table *table, int write,
		  void __user *buffer, size_t *lenp, loff_t *ppos)
{
	return proc_watchdog_common(NMI_WATCHDOG_ENABLED|SOFT_WATCHDOG_ENABLED,
				    table, write, buffer, lenp, ppos);
}

int proc_nmi_watchdog(struct ctl_table *table, int write,
		      void __user *buffer, size_t *lenp, loff_t *ppos)
{
	return proc_watchdog_common(NMI_WATCHDOG_ENABLED,
				    table, write, buffer, lenp, ppos);
}

int proc_soft_watchdog(struct ctl_table *table, int write,
			void __user *buffer, size_t *lenp, loff_t *ppos)
{
	return proc_watchdog_common(SOFT_WATCHDOG_ENABLED,
				    table, write, buffer, lenp, ppos);
}

int proc_watchdog_thresh(struct ctl_table *table, int write,
			 void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int err, old, new;

	get_online_cpus();
	mutex_lock(&watchdog_proc_mutex);

	if (watchdog_suspended) {
		 
		err = -EAGAIN;
		goto out;
	}

	old = ACCESS_ONCE(watchdog_thresh);
	err = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (err || !write)
		goto out;

	new = ACCESS_ONCE(watchdog_thresh);
	if (old == new)
		goto out;

	set_sample_period();
	err = proc_watchdog_update();
	if (err) {
		watchdog_thresh = old;
		set_sample_period();
	}
out:
	mutex_unlock(&watchdog_proc_mutex);
	put_online_cpus();
	return err;
}

int proc_watchdog_cpumask(struct ctl_table *table, int write,
			  void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int err;

	get_online_cpus();
	mutex_lock(&watchdog_proc_mutex);

	if (watchdog_suspended) {
		 
		err = -EAGAIN;
		goto out;
	}

	err = proc_do_large_bitmap(table, write, buffer, lenp, ppos);
	if (!err && write) {
		 
		cpumask_and(&watchdog_cpumask, &watchdog_cpumask,
			    cpu_possible_mask);

		if (watchdog_running) {
			 
			if (smpboot_update_cpumask_percpu_thread(
				    &watchdog_threads, &watchdog_cpumask) != 0)
				pr_err("cpumask update failed\n");
		}
	}
out:
	mutex_unlock(&watchdog_proc_mutex);
	put_online_cpus();
	return err;
}

#endif  

void __init lockup_detector_init(void)
{
	set_sample_period();

#ifdef CONFIG_NO_HZ_FULL
	if (tick_nohz_full_enabled()) {
		pr_info("Disabling watchdog on nohz_full cores by default\n");
		cpumask_copy(&watchdog_cpumask, housekeeping_mask);
	} else
		cpumask_copy(&watchdog_cpumask, cpu_possible_mask);
#else
	cpumask_copy(&watchdog_cpumask, cpu_possible_mask);
#endif

	if (watchdog_enabled)
		watchdog_enable_all_cpus();
}
