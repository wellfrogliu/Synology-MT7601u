#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/percpu.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/mutex.h>
#include <linux/export.h>
#include <linux/hardirq.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/tick.h>

#define CREATE_TRACE_POINTS

#include "rcu.h"

MODULE_ALIAS("rcupdate");
#ifdef MODULE_PARAM_PREFIX
#undef MODULE_PARAM_PREFIX
#endif
#define MODULE_PARAM_PREFIX "rcupdate."

module_param(rcu_expedited, int, 0);

#if defined(CONFIG_DEBUG_LOCK_ALLOC) && defined(CONFIG_PREEMPT_COUNT)
 
int rcu_read_lock_sched_held(void)
{
	int lockdep_opinion = 0;

	if (!debug_lockdep_rcu_enabled())
		return 1;
	if (!rcu_is_watching())
		return 0;
	if (!rcu_lockdep_current_cpu_online())
		return 0;
	if (debug_locks)
		lockdep_opinion = lock_is_held(&rcu_sched_lock_map);
	return lockdep_opinion || preempt_count() != 0 || irqs_disabled();
}
EXPORT_SYMBOL(rcu_read_lock_sched_held);
#endif

#ifndef CONFIG_TINY_RCU

static atomic_t rcu_expedited_nesting =
	ATOMIC_INIT(IS_ENABLED(CONFIG_RCU_EXPEDITE_BOOT) ? 1 : 0);

bool rcu_gp_is_expedited(void)
{
	return rcu_expedited || atomic_read(&rcu_expedited_nesting);
}
EXPORT_SYMBOL_GPL(rcu_gp_is_expedited);

void rcu_expedite_gp(void)
{
	atomic_inc(&rcu_expedited_nesting);
}
EXPORT_SYMBOL_GPL(rcu_expedite_gp);

void rcu_unexpedite_gp(void)
{
	atomic_dec(&rcu_expedited_nesting);
}
EXPORT_SYMBOL_GPL(rcu_unexpedite_gp);

#endif  

void rcu_end_inkernel_boot(void)
{
	if (IS_ENABLED(CONFIG_RCU_EXPEDITE_BOOT))
		rcu_unexpedite_gp();
}

#ifdef CONFIG_PREEMPT_RCU

void __rcu_read_lock(void)
{
	current->rcu_read_lock_nesting++;
	barrier();   
}
EXPORT_SYMBOL_GPL(__rcu_read_lock);

void __rcu_read_unlock(void)
{
	struct task_struct *t = current;

	if (t->rcu_read_lock_nesting != 1) {
		--t->rcu_read_lock_nesting;
	} else {
		barrier();   
		t->rcu_read_lock_nesting = INT_MIN;
		barrier();   
		if (unlikely(READ_ONCE(t->rcu_read_unlock_special.s)))
			rcu_read_unlock_special(t);
		barrier();   
		t->rcu_read_lock_nesting = 0;
	}
#ifdef CONFIG_PROVE_LOCKING
	{
		int rrln = READ_ONCE(t->rcu_read_lock_nesting);

		WARN_ON_ONCE(rrln < 0 && rrln > INT_MIN / 2);
	}
#endif  
}
EXPORT_SYMBOL_GPL(__rcu_read_unlock);

#endif  

#ifdef CONFIG_DEBUG_LOCK_ALLOC
static struct lock_class_key rcu_lock_key;
struct lockdep_map rcu_lock_map =
	STATIC_LOCKDEP_MAP_INIT("rcu_read_lock", &rcu_lock_key);
EXPORT_SYMBOL_GPL(rcu_lock_map);

static struct lock_class_key rcu_bh_lock_key;
struct lockdep_map rcu_bh_lock_map =
	STATIC_LOCKDEP_MAP_INIT("rcu_read_lock_bh", &rcu_bh_lock_key);
EXPORT_SYMBOL_GPL(rcu_bh_lock_map);

static struct lock_class_key rcu_sched_lock_key;
struct lockdep_map rcu_sched_lock_map =
	STATIC_LOCKDEP_MAP_INIT("rcu_read_lock_sched", &rcu_sched_lock_key);
EXPORT_SYMBOL_GPL(rcu_sched_lock_map);

static struct lock_class_key rcu_callback_key;
struct lockdep_map rcu_callback_map =
	STATIC_LOCKDEP_MAP_INIT("rcu_callback", &rcu_callback_key);
EXPORT_SYMBOL_GPL(rcu_callback_map);

int notrace debug_lockdep_rcu_enabled(void)
{
	return rcu_scheduler_active && debug_locks &&
	       current->lockdep_recursion == 0;
}
EXPORT_SYMBOL_GPL(debug_lockdep_rcu_enabled);

int rcu_read_lock_held(void)
{
	if (!debug_lockdep_rcu_enabled())
		return 1;
	if (!rcu_is_watching())
		return 0;
	if (!rcu_lockdep_current_cpu_online())
		return 0;
	return lock_is_held(&rcu_lock_map);
}
EXPORT_SYMBOL_GPL(rcu_read_lock_held);

int rcu_read_lock_bh_held(void)
{
	if (!debug_lockdep_rcu_enabled())
		return 1;
	if (!rcu_is_watching())
		return 0;
	if (!rcu_lockdep_current_cpu_online())
		return 0;
	return in_softirq() || irqs_disabled();
}
EXPORT_SYMBOL_GPL(rcu_read_lock_bh_held);

#endif  

void wakeme_after_rcu(struct rcu_head *head)
{
	struct rcu_synchronize *rcu;

	rcu = container_of(head, struct rcu_synchronize, head);
	complete(&rcu->completion);
}
EXPORT_SYMBOL_GPL(wakeme_after_rcu);

void __wait_rcu_gp(bool checktiny, int n, call_rcu_func_t *crcu_array,
		   struct rcu_synchronize *rs_array)
{
	int i;

	for (i = 0; i < n; i++) {
		if (checktiny &&
		    (crcu_array[i] == call_rcu ||
		     crcu_array[i] == call_rcu_bh)) {
			might_sleep();
			continue;
		}
		init_rcu_head_on_stack(&rs_array[i].head);
		init_completion(&rs_array[i].completion);
		(crcu_array[i])(&rs_array[i].head, wakeme_after_rcu);
	}

	for (i = 0; i < n; i++) {
		if (checktiny &&
		    (crcu_array[i] == call_rcu ||
		     crcu_array[i] == call_rcu_bh))
			continue;
		wait_for_completion(&rs_array[i].completion);
		destroy_rcu_head_on_stack(&rs_array[i].head);
	}
}
EXPORT_SYMBOL_GPL(__wait_rcu_gp);

#ifdef CONFIG_DEBUG_OBJECTS_RCU_HEAD
void init_rcu_head(struct rcu_head *head)
{
	debug_object_init(head, &rcuhead_debug_descr);
}

void destroy_rcu_head(struct rcu_head *head)
{
	debug_object_free(head, &rcuhead_debug_descr);
}

static int rcuhead_fixup_activate(void *addr, enum debug_obj_state state)
{
	struct rcu_head *head = addr;

	switch (state) {

	case ODEBUG_STATE_NOTAVAILABLE:
		 
		debug_object_init(head, &rcuhead_debug_descr);
		debug_object_activate(head, &rcuhead_debug_descr);
		return 0;
	default:
		return 1;
	}
}

void init_rcu_head_on_stack(struct rcu_head *head)
{
	debug_object_init_on_stack(head, &rcuhead_debug_descr);
}
EXPORT_SYMBOL_GPL(init_rcu_head_on_stack);

void destroy_rcu_head_on_stack(struct rcu_head *head)
{
	debug_object_free(head, &rcuhead_debug_descr);
}
EXPORT_SYMBOL_GPL(destroy_rcu_head_on_stack);

struct debug_obj_descr rcuhead_debug_descr = {
	.name = "rcu_head",
	.fixup_activate = rcuhead_fixup_activate,
};
EXPORT_SYMBOL_GPL(rcuhead_debug_descr);
#endif  

#if defined(CONFIG_TREE_RCU) || defined(CONFIG_PREEMPT_RCU) || defined(CONFIG_RCU_TRACE)
void do_trace_rcu_torture_read(const char *rcutorturename, struct rcu_head *rhp,
			       unsigned long secs,
			       unsigned long c_old, unsigned long c)
{
	trace_rcu_torture_read(rcutorturename, rhp, secs, c_old, c);
}
EXPORT_SYMBOL_GPL(do_trace_rcu_torture_read);
#else
#define do_trace_rcu_torture_read(rcutorturename, rhp, secs, c_old, c) \
	do { } while (0)
#endif

#ifdef CONFIG_RCU_STALL_COMMON

#ifdef CONFIG_PROVE_RCU
#define RCU_STALL_DELAY_DELTA	       (5 * HZ)
#else
#define RCU_STALL_DELAY_DELTA	       0
#endif

#ifdef MY_ABC_HERE
int rcu_cpu_stall_suppress __read_mostly = 1;  
#else
int rcu_cpu_stall_suppress __read_mostly;  
#endif  
static int rcu_cpu_stall_timeout __read_mostly = CONFIG_RCU_CPU_STALL_TIMEOUT;

module_param(rcu_cpu_stall_suppress, int, 0644);
module_param(rcu_cpu_stall_timeout, int, 0644);

int rcu_jiffies_till_stall_check(void)
{
	int till_stall_check = READ_ONCE(rcu_cpu_stall_timeout);

	if (till_stall_check < 3) {
		WRITE_ONCE(rcu_cpu_stall_timeout, 3);
		till_stall_check = 3;
	} else if (till_stall_check > 300) {
		WRITE_ONCE(rcu_cpu_stall_timeout, 300);
		till_stall_check = 300;
	}
	return till_stall_check * HZ + RCU_STALL_DELAY_DELTA;
}

void rcu_sysrq_start(void)
{
	if (!rcu_cpu_stall_suppress)
		rcu_cpu_stall_suppress = 2;
}

void rcu_sysrq_end(void)
{
	if (rcu_cpu_stall_suppress == 2)
		rcu_cpu_stall_suppress = 0;
}

static int rcu_panic(struct notifier_block *this, unsigned long ev, void *ptr)
{
	rcu_cpu_stall_suppress = 1;
	return NOTIFY_DONE;
}

static struct notifier_block rcu_panic_block = {
	.notifier_call = rcu_panic,
};

static int __init check_cpu_stall_init(void)
{
	atomic_notifier_chain_register(&panic_notifier_list, &rcu_panic_block);
	return 0;
}
early_initcall(check_cpu_stall_init);

#endif  

#ifdef CONFIG_TASKS_RCU

static struct rcu_head *rcu_tasks_cbs_head;
static struct rcu_head **rcu_tasks_cbs_tail = &rcu_tasks_cbs_head;
static DECLARE_WAIT_QUEUE_HEAD(rcu_tasks_cbs_wq);
static DEFINE_RAW_SPINLOCK(rcu_tasks_cbs_lock);

DEFINE_SRCU(tasks_rcu_exit_srcu);

static int rcu_task_stall_timeout __read_mostly = HZ * 60 * 10;
module_param(rcu_task_stall_timeout, int, 0644);

static void rcu_spawn_tasks_kthread(void);

void call_rcu_tasks(struct rcu_head *rhp, rcu_callback_t func)
{
	unsigned long flags;
	bool needwake;

	rhp->next = NULL;
	rhp->func = func;
	raw_spin_lock_irqsave(&rcu_tasks_cbs_lock, flags);
	needwake = !rcu_tasks_cbs_head;
	*rcu_tasks_cbs_tail = rhp;
	rcu_tasks_cbs_tail = &rhp->next;
	raw_spin_unlock_irqrestore(&rcu_tasks_cbs_lock, flags);
	if (needwake) {
		rcu_spawn_tasks_kthread();
		wake_up(&rcu_tasks_cbs_wq);
	}
}
EXPORT_SYMBOL_GPL(call_rcu_tasks);

void synchronize_rcu_tasks(void)
{
	 
	RCU_LOCKDEP_WARN(!rcu_scheduler_active,
			 "synchronize_rcu_tasks called too soon");

	wait_rcu_gp(call_rcu_tasks);
}
EXPORT_SYMBOL_GPL(synchronize_rcu_tasks);

void rcu_barrier_tasks(void)
{
	 
	synchronize_rcu_tasks();
}
EXPORT_SYMBOL_GPL(rcu_barrier_tasks);

static void check_holdout_task(struct task_struct *t,
			       bool needreport, bool *firstreport)
{
	int cpu;

	if (!READ_ONCE(t->rcu_tasks_holdout) ||
	    t->rcu_tasks_nvcsw != READ_ONCE(t->nvcsw) ||
	    !READ_ONCE(t->on_rq) ||
	    (IS_ENABLED(CONFIG_NO_HZ_FULL) &&
	     !is_idle_task(t) && t->rcu_tasks_idle_cpu >= 0)) {
		WRITE_ONCE(t->rcu_tasks_holdout, false);
		list_del_init(&t->rcu_tasks_holdout_list);
		put_task_struct(t);
		return;
	}
	if (!needreport)
		return;
	if (*firstreport) {
		pr_err("INFO: rcu_tasks detected stalls on tasks:\n");
		*firstreport = false;
	}
	cpu = task_cpu(t);
	pr_alert("%p: %c%c nvcsw: %lu/%lu holdout: %d idle_cpu: %d/%d\n",
		 t, ".I"[is_idle_task(t)],
		 "N."[cpu < 0 || !tick_nohz_full_cpu(cpu)],
		 t->rcu_tasks_nvcsw, t->nvcsw, t->rcu_tasks_holdout,
		 t->rcu_tasks_idle_cpu, cpu);
	sched_show_task(t);
}

static int __noreturn rcu_tasks_kthread(void *arg)
{
	unsigned long flags;
	struct task_struct *g, *t;
	unsigned long lastreport;
	struct rcu_head *list;
	struct rcu_head *next;
	LIST_HEAD(rcu_tasks_holdouts);

	housekeeping_affine(current);

	for (;;) {

		raw_spin_lock_irqsave(&rcu_tasks_cbs_lock, flags);
		list = rcu_tasks_cbs_head;
		rcu_tasks_cbs_head = NULL;
		rcu_tasks_cbs_tail = &rcu_tasks_cbs_head;
		raw_spin_unlock_irqrestore(&rcu_tasks_cbs_lock, flags);

		if (!list) {
			wait_event_interruptible(rcu_tasks_cbs_wq,
						 rcu_tasks_cbs_head);
			if (!rcu_tasks_cbs_head) {
				WARN_ON(signal_pending(current));
				schedule_timeout_interruptible(HZ/10);
			}
			continue;
		}

		synchronize_sched();

		rcu_read_lock();
		for_each_process_thread(g, t) {
			if (t != current && READ_ONCE(t->on_rq) &&
			    !is_idle_task(t)) {
				get_task_struct(t);
				t->rcu_tasks_nvcsw = READ_ONCE(t->nvcsw);
				WRITE_ONCE(t->rcu_tasks_holdout, true);
				list_add(&t->rcu_tasks_holdout_list,
					 &rcu_tasks_holdouts);
			}
		}
		rcu_read_unlock();

		synchronize_srcu(&tasks_rcu_exit_srcu);

		lastreport = jiffies;
		while (!list_empty(&rcu_tasks_holdouts)) {
			bool firstreport;
			bool needreport;
			int rtst;
			struct task_struct *t1;

			schedule_timeout_interruptible(HZ);
			rtst = READ_ONCE(rcu_task_stall_timeout);
			needreport = rtst > 0 &&
				     time_after(jiffies, lastreport + rtst);
			if (needreport)
				lastreport = jiffies;
			firstreport = true;
			WARN_ON(signal_pending(current));
			list_for_each_entry_safe(t, t1, &rcu_tasks_holdouts,
						rcu_tasks_holdout_list) {
				check_holdout_task(t, needreport, &firstreport);
				cond_resched();
			}
		}

		synchronize_sched();

		while (list) {
			next = list->next;
			local_bh_disable();
			list->func(list);
			local_bh_enable();
			list = next;
			cond_resched();
		}
		schedule_timeout_uninterruptible(HZ/10);
	}
}

static void rcu_spawn_tasks_kthread(void)
{
	static DEFINE_MUTEX(rcu_tasks_kthread_mutex);
	static struct task_struct *rcu_tasks_kthread_ptr;
	struct task_struct *t;

	if (READ_ONCE(rcu_tasks_kthread_ptr)) {
		smp_mb();  
		return;
	}
	mutex_lock(&rcu_tasks_kthread_mutex);
	if (rcu_tasks_kthread_ptr) {
		mutex_unlock(&rcu_tasks_kthread_mutex);
		return;
	}
	t = kthread_run(rcu_tasks_kthread, NULL, "rcu_tasks_kthread");
	BUG_ON(IS_ERR(t));
	smp_mb();  
	WRITE_ONCE(rcu_tasks_kthread_ptr, t);
	mutex_unlock(&rcu_tasks_kthread_mutex);
}

#endif  

#ifdef CONFIG_PROVE_RCU

static bool rcu_self_test;
static bool rcu_self_test_bh;
static bool rcu_self_test_sched;

module_param(rcu_self_test, bool, 0444);
module_param(rcu_self_test_bh, bool, 0444);
module_param(rcu_self_test_sched, bool, 0444);

static int rcu_self_test_counter;

static void test_callback(struct rcu_head *r)
{
	rcu_self_test_counter++;
	pr_info("RCU test callback executed %d\n", rcu_self_test_counter);
}

static void early_boot_test_call_rcu(void)
{
	static struct rcu_head head;

	call_rcu(&head, test_callback);
}

static void early_boot_test_call_rcu_bh(void)
{
	static struct rcu_head head;

	call_rcu_bh(&head, test_callback);
}

static void early_boot_test_call_rcu_sched(void)
{
	static struct rcu_head head;

	call_rcu_sched(&head, test_callback);
}

void rcu_early_boot_tests(void)
{
	pr_info("Running RCU self tests\n");

	if (rcu_self_test)
		early_boot_test_call_rcu();
	if (rcu_self_test_bh)
		early_boot_test_call_rcu_bh();
	if (rcu_self_test_sched)
		early_boot_test_call_rcu_sched();
}

static int rcu_verify_early_boot_tests(void)
{
	int ret = 0;
	int early_boot_test_counter = 0;

	if (rcu_self_test) {
		early_boot_test_counter++;
		rcu_barrier();
	}
	if (rcu_self_test_bh) {
		early_boot_test_counter++;
		rcu_barrier_bh();
	}
	if (rcu_self_test_sched) {
		early_boot_test_counter++;
		rcu_barrier_sched();
	}

	if (rcu_self_test_counter != early_boot_test_counter) {
		WARN_ON(1);
		ret = -1;
	}

	return ret;
}
late_initcall(rcu_verify_early_boot_tests);
#else
void rcu_early_boot_tests(void) {}
#endif  
