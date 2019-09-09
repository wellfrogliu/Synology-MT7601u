#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/oom.h>
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/sched.h>
#include <linux/swap.h>
#include <linux/timex.h>
#include <linux/jiffies.h>
#include <linux/cpuset.h>
#include <linux/export.h>
#include <linux/notifier.h>
#include <linux/memcontrol.h>
#include <linux/mempolicy.h>
#include <linux/security.h>
#include <linux/ptrace.h>
#include <linux/freezer.h>
#include <linux/ftrace.h>
#include <linux/ratelimit.h>

#define CREATE_TRACE_POINTS
#include <trace/events/oom.h>

int sysctl_panic_on_oom;
int sysctl_oom_kill_allocating_task;
int sysctl_oom_dump_tasks = 1;

#ifdef MY_ABC_HERE
extern void syno_dump_modules(void);
#endif  

DEFINE_MUTEX(oom_lock);

#ifdef CONFIG_NUMA
 
static bool has_intersects_mems_allowed(struct task_struct *start,
					const nodemask_t *mask)
{
	struct task_struct *tsk;
	bool ret = false;

	rcu_read_lock();
	for_each_thread(start, tsk) {
		if (mask) {
			 
			ret = mempolicy_nodemask_intersects(tsk, mask);
		} else {
			 
			ret = cpuset_mems_allowed_intersects(current, tsk);
		}
		if (ret)
			break;
	}
	rcu_read_unlock();

	return ret;
}
#else
static bool has_intersects_mems_allowed(struct task_struct *tsk,
					const nodemask_t *mask)
{
	return true;
}
#endif  

struct task_struct *find_lock_task_mm(struct task_struct *p)
{
	struct task_struct *t;

	rcu_read_lock();

	for_each_thread(p, t) {
		task_lock(t);
		if (likely(t->mm))
			goto found;
		task_unlock(t);
	}
	t = NULL;
found:
	rcu_read_unlock();

	return t;
}

static inline bool is_sysrq_oom(struct oom_control *oc)
{
	return oc->order == -1;
}

static bool oom_unkillable_task(struct task_struct *p,
		struct mem_cgroup *memcg, const nodemask_t *nodemask)
{
	if (is_global_init(p))
		return true;
	if (p->flags & PF_KTHREAD)
		return true;

	if (memcg && !task_in_mem_cgroup(p, memcg))
		return true;

	if (!has_intersects_mems_allowed(p, nodemask))
		return true;

	return false;
}

unsigned long oom_badness(struct task_struct *p, struct mem_cgroup *memcg,
			  const nodemask_t *nodemask, unsigned long totalpages)
{
	long points;
	long adj;

	if (oom_unkillable_task(p, memcg, nodemask))
		return 0;

	p = find_lock_task_mm(p);
	if (!p)
		return 0;

	adj = (long)p->signal->oom_score_adj;
	if (adj == OOM_SCORE_ADJ_MIN) {
		task_unlock(p);
		return 0;
	}

	points = get_mm_rss(p->mm) + get_mm_counter(p->mm, MM_SWAPENTS) +
		atomic_long_read(&p->mm->nr_ptes) + mm_nr_pmds(p->mm);
	task_unlock(p);

	if (has_capability_noaudit(p, CAP_SYS_ADMIN))
		points -= (points * 3) / 100;

	adj *= totalpages / 1000;
	points += adj;

	return points > 0 ? points : 1;
}

#ifdef CONFIG_NUMA
static enum oom_constraint constrained_alloc(struct oom_control *oc,
					     unsigned long *totalpages)
{
	struct zone *zone;
	struct zoneref *z;
	enum zone_type high_zoneidx = gfp_zone(oc->gfp_mask);
	bool cpuset_limited = false;
	int nid;

	*totalpages = totalram_pages + total_swap_pages;

	if (!oc->zonelist)
		return CONSTRAINT_NONE;
	 
	if (oc->gfp_mask & __GFP_THISNODE)
		return CONSTRAINT_NONE;

	if (oc->nodemask &&
	    !nodes_subset(node_states[N_MEMORY], *oc->nodemask)) {
		*totalpages = total_swap_pages;
		for_each_node_mask(nid, *oc->nodemask)
			*totalpages += node_spanned_pages(nid);
		return CONSTRAINT_MEMORY_POLICY;
	}

	for_each_zone_zonelist_nodemask(zone, z, oc->zonelist,
			high_zoneidx, oc->nodemask)
		if (!cpuset_zone_allowed(zone, oc->gfp_mask))
			cpuset_limited = true;

	if (cpuset_limited) {
		*totalpages = total_swap_pages;
		for_each_node_mask(nid, cpuset_current_mems_allowed)
			*totalpages += node_spanned_pages(nid);
		return CONSTRAINT_CPUSET;
	}
	return CONSTRAINT_NONE;
}
#else
static enum oom_constraint constrained_alloc(struct oom_control *oc,
					     unsigned long *totalpages)
{
	*totalpages = totalram_pages + total_swap_pages;
	return CONSTRAINT_NONE;
}
#endif

enum oom_scan_t oom_scan_process_thread(struct oom_control *oc,
			struct task_struct *task, unsigned long totalpages)
{
	if (oom_unkillable_task(task, NULL, oc->nodemask))
		return OOM_SCAN_CONTINUE;

	if (test_tsk_thread_flag(task, TIF_MEMDIE)) {
		if (!is_sysrq_oom(oc))
			return OOM_SCAN_ABORT;
	}
	if (!task->mm)
		return OOM_SCAN_CONTINUE;

	if (oom_task_origin(task))
		return OOM_SCAN_SELECT;

	if (task_will_free_mem(task) && !is_sysrq_oom(oc))
		return OOM_SCAN_ABORT;

	return OOM_SCAN_OK;
}

static struct task_struct *select_bad_process(struct oom_control *oc,
		unsigned int *ppoints, unsigned long totalpages)
{
	struct task_struct *g, *p;
	struct task_struct *chosen = NULL;
	unsigned long chosen_points = 0;

	rcu_read_lock();
	for_each_process_thread(g, p) {
		unsigned int points;

		switch (oom_scan_process_thread(oc, p, totalpages)) {
		case OOM_SCAN_SELECT:
			chosen = p;
			chosen_points = ULONG_MAX;
			 
		case OOM_SCAN_CONTINUE:
			continue;
		case OOM_SCAN_ABORT:
			rcu_read_unlock();
			return (struct task_struct *)(-1UL);
		case OOM_SCAN_OK:
			break;
		};
		points = oom_badness(p, NULL, oc->nodemask, totalpages);
		if (!points || points < chosen_points)
			continue;
		 
		if (points == chosen_points && thread_group_leader(chosen))
			continue;

		chosen = p;
		chosen_points = points;
	}
	if (chosen)
		get_task_struct(chosen);
	rcu_read_unlock();

	*ppoints = chosen_points * 1000 / totalpages;
	return chosen;
}

static void dump_tasks(struct mem_cgroup *memcg, const nodemask_t *nodemask)
{
	struct task_struct *p;
	struct task_struct *task;

#ifdef MY_ABC_HERE
	pr_warning("[ pid ]   uid  tgid total_vm      rss nr_ptes nr_pmds swapents oom_score_adj name\n");
#else
	pr_info("[ pid ]   uid  tgid total_vm      rss nr_ptes nr_pmds swapents oom_score_adj name\n");
#endif  
	rcu_read_lock();
	for_each_process(p) {
		if (oom_unkillable_task(p, memcg, nodemask))
			continue;

		task = find_lock_task_mm(p);
		if (!task) {
			 
			continue;
		}

#ifdef MY_ABC_HERE
		pr_warning("[%5d] %5d %5d %8lu %8lu %7ld %7ld %8lu         %5hd %s\n",
#else
		pr_info("[%5d] %5d %5d %8lu %8lu %7ld %7ld %8lu         %5hd %s\n",
#endif  
			task->pid, from_kuid(&init_user_ns, task_uid(task)),
			task->tgid, task->mm->total_vm, get_mm_rss(task->mm),
			atomic_long_read(&task->mm->nr_ptes),
			mm_nr_pmds(task->mm),
			get_mm_counter(task->mm, MM_SWAPENTS),
			task->signal->oom_score_adj, task->comm);
		task_unlock(task);
	}
	rcu_read_unlock();
}

static void dump_header(struct oom_control *oc, struct task_struct *p,
			struct mem_cgroup *memcg)
{
	pr_warning("%s invoked oom-killer: gfp_mask=0x%x, order=%d, "
		"oom_score_adj=%hd\n",
		current->comm, oc->gfp_mask, oc->order,
		current->signal->oom_score_adj);
	cpuset_print_current_mems_allowed();
	dump_stack();
	if (memcg)
		mem_cgroup_print_oom_info(memcg, p);
	else
		show_mem(SHOW_MEM_FILTER_NODES);
	if (sysctl_oom_dump_tasks)
		dump_tasks(memcg, oc->nodemask);
#ifdef MY_ABC_HERE
	syno_dump_modules();
#endif  
}

static atomic_t oom_victims = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(oom_victims_wait);

bool oom_killer_disabled __read_mostly;

void mark_oom_victim(struct task_struct *tsk)
{
	WARN_ON(oom_killer_disabled);
	 
	if (test_and_set_tsk_thread_flag(tsk, TIF_MEMDIE))
		return;
	 
	__thaw_task(tsk);
	atomic_inc(&oom_victims);
}

void exit_oom_victim(void)
{
	clear_thread_flag(TIF_MEMDIE);

	if (!atomic_dec_return(&oom_victims))
		wake_up_all(&oom_victims_wait);
}

bool oom_killer_disable(void)
{
	 
	mutex_lock(&oom_lock);
	if (test_thread_flag(TIF_MEMDIE)) {
		mutex_unlock(&oom_lock);
		return false;
	}

	oom_killer_disabled = true;
	mutex_unlock(&oom_lock);

	wait_event(oom_victims_wait, !atomic_read(&oom_victims));

	return true;
}

void oom_killer_enable(void)
{
	oom_killer_disabled = false;
}

static bool process_shares_mm(struct task_struct *p, struct mm_struct *mm)
{
	struct task_struct *t;

	for_each_thread(p, t) {
		struct mm_struct *t_mm = READ_ONCE(t->mm);
		if (t_mm)
			return t_mm == mm;
	}
	return false;
}

#define K(x) ((x) << (PAGE_SHIFT-10))
 
void oom_kill_process(struct oom_control *oc, struct task_struct *p,
		      unsigned int points, unsigned long totalpages,
		      struct mem_cgroup *memcg, const char *message)
{
	struct task_struct *victim = p;
	struct task_struct *child;
	struct task_struct *t;
	struct mm_struct *mm;
	unsigned int victim_points = 0;
	static DEFINE_RATELIMIT_STATE(oom_rs, DEFAULT_RATELIMIT_INTERVAL,
					      DEFAULT_RATELIMIT_BURST);

	task_lock(p);
	if (p->mm && task_will_free_mem(p)) {
		mark_oom_victim(p);
		task_unlock(p);
		put_task_struct(p);
		return;
	}
	task_unlock(p);

	if (__ratelimit(&oom_rs))
		dump_header(oc, p, memcg);

	pr_err("%s: Kill process %d (%s) score %u or sacrifice child\n",
		message, task_pid_nr(p), p->comm, points);

	read_lock(&tasklist_lock);
	for_each_thread(p, t) {
		list_for_each_entry(child, &t->children, sibling) {
			unsigned int child_points;

			if (process_shares_mm(child, p->mm))
				continue;
			 
			child_points = oom_badness(child, memcg, oc->nodemask,
								totalpages);
			if (child_points > victim_points) {
				put_task_struct(victim);
				victim = child;
				victim_points = child_points;
				get_task_struct(victim);
			}
		}
	}
	read_unlock(&tasklist_lock);

	p = find_lock_task_mm(victim);
	if (!p) {
		put_task_struct(victim);
		return;
	} else if (victim != p) {
		get_task_struct(p);
		put_task_struct(victim);
		victim = p;
	}

	mm = victim->mm;
	atomic_inc(&mm->mm_count);
	 
	do_send_sig_info(SIGKILL, SEND_SIG_FORCED, victim, true);
	mark_oom_victim(victim);
	pr_err("Killed process %d (%s) total-vm:%lukB, anon-rss:%lukB, file-rss:%lukB\n",
		task_pid_nr(victim), victim->comm, K(victim->mm->total_vm),
		K(get_mm_counter(victim->mm, MM_ANONPAGES)),
		K(get_mm_counter(victim->mm, MM_FILEPAGES)));
	task_unlock(victim);

	rcu_read_lock();
	for_each_process(p) {
		if (!process_shares_mm(p, mm))
			continue;
		if (same_thread_group(p, victim))
			continue;
		if (unlikely(p->flags & PF_KTHREAD))
			continue;
		if (is_global_init(p))
			continue;
		if (p->signal->oom_score_adj == OOM_SCORE_ADJ_MIN)
			continue;

		do_send_sig_info(SIGKILL, SEND_SIG_FORCED, p, true);
	}
	rcu_read_unlock();

	mmdrop(mm);
	put_task_struct(victim);
}
#undef K

void check_panic_on_oom(struct oom_control *oc, enum oom_constraint constraint,
			struct mem_cgroup *memcg)
{
	if (likely(!sysctl_panic_on_oom))
		return;
	if (sysctl_panic_on_oom != 2) {
		 
		if (constraint != CONSTRAINT_NONE)
			return;
	}
	 
	if (is_sysrq_oom(oc))
		return;
	dump_header(oc, NULL, memcg);
	panic("Out of memory: %s panic_on_oom is enabled\n",
		sysctl_panic_on_oom == 2 ? "compulsory" : "system-wide");
}

static BLOCKING_NOTIFIER_HEAD(oom_notify_list);

int register_oom_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&oom_notify_list, nb);
}
EXPORT_SYMBOL_GPL(register_oom_notifier);

int unregister_oom_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&oom_notify_list, nb);
}
EXPORT_SYMBOL_GPL(unregister_oom_notifier);

bool out_of_memory(struct oom_control *oc)
{
	struct task_struct *p;
	unsigned long totalpages;
	unsigned long freed = 0;
	unsigned int uninitialized_var(points);
	enum oom_constraint constraint = CONSTRAINT_NONE;

	if (oom_killer_disabled)
		return false;

	blocking_notifier_call_chain(&oom_notify_list, 0, &freed);
	if (freed > 0)
		 
		return true;

	if (current->mm &&
	    (fatal_signal_pending(current) || task_will_free_mem(current))) {
		mark_oom_victim(current);
		return true;
	}

	constraint = constrained_alloc(oc, &totalpages);
	if (constraint != CONSTRAINT_MEMORY_POLICY)
		oc->nodemask = NULL;
	check_panic_on_oom(oc, constraint, NULL);

	if (sysctl_oom_kill_allocating_task && current->mm &&
	    !oom_unkillable_task(current, NULL, oc->nodemask) &&
	    current->signal->oom_score_adj != OOM_SCORE_ADJ_MIN) {
		get_task_struct(current);
		oom_kill_process(oc, current, 0, totalpages, NULL,
				 "Out of memory (oom_kill_allocating_task)");
		return true;
	}

	p = select_bad_process(oc, &points, totalpages);
	 
	if (!p && !is_sysrq_oom(oc)) {
		dump_header(oc, NULL, NULL);
		panic("Out of memory and no killable processes...\n");
	}
	if (p && p != (void *)-1UL) {
		oom_kill_process(oc, p, points, totalpages, NULL,
				 "Out of memory");
		 
		schedule_timeout_killable(1);
	}
	return true;
}

void pagefault_out_of_memory(void)
{
	struct oom_control oc = {
		.zonelist = NULL,
		.nodemask = NULL,
		.gfp_mask = 0,
		.order = 0,
	};

	if (mem_cgroup_oom_synchronize(true))
		return;

	if (!mutex_trylock(&oom_lock))
		return;

	if (!out_of_memory(&oc)) {
		 
		WARN_ON(test_thread_flag(TIF_MEMDIE));
	}

	mutex_unlock(&oom_lock);
}
