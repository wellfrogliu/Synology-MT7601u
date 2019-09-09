#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#ifndef _LINUX_SCHED_H
#define _LINUX_SCHED_H

#include <uapi/linux/sched.h>

#include <linux/sched/prio.h>

struct sched_param {
	int sched_priority;
};

#include <asm/param.h>	 

#include <linux/capability.h>
#include <linux/threads.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/timex.h>
#include <linux/jiffies.h>
#include <linux/plist.h>
#include <linux/rbtree.h>
#include <linux/thread_info.h>
#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/nodemask.h>
#include <linux/mm_types.h>
#include <linux/preempt.h>

#include <asm/page.h>
#include <asm/ptrace.h>
#include <linux/cputime.h>

#include <linux/smp.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <linux/signal.h>
#include <linux/compiler.h>
#include <linux/completion.h>
#include <linux/pid.h>
#include <linux/percpu.h>
#include <linux/topology.h>
#include <linux/proportions.h>
#include <linux/seccomp.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/rtmutex.h>

#include <linux/time.h>
#include <linux/param.h>
#include <linux/resource.h>
#include <linux/timer.h>
#include <linux/hrtimer.h>
#include <linux/task_io_accounting.h>
#include <linux/latencytop.h>
#include <linux/cred.h>
#include <linux/llist.h>
#include <linux/uidgid.h>
#include <linux/gfp.h>
#include <linux/magic.h>
#include <linux/cgroup-defs.h>

#include <asm/processor.h>

#define SCHED_ATTR_SIZE_VER0	48	 

struct sched_attr {
	u32 size;

	u32 sched_policy;
	u64 sched_flags;

	s32 sched_nice;

	u32 sched_priority;

	u64 sched_runtime;
	u64 sched_deadline;
	u64 sched_period;
};

struct futex_pi_state;
struct robust_list_head;
struct bio_list;
struct fs_struct;
struct perf_event_context;
struct blk_plug;
struct filename;
struct nameidata;

#define VMACACHE_BITS 2
#define VMACACHE_SIZE (1U << VMACACHE_BITS)
#define VMACACHE_MASK (VMACACHE_SIZE - 1)

extern unsigned long avenrun[];		 
extern void get_avenrun(unsigned long *loads, unsigned long offset, int shift);

#define FSHIFT		11		 
#define FIXED_1		(1<<FSHIFT)	 
#define LOAD_FREQ	(5*HZ+1)	 
#define EXP_1		1884		 
#define EXP_5		2014		 
#define EXP_15		2037		 

#define CALC_LOAD(load,exp,n) \
	load *= exp; \
	load += n*(FIXED_1-exp); \
	load >>= FSHIFT;

extern unsigned long total_forks;
extern int nr_threads;
DECLARE_PER_CPU(unsigned long, process_counts);
extern int nr_processes(void);
extern unsigned long nr_running(void);
extern bool single_task_running(void);
extern unsigned long nr_iowait(void);
extern unsigned long nr_iowait_cpu(int cpu);
extern void get_iowait_load(unsigned long *nr_waiters, unsigned long *load);

extern void calc_global_load(unsigned long ticks);

#if defined(CONFIG_SMP) && defined(CONFIG_NO_HZ_COMMON)
extern void update_cpu_load_nohz(void);
#else
static inline void update_cpu_load_nohz(void) { }
#endif

extern unsigned long get_parent_ip(unsigned long addr);

extern void dump_cpu_task(int cpu);

struct seq_file;
struct cfs_rq;
struct task_group;
#ifdef CONFIG_SCHED_DEBUG
extern void proc_sched_show_task(struct task_struct *p, struct seq_file *m);
extern void proc_sched_set_task(struct task_struct *p);
#endif

#define TASK_RUNNING		0
#define TASK_INTERRUPTIBLE	1
#define TASK_UNINTERRUPTIBLE	2
#define __TASK_STOPPED		4
#define __TASK_TRACED		8
 
#define EXIT_DEAD		16
#define EXIT_ZOMBIE		32
#define EXIT_TRACE		(EXIT_ZOMBIE | EXIT_DEAD)
 
#define TASK_DEAD		64
#define TASK_WAKEKILL		128
#define TASK_WAKING		256
#define TASK_PARKED		512
#define TASK_NOLOAD		1024
#define TASK_STATE_MAX		2048

#define TASK_STATE_TO_CHAR_STR "RSDTtXZxKWPN"

extern char ___assert_task_state[1 - 2*!!(
		sizeof(TASK_STATE_TO_CHAR_STR)-1 != ilog2(TASK_STATE_MAX)+1)];

#define TASK_KILLABLE		(TASK_WAKEKILL | TASK_UNINTERRUPTIBLE)
#define TASK_STOPPED		(TASK_WAKEKILL | __TASK_STOPPED)
#define TASK_TRACED		(TASK_WAKEKILL | __TASK_TRACED)

#define TASK_IDLE		(TASK_UNINTERRUPTIBLE | TASK_NOLOAD)

#define TASK_NORMAL		(TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE)
#define TASK_ALL		(TASK_NORMAL | __TASK_STOPPED | __TASK_TRACED)

#define TASK_REPORT		(TASK_RUNNING | TASK_INTERRUPTIBLE | \
				 TASK_UNINTERRUPTIBLE | __TASK_STOPPED | \
				 __TASK_TRACED | EXIT_ZOMBIE | EXIT_DEAD)

#define task_is_traced(task)	((task->state & __TASK_TRACED) != 0)
#define task_is_stopped(task)	((task->state & __TASK_STOPPED) != 0)
#define task_is_stopped_or_traced(task)	\
			((task->state & (__TASK_STOPPED | __TASK_TRACED)) != 0)
#define task_contributes_to_load(task)	\
				((task->state & TASK_UNINTERRUPTIBLE) != 0 && \
				 (task->flags & PF_FROZEN) == 0 && \
				 (task->state & TASK_NOLOAD) == 0)

#ifdef CONFIG_DEBUG_ATOMIC_SLEEP

#define __set_task_state(tsk, state_value)			\
	do {							\
		(tsk)->task_state_change = _THIS_IP_;		\
		(tsk)->state = (state_value);			\
	} while (0)
#define set_task_state(tsk, state_value)			\
	do {							\
		(tsk)->task_state_change = _THIS_IP_;		\
		smp_store_mb((tsk)->state, (state_value));		\
	} while (0)

#define __set_current_state(state_value)			\
	do {							\
		current->task_state_change = _THIS_IP_;		\
		current->state = (state_value);			\
	} while (0)
#define set_current_state(state_value)				\
	do {							\
		current->task_state_change = _THIS_IP_;		\
		smp_store_mb(current->state, (state_value));		\
	} while (0)

#else

#define __set_task_state(tsk, state_value)		\
	do { (tsk)->state = (state_value); } while (0)
#define set_task_state(tsk, state_value)		\
	smp_store_mb((tsk)->state, (state_value))

#define __set_current_state(state_value)		\
	do { current->state = (state_value); } while (0)
#define set_current_state(state_value)			\
	smp_store_mb(current->state, (state_value))

#endif

#define TASK_COMM_LEN 16

#include <linux/spinlock.h>

extern rwlock_t tasklist_lock;
extern spinlock_t mmlist_lock;

struct task_struct;

#ifdef CONFIG_PROVE_RCU
extern int lockdep_tasklist_lock_is_held(void);
#endif  

extern void sched_init(void);
extern void sched_init_smp(void);
extern asmlinkage void schedule_tail(struct task_struct *prev);
extern void init_idle(struct task_struct *idle, int cpu);
extern void init_idle_bootup_task(struct task_struct *idle);

extern cpumask_var_t cpu_isolated_map;

extern int runqueue_is_locked(int cpu);

#if defined(CONFIG_SMP) && defined(CONFIG_NO_HZ_COMMON)
extern void nohz_balance_enter_idle(int cpu);
extern void set_cpu_sd_state_idle(void);
extern int get_nohz_timer_target(void);
#else
static inline void nohz_balance_enter_idle(int cpu) { }
static inline void set_cpu_sd_state_idle(void) { }
#endif

extern void show_state_filter(unsigned long state_filter);

static inline void show_state(void)
{
	show_state_filter(0);
}

extern void show_regs(struct pt_regs *);

extern void show_stack(struct task_struct *task, unsigned long *sp);

extern void cpu_init (void);
extern void trap_init(void);
extern void update_process_times(int user);
extern void scheduler_tick(void);

extern void sched_show_task(struct task_struct *p);

#ifdef CONFIG_LOCKUP_DETECTOR
extern void touch_softlockup_watchdog(void);
extern void touch_softlockup_watchdog_sync(void);
extern void touch_all_softlockup_watchdogs(void);
extern int proc_dowatchdog_thresh(struct ctl_table *table, int write,
				  void __user *buffer,
				  size_t *lenp, loff_t *ppos);
extern unsigned int  softlockup_panic;
extern unsigned int  hardlockup_panic;
void lockup_detector_init(void);
#else
static inline void touch_softlockup_watchdog(void)
{
}
static inline void touch_softlockup_watchdog_sync(void)
{
}
static inline void touch_all_softlockup_watchdogs(void)
{
}
static inline void lockup_detector_init(void)
{
}
#endif

#ifdef CONFIG_DETECT_HUNG_TASK
void reset_hung_task_detector(void);
#else
static inline void reset_hung_task_detector(void)
{
}
#endif

#define __sched		__attribute__((__section__(".sched.text")))

extern char __sched_text_start[], __sched_text_end[];

extern int in_sched_functions(unsigned long addr);

#define	MAX_SCHEDULE_TIMEOUT	LONG_MAX
extern signed long schedule_timeout(signed long timeout);
extern signed long schedule_timeout_interruptible(signed long timeout);
extern signed long schedule_timeout_killable(signed long timeout);
extern signed long schedule_timeout_uninterruptible(signed long timeout);
asmlinkage void schedule(void);
extern void schedule_preempt_disabled(void);

extern long io_schedule_timeout(long timeout);

static inline void io_schedule(void)
{
	io_schedule_timeout(MAX_SCHEDULE_TIMEOUT);
}

struct nsproxy;
struct user_namespace;

#ifdef CONFIG_MMU
extern void arch_pick_mmap_layout(struct mm_struct *mm);
extern unsigned long
arch_get_unmapped_area(struct file *, unsigned long, unsigned long,
		       unsigned long, unsigned long);
extern unsigned long
arch_get_unmapped_area_topdown(struct file *filp, unsigned long addr,
			  unsigned long len, unsigned long pgoff,
			  unsigned long flags);
#else
static inline void arch_pick_mmap_layout(struct mm_struct *mm) {}
#endif

#define SUID_DUMP_DISABLE	0	 
#define SUID_DUMP_USER		1	 
#define SUID_DUMP_ROOT		2	 

#define MMF_DUMPABLE_BITS 2
#define MMF_DUMPABLE_MASK ((1 << MMF_DUMPABLE_BITS) - 1)

extern void set_dumpable(struct mm_struct *mm, int value);
 
static inline int __get_dumpable(unsigned long mm_flags)
{
	return mm_flags & MMF_DUMPABLE_MASK;
}

static inline int get_dumpable(struct mm_struct *mm)
{
	return __get_dumpable(mm->flags);
}

#define MMF_DUMP_ANON_PRIVATE	2
#define MMF_DUMP_ANON_SHARED	3
#define MMF_DUMP_MAPPED_PRIVATE	4
#define MMF_DUMP_MAPPED_SHARED	5
#define MMF_DUMP_ELF_HEADERS	6
#define MMF_DUMP_HUGETLB_PRIVATE 7
#define MMF_DUMP_HUGETLB_SHARED  8
#define MMF_DUMP_DAX_PRIVATE	9
#define MMF_DUMP_DAX_SHARED	10

#define MMF_DUMP_FILTER_SHIFT	MMF_DUMPABLE_BITS
#define MMF_DUMP_FILTER_BITS	9
#define MMF_DUMP_FILTER_MASK \
	(((1 << MMF_DUMP_FILTER_BITS) - 1) << MMF_DUMP_FILTER_SHIFT)
#define MMF_DUMP_FILTER_DEFAULT \
	((1 << MMF_DUMP_ANON_PRIVATE) |	(1 << MMF_DUMP_ANON_SHARED) |\
	 (1 << MMF_DUMP_HUGETLB_PRIVATE) | MMF_DUMP_MASK_DEFAULT_ELF)

#ifdef CONFIG_CORE_DUMP_DEFAULT_ELF_HEADERS
# define MMF_DUMP_MASK_DEFAULT_ELF	(1 << MMF_DUMP_ELF_HEADERS)
#else
# define MMF_DUMP_MASK_DEFAULT_ELF	0
#endif
					 
#define MMF_VM_MERGEABLE	16	 
#define MMF_VM_HUGEPAGE		17	 
#define MMF_EXE_FILE_CHANGED	18	 

#define MMF_HAS_UPROBES		19	 
#define MMF_RECALC_UPROBES	20	 

#define MMF_INIT_MASK		(MMF_DUMPABLE_MASK | MMF_DUMP_FILTER_MASK)

struct sighand_struct {
	atomic_t		count;
	struct k_sigaction	action[_NSIG];
	spinlock_t		siglock;
	wait_queue_head_t	signalfd_wqh;
};

struct pacct_struct {
	int			ac_flag;
	long			ac_exitcode;
	unsigned long		ac_mem;
	cputime_t		ac_utime, ac_stime;
	unsigned long		ac_minflt, ac_majflt;
};

struct cpu_itimer {
	cputime_t expires;
	cputime_t incr;
	u32 error;
	u32 incr_error;
};

struct prev_cputime {
#ifndef CONFIG_VIRT_CPU_ACCOUNTING_NATIVE
	cputime_t utime;
	cputime_t stime;
	raw_spinlock_t lock;
#endif
};

static inline void prev_cputime_init(struct prev_cputime *prev)
{
#ifndef CONFIG_VIRT_CPU_ACCOUNTING_NATIVE
	prev->utime = prev->stime = 0;
	raw_spin_lock_init(&prev->lock);
#endif
}

struct task_cputime {
	cputime_t utime;
	cputime_t stime;
	unsigned long long sum_exec_runtime;
};

#define virt_exp	utime
#define prof_exp	stime
#define sched_exp	sum_exec_runtime

#define INIT_CPUTIME	\
	(struct task_cputime) {					\
		.utime = 0,					\
		.stime = 0,					\
		.sum_exec_runtime = 0,				\
	}

struct task_cputime_atomic {
	atomic64_t utime;
	atomic64_t stime;
	atomic64_t sum_exec_runtime;
};

#define INIT_CPUTIME_ATOMIC \
	(struct task_cputime_atomic) {				\
		.utime = ATOMIC64_INIT(0),			\
		.stime = ATOMIC64_INIT(0),			\
		.sum_exec_runtime = ATOMIC64_INIT(0),		\
	}

#define PREEMPT_DISABLED	(PREEMPT_DISABLE_OFFSET + PREEMPT_ENABLED)

#define INIT_PREEMPT_COUNT	PREEMPT_OFFSET

#define FORK_PREEMPT_COUNT	(2*PREEMPT_DISABLE_OFFSET + PREEMPT_ENABLED)

struct thread_group_cputimer {
	struct task_cputime_atomic cputime_atomic;
	bool running;
	bool checking_timer;
};

#include <linux/rwsem.h>
struct autogroup;

struct signal_struct {
	atomic_t		sigcnt;
	atomic_t		live;
	int			nr_threads;
	struct list_head	thread_head;

	wait_queue_head_t	wait_chldexit;	 

	struct task_struct	*curr_target;

	struct sigpending	shared_pending;

	int			group_exit_code;
	 
	int			notify_count;
	struct task_struct	*group_exit_task;

	int			group_stop_count;
	unsigned int		flags;  

	unsigned int		is_child_subreaper:1;
	unsigned int		has_child_subreaper:1;

	int			posix_timer_id;
	struct list_head	posix_timers;

	struct hrtimer real_timer;
	struct pid *leader_pid;
	ktime_t it_real_incr;

	struct cpu_itimer it[2];

	struct thread_group_cputimer cputimer;

	struct task_cputime cputime_expires;

	struct list_head cpu_timers[3];

	struct pid *tty_old_pgrp;

	int leader;

	struct tty_struct *tty;  

#ifdef CONFIG_SCHED_AUTOGROUP
	struct autogroup *autogroup;
#endif
	 
	seqlock_t stats_lock;
	cputime_t utime, stime, cutime, cstime;
	cputime_t gtime;
	cputime_t cgtime;
	struct prev_cputime prev_cputime;
	unsigned long nvcsw, nivcsw, cnvcsw, cnivcsw;
	unsigned long min_flt, maj_flt, cmin_flt, cmaj_flt;
	unsigned long inblock, oublock, cinblock, coublock;
	unsigned long maxrss, cmaxrss;
	struct task_io_accounting ioac;

	unsigned long long sum_sched_runtime;

	struct rlimit rlim[RLIM_NLIMITS];

#ifdef CONFIG_BSD_PROCESS_ACCT
	struct pacct_struct pacct;	 
#endif
#ifdef CONFIG_TASKSTATS
	struct taskstats *stats;
#endif
#ifdef CONFIG_AUDIT
	unsigned audit_tty;
	unsigned audit_tty_log_passwd;
	struct tty_audit_buf *tty_audit_buf;
#endif

	oom_flags_t oom_flags;
	short oom_score_adj;		 
	short oom_score_adj_min;	 

	struct mutex cred_guard_mutex;	 
};

#define SIGNAL_STOP_STOPPED	0x00000001  
#define SIGNAL_STOP_CONTINUED	0x00000002  
#define SIGNAL_GROUP_EXIT	0x00000004  
#define SIGNAL_GROUP_COREDUMP	0x00000008  
 
#define SIGNAL_CLD_STOPPED	0x00000010
#define SIGNAL_CLD_CONTINUED	0x00000020
#define SIGNAL_CLD_MASK		(SIGNAL_CLD_STOPPED|SIGNAL_CLD_CONTINUED)

#define SIGNAL_UNKILLABLE	0x00000040  

static inline int signal_group_exit(const struct signal_struct *sig)
{
	return	(sig->flags & SIGNAL_GROUP_EXIT) ||
		(sig->group_exit_task != NULL);
}

struct user_struct {
	atomic_t __count;	 
	atomic_t processes;	 
	atomic_t sigpending;	 
#ifdef CONFIG_INOTIFY_USER
	atomic_t inotify_watches;  
	atomic_t inotify_devs;	 
#endif
#ifdef MY_ABC_HERE
	atomic_t synotify_instances;
#endif  
#ifdef CONFIG_FANOTIFY
	atomic_t fanotify_listeners;
#endif
#ifdef CONFIG_EPOLL
	atomic_long_t epoll_watches;  
#endif
#ifdef CONFIG_POSIX_MQUEUE
	 
	unsigned long mq_bytes;	 
#endif
	unsigned long locked_shm;  
	unsigned long unix_inflight;	 
	atomic_long_t pipe_bufs;   

#ifdef CONFIG_KEYS
	struct key *uid_keyring;	 
	struct key *session_keyring;	 
#endif

	struct hlist_node uidhash_node;
	kuid_t uid;

#if defined(CONFIG_PERF_EVENTS) || defined(CONFIG_BPF_SYSCALL)
	atomic_long_t locked_vm;
#endif
};

extern int uids_sysfs_init(void);

extern struct user_struct *find_user(kuid_t);

extern struct user_struct root_user;
#define INIT_USER (&root_user)

struct backing_dev_info;
struct reclaim_state;

#ifdef CONFIG_SCHED_INFO
struct sched_info {
	 
	unsigned long pcount;	       
	unsigned long long run_delay;  

	unsigned long long last_arrival, 
			   last_queued;	 
};
#endif  

#ifdef CONFIG_TASK_DELAY_ACCT
struct task_delay_info {
	spinlock_t	lock;
	unsigned int	flags;	 

	u64 blkio_start;	 
	u64 blkio_delay;	 
	u64 swapin_delay;	 
	u32 blkio_count;	 
				 
	u32 swapin_count;	 
				 
	u64 freepages_start;
	u64 freepages_delay;	 
	u32 freepages_count;	 
};
#endif	 

static inline int sched_info_on(void)
{
#ifdef CONFIG_SCHEDSTATS
	return 1;
#elif defined(CONFIG_TASK_DELAY_ACCT)
	extern int delayacct_on;
	return delayacct_on;
#else
	return 0;
#endif
}

enum cpu_idle_type {
	CPU_IDLE,
	CPU_NOT_IDLE,
	CPU_NEWLY_IDLE,
	CPU_MAX_IDLE_TYPES
};

#define SCHED_CAPACITY_SHIFT	10
#define SCHED_CAPACITY_SCALE	(1L << SCHED_CAPACITY_SHIFT)

struct wake_q_node {
	struct wake_q_node *next;
};

struct wake_q_head {
	struct wake_q_node *first;
	struct wake_q_node **lastp;
};

#define WAKE_Q_TAIL ((struct wake_q_node *) 0x01)

#define WAKE_Q(name)					\
	struct wake_q_head name = { WAKE_Q_TAIL, &name.first }

extern void wake_q_add(struct wake_q_head *head,
		       struct task_struct *task);
extern void wake_up_q(struct wake_q_head *head);

#ifdef CONFIG_SMP
#define SD_LOAD_BALANCE		0x0001	 
#define SD_BALANCE_NEWIDLE	0x0002	 
#define SD_BALANCE_EXEC		0x0004	 
#define SD_BALANCE_FORK		0x0008	 
#define SD_BALANCE_WAKE		0x0010   
#define SD_WAKE_AFFINE		0x0020	 
#define SD_SHARE_CPUCAPACITY	0x0080	 
#define SD_SHARE_POWERDOMAIN	0x0100	 
#define SD_SHARE_PKG_RESOURCES	0x0200	 
#define SD_SERIALIZE		0x0400	 
#define SD_ASYM_PACKING		0x0800   
#define SD_PREFER_SIBLING	0x1000	 
#define SD_OVERLAP		0x2000	 
#define SD_NUMA			0x4000	 

#ifdef CONFIG_SCHED_SMT
static inline int cpu_smt_flags(void)
{
	return SD_SHARE_CPUCAPACITY | SD_SHARE_PKG_RESOURCES;
}
#endif

#ifdef CONFIG_SCHED_MC
static inline int cpu_core_flags(void)
{
	return SD_SHARE_PKG_RESOURCES;
}
#endif

#ifdef CONFIG_NUMA
static inline int cpu_numa_flags(void)
{
	return SD_NUMA;
}
#endif

struct sched_domain_attr {
	int relax_domain_level;
};

#define SD_ATTR_INIT	(struct sched_domain_attr) {	\
	.relax_domain_level = -1,			\
}

extern int sched_domain_level_max;

struct sched_group;

struct sched_domain {
	 
	struct sched_domain *parent;	 
	struct sched_domain *child;	 
	struct sched_group *groups;	 
	unsigned long min_interval;	 
	unsigned long max_interval;	 
	unsigned int busy_factor;	 
	unsigned int imbalance_pct;	 
	unsigned int cache_nice_tries;	 
	unsigned int busy_idx;
	unsigned int idle_idx;
	unsigned int newidle_idx;
	unsigned int wake_idx;
	unsigned int forkexec_idx;
	unsigned int smt_gain;

	int nohz_idle;			 
	int flags;			 
	int level;

	unsigned long last_balance;	 
	unsigned int balance_interval;	 
	unsigned int nr_balance_failed;  

	u64 max_newidle_lb_cost;
	unsigned long next_decay_max_lb_cost;

#ifdef CONFIG_SCHEDSTATS
	 
	unsigned int lb_count[CPU_MAX_IDLE_TYPES];
	unsigned int lb_failed[CPU_MAX_IDLE_TYPES];
	unsigned int lb_balanced[CPU_MAX_IDLE_TYPES];
	unsigned int lb_imbalance[CPU_MAX_IDLE_TYPES];
	unsigned int lb_gained[CPU_MAX_IDLE_TYPES];
	unsigned int lb_hot_gained[CPU_MAX_IDLE_TYPES];
	unsigned int lb_nobusyg[CPU_MAX_IDLE_TYPES];
	unsigned int lb_nobusyq[CPU_MAX_IDLE_TYPES];

	unsigned int alb_count;
	unsigned int alb_failed;
	unsigned int alb_pushed;

	unsigned int sbe_count;
	unsigned int sbe_balanced;
	unsigned int sbe_pushed;

	unsigned int sbf_count;
	unsigned int sbf_balanced;
	unsigned int sbf_pushed;

	unsigned int ttwu_wake_remote;
	unsigned int ttwu_move_affine;
	unsigned int ttwu_move_balance;
#endif
#ifdef CONFIG_SCHED_DEBUG
	char *name;
#endif
	union {
		void *private;		 
		struct rcu_head rcu;	 
	};

	unsigned int span_weight;
	 
	unsigned long span[0];
};

static inline struct cpumask *sched_domain_span(struct sched_domain *sd)
{
	return to_cpumask(sd->span);
}

extern void partition_sched_domains(int ndoms_new, cpumask_var_t doms_new[],
				    struct sched_domain_attr *dattr_new);

cpumask_var_t *alloc_sched_domains(unsigned int ndoms);
void free_sched_domains(cpumask_var_t doms[], unsigned int ndoms);

bool cpus_share_cache(int this_cpu, int that_cpu);

typedef const struct cpumask *(*sched_domain_mask_f)(int cpu);
typedef int (*sched_domain_flags_f)(void);

#define SDTL_OVERLAP	0x01

struct sd_data {
	struct sched_domain **__percpu sd;
	struct sched_group **__percpu sg;
	struct sched_group_capacity **__percpu sgc;
};

struct sched_domain_topology_level {
	sched_domain_mask_f mask;
	sched_domain_flags_f sd_flags;
	int		    flags;
	int		    numa_level;
	struct sd_data      data;
#ifdef CONFIG_SCHED_DEBUG
	char                *name;
#endif
};

extern void set_sched_topology(struct sched_domain_topology_level *tl);
extern void wake_up_if_idle(int cpu);

#ifdef CONFIG_SCHED_DEBUG
# define SD_INIT_NAME(type)		.name = #type
#else
# define SD_INIT_NAME(type)
#endif

#else  

struct sched_domain_attr;

static inline void
partition_sched_domains(int ndoms_new, cpumask_var_t doms_new[],
			struct sched_domain_attr *dattr_new)
{
}

static inline bool cpus_share_cache(int this_cpu, int that_cpu)
{
	return true;
}

#endif	 

struct io_context;			 

#ifdef ARCH_HAS_PREFETCH_SWITCH_STACK
extern void prefetch_stack(struct task_struct *t);
#else
static inline void prefetch_stack(struct task_struct *t) { }
#endif

struct audit_context;		 
struct mempolicy;
struct pipe_inode_info;
struct uts_namespace;

struct load_weight {
	unsigned long weight;
	u32 inv_weight;
};

struct sched_avg {
	u64 last_update_time, load_sum;
	u32 util_sum, period_contrib;
	unsigned long load_avg, util_avg;
};

#ifdef CONFIG_SCHEDSTATS
struct sched_statistics {
	u64			wait_start;
	u64			wait_max;
	u64			wait_count;
	u64			wait_sum;
	u64			iowait_count;
	u64			iowait_sum;

	u64			sleep_start;
	u64			sleep_max;
	s64			sum_sleep_runtime;

	u64			block_start;
	u64			block_max;
	u64			exec_max;
	u64			slice_max;

	u64			nr_migrations_cold;
	u64			nr_failed_migrations_affine;
	u64			nr_failed_migrations_running;
	u64			nr_failed_migrations_hot;
	u64			nr_forced_migrations;

	u64			nr_wakeups;
	u64			nr_wakeups_sync;
	u64			nr_wakeups_migrate;
	u64			nr_wakeups_local;
	u64			nr_wakeups_remote;
	u64			nr_wakeups_affine;
	u64			nr_wakeups_affine_attempts;
	u64			nr_wakeups_passive;
	u64			nr_wakeups_idle;
};
#endif

struct sched_entity {
	struct load_weight	load;		 
	struct rb_node		run_node;
	struct list_head	group_node;
	unsigned int		on_rq;

	u64			exec_start;
	u64			sum_exec_runtime;
	u64			vruntime;
	u64			prev_sum_exec_runtime;

	u64			nr_migrations;

#ifdef CONFIG_SCHEDSTATS
	struct sched_statistics statistics;
#endif

#ifdef CONFIG_FAIR_GROUP_SCHED
	int			depth;
	struct sched_entity	*parent;
	 
	struct cfs_rq		*cfs_rq;
	 
	struct cfs_rq		*my_q;
#endif

#ifdef CONFIG_SMP
	 
	struct sched_avg	avg;
#endif
};

struct sched_rt_entity {
	struct list_head run_list;
	unsigned long timeout;
	unsigned long watchdog_stamp;
	unsigned int time_slice;

	struct sched_rt_entity *back;
#ifdef CONFIG_RT_GROUP_SCHED
	struct sched_rt_entity	*parent;
	 
	struct rt_rq		*rt_rq;
	 
	struct rt_rq		*my_q;
#endif
};

struct sched_dl_entity {
	struct rb_node	rb_node;

	u64 dl_runtime;		 
	u64 dl_deadline;	 
	u64 dl_period;		 
	u64 dl_bw;		 

	s64 runtime;		 
	u64 deadline;		 
	unsigned int flags;	 

	int dl_throttled, dl_new, dl_boosted, dl_yielded;

	struct hrtimer dl_timer;
};

union rcu_special {
	struct {
		u8 blocked;
		u8 need_qs;
		u8 exp_need_qs;
		u8 pad;	 
	} b;  
	u32 s;  
};
struct rcu_node;

enum perf_event_task_context {
	perf_invalid_context = -1,
	perf_hw_context = 0,
	perf_sw_context,
	perf_nr_task_contexts,
};

struct tlbflush_unmap_batch {
	 
	struct cpumask cpumask;

	bool flush_required;

	bool writable;
};

struct task_struct {
	volatile long state;	 
	void *stack;
	atomic_t usage;
	unsigned int flags;	 
	unsigned int ptrace;

#ifdef CONFIG_SMP
	struct llist_node wake_entry;
	int on_cpu;
	unsigned int wakee_flips;
	unsigned long wakee_flip_decay_ts;
	struct task_struct *last_wakee;

	int wake_cpu;
#endif
	int on_rq;

	int prio, static_prio, normal_prio;
	unsigned int rt_priority;
	const struct sched_class *sched_class;
	struct sched_entity se;
	struct sched_rt_entity rt;
#ifdef CONFIG_CGROUP_SCHED
	struct task_group *sched_task_group;
#endif
	struct sched_dl_entity dl;

#ifdef CONFIG_PREEMPT_NOTIFIERS
	 
	struct hlist_head preempt_notifiers;
#endif

#ifdef CONFIG_BLK_DEV_IO_TRACE
	unsigned int btrace_seq;
#endif

	unsigned int policy;
	int nr_cpus_allowed;
	cpumask_t cpus_allowed;

#ifdef CONFIG_PREEMPT_RCU
	int rcu_read_lock_nesting;
	union rcu_special rcu_read_unlock_special;
	struct list_head rcu_node_entry;
	struct rcu_node *rcu_blocked_node;
#endif  
#ifdef CONFIG_TASKS_RCU
	unsigned long rcu_tasks_nvcsw;
	bool rcu_tasks_holdout;
	struct list_head rcu_tasks_holdout_list;
	int rcu_tasks_idle_cpu;
#endif  

#ifdef CONFIG_SCHED_INFO
	struct sched_info sched_info;
#endif

	struct list_head tasks;
#ifdef CONFIG_SMP
	struct plist_node pushable_tasks;
	struct rb_node pushable_dl_tasks;
#endif

	struct mm_struct *mm, *active_mm;
	 
	u32 vmacache_seqnum;
	struct vm_area_struct *vmacache[VMACACHE_SIZE];
#if defined(SPLIT_RSS_COUNTING)
	struct task_rss_stat	rss_stat;
#endif
 
	int exit_state;
	int exit_code, exit_signal;
	int pdeath_signal;   
	unsigned long jobctl;	 

	unsigned int personality;

	unsigned sched_reset_on_fork:1;
	unsigned sched_contributes_to_load:1;
	unsigned sched_migrated:1;
	unsigned :0;  

	unsigned in_execve:1;  
	unsigned in_iowait:1;
#ifdef CONFIG_MEMCG
	unsigned memcg_may_oom:1;
#endif
#ifdef CONFIG_MEMCG_KMEM
	unsigned memcg_kmem_skip_account:1;
#endif
#ifdef CONFIG_COMPAT_BRK
	unsigned brk_randomized:1;
#endif

	unsigned long atomic_flags;  

	struct restart_block restart_block;

	pid_t pid;
	pid_t tgid;

#ifdef CONFIG_CC_STACKPROTECTOR
	 
	unsigned long stack_canary;
#endif
	 
	struct task_struct __rcu *real_parent;  
	struct task_struct __rcu *parent;  
	 
	struct list_head children;	 
	struct list_head sibling;	 
	struct task_struct *group_leader;	 

	struct list_head ptraced;
	struct list_head ptrace_entry;

	struct pid_link pids[PIDTYPE_MAX];
	struct list_head thread_group;
	struct list_head thread_node;

	struct completion *vfork_done;		 
	int __user *set_child_tid;		 
	int __user *clear_child_tid;		 

	cputime_t utime, stime, utimescaled, stimescaled;
	cputime_t gtime;
	struct prev_cputime prev_cputime;
#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN
	seqlock_t vtime_seqlock;
	unsigned long long vtime_snap;
	enum {
		VTIME_SLEEPING = 0,
		VTIME_USER,
		VTIME_SYS,
	} vtime_snap_whence;
#endif
	unsigned long nvcsw, nivcsw;  
	u64 start_time;		 
	u64 real_start_time;	 
 
	unsigned long min_flt, maj_flt;

	struct task_cputime cputime_expires;
	struct list_head cpu_timers[3];

	const struct cred __rcu *ptracer_cred;  
	const struct cred __rcu *real_cred;  
	const struct cred __rcu *cred;	 
	char comm[TASK_COMM_LEN];  
 
	struct nameidata *nameidata;
#ifdef CONFIG_SYSVIPC
 
	struct sysv_sem sysvsem;
	struct sysv_shm sysvshm;
#endif
#ifdef CONFIG_DETECT_HUNG_TASK
 
	unsigned long last_switch_count;
#endif
 
	struct fs_struct *fs;
 
	struct files_struct *files;
 
	struct nsproxy *nsproxy;
 
	struct signal_struct *signal;
	struct sighand_struct *sighand;

	sigset_t blocked, real_blocked;
	sigset_t saved_sigmask;	 
	struct sigpending pending;

	unsigned long sas_ss_sp;
	size_t sas_ss_size;

	struct callback_head *task_works;

	struct audit_context *audit_context;
#ifdef CONFIG_AUDITSYSCALL
	kuid_t loginuid;
	unsigned int sessionid;
#endif
	struct seccomp seccomp;

   	u32 parent_exec_id;
   	u32 self_exec_id;
 
	spinlock_t alloc_lock;

	raw_spinlock_t pi_lock;

	struct wake_q_node wake_q;

#ifdef CONFIG_RT_MUTEXES
	 
	struct rb_root pi_waiters;
	struct rb_node *pi_waiters_leftmost;
	 
	struct rt_mutex_waiter *pi_blocked_on;
#endif

#ifdef CONFIG_DEBUG_MUTEXES
	 
	struct mutex_waiter *blocked_on;
#endif
#ifdef CONFIG_TRACE_IRQFLAGS
	unsigned int irq_events;
	unsigned long hardirq_enable_ip;
	unsigned long hardirq_disable_ip;
	unsigned int hardirq_enable_event;
	unsigned int hardirq_disable_event;
	int hardirqs_enabled;
	int hardirq_context;
	unsigned long softirq_disable_ip;
	unsigned long softirq_enable_ip;
	unsigned int softirq_disable_event;
	unsigned int softirq_enable_event;
	int softirqs_enabled;
	int softirq_context;
#endif
#ifdef CONFIG_LOCKDEP
# define MAX_LOCK_DEPTH 48UL
	u64 curr_chain_key;
	int lockdep_depth;
	unsigned int lockdep_recursion;
	struct held_lock held_locks[MAX_LOCK_DEPTH];
	gfp_t lockdep_reclaim_gfp;
#endif

	void *journal_info;

	struct bio_list *bio_list;

#ifdef CONFIG_BLOCK
 
	struct blk_plug *plug;
#endif

	struct reclaim_state *reclaim_state;

	struct backing_dev_info *backing_dev_info;

	struct io_context *io_context;

	unsigned long ptrace_message;
	siginfo_t *last_siginfo;  
	struct task_io_accounting ioac;
#if defined(CONFIG_TASK_XACCT)
	u64 acct_rss_mem1;	 
	u64 acct_vm_mem1;	 
	cputime_t acct_timexpd;	 
#endif
#ifdef CONFIG_CPUSETS
	nodemask_t mems_allowed;	 
	seqcount_t mems_allowed_seq;	 
	int cpuset_mem_spread_rotor;
	int cpuset_slab_spread_rotor;
#endif
#ifdef CONFIG_CGROUPS
	 
	struct css_set __rcu *cgroups;
	 
	struct list_head cg_list;
#endif
#ifdef CONFIG_FUTEX
	struct robust_list_head __user *robust_list;
#ifdef CONFIG_COMPAT
	struct compat_robust_list_head __user *compat_robust_list;
#endif
	struct list_head pi_state_list;
	struct futex_pi_state *pi_state_cache;
#endif
#ifdef CONFIG_PERF_EVENTS
	struct perf_event_context *perf_event_ctxp[perf_nr_task_contexts];
	struct mutex perf_event_mutex;
	struct list_head perf_event_list;
#endif
#ifdef CONFIG_DEBUG_PREEMPT
	unsigned long preempt_disable_ip;
#endif
#ifdef CONFIG_NUMA
	struct mempolicy *mempolicy;	 
	short il_next;
	short pref_node_fork;
#endif
#ifdef CONFIG_NUMA_BALANCING
	int numa_scan_seq;
	unsigned int numa_scan_period;
	unsigned int numa_scan_period_max;
	int numa_preferred_nid;
	unsigned long numa_migrate_retry;
	u64 node_stamp;			 
	u64 last_task_numa_placement;
	u64 last_sum_exec_runtime;
	struct callback_head numa_work;

	struct list_head numa_entry;
	struct numa_group *numa_group;

	unsigned long *numa_faults;
	unsigned long total_numa_faults;

	unsigned long numa_faults_locality[3];

	unsigned long numa_pages_migrated;
#endif  

#ifdef CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH
	struct tlbflush_unmap_batch tlb_ubc;
#endif

	struct rcu_head rcu;

	struct pipe_inode_info *splice_pipe;

	struct page_frag task_frag;

#ifdef	CONFIG_TASK_DELAY_ACCT
	struct task_delay_info *delays;
#endif
#ifdef CONFIG_FAULT_INJECTION
	int make_it_fail;
#endif
	 
	int nr_dirtied;
	int nr_dirtied_pause;
	unsigned long dirty_paused_when;  

#ifdef CONFIG_LATENCYTOP
	int latency_record_count;
	struct latency_record latency_record[LT_SAVECOUNT];
#endif
	 
	unsigned long timer_slack_ns;
	unsigned long default_timer_slack_ns;

#ifdef CONFIG_KASAN
	unsigned int kasan_depth;
#endif
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	 
	int curr_ret_stack;
	 
	struct ftrace_ret_stack	*ret_stack;
	 
	unsigned long long ftrace_timestamp;
	 
	atomic_t trace_overrun;
	 
	atomic_t tracing_graph_pause;
#endif
#ifdef CONFIG_TRACING
	 
	unsigned long trace;
	 
	unsigned long trace_recursion;
#endif  
#ifdef CONFIG_MEMCG
	struct mem_cgroup *memcg_in_oom;
	gfp_t memcg_oom_gfp_mask;
	int memcg_oom_order;

	unsigned int memcg_nr_pages_over_high;
#endif
#ifdef CONFIG_UPROBES
	struct uprobe_task *utask;
#endif
#if defined(CONFIG_BCACHE) || defined(CONFIG_BCACHE_MODULE)
	unsigned int	sequential_io;
	unsigned int	sequential_io_avg;
#endif
#ifdef CONFIG_DEBUG_ATOMIC_SLEEP
	unsigned long	task_state_change;
#endif
	int pagefault_disabled;
 
	struct thread_struct thread;
 
};

#ifdef CONFIG_ARCH_WANTS_DYNAMIC_TASK_STRUCT
extern int arch_task_struct_size __read_mostly;
#else
# define arch_task_struct_size (sizeof(struct task_struct))
#endif

#define tsk_cpus_allowed(tsk) (&(tsk)->cpus_allowed)

#define TNF_MIGRATED	0x01
#define TNF_NO_GROUP	0x02
#define TNF_SHARED	0x04
#define TNF_FAULT_LOCAL	0x08
#define TNF_MIGRATE_FAIL 0x10

#ifdef CONFIG_NUMA_BALANCING
extern void task_numa_fault(int last_node, int node, int pages, int flags);
extern pid_t task_numa_group_id(struct task_struct *p);
extern void set_numabalancing_state(bool enabled);
extern void task_numa_free(struct task_struct *p);
extern bool should_numa_migrate_memory(struct task_struct *p, struct page *page,
					int src_nid, int dst_cpu);
#else
static inline void task_numa_fault(int last_node, int node, int pages,
				   int flags)
{
}
static inline pid_t task_numa_group_id(struct task_struct *p)
{
	return 0;
}
static inline void set_numabalancing_state(bool enabled)
{
}
static inline void task_numa_free(struct task_struct *p)
{
}
static inline bool should_numa_migrate_memory(struct task_struct *p,
				struct page *page, int src_nid, int dst_cpu)
{
	return true;
}
#endif

static inline struct pid *task_pid(struct task_struct *task)
{
	return task->pids[PIDTYPE_PID].pid;
}

static inline struct pid *task_tgid(struct task_struct *task)
{
	return task->group_leader->pids[PIDTYPE_PID].pid;
}

static inline struct pid *task_pgrp(struct task_struct *task)
{
	return task->group_leader->pids[PIDTYPE_PGID].pid;
}

static inline struct pid *task_session(struct task_struct *task)
{
	return task->group_leader->pids[PIDTYPE_SID].pid;
}

struct pid_namespace;

pid_t __task_pid_nr_ns(struct task_struct *task, enum pid_type type,
			struct pid_namespace *ns);

static inline pid_t task_pid_nr(struct task_struct *tsk)
{
	return tsk->pid;
}

static inline pid_t task_pid_nr_ns(struct task_struct *tsk,
					struct pid_namespace *ns)
{
	return __task_pid_nr_ns(tsk, PIDTYPE_PID, ns);
}

static inline pid_t task_pid_vnr(struct task_struct *tsk)
{
	return __task_pid_nr_ns(tsk, PIDTYPE_PID, NULL);
}

static inline pid_t task_tgid_nr(struct task_struct *tsk)
{
	return tsk->tgid;
}

pid_t task_tgid_nr_ns(struct task_struct *tsk, struct pid_namespace *ns);

static inline pid_t task_tgid_vnr(struct task_struct *tsk)
{
	return pid_vnr(task_tgid(tsk));
}

static inline int pid_alive(const struct task_struct *p);
static inline pid_t task_ppid_nr_ns(const struct task_struct *tsk, struct pid_namespace *ns)
{
	pid_t pid = 0;

	rcu_read_lock();
	if (pid_alive(tsk))
		pid = task_tgid_nr_ns(rcu_dereference(tsk->real_parent), ns);
	rcu_read_unlock();

	return pid;
}

static inline pid_t task_ppid_nr(const struct task_struct *tsk)
{
	return task_ppid_nr_ns(tsk, &init_pid_ns);
}

static inline pid_t task_pgrp_nr_ns(struct task_struct *tsk,
					struct pid_namespace *ns)
{
	return __task_pid_nr_ns(tsk, PIDTYPE_PGID, ns);
}

static inline pid_t task_pgrp_vnr(struct task_struct *tsk)
{
	return __task_pid_nr_ns(tsk, PIDTYPE_PGID, NULL);
}

static inline pid_t task_session_nr_ns(struct task_struct *tsk,
					struct pid_namespace *ns)
{
	return __task_pid_nr_ns(tsk, PIDTYPE_SID, ns);
}

static inline pid_t task_session_vnr(struct task_struct *tsk)
{
	return __task_pid_nr_ns(tsk, PIDTYPE_SID, NULL);
}

static inline pid_t task_pgrp_nr(struct task_struct *tsk)
{
	return task_pgrp_nr_ns(tsk, &init_pid_ns);
}

static inline int pid_alive(const struct task_struct *p)
{
	return p->pids[PIDTYPE_PID].pid != NULL;
}

static inline int is_global_init(struct task_struct *tsk)
{
	return task_tgid_nr(tsk) == 1;
}

extern struct pid *cad_pid;

extern void free_task(struct task_struct *tsk);
#define get_task_struct(tsk) do { atomic_inc(&(tsk)->usage); } while(0)

extern void __put_task_struct(struct task_struct *t);

static inline void put_task_struct(struct task_struct *t)
{
	if (atomic_dec_and_test(&t->usage))
		__put_task_struct(t);
}

#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN
extern void task_cputime(struct task_struct *t,
			 cputime_t *utime, cputime_t *stime);
extern void task_cputime_scaled(struct task_struct *t,
				cputime_t *utimescaled, cputime_t *stimescaled);
extern cputime_t task_gtime(struct task_struct *t);
#else
static inline void task_cputime(struct task_struct *t,
				cputime_t *utime, cputime_t *stime)
{
	if (utime)
		*utime = t->utime;
	if (stime)
		*stime = t->stime;
}

static inline void task_cputime_scaled(struct task_struct *t,
				       cputime_t *utimescaled,
				       cputime_t *stimescaled)
{
	if (utimescaled)
		*utimescaled = t->utimescaled;
	if (stimescaled)
		*stimescaled = t->stimescaled;
}

static inline cputime_t task_gtime(struct task_struct *t)
{
	return t->gtime;
}
#endif
extern void task_cputime_adjusted(struct task_struct *p, cputime_t *ut, cputime_t *st);
extern void thread_group_cputime_adjusted(struct task_struct *p, cputime_t *ut, cputime_t *st);

#define PF_EXITING	0x00000004	 
#define PF_EXITPIDONE	0x00000008	 
#define PF_VCPU		0x00000010	 
#define PF_WQ_WORKER	0x00000020	 
#define PF_FORKNOEXEC	0x00000040	 
#define PF_MCE_PROCESS  0x00000080       
#define PF_SUPERPRIV	0x00000100	 
#define PF_DUMPCORE	0x00000200	 
#define PF_SIGNALED	0x00000400	 
#define PF_MEMALLOC	0x00000800	 
#define PF_NPROC_EXCEEDED 0x00001000	 
#define PF_USED_MATH	0x00002000	 
#define PF_USED_ASYNC	0x00004000	 
#define PF_NOFREEZE	0x00008000	 
#define PF_FROZEN	0x00010000	 
#define PF_FSTRANS	0x00020000	 
#define PF_KSWAPD	0x00040000	 
#define PF_MEMALLOC_NOIO 0x00080000	 
#define PF_LESS_THROTTLE 0x00100000	 
#define PF_KTHREAD	0x00200000	 
#define PF_RANDOMIZE	0x00400000	 
#define PF_SWAPWRITE	0x00800000	 
#define PF_NO_SETAFFINITY 0x04000000	 
#define PF_MCE_EARLY    0x08000000       
#define PF_MUTEX_TESTER	0x20000000	 
#define PF_FREEZER_SKIP	0x40000000	 
#define PF_SUSPEND_TASK 0x80000000       

#define clear_stopped_child_used_math(child) do { (child)->flags &= ~PF_USED_MATH; } while (0)
#define set_stopped_child_used_math(child) do { (child)->flags |= PF_USED_MATH; } while (0)
#define clear_used_math() clear_stopped_child_used_math(current)
#define set_used_math() set_stopped_child_used_math(current)
#define conditional_stopped_child_used_math(condition, child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= (condition) ? PF_USED_MATH : 0; } while (0)
#define conditional_used_math(condition) \
	conditional_stopped_child_used_math(condition, current)
#define copy_to_stopped_child_used_math(child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= current->flags & PF_USED_MATH; } while (0)
 
#define tsk_used_math(p) ((p)->flags & PF_USED_MATH)
#define used_math() tsk_used_math(current)

static inline gfp_t memalloc_noio_flags(gfp_t flags)
{
	if (unlikely(current->flags & PF_MEMALLOC_NOIO))
		flags &= ~(__GFP_IO | __GFP_FS);
	return flags;
}

static inline unsigned int memalloc_noio_save(void)
{
	unsigned int flags = current->flags & PF_MEMALLOC_NOIO;
	current->flags |= PF_MEMALLOC_NOIO;
	return flags;
}

static inline void memalloc_noio_restore(unsigned int flags)
{
	current->flags = (current->flags & ~PF_MEMALLOC_NOIO) | flags;
}

#define PFA_NO_NEW_PRIVS 0	 
#define PFA_SPREAD_PAGE  1       
#define PFA_SPREAD_SLAB  2       

#define TASK_PFA_TEST(name, func)					\
	static inline bool task_##func(struct task_struct *p)		\
	{ return test_bit(PFA_##name, &p->atomic_flags); }
#define TASK_PFA_SET(name, func)					\
	static inline void task_set_##func(struct task_struct *p)	\
	{ set_bit(PFA_##name, &p->atomic_flags); }
#define TASK_PFA_CLEAR(name, func)					\
	static inline void task_clear_##func(struct task_struct *p)	\
	{ clear_bit(PFA_##name, &p->atomic_flags); }

TASK_PFA_TEST(NO_NEW_PRIVS, no_new_privs)
TASK_PFA_SET(NO_NEW_PRIVS, no_new_privs)

TASK_PFA_TEST(SPREAD_PAGE, spread_page)
TASK_PFA_SET(SPREAD_PAGE, spread_page)
TASK_PFA_CLEAR(SPREAD_PAGE, spread_page)

TASK_PFA_TEST(SPREAD_SLAB, spread_slab)
TASK_PFA_SET(SPREAD_SLAB, spread_slab)
TASK_PFA_CLEAR(SPREAD_SLAB, spread_slab)

#define JOBCTL_STOP_SIGMASK	0xffff	 

#define JOBCTL_STOP_DEQUEUED_BIT 16	 
#define JOBCTL_STOP_PENDING_BIT	17	 
#define JOBCTL_STOP_CONSUME_BIT	18	 
#define JOBCTL_TRAP_STOP_BIT	19	 
#define JOBCTL_TRAP_NOTIFY_BIT	20	 
#define JOBCTL_TRAPPING_BIT	21	 
#define JOBCTL_LISTENING_BIT	22	 

#define JOBCTL_STOP_DEQUEUED	(1UL << JOBCTL_STOP_DEQUEUED_BIT)
#define JOBCTL_STOP_PENDING	(1UL << JOBCTL_STOP_PENDING_BIT)
#define JOBCTL_STOP_CONSUME	(1UL << JOBCTL_STOP_CONSUME_BIT)
#define JOBCTL_TRAP_STOP	(1UL << JOBCTL_TRAP_STOP_BIT)
#define JOBCTL_TRAP_NOTIFY	(1UL << JOBCTL_TRAP_NOTIFY_BIT)
#define JOBCTL_TRAPPING		(1UL << JOBCTL_TRAPPING_BIT)
#define JOBCTL_LISTENING	(1UL << JOBCTL_LISTENING_BIT)

#define JOBCTL_TRAP_MASK	(JOBCTL_TRAP_STOP | JOBCTL_TRAP_NOTIFY)
#define JOBCTL_PENDING_MASK	(JOBCTL_STOP_PENDING | JOBCTL_TRAP_MASK)

extern bool task_set_jobctl_pending(struct task_struct *task,
				    unsigned long mask);
extern void task_clear_jobctl_trapping(struct task_struct *task);
extern void task_clear_jobctl_pending(struct task_struct *task,
				      unsigned long mask);

static inline void rcu_copy_process(struct task_struct *p)
{
#ifdef CONFIG_PREEMPT_RCU
	p->rcu_read_lock_nesting = 0;
	p->rcu_read_unlock_special.s = 0;
	p->rcu_blocked_node = NULL;
	INIT_LIST_HEAD(&p->rcu_node_entry);
#endif  
#ifdef CONFIG_TASKS_RCU
	p->rcu_tasks_holdout = false;
	INIT_LIST_HEAD(&p->rcu_tasks_holdout_list);
	p->rcu_tasks_idle_cpu = -1;
#endif  
}

static inline void tsk_restore_flags(struct task_struct *task,
				unsigned long orig_flags, unsigned long flags)
{
	task->flags &= ~flags;
	task->flags |= orig_flags & flags;
}

extern int cpuset_cpumask_can_shrink(const struct cpumask *cur,
				     const struct cpumask *trial);
extern int task_can_attach(struct task_struct *p,
			   const struct cpumask *cs_cpus_allowed);
#ifdef CONFIG_SMP
extern void do_set_cpus_allowed(struct task_struct *p,
			       const struct cpumask *new_mask);

extern int set_cpus_allowed_ptr(struct task_struct *p,
				const struct cpumask *new_mask);
#else
static inline void do_set_cpus_allowed(struct task_struct *p,
				      const struct cpumask *new_mask)
{
}
static inline int set_cpus_allowed_ptr(struct task_struct *p,
				       const struct cpumask *new_mask)
{
	if (!cpumask_test_cpu(0, new_mask))
		return -EINVAL;
	return 0;
}
#endif

#ifdef CONFIG_NO_HZ_COMMON
void calc_load_enter_idle(void);
void calc_load_exit_idle(void);
#else
static inline void calc_load_enter_idle(void) { }
static inline void calc_load_exit_idle(void) { }
#endif  

extern unsigned long long notrace sched_clock(void);
 
extern u64 cpu_clock(int cpu);
extern u64 local_clock(void);
extern u64 running_clock(void);
extern u64 sched_clock_cpu(int cpu);

extern void sched_clock_init(void);

#ifndef CONFIG_HAVE_UNSTABLE_SCHED_CLOCK
static inline void sched_clock_tick(void)
{
}

static inline void sched_clock_idle_sleep_event(void)
{
}

static inline void sched_clock_idle_wakeup_event(u64 delta_ns)
{
}
#else
 
extern int sched_clock_stable(void);
extern void set_sched_clock_stable(void);
extern void clear_sched_clock_stable(void);

extern void sched_clock_tick(void);
extern void sched_clock_idle_sleep_event(void);
extern void sched_clock_idle_wakeup_event(u64 delta_ns);
#endif

#ifdef CONFIG_IRQ_TIME_ACCOUNTING
 
extern void enable_sched_clock_irqtime(void);
extern void disable_sched_clock_irqtime(void);
#else
static inline void enable_sched_clock_irqtime(void) {}
static inline void disable_sched_clock_irqtime(void) {}
#endif

extern unsigned long long
task_sched_runtime(struct task_struct *task);

#ifdef CONFIG_SMP
extern void sched_exec(void);
#else
#define sched_exec()   {}
#endif

extern void sched_clock_idle_sleep_event(void);
extern void sched_clock_idle_wakeup_event(u64 delta_ns);

#ifdef CONFIG_HOTPLUG_CPU
extern void idle_task_exit(void);
#else
static inline void idle_task_exit(void) {}
#endif

#if defined(CONFIG_NO_HZ_COMMON) && defined(CONFIG_SMP)
extern void wake_up_nohz_cpu(int cpu);
#else
static inline void wake_up_nohz_cpu(int cpu) { }
#endif

#ifdef CONFIG_NO_HZ_FULL
extern bool sched_can_stop_tick(void);
extern u64 scheduler_tick_max_deferment(void);
#else
static inline bool sched_can_stop_tick(void) { return false; }
#endif

#ifdef CONFIG_SCHED_AUTOGROUP
extern void sched_autogroup_create_attach(struct task_struct *p);
extern void sched_autogroup_detach(struct task_struct *p);
extern void sched_autogroup_fork(struct signal_struct *sig);
extern void sched_autogroup_exit(struct signal_struct *sig);
#ifdef CONFIG_PROC_FS
extern void proc_sched_autogroup_show_task(struct task_struct *p, struct seq_file *m);
extern int proc_sched_autogroup_set_nice(struct task_struct *p, int nice);
#endif
#else
static inline void sched_autogroup_create_attach(struct task_struct *p) { }
static inline void sched_autogroup_detach(struct task_struct *p) { }
static inline void sched_autogroup_fork(struct signal_struct *sig) { }
static inline void sched_autogroup_exit(struct signal_struct *sig) { }
#endif

extern int yield_to(struct task_struct *p, bool preempt);
extern void set_user_nice(struct task_struct *p, long nice);
extern int task_prio(const struct task_struct *p);
 
static inline int task_nice(const struct task_struct *p)
{
	return PRIO_TO_NICE((p)->static_prio);
}
extern int can_nice(const struct task_struct *p, const int nice);
extern int task_curr(const struct task_struct *p);
extern int idle_cpu(int cpu);
extern int sched_setscheduler(struct task_struct *, int,
			      const struct sched_param *);
extern int sched_setscheduler_nocheck(struct task_struct *, int,
				      const struct sched_param *);
extern int sched_setattr(struct task_struct *,
			 const struct sched_attr *);
extern struct task_struct *idle_task(int cpu);
 
static inline bool is_idle_task(const struct task_struct *p)
{
	return p->pid == 0;
}
extern struct task_struct *curr_task(int cpu);
extern void set_curr_task(int cpu, struct task_struct *p);

void yield(void);

union thread_union {
	struct thread_info thread_info;
	unsigned long stack[THREAD_SIZE/sizeof(long)];
};

#ifndef __HAVE_ARCH_KSTACK_END
static inline int kstack_end(void *addr)
{
	 
	return !(((unsigned long)addr+sizeof(void*)-1) & (THREAD_SIZE-sizeof(void*)));
}
#endif

extern union thread_union init_thread_union;
extern struct task_struct init_task;

extern struct   mm_struct init_mm;

extern struct pid_namespace init_pid_ns;

extern struct task_struct *find_task_by_vpid(pid_t nr);
extern struct task_struct *find_task_by_pid_ns(pid_t nr,
		struct pid_namespace *ns);

extern struct user_struct * alloc_uid(kuid_t);
static inline struct user_struct *get_uid(struct user_struct *u)
{
	atomic_inc(&u->__count);
	return u;
}
extern void free_uid(struct user_struct *);

#include <asm/current.h>

extern void xtime_update(unsigned long ticks);

extern int wake_up_state(struct task_struct *tsk, unsigned int state);
extern int wake_up_process(struct task_struct *tsk);
extern void wake_up_new_task(struct task_struct *tsk);
#ifdef CONFIG_SMP
 extern void kick_process(struct task_struct *tsk);
#else
 static inline void kick_process(struct task_struct *tsk) { }
#endif
extern int sched_fork(unsigned long clone_flags, struct task_struct *p);
extern void sched_dead(struct task_struct *p);

extern void proc_caches_init(void);
extern void flush_signals(struct task_struct *);
extern void ignore_signals(struct task_struct *);
extern void flush_signal_handlers(struct task_struct *, int force_default);
extern int dequeue_signal(struct task_struct *tsk, sigset_t *mask, siginfo_t *info);

static inline int kernel_dequeue_signal(siginfo_t *info)
{
	struct task_struct *tsk = current;
	siginfo_t __info;
	int ret;

	spin_lock_irq(&tsk->sighand->siglock);
	ret = dequeue_signal(tsk, &tsk->blocked, info ?: &__info);
	spin_unlock_irq(&tsk->sighand->siglock);

	return ret;
}

static inline void kernel_signal_stop(void)
{
	spin_lock_irq(&current->sighand->siglock);
	if (current->jobctl & JOBCTL_STOP_DEQUEUED)
		__set_current_state(TASK_STOPPED);
	spin_unlock_irq(&current->sighand->siglock);

	schedule();
}

extern void release_task(struct task_struct * p);
extern int send_sig_info(int, struct siginfo *, struct task_struct *);
extern int force_sigsegv(int, struct task_struct *);
extern int force_sig_info(int, struct siginfo *, struct task_struct *);
extern int __kill_pgrp_info(int sig, struct siginfo *info, struct pid *pgrp);
extern int kill_pid_info(int sig, struct siginfo *info, struct pid *pid);
extern int kill_pid_info_as_cred(int, struct siginfo *, struct pid *,
				const struct cred *, u32);
extern int kill_pgrp(struct pid *pid, int sig, int priv);
extern int kill_pid(struct pid *pid, int sig, int priv);
extern int kill_proc_info(int, struct siginfo *, pid_t);
extern __must_check bool do_notify_parent(struct task_struct *, int);
extern void __wake_up_parent(struct task_struct *p, struct task_struct *parent);
extern void force_sig(int, struct task_struct *);
extern int send_sig(int, struct task_struct *, int);
extern int zap_other_threads(struct task_struct *p);
extern struct sigqueue *sigqueue_alloc(void);
extern void sigqueue_free(struct sigqueue *);
extern int send_sigqueue(struct sigqueue *,  struct task_struct *, int group);
extern int do_sigaction(int, struct k_sigaction *, struct k_sigaction *);

static inline void restore_saved_sigmask(void)
{
	if (test_and_clear_restore_sigmask())
		__set_current_blocked(&current->saved_sigmask);
}

static inline sigset_t *sigmask_to_save(void)
{
	sigset_t *res = &current->blocked;
	if (unlikely(test_restore_sigmask()))
		res = &current->saved_sigmask;
	return res;
}

static inline int kill_cad_pid(int sig, int priv)
{
	return kill_pid(cad_pid, sig, priv);
}

#define SEND_SIG_NOINFO ((struct siginfo *) 0)
#define SEND_SIG_PRIV	((struct siginfo *) 1)
#define SEND_SIG_FORCED	((struct siginfo *) 2)

static inline int on_sig_stack(unsigned long sp)
{
#ifdef CONFIG_STACK_GROWSUP
	return sp >= current->sas_ss_sp &&
		sp - current->sas_ss_sp < current->sas_ss_size;
#else
	return sp > current->sas_ss_sp &&
		sp - current->sas_ss_sp <= current->sas_ss_size;
#endif
}

static inline int sas_ss_flags(unsigned long sp)
{
	if (!current->sas_ss_size)
		return SS_DISABLE;

	return on_sig_stack(sp) ? SS_ONSTACK : 0;
}

static inline unsigned long sigsp(unsigned long sp, struct ksignal *ksig)
{
	if (unlikely((ksig->ka.sa.sa_flags & SA_ONSTACK)) && ! sas_ss_flags(sp))
#ifdef CONFIG_STACK_GROWSUP
		return current->sas_ss_sp;
#else
		return current->sas_ss_sp + current->sas_ss_size;
#endif
	return sp;
}

extern struct mm_struct * mm_alloc(void);

extern void __mmdrop(struct mm_struct *);
static inline void mmdrop(struct mm_struct * mm)
{
	if (unlikely(atomic_dec_and_test(&mm->mm_count)))
		__mmdrop(mm);
}

extern void mmput(struct mm_struct *);
 
extern struct mm_struct *get_task_mm(struct task_struct *task);
 
extern struct mm_struct *mm_access(struct task_struct *task, unsigned int mode);
 
extern void mm_release(struct task_struct *, struct mm_struct *);

#ifdef CONFIG_HAVE_COPY_THREAD_TLS
extern int copy_thread_tls(unsigned long, unsigned long, unsigned long,
			struct task_struct *, unsigned long);
#else
extern int copy_thread(unsigned long, unsigned long, unsigned long,
			struct task_struct *);

static inline int copy_thread_tls(
		unsigned long clone_flags, unsigned long sp, unsigned long arg,
		struct task_struct *p, unsigned long tls)
{
	return copy_thread(clone_flags, sp, arg, p);
}
#endif
extern void flush_thread(void);
extern void exit_thread(void);

extern void exit_files(struct task_struct *);
extern void __cleanup_sighand(struct sighand_struct *);

extern void exit_itimers(struct signal_struct *);
extern void flush_itimer_signals(void);

extern void do_group_exit(int);

extern int do_execve(struct filename *,
		     const char __user * const __user *,
		     const char __user * const __user *);
extern int do_execveat(int, struct filename *,
		       const char __user * const __user *,
		       const char __user * const __user *,
		       int);
extern long _do_fork(unsigned long, unsigned long, unsigned long, int __user *, int __user *, unsigned long);
extern long do_fork(unsigned long, unsigned long, unsigned long, int __user *, int __user *);
struct task_struct *fork_idle(int);
extern pid_t kernel_thread(int (*fn)(void *), void *arg, unsigned long flags);

extern void __set_task_comm(struct task_struct *tsk, const char *from, bool exec);
static inline void set_task_comm(struct task_struct *tsk, const char *from)
{
	__set_task_comm(tsk, from, false);
}
extern char *get_task_comm(char *to, struct task_struct *tsk);

#ifdef CONFIG_SMP
void scheduler_ipi(void);
extern unsigned long wait_task_inactive(struct task_struct *, long match_state);
#else
static inline void scheduler_ipi(void) { }
static inline unsigned long wait_task_inactive(struct task_struct *p,
					       long match_state)
{
	return 1;
}
#endif

#define tasklist_empty() \
	list_empty(&init_task.tasks)

#define next_task(p) \
	list_entry_rcu((p)->tasks.next, struct task_struct, tasks)

#define for_each_process(p) \
	for (p = &init_task ; (p = next_task(p)) != &init_task ; )

extern bool current_is_single_threaded(void);

#define do_each_thread(g, t) \
	for (g = t = &init_task ; (g = t = next_task(g)) != &init_task ; ) do

#define while_each_thread(g, t) \
	while ((t = next_thread(t)) != g)

#define __for_each_thread(signal, t)	\
	list_for_each_entry_rcu(t, &(signal)->thread_head, thread_node)

#define for_each_thread(p, t)		\
	__for_each_thread((p)->signal, t)

#define for_each_process_thread(p, t)	\
	for_each_process(p) for_each_thread(p, t)

static inline int get_nr_threads(struct task_struct *tsk)
{
	return tsk->signal->nr_threads;
}

static inline bool thread_group_leader(struct task_struct *p)
{
	return p->exit_signal >= 0;
}

static inline bool has_group_leader_pid(struct task_struct *p)
{
	return task_pid(p) == p->signal->leader_pid;
}

static inline
bool same_thread_group(struct task_struct *p1, struct task_struct *p2)
{
	return p1->signal == p2->signal;
}

static inline struct task_struct *next_thread(const struct task_struct *p)
{
	return list_entry_rcu(p->thread_group.next,
			      struct task_struct, thread_group);
}

static inline int thread_group_empty(struct task_struct *p)
{
	return list_empty(&p->thread_group);
}

#define delay_group_leader(p) \
		(thread_group_leader(p) && !thread_group_empty(p))

static inline void task_lock(struct task_struct *p)
{
	spin_lock(&p->alloc_lock);
}

static inline void task_unlock(struct task_struct *p)
{
	spin_unlock(&p->alloc_lock);
}

extern struct sighand_struct *__lock_task_sighand(struct task_struct *tsk,
							unsigned long *flags);

static inline struct sighand_struct *lock_task_sighand(struct task_struct *tsk,
						       unsigned long *flags)
{
	struct sighand_struct *ret;

	ret = __lock_task_sighand(tsk, flags);
	(void)__cond_lock(&tsk->sighand->siglock, ret);
	return ret;
}

static inline void unlock_task_sighand(struct task_struct *tsk,
						unsigned long *flags)
{
	spin_unlock_irqrestore(&tsk->sighand->siglock, *flags);
}

static inline void threadgroup_change_begin(struct task_struct *tsk)
{
	might_sleep();
	cgroup_threadgroup_change_begin(tsk);
}

static inline void threadgroup_change_end(struct task_struct *tsk)
{
	cgroup_threadgroup_change_end(tsk);
}

#ifndef __HAVE_THREAD_FUNCTIONS

#define task_thread_info(task)	((struct thread_info *)(task)->stack)
#define task_stack_page(task)	((task)->stack)

static inline void setup_thread_stack(struct task_struct *p, struct task_struct *org)
{
	*task_thread_info(p) = *task_thread_info(org);
	task_thread_info(p)->task = p;
}

static inline unsigned long *end_of_stack(struct task_struct *p)
{
#ifdef CONFIG_STACK_GROWSUP
	return (unsigned long *)((unsigned long)task_thread_info(p) + THREAD_SIZE) - 1;
#else
	return (unsigned long *)(task_thread_info(p) + 1);
#endif
}

#endif
#define task_stack_end_corrupted(task) \
		(*(end_of_stack(task)) != STACK_END_MAGIC)

static inline int object_is_on_stack(void *obj)
{
	void *stack = task_stack_page(current);

	return (obj >= stack) && (obj < (stack + THREAD_SIZE));
}

extern void thread_info_cache_init(void);

#ifdef CONFIG_DEBUG_STACK_USAGE
static inline unsigned long stack_not_used(struct task_struct *p)
{
	unsigned long *n = end_of_stack(p);

	do { 	 
		n++;
	} while (!*n);

	return (unsigned long)n - (unsigned long)end_of_stack(p);
}
#endif
extern void set_task_stack_end_magic(struct task_struct *tsk);

static inline void set_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	set_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline void clear_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	clear_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline int test_and_set_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	return test_and_set_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline int test_and_clear_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	return test_and_clear_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline int test_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	return test_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline void set_tsk_need_resched(struct task_struct *tsk)
{
	set_tsk_thread_flag(tsk,TIF_NEED_RESCHED);
}

static inline void clear_tsk_need_resched(struct task_struct *tsk)
{
	clear_tsk_thread_flag(tsk,TIF_NEED_RESCHED);
}

static inline int test_tsk_need_resched(struct task_struct *tsk)
{
	return unlikely(test_tsk_thread_flag(tsk,TIF_NEED_RESCHED));
}

static inline int restart_syscall(void)
{
	set_tsk_thread_flag(current, TIF_SIGPENDING);
	return -ERESTARTNOINTR;
}

static inline int signal_pending(struct task_struct *p)
{
	return unlikely(test_tsk_thread_flag(p,TIF_SIGPENDING));
}

static inline int __fatal_signal_pending(struct task_struct *p)
{
	return unlikely(sigismember(&p->pending.signal, SIGKILL));
}

static inline int fatal_signal_pending(struct task_struct *p)
{
	return signal_pending(p) && __fatal_signal_pending(p);
}

static inline int signal_pending_state(long state, struct task_struct *p)
{
	if (!(state & (TASK_INTERRUPTIBLE | TASK_WAKEKILL)))
		return 0;
	if (!signal_pending(p))
		return 0;

	return (state & TASK_INTERRUPTIBLE) || __fatal_signal_pending(p);
}

extern int _cond_resched(void);

#define cond_resched() ({			\
	___might_sleep(__FILE__, __LINE__, 0);	\
	_cond_resched();			\
})

extern int __cond_resched_lock(spinlock_t *lock);

#define cond_resched_lock(lock) ({				\
	___might_sleep(__FILE__, __LINE__, PREEMPT_LOCK_OFFSET);\
	__cond_resched_lock(lock);				\
})

extern int __cond_resched_softirq(void);

#define cond_resched_softirq() ({					\
	___might_sleep(__FILE__, __LINE__, SOFTIRQ_DISABLE_OFFSET);	\
	__cond_resched_softirq();					\
})

static inline void cond_resched_rcu(void)
{
#if defined(CONFIG_DEBUG_ATOMIC_SLEEP) || !defined(CONFIG_PREEMPT_RCU)
	rcu_read_unlock();
	cond_resched();
	rcu_read_lock();
#endif
}

static inline int spin_needbreak(spinlock_t *lock)
{
#ifdef CONFIG_PREEMPT
	return spin_is_contended(lock);
#else
	return 0;
#endif
}

#ifdef TIF_POLLING_NRFLAG
static inline int tsk_is_polling(struct task_struct *p)
{
	return test_tsk_thread_flag(p, TIF_POLLING_NRFLAG);
}

static inline void __current_set_polling(void)
{
	set_thread_flag(TIF_POLLING_NRFLAG);
}

static inline bool __must_check current_set_polling_and_test(void)
{
	__current_set_polling();

	smp_mb__after_atomic();

	return unlikely(tif_need_resched());
}

static inline void __current_clr_polling(void)
{
	clear_thread_flag(TIF_POLLING_NRFLAG);
}

static inline bool __must_check current_clr_polling_and_test(void)
{
	__current_clr_polling();

	smp_mb__after_atomic();

	return unlikely(tif_need_resched());
}

#else
static inline int tsk_is_polling(struct task_struct *p) { return 0; }
static inline void __current_set_polling(void) { }
static inline void __current_clr_polling(void) { }

static inline bool __must_check current_set_polling_and_test(void)
{
	return unlikely(tif_need_resched());
}
static inline bool __must_check current_clr_polling_and_test(void)
{
	return unlikely(tif_need_resched());
}
#endif

static inline void current_clr_polling(void)
{
	__current_clr_polling();

	smp_mb();  

	preempt_fold_need_resched();
}

static __always_inline bool need_resched(void)
{
	return unlikely(tif_need_resched());
}

void thread_group_cputime(struct task_struct *tsk, struct task_cputime *times);
void thread_group_cputimer(struct task_struct *tsk, struct task_cputime *times);

extern void recalc_sigpending_and_wake(struct task_struct *t);
extern void recalc_sigpending(void);

extern void signal_wake_up_state(struct task_struct *t, unsigned int state);

static inline void signal_wake_up(struct task_struct *t, bool resume)
{
	signal_wake_up_state(t, resume ? TASK_WAKEKILL : 0);
}
static inline void ptrace_signal_wake_up(struct task_struct *t, bool resume)
{
	signal_wake_up_state(t, resume ? __TASK_TRACED : 0);
}

#ifdef CONFIG_SMP

static inline unsigned int task_cpu(const struct task_struct *p)
{
	return task_thread_info(p)->cpu;
}

static inline int task_node(const struct task_struct *p)
{
	return cpu_to_node(task_cpu(p));
}

extern void set_task_cpu(struct task_struct *p, unsigned int cpu);

#else

static inline unsigned int task_cpu(const struct task_struct *p)
{
	return 0;
}

static inline void set_task_cpu(struct task_struct *p, unsigned int cpu)
{
}

#endif  

extern long sched_setaffinity(pid_t pid, const struct cpumask *new_mask);
extern long sched_getaffinity(pid_t pid, struct cpumask *mask);

#ifdef CONFIG_CGROUP_SCHED
extern struct task_group root_task_group;
#endif  

extern int task_can_switch_user(struct user_struct *up,
					struct task_struct *tsk);

#ifdef CONFIG_TASK_XACCT
static inline void add_rchar(struct task_struct *tsk, ssize_t amt)
{
	tsk->ioac.rchar += amt;
}

static inline void add_wchar(struct task_struct *tsk, ssize_t amt)
{
	tsk->ioac.wchar += amt;
}

static inline void inc_syscr(struct task_struct *tsk)
{
	tsk->ioac.syscr++;
}

static inline void inc_syscw(struct task_struct *tsk)
{
	tsk->ioac.syscw++;
}
#else
static inline void add_rchar(struct task_struct *tsk, ssize_t amt)
{
}

static inline void add_wchar(struct task_struct *tsk, ssize_t amt)
{
}

static inline void inc_syscr(struct task_struct *tsk)
{
}

static inline void inc_syscw(struct task_struct *tsk)
{
}
#endif

#ifndef TASK_SIZE_OF
#define TASK_SIZE_OF(tsk)	TASK_SIZE
#endif

#ifdef CONFIG_MEMCG
extern void mm_update_next_owner(struct mm_struct *mm);
#else
static inline void mm_update_next_owner(struct mm_struct *mm)
{
}
#endif  

static inline unsigned long task_rlimit(const struct task_struct *tsk,
		unsigned int limit)
{
	return READ_ONCE(tsk->signal->rlim[limit].rlim_cur);
}

static inline unsigned long task_rlimit_max(const struct task_struct *tsk,
		unsigned int limit)
{
	return READ_ONCE(tsk->signal->rlim[limit].rlim_max);
}

static inline unsigned long rlimit(unsigned int limit)
{
	return task_rlimit(current, limit);
}

static inline unsigned long rlimit_max(unsigned int limit)
{
	return task_rlimit_max(current, limit);
}

#endif
