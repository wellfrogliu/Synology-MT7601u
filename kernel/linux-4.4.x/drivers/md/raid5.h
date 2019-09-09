#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#ifndef _RAID5_H
#define _RAID5_H

#include <linux/raid/xor.h>
#include <linux/dmaengine.h>

enum check_states {
	check_state_idle = 0,
	check_state_run,  
	check_state_run_q,  
	check_state_run_pq,  
	check_state_check_result,
	check_state_compute_run,  
	check_state_compute_result,
};

enum reconstruct_states {
	reconstruct_state_idle = 0,
	reconstruct_state_prexor_drain_run,	 
	reconstruct_state_drain_run,		 
	reconstruct_state_run,			 
	reconstruct_state_prexor_drain_result,
	reconstruct_state_drain_result,
	reconstruct_state_result,
};

struct stripe_head {
	struct hlist_node	hash;
	struct list_head	lru;	       
	struct llist_node	release_list;
	struct r5conf		*raid_conf;
	short			generation;	 
	sector_t		sector;		 
	short			pd_idx;		 
	short			qd_idx;		 
	short			ddf_layout; 
	short			hash_lock_index;
	unsigned long		state;		 
	atomic_t		count;	       
	int			bm_seq;	 
	int			disks;		 
	int			overwrite_disks;  
	enum check_states	check_state;
	enum reconstruct_states reconstruct_state;
	spinlock_t		stripe_lock;
	int			cpu;
	struct r5worker_group	*group;

	struct stripe_head	*batch_head;  
	spinlock_t		batch_lock;  
	struct list_head	batch_list;  

	struct r5l_io_unit	*log_io;
	struct list_head	log_list;
	 
	struct stripe_operations {
		int 		     target, target2;
		enum sum_check_flags zero_sum_result;
	} ops;
	struct r5dev {
		 
		struct bio	req, rreq;
		struct bio_vec	vec, rvec;
		struct page	*page, *orig_page;
		struct bio	*toread, *read, *towrite, *written;
		sector_t	sector;			 
		unsigned long	flags;
		u32		log_checksum;
	} dev[1];  
};

struct stripe_head_state {
	 
	int syncing, expanding, expanded, replacing;
	int locked, uptodate, to_read, to_write, failed, written;
	int to_fill, compute, req_compute, non_overwrite;
	int failed_num[2];
	int p_failed, q_failed;
	int dec_preread_active;
	unsigned long ops_request;

	struct bio_list return_bi;
	struct md_rdev *blocked_rdev;
	int handle_bad_blocks;
	int log_failed;
};

enum r5dev_flags {
	R5_UPTODATE,	 
	R5_LOCKED,	 
	R5_DOUBLE_LOCKED, 
	R5_OVERWRITE,	 
 
	R5_Insync,	 
	R5_Wantread,	 
	R5_Wantwrite,
	R5_Overlap,	 
	R5_ReadNoMerge,  
	R5_ReadError,	 
	R5_ReWrite,	 

	R5_Expanded,	 
	R5_Wantcompute,	 
	R5_Wantfill,	 
	R5_Wantdrain,	 
	R5_WantFUA,	 
	R5_SyncIO,	 
	R5_WriteError,	 
	R5_MadeGood,	 
	R5_ReadRepl,	 
	R5_MadeGoodRepl, 
	R5_NeedReplace,	 
	R5_WantReplace,  
	R5_Discard,	 
	R5_SkipCopy,	 
};

enum {
	STRIPE_ACTIVE,
	STRIPE_HANDLE,
	STRIPE_SYNC_REQUESTED,
	STRIPE_SYNCING,
	STRIPE_INSYNC,
	STRIPE_REPLACED,
	STRIPE_PREREAD_ACTIVE,
	STRIPE_DELAYED,
	STRIPE_DEGRADED,
	STRIPE_BIT_DELAY,
	STRIPE_EXPANDING,
	STRIPE_EXPAND_SOURCE,
	STRIPE_EXPAND_READY,
	STRIPE_IO_STARTED,	 
	STRIPE_FULL_WRITE,	 
	STRIPE_BIOFILL_RUN,
	STRIPE_COMPUTE_RUN,
	STRIPE_OPS_REQ_PENDING,
	STRIPE_ON_UNPLUG_LIST,
	STRIPE_DISCARD,
	STRIPE_ON_RELEASE_LIST,
	STRIPE_BATCH_READY,
	STRIPE_BATCH_ERR,
	STRIPE_BITMAP_PENDING,	 
	STRIPE_LOG_TRAPPED,  
#ifdef MY_ABC_HERE
	STRIPE_NORETRY,
#endif  
};

#define STRIPE_EXPAND_SYNC_FLAGS \
	((1 << STRIPE_EXPAND_SOURCE) |\
	(1 << STRIPE_EXPAND_READY) |\
	(1 << STRIPE_EXPANDING) |\
	(1 << STRIPE_SYNC_REQUESTED))
 
enum {
	STRIPE_OP_BIOFILL,
	STRIPE_OP_COMPUTE_BLK,
	STRIPE_OP_PREXOR,
	STRIPE_OP_BIODRAIN,
	STRIPE_OP_RECONSTRUCT,
	STRIPE_OP_CHECK,
};

enum {
	PARITY_DISABLE_RMW = 0,
	PARITY_ENABLE_RMW,
	PARITY_PREFER_RMW,
};

enum {
	SYNDROME_SRC_ALL,
	SYNDROME_SRC_WANT_DRAIN,
	SYNDROME_SRC_WRITTEN,
};
 
struct disk_info {
	struct md_rdev	*rdev, *replacement;
};

#define NR_STRIPE_HASH_LOCKS 8
#define STRIPE_HASH_LOCKS_MASK (NR_STRIPE_HASH_LOCKS - 1)

struct r5worker {
	struct work_struct work;
	struct r5worker_group *group;
	struct list_head temp_inactive_list[NR_STRIPE_HASH_LOCKS];
	bool working;
};

struct r5worker_group {
	struct list_head handle_list;
	struct r5conf *conf;
	struct r5worker *workers;
	int stripes_cnt;
};

struct r5conf {
	struct hlist_head	*stripe_hashtbl;
	 
	spinlock_t		hash_locks[NR_STRIPE_HASH_LOCKS];
	struct mddev		*mddev;
	int			chunk_sectors;
	int			level, algorithm, rmw_level;
	int			max_degraded;
	int			raid_disks;
	int			max_nr_stripes;
	int			min_nr_stripes;

	sector_t		reshape_progress;
	 
	sector_t		reshape_safe;
	int			previous_raid_disks;
	int			prev_chunk_sectors;
	int			prev_algo;
	short			generation;  
	seqcount_t		gen_lock;	 
	unsigned long		reshape_checkpoint;  
	long long		min_offset_diff;  

	struct list_head	handle_list;  
	struct list_head	hold_list;  
	struct list_head	delayed_list;  
	struct list_head	bitmap_list;  
	struct bio		*retry_read_aligned;  
	struct bio		*retry_read_aligned_list;  
	atomic_t		preread_active_stripes;  
	atomic_t		active_aligned_reads;
	atomic_t		pending_full_writes;  
	int			bypass_count;  
	int			bypass_threshold;  
	int			skip_copy;  
#ifdef MY_ABC_HERE
	int         stripe_cache_memory_usage;
#endif  
	struct list_head	*last_hold;  

	struct bio_list		return_bi;

	atomic_t		reshape_stripes;  
	 
	int			active_name;
	char			cache_name[2][32];
	struct kmem_cache	*slab_cache;  
	struct mutex		cache_size_mutex;  

	int			seq_flush, seq_write;
	int			quiesce;

	int			fullsync;   
	int			recovery_disabled;
	 
	struct raid5_percpu {
		struct page	*spare_page;  
		struct flex_array *scribble;    
	} __percpu *percpu;
	int scribble_disks;
	int scribble_sectors;
#ifdef CONFIG_HOTPLUG_CPU
	struct notifier_block	cpu_notify;
#endif

#ifdef MY_ABC_HERE
	atomic_t            proxy_enable;
	struct md_thread   *proxy_thread;
#endif  
	 
	atomic_t		active_stripes;
	struct list_head	inactive_list[NR_STRIPE_HASH_LOCKS];
	atomic_t		empty_inactive_list_nr;
	struct llist_head	released_stripes;
	wait_queue_head_t	wait_for_quiescent;
	wait_queue_head_t	wait_for_stripe;
	wait_queue_head_t	wait_for_overlap;
	unsigned long		cache_state;
#define R5_INACTIVE_BLOCKED	1	 
#define R5_ALLOC_MORE		2	 
#define R5_DID_ALLOC		4	 
	struct shrinker		shrinker;
	int			pool_size;  
	spinlock_t		device_lock;
	struct disk_info	*disks;

	struct md_thread	*thread;
	struct list_head	temp_inactive_list[NR_STRIPE_HASH_LOCKS];
	struct r5worker_group	*worker_groups;
	int			group_cnt;
	int			worker_cnt_per_group;
	struct r5l_log		*log;
};

#define ALGORITHM_LEFT_ASYMMETRIC	0  
#define ALGORITHM_RIGHT_ASYMMETRIC	1  
#define ALGORITHM_LEFT_SYMMETRIC	2  
#define ALGORITHM_RIGHT_SYMMETRIC	3  

#define ALGORITHM_PARITY_0		4  
#define ALGORITHM_PARITY_N		5  

#define ALGORITHM_ROTATING_ZERO_RESTART	8  
#define ALGORITHM_ROTATING_N_RESTART	9  
#define ALGORITHM_ROTATING_N_CONTINUE	10  

#define ALGORITHM_LEFT_ASYMMETRIC_6	16
#define ALGORITHM_RIGHT_ASYMMETRIC_6	17
#define ALGORITHM_LEFT_SYMMETRIC_6	18
#define ALGORITHM_RIGHT_SYMMETRIC_6	19
#define ALGORITHM_PARITY_0_6		20
#define ALGORITHM_PARITY_N_6		ALGORITHM_PARITY_N

static inline int algorithm_valid_raid5(int layout)
{
	return (layout >= 0) &&
		(layout <= 5);
}
static inline int algorithm_valid_raid6(int layout)
{
	return (layout >= 0 && layout <= 5)
		||
		(layout >= 8 && layout <= 10)
		||
		(layout >= 16 && layout <= 20);
}

static inline int algorithm_is_DDF(int layout)
{
	return layout >= 8 && layout <= 10;
}

extern void md_raid5_kick_device(struct r5conf *conf);
extern int raid5_set_cache_size(struct mddev *mddev, int size);
extern sector_t raid5_compute_blocknr(struct stripe_head *sh, int i, int previous);
extern void raid5_release_stripe(struct stripe_head *sh);
extern sector_t raid5_compute_sector(struct r5conf *conf, sector_t r_sector,
				     int previous, int *dd_idx,
				     struct stripe_head *sh);
extern struct stripe_head *
raid5_get_active_stripe(struct r5conf *conf, sector_t sector,
			int previous, int noblock, int noquiesce);
extern int r5l_init_log(struct r5conf *conf, struct md_rdev *rdev);
extern void r5l_exit_log(struct r5l_log *log);
extern int r5l_write_stripe(struct r5l_log *log, struct stripe_head *head_sh);
extern void r5l_write_stripe_run(struct r5l_log *log);
extern void r5l_flush_stripe_to_raid(struct r5l_log *log);
extern void r5l_stripe_write_finished(struct stripe_head *sh);
extern int r5l_handle_flush_request(struct r5l_log *log, struct bio *bio);
extern void r5l_quiesce(struct r5l_log *log, int state);
extern bool r5l_log_disk_error(struct r5conf *conf);

#ifdef MY_ABC_HERE
#define sector_mod(a,b) sector_div(a,b)
#endif  

#endif
