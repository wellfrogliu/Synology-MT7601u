#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef _MD_MD_H
#define _MD_MD_H

#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include "md-cluster.h"

#ifdef MY_ABC_HERE
#define CHECKINTERVAL (7UL*HZ)
#endif  

#ifdef MY_ABC_HERE
#include <linux/raid/libmd-report.h>
#endif  
#ifdef MY_ABC_HERE
#include <linux/raid/libmd-sync-report.h>
#endif  

#define MaxSector (~(sector_t)0)

#define MD_MAX_BADBLOCKS	(PAGE_SIZE/8)

#ifdef MY_ABC_HERE
typedef struct _tag_SYNO_WAKEUP_DEVICE_WORK {
    struct work_struct work;
    struct mddev *mddev;
} SYNO_WAKEUP_DEVICE_WORK;
#endif  

struct md_rdev {
	struct list_head same_set;	 

	sector_t sectors;		 
	struct mddev *mddev;		 
	int last_events;		 

	struct block_device *meta_bdev;
	struct block_device *bdev;	 

	struct page	*sb_page, *bb_page;
#ifdef MY_ABC_HERE
	struct page	*wakeup_page;
#endif  
	int		sb_loaded;
	__u64		sb_events;
	sector_t	data_offset;	 
	sector_t	new_data_offset; 
	sector_t	sb_start;	 
	int		sb_size;	 
	int		preferred_minor;	 

	struct kobject	kobj;

	unsigned long	flags;	 
	wait_queue_head_t blocked_wait;

	int desc_nr;			 
	int raid_disk;			 
	int new_raid_disk;		 
	int saved_raid_disk;		 
	union {
		sector_t recovery_offset; 
		sector_t journal_tail;	 
	};

	atomic_t	nr_pending;	 
	atomic_t	read_errors;	 
	struct timespec last_read_error;	 
	atomic_t	corrected_errors;  
	struct work_struct del_work;	 

	struct kernfs_node *sysfs_state;  

	struct badblocks {
		int	count;		 
		int	unacked_exist;	 
		int	shift;		 
		u64	*page;		 
		int	changed;
		seqlock_t lock;

		sector_t sector;
		sector_t size;		 
	} badblocks;
};

#ifdef MY_ABC_HERE
typedef struct _tag_SYNO_UPDATE_SB_WORK{
    struct work_struct work;
    struct mddev *mddev;
} SYNO_UPDATE_SB_WORK;
#endif  

enum flag_bits {
	Faulty,			 
	In_sync,		 
	Bitmap_sync,		 
	WriteMostly,		 
	AutoDetected,		 
	Blocked,		 
	WriteErrorSeen,		 
	FaultRecorded,		 
	BlockedBadBlocks,	 
	WantReplacement,	 
	Replacement,		 
	Candidate,		 
	Journal,		 
#ifdef MY_ABC_HERE
	DiskError,	 
#endif  
};

#define BB_LEN_MASK	(0x00000000000001FFULL)
#define BB_OFFSET_MASK	(0x7FFFFFFFFFFFFE00ULL)
#define BB_ACK_MASK	(0x8000000000000000ULL)
#define BB_MAX_LEN	512
#define BB_OFFSET(x)	(((x) & BB_OFFSET_MASK) >> 9)
#define BB_LEN(x)	(((x) & BB_LEN_MASK) + 1)
#define BB_ACK(x)	(!!((x) & BB_ACK_MASK))
#define BB_MAKE(a, l, ack) (((a)<<9) | ((l)-1) | ((u64)(!!(ack)) << 63))

extern int md_is_badblock(struct badblocks *bb, sector_t s, int sectors,
			  sector_t *first_bad, int *bad_sectors);
static inline int is_badblock(struct md_rdev *rdev, sector_t s, int sectors,
			      sector_t *first_bad, int *bad_sectors)
{
	if (unlikely(rdev->badblocks.count)) {
		int rv = md_is_badblock(&rdev->badblocks, rdev->data_offset + s,
					sectors,
					first_bad, bad_sectors);
		if (rv)
			*first_bad -= rdev->data_offset;
		return rv;
	}
	return 0;
}
extern int rdev_set_badblocks(struct md_rdev *rdev, sector_t s, int sectors,
			      int is_new);
extern int rdev_clear_badblocks(struct md_rdev *rdev, sector_t s, int sectors,
				int is_new);
extern void md_ack_all_badblocks(struct badblocks *bb);

struct md_cluster_info;

struct mddev {
	void				*private;
	struct md_personality		*pers;
	dev_t				unit;
	int				md_minor;
	struct list_head		disks;
	unsigned long			flags;
#define MD_CHANGE_DEVS	0	 
#define MD_CHANGE_CLEAN 1	 
#define MD_CHANGE_PENDING 2	 
#define MD_UPDATE_SB_FLAGS (1 | 2 | 4)	 
#define MD_ARRAY_FIRST_USE 3     
#define MD_STILL_CLOSED	4	 
#define MD_JOURNAL_CLEAN 5	 
#define MD_HAS_JOURNAL	6	 

	int				suspended;
	atomic_t			active_io;
	int				ro;
	int				sysfs_active;  
	int				ready;  
	struct gendisk			*gendisk;

	struct kobject			kobj;
	int				hold_active;
#define	UNTIL_IOCTL	1
#define	UNTIL_STOP	2

	int				major_version,
					minor_version,
					patch_version;
	int				persistent;
	int				external;	 
	char				metadata_type[17];  
	int				chunk_sectors;
	time_t				ctime, utime;
	int				level, layout;
	char				clevel[16];
	int				raid_disks;
	int				max_disks;
	sector_t			dev_sectors;	 
	sector_t			array_sectors;  
	int				external_size;  
	__u64				events;
	 
	int				can_decrease_events;

	char				uuid[16];

	sector_t			reshape_position;
	int				delta_disks, new_level, new_layout;
	int				new_chunk_sectors;
	int				reshape_backwards;

	struct md_thread		*thread;	 
	struct md_thread		*sync_thread;	 

	char				*last_sync_action;
	sector_t			curr_resync;	 
	 
	sector_t			curr_resync_completed;
	unsigned long			resync_mark;	 
	sector_t			resync_mark_cnt; 
	sector_t			curr_mark_cnt;  

	sector_t			resync_max_sectors;  

	atomic64_t			resync_mismatches;  

	sector_t			suspend_lo;
	sector_t			suspend_hi;
	 
	int				sync_speed_min;
	int				sync_speed_max;

	int				parallel_resync;

	int				ok_start_degraded;
	 
#define	MD_RECOVERY_RUNNING	0
#define	MD_RECOVERY_SYNC	1
#define	MD_RECOVERY_RECOVER	2
#define	MD_RECOVERY_INTR	3
#define	MD_RECOVERY_DONE	4
#define	MD_RECOVERY_NEEDED	5
#define	MD_RECOVERY_REQUESTED	6
#define	MD_RECOVERY_CHECK	7
#define MD_RECOVERY_RESHAPE	8
#define	MD_RECOVERY_FROZEN	9
#define	MD_RECOVERY_ERROR	10

	unsigned long			recovery;
	 
#ifdef MY_ABC_HERE
	 
	int     reshape_interrupt;
#endif  
	int				recovery_disabled;

	int				in_sync;	 
	 
	struct mutex			open_mutex;
	struct mutex			reconfig_mutex;
	atomic_t			active;		 
	atomic_t			openers;	 

	int				changed;	 
	int				degraded;	 

	atomic_t			recovery_active;  
	wait_queue_head_t		recovery_wait;
	sector_t			recovery_cp;
	sector_t			resync_min;	 
	sector_t			resync_max;	 

	struct kernfs_node		*sysfs_state;	 
	struct kernfs_node		*sysfs_action;   

	struct work_struct del_work;	 

	spinlock_t			lock;
	wait_queue_head_t		sb_wait;	 
	atomic_t			pending_writes;	 

	unsigned int			safemode;	 
	unsigned int			safemode_delay;
	struct timer_list		safemode_timer;
	atomic_t			writes_pending;
	struct request_queue		*queue;	 

	struct bitmap			*bitmap;  
	struct {
		struct file		*file;  
		loff_t			offset;  
		unsigned long		space;  
		loff_t			default_offset;  
		unsigned long		default_space;  
		struct mutex		mutex;
		unsigned long		chunksize;
		unsigned long		daemon_sleep;  
		unsigned long		max_write_behind;  
		int			external;
		int			nodes;  
		char                    cluster_name[64];  
	} bitmap_info;

	atomic_t			max_corr_read_errors;  
	struct list_head		all_mddevs;
#ifdef MY_ABC_HERE
	unsigned char			blActive;   
	spinlock_t				ActLock;    
	unsigned long			ulLastReq;  
#endif  
#ifdef MY_ABC_HERE
    unsigned char           nodev_and_crashed;      
#endif  
#ifdef MY_ABC_HERE
#define MD_AUTO_REMAP_MODE_FORCE_OFF 0
#define MD_AUTO_REMAP_MODE_FORCE_ON 1
#define MD_AUTO_REMAP_MODE_ISMAXDEGRADE 2
    unsigned char           auto_remap;
#endif  
#ifdef MY_ABC_HERE
	void                            *syno_private;     
	char                            lv_name[16];
#endif  
#ifdef MY_ABC_HERE
	mempool_t	*syno_mdio_mempool;
#endif  

	struct attribute_group		*to_remove;

	struct bio_set			*bio_set;

	struct bio *flush_bio;
	atomic_t flush_pending;
	struct work_struct flush_work;
	struct work_struct event_work;	 
	void (*sync_super)(struct mddev *mddev, struct md_rdev *rdev);
	struct md_cluster_info		*cluster_info;
};

static inline int __must_check mddev_lock(struct mddev *mddev)
{
	return mutex_lock_interruptible(&mddev->reconfig_mutex);
}

static inline void mddev_lock_nointr(struct mddev *mddev)
{
	mutex_lock(&mddev->reconfig_mutex);
}

static inline int mddev_is_locked(struct mddev *mddev)
{
	return mutex_is_locked(&mddev->reconfig_mutex);
}

static inline int mddev_trylock(struct mddev *mddev)
{
	return mutex_trylock(&mddev->reconfig_mutex);
}
extern void mddev_unlock(struct mddev *mddev);

static inline void md_sync_acct(struct block_device *bdev, unsigned long nr_sectors)
{
	atomic_add(nr_sectors, &bdev->bd_contains->bd_disk->sync_io);
}

struct md_personality
{
	char *name;
	int level;
	struct list_head list;
	struct module *owner;
	void (*make_request)(struct mddev *mddev, struct bio *bio);
	int (*run)(struct mddev *mddev);
	void (*free)(struct mddev *mddev, void *priv);
	void (*status)(struct seq_file *seq, struct mddev *mddev);
#ifdef MY_ABC_HERE
	 
	void (*syno_error_handler)(struct mddev *mddev, struct md_rdev *rdev);
#endif  
	 
	void (*error_handler)(struct mddev *mddev, struct md_rdev *rdev);
	int (*hot_add_disk) (struct mddev *mddev, struct md_rdev *rdev);
	int (*hot_remove_disk) (struct mddev *mddev, struct md_rdev *rdev);
	int (*spare_active) (struct mddev *mddev);
	sector_t (*sync_request)(struct mddev *mddev, sector_t sector_nr, int *skipped);
	int (*resize) (struct mddev *mddev, sector_t sectors);
	sector_t (*size) (struct mddev *mddev, sector_t sectors, int raid_disks);
	int (*check_reshape) (struct mddev *mddev);
	int (*start_reshape) (struct mddev *mddev);
	void (*finish_reshape) (struct mddev *mddev);
	 
	void (*quiesce) (struct mddev *mddev, int state);
	 
#ifdef MY_ABC_HERE
	unsigned char (*ismaxdegrade) (struct mddev *mddev);
	void (*syno_set_rdev_auto_remap) (struct mddev *mddev);
#endif  
	void *(*takeover) (struct mddev *mddev);
	 
	int (*congested)(struct mddev *mddev, int bits);
};

struct md_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct mddev *, char *);
	ssize_t (*store)(struct mddev *, const char *, size_t);
};
extern struct attribute_group md_bitmap_group;

static inline struct kernfs_node *sysfs_get_dirent_safe(struct kernfs_node *sd, char *name)
{
	if (sd)
		return sysfs_get_dirent(sd, name);
	return sd;
}
static inline void sysfs_notify_dirent_safe(struct kernfs_node *sd)
{
	if (sd)
		sysfs_notify_dirent(sd);
}

static inline char * mdname (struct mddev * mddev)
{
	return mddev->gendisk ? mddev->gendisk->disk_name : "mdX";
}

static inline int sysfs_link_rdev(struct mddev *mddev, struct md_rdev *rdev)
{
	char nm[20];
	if (!test_bit(Replacement, &rdev->flags) &&
	    !test_bit(Journal, &rdev->flags) &&
	    mddev->kobj.sd) {
		sprintf(nm, "rd%d", rdev->raid_disk);
		return sysfs_create_link(&mddev->kobj, &rdev->kobj, nm);
	} else
		return 0;
}

static inline void sysfs_unlink_rdev(struct mddev *mddev, struct md_rdev *rdev)
{
	char nm[20];
	if (!test_bit(Replacement, &rdev->flags) &&
	    !test_bit(Journal, &rdev->flags) &&
	    mddev->kobj.sd) {
		sprintf(nm, "rd%d", rdev->raid_disk);
		sysfs_remove_link(&mddev->kobj, nm);
	}
}

#define rdev_for_each_list(rdev, tmp, head)				\
	list_for_each_entry_safe(rdev, tmp, head, same_set)

#define rdev_for_each(rdev, mddev)				\
	list_for_each_entry(rdev, &((mddev)->disks), same_set)

#define rdev_for_each_safe(rdev, tmp, mddev)				\
	list_for_each_entry_safe(rdev, tmp, &((mddev)->disks), same_set)

#define rdev_for_each_rcu(rdev, mddev)				\
	list_for_each_entry_rcu(rdev, &((mddev)->disks), same_set)

struct md_thread {
	void			(*run) (struct md_thread *thread);
	struct mddev		*mddev;
	wait_queue_head_t	wqueue;
	unsigned long		flags;
	struct task_struct	*tsk;
	unsigned long		timeout;
	void			*private;
};

#define THREAD_WAKEUP  0

static inline void safe_put_page(struct page *p)
{
	if (p) put_page(p);
}

#ifdef MY_ABC_HERE
extern void SynoUpdateSBTask(struct work_struct *work);
#endif  
#ifdef MY_ABC_HERE
extern void syno_md_error (struct mddev *mddev, struct md_rdev *rdev);
extern int IsDeviceDisappear(struct block_device *bdev);
#endif  
extern int register_md_personality(struct md_personality *p);
extern int unregister_md_personality(struct md_personality *p);
extern int register_md_cluster_operations(struct md_cluster_operations *ops,
		struct module *module);
extern int unregister_md_cluster_operations(void);
extern int md_setup_cluster(struct mddev *mddev, int nodes);
extern void md_cluster_stop(struct mddev *mddev);
extern struct md_thread *md_register_thread(
	void (*run)(struct md_thread *thread),
	struct mddev *mddev,
	const char *name);
extern void md_unregister_thread(struct md_thread **threadp);
extern void md_wakeup_thread(struct md_thread *thread);
extern void md_check_recovery(struct mddev *mddev);
extern void md_reap_sync_thread(struct mddev *mddev);
extern void md_write_start(struct mddev *mddev, struct bio *bi);
extern void md_write_end(struct mddev *mddev);
extern void md_done_sync(struct mddev *mddev, int blocks, int ok);
extern void md_error(struct mddev *mddev, struct md_rdev *rdev);
extern void md_finish_reshape(struct mddev *mddev);

extern int mddev_congested(struct mddev *mddev, int bits);
extern void md_flush_request(struct mddev *mddev, struct bio *bio);
extern void md_super_write(struct mddev *mddev, struct md_rdev *rdev,
			   sector_t sector, int size, struct page *page);
extern void md_super_wait(struct mddev *mddev);
extern int sync_page_io(struct md_rdev *rdev, sector_t sector, int size,
			struct page *page, int rw, bool metadata_op);
extern void md_do_sync(struct md_thread *thread);
extern void md_new_event(struct mddev *mddev);
extern int md_allow_write(struct mddev *mddev);
extern void md_wait_for_blocked_rdev(struct md_rdev *rdev, struct mddev *mddev);
extern void md_set_array_sectors(struct mddev *mddev, sector_t array_sectors);
extern int md_check_no_bitmap(struct mddev *mddev);
extern int md_integrity_register(struct mddev *mddev);
extern int md_integrity_add_rdev(struct md_rdev *rdev, struct mddev *mddev);
extern int strict_strtoul_scaled(const char *cp, unsigned long *res, int scale);

#ifdef MY_ABC_HERE
void SynoAutoRemapReport(struct mddev *mddev, sector_t sector, struct block_device *bdev);
#endif  
#ifdef MY_ABC_HERE
void RaidRemapModeSet(struct block_device *, unsigned char);
#endif  

#ifdef MY_ABC_HERE
void SYNORaidRdevUnplug(struct mddev *mddev, struct md_rdev *rdev);
#endif  
extern void mddev_init(struct mddev *mddev);
extern int md_run(struct mddev *mddev);
extern void md_stop(struct mddev *mddev);
extern void md_stop_writes(struct mddev *mddev);
extern int md_rdev_init(struct md_rdev *rdev);
extern void md_rdev_clear(struct md_rdev *rdev);

extern void mddev_suspend(struct mddev *mddev);
extern void mddev_resume(struct mddev *mddev);
extern struct bio *bio_clone_mddev(struct bio *bio, gfp_t gfp_mask,
				   struct mddev *mddev);
extern struct bio *bio_alloc_mddev(gfp_t gfp_mask, int nr_iovecs,
				   struct mddev *mddev);

extern void md_unplug(struct blk_plug_cb *cb, bool from_schedule);
extern void md_reload_sb(struct mddev *mddev, int raid_disk);
extern void md_update_sb(struct mddev *mddev, int force);
extern void md_kick_rdev_from_array(struct md_rdev * rdev);
struct md_rdev *md_find_rdev_nr_rcu(struct mddev *mddev, int nr);
static inline int mddev_check_plugged(struct mddev *mddev)
{
	return !!blk_check_plugged(md_unplug, mddev,
				   sizeof(struct blk_plug_cb));
}

static inline void rdev_dec_pending(struct md_rdev *rdev, struct mddev *mddev)
{
	int faulty = test_bit(Faulty, &rdev->flags);
	if (atomic_dec_and_test(&rdev->nr_pending) && faulty) {
		set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
		md_wakeup_thread(mddev->thread);
	}
}

extern struct md_cluster_operations *md_cluster_ops;
static inline int mddev_is_clustered(struct mddev *mddev)
{
	return mddev->cluster_info && mddev->bitmap_info.nodes > 1;
}
#endif  
