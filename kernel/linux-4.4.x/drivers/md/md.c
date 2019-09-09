#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/kthread.h>
#include <linux/blkdev.h>
#include <linux/sysctl.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/hdreg.h>
#include <linux/proc_fs.h>
#include <linux/random.h>
#include <linux/module.h>
#include <linux/reboot.h>
#include <linux/file.h>
#include <linux/compat.h>
#include <linux/delay.h>
#include <linux/raid/md_p.h>
#include <linux/raid/md_u.h>
#include <linux/slab.h>
#ifdef MY_ABC_HERE
#include <linux/list_sort.h>
#endif  
#include "md.h"
#include "bitmap.h"
#include "md-cluster.h"

#ifdef MY_ABC_HERE
static struct kmem_cache *syno_mdio_cache;

struct syno_mdio {
	unsigned long start_time;
	struct mddev *mddev;
	void *bi_private;
	bio_end_io_t *bi_end_io;
};
#endif  

#ifdef MY_ABC_HERE
void SynoMDWakeUpDevices(void *md);
#endif  

#ifdef MY_ABC_HERE
extern struct rw_semaphore s_reshape_mount_key;
#endif  

#ifndef MODULE
static void autostart_arrays(int part);
#endif

#ifdef MY_ABC_HERE
extern int (*funcSYNORaidDiskUnplug)(char *szDiskName);
#ifdef CONFIG_BLK_DEV_NVME
extern int (*funcSYNORaidNVMeUnplug)(char *szDiskName);
#endif  
EXPORT_SYMBOL(SYNORaidRdevUnplug);
int SYNORaidDiskUnplug(char *szArgDiskName);
void SYNORaidUnplugTask(struct work_struct *);
#endif   

static LIST_HEAD(pers_list);
static DEFINE_SPINLOCK(pers_lock);

struct md_cluster_operations *md_cluster_ops;
EXPORT_SYMBOL(md_cluster_ops);
struct module *md_cluster_mod;
EXPORT_SYMBOL(md_cluster_mod);

static DECLARE_WAIT_QUEUE_HEAD(resync_wait);
static struct workqueue_struct *md_wq;
static struct workqueue_struct *md_misc_wq;

static int remove_and_add_spares(struct mddev *mddev,
				 struct md_rdev *this);
static void mddev_detach(struct mddev *mddev);

#define MD_DEFAULT_MAX_CORRECTED_READ_ERRORS 20
 
static int sysctl_speed_limit_min = 1000;
static int sysctl_speed_limit_max = 200000;
static inline int speed_min(struct mddev *mddev)
{
	return mddev->sync_speed_min ?
		mddev->sync_speed_min : sysctl_speed_limit_min;
}

static inline int speed_max(struct mddev *mddev)
{
	return mddev->sync_speed_max ?
		mddev->sync_speed_max : sysctl_speed_limit_max;
}

static struct ctl_table_header *raid_table_header;

static struct ctl_table raid_table[] = {
	{
		.procname	= "speed_limit_min",
		.data		= &sysctl_speed_limit_min,
		.maxlen		= sizeof(int),
		.mode		= S_IRUGO|S_IWUSR,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "speed_limit_max",
		.data		= &sysctl_speed_limit_max,
		.maxlen		= sizeof(int),
		.mode		= S_IRUGO|S_IWUSR,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

static struct ctl_table raid_dir_table[] = {
	{
		.procname	= "raid",
		.maxlen		= 0,
		.mode		= S_IRUGO|S_IXUGO,
		.child		= raid_table,
	},
	{ }
};

static struct ctl_table raid_root_table[] = {
	{
		.procname	= "dev",
		.maxlen		= 0,
		.mode		= 0555,
		.child		= raid_dir_table,
	},
	{  }
};

static const struct block_device_operations md_fops;

static int start_readonly;

struct bio *bio_alloc_mddev(gfp_t gfp_mask, int nr_iovecs,
			    struct mddev *mddev)
{
	struct bio *b;

	if (!mddev || !mddev->bio_set)
		return bio_alloc(gfp_mask, nr_iovecs);

	b = bio_alloc_bioset(gfp_mask, nr_iovecs, mddev->bio_set);
	if (!b)
		return NULL;
	return b;
}
EXPORT_SYMBOL_GPL(bio_alloc_mddev);

struct bio *bio_clone_mddev(struct bio *bio, gfp_t gfp_mask,
			    struct mddev *mddev)
{
	if (!mddev || !mddev->bio_set)
		return bio_clone(bio, gfp_mask);

	return bio_clone_bioset(bio, gfp_mask, mddev->bio_set);
}
EXPORT_SYMBOL_GPL(bio_clone_mddev);

static DECLARE_WAIT_QUEUE_HEAD(md_event_waiters);
static atomic_t md_event_count;
void md_new_event(struct mddev *mddev)
{
	atomic_inc(&md_event_count);
	wake_up(&md_event_waiters);
}
EXPORT_SYMBOL_GPL(md_new_event);

static void md_new_event_inintr(struct mddev *mddev)
{
	atomic_inc(&md_event_count);
	wake_up(&md_event_waiters);
}

static LIST_HEAD(all_mddevs);
static DEFINE_SPINLOCK(all_mddevs_lock);

#define for_each_mddev(_mddev,_tmp)					\
									\
	for (({ spin_lock(&all_mddevs_lock);				\
		_tmp = all_mddevs.next;					\
		_mddev = NULL;});					\
	     ({ if (_tmp != &all_mddevs)				\
			mddev_get(list_entry(_tmp, struct mddev, all_mddevs));\
		spin_unlock(&all_mddevs_lock);				\
		if (_mddev) mddev_put(_mddev);				\
		_mddev = list_entry(_tmp, struct mddev, all_mddevs);	\
		_tmp != &all_mddevs;});					\
	     ({ spin_lock(&all_mddevs_lock);				\
		_tmp = _tmp->next;})					\
		)

#ifdef MY_ABC_HERE
static void syno_md_endio(struct bio *bio)
{
	struct syno_mdio *mdio = bio->bi_private;
	int rw = bio_data_dir(bio);
	unsigned long duration = jiffies - mdio->start_time;
	struct mddev *mddev = mdio->mddev;
	int cpu;

	cpu = part_stat_lock();
	part_stat_add(cpu, &mddev->gendisk->part0, ticks[rw], duration);
	part_round_stats(cpu, &mddev->gendisk->part0);
	part_dec_in_flight(&mddev->gendisk->part0, rw);
	part_stat_unlock();

	bio->bi_end_io = mdio->bi_end_io;
	bio->bi_private = mdio->bi_private;
	mempool_free(mdio, mddev->syno_mdio_mempool);
	bio_endio(bio);
}
#endif  

static blk_qc_t md_make_request(struct request_queue *q, struct bio *bio)
{
	const int rw = bio_data_dir(bio);
	struct mddev *mddev = q->queuedata;
	unsigned int sectors;
	int cpu;
#ifdef MY_ABC_HERE
	unsigned char blActive = 1;
#endif  
#ifdef MY_ABC_HERE
	struct syno_mdio *mdio;
#endif  

	blk_queue_split(q, &bio, q->bio_split);

	if (mddev == NULL || mddev->pers == NULL
	    || !mddev->ready) {
		bio_io_error(bio);
		return BLK_QC_T_NONE;
	}
	if (mddev->ro == 1 && unlikely(rw == WRITE)) {
		if (bio_sectors(bio) != 0)
			bio->bi_error = -EROFS;
		bio_endio(bio);
		return BLK_QC_T_NONE;
	}
	smp_rmb();  
	rcu_read_lock();
	if (mddev->suspended) {
		DEFINE_WAIT(__wait);
		for (;;) {
			prepare_to_wait(&mddev->sb_wait, &__wait,
					TASK_UNINTERRUPTIBLE);
			if (!mddev->suspended)
				break;
			rcu_read_unlock();
			schedule();
			rcu_read_lock();
		}
		finish_wait(&mddev->sb_wait, &__wait);
	}
	atomic_inc(&mddev->active_io);
	rcu_read_unlock();

#ifdef MY_ABC_HERE
	 
	if (time_after(jiffies, mddev->ulLastReq + CHECKINTERVAL)) {
		spin_lock(&mddev->ActLock);
		blActive = mddev->blActive;
		mddev->blActive = 1;
		spin_unlock(&mddev->ActLock);

		if (!blActive) {
			SynoMDWakeUpDevices(mddev);
		}
	}

	mddev->ulLastReq = jiffies;
#endif  

#ifdef MY_ABC_HERE
	mdio = mempool_alloc(mddev->syno_mdio_mempool, GFP_NOIO);
	if (!mdio) {
		bio->bi_error = -ENOMEM;
		bio_endio(bio);
		return BLK_QC_T_NONE;
	}
	mdio->start_time = jiffies;
	mdio->bi_private = bio->bi_private;
	mdio->bi_end_io = bio->bi_end_io;
	mdio->mddev = mddev;
	bio->bi_end_io = syno_md_endio;
	bio->bi_private = mdio;
#endif  
	 
	sectors = bio_sectors(bio);
	 
	bio->bi_rw &= ~REQ_NOMERGE;
	mddev->pers->make_request(mddev, bio);

	cpu = part_stat_lock();
	part_stat_inc(cpu, &mddev->gendisk->part0, ios[rw]);
	part_stat_add(cpu, &mddev->gendisk->part0, sectors[rw], sectors);
#ifdef MY_ABC_HERE
	part_round_stats(cpu, &mddev->gendisk->part0);
	part_inc_in_flight(&mddev->gendisk->part0, rw);
#endif  
	part_stat_unlock();

	if (atomic_dec_and_test(&mddev->active_io) && mddev->suspended)
		wake_up(&mddev->sb_wait);

	return BLK_QC_T_NONE;
}

void mddev_suspend(struct mddev *mddev)
{
#ifdef MY_ABC_HERE
	sector_t ori_suspend_lo, ori_suspend_hi;
	DEFINE_WAIT(wait_noio);
#endif  

	if (mddev->suspended++)
		return;
	synchronize_rcu();
#ifdef MY_ABC_HERE
	ori_suspend_lo = mddev->suspend_lo;
	ori_suspend_hi = mddev->suspend_hi;
	mddev->suspend_lo = 0;
	mddev->suspend_hi = 0;
	mddev->pers->quiesce(mddev, 2);

	while (atomic_read(&mddev->active_io) > 0) {
		prepare_to_wait(&mddev->sb_wait, &wait_noio, TASK_UNINTERRUPTIBLE);
		if (mddev->flags & MD_UPDATE_SB_FLAGS) {
			md_update_sb(mddev, 0);
		}
		schedule();
	}
	finish_wait(&mddev->sb_wait, &wait_noio);

	mddev->suspend_lo = ori_suspend_lo;
	mddev->suspend_hi = ori_suspend_hi;
#else  
	wait_event(mddev->sb_wait, atomic_read(&mddev->active_io) == 0);
#endif  
	mddev->pers->quiesce(mddev, 1);

	del_timer_sync(&mddev->safemode_timer);
}
EXPORT_SYMBOL_GPL(mddev_suspend);

void mddev_resume(struct mddev *mddev)
{
	if (--mddev->suspended)
		return;
	wake_up(&mddev->sb_wait);
	mddev->pers->quiesce(mddev, 0);

	set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
	md_wakeup_thread(mddev->thread);
	md_wakeup_thread(mddev->sync_thread);  
}
EXPORT_SYMBOL_GPL(mddev_resume);

int mddev_congested(struct mddev *mddev, int bits)
{
	struct md_personality *pers = mddev->pers;
	int ret = 0;

	rcu_read_lock();
	if (mddev->suspended)
		ret = 1;
	else if (pers && pers->congested)
		ret = pers->congested(mddev, bits);
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(mddev_congested);
static int md_congested(void *data, int bits)
{
	struct mddev *mddev = data;
	return mddev_congested(mddev, bits);
}

static void md_end_flush(struct bio *bio)
{
	struct md_rdev *rdev = bio->bi_private;
	struct mddev *mddev = rdev->mddev;

	rdev_dec_pending(rdev, mddev);

	if (atomic_dec_and_test(&mddev->flush_pending)) {
		 
		queue_work(md_wq, &mddev->flush_work);
	}
	bio_put(bio);
}

static void md_submit_flush_data(struct work_struct *ws);

static void submit_flushes(struct work_struct *ws)
{
	struct mddev *mddev = container_of(ws, struct mddev, flush_work);
	struct md_rdev *rdev;

	INIT_WORK(&mddev->flush_work, md_submit_flush_data);
	atomic_set(&mddev->flush_pending, 1);
	rcu_read_lock();
	rdev_for_each_rcu(rdev, mddev)
		if (rdev->raid_disk >= 0 &&
		    !test_bit(Faulty, &rdev->flags)) {
			 
			struct bio *bi;
			atomic_inc(&rdev->nr_pending);
			atomic_inc(&rdev->nr_pending);
			rcu_read_unlock();
			bi = bio_alloc_mddev(GFP_NOIO, 0, mddev);
			bi->bi_end_io = md_end_flush;
			bi->bi_private = rdev;
			bi->bi_bdev = rdev->bdev;
			atomic_inc(&mddev->flush_pending);
			submit_bio(WRITE_FLUSH, bi);
			rcu_read_lock();
			rdev_dec_pending(rdev, mddev);
		}
	rcu_read_unlock();
	if (atomic_dec_and_test(&mddev->flush_pending))
		queue_work(md_wq, &mddev->flush_work);
}

static void md_submit_flush_data(struct work_struct *ws)
{
	struct mddev *mddev = container_of(ws, struct mddev, flush_work);
	struct bio *bio = mddev->flush_bio;

	if (bio->bi_iter.bi_size == 0)
		 
		bio_endio(bio);
	else {
		bio->bi_rw &= ~REQ_FLUSH;
		mddev->pers->make_request(mddev, bio);
	}

	mddev->flush_bio = NULL;
	wake_up(&mddev->sb_wait);
}

void md_flush_request(struct mddev *mddev, struct bio *bio)
{
	spin_lock_irq(&mddev->lock);
	wait_event_lock_irq(mddev->sb_wait,
			    !mddev->flush_bio,
			    mddev->lock);
	mddev->flush_bio = bio;
	spin_unlock_irq(&mddev->lock);

	INIT_WORK(&mddev->flush_work, submit_flushes);
	queue_work(md_wq, &mddev->flush_work);
}
EXPORT_SYMBOL(md_flush_request);

void md_unplug(struct blk_plug_cb *cb, bool from_schedule)
{
	struct mddev *mddev = cb->data;
	md_wakeup_thread(mddev->thread);
	kfree(cb);
}
EXPORT_SYMBOL(md_unplug);

static inline struct mddev *mddev_get(struct mddev *mddev)
{
	atomic_inc(&mddev->active);
	return mddev;
}

static void mddev_delayed_delete(struct work_struct *ws);

static void mddev_put(struct mddev *mddev)
{
	struct bio_set *bs = NULL;
#ifdef MY_ABC_HERE
	mempool_t *mempool = NULL;
#endif  

	if (!atomic_dec_and_lock(&mddev->active, &all_mddevs_lock))
		return;
	if (!mddev->raid_disks && list_empty(&mddev->disks) &&
	    mddev->ctime == 0 && !mddev->hold_active) {
		 
		list_del_init(&mddev->all_mddevs);
		bs = mddev->bio_set;
		mddev->bio_set = NULL;
#ifdef MY_ABC_HERE
		mempool = mddev->syno_mdio_mempool;
		mddev->syno_mdio_mempool = NULL;
#endif  
		if (mddev->gendisk) {
			 
			INIT_WORK(&mddev->del_work, mddev_delayed_delete);
			queue_work(md_misc_wq, &mddev->del_work);
		} else
			kfree(mddev);
	}
	spin_unlock(&all_mddevs_lock);
	if (bs)
		bioset_free(bs);
#ifdef MY_ABC_HERE
	if (mempool) {
		mempool_destroy(mempool);
	}
#endif  
}

static void md_safemode_timeout(unsigned long data);

void mddev_init(struct mddev *mddev)
{
	mutex_init(&mddev->open_mutex);
	mutex_init(&mddev->reconfig_mutex);
	mutex_init(&mddev->bitmap_info.mutex);
	INIT_LIST_HEAD(&mddev->disks);
	INIT_LIST_HEAD(&mddev->all_mddevs);
	setup_timer(&mddev->safemode_timer, md_safemode_timeout,
		    (unsigned long) mddev);
	atomic_set(&mddev->active, 1);
	atomic_set(&mddev->openers, 0);
	atomic_set(&mddev->active_io, 0);
	spin_lock_init(&mddev->lock);
	atomic_set(&mddev->flush_pending, 0);
#ifdef MY_ABC_HERE
	spin_lock_init(&mddev->ActLock);
	mddev->blActive = 1;
	mddev->ulLastReq = jiffies;
#endif  
	init_waitqueue_head(&mddev->sb_wait);
	init_waitqueue_head(&mddev->recovery_wait);
	mddev->reshape_position = MaxSector;
	mddev->reshape_backwards = 0;
	mddev->last_sync_action = "none";
	mddev->resync_min = 0;
	mddev->resync_max = MaxSector;
	mddev->level = LEVEL_NONE;
}
EXPORT_SYMBOL_GPL(mddev_init);

static struct mddev *mddev_find(dev_t unit)
{
	struct mddev *mddev, *new = NULL;

	if (unit && MAJOR(unit) != MD_MAJOR)
		unit &= ~((1<<MdpMinorShift)-1);

 retry:
	spin_lock(&all_mddevs_lock);

	if (unit) {
		list_for_each_entry(mddev, &all_mddevs, all_mddevs)
			if (mddev->unit == unit) {
				mddev_get(mddev);
				spin_unlock(&all_mddevs_lock);
				kfree(new);
				return mddev;
			}

		if (new) {
			list_add(&new->all_mddevs, &all_mddevs);
			spin_unlock(&all_mddevs_lock);
			new->hold_active = UNTIL_IOCTL;
			return new;
		}
	} else if (new) {
		 
		static int next_minor = 512;
		int start = next_minor;
		int is_free = 0;
		int dev = 0;
		while (!is_free) {
			dev = MKDEV(MD_MAJOR, next_minor);
			next_minor++;
			if (next_minor > MINORMASK)
				next_minor = 0;
			if (next_minor == start) {
				 
				spin_unlock(&all_mddevs_lock);
				kfree(new);
				return NULL;
			}

			is_free = 1;
			list_for_each_entry(mddev, &all_mddevs, all_mddevs)
				if (mddev->unit == dev) {
					is_free = 0;
					break;
				}
		}
		new->unit = dev;
		new->md_minor = MINOR(dev);
		new->hold_active = UNTIL_STOP;
		list_add(&new->all_mddevs, &all_mddevs);
		spin_unlock(&all_mddevs_lock);
		return new;
	}
	spin_unlock(&all_mddevs_lock);

	new = kzalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return NULL;

	new->unit = unit;
	if (MAJOR(unit) == MD_MAJOR)
		new->md_minor = MINOR(unit);
	else
		new->md_minor = MINOR(unit) >> MdpMinorShift;

	mddev_init(new);

	goto retry;
}

static struct attribute_group md_redundancy_group;

void mddev_unlock(struct mddev *mddev)
{
	if (mddev->to_remove) {
		 
		struct attribute_group *to_remove = mddev->to_remove;
		mddev->to_remove = NULL;
		mddev->sysfs_active = 1;
		mutex_unlock(&mddev->reconfig_mutex);

		if (mddev->kobj.sd) {
			if (to_remove != &md_redundancy_group)
				sysfs_remove_group(&mddev->kobj, to_remove);
			if (mddev->pers == NULL ||
			    mddev->pers->sync_request == NULL) {
				sysfs_remove_group(&mddev->kobj, &md_redundancy_group);
				if (mddev->sysfs_action)
					sysfs_put(mddev->sysfs_action);
				mddev->sysfs_action = NULL;
			}
		}
		mddev->sysfs_active = 0;
	} else
		mutex_unlock(&mddev->reconfig_mutex);

	spin_lock(&pers_lock);
	md_wakeup_thread(mddev->thread);
	spin_unlock(&pers_lock);
}
EXPORT_SYMBOL_GPL(mddev_unlock);

struct md_rdev *md_find_rdev_nr_rcu(struct mddev *mddev, int nr)
{
	struct md_rdev *rdev;

	rdev_for_each_rcu(rdev, mddev)
		if (rdev->desc_nr == nr)
			return rdev;

	return NULL;
}
EXPORT_SYMBOL_GPL(md_find_rdev_nr_rcu);

static struct md_rdev *find_rdev(struct mddev *mddev, dev_t dev)
{
	struct md_rdev *rdev;

	rdev_for_each(rdev, mddev)
		if (rdev->bdev->bd_dev == dev)
			return rdev;

	return NULL;
}

static struct md_rdev *find_rdev_rcu(struct mddev *mddev, dev_t dev)
{
	struct md_rdev *rdev;

	rdev_for_each_rcu(rdev, mddev)
		if (rdev->bdev->bd_dev == dev)
			return rdev;

	return NULL;
}

static struct md_personality *find_pers(int level, char *clevel)
{
	struct md_personality *pers;
	list_for_each_entry(pers, &pers_list, list) {
		if (level != LEVEL_NONE && pers->level == level)
			return pers;
		if (strcmp(pers->name, clevel)==0)
			return pers;
	}
	return NULL;
}

static inline sector_t calc_dev_sboffset(struct md_rdev *rdev)
{
	sector_t num_sectors = i_size_read(rdev->bdev->bd_inode) / 512;
	return MD_NEW_SIZE_SECTORS(num_sectors);
}

static int alloc_disk_sb(struct md_rdev *rdev)
{
	rdev->sb_page = alloc_page(GFP_KERNEL);
	if (!rdev->sb_page) {
		printk(KERN_ALERT "md: out of memory.\n");
		return -ENOMEM;
	}

	return 0;
}
#ifdef MY_ABC_HERE
static int alloc_disk_wakeup_page(struct md_rdev * rdev)
{
	if (rdev->wakeup_page)
		printk(KERN_ERR "md: bug in file %s, line %d\n", __FILE__, __LINE__);

	rdev->wakeup_page = alloc_page(GFP_KERNEL);
	if (!rdev->wakeup_page) {
		printk(KERN_ALERT "md: out of memory.\n");
		return -ENOMEM;
	}

	return 0;
}

static void free_disk_wakeup_page(struct md_rdev * rdev)
{
	if (rdev->wakeup_page) {
		put_page(rdev->wakeup_page);
	}
}
#endif  

void md_rdev_clear(struct md_rdev *rdev)
{
	if (rdev->sb_page) {
		put_page(rdev->sb_page);
		rdev->sb_loaded = 0;
		rdev->sb_page = NULL;
		rdev->sb_start = 0;
		rdev->sectors = 0;
	}
	if (rdev->bb_page) {
		put_page(rdev->bb_page);
		rdev->bb_page = NULL;
	}
	kfree(rdev->badblocks.page);
	rdev->badblocks.page = NULL;
}
EXPORT_SYMBOL_GPL(md_rdev_clear);

static void super_written(struct bio *bio)
{
	struct md_rdev *rdev = bio->bi_private;
	struct mddev *mddev = rdev->mddev;

	if (bio->bi_error) {
		printk("md: super_written gets error=%d\n", bio->bi_error);
#ifdef MY_ABC_HERE
		if (IsDeviceDisappear(rdev->bdev)) {
			syno_md_error(mddev, rdev);
		} else {
			md_error(mddev, rdev);
		}
#else  
		md_error(mddev, rdev);
#endif  
	}

	if (atomic_dec_and_test(&mddev->pending_writes))
		wake_up(&mddev->sb_wait);
	bio_put(bio);
}

void md_super_write(struct mddev *mddev, struct md_rdev *rdev,
		   sector_t sector, int size, struct page *page)
{
	 
	struct bio *bio = bio_alloc_mddev(GFP_NOIO, 1, mddev);

	bio->bi_bdev = rdev->meta_bdev ? rdev->meta_bdev : rdev->bdev;
	bio->bi_iter.bi_sector = sector;
	bio_add_page(bio, page, size, 0);
	bio->bi_private = rdev;
	bio->bi_end_io = super_written;

	atomic_inc(&mddev->pending_writes);
	submit_bio(WRITE_FLUSH_FUA, bio);
}

void md_super_wait(struct mddev *mddev)
{
	 
	wait_event(mddev->sb_wait, atomic_read(&mddev->pending_writes)==0);
}

int sync_page_io(struct md_rdev *rdev, sector_t sector, int size,
		 struct page *page, int rw, bool metadata_op)
{
	struct bio *bio = bio_alloc_mddev(GFP_NOIO, 1, rdev->mddev);
	int ret;

	bio->bi_bdev = (metadata_op && rdev->meta_bdev) ?
		rdev->meta_bdev : rdev->bdev;
	if (metadata_op)
		bio->bi_iter.bi_sector = sector + rdev->sb_start;
	else if (rdev->mddev->reshape_position != MaxSector &&
		 (rdev->mddev->reshape_backwards ==
		  (sector >= rdev->mddev->reshape_position)))
		bio->bi_iter.bi_sector = sector + rdev->new_data_offset;
	else
		bio->bi_iter.bi_sector = sector + rdev->data_offset;
	bio_add_page(bio, page, size, 0);
	submit_bio_wait(rw, bio);

	ret = !bio->bi_error;
	bio_put(bio);
	return ret;
}
EXPORT_SYMBOL_GPL(sync_page_io);

#ifdef MY_ABC_HERE
void SYNOSwapSuperblock0(mdp_super_t *sb)
{
	int i;
	__u32 t32;
	char bTmp, *ptr = (char *)sb;

	for (i = 0; i < 4096; i += 4) {
		bTmp = ptr[0];
		ptr[0] = ptr[3];
		ptr[3] = bTmp;
		bTmp = ptr[1];
		ptr[1] = ptr[2];
		ptr[2] = bTmp;
		ptr += 4;
	}

	t32 = sb->events_hi;
	sb->events_hi = sb->events_lo;
	sb->events_lo = t32;

	t32 = sb->cp_events_hi;
	sb->cp_events_hi = sb->cp_events_lo;
	sb->cp_events_lo = t32;
}
#endif  

#ifdef MY_ABC_HERE
static inline void
RaidMemberAutoRemapSet(struct mddev *mddev)
{
	struct md_rdev *rdev;
	char b[BDEVNAME_SIZE];

#ifdef MY_ABC_HERE
	if (MD_AUTO_REMAP_MODE_ISMAXDEGRADE == mddev->auto_remap && mddev->pers->syno_set_rdev_auto_remap) {
		mddev->pers->syno_set_rdev_auto_remap(mddev);
	} else {
		rdev_for_each(rdev, mddev) {
			bdevname(rdev->bdev, b);
			RaidRemapModeSet(rdev->bdev, mddev->auto_remap);
			printk("md: %s: set %s to auto_remap [%d]\n", mdname(mddev), b, mddev->auto_remap);
		}
	}
#else  
	rdev_for_each(rdev, mddev) {
		bdevname(rdev->bdev, b);
		RaidRemapModeSet(rdev->bdev, mddev->auto_remap);
		printk("md: %s: set %s to auto_remap [%d]\n", mdname(mddev), b, mddev->auto_remap);
	}
#endif  
}
#endif  

#ifdef MY_ABC_HERE
static int sync_sb_page_io(struct block_device *bdev, sector_t sector, int size,
		struct page *page, int rw)
{
	struct bio *bio = bio_alloc(GFP_NOIO, 1);
	int ret;

	rw |= REQ_SYNC;

	bio->bi_bdev = bdev;
	bio->bi_iter.bi_sector = sector;
	bio_add_page(bio, page, size, 0);
	submit_bio_wait(rw, bio);

	ret = !bio->bi_error;
	if (ret && bio_flagged(bio, BIO_AUTO_REMAP)) {
		bio_clear_flag(bio, BIO_AUTO_REMAP);
		ret = 0;
	}

	bio_put(bio);
	return ret;
}

static int SynoRaidAutoRemapAdjust(struct mddev *mddev, int specify_setting)
{
	int old_setting = -1;

	if (NULL == mddev || NULL == mddev->pers) {
		goto END;
	}

	old_setting = mddev->auto_remap;

	if (MD_AUTO_REMAP_MODE_ISMAXDEGRADE == specify_setting) {
		if (mddev->pers->ismaxdegrade && mddev->pers->ismaxdegrade(mddev)) {
			if (!mddev->pers->syno_set_rdev_auto_remap) {
				specify_setting = MD_AUTO_REMAP_MODE_FORCE_ON;
			}
		} else {
			specify_setting = MD_AUTO_REMAP_MODE_FORCE_OFF;
		}
	}

	mddev->auto_remap = specify_setting;

	if (old_setting != mddev->auto_remap || MD_AUTO_REMAP_MODE_ISMAXDEGRADE == mddev->auto_remap) {
		RaidMemberAutoRemapSet(mddev);
	} else {  
		printk("md: %s: current auto_remap = %d\n", mdname(mddev), mddev->auto_remap);
	}

END:
	 
	return old_setting;
}
#endif  

static int read_disk_sb(struct md_rdev *rdev, int size)
{
	char b[BDEVNAME_SIZE];
#ifdef MY_ABC_HERE
	mdp_super_t *sb;
#endif  
	if (!rdev->sb_page) {
		printk(KERN_ERR "md: bug in file %s, line %d\n", __FILE__, __LINE__);
		return -EINVAL;
	}
	if (rdev->sb_loaded)
		return 0;

#ifdef MY_ABC_HERE
	if (!sync_sb_page_io(rdev->bdev, rdev->sb_start, size, rdev->sb_page, READ))
		goto fail;
#else  
	if (!sync_page_io(rdev, 0, size, rdev->sb_page, READ, true))
		goto fail;
#endif  

#ifdef MY_ABC_HERE
	sb = (mdp_super_t*)page_address(rdev->sb_page);
	if (sb->major_version == 0) {
		if (sb->md_magic != MD_SB_MAGIC) {
			SYNOSwapSuperblock0(sb);
		}
	}
#endif  
	rdev->sb_loaded = 1;
	return 0;

fail:
	printk(KERN_WARNING "md: disabled device %s, could not read superblock.\n",
		bdevname(rdev->bdev,b));
	return -EINVAL;
}

static int uuid_equal(mdp_super_t *sb1, mdp_super_t *sb2)
{
	return	sb1->set_uuid0 == sb2->set_uuid0 &&
		sb1->set_uuid1 == sb2->set_uuid1 &&
		sb1->set_uuid2 == sb2->set_uuid2 &&
		sb1->set_uuid3 == sb2->set_uuid3;
}

static int sb_equal(mdp_super_t *sb1, mdp_super_t *sb2)
{
	int ret;
	mdp_super_t *tmp1, *tmp2;

	tmp1 = kmalloc(sizeof(*tmp1),GFP_KERNEL);
	tmp2 = kmalloc(sizeof(*tmp2),GFP_KERNEL);

	if (!tmp1 || !tmp2) {
		ret = 0;
		printk(KERN_INFO "md.c sb_equal(): failed to allocate memory!\n");
		goto abort;
	}

	*tmp1 = *sb1;
	*tmp2 = *sb2;

	tmp1->nr_disks = 0;
	tmp2->nr_disks = 0;

	ret = (memcmp(tmp1, tmp2, MD_SB_GENERIC_CONSTANT_WORDS * 4) == 0);
abort:
	kfree(tmp1);
	kfree(tmp2);
	return ret;
}

static u32 md_csum_fold(u32 csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	return (csum & 0xffff) + (csum >> 16);
}

static unsigned int calc_sb_csum(mdp_super_t *sb)
{
	u64 newcsum = 0;
	u32 *sb32 = (u32*)sb;
	int i;
	unsigned int disk_csum, csum;

	disk_csum = sb->sb_csum;
	sb->sb_csum = 0;

	for (i = 0; i < MD_SB_BYTES/4 ; i++)
		newcsum += sb32[i];
	csum = (newcsum & 0xffffffff) + (newcsum>>32);

#ifdef CONFIG_ALPHA
	 
	sb->sb_csum = md_csum_fold(disk_csum);
#else
	sb->sb_csum = disk_csum;
#endif
	return csum;
}

struct super_type  {
	char		    *name;
	struct module	    *owner;
	int		    (*load_super)(struct md_rdev *rdev,
					  struct md_rdev *refdev,
					  int minor_version);
	int		    (*validate_super)(struct mddev *mddev,
					      struct md_rdev *rdev);
	void		    (*sync_super)(struct mddev *mddev,
					  struct md_rdev *rdev);
	unsigned long long  (*rdev_size_change)(struct md_rdev *rdev,
						sector_t num_sectors);
	int		    (*allow_new_offset)(struct md_rdev *rdev,
						unsigned long long new_offset);
};

int md_check_no_bitmap(struct mddev *mddev)
{
	if (!mddev->bitmap_info.file && !mddev->bitmap_info.offset)
		return 0;
	printk(KERN_ERR "%s: bitmaps are not supported for %s\n",
		mdname(mddev), mddev->pers->name);
	return 1;
}
EXPORT_SYMBOL(md_check_no_bitmap);

#ifdef MY_ABC_HERE
static int
super_90_validate_rdev_event(struct md_rdev *newest_rdev, struct md_rdev *rdev)
{
	mdp_super_t *newest_sb = (mdp_super_t *)page_address(newest_rdev->sb_page);
	mdp_super_t *valid_sb = (mdp_super_t *)page_address(rdev->sb_page);

	if (md_event(valid_sb) < md_event(newest_sb)) {
		return 1;
	}
	return 0;
}
#endif  

static int super_90_load(struct md_rdev *rdev, struct md_rdev *refdev, int minor_version)
{
	char b[BDEVNAME_SIZE], b2[BDEVNAME_SIZE];
	mdp_super_t *sb;
	int ret;

	rdev->sb_start = calc_dev_sboffset(rdev);

	ret = read_disk_sb(rdev, MD_SB_BYTES);
	if (ret) return ret;

	ret = -EINVAL;

	bdevname(rdev->bdev, b);
	sb = page_address(rdev->sb_page);

	if (sb->md_magic != MD_SB_MAGIC) {
		printk(KERN_ERR "md: invalid raid superblock magic on %s\n",
		       b);
		goto abort;
	}

	if (sb->major_version != 0 ||
	    sb->minor_version < 90 ||
	    sb->minor_version > 91) {
		printk(KERN_WARNING "Bad version number %d.%d on %s\n",
			sb->major_version, sb->minor_version,
			b);
		goto abort;
	}

	if (sb->raid_disks <= 0)
		goto abort;

	if (md_csum_fold(calc_sb_csum(sb)) != md_csum_fold(sb->sb_csum)) {
		printk(KERN_WARNING "md: invalid superblock checksum on %s\n",
			b);
		goto abort;
	}

	rdev->preferred_minor = sb->md_minor;
	rdev->data_offset = 0;
	rdev->new_data_offset = 0;
	rdev->sb_size = MD_SB_BYTES;
	rdev->badblocks.shift = -1;

	if (sb->level == LEVEL_MULTIPATH)
		rdev->desc_nr = -1;
	else
		rdev->desc_nr = sb->this_disk.number;

	if (!refdev) {
		ret = 1;
	} else {
		__u64 ev1, ev2;
		mdp_super_t *refsb = page_address(refdev->sb_page);
		if (!uuid_equal(refsb, sb)) {
			printk(KERN_WARNING "md: %s has different UUID to %s\n",
				b, bdevname(refdev->bdev,b2));
			goto abort;
		}
		if (!sb_equal(refsb, sb)) {
			printk(KERN_WARNING "md: %s has same UUID"
			       " but different superblock to %s\n",
			       b, bdevname(refdev->bdev, b2));
			goto abort;
		}
		ev1 = md_event(sb);
		ev2 = md_event(refsb);
		if (ev1 > ev2)
			ret = 1;
		else
			ret = 0;
	}
	rdev->sectors = rdev->sb_start;
	 
	if (rdev->sectors >= (2ULL << 32) && sb->level >= 1)
		rdev->sectors = (2ULL << 32) - 2;

	if (rdev->sectors < ((sector_t)sb->size) * 2 && sb->level >= 1)
		 
		ret = -EINVAL;

 abort:
	return ret;
}

static int super_90_validate(struct mddev *mddev, struct md_rdev *rdev)
{
	mdp_disk_t *desc;
	mdp_super_t *sb = page_address(rdev->sb_page);
	__u64 ev1 = md_event(sb);

	rdev->raid_disk = -1;
	clear_bit(Faulty, &rdev->flags);
	clear_bit(In_sync, &rdev->flags);
	clear_bit(Bitmap_sync, &rdev->flags);
	clear_bit(WriteMostly, &rdev->flags);

	if (mddev->raid_disks == 0) {
		mddev->major_version = 0;
		mddev->minor_version = sb->minor_version;
		mddev->patch_version = sb->patch_version;
		mddev->external = 0;
		mddev->chunk_sectors = sb->chunk_size >> 9;
		mddev->ctime = sb->ctime;
		mddev->utime = sb->utime;
		mddev->level = sb->level;
		mddev->clevel[0] = 0;
		mddev->layout = sb->layout;
		mddev->raid_disks = sb->raid_disks;
		mddev->dev_sectors = ((sector_t)sb->size) * 2;
		mddev->events = ev1;
		mddev->bitmap_info.offset = 0;
		mddev->bitmap_info.space = 0;
		 
		mddev->bitmap_info.default_offset = MD_SB_BYTES >> 9;
		mddev->bitmap_info.default_space = 64*2 - (MD_SB_BYTES >> 9);
		mddev->reshape_backwards = 0;

		if (mddev->minor_version >= 91) {
			mddev->reshape_position = sb->reshape_position;
			mddev->delta_disks = sb->delta_disks;
			mddev->new_level = sb->new_level;
			mddev->new_layout = sb->new_layout;
			mddev->new_chunk_sectors = sb->new_chunk >> 9;
			if (mddev->delta_disks < 0)
				mddev->reshape_backwards = 1;
		} else {
			mddev->reshape_position = MaxSector;
			mddev->delta_disks = 0;
			mddev->new_level = mddev->level;
			mddev->new_layout = mddev->layout;
			mddev->new_chunk_sectors = mddev->chunk_sectors;
		}

		if (sb->state & (1<<MD_SB_CLEAN))
			mddev->recovery_cp = MaxSector;
		else {
			if (sb->events_hi == sb->cp_events_hi &&
				sb->events_lo == sb->cp_events_lo) {
				mddev->recovery_cp = sb->recovery_cp;
			} else
				mddev->recovery_cp = 0;
		}

		memcpy(mddev->uuid+0, &sb->set_uuid0, 4);
		memcpy(mddev->uuid+4, &sb->set_uuid1, 4);
		memcpy(mddev->uuid+8, &sb->set_uuid2, 4);
		memcpy(mddev->uuid+12,&sb->set_uuid3, 4);

		mddev->max_disks = MD_SB_DISKS;

		if (sb->state & (1<<MD_SB_BITMAP_PRESENT) &&
		    mddev->bitmap_info.file == NULL) {
			mddev->bitmap_info.offset =
				mddev->bitmap_info.default_offset;
			mddev->bitmap_info.space =
				mddev->bitmap_info.default_space;
		}

	} else if (mddev->pers == NULL) {
		 
		++ev1;
		if (sb->disks[rdev->desc_nr].state & (
			    (1<<MD_DISK_SYNC) | (1 << MD_DISK_ACTIVE)))
			if (ev1 < mddev->events)
				return -EINVAL;
	} else if (mddev->bitmap) {
		 
		if (ev1 < mddev->bitmap->events_cleared)
			return 0;
		if (ev1 < mddev->events)
			set_bit(Bitmap_sync, &rdev->flags);
	} else {
		if (ev1 < mddev->events)
			 
			return 0;
	}

	if (mddev->level != LEVEL_MULTIPATH) {
		desc = sb->disks + rdev->desc_nr;

		if (desc->state & (1<<MD_DISK_FAULTY))
			set_bit(Faulty, &rdev->flags);
		else if (desc->state & (1<<MD_DISK_SYNC)  ) {
			set_bit(In_sync, &rdev->flags);
			rdev->raid_disk = desc->raid_disk;
			rdev->saved_raid_disk = desc->raid_disk;
#ifdef MY_ABC_HERE
			if (desc->state & (1 << MD_DISK_ERROR)) {
				set_bit(DiskError, &rdev->flags);
			}
#endif  
		} else if (desc->state & (1<<MD_DISK_ACTIVE)) {
			 
			if (mddev->minor_version >= 91) {
				rdev->recovery_offset = 0;
				rdev->raid_disk = desc->raid_disk;
			}
		}
		if (desc->state & (1<<MD_DISK_WRITEMOSTLY))
			set_bit(WriteMostly, &rdev->flags);
	} else  
		set_bit(In_sync, &rdev->flags);
	return 0;
}

static void super_90_sync(struct mddev *mddev, struct md_rdev *rdev)
{
	mdp_super_t *sb;
	struct md_rdev *rdev2;
	int next_spare = mddev->raid_disks;

	int i;
	int active=0, working=0,failed=0,spare=0,nr_disks=0;

	rdev->sb_size = MD_SB_BYTES;

	sb = page_address(rdev->sb_page);

	memset(sb, 0, sizeof(*sb));

	sb->md_magic = MD_SB_MAGIC;
	sb->major_version = mddev->major_version;
	sb->patch_version = mddev->patch_version;
	sb->gvalid_words  = 0;  
	memcpy(&sb->set_uuid0, mddev->uuid+0, 4);
	memcpy(&sb->set_uuid1, mddev->uuid+4, 4);
	memcpy(&sb->set_uuid2, mddev->uuid+8, 4);
	memcpy(&sb->set_uuid3, mddev->uuid+12,4);

	sb->ctime = mddev->ctime;
	sb->level = mddev->level;
	sb->size = mddev->dev_sectors / 2;
	sb->raid_disks = mddev->raid_disks;
	sb->md_minor = mddev->md_minor;
	sb->not_persistent = 0;
	sb->utime = mddev->utime;
	sb->state = 0;
	sb->events_hi = (mddev->events>>32);
	sb->events_lo = (u32)mddev->events;

	if (mddev->reshape_position == MaxSector)
		sb->minor_version = 90;
	else {
		sb->minor_version = 91;
		sb->reshape_position = mddev->reshape_position;
		sb->new_level = mddev->new_level;
		sb->delta_disks = mddev->delta_disks;
		sb->new_layout = mddev->new_layout;
		sb->new_chunk = mddev->new_chunk_sectors << 9;
	}
	mddev->minor_version = sb->minor_version;
	if (mddev->in_sync)
	{
		sb->recovery_cp = mddev->recovery_cp;
		sb->cp_events_hi = (mddev->events>>32);
		sb->cp_events_lo = (u32)mddev->events;
		if (mddev->recovery_cp == MaxSector)
			sb->state = (1<< MD_SB_CLEAN);
	} else
		sb->recovery_cp = 0;

	sb->layout = mddev->layout;
	sb->chunk_size = mddev->chunk_sectors << 9;

	if (mddev->bitmap && mddev->bitmap_info.file == NULL)
		sb->state |= (1<<MD_SB_BITMAP_PRESENT);

	sb->disks[0].state = (1<<MD_DISK_REMOVED);
	rdev_for_each(rdev2, mddev) {
		mdp_disk_t *d;
		int desc_nr;
		int is_active = test_bit(In_sync, &rdev2->flags);

		if (rdev2->raid_disk >= 0 &&
		    sb->minor_version >= 91)
			 
			is_active = 1;
		if (rdev2->raid_disk < 0 ||
		    test_bit(Faulty, &rdev2->flags))
			is_active = 0;
		if (is_active)
			desc_nr = rdev2->raid_disk;
		else
			desc_nr = next_spare++;
		rdev2->desc_nr = desc_nr;
		d = &sb->disks[rdev2->desc_nr];
		nr_disks++;
		d->number = rdev2->desc_nr;
		d->major = MAJOR(rdev2->bdev->bd_dev);
		d->minor = MINOR(rdev2->bdev->bd_dev);
		if (is_active)
			d->raid_disk = rdev2->raid_disk;
		else
			d->raid_disk = rdev2->desc_nr;  
		if (test_bit(Faulty, &rdev2->flags))
			d->state = (1<<MD_DISK_FAULTY);
		else if (is_active) {
			d->state = (1<<MD_DISK_ACTIVE);
			if (test_bit(In_sync, &rdev2->flags))
				d->state |= (1<<MD_DISK_SYNC);
#ifdef MY_ABC_HERE
			if (test_bit(DiskError, &rdev2->flags)) {
				d->state |= (1 << MD_DISK_ERROR);
			}
#endif  
			active++;
			working++;
		} else {
			d->state = 0;
			spare++;
			working++;
		}
		if (test_bit(WriteMostly, &rdev2->flags))
			d->state |= (1<<MD_DISK_WRITEMOSTLY);
	}
	 
	for (i=0 ; i < mddev->raid_disks ; i++) {
		mdp_disk_t *d = &sb->disks[i];
		if (d->state == 0 && d->number == 0) {
			d->number = i;
			d->raid_disk = i;
			d->state = (1<<MD_DISK_REMOVED);
			d->state |= (1<<MD_DISK_FAULTY);
			failed++;
		}
	}
	sb->nr_disks = nr_disks;
	sb->active_disks = active;
	sb->working_disks = working;
	sb->failed_disks = failed;
	sb->spare_disks = spare;

	sb->this_disk = sb->disks[rdev->desc_nr];
	sb->sb_csum = calc_sb_csum(sb);
#ifdef MY_ABC_HERE
#ifdef __LITTLE_ENDIAN
	SYNOSwapSuperblock0(sb);
#endif  
#endif  
}

static unsigned long long
super_90_rdev_size_change(struct md_rdev *rdev, sector_t num_sectors)
{
	if (num_sectors && num_sectors < rdev->mddev->dev_sectors)
		return 0;  
	if (rdev->mddev->bitmap_info.offset)
		return 0;  
	rdev->sb_start = calc_dev_sboffset(rdev);
	if (!num_sectors || num_sectors > rdev->sb_start)
		num_sectors = rdev->sb_start;
	 
	if (num_sectors >= (2ULL << 32) && rdev->mddev->level >= 1)
		num_sectors = (2ULL << 32) - 2;
	md_super_write(rdev->mddev, rdev, rdev->sb_start, rdev->sb_size,
		       rdev->sb_page);
	md_super_wait(rdev->mddev);
	return num_sectors;
}

static int
super_90_allow_new_offset(struct md_rdev *rdev, unsigned long long new_offset)
{
	 
	return new_offset == 0;
}

static __le32 calc_sb_1_csum(struct mdp_superblock_1 *sb)
{
	__le32 disk_csum;
	u32 csum;
	unsigned long long newcsum;
	int size = 256 + le32_to_cpu(sb->max_dev)*2;
	__le32 *isuper = (__le32*)sb;

	disk_csum = sb->sb_csum;
	sb->sb_csum = 0;
	newcsum = 0;
	for (; size >= 4; size -= 4)
		newcsum += le32_to_cpu(*isuper++);

	if (size == 2)
		newcsum += le16_to_cpu(*(__le16*) isuper);

	csum = (newcsum & 0xffffffff) + (newcsum >> 32);
	sb->sb_csum = disk_csum;
	return cpu_to_le32(csum);
}

static int md_set_badblocks(struct badblocks *bb, sector_t s, int sectors,
			    int acknowledged);
static int super_1_load(struct md_rdev *rdev, struct md_rdev *refdev, int minor_version)
{
	struct mdp_superblock_1 *sb;
	int ret;
	sector_t sb_start;
	sector_t sectors;
	char b[BDEVNAME_SIZE], b2[BDEVNAME_SIZE];
	int bmask;

	switch(minor_version) {
	case 0:
		sb_start = i_size_read(rdev->bdev->bd_inode) >> 9;
		sb_start -= 8*2;
		sb_start &= ~(sector_t)(4*2-1);
		break;
	case 1:
		sb_start = 0;
		break;
	case 2:
		sb_start = 8;
		break;
	default:
		return -EINVAL;
	}
	rdev->sb_start = sb_start;

	ret = read_disk_sb(rdev, 4096);
	if (ret) return ret;

	sb = page_address(rdev->sb_page);

	if (sb->magic != cpu_to_le32(MD_SB_MAGIC) ||
	    sb->major_version != cpu_to_le32(1) ||
	    le32_to_cpu(sb->max_dev) > (4096-256)/2 ||
	    le64_to_cpu(sb->super_offset) != rdev->sb_start ||
	    (le32_to_cpu(sb->feature_map) & ~MD_FEATURE_ALL) != 0)
		return -EINVAL;

	if (calc_sb_1_csum(sb) != sb->sb_csum) {
		printk("md: invalid superblock checksum on %s\n",
			bdevname(rdev->bdev,b));
		return -EINVAL;
	}
	if (le64_to_cpu(sb->data_size) < 10) {
		printk("md: data_size too small on %s\n",
		       bdevname(rdev->bdev,b));
		return -EINVAL;
	}
	if (sb->pad0 ||
	    sb->pad3[0] ||
	    memcmp(sb->pad3, sb->pad3+1, sizeof(sb->pad3) - sizeof(sb->pad3[1])))
		 
		return -EINVAL;

	rdev->preferred_minor = 0xffff;
	rdev->data_offset = le64_to_cpu(sb->data_offset);
	rdev->new_data_offset = rdev->data_offset;
	if ((le32_to_cpu(sb->feature_map) & MD_FEATURE_RESHAPE_ACTIVE) &&
	    (le32_to_cpu(sb->feature_map) & MD_FEATURE_NEW_OFFSET))
		rdev->new_data_offset += (s32)le32_to_cpu(sb->new_offset);
	atomic_set(&rdev->corrected_errors, le32_to_cpu(sb->cnt_corrected_read));

	rdev->sb_size = le32_to_cpu(sb->max_dev) * 2 + 256;
	bmask = queue_logical_block_size(rdev->bdev->bd_disk->queue)-1;
	if (rdev->sb_size & bmask)
		rdev->sb_size = (rdev->sb_size | bmask) + 1;

	if (minor_version
	    && rdev->data_offset < sb_start + (rdev->sb_size/512))
		return -EINVAL;
	if (minor_version
	    && rdev->new_data_offset < sb_start + (rdev->sb_size/512))
		return -EINVAL;

	if (sb->level == cpu_to_le32(LEVEL_MULTIPATH))
		rdev->desc_nr = -1;
	else
		rdev->desc_nr = le32_to_cpu(sb->dev_number);

	if (!rdev->bb_page) {
		rdev->bb_page = alloc_page(GFP_KERNEL);
		if (!rdev->bb_page)
			return -ENOMEM;
	}
	if ((le32_to_cpu(sb->feature_map) & MD_FEATURE_BAD_BLOCKS) &&
	    rdev->badblocks.count == 0) {
		 
		s32 offset;
		sector_t bb_sector;
		u64 *bbp;
		int i;
		int sectors = le16_to_cpu(sb->bblog_size);
		if (sectors > (PAGE_SIZE / 512))
			return -EINVAL;
		offset = le32_to_cpu(sb->bblog_offset);
		if (offset == 0)
			return -EINVAL;
		bb_sector = (long long)offset;
		if (!sync_page_io(rdev, bb_sector, sectors << 9,
				  rdev->bb_page, READ, true))
			return -EIO;
		bbp = (u64 *)page_address(rdev->bb_page);
		rdev->badblocks.shift = sb->bblog_shift;
		for (i = 0 ; i < (sectors << (9-3)) ; i++, bbp++) {
			u64 bb = le64_to_cpu(*bbp);
			int count = bb & (0x3ff);
			u64 sector = bb >> 10;
			sector <<= sb->bblog_shift;
			count <<= sb->bblog_shift;
			if (bb + 1 == 0)
				break;
			if (md_set_badblocks(&rdev->badblocks,
					     sector, count, 1) == 0)
				return -EINVAL;
		}
	} else if (sb->bblog_offset != 0)
		rdev->badblocks.shift = 0;

	if (!refdev) {
		ret = 1;
	} else {
		__u64 ev1, ev2;
		struct mdp_superblock_1 *refsb = page_address(refdev->sb_page);

		if (memcmp(sb->set_uuid, refsb->set_uuid, 16) != 0 ||
		    sb->level != refsb->level ||
		    sb->layout != refsb->layout ||
		    sb->chunksize != refsb->chunksize) {
			printk(KERN_WARNING "md: %s has strangely different"
				" superblock to %s\n",
				bdevname(rdev->bdev,b),
				bdevname(refdev->bdev,b2));
			return -EINVAL;
		}
		ev1 = le64_to_cpu(sb->events);
		ev2 = le64_to_cpu(refsb->events);

		if (ev1 > ev2)
			ret = 1;
		else
			ret = 0;
	}
	if (minor_version) {
		sectors = (i_size_read(rdev->bdev->bd_inode) >> 9);
		sectors -= rdev->data_offset;
	} else
		sectors = rdev->sb_start;
	if (sectors < le64_to_cpu(sb->data_size))
		return -EINVAL;
	rdev->sectors = le64_to_cpu(sb->data_size);
	return ret;
}

static int super_1_validate(struct mddev *mddev, struct md_rdev *rdev)
{
	struct mdp_superblock_1 *sb = page_address(rdev->sb_page);
	__u64 ev1 = le64_to_cpu(sb->events);

	rdev->raid_disk = -1;
	clear_bit(Faulty, &rdev->flags);
	clear_bit(In_sync, &rdev->flags);
	clear_bit(Bitmap_sync, &rdev->flags);
	clear_bit(WriteMostly, &rdev->flags);

	if (mddev->raid_disks == 0) {
		mddev->major_version = 1;
		mddev->patch_version = 0;
		mddev->external = 0;
		mddev->chunk_sectors = le32_to_cpu(sb->chunksize);
		mddev->ctime = le64_to_cpu(sb->ctime) & ((1ULL << 32)-1);
		mddev->utime = le64_to_cpu(sb->utime) & ((1ULL << 32)-1);
		mddev->level = le32_to_cpu(sb->level);
		mddev->clevel[0] = 0;
		mddev->layout = le32_to_cpu(sb->layout);
		mddev->raid_disks = le32_to_cpu(sb->raid_disks);
		mddev->dev_sectors = le64_to_cpu(sb->size);
		mddev->events = ev1;
		mddev->bitmap_info.offset = 0;
		mddev->bitmap_info.space = 0;
		 
		mddev->bitmap_info.default_offset = 1024 >> 9;
		mddev->bitmap_info.default_space = (4096-1024) >> 9;
		mddev->reshape_backwards = 0;

		mddev->recovery_cp = le64_to_cpu(sb->resync_offset);
		memcpy(mddev->uuid, sb->set_uuid, 16);

		mddev->max_disks =  (4096-256)/2;

		if ((le32_to_cpu(sb->feature_map) & MD_FEATURE_BITMAP_OFFSET) &&
		    mddev->bitmap_info.file == NULL) {
			mddev->bitmap_info.offset =
				(__s32)le32_to_cpu(sb->bitmap_offset);
			 
			if (mddev->minor_version > 0)
				mddev->bitmap_info.space = 0;
			else if (mddev->bitmap_info.offset > 0)
				mddev->bitmap_info.space =
					8 - mddev->bitmap_info.offset;
			else
				mddev->bitmap_info.space =
					-mddev->bitmap_info.offset;
		}

		if ((le32_to_cpu(sb->feature_map) & MD_FEATURE_RESHAPE_ACTIVE)) {
			mddev->reshape_position = le64_to_cpu(sb->reshape_position);
			mddev->delta_disks = le32_to_cpu(sb->delta_disks);
			mddev->new_level = le32_to_cpu(sb->new_level);
			mddev->new_layout = le32_to_cpu(sb->new_layout);
			mddev->new_chunk_sectors = le32_to_cpu(sb->new_chunk);
			if (mddev->delta_disks < 0 ||
			    (mddev->delta_disks == 0 &&
			     (le32_to_cpu(sb->feature_map)
			      & MD_FEATURE_RESHAPE_BACKWARDS)))
				mddev->reshape_backwards = 1;
		} else {
			mddev->reshape_position = MaxSector;
			mddev->delta_disks = 0;
			mddev->new_level = mddev->level;
			mddev->new_layout = mddev->layout;
			mddev->new_chunk_sectors = mddev->chunk_sectors;
		}

	} else if (mddev->pers == NULL) {
		 
		++ev1;
		if (rdev->desc_nr >= 0 &&
		    rdev->desc_nr < le32_to_cpu(sb->max_dev) &&
		    (le16_to_cpu(sb->dev_roles[rdev->desc_nr]) < MD_DISK_ROLE_MAX ||
		     le16_to_cpu(sb->dev_roles[rdev->desc_nr]) == MD_DISK_ROLE_JOURNAL))
			if (ev1 < mddev->events)
				return -EINVAL;
	} else if (mddev->bitmap) {
		 
		if (ev1 < mddev->bitmap->events_cleared)
			return 0;
		if (ev1 < mddev->events)
			set_bit(Bitmap_sync, &rdev->flags);
	} else {
		if (ev1 < mddev->events)
			 
			return 0;
	}
	if (mddev->level != LEVEL_MULTIPATH) {
		int role;
		if (rdev->desc_nr < 0 ||
		    rdev->desc_nr >= le32_to_cpu(sb->max_dev)) {
			role = MD_DISK_ROLE_SPARE;
			rdev->desc_nr = -1;
		} else
			role = le16_to_cpu(sb->dev_roles[rdev->desc_nr]);
		switch(role) {
		case MD_DISK_ROLE_SPARE:  
			break;
		case MD_DISK_ROLE_FAULTY:  
			set_bit(Faulty, &rdev->flags);
			break;
		case MD_DISK_ROLE_JOURNAL:  
			if (!(le32_to_cpu(sb->feature_map) & MD_FEATURE_JOURNAL)) {
				 
				printk(KERN_WARNING
				  "md: journal device provided without journal feature, ignoring the device\n");
				return -EINVAL;
			}
			set_bit(Journal, &rdev->flags);
			rdev->journal_tail = le64_to_cpu(sb->journal_tail);
			if (mddev->recovery_cp == MaxSector)
				set_bit(MD_JOURNAL_CLEAN, &mddev->flags);
			rdev->raid_disk = 0;
			break;
		default:
			rdev->saved_raid_disk = role;
			if ((le32_to_cpu(sb->feature_map) &
			     MD_FEATURE_RECOVERY_OFFSET)) {
				rdev->recovery_offset = le64_to_cpu(sb->recovery_offset);
				if (!(le32_to_cpu(sb->feature_map) &
				      MD_FEATURE_RECOVERY_BITMAP))
					rdev->saved_raid_disk = -1;
			} else
				set_bit(In_sync, &rdev->flags);
#ifdef MY_ABC_HERE
			if (role & 0x8000) {
				set_bit(DiskError, &rdev->flags);
				role &= ~(0x8000);
				sb->dev_roles[rdev->desc_nr] = cpu_to_le16(role);
			}
#endif  
			rdev->raid_disk = role;
			break;
		}
		if (sb->devflags & WriteMostly1)
			set_bit(WriteMostly, &rdev->flags);
		if (le32_to_cpu(sb->feature_map) & MD_FEATURE_REPLACEMENT)
			set_bit(Replacement, &rdev->flags);
		if (le32_to_cpu(sb->feature_map) & MD_FEATURE_JOURNAL)
			set_bit(MD_HAS_JOURNAL, &mddev->flags);
	} else  
		set_bit(In_sync, &rdev->flags);

	return 0;
}

static void super_1_sync(struct mddev *mddev, struct md_rdev *rdev)
{
	struct mdp_superblock_1 *sb;
	struct md_rdev *rdev2;
	int max_dev, i;
	 
	sb = page_address(rdev->sb_page);

	sb->feature_map = 0;
	sb->pad0 = 0;
	sb->recovery_offset = cpu_to_le64(0);
	memset(sb->pad3, 0, sizeof(sb->pad3));

	sb->utime = cpu_to_le64((__u64)mddev->utime);
	sb->events = cpu_to_le64(mddev->events);
	if (mddev->in_sync)
		sb->resync_offset = cpu_to_le64(mddev->recovery_cp);
	else if (test_bit(MD_JOURNAL_CLEAN, &mddev->flags))
		sb->resync_offset = cpu_to_le64(MaxSector);
	else
		sb->resync_offset = cpu_to_le64(0);

	sb->cnt_corrected_read = cpu_to_le32(atomic_read(&rdev->corrected_errors));

	sb->raid_disks = cpu_to_le32(mddev->raid_disks);
	sb->size = cpu_to_le64(mddev->dev_sectors);
	sb->chunksize = cpu_to_le32(mddev->chunk_sectors);
	sb->level = cpu_to_le32(mddev->level);
	sb->layout = cpu_to_le32(mddev->layout);

	if (test_bit(WriteMostly, &rdev->flags))
		sb->devflags |= WriteMostly1;
	else
		sb->devflags &= ~WriteMostly1;
	sb->data_offset = cpu_to_le64(rdev->data_offset);
	sb->data_size = cpu_to_le64(rdev->sectors);

	if (mddev->bitmap && mddev->bitmap_info.file == NULL) {
		sb->bitmap_offset = cpu_to_le32((__u32)mddev->bitmap_info.offset);
		sb->feature_map = cpu_to_le32(MD_FEATURE_BITMAP_OFFSET);
	}

	if (rdev->raid_disk >= 0 && !test_bit(Journal, &rdev->flags) &&
	    !test_bit(In_sync, &rdev->flags)) {
		sb->feature_map |=
			cpu_to_le32(MD_FEATURE_RECOVERY_OFFSET);
		sb->recovery_offset =
			cpu_to_le64(rdev->recovery_offset);
		if (rdev->saved_raid_disk >= 0 && mddev->bitmap)
			sb->feature_map |=
				cpu_to_le32(MD_FEATURE_RECOVERY_BITMAP);
	}
	 
	if (test_bit(Journal, &rdev->flags))
		sb->journal_tail = cpu_to_le64(rdev->journal_tail);
	if (test_bit(Replacement, &rdev->flags))
		sb->feature_map |=
			cpu_to_le32(MD_FEATURE_REPLACEMENT);

	if (mddev->reshape_position != MaxSector) {
		sb->feature_map |= cpu_to_le32(MD_FEATURE_RESHAPE_ACTIVE);
		sb->reshape_position = cpu_to_le64(mddev->reshape_position);
		sb->new_layout = cpu_to_le32(mddev->new_layout);
		sb->delta_disks = cpu_to_le32(mddev->delta_disks);
		sb->new_level = cpu_to_le32(mddev->new_level);
		sb->new_chunk = cpu_to_le32(mddev->new_chunk_sectors);
		if (mddev->delta_disks == 0 &&
		    mddev->reshape_backwards)
			sb->feature_map
				|= cpu_to_le32(MD_FEATURE_RESHAPE_BACKWARDS);
		if (rdev->new_data_offset != rdev->data_offset) {
			sb->feature_map
				|= cpu_to_le32(MD_FEATURE_NEW_OFFSET);
			sb->new_offset = cpu_to_le32((__u32)(rdev->new_data_offset
							     - rdev->data_offset));
		}
	}

	if (mddev_is_clustered(mddev))
		sb->feature_map |= cpu_to_le32(MD_FEATURE_CLUSTERED);

	if (rdev->badblocks.count == 0)
		  ;
	else if (sb->bblog_offset == 0)
		 
		md_error(mddev, rdev);
	else {
		struct badblocks *bb = &rdev->badblocks;
		u64 *bbp = (u64 *)page_address(rdev->bb_page);
		u64 *p = bb->page;
		sb->feature_map |= cpu_to_le32(MD_FEATURE_BAD_BLOCKS);
		if (bb->changed) {
			unsigned seq;

retry:
			seq = read_seqbegin(&bb->lock);

			memset(bbp, 0xff, PAGE_SIZE);

			for (i = 0 ; i < bb->count ; i++) {
				u64 internal_bb = p[i];
				u64 store_bb = ((BB_OFFSET(internal_bb) << 10)
						| BB_LEN(internal_bb));
				bbp[i] = cpu_to_le64(store_bb);
			}
			bb->changed = 0;
			if (read_seqretry(&bb->lock, seq))
				goto retry;

			bb->sector = (rdev->sb_start +
				      (int)le32_to_cpu(sb->bblog_offset));
			bb->size = le16_to_cpu(sb->bblog_size);
		}
	}

	max_dev = 0;
	rdev_for_each(rdev2, mddev)
		if (rdev2->desc_nr+1 > max_dev)
			max_dev = rdev2->desc_nr+1;

	if (max_dev > le32_to_cpu(sb->max_dev)) {
		int bmask;
		sb->max_dev = cpu_to_le32(max_dev);
		rdev->sb_size = max_dev * 2 + 256;
		bmask = queue_logical_block_size(rdev->bdev->bd_disk->queue)-1;
		if (rdev->sb_size & bmask)
			rdev->sb_size = (rdev->sb_size | bmask) + 1;
	} else
		max_dev = le32_to_cpu(sb->max_dev);

	for (i=0; i<max_dev;i++)
		sb->dev_roles[i] = cpu_to_le16(MD_DISK_ROLE_FAULTY);

	if (test_bit(MD_HAS_JOURNAL, &mddev->flags))
		sb->feature_map |= cpu_to_le32(MD_FEATURE_JOURNAL);

	rdev_for_each(rdev2, mddev) {
		i = rdev2->desc_nr;
		if (test_bit(Faulty, &rdev2->flags))
			sb->dev_roles[i] = cpu_to_le16(MD_DISK_ROLE_FAULTY);
		else if (test_bit(In_sync, &rdev2->flags))
#ifdef MY_ABC_HERE
		{
			if (test_bit(DiskError, &rdev2->flags)) {
				 
				sb->dev_roles[i] = cpu_to_le16(0x8000 | rdev2->raid_disk);
			} else {
				sb->dev_roles[i] = cpu_to_le16(rdev2->raid_disk);
			}
		}
#else  
			sb->dev_roles[i] = cpu_to_le16(rdev2->raid_disk);
#endif  
		else if (test_bit(Journal, &rdev2->flags))
			sb->dev_roles[i] = cpu_to_le16(MD_DISK_ROLE_JOURNAL);
		else if (rdev2->raid_disk >= 0)
			sb->dev_roles[i] = cpu_to_le16(rdev2->raid_disk);
		else
			sb->dev_roles[i] = cpu_to_le16(MD_DISK_ROLE_SPARE);
	}

	sb->sb_csum = calc_sb_1_csum(sb);
}

static unsigned long long
super_1_rdev_size_change(struct md_rdev *rdev, sector_t num_sectors)
{
	struct mdp_superblock_1 *sb;
	sector_t max_sectors;
	if (num_sectors && num_sectors < rdev->mddev->dev_sectors)
		return 0;  
	if (rdev->data_offset != rdev->new_data_offset)
		return 0;  
	if (rdev->sb_start < rdev->data_offset) {
		 
		max_sectors = i_size_read(rdev->bdev->bd_inode) >> 9;
		max_sectors -= rdev->data_offset;
		if (!num_sectors || num_sectors > max_sectors)
			num_sectors = max_sectors;
	} else if (rdev->mddev->bitmap_info.offset) {
		 
		return 0;
	} else {
		 
		sector_t sb_start;
		sb_start = (i_size_read(rdev->bdev->bd_inode) >> 9) - 8*2;
		sb_start &= ~(sector_t)(4*2 - 1);
		max_sectors = rdev->sectors + sb_start - rdev->sb_start;
		if (!num_sectors || num_sectors > max_sectors)
			num_sectors = max_sectors;
		rdev->sb_start = sb_start;
	}
	sb = page_address(rdev->sb_page);
	sb->data_size = cpu_to_le64(num_sectors);
	sb->super_offset = rdev->sb_start;
	sb->sb_csum = calc_sb_1_csum(sb);
	md_super_write(rdev->mddev, rdev, rdev->sb_start, rdev->sb_size,
		       rdev->sb_page);
	md_super_wait(rdev->mddev);
	return num_sectors;

}

static int
super_1_allow_new_offset(struct md_rdev *rdev,
			 unsigned long long new_offset)
{
	 
	struct bitmap *bitmap;
	if (new_offset >= rdev->data_offset)
		return 1;

	if (rdev->mddev->minor_version == 0)
		return 1;

	if (rdev->sb_start + (32+4)*2 > new_offset)
		return 0;
	bitmap = rdev->mddev->bitmap;
	if (bitmap && !rdev->mddev->bitmap_info.file &&
	    rdev->sb_start + rdev->mddev->bitmap_info.offset +
	    bitmap->storage.file_pages * (PAGE_SIZE>>9) > new_offset)
		return 0;
	if (rdev->badblocks.sector + rdev->badblocks.size > new_offset)
		return 0;

	return 1;
}

static struct super_type super_types[] = {
	[0] = {
		.name	= "0.90.0",
		.owner	= THIS_MODULE,
		.load_super	    = super_90_load,
		.validate_super	    = super_90_validate,
		.sync_super	    = super_90_sync,
		.rdev_size_change   = super_90_rdev_size_change,
		.allow_new_offset   = super_90_allow_new_offset,
	},
	[1] = {
		.name	= "md-1",
		.owner	= THIS_MODULE,
		.load_super	    = super_1_load,
		.validate_super	    = super_1_validate,
		.sync_super	    = super_1_sync,
		.rdev_size_change   = super_1_rdev_size_change,
		.allow_new_offset   = super_1_allow_new_offset,
	},
};

static void sync_super(struct mddev *mddev, struct md_rdev *rdev)
{
	if (mddev->sync_super) {
		mddev->sync_super(mddev, rdev);
		return;
	}

	BUG_ON(mddev->major_version >= ARRAY_SIZE(super_types));

	super_types[mddev->major_version].sync_super(mddev, rdev);
}

static int match_mddev_units(struct mddev *mddev1, struct mddev *mddev2)
{
	struct md_rdev *rdev, *rdev2;

	rcu_read_lock();
	rdev_for_each_rcu(rdev, mddev1) {
		if (test_bit(Faulty, &rdev->flags) ||
		    test_bit(Journal, &rdev->flags) ||
		    rdev->raid_disk == -1)
			continue;
		rdev_for_each_rcu(rdev2, mddev2) {
			if (test_bit(Faulty, &rdev2->flags) ||
			    test_bit(Journal, &rdev2->flags) ||
			    rdev2->raid_disk == -1)
				continue;
			if (rdev->bdev->bd_contains ==
			    rdev2->bdev->bd_contains) {
				rcu_read_unlock();
				return 1;
			}
		}
	}
	rcu_read_unlock();
	return 0;
}

static LIST_HEAD(pending_raid_disks);

int md_integrity_register(struct mddev *mddev)
{
	struct md_rdev *rdev, *reference = NULL;

	if (list_empty(&mddev->disks))
		return 0;  
	if (!mddev->gendisk || blk_get_integrity(mddev->gendisk))
		return 0;  
	rdev_for_each(rdev, mddev) {
		 
		if (test_bit(Faulty, &rdev->flags))
			continue;
		if (rdev->raid_disk < 0)
			continue;
		if (!reference) {
			 
			reference = rdev;
			continue;
		}
		 
		if (blk_integrity_compare(reference->bdev->bd_disk,
				rdev->bdev->bd_disk) < 0)
			return -EINVAL;
	}
	if (!reference || !bdev_get_integrity(reference->bdev))
		return 0;
	 
	blk_integrity_register(mddev->gendisk,
			       bdev_get_integrity(reference->bdev));

	printk(KERN_NOTICE "md: data integrity enabled on %s\n", mdname(mddev));
	if (bioset_integrity_create(mddev->bio_set, BIO_POOL_SIZE)) {
		printk(KERN_ERR "md: failed to create integrity pool for %s\n",
		       mdname(mddev));
		return -EINVAL;
	}
	return 0;
}
EXPORT_SYMBOL(md_integrity_register);

int md_integrity_add_rdev(struct md_rdev *rdev, struct mddev *mddev)
{
	struct blk_integrity *bi_rdev;
	struct blk_integrity *bi_mddev;
	char name[BDEVNAME_SIZE];

	if (!mddev->gendisk)
		return 0;

	bi_rdev = bdev_get_integrity(rdev->bdev);
	bi_mddev = blk_get_integrity(mddev->gendisk);

	if (!bi_mddev)  
		return 0;

	if (blk_integrity_compare(mddev->gendisk, rdev->bdev->bd_disk) != 0) {
		printk(KERN_NOTICE "%s: incompatible integrity profile for %s\n",
				mdname(mddev), bdevname(rdev->bdev, name));
		return -ENXIO;
	}

	return 0;
}
EXPORT_SYMBOL(md_integrity_add_rdev);

static int bind_rdev_to_array(struct md_rdev *rdev, struct mddev *mddev)
{
	char b[BDEVNAME_SIZE];
	struct kobject *ko;
	int err;

	if (find_rdev(mddev, rdev->bdev->bd_dev))
		return -EEXIST;

	if (rdev->sectors && (mddev->dev_sectors == 0 ||
			rdev->sectors < mddev->dev_sectors)) {
		if (mddev->pers) {
			 
			if (mddev->level > 0)
				return -ENOSPC;
		} else
			mddev->dev_sectors = rdev->sectors;
	}

	rcu_read_lock();
	if (rdev->desc_nr < 0) {
		int choice = 0;
		if (mddev->pers)
			choice = mddev->raid_disks;
		while (md_find_rdev_nr_rcu(mddev, choice))
			choice++;
		rdev->desc_nr = choice;
	} else {
		if (md_find_rdev_nr_rcu(mddev, rdev->desc_nr)) {
			rcu_read_unlock();
			return -EBUSY;
		}
	}
	rcu_read_unlock();
	if (mddev->max_disks && rdev->desc_nr >= mddev->max_disks) {
		printk(KERN_WARNING "md: %s: array is limited to %d devices\n",
		       mdname(mddev), mddev->max_disks);
		return -EBUSY;
	}
	bdevname(rdev->bdev,b);
	strreplace(b, '/', '!');

	rdev->mddev = mddev;
	printk(KERN_INFO "md: bind<%s>\n", b);

	if ((err = kobject_add(&rdev->kobj, &mddev->kobj, "dev-%s", b)))
		goto fail;

	ko = &part_to_dev(rdev->bdev->bd_part)->kobj;
	if (sysfs_create_link(&rdev->kobj, ko, "block"))
		 ;
	rdev->sysfs_state = sysfs_get_dirent_safe(rdev->kobj.sd, "state");

	list_add_rcu(&rdev->same_set, &mddev->disks);
	bd_link_disk_holder(rdev->bdev, mddev->gendisk);

	mddev->recovery_disabled++;

	return 0;

 fail:
	printk(KERN_WARNING "md: failed to register dev-%s for %s\n",
	       b, mdname(mddev));
	return err;
}

static void md_delayed_delete(struct work_struct *ws)
{
	struct md_rdev *rdev = container_of(ws, struct md_rdev, del_work);
	kobject_del(&rdev->kobj);
	kobject_put(&rdev->kobj);
}

static void unbind_rdev_from_array(struct md_rdev *rdev)
{
	char b[BDEVNAME_SIZE];

	bd_unlink_disk_holder(rdev->bdev, rdev->mddev->gendisk);
	list_del_rcu(&rdev->same_set);
	printk(KERN_INFO "md: unbind<%s>\n", bdevname(rdev->bdev,b));
	rdev->mddev = NULL;
	sysfs_remove_link(&rdev->kobj, "block");
	sysfs_put(rdev->sysfs_state);
	rdev->sysfs_state = NULL;
	rdev->badblocks.count = 0;
	 
	synchronize_rcu();
	INIT_WORK(&rdev->del_work, md_delayed_delete);
	kobject_get(&rdev->kobj);
	queue_work(md_misc_wq, &rdev->del_work);
}

static int lock_rdev(struct md_rdev *rdev, dev_t dev, int shared)
{
	int err = 0;
	struct block_device *bdev;
	char b[BDEVNAME_SIZE];

	bdev = blkdev_get_by_dev(dev, FMODE_READ|FMODE_WRITE|FMODE_EXCL,
				 shared ? (struct md_rdev *)lock_rdev : rdev);
	if (IS_ERR(bdev)) {
		printk(KERN_ERR "md: could not open %s.\n",
			__bdevname(dev, b));
		return PTR_ERR(bdev);
	}
	rdev->bdev = bdev;
	return err;
}

static void unlock_rdev(struct md_rdev *rdev)
{
	struct block_device *bdev = rdev->bdev;
	rdev->bdev = NULL;
	blkdev_put(bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
}

void md_autodetect_dev(dev_t dev);

static void export_rdev(struct md_rdev *rdev)
{
	char b[BDEVNAME_SIZE];

	printk(KERN_INFO "md: export_rdev(%s)\n",
		bdevname(rdev->bdev,b));
	md_rdev_clear(rdev);
#ifdef MY_ABC_HERE
	free_disk_wakeup_page(rdev);
#endif  
#ifndef MODULE
	if (test_bit(AutoDetected, &rdev->flags))
		md_autodetect_dev(rdev->bdev->bd_dev);
#endif
	unlock_rdev(rdev);
	kobject_put(&rdev->kobj);
}

void md_kick_rdev_from_array(struct md_rdev *rdev)
{
#ifdef MY_ABC_HERE
	RaidRemapModeSet(rdev->bdev, 0);
#endif  
	unbind_rdev_from_array(rdev);
	export_rdev(rdev);
}
EXPORT_SYMBOL_GPL(md_kick_rdev_from_array);

static void export_array(struct mddev *mddev)
{
	struct md_rdev *rdev;

	while (!list_empty(&mddev->disks)) {
		rdev = list_first_entry(&mddev->disks, struct md_rdev,
					same_set);
		md_kick_rdev_from_array(rdev);
	}
	mddev->raid_disks = 0;
	mddev->major_version = 0;
}

static void sync_sbs(struct mddev *mddev, int nospares)
{
	 
	struct md_rdev *rdev;
	rdev_for_each(rdev, mddev) {
		if (rdev->sb_events == mddev->events ||
		    (nospares &&
		     rdev->raid_disk < 0 &&
		     rdev->sb_events+1 == mddev->events)) {
			 
			rdev->sb_loaded = 2;
		} else {
			sync_super(mddev, rdev);
			rdev->sb_loaded = 1;
		}
	}
}

static bool does_sb_need_changing(struct mddev *mddev)
{
	struct md_rdev *rdev;
	struct mdp_superblock_1 *sb;
	int role;

	rdev_for_each(rdev, mddev)
		if ((rdev->raid_disk >= 0) && !test_bit(Faulty, &rdev->flags))
			break;

	if (!rdev)
		return false;

	sb = page_address(rdev->sb_page);
	 
	rdev_for_each(rdev, mddev) {
		role = le16_to_cpu(sb->dev_roles[rdev->desc_nr]);
		 
		if (role == 0xffff && rdev->raid_disk >=0 &&
		    !test_bit(Faulty, &rdev->flags))
			return true;
		 
		if (test_bit(Faulty, &rdev->flags) && (role < 0xfffd))
			return true;
	}

	if ((mddev->dev_sectors != le64_to_cpu(sb->size)) ||
	    (mddev->reshape_position != le64_to_cpu(sb->reshape_position)) ||
	    (mddev->layout != le64_to_cpu(sb->layout)) ||
	    (mddev->raid_disks != le32_to_cpu(sb->raid_disks)) ||
	    (mddev->chunk_sectors != le32_to_cpu(sb->chunksize)))
		return true;

	return false;
}

void md_update_sb(struct mddev *mddev, int force_change)
{
	struct md_rdev *rdev;
	int sync_req;
	int nospares = 0;
	int any_badblocks_changed = 0;
	int ret = -1;

	if (mddev->ro) {
		if (force_change)
			set_bit(MD_CHANGE_DEVS, &mddev->flags);
		return;
	}

	if (mddev_is_clustered(mddev)) {
		if (test_and_clear_bit(MD_CHANGE_DEVS, &mddev->flags))
			force_change = 1;
		ret = md_cluster_ops->metadata_update_start(mddev);
		 
		if (!does_sb_need_changing(mddev)) {
			if (ret == 0)
				md_cluster_ops->metadata_update_cancel(mddev);
			clear_bit(MD_CHANGE_PENDING, &mddev->flags);
			return;
		}
	}
repeat:
	 
	rdev_for_each(rdev, mddev) {
		if (rdev->raid_disk >= 0 &&
		    mddev->delta_disks >= 0 &&
		    !test_bit(Journal, &rdev->flags) &&
		    !test_bit(In_sync, &rdev->flags) &&
		    mddev->curr_resync_completed > rdev->recovery_offset)
				rdev->recovery_offset = mddev->curr_resync_completed;

	}
	if (!mddev->persistent) {
		clear_bit(MD_CHANGE_CLEAN, &mddev->flags);
		clear_bit(MD_CHANGE_DEVS, &mddev->flags);
		if (!mddev->external) {
			clear_bit(MD_CHANGE_PENDING, &mddev->flags);
			rdev_for_each(rdev, mddev) {
				if (rdev->badblocks.changed) {
					rdev->badblocks.changed = 0;
					md_ack_all_badblocks(&rdev->badblocks);
					md_error(mddev, rdev);
				}
				clear_bit(Blocked, &rdev->flags);
				clear_bit(BlockedBadBlocks, &rdev->flags);
				wake_up(&rdev->blocked_wait);
			}
		}
		wake_up(&mddev->sb_wait);
		return;
	}

	spin_lock(&mddev->lock);

	mddev->utime = get_seconds();

	if (test_and_clear_bit(MD_CHANGE_DEVS, &mddev->flags))
		force_change = 1;
	if (test_and_clear_bit(MD_CHANGE_CLEAN, &mddev->flags))
		 
		nospares = 1;
	if (force_change)
		nospares = 0;
	if (mddev->degraded)
		 
		nospares = 0;

	sync_req = mddev->in_sync;

	if (nospares
	    && (mddev->in_sync && mddev->recovery_cp == MaxSector)
	    && mddev->can_decrease_events
	    && mddev->events != 1) {
		mddev->events--;
		mddev->can_decrease_events = 0;
	} else {
		 
		mddev->events ++;
		mddev->can_decrease_events = nospares;
	}

	WARN_ON(mddev->events == 0);

	rdev_for_each(rdev, mddev) {
		if (rdev->badblocks.changed)
			any_badblocks_changed++;
		if (test_bit(Faulty, &rdev->flags))
			set_bit(FaultRecorded, &rdev->flags);
	}

	sync_sbs(mddev, nospares);
	spin_unlock(&mddev->lock);

	pr_debug("md: updating %s RAID superblock on device (in sync %d)\n",
		 mdname(mddev), mddev->in_sync);

	bitmap_update_sb(mddev->bitmap);
	rdev_for_each(rdev, mddev) {
		char b[BDEVNAME_SIZE];

		if (rdev->sb_loaded != 1)
			continue;  

		if (!test_bit(Faulty, &rdev->flags)) {
			md_super_write(mddev,rdev,
				       rdev->sb_start, rdev->sb_size,
				       rdev->sb_page);
			pr_debug("md: (write) %s's sb offset: %llu\n",
				 bdevname(rdev->bdev, b),
				 (unsigned long long)rdev->sb_start);
			rdev->sb_events = mddev->events;
			if (rdev->badblocks.size) {
				md_super_write(mddev, rdev,
					       rdev->badblocks.sector,
					       rdev->badblocks.size << 9,
					       rdev->bb_page);
				rdev->badblocks.size = 0;
			}

		} else
			pr_debug("md: %s (skipping faulty)\n",
				 bdevname(rdev->bdev, b));

		if (mddev->level == LEVEL_MULTIPATH)
			 
			break;
	}
	md_super_wait(mddev);
	 
	spin_lock(&mddev->lock);
	if (mddev->in_sync != sync_req ||
	    test_bit(MD_CHANGE_DEVS, &mddev->flags)) {
		 
		spin_unlock(&mddev->lock);
		goto repeat;
	}
	clear_bit(MD_CHANGE_PENDING, &mddev->flags);
	spin_unlock(&mddev->lock);
	wake_up(&mddev->sb_wait);
	if (test_bit(MD_RECOVERY_RUNNING, &mddev->recovery))
		sysfs_notify(&mddev->kobj, NULL, "sync_completed");

	rdev_for_each(rdev, mddev) {
		if (test_and_clear_bit(FaultRecorded, &rdev->flags))
			clear_bit(Blocked, &rdev->flags);

		if (any_badblocks_changed)
			md_ack_all_badblocks(&rdev->badblocks);
		clear_bit(BlockedBadBlocks, &rdev->flags);
		wake_up(&rdev->blocked_wait);
	}

	if (mddev_is_clustered(mddev) && ret == 0)
		md_cluster_ops->metadata_update_finish(mddev);
}
EXPORT_SYMBOL(md_update_sb);

static int add_bound_rdev(struct md_rdev *rdev)
{
	struct mddev *mddev = rdev->mddev;
	int err = 0;

#ifdef MY_ABC_HERE
	if (LEVEL_LINEAR == mddev->level) {
		 
#else  
	if (!mddev->pers->hot_remove_disk) {
#endif  
		 
		super_types[mddev->major_version].
			validate_super(mddev, rdev);
		err = mddev->pers->hot_add_disk(mddev, rdev);
		if (err) {
			unbind_rdev_from_array(rdev);
			export_rdev(rdev);
			return err;
		}
	}
	sysfs_notify_dirent_safe(rdev->sysfs_state);

	set_bit(MD_CHANGE_DEVS, &mddev->flags);
	if (mddev->degraded)
		set_bit(MD_RECOVERY_RECOVER, &mddev->recovery);
	set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
	md_new_event(mddev);
	md_wakeup_thread(mddev->thread);
	return 0;
}

static int cmd_match(const char *cmd, const char *str)
{
	 
	while (*cmd && *str && *cmd == *str) {
		cmd++;
		str++;
	}
	if (*cmd == '\n')
		cmd++;
	if (*str || *cmd)
		return 0;
	return 1;
}

struct rdev_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct md_rdev *, char *);
	ssize_t (*store)(struct md_rdev *, const char *, size_t);
};

static ssize_t
state_show(struct md_rdev *rdev, char *page)
{
	char *sep = "";
	size_t len = 0;
	unsigned long flags = ACCESS_ONCE(rdev->flags);

	if (test_bit(Faulty, &flags) ||
	    rdev->badblocks.unacked_exist) {
		len+= sprintf(page+len, "%sfaulty",sep);
		sep = ",";
	}
#ifdef MY_ABC_HERE
	if (test_bit(DiskError, &flags)) {
		len += sprintf(page+len, "%serror",sep);
		sep = ",";
	}
#endif  
	if (test_bit(In_sync, &flags)) {
		len += sprintf(page+len, "%sin_sync",sep);
		sep = ",";
	}
	if (test_bit(Journal, &flags)) {
		len += sprintf(page+len, "%sjournal",sep);
		sep = ",";
	}
	if (test_bit(WriteMostly, &flags)) {
		len += sprintf(page+len, "%swrite_mostly",sep);
		sep = ",";
	}
	if (test_bit(Blocked, &flags) ||
	    (rdev->badblocks.unacked_exist
	     && !test_bit(Faulty, &flags))) {
		len += sprintf(page+len, "%sblocked", sep);
		sep = ",";
	}
	if (!test_bit(Faulty, &flags) &&
	    !test_bit(Journal, &flags) &&
	    !test_bit(In_sync, &flags)) {
		len += sprintf(page+len, "%sspare", sep);
		sep = ",";
	}
	if (test_bit(WriteErrorSeen, &flags)) {
		len += sprintf(page+len, "%swrite_error", sep);
		sep = ",";
	}
	if (test_bit(WantReplacement, &flags)) {
		len += sprintf(page+len, "%swant_replacement", sep);
		sep = ",";
	}
	if (test_bit(Replacement, &flags)) {
		len += sprintf(page+len, "%sreplacement", sep);
		sep = ",";
	}

	return len+sprintf(page+len, "\n");
}

static ssize_t
state_store(struct md_rdev *rdev, const char *buf, size_t len)
{
	 
	int err = -EINVAL;
	if (cmd_match(buf, "faulty") && rdev->mddev->pers) {
		md_error(rdev->mddev, rdev);
		if (test_bit(Faulty, &rdev->flags))
			err = 0;
		else
			err = -EBUSY;
	} else if (cmd_match(buf, "remove")) {
		if (rdev->raid_disk >= 0)
			err = -EBUSY;
		else {
			struct mddev *mddev = rdev->mddev;
			err = 0;
			if (mddev_is_clustered(mddev))
				err = md_cluster_ops->remove_disk(mddev, rdev);

			if (err == 0) {
				md_kick_rdev_from_array(rdev);
				if (mddev->pers)
					md_update_sb(mddev, 1);
				md_new_event(mddev);
			}
		}
	} else if (cmd_match(buf, "writemostly")) {
		set_bit(WriteMostly, &rdev->flags);
		err = 0;
	} else if (cmd_match(buf, "-writemostly")) {
		clear_bit(WriteMostly, &rdev->flags);
		err = 0;
	} else if (cmd_match(buf, "blocked")) {
		set_bit(Blocked, &rdev->flags);
		err = 0;
	} else if (cmd_match(buf, "-blocked")) {
		if (!test_bit(Faulty, &rdev->flags) &&
		    rdev->badblocks.unacked_exist) {
			 
			md_error(rdev->mddev, rdev);
		}
		clear_bit(Blocked, &rdev->flags);
		clear_bit(BlockedBadBlocks, &rdev->flags);
		wake_up(&rdev->blocked_wait);
		set_bit(MD_RECOVERY_NEEDED, &rdev->mddev->recovery);
		md_wakeup_thread(rdev->mddev->thread);

		err = 0;
	} else if (cmd_match(buf, "insync") && rdev->raid_disk == -1) {
		set_bit(In_sync, &rdev->flags);
		err = 0;
	} else if (cmd_match(buf, "-insync") && rdev->raid_disk >= 0 &&
		   !test_bit(Journal, &rdev->flags)) {
		if (rdev->mddev->pers == NULL) {
			clear_bit(In_sync, &rdev->flags);
			rdev->saved_raid_disk = rdev->raid_disk;
			rdev->raid_disk = -1;
			err = 0;
		}
	} else if (cmd_match(buf, "write_error")) {
		set_bit(WriteErrorSeen, &rdev->flags);
		err = 0;
	} else if (cmd_match(buf, "-write_error")) {
		clear_bit(WriteErrorSeen, &rdev->flags);
		err = 0;
	} else if (cmd_match(buf, "want_replacement")) {
		 
		if (rdev->raid_disk >= 0 &&
		    !test_bit(Journal, &rdev->flags) &&
		    !test_bit(Replacement, &rdev->flags))
			set_bit(WantReplacement, &rdev->flags);
		set_bit(MD_RECOVERY_NEEDED, &rdev->mddev->recovery);
		md_wakeup_thread(rdev->mddev->thread);
		err = 0;
	} else if (cmd_match(buf, "-want_replacement")) {
		 
		err = 0;
		clear_bit(WantReplacement, &rdev->flags);
	} else if (cmd_match(buf, "replacement")) {
		 
		if (rdev->mddev->pers)
			err = -EBUSY;
		else {
			set_bit(Replacement, &rdev->flags);
			err = 0;
		}
	} else if (cmd_match(buf, "-replacement")) {
		 
		if (rdev->mddev->pers)
			err = -EBUSY;
		else {
			clear_bit(Replacement, &rdev->flags);
			err = 0;
		}
	} else if (cmd_match(buf, "re-add")) {
		if (test_bit(Faulty, &rdev->flags) && (rdev->raid_disk == -1)) {
			 
			if (!mddev_is_clustered(rdev->mddev) ||
			    (err = md_cluster_ops->gather_bitmaps(rdev)) == 0) {
				clear_bit(Faulty, &rdev->flags);
				err = add_bound_rdev(rdev);
			}
		} else
			err = -EBUSY;
	}
	if (!err)
		sysfs_notify_dirent_safe(rdev->sysfs_state);
	return err ? err : len;
}
static struct rdev_sysfs_entry rdev_state =
__ATTR_PREALLOC(state, S_IRUGO|S_IWUSR, state_show, state_store);

static ssize_t
errors_show(struct md_rdev *rdev, char *page)
{
	return sprintf(page, "%d\n", atomic_read(&rdev->corrected_errors));
}

static ssize_t
errors_store(struct md_rdev *rdev, const char *buf, size_t len)
{
	unsigned int n;
	int rv;

	rv = kstrtouint(buf, 10, &n);
	if (rv < 0)
		return rv;
	atomic_set(&rdev->corrected_errors, n);
	return len;
}
static struct rdev_sysfs_entry rdev_errors =
__ATTR(errors, S_IRUGO|S_IWUSR, errors_show, errors_store);

static ssize_t
slot_show(struct md_rdev *rdev, char *page)
{
	if (test_bit(Journal, &rdev->flags))
		return sprintf(page, "journal\n");
	else if (rdev->raid_disk < 0)
		return sprintf(page, "none\n");
	else
		return sprintf(page, "%d\n", rdev->raid_disk);
}

static ssize_t
slot_store(struct md_rdev *rdev, const char *buf, size_t len)
{
	int slot;
	int err;

	if (test_bit(Journal, &rdev->flags))
		return -EBUSY;
	if (strncmp(buf, "none", 4)==0)
		slot = -1;
	else {
		err = kstrtouint(buf, 10, (unsigned int *)&slot);
		if (err < 0)
			return err;
	}
	if (rdev->mddev->pers && slot == -1) {
		 
		if (rdev->raid_disk == -1)
			return -EEXIST;
		 
		if (rdev->mddev->pers->hot_remove_disk == NULL)
			return -EINVAL;
		clear_bit(Blocked, &rdev->flags);
		remove_and_add_spares(rdev->mddev, rdev);
		if (rdev->raid_disk >= 0)
			return -EBUSY;
		set_bit(MD_RECOVERY_NEEDED, &rdev->mddev->recovery);
		md_wakeup_thread(rdev->mddev->thread);
	} else if (rdev->mddev->pers) {
		 
		int err;

		if (rdev->raid_disk != -1)
			return -EBUSY;

		if (test_bit(MD_RECOVERY_RUNNING, &rdev->mddev->recovery))
			return -EBUSY;

		if (rdev->mddev->pers->hot_add_disk == NULL)
			return -EINVAL;

		if (slot >= rdev->mddev->raid_disks &&
		    slot >= rdev->mddev->raid_disks + rdev->mddev->delta_disks)
			return -ENOSPC;

		rdev->raid_disk = slot;
		if (test_bit(In_sync, &rdev->flags))
			rdev->saved_raid_disk = slot;
		else
			rdev->saved_raid_disk = -1;
		clear_bit(In_sync, &rdev->flags);
		clear_bit(Bitmap_sync, &rdev->flags);
		err = rdev->mddev->pers->
			hot_add_disk(rdev->mddev, rdev);
		if (err) {
			rdev->raid_disk = -1;
			return err;
		} else
			sysfs_notify_dirent_safe(rdev->sysfs_state);
		if (sysfs_link_rdev(rdev->mddev, rdev))
			 ;
		 
	} else {
		if (slot >= rdev->mddev->raid_disks &&
		    slot >= rdev->mddev->raid_disks + rdev->mddev->delta_disks)
			return -ENOSPC;
		rdev->raid_disk = slot;
		 
		clear_bit(Faulty, &rdev->flags);
		clear_bit(WriteMostly, &rdev->flags);
		set_bit(In_sync, &rdev->flags);
		sysfs_notify_dirent_safe(rdev->sysfs_state);
	}
	return len;
}

static struct rdev_sysfs_entry rdev_slot =
__ATTR(slot, S_IRUGO|S_IWUSR, slot_show, slot_store);

static ssize_t
offset_show(struct md_rdev *rdev, char *page)
{
	return sprintf(page, "%llu\n", (unsigned long long)rdev->data_offset);
}

static ssize_t
offset_store(struct md_rdev *rdev, const char *buf, size_t len)
{
	unsigned long long offset;
	if (kstrtoull(buf, 10, &offset) < 0)
		return -EINVAL;
	if (rdev->mddev->pers && rdev->raid_disk >= 0)
		return -EBUSY;
	if (rdev->sectors && rdev->mddev->external)
		 
		return -EBUSY;
	rdev->data_offset = offset;
	rdev->new_data_offset = offset;
	return len;
}

static struct rdev_sysfs_entry rdev_offset =
__ATTR(offset, S_IRUGO|S_IWUSR, offset_show, offset_store);

static ssize_t new_offset_show(struct md_rdev *rdev, char *page)
{
	return sprintf(page, "%llu\n",
		       (unsigned long long)rdev->new_data_offset);
}

static ssize_t new_offset_store(struct md_rdev *rdev,
				const char *buf, size_t len)
{
	unsigned long long new_offset;
	struct mddev *mddev = rdev->mddev;

	if (kstrtoull(buf, 10, &new_offset) < 0)
		return -EINVAL;

	if (mddev->sync_thread ||
	    test_bit(MD_RECOVERY_RUNNING,&mddev->recovery))
		return -EBUSY;
	if (new_offset == rdev->data_offset)
		 
		;
	else if (new_offset > rdev->data_offset) {
		 
		if (new_offset - rdev->data_offset
		    + mddev->dev_sectors > rdev->sectors)
				return -E2BIG;
	}
	 
	if (new_offset < rdev->data_offset &&
	    mddev->reshape_backwards)
		return -EINVAL;
	 
	if (new_offset > rdev->data_offset &&
	    !mddev->reshape_backwards)
		return -EINVAL;

	if (mddev->pers && mddev->persistent &&
	    !super_types[mddev->major_version]
	    .allow_new_offset(rdev, new_offset))
		return -E2BIG;
	rdev->new_data_offset = new_offset;
	if (new_offset > rdev->data_offset)
		mddev->reshape_backwards = 1;
	else if (new_offset < rdev->data_offset)
		mddev->reshape_backwards = 0;

	return len;
}
static struct rdev_sysfs_entry rdev_new_offset =
__ATTR(new_offset, S_IRUGO|S_IWUSR, new_offset_show, new_offset_store);

static ssize_t
rdev_size_show(struct md_rdev *rdev, char *page)
{
	return sprintf(page, "%llu\n", (unsigned long long)rdev->sectors / 2);
}

static int overlaps(sector_t s1, sector_t l1, sector_t s2, sector_t l2)
{
	 
	if (s1+l1 <= s2)
		return 0;
	if (s2+l2 <= s1)
		return 0;
	return 1;
}

static int strict_blocks_to_sectors(const char *buf, sector_t *sectors)
{
	unsigned long long blocks;
	sector_t new;

	if (kstrtoull(buf, 10, &blocks) < 0)
		return -EINVAL;

	if (blocks & 1ULL << (8 * sizeof(blocks) - 1))
		return -EINVAL;  

	new = blocks * 2;
	if (new != blocks * 2)
		return -EINVAL;  

	*sectors = new;
	return 0;
}

static ssize_t
rdev_size_store(struct md_rdev *rdev, const char *buf, size_t len)
{
	struct mddev *my_mddev = rdev->mddev;
	sector_t oldsectors = rdev->sectors;
	sector_t sectors;

	if (test_bit(Journal, &rdev->flags))
		return -EBUSY;
	if (strict_blocks_to_sectors(buf, &sectors) < 0)
		return -EINVAL;
	if (rdev->data_offset != rdev->new_data_offset)
		return -EINVAL;  
	if (my_mddev->pers && rdev->raid_disk >= 0) {
		if (my_mddev->persistent) {
			sectors = super_types[my_mddev->major_version].
				rdev_size_change(rdev, sectors);
			if (!sectors)
				return -EBUSY;
		} else if (!sectors)
			sectors = (i_size_read(rdev->bdev->bd_inode) >> 9) -
				rdev->data_offset;
		if (!my_mddev->pers->resize)
			 
			return -EINVAL;
	}
	if (sectors < my_mddev->dev_sectors)
		return -EINVAL;  

	rdev->sectors = sectors;
	if (sectors > oldsectors && my_mddev->external) {
		 
		struct mddev *mddev;
		int overlap = 0;
		struct list_head *tmp;

		rcu_read_lock();
		for_each_mddev(mddev, tmp) {
			struct md_rdev *rdev2;

			rdev_for_each(rdev2, mddev)
				if (rdev->bdev == rdev2->bdev &&
				    rdev != rdev2 &&
				    overlaps(rdev->data_offset, rdev->sectors,
					     rdev2->data_offset,
					     rdev2->sectors)) {
					overlap = 1;
					break;
				}
			if (overlap) {
				mddev_put(mddev);
				break;
			}
		}
		rcu_read_unlock();
		if (overlap) {
			 
			rdev->sectors = oldsectors;
			return -EBUSY;
		}
	}
	return len;
}

static struct rdev_sysfs_entry rdev_size =
__ATTR(size, S_IRUGO|S_IWUSR, rdev_size_show, rdev_size_store);

static ssize_t recovery_start_show(struct md_rdev *rdev, char *page)
{
	unsigned long long recovery_start = rdev->recovery_offset;

	if (test_bit(In_sync, &rdev->flags) ||
	    recovery_start == MaxSector)
		return sprintf(page, "none\n");

	return sprintf(page, "%llu\n", recovery_start);
}

static ssize_t recovery_start_store(struct md_rdev *rdev, const char *buf, size_t len)
{
	unsigned long long recovery_start;

	if (cmd_match(buf, "none"))
		recovery_start = MaxSector;
	else if (kstrtoull(buf, 10, &recovery_start))
		return -EINVAL;

	if (rdev->mddev->pers &&
	    rdev->raid_disk >= 0)
		return -EBUSY;

	rdev->recovery_offset = recovery_start;
	if (recovery_start == MaxSector)
		set_bit(In_sync, &rdev->flags);
	else
		clear_bit(In_sync, &rdev->flags);
	return len;
}

static struct rdev_sysfs_entry rdev_recovery_start =
__ATTR(recovery_start, S_IRUGO|S_IWUSR, recovery_start_show, recovery_start_store);

static ssize_t
badblocks_show(struct badblocks *bb, char *page, int unack);
static ssize_t
badblocks_store(struct badblocks *bb, const char *page, size_t len, int unack);

static ssize_t bb_show(struct md_rdev *rdev, char *page)
{
	return badblocks_show(&rdev->badblocks, page, 0);
}
static ssize_t bb_store(struct md_rdev *rdev, const char *page, size_t len)
{
	int rv = badblocks_store(&rdev->badblocks, page, len, 0);
	 
	if (test_and_clear_bit(BlockedBadBlocks, &rdev->flags))
		wake_up(&rdev->blocked_wait);
	return rv;
}
static struct rdev_sysfs_entry rdev_bad_blocks =
__ATTR(bad_blocks, S_IRUGO|S_IWUSR, bb_show, bb_store);

static ssize_t ubb_show(struct md_rdev *rdev, char *page)
{
	return badblocks_show(&rdev->badblocks, page, 1);
}
static ssize_t ubb_store(struct md_rdev *rdev, const char *page, size_t len)
{
	return badblocks_store(&rdev->badblocks, page, len, 1);
}
static struct rdev_sysfs_entry rdev_unack_bad_blocks =
__ATTR(unacknowledged_bad_blocks, S_IRUGO|S_IWUSR, ubb_show, ubb_store);

static struct attribute *rdev_default_attrs[] = {
	&rdev_state.attr,
	&rdev_errors.attr,
	&rdev_slot.attr,
	&rdev_offset.attr,
	&rdev_new_offset.attr,
	&rdev_size.attr,
	&rdev_recovery_start.attr,
	&rdev_bad_blocks.attr,
	&rdev_unack_bad_blocks.attr,
	NULL,
};
static ssize_t
rdev_attr_show(struct kobject *kobj, struct attribute *attr, char *page)
{
	struct rdev_sysfs_entry *entry = container_of(attr, struct rdev_sysfs_entry, attr);
	struct md_rdev *rdev = container_of(kobj, struct md_rdev, kobj);

	if (!entry->show)
		return -EIO;
	if (!rdev->mddev)
		return -EBUSY;
	return entry->show(rdev, page);
}

static ssize_t
rdev_attr_store(struct kobject *kobj, struct attribute *attr,
	      const char *page, size_t length)
{
	struct rdev_sysfs_entry *entry = container_of(attr, struct rdev_sysfs_entry, attr);
	struct md_rdev *rdev = container_of(kobj, struct md_rdev, kobj);
	ssize_t rv;
	struct mddev *mddev = rdev->mddev;

	if (!entry->store)
		return -EIO;
	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;
	rv = mddev ? mddev_lock(mddev): -EBUSY;
	if (!rv) {
		if (rdev->mddev == NULL)
			rv = -EBUSY;
		else
			rv = entry->store(rdev, page, length);
		mddev_unlock(mddev);
	}
	return rv;
}

static void rdev_free(struct kobject *ko)
{
	struct md_rdev *rdev = container_of(ko, struct md_rdev, kobj);
	kfree(rdev);
}
static const struct sysfs_ops rdev_sysfs_ops = {
	.show		= rdev_attr_show,
	.store		= rdev_attr_store,
};
static struct kobj_type rdev_ktype = {
	.release	= rdev_free,
	.sysfs_ops	= &rdev_sysfs_ops,
	.default_attrs	= rdev_default_attrs,
};

int md_rdev_init(struct md_rdev *rdev)
{
	rdev->desc_nr = -1;
	rdev->saved_raid_disk = -1;
	rdev->raid_disk = -1;
	rdev->flags = 0;
	rdev->data_offset = 0;
	rdev->new_data_offset = 0;
	rdev->sb_events = 0;
	rdev->last_read_error.tv_sec  = 0;
	rdev->last_read_error.tv_nsec = 0;
	rdev->sb_loaded = 0;
	rdev->bb_page = NULL;
	atomic_set(&rdev->nr_pending, 0);
	atomic_set(&rdev->read_errors, 0);
	atomic_set(&rdev->corrected_errors, 0);

	INIT_LIST_HEAD(&rdev->same_set);
	init_waitqueue_head(&rdev->blocked_wait);

	rdev->badblocks.count = 0;
	rdev->badblocks.shift = -1;  
	rdev->badblocks.page = kmalloc(PAGE_SIZE, GFP_KERNEL);
	seqlock_init(&rdev->badblocks.lock);
	if (rdev->badblocks.page == NULL)
		return -ENOMEM;

	return 0;
}
EXPORT_SYMBOL_GPL(md_rdev_init);
 
static struct md_rdev *md_import_device(dev_t newdev, int super_format, int super_minor)
{
	char b[BDEVNAME_SIZE];
	int err;
	struct md_rdev *rdev;
	sector_t size;

	rdev = kzalloc(sizeof(*rdev), GFP_KERNEL);
	if (!rdev) {
		printk(KERN_ERR "md: could not alloc mem for new device!\n");
		return ERR_PTR(-ENOMEM);
	}

	err = md_rdev_init(rdev);
	if (err)
		goto abort_free;
	err = alloc_disk_sb(rdev);
	if (err)
		goto abort_free;

#ifdef MY_ABC_HERE
	if ((err = alloc_disk_wakeup_page(rdev)))
		goto abort_free;
#endif  

	err = lock_rdev(rdev, newdev, super_format == -2);
	if (err)
		goto abort_free;

#ifdef MY_ABC_HERE
	RaidRemapModeSet(rdev->bdev, 0);
#endif  
	kobject_init(&rdev->kobj, &rdev_ktype);

	size = i_size_read(rdev->bdev->bd_inode) >> BLOCK_SIZE_BITS;
	if (!size) {
		printk(KERN_WARNING
			"md: %s has zero or unknown size, marking faulty!\n",
			bdevname(rdev->bdev,b));
		err = -EINVAL;
		goto abort_free;
	}

	if (super_format >= 0) {
		err = super_types[super_format].
			load_super(rdev, NULL, super_minor);
		if (err == -EINVAL) {
			printk(KERN_WARNING
				"md: %s does not have a valid v%d.%d "
			       "superblock, not importing!\n",
				bdevname(rdev->bdev,b),
			       super_format, super_minor);
			goto abort_free;
		}
		if (err < 0) {
			printk(KERN_WARNING
				"md: could not read %s's sb, not importing!\n",
				bdevname(rdev->bdev,b));
			goto abort_free;
		}
	}

	return rdev;

abort_free:
	if (rdev->bdev)
		unlock_rdev(rdev);
	md_rdev_clear(rdev);
#ifdef MY_ABC_HERE
	if (rdev->wakeup_page){
		free_disk_wakeup_page(rdev);
	}
#endif  
	kfree(rdev);
	return ERR_PTR(err);
}

static void analyze_sbs(struct mddev *mddev)
{
	int i;
	struct md_rdev *rdev, *freshest, *tmp;
	char b[BDEVNAME_SIZE];

	freshest = NULL;
	rdev_for_each_safe(rdev, tmp, mddev)
		switch (super_types[mddev->major_version].
			load_super(rdev, freshest, mddev->minor_version)) {
		case 1:
			freshest = rdev;
			break;
		case 0:
			break;
		default:
			printk( KERN_ERR \
				"md: fatal superblock inconsistency in %s"
				" -- removing from array\n",
				bdevname(rdev->bdev,b));
			md_kick_rdev_from_array(rdev);
		}

	super_types[mddev->major_version].
		validate_super(mddev, freshest);

	i = 0;
	rdev_for_each_safe(rdev, tmp, mddev) {
		if (mddev->max_disks &&
		    (rdev->desc_nr >= mddev->max_disks ||
		     i > mddev->max_disks)) {
			printk(KERN_WARNING
			       "md: %s: %s: only %d devices permitted\n",
			       mdname(mddev), bdevname(rdev->bdev, b),
			       mddev->max_disks);
			md_kick_rdev_from_array(rdev);
			continue;
		}
		if (rdev != freshest) {
			if (super_types[mddev->major_version].
			    validate_super(mddev, rdev)) {
				printk(KERN_WARNING "md: kicking non-fresh %s"
					" from array!\n",
					bdevname(rdev->bdev,b));
				md_kick_rdev_from_array(rdev);
				continue;
			}
		}
		if (mddev->level == LEVEL_MULTIPATH) {
			rdev->desc_nr = i++;
			rdev->raid_disk = rdev->desc_nr;
			set_bit(In_sync, &rdev->flags);
		} else if (rdev->raid_disk >=
			    (mddev->raid_disks - min(0, mddev->delta_disks)) &&
			   !test_bit(Journal, &rdev->flags)) {
			rdev->raid_disk = -1;
			clear_bit(In_sync, &rdev->flags);
		}
	}
}

int strict_strtoul_scaled(const char *cp, unsigned long *res, int scale)
{
	unsigned long result = 0;
	long decimals = -1;
	while (isdigit(*cp) || (*cp == '.' && decimals < 0)) {
		if (*cp == '.')
			decimals = 0;
		else if (decimals < scale) {
			unsigned int value;
			value = *cp - '0';
			result = result * 10 + value;
			if (decimals >= 0)
				decimals++;
		}
		cp++;
	}
	if (*cp == '\n')
		cp++;
	if (*cp)
		return -EINVAL;
	if (decimals < 0)
		decimals = 0;
	while (decimals < scale) {
		result *= 10;
		decimals ++;
	}
	*res = result;
	return 0;
}

static ssize_t
safe_delay_show(struct mddev *mddev, char *page)
{
	int msec = (mddev->safemode_delay*1000)/HZ;
	return sprintf(page, "%d.%03d\n", msec/1000, msec%1000);
}
static ssize_t
safe_delay_store(struct mddev *mddev, const char *cbuf, size_t len)
{
	unsigned long msec;

	if (mddev_is_clustered(mddev)) {
		pr_info("md: Safemode is disabled for clustered mode\n");
		return -EINVAL;
	}

	if (strict_strtoul_scaled(cbuf, &msec, 3) < 0)
		return -EINVAL;
	if (msec == 0)
		mddev->safemode_delay = 0;
	else {
		unsigned long old_delay = mddev->safemode_delay;
		unsigned long new_delay = (msec*HZ)/1000;

		if (new_delay == 0)
			new_delay = 1;
		mddev->safemode_delay = new_delay;
		if (new_delay < old_delay || old_delay == 0)
			mod_timer(&mddev->safemode_timer, jiffies+1);
	}
	return len;
}
static struct md_sysfs_entry md_safe_delay =
__ATTR(safe_mode_delay, S_IRUGO|S_IWUSR,safe_delay_show, safe_delay_store);

static ssize_t
level_show(struct mddev *mddev, char *page)
{
	struct md_personality *p;
	int ret;
	spin_lock(&mddev->lock);
	p = mddev->pers;
	if (p)
		ret = sprintf(page, "%s\n", p->name);
	else if (mddev->clevel[0])
		ret = sprintf(page, "%s\n", mddev->clevel);
	else if (mddev->level != LEVEL_NONE)
		ret = sprintf(page, "%d\n", mddev->level);
	else
		ret = 0;
	spin_unlock(&mddev->lock);
	return ret;
}

static ssize_t
level_store(struct mddev *mddev, const char *buf, size_t len)
{
	char clevel[16];
	ssize_t rv;
	size_t slen = len;
	struct md_personality *pers, *oldpers;
	long level;
	void *priv, *oldpriv;
	struct md_rdev *rdev;

	if (slen == 0 || slen >= sizeof(clevel))
		return -EINVAL;

	rv = mddev_lock(mddev);
	if (rv)
		return rv;

	if (mddev->pers == NULL) {
		strncpy(mddev->clevel, buf, slen);
		if (mddev->clevel[slen-1] == '\n')
			slen--;
		mddev->clevel[slen] = 0;
		mddev->level = LEVEL_NONE;
		rv = len;
		goto out_unlock;
	}
	rv = -EROFS;
	if (mddev->ro)
		goto out_unlock;

	rv = -EBUSY;
	if (mddev->sync_thread ||
	    test_bit(MD_RECOVERY_RUNNING, &mddev->recovery) ||
	    mddev->reshape_position != MaxSector ||
	    mddev->sysfs_active)
		goto out_unlock;

	rv = -EINVAL;
	if (!mddev->pers->quiesce) {
		printk(KERN_WARNING "md: %s: %s does not support online personality change\n",
		       mdname(mddev), mddev->pers->name);
		goto out_unlock;
	}

	strncpy(clevel, buf, slen);
	if (clevel[slen-1] == '\n')
		slen--;
	clevel[slen] = 0;
	if (kstrtol(clevel, 10, &level))
		level = LEVEL_NONE;

	if (request_module("md-%s", clevel) != 0)
		request_module("md-level-%s", clevel);
	spin_lock(&pers_lock);
	pers = find_pers(level, clevel);
	if (!pers || !try_module_get(pers->owner)) {
		spin_unlock(&pers_lock);
		printk(KERN_WARNING "md: personality %s not loaded\n", clevel);
		rv = -EINVAL;
		goto out_unlock;
	}
	spin_unlock(&pers_lock);

	if (pers == mddev->pers) {
		 
		module_put(pers->owner);
		rv = len;
		goto out_unlock;
	}
	if (!pers->takeover) {
		module_put(pers->owner);
		printk(KERN_WARNING "md: %s: %s does not support personality takeover\n",
		       mdname(mddev), clevel);
		rv = -EINVAL;
		goto out_unlock;
	}

	rdev_for_each(rdev, mddev)
		rdev->new_raid_disk = rdev->raid_disk;

	priv = pers->takeover(mddev);
	if (IS_ERR(priv)) {
		mddev->new_level = mddev->level;
		mddev->new_layout = mddev->layout;
		mddev->new_chunk_sectors = mddev->chunk_sectors;
		mddev->raid_disks -= mddev->delta_disks;
		mddev->delta_disks = 0;
		mddev->reshape_backwards = 0;
		module_put(pers->owner);
		printk(KERN_WARNING "md: %s: %s would not accept array\n",
		       mdname(mddev), clevel);
		rv = PTR_ERR(priv);
		goto out_unlock;
	}

	mddev_suspend(mddev);
	mddev_detach(mddev);

	spin_lock(&mddev->lock);
	oldpers = mddev->pers;
	oldpriv = mddev->private;
	mddev->pers = pers;
	mddev->private = priv;
	strlcpy(mddev->clevel, pers->name, sizeof(mddev->clevel));
	mddev->level = mddev->new_level;
	mddev->layout = mddev->new_layout;
	mddev->chunk_sectors = mddev->new_chunk_sectors;
	mddev->delta_disks = 0;
	mddev->reshape_backwards = 0;
	mddev->degraded = 0;
	spin_unlock(&mddev->lock);

	if (oldpers->sync_request == NULL &&
	    mddev->external) {
		 
		mddev->in_sync = 0;
		mddev->safemode_delay = 0;
		mddev->safemode = 0;
	}

	oldpers->free(mddev, oldpriv);

	if (oldpers->sync_request == NULL &&
	    pers->sync_request != NULL) {
		 
		if (sysfs_create_group(&mddev->kobj, &md_redundancy_group))
			printk(KERN_WARNING
			       "md: cannot register extra attributes for %s\n",
			       mdname(mddev));
		mddev->sysfs_action = sysfs_get_dirent(mddev->kobj.sd, "sync_action");
	}
	if (oldpers->sync_request != NULL &&
	    pers->sync_request == NULL) {
		 
		if (mddev->to_remove == NULL)
			mddev->to_remove = &md_redundancy_group;
	}

	rdev_for_each(rdev, mddev) {
		if (rdev->raid_disk < 0)
			continue;
		if (rdev->new_raid_disk >= mddev->raid_disks)
			rdev->new_raid_disk = -1;
		if (rdev->new_raid_disk == rdev->raid_disk)
			continue;
		sysfs_unlink_rdev(mddev, rdev);
	}
	rdev_for_each(rdev, mddev) {
		if (rdev->raid_disk < 0)
			continue;
		if (rdev->new_raid_disk == rdev->raid_disk)
			continue;
		rdev->raid_disk = rdev->new_raid_disk;
		if (rdev->raid_disk < 0)
			clear_bit(In_sync, &rdev->flags);
		else {
			if (sysfs_link_rdev(mddev, rdev))
				printk(KERN_WARNING "md: cannot register rd%d"
				       " for %s after level change\n",
				       rdev->raid_disk, mdname(mddev));
		}
	}

	if (pers->sync_request == NULL) {
		 
		mddev->in_sync = 1;
		del_timer_sync(&mddev->safemode_timer);
	}
	blk_set_stacking_limits(&mddev->queue->limits);
	pers->run(mddev);
	set_bit(MD_CHANGE_DEVS, &mddev->flags);
	mddev_resume(mddev);
	if (!mddev->thread)
		md_update_sb(mddev, 1);
	sysfs_notify(&mddev->kobj, NULL, "level");
	md_new_event(mddev);
	rv = len;
out_unlock:
	mddev_unlock(mddev);
	return rv;
}

static struct md_sysfs_entry md_level =
__ATTR(level, S_IRUGO|S_IWUSR, level_show, level_store);

static ssize_t
layout_show(struct mddev *mddev, char *page)
{
	 
	if (mddev->reshape_position != MaxSector &&
	    mddev->layout != mddev->new_layout)
		return sprintf(page, "%d (%d)\n",
			       mddev->new_layout, mddev->layout);
	return sprintf(page, "%d\n", mddev->layout);
}

static ssize_t
layout_store(struct mddev *mddev, const char *buf, size_t len)
{
	unsigned int n;
	int err;

	err = kstrtouint(buf, 10, &n);
	if (err < 0)
		return err;
	err = mddev_lock(mddev);
	if (err)
		return err;

	if (mddev->pers) {
		if (mddev->pers->check_reshape == NULL)
			err = -EBUSY;
		else if (mddev->ro)
			err = -EROFS;
		else {
			mddev->new_layout = n;
			err = mddev->pers->check_reshape(mddev);
			if (err)
				mddev->new_layout = mddev->layout;
		}
	} else {
		mddev->new_layout = n;
		if (mddev->reshape_position == MaxSector)
			mddev->layout = n;
	}
	mddev_unlock(mddev);
	return err ?: len;
}
static struct md_sysfs_entry md_layout =
__ATTR(layout, S_IRUGO|S_IWUSR, layout_show, layout_store);

static ssize_t
raid_disks_show(struct mddev *mddev, char *page)
{
	if (mddev->raid_disks == 0)
		return 0;
	if (mddev->reshape_position != MaxSector &&
	    mddev->delta_disks != 0)
		return sprintf(page, "%d (%d)\n", mddev->raid_disks,
			       mddev->raid_disks - mddev->delta_disks);
	return sprintf(page, "%d\n", mddev->raid_disks);
}

static int update_raid_disks(struct mddev *mddev, int raid_disks);

static ssize_t
raid_disks_store(struct mddev *mddev, const char *buf, size_t len)
{
	unsigned int n;
	int err;

	err = kstrtouint(buf, 10, &n);
	if (err < 0)
		return err;

	err = mddev_lock(mddev);
	if (err)
		return err;
	if (mddev->pers)
		err = update_raid_disks(mddev, n);
	else if (mddev->reshape_position != MaxSector) {
		struct md_rdev *rdev;
		int olddisks = mddev->raid_disks - mddev->delta_disks;

		err = -EINVAL;
		rdev_for_each(rdev, mddev) {
			if (olddisks < n &&
			    rdev->data_offset < rdev->new_data_offset)
				goto out_unlock;
			if (olddisks > n &&
			    rdev->data_offset > rdev->new_data_offset)
				goto out_unlock;
		}
		err = 0;
		mddev->delta_disks = n - olddisks;
		mddev->raid_disks = n;
		mddev->reshape_backwards = (mddev->delta_disks < 0);
	} else
		mddev->raid_disks = n;
out_unlock:
	mddev_unlock(mddev);
	return err ? err : len;
}
static struct md_sysfs_entry md_raid_disks =
__ATTR(raid_disks, S_IRUGO|S_IWUSR, raid_disks_show, raid_disks_store);

static ssize_t
chunk_size_show(struct mddev *mddev, char *page)
{
	if (mddev->reshape_position != MaxSector &&
	    mddev->chunk_sectors != mddev->new_chunk_sectors)
		return sprintf(page, "%d (%d)\n",
			       mddev->new_chunk_sectors << 9,
			       mddev->chunk_sectors << 9);
	return sprintf(page, "%d\n", mddev->chunk_sectors << 9);
}

static ssize_t
chunk_size_store(struct mddev *mddev, const char *buf, size_t len)
{
	unsigned long n;
	int err;

	err = kstrtoul(buf, 10, &n);
	if (err < 0)
		return err;

	err = mddev_lock(mddev);
	if (err)
		return err;
	if (mddev->pers) {
		if (mddev->pers->check_reshape == NULL)
			err = -EBUSY;
		else if (mddev->ro)
			err = -EROFS;
		else {
			mddev->new_chunk_sectors = n >> 9;
			err = mddev->pers->check_reshape(mddev);
			if (err)
				mddev->new_chunk_sectors = mddev->chunk_sectors;
		}
	} else {
		mddev->new_chunk_sectors = n >> 9;
		if (mddev->reshape_position == MaxSector)
			mddev->chunk_sectors = n >> 9;
	}
	mddev_unlock(mddev);
	return err ?: len;
}
static struct md_sysfs_entry md_chunk_size =
__ATTR(chunk_size, S_IRUGO|S_IWUSR, chunk_size_show, chunk_size_store);

static ssize_t
resync_start_show(struct mddev *mddev, char *page)
{
	if (mddev->recovery_cp == MaxSector)
		return sprintf(page, "none\n");
	return sprintf(page, "%llu\n", (unsigned long long)mddev->recovery_cp);
}

static ssize_t
resync_start_store(struct mddev *mddev, const char *buf, size_t len)
{
	unsigned long long n;
	int err;

	if (cmd_match(buf, "none"))
		n = MaxSector;
	else {
		err = kstrtoull(buf, 10, &n);
		if (err < 0)
			return err;
		if (n != (sector_t)n)
			return -EINVAL;
	}

	err = mddev_lock(mddev);
	if (err)
		return err;
	if (mddev->pers && !test_bit(MD_RECOVERY_FROZEN, &mddev->recovery))
		err = -EBUSY;

	if (!err) {
		mddev->recovery_cp = n;
		if (mddev->pers)
			set_bit(MD_CHANGE_CLEAN, &mddev->flags);
	}
	mddev_unlock(mddev);
	return err ?: len;
}
static struct md_sysfs_entry md_resync_start =
__ATTR_PREALLOC(resync_start, S_IRUGO|S_IWUSR,
		resync_start_show, resync_start_store);

enum array_state { clear, inactive, suspended, readonly, read_auto, clean, active,
		   write_pending, active_idle, bad_word};
static char *array_states[] = {
	"clear", "inactive", "suspended", "readonly", "read-auto", "clean", "active",
	"write-pending", "active-idle", NULL };

static int match_word(const char *word, char **list)
{
	int n;
	for (n=0; list[n]; n++)
		if (cmd_match(word, list[n]))
			break;
	return n;
}

static ssize_t
array_state_show(struct mddev *mddev, char *page)
{
	enum array_state st = inactive;

	if (mddev->pers)
		switch(mddev->ro) {
		case 1:
			st = readonly;
			break;
		case 2:
			st = read_auto;
			break;
		case 0:
			if (mddev->in_sync)
				st = clean;
			else if (test_bit(MD_CHANGE_PENDING, &mddev->flags))
				st = write_pending;
			else if (mddev->safemode)
				st = active_idle;
			else
				st = active;
		}
	else {
		if (list_empty(&mddev->disks) &&
		    mddev->raid_disks == 0 &&
		    mddev->dev_sectors == 0)
			st = clear;
		else
			st = inactive;
	}
	return sprintf(page, "%s\n", array_states[st]);
}

static int do_md_stop(struct mddev *mddev, int ro, struct block_device *bdev);
static int md_set_readonly(struct mddev *mddev, struct block_device *bdev);
static int do_md_run(struct mddev *mddev);
static int restart_array(struct mddev *mddev);

static ssize_t
array_state_store(struct mddev *mddev, const char *buf, size_t len)
{
	int err;
	enum array_state st = match_word(buf, array_states);

	if (mddev->pers && (st == active || st == clean) && mddev->ro != 1) {
		 
		spin_lock(&mddev->lock);
		if (st == active) {
			restart_array(mddev);
			clear_bit(MD_CHANGE_PENDING, &mddev->flags);
			wake_up(&mddev->sb_wait);
			err = 0;
		} else   {
			restart_array(mddev);
			if (atomic_read(&mddev->writes_pending) == 0) {
				if (mddev->in_sync == 0) {
					mddev->in_sync = 1;
					if (mddev->safemode == 1)
						mddev->safemode = 0;
					set_bit(MD_CHANGE_CLEAN, &mddev->flags);
				}
				err = 0;
			} else
				err = -EBUSY;
		}
		spin_unlock(&mddev->lock);
		return err ?: len;
	}
	err = mddev_lock(mddev);
	if (err)
		return err;
	err = -EINVAL;
	switch(st) {
	case bad_word:
		break;
	case clear:
		 
		err = do_md_stop(mddev, 0, NULL);
		break;
	case inactive:
		 
		if (mddev->pers)
			err = do_md_stop(mddev, 2, NULL);
		else
			err = 0;  
		break;
	case suspended:
		break;  
	case readonly:
		if (mddev->pers)
			err = md_set_readonly(mddev, NULL);
		else {
			mddev->ro = 1;
			set_disk_ro(mddev->gendisk, 1);
			err = do_md_run(mddev);
		}
		break;
	case read_auto:
		if (mddev->pers) {
			if (mddev->ro == 0)
				err = md_set_readonly(mddev, NULL);
			else if (mddev->ro == 1)
				err = restart_array(mddev);
			if (err == 0) {
				mddev->ro = 2;
				set_disk_ro(mddev->gendisk, 0);
			}
		} else {
			mddev->ro = 2;
			err = do_md_run(mddev);
		}
		break;
	case clean:
		if (mddev->pers) {
			err = restart_array(mddev);
			if (err)
				break;
			spin_lock(&mddev->lock);
			if (atomic_read(&mddev->writes_pending) == 0) {
				if (mddev->in_sync == 0) {
					mddev->in_sync = 1;
					if (mddev->safemode == 1)
						mddev->safemode = 0;
					set_bit(MD_CHANGE_CLEAN, &mddev->flags);
				}
				err = 0;
			} else
				err = -EBUSY;
			spin_unlock(&mddev->lock);
		} else
			err = -EINVAL;
		break;
	case active:
		if (mddev->pers) {
			err = restart_array(mddev);
			if (err)
				break;
			clear_bit(MD_CHANGE_PENDING, &mddev->flags);
			wake_up(&mddev->sb_wait);
			err = 0;
		} else {
			mddev->ro = 0;
			set_disk_ro(mddev->gendisk, 0);
			err = do_md_run(mddev);
		}
		break;
	case write_pending:
	case active_idle:
		 
		break;
	}

	if (!err) {
		if (mddev->hold_active == UNTIL_IOCTL)
			mddev->hold_active = 0;
		sysfs_notify_dirent_safe(mddev->sysfs_state);
	}
	mddev_unlock(mddev);
	return err ?: len;
}
static struct md_sysfs_entry md_array_state =
__ATTR_PREALLOC(array_state, S_IRUGO|S_IWUSR, array_state_show, array_state_store);

static ssize_t
max_corrected_read_errors_show(struct mddev *mddev, char *page) {
	return sprintf(page, "%d\n",
		       atomic_read(&mddev->max_corr_read_errors));
}

static ssize_t
max_corrected_read_errors_store(struct mddev *mddev, const char *buf, size_t len)
{
	unsigned int n;
	int rv;

	rv = kstrtouint(buf, 10, &n);
	if (rv < 0)
		return rv;
	atomic_set(&mddev->max_corr_read_errors, n);
	return len;
}

static struct md_sysfs_entry max_corr_read_errors =
__ATTR(max_read_errors, S_IRUGO|S_IWUSR, max_corrected_read_errors_show,
	max_corrected_read_errors_store);

static ssize_t
null_show(struct mddev *mddev, char *page)
{
	return -EINVAL;
}

static ssize_t
new_dev_store(struct mddev *mddev, const char *buf, size_t len)
{
	 
	char *e;
	int major = simple_strtoul(buf, &e, 10);
	int minor;
	dev_t dev;
	struct md_rdev *rdev;
	int err;

	if (!*buf || *e != ':' || !e[1] || e[1] == '\n')
		return -EINVAL;
	minor = simple_strtoul(e+1, &e, 10);
	if (*e && *e != '\n')
		return -EINVAL;
	dev = MKDEV(major, minor);
	if (major != MAJOR(dev) ||
	    minor != MINOR(dev))
		return -EOVERFLOW;

	flush_workqueue(md_misc_wq);

	err = mddev_lock(mddev);
	if (err)
		return err;
	if (mddev->persistent) {
		rdev = md_import_device(dev, mddev->major_version,
					mddev->minor_version);
		if (!IS_ERR(rdev) && !list_empty(&mddev->disks)) {
			struct md_rdev *rdev0
				= list_entry(mddev->disks.next,
					     struct md_rdev, same_set);
			err = super_types[mddev->major_version]
				.load_super(rdev, rdev0, mddev->minor_version);
			if (err < 0)
				goto out;
		}
	} else if (mddev->external)
		rdev = md_import_device(dev, -2, -1);
	else
		rdev = md_import_device(dev, -1, -1);

	if (IS_ERR(rdev)) {
		mddev_unlock(mddev);
		return PTR_ERR(rdev);
	}
	err = bind_rdev_to_array(rdev, mddev);
 out:
	if (err)
		export_rdev(rdev);
	mddev_unlock(mddev);
	return err ? err : len;
}

static struct md_sysfs_entry md_new_device =
__ATTR(new_dev, S_IWUSR, null_show, new_dev_store);

static ssize_t
bitmap_store(struct mddev *mddev, const char *buf, size_t len)
{
	char *end;
	unsigned long chunk, end_chunk;
	int err;

	err = mddev_lock(mddev);
	if (err)
		return err;
	if (!mddev->bitmap)
		goto out;
	 
	while (*buf) {
		chunk = end_chunk = simple_strtoul(buf, &end, 0);
		if (buf == end) break;
		if (*end == '-') {  
			buf = end + 1;
			end_chunk = simple_strtoul(buf, &end, 0);
			if (buf == end) break;
		}
		if (*end && !isspace(*end)) break;
		bitmap_dirty_bits(mddev->bitmap, chunk, end_chunk);
		buf = skip_spaces(end);
	}
	bitmap_unplug(mddev->bitmap);  
out:
	mddev_unlock(mddev);
	return len;
}

static struct md_sysfs_entry md_bitmap =
__ATTR(bitmap_set_bits, S_IWUSR, null_show, bitmap_store);

static ssize_t
size_show(struct mddev *mddev, char *page)
{
	return sprintf(page, "%llu\n",
		(unsigned long long)mddev->dev_sectors / 2);
}

static int update_size(struct mddev *mddev, sector_t num_sectors);

static ssize_t
size_store(struct mddev *mddev, const char *buf, size_t len)
{
	 
	sector_t sectors;
	int err = strict_blocks_to_sectors(buf, &sectors);

	if (err < 0)
		return err;
	err = mddev_lock(mddev);
	if (err)
		return err;
	if (mddev->pers) {
		err = update_size(mddev, sectors);
		md_update_sb(mddev, 1);
	} else {
		if (mddev->dev_sectors == 0 ||
		    mddev->dev_sectors > sectors)
			mddev->dev_sectors = sectors;
		else
			err = -ENOSPC;
	}
	mddev_unlock(mddev);
	return err ? err : len;
}

static struct md_sysfs_entry md_size =
__ATTR(component_size, S_IRUGO|S_IWUSR, size_show, size_store);

static ssize_t
metadata_show(struct mddev *mddev, char *page)
{
	if (mddev->persistent)
		return sprintf(page, "%d.%d\n",
			       mddev->major_version, mddev->minor_version);
	else if (mddev->external)
		return sprintf(page, "external:%s\n", mddev->metadata_type);
	else
		return sprintf(page, "none\n");
}

static ssize_t
metadata_store(struct mddev *mddev, const char *buf, size_t len)
{
	int major, minor;
	char *e;
	int err;
	 
	err = mddev_lock(mddev);
	if (err)
		return err;
	err = -EBUSY;
	if (mddev->external && strncmp(buf, "external:", 9) == 0)
		;
	else if (!list_empty(&mddev->disks))
		goto out_unlock;

	err = 0;
	if (cmd_match(buf, "none")) {
		mddev->persistent = 0;
		mddev->external = 0;
		mddev->major_version = 0;
		mddev->minor_version = 90;
		goto out_unlock;
	}
	if (strncmp(buf, "external:", 9) == 0) {
		size_t namelen = len-9;
		if (namelen >= sizeof(mddev->metadata_type))
			namelen = sizeof(mddev->metadata_type)-1;
		strncpy(mddev->metadata_type, buf+9, namelen);
		mddev->metadata_type[namelen] = 0;
		if (namelen && mddev->metadata_type[namelen-1] == '\n')
			mddev->metadata_type[--namelen] = 0;
		mddev->persistent = 0;
		mddev->external = 1;
		mddev->major_version = 0;
		mddev->minor_version = 90;
		goto out_unlock;
	}
	major = simple_strtoul(buf, &e, 10);
	err = -EINVAL;
	if (e==buf || *e != '.')
		goto out_unlock;
	buf = e+1;
	minor = simple_strtoul(buf, &e, 10);
	if (e==buf || (*e && *e != '\n') )
		goto out_unlock;
	err = -ENOENT;
	if (major >= ARRAY_SIZE(super_types) || super_types[major].name == NULL)
		goto out_unlock;
	mddev->major_version = major;
	mddev->minor_version = minor;
	mddev->persistent = 1;
	mddev->external = 0;
	err = 0;
out_unlock:
	mddev_unlock(mddev);
	return err ?: len;
}

static struct md_sysfs_entry md_metadata =
__ATTR_PREALLOC(metadata_version, S_IRUGO|S_IWUSR, metadata_show, metadata_store);

static ssize_t
action_show(struct mddev *mddev, char *page)
{
	char *type = "idle";
	unsigned long recovery = mddev->recovery;
	if (test_bit(MD_RECOVERY_FROZEN, &recovery))
		type = "frozen";
	else if (test_bit(MD_RECOVERY_RUNNING, &recovery) ||
	    (!mddev->ro && test_bit(MD_RECOVERY_NEEDED, &recovery))) {
		if (test_bit(MD_RECOVERY_RESHAPE, &recovery))
			type = "reshape";
		else if (test_bit(MD_RECOVERY_SYNC, &recovery)) {
			if (!test_bit(MD_RECOVERY_REQUESTED, &recovery))
				type = "resync";
			else if (test_bit(MD_RECOVERY_CHECK, &recovery))
				type = "check";
			else
				type = "repair";
		} else if (test_bit(MD_RECOVERY_RECOVER, &recovery))
			type = "recover";
		else if (mddev->reshape_position != MaxSector)
			type = "reshape";
	}
	return sprintf(page, "%s\n", type);
}

static ssize_t
action_store(struct mddev *mddev, const char *page, size_t len)
{
	if (!mddev->pers || !mddev->pers->sync_request)
		return -EINVAL;

	if (cmd_match(page, "idle") || cmd_match(page, "frozen")) {
		if (cmd_match(page, "frozen"))
			set_bit(MD_RECOVERY_FROZEN, &mddev->recovery);
		else
			clear_bit(MD_RECOVERY_FROZEN, &mddev->recovery);
		if (test_bit(MD_RECOVERY_RUNNING, &mddev->recovery) &&
		    mddev_lock(mddev) == 0) {
			flush_workqueue(md_misc_wq);
			if (mddev->sync_thread) {
				set_bit(MD_RECOVERY_INTR, &mddev->recovery);
				md_reap_sync_thread(mddev);
			}
			mddev_unlock(mddev);
		}
	} else if (test_bit(MD_RECOVERY_RUNNING, &mddev->recovery))
		return -EBUSY;
	else if (cmd_match(page, "resync"))
		clear_bit(MD_RECOVERY_FROZEN, &mddev->recovery);
	else if (cmd_match(page, "recover")) {
		clear_bit(MD_RECOVERY_FROZEN, &mddev->recovery);
		set_bit(MD_RECOVERY_RECOVER, &mddev->recovery);
	} else if (cmd_match(page, "reshape")) {
		int err;
		if (mddev->pers->start_reshape == NULL)
			return -EINVAL;
		err = mddev_lock(mddev);
		if (!err) {
			if (test_bit(MD_RECOVERY_RUNNING, &mddev->recovery))
				err =  -EBUSY;
			else {
				clear_bit(MD_RECOVERY_FROZEN, &mddev->recovery);
				err = mddev->pers->start_reshape(mddev);
			}
			mddev_unlock(mddev);
		}
		if (err)
			return err;
		sysfs_notify(&mddev->kobj, NULL, "degraded");
	} else {
		if (cmd_match(page, "check"))
			set_bit(MD_RECOVERY_CHECK, &mddev->recovery);
		else if (!cmd_match(page, "repair"))
			return -EINVAL;
		clear_bit(MD_RECOVERY_FROZEN, &mddev->recovery);
		set_bit(MD_RECOVERY_REQUESTED, &mddev->recovery);
		set_bit(MD_RECOVERY_SYNC, &mddev->recovery);
	}
	if (mddev->ro == 2) {
		 
		mddev->ro = 0;
		md_wakeup_thread(mddev->sync_thread);
	}
	set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
	md_wakeup_thread(mddev->thread);
	sysfs_notify_dirent_safe(mddev->sysfs_action);
	return len;
}

static struct md_sysfs_entry md_scan_mode =
__ATTR_PREALLOC(sync_action, S_IRUGO|S_IWUSR, action_show, action_store);

static ssize_t
last_sync_action_show(struct mddev *mddev, char *page)
{
	return sprintf(page, "%s\n", mddev->last_sync_action);
}

static struct md_sysfs_entry md_last_scan_mode = __ATTR_RO(last_sync_action);

static ssize_t
mismatch_cnt_show(struct mddev *mddev, char *page)
{
	return sprintf(page, "%llu\n",
		       (unsigned long long)
		       atomic64_read(&mddev->resync_mismatches));
}

static struct md_sysfs_entry md_mismatches = __ATTR_RO(mismatch_cnt);

static ssize_t
sync_min_show(struct mddev *mddev, char *page)
{
	return sprintf(page, "%d (%s)\n", speed_min(mddev),
		       mddev->sync_speed_min ? "local": "system");
}

static ssize_t
sync_min_store(struct mddev *mddev, const char *buf, size_t len)
{
	unsigned int min;
	int rv;

	if (strncmp(buf, "system", 6)==0) {
		min = 0;
	} else {
		rv = kstrtouint(buf, 10, &min);
		if (rv < 0)
			return rv;
		if (min == 0)
			return -EINVAL;
	}
	mddev->sync_speed_min = min;
	return len;
}

static struct md_sysfs_entry md_sync_min =
__ATTR(sync_speed_min, S_IRUGO|S_IWUSR, sync_min_show, sync_min_store);

static ssize_t
sync_max_show(struct mddev *mddev, char *page)
{
	return sprintf(page, "%d (%s)\n", speed_max(mddev),
		       mddev->sync_speed_max ? "local": "system");
}

static ssize_t
sync_max_store(struct mddev *mddev, const char *buf, size_t len)
{
	unsigned int max;
	int rv;

	if (strncmp(buf, "system", 6)==0) {
		max = 0;
	} else {
		rv = kstrtouint(buf, 10, &max);
		if (rv < 0)
			return rv;
		if (max == 0)
			return -EINVAL;
	}
	mddev->sync_speed_max = max;
	return len;
}

static struct md_sysfs_entry md_sync_max =
__ATTR(sync_speed_max, S_IRUGO|S_IWUSR, sync_max_show, sync_max_store);

static ssize_t
degraded_show(struct mddev *mddev, char *page)
{
	return sprintf(page, "%d\n", mddev->degraded);
}
static struct md_sysfs_entry md_degraded = __ATTR_RO(degraded);

static ssize_t
sync_force_parallel_show(struct mddev *mddev, char *page)
{
	return sprintf(page, "%d\n", mddev->parallel_resync);
}

static ssize_t
sync_force_parallel_store(struct mddev *mddev, const char *buf, size_t len)
{
	long n;

	if (kstrtol(buf, 10, &n))
		return -EINVAL;

	if (n != 0 && n != 1)
		return -EINVAL;

	mddev->parallel_resync = n;

	if (mddev->sync_thread)
		wake_up(&resync_wait);

	return len;
}

static struct md_sysfs_entry md_sync_force_parallel =
__ATTR(sync_force_parallel, S_IRUGO|S_IWUSR,
       sync_force_parallel_show, sync_force_parallel_store);

static ssize_t
sync_speed_show(struct mddev *mddev, char *page)
{
	unsigned long resync, dt, db;
	if (mddev->curr_resync == 0)
		return sprintf(page, "none\n");
	resync = mddev->curr_mark_cnt - atomic_read(&mddev->recovery_active);
	dt = (jiffies - mddev->resync_mark) / HZ;
	if (!dt) dt++;
	db = resync - mddev->resync_mark_cnt;
	return sprintf(page, "%lu\n", db/dt/2);  
}

static struct md_sysfs_entry md_sync_speed = __ATTR_RO(sync_speed);

static ssize_t
sync_completed_show(struct mddev *mddev, char *page)
{
	unsigned long long max_sectors, resync;

	if (!test_bit(MD_RECOVERY_RUNNING, &mddev->recovery))
		return sprintf(page, "none\n");

	if (mddev->curr_resync == 1 ||
	    mddev->curr_resync == 2)
		return sprintf(page, "delayed\n");

	if (test_bit(MD_RECOVERY_SYNC, &mddev->recovery) ||
	    test_bit(MD_RECOVERY_RESHAPE, &mddev->recovery))
		max_sectors = mddev->resync_max_sectors;
	else
		max_sectors = mddev->dev_sectors;

	resync = mddev->curr_resync_completed;
	return sprintf(page, "%llu / %llu\n", resync, max_sectors);
}

static struct md_sysfs_entry md_sync_completed =
	__ATTR_PREALLOC(sync_completed, S_IRUGO, sync_completed_show, NULL);

static ssize_t
min_sync_show(struct mddev *mddev, char *page)
{
	return sprintf(page, "%llu\n",
		       (unsigned long long)mddev->resync_min);
}
static ssize_t
min_sync_store(struct mddev *mddev, const char *buf, size_t len)
{
	unsigned long long min;
	int err;

	if (kstrtoull(buf, 10, &min))
		return -EINVAL;

	spin_lock(&mddev->lock);
	err = -EINVAL;
	if (min > mddev->resync_max)
		goto out_unlock;

	err = -EBUSY;
	if (test_bit(MD_RECOVERY_RUNNING, &mddev->recovery))
		goto out_unlock;

	mddev->resync_min = round_down(min, 8);
	err = 0;

out_unlock:
	spin_unlock(&mddev->lock);
	return err ?: len;
}

static struct md_sysfs_entry md_min_sync =
__ATTR(sync_min, S_IRUGO|S_IWUSR, min_sync_show, min_sync_store);

static ssize_t
max_sync_show(struct mddev *mddev, char *page)
{
	if (mddev->resync_max == MaxSector)
		return sprintf(page, "max\n");
	else
		return sprintf(page, "%llu\n",
			       (unsigned long long)mddev->resync_max);
}
static ssize_t
max_sync_store(struct mddev *mddev, const char *buf, size_t len)
{
	int err;
	spin_lock(&mddev->lock);
	if (strncmp(buf, "max", 3) == 0)
		mddev->resync_max = MaxSector;
	else {
		unsigned long long max;
		int chunk;

		err = -EINVAL;
		if (kstrtoull(buf, 10, &max))
			goto out_unlock;
		if (max < mddev->resync_min)
			goto out_unlock;

		err = -EBUSY;
		if (max < mddev->resync_max &&
		    mddev->ro == 0 &&
		    test_bit(MD_RECOVERY_RUNNING, &mddev->recovery))
			goto out_unlock;

		chunk = mddev->chunk_sectors;
		if (chunk) {
			sector_t temp = max;

			err = -EINVAL;
			if (sector_div(temp, chunk))
				goto out_unlock;
		}
		mddev->resync_max = max;
	}
	wake_up(&mddev->recovery_wait);
	err = 0;
out_unlock:
	spin_unlock(&mddev->lock);
	return err ?: len;
}

static struct md_sysfs_entry md_max_sync =
__ATTR(sync_max, S_IRUGO|S_IWUSR, max_sync_show, max_sync_store);

static ssize_t
suspend_lo_show(struct mddev *mddev, char *page)
{
	return sprintf(page, "%llu\n", (unsigned long long)mddev->suspend_lo);
}

static ssize_t
suspend_lo_store(struct mddev *mddev, const char *buf, size_t len)
{
	unsigned long long old, new;
	int err;

	err = kstrtoull(buf, 10, &new);
	if (err < 0)
		return err;
	if (new != (sector_t)new)
		return -EINVAL;

	err = mddev_lock(mddev);
	if (err)
		return err;
	err = -EINVAL;
	if (mddev->pers == NULL ||
	    mddev->pers->quiesce == NULL)
		goto unlock;
	old = mddev->suspend_lo;
	mddev->suspend_lo = new;
	if (new >= old)
		 
		mddev->pers->quiesce(mddev, 2);
	else {
		 
		mddev->pers->quiesce(mddev, 1);
		mddev->pers->quiesce(mddev, 0);
	}
	err = 0;
unlock:
	mddev_unlock(mddev);
	return err ?: len;
}
static struct md_sysfs_entry md_suspend_lo =
__ATTR(suspend_lo, S_IRUGO|S_IWUSR, suspend_lo_show, suspend_lo_store);

static ssize_t
suspend_hi_show(struct mddev *mddev, char *page)
{
	return sprintf(page, "%llu\n", (unsigned long long)mddev->suspend_hi);
}

static ssize_t
suspend_hi_store(struct mddev *mddev, const char *buf, size_t len)
{
	unsigned long long old, new;
	int err;

	err = kstrtoull(buf, 10, &new);
	if (err < 0)
		return err;
	if (new != (sector_t)new)
		return -EINVAL;

	err = mddev_lock(mddev);
	if (err)
		return err;
	err = -EINVAL;
	if (mddev->pers == NULL ||
	    mddev->pers->quiesce == NULL)
		goto unlock;
	old = mddev->suspend_hi;
	mddev->suspend_hi = new;
	if (new <= old)
		 
		mddev->pers->quiesce(mddev, 2);
	else {
		 
		mddev->pers->quiesce(mddev, 1);
		mddev->pers->quiesce(mddev, 0);
	}
	err = 0;
unlock:
	mddev_unlock(mddev);
	return err ?: len;
}
static struct md_sysfs_entry md_suspend_hi =
__ATTR(suspend_hi, S_IRUGO|S_IWUSR, suspend_hi_show, suspend_hi_store);

static ssize_t
reshape_position_show(struct mddev *mddev, char *page)
{
	if (mddev->reshape_position != MaxSector)
		return sprintf(page, "%llu\n",
			       (unsigned long long)mddev->reshape_position);
	strcpy(page, "none\n");
	return 5;
}

static ssize_t
reshape_position_store(struct mddev *mddev, const char *buf, size_t len)
{
	struct md_rdev *rdev;
	unsigned long long new;
	int err;

	err = kstrtoull(buf, 10, &new);
	if (err < 0)
		return err;
	if (new != (sector_t)new)
		return -EINVAL;
	err = mddev_lock(mddev);
	if (err)
		return err;
	err = -EBUSY;
	if (mddev->pers)
		goto unlock;
	mddev->reshape_position = new;
	mddev->delta_disks = 0;
	mddev->reshape_backwards = 0;
	mddev->new_level = mddev->level;
	mddev->new_layout = mddev->layout;
	mddev->new_chunk_sectors = mddev->chunk_sectors;
	rdev_for_each(rdev, mddev)
		rdev->new_data_offset = rdev->data_offset;
	err = 0;
unlock:
	mddev_unlock(mddev);
	return err ?: len;
}

static struct md_sysfs_entry md_reshape_position =
__ATTR(reshape_position, S_IRUGO|S_IWUSR, reshape_position_show,
       reshape_position_store);

static ssize_t
reshape_direction_show(struct mddev *mddev, char *page)
{
	return sprintf(page, "%s\n",
		       mddev->reshape_backwards ? "backwards" : "forwards");
}

static ssize_t
reshape_direction_store(struct mddev *mddev, const char *buf, size_t len)
{
	int backwards = 0;
	int err;

	if (cmd_match(buf, "forwards"))
		backwards = 0;
	else if (cmd_match(buf, "backwards"))
		backwards = 1;
	else
		return -EINVAL;
	if (mddev->reshape_backwards == backwards)
		return len;

	err = mddev_lock(mddev);
	if (err)
		return err;
	 
	if (mddev->delta_disks)
		err = -EBUSY;
	else if (mddev->persistent &&
	    mddev->major_version == 0)
		err =  -EINVAL;
	else
		mddev->reshape_backwards = backwards;
	mddev_unlock(mddev);
	return err ?: len;
}

static struct md_sysfs_entry md_reshape_direction =
__ATTR(reshape_direction, S_IRUGO|S_IWUSR, reshape_direction_show,
       reshape_direction_store);

#ifdef MY_ABC_HERE
static ssize_t
auto_remap_show(struct mddev *mddev, char *page)
{
	return sprintf(page, "%d\n", mddev->auto_remap);
}

static ssize_t
auto_remap_store(struct mddev *mddev, const char *page, size_t len)
{
	int auto_remap_mode = -1;

	if (!mddev->pers){
		len = -EINVAL;
		goto END;
	}
#ifdef MY_ABC_HERE
	if (mddev->nodev_and_crashed) {
		 
		goto END;
	}
#endif  

#ifdef MY_ABC_HERE
	if (cmd_match(page, "2")) {  
		auto_remap_mode = MD_AUTO_REMAP_MODE_ISMAXDEGRADE;
	} else
#endif  
	if (cmd_match(page, "1")) {
		auto_remap_mode = MD_AUTO_REMAP_MODE_FORCE_ON;
	} else if (cmd_match(page, "0")) {
		auto_remap_mode = MD_AUTO_REMAP_MODE_FORCE_OFF;
	} else {
		printk("md: %s: auto_remap, error input\n", mdname(mddev));
		goto END;
	}

#ifdef MY_ABC_HERE
	SynoRaidAutoRemapAdjust(mddev, auto_remap_mode);
#else  
	mddev->auto_remap = auto_remap_mode;
	RaidMemberAutoRemapSet(mddev);
#endif  

END:
	return len;
}

static struct md_sysfs_entry md_auto_remap =
__ATTR(auto_remap, S_IRUGO|S_IWUSR, auto_remap_show, auto_remap_store);
#endif  

#ifdef MY_ABC_HERE
static ssize_t
md_active_show(struct mddev *mddev, char *page)
{
	return sprintf(page, "%d\n", mddev->blActive);
}

static ssize_t
md_active_store(struct mddev *mddev, const char *page, size_t len)
{
	int iNeedWake = 0;

	spin_lock(&mddev->ActLock);
	if (cmd_match(page, "1")) {
		if (!(mddev->blActive)) {
			iNeedWake = 1;
		}
		mddev->blActive = 1;
	} else if (cmd_match(page, "0")) {
		mddev->blActive = 0;
	} else {
		printk("md: %s: active, error input\n", mdname(mddev));
	}
	spin_unlock(&mddev->ActLock);

	if (iNeedWake) {
		SynoMDWakeUpDevices(mddev);
	}

	return len;
}

static struct md_sysfs_entry md_active =
__ATTR(active, S_IRUGO|S_IWUSR, md_active_show, md_active_store);
#endif  

static ssize_t
array_size_show(struct mddev *mddev, char *page)
{
	if (mddev->external_size)
		return sprintf(page, "%llu\n",
			       (unsigned long long)mddev->array_sectors/2);
	else
		return sprintf(page, "default\n");
}

static ssize_t
array_size_store(struct mddev *mddev, const char *buf, size_t len)
{
	sector_t sectors;
	int err;

	err = mddev_lock(mddev);
	if (err)
		return err;

	if (strncmp(buf, "default", 7) == 0) {
		if (mddev->pers)
			sectors = mddev->pers->size(mddev, 0, 0);
		else
			sectors = mddev->array_sectors;

		mddev->external_size = 0;
	} else {
		if (strict_blocks_to_sectors(buf, &sectors) < 0)
			err = -EINVAL;
		else if (mddev->pers && mddev->pers->size(mddev, 0, 0) < sectors)
			err = -E2BIG;
		else
			mddev->external_size = 1;
	}

	if (!err) {
		mddev->array_sectors = sectors;
		if (mddev->pers) {
			set_capacity(mddev->gendisk, mddev->array_sectors);
			revalidate_disk(mddev->gendisk);
		}
	}
	mddev_unlock(mddev);
	return err ?: len;
}

static struct md_sysfs_entry md_array_size =
__ATTR(array_size, S_IRUGO|S_IWUSR, array_size_show,
       array_size_store);

static struct attribute *md_default_attrs[] = {
	&md_level.attr,
	&md_layout.attr,
	&md_raid_disks.attr,
	&md_chunk_size.attr,
	&md_size.attr,
	&md_resync_start.attr,
	&md_metadata.attr,
	&md_new_device.attr,
	&md_safe_delay.attr,
	&md_array_state.attr,
	&md_reshape_position.attr,
	&md_reshape_direction.attr,
	&md_array_size.attr,
	&max_corr_read_errors.attr,
#ifdef MY_ABC_HERE
	&md_auto_remap.attr,
#endif  
#ifdef MY_ABC_HERE
	&md_active.attr,
#endif  
	NULL,
};

static struct attribute *md_redundancy_attrs[] = {
	&md_scan_mode.attr,
	&md_last_scan_mode.attr,
	&md_mismatches.attr,
	&md_sync_min.attr,
	&md_sync_max.attr,
	&md_sync_speed.attr,
	&md_sync_force_parallel.attr,
	&md_sync_completed.attr,
	&md_min_sync.attr,
	&md_max_sync.attr,
	&md_suspend_lo.attr,
	&md_suspend_hi.attr,
	&md_bitmap.attr,
	&md_degraded.attr,
	NULL,
};
static struct attribute_group md_redundancy_group = {
	.name = NULL,
	.attrs = md_redundancy_attrs,
};

static ssize_t
md_attr_show(struct kobject *kobj, struct attribute *attr, char *page)
{
	struct md_sysfs_entry *entry = container_of(attr, struct md_sysfs_entry, attr);
	struct mddev *mddev = container_of(kobj, struct mddev, kobj);
	ssize_t rv;

	if (!entry->show)
		return -EIO;
	spin_lock(&all_mddevs_lock);
	if (list_empty(&mddev->all_mddevs)) {
		spin_unlock(&all_mddevs_lock);
		return -EBUSY;
	}
	mddev_get(mddev);
	spin_unlock(&all_mddevs_lock);

	rv = entry->show(mddev, page);
	mddev_put(mddev);
	return rv;
}

static ssize_t
md_attr_store(struct kobject *kobj, struct attribute *attr,
	      const char *page, size_t length)
{
	struct md_sysfs_entry *entry = container_of(attr, struct md_sysfs_entry, attr);
	struct mddev *mddev = container_of(kobj, struct mddev, kobj);
	ssize_t rv;

	if (!entry->store)
		return -EIO;
	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;
	spin_lock(&all_mddevs_lock);
	if (list_empty(&mddev->all_mddevs)) {
		spin_unlock(&all_mddevs_lock);
		return -EBUSY;
	}
	mddev_get(mddev);
	spin_unlock(&all_mddevs_lock);
	rv = entry->store(mddev, page, length);
	mddev_put(mddev);
	return rv;
}

static void md_free(struct kobject *ko)
{
	struct mddev *mddev = container_of(ko, struct mddev, kobj);

	if (mddev->sysfs_state)
		sysfs_put(mddev->sysfs_state);

	if (mddev->queue)
		blk_cleanup_queue(mddev->queue);
	if (mddev->gendisk) {
		del_gendisk(mddev->gendisk);
		put_disk(mddev->gendisk);
	}

	kfree(mddev);
}

static const struct sysfs_ops md_sysfs_ops = {
	.show	= md_attr_show,
	.store	= md_attr_store,
};
static struct kobj_type md_ktype = {
	.release	= md_free,
	.sysfs_ops	= &md_sysfs_ops,
	.default_attrs	= md_default_attrs,
};

int mdp_major = 0;

static void mddev_delayed_delete(struct work_struct *ws)
{
	struct mddev *mddev = container_of(ws, struct mddev, del_work);

	sysfs_remove_group(&mddev->kobj, &md_bitmap_group);
	kobject_del(&mddev->kobj);
	kobject_put(&mddev->kobj);
}

static int md_alloc(dev_t dev, char *name)
{
	static DEFINE_MUTEX(disks_mutex);
	struct mddev *mddev = mddev_find(dev);
	struct gendisk *disk;
	int partitioned;
	int shift;
	int unit;
	int error;

	if (!mddev)
		return -ENODEV;

	partitioned = (MAJOR(mddev->unit) != MD_MAJOR);
	shift = partitioned ? MdpMinorShift : 0;
	unit = MINOR(mddev->unit) >> shift;

	flush_workqueue(md_misc_wq);

	mutex_lock(&disks_mutex);
	error = -EEXIST;
	if (mddev->gendisk)
		goto abort;

	if (name) {
		 
		struct mddev *mddev2;
		spin_lock(&all_mddevs_lock);

		list_for_each_entry(mddev2, &all_mddevs, all_mddevs)
			if (mddev2->gendisk &&
			    strcmp(mddev2->gendisk->disk_name, name) == 0) {
				spin_unlock(&all_mddevs_lock);
				goto abort;
			}
		spin_unlock(&all_mddevs_lock);
	}

	error = -ENOMEM;
	mddev->queue = blk_alloc_queue(GFP_KERNEL);
	if (!mddev->queue)
		goto abort;
	mddev->queue->queuedata = mddev;

	blk_queue_make_request(mddev->queue, md_make_request);
	blk_set_stacking_limits(&mddev->queue->limits);

	disk = alloc_disk(1 << shift);
	if (!disk) {
		blk_cleanup_queue(mddev->queue);
		mddev->queue = NULL;
		goto abort;
	}
	disk->major = MAJOR(mddev->unit);
	disk->first_minor = unit << shift;
	if (name)
		strcpy(disk->disk_name, name);
	else if (partitioned)
		sprintf(disk->disk_name, "md_d%d", unit);
	else
		sprintf(disk->disk_name, "md%d", unit);
	disk->fops = &md_fops;
	disk->private_data = mddev;
	disk->queue = mddev->queue;
	blk_queue_write_cache(mddev->queue, true, true);
	 
	disk->flags |= GENHD_FL_EXT_DEVT;
	mddev->gendisk = disk;
	 
	mutex_lock(&mddev->open_mutex);
	add_disk(disk);

	error = kobject_init_and_add(&mddev->kobj, &md_ktype,
				     &disk_to_dev(disk)->kobj, "%s", "md");
	if (error) {
		 
		printk(KERN_WARNING "md: cannot register %s/md - name in use\n",
		       disk->disk_name);
		error = 0;
	}
	if (mddev->kobj.sd &&
	    sysfs_create_group(&mddev->kobj, &md_bitmap_group))
		printk(KERN_DEBUG "pointless warning\n");
	mutex_unlock(&mddev->open_mutex);
 abort:
	mutex_unlock(&disks_mutex);
	if (!error && mddev->kobj.sd) {
		kobject_uevent(&mddev->kobj, KOBJ_ADD);
		mddev->sysfs_state = sysfs_get_dirent_safe(mddev->kobj.sd, "array_state");
	}
	mddev_put(mddev);
	return error;
}

static struct kobject *md_probe(dev_t dev, int *part, void *data)
{
	md_alloc(dev, NULL);
	return NULL;
}

static int add_named_array(const char *val, struct kernel_param *kp)
{
	 
	int len = strlen(val);
	char buf[DISK_NAME_LEN];

	while (len && val[len-1] == '\n')
		len--;
	if (len >= DISK_NAME_LEN)
		return -E2BIG;
	strlcpy(buf, val, len+1);
	if (strncmp(buf, "md_", 3) != 0)
		return -EINVAL;
	return md_alloc(0, buf);
}

static void md_safemode_timeout(unsigned long data)
{
	struct mddev *mddev = (struct mddev *) data;

	if (!atomic_read(&mddev->writes_pending)) {
		mddev->safemode = 1;
		if (mddev->external)
			sysfs_notify_dirent_safe(mddev->sysfs_state);
	}
	md_wakeup_thread(mddev->thread);
}

#ifdef MY_ABC_HERE
void SYNOLvInfoSet(struct block_device *bdev, void *private, const char *name)
{
	struct mddev *mddev = NULL;
	char *szDiskName = NULL;

	if (!bdev || !private || !name){
		printk("%s:%s(%d) error params\n", __FILE__, __FUNCTION__, __LINE__);
		return;
	}

	szDiskName = bdev->bd_disk->disk_name;
	if (NULL == strstr(szDiskName, "md")) {
		printk("%s:%s(%d) This's not md device:[%s]\n",
			__FILE__, __FUNCTION__, __LINE__, szDiskName);
		return;
	}

	mddev = bdev->bd_disk->private_data;
	if (mddev) {
		mddev->syno_private = private;
	}

	snprintf(mddev->lv_name, 16, "%s", name);
}
EXPORT_SYMBOL(SYNOLvInfoSet);
#endif  

#ifdef MY_ABC_HERE
static int start_dirty_degraded = 1;
#else  
static int start_dirty_degraded;
#endif  

int md_run(struct mddev *mddev)
{
	int err;
	struct md_rdev *rdev;
	struct md_personality *pers;

	if (list_empty(&mddev->disks))
		 
		return -EINVAL;

	if (mddev->pers)
		return -EBUSY;
	 
	if (mddev->sysfs_active)
		return -EBUSY;

	if (!mddev->raid_disks) {
		if (!mddev->persistent)
			return -EINVAL;
		analyze_sbs(mddev);
	}

	if (mddev->level != LEVEL_NONE)
		request_module("md-level-%d", mddev->level);
	else if (mddev->clevel[0])
		request_module("md-%s", mddev->clevel);

	rdev_for_each(rdev, mddev) {
		if (test_bit(Faulty, &rdev->flags))
			continue;
		sync_blockdev(rdev->bdev);
		invalidate_bdev(rdev->bdev);

		if (rdev->meta_bdev) {
			 ;
		} else if (rdev->data_offset < rdev->sb_start) {
			if (mddev->dev_sectors &&
			    rdev->data_offset + mddev->dev_sectors
			    > rdev->sb_start) {
				printk("md: %s: data overlaps metadata\n",
				       mdname(mddev));
				return -EINVAL;
			}
		} else {
			if (rdev->sb_start + rdev->sb_size/512
			    > rdev->data_offset) {
				printk("md: %s: metadata overlaps data\n",
				       mdname(mddev));
				return -EINVAL;
			}
		}
		sysfs_notify_dirent_safe(rdev->sysfs_state);
	}

#ifdef MY_ABC_HERE
	if (mddev->syno_mdio_mempool == NULL) {
		mddev->syno_mdio_mempool = mempool_create_slab_pool(256, syno_mdio_cache);
		if (mddev->syno_mdio_mempool == NULL) {
			return -ENOMEM;
		}
	}
#endif  

	if (mddev->bio_set == NULL)
		mddev->bio_set = bioset_create(BIO_POOL_SIZE, 0);

	spin_lock(&pers_lock);
	pers = find_pers(mddev->level, mddev->clevel);
	if (!pers || !try_module_get(pers->owner)) {
		spin_unlock(&pers_lock);
		if (mddev->level != LEVEL_NONE)
			printk(KERN_WARNING "md: personality for level %d is not loaded!\n",
			       mddev->level);
		else
			printk(KERN_WARNING "md: personality for level %s is not loaded!\n",
			       mddev->clevel);
		return -EINVAL;
	}
	spin_unlock(&pers_lock);
	if (mddev->level != pers->level) {
		mddev->level = pers->level;
		mddev->new_level = pers->level;
	}
	strlcpy(mddev->clevel, pers->name, sizeof(mddev->clevel));

	if (mddev->reshape_position != MaxSector &&
	    pers->start_reshape == NULL) {
		 
		module_put(pers->owner);
		return -EINVAL;
	}

	if (pers->sync_request) {
		 
		char b[BDEVNAME_SIZE], b2[BDEVNAME_SIZE];
		struct md_rdev *rdev2;
		int warned = 0;

		rdev_for_each(rdev, mddev)
			rdev_for_each(rdev2, mddev) {
				if (rdev < rdev2 &&
				    rdev->bdev->bd_contains ==
				    rdev2->bdev->bd_contains) {
					printk(KERN_WARNING
					       "%s: WARNING: %s appears to be"
					       " on the same physical disk as"
					       " %s.\n",
					       mdname(mddev),
					       bdevname(rdev->bdev,b),
					       bdevname(rdev2->bdev,b2));
					warned = 1;
				}
			}

		if (warned)
			printk(KERN_WARNING
			       "True protection against single-disk"
			       " failure might be compromised.\n");
	}

	mddev->recovery = 0;
	 
	mddev->resync_max_sectors = mddev->dev_sectors;

	mddev->ok_start_degraded = start_dirty_degraded;
#ifdef MY_ABC_HERE
	mddev->nodev_and_crashed = 0;
#endif  
#ifdef MY_ABC_HERE
	if (0 == strcmp("md0", mdname(mddev)) || 0 == strcmp("md1", mdname(mddev))) {
		mddev->parallel_resync = 1;
	}
#endif  

	if (start_readonly && mddev->ro == 0)
		mddev->ro = 2;  

	err = pers->run(mddev);
	if (err)
		printk(KERN_ERR "md: pers->run() failed ...\n");
	else if (pers->size(mddev, 0, 0) < mddev->array_sectors) {
		WARN_ONCE(!mddev->external_size, "%s: default size too small,"
			  " but 'external_size' not in effect?\n", __func__);
		printk(KERN_ERR
		       "md: invalid array_size %llu > default size %llu\n",
		       (unsigned long long)mddev->array_sectors / 2,
		       (unsigned long long)pers->size(mddev, 0, 0) / 2);
		err = -EINVAL;
	}
	if (err == 0 && pers->sync_request &&
	    (mddev->bitmap_info.file || mddev->bitmap_info.offset)) {
		struct bitmap *bitmap;

		bitmap = bitmap_create(mddev, -1);
		if (IS_ERR(bitmap)) {
			err = PTR_ERR(bitmap);
			printk(KERN_ERR "%s: failed to create bitmap (%d)\n",
			       mdname(mddev), err);
		} else
			mddev->bitmap = bitmap;

	}
	if (err) {
		mddev_detach(mddev);
		if (mddev->private)
			pers->free(mddev, mddev->private);
		mddev->private = NULL;
		module_put(pers->owner);
		bitmap_destroy(mddev);
		return err;
	}
	if (mddev->queue) {
		mddev->queue->backing_dev_info.congested_data = mddev;
		mddev->queue->backing_dev_info.congested_fn = md_congested;
	}
	if (pers->sync_request) {
		if (mddev->kobj.sd &&
		    sysfs_create_group(&mddev->kobj, &md_redundancy_group))
			printk(KERN_WARNING
			       "md: cannot register extra attributes for %s\n",
			       mdname(mddev));
		mddev->sysfs_action = sysfs_get_dirent_safe(mddev->kobj.sd, "sync_action");
	} else if (mddev->ro == 2)  
		mddev->ro = 0;

	atomic_set(&mddev->writes_pending,0);
	atomic_set(&mddev->max_corr_read_errors,
		   MD_DEFAULT_MAX_CORRECTED_READ_ERRORS);
	mddev->safemode = 0;
	if (mddev_is_clustered(mddev))
		mddev->safemode_delay = 0;
	else
		mddev->safemode_delay = (200 * HZ)/1000 +1;  
	mddev->in_sync = 1;
	smp_wmb();
	spin_lock(&mddev->lock);
	mddev->pers = pers;
	mddev->ready = 1;
	spin_unlock(&mddev->lock);
	rdev_for_each(rdev, mddev)
		if (rdev->raid_disk >= 0)
			if (sysfs_link_rdev(mddev, rdev))
				 ;

	if (mddev->degraded && !mddev->ro)
		 
		set_bit(MD_RECOVERY_RECOVER, &mddev->recovery);
	set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);

	if (mddev->flags & MD_UPDATE_SB_FLAGS)
		md_update_sb(mddev, 0);

	md_new_event(mddev);
	sysfs_notify_dirent_safe(mddev->sysfs_state);
	sysfs_notify_dirent_safe(mddev->sysfs_action);
	sysfs_notify(&mddev->kobj, NULL, "degraded");
	return 0;
}
EXPORT_SYMBOL_GPL(md_run);

static int do_md_run(struct mddev *mddev)
{
	int err;

	err = md_run(mddev);
	if (err)
		goto out;
	err = bitmap_load(mddev);
	if (err) {
		bitmap_destroy(mddev);
		goto out;
	}

	if (mddev_is_clustered(mddev))
		md_allow_write(mddev);

	md_wakeup_thread(mddev->thread);
	md_wakeup_thread(mddev->sync_thread);  

	set_capacity(mddev->gendisk, mddev->array_sectors);
	revalidate_disk(mddev->gendisk);
	mddev->changed = 1;
	kobject_uevent(&disk_to_dev(mddev->gendisk)->kobj, KOBJ_CHANGE);
out:
	return err;
}

static int restart_array(struct mddev *mddev)
{
	struct gendisk *disk = mddev->gendisk;

	if (list_empty(&mddev->disks))
		return -ENXIO;
	if (!mddev->pers)
		return -EINVAL;
	if (!mddev->ro)
		return -EBUSY;
	if (test_bit(MD_HAS_JOURNAL, &mddev->flags)) {
		struct md_rdev *rdev;
		bool has_journal = false;

		rcu_read_lock();
		rdev_for_each_rcu(rdev, mddev) {
			if (test_bit(Journal, &rdev->flags) &&
			    !test_bit(Faulty, &rdev->flags)) {
				has_journal = true;
				break;
			}
		}
		rcu_read_unlock();

		if (!has_journal)
			return -EINVAL;
	}

	mddev->safemode = 0;
	mddev->ro = 0;
	set_disk_ro(disk, 0);
	printk(KERN_INFO "md: %s switched to read-write mode.\n",
		mdname(mddev));
	 
	set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
	md_wakeup_thread(mddev->thread);
	md_wakeup_thread(mddev->sync_thread);
	sysfs_notify_dirent_safe(mddev->sysfs_state);
	return 0;
}

static void md_clean(struct mddev *mddev)
{
	mddev->array_sectors = 0;
	mddev->external_size = 0;
	mddev->dev_sectors = 0;
	mddev->raid_disks = 0;
	mddev->recovery_cp = 0;
	mddev->resync_min = 0;
	mddev->resync_max = MaxSector;
	mddev->reshape_position = MaxSector;
	mddev->external = 0;
	mddev->persistent = 0;
	mddev->level = LEVEL_NONE;
	mddev->clevel[0] = 0;
	mddev->flags = 0;
	mddev->ro = 0;
	mddev->metadata_type[0] = 0;
	mddev->chunk_sectors = 0;
	mddev->ctime = mddev->utime = 0;
	mddev->layout = 0;
	mddev->max_disks = 0;
	mddev->events = 0;
	mddev->can_decrease_events = 0;
	mddev->delta_disks = 0;
	mddev->reshape_backwards = 0;
	mddev->new_level = LEVEL_NONE;
	mddev->new_layout = 0;
	mddev->new_chunk_sectors = 0;
	mddev->curr_resync = 0;
	atomic64_set(&mddev->resync_mismatches, 0);
	mddev->suspend_lo = mddev->suspend_hi = 0;
	mddev->sync_speed_min = mddev->sync_speed_max = 0;
	mddev->recovery = 0;
	mddev->in_sync = 0;
	mddev->changed = 0;
	mddev->degraded = 0;
	mddev->safemode = 0;
	mddev->private = NULL;
	mddev->bitmap_info.offset = 0;
	mddev->bitmap_info.default_offset = 0;
	mddev->bitmap_info.default_space = 0;
	mddev->bitmap_info.chunksize = 0;
	mddev->bitmap_info.daemon_sleep = 0;
	mddev->bitmap_info.max_write_behind = 0;
}

static void __md_stop_writes(struct mddev *mddev)
{
	set_bit(MD_RECOVERY_FROZEN, &mddev->recovery);
	flush_workqueue(md_misc_wq);
	if (mddev->sync_thread) {
		set_bit(MD_RECOVERY_INTR, &mddev->recovery);
		md_reap_sync_thread(mddev);
	}

	del_timer_sync(&mddev->safemode_timer);

	bitmap_flush(mddev);
	md_super_wait(mddev);

	if (mddev->ro == 0 &&
	    ((!mddev->in_sync && !mddev_is_clustered(mddev)) ||
	     (mddev->flags & MD_UPDATE_SB_FLAGS))) {
		 
		if (!mddev_is_clustered(mddev))
			mddev->in_sync = 1;
		md_update_sb(mddev, 1);
	}
}

void md_stop_writes(struct mddev *mddev)
{
	mddev_lock_nointr(mddev);
	__md_stop_writes(mddev);
	mddev_unlock(mddev);
}
EXPORT_SYMBOL_GPL(md_stop_writes);

static void mddev_detach(struct mddev *mddev)
{
	struct bitmap *bitmap = mddev->bitmap;
	 
	if (bitmap && atomic_read(&bitmap->behind_writes) > 0) {
		printk(KERN_INFO "md:%s: behind writes in progress - waiting to stop.\n",
		       mdname(mddev));
		 
		wait_event(bitmap->behind_wait,
			   atomic_read(&bitmap->behind_writes) == 0);
	}
	if (mddev->pers && mddev->pers->quiesce) {
		mddev->pers->quiesce(mddev, 1);
		mddev->pers->quiesce(mddev, 0);
	}
	md_unregister_thread(&mddev->thread);
	if (mddev->queue)
		blk_sync_queue(mddev->queue);  
}

static void __md_stop(struct mddev *mddev)
{
	struct md_personality *pers = mddev->pers;
	mddev_detach(mddev);
	 
	flush_workqueue(md_misc_wq);
	spin_lock(&mddev->lock);
	mddev->ready = 0;
	mddev->pers = NULL;
	spin_unlock(&mddev->lock);
	pers->free(mddev, mddev->private);
	mddev->private = NULL;
	if (pers->sync_request && mddev->to_remove == NULL)
		mddev->to_remove = &md_redundancy_group;
	module_put(pers->owner);
	clear_bit(MD_RECOVERY_FROZEN, &mddev->recovery);
}

void md_stop(struct mddev *mddev)
{
	 
	__md_stop(mddev);
	bitmap_destroy(mddev);
	if (mddev->bio_set)
		bioset_free(mddev->bio_set);
}

EXPORT_SYMBOL_GPL(md_stop);

static int md_set_readonly(struct mddev *mddev, struct block_device *bdev)
{
	int err = 0;
	int did_freeze = 0;

	if (!test_bit(MD_RECOVERY_FROZEN, &mddev->recovery)) {
		did_freeze = 1;
		set_bit(MD_RECOVERY_FROZEN, &mddev->recovery);
		md_wakeup_thread(mddev->thread);
	}
	if (test_bit(MD_RECOVERY_RUNNING, &mddev->recovery))
		set_bit(MD_RECOVERY_INTR, &mddev->recovery);
	if (mddev->sync_thread)
		 
		wake_up_process(mddev->sync_thread->tsk);

	if (mddev->external && test_bit(MD_CHANGE_PENDING, &mddev->flags))
		return -EBUSY;
	mddev_unlock(mddev);
	wait_event(resync_wait, !test_bit(MD_RECOVERY_RUNNING,
					  &mddev->recovery));
	wait_event(mddev->sb_wait,
		   !test_bit(MD_CHANGE_PENDING, &mddev->flags));
	mddev_lock_nointr(mddev);

	mutex_lock(&mddev->open_mutex);
	if ((mddev->pers && atomic_read(&mddev->openers) > !!bdev) ||
	    mddev->sync_thread ||
	    test_bit(MD_RECOVERY_RUNNING, &mddev->recovery) ||
	    (bdev && !test_bit(MD_STILL_CLOSED, &mddev->flags))) {
		printk("md: %s still in use.\n",mdname(mddev));
		if (did_freeze) {
			clear_bit(MD_RECOVERY_FROZEN, &mddev->recovery);
			set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
			md_wakeup_thread(mddev->thread);
		}
		err = -EBUSY;
		goto out;
	}
	if (mddev->pers) {
		__md_stop_writes(mddev);

		err  = -ENXIO;
		if (mddev->ro==1)
			goto out;
		mddev->ro = 1;
		set_disk_ro(mddev->gendisk, 1);
		clear_bit(MD_RECOVERY_FROZEN, &mddev->recovery);
		set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
		md_wakeup_thread(mddev->thread);
		sysfs_notify_dirent_safe(mddev->sysfs_state);
		err = 0;
	}
out:
	mutex_unlock(&mddev->open_mutex);
	return err;
}

static int do_md_stop(struct mddev *mddev, int mode,
		      struct block_device *bdev)
{
	struct gendisk *disk = mddev->gendisk;
	struct md_rdev *rdev;
	int did_freeze = 0;

	if (!test_bit(MD_RECOVERY_FROZEN, &mddev->recovery)) {
		did_freeze = 1;
		set_bit(MD_RECOVERY_FROZEN, &mddev->recovery);
		md_wakeup_thread(mddev->thread);
	}
	if (test_bit(MD_RECOVERY_RUNNING, &mddev->recovery))
		set_bit(MD_RECOVERY_INTR, &mddev->recovery);
	if (mddev->sync_thread)
		 
		wake_up_process(mddev->sync_thread->tsk);

	mddev_unlock(mddev);
	wait_event(resync_wait, (mddev->sync_thread == NULL &&
				 !test_bit(MD_RECOVERY_RUNNING,
					   &mddev->recovery)));
	mddev_lock_nointr(mddev);

	mutex_lock(&mddev->open_mutex);
	if ((mddev->pers && atomic_read(&mddev->openers) > !!bdev) ||
	    mddev->sysfs_active ||
	    mddev->sync_thread ||
	    test_bit(MD_RECOVERY_RUNNING, &mddev->recovery) ||
	    (bdev && !test_bit(MD_STILL_CLOSED, &mddev->flags))) {
		printk("md: %s still in use.\n",mdname(mddev));
		mutex_unlock(&mddev->open_mutex);
		if (did_freeze) {
			clear_bit(MD_RECOVERY_FROZEN, &mddev->recovery);
			set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
			md_wakeup_thread(mddev->thread);
		}
		return -EBUSY;
	}
	if (mddev->pers) {
		if (mddev->ro)
			set_disk_ro(disk, 0);

		__md_stop_writes(mddev);
		__md_stop(mddev);
		mddev->queue->backing_dev_info.congested_fn = NULL;

		sysfs_notify_dirent_safe(mddev->sysfs_state);

		rdev_for_each(rdev, mddev)
			if (rdev->raid_disk >= 0)
				sysfs_unlink_rdev(mddev, rdev);

		set_capacity(disk, 0);
		mutex_unlock(&mddev->open_mutex);
		mddev->changed = 1;
		revalidate_disk(disk);

		if (mddev->ro)
			mddev->ro = 0;
#ifdef MY_ABC_HERE
		mddev->auto_remap = MD_AUTO_REMAP_MODE_FORCE_OFF;
		RaidMemberAutoRemapSet(mddev);
#endif  
	} else
		mutex_unlock(&mddev->open_mutex);
	 
	if (mode == 0) {
		printk(KERN_INFO "md: %s stopped.\n", mdname(mddev));

		bitmap_destroy(mddev);
		if (mddev->bitmap_info.file) {
			struct file *f = mddev->bitmap_info.file;
			spin_lock(&mddev->lock);
			mddev->bitmap_info.file = NULL;
			spin_unlock(&mddev->lock);
			fput(f);
		}
		mddev->bitmap_info.offset = 0;

		export_array(mddev);

		md_clean(mddev);
		kobject_uevent(&disk_to_dev(mddev->gendisk)->kobj, KOBJ_CHANGE);
		if (mddev->hold_active == UNTIL_STOP)
			mddev->hold_active = 0;
	}
	md_new_event(mddev);
	sysfs_notify_dirent_safe(mddev->sysfs_state);
	return 0;
}

#ifndef MODULE
static void autorun_array(struct mddev *mddev)
{
	struct md_rdev *rdev;
	int err;

	if (list_empty(&mddev->disks))
		return;

	printk(KERN_INFO "md: running: ");

	rdev_for_each(rdev, mddev) {
		char b[BDEVNAME_SIZE];
		printk("<%s>", bdevname(rdev->bdev,b));
	}
	printk("\n");

	err = do_md_run(mddev);
	if (err) {
		printk(KERN_WARNING "md: do_md_run() returned %d\n", err);
		do_md_stop(mddev, 0, NULL);
	}
}

static void autorun_devices(int part)
{
	struct md_rdev *rdev0, *rdev, *tmp;
	struct mddev *mddev;
	char b[BDEVNAME_SIZE];

	printk(KERN_INFO "md: autorun ...\n");
	while (!list_empty(&pending_raid_disks)) {
		int unit;
		dev_t dev;
		LIST_HEAD(candidates);
		rdev0 = list_entry(pending_raid_disks.next,
					 struct md_rdev, same_set);

		printk(KERN_INFO "md: considering %s ...\n",
			bdevname(rdev0->bdev,b));
		INIT_LIST_HEAD(&candidates);
		rdev_for_each_list(rdev, tmp, &pending_raid_disks)
			if (super_90_load(rdev, rdev0, 0) >= 0) {
				printk(KERN_INFO "md:  adding %s ...\n",
					bdevname(rdev->bdev,b));
				list_move(&rdev->same_set, &candidates);
			}
		 
		if (part) {
			dev = MKDEV(mdp_major,
				    rdev0->preferred_minor << MdpMinorShift);
			unit = MINOR(dev) >> MdpMinorShift;
		} else {
			dev = MKDEV(MD_MAJOR, rdev0->preferred_minor);
			unit = MINOR(dev);
		}
		if (rdev0->preferred_minor != unit) {
			printk(KERN_INFO "md: unit number in %s is bad: %d\n",
			       bdevname(rdev0->bdev, b), rdev0->preferred_minor);
			break;
		}

		md_probe(dev, NULL, NULL);
		mddev = mddev_find(dev);
		if (!mddev || !mddev->gendisk) {
			if (mddev)
				mddev_put(mddev);
			printk(KERN_ERR
				"md: cannot allocate memory for md drive.\n");
			break;
		}
		if (mddev_lock(mddev))
			printk(KERN_WARNING "md: %s locked, cannot run\n",
			       mdname(mddev));
		else if (mddev->raid_disks || mddev->major_version
			 || !list_empty(&mddev->disks)) {
			printk(KERN_WARNING
				"md: %s already running, cannot run %s\n",
				mdname(mddev), bdevname(rdev0->bdev,b));
			mddev_unlock(mddev);
		} else {
#ifdef MY_ABC_HERE
			mdp_super_t *newest_sb = NULL;
			unsigned int cRaidDisks = 0;
			unsigned int cCandidates = 0;

			struct md_rdev *rdev_newest = NULL;
			rdev_for_each_list(rdev, tmp, &candidates) {
				if (1 == super_90_load(rdev, rdev_newest, mddev->minor_version)) {
					rdev_newest = rdev;
				}
				cCandidates++;
			}

			newest_sb = (mdp_super_t *)page_address(rdev_newest->sb_page);
			cRaidDisks = newest_sb->raid_disks;

			if (cRaidDisks < cCandidates) {
				 
				rdev_for_each_list(rdev, tmp, &candidates) {
					if (rdev != rdev_newest) {
						if (super_90_validate_rdev_event(rdev_newest, rdev)) {
							printk(KERN_WARNING "md: kicking non-fresh %s from candidates rdevs!\n",
								   bdevname(rdev->bdev,b));
							list_del_init(&rdev->same_set);
							export_rdev(rdev);
							continue;
						}
					}
				}
			}
#endif  
			printk(KERN_INFO "md: created %s\n", mdname(mddev));
			mddev->persistent = 1;
			rdev_for_each_list(rdev, tmp, &candidates) {
				list_del_init(&rdev->same_set);
				if (bind_rdev_to_array(rdev, mddev))
					export_rdev(rdev);
			}
			autorun_array(mddev);
			mddev_unlock(mddev);
		}
		 
		rdev_for_each_list(rdev, tmp, &candidates) {
			list_del_init(&rdev->same_set);
			export_rdev(rdev);
		}
		mddev_put(mddev);
	}
	printk(KERN_INFO "md: ... autorun DONE.\n");
}
#endif  

static int get_version(void __user *arg)
{
	mdu_version_t ver;

	ver.major = MD_MAJOR_VERSION;
	ver.minor = MD_MINOR_VERSION;
	ver.patchlevel = MD_PATCHLEVEL_VERSION;

	if (copy_to_user(arg, &ver, sizeof(ver)))
		return -EFAULT;

	return 0;
}

static int get_array_info(struct mddev *mddev, void __user *arg)
{
	mdu_array_info_t info;
	int nr,working,insync,failed,spare;
	struct md_rdev *rdev;

	nr = working = insync = failed = spare = 0;
	rcu_read_lock();
	rdev_for_each_rcu(rdev, mddev) {
		nr++;
		if (test_bit(Faulty, &rdev->flags))
			failed++;
		else {
			working++;
			if (test_bit(In_sync, &rdev->flags))
				insync++;
			else
				spare++;
		}
	}
	rcu_read_unlock();

	info.major_version = mddev->major_version;
	info.minor_version = mddev->minor_version;
	info.patch_version = MD_PATCHLEVEL_VERSION;
	info.ctime         = mddev->ctime;
	info.level         = mddev->level;
	info.size          = mddev->dev_sectors / 2;
	if (info.size != mddev->dev_sectors / 2)  
		info.size = -1;
	info.nr_disks      = nr;
	info.raid_disks    = mddev->raid_disks;
	info.md_minor      = mddev->md_minor;
	info.not_persistent= !mddev->persistent;

	info.utime         = mddev->utime;
	info.state         = 0;
	if (mddev->in_sync)
		info.state = (1<<MD_SB_CLEAN);
	if (mddev->bitmap && mddev->bitmap_info.offset)
		info.state |= (1<<MD_SB_BITMAP_PRESENT);
	if (mddev_is_clustered(mddev))
		info.state |= (1<<MD_SB_CLUSTERED);
	info.active_disks  = insync;
	info.working_disks = working;
	info.failed_disks  = failed;
	info.spare_disks   = spare;

	info.layout        = mddev->layout;
	info.chunk_size    = mddev->chunk_sectors << 9;

	if (copy_to_user(arg, &info, sizeof(info)))
		return -EFAULT;

	return 0;
}

static int get_bitmap_file(struct mddev *mddev, void __user * arg)
{
	mdu_bitmap_file_t *file = NULL;  
	char *ptr;
	int err;

	file = kzalloc(sizeof(*file), GFP_NOIO);
	if (!file)
		return -ENOMEM;

	err = 0;
	spin_lock(&mddev->lock);
	 
	if (mddev->bitmap_info.file) {
		ptr = file_path(mddev->bitmap_info.file, file->pathname,
				sizeof(file->pathname));
		if (IS_ERR(ptr))
			err = PTR_ERR(ptr);
		else
			memmove(file->pathname, ptr,
				sizeof(file->pathname)-(ptr-file->pathname));
	}
	spin_unlock(&mddev->lock);

	if (err == 0 &&
	    copy_to_user(arg, file, sizeof(*file)))
		err = -EFAULT;

	kfree(file);
	return err;
}

static int get_disk_info(struct mddev *mddev, void __user * arg)
{
	mdu_disk_info_t info;
	struct md_rdev *rdev;

	if (copy_from_user(&info, arg, sizeof(info)))
		return -EFAULT;

	rcu_read_lock();
	rdev = md_find_rdev_nr_rcu(mddev, info.number);
	if (rdev) {
		info.major = MAJOR(rdev->bdev->bd_dev);
		info.minor = MINOR(rdev->bdev->bd_dev);
		info.raid_disk = rdev->raid_disk;
		info.state = 0;
		if (test_bit(Faulty, &rdev->flags))
			info.state |= (1<<MD_DISK_FAULTY);
		else if (test_bit(In_sync, &rdev->flags)) {
			info.state |= (1<<MD_DISK_ACTIVE);
			info.state |= (1<<MD_DISK_SYNC);
#ifdef MY_ABC_HERE
			if (test_bit(DiskError, &rdev->flags)) {
				info.state |= (1 << MD_DISK_ERROR);
			}
#endif  
		}
		if (test_bit(Journal, &rdev->flags))
			info.state |= (1<<MD_DISK_JOURNAL);
		if (test_bit(WriteMostly, &rdev->flags))
			info.state |= (1<<MD_DISK_WRITEMOSTLY);
	} else {
		info.major = info.minor = 0;
		info.raid_disk = -1;
		info.state = (1<<MD_DISK_REMOVED);
	}
	rcu_read_unlock();

	if (copy_to_user(arg, &info, sizeof(info)))
		return -EFAULT;

	return 0;
}

static int add_new_disk(struct mddev *mddev, mdu_disk_info_t *info)
{
	char b[BDEVNAME_SIZE], b2[BDEVNAME_SIZE];
	struct md_rdev *rdev;
	dev_t dev = MKDEV(info->major,info->minor);

	if (mddev_is_clustered(mddev) &&
		!(info->state & ((1 << MD_DISK_CLUSTER_ADD) | (1 << MD_DISK_CANDIDATE)))) {
		pr_err("%s: Cannot add to clustered mddev.\n",
			       mdname(mddev));
		return -EINVAL;
	}

	if (info->major != MAJOR(dev) || info->minor != MINOR(dev))
		return -EOVERFLOW;

	if (!mddev->raid_disks) {
		int err;
		 
		rdev = md_import_device(dev, mddev->major_version, mddev->minor_version);
		if (IS_ERR(rdev)) {
			printk(KERN_WARNING
				"md: md_import_device returned %ld\n",
				PTR_ERR(rdev));
			return PTR_ERR(rdev);
		}
		if (!list_empty(&mddev->disks)) {
			struct md_rdev *rdev0
				= list_entry(mddev->disks.next,
					     struct md_rdev, same_set);
			err = super_types[mddev->major_version]
				.load_super(rdev, rdev0, mddev->minor_version);
			if (err < 0) {
				printk(KERN_WARNING
					"md: %s has different UUID to %s\n",
					bdevname(rdev->bdev,b),
					bdevname(rdev0->bdev,b2));
				export_rdev(rdev);
				return -EINVAL;
			}
		}
		err = bind_rdev_to_array(rdev, mddev);
		if (err)
			export_rdev(rdev);
		return err;
	}

	if (mddev->pers) {
		int err;
		if (!mddev->pers->hot_add_disk) {
			printk(KERN_WARNING
				"%s: personality does not support diskops!\n",
			       mdname(mddev));
			return -EINVAL;
		}
		if (mddev->persistent)
			rdev = md_import_device(dev, mddev->major_version,
						mddev->minor_version);
		else
			rdev = md_import_device(dev, -1, -1);
		if (IS_ERR(rdev)) {
			printk(KERN_WARNING
				"md: md_import_device returned %ld\n",
				PTR_ERR(rdev));
			return PTR_ERR(rdev);
		}
		 
		if (!mddev->persistent) {
			if (info->state & (1<<MD_DISK_SYNC)  &&
			    info->raid_disk < mddev->raid_disks) {
				rdev->raid_disk = info->raid_disk;
				set_bit(In_sync, &rdev->flags);
				clear_bit(Bitmap_sync, &rdev->flags);
			} else
				rdev->raid_disk = -1;
			rdev->saved_raid_disk = rdev->raid_disk;
		} else
			super_types[mddev->major_version].
				validate_super(mddev, rdev);
		if ((info->state & (1<<MD_DISK_SYNC)) &&
		     rdev->raid_disk != info->raid_disk) {
			 
			export_rdev(rdev);
			return -EINVAL;
		}

		clear_bit(In_sync, &rdev->flags);  
		if (info->state & (1<<MD_DISK_WRITEMOSTLY))
			set_bit(WriteMostly, &rdev->flags);
		else
			clear_bit(WriteMostly, &rdev->flags);

		if (info->state & (1<<MD_DISK_JOURNAL))
			set_bit(Journal, &rdev->flags);
		 
		if (mddev_is_clustered(mddev)) {
			if (info->state & (1 << MD_DISK_CANDIDATE))
				set_bit(Candidate, &rdev->flags);
			else if (info->state & (1 << MD_DISK_CLUSTER_ADD)) {
				 
				err = md_cluster_ops->add_new_disk(mddev, rdev);
				if (err) {
					export_rdev(rdev);
					return err;
				}
			}
		}

		rdev->raid_disk = -1;
		err = bind_rdev_to_array(rdev, mddev);

		if (err)
			export_rdev(rdev);

		if (mddev_is_clustered(mddev)) {
			if (info->state & (1 << MD_DISK_CANDIDATE))
				md_cluster_ops->new_disk_ack(mddev, (err == 0));
			else {
				if (err)
					md_cluster_ops->add_new_disk_cancel(mddev);
				else
					err = add_bound_rdev(rdev);
			}

		} else if (!err)
			err = add_bound_rdev(rdev);

		return err;
	}

	if (mddev->major_version != 0) {
		printk(KERN_WARNING "%s: ADD_NEW_DISK not supported\n",
		       mdname(mddev));
		return -EINVAL;
	}

	if (!(info->state & (1<<MD_DISK_FAULTY))) {
		int err;
		rdev = md_import_device(dev, -1, 0);
		if (IS_ERR(rdev)) {
			printk(KERN_WARNING
				"md: error, md_import_device() returned %ld\n",
				PTR_ERR(rdev));
			return PTR_ERR(rdev);
		}
		rdev->desc_nr = info->number;
		if (info->raid_disk < mddev->raid_disks)
			rdev->raid_disk = info->raid_disk;
		else
			rdev->raid_disk = -1;

		if (rdev->raid_disk < mddev->raid_disks)
			if (info->state & (1<<MD_DISK_SYNC))
				set_bit(In_sync, &rdev->flags);

		if (info->state & (1<<MD_DISK_WRITEMOSTLY))
			set_bit(WriteMostly, &rdev->flags);

		if (!mddev->persistent) {
			printk(KERN_INFO "md: nonpersistent superblock ...\n");
			rdev->sb_start = i_size_read(rdev->bdev->bd_inode) / 512;
		} else
			rdev->sb_start = calc_dev_sboffset(rdev);
		rdev->sectors = rdev->sb_start;

		err = bind_rdev_to_array(rdev, mddev);
		if (err) {
			export_rdev(rdev);
			return err;
		}
	}

	return 0;
}

static int hot_remove_disk(struct mddev *mddev, dev_t dev)
{
	char b[BDEVNAME_SIZE];
	struct md_rdev *rdev;
	int ret = -1;

	rdev = find_rdev(mddev, dev);
	if (!rdev)
		return -ENXIO;

	if (mddev_is_clustered(mddev))
		ret = md_cluster_ops->metadata_update_start(mddev);

	if (rdev->raid_disk < 0)
		goto kick_rdev;

	clear_bit(Blocked, &rdev->flags);
	remove_and_add_spares(mddev, rdev);

	if (rdev->raid_disk >= 0)
		goto busy;

kick_rdev:
	if (mddev_is_clustered(mddev) && ret == 0)
		md_cluster_ops->remove_disk(mddev, rdev);

	md_kick_rdev_from_array(rdev);
	md_update_sb(mddev, 1);
	md_new_event(mddev);

	return 0;
busy:
	if (mddev_is_clustered(mddev) && ret == 0)
		md_cluster_ops->metadata_update_cancel(mddev);

	printk(KERN_WARNING "md: cannot remove active disk %s from %s ...\n",
		bdevname(rdev->bdev,b), mdname(mddev));
	return -EBUSY;
}

static int hot_add_disk(struct mddev *mddev, dev_t dev)
{
	char b[BDEVNAME_SIZE];
	int err;
	struct md_rdev *rdev;

	if (!mddev->pers)
		return -ENODEV;

	if (mddev->major_version != 0) {
		printk(KERN_WARNING "%s: HOT_ADD may only be used with"
			" version-0 superblocks.\n",
			mdname(mddev));
		return -EINVAL;
	}
	if (!mddev->pers->hot_add_disk) {
		printk(KERN_WARNING
			"%s: personality does not support diskops!\n",
			mdname(mddev));
		return -EINVAL;
	}

	rdev = md_import_device(dev, -1, 0);
	if (IS_ERR(rdev)) {
		printk(KERN_WARNING
			"md: error, md_import_device() returned %ld\n",
			PTR_ERR(rdev));
		return -EINVAL;
	}

	if (mddev->persistent)
		rdev->sb_start = calc_dev_sboffset(rdev);
	else
		rdev->sb_start = i_size_read(rdev->bdev->bd_inode) / 512;

	rdev->sectors = rdev->sb_start;

	if (test_bit(Faulty, &rdev->flags)) {
		printk(KERN_WARNING
			"md: can not hot-add faulty %s disk to %s!\n",
			bdevname(rdev->bdev,b), mdname(mddev));
		err = -EINVAL;
		goto abort_export;
	}

	clear_bit(In_sync, &rdev->flags);
	rdev->desc_nr = -1;
	rdev->saved_raid_disk = -1;
	err = bind_rdev_to_array(rdev, mddev);
	if (err)
		goto abort_export;

	rdev->raid_disk = -1;

	md_update_sb(mddev, 1);
	 
	set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
	md_wakeup_thread(mddev->thread);
	md_new_event(mddev);
	return 0;

abort_export:
	export_rdev(rdev);
	return err;
}

static int set_bitmap_file(struct mddev *mddev, int fd)
{
	int err = 0;

	if (mddev->pers) {
		if (!mddev->pers->quiesce || !mddev->thread)
			return -EBUSY;
		if (mddev->recovery || mddev->sync_thread)
			return -EBUSY;
		 
	}

	if (fd >= 0) {
		struct inode *inode;
		struct file *f;

		if (mddev->bitmap || mddev->bitmap_info.file)
			return -EEXIST;  
		f = fget(fd);

		if (f == NULL) {
			printk(KERN_ERR "%s: error: failed to get bitmap file\n",
			       mdname(mddev));
			return -EBADF;
		}

		inode = f->f_mapping->host;
		if (!S_ISREG(inode->i_mode)) {
			printk(KERN_ERR "%s: error: bitmap file must be a regular file\n",
			       mdname(mddev));
			err = -EBADF;
		} else if (!(f->f_mode & FMODE_WRITE)) {
			printk(KERN_ERR "%s: error: bitmap file must open for write\n",
			       mdname(mddev));
			err = -EBADF;
		} else if (atomic_read(&inode->i_writecount) != 1) {
			printk(KERN_ERR "%s: error: bitmap file is already in use\n",
			       mdname(mddev));
			err = -EBUSY;
		}
		if (err) {
			fput(f);
			return err;
		}
		mddev->bitmap_info.file = f;
		mddev->bitmap_info.offset = 0;  
	} else if (mddev->bitmap == NULL)
		return -ENOENT;  
	err = 0;
	if (mddev->pers) {
		mddev->pers->quiesce(mddev, 1);
		if (fd >= 0) {
			struct bitmap *bitmap;

			bitmap = bitmap_create(mddev, -1);
			if (!IS_ERR(bitmap)) {
				mddev->bitmap = bitmap;
				err = bitmap_load(mddev);
			} else
				err = PTR_ERR(bitmap);
		}
		if (fd < 0 || err) {
			bitmap_destroy(mddev);
			fd = -1;  
		}
		mddev->pers->quiesce(mddev, 0);
	}
	if (fd < 0) {
		struct file *f = mddev->bitmap_info.file;
		if (f) {
			spin_lock(&mddev->lock);
			mddev->bitmap_info.file = NULL;
			spin_unlock(&mddev->lock);
			fput(f);
		}
	}

	return err;
}

static int set_array_info(struct mddev *mddev, mdu_array_info_t *info)
{

	if (info->raid_disks == 0) {
		 
		if (info->major_version < 0 ||
		    info->major_version >= ARRAY_SIZE(super_types) ||
		    super_types[info->major_version].name == NULL) {
			 
			printk(KERN_INFO
				"md: superblock version %d not known\n",
				info->major_version);
			return -EINVAL;
		}
		mddev->major_version = info->major_version;
		mddev->minor_version = info->minor_version;
		mddev->patch_version = info->patch_version;
		mddev->persistent = !info->not_persistent;
		 
		mddev->ctime         = get_seconds();
		return 0;
	}
	mddev->major_version = MD_MAJOR_VERSION;
	mddev->minor_version = MD_MINOR_VERSION;
	mddev->patch_version = MD_PATCHLEVEL_VERSION;
	mddev->ctime         = get_seconds();

	mddev->level         = info->level;
	mddev->clevel[0]     = 0;
	mddev->dev_sectors   = 2 * (sector_t)info->size;
	mddev->raid_disks    = info->raid_disks;
	 
	if (info->state & (1<<MD_SB_CLEAN))
		mddev->recovery_cp = MaxSector;
	else
		mddev->recovery_cp = 0;
	mddev->persistent    = ! info->not_persistent;
	mddev->external	     = 0;

	mddev->layout        = info->layout;
	mddev->chunk_sectors = info->chunk_size >> 9;

	mddev->max_disks     = MD_SB_DISKS;

	if (mddev->persistent)
		mddev->flags         = 0;
	set_bit(MD_CHANGE_DEVS, &mddev->flags);

	mddev->bitmap_info.default_offset = MD_SB_BYTES >> 9;
	mddev->bitmap_info.default_space = 64*2 - (MD_SB_BYTES >> 9);
	mddev->bitmap_info.offset = 0;

	mddev->reshape_position = MaxSector;

	get_random_bytes(mddev->uuid, 16);

	mddev->new_level = mddev->level;
	mddev->new_chunk_sectors = mddev->chunk_sectors;
	mddev->new_layout = mddev->layout;
	mddev->delta_disks = 0;
	mddev->reshape_backwards = 0;

	return 0;
}

void md_set_array_sectors(struct mddev *mddev, sector_t array_sectors)
{
	WARN(!mddev_is_locked(mddev), "%s: unlocked mddev!\n", __func__);

	if (mddev->external_size)
		return;

	mddev->array_sectors = array_sectors;
}
EXPORT_SYMBOL(md_set_array_sectors);

static int update_size(struct mddev *mddev, sector_t num_sectors)
{
	struct md_rdev *rdev;
	int rv;
	int fit = (num_sectors == 0);

	if (mddev->pers->resize == NULL)
		return -EINVAL;
	 
	if (test_bit(MD_RECOVERY_RUNNING, &mddev->recovery) ||
	    mddev->sync_thread)
		return -EBUSY;
	if (mddev->ro)
		return -EROFS;

	rdev_for_each(rdev, mddev) {
		sector_t avail = rdev->sectors;

		if (fit && (num_sectors == 0 || num_sectors > avail))
			num_sectors = avail;
		if (avail < num_sectors)
			return -ENOSPC;
	}
	rv = mddev->pers->resize(mddev, num_sectors);
	if (!rv)
		revalidate_disk(mddev->gendisk);
	return rv;
}

static int update_raid_disks(struct mddev *mddev, int raid_disks)
{
	int rv;
	struct md_rdev *rdev;
	 
	if (mddev->pers->check_reshape == NULL)
		return -EINVAL;
	if (mddev->ro)
		return -EROFS;
	if (raid_disks <= 0 ||
	    (mddev->max_disks && raid_disks >= mddev->max_disks))
		return -EINVAL;
	if (mddev->sync_thread ||
	    test_bit(MD_RECOVERY_RUNNING, &mddev->recovery) ||
	    mddev->reshape_position != MaxSector)
		return -EBUSY;

	rdev_for_each(rdev, mddev) {
		if (mddev->raid_disks < raid_disks &&
		    rdev->data_offset < rdev->new_data_offset)
			return -EINVAL;
		if (mddev->raid_disks > raid_disks &&
		    rdev->data_offset > rdev->new_data_offset)
			return -EINVAL;
	}

	mddev->delta_disks = raid_disks - mddev->raid_disks;
	if (mddev->delta_disks < 0)
		mddev->reshape_backwards = 1;
	else if (mddev->delta_disks > 0)
		mddev->reshape_backwards = 0;

	rv = mddev->pers->check_reshape(mddev);
	if (rv < 0) {
		mddev->delta_disks = 0;
		mddev->reshape_backwards = 0;
	}
	return rv;
}

static int update_array_info(struct mddev *mddev, mdu_array_info_t *info)
{
	int rv = 0;
	int cnt = 0;
	int state = 0;

	if (mddev->bitmap && mddev->bitmap_info.offset)
		state |= (1 << MD_SB_BITMAP_PRESENT);

	if (mddev->major_version != info->major_version ||
	    mddev->minor_version != info->minor_version ||
 
	    mddev->ctime         != info->ctime         ||
	    mddev->level         != info->level         ||
 
	    mddev->persistent	 != !info->not_persistent ||
	    mddev->chunk_sectors != info->chunk_size >> 9 ||
	     
	    ((state^info->state) & 0xfffffe00)
		)
		return -EINVAL;
	 
	if (info->size >= 0 && mddev->dev_sectors / 2 != info->size)
		cnt++;
	if (mddev->raid_disks != info->raid_disks)
		cnt++;
	if (mddev->layout != info->layout)
		cnt++;
	if ((state ^ info->state) & (1<<MD_SB_BITMAP_PRESENT))
		cnt++;
	if (cnt == 0)
		return 0;
	if (cnt > 1)
		return -EINVAL;

	if (mddev->layout != info->layout) {
		 
		if (mddev->pers->check_reshape == NULL)
			return -EINVAL;
		else {
			mddev->new_layout = info->layout;
			rv = mddev->pers->check_reshape(mddev);
			if (rv)
				mddev->new_layout = mddev->layout;
			return rv;
		}
	}
	if (info->size >= 0 && mddev->dev_sectors / 2 != info->size)
		rv = update_size(mddev, (sector_t)info->size * 2);

	if (mddev->raid_disks    != info->raid_disks)
		rv = update_raid_disks(mddev, info->raid_disks);

	if ((state ^ info->state) & (1<<MD_SB_BITMAP_PRESENT)) {
		if (mddev->pers->quiesce == NULL || mddev->thread == NULL) {
			rv = -EINVAL;
			goto err;
		}
		if (mddev->recovery || mddev->sync_thread) {
			rv = -EBUSY;
			goto err;
		}
		if (info->state & (1<<MD_SB_BITMAP_PRESENT)) {
			struct bitmap *bitmap;
			 
			if (mddev->bitmap) {
				rv = -EEXIST;
				goto err;
			}
			if (mddev->bitmap_info.default_offset == 0) {
				rv = -EINVAL;
				goto err;
			}
			mddev->bitmap_info.offset =
				mddev->bitmap_info.default_offset;
			mddev->bitmap_info.space =
				mddev->bitmap_info.default_space;
			mddev->pers->quiesce(mddev, 1);
			bitmap = bitmap_create(mddev, -1);
			if (!IS_ERR(bitmap)) {
				mddev->bitmap = bitmap;
				rv = bitmap_load(mddev);
			} else
				rv = PTR_ERR(bitmap);
			if (rv)
				bitmap_destroy(mddev);
			mddev->pers->quiesce(mddev, 0);
		} else {
			 
			if (!mddev->bitmap) {
				rv = -ENOENT;
				goto err;
			}
			if (mddev->bitmap->storage.file) {
				rv = -EINVAL;
				goto err;
			}
			mddev->pers->quiesce(mddev, 1);
			bitmap_destroy(mddev);
			mddev->pers->quiesce(mddev, 0);
			mddev->bitmap_info.offset = 0;
		}
	}
	md_update_sb(mddev, 1);
	return rv;
err:
	return rv;
}

static int set_disk_faulty(struct mddev *mddev, dev_t dev)
{
	struct md_rdev *rdev;
	int err = 0;

	if (mddev->pers == NULL)
		return -ENODEV;

	rcu_read_lock();
	rdev = find_rdev_rcu(mddev, dev);
	if (!rdev)
		err =  -ENODEV;
	else {
		md_error(mddev, rdev);
		if (!test_bit(Faulty, &rdev->flags))
			err = -EBUSY;
	}
	rcu_read_unlock();
	return err;
}

static int md_getgeo(struct block_device *bdev, struct hd_geometry *geo)
{
	struct mddev *mddev = bdev->bd_disk->private_data;

	geo->heads = 2;
	geo->sectors = 4;
	geo->cylinders = mddev->array_sectors / 8;
	return 0;
}

static inline bool md_ioctl_valid(unsigned int cmd)
{
	switch (cmd) {
	case ADD_NEW_DISK:
	case BLKROSET:
	case GET_ARRAY_INFO:
	case GET_BITMAP_FILE:
	case GET_DISK_INFO:
	case HOT_ADD_DISK:
	case HOT_REMOVE_DISK:
	case RAID_AUTORUN:
	case RAID_VERSION:
	case RESTART_ARRAY_RW:
	case RUN_ARRAY:
	case SET_ARRAY_INFO:
	case SET_BITMAP_FILE:
	case SET_DISK_FAULTY:
	case STOP_ARRAY:
	case STOP_ARRAY_RO:
	case CLUSTERED_DISK_NACK:
#ifdef MY_ABC_HERE
	case GET_ARRAY_STATUS:
	case GET_SYNC_STATUS:
#endif  
		return true;
	default:
		return false;
	}
}

static int md_ioctl(struct block_device *bdev, fmode_t mode,
			unsigned int cmd, unsigned long arg)
{
	int err = 0;
	void __user *argp = (void __user *)arg;
	struct mddev *mddev = NULL;
	int ro;

	if (!md_ioctl_valid(cmd))
		return -ENOTTY;

	switch (cmd) {
	case RAID_VERSION:
	case GET_ARRAY_INFO:
	case GET_DISK_INFO:
		break;
	default:
		if (!capable(CAP_SYS_ADMIN))
			return -EACCES;
	}

	switch (cmd) {
	case RAID_VERSION:
		err = get_version(argp);
		goto out;

#ifndef MODULE
	case RAID_AUTORUN:
		err = 0;
		autostart_arrays(arg);
		goto out;
#endif
	default:;
	}

	mddev = bdev->bd_disk->private_data;

	if (!mddev) {
		BUG();
		goto out;
	}

	switch (cmd) {
	case GET_ARRAY_INFO:
		if (!mddev->raid_disks && !mddev->external)
			err = -ENODEV;
		else
			err = get_array_info(mddev, argp);
		goto out;

	case GET_DISK_INFO:
		if (!mddev->raid_disks && !mddev->external)
			err = -ENODEV;
		else
			err = get_disk_info(mddev, argp);
		goto out;

	case SET_DISK_FAULTY:
		err = set_disk_faulty(mddev, new_decode_dev(arg));
		goto out;

	case GET_BITMAP_FILE:
		err = get_bitmap_file(mddev, argp);
		goto out;

	}

	if (cmd == ADD_NEW_DISK)
		 
		flush_workqueue(md_misc_wq);

	if (cmd == HOT_REMOVE_DISK)
		 
		wait_event_interruptible_timeout(mddev->sb_wait,
						 !test_bit(MD_RECOVERY_NEEDED,
							   &mddev->recovery),
						 msecs_to_jiffies(5000));
	if (cmd == STOP_ARRAY || cmd == STOP_ARRAY_RO) {
		 
		mutex_lock(&mddev->open_mutex);
		if (mddev->pers && atomic_read(&mddev->openers) > 1) {
			mutex_unlock(&mddev->open_mutex);
			err = -EBUSY;
			goto out;
		}
		set_bit(MD_STILL_CLOSED, &mddev->flags);
		mutex_unlock(&mddev->open_mutex);
		sync_blockdev(bdev);
	}
	err = mddev_lock(mddev);
	if (err) {
		printk(KERN_INFO
			"md: ioctl lock interrupted, reason %d, cmd %d\n",
			err, cmd);
		goto out;
	}

	if (cmd == SET_ARRAY_INFO) {
		mdu_array_info_t info;
		if (!arg)
			memset(&info, 0, sizeof(info));
		else if (copy_from_user(&info, argp, sizeof(info))) {
			err = -EFAULT;
			goto unlock;
		}
		if (mddev->pers) {
			err = update_array_info(mddev, &info);
			if (err) {
				printk(KERN_WARNING "md: couldn't update"
				       " array info. %d\n", err);
				goto unlock;
			}
			goto unlock;
		}
		if (!list_empty(&mddev->disks)) {
			printk(KERN_WARNING
			       "md: array %s already has disks!\n",
			       mdname(mddev));
			err = -EBUSY;
			goto unlock;
		}
		if (mddev->raid_disks) {
			printk(KERN_WARNING
			       "md: array %s already initialised!\n",
			       mdname(mddev));
			err = -EBUSY;
			goto unlock;
		}
		err = set_array_info(mddev, &info);
		if (err) {
			printk(KERN_WARNING "md: couldn't set"
			       " array info. %d\n", err);
			goto unlock;
		}
		goto unlock;
	}

	if ((!mddev->raid_disks && !mddev->external)
	    && cmd != ADD_NEW_DISK && cmd != STOP_ARRAY
	    && cmd != RUN_ARRAY && cmd != SET_BITMAP_FILE
	    && cmd != GET_BITMAP_FILE) {
		err = -ENODEV;
		goto unlock;
	}

	switch (cmd) {
	case RESTART_ARRAY_RW:
		err = restart_array(mddev);
		goto unlock;

	case STOP_ARRAY:
		err = do_md_stop(mddev, 0, bdev);
		goto unlock;

	case STOP_ARRAY_RO:
		err = md_set_readonly(mddev, bdev);
		goto unlock;

	case HOT_REMOVE_DISK:
		err = hot_remove_disk(mddev, new_decode_dev(arg));
		goto unlock;

	case ADD_NEW_DISK:
		 
		if (mddev->pers) {
			mdu_disk_info_t info;
			if (copy_from_user(&info, argp, sizeof(info)))
				err = -EFAULT;
			else if (!(info.state & (1<<MD_DISK_SYNC)))
				 
				break;
			else
				err = add_new_disk(mddev, &info);
			goto unlock;
		}
		break;

	case BLKROSET:
		if (get_user(ro, (int __user *)(arg))) {
			err = -EFAULT;
			goto unlock;
		}
		err = -EINVAL;

		if (ro)
			goto unlock;

		if (mddev->ro != 1)
			goto unlock;

		if (mddev->pers) {
			err = restart_array(mddev);
			if (err == 0) {
				mddev->ro = 2;
				set_disk_ro(mddev->gendisk, 0);
			}
		}
		goto unlock;
	}

	if (mddev->ro && mddev->pers) {
		if (mddev->ro == 2) {
			mddev->ro = 0;
			sysfs_notify_dirent_safe(mddev->sysfs_state);
			set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
			 
			if (test_bit(MD_CHANGE_DEVS, &mddev->flags)) {
				mddev_unlock(mddev);
				wait_event(mddev->sb_wait,
					   !test_bit(MD_CHANGE_DEVS, &mddev->flags) &&
					   !test_bit(MD_CHANGE_PENDING, &mddev->flags));
				mddev_lock_nointr(mddev);
			}
		} else {
			err = -EROFS;
			goto unlock;
		}
	}

	switch (cmd) {
	case ADD_NEW_DISK:
	{
		mdu_disk_info_t info;
		if (copy_from_user(&info, argp, sizeof(info)))
			err = -EFAULT;
		else
			err = add_new_disk(mddev, &info);
		goto unlock;
	}

	case CLUSTERED_DISK_NACK:
		if (mddev_is_clustered(mddev))
			md_cluster_ops->new_disk_ack(mddev, false);
		else
			err = -EINVAL;
		goto unlock;

	case HOT_ADD_DISK:
		err = hot_add_disk(mddev, new_decode_dev(arg));
		goto unlock;

	case RUN_ARRAY:
		err = do_md_run(mddev);
		goto unlock;

	case SET_BITMAP_FILE:
		err = set_bitmap_file(mddev, (int)arg);
		goto unlock;

#ifdef MY_ABC_HERE
	 
	case GET_ARRAY_STATUS:
	{
		int ret = 0;
#ifdef MY_ABC_HERE
		struct md_rdev *rdev;
#endif  

		if (mddev->degraded)
			ret = 1;

#ifdef MY_ABC_HERE
		if (mddev->nodev_and_crashed)
			ret = 2;
#endif  

#ifdef MY_ABC_HERE
		list_for_each_entry(rdev, &mddev->disks, same_set) {
			if (test_bit(DiskError, &rdev->flags))
				ret = 2;
		}
#endif  

		if (copy_to_user(argp, &ret, sizeof(ret))) {
			err = -EFAULT;
			goto unlock;
		}
		break;
	}
	case GET_SYNC_STATUS:
	{
		MD_SYNC_STATUS status;
		if (test_bit(MD_RECOVERY_RUNNING, &mddev->recovery) ||
			test_bit(MD_RECOVERY_NEEDED, &mddev->recovery)) {
			status.inSync = 1;
		} else {
			status.inSync = 0;
		}
		if (0 == mddev->level || LEVEL_LINEAR == mddev->level) {
			 
			status.inSync = 0;
		}
		if (mddev->curr_resync > 2) {
			status.finishSectors = (mddev->curr_resync - atomic_read(&mddev->recovery_active));
		} else {
			status.finishSectors = 0;
		}

		if (test_bit(MD_RECOVERY_SYNC, &mddev->recovery))
			status.totalSectors = mddev->resync_max_sectors;
		else
			status.totalSectors = mddev->dev_sectors;

		if (copy_to_user(argp, &status, sizeof(status))) {
			err = -EFAULT;
			goto unlock;
		}
		break;
	}
#endif  
	default:
		err = -EINVAL;
		goto unlock;
	}

unlock:
	if (mddev->hold_active == UNTIL_IOCTL &&
	    err != -EINVAL)
		mddev->hold_active = 0;
	mddev_unlock(mddev);
out:
	return err;
}
#ifdef CONFIG_COMPAT
static int md_compat_ioctl(struct block_device *bdev, fmode_t mode,
		    unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case HOT_REMOVE_DISK:
	case HOT_ADD_DISK:
	case SET_DISK_FAULTY:
	case SET_BITMAP_FILE:
		 
		break;
	default:
		arg = (unsigned long)compat_ptr(arg);
		break;
	}

	return md_ioctl(bdev, mode, cmd, arg);
}
#endif  

static int md_open(struct block_device *bdev, fmode_t mode)
{
	 
	struct mddev *mddev = mddev_find(bdev->bd_dev);
	int err;

	if (!mddev)
		return -ENODEV;

	if (mddev->gendisk != bdev->bd_disk) {
		 
		mddev_put(mddev);
		 
		flush_workqueue(md_misc_wq);
		 
		return -ERESTARTSYS;
	}
	BUG_ON(mddev != bdev->bd_disk->private_data);

	if ((err = mutex_lock_interruptible(&mddev->open_mutex)))
		goto out;

	err = 0;
	atomic_inc(&mddev->openers);
	clear_bit(MD_STILL_CLOSED, &mddev->flags);
	mutex_unlock(&mddev->open_mutex);

	check_disk_change(bdev);
 out:
	return err;
}

static void md_release(struct gendisk *disk, fmode_t mode)
{
	struct mddev *mddev = disk->private_data;

	BUG_ON(!mddev);
	atomic_dec(&mddev->openers);
	mddev_put(mddev);
}

static int md_media_changed(struct gendisk *disk)
{
	struct mddev *mddev = disk->private_data;

	return mddev->changed;
}

static int md_revalidate(struct gendisk *disk)
{
	struct mddev *mddev = disk->private_data;

	mddev->changed = 0;
	return 0;
}
static const struct block_device_operations md_fops =
{
	.owner		= THIS_MODULE,
	.open		= md_open,
	.release	= md_release,
	.ioctl		= md_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= md_compat_ioctl,
#endif
	.getgeo		= md_getgeo,
	.media_changed  = md_media_changed,
	.revalidate_disk= md_revalidate,
};

static int md_thread(void *arg)
{
	struct md_thread *thread = arg;

	allow_signal(SIGKILL);
	while (!kthread_should_stop()) {

		if (signal_pending(current))
			flush_signals(current);

		wait_event_interruptible_timeout
			(thread->wqueue,
			 test_bit(THREAD_WAKEUP, &thread->flags)
			 || kthread_should_stop(),
			 thread->timeout);

		clear_bit(THREAD_WAKEUP, &thread->flags);
		if (!kthread_should_stop())
			thread->run(thread);
	}

	return 0;
}

void md_wakeup_thread(struct md_thread *thread)
{
	if (thread) {
		pr_debug("md: waking up MD thread %s.\n", thread->tsk->comm);
		set_bit(THREAD_WAKEUP, &thread->flags);
		wake_up(&thread->wqueue);
	}
}
EXPORT_SYMBOL(md_wakeup_thread);

struct md_thread *md_register_thread(void (*run) (struct md_thread *),
		struct mddev *mddev, const char *name)
{
	struct md_thread *thread;

	thread = kzalloc(sizeof(struct md_thread), GFP_KERNEL);
	if (!thread)
		return NULL;

	init_waitqueue_head(&thread->wqueue);

	thread->run = run;
	thread->mddev = mddev;
	thread->timeout = MAX_SCHEDULE_TIMEOUT;
	thread->tsk = kthread_run(md_thread, thread,
				  "%s_%s",
				  mdname(thread->mddev),
				  name);
	if (IS_ERR(thread->tsk)) {
		kfree(thread);
		return NULL;
	}
	return thread;
}
EXPORT_SYMBOL(md_register_thread);

void md_unregister_thread(struct md_thread **threadp)
{
	struct md_thread *thread = *threadp;
	if (!thread)
		return;
	pr_debug("interrupting MD-thread pid %d\n", task_pid_nr(thread->tsk));
	 
	spin_lock(&pers_lock);
	*threadp = NULL;
	spin_unlock(&pers_lock);

	kthread_stop(thread->tsk);
	kfree(thread);
}
EXPORT_SYMBOL(md_unregister_thread);

void md_error(struct mddev *mddev, struct md_rdev *rdev)
{
	if (!rdev || test_bit(Faulty, &rdev->flags))
		return;

	if (!mddev->pers || !mddev->pers->error_handler)
		return;
	mddev->pers->error_handler(mddev,rdev);
	if (mddev->degraded)
		set_bit(MD_RECOVERY_RECOVER, &mddev->recovery);
	sysfs_notify_dirent_safe(rdev->sysfs_state);
	set_bit(MD_RECOVERY_INTR, &mddev->recovery);
	set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
#ifdef MY_ABC_HERE
	if (test_bit(MD_RECOVERY_RESHAPE, &mddev->recovery)) {
		mddev->reshape_interrupt = 1;
	}
#endif  
	md_wakeup_thread(mddev->thread);
	if (mddev->event_work.func)
		queue_work(md_misc_wq, &mddev->event_work);
	md_new_event_inintr(mddev);
}
EXPORT_SYMBOL(md_error);

static void status_unused(struct seq_file *seq)
{
	int i = 0;
	struct md_rdev *rdev;

	seq_printf(seq, "unused devices: ");

	list_for_each_entry(rdev, &pending_raid_disks, same_set) {
		char b[BDEVNAME_SIZE];
		i++;
		seq_printf(seq, "%s ",
			      bdevname(rdev->bdev,b));
	}
	if (!i)
		seq_printf(seq, "<none>");

	seq_printf(seq, "\n");
}

static int status_resync(struct seq_file *seq, struct mddev *mddev)
{
	sector_t max_sectors, resync, res;
	unsigned long dt, db;
	sector_t rt;
	int scale;
	unsigned int per_milli;

	if (test_bit(MD_RECOVERY_SYNC, &mddev->recovery) ||
	    test_bit(MD_RECOVERY_RESHAPE, &mddev->recovery))
		max_sectors = mddev->resync_max_sectors;
	else
		max_sectors = mddev->dev_sectors;

	resync = mddev->curr_resync;
	if (resync <= 3) {
		if (test_bit(MD_RECOVERY_DONE, &mddev->recovery))
			 
			resync = max_sectors;
	} else
		resync -= atomic_read(&mddev->recovery_active);

	if (resync == 0) {
		if (mddev->recovery_cp < MaxSector) {
			seq_printf(seq, "\tresync=PENDING");
			return 1;
		}
		return 0;
	}
	if (resync < 3) {
		seq_printf(seq, "\tresync=DELAYED");
		return 1;
	}

	WARN_ON(max_sectors == 0);
	 
	scale = 10;
	if (sizeof(sector_t) > sizeof(unsigned long)) {
		while ( max_sectors/2 > (1ULL<<(scale+32)))
			scale++;
	}
	res = (resync>>scale)*1000;
	sector_div(res, (u32)((max_sectors>>scale)+1));

	per_milli = res;
	{
		int i, x = per_milli/50, y = 20-x;
		seq_printf(seq, "[");
		for (i = 0; i < x; i++)
			seq_printf(seq, "=");
		seq_printf(seq, ">");
		for (i = 0; i < y; i++)
			seq_printf(seq, ".");
		seq_printf(seq, "] ");
	}
	seq_printf(seq, " %s =%3u.%u%% (%llu/%llu)",
		   (test_bit(MD_RECOVERY_RESHAPE, &mddev->recovery)?
		    "reshape" :
		    (test_bit(MD_RECOVERY_CHECK, &mddev->recovery)?
		     "check" :
		     (test_bit(MD_RECOVERY_SYNC, &mddev->recovery) ?
		      "resync" : "recovery"))),
		   per_milli/10, per_milli % 10,
		   (unsigned long long) resync/2,
		   (unsigned long long) max_sectors/2);

	dt = ((jiffies - mddev->resync_mark) / HZ);
	if (!dt) dt++;
	db = (mddev->curr_mark_cnt - atomic_read(&mddev->recovery_active))
		- mddev->resync_mark_cnt;

	rt = max_sectors - resync;     
	sector_div(rt, db/32+1);
	rt *= dt;
	rt >>= 5;

	seq_printf(seq, " finish=%lu.%lumin", (unsigned long)rt / 60,
		   ((unsigned long)rt % 60)/6);

	seq_printf(seq, " speed=%ldK/sec", db/2/dt);
	return 1;
}

static void *md_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct list_head *tmp;
	loff_t l = *pos;
	struct mddev *mddev;

	if (l >= 0x10000)
		return NULL;
	if (!l--)
		 
		return (void*)1;

	spin_lock(&all_mddevs_lock);
	list_for_each(tmp,&all_mddevs)
		if (!l--) {
			mddev = list_entry(tmp, struct mddev, all_mddevs);
			mddev_get(mddev);
			spin_unlock(&all_mddevs_lock);
			return mddev;
		}
	spin_unlock(&all_mddevs_lock);
	if (!l--)
		return (void*)2; 
	return NULL;
}

static void *md_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct list_head *tmp;
	struct mddev *next_mddev, *mddev = v;

	++*pos;
	if (v == (void*)2)
		return NULL;

	spin_lock(&all_mddevs_lock);
	if (v == (void*)1)
		tmp = all_mddevs.next;
	else
		tmp = mddev->all_mddevs.next;
	if (tmp != &all_mddevs)
		next_mddev = mddev_get(list_entry(tmp,struct mddev,all_mddevs));
	else {
		next_mddev = (void*)2;
		*pos = 0x10000;
	}
	spin_unlock(&all_mddevs_lock);

	if (v != (void*)1)
		mddev_put(mddev);
	return next_mddev;

}

static void md_seq_stop(struct seq_file *seq, void *v)
{
	struct mddev *mddev = v;

	if (mddev && v != (void*)1 && v != (void*)2)
		mddev_put(mddev);
}

static int md_seq_show(struct seq_file *seq, void *v)
{
	struct mddev *mddev = v;
	sector_t sectors;
	struct md_rdev *rdev;

	if (v == (void*)1) {
		struct md_personality *pers;
		seq_printf(seq, "Personalities : ");
		spin_lock(&pers_lock);
		list_for_each_entry(pers, &pers_list, list)
			seq_printf(seq, "[%s] ", pers->name);

		spin_unlock(&pers_lock);
		seq_printf(seq, "\n");
		seq->poll_event = atomic_read(&md_event_count);
		return 0;
	}
	if (v == (void*)2) {
		status_unused(seq);
		return 0;
	}

	spin_lock(&mddev->lock);
	if (mddev->pers || mddev->raid_disks || !list_empty(&mddev->disks)) {
		seq_printf(seq, "%s : %sactive", mdname(mddev),
						mddev->pers ? "" : "in");
		if (mddev->pers) {
			if (mddev->ro==1)
				seq_printf(seq, " (read-only)");
			if (mddev->ro==2)
				seq_printf(seq, " (auto-read-only)");
			seq_printf(seq, " %s", mddev->pers->name);
		}

		sectors = 0;
		rcu_read_lock();
		rdev_for_each_rcu(rdev, mddev) {
			char b[BDEVNAME_SIZE];
			seq_printf(seq, " %s[%d]",
				bdevname(rdev->bdev,b), rdev->desc_nr);
			if (test_bit(WriteMostly, &rdev->flags))
				seq_printf(seq, "(W)");
			if (test_bit(Journal, &rdev->flags))
				seq_printf(seq, "(J)");
			if (test_bit(Faulty, &rdev->flags)) {
				seq_printf(seq, "(F)");
				continue;
			}
#ifdef MY_ABC_HERE
			if (test_bit(DiskError, &rdev->flags)) {
				seq_printf(seq, "(E)");
				continue;
			}
#endif  
			if (rdev->raid_disk < 0)
				seq_printf(seq, "(S)");  
			if (test_bit(Replacement, &rdev->flags))
				seq_printf(seq, "(R)");
			sectors += rdev->sectors;
		}
		rcu_read_unlock();

		if (!list_empty(&mddev->disks)) {
			if (mddev->pers)
				seq_printf(seq, "\n      %llu blocks",
					   (unsigned long long)
					   mddev->array_sectors / 2);
			else
				seq_printf(seq, "\n      %llu blocks",
					   (unsigned long long)sectors / 2);
		}
		if (mddev->persistent) {
			if (mddev->major_version != 0 ||
			    mddev->minor_version != 90) {
				seq_printf(seq," super %d.%d",
					   mddev->major_version,
					   mddev->minor_version);
			}
		} else if (mddev->external)
			seq_printf(seq, " super external:%s",
				   mddev->metadata_type);
		else
			seq_printf(seq, " super non-persistent");

		if (mddev->pers) {
			mddev->pers->status(seq, mddev);
			seq_printf(seq, "\n      ");
			if (mddev->pers->sync_request) {
				if (status_resync(seq, mddev))
					seq_printf(seq, "\n      ");
			}
		} else
			seq_printf(seq, "\n       ");

		bitmap_status(seq, mddev->bitmap);

		seq_printf(seq, "\n");
	}
	spin_unlock(&mddev->lock);

	return 0;
}

static const struct seq_operations md_seq_ops = {
	.start  = md_seq_start,
	.next   = md_seq_next,
	.stop   = md_seq_stop,
	.show   = md_seq_show,
};

static int md_seq_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int error;

	error = seq_open(file, &md_seq_ops);
	if (error)
		return error;

	seq = file->private_data;
	seq->poll_event = atomic_read(&md_event_count);
	return error;
}

static int md_unloading;
static unsigned int mdstat_poll(struct file *filp, poll_table *wait)
{
	struct seq_file *seq = filp->private_data;
	int mask;

	if (md_unloading)
		return POLLIN|POLLRDNORM|POLLERR|POLLPRI;
	poll_wait(filp, &md_event_waiters, wait);

	mask = POLLIN | POLLRDNORM;

	if (seq->poll_event != atomic_read(&md_event_count))
		mask |= POLLERR | POLLPRI;
	return mask;
}

static const struct file_operations md_seq_fops = {
	.owner		= THIS_MODULE,
	.open           = md_seq_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release	= seq_release_private,
	.poll		= mdstat_poll,
};

int register_md_personality(struct md_personality *p)
{
	printk(KERN_INFO "md: %s personality registered for level %d\n",
						p->name, p->level);
	spin_lock(&pers_lock);
	list_add_tail(&p->list, &pers_list);
	spin_unlock(&pers_lock);
	return 0;
}
EXPORT_SYMBOL(register_md_personality);

int unregister_md_personality(struct md_personality *p)
{
	printk(KERN_INFO "md: %s personality unregistered\n", p->name);
	spin_lock(&pers_lock);
	list_del_init(&p->list);
	spin_unlock(&pers_lock);
	return 0;
}
EXPORT_SYMBOL(unregister_md_personality);

int register_md_cluster_operations(struct md_cluster_operations *ops,
				   struct module *module)
{
	int ret = 0;
	spin_lock(&pers_lock);
	if (md_cluster_ops != NULL)
		ret = -EALREADY;
	else {
		md_cluster_ops = ops;
		md_cluster_mod = module;
	}
	spin_unlock(&pers_lock);
	return ret;
}
EXPORT_SYMBOL(register_md_cluster_operations);

int unregister_md_cluster_operations(void)
{
	spin_lock(&pers_lock);
	md_cluster_ops = NULL;
	spin_unlock(&pers_lock);
	return 0;
}
EXPORT_SYMBOL(unregister_md_cluster_operations);

int md_setup_cluster(struct mddev *mddev, int nodes)
{
	if (!md_cluster_ops)
		request_module("md-cluster");
	spin_lock(&pers_lock);
	 
	if (!md_cluster_ops || !try_module_get(md_cluster_mod)) {
		pr_err("can't find md-cluster module or get it's reference.\n");
		spin_unlock(&pers_lock);
		return -ENOENT;
	}
	spin_unlock(&pers_lock);

	return md_cluster_ops->join(mddev, nodes);
}

void md_cluster_stop(struct mddev *mddev)
{
	if (!md_cluster_ops)
		return;
	md_cluster_ops->leave(mddev);
	module_put(md_cluster_mod);
}

static int is_mddev_idle(struct mddev *mddev, int init)
{
	struct md_rdev *rdev;
	int idle;
	int curr_events;

	idle = 1;
	rcu_read_lock();
	rdev_for_each_rcu(rdev, mddev) {
		struct gendisk *disk = rdev->bdev->bd_contains->bd_disk;
		curr_events = (int)part_stat_read(&disk->part0, sectors[0]) +
			      (int)part_stat_read(&disk->part0, sectors[1]) -
			      atomic_read(&disk->sync_io);
		 
		if (init || curr_events - rdev->last_events > 64) {
			rdev->last_events = curr_events;
			idle = 0;
		}
	}
	rcu_read_unlock();
	return idle;
}

void md_done_sync(struct mddev *mddev, int blocks, int ok)
{
	 
	atomic_sub(blocks, &mddev->recovery_active);
	wake_up(&mddev->recovery_wait);
	if (!ok) {
		set_bit(MD_RECOVERY_INTR, &mddev->recovery);
		set_bit(MD_RECOVERY_ERROR, &mddev->recovery);
		md_wakeup_thread(mddev->thread);
		 
	}
}
EXPORT_SYMBOL(md_done_sync);

void md_write_start(struct mddev *mddev, struct bio *bi)
{
	int did_change = 0;
	if (bio_data_dir(bi) != WRITE)
		return;

	BUG_ON(mddev->ro == 1);
	if (mddev->ro == 2) {
		 
		mddev->ro = 0;
		set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
		md_wakeup_thread(mddev->thread);
		md_wakeup_thread(mddev->sync_thread);
		did_change = 1;
	}
	atomic_inc(&mddev->writes_pending);
	if (mddev->safemode == 1)
		mddev->safemode = 0;
	if (mddev->in_sync) {
		spin_lock(&mddev->lock);
		if (mddev->in_sync) {
			mddev->in_sync = 0;
			set_bit(MD_CHANGE_CLEAN, &mddev->flags);
			set_bit(MD_CHANGE_PENDING, &mddev->flags);
			md_wakeup_thread(mddev->thread);
			did_change = 1;
		}
		spin_unlock(&mddev->lock);
	}
	if (did_change)
		sysfs_notify_dirent_safe(mddev->sysfs_state);
	wait_event(mddev->sb_wait,
		   !test_bit(MD_CHANGE_PENDING, &mddev->flags));
}
EXPORT_SYMBOL(md_write_start);

void md_write_end(struct mddev *mddev)
{
	if (atomic_dec_and_test(&mddev->writes_pending)) {
		if (mddev->safemode == 2)
			md_wakeup_thread(mddev->thread);
		else if (mddev->safemode_delay)
			mod_timer(&mddev->safemode_timer, jiffies + mddev->safemode_delay);
	}
}
EXPORT_SYMBOL(md_write_end);

int md_allow_write(struct mddev *mddev)
{
	if (!mddev->pers)
		return 0;
	if (mddev->ro)
		return 0;
	if (!mddev->pers->sync_request)
		return 0;

	spin_lock(&mddev->lock);
	if (mddev->in_sync) {
		mddev->in_sync = 0;
		set_bit(MD_CHANGE_CLEAN, &mddev->flags);
		set_bit(MD_CHANGE_PENDING, &mddev->flags);
		if (mddev->safemode_delay &&
		    mddev->safemode == 0)
			mddev->safemode = 1;
		spin_unlock(&mddev->lock);
		md_update_sb(mddev, 0);
		sysfs_notify_dirent_safe(mddev->sysfs_state);
	} else
		spin_unlock(&mddev->lock);

	if (test_bit(MD_CHANGE_PENDING, &mddev->flags))
		return -EAGAIN;
	else
		return 0;
}
EXPORT_SYMBOL_GPL(md_allow_write);

#define SYNC_MARKS	10
#define	SYNC_MARK_STEP	(3*HZ)
#define UPDATE_FREQUENCY (5*60*HZ)
void md_do_sync(struct md_thread *thread)
{
	struct mddev *mddev = thread->mddev;
	struct mddev *mddev2;
	unsigned int currspeed = 0,
		 window;
	sector_t max_sectors,j, io_sectors, recovery_done;
	unsigned long mark[SYNC_MARKS];
	unsigned long update_time;
#ifdef MY_ABC_HERE
	unsigned long last_print_time = jiffies - (1 * 60 * 60 * HZ);
#endif  
	sector_t mark_cnt[SYNC_MARKS];
	int last_mark,m;
	struct list_head *tmp;
	sector_t last_check;
	int skipped = 0;
	struct md_rdev *rdev;
	char *desc, *action = NULL;
	struct blk_plug plug;
	bool cluster_resync_finished = false;
#ifdef MY_ABC_HERE
	int old_auto_remap_setting = -1;
#endif  

	if (test_bit(MD_RECOVERY_DONE, &mddev->recovery))
		return;
	if (mddev->ro) { 
		set_bit(MD_RECOVERY_INTR, &mddev->recovery);
		return;
	}

#ifdef MY_ABC_HERE
	old_auto_remap_setting = SynoRaidAutoRemapAdjust(mddev, MD_AUTO_REMAP_MODE_ISMAXDEGRADE);
#endif  

	if (test_bit(MD_RECOVERY_SYNC, &mddev->recovery)) {
		if (test_bit(MD_RECOVERY_CHECK, &mddev->recovery)) {
			desc = "data-check";
			action = "check";
		} else if (test_bit(MD_RECOVERY_REQUESTED, &mddev->recovery)) {
			desc = "requested-resync";
			action = "repair";
		} else
			desc = "resync";
	} else if (test_bit(MD_RECOVERY_RESHAPE, &mddev->recovery))
		desc = "reshape";
	else
		desc = "recovery";

	mddev->last_sync_action = action ?: desc;

	do {
		mddev->curr_resync = 2;

	try_again:
		if (test_bit(MD_RECOVERY_INTR, &mddev->recovery))
			goto skip;
		for_each_mddev(mddev2, tmp) {
			if (mddev2 == mddev)
				continue;
			if (!mddev->parallel_resync
			&&  mddev2->curr_resync
			&&  match_mddev_units(mddev, mddev2)) {
				DEFINE_WAIT(wq);
				if (mddev < mddev2 && mddev->curr_resync == 2) {
					 
					mddev->curr_resync = 1;
					wake_up(&resync_wait);
				}
				if (mddev > mddev2 && mddev->curr_resync == 1)
					 
					continue;
				 
				prepare_to_wait(&resync_wait, &wq, TASK_INTERRUPTIBLE);
				if (!test_bit(MD_RECOVERY_INTR, &mddev->recovery) &&
				    mddev2->curr_resync >= mddev->curr_resync) {
#ifdef MY_ABC_HERE
					if (time_after_eq(jiffies, last_print_time + 1 * 60 * 60 * HZ)) {
						printk(KERN_INFO "md: delaying %s of %s"
							" until %s has finished (they"
							" share one or more physical units)\n",
							desc, mdname(mddev), mdname(mddev2));
						last_print_time = jiffies;
					}
#else  
					printk(KERN_INFO "md: delaying %s of %s"
					       " until %s has finished (they"
					       " share one or more physical units)\n",
					       desc, mdname(mddev), mdname(mddev2));
#endif  
					mddev_put(mddev2);
					if (signal_pending(current))
						flush_signals(current);
					schedule();
					finish_wait(&resync_wait, &wq);
					goto try_again;
				}
				finish_wait(&resync_wait, &wq);
			}
		}
	} while (mddev->curr_resync < 2);

	j = 0;
	if (test_bit(MD_RECOVERY_SYNC, &mddev->recovery)) {
		 
		max_sectors = mddev->resync_max_sectors;
		atomic64_set(&mddev->resync_mismatches, 0);
		 
		if (test_bit(MD_RECOVERY_REQUESTED, &mddev->recovery))
			j = mddev->resync_min;
		else if (!mddev->bitmap)
			j = mddev->recovery_cp;

	} else if (test_bit(MD_RECOVERY_RESHAPE, &mddev->recovery))
		max_sectors = mddev->resync_max_sectors;
	else {
		 
		max_sectors = mddev->dev_sectors;
		j = MaxSector;
		rcu_read_lock();
		rdev_for_each_rcu(rdev, mddev)
			if (rdev->raid_disk >= 0 &&
			    !test_bit(Journal, &rdev->flags) &&
			    !test_bit(Faulty, &rdev->flags) &&
			    !test_bit(In_sync, &rdev->flags) &&
			    rdev->recovery_offset < j)
				j = rdev->recovery_offset;
		rcu_read_unlock();

		if (mddev->bitmap) {
			mddev->pers->quiesce(mddev, 1);
			mddev->pers->quiesce(mddev, 0);
		}
	}

#ifdef MY_ABC_HERE
	printk(KERN_WARNING "md: %s of RAID array %s\n", desc, mdname(mddev));
#else  
	printk(KERN_INFO "md: %s of RAID array %s\n", desc, mdname(mddev));
#endif  
#ifdef MY_ABC_HERE
	SynoReportSyncStatus(desc, 0, 0, mddev->md_minor);
#endif  
	printk(KERN_INFO "md: minimum _guaranteed_  speed:"
		" %d KB/sec/disk.\n", speed_min(mddev));
	printk(KERN_INFO "md: using maximum available idle IO bandwidth "
	       "(but not more than %d KB/sec) for %s.\n",
	       speed_max(mddev), desc);

	is_mddev_idle(mddev, 1);  

	io_sectors = 0;
	for (m = 0; m < SYNC_MARKS; m++) {
		mark[m] = jiffies;
		mark_cnt[m] = io_sectors;
	}
	last_mark = 0;
	mddev->resync_mark = mark[last_mark];
	mddev->resync_mark_cnt = mark_cnt[last_mark];

	window = 32*(PAGE_SIZE/512);
	printk(KERN_INFO "md: using %dk window, over a total of %lluk.\n",
		window/2, (unsigned long long)max_sectors/2);

	atomic_set(&mddev->recovery_active, 0);
	last_check = 0;

	if (j>2) {
		printk(KERN_INFO
		       "md: resuming %s of %s from checkpoint.\n",
		       desc, mdname(mddev));
		mddev->curr_resync = j;
	} else
		mddev->curr_resync = 3;  
	mddev->curr_resync_completed = j;
	sysfs_notify(&mddev->kobj, NULL, "sync_completed");
	md_new_event(mddev);
	update_time = jiffies;

	blk_start_plug(&plug);
	while (j < max_sectors) {
		sector_t sectors;

		skipped = 0;

		if (!test_bit(MD_RECOVERY_RESHAPE, &mddev->recovery) &&
		    ((mddev->curr_resync > mddev->curr_resync_completed &&
		      (mddev->curr_resync - mddev->curr_resync_completed)
		      > (max_sectors >> 4)) ||
		     time_after_eq(jiffies, update_time + UPDATE_FREQUENCY) ||
		     (j - mddev->curr_resync_completed)*2
		     >= mddev->resync_max - mddev->curr_resync_completed ||
		     mddev->curr_resync_completed > mddev->resync_max
			    )) {
			 
			wait_event(mddev->recovery_wait,
				   atomic_read(&mddev->recovery_active) == 0);
			mddev->curr_resync_completed = j;
			if (test_bit(MD_RECOVERY_SYNC, &mddev->recovery) &&
			    j > mddev->recovery_cp)
				mddev->recovery_cp = j;
			update_time = jiffies;
			set_bit(MD_CHANGE_CLEAN, &mddev->flags);
			sysfs_notify(&mddev->kobj, NULL, "sync_completed");
		}

		while (j >= mddev->resync_max &&
		       !test_bit(MD_RECOVERY_INTR, &mddev->recovery)) {
			 
			flush_signals(current);  
			wait_event_interruptible(mddev->recovery_wait,
						 mddev->resync_max > j
						 || test_bit(MD_RECOVERY_INTR,
							     &mddev->recovery));
		}

		if (test_bit(MD_RECOVERY_INTR, &mddev->recovery))
			break;

		sectors = mddev->pers->sync_request(mddev, j, &skipped);
		if (sectors == 0) {
			set_bit(MD_RECOVERY_INTR, &mddev->recovery);
			break;
		}

		if (!skipped) {  
			io_sectors += sectors;
			atomic_add(sectors, &mddev->recovery_active);
		}

		if (test_bit(MD_RECOVERY_INTR, &mddev->recovery))
			break;

		j += sectors;
		if (j > max_sectors)
			 
			j = max_sectors;
		if (j > 2)
			mddev->curr_resync = j;
		mddev->curr_mark_cnt = io_sectors;
		if (last_check == 0)
			 
			md_new_event(mddev);

		if (last_check + window > io_sectors || j == max_sectors)
			continue;

		last_check = io_sectors;
	repeat:
		if (time_after_eq(jiffies, mark[last_mark] + SYNC_MARK_STEP )) {
			 
			int next = (last_mark+1) % SYNC_MARKS;

			mddev->resync_mark = mark[next];
			mddev->resync_mark_cnt = mark_cnt[next];
			mark[next] = jiffies;
			mark_cnt[next] = io_sectors - atomic_read(&mddev->recovery_active);
			last_mark = next;
		}

		if (test_bit(MD_RECOVERY_INTR, &mddev->recovery))
			break;

		cond_resched();

		recovery_done = io_sectors - atomic_read(&mddev->recovery_active);
		currspeed = ((unsigned long)(recovery_done - mddev->resync_mark_cnt))/2
			/((jiffies-mddev->resync_mark)/HZ +1) +1;

		if (currspeed > speed_min(mddev)) {
			if (currspeed > speed_max(mddev)) {
				msleep(500);
				goto repeat;
			}
			if (!is_mddev_idle(mddev, 0)) {
				 
				wait_event(mddev->recovery_wait,
					   !atomic_read(&mddev->recovery_active));
			}
		}
#ifdef MY_ABC_HERE
		if (mddev->nodev_and_crashed) {
			j = max_sectors;
		}
#endif  
	}
#ifdef MY_ABC_HERE
	printk(KERN_WARNING "md: %s: %s %s.\n",mdname(mddev), desc,
	       test_bit(MD_RECOVERY_INTR, &mddev->recovery)
	       ? "interrupted" : "done");
#else  
	printk(KERN_INFO "md: %s: %s %s.\n",mdname(mddev), desc,
	       test_bit(MD_RECOVERY_INTR, &mddev->recovery)
	       ? "interrupted" : "done");
#endif  
	 
	blk_finish_plug(&plug);
	wait_event(mddev->recovery_wait, !atomic_read(&mddev->recovery_active));

	if (!test_bit(MD_RECOVERY_RESHAPE, &mddev->recovery) &&
	    !test_bit(MD_RECOVERY_INTR, &mddev->recovery) &&
	    mddev->curr_resync > 2) {
		mddev->curr_resync_completed = mddev->curr_resync;
		sysfs_notify(&mddev->kobj, NULL, "sync_completed");
	}
	 
	if (mddev_is_clustered(mddev)) {
		md_cluster_ops->resync_finish(mddev);
		cluster_resync_finished = true;
	}
	mddev->pers->sync_request(mddev, max_sectors, &skipped);
#ifdef MY_ABC_HERE
	SynoReportSyncStatus(desc, 1, (test_bit(MD_RECOVERY_INTR, &mddev->recovery) ? 1 : 0), mddev->md_minor);
#endif  

	if (!test_bit(MD_RECOVERY_CHECK, &mddev->recovery) &&
	    mddev->curr_resync > 2) {
		if (test_bit(MD_RECOVERY_SYNC, &mddev->recovery)) {
			if (test_bit(MD_RECOVERY_INTR, &mddev->recovery)) {
				if (mddev->curr_resync >= mddev->recovery_cp) {
					printk(KERN_INFO
					       "md: checkpointing %s of %s.\n",
					       desc, mdname(mddev));
					if (test_bit(MD_RECOVERY_ERROR,
						&mddev->recovery))
						mddev->recovery_cp =
							mddev->curr_resync_completed;
					else
						mddev->recovery_cp =
							mddev->curr_resync;
				}
			} else
				mddev->recovery_cp = MaxSector;
		} else {
			if (!test_bit(MD_RECOVERY_INTR, &mddev->recovery))
				mddev->curr_resync = MaxSector;
			rcu_read_lock();
			rdev_for_each_rcu(rdev, mddev)
				if (rdev->raid_disk >= 0 &&
				    mddev->delta_disks >= 0 &&
				    !test_bit(Journal, &rdev->flags) &&
				    !test_bit(Faulty, &rdev->flags) &&
				    !test_bit(In_sync, &rdev->flags) &&
				    rdev->recovery_offset < mddev->curr_resync)
					rdev->recovery_offset = mddev->curr_resync;
			rcu_read_unlock();
		}
	}
 skip:
	set_bit(MD_CHANGE_DEVS, &mddev->flags);

	if (mddev_is_clustered(mddev) &&
	    test_bit(MD_RECOVERY_INTR, &mddev->recovery) &&
	    !cluster_resync_finished)
		md_cluster_ops->resync_finish(mddev);

	spin_lock(&mddev->lock);
	if (!test_bit(MD_RECOVERY_INTR, &mddev->recovery)) {
		 
		if (test_bit(MD_RECOVERY_REQUESTED, &mddev->recovery))
			mddev->resync_min = 0;
		mddev->resync_max = MaxSector;
	} else if (test_bit(MD_RECOVERY_REQUESTED, &mddev->recovery))
		mddev->resync_min = mddev->curr_resync_completed;
	set_bit(MD_RECOVERY_DONE, &mddev->recovery);
	mddev->curr_resync = 0;
	spin_unlock(&mddev->lock);

	wake_up(&resync_wait);
	md_wakeup_thread(mddev->thread);
#ifdef MY_ABC_HERE
	 
	SynoRaidAutoRemapAdjust(mddev, old_auto_remap_setting);
#endif  
	return;
}
EXPORT_SYMBOL_GPL(md_do_sync);

#if defined(MY_ABC_HERE)
static void
remove_faulty(struct mddev *mddev)
{
	struct md_rdev *rdev;

	list_for_each_entry(rdev, &mddev->disks, same_set)
		if (rdev->raid_disk >= 0 &&
		    test_bit(Faulty, &rdev->flags) &&
		    0 == atomic_read(&rdev->nr_pending)) {
			if (0 == mddev->pers->hot_remove_disk(mddev, rdev)) {
				char nm[20];
				sprintf(nm,"rd%d", rdev->raid_disk);
				sysfs_remove_link(&mddev->kobj, nm);
				rdev->raid_disk = -1;
			}
		}
}
#endif  

static int remove_and_add_spares(struct mddev *mddev,
				 struct md_rdev *this)
{
	struct md_rdev *rdev;
	int spares = 0;
	int removed = 0;

	rdev_for_each(rdev, mddev)
		if ((this == NULL || rdev == this) &&
		    rdev->raid_disk >= 0 &&
		    !test_bit(Blocked, &rdev->flags) &&
		    (test_bit(Faulty, &rdev->flags) ||
		     (!test_bit(In_sync, &rdev->flags) &&
		      !test_bit(Journal, &rdev->flags))) &&
		    atomic_read(&rdev->nr_pending)==0) {
			if (mddev->pers->hot_remove_disk(
				    mddev, rdev) == 0) {
				sysfs_unlink_rdev(mddev, rdev);
				rdev->raid_disk = -1;
				removed++;
			}
		}
	if (removed && mddev->kobj.sd)
		sysfs_notify(&mddev->kobj, NULL, "degraded");

	if (this && removed)
		goto no_add;

	rdev_for_each(rdev, mddev) {
		if (this && this != rdev)
			continue;
		if (test_bit(Candidate, &rdev->flags))
			continue;
		if (rdev->raid_disk >= 0 &&
		    !test_bit(In_sync, &rdev->flags) &&
		    !test_bit(Journal, &rdev->flags) &&
		    !test_bit(Faulty, &rdev->flags))
			spares++;
		if (rdev->raid_disk >= 0)
			continue;
		if (test_bit(Faulty, &rdev->flags))
			continue;
		if (test_bit(Journal, &rdev->flags))
			continue;
		if (mddev->ro &&
		    ! (rdev->saved_raid_disk >= 0 &&
		       !test_bit(Bitmap_sync, &rdev->flags)))
			continue;

		rdev->recovery_offset = 0;
		if (mddev->pers->
		    hot_add_disk(mddev, rdev) == 0) {
			if (sysfs_link_rdev(mddev, rdev))
				 ;
			spares++;
			md_new_event(mddev);
			set_bit(MD_CHANGE_DEVS, &mddev->flags);
		}
	}
no_add:
	if (removed)
		set_bit(MD_CHANGE_DEVS, &mddev->flags);
	return spares;
}

static void md_start_sync(struct work_struct *ws)
{
	struct mddev *mddev = container_of(ws, struct mddev, del_work);
	int ret = 0;

	if (mddev_is_clustered(mddev)) {
		ret = md_cluster_ops->resync_start(mddev);
		if (ret) {
			mddev->sync_thread = NULL;
			goto out;
		}
	}

	mddev->sync_thread = md_register_thread(md_do_sync,
						mddev,
						"resync");
out:
	if (!mddev->sync_thread) {
		if (!(mddev_is_clustered(mddev) && ret == -EAGAIN))
			printk(KERN_ERR "%s: could not start resync"
			       " thread...\n",
			       mdname(mddev));
		 
		clear_bit(MD_RECOVERY_SYNC, &mddev->recovery);
		clear_bit(MD_RECOVERY_RESHAPE, &mddev->recovery);
		clear_bit(MD_RECOVERY_REQUESTED, &mddev->recovery);
		clear_bit(MD_RECOVERY_CHECK, &mddev->recovery);
		clear_bit(MD_RECOVERY_RUNNING, &mddev->recovery);
		wake_up(&resync_wait);
		if (test_and_clear_bit(MD_RECOVERY_RECOVER,
				       &mddev->recovery))
			if (mddev->sysfs_action)
				sysfs_notify_dirent_safe(mddev->sysfs_action);
	} else
		md_wakeup_thread(mddev->sync_thread);
	sysfs_notify_dirent_safe(mddev->sysfs_action);
	md_new_event(mddev);
}

void md_check_recovery(struct mddev *mddev)
{
#ifdef MY_ABC_HERE
	int is_get_reshape_and_mount_lock = 0;
#endif  

	if (mddev->suspended)
#ifdef MY_ABC_HERE
	{
		if (mddev->flags & MD_UPDATE_SB_FLAGS) {
			wake_up(&mddev->sb_wait);
		}
		return;
	}
#else  
		return;
#endif  

	if (mddev->bitmap)
		bitmap_daemon_work(mddev);

	if (signal_pending(current)) {
		if (mddev->pers->sync_request && !mddev->external) {
			printk(KERN_INFO "md: %s in immediate safe mode\n",
			       mdname(mddev));
			mddev->safemode = 2;
		}
		flush_signals(current);
	}

	if (mddev->ro && !test_bit(MD_RECOVERY_NEEDED, &mddev->recovery))
		return;
	if ( ! (
		(mddev->flags & MD_UPDATE_SB_FLAGS & ~ (1<<MD_CHANGE_PENDING)) ||
		test_bit(MD_RECOVERY_NEEDED, &mddev->recovery) ||
		test_bit(MD_RECOVERY_DONE, &mddev->recovery) ||
		(mddev->external == 0 && mddev->safemode == 1) ||
		(mddev->safemode == 2 && ! atomic_read(&mddev->writes_pending)
		 && !mddev->in_sync && mddev->recovery_cp == MaxSector)
		))
		return;

#ifdef MY_ABC_HERE
	if (test_bit(MD_RECOVERY_DONE, &mddev->recovery) && mddev->sync_thread) {
		if (1 == down_write_trylock(&s_reshape_mount_key)) {
			is_get_reshape_and_mount_lock = 1;
		} else {
			return;
		}
	}
#endif  

	if (mddev_trylock(mddev)) {
		int spares = 0;

		if (mddev->ro) {
			struct md_rdev *rdev;
			if (!mddev->external && mddev->in_sync)
				 
				rdev_for_each(rdev, mddev)
					clear_bit(Blocked, &rdev->flags);
			 
			remove_and_add_spares(mddev, NULL);
			 
			set_bit(MD_RECOVERY_INTR, &mddev->recovery);
			md_reap_sync_thread(mddev);
			clear_bit(MD_RECOVERY_RECOVER, &mddev->recovery);
			clear_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
			clear_bit(MD_CHANGE_PENDING, &mddev->flags);
			goto unlock;
		}

		if (!mddev->external) {
			int did_change = 0;
			spin_lock(&mddev->lock);
			if (mddev->safemode &&
			    !atomic_read(&mddev->writes_pending) &&
			    !mddev->in_sync &&
			    mddev->recovery_cp == MaxSector) {
				mddev->in_sync = 1;
				did_change = 1;
				set_bit(MD_CHANGE_CLEAN, &mddev->flags);
			}
			if (mddev->safemode == 1)
				mddev->safemode = 0;
			spin_unlock(&mddev->lock);
			if (did_change)
				sysfs_notify_dirent_safe(mddev->sysfs_state);
		}

		if (mddev->flags & MD_UPDATE_SB_FLAGS)
			md_update_sb(mddev, 0);

		if (test_bit(MD_RECOVERY_RUNNING, &mddev->recovery) &&
		    !test_bit(MD_RECOVERY_DONE, &mddev->recovery)) {
			 
			clear_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
			goto unlock;
		}
		if (mddev->sync_thread) {
			md_reap_sync_thread(mddev);
			goto unlock;
		}
		 
		mddev->curr_resync_completed = 0;
		spin_lock(&mddev->lock);
		set_bit(MD_RECOVERY_RUNNING, &mddev->recovery);
		spin_unlock(&mddev->lock);
		 
		clear_bit(MD_RECOVERY_INTR, &mddev->recovery);
		clear_bit(MD_RECOVERY_DONE, &mddev->recovery);

		if (!test_and_clear_bit(MD_RECOVERY_NEEDED, &mddev->recovery) ||
		    test_bit(MD_RECOVERY_FROZEN, &mddev->recovery))
			goto not_running;
		 
		if (mddev->reshape_position != MaxSector) {
#ifdef MY_ABC_HERE
			 
			if (mddev->degraded) {
				remove_faulty(mddev);
			}
#endif  
			if (mddev->pers->check_reshape == NULL ||
			    mddev->pers->check_reshape(mddev) != 0)
				 
				goto not_running;
			set_bit(MD_RECOVERY_RESHAPE, &mddev->recovery);
			clear_bit(MD_RECOVERY_RECOVER, &mddev->recovery);
		} else if ((spares = remove_and_add_spares(mddev, NULL))) {
			clear_bit(MD_RECOVERY_SYNC, &mddev->recovery);
			clear_bit(MD_RECOVERY_CHECK, &mddev->recovery);
			clear_bit(MD_RECOVERY_REQUESTED, &mddev->recovery);
			set_bit(MD_RECOVERY_RECOVER, &mddev->recovery);
		} else if (mddev->recovery_cp < MaxSector) {
			set_bit(MD_RECOVERY_SYNC, &mddev->recovery);
			clear_bit(MD_RECOVERY_RECOVER, &mddev->recovery);
		} else if (!test_bit(MD_RECOVERY_SYNC, &mddev->recovery))
			 
			goto not_running;

#ifdef MY_ABC_HERE
		if (mddev->nodev_and_crashed) {
			printk(KERN_ERR "%s: crashed, stop sync\n", mdname(mddev));
			clear_bit(MD_RECOVERY_SYNC, &mddev->recovery);
			clear_bit(MD_RECOVERY_RECOVER, &mddev->recovery);
			goto not_running;
		}
#endif  
		if (mddev->pers->sync_request) {
			if (spares) {
				 
				bitmap_write_all(mddev->bitmap);
			}
			INIT_WORK(&mddev->del_work, md_start_sync);
			queue_work(md_misc_wq, &mddev->del_work);
			goto unlock;
		}
	not_running:
		if (!mddev->sync_thread) {
			clear_bit(MD_RECOVERY_RUNNING, &mddev->recovery);
			wake_up(&resync_wait);
			if (test_and_clear_bit(MD_RECOVERY_RECOVER,
					       &mddev->recovery))
				if (mddev->sysfs_action)
					sysfs_notify_dirent_safe(mddev->sysfs_action);
		}
	unlock:
		wake_up(&mddev->sb_wait);
		mddev_unlock(mddev);
	}
#ifdef MY_ABC_HERE
	if (is_get_reshape_and_mount_lock) {
		up_write(&s_reshape_mount_key);
	}
#endif  
}
EXPORT_SYMBOL(md_check_recovery);

void md_reap_sync_thread(struct mddev *mddev)
{
	struct md_rdev *rdev;

	md_unregister_thread(&mddev->sync_thread);
	if (!test_bit(MD_RECOVERY_INTR, &mddev->recovery) &&
	    !test_bit(MD_RECOVERY_REQUESTED, &mddev->recovery)) {
		 
		if (mddev->pers->spare_active(mddev)) {
			sysfs_notify(&mddev->kobj, NULL,
				     "degraded");
			set_bit(MD_CHANGE_DEVS, &mddev->flags);
		}
	}
	if (test_bit(MD_RECOVERY_RESHAPE, &mddev->recovery) &&
	    mddev->pers->finish_reshape)
		mddev->pers->finish_reshape(mddev);

	if (!mddev->degraded)
		rdev_for_each(rdev, mddev)
			rdev->saved_raid_disk = -1;

	md_update_sb(mddev, 1);
	clear_bit(MD_RECOVERY_RUNNING, &mddev->recovery);
	clear_bit(MD_RECOVERY_DONE, &mddev->recovery);
	clear_bit(MD_RECOVERY_SYNC, &mddev->recovery);
	clear_bit(MD_RECOVERY_RESHAPE, &mddev->recovery);
	clear_bit(MD_RECOVERY_REQUESTED, &mddev->recovery);
	clear_bit(MD_RECOVERY_CHECK, &mddev->recovery);
	wake_up(&resync_wait);
	 
	set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
	sysfs_notify_dirent_safe(mddev->sysfs_action);
	md_new_event(mddev);
	if (mddev->event_work.func)
		queue_work(md_misc_wq, &mddev->event_work);
}
EXPORT_SYMBOL(md_reap_sync_thread);

void md_wait_for_blocked_rdev(struct md_rdev *rdev, struct mddev *mddev)
{
	sysfs_notify_dirent_safe(rdev->sysfs_state);
	wait_event_timeout(rdev->blocked_wait,
			   !test_bit(Blocked, &rdev->flags) &&
			   !test_bit(BlockedBadBlocks, &rdev->flags),
			   msecs_to_jiffies(5000));
	rdev_dec_pending(rdev, mddev);
}
EXPORT_SYMBOL(md_wait_for_blocked_rdev);

void md_finish_reshape(struct mddev *mddev)
{
	 
	struct md_rdev *rdev;

	rdev_for_each(rdev, mddev) {
		if (rdev->data_offset > rdev->new_data_offset)
			rdev->sectors += rdev->data_offset - rdev->new_data_offset;
		else
			rdev->sectors -= rdev->new_data_offset - rdev->data_offset;
		rdev->data_offset = rdev->new_data_offset;
	}
}
EXPORT_SYMBOL(md_finish_reshape);

int md_is_badblock(struct badblocks *bb, sector_t s, int sectors,
		   sector_t *first_bad, int *bad_sectors)
{
	int hi;
	int lo;
	u64 *p = bb->page;
	int rv;
	sector_t target = s + sectors;
	unsigned seq;

	if (bb->shift > 0) {
		 
		s >>= bb->shift;
		target += (1<<bb->shift) - 1;
		target >>= bb->shift;
		sectors = target - s;
	}
	 
retry:
	seq = read_seqbegin(&bb->lock);
	lo = 0;
	rv = 0;
	hi = bb->count;

	while (hi - lo > 1) {
		int mid = (lo + hi) / 2;
		sector_t a = BB_OFFSET(p[mid]);
		if (a < target)
			 
			lo = mid;
		else
			 
			hi = mid;
	}
	 
	if (hi > lo) {
		 
		while (lo >= 0 &&
		       BB_OFFSET(p[lo]) + BB_LEN(p[lo]) > s) {
			if (BB_OFFSET(p[lo]) < target) {
				 
				if (rv != -1 && BB_ACK(p[lo]))
					rv = 1;
				else
					rv = -1;
				*first_bad = BB_OFFSET(p[lo]);
				*bad_sectors = BB_LEN(p[lo]);
			}
			lo--;
		}
	}

	if (read_seqretry(&bb->lock, seq))
		goto retry;

	return rv;
}
EXPORT_SYMBOL_GPL(md_is_badblock);

static int md_set_badblocks(struct badblocks *bb, sector_t s, int sectors,
			    int acknowledged)
{
	u64 *p;
	int lo, hi;
	int rv = 1;
	unsigned long flags;

	if (bb->shift < 0)
		 
		return 0;

	if (bb->shift) {
		 
		sector_t next = s + sectors;
		s >>= bb->shift;
		next += (1<<bb->shift) - 1;
		next >>= bb->shift;
		sectors = next - s;
	}

	write_seqlock_irqsave(&bb->lock, flags);

	p = bb->page;
	lo = 0;
	hi = bb->count;
	 
	while (hi - lo > 1) {
		int mid = (lo + hi) / 2;
		sector_t a = BB_OFFSET(p[mid]);
		if (a <= s)
			lo = mid;
		else
			hi = mid;
	}
	if (hi > lo && BB_OFFSET(p[lo]) > s)
		hi = lo;

	if (hi > lo) {
		 
		sector_t a = BB_OFFSET(p[lo]);
		sector_t e = a + BB_LEN(p[lo]);
		int ack = BB_ACK(p[lo]);
		if (e >= s) {
			 
			if (s == a && s + sectors >= e)
				 
				ack = acknowledged;
			else
				ack = ack && acknowledged;

			if (e < s + sectors)
				e = s + sectors;
			if (e - a <= BB_MAX_LEN) {
				p[lo] = BB_MAKE(a, e-a, ack);
				s = e;
			} else {
				 
				if (BB_LEN(p[lo]) != BB_MAX_LEN)
					p[lo] = BB_MAKE(a, BB_MAX_LEN, ack);
				s = a + BB_MAX_LEN;
			}
			sectors = e - s;
		}
	}
	if (sectors && hi < bb->count) {
		 
		sector_t a = BB_OFFSET(p[hi]);
		sector_t e = a + BB_LEN(p[hi]);
		int ack = BB_ACK(p[hi]);
		if (a <= s + sectors) {
			 
			if (e <= s + sectors) {
				 
				e = s + sectors;
				ack = acknowledged;
			} else
				ack = ack && acknowledged;

			a = s;
			if (e - a <= BB_MAX_LEN) {
				p[hi] = BB_MAKE(a, e-a, ack);
				s = e;
			} else {
				p[hi] = BB_MAKE(a, BB_MAX_LEN, ack);
				s = a + BB_MAX_LEN;
			}
			sectors = e - s;
			lo = hi;
			hi++;
		}
	}
	if (sectors == 0 && hi < bb->count) {
		 
		sector_t a = BB_OFFSET(p[hi]);
		int lolen = BB_LEN(p[lo]);
		int hilen = BB_LEN(p[hi]);
		int newlen = lolen + hilen - (s - a);
		if (s >= a && newlen < BB_MAX_LEN) {
			 
			int ack = BB_ACK(p[lo]) && BB_ACK(p[hi]);
			p[lo] = BB_MAKE(BB_OFFSET(p[lo]), newlen, ack);
			memmove(p + hi, p + hi + 1,
				(bb->count - hi - 1) * 8);
			bb->count--;
		}
	}
	while (sectors) {
		 
		if (bb->count >= MD_MAX_BADBLOCKS) {
			 
			rv = 0;
			break;
		} else {
			int this_sectors = sectors;
			memmove(p + hi + 1, p + hi,
				(bb->count - hi) * 8);
			bb->count++;

			if (this_sectors > BB_MAX_LEN)
				this_sectors = BB_MAX_LEN;
			p[hi] = BB_MAKE(s, this_sectors, acknowledged);
			sectors -= this_sectors;
			s += this_sectors;
		}
	}

	bb->changed = 1;
	if (!acknowledged)
		bb->unacked_exist = 1;
	write_sequnlock_irqrestore(&bb->lock, flags);

	return rv;
}

int rdev_set_badblocks(struct md_rdev *rdev, sector_t s, int sectors,
		       int is_new)
{
	int rv;
	if (is_new)
		s += rdev->new_data_offset;
	else
		s += rdev->data_offset;
	rv = md_set_badblocks(&rdev->badblocks,
			      s, sectors, 0);
	if (rv) {
		 
		sysfs_notify_dirent_safe(rdev->sysfs_state);
		set_bit(MD_CHANGE_CLEAN, &rdev->mddev->flags);
		set_bit(MD_CHANGE_PENDING, &rdev->mddev->flags);
		md_wakeup_thread(rdev->mddev->thread);
	}
	return rv;
}
EXPORT_SYMBOL_GPL(rdev_set_badblocks);

static int md_clear_badblocks(struct badblocks *bb, sector_t s, int sectors)
{
	u64 *p;
	int lo, hi;
	sector_t target = s + sectors;
	int rv = 0;

	if (bb->shift > 0) {
		 
		s += (1<<bb->shift) - 1;
		s >>= bb->shift;
		target >>= bb->shift;
		sectors = target - s;
	}

	write_seqlock_irq(&bb->lock);

	p = bb->page;
	lo = 0;
	hi = bb->count;
	 
	while (hi - lo > 1) {
		int mid = (lo + hi) / 2;
		sector_t a = BB_OFFSET(p[mid]);
		if (a < target)
			lo = mid;
		else
			hi = mid;
	}
	if (hi > lo) {
		 
		if (BB_OFFSET(p[lo]) + BB_LEN(p[lo]) > target) {
			 
			int ack = BB_ACK(p[lo]);
			sector_t a = BB_OFFSET(p[lo]);
			sector_t end = a + BB_LEN(p[lo]);

			if (a < s) {
				 
				if (bb->count >= MD_MAX_BADBLOCKS) {
					rv = -ENOSPC;
					goto out;
				}
				memmove(p+lo+1, p+lo, (bb->count - lo) * 8);
				bb->count++;
				p[lo] = BB_MAKE(a, s-a, ack);
				lo++;
			}
			p[lo] = BB_MAKE(target, end - target, ack);
			 
			hi = lo;
			lo--;
		}
		while (lo >= 0 &&
		       BB_OFFSET(p[lo]) + BB_LEN(p[lo]) > s) {
			 
			if (BB_OFFSET(p[lo]) < s) {
				 
				int ack = BB_ACK(p[lo]);
				sector_t start = BB_OFFSET(p[lo]);
				p[lo] = BB_MAKE(start, s - start, ack);
				 
				break;
			}
			lo--;
		}
		 
		if (hi - lo > 1) {
			memmove(p+lo+1, p+hi, (bb->count - hi) * 8);
			bb->count -= (hi - lo - 1);
		}
	}

	bb->changed = 1;
out:
	write_sequnlock_irq(&bb->lock);
	return rv;
}

int rdev_clear_badblocks(struct md_rdev *rdev, sector_t s, int sectors,
			 int is_new)
{
	if (is_new)
		s += rdev->new_data_offset;
	else
		s += rdev->data_offset;
	return md_clear_badblocks(&rdev->badblocks,
				  s, sectors);
}
EXPORT_SYMBOL_GPL(rdev_clear_badblocks);

void md_ack_all_badblocks(struct badblocks *bb)
{
	if (bb->page == NULL || bb->changed)
		 
		return;
	write_seqlock_irq(&bb->lock);

	if (bb->changed == 0 && bb->unacked_exist) {
		u64 *p = bb->page;
		int i;
		for (i = 0; i < bb->count ; i++) {
			if (!BB_ACK(p[i])) {
				sector_t start = BB_OFFSET(p[i]);
				int len = BB_LEN(p[i]);
				p[i] = BB_MAKE(start, len, 1);
			}
		}
		bb->unacked_exist = 0;
	}
	write_sequnlock_irq(&bb->lock);
}
EXPORT_SYMBOL_GPL(md_ack_all_badblocks);

static ssize_t
badblocks_show(struct badblocks *bb, char *page, int unack)
{
	size_t len;
	int i;
	u64 *p = bb->page;
	unsigned seq;

	if (bb->shift < 0)
		return 0;

retry:
	seq = read_seqbegin(&bb->lock);

	len = 0;
	i = 0;

	while (len < PAGE_SIZE && i < bb->count) {
		sector_t s = BB_OFFSET(p[i]);
		unsigned int length = BB_LEN(p[i]);
		int ack = BB_ACK(p[i]);
		i++;

		if (unack && ack)
			continue;

		len += snprintf(page+len, PAGE_SIZE-len, "%llu %u\n",
				(unsigned long long)s << bb->shift,
				length << bb->shift);
	}
	if (unack && len == 0)
		bb->unacked_exist = 0;

	if (read_seqretry(&bb->lock, seq))
		goto retry;

	return len;
}

#define DO_DEBUG 1

static ssize_t
badblocks_store(struct badblocks *bb, const char *page, size_t len, int unack)
{
	unsigned long long sector;
	int length;
	char newline;
#ifdef DO_DEBUG
	 
	int clear = 0;
	if (page[0] == '-') {
		clear = 1;
		page++;
	}
#endif  

	switch (sscanf(page, "%llu %d%c", &sector, &length, &newline)) {
	case 3:
		if (newline != '\n')
			return -EINVAL;
	case 2:
		if (length <= 0)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

#ifdef DO_DEBUG
	if (clear) {
		md_clear_badblocks(bb, sector, length);
		return len;
	}
#endif  
	if (md_set_badblocks(bb, sector, length, !unack))
		return len;
	else
		return -ENOSPC;
}

static int md_notify_reboot(struct notifier_block *this,
			    unsigned long code, void *x)
{
	struct list_head *tmp;
	struct mddev *mddev;
	int need_delay = 0;

	for_each_mddev(mddev, tmp) {
		if (mddev_trylock(mddev)) {
			if (mddev->pers)
				__md_stop_writes(mddev);
			if (mddev->persistent)
				mddev->safemode = 2;
			mddev_unlock(mddev);
		}
		need_delay = 1;
	}
	 
	if (need_delay)
		mdelay(1000*1);

	return NOTIFY_DONE;
}

static struct notifier_block md_notifier = {
	.notifier_call	= md_notify_reboot,
	.next		= NULL,
	.priority	= INT_MAX,  
};

static void md_geninit(void)
{
	pr_debug("md: sizeof(mdp_super_t) = %d\n", (int)sizeof(mdp_super_t));

	proc_create("mdstat", S_IRUGO, NULL, &md_seq_fops);
}

static int __init md_init(void)
{
	int ret = -ENOMEM;

	md_wq = alloc_workqueue("md", WQ_MEM_RECLAIM, 0);
	if (!md_wq)
		goto err_wq;

	md_misc_wq = alloc_workqueue("md_misc", 0, 0);
	if (!md_misc_wq)
		goto err_misc_wq;

	if ((ret = register_blkdev(MD_MAJOR, "md")) < 0)
		goto err_md;

	if ((ret = register_blkdev(0, "mdp")) < 0)
		goto err_mdp;
	mdp_major = ret;

#ifdef MY_ABC_HERE
	syno_mdio_cache = KMEM_CACHE(syno_mdio, 0);
	if (!syno_mdio_cache)
		goto err_cache;
#endif  

	blk_register_region(MKDEV(MD_MAJOR, 0), 512, THIS_MODULE,
			    md_probe, NULL, NULL);
	blk_register_region(MKDEV(mdp_major, 0), 1UL<<MINORBITS, THIS_MODULE,
			    md_probe, NULL, NULL);

	register_reboot_notifier(&md_notifier);
	raid_table_header = register_sysctl_table(raid_root_table);

	md_geninit();

#ifdef MY_ABC_HERE
	funcSYNORaidDiskUnplug = SYNORaidDiskUnplug;
#ifdef CONFIG_BLK_DEV_NVME
	funcSYNORaidNVMeUnplug = SYNORaidDiskUnplug;
#endif  
#endif  

	return 0;

#ifdef MY_ABC_HERE
err_cache:
	unregister_blkdev(mdp_major, "mdp");
#endif  
err_mdp:
	unregister_blkdev(MD_MAJOR, "md");
err_md:
	destroy_workqueue(md_misc_wq);
err_misc_wq:
	destroy_workqueue(md_wq);
err_wq:
	return ret;
}

static void check_sb_changes(struct mddev *mddev, struct md_rdev *rdev)
{
	struct mdp_superblock_1 *sb = page_address(rdev->sb_page);
	struct md_rdev *rdev2;
	int role, ret;
	char b[BDEVNAME_SIZE];

	rdev_for_each(rdev2, mddev) {
		if (test_bit(Faulty, &rdev2->flags))
			continue;

		role = le16_to_cpu(sb->dev_roles[rdev2->desc_nr]);

		if (test_bit(Candidate, &rdev2->flags)) {
			if (role == 0xfffe) {
				pr_info("md: Removing Candidate device %s because add failed\n", bdevname(rdev2->bdev,b));
				md_kick_rdev_from_array(rdev2);
				continue;
			}
			else
				clear_bit(Candidate, &rdev2->flags);
		}

		if (role != rdev2->raid_disk) {
			 
			if (rdev2->raid_disk == -1 && role != 0xffff) {
				rdev2->saved_raid_disk = role;
				ret = remove_and_add_spares(mddev, rdev2);
				pr_info("Activated spare: %s\n",
						bdevname(rdev2->bdev,b));
				continue;
			}
			 
			if ((role == 0xfffe) || (role == 0xfffd)) {
				md_error(mddev, rdev2);
				clear_bit(Blocked, &rdev2->flags);
			}
		}
	}

	if (mddev->raid_disks != le32_to_cpu(sb->raid_disks))
		update_raid_disks(mddev, le32_to_cpu(sb->raid_disks));

	mddev->events = le64_to_cpu(sb->events);
}

static int read_rdev(struct mddev *mddev, struct md_rdev *rdev)
{
	int err;
	struct page *swapout = rdev->sb_page;
	struct mdp_superblock_1 *sb;

	rdev->sb_page = NULL;
	alloc_disk_sb(rdev);
	ClearPageUptodate(rdev->sb_page);
	rdev->sb_loaded = 0;
	err = super_types[mddev->major_version].load_super(rdev, NULL, mddev->minor_version);

	if (err < 0) {
		pr_warn("%s: %d Could not reload rdev(%d) err: %d. Restoring old values\n",
				__func__, __LINE__, rdev->desc_nr, err);
		put_page(rdev->sb_page);
		rdev->sb_page = swapout;
		rdev->sb_loaded = 1;
		return err;
	}

	sb = page_address(rdev->sb_page);
	 
	if ((le32_to_cpu(sb->feature_map) & MD_FEATURE_RECOVERY_OFFSET))
		rdev->recovery_offset = le64_to_cpu(sb->recovery_offset);

	if (rdev->recovery_offset == MaxSector &&
	    !test_bit(In_sync, &rdev->flags) &&
	    mddev->pers->spare_active(mddev))
		sysfs_notify(&mddev->kobj, NULL, "degraded");

	put_page(swapout);
	return 0;
}

void md_reload_sb(struct mddev *mddev, int nr)
{
	struct md_rdev *rdev;
	int err;

	rdev_for_each_rcu(rdev, mddev) {
		if (rdev->desc_nr == nr)
			break;
	}

	if (!rdev || rdev->desc_nr != nr) {
		pr_warn("%s: %d Could not find rdev with nr %d\n", __func__, __LINE__, nr);
		return;
	}

	err = read_rdev(mddev, rdev);
	if (err < 0)
		return;

	check_sb_changes(mddev, rdev);

	rdev_for_each_rcu(rdev, mddev)
		read_rdev(mddev, rdev);
}
EXPORT_SYMBOL(md_reload_sb);

#ifndef MODULE

#ifdef MY_ABC_HERE
DEFINE_SPINLOCK(all_detected_devices_lock);
#endif  
static LIST_HEAD(all_detected_devices);
struct detected_devices_node {
	struct list_head list;
	dev_t dev;
};

void md_autodetect_dev(dev_t dev)
{
	struct detected_devices_node *node_detected_dev;

	node_detected_dev = kzalloc(sizeof(*node_detected_dev), GFP_KERNEL);
	if (node_detected_dev) {
		node_detected_dev->dev = dev;
#ifdef MY_ABC_HERE
		spin_lock(&all_detected_devices_lock);
#endif  
		list_add_tail(&node_detected_dev->list, &all_detected_devices);
#ifdef MY_ABC_HERE
		spin_unlock(&all_detected_devices_lock);
#endif  
	} else {
		printk(KERN_CRIT "md: md_autodetect_dev: kzalloc failed"
			", skipping dev(%d,%d)\n", MAJOR(dev), MINOR(dev));
	}
}

#ifdef MY_ABC_HERE
 
static u8
blDenyDisks(const struct block_device *pBDev)
{
	u8 ret = 1;
	int part = -1;

	if (!pBDev) {
		goto END;
	}
	 
#if defined(MY_DEF_HERE)
	 
#else
	if (!(pBDev->bd_disk->systemDisk)) {
		goto END;
	}
#endif

	part = MINOR(pBDev->bd_dev) - pBDev->bd_disk->first_minor;
	 
	if (part > 2) {
		goto END;
	}

	ret = 0;
END:
	return ret;
}
#endif  

#ifdef MY_ABC_HERE
 
static int device_sort_cmp(void *priv, struct list_head *plistHead1, struct list_head *plistHead2)
{
	struct detected_devices_node *pnode1 = NULL;
	struct detected_devices_node *pnode2 = NULL;
	int iRet = 0;

	if (plistHead1 != plistHead2) {
		pnode1 = list_entry(plistHead1, struct detected_devices_node, list);
		pnode2 = list_entry(plistHead2, struct detected_devices_node, list);

		if (MAJOR(pnode1->dev) == MAJOR(pnode2->dev)) {
			iRet = MINOR(pnode1->dev) - MINOR(pnode2->dev);
		} else {
			iRet = MAJOR(pnode1->dev) - MAJOR(pnode2->dev);
		}
	}

	return iRet;
}
#endif  

static void autostart_arrays(int part)
{
	struct md_rdev *rdev;
	struct detected_devices_node *node_detected_dev;
	dev_t dev;
	int i_scanned, i_passed;
#ifdef MY_ABC_HERE
	int iIsEmpty = 0;
#endif  

	i_scanned = 0;
	i_passed = 0;

	printk(KERN_INFO "md: Autodetecting RAID arrays.\n");

#ifdef MY_ABC_HERE
	spin_lock(&all_detected_devices_lock);
	iIsEmpty = list_empty(&all_detected_devices);
#ifdef MY_ABC_HERE
	list_sort(NULL, &all_detected_devices, device_sort_cmp);
#endif  
	spin_unlock(&all_detected_devices_lock);
	while (!iIsEmpty && i_scanned < INT_MAX) {
		i_scanned++;
		spin_lock(&all_detected_devices_lock);
		node_detected_dev = list_entry(all_detected_devices.next,
					struct detected_devices_node, list);
		list_del(&node_detected_dev->list);
		iIsEmpty = list_empty(&all_detected_devices);
		spin_unlock(&all_detected_devices_lock);
#else  
#ifdef MY_ABC_HERE
	list_sort(NULL, &all_detected_devices, device_sort_cmp);
#endif  
	while (!list_empty(&all_detected_devices) && i_scanned < INT_MAX) {
		i_scanned++;
		node_detected_dev = list_entry(all_detected_devices.next,
					struct detected_devices_node, list);
		list_del(&node_detected_dev->list);
#endif  
		dev = node_detected_dev->dev;
		kfree(node_detected_dev);
		rdev = md_import_device(dev,0, 90);
		if (IS_ERR(rdev))
			continue;

		if (test_bit(Faulty, &rdev->flags))
			continue;

#ifdef MY_ABC_HERE
		if (blDenyDisks(rdev->bdev)) {
			char b[BDEVNAME_SIZE];

			printk(KERN_INFO "md: deny %s.\n",
				   bdevname(rdev->bdev,b));

			export_rdev(rdev);
			continue;
		}
#endif  
		set_bit(AutoDetected, &rdev->flags);
#ifdef MY_ABC_HERE
		 
		list_add_tail(&rdev->same_set, &pending_raid_disks);
#else  
		list_add(&rdev->same_set, &pending_raid_disks);
#endif  
		i_passed++;
	}

	printk(KERN_INFO "md: Scanned %d and added %d devices.\n",
						i_scanned, i_passed);

	autorun_devices(part);
}

#endif  

static __exit void md_exit(void)
{
	struct mddev *mddev;
	struct list_head *tmp;
	int delay = 1;

#ifdef MY_ABC_HERE
	kmem_cache_destroy(syno_mdio_cache);
#endif  
	blk_unregister_region(MKDEV(MD_MAJOR,0), 512);
	blk_unregister_region(MKDEV(mdp_major,0), 1U << MINORBITS);

	unregister_blkdev(MD_MAJOR,"md");
	unregister_blkdev(mdp_major, "mdp");
	unregister_reboot_notifier(&md_notifier);
	unregister_sysctl_table(raid_table_header);

	md_unloading = 1;
	while (waitqueue_active(&md_event_waiters)) {
		 
		wake_up(&md_event_waiters);
		msleep(delay);
		delay += delay;
	}
	remove_proc_entry("mdstat", NULL);

	for_each_mddev(mddev, tmp) {
		export_array(mddev);
		mddev->hold_active = 0;
	}
	destroy_workqueue(md_misc_wq);
	destroy_workqueue(md_wq);
}

subsys_initcall(md_init);
module_exit(md_exit)

static int get_ro(char *buffer, struct kernel_param *kp)
{
	return sprintf(buffer, "%d", start_readonly);
}
static int set_ro(const char *val, struct kernel_param *kp)
{
	return kstrtouint(val, 10, (unsigned int *)&start_readonly);
}

module_param_call(start_ro, set_ro, get_ro, NULL, S_IRUSR|S_IWUSR);
module_param(start_dirty_degraded, int, S_IRUGO|S_IWUSR);
module_param_call(new_array, add_named_array, NULL, NULL, S_IWUSR);

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)

#ifdef MY_ABC_HERE
void syno_md_error(struct mddev *mddev, struct md_rdev *rdev)
#else  
static void syno_md_error(struct mddev *mddev, struct md_rdev *rdev)
#endif  
{
	if (!mddev) {
		printk(KERN_ERR "md: bug in file %s, line %d\n", __FILE__, __LINE__);
		return;
	}

	if (!rdev || test_bit(Faulty, &rdev->flags))
		return;
 
	if (!mddev->pers)
		return;
	if (!mddev->pers->error_handler)
		return;
#ifdef MY_ABC_HERE
	if(NULL != mddev->pers->syno_error_handler) {
		mddev->pers->syno_error_handler(mddev,rdev);
	} else {
		mddev->pers->error_handler(mddev,rdev);
	}
#else  
	mddev->pers->error_handler(mddev,rdev);
#endif  
	if (mddev->degraded)
		set_bit(MD_RECOVERY_RECOVER, &mddev->recovery);
	sysfs_notify_dirent_safe(rdev->sysfs_state);
	set_bit(MD_RECOVERY_INTR, &mddev->recovery);
	set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
#ifdef MY_ABC_HERE
	if (test_bit(MD_RECOVERY_RESHAPE, &mddev->recovery)) {
		mddev->reshape_interrupt = 1;
	}
#endif  
	md_wakeup_thread(mddev->thread);
	if (mddev->event_work.func)
		queue_work(md_misc_wq, &mddev->event_work);
	md_new_event_inintr(mddev);
}

EXPORT_SYMBOL(syno_md_error);
#endif  

#ifdef MY_ABC_HERE
 
#define SYNO_RAID0 0
static int syno_hot_remove_disk(struct mddev * mddev, struct md_rdev *rdev)
{
	char b[BDEVNAME_SIZE];
	int res = -1;
	struct md_rdev *rdev_tmp;
	unsigned char blNoRdev = 1;

	if(0 != mddev_lock(mddev)) {
		res = -EAGAIN;
		printk(KERN_WARNING "%s (%d): mddev_lock fail try again!\n",__FUNCTION__, __LINE__);
		goto ABORT;
	}

	list_for_each_entry(rdev_tmp, &mddev->disks, same_set) {
		 
		if (rdev_tmp == rdev) {
			blNoRdev = 0;
		}
	}

	if (blNoRdev) {
		res = -ENODEV;
		goto END;
	}

	if (!mddev->pers || !rdev || !rdev->mddev) {
		printk(KERN_WARNING "%s (%d): !mddev->pers || !rdev->mddev || !rdev\n",__FUNCTION__, __LINE__);
		res = -ENODEV;
		goto END;
	}

	if(SYNO_RAID0 == mddev->level ||
	   LEVEL_LINEAR == mddev->level) {
		 
		if(mddev->pers->hot_remove_disk) {
			if(0 != mddev->pers->hot_remove_disk(mddev, rdev)) {
				res = -EAGAIN;
				goto END;
			}
		}
	} else {
		 
		if (mddev->ro) {
			 
			printk(KERN_WARNING "%s (%d): %s is in readonly mode, remove faulty disk %s by ourself\n",__FUNCTION__, __LINE__, mdname(mddev), bdevname(rdev->bdev,b));
			remove_faulty(mddev);
		}
	}

	if (rdev->raid_disk >= 0) {
		if (mddev->curr_resync == 1 || mddev->curr_resync == 2) {
			res = -EBUSY;
			remove_faulty(mddev);
		} else {
			res = -EAGAIN;
		}
		printk(KERN_WARNING "%s (%d): cannot remove active disk %s from %s ... rdev->raid_disk %d pending %u\n",
			   __FUNCTION__, __LINE__, bdevname(rdev->bdev,b), mdname(mddev), rdev->raid_disk, atomic_read(&rdev->nr_pending));
		goto END;
	}

	md_kick_rdev_from_array(rdev);
	md_update_sb(mddev, 1);
	md_new_event(mddev);

	res = 0;
END:
	mddev_unlock(mddev);
ABORT:
	return res;
}

static int syno_set_disk_faulty(struct mddev * mddev, struct md_rdev *rdev)
{
	int res = -1;
	struct md_rdev *rdev_tmp;
	unsigned char blNoRdev = 1;

	if(0 != mddev_lock(mddev)) {
		printk(KERN_WARNING "%s (%d): mddev_lock fail try again!\n",__FUNCTION__, __LINE__);
		res = -EAGAIN;
		goto ABORT;
	}

	list_for_each_entry(rdev_tmp, &mddev->disks, same_set) {
		 
		if (rdev_tmp == rdev) {
			blNoRdev = 0;
		}
	}

	if (blNoRdev) {
		res = -ENODEV;
		goto END;
	}

	if (mddev->pers == NULL || !rdev || !rdev->mddev) {
		printk(KERN_WARNING "%s (%d): set faulty error! \n",__FUNCTION__, __LINE__);
		res = -ENODEV;
		goto END;
	}

	syno_md_error(mddev, rdev);

	res = 0;
END:
	mddev_unlock(mddev);
ABORT:
	return res;
}

static int SynoCheckRdevIsWorking(struct mddev *mddev, struct md_rdev *rdev)
{
	int res = -1;
	char b[BDEVNAME_SIZE];
	struct md_rdev *rdev_tmp;
	unsigned char blNoRdev = 1;

	if (0 != mddev_lock(mddev)) {
		printk(KERN_WARNING "%s (%d): mddev_lock fail try again!\n",__FUNCTION__, __LINE__);
		res = -EAGAIN;
		goto ABORT;
	}

	list_for_each_entry(rdev_tmp, &mddev->disks, same_set) {
		 
		if (rdev_tmp == rdev) {
			blNoRdev = 0;
		}
	}

	if (blNoRdev) {
		res = -ENODEV;
		goto END;
	}

	if (mddev->pers == NULL || !rdev || !rdev->mddev) {
		res = -ENODEV;
		goto END;
	}

	printk("%s (%d): remove active disk %s from %s "
				   "raid_disks %d mddev->degraded %d mddev->level %d \n", __FUNCTION__, __LINE__,
				   bdevname(rdev->bdev, b), mdname(mddev),
				   mddev->raid_disks, mddev->degraded, mddev->level);
	res = 0;
END:
	mddev_unlock(mddev);
ABORT:
	return res;
}

typedef struct _tag_SYNO_RAID_UNPLUG_WORK{
	struct work_struct work;
	char szDiskName[BDEVNAME_SIZE];
}SYNO_RAID_UNPLUG_WORK;

typedef struct _tag_SYNO_RDEV_UNPLUG_WORK{
	struct work_struct work;
	struct mddev *mddev;
	struct md_rdev *rdev;
}SYNO_RDEV_UNPLUG_WORK;

static int SynoRaidUnplugSingleRdev(struct mddev *mddev, struct md_rdev *rdev)
{
	int status;
	int res = 0;

AGAIN:
	status = SynoCheckRdevIsWorking(mddev, rdev);
	if (-ENODEV == status) {
		goto END;
	}

	if (-EAGAIN == status) {
		goto AGAIN;
	}

	status = syno_set_disk_faulty(mddev, rdev);
	if (-ENODEV == status) {
		goto END;
	}

	if (-EAGAIN == status) {
		goto AGAIN;
	}

	status = syno_hot_remove_disk(mddev, rdev);
	if (-EBUSY == status) {
		res = -1;
		goto END;
	}

	if (-EAGAIN == status) {
		 
		msleep(1000);
		goto AGAIN;
	}

END:
	return res;
}

void SYNORaidUnplugTask(struct work_struct *work)
{
	struct mddev *mddev;
	struct md_rdev *rdev;
	struct list_head *mdev_tmp;
	char b[BDEVNAME_SIZE];
	char *szDiskName;

	SYNO_RAID_UNPLUG_WORK *raid_unplug_work = container_of(work, SYNO_RAID_UNPLUG_WORK, work);

	if(NULL == raid_unplug_work) {
		printk("%s %d: NULL == raid_unplug_work, not doing this function done.\n", __FILE__, __LINE__);
		return;
	}

	szDiskName = raid_unplug_work->szDiskName;

	if (NULL == szDiskName || 0 == szDiskName[0]) {
		kfree(raid_unplug_work);
		return;
	}

	for_each_mddev(mddev, mdev_tmp) {
		if(0 != mddev_lock(mddev)) {
			WARN_ON(1);
			printk(KERN_WARNING "%s (%d): mddev_lock fail try again!\n",__FUNCTION__, __LINE__);
			continue;
		}

		list_for_each_entry(rdev, &mddev->disks, same_set) {
			 
			if (rdev && rdev->mddev) {
				bdevname(rdev->bdev, b);
			} else {
				continue;
			}

			if (!strcmp(rdev->bdev->bd_disk->disk_name, szDiskName)) {
				SYNORaidRdevUnplug(mddev, rdev);
			}
		}
		mddev_unlock(mddev);
	}

	kfree(raid_unplug_work);
	return;
}

static void SYNORdevUnplugTask(struct work_struct *work)
{
	struct mddev *mddev;
	struct md_rdev *rdev;
	SYNO_RDEV_UNPLUG_WORK *rdev_unplug_work = container_of(work, SYNO_RDEV_UNPLUG_WORK, work);

	if(NULL == rdev_unplug_work) {
		printk("%s %d: NULL == raid_unplug_work, not doing this function done.\n", __FILE__, __LINE__);
		return;
	}

	mddev = rdev_unplug_work->mddev;
	rdev = rdev_unplug_work->rdev;

	if (SynoRaidUnplugSingleRdev(mddev, rdev)) {
		schedule_work(&rdev_unplug_work->work);
		return;
	}

	kfree(rdev_unplug_work);
	return;
}

int SYNORaidDiskUnplug(char *szArgDiskName)
{
	SYNO_RAID_UNPLUG_WORK *raid_unplug_work = kmalloc(sizeof(SYNO_RAID_UNPLUG_WORK), GFP_ATOMIC);

	if(raid_unplug_work != NULL) {
		strlcpy(raid_unplug_work->szDiskName, szArgDiskName, BDEVNAME_SIZE);

		INIT_WORK(&raid_unplug_work->work, SYNORaidUnplugTask);

		if (schedule_work(&raid_unplug_work->work) == 0) {
			printk("(%s) [%s] - %d,"
				   " schedule_work(&worker->work) already on the queue, not queuing again\n", __FILE__, __func__, __LINE__);
			kfree(raid_unplug_work);
		}

	} else {
		printk("%s %d: kmalloc error\n", __FILE__, __LINE__);
	}
	return 0;
}

void SYNORaidRdevUnplug(struct mddev *mddev, struct md_rdev *rdev)
{
	SYNO_RDEV_UNPLUG_WORK *rdev_unplug_work = kmalloc(sizeof(SYNO_RDEV_UNPLUG_WORK), GFP_ATOMIC);

	if(rdev_unplug_work != NULL) {
		rdev_unplug_work->mddev = mddev;
		rdev_unplug_work->rdev = rdev;
		INIT_WORK(&rdev_unplug_work->work, SYNORdevUnplugTask);

		if (schedule_work(&rdev_unplug_work->work) == 0) {
			printk("(%s) [%s] - %d,"
				   " schedule_work(&rdev_unplug_work->work) already on the queue, not queuing again\n", __FILE__, __func__, __LINE__);
			kfree(rdev_unplug_work);
		}
	} else {
		printk("%s %d: kmalloc error\n", __FILE__, __LINE__);
	}
}

void
SynoUpdateSBTask(struct work_struct *work)
{
	SYNO_UPDATE_SB_WORK *update_sb = container_of(work, SYNO_UPDATE_SB_WORK, work);

	if (!update_sb) {
		WARN_ON(!update_sb);
		return;
	}

	if (!update_sb->mddev) {
		WARN_ON(!update_sb->mddev);
		goto END;
	}

	if(0 != mddev_lock(update_sb->mddev)) {
		printk(KERN_WARNING "%s (%d): mddev_lock fail try again!\n",__FUNCTION__, __LINE__);
		goto END;
	}

	md_update_sb(update_sb->mddev, 1);

	mddev_unlock(update_sb->mddev);
END:
	kfree(update_sb);
}
EXPORT_SYMBOL(SynoUpdateSBTask);
#endif  
#ifdef MY_ABC_HERE
static void wakeup_bi_complete(struct bio *bio)
{
	bio_put(bio);
}

static void wakeup_io(struct block_device *bdev, sector_t sector, int size,
		   struct page *page, int rw)
{
	struct bio *bio = bio_alloc(GFP_NOIO, 1);

	rw |= REQ_SYNC;

	bio->bi_bdev = bdev;
	bio->bi_iter.bi_sector = sector;
	bio_add_page(bio, page, size, 0);
	bio->bi_private = NULL;
	bio->bi_end_io = wakeup_bi_complete;
	submit_bio(rw, bio);
}

static void SYNOWakeUpTask(struct work_struct *work) {
	struct md_rdev *rdev = NULL;
	SYNO_WAKEUP_DEVICE_WORK *pWakeup_work = container_of(work, SYNO_WAKEUP_DEVICE_WORK, work);
	struct mddev *mddev = pWakeup_work->mddev;

	if (!mddev) {
		goto END;
	}

	if(0 != mddev_lock(mddev)){
		goto END;
	}

	list_for_each_entry(rdev, &mddev->disks, same_set) {
		wakeup_io(rdev->bdev, rdev->sb_start, MD_SB_BYTES, rdev->wakeup_page, 0);
	}
	mddev_unlock(mddev);
	kfree(pWakeup_work);
END:
	return;
}

void SynoMDWakeUpDevices(void *md)
{
	SYNO_WAKEUP_DEVICE_WORK *pWakeup_work = NULL;
	struct mddev *mddev = md;

	if (!md) {
		printk("%s no mddev\n", __FUNCTION__);
		goto END;
	}

	if (NULL == (pWakeup_work = kzalloc(sizeof(SYNO_WAKEUP_DEVICE_WORK), GFP_ATOMIC))){
		WARN_ON(!pWakeup_work);
		goto END;
	}

	INIT_WORK(&pWakeup_work->work, SYNOWakeUpTask);
	pWakeup_work->mddev = mddev;
	schedule_work(&pWakeup_work->work);

	spin_lock(&mddev->ActLock);
	mddev->blActive = 1;
	spin_unlock(&mddev->ActLock);
END:
	return;
}
EXPORT_SYMBOL(SynoMDWakeUpDevices);
#endif  

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MD RAID framework");
MODULE_ALIAS("md");
MODULE_ALIAS_BLOCKDEV_MAJOR(MD_MAJOR);
