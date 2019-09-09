#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include "dm.h"
#include "dm-uevent.h"
#ifdef MY_ABC_HERE
#include "md.h"
#endif  

#include <linux/init.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/moduleparam.h>
#include <linux/blkpg.h>
#include <linux/bio.h>
#include <linux/mempool.h>
#include <linux/slab.h>
#include <linux/idr.h>
#include <linux/hdreg.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/ktime.h>
#include <linux/elevator.h>  
#include <linux/blk-mq.h>
#include <linux/pr.h>

#include <trace/events/block.h>

#define DM_MSG_PREFIX "core"

#ifdef CONFIG_PRINTK
 
DEFINE_RATELIMIT_STATE(dm_ratelimit_state,
		       DEFAULT_RATELIMIT_INTERVAL,
		       DEFAULT_RATELIMIT_BURST);
EXPORT_SYMBOL(dm_ratelimit_state);
#endif

#define DM_COOKIE_ENV_VAR_NAME "DM_COOKIE"
#define DM_COOKIE_LENGTH 24
#ifdef MY_ABC_HERE
void SynoMDWakeUpDevices(void *md);
#endif  

static const char *_name = DM_NAME;

static unsigned int major = 0;
static unsigned int _major = 0;

static DEFINE_IDR(_minor_idr);

#ifdef MY_ABC_HERE
extern sector_t (*funcSYNOLvLgSectorCount)(void *private, sector_t sector);
sector_t SynoLvLgSectorCount(void *, sector_t);
#endif  

static DEFINE_SPINLOCK(_minor_lock);

static void do_deferred_remove(struct work_struct *w);

static DECLARE_WORK(deferred_remove_work, do_deferred_remove);

static struct workqueue_struct *deferred_remove_workqueue;

struct dm_io {
	struct mapped_device *md;
	int error;
	atomic_t io_count;
	struct bio *bio;
	unsigned long start_time;
	spinlock_t endio_lock;
	struct dm_stats_aux stats_aux;
};

struct dm_rq_target_io {
	struct mapped_device *md;
	struct dm_target *ti;
	struct request *orig, *clone;
	struct kthread_work work;
	int error;
	union map_info info;
	struct dm_stats_aux stats_aux;
	unsigned long duration_jiffies;
	unsigned n_sectors;
};

struct dm_rq_clone_bio_info {
	struct bio *orig;
	struct dm_rq_target_io *tio;
	struct bio clone;
};

union map_info *dm_get_rq_mapinfo(struct request *rq)
{
	if (rq && rq->end_io_data)
		return &((struct dm_rq_target_io *)rq->end_io_data)->info;
	return NULL;
}
EXPORT_SYMBOL_GPL(dm_get_rq_mapinfo);

#define MINOR_ALLOCED ((void *)-1)

#define DMF_BLOCK_IO_FOR_SUSPEND 0
#define DMF_SUSPENDED 1
#define DMF_FROZEN 2
#define DMF_FREEING 3
#define DMF_DELETING 4
#define DMF_NOFLUSH_SUSPENDING 5
#define DMF_DEFERRED_REMOVE 6
#define DMF_SUSPENDED_INTERNALLY 7

struct dm_table {
	int undefined__;
};

struct mapped_device {
	struct srcu_struct io_barrier;
	struct mutex suspend_lock;
	atomic_t holders;
	atomic_t open_count;

	struct dm_table __rcu *map;

	struct list_head table_devices;
	struct mutex table_devices_lock;

	unsigned long flags;

	struct request_queue *queue;
	unsigned type;
	 
	struct mutex type_lock;

	struct target_type *immutable_target_type;

	struct gendisk *disk;
	char name[16];

	void *interface_ptr;

	atomic_t pending[2];
	wait_queue_head_t wait;
	struct work_struct work;
	struct bio_list deferred;
	spinlock_t deferred_lock;

	struct workqueue_struct *wq;

	mempool_t *io_pool;
	mempool_t *rq_pool;

	struct bio_set *bs;

	atomic_t event_nr;
	wait_queue_head_t eventq;
	atomic_t uevent_seq;
	struct list_head uevent_list;
	spinlock_t uevent_lock;  

	struct super_block *frozen_sb;
	struct block_device *bdev;

	struct hd_geometry geometry;

	struct dm_kobject_holder kobj_holder;

	struct bio flush_bio;
#ifdef MY_ABC_HERE
	 
	int blActive;

	spinlock_t	ActLock;

	unsigned long ulLastReq;
#endif  

	unsigned internal_suspend_count;

	struct dm_stats stats;

	struct kthread_worker kworker;
	struct task_struct *kworker_task;

	unsigned seq_rq_merge_deadline_usecs;
	int last_rq_rw;
	sector_t last_rq_pos;
	ktime_t last_rq_start_time;

	struct blk_mq_tag_set tag_set;
	bool use_blk_mq;
};

#ifdef CONFIG_DM_MQ_DEFAULT
static bool use_blk_mq = true;
#else
static bool use_blk_mq = false;
#endif

bool dm_use_blk_mq(struct mapped_device *md)
{
	return md->use_blk_mq;
}

struct dm_md_mempools {
	mempool_t *io_pool;
	mempool_t *rq_pool;
	struct bio_set *bs;
};

struct table_device {
	struct list_head list;
	atomic_t count;
	struct dm_dev dm_dev;
};

#define RESERVED_BIO_BASED_IOS		16
#define RESERVED_REQUEST_BASED_IOS	256
#define RESERVED_MAX_IOS		1024
static struct kmem_cache *_io_cache;
static struct kmem_cache *_rq_tio_cache;
static struct kmem_cache *_rq_cache;

static unsigned reserved_bio_based_ios = RESERVED_BIO_BASED_IOS;

static unsigned reserved_rq_based_ios = RESERVED_REQUEST_BASED_IOS;

static unsigned __dm_get_module_param(unsigned *module_param,
				      unsigned def, unsigned max)
{
	unsigned param = ACCESS_ONCE(*module_param);
	unsigned modified_param = 0;

	if (!param)
		modified_param = def;
	else if (param > max)
		modified_param = max;

	if (modified_param) {
		(void)cmpxchg(module_param, param, modified_param);
		param = modified_param;
	}

	return param;
}

unsigned dm_get_reserved_bio_based_ios(void)
{
	return __dm_get_module_param(&reserved_bio_based_ios,
				     RESERVED_BIO_BASED_IOS, RESERVED_MAX_IOS);
}
EXPORT_SYMBOL_GPL(dm_get_reserved_bio_based_ios);

unsigned dm_get_reserved_rq_based_ios(void)
{
	return __dm_get_module_param(&reserved_rq_based_ios,
				     RESERVED_REQUEST_BASED_IOS, RESERVED_MAX_IOS);
}
EXPORT_SYMBOL_GPL(dm_get_reserved_rq_based_ios);

static int __init local_init(void)
{
	int r = -ENOMEM;

	_io_cache = KMEM_CACHE(dm_io, 0);
	if (!_io_cache)
		return r;

	_rq_tio_cache = KMEM_CACHE(dm_rq_target_io, 0);
	if (!_rq_tio_cache)
		goto out_free_io_cache;

	_rq_cache = kmem_cache_create("dm_clone_request", sizeof(struct request),
				      __alignof__(struct request), 0, NULL);
	if (!_rq_cache)
		goto out_free_rq_tio_cache;

	r = dm_uevent_init();
	if (r)
		goto out_free_rq_cache;

	deferred_remove_workqueue = alloc_workqueue("kdmremove", WQ_UNBOUND, 1);
	if (!deferred_remove_workqueue) {
		r = -ENOMEM;
		goto out_uevent_exit;
	}

	_major = major;
	r = register_blkdev(_major, _name);
	if (r < 0)
		goto out_free_workqueue;

	if (!_major)
		_major = r;

	return 0;

out_free_workqueue:
	destroy_workqueue(deferred_remove_workqueue);
out_uevent_exit:
	dm_uevent_exit();
out_free_rq_cache:
	kmem_cache_destroy(_rq_cache);
out_free_rq_tio_cache:
	kmem_cache_destroy(_rq_tio_cache);
out_free_io_cache:
	kmem_cache_destroy(_io_cache);

	return r;
}

static void local_exit(void)
{
	flush_scheduled_work();
	destroy_workqueue(deferred_remove_workqueue);

	kmem_cache_destroy(_rq_cache);
	kmem_cache_destroy(_rq_tio_cache);
	kmem_cache_destroy(_io_cache);
	unregister_blkdev(_major, _name);
	dm_uevent_exit();

	_major = 0;

	DMINFO("cleaned up");
}

static int (*_inits[])(void) __initdata = {
	local_init,
	dm_target_init,
	dm_linear_init,
	dm_stripe_init,
	dm_io_init,
	dm_kcopyd_init,
	dm_interface_init,
	dm_statistics_init,
};

static void (*_exits[])(void) = {
	local_exit,
	dm_target_exit,
	dm_linear_exit,
	dm_stripe_exit,
	dm_io_exit,
	dm_kcopyd_exit,
	dm_interface_exit,
	dm_statistics_exit,
};

static int __init dm_init(void)
{
	const int count = ARRAY_SIZE(_inits);

	int r, i;

	for (i = 0; i < count; i++) {
		r = _inits[i]();
		if (r)
			goto bad;
	}

#ifdef MY_ABC_HERE
	funcSYNOLvLgSectorCount = SynoLvLgSectorCount;
#endif  

	return 0;

      bad:
	while (i--)
		_exits[i]();

	return r;
}

static void __exit dm_exit(void)
{
	int i = ARRAY_SIZE(_exits);

	while (i--)
		_exits[i]();

	idr_destroy(&_minor_idr);
}

int dm_deleting_md(struct mapped_device *md)
{
	return test_bit(DMF_DELETING, &md->flags);
}

static int dm_blk_open(struct block_device *bdev, fmode_t mode)
{
	struct mapped_device *md;

	spin_lock(&_minor_lock);

	md = bdev->bd_disk->private_data;
	if (!md)
		goto out;

	if (test_bit(DMF_FREEING, &md->flags) ||
	    dm_deleting_md(md)) {
		md = NULL;
		goto out;
	}

	dm_get(md);
	atomic_inc(&md->open_count);
out:
	spin_unlock(&_minor_lock);

	return md ? 0 : -ENXIO;
}

static void dm_blk_close(struct gendisk *disk, fmode_t mode)
{
	struct mapped_device *md;

	spin_lock(&_minor_lock);

	md = disk->private_data;
	if (WARN_ON(!md))
		goto out;

	if (atomic_dec_and_test(&md->open_count) &&
	    (test_bit(DMF_DEFERRED_REMOVE, &md->flags)))
		queue_work(deferred_remove_workqueue, &deferred_remove_work);

	dm_put(md);
out:
	spin_unlock(&_minor_lock);
}

int dm_open_count(struct mapped_device *md)
{
	return atomic_read(&md->open_count);
}

int dm_lock_for_deletion(struct mapped_device *md, bool mark_deferred, bool only_deferred)
{
	int r = 0;

	spin_lock(&_minor_lock);

	if (dm_open_count(md)) {
		r = -EBUSY;
		if (mark_deferred)
			set_bit(DMF_DEFERRED_REMOVE, &md->flags);
	} else if (only_deferred && !test_bit(DMF_DEFERRED_REMOVE, &md->flags))
		r = -EEXIST;
	else
		set_bit(DMF_DELETING, &md->flags);

	spin_unlock(&_minor_lock);

	return r;
}

int dm_cancel_deferred_remove(struct mapped_device *md)
{
	int r = 0;

	spin_lock(&_minor_lock);

	if (test_bit(DMF_DELETING, &md->flags))
		r = -EBUSY;
	else
		clear_bit(DMF_DEFERRED_REMOVE, &md->flags);

	spin_unlock(&_minor_lock);

	return r;
}

static void do_deferred_remove(struct work_struct *w)
{
	dm_deferred_remove();
}

sector_t dm_get_size(struct mapped_device *md)
{
	return get_capacity(md->disk);
}

struct request_queue *dm_get_md_queue(struct mapped_device *md)
{
	return md->queue;
}

struct dm_stats *dm_get_stats(struct mapped_device *md)
{
	return &md->stats;
}

static int dm_blk_getgeo(struct block_device *bdev, struct hd_geometry *geo)
{
	struct mapped_device *md = bdev->bd_disk->private_data;

	return dm_get_geometry(md, geo);
}

static int dm_get_live_table_for_ioctl(struct mapped_device *md,
		struct dm_target **tgt, struct block_device **bdev,
		fmode_t *mode, int *srcu_idx)
{
	struct dm_table *map;
	int r;

retry:
	r = -ENOTTY;
	map = dm_get_live_table(md, srcu_idx);
	if (!map || !dm_table_get_size(map))
		goto out;

	if (dm_table_get_num_targets(map) != 1)
		goto out;

	*tgt = dm_table_get_target(map, 0);

	if (!(*tgt)->type->prepare_ioctl)
		goto out;

	if (dm_suspended_md(md)) {
		r = -EAGAIN;
		goto out;
	}

	r = (*tgt)->type->prepare_ioctl(*tgt, bdev, mode);
	if (r < 0)
		goto out;

	return r;

out:
	dm_put_live_table(md, *srcu_idx);
	if (r == -ENOTCONN && !fatal_signal_pending(current)) {
		msleep(10);
		goto retry;
	}
	return r;
}

#ifdef MY_ABC_HERE
 
static int syno_dm_do_extra_ioctl(struct mapped_device *md,
		struct dm_target **tgt, struct block_device **bdev,
		fmode_t *mode, int *srcu_idx, unsigned int cmd, unsigned long arg)
{
	struct dm_table *map;
	int r;

retry:
	r = -ENOTTY;
	map = dm_get_live_table(md, srcu_idx);
	if (!map || !dm_table_get_size(map))
		goto out;

	if (dm_table_get_num_targets(map) != 1)
		goto out;

	*tgt = dm_table_get_target(map, 0);

	if (!(*tgt)->type->extra_ioctl) {
		r = 1;
		goto out;
	}

	if (dm_suspended_md(md)) {
		r = -EAGAIN;
		goto out;
	}

	r = (*tgt)->type->extra_ioctl(*tgt, cmd, arg);
	if (r < 0) {
		printk(KERN_ERR "%s: Invoke extra ioctl failed, cmd=%d", __FUNCTION__, cmd);
	}
	 
out:
	dm_put_live_table(md, *srcu_idx);
	if ((r == -ENOTCONN && !fatal_signal_pending(current)) || (-EAGAIN == r)) {
		msleep(10);
		goto retry;
	}
	return r;
}
#endif  

#ifdef MY_ABC_HERE
static void syno_md_fast_volume_wakeup(struct mapped_device *md)
{
	struct dm_dev_internal *dd = NULL;
	struct dm_table *map = NULL;
	char b[BDEVNAME_SIZE] = {'\0'};
	unsigned char blActive = 0;
	int srcu_idx = 0;

	if (time_after(jiffies, md->ulLastReq + CHECKINTERVAL)) {
		spin_lock(&md->ActLock);
		blActive = md->blActive;
		md->blActive = 1;
		spin_unlock(&md->ActLock);

		map = dm_get_live_table(md, &srcu_idx);
		if (map && !blActive) {
			list_for_each_entry (dd, dm_table_get_devices(map), list) {

				if (dd && dd->dm_dev->bdev && NULL != strstr(bdevname(dd->dm_dev->bdev, b), "md")) {
					if (dd->dm_dev->bdev->bd_disk && dd->dm_dev->bdev->bd_disk->private_data) {
						SynoMDWakeUpDevices(dd->dm_dev->bdev->bd_disk->private_data);
					}
				}
			}
		}
		dm_put_live_table(md, srcu_idx);
	}

	md->ulLastReq = jiffies;
}
#endif  

static int dm_blk_ioctl(struct block_device *bdev, fmode_t mode,
			unsigned int cmd, unsigned long arg)
{
	struct mapped_device *md = bdev->bd_disk->private_data;
	struct dm_target *tgt;
	struct block_device *tgt_bdev = NULL;
	int srcu_idx, r;

#ifdef MY_ABC_HERE
	r = syno_dm_do_extra_ioctl(md, &tgt, &tgt_bdev, &mode, &srcu_idx, cmd, arg);
	if (0 >= r) {
		goto out_no_put;
	}
	 
#endif  
	r = dm_get_live_table_for_ioctl(md, &tgt, &tgt_bdev, &mode, &srcu_idx);
	if (r < 0)
		return r;

	if (r > 0) {
		 
		r = scsi_verify_blk_ioctl(NULL, cmd);
		if (r)
			goto out;
	}

	r =  __blkdev_driver_ioctl(tgt_bdev, mode, cmd, arg);
out:
	dm_put_live_table(md, srcu_idx);
#ifdef MY_ABC_HERE
out_no_put:
#endif  
	return r;
}

static struct dm_io *alloc_io(struct mapped_device *md)
{
	return mempool_alloc(md->io_pool, GFP_NOIO);
}

static void free_io(struct mapped_device *md, struct dm_io *io)
{
	mempool_free(io, md->io_pool);
}

static void free_tio(struct mapped_device *md, struct dm_target_io *tio)
{
	bio_put(&tio->clone);
}

static struct dm_rq_target_io *alloc_rq_tio(struct mapped_device *md,
					    gfp_t gfp_mask)
{
	return mempool_alloc(md->io_pool, gfp_mask);
}

static void free_rq_tio(struct dm_rq_target_io *tio)
{
	mempool_free(tio, tio->md->io_pool);
}

static struct request *alloc_clone_request(struct mapped_device *md,
					   gfp_t gfp_mask)
{
	return mempool_alloc(md->rq_pool, gfp_mask);
}

static void free_clone_request(struct mapped_device *md, struct request *rq)
{
	mempool_free(rq, md->rq_pool);
}

static int md_in_flight(struct mapped_device *md)
{
	return atomic_read(&md->pending[READ]) +
	       atomic_read(&md->pending[WRITE]);
}

static void start_io_acct(struct dm_io *io)
{
	struct mapped_device *md = io->md;
	struct bio *bio = io->bio;
	int cpu;
	int rw = bio_data_dir(bio);

	io->start_time = jiffies;

	cpu = part_stat_lock();
	part_round_stats(cpu, &dm_disk(md)->part0);
	part_stat_unlock();
	atomic_set(&dm_disk(md)->part0.in_flight[rw],
		atomic_inc_return(&md->pending[rw]));

	if (unlikely(dm_stats_used(&md->stats)))
		dm_stats_account_io(&md->stats, bio->bi_rw, bio->bi_iter.bi_sector,
				    bio_sectors(bio), false, 0, &io->stats_aux);
}

static void end_io_acct(struct dm_io *io)
{
	struct mapped_device *md = io->md;
	struct bio *bio = io->bio;
	unsigned long duration = jiffies - io->start_time;
	int pending;
	int rw = bio_data_dir(bio);

	generic_end_io_acct(rw, &dm_disk(md)->part0, io->start_time);

	if (unlikely(dm_stats_used(&md->stats)))
		dm_stats_account_io(&md->stats, bio->bi_rw, bio->bi_iter.bi_sector,
				    bio_sectors(bio), true, duration, &io->stats_aux);

	pending = atomic_dec_return(&md->pending[rw]);
	atomic_set(&dm_disk(md)->part0.in_flight[rw], pending);
	pending += atomic_read(&md->pending[rw^0x1]);

	if (!pending)
		wake_up(&md->wait);
}

static void queue_io(struct mapped_device *md, struct bio *bio)
{
	unsigned long flags;

	spin_lock_irqsave(&md->deferred_lock, flags);
	bio_list_add(&md->deferred, bio);
	spin_unlock_irqrestore(&md->deferred_lock, flags);
	queue_work(md->wq, &md->work);
}

struct dm_table *dm_get_live_table(struct mapped_device *md, int *srcu_idx) __acquires(md->io_barrier)
{
	*srcu_idx = srcu_read_lock(&md->io_barrier);

	return srcu_dereference(md->map, &md->io_barrier);
}

void dm_put_live_table(struct mapped_device *md, int srcu_idx) __releases(md->io_barrier)
{
	srcu_read_unlock(&md->io_barrier, srcu_idx);
}

void dm_sync_table(struct mapped_device *md)
{
	synchronize_srcu(&md->io_barrier);
	synchronize_rcu_expedited();
}

static struct dm_table *dm_get_live_table_fast(struct mapped_device *md) __acquires(RCU)
{
	rcu_read_lock();
	return rcu_dereference(md->map);
}

static void dm_put_live_table_fast(struct mapped_device *md) __releases(RCU)
{
	rcu_read_unlock();
}

static int open_table_device(struct table_device *td, dev_t dev,
			     struct mapped_device *md)
{
	static char *_claim_ptr = "I belong to device-mapper";
	struct block_device *bdev;

	int r;

	BUG_ON(td->dm_dev.bdev);

	bdev = blkdev_get_by_dev(dev, td->dm_dev.mode | FMODE_EXCL, _claim_ptr);
	if (IS_ERR(bdev))
		return PTR_ERR(bdev);

	r = bd_link_disk_holder(bdev, dm_disk(md));
	if (r) {
		blkdev_put(bdev, td->dm_dev.mode | FMODE_EXCL);
		return r;
	}

	td->dm_dev.bdev = bdev;
	return 0;
}

static void close_table_device(struct table_device *td, struct mapped_device *md)
{
	if (!td->dm_dev.bdev)
		return;

	bd_unlink_disk_holder(td->dm_dev.bdev, dm_disk(md));
	blkdev_put(td->dm_dev.bdev, td->dm_dev.mode | FMODE_EXCL);
	td->dm_dev.bdev = NULL;
}

static struct table_device *find_table_device(struct list_head *l, dev_t dev,
					      fmode_t mode) {
	struct table_device *td;

	list_for_each_entry(td, l, list)
		if (td->dm_dev.bdev->bd_dev == dev && td->dm_dev.mode == mode)
			return td;

	return NULL;
}

int dm_get_table_device(struct mapped_device *md, dev_t dev, fmode_t mode,
			struct dm_dev **result) {
	int r;
	struct table_device *td;

	mutex_lock(&md->table_devices_lock);
	td = find_table_device(&md->table_devices, dev, mode);
	if (!td) {
		td = kmalloc(sizeof(*td), GFP_KERNEL);
		if (!td) {
			mutex_unlock(&md->table_devices_lock);
			return -ENOMEM;
		}

		td->dm_dev.mode = mode;
		td->dm_dev.bdev = NULL;

		if ((r = open_table_device(td, dev, md))) {
			mutex_unlock(&md->table_devices_lock);
			kfree(td);
			return r;
		}

		format_dev_t(td->dm_dev.name, dev);

		atomic_set(&td->count, 0);
		list_add(&td->list, &md->table_devices);
	}
	atomic_inc(&td->count);
	mutex_unlock(&md->table_devices_lock);

	*result = &td->dm_dev;
	return 0;
}
EXPORT_SYMBOL_GPL(dm_get_table_device);

void dm_put_table_device(struct mapped_device *md, struct dm_dev *d)
{
	struct table_device *td = container_of(d, struct table_device, dm_dev);

	mutex_lock(&md->table_devices_lock);
	if (atomic_dec_and_test(&td->count)) {
		close_table_device(td, md);
		list_del(&td->list);
		kfree(td);
	}
	mutex_unlock(&md->table_devices_lock);
}
EXPORT_SYMBOL(dm_put_table_device);

static void free_table_devices(struct list_head *devices)
{
	struct list_head *tmp, *next;

	list_for_each_safe(tmp, next, devices) {
		struct table_device *td = list_entry(tmp, struct table_device, list);

		DMWARN("dm_destroy: %s still exists with %d references",
		       td->dm_dev.name, atomic_read(&td->count));
		kfree(td);
	}
}

int dm_get_geometry(struct mapped_device *md, struct hd_geometry *geo)
{
	*geo = md->geometry;

	return 0;
}

int dm_set_geometry(struct mapped_device *md, struct hd_geometry *geo)
{
	sector_t sz = (sector_t)geo->cylinders * geo->heads * geo->sectors;

	if (geo->start > sz) {
		DMWARN("Start sector is beyond the geometry limits.");
		return -EINVAL;
	}

	md->geometry = *geo;

	return 0;
}

static int __noflush_suspending(struct mapped_device *md)
{
	return test_bit(DMF_NOFLUSH_SUSPENDING, &md->flags);
}

static void dec_pending(struct dm_io *io, int error)
{
	unsigned long flags;
	int io_error;
	struct bio *bio;
	struct mapped_device *md = io->md;

	if (unlikely(error)) {
		spin_lock_irqsave(&io->endio_lock, flags);
		if (!(io->error > 0 && __noflush_suspending(md)))
			io->error = error;
		spin_unlock_irqrestore(&io->endio_lock, flags);
	}

	if (atomic_dec_and_test(&io->io_count)) {
		if (io->error == DM_ENDIO_REQUEUE) {
			 
			spin_lock_irqsave(&md->deferred_lock, flags);
			if (__noflush_suspending(md))
				bio_list_add_head(&md->deferred, io->bio);
			else
				 
				io->error = -EIO;
			spin_unlock_irqrestore(&md->deferred_lock, flags);
		}

		io_error = io->error;
		bio = io->bio;
		end_io_acct(io);
		free_io(md, io);

		if (io_error == DM_ENDIO_REQUEUE)
			return;

		if ((bio->bi_rw & REQ_FLUSH) && bio->bi_iter.bi_size) {
			 
			bio->bi_rw &= ~REQ_FLUSH;
			queue_io(md, bio);
		} else {
			 
			trace_block_bio_complete(md->queue, bio, io_error);
			bio->bi_error = io_error;
			bio_endio(bio);
		}
	}
}

static void disable_write_same(struct mapped_device *md)
{
	struct queue_limits *limits = dm_get_queue_limits(md);

	limits->max_write_same_sectors = 0;
}

static void clone_endio(struct bio *bio)
{
	int error = bio->bi_error;
	int r = error;
	struct dm_target_io *tio = container_of(bio, struct dm_target_io, clone);
	struct dm_io *io = tio->io;
	struct mapped_device *md = tio->io->md;
	dm_endio_fn endio = tio->ti->type->end_io;

	if (endio) {
		r = endio(tio->ti, bio, error);
		if (r < 0 || r == DM_ENDIO_REQUEUE)
			 
			error = r;
		else if (r == DM_ENDIO_INCOMPLETE)
			 
			return;
		else if (r) {
			DMWARN("unimplemented target endio return value: %d", r);
			BUG();
		}
	}

	if (unlikely(r == -EREMOTEIO && (bio->bi_rw & REQ_WRITE_SAME) &&
		     !bdev_get_queue(bio->bi_bdev)->limits.max_write_same_sectors))
		disable_write_same(md);

	free_tio(md, tio);
	dec_pending(io, error);
}

static void end_clone_bio(struct bio *clone)
{
	struct dm_rq_clone_bio_info *info =
		container_of(clone, struct dm_rq_clone_bio_info, clone);
	struct dm_rq_target_io *tio = info->tio;
	struct bio *bio = info->orig;
	unsigned int nr_bytes = info->orig->bi_iter.bi_size;
	int error = clone->bi_error;

	bio_put(clone);

	if (tio->error)
		 
		return;
	else if (error) {
		 
		tio->error = error;
		return;
	}

	if (tio->orig->bio != bio)
		DMERR("bio completion is going in the middle of the request");

	blk_update_request(tio->orig, 0, nr_bytes);
}

static struct dm_rq_target_io *tio_from_request(struct request *rq)
{
	return (rq->q->mq_ops ? blk_mq_rq_to_pdu(rq) : rq->special);
}

static void rq_end_stats(struct mapped_device *md, struct request *orig)
{
	if (unlikely(dm_stats_used(&md->stats))) {
		struct dm_rq_target_io *tio = tio_from_request(orig);
		tio->duration_jiffies = jiffies - tio->duration_jiffies;
		dm_stats_account_io(&md->stats, orig->cmd_flags, blk_rq_pos(orig),
				    tio->n_sectors, true, tio->duration_jiffies,
				    &tio->stats_aux);
	}
}

static void rq_completed(struct mapped_device *md, int rw, bool run_queue)
{
	atomic_dec(&md->pending[rw]);

	if (!md_in_flight(md))
		wake_up(&md->wait);

	if (!md->queue->mq_ops && run_queue)
		blk_run_queue_async(md->queue);

	dm_put(md);
}

static void free_rq_clone(struct request *clone)
{
	struct dm_rq_target_io *tio = clone->end_io_data;
	struct mapped_device *md = tio->md;

	blk_rq_unprep_clone(clone);

	if (md->type == DM_TYPE_MQ_REQUEST_BASED)
		 
		tio->ti->type->release_clone_rq(clone);
	else if (!md->queue->mq_ops)
		 
		free_clone_request(md, clone);
	 
	if (!md->queue->mq_ops)
		free_rq_tio(tio);
}

static void dm_end_request(struct request *clone, int error)
{
	int rw = rq_data_dir(clone);
	struct dm_rq_target_io *tio = clone->end_io_data;
	struct mapped_device *md = tio->md;
	struct request *rq = tio->orig;

	if (rq->cmd_type == REQ_TYPE_BLOCK_PC) {
		rq->errors = clone->errors;
		rq->resid_len = clone->resid_len;

		if (rq->sense)
			 
			rq->sense_len = clone->sense_len;
	}

	free_rq_clone(clone);
	rq_end_stats(md, rq);
	if (!rq->q->mq_ops)
		blk_end_request_all(rq, error);
	else
		blk_mq_end_request(rq, error);
	rq_completed(md, rw, true);
}

static void dm_unprep_request(struct request *rq)
{
	struct dm_rq_target_io *tio = tio_from_request(rq);
	struct request *clone = tio->clone;

	if (!rq->q->mq_ops) {
		rq->special = NULL;
		rq->cmd_flags &= ~REQ_DONTPREP;
	}

	if (clone)
		free_rq_clone(clone);
	else if (!tio->md->queue->mq_ops)
		free_rq_tio(tio);
}

static void old_requeue_request(struct request *rq)
{
	struct request_queue *q = rq->q;
	unsigned long flags;

	spin_lock_irqsave(q->queue_lock, flags);
	blk_requeue_request(q, rq);
	blk_run_queue_async(q);
	spin_unlock_irqrestore(q->queue_lock, flags);
}

static void dm_requeue_original_request(struct mapped_device *md,
					struct request *rq)
{
	int rw = rq_data_dir(rq);

	rq_end_stats(md, rq);
	dm_unprep_request(rq);

	if (!rq->q->mq_ops)
		old_requeue_request(rq);
	else {
		blk_mq_requeue_request(rq);
		blk_mq_kick_requeue_list(rq->q);
	}

	rq_completed(md, rw, false);
}

static void old_stop_queue(struct request_queue *q)
{
	unsigned long flags;

	if (blk_queue_stopped(q))
		return;

	spin_lock_irqsave(q->queue_lock, flags);
	blk_stop_queue(q);
	spin_unlock_irqrestore(q->queue_lock, flags);
}

static void stop_queue(struct request_queue *q)
{
	if (!q->mq_ops)
		old_stop_queue(q);
	else
		blk_mq_stop_hw_queues(q);
}

static void old_start_queue(struct request_queue *q)
{
	unsigned long flags;

	spin_lock_irqsave(q->queue_lock, flags);
	if (blk_queue_stopped(q))
		blk_start_queue(q);
	spin_unlock_irqrestore(q->queue_lock, flags);
}

static void start_queue(struct request_queue *q)
{
	if (!q->mq_ops)
		old_start_queue(q);
	else
		blk_mq_start_stopped_hw_queues(q, true);
}

static void dm_done(struct request *clone, int error, bool mapped)
{
	int r = error;
	struct dm_rq_target_io *tio = clone->end_io_data;
	dm_request_endio_fn rq_end_io = NULL;

	if (tio->ti) {
		rq_end_io = tio->ti->type->rq_end_io;

		if (mapped && rq_end_io)
			r = rq_end_io(tio->ti, clone, error, &tio->info);
	}

	if (unlikely(r == -EREMOTEIO && (clone->cmd_flags & REQ_WRITE_SAME) &&
		     !clone->q->limits.max_write_same_sectors))
		disable_write_same(tio->md);

	if (r <= 0)
		 
		dm_end_request(clone, r);
	else if (r == DM_ENDIO_INCOMPLETE)
		 
		return;
	else if (r == DM_ENDIO_REQUEUE)
		 
		dm_requeue_original_request(tio->md, tio->orig);
	else {
		DMWARN("unimplemented target endio return value: %d", r);
		BUG();
	}
}

static void dm_softirq_done(struct request *rq)
{
	bool mapped = true;
	struct dm_rq_target_io *tio = tio_from_request(rq);
	struct request *clone = tio->clone;
	int rw;

	if (!clone) {
		rq_end_stats(tio->md, rq);
		rw = rq_data_dir(rq);
		if (!rq->q->mq_ops) {
			blk_end_request_all(rq, tio->error);
			rq_completed(tio->md, rw, false);
			free_rq_tio(tio);
		} else {
			blk_mq_end_request(rq, tio->error);
			rq_completed(tio->md, rw, false);
		}
		return;
	}

	if (rq->cmd_flags & REQ_FAILED)
		mapped = false;

	dm_done(clone, tio->error, mapped);
}

static void dm_complete_request(struct request *rq, int error)
{
	struct dm_rq_target_io *tio = tio_from_request(rq);

	tio->error = error;
	if (!rq->q->mq_ops)
		blk_complete_request(rq);
	else
		blk_mq_complete_request(rq, error);
}

static void dm_kill_unmapped_request(struct request *rq, int error)
{
	rq->cmd_flags |= REQ_FAILED;
	dm_complete_request(rq, error);
}

static void end_clone_request(struct request *clone, int error)
{
	struct dm_rq_target_io *tio = clone->end_io_data;

	if (!clone->q->mq_ops) {
		 
		__blk_put_request(clone->q, clone);
	}

	dm_complete_request(tio->orig, error);
}

static sector_t max_io_len_target_boundary(sector_t sector, struct dm_target *ti)
{
	sector_t target_offset = dm_target_offset(ti, sector);

	return ti->len - target_offset;
}

static sector_t max_io_len(sector_t sector, struct dm_target *ti)
{
	sector_t len = max_io_len_target_boundary(sector, ti);
	sector_t offset, max_len;

	if (ti->max_io_len) {
		offset = dm_target_offset(ti, sector);
		if (unlikely(ti->max_io_len & (ti->max_io_len - 1)))
			max_len = sector_div(offset, ti->max_io_len);
		else
			max_len = offset & (ti->max_io_len - 1);
		max_len = ti->max_io_len - max_len;

		if (len > max_len)
			len = max_len;
	}

	return len;
}

int dm_set_target_max_io_len(struct dm_target *ti, sector_t len)
{
	if (len > UINT_MAX) {
		DMERR("Specified maximum size of target IO (%llu) exceeds limit (%u)",
		      (unsigned long long)len, UINT_MAX);
		ti->error = "Maximum size of target IO is too large";
		return -EINVAL;
	}

	ti->max_io_len = (uint32_t) len;

	return 0;
}
EXPORT_SYMBOL_GPL(dm_set_target_max_io_len);

void dm_accept_partial_bio(struct bio *bio, unsigned n_sectors)
{
	struct dm_target_io *tio = container_of(bio, struct dm_target_io, clone);
	unsigned bi_size = bio->bi_iter.bi_size >> SECTOR_SHIFT;
	BUG_ON(bio->bi_rw & REQ_FLUSH);
	BUG_ON(bi_size > *tio->len_ptr);
	BUG_ON(n_sectors > bi_size);
	*tio->len_ptr -= bi_size - n_sectors;
	bio->bi_iter.bi_size = n_sectors << SECTOR_SHIFT;
}
EXPORT_SYMBOL_GPL(dm_accept_partial_bio);

#ifdef MY_ABC_HERE
sector_t SynoLvLgSectorCount(void *private, sector_t sector)
{
	struct dm_target *ti = (struct dm_target *)private;

	if (ti && ti->type->lg_sector_get) {
		return ti->type->lg_sector_get(sector, ti);
	}

	return 0;
}
EXPORT_SYMBOL(SynoLvLgSectorCount);
#endif  

struct dm_offload {
	struct blk_plug plug;
	struct blk_plug_cb cb;
};

static void flush_current_bio_list(struct blk_plug_cb *cb, bool from_schedule)
{
	struct dm_offload *o = container_of(cb, struct dm_offload, cb);
	struct bio_list list;
	struct bio *bio;

	INIT_LIST_HEAD(&o->cb.list);

	if (unlikely(!current->bio_list))
		return;

	list = *current->bio_list;
	bio_list_init(current->bio_list);

	while ((bio = bio_list_pop(&list))) {
		struct bio_set *bs = bio->bi_pool;
		if (unlikely(!bs) || bs == fs_bio_set) {
			bio_list_add(current->bio_list, bio);
			continue;
		}

		spin_lock(&bs->rescue_lock);
		bio_list_add(&bs->rescue_list, bio);
		queue_work(bs->rescue_workqueue, &bs->rescue_work);
		spin_unlock(&bs->rescue_lock);
	}
}

static void dm_offload_start(struct dm_offload *o)
{
	blk_start_plug(&o->plug);
	o->cb.callback = flush_current_bio_list;
	list_add(&o->cb.list, &current->plug->cb_list);
}

static void dm_offload_end(struct dm_offload *o)
{
	list_del(&o->cb.list);
	blk_finish_plug(&o->plug);
}

static void __map_bio(struct dm_target_io *tio)
{
	int r;
	sector_t sector;
	struct mapped_device *md;
	struct dm_offload o;
	struct bio *clone = &tio->clone;
	struct dm_target *ti = tio->ti;

	clone->bi_end_io = clone_endio;

	atomic_inc(&tio->io->io_count);
	sector = clone->bi_iter.bi_sector;

	dm_offload_start(&o);
	r = ti->type->map(ti, clone);
	dm_offload_end(&o);

	if (r == DM_MAPIO_REMAPPED) {
		 
		trace_block_bio_remap(bdev_get_queue(clone->bi_bdev), clone,
				      tio->io->bio->bi_bdev->bd_dev, sector);

		generic_make_request(clone);
	} else if (r < 0 || r == DM_MAPIO_REQUEUE) {
		 
		md = tio->io->md;
		dec_pending(tio->io, r);
		free_tio(md, tio);
	} else if (r != DM_MAPIO_SUBMITTED) {
		DMWARN("unimplemented target map return value: %d", r);
		BUG();
	}
}

struct clone_info {
	struct mapped_device *md;
	struct dm_table *map;
	struct bio *bio;
	struct dm_io *io;
	sector_t sector;
	unsigned sector_count;
};

static void bio_setup_sector(struct bio *bio, sector_t sector, unsigned len)
{
	bio->bi_iter.bi_sector = sector;
	bio->bi_iter.bi_size = to_bytes(len);
}

static void clone_bio(struct dm_target_io *tio, struct bio *bio,
		      sector_t sector, unsigned len)
{
	struct bio *clone = &tio->clone;

	__bio_clone_fast(clone, bio);

	if (bio_integrity(bio))
		bio_integrity_clone(clone, bio, GFP_NOIO);

	bio_advance(clone, to_bytes(sector - clone->bi_iter.bi_sector));
	clone->bi_iter.bi_size = to_bytes(len);

	if (bio_integrity(bio))
		bio_integrity_trim(clone, 0, len);
}

static struct dm_target_io *alloc_tio(struct clone_info *ci,
				      struct dm_target *ti,
				      unsigned target_bio_nr)
{
	struct dm_target_io *tio;
	struct bio *clone;

	clone = bio_alloc_bioset(GFP_NOIO, 0, ci->md->bs);
	tio = container_of(clone, struct dm_target_io, clone);

	tio->io = ci->io;
	tio->ti = ti;
	tio->target_bio_nr = target_bio_nr;

	return tio;
}

static void __clone_and_map_simple_bio(struct clone_info *ci,
				       struct dm_target *ti,
				       unsigned target_bio_nr, unsigned *len)
{
	struct dm_target_io *tio = alloc_tio(ci, ti, target_bio_nr);
	struct bio *clone = &tio->clone;

	tio->len_ptr = len;

	__bio_clone_fast(clone, ci->bio);
	if (len)
		bio_setup_sector(clone, ci->sector, *len);

	__map_bio(tio);
}

static void __send_duplicate_bios(struct clone_info *ci, struct dm_target *ti,
				  unsigned num_bios, unsigned *len)
{
	unsigned target_bio_nr;

	for (target_bio_nr = 0; target_bio_nr < num_bios; target_bio_nr++)
		__clone_and_map_simple_bio(ci, ti, target_bio_nr, len);
}

static int __send_empty_flush(struct clone_info *ci)
{
	unsigned target_nr = 0;
	struct dm_target *ti;

	BUG_ON(bio_has_data(ci->bio));
	while ((ti = dm_table_get_target(ci->map, target_nr++)))
		__send_duplicate_bios(ci, ti, ti->num_flush_bios, NULL);

	return 0;
}

static void __clone_and_map_data_bio(struct clone_info *ci, struct dm_target *ti,
				     sector_t sector, unsigned *len)
{
	struct bio *bio = ci->bio;
	struct dm_target_io *tio;
	unsigned target_bio_nr;
	unsigned num_target_bios = 1;

	if (bio_data_dir(bio) == WRITE && ti->num_write_bios)
		num_target_bios = ti->num_write_bios(ti, bio);

	for (target_bio_nr = 0; target_bio_nr < num_target_bios; target_bio_nr++) {
		tio = alloc_tio(ci, ti, target_bio_nr);
		tio->len_ptr = len;
		clone_bio(tio, bio, sector, *len);
		__map_bio(tio);
	}
}

typedef unsigned (*get_num_bios_fn)(struct dm_target *ti);

static unsigned get_num_discard_bios(struct dm_target *ti)
{
	return ti->num_discard_bios;
}

static unsigned get_num_write_same_bios(struct dm_target *ti)
{
	return ti->num_write_same_bios;
}

typedef bool (*is_split_required_fn)(struct dm_target *ti);

static bool is_split_required_for_discard(struct dm_target *ti)
{
	return ti->split_discard_bios;
}

static int __send_changing_extent_only(struct clone_info *ci,
				       get_num_bios_fn get_num_bios,
				       is_split_required_fn is_split_required)
{
	struct dm_target *ti;
	unsigned len;
	unsigned num_bios;

	do {
		ti = dm_table_find_target(ci->map, ci->sector);
		if (!dm_target_is_valid(ti))
			return -EIO;

		num_bios = get_num_bios ? get_num_bios(ti) : 0;
		if (!num_bios)
			return -EOPNOTSUPP;

		if (is_split_required && !is_split_required(ti))
			len = min((sector_t)ci->sector_count, max_io_len_target_boundary(ci->sector, ti));
		else
			len = min((sector_t)ci->sector_count, max_io_len(ci->sector, ti));

		__send_duplicate_bios(ci, ti, num_bios, &len);

		ci->sector += len;
	} while (ci->sector_count -= len);

	return 0;
}

static int __send_discard(struct clone_info *ci)
{
	return __send_changing_extent_only(ci, get_num_discard_bios,
					   is_split_required_for_discard);
}

static int __send_write_same(struct clone_info *ci)
{
	return __send_changing_extent_only(ci, get_num_write_same_bios, NULL);
}

static int __split_and_process_non_flush(struct clone_info *ci)
{
	struct bio *bio = ci->bio;
	struct dm_target *ti;
	unsigned len;

	if (unlikely(bio->bi_rw & REQ_DISCARD))
		return __send_discard(ci);
	else if (unlikely(bio->bi_rw & REQ_WRITE_SAME))
		return __send_write_same(ci);

	ti = dm_table_find_target(ci->map, ci->sector);
	if (!dm_target_is_valid(ti))
		return -EIO;

	len = min_t(sector_t, max_io_len(ci->sector, ti), ci->sector_count);

	__clone_and_map_data_bio(ci, ti, ci->sector, &len);

	ci->sector += len;
	ci->sector_count -= len;

	return 0;
}

static void __split_and_process_bio(struct mapped_device *md,
				    struct dm_table *map, struct bio *bio)
{
	struct clone_info ci;
	int error = 0;

	if (unlikely(!map)) {
		bio_io_error(bio);
		return;
	}

	ci.map = map;
	ci.md = md;
	ci.io = alloc_io(md);
	ci.io->error = 0;
	atomic_set(&ci.io->io_count, 1);
	ci.io->bio = bio;
	ci.io->md = md;
	spin_lock_init(&ci.io->endio_lock);
	ci.sector = bio->bi_iter.bi_sector;

	start_io_acct(ci.io);

	if (bio->bi_rw & REQ_FLUSH) {
		ci.bio = &ci.md->flush_bio;
		ci.sector_count = 0;
		error = __send_empty_flush(&ci);
		 
	} else {
		ci.bio = bio;
		ci.sector_count = bio_sectors(bio);
		while (ci.sector_count && !error)
			error = __split_and_process_non_flush(&ci);
	}

	dec_pending(ci.io, error);
}
 
static blk_qc_t dm_make_request(struct request_queue *q, struct bio *bio)
{
	int rw = bio_data_dir(bio);
	struct mapped_device *md = q->queuedata;
	int srcu_idx;
	struct dm_table *map;

#ifdef MY_ABC_HERE
	syno_md_fast_volume_wakeup(md);
#endif  

	map = dm_get_live_table(md, &srcu_idx);

	generic_start_io_acct(rw, bio_sectors(bio), &dm_disk(md)->part0);

	if (unlikely(test_bit(DMF_BLOCK_IO_FOR_SUSPEND, &md->flags))) {
		dm_put_live_table(md, srcu_idx);

		if (bio_rw(bio) != READA)
			queue_io(md, bio);
		else
			bio_io_error(bio);
		return BLK_QC_T_NONE;
	}

	__split_and_process_bio(md, map, bio);
	dm_put_live_table(md, srcu_idx);
	return BLK_QC_T_NONE;
}

int dm_request_based(struct mapped_device *md)
{
	return blk_queue_stackable(md->queue);
}

static void dm_dispatch_clone_request(struct request *clone, struct request *rq)
{
	int r;

	if (blk_queue_io_stat(clone->q))
		clone->cmd_flags |= REQ_IO_STAT;

	clone->start_time = jiffies;
	r = blk_insert_cloned_request(clone->q, clone);
	if (r)
		 
		dm_complete_request(rq, r);
}

static int dm_rq_bio_constructor(struct bio *bio, struct bio *bio_orig,
				 void *data)
{
	struct dm_rq_target_io *tio = data;
	struct dm_rq_clone_bio_info *info =
		container_of(bio, struct dm_rq_clone_bio_info, clone);

	info->orig = bio_orig;
	info->tio = tio;
	bio->bi_end_io = end_clone_bio;

	return 0;
}

static int setup_clone(struct request *clone, struct request *rq,
		       struct dm_rq_target_io *tio, gfp_t gfp_mask)
{
	int r;

	r = blk_rq_prep_clone(clone, rq, tio->md->bs, gfp_mask,
			      dm_rq_bio_constructor, tio);
	if (r)
		return r;

	clone->cmd = rq->cmd;
	clone->cmd_len = rq->cmd_len;
	clone->sense = rq->sense;
	clone->end_io = end_clone_request;
	clone->end_io_data = tio;

	tio->clone = clone;

	return 0;
}

static struct request *clone_rq(struct request *rq, struct mapped_device *md,
				struct dm_rq_target_io *tio, gfp_t gfp_mask)
{
	 
	bool alloc_clone = !tio->clone;
	struct request *clone;

	if (alloc_clone) {
		clone = alloc_clone_request(md, gfp_mask);
		if (!clone)
			return NULL;
	} else
		clone = tio->clone;

	blk_rq_init(NULL, clone);
	if (setup_clone(clone, rq, tio, gfp_mask)) {
		 
		if (alloc_clone)
			free_clone_request(md, clone);
		return NULL;
	}

	return clone;
}

static void map_tio_request(struct kthread_work *work);

static void init_tio(struct dm_rq_target_io *tio, struct request *rq,
		     struct mapped_device *md)
{
	tio->md = md;
	tio->ti = NULL;
	tio->clone = NULL;
	tio->orig = rq;
	tio->error = 0;
	memset(&tio->info, 0, sizeof(tio->info));
	if (md->kworker_task)
		init_kthread_work(&tio->work, map_tio_request);
}

static struct dm_rq_target_io *prep_tio(struct request *rq,
					struct mapped_device *md, gfp_t gfp_mask)
{
	struct dm_rq_target_io *tio;
	int srcu_idx;
	struct dm_table *table;

	tio = alloc_rq_tio(md, gfp_mask);
	if (!tio)
		return NULL;

	init_tio(tio, rq, md);

	table = dm_get_live_table(md, &srcu_idx);
	if (!dm_table_mq_request_based(table)) {
		if (!clone_rq(rq, md, tio, gfp_mask)) {
			dm_put_live_table(md, srcu_idx);
			free_rq_tio(tio);
			return NULL;
		}
	}
	dm_put_live_table(md, srcu_idx);

	return tio;
}

static int dm_prep_fn(struct request_queue *q, struct request *rq)
{
	struct mapped_device *md = q->queuedata;
	struct dm_rq_target_io *tio;

	if (unlikely(rq->special)) {
		DMWARN("Already has something in rq->special.");
		return BLKPREP_KILL;
	}

	tio = prep_tio(rq, md, GFP_ATOMIC);
	if (!tio)
		return BLKPREP_DEFER;

	rq->special = tio;
	rq->cmd_flags |= REQ_DONTPREP;

	return BLKPREP_OK;
}

static int map_request(struct dm_rq_target_io *tio, struct request *rq,
		       struct mapped_device *md)
{
	int r;
	struct dm_target *ti = tio->ti;
	struct request *clone = NULL;

	if (tio->clone) {
		clone = tio->clone;
		r = ti->type->map_rq(ti, clone, &tio->info);
	} else {
		r = ti->type->clone_and_map_rq(ti, rq, &tio->info, &clone);
		if (r < 0) {
			 
			dm_kill_unmapped_request(rq, r);
			return r;
		}
		if (r != DM_MAPIO_REMAPPED)
			return r;
		if (setup_clone(clone, rq, tio, GFP_ATOMIC)) {
			 
			ti->type->release_clone_rq(clone);
			return DM_MAPIO_REQUEUE;
		}
	}

	switch (r) {
	case DM_MAPIO_SUBMITTED:
		 
		break;
	case DM_MAPIO_REMAPPED:
		 
		trace_block_rq_remap(clone->q, clone, disk_devt(dm_disk(md)),
				     blk_rq_pos(rq));
		dm_dispatch_clone_request(clone, rq);
		break;
	case DM_MAPIO_REQUEUE:
		 
		dm_requeue_original_request(md, tio->orig);
		break;
	default:
		if (r > 0) {
			DMWARN("unimplemented target map return value: %d", r);
			BUG();
		}

		dm_kill_unmapped_request(rq, r);
		return r;
	}

	return 0;
}

static void map_tio_request(struct kthread_work *work)
{
	struct dm_rq_target_io *tio = container_of(work, struct dm_rq_target_io, work);
	struct request *rq = tio->orig;
	struct mapped_device *md = tio->md;

	if (map_request(tio, rq, md) == DM_MAPIO_REQUEUE)
		dm_requeue_original_request(md, rq);
}

static void dm_start_request(struct mapped_device *md, struct request *orig)
{
	if (!orig->q->mq_ops)
		blk_start_request(orig);
	else
		blk_mq_start_request(orig);
	atomic_inc(&md->pending[rq_data_dir(orig)]);

	if (md->seq_rq_merge_deadline_usecs) {
		md->last_rq_pos = rq_end_sector(orig);
		md->last_rq_rw = rq_data_dir(orig);
		md->last_rq_start_time = ktime_get();
	}

	if (unlikely(dm_stats_used(&md->stats))) {
		struct dm_rq_target_io *tio = tio_from_request(orig);
		tio->duration_jiffies = jiffies;
		tio->n_sectors = blk_rq_sectors(orig);
		dm_stats_account_io(&md->stats, orig->cmd_flags, blk_rq_pos(orig),
				    tio->n_sectors, false, 0, &tio->stats_aux);
	}

	dm_get(md);
}

#define MAX_SEQ_RQ_MERGE_DEADLINE_USECS 100000

ssize_t dm_attr_rq_based_seq_io_merge_deadline_show(struct mapped_device *md, char *buf)
{
	return sprintf(buf, "%u\n", md->seq_rq_merge_deadline_usecs);
}

ssize_t dm_attr_rq_based_seq_io_merge_deadline_store(struct mapped_device *md,
						     const char *buf, size_t count)
{
	unsigned deadline;

	if (!dm_request_based(md) || md->use_blk_mq)
		return count;

	if (kstrtouint(buf, 10, &deadline))
		return -EINVAL;

	if (deadline > MAX_SEQ_RQ_MERGE_DEADLINE_USECS)
		deadline = MAX_SEQ_RQ_MERGE_DEADLINE_USECS;

	md->seq_rq_merge_deadline_usecs = deadline;

	return count;
}

static bool dm_request_peeked_before_merge_deadline(struct mapped_device *md)
{
	ktime_t kt_deadline;

	if (!md->seq_rq_merge_deadline_usecs)
		return false;

	kt_deadline = ns_to_ktime((u64)md->seq_rq_merge_deadline_usecs * NSEC_PER_USEC);
	kt_deadline = ktime_add_safe(md->last_rq_start_time, kt_deadline);

	return !ktime_after(ktime_get(), kt_deadline);
}

static void dm_request_fn(struct request_queue *q)
{
	struct mapped_device *md = q->queuedata;
	int srcu_idx;
	struct dm_table *map = dm_get_live_table(md, &srcu_idx);
	struct dm_target *ti;
	struct request *rq;
	struct dm_rq_target_io *tio;
	sector_t pos;

#ifdef MY_ABC_HERE
	syno_md_fast_volume_wakeup(md);
#endif  

	while (!blk_queue_stopped(q)) {
		rq = blk_peek_request(q);
		if (!rq)
			goto out;

		pos = 0;
		if (!(rq->cmd_flags & REQ_FLUSH))
			pos = blk_rq_pos(rq);

		ti = dm_table_find_target(map, pos);
		if (!dm_target_is_valid(ti)) {
			 
			DMERR_LIMIT("request attempted access beyond the end of device");
			dm_start_request(md, rq);
			dm_kill_unmapped_request(rq, -EIO);
			continue;
		}

		if (dm_request_peeked_before_merge_deadline(md) &&
		    md_in_flight(md) && rq->bio && rq->bio->bi_vcnt == 1 &&
		    md->last_rq_pos == pos && md->last_rq_rw == rq_data_dir(rq))
			goto delay_and_out;

		if (ti->type->busy && ti->type->busy(ti))
			goto delay_and_out;

		dm_start_request(md, rq);

		tio = tio_from_request(rq);
		 
		tio->ti = ti;
		queue_kthread_work(&md->kworker, &tio->work);
		BUG_ON(!irqs_disabled());
	}

	goto out;

delay_and_out:
	blk_delay_queue(q, HZ / 100);
out:
	dm_put_live_table(md, srcu_idx);
}

static int dm_any_congested(void *congested_data, int bdi_bits)
{
	int r = bdi_bits;
	struct mapped_device *md = congested_data;
	struct dm_table *map;

	if (!test_bit(DMF_BLOCK_IO_FOR_SUSPEND, &md->flags)) {
		map = dm_get_live_table_fast(md);
		if (map) {
			 
			if (dm_request_based(md))
				r = md->queue->backing_dev_info.wb.state &
				    bdi_bits;
			else
				r = dm_table_any_congested(map, bdi_bits);
		}
		dm_put_live_table_fast(md);
	}

	return r;
}

static void free_minor(int minor)
{
	spin_lock(&_minor_lock);
	idr_remove(&_minor_idr, minor);
	spin_unlock(&_minor_lock);
}

static int specific_minor(int minor)
{
	int r;

	if (minor >= (1 << MINORBITS))
		return -EINVAL;

	idr_preload(GFP_KERNEL);
	spin_lock(&_minor_lock);

	r = idr_alloc(&_minor_idr, MINOR_ALLOCED, minor, minor + 1, GFP_NOWAIT);

	spin_unlock(&_minor_lock);
	idr_preload_end();
	if (r < 0)
		return r == -ENOSPC ? -EBUSY : r;
	return 0;
}

static int next_free_minor(int *minor)
{
	int r;

	idr_preload(GFP_KERNEL);
	spin_lock(&_minor_lock);

	r = idr_alloc(&_minor_idr, MINOR_ALLOCED, 0, 1 << MINORBITS, GFP_NOWAIT);

	spin_unlock(&_minor_lock);
	idr_preload_end();
	if (r < 0)
		return r;
	*minor = r;
	return 0;
}

static const struct block_device_operations dm_blk_dops;

static void dm_wq_work(struct work_struct *work);

static void dm_init_md_queue(struct mapped_device *md)
{
	 
	queue_flag_clear_unlocked(QUEUE_FLAG_STACKABLE, md->queue);

	md->queue->queuedata = md;
	md->queue->backing_dev_info.congested_data = md;
}

static void dm_init_old_md_queue(struct mapped_device *md)
{
	md->use_blk_mq = false;
	dm_init_md_queue(md);

	md->queue->backing_dev_info.congested_fn = dm_any_congested;
	blk_queue_bounce_limit(md->queue, BLK_BOUNCE_ANY);
}

static void cleanup_mapped_device(struct mapped_device *md)
{
	if (md->wq)
		destroy_workqueue(md->wq);
	if (md->kworker_task)
		kthread_stop(md->kworker_task);
	mempool_destroy(md->io_pool);
	mempool_destroy(md->rq_pool);
	if (md->bs)
		bioset_free(md->bs);

	if (md->disk) {
		spin_lock(&_minor_lock);
		md->disk->private_data = NULL;
		spin_unlock(&_minor_lock);
		del_gendisk(md->disk);
		put_disk(md->disk);
	}

	if (md->queue)
		blk_cleanup_queue(md->queue);

	cleanup_srcu_struct(&md->io_barrier);

	if (md->bdev) {
		bdput(md->bdev);
		md->bdev = NULL;
	}
}

static struct mapped_device *alloc_dev(int minor)
{
	int r;
	struct mapped_device *md = kzalloc(sizeof(*md), GFP_KERNEL);
	void *old_md;

	if (!md) {
		DMWARN("unable to allocate device, out of memory.");
		return NULL;
	}

	if (!try_module_get(THIS_MODULE))
		goto bad_module_get;

	if (minor == DM_ANY_MINOR)
		r = next_free_minor(&minor);
	else
		r = specific_minor(minor);
	if (r < 0)
		goto bad_minor;

	r = init_srcu_struct(&md->io_barrier);
	if (r < 0)
		goto bad_io_barrier;

	md->use_blk_mq = use_blk_mq;
	md->type = DM_TYPE_NONE;
	mutex_init(&md->suspend_lock);
	mutex_init(&md->type_lock);
	mutex_init(&md->table_devices_lock);
	spin_lock_init(&md->deferred_lock);
	atomic_set(&md->holders, 1);
	atomic_set(&md->open_count, 0);
	atomic_set(&md->event_nr, 0);
	atomic_set(&md->uevent_seq, 0);
	INIT_LIST_HEAD(&md->uevent_list);
	INIT_LIST_HEAD(&md->table_devices);
	spin_lock_init(&md->uevent_lock);

	md->queue = blk_alloc_queue(GFP_KERNEL);
	if (!md->queue)
		goto bad;

	dm_init_md_queue(md);

	md->disk = alloc_disk(1);
	if (!md->disk)
		goto bad;

	atomic_set(&md->pending[0], 0);
	atomic_set(&md->pending[1], 0);
	init_waitqueue_head(&md->wait);
	INIT_WORK(&md->work, dm_wq_work);
	init_waitqueue_head(&md->eventq);
	init_completion(&md->kobj_holder.completion);
	md->kworker_task = NULL;

	md->disk->major = _major;
	md->disk->first_minor = minor;
	md->disk->fops = &dm_blk_dops;
	md->disk->queue = md->queue;
	md->disk->private_data = md;
	sprintf(md->disk->disk_name, "dm-%d", minor);
	add_disk(md->disk);
	format_dev_t(md->name, MKDEV(_major, minor));

	md->wq = alloc_workqueue("kdmflush", WQ_MEM_RECLAIM, 0);
	if (!md->wq)
		goto bad;

	md->bdev = bdget_disk(md->disk, 0);
	if (!md->bdev)
		goto bad;

	bio_init(&md->flush_bio);
	md->flush_bio.bi_bdev = md->bdev;
	md->flush_bio.bi_rw = WRITE_FLUSH;

	dm_stats_init(&md->stats);

	spin_lock(&_minor_lock);
	old_md = idr_replace(&_minor_idr, md, minor);
	spin_unlock(&_minor_lock);

	BUG_ON(old_md != MINOR_ALLOCED);
#ifdef MY_ABC_HERE
	spin_lock_init(&md->ActLock);
	md->blActive = 0;
	md->ulLastReq = jiffies;
#endif  
	return md;

bad:
	cleanup_mapped_device(md);
bad_io_barrier:
	free_minor(minor);
bad_minor:
	module_put(THIS_MODULE);
bad_module_get:
	kfree(md);
	return NULL;
}

static void unlock_fs(struct mapped_device *md);

static void free_dev(struct mapped_device *md)
{
	int minor = MINOR(disk_devt(md->disk));

	unlock_fs(md);

	cleanup_mapped_device(md);
	if (md->use_blk_mq)
		blk_mq_free_tag_set(&md->tag_set);

	free_table_devices(&md->table_devices);
	dm_stats_cleanup(&md->stats);
	free_minor(minor);

	module_put(THIS_MODULE);
	kfree(md);
}

static void __bind_mempools(struct mapped_device *md, struct dm_table *t)
{
	struct dm_md_mempools *p = dm_table_get_md_mempools(t);

	if (md->bs) {
		 
		if (dm_table_get_type(t) == DM_TYPE_BIO_BASED) {
			 
			bioset_free(md->bs);
			md->bs = p->bs;
			p->bs = NULL;
		}
		 
		goto out;
	}

	BUG_ON(!p || md->io_pool || md->rq_pool || md->bs);

	md->io_pool = p->io_pool;
	p->io_pool = NULL;
	md->rq_pool = p->rq_pool;
	p->rq_pool = NULL;
	md->bs = p->bs;
	p->bs = NULL;

out:
	 
	dm_table_free_md_mempools(t);
}

static void event_callback(void *context)
{
	unsigned long flags;
	LIST_HEAD(uevents);
	struct mapped_device *md = (struct mapped_device *) context;

	spin_lock_irqsave(&md->uevent_lock, flags);
	list_splice_init(&md->uevent_list, &uevents);
	spin_unlock_irqrestore(&md->uevent_lock, flags);

	dm_send_uevents(&uevents, &disk_to_dev(md->disk)->kobj);

	atomic_inc(&md->event_nr);
	wake_up(&md->eventq);
}

static void __set_size(struct mapped_device *md, sector_t size)
{
	set_capacity(md->disk, size);

	i_size_write(md->bdev->bd_inode, (loff_t)size << SECTOR_SHIFT);
}

static struct dm_table *__bind(struct mapped_device *md, struct dm_table *t,
			       struct queue_limits *limits)
{
	struct dm_table *old_map;
	struct request_queue *q = md->queue;
	sector_t size;

	size = dm_table_get_size(t);

	if (size != dm_get_size(md))
		memset(&md->geometry, 0, sizeof(md->geometry));

	__set_size(md, size);

	dm_table_event_callback(t, event_callback, md);

	if (dm_table_request_based(t))
		stop_queue(q);

	__bind_mempools(md, t);

	old_map = rcu_dereference_protected(md->map, lockdep_is_held(&md->suspend_lock));
	rcu_assign_pointer(md->map, t);
	md->immutable_target_type = dm_table_get_immutable_target_type(t);

	dm_table_set_restrictions(t, q, limits);
	if (old_map)
		dm_sync_table(md);

	return old_map;
}

static struct dm_table *__unbind(struct mapped_device *md)
{
	struct dm_table *map = rcu_dereference_protected(md->map, 1);

	if (!map)
		return NULL;

	dm_table_event_callback(map, NULL, NULL);
	RCU_INIT_POINTER(md->map, NULL);
	dm_sync_table(md);

	return map;
}

int dm_create(int minor, struct mapped_device **result)
{
	struct mapped_device *md;

	md = alloc_dev(minor);
	if (!md)
		return -ENXIO;

	dm_sysfs_init(md);

	*result = md;
	return 0;
}

void dm_lock_md_type(struct mapped_device *md)
{
	mutex_lock(&md->type_lock);
}

void dm_unlock_md_type(struct mapped_device *md)
{
	mutex_unlock(&md->type_lock);
}

void dm_set_md_type(struct mapped_device *md, unsigned type)
{
	BUG_ON(!mutex_is_locked(&md->type_lock));
	md->type = type;
}

unsigned dm_get_md_type(struct mapped_device *md)
{
	BUG_ON(!mutex_is_locked(&md->type_lock));
	return md->type;
}

struct target_type *dm_get_immutable_target_type(struct mapped_device *md)
{
	return md->immutable_target_type;
}

struct queue_limits *dm_get_queue_limits(struct mapped_device *md)
{
	BUG_ON(!atomic_read(&md->holders));
	return &md->queue->limits;
}
EXPORT_SYMBOL_GPL(dm_get_queue_limits);

static void init_rq_based_worker_thread(struct mapped_device *md)
{
	 
	init_kthread_worker(&md->kworker);
	md->kworker_task = kthread_run(kthread_worker_fn, &md->kworker,
				       "kdmwork-%s", dm_device_name(md));
}

static int dm_init_request_based_queue(struct mapped_device *md)
{
	struct request_queue *q = NULL;

	q = blk_init_allocated_queue(md->queue, dm_request_fn, NULL);
	if (!q)
		return -EINVAL;

	md->seq_rq_merge_deadline_usecs = 0;

	md->queue = q;
	dm_init_old_md_queue(md);
	blk_queue_softirq_done(md->queue, dm_softirq_done);
	blk_queue_prep_rq(md->queue, dm_prep_fn);

	init_rq_based_worker_thread(md);

	elv_register_queue(md->queue);

	return 0;
}

static int dm_mq_init_request(void *data, struct request *rq,
			      unsigned int hctx_idx, unsigned int request_idx,
			      unsigned int numa_node)
{
	struct mapped_device *md = data;
	struct dm_rq_target_io *tio = blk_mq_rq_to_pdu(rq);

	tio->md = md;

	return 0;
}

static int dm_mq_queue_rq(struct blk_mq_hw_ctx *hctx,
			  const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;
	struct dm_rq_target_io *tio = blk_mq_rq_to_pdu(rq);
	struct mapped_device *md = tio->md;
	int srcu_idx;
	struct dm_table *map = dm_get_live_table(md, &srcu_idx);
	struct dm_target *ti;
	sector_t pos;

#ifdef MY_ABC_HERE
	syno_md_fast_volume_wakeup(md);
#endif  

	pos = 0;
	if (!(rq->cmd_flags & REQ_FLUSH))
		pos = blk_rq_pos(rq);

	ti = dm_table_find_target(map, pos);
	if (!dm_target_is_valid(ti)) {
		dm_put_live_table(md, srcu_idx);
		DMERR_LIMIT("request attempted access beyond the end of device");
		 
		dm_start_request(md, rq);
		return BLK_MQ_RQ_QUEUE_ERROR;
	}
	dm_put_live_table(md, srcu_idx);

	if (ti->type->busy && ti->type->busy(ti))
		return BLK_MQ_RQ_QUEUE_BUSY;

	dm_start_request(md, rq);

	init_tio(tio, rq, md);

	tio->ti = ti;

	if (dm_table_get_type(map) == DM_TYPE_REQUEST_BASED) {
		 
		tio->clone = (void *)blk_mq_rq_to_pdu(rq) + sizeof(struct dm_rq_target_io);
		(void) clone_rq(rq, md, tio, GFP_ATOMIC);
		queue_kthread_work(&md->kworker, &tio->work);
	} else {
		 
		if (map_request(tio, rq, md) == DM_MAPIO_REQUEUE) {
			 
			rq_end_stats(md, rq);
			rq_completed(md, rq_data_dir(rq), false);
			return BLK_MQ_RQ_QUEUE_BUSY;
		}
	}

	return BLK_MQ_RQ_QUEUE_OK;
}

static struct blk_mq_ops dm_mq_ops = {
	.queue_rq = dm_mq_queue_rq,
	.map_queue = blk_mq_map_queue,
	.complete = dm_softirq_done,
	.init_request = dm_mq_init_request,
};

static int dm_init_request_based_blk_mq_queue(struct mapped_device *md)
{
	unsigned md_type = dm_get_md_type(md);
	struct request_queue *q;
	int err;

	memset(&md->tag_set, 0, sizeof(md->tag_set));
	md->tag_set.ops = &dm_mq_ops;
	md->tag_set.queue_depth = BLKDEV_MAX_RQ;
	md->tag_set.numa_node = NUMA_NO_NODE;
	md->tag_set.flags = BLK_MQ_F_SHOULD_MERGE | BLK_MQ_F_SG_MERGE;
	md->tag_set.nr_hw_queues = 1;
	if (md_type == DM_TYPE_REQUEST_BASED) {
		 
		md->tag_set.cmd_size = sizeof(struct dm_rq_target_io) + sizeof(struct request);
	} else
		md->tag_set.cmd_size = sizeof(struct dm_rq_target_io);
	md->tag_set.driver_data = md;

	err = blk_mq_alloc_tag_set(&md->tag_set);
	if (err)
		return err;

	q = blk_mq_init_allocated_queue(&md->tag_set, md->queue);
	if (IS_ERR(q)) {
		err = PTR_ERR(q);
		goto out_tag_set;
	}
	md->queue = q;
	dm_init_md_queue(md);

	blk_mq_register_disk(md->disk);

	if (md_type == DM_TYPE_REQUEST_BASED)
		init_rq_based_worker_thread(md);

	return 0;

out_tag_set:
	blk_mq_free_tag_set(&md->tag_set);
	return err;
}

static unsigned filter_md_type(unsigned type, struct mapped_device *md)
{
	if (type == DM_TYPE_BIO_BASED)
		return type;

	return !md->use_blk_mq ? DM_TYPE_REQUEST_BASED : DM_TYPE_MQ_REQUEST_BASED;
}

int dm_setup_md_queue(struct mapped_device *md)
{
	int r;
	unsigned md_type = filter_md_type(dm_get_md_type(md), md);

	switch (md_type) {
	case DM_TYPE_REQUEST_BASED:
		r = dm_init_request_based_queue(md);
		if (r) {
			DMWARN("Cannot initialize queue for request-based mapped device");
			return r;
		}
		break;
	case DM_TYPE_MQ_REQUEST_BASED:
		r = dm_init_request_based_blk_mq_queue(md);
		if (r) {
			DMWARN("Cannot initialize queue for request-based blk-mq mapped device");
			return r;
		}
		break;
	case DM_TYPE_BIO_BASED:
		dm_init_old_md_queue(md);
		blk_queue_make_request(md->queue, dm_make_request);
		 
		bioset_free(md->queue->bio_split);
		md->queue->bio_split = NULL;
		break;
	}

	return 0;
}

struct mapped_device *dm_get_md(dev_t dev)
{
	struct mapped_device *md;
	unsigned minor = MINOR(dev);

	if (MAJOR(dev) != _major || minor >= (1 << MINORBITS))
		return NULL;

	spin_lock(&_minor_lock);

	md = idr_find(&_minor_idr, minor);
	if (md) {
		if ((md == MINOR_ALLOCED ||
		     (MINOR(disk_devt(dm_disk(md))) != minor) ||
		     dm_deleting_md(md) ||
		     test_bit(DMF_FREEING, &md->flags))) {
			md = NULL;
			goto out;
		}
		dm_get(md);
	}

out:
	spin_unlock(&_minor_lock);

	return md;
}
EXPORT_SYMBOL_GPL(dm_get_md);

void *dm_get_mdptr(struct mapped_device *md)
{
	return md->interface_ptr;
}

void dm_set_mdptr(struct mapped_device *md, void *ptr)
{
	md->interface_ptr = ptr;
}

void dm_get(struct mapped_device *md)
{
	atomic_inc(&md->holders);
	BUG_ON(test_bit(DMF_FREEING, &md->flags));
}

int dm_hold(struct mapped_device *md)
{
	spin_lock(&_minor_lock);
	if (test_bit(DMF_FREEING, &md->flags)) {
		spin_unlock(&_minor_lock);
		return -EBUSY;
	}
	dm_get(md);
	spin_unlock(&_minor_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(dm_hold);

const char *dm_device_name(struct mapped_device *md)
{
	return md->name;
}
EXPORT_SYMBOL_GPL(dm_device_name);

static void __dm_destroy(struct mapped_device *md, bool wait)
{
	struct request_queue *q = dm_get_md_queue(md);
	struct dm_table *map;
	int srcu_idx;

	might_sleep();

	spin_lock(&_minor_lock);
	idr_replace(&_minor_idr, MINOR_ALLOCED, MINOR(disk_devt(dm_disk(md))));
	set_bit(DMF_FREEING, &md->flags);
	spin_unlock(&_minor_lock);

	spin_lock_irq(q->queue_lock);
	queue_flag_set(QUEUE_FLAG_DYING, q);
	spin_unlock_irq(q->queue_lock);

	if (dm_request_based(md) && md->kworker_task)
		flush_kthread_worker(&md->kworker);

	mutex_lock(&md->suspend_lock);
	map = dm_get_live_table(md, &srcu_idx);
	if (!dm_suspended_md(md)) {
		dm_table_presuspend_targets(map);
		dm_table_postsuspend_targets(map);
	}
	 
	dm_put_live_table(md, srcu_idx);
	mutex_unlock(&md->suspend_lock);

	if (wait)
		while (atomic_read(&md->holders))
			msleep(1);
	else if (atomic_read(&md->holders))
		DMWARN("%s: Forcibly removing mapped_device still in use! (%d users)",
		       dm_device_name(md), atomic_read(&md->holders));

	dm_sysfs_exit(md);
	dm_table_destroy(__unbind(md));
	free_dev(md);
}

void dm_destroy(struct mapped_device *md)
{
	__dm_destroy(md, true);
}

void dm_destroy_immediate(struct mapped_device *md)
{
	__dm_destroy(md, false);
}

void dm_put(struct mapped_device *md)
{
	atomic_dec(&md->holders);
}
EXPORT_SYMBOL_GPL(dm_put);

static int dm_wait_for_completion(struct mapped_device *md, int interruptible)
{
	int r = 0;
	DECLARE_WAITQUEUE(wait, current);

	add_wait_queue(&md->wait, &wait);

	while (1) {
		set_current_state(interruptible);

		if (!md_in_flight(md))
			break;

		if (interruptible == TASK_INTERRUPTIBLE &&
		    signal_pending(current)) {
			r = -EINTR;
			break;
		}

		io_schedule();
	}
	set_current_state(TASK_RUNNING);

	remove_wait_queue(&md->wait, &wait);

	return r;
}

static void dm_wq_work(struct work_struct *work)
{
	struct mapped_device *md = container_of(work, struct mapped_device,
						work);
	struct bio *c;
	int srcu_idx;
	struct dm_table *map;

	map = dm_get_live_table(md, &srcu_idx);

	while (!test_bit(DMF_BLOCK_IO_FOR_SUSPEND, &md->flags)) {
		spin_lock_irq(&md->deferred_lock);
		c = bio_list_pop(&md->deferred);
		spin_unlock_irq(&md->deferred_lock);

		if (!c)
			break;

		if (dm_request_based(md))
			generic_make_request(c);
		else
			__split_and_process_bio(md, map, c);
	}

	dm_put_live_table(md, srcu_idx);
}

static void dm_queue_flush(struct mapped_device *md)
{
	clear_bit(DMF_BLOCK_IO_FOR_SUSPEND, &md->flags);
	smp_mb__after_atomic();
	queue_work(md->wq, &md->work);
}

struct dm_table *dm_swap_table(struct mapped_device *md, struct dm_table *table)
{
	struct dm_table *live_map = NULL, *map = ERR_PTR(-EINVAL);
	struct queue_limits limits;
	int r;

	mutex_lock(&md->suspend_lock);

	if (!dm_suspended_md(md))
		goto out;

	if (dm_table_has_no_data_devices(table)) {
		live_map = dm_get_live_table_fast(md);
		if (live_map)
			limits = md->queue->limits;
		dm_put_live_table_fast(md);
	}

	if (!live_map) {
		r = dm_calculate_queue_limits(table, &limits);
		if (r) {
			map = ERR_PTR(r);
			goto out;
		}
	}

	map = __bind(md, table, &limits);

out:
	mutex_unlock(&md->suspend_lock);
	return map;
}

static int lock_fs(struct mapped_device *md)
{
	int r;

	WARN_ON(md->frozen_sb);

	md->frozen_sb = freeze_bdev(md->bdev);
	if (IS_ERR(md->frozen_sb)) {
		r = PTR_ERR(md->frozen_sb);
		md->frozen_sb = NULL;
		return r;
	}

	set_bit(DMF_FROZEN, &md->flags);

	return 0;
}

static void unlock_fs(struct mapped_device *md)
{
	if (!test_bit(DMF_FROZEN, &md->flags))
		return;

	thaw_bdev(md->bdev, md->frozen_sb);
	md->frozen_sb = NULL;
	clear_bit(DMF_FROZEN, &md->flags);
}

static int __dm_suspend(struct mapped_device *md, struct dm_table *map,
			unsigned suspend_flags, int interruptible,
			int dmf_suspended_flag)
{
	bool do_lockfs = suspend_flags & DM_SUSPEND_LOCKFS_FLAG;
	bool noflush = suspend_flags & DM_SUSPEND_NOFLUSH_FLAG;
	int r;

	if (noflush)
		set_bit(DMF_NOFLUSH_SUSPENDING, &md->flags);

	dm_table_presuspend_targets(map);

	if (!noflush && do_lockfs) {
		r = lock_fs(md);
		if (r) {
			dm_table_presuspend_undo_targets(map);
			return r;
		}
	}

	set_bit(DMF_BLOCK_IO_FOR_SUSPEND, &md->flags);
	if (map)
		synchronize_srcu(&md->io_barrier);

	if (dm_request_based(md)) {
		stop_queue(md->queue);
		if (md->kworker_task)
			flush_kthread_worker(&md->kworker);
	}

	flush_workqueue(md->wq);

	r = dm_wait_for_completion(md, interruptible);
	if (!r)
		set_bit(dmf_suspended_flag, &md->flags);

	if (noflush)
		clear_bit(DMF_NOFLUSH_SUSPENDING, &md->flags);
	if (map)
		synchronize_srcu(&md->io_barrier);

	if (r < 0) {
		dm_queue_flush(md);

		if (dm_request_based(md))
			start_queue(md->queue);

		unlock_fs(md);
		dm_table_presuspend_undo_targets(map);
		 
	}

	return r;
}

int dm_suspend(struct mapped_device *md, unsigned suspend_flags)
{
	struct dm_table *map = NULL;
	int r = 0;

retry:
	mutex_lock_nested(&md->suspend_lock, SINGLE_DEPTH_NESTING);

	if (dm_suspended_md(md)) {
		r = -EINVAL;
		goto out_unlock;
	}

	if (dm_suspended_internally_md(md)) {
		 
		mutex_unlock(&md->suspend_lock);
		r = wait_on_bit(&md->flags, DMF_SUSPENDED_INTERNALLY, TASK_INTERRUPTIBLE);
		if (r)
			return r;
		goto retry;
	}

	map = rcu_dereference_protected(md->map, lockdep_is_held(&md->suspend_lock));

	r = __dm_suspend(md, map, suspend_flags, TASK_INTERRUPTIBLE, DMF_SUSPENDED);
	if (r)
		goto out_unlock;

	dm_table_postsuspend_targets(map);

out_unlock:
	mutex_unlock(&md->suspend_lock);
	return r;
}

static int __dm_resume(struct mapped_device *md, struct dm_table *map)
{
	if (map) {
		int r = dm_table_resume_targets(map);
		if (r)
			return r;
	}

	dm_queue_flush(md);

	if (dm_request_based(md))
		start_queue(md->queue);

	unlock_fs(md);

	return 0;
}

int dm_resume(struct mapped_device *md)
{
	int r;
	struct dm_table *map = NULL;

retry:
	r = -EINVAL;
	mutex_lock_nested(&md->suspend_lock, SINGLE_DEPTH_NESTING);

	if (!dm_suspended_md(md))
		goto out;

	if (dm_suspended_internally_md(md)) {
		 
		mutex_unlock(&md->suspend_lock);
		r = wait_on_bit(&md->flags, DMF_SUSPENDED_INTERNALLY, TASK_INTERRUPTIBLE);
		if (r)
			return r;
		goto retry;
	}

	map = rcu_dereference_protected(md->map, lockdep_is_held(&md->suspend_lock));
	if (!map || !dm_table_get_size(map))
		goto out;

	r = __dm_resume(md, map);
	if (r)
		goto out;

	clear_bit(DMF_SUSPENDED, &md->flags);
out:
	mutex_unlock(&md->suspend_lock);

	return r;
}

static void __dm_internal_suspend(struct mapped_device *md, unsigned suspend_flags)
{
	struct dm_table *map = NULL;

	if (md->internal_suspend_count++)
		return;  

	if (dm_suspended_md(md)) {
		set_bit(DMF_SUSPENDED_INTERNALLY, &md->flags);
		return;  
	}

	map = rcu_dereference_protected(md->map, lockdep_is_held(&md->suspend_lock));

	(void) __dm_suspend(md, map, suspend_flags, TASK_UNINTERRUPTIBLE,
			    DMF_SUSPENDED_INTERNALLY);

	dm_table_postsuspend_targets(map);
}

static void __dm_internal_resume(struct mapped_device *md)
{
	BUG_ON(!md->internal_suspend_count);

	if (--md->internal_suspend_count)
		return;  

	if (dm_suspended_md(md))
		goto done;  

	(void) __dm_resume(md, NULL);

done:
	clear_bit(DMF_SUSPENDED_INTERNALLY, &md->flags);
	smp_mb__after_atomic();
	wake_up_bit(&md->flags, DMF_SUSPENDED_INTERNALLY);
}

void dm_internal_suspend_noflush(struct mapped_device *md)
{
	mutex_lock(&md->suspend_lock);
	__dm_internal_suspend(md, DM_SUSPEND_NOFLUSH_FLAG);
	mutex_unlock(&md->suspend_lock);
}
EXPORT_SYMBOL_GPL(dm_internal_suspend_noflush);

void dm_internal_resume(struct mapped_device *md)
{
	mutex_lock(&md->suspend_lock);
	__dm_internal_resume(md);
	mutex_unlock(&md->suspend_lock);
}
EXPORT_SYMBOL_GPL(dm_internal_resume);

void dm_internal_suspend_fast(struct mapped_device *md)
{
	mutex_lock(&md->suspend_lock);
	if (dm_suspended_md(md) || dm_suspended_internally_md(md))
		return;

	set_bit(DMF_BLOCK_IO_FOR_SUSPEND, &md->flags);
	synchronize_srcu(&md->io_barrier);
	flush_workqueue(md->wq);
	dm_wait_for_completion(md, TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL_GPL(dm_internal_suspend_fast);

void dm_internal_resume_fast(struct mapped_device *md)
{
	if (dm_suspended_md(md) || dm_suspended_internally_md(md))
		goto done;

	dm_queue_flush(md);

done:
	mutex_unlock(&md->suspend_lock);
}
EXPORT_SYMBOL_GPL(dm_internal_resume_fast);

int dm_kobject_uevent(struct mapped_device *md, enum kobject_action action,
		       unsigned cookie)
{
	char udev_cookie[DM_COOKIE_LENGTH];
	char *envp[] = { udev_cookie, NULL };

	if (!cookie)
		return kobject_uevent(&disk_to_dev(md->disk)->kobj, action);
	else {
		snprintf(udev_cookie, DM_COOKIE_LENGTH, "%s=%u",
			 DM_COOKIE_ENV_VAR_NAME, cookie);
		return kobject_uevent_env(&disk_to_dev(md->disk)->kobj,
					  action, envp);
	}
}

uint32_t dm_next_uevent_seq(struct mapped_device *md)
{
	return atomic_add_return(1, &md->uevent_seq);
}

uint32_t dm_get_event_nr(struct mapped_device *md)
{
	return atomic_read(&md->event_nr);
}

int dm_wait_event(struct mapped_device *md, int event_nr)
{
	return wait_event_interruptible(md->eventq,
			(event_nr != atomic_read(&md->event_nr)));
}

void dm_uevent_add(struct mapped_device *md, struct list_head *elist)
{
	unsigned long flags;

	spin_lock_irqsave(&md->uevent_lock, flags);
	list_add(elist, &md->uevent_list);
	spin_unlock_irqrestore(&md->uevent_lock, flags);
}

struct gendisk *dm_disk(struct mapped_device *md)
{
	return md->disk;
}
EXPORT_SYMBOL_GPL(dm_disk);

struct kobject *dm_kobject(struct mapped_device *md)
{
	return &md->kobj_holder.kobj;
}

struct mapped_device *dm_get_from_kobject(struct kobject *kobj)
{
	struct mapped_device *md;

	md = container_of(kobj, struct mapped_device, kobj_holder.kobj);

	if (test_bit(DMF_FREEING, &md->flags) ||
	    dm_deleting_md(md))
		return NULL;

	dm_get(md);
	return md;
}

int dm_suspended_md(struct mapped_device *md)
{
	return test_bit(DMF_SUSPENDED, &md->flags);
}

int dm_suspended_internally_md(struct mapped_device *md)
{
	return test_bit(DMF_SUSPENDED_INTERNALLY, &md->flags);
}

int dm_test_deferred_remove_flag(struct mapped_device *md)
{
	return test_bit(DMF_DEFERRED_REMOVE, &md->flags);
}

int dm_suspended(struct dm_target *ti)
{
	return dm_suspended_md(dm_table_get_md(ti->table));
}
EXPORT_SYMBOL_GPL(dm_suspended);

#ifdef MY_ABC_HERE
int dm_active_get(struct mapped_device *md)
{
	unsigned char blActive = 0;

	spin_lock(&md->ActLock);
	blActive = md->blActive;
	spin_unlock(&md->ActLock);

	return blActive;
}

int dm_active_set(struct mapped_device *md, int value)
{
	struct dm_table *map = NULL;
	struct dm_dev_internal *dd = NULL;
	char b[BDEVNAME_SIZE] = {'\0'};
	int iNeedWake = 0;
	int srcu_idx;

	spin_lock(&md->ActLock);
	if (!(md->blActive) && value) {
		iNeedWake = 1;
	}
	md->blActive = value;
	spin_unlock(&md->ActLock);

	map = dm_get_live_table(md, &srcu_idx);
	if (map) {
		list_for_each_entry (dd, dm_table_get_devices(map), list) {
			if (dd && dd->dm_dev->bdev && NULL != strstr(bdevname(dd->dm_dev->bdev, b), "md")) {
				if (dd->dm_dev->bdev->bd_disk && dd->dm_dev->bdev->bd_disk->private_data) {
					struct mddev *mddev = dd->dm_dev->bdev->bd_disk->private_data;
					if (iNeedWake) {
						SynoMDWakeUpDevices(mddev);
					}
					spin_lock(&mddev->ActLock);
					mddev->blActive = value;
					spin_unlock(&mddev->ActLock);
				}
			}
		}
	}
	dm_put_live_table(md, srcu_idx);

	return 0;
}
#endif  

int dm_noflush_suspending(struct dm_target *ti)
{
	return __noflush_suspending(dm_table_get_md(ti->table));
}
EXPORT_SYMBOL_GPL(dm_noflush_suspending);

struct dm_md_mempools *dm_alloc_md_mempools(struct mapped_device *md, unsigned type,
					    unsigned integrity, unsigned per_bio_data_size)
{
	struct dm_md_mempools *pools = kzalloc(sizeof(*pools), GFP_KERNEL);
	struct kmem_cache *cachep = NULL;
	unsigned int pool_size = 0;
	unsigned int front_pad;

	if (!pools)
		return NULL;

	type = filter_md_type(type, md);

	switch (type) {
	case DM_TYPE_BIO_BASED:
		cachep = _io_cache;
		pool_size = dm_get_reserved_bio_based_ios();
		front_pad = roundup(per_bio_data_size, __alignof__(struct dm_target_io)) + offsetof(struct dm_target_io, clone);
		break;
	case DM_TYPE_REQUEST_BASED:
		cachep = _rq_tio_cache;
		pool_size = dm_get_reserved_rq_based_ios();
		pools->rq_pool = mempool_create_slab_pool(pool_size, _rq_cache);
		if (!pools->rq_pool)
			goto out;
		 
	case DM_TYPE_MQ_REQUEST_BASED:
		if (!pool_size)
			pool_size = dm_get_reserved_rq_based_ios();
		front_pad = offsetof(struct dm_rq_clone_bio_info, clone);
		 
		WARN_ON(per_bio_data_size != 0);
		break;
	default:
		BUG();
	}

	if (cachep) {
		pools->io_pool = mempool_create_slab_pool(pool_size, cachep);
		if (!pools->io_pool)
			goto out;
	}

	pools->bs = bioset_create_nobvec(pool_size, front_pad);
	if (!pools->bs)
		goto out;

	if (integrity && bioset_integrity_create(pools->bs, pool_size))
		goto out;

	return pools;

out:
	dm_free_md_mempools(pools);

	return NULL;
}

void dm_free_md_mempools(struct dm_md_mempools *pools)
{
	if (!pools)
		return;

	mempool_destroy(pools->io_pool);
	mempool_destroy(pools->rq_pool);

	if (pools->bs)
		bioset_free(pools->bs);

	kfree(pools);
}

static int dm_pr_register(struct block_device *bdev, u64 old_key, u64 new_key,
		u32 flags)
{
	struct mapped_device *md = bdev->bd_disk->private_data;
	const struct pr_ops *ops;
	struct dm_target *tgt;
	fmode_t mode;
	int srcu_idx, r;

	r = dm_get_live_table_for_ioctl(md, &tgt, &bdev, &mode, &srcu_idx);
	if (r < 0)
		return r;

	ops = bdev->bd_disk->fops->pr_ops;
	if (ops && ops->pr_register)
		r = ops->pr_register(bdev, old_key, new_key, flags);
	else
		r = -EOPNOTSUPP;

	dm_put_live_table(md, srcu_idx);
	return r;
}

static int dm_pr_reserve(struct block_device *bdev, u64 key, enum pr_type type,
		u32 flags)
{
	struct mapped_device *md = bdev->bd_disk->private_data;
	const struct pr_ops *ops;
	struct dm_target *tgt;
	fmode_t mode;
	int srcu_idx, r;

	r = dm_get_live_table_for_ioctl(md, &tgt, &bdev, &mode, &srcu_idx);
	if (r < 0)
		return r;

	ops = bdev->bd_disk->fops->pr_ops;
	if (ops && ops->pr_reserve)
		r = ops->pr_reserve(bdev, key, type, flags);
	else
		r = -EOPNOTSUPP;

	dm_put_live_table(md, srcu_idx);
	return r;
}

static int dm_pr_release(struct block_device *bdev, u64 key, enum pr_type type)
{
	struct mapped_device *md = bdev->bd_disk->private_data;
	const struct pr_ops *ops;
	struct dm_target *tgt;
	fmode_t mode;
	int srcu_idx, r;

	r = dm_get_live_table_for_ioctl(md, &tgt, &bdev, &mode, &srcu_idx);
	if (r < 0)
		return r;

	ops = bdev->bd_disk->fops->pr_ops;
	if (ops && ops->pr_release)
		r = ops->pr_release(bdev, key, type);
	else
		r = -EOPNOTSUPP;

	dm_put_live_table(md, srcu_idx);
	return r;
}

static int dm_pr_preempt(struct block_device *bdev, u64 old_key, u64 new_key,
		enum pr_type type, bool abort)
{
	struct mapped_device *md = bdev->bd_disk->private_data;
	const struct pr_ops *ops;
	struct dm_target *tgt;
	fmode_t mode;
	int srcu_idx, r;

	r = dm_get_live_table_for_ioctl(md, &tgt, &bdev, &mode, &srcu_idx);
	if (r < 0)
		return r;

	ops = bdev->bd_disk->fops->pr_ops;
	if (ops && ops->pr_preempt)
		r = ops->pr_preempt(bdev, old_key, new_key, type, abort);
	else
		r = -EOPNOTSUPP;

	dm_put_live_table(md, srcu_idx);
	return r;
}

static int dm_pr_clear(struct block_device *bdev, u64 key)
{
	struct mapped_device *md = bdev->bd_disk->private_data;
	const struct pr_ops *ops;
	struct dm_target *tgt;
	fmode_t mode;
	int srcu_idx, r;

	r = dm_get_live_table_for_ioctl(md, &tgt, &bdev, &mode, &srcu_idx);
	if (r < 0)
		return r;

	ops = bdev->bd_disk->fops->pr_ops;
	if (ops && ops->pr_clear)
		r = ops->pr_clear(bdev, key);
	else
		r = -EOPNOTSUPP;

	dm_put_live_table(md, srcu_idx);
	return r;
}

static const struct pr_ops dm_pr_ops = {
	.pr_register	= dm_pr_register,
	.pr_reserve	= dm_pr_reserve,
	.pr_release	= dm_pr_release,
	.pr_preempt	= dm_pr_preempt,
	.pr_clear	= dm_pr_clear,
};

static const struct block_device_operations dm_blk_dops = {
	.open = dm_blk_open,
	.release = dm_blk_close,
	.ioctl = dm_blk_ioctl,
	.getgeo = dm_blk_getgeo,
	.pr_ops = &dm_pr_ops,
	.owner = THIS_MODULE
};

module_init(dm_init);
module_exit(dm_exit);

module_param(major, uint, 0);
MODULE_PARM_DESC(major, "The major number of the device mapper");

module_param(reserved_bio_based_ios, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(reserved_bio_based_ios, "Reserved IOs in bio-based mempools");

module_param(reserved_rq_based_ios, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(reserved_rq_based_ios, "Reserved IOs in request-based mempools");

module_param(use_blk_mq, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(use_blk_mq, "Use block multiqueue for request-based DM devices");

MODULE_DESCRIPTION(DM_NAME " driver");
MODULE_AUTHOR("Joe Thornber <dm-devel@redhat.com>");
MODULE_LICENSE("GPL");
