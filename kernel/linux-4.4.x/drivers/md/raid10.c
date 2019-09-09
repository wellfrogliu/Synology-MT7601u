#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/blkdev.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/ratelimit.h>
#include <linux/kthread.h>
#include "md.h"
#include "raid10.h"
#include "raid0.h"
#include "bitmap.h"

#define	NR_RAID10_BIOS 256

#define IO_BLOCKED ((struct bio *)1)
 
#define IO_MADE_GOOD ((struct bio *)2)

#define BIO_SPECIAL(bio) ((unsigned long)bio <= 2)

static int max_queued_requests = 1024;

static void allow_barrier(struct r10conf *conf);
static void lower_barrier(struct r10conf *conf);
static int _enough(struct r10conf *conf, int previous, int ignore);
#ifdef MY_ABC_HERE
static unsigned char
IsDiskErrorSet(struct mddev *mddev)
{
	int i;
	unsigned char res = 0;
	struct r10conf *conf = mddev->private;
	struct md_rdev *rdev_tmp = NULL;

	for (i = 0; i < conf->geo.raid_disks; i++) {
		rdev_tmp = conf->mirrors[i].rdev;
		if (rdev_tmp && test_bit(DiskError, &rdev_tmp->flags)) {
			res = 1;
			goto END;
		}
	}
END:
	return res;
}
#endif  
static sector_t reshape_request(struct mddev *mddev, sector_t sector_nr,
				int *skipped);
static void reshape_request_write(struct mddev *mddev, struct r10bio *r10_bio);
static void end_reshape_write(struct bio *bio);
static void end_reshape(struct r10conf *conf);

#if defined(MY_ABC_HERE)
static int blRaid10Enough(struct r10conf *conf, struct md_rdev *rdev);
#endif  

static void * r10bio_pool_alloc(gfp_t gfp_flags, void *data)
{
	struct r10conf *conf = data;
	int size = offsetof(struct r10bio, devs[conf->copies]);

	return kzalloc(size, gfp_flags);
}

static void r10bio_pool_free(void *r10_bio, void *data)
{
	kfree(r10_bio);
}

#define RESYNC_BLOCK_SIZE (64*1024)
#define RESYNC_PAGES ((RESYNC_BLOCK_SIZE + PAGE_SIZE-1) / PAGE_SIZE)
 
#define RESYNC_WINDOW (1024*1024)
 
#define RESYNC_DEPTH (32*1024*1024/RESYNC_BLOCK_SIZE)

static void * r10buf_pool_alloc(gfp_t gfp_flags, void *data)
{
	struct r10conf *conf = data;
	struct page *page;
	struct r10bio *r10_bio;
	struct bio *bio;
	int i, j;
	int nalloc;

	r10_bio = r10bio_pool_alloc(gfp_flags, conf);
	if (!r10_bio)
		return NULL;

	if (test_bit(MD_RECOVERY_SYNC, &conf->mddev->recovery) ||
	    test_bit(MD_RECOVERY_RESHAPE, &conf->mddev->recovery))
		nalloc = conf->copies;  
	else
		nalloc = 2;  

	for (j = nalloc ; j-- ; ) {
		bio = bio_kmalloc(gfp_flags, RESYNC_PAGES);
		if (!bio)
			goto out_free_bio;
		r10_bio->devs[j].bio = bio;
		if (!conf->have_replacement)
			continue;
		bio = bio_kmalloc(gfp_flags, RESYNC_PAGES);
		if (!bio)
			goto out_free_bio;
		r10_bio->devs[j].repl_bio = bio;
	}
	 
	for (j = 0 ; j < nalloc; j++) {
		struct bio *rbio = r10_bio->devs[j].repl_bio;
		bio = r10_bio->devs[j].bio;
		for (i = 0; i < RESYNC_PAGES; i++) {
			if (j > 0 && !test_bit(MD_RECOVERY_SYNC,
					       &conf->mddev->recovery)) {
				 
				struct bio *rbio = r10_bio->devs[0].bio;
				page = rbio->bi_io_vec[i].bv_page;
				get_page(page);
			} else
				page = alloc_page(gfp_flags);
			if (unlikely(!page))
				goto out_free_pages;

			bio->bi_io_vec[i].bv_page = page;
			if (rbio)
				rbio->bi_io_vec[i].bv_page = page;
		}
	}

	return r10_bio;

out_free_pages:
	for ( ; i > 0 ; i--)
		safe_put_page(bio->bi_io_vec[i-1].bv_page);
	while (j--)
		for (i = 0; i < RESYNC_PAGES ; i++)
			safe_put_page(r10_bio->devs[j].bio->bi_io_vec[i].bv_page);
	j = 0;
out_free_bio:
	for ( ; j < nalloc; j++) {
		if (r10_bio->devs[j].bio)
			bio_put(r10_bio->devs[j].bio);
		if (r10_bio->devs[j].repl_bio)
			bio_put(r10_bio->devs[j].repl_bio);
	}
	r10bio_pool_free(r10_bio, conf);
	return NULL;
}

static void r10buf_pool_free(void *__r10_bio, void *data)
{
	int i;
	struct r10conf *conf = data;
	struct r10bio *r10bio = __r10_bio;
	int j;

	for (j=0; j < conf->copies; j++) {
		struct bio *bio = r10bio->devs[j].bio;
		if (bio) {
			for (i = 0; i < RESYNC_PAGES; i++) {
				safe_put_page(bio->bi_io_vec[i].bv_page);
				bio->bi_io_vec[i].bv_page = NULL;
			}
			bio_put(bio);
		}
		bio = r10bio->devs[j].repl_bio;
		if (bio)
			bio_put(bio);
	}
	r10bio_pool_free(r10bio, conf);
}

static void put_all_bios(struct r10conf *conf, struct r10bio *r10_bio)
{
	int i;

	for (i = 0; i < conf->copies; i++) {
		struct bio **bio = & r10_bio->devs[i].bio;
		if (!BIO_SPECIAL(*bio))
			bio_put(*bio);
		*bio = NULL;
		bio = &r10_bio->devs[i].repl_bio;
		if (r10_bio->read_slot < 0 && !BIO_SPECIAL(*bio))
			bio_put(*bio);
		*bio = NULL;
	}
}

static void free_r10bio(struct r10bio *r10_bio)
{
	struct r10conf *conf = r10_bio->mddev->private;

	put_all_bios(conf, r10_bio);
	mempool_free(r10_bio, conf->r10bio_pool);
}

static void put_buf(struct r10bio *r10_bio)
{
	struct r10conf *conf = r10_bio->mddev->private;

	mempool_free(r10_bio, conf->r10buf_pool);

	lower_barrier(conf);
}

static void reschedule_retry(struct r10bio *r10_bio)
{
	unsigned long flags;
	struct mddev *mddev = r10_bio->mddev;
	struct r10conf *conf = mddev->private;

	spin_lock_irqsave(&conf->device_lock, flags);
	list_add(&r10_bio->retry_list, &conf->retry_list);
	conf->nr_queued ++;
	spin_unlock_irqrestore(&conf->device_lock, flags);

	wake_up(&conf->wait_barrier);

	md_wakeup_thread(mddev->thread);
}

static void raid_end_bio_io(struct r10bio *r10_bio)
{
	struct bio *bio = r10_bio->master_bio;
	int done;
	struct r10conf *conf = r10_bio->mddev->private;

	if (bio->bi_phys_segments) {
		unsigned long flags;
		spin_lock_irqsave(&conf->device_lock, flags);
		bio->bi_phys_segments--;
		done = (bio->bi_phys_segments == 0);
		spin_unlock_irqrestore(&conf->device_lock, flags);
	} else
		done = 1;
	if (!test_bit(R10BIO_Uptodate, &r10_bio->state))
		bio->bi_error = -EIO;
	if (done) {
		bio_endio(bio);
		 
		allow_barrier(conf);
	}
	free_r10bio(r10_bio);
}

static inline void update_head_pos(int slot, struct r10bio *r10_bio)
{
	struct r10conf *conf = r10_bio->mddev->private;

	conf->mirrors[r10_bio->devs[slot].devnum].head_position =
		r10_bio->devs[slot].addr + (r10_bio->sectors);
}

static int find_bio_disk(struct r10conf *conf, struct r10bio *r10_bio,
			 struct bio *bio, int *slotp, int *replp)
{
	int slot;
	int repl = 0;

	for (slot = 0; slot < conf->copies; slot++) {
		if (r10_bio->devs[slot].bio == bio)
			break;
		if (r10_bio->devs[slot].repl_bio == bio) {
			repl = 1;
			break;
		}
	}

	BUG_ON(slot == conf->copies);
	update_head_pos(slot, r10_bio);

	if (slotp)
		*slotp = slot;
	if (replp)
		*replp = repl;
	return r10_bio->devs[slot].devnum;
}

static void raid10_end_read_request(struct bio *bio)
{
	int uptodate = !bio->bi_error;
	struct r10bio *r10_bio = bio->bi_private;
	int slot, dev;
	struct md_rdev *rdev;
	struct r10conf *conf = r10_bio->mddev->private;

	slot = r10_bio->read_slot;
	dev = r10_bio->devs[slot].devnum;
	rdev = r10_bio->devs[slot].rdev;
	 
	update_head_pos(slot, r10_bio);

#ifdef MY_ABC_HERE
	if (bio_flagged(bio, BIO_AUTO_REMAP)) {
		printk("%s:%s(%d) BIO_AUTO_REMAP detected\n", __FILE__, __FUNCTION__, __LINE__);
		SynoAutoRemapReport(conf->mddev, r10_bio->sector, conf->mirrors[dev].rdev->bdev);
	}
#endif  

	if (uptodate) {
		 
		set_bit(R10BIO_Uptodate, &r10_bio->state);
	} else {
		 
#ifdef MY_ABC_HERE
		if (!blRaid10Enough(conf, conf->mirrors[dev].rdev))
#else  
		if (!_enough(conf, test_bit(R10BIO_Previous, &r10_bio->state),
			     rdev->raid_disk))
#endif  
			uptodate = 1;

#ifdef MY_ABC_HERE
		if (!IsDeviceDisappear(conf->mirrors[dev].rdev->bdev)) {
#ifdef MY_ABC_HERE
			if (bio_flagged(bio, BIO_AUTO_REMAP)) {
				SynoReportBadSector(bio->bi_iter.bi_sector, READ,
								conf->mddev->md_minor, conf->mirrors[dev].rdev->bdev, __FUNCTION__);
			}
#else  
			SynoReportBadSector(bio->bi_iter.bi_sector, READ,
								conf->mddev->md_minor, conf->mirrors[dev].rdev->bdev, __FUNCTION__);
#endif  
		}
#endif  

#ifdef MY_ABC_HERE
		 
		if (uptodate) {
			md_error(r10_bio->mddev, conf->mirrors[dev].rdev);
		}
#endif  
	}

	if (uptodate) {
		raid_end_bio_io(r10_bio);
		rdev_dec_pending(rdev, conf->mddev);
	} else {
		 
		char b[BDEVNAME_SIZE];
		printk_ratelimited(KERN_ERR
				   "md/raid10:%s: %s: rescheduling sector %llu\n",
				   mdname(conf->mddev),
				   bdevname(rdev->bdev, b),
				   (unsigned long long)r10_bio->sector);
		set_bit(R10BIO_ReadError, &r10_bio->state);

		reschedule_retry(r10_bio);
	}
}

static void close_write(struct r10bio *r10_bio)
{
	 
	bitmap_endwrite(r10_bio->mddev->bitmap, r10_bio->sector,
			r10_bio->sectors,
			!test_bit(R10BIO_Degraded, &r10_bio->state),
			0);
	md_write_end(r10_bio->mddev);
}

static void one_write_done(struct r10bio *r10_bio)
{
	if (atomic_dec_and_test(&r10_bio->remaining)) {
		if (test_bit(R10BIO_WriteError, &r10_bio->state))
			reschedule_retry(r10_bio);
		else {
			close_write(r10_bio);
			if (test_bit(R10BIO_MadeGood, &r10_bio->state))
				reschedule_retry(r10_bio);
			else
				raid_end_bio_io(r10_bio);
		}
	}
}

static void raid10_end_write_request(struct bio *bio)
{
	struct r10bio *r10_bio = bio->bi_private;
	int dev;
	int dec_rdev = 1;
	struct r10conf *conf = r10_bio->mddev->private;
	int slot, repl;
	struct md_rdev *rdev = NULL;

	dev = find_bio_disk(conf, r10_bio, bio, &slot, &repl);

	if (repl)
		rdev = conf->mirrors[dev].replacement;
	if (!rdev) {
		smp_rmb();
		repl = 0;
		rdev = conf->mirrors[dev].rdev;
	}
	 
	if (bio->bi_error) {
		if (repl)
			 
			md_error(rdev->mddev, rdev);
		else {
#ifdef MY_ABC_HERE
			if (!IsDeviceDisappear(conf->mirrors[dev].rdev->bdev)) {
				SynoReportBadSector(bio->bi_iter.bi_sector, WRITE, conf->mddev->md_minor,
									conf->mirrors[dev].rdev->bdev, __FUNCTION__);
			}
#endif  
			set_bit(WriteErrorSeen,	&rdev->flags);
			if (!test_and_set_bit(WantReplacement, &rdev->flags))
				set_bit(MD_RECOVERY_NEEDED,
					&rdev->mddev->recovery);
			set_bit(R10BIO_WriteError, &r10_bio->state);
			dec_rdev = 0;
		}
	} else {
		 
		sector_t first_bad;
		int bad_sectors;

		if (test_bit(In_sync, &rdev->flags) &&
		    !test_bit(Faulty, &rdev->flags))
			set_bit(R10BIO_Uptodate, &r10_bio->state);

		if (is_badblock(rdev,
				r10_bio->devs[slot].addr,
				r10_bio->sectors,
				&first_bad, &bad_sectors)) {
			bio_put(bio);
			if (repl)
				r10_bio->devs[slot].repl_bio = IO_MADE_GOOD;
			else
				r10_bio->devs[slot].bio = IO_MADE_GOOD;
			dec_rdev = 0;
			set_bit(R10BIO_MadeGood, &r10_bio->state);
		}
	}

	one_write_done(r10_bio);
	if (dec_rdev)
		rdev_dec_pending(rdev, conf->mddev);
}

static void __raid10_find_phys(struct geom *geo, struct r10bio *r10bio)
{
	int n,f;
	sector_t sector;
	sector_t chunk;
	sector_t stripe;
	int dev;
	int slot = 0;
	int last_far_set_start, last_far_set_size;

	last_far_set_start = (geo->raid_disks / geo->far_set_size) - 1;
	last_far_set_start *= geo->far_set_size;

	last_far_set_size = geo->far_set_size;
	last_far_set_size += (geo->raid_disks % geo->far_set_size);

	chunk = r10bio->sector >> geo->chunk_shift;
	sector = r10bio->sector & geo->chunk_mask;

	chunk *= geo->near_copies;
	stripe = chunk;
	dev = sector_div(stripe, geo->raid_disks);
	if (geo->far_offset)
		stripe *= geo->far_copies;

	sector += stripe << geo->chunk_shift;

	for (n = 0; n < geo->near_copies; n++) {
		int d = dev;
		int set;
		sector_t s = sector;
		r10bio->devs[slot].devnum = d;
		r10bio->devs[slot].addr = s;
		slot++;

		for (f = 1; f < geo->far_copies; f++) {
			set = d / geo->far_set_size;
			d += geo->near_copies;

			if ((geo->raid_disks % geo->far_set_size) &&
			    (d > last_far_set_start)) {
				d -= last_far_set_start;
				d %= last_far_set_size;
				d += last_far_set_start;
			} else {
				d %= geo->far_set_size;
				d += geo->far_set_size * set;
			}
			s += geo->stride;
			r10bio->devs[slot].devnum = d;
			r10bio->devs[slot].addr = s;
			slot++;
		}
		dev++;
		if (dev >= geo->raid_disks) {
			dev = 0;
			sector += (geo->chunk_mask + 1);
		}
	}
}

static void raid10_find_phys(struct r10conf *conf, struct r10bio *r10bio)
{
	struct geom *geo = &conf->geo;

	if (conf->reshape_progress != MaxSector &&
	    ((r10bio->sector >= conf->reshape_progress) !=
	     conf->mddev->reshape_backwards)) {
		set_bit(R10BIO_Previous, &r10bio->state);
		geo = &conf->prev;
	} else
		clear_bit(R10BIO_Previous, &r10bio->state);

	__raid10_find_phys(geo, r10bio);
}

static sector_t raid10_find_virt(struct r10conf *conf, sector_t sector, int dev)
{
	sector_t offset, chunk, vchunk;
	 
	struct geom *geo = &conf->geo;
	int far_set_start = (dev / geo->far_set_size) * geo->far_set_size;
	int far_set_size = geo->far_set_size;
	int last_far_set_start;

	if (geo->raid_disks % geo->far_set_size) {
		last_far_set_start = (geo->raid_disks / geo->far_set_size) - 1;
		last_far_set_start *= geo->far_set_size;

		if (dev >= last_far_set_start) {
			far_set_size = geo->far_set_size;
			far_set_size += (geo->raid_disks % geo->far_set_size);
			far_set_start = last_far_set_start;
		}
	}

	offset = sector & geo->chunk_mask;
	if (geo->far_offset) {
		int fc;
		chunk = sector >> geo->chunk_shift;
		fc = sector_div(chunk, geo->far_copies);
		dev -= fc * geo->near_copies;
		if (dev < far_set_start)
			dev += far_set_size;
	} else {
		while (sector >= geo->stride) {
			sector -= geo->stride;
			if (dev < (geo->near_copies + far_set_start))
				dev += far_set_size - geo->near_copies;
			else
				dev -= geo->near_copies;
		}
		chunk = sector >> geo->chunk_shift;
	}
	vchunk = chunk * geo->raid_disks + dev;
	sector_div(vchunk, geo->near_copies);
	return (vchunk << geo->chunk_shift) + offset;
}

static struct md_rdev *read_balance(struct r10conf *conf,
				    struct r10bio *r10_bio,
				    int *max_sectors)
{
	const sector_t this_sector = r10_bio->sector;
	int disk, slot;
	int sectors = r10_bio->sectors;
	int best_good_sectors;
	sector_t new_distance, best_dist;
	struct md_rdev *best_rdev, *rdev = NULL;
	int do_balance;
	int best_slot;
	struct geom *geo = &conf->geo;

	raid10_find_phys(conf, r10_bio);
	rcu_read_lock();
retry:
	sectors = r10_bio->sectors;
	best_slot = -1;
	best_rdev = NULL;
	best_dist = MaxSector;
	best_good_sectors = 0;
	do_balance = 1;
	 
	if (conf->mddev->recovery_cp < MaxSector
	    && (this_sector + sectors >= conf->next_resync))
		do_balance = 0;

	for (slot = 0; slot < conf->copies ; slot++) {
		sector_t first_bad;
		int bad_sectors;
		sector_t dev_sector;

		if (r10_bio->devs[slot].bio == IO_BLOCKED)
			continue;
		disk = r10_bio->devs[slot].devnum;
		rdev = rcu_dereference(conf->mirrors[disk].replacement);
		if (rdev == NULL || test_bit(Faulty, &rdev->flags) ||
		    r10_bio->devs[slot].addr + sectors > rdev->recovery_offset)
			rdev = rcu_dereference(conf->mirrors[disk].rdev);
		if (rdev == NULL ||
		    test_bit(Faulty, &rdev->flags))
			continue;
		if (!test_bit(In_sync, &rdev->flags) &&
		    r10_bio->devs[slot].addr + sectors > rdev->recovery_offset)
			continue;

		dev_sector = r10_bio->devs[slot].addr;
		if (is_badblock(rdev, dev_sector, sectors,
				&first_bad, &bad_sectors)) {
			if (best_dist < MaxSector)
				 
				continue;
			if (first_bad <= dev_sector) {
				 
				bad_sectors -= (dev_sector - first_bad);
				if (!do_balance && sectors > bad_sectors)
					sectors = bad_sectors;
				if (best_good_sectors > sectors)
					best_good_sectors = sectors;
			} else {
				sector_t good_sectors =
					first_bad - dev_sector;
				if (good_sectors > best_good_sectors) {
					best_good_sectors = good_sectors;
					best_slot = slot;
					best_rdev = rdev;
				}
				if (!do_balance)
					 
					break;
			}
			continue;
		} else
			best_good_sectors = sectors;

		if (!do_balance)
			break;

		if (geo->near_copies > 1 && !atomic_read(&rdev->nr_pending))
			break;

		if (geo->far_copies > 1)
			new_distance = r10_bio->devs[slot].addr;
		else
			new_distance = abs(r10_bio->devs[slot].addr -
					   conf->mirrors[disk].head_position);
		if (new_distance < best_dist) {
			best_dist = new_distance;
			best_slot = slot;
			best_rdev = rdev;
		}
	}
	if (slot >= conf->copies) {
		slot = best_slot;
		rdev = best_rdev;
	}

	if (slot >= 0) {
		atomic_inc(&rdev->nr_pending);
		if (test_bit(Faulty, &rdev->flags)) {
			 
			rdev_dec_pending(rdev, conf->mddev);
			goto retry;
		}
		r10_bio->read_slot = slot;
	} else
		rdev = NULL;
	rcu_read_unlock();
	*max_sectors = best_good_sectors;

	return rdev;
}

static int raid10_congested(struct mddev *mddev, int bits)
{
	struct r10conf *conf = mddev->private;
	int i, ret = 0;

	if ((bits & (1 << WB_async_congested)) &&
	    conf->pending_count >= max_queued_requests)
		return 1;

	rcu_read_lock();
	for (i = 0;
	     (i < conf->geo.raid_disks || i < conf->prev.raid_disks)
		     && ret == 0;
	     i++) {
		struct md_rdev *rdev = rcu_dereference(conf->mirrors[i].rdev);
		if (rdev && !test_bit(Faulty, &rdev->flags)) {
			struct request_queue *q = bdev_get_queue(rdev->bdev);

			ret |= bdi_congested(&q->backing_dev_info, bits);
		}
	}
	rcu_read_unlock();
	return ret;
}

static void flush_pending_writes(struct r10conf *conf)
{
	 
	spin_lock_irq(&conf->device_lock);

	if (conf->pending_bio_list.head) {
		struct bio *bio;
		bio = bio_list_get(&conf->pending_bio_list);
		conf->pending_count = 0;
		spin_unlock_irq(&conf->device_lock);
		 
		bitmap_unplug(conf->mddev->bitmap);
		wake_up(&conf->wait_barrier);

		while (bio) {  
			struct bio *next = bio->bi_next;
			bio->bi_next = NULL;
			if (unlikely((bio->bi_rw & REQ_DISCARD) &&
			    !blk_queue_discard(bdev_get_queue(bio->bi_bdev))))
				 
				bio_endio(bio);
			else
				generic_make_request(bio);
			bio = next;
		}
	} else
		spin_unlock_irq(&conf->device_lock);
}

static void raise_barrier(struct r10conf *conf, int force)
{
	BUG_ON(force && !conf->barrier);
	spin_lock_irq(&conf->resync_lock);

	wait_event_lock_irq(conf->wait_barrier, force || !conf->nr_waiting,
			    conf->resync_lock);

	conf->barrier++;

	wait_event_lock_irq(conf->wait_barrier,
			    !conf->nr_pending && conf->barrier < RESYNC_DEPTH,
			    conf->resync_lock);

	spin_unlock_irq(&conf->resync_lock);
}

static void lower_barrier(struct r10conf *conf)
{
	unsigned long flags;
	spin_lock_irqsave(&conf->resync_lock, flags);
	conf->barrier--;
	spin_unlock_irqrestore(&conf->resync_lock, flags);
	wake_up(&conf->wait_barrier);
}

static void wait_barrier(struct r10conf *conf)
{
	spin_lock_irq(&conf->resync_lock);
	if (conf->barrier) {
		conf->nr_waiting++;
		 
		wait_event_lock_irq(conf->wait_barrier,
				    !conf->barrier ||
				    (conf->nr_pending &&
				     current->bio_list &&
				     !bio_list_empty(current->bio_list)),
				    conf->resync_lock);
		conf->nr_waiting--;
	}
	conf->nr_pending++;
	spin_unlock_irq(&conf->resync_lock);
}

static void allow_barrier(struct r10conf *conf)
{
	unsigned long flags;
	spin_lock_irqsave(&conf->resync_lock, flags);
	conf->nr_pending--;
	spin_unlock_irqrestore(&conf->resync_lock, flags);
	wake_up(&conf->wait_barrier);
}

static void freeze_array(struct r10conf *conf, int extra)
{
	 
	spin_lock_irq(&conf->resync_lock);
	conf->barrier++;
	conf->nr_waiting++;
	wait_event_lock_irq_cmd(conf->wait_barrier,
				conf->nr_pending == conf->nr_queued+extra,
				conf->resync_lock,
				flush_pending_writes(conf));

	spin_unlock_irq(&conf->resync_lock);
}

static void unfreeze_array(struct r10conf *conf)
{
	 
	spin_lock_irq(&conf->resync_lock);
	conf->barrier--;
	conf->nr_waiting--;
	wake_up(&conf->wait_barrier);
	spin_unlock_irq(&conf->resync_lock);
}

static sector_t choose_data_offset(struct r10bio *r10_bio,
				   struct md_rdev *rdev)
{
	if (!test_bit(MD_RECOVERY_RESHAPE, &rdev->mddev->recovery) ||
	    test_bit(R10BIO_Previous, &r10_bio->state))
		return rdev->data_offset;
	else
		return rdev->new_data_offset;
}

struct raid10_plug_cb {
	struct blk_plug_cb	cb;
	struct bio_list		pending;
	int			pending_cnt;
};

static void raid10_unplug(struct blk_plug_cb *cb, bool from_schedule)
{
	struct raid10_plug_cb *plug = container_of(cb, struct raid10_plug_cb,
						   cb);
	struct mddev *mddev = plug->cb.data;
	struct r10conf *conf = mddev->private;
	struct bio *bio;

	if (from_schedule || current->bio_list) {
		spin_lock_irq(&conf->device_lock);
		bio_list_merge(&conf->pending_bio_list, &plug->pending);
		conf->pending_count += plug->pending_cnt;
		spin_unlock_irq(&conf->device_lock);
		wake_up(&conf->wait_barrier);
		md_wakeup_thread(mddev->thread);
		kfree(plug);
		return;
	}

	bio = bio_list_get(&plug->pending);
	bitmap_unplug(mddev->bitmap);
	wake_up(&conf->wait_barrier);

	while (bio) {  
		struct bio *next = bio->bi_next;
		bio->bi_next = NULL;
		if (unlikely((bio->bi_rw & REQ_DISCARD) &&
		    !blk_queue_discard(bdev_get_queue(bio->bi_bdev))))
			 
			bio_endio(bio);
		else
			generic_make_request(bio);
		bio = next;
	}
	kfree(plug);
}

static void __make_request(struct mddev *mddev, struct bio *bio)
{
	struct r10conf *conf = mddev->private;
	struct r10bio *r10_bio;
	struct bio *read_bio;
	int i;
	const int rw = bio_data_dir(bio);
	const unsigned long do_sync = (bio->bi_rw & REQ_SYNC);
	const unsigned long do_fua = (bio->bi_rw & REQ_FUA);
	const unsigned long do_discard = (bio->bi_rw
					  & (REQ_DISCARD | REQ_SECURE));
	const unsigned long do_same = (bio->bi_rw & REQ_WRITE_SAME);
	unsigned long flags;
	struct md_rdev *blocked_rdev;
	struct blk_plug_cb *cb;
	struct raid10_plug_cb *plug = NULL;
	int sectors_handled;
	int max_sectors;
	int sectors;

#ifdef MY_ABC_HERE
#ifdef MY_ABC_HERE
	if (mddev->nodev_and_crashed) {
#else  
	if (!blRaid10Enough(conf, NULL)) {
#endif  
#ifdef  MY_ABC_HERE
		syno_flashcache_return_error(bio);
#else
		bio->bi_error = -EIO;
		bio_endio(bio);
#endif
		return;
	}
#endif  

	md_write_start(mddev, bio);

	wait_barrier(conf);

	sectors = bio_sectors(bio);
	while (test_bit(MD_RECOVERY_RESHAPE, &mddev->recovery) &&
	    bio->bi_iter.bi_sector < conf->reshape_progress &&
	    bio->bi_iter.bi_sector + sectors > conf->reshape_progress) {
		 
		allow_barrier(conf);
		wait_event(conf->wait_barrier,
			   conf->reshape_progress <= bio->bi_iter.bi_sector ||
			   conf->reshape_progress >= bio->bi_iter.bi_sector +
			   sectors);
		wait_barrier(conf);
	}
	if (test_bit(MD_RECOVERY_RESHAPE, &mddev->recovery) &&
	    bio_data_dir(bio) == WRITE &&
	    (mddev->reshape_backwards
	     ? (bio->bi_iter.bi_sector < conf->reshape_safe &&
		bio->bi_iter.bi_sector + sectors > conf->reshape_progress)
	     : (bio->bi_iter.bi_sector + sectors > conf->reshape_safe &&
		bio->bi_iter.bi_sector < conf->reshape_progress))) {
		 
		mddev->reshape_position = conf->reshape_progress;
		set_bit(MD_CHANGE_DEVS, &mddev->flags);
		set_bit(MD_CHANGE_PENDING, &mddev->flags);
		md_wakeup_thread(mddev->thread);
		wait_event(mddev->sb_wait,
			   !test_bit(MD_CHANGE_PENDING, &mddev->flags));

		conf->reshape_safe = mddev->reshape_position;
	}

	r10_bio = mempool_alloc(conf->r10bio_pool, GFP_NOIO);

	r10_bio->master_bio = bio;
	r10_bio->sectors = sectors;

	r10_bio->mddev = mddev;
	r10_bio->sector = bio->bi_iter.bi_sector;
	r10_bio->state = 0;

	bio->bi_phys_segments = 0;
	bio_clear_flag(bio, BIO_SEG_VALID);

	if (rw == READ) {
		 
		struct md_rdev *rdev;
		int slot;

read_again:
		rdev = read_balance(conf, r10_bio, &max_sectors);
		if (!rdev) {
			raid_end_bio_io(r10_bio);
			return;
		}
		slot = r10_bio->read_slot;

		read_bio = bio_clone_mddev(bio, GFP_NOIO, mddev);
		bio_trim(read_bio, r10_bio->sector - bio->bi_iter.bi_sector,
			 max_sectors);

		r10_bio->devs[slot].bio = read_bio;
		r10_bio->devs[slot].rdev = rdev;

		read_bio->bi_iter.bi_sector = r10_bio->devs[slot].addr +
			choose_data_offset(r10_bio, rdev);
		read_bio->bi_bdev = rdev->bdev;
		read_bio->bi_end_io = raid10_end_read_request;
		read_bio->bi_rw = READ | do_sync;
		read_bio->bi_private = r10_bio;

		if (max_sectors < r10_bio->sectors) {
			 
			sectors_handled = (r10_bio->sector + max_sectors
					   - bio->bi_iter.bi_sector);
			r10_bio->sectors = max_sectors;
			spin_lock_irq(&conf->device_lock);
			if (bio->bi_phys_segments == 0)
				bio->bi_phys_segments = 2;
			else
				bio->bi_phys_segments++;
			spin_unlock_irq(&conf->device_lock);
			 
			reschedule_retry(r10_bio);

			r10_bio = mempool_alloc(conf->r10bio_pool, GFP_NOIO);

			r10_bio->master_bio = bio;
			r10_bio->sectors = bio_sectors(bio) - sectors_handled;
			r10_bio->state = 0;
			r10_bio->mddev = mddev;
			r10_bio->sector = bio->bi_iter.bi_sector +
				sectors_handled;
			goto read_again;
		} else
			generic_make_request(read_bio);
		return;
	}

	if (conf->pending_count >= max_queued_requests) {
		md_wakeup_thread(mddev->thread);
		wait_event(conf->wait_barrier,
			   conf->pending_count < max_queued_requests);
	}
	 
	r10_bio->read_slot = -1;  
	raid10_find_phys(conf, r10_bio);
retry_write:
	blocked_rdev = NULL;
	rcu_read_lock();
	max_sectors = r10_bio->sectors;

	for (i = 0;  i < conf->copies; i++) {
		int d = r10_bio->devs[i].devnum;
		struct md_rdev *rdev = rcu_dereference(conf->mirrors[d].rdev);
		struct md_rdev *rrdev = rcu_dereference(
			conf->mirrors[d].replacement);
		if (rdev == rrdev)
			rrdev = NULL;
		if (rdev && unlikely(test_bit(Blocked, &rdev->flags))) {
			atomic_inc(&rdev->nr_pending);
			blocked_rdev = rdev;
			break;
		}
		if (rrdev && unlikely(test_bit(Blocked, &rrdev->flags))) {
			atomic_inc(&rrdev->nr_pending);
			blocked_rdev = rrdev;
			break;
		}
		if (rdev && (test_bit(Faulty, &rdev->flags)))
			rdev = NULL;
		if (rrdev && (test_bit(Faulty, &rrdev->flags)))
			rrdev = NULL;

		r10_bio->devs[i].bio = NULL;
		r10_bio->devs[i].repl_bio = NULL;

		if (!rdev && !rrdev) {
			set_bit(R10BIO_Degraded, &r10_bio->state);
			continue;
		}
		if (rdev && test_bit(WriteErrorSeen, &rdev->flags)) {
			sector_t first_bad;
			sector_t dev_sector = r10_bio->devs[i].addr;
			int bad_sectors;
			int is_bad;

			is_bad = is_badblock(rdev, dev_sector,
					     max_sectors,
					     &first_bad, &bad_sectors);
			if (is_bad < 0) {
				 
				atomic_inc(&rdev->nr_pending);
				set_bit(BlockedBadBlocks, &rdev->flags);
				blocked_rdev = rdev;
				break;
			}
			if (is_bad && first_bad <= dev_sector) {
				 
				bad_sectors -= (dev_sector - first_bad);
				if (bad_sectors < max_sectors)
					 
					max_sectors = bad_sectors;
				 
				continue;
			}
			if (is_bad) {
				int good_sectors = first_bad - dev_sector;
				if (good_sectors < max_sectors)
					max_sectors = good_sectors;
			}
		}
		if (rdev) {
			r10_bio->devs[i].bio = bio;
			atomic_inc(&rdev->nr_pending);
		}
		if (rrdev) {
			r10_bio->devs[i].repl_bio = bio;
			atomic_inc(&rrdev->nr_pending);
		}
	}
	rcu_read_unlock();

	if (unlikely(blocked_rdev)) {
		 
		int j;
		int d;

		for (j = 0; j < i; j++) {
			if (r10_bio->devs[j].bio) {
				d = r10_bio->devs[j].devnum;
				rdev_dec_pending(conf->mirrors[d].rdev, mddev);
			}
			if (r10_bio->devs[j].repl_bio) {
				struct md_rdev *rdev;
				d = r10_bio->devs[j].devnum;
				rdev = conf->mirrors[d].replacement;
				if (!rdev) {
					 
					smp_mb();
					rdev = conf->mirrors[d].rdev;
				}
				rdev_dec_pending(rdev, mddev);
			}
		}
		allow_barrier(conf);
		md_wait_for_blocked_rdev(blocked_rdev, mddev);
		wait_barrier(conf);
		goto retry_write;
	}

	if (max_sectors < r10_bio->sectors) {
		 
		r10_bio->sectors = max_sectors;
		spin_lock_irq(&conf->device_lock);
		if (bio->bi_phys_segments == 0)
			bio->bi_phys_segments = 2;
		else
			bio->bi_phys_segments++;
		spin_unlock_irq(&conf->device_lock);
	}
	sectors_handled = r10_bio->sector + max_sectors -
		bio->bi_iter.bi_sector;

	atomic_set(&r10_bio->remaining, 1);
	bitmap_startwrite(mddev->bitmap, r10_bio->sector, r10_bio->sectors, 0);

	for (i = 0; i < conf->copies; i++) {
		struct bio *mbio;
		int d = r10_bio->devs[i].devnum;
		if (r10_bio->devs[i].bio) {
			struct md_rdev *rdev = conf->mirrors[d].rdev;
			mbio = bio_clone_mddev(bio, GFP_NOIO, mddev);
			bio_trim(mbio, r10_bio->sector - bio->bi_iter.bi_sector,
				 max_sectors);
			r10_bio->devs[i].bio = mbio;

			mbio->bi_iter.bi_sector	= (r10_bio->devs[i].addr+
					   choose_data_offset(r10_bio,
							      rdev));
			mbio->bi_bdev = rdev->bdev;
			mbio->bi_end_io	= raid10_end_write_request;
			mbio->bi_rw =
				WRITE | do_sync | do_fua | do_discard | do_same;
			mbio->bi_private = r10_bio;

			atomic_inc(&r10_bio->remaining);

			cb = blk_check_plugged(raid10_unplug, mddev,
					       sizeof(*plug));
			if (cb)
				plug = container_of(cb, struct raid10_plug_cb,
						    cb);
			else
				plug = NULL;
			spin_lock_irqsave(&conf->device_lock, flags);
			if (plug) {
				bio_list_add(&plug->pending, mbio);
				plug->pending_cnt++;
			} else {
				bio_list_add(&conf->pending_bio_list, mbio);
				conf->pending_count++;
			}
			spin_unlock_irqrestore(&conf->device_lock, flags);
			if (!plug)
				md_wakeup_thread(mddev->thread);
		}

		if (r10_bio->devs[i].repl_bio) {
			struct md_rdev *rdev = conf->mirrors[d].replacement;
			if (rdev == NULL) {
				 
				smp_mb();
				rdev = conf->mirrors[d].rdev;
			}
			mbio = bio_clone_mddev(bio, GFP_NOIO, mddev);
			bio_trim(mbio, r10_bio->sector - bio->bi_iter.bi_sector,
				 max_sectors);
			r10_bio->devs[i].repl_bio = mbio;

			mbio->bi_iter.bi_sector	= (r10_bio->devs[i].addr +
					   choose_data_offset(
						   r10_bio, rdev));
			mbio->bi_bdev = rdev->bdev;
			mbio->bi_end_io	= raid10_end_write_request;
			mbio->bi_rw =
				WRITE | do_sync | do_fua | do_discard | do_same;
			mbio->bi_private = r10_bio;

			atomic_inc(&r10_bio->remaining);
			spin_lock_irqsave(&conf->device_lock, flags);
			bio_list_add(&conf->pending_bio_list, mbio);
			conf->pending_count++;
			spin_unlock_irqrestore(&conf->device_lock, flags);
			if (!mddev_check_plugged(mddev))
				md_wakeup_thread(mddev->thread);
		}
	}

	if (sectors_handled < bio_sectors(bio)) {
		one_write_done(r10_bio);
		 
		r10_bio = mempool_alloc(conf->r10bio_pool, GFP_NOIO);

		r10_bio->master_bio = bio;
		r10_bio->sectors = bio_sectors(bio) - sectors_handled;

		r10_bio->mddev = mddev;
		r10_bio->sector = bio->bi_iter.bi_sector + sectors_handled;
		r10_bio->state = 0;
		goto retry_write;
	}
	one_write_done(r10_bio);
}

static void make_request(struct mddev *mddev, struct bio *bio)
{
	struct r10conf *conf = mddev->private;
	sector_t chunk_mask = (conf->geo.chunk_mask & conf->prev.chunk_mask);
	int chunk_sects = chunk_mask + 1;

	struct bio *split;

	if (unlikely(bio->bi_rw & REQ_FLUSH)) {
		md_flush_request(mddev, bio);
		return;
	}

	do {

		if (unlikely((bio->bi_iter.bi_sector & chunk_mask) +
			     bio_sectors(bio) > chunk_sects
			     && (conf->geo.near_copies < conf->geo.raid_disks
				 || conf->prev.near_copies <
				 conf->prev.raid_disks))) {
			split = bio_split(bio, chunk_sects -
					  (bio->bi_iter.bi_sector &
					   (chunk_sects - 1)),
					  GFP_NOIO, fs_bio_set);
			bio_chain(split, bio);
		} else {
			split = bio;
		}

		__make_request(mddev, split);
		if (split != bio && bio_data_dir(bio) == READ) {
			generic_make_request(bio);
			break;
		}
	} while (split != bio);

	wake_up(&conf->wait_barrier);
}

static void status(struct seq_file *seq, struct mddev *mddev)
{
	struct r10conf *conf = mddev->private;
	int i;

	if (conf->geo.near_copies < conf->geo.raid_disks)
		seq_printf(seq, " %dK chunks", mddev->chunk_sectors / 2);
	if (conf->geo.near_copies > 1)
		seq_printf(seq, " %d near-copies", conf->geo.near_copies);
	if (conf->geo.far_copies > 1) {
		if (conf->geo.far_offset)
			seq_printf(seq, " %d offset-copies", conf->geo.far_copies);
		else
			seq_printf(seq, " %d far-copies", conf->geo.far_copies);
		if (conf->geo.far_set_size != conf->geo.raid_disks)
			seq_printf(seq, " %d devices per set", conf->geo.far_set_size);
	}
	seq_printf(seq, " [%d/%d] [", conf->geo.raid_disks,
					conf->geo.raid_disks - mddev->degraded);
	for (i = 0; i < conf->geo.raid_disks; i++)
#ifdef MY_ABC_HERE
		seq_printf(seq, "%s",
				   conf->mirrors[i].rdev && test_bit(In_sync, &conf->mirrors[i].rdev->flags) ?
				   (test_bit(DiskError, &conf->mirrors[i].rdev->flags) ?  "E" : "U") : "_");
#else  
		seq_printf(seq, "%s",
			      conf->mirrors[i].rdev &&
			      test_bit(In_sync, &conf->mirrors[i].rdev->flags) ? "U" : "_");
#endif  
	seq_printf(seq, "]");
}

static int _enough(struct r10conf *conf, int previous, int ignore)
{
	int first = 0;
	int has_enough = 0;
	int disks, ncopies;
	if (previous) {
		disks = conf->prev.raid_disks;
		ncopies = conf->prev.near_copies;
	} else {
		disks = conf->geo.raid_disks;
		ncopies = conf->geo.near_copies;
	}

	rcu_read_lock();
	do {
		int n = conf->copies;
		int cnt = 0;
		int this = first;
		while (n--) {
			struct md_rdev *rdev;
			if (this != ignore &&
			    (rdev = rcu_dereference(conf->mirrors[this].rdev)) &&
			    test_bit(In_sync, &rdev->flags))
				cnt++;
			this = (this+1) % disks;
		}
		if (cnt == 0)
			goto out;
		first = (first + ncopies) % disks;
	} while (first != 0);
	has_enough = 1;
out:
	rcu_read_unlock();
	return has_enough;
}

static int enough(struct r10conf *conf, int ignore)
{
	 
	return _enough(conf, 0, ignore) &&
		_enough(conf, 1, ignore);
}

#if defined(MY_ABC_HERE)
#ifdef MY_ABC_HERE
static inline void SynoSetRdevAutoRemap(struct mddev *mddev)
{
	struct r10conf *conf = mddev->private;
	struct geom* geo = &conf->geo;
	struct md_rdev *rdev;
	char b[BDEVNAME_SIZE];
	int rdev_idx = 0;

	if (1 >= geo->near_copies || (geo->raid_disks % geo->near_copies)) {
		printk("md: %s: not a standard RAID 10, does not support auto remap mode", mdname(mddev));
		return;
	}

	rdev_for_each(rdev, mddev) {
		RaidRemapModeSet(rdev->bdev, MD_AUTO_REMAP_MODE_FORCE_OFF);
	}

	do {
		int num_data_copies = conf->copies;
		int survival_cnt = 0;
		int last_survival_rdev = -1;

		while (num_data_copies--) {
			if (conf->mirrors[rdev_idx].rdev &&
				!test_bit(Faulty, &conf->mirrors[rdev_idx].rdev->flags) &&
				test_bit(In_sync, &conf->mirrors[rdev_idx].rdev->flags)) {
				survival_cnt++;
				last_survival_rdev = rdev_idx;
			}
			rdev_idx = (rdev_idx + 1) % geo->raid_disks;
		}

		if (1 == survival_cnt) {
			RaidRemapModeSet(conf->mirrors[last_survival_rdev].rdev->bdev, MD_AUTO_REMAP_MODE_FORCE_ON);
		}
	} while (0 != rdev_idx);

	rdev_for_each(rdev, mddev) {
		if (rdev && rdev->bdev && rdev->bdev->bd_part) {
			bdevname(rdev->bdev, b);
			printk("md: %s: set %s to auto_remap [%d]\n", mdname(mddev), b, rdev->bdev->bd_part->auto_remap);
		}
	}
}

static inline unsigned char SynoIsRaidReachMaxDegrade(struct mddev *mddev)
{
	struct r10conf *conf = mddev->private;
	int first = 0;
	int first_orig = first;
	int blStandardRaid10 = 0;
	int ret = 0;
	struct geom* geo = &conf->geo;

	if (1 < geo->near_copies && !(geo->raid_disks % geo->near_copies)) {
		blStandardRaid10 = 1;
	}

	do {
		int n = conf->copies;
		int cnt = 0;

		while (n--) {
			if (conf->mirrors[first].rdev &&
				!test_bit(Faulty, &conf->mirrors[first].rdev->flags) &&
				test_bit(In_sync, &conf->mirrors[first].rdev->flags)) {
				cnt++;
			}
			first = (first+1) % geo->raid_disks;
		}

		if (cnt <= 1) {
			ret = 1;
			goto END;
		}

		if (!blStandardRaid10) {
			first_orig = (first_orig+1) % geo->raid_disks;
			first = first_orig;
		}
	} while (first != 0);

END:
	return ret;
}
#endif  

static int
blRaid10Enough(struct r10conf *conf,
			   struct md_rdev *rdev)
{
	int first = 0;
	int first_orig = first;
	int blStandardRaid10 = 0;
	int ret = 0;
	struct geom* geo = &conf->geo;
	 
	if (1 < geo->near_copies && !(geo->raid_disks % geo->near_copies)) {
		blStandardRaid10 = 1;
	}

	do {
		int n = conf->copies;
		int cnt = 0;

		while (n--) {
			if (conf->mirrors[first].rdev &&
				!test_bit(Faulty, &conf->mirrors[first].rdev->flags)&&
				test_bit(In_sync, &conf->mirrors[first].rdev->flags)) {
				if (!(rdev && conf->mirrors[first].rdev == rdev)) {
					cnt++;
				}
			}
			first = (first+1) % geo->raid_disks;
		}

		if (cnt == 0) {
			goto END;
		}

		if (!blStandardRaid10) {
			first_orig = (first_orig+1) % geo->raid_disks;
			first = first_orig;
		}
	} while (first != 0);

	ret = 1;
END:
	return ret;
}
#endif  

#ifdef MY_ABC_HERE
static void
syno_error_common(struct mddev *mddev,
				  struct md_rdev *rdev)
{
	char b[BDEVNAME_SIZE];
	struct r10conf *conf = mddev->private;
	unsigned long flags;

	spin_lock_irqsave(&conf->device_lock, flags);
	if (test_and_clear_bit(In_sync, &rdev->flags)) {
		mddev->degraded++;

#ifdef MY_ABC_HERE
		if (!blRaid10Enough(conf, rdev)) {
			mddev->nodev_and_crashed = 1;
		}
#endif  
#ifdef MY_ABC_HERE
		clear_bit(DiskError, &rdev->flags);
#endif  
	}
	 
	set_bit(MD_RECOVERY_INTR, &mddev->recovery);
	set_bit(Blocked, &rdev->flags);
	set_bit(Faulty, &rdev->flags);
	set_bit(MD_CHANGE_DEVS, &mddev->flags);
	set_bit(MD_CHANGE_PENDING, &mddev->flags);
	spin_unlock_irqrestore(&conf->device_lock, flags);
	printk(KERN_ALERT "raid10: Disk failure on %s, disabling device. \n"
		"	Operation continuing on %d devices\n",
		bdevname(rdev->bdev,b), conf->geo.raid_disks - mddev->degraded);
}

static void
syno_error_for_hotplug(struct mddev *mddev,
					   struct md_rdev *rdev)
{
	char b1[BDEVNAME_SIZE], b2[BDEVNAME_SIZE];
	struct r10conf *conf = mddev->private;
	struct md_rdev *rdev_tmp;

	if (test_bit(In_sync, &rdev->flags)
	    && blRaid10Enough(conf, NULL) &&
		!blRaid10Enough(conf, rdev)) {
		list_for_each_entry(rdev_tmp, &mddev->disks, same_set) {
			if(!test_bit(Faulty, &rdev_tmp->flags) &&
			   !test_bit(In_sync, &rdev_tmp->flags) &&
			   0 != strcmp(bdevname(rdev_tmp->bdev, b1), bdevname(rdev->bdev, b2))) {
				printk("[%s] %d: %s is being to unplug, but %s is sync now, disable both\n",
					   __FILE__, __LINE__, bdevname(rdev->bdev, b2), bdevname(rdev_tmp->bdev, b1));
				SYNORaidRdevUnplug(mddev, rdev_tmp);
			}
		}
	}

	syno_error_common(mddev, rdev);
}

static
void syno_error_for_internal(struct mddev *mddev,
							 struct md_rdev *rdev)
{
	struct r10conf *conf = mddev->private;
	struct md_rdev *rdev_tmp;
	char b1[BDEVNAME_SIZE], b2[BDEVNAME_SIZE];

	if (test_bit(In_sync, &rdev->flags)
	    && blRaid10Enough(conf, NULL) &&
		!blRaid10Enough(conf, rdev)) {
#ifdef MY_ABC_HERE
			 
			if (!test_bit(DiskError, &rdev->flags)) {
				set_bit(DiskError, &rdev->flags);
				set_bit(MD_CHANGE_DEVS, &mddev->flags);
			}
#endif  
			 
			list_for_each_entry(rdev_tmp, &mddev->disks, same_set) {
				if(!test_bit(Faulty, &rdev_tmp->flags) &&
				   !test_bit(In_sync, &rdev_tmp->flags) &&
				   0 != strcmp(bdevname(rdev_tmp->bdev, b1), bdevname(rdev->bdev, b2))) {
					printk("[%s] %d: %s is faulty, but %s is sync now, disable both\n",
						   __FILE__, __LINE__, bdevname(rdev->bdev, b2), bdevname(rdev_tmp->bdev, b1));
					SYNORaidRdevUnplug(mddev, rdev_tmp);
					set_bit(MD_RECOVERY_INTR, &mddev->recovery);
				}
			}

			return;
	}

	syno_error_common(mddev, rdev);
}

#else  
static void error(struct mddev *mddev, struct md_rdev *rdev)
{
	char b[BDEVNAME_SIZE];
	struct r10conf *conf = mddev->private;
	unsigned long flags;

	spin_lock_irqsave(&conf->device_lock, flags);
	if (test_bit(In_sync, &rdev->flags)
	    && !enough(conf, rdev->raid_disk)) {
		 
		spin_unlock_irqrestore(&conf->device_lock, flags);
		return;
	}
	if (test_and_clear_bit(In_sync, &rdev->flags))
		mddev->degraded++;
	 
	set_bit(MD_RECOVERY_INTR, &mddev->recovery);
	set_bit(Blocked, &rdev->flags);
	set_bit(Faulty, &rdev->flags);
	set_bit(MD_CHANGE_DEVS, &mddev->flags);
	set_bit(MD_CHANGE_PENDING, &mddev->flags);
	spin_unlock_irqrestore(&conf->device_lock, flags);
	printk(KERN_ALERT
	       "md/raid10:%s: Disk failure on %s, disabling device.\n"
	       "md/raid10:%s: Operation continuing on %d devices.\n",
	       mdname(mddev), bdevname(rdev->bdev, b),
	       mdname(mddev), conf->geo.raid_disks - mddev->degraded);
}
#endif  

static void print_conf(struct r10conf *conf)
{
	int i;
	struct raid10_info *tmp;

	printk(KERN_DEBUG "RAID10 conf printout:\n");
	if (!conf) {
		printk(KERN_DEBUG "(!conf)\n");
		return;
	}
	printk(KERN_DEBUG " --- wd:%d rd:%d\n", conf->geo.raid_disks - conf->mddev->degraded,
		conf->geo.raid_disks);

	for (i = 0; i < conf->geo.raid_disks; i++) {
		char b[BDEVNAME_SIZE];
		tmp = conf->mirrors + i;
		if (tmp->rdev)
			printk(KERN_DEBUG " disk %d, wo:%d, o:%d, dev:%s\n",
				i, !test_bit(In_sync, &tmp->rdev->flags),
			        !test_bit(Faulty, &tmp->rdev->flags),
				bdevname(tmp->rdev->bdev,b));
	}
}

static void close_sync(struct r10conf *conf)
{
	wait_barrier(conf);
	allow_barrier(conf);

	mempool_destroy(conf->r10buf_pool);
	conf->r10buf_pool = NULL;
}

static int raid10_spare_active(struct mddev *mddev)
{
	int i;
	struct r10conf *conf = mddev->private;
	struct raid10_info *tmp;
	int count = 0;
	unsigned long flags;

#ifdef MY_ABC_HERE
	if (IsDiskErrorSet(mddev)) {
		return 0;
	}
#endif  

	for (i = 0; i < conf->geo.raid_disks; i++) {
		tmp = conf->mirrors + i;
		if (tmp->replacement
		    && tmp->replacement->recovery_offset == MaxSector
		    && !test_bit(Faulty, &tmp->replacement->flags)
		    && !test_and_set_bit(In_sync, &tmp->replacement->flags)) {
			 
			if (!tmp->rdev
			    || !test_and_clear_bit(In_sync, &tmp->rdev->flags))
				count++;
			if (tmp->rdev) {
				 
				set_bit(Faulty, &tmp->rdev->flags);
				sysfs_notify_dirent_safe(
					tmp->rdev->sysfs_state);
			}
			sysfs_notify_dirent_safe(tmp->replacement->sysfs_state);
		} else if (tmp->rdev
			   && tmp->rdev->recovery_offset == MaxSector
			   && !test_bit(Faulty, &tmp->rdev->flags)
			   && !test_and_set_bit(In_sync, &tmp->rdev->flags)) {
			count++;
			sysfs_notify_dirent_safe(tmp->rdev->sysfs_state);
		}
	}
	spin_lock_irqsave(&conf->device_lock, flags);
	mddev->degraded -= count;
	spin_unlock_irqrestore(&conf->device_lock, flags);

	print_conf(conf);
	return count;
}

static int raid10_add_disk(struct mddev *mddev, struct md_rdev *rdev)
{
	struct r10conf *conf = mddev->private;
	int err = -EEXIST;
	int mirror;
	int first = 0;
	int last = conf->geo.raid_disks - 1;

#ifdef MY_ABC_HERE
	if (IsDiskErrorSet(mddev)) {
		return -EINVAL;
	}

	if (!blRaid10Enough(conf, NULL)) {
		return -EINVAL;
	}
#endif  

	if (mddev->recovery_cp < MaxSector)
		 
		return -EBUSY;
	if (rdev->saved_raid_disk < 0 && !_enough(conf, 1, -1))
		return -EINVAL;

	if (md_integrity_add_rdev(rdev, mddev))
		return -ENXIO;

	if (rdev->raid_disk >= 0)
		first = last = rdev->raid_disk;

	if (rdev->saved_raid_disk >= first &&
	    conf->mirrors[rdev->saved_raid_disk].rdev == NULL)
		mirror = rdev->saved_raid_disk;
	else
		mirror = first;
	for ( ; mirror <= last ; mirror++) {
		struct raid10_info *p = &conf->mirrors[mirror];
		if (p->recovery_disabled == mddev->recovery_disabled)
			continue;
		if (p->rdev) {
			if (!test_bit(WantReplacement, &p->rdev->flags) ||
			    p->replacement != NULL)
				continue;
			clear_bit(In_sync, &rdev->flags);
			set_bit(Replacement, &rdev->flags);
			rdev->raid_disk = mirror;
			err = 0;
			if (mddev->gendisk)
				disk_stack_limits(mddev->gendisk, rdev->bdev,
						  rdev->data_offset << 9);
			conf->fullsync = 1;
			rcu_assign_pointer(p->replacement, rdev);
			break;
		}

		if (mddev->gendisk)
			disk_stack_limits(mddev->gendisk, rdev->bdev,
					  rdev->data_offset << 9);

		p->head_position = 0;
		p->recovery_disabled = mddev->recovery_disabled - 1;
		rdev->raid_disk = mirror;
		err = 0;
		if (rdev->saved_raid_disk != mirror)
			conf->fullsync = 1;
		rcu_assign_pointer(p->rdev, rdev);
		break;
	}
	if (mddev->queue && blk_queue_discard(bdev_get_queue(rdev->bdev)))
		queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, mddev->queue);

	print_conf(conf);
	return err;
}

static int raid10_remove_disk(struct mddev *mddev, struct md_rdev *rdev)
{
	struct r10conf *conf = mddev->private;
	int err = 0;
	int number = rdev->raid_disk;
	struct md_rdev **rdevp;
	struct raid10_info *p = conf->mirrors + number;

	print_conf(conf);
	if (rdev == p->rdev)
		rdevp = &p->rdev;
	else if (rdev == p->replacement)
		rdevp = &p->replacement;
	else
		return 0;

	if (test_bit(In_sync, &rdev->flags) ||
	    atomic_read(&rdev->nr_pending)) {
		err = -EBUSY;
		goto abort;
	}
	 
	if (!test_bit(Faulty, &rdev->flags) &&
	    mddev->recovery_disabled != p->recovery_disabled &&
	    (!p->replacement || p->replacement == rdev) &&
	    number < conf->geo.raid_disks &&
	    enough(conf, -1)) {
		err = -EBUSY;
		goto abort;
	}
	*rdevp = NULL;
	synchronize_rcu();
	if (atomic_read(&rdev->nr_pending)) {
		 
		err = -EBUSY;
		*rdevp = rdev;
		goto abort;
	} else if (p->replacement) {
		 
		p->rdev = p->replacement;
		clear_bit(Replacement, &p->replacement->flags);
		smp_mb();  
		p->replacement = NULL;
		clear_bit(WantReplacement, &rdev->flags);
	} else
		 
		clear_bit(WantReplacement, &rdev->flags);

	err = md_integrity_register(mddev);

abort:

	print_conf(conf);
	return err;
}

static void end_sync_read(struct bio *bio)
{
	struct r10bio *r10_bio = bio->bi_private;
	struct r10conf *conf = r10_bio->mddev->private;
	int d;

	if (bio == r10_bio->master_bio) {
		 
		d = r10_bio->read_slot;  
	} else
		d = find_bio_disk(conf, r10_bio, bio, NULL, NULL);

#ifdef MY_ABC_HERE
	if (bio_flagged(bio, BIO_AUTO_REMAP)) {
		printk("%s:%s(%d) BIO_AUTO_REMAP detected\n", __FILE__, __FUNCTION__, __LINE__);
		SynoAutoRemapReport(conf->mddev, r10_bio->sector, conf->mirrors[d].rdev->bdev);
	}
#endif  

	if (!bio->bi_error)
		set_bit(R10BIO_Uptodate, &r10_bio->state);
	else
#ifdef MY_ABC_HERE
	{
		if (!IsDeviceDisappear(conf->mirrors[d].rdev->bdev)) {
			SynoReportBadSector(bio->bi_iter.bi_sector, READ,
					conf->mddev->md_minor, conf->mirrors[d].rdev->bdev, __FUNCTION__);
		}
		atomic_add(r10_bio->sectors,
				&conf->mirrors[d].rdev->corrected_errors);
	}
#else  
		 
		atomic_add(r10_bio->sectors,
			   &conf->mirrors[d].rdev->corrected_errors);
#endif  

	rdev_dec_pending(conf->mirrors[d].rdev, conf->mddev);
	if (test_bit(R10BIO_IsRecover, &r10_bio->state) ||
	    atomic_dec_and_test(&r10_bio->remaining)) {
		 
		reschedule_retry(r10_bio);
	}
}

static void end_sync_request(struct r10bio *r10_bio)
{
	struct mddev *mddev = r10_bio->mddev;

	while (atomic_dec_and_test(&r10_bio->remaining)) {
		if (r10_bio->master_bio == NULL) {
			 
			sector_t s = r10_bio->sectors;
			if (test_bit(R10BIO_MadeGood, &r10_bio->state) ||
			    test_bit(R10BIO_WriteError, &r10_bio->state))
				reschedule_retry(r10_bio);
			else
				put_buf(r10_bio);
			md_done_sync(mddev, s, 1);
			break;
		} else {
			struct r10bio *r10_bio2 = (struct r10bio *)r10_bio->master_bio;
			if (test_bit(R10BIO_MadeGood, &r10_bio->state) ||
			    test_bit(R10BIO_WriteError, &r10_bio->state))
				reschedule_retry(r10_bio);
			else
				put_buf(r10_bio);
			r10_bio = r10_bio2;
		}
	}
}

static void end_sync_write(struct bio *bio)
{
	struct r10bio *r10_bio = bio->bi_private;
	struct mddev *mddev = r10_bio->mddev;
	struct r10conf *conf = mddev->private;
	int d;
	sector_t first_bad;
	int bad_sectors;
	int slot;
	int repl;
	struct md_rdev *rdev = NULL;

	d = find_bio_disk(conf, r10_bio, bio, &slot, &repl);
	if (repl)
		rdev = conf->mirrors[d].replacement;
	else
		rdev = conf->mirrors[d].rdev;

	if (bio->bi_error) {
		if (repl)
			md_error(mddev, rdev);
		else {
#ifdef MY_ABC_HERE
			if (IsDeviceDisappear(rdev->bdev)) {
				set_bit(WriteErrorSeen, &rdev->flags);
				if (!test_and_set_bit(WantReplacement, &rdev->flags))
					set_bit(MD_RECOVERY_NEEDED,
						&rdev->mddev->recovery);
				set_bit(R10BIO_WriteError, &r10_bio->state);
			} else {
#ifdef MY_ABC_HERE
				if (-EIO == bio->bi_error) {
					 
					SynoReportBadSector(bio->bi_iter.bi_sector, WRITE,
										conf->mddev->md_minor, conf->mirrors[d].rdev->bdev, __FUNCTION__);
					set_bit(WriteErrorSeen, &rdev->flags);
					if (!test_and_set_bit(WantReplacement, &rdev->flags))
						set_bit(MD_RECOVERY_NEEDED,
							&rdev->mddev->recovery);
					set_bit(R10BIO_WriteError, &r10_bio->state);
				} else if (-EEXIST == bio->bi_error) {
					 
				} else {
					;
				}
#endif  
			}
#else  
			set_bit(WriteErrorSeen, &rdev->flags);
			if (!test_and_set_bit(WantReplacement, &rdev->flags))
				set_bit(MD_RECOVERY_NEEDED,
					&rdev->mddev->recovery);
			set_bit(R10BIO_WriteError, &r10_bio->state);
#endif  
		}
	} else if (is_badblock(rdev,
			     r10_bio->devs[slot].addr,
			     r10_bio->sectors,
			     &first_bad, &bad_sectors))
		set_bit(R10BIO_MadeGood, &r10_bio->state);

	rdev_dec_pending(rdev, mddev);

	end_sync_request(r10_bio);
}

static void sync_request_write(struct mddev *mddev, struct r10bio *r10_bio)
{
	struct r10conf *conf = mddev->private;
	int i, first;
	struct bio *tbio, *fbio;
	int vcnt;

	atomic_set(&r10_bio->remaining, 1);

	for (i=0; i<conf->copies; i++)
		if (!r10_bio->devs[i].bio->bi_error)
			break;

	if (i == conf->copies)
		goto done;

	first = i;
	fbio = r10_bio->devs[i].bio;
	fbio->bi_iter.bi_size = r10_bio->sectors << 9;
	fbio->bi_iter.bi_idx = 0;

	vcnt = (r10_bio->sectors + (PAGE_SIZE >> 9) - 1) >> (PAGE_SHIFT - 9);
	 
	for (i=0 ; i < conf->copies ; i++) {
		int  j, d;

		tbio = r10_bio->devs[i].bio;

		if (tbio->bi_end_io != end_sync_read)
			continue;
		if (i == first)
			continue;
		if (!r10_bio->devs[i].bio->bi_error) {
			 
			int sectors = r10_bio->sectors;
			for (j = 0; j < vcnt; j++) {
				int len = PAGE_SIZE;
				if (sectors < (len / 512))
					len = sectors * 512;
				if (memcmp(page_address(fbio->bi_io_vec[j].bv_page),
					   page_address(tbio->bi_io_vec[j].bv_page),
					   len))
					break;
				sectors -= len/512;
			}
			if (j == vcnt)
				continue;
			atomic64_add(r10_bio->sectors, &mddev->resync_mismatches);
			if (test_bit(MD_RECOVERY_CHECK, &mddev->recovery))
				 
				continue;
		}
		 
		bio_reset(tbio);

		tbio->bi_vcnt = vcnt;
		tbio->bi_iter.bi_size = fbio->bi_iter.bi_size;
		tbio->bi_rw = WRITE;
		tbio->bi_private = r10_bio;
		tbio->bi_iter.bi_sector = r10_bio->devs[i].addr;
		tbio->bi_end_io = end_sync_write;

		bio_copy_data(tbio, fbio);

		d = r10_bio->devs[i].devnum;
		atomic_inc(&conf->mirrors[d].rdev->nr_pending);
		atomic_inc(&r10_bio->remaining);
		md_sync_acct(conf->mirrors[d].rdev->bdev, bio_sectors(tbio));

		tbio->bi_iter.bi_sector += conf->mirrors[d].rdev->data_offset;
		tbio->bi_bdev = conf->mirrors[d].rdev->bdev;
		generic_make_request(tbio);
	}

	for (i = 0; i < conf->copies; i++) {
		int d;

		tbio = r10_bio->devs[i].repl_bio;
		if (!tbio || !tbio->bi_end_io)
			continue;
		if (r10_bio->devs[i].bio->bi_end_io != end_sync_write
		    && r10_bio->devs[i].bio != fbio)
			bio_copy_data(tbio, fbio);
		d = r10_bio->devs[i].devnum;
		atomic_inc(&r10_bio->remaining);
		md_sync_acct(conf->mirrors[d].replacement->bdev,
			     bio_sectors(tbio));
		generic_make_request(tbio);
	}

done:
	if (atomic_dec_and_test(&r10_bio->remaining)) {
		md_done_sync(mddev, r10_bio->sectors, 1);
		put_buf(r10_bio);
	}
}

static void fix_recovery_read_error(struct r10bio *r10_bio)
{
	 
	struct mddev *mddev = r10_bio->mddev;
	struct r10conf *conf = mddev->private;
	struct bio *bio = r10_bio->devs[0].bio;
	sector_t sect = 0;
	int sectors = r10_bio->sectors;
	int idx = 0;
	int dr = r10_bio->devs[0].devnum;
	int dw = r10_bio->devs[1].devnum;

	while (sectors) {
		int s = sectors;
		struct md_rdev *rdev;
		sector_t addr;
		int ok;

		if (s > (PAGE_SIZE>>9))
			s = PAGE_SIZE >> 9;

		rdev = conf->mirrors[dr].rdev;
		addr = r10_bio->devs[0].addr + sect,
		ok = sync_page_io(rdev,
				  addr,
				  s << 9,
				  bio->bi_io_vec[idx].bv_page,
				  READ, false);
		if (ok) {
			rdev = conf->mirrors[dw].rdev;
			addr = r10_bio->devs[1].addr + sect;
			ok = sync_page_io(rdev,
					  addr,
					  s << 9,
					  bio->bi_io_vec[idx].bv_page,
					  WRITE, false);
			if (!ok) {
				set_bit(WriteErrorSeen, &rdev->flags);
				if (!test_and_set_bit(WantReplacement,
						      &rdev->flags))
					set_bit(MD_RECOVERY_NEEDED,
						&rdev->mddev->recovery);
			}
		}
		if (!ok) {
			 
			rdev_set_badblocks(rdev, addr, s, 0);

			if (rdev != conf->mirrors[dw].rdev) {
				 
				struct md_rdev *rdev2 = conf->mirrors[dw].rdev;
#ifdef MY_ABC_HERE
				char b1[BDEVNAME_SIZE];
				char b2[BDEVNAME_SIZE];
#endif  
				addr = r10_bio->devs[1].addr + sect;
				ok = rdev_set_badblocks(rdev2, addr, s, 0);
				if (!ok) {
					 
					printk(KERN_NOTICE
					       "md/raid10:%s: recovery aborted"
					       " due to read error\n",
					       mdname(mddev));
#ifdef MY_ABC_HERE
					printk("md/raid10:%s: Failed to sync from %s to %s\n", mdname(mddev), bdevname(rdev->bdev, b1), bdevname(rdev2->bdev, b2));
					md_error(mddev, rdev);
#endif  

					conf->mirrors[dw].recovery_disabled
						= mddev->recovery_disabled;
					set_bit(MD_RECOVERY_INTR,
						&mddev->recovery);
					break;
				}
			}
		}

		sectors -= s;
		sect += s;
		idx++;
	}
}

static void recovery_request_write(struct mddev *mddev, struct r10bio *r10_bio)
{
	struct r10conf *conf = mddev->private;
	int d;
	struct bio *wbio, *wbio2;

	if (!test_bit(R10BIO_Uptodate, &r10_bio->state)) {
		fix_recovery_read_error(r10_bio);
		end_sync_request(r10_bio);
		return;
	}

	d = r10_bio->devs[1].devnum;
	wbio = r10_bio->devs[1].bio;
	wbio2 = r10_bio->devs[1].repl_bio;
	 
	if (wbio2 && !wbio2->bi_end_io)
		wbio2 = NULL;
	if (wbio->bi_end_io) {
		atomic_inc(&conf->mirrors[d].rdev->nr_pending);
		md_sync_acct(conf->mirrors[d].rdev->bdev, bio_sectors(wbio));
		generic_make_request(wbio);
	}
	if (wbio2) {
		atomic_inc(&conf->mirrors[d].replacement->nr_pending);
		md_sync_acct(conf->mirrors[d].replacement->bdev,
			     bio_sectors(wbio2));
		generic_make_request(wbio2);
	}
}

static void check_decay_read_errors(struct mddev *mddev, struct md_rdev *rdev)
{
	struct timespec cur_time_mon;
	unsigned long hours_since_last;
	unsigned int read_errors = atomic_read(&rdev->read_errors);

	ktime_get_ts(&cur_time_mon);

	if (rdev->last_read_error.tv_sec == 0 &&
	    rdev->last_read_error.tv_nsec == 0) {
		 
		rdev->last_read_error = cur_time_mon;
		return;
	}

	hours_since_last = (cur_time_mon.tv_sec -
			    rdev->last_read_error.tv_sec) / 3600;

	rdev->last_read_error = cur_time_mon;

	if (hours_since_last >= 8 * sizeof(read_errors))
		atomic_set(&rdev->read_errors, 0);
	else
		atomic_set(&rdev->read_errors, read_errors >> hours_since_last);
}

static int r10_sync_page_io(struct md_rdev *rdev, sector_t sector,
			    int sectors, struct page *page, int rw)
{
	sector_t first_bad;
	int bad_sectors;

	if (is_badblock(rdev, sector, sectors, &first_bad, &bad_sectors)
	    && (rw == READ || test_bit(WriteErrorSeen, &rdev->flags)))
		return -1;
	if (sync_page_io(rdev, sector, sectors << 9, page, rw, false))
		 
		return 1;
	if (rw == WRITE) {
		set_bit(WriteErrorSeen, &rdev->flags);
		if (!test_and_set_bit(WantReplacement, &rdev->flags))
			set_bit(MD_RECOVERY_NEEDED,
				&rdev->mddev->recovery);
	}
	 
	if (!rdev_set_badblocks(rdev, sector, sectors, 0))
		md_error(rdev->mddev, rdev);
	return 0;
}

static void fix_read_error(struct r10conf *conf, struct mddev *mddev, struct r10bio *r10_bio)
{
	int sect = 0;  
	int sectors = r10_bio->sectors;
	struct md_rdev*rdev;
	int max_read_errors = atomic_read(&mddev->max_corr_read_errors);
	int d = r10_bio->devs[r10_bio->read_slot].devnum;

	rdev = conf->mirrors[d].rdev;

	if (test_bit(Faulty, &rdev->flags))
		 
		return;

	check_decay_read_errors(mddev, rdev);
	atomic_inc(&rdev->read_errors);
	if (atomic_read(&rdev->read_errors) > max_read_errors) {
		char b[BDEVNAME_SIZE];
		bdevname(rdev->bdev, b);

		printk(KERN_NOTICE
		       "md/raid10:%s: %s: Raid device exceeded "
		       "read_error threshold [cur %d:max %d]\n",
		       mdname(mddev), b,
		       atomic_read(&rdev->read_errors), max_read_errors);
		printk(KERN_NOTICE
		       "md/raid10:%s: %s: Failing raid device\n",
		       mdname(mddev), b);
		md_error(mddev, conf->mirrors[d].rdev);
		r10_bio->devs[r10_bio->read_slot].bio = IO_BLOCKED;
		return;
	}

	while(sectors) {
		int s = sectors;
		int sl = r10_bio->read_slot;
		int success = 0;
		int start;

		if (s > (PAGE_SIZE>>9))
			s = PAGE_SIZE >> 9;

		rcu_read_lock();
		do {
			sector_t first_bad;
			int bad_sectors;

			d = r10_bio->devs[sl].devnum;
			rdev = rcu_dereference(conf->mirrors[d].rdev);
			if (rdev &&
			    test_bit(In_sync, &rdev->flags) &&
			    is_badblock(rdev, r10_bio->devs[sl].addr + sect, s,
					&first_bad, &bad_sectors) == 0) {
				atomic_inc(&rdev->nr_pending);
				rcu_read_unlock();
				success = sync_page_io(rdev,
						       r10_bio->devs[sl].addr +
						       sect,
						       s<<9,
						       conf->tmppage, READ, false);
				rdev_dec_pending(rdev, mddev);
				rcu_read_lock();
				if (success)
					break;
			}
			sl++;
			if (sl == conf->copies)
				sl = 0;
		} while (!success && sl != r10_bio->read_slot);
		rcu_read_unlock();

		if (!success) {
			 
			int dn = r10_bio->devs[r10_bio->read_slot].devnum;
			rdev = conf->mirrors[dn].rdev;

			if (!rdev_set_badblocks(
				    rdev,
				    r10_bio->devs[r10_bio->read_slot].addr
				    + sect,
				    s, 0)) {
				md_error(mddev, rdev);
				r10_bio->devs[r10_bio->read_slot].bio
					= IO_BLOCKED;
			}
			break;
		}

		start = sl;
		 
		rcu_read_lock();
		while (sl != r10_bio->read_slot) {
			char b[BDEVNAME_SIZE];

			if (sl==0)
				sl = conf->copies;
			sl--;
			d = r10_bio->devs[sl].devnum;
			rdev = rcu_dereference(conf->mirrors[d].rdev);
			if (!rdev ||
			    !test_bit(In_sync, &rdev->flags))
				continue;

			atomic_inc(&rdev->nr_pending);
			rcu_read_unlock();
			if (r10_sync_page_io(rdev,
					     r10_bio->devs[sl].addr +
					     sect,
					     s, conf->tmppage, WRITE)
			    == 0) {
				 
				printk(KERN_NOTICE
				       "md/raid10:%s: read correction "
				       "write failed"
				       " (%d sectors at %llu on %s)\n",
				       mdname(mddev), s,
				       (unsigned long long)(
					       sect +
					       choose_data_offset(r10_bio,
								  rdev)),
				       bdevname(rdev->bdev, b));
				printk(KERN_NOTICE "md/raid10:%s: %s: failing "
				       "drive\n",
				       mdname(mddev),
				       bdevname(rdev->bdev, b));
			}
			rdev_dec_pending(rdev, mddev);
			rcu_read_lock();
		}
		sl = start;
		while (sl != r10_bio->read_slot) {
			char b[BDEVNAME_SIZE];

			if (sl==0)
				sl = conf->copies;
			sl--;
			d = r10_bio->devs[sl].devnum;
			rdev = rcu_dereference(conf->mirrors[d].rdev);
			if (!rdev ||
			    !test_bit(In_sync, &rdev->flags))
				continue;

			atomic_inc(&rdev->nr_pending);
			rcu_read_unlock();
			switch (r10_sync_page_io(rdev,
					     r10_bio->devs[sl].addr +
					     sect,
					     s, conf->tmppage,
						 READ)) {
			case 0:
				 
				printk(KERN_NOTICE
				       "md/raid10:%s: unable to read back "
				       "corrected sectors"
				       " (%d sectors at %llu on %s)\n",
				       mdname(mddev), s,
				       (unsigned long long)(
					       sect +
					       choose_data_offset(r10_bio, rdev)),
				       bdevname(rdev->bdev, b));
				printk(KERN_NOTICE "md/raid10:%s: %s: failing "
				       "drive\n",
				       mdname(mddev),
				       bdevname(rdev->bdev, b));
				break;
			case 1:
				printk(KERN_INFO
				       "md/raid10:%s: read error corrected"
				       " (%d sectors at %llu on %s)\n",
				       mdname(mddev), s,
				       (unsigned long long)(
					       sect +
					       choose_data_offset(r10_bio, rdev)),
				       bdevname(rdev->bdev, b));
				atomic_add(s, &rdev->corrected_errors);
			}

			rdev_dec_pending(rdev, mddev);
			rcu_read_lock();
		}
		rcu_read_unlock();

		sectors -= s;
		sect += s;
	}
}

static int narrow_write_error(struct r10bio *r10_bio, int i)
{
	struct bio *bio = r10_bio->master_bio;
	struct mddev *mddev = r10_bio->mddev;
	struct r10conf *conf = mddev->private;
	struct md_rdev *rdev = conf->mirrors[r10_bio->devs[i].devnum].rdev;
	 
	int block_sectors;
	sector_t sector;
	int sectors;
	int sect_to_write = r10_bio->sectors;
	int ok = 1;

	if (rdev->badblocks.shift < 0)
		return 0;

	block_sectors = roundup(1 << rdev->badblocks.shift,
				bdev_logical_block_size(rdev->bdev) >> 9);
	sector = r10_bio->sector;
	sectors = ((r10_bio->sector + block_sectors)
		   & ~(sector_t)(block_sectors - 1))
		- sector;

	while (sect_to_write) {
		struct bio *wbio;
		if (sectors > sect_to_write)
			sectors = sect_to_write;
		 
		wbio = bio_clone_mddev(bio, GFP_NOIO, mddev);
		bio_trim(wbio, sector - bio->bi_iter.bi_sector, sectors);
		wbio->bi_iter.bi_sector = (r10_bio->devs[i].addr+
				   choose_data_offset(r10_bio, rdev) +
				   (sector - r10_bio->sector));
		wbio->bi_bdev = rdev->bdev;
		if (submit_bio_wait(WRITE, wbio) < 0)
			 
			ok = rdev_set_badblocks(rdev, sector,
						sectors, 0)
				&& ok;

		bio_put(wbio);
		sect_to_write -= sectors;
		sector += sectors;
		sectors = block_sectors;
	}
	return ok;
}

static void handle_read_error(struct mddev *mddev, struct r10bio *r10_bio)
{
	int slot = r10_bio->read_slot;
	struct bio *bio;
	struct r10conf *conf = mddev->private;
	struct md_rdev *rdev = r10_bio->devs[slot].rdev;
	char b[BDEVNAME_SIZE];
	unsigned long do_sync;
	int max_sectors;

	bio = r10_bio->devs[slot].bio;
#ifdef MY_ABC_HERE
#else  
	bdevname(bio->bi_bdev, b);
#endif  
	bio_put(bio);
	r10_bio->devs[slot].bio = NULL;

#ifdef MY_ABC_HERE
	if (!rdev || IsDeviceDisappear(rdev->bdev)) {
		syno_md_error(mddev, rdev);
	} else
#endif  
	if (mddev->ro == 0) {
		freeze_array(conf, 1);
		fix_read_error(conf, mddev, r10_bio);
		unfreeze_array(conf);
	} else
		r10_bio->devs[slot].bio = IO_BLOCKED;

	rdev_dec_pending(rdev, mddev);

read_more:
	rdev = read_balance(conf, r10_bio, &max_sectors);
	if (rdev == NULL) {
#ifdef MY_ABC_HERE
		if (mddev->nodev_and_crashed) {
			 
			printk(KERN_ALERT "md/raid10: no bdev: unrecoverable I/O"
					" read error for block %llu\n",
					(unsigned long long)r10_bio->sector);
		} else
#endif  
#ifdef MY_ABC_HERE
		printk(KERN_ALERT "md/raid10:%s: unrecoverable I/O"
		       " read error for block %llu\n",
		       mdname(mddev),
		       (unsigned long long)r10_bio->sector);
#else  
		printk(KERN_ALERT "md/raid10:%s: %s: unrecoverable I/O"
		       " read error for block %llu\n",
		       mdname(mddev), b,
		       (unsigned long long)r10_bio->sector);
#endif  
		raid_end_bio_io(r10_bio);
		return;
	}

	do_sync = (r10_bio->master_bio->bi_rw & REQ_SYNC);
#ifdef MY_ABC_HERE
	set_bit(R10BIO_FIX_READ_ERROR, &r10_bio->state);
#endif  
	slot = r10_bio->read_slot;
	printk_ratelimited(
		KERN_ERR
		"md/raid10:%s: %s: redirecting "
		"sector %llu to another mirror\n",
		mdname(mddev),
		bdevname(rdev->bdev, b),
		(unsigned long long)r10_bio->sector);
	bio = bio_clone_mddev(r10_bio->master_bio,
			      GFP_NOIO, mddev);
	bio_trim(bio, r10_bio->sector - bio->bi_iter.bi_sector, max_sectors);
	r10_bio->devs[slot].bio = bio;
	r10_bio->devs[slot].rdev = rdev;
	bio->bi_iter.bi_sector = r10_bio->devs[slot].addr
		+ choose_data_offset(r10_bio, rdev);
	bio->bi_bdev = rdev->bdev;
	bio->bi_rw = READ | do_sync;
	bio->bi_private = r10_bio;
	bio->bi_end_io = raid10_end_read_request;
	if (max_sectors < r10_bio->sectors) {
		 
		struct bio *mbio = r10_bio->master_bio;
		int sectors_handled =
			r10_bio->sector + max_sectors
			- mbio->bi_iter.bi_sector;
		r10_bio->sectors = max_sectors;
		spin_lock_irq(&conf->device_lock);
		if (mbio->bi_phys_segments == 0)
			mbio->bi_phys_segments = 2;
		else
			mbio->bi_phys_segments++;
		spin_unlock_irq(&conf->device_lock);
		generic_make_request(bio);

		r10_bio = mempool_alloc(conf->r10bio_pool,
					GFP_NOIO);
		r10_bio->master_bio = mbio;
		r10_bio->sectors = bio_sectors(mbio) - sectors_handled;
		r10_bio->state = 0;
		set_bit(R10BIO_ReadError,
			&r10_bio->state);
		r10_bio->mddev = mddev;
		r10_bio->sector = mbio->bi_iter.bi_sector
			+ sectors_handled;

		goto read_more;
	} else
		generic_make_request(bio);
}

static void handle_write_completed(struct r10conf *conf, struct r10bio *r10_bio)
{
	 
	int m;
	struct md_rdev *rdev;

	if (test_bit(R10BIO_IsSync, &r10_bio->state) ||
	    test_bit(R10BIO_IsRecover, &r10_bio->state)) {
		for (m = 0; m < conf->copies; m++) {
			int dev = r10_bio->devs[m].devnum;
			rdev = conf->mirrors[dev].rdev;
			if (r10_bio->devs[m].bio == NULL)
				continue;
			if (!r10_bio->devs[m].bio->bi_error) {
				rdev_clear_badblocks(
					rdev,
					r10_bio->devs[m].addr,
					r10_bio->sectors, 0);
			} else {
#ifdef MY_ABC_HERE
				if (IsDeviceDisappear(rdev->bdev)) {
					syno_md_error(conf->mddev, rdev);
				} else
#endif  
				if (!rdev_set_badblocks(
					    rdev,
					    r10_bio->devs[m].addr,
					    r10_bio->sectors, 0))
					md_error(conf->mddev, rdev);
			}
			rdev = conf->mirrors[dev].replacement;
			if (r10_bio->devs[m].repl_bio == NULL)
				continue;

			if (!r10_bio->devs[m].repl_bio->bi_error) {
				rdev_clear_badblocks(
					rdev,
					r10_bio->devs[m].addr,
					r10_bio->sectors, 0);
			} else {
				if (!rdev_set_badblocks(
					    rdev,
					    r10_bio->devs[m].addr,
					    r10_bio->sectors, 0))
					md_error(conf->mddev, rdev);
			}
		}
		put_buf(r10_bio);
	} else {
		bool fail = false;
		for (m = 0; m < conf->copies; m++) {
			int dev = r10_bio->devs[m].devnum;
			struct bio *bio = r10_bio->devs[m].bio;
			rdev = conf->mirrors[dev].rdev;
			if (bio == IO_MADE_GOOD) {
				rdev_clear_badblocks(
					rdev,
					r10_bio->devs[m].addr,
					r10_bio->sectors, 0);
				rdev_dec_pending(rdev, conf->mddev);
			} else if (bio != NULL && bio->bi_error) {
				fail = true;
#ifdef MY_ABC_HERE
				if (IsDeviceDisappear(rdev->bdev)) {
					syno_md_error(conf->mddev, rdev);
					set_bit(R10BIO_Degraded,
						&r10_bio->state);
				} else
#endif  
				if (!narrow_write_error(r10_bio, m)) {
					md_error(conf->mddev, rdev);
					set_bit(R10BIO_Degraded,
						&r10_bio->state);
				}
				rdev_dec_pending(rdev, conf->mddev);
			}
			bio = r10_bio->devs[m].repl_bio;
			rdev = conf->mirrors[dev].replacement;
			if (rdev && bio == IO_MADE_GOOD) {
				rdev_clear_badblocks(
					rdev,
					r10_bio->devs[m].addr,
					r10_bio->sectors, 0);
				rdev_dec_pending(rdev, conf->mddev);
			}
		}
		if (fail) {
			spin_lock_irq(&conf->device_lock);
			list_add(&r10_bio->retry_list, &conf->bio_end_io_list);
			conf->nr_queued++;
			spin_unlock_irq(&conf->device_lock);
			md_wakeup_thread(conf->mddev->thread);
		} else {
			if (test_bit(R10BIO_WriteError,
				     &r10_bio->state))
				close_write(r10_bio);
			raid_end_bio_io(r10_bio);
		}
	}
}

static void raid10d(struct md_thread *thread)
{
	struct mddev *mddev = thread->mddev;
	struct r10bio *r10_bio;
	unsigned long flags;
	struct r10conf *conf = mddev->private;
	struct list_head *head = &conf->retry_list;
	struct blk_plug plug;

	md_check_recovery(mddev);

	if (!list_empty_careful(&conf->bio_end_io_list) &&
	    !test_bit(MD_CHANGE_PENDING, &mddev->flags)) {
		LIST_HEAD(tmp);
		spin_lock_irqsave(&conf->device_lock, flags);
		if (!test_bit(MD_CHANGE_PENDING, &mddev->flags)) {
			while (!list_empty(&conf->bio_end_io_list)) {
				list_move(conf->bio_end_io_list.prev, &tmp);
				conf->nr_queued--;
			}
		}
		spin_unlock_irqrestore(&conf->device_lock, flags);
		while (!list_empty(&tmp)) {
			r10_bio = list_first_entry(&tmp, struct r10bio,
						   retry_list);
			list_del(&r10_bio->retry_list);
			if (mddev->degraded)
				set_bit(R10BIO_Degraded, &r10_bio->state);

			if (test_bit(R10BIO_WriteError,
				     &r10_bio->state))
				close_write(r10_bio);
			raid_end_bio_io(r10_bio);
		}
	}

	blk_start_plug(&plug);
	for (;;) {

		flush_pending_writes(conf);

		spin_lock_irqsave(&conf->device_lock, flags);
		if (list_empty(head)) {
			spin_unlock_irqrestore(&conf->device_lock, flags);
			break;
		}
		r10_bio = list_entry(head->prev, struct r10bio, retry_list);
		list_del(head->prev);
		conf->nr_queued--;
		spin_unlock_irqrestore(&conf->device_lock, flags);

		mddev = r10_bio->mddev;
		conf = mddev->private;
		if (test_bit(R10BIO_MadeGood, &r10_bio->state) ||
		    test_bit(R10BIO_WriteError, &r10_bio->state))
			handle_write_completed(conf, r10_bio);
		else if (test_bit(R10BIO_IsReshape, &r10_bio->state))
			reshape_request_write(mddev, r10_bio);
		else if (test_bit(R10BIO_IsSync, &r10_bio->state))
			sync_request_write(mddev, r10_bio);
		else if (test_bit(R10BIO_IsRecover, &r10_bio->state))
			recovery_request_write(mddev, r10_bio);
		else if (test_bit(R10BIO_ReadError, &r10_bio->state))
			handle_read_error(mddev, r10_bio);
		else {
			 
			int slot = r10_bio->read_slot;
			generic_make_request(r10_bio->devs[slot].bio);
		}

		cond_resched();
		if (mddev->flags & ~(1<<MD_CHANGE_PENDING))
			md_check_recovery(mddev);
	}
	blk_finish_plug(&plug);
}

static int init_resync(struct r10conf *conf)
{
	int buffs;
	int i;

	buffs = RESYNC_WINDOW / RESYNC_BLOCK_SIZE;
	BUG_ON(conf->r10buf_pool);
	conf->have_replacement = 0;
	for (i = 0; i < conf->geo.raid_disks; i++)
		if (conf->mirrors[i].replacement)
			conf->have_replacement = 1;
	conf->r10buf_pool = mempool_create(buffs, r10buf_pool_alloc, r10buf_pool_free, conf);
	if (!conf->r10buf_pool)
		return -ENOMEM;
	conf->next_resync = 0;
	return 0;
}

static sector_t sync_request(struct mddev *mddev, sector_t sector_nr,
			     int *skipped)
{
	struct r10conf *conf = mddev->private;
	struct r10bio *r10_bio;
	struct bio *biolist = NULL, *bio;
	sector_t max_sector, nr_sectors;
	int i;
	int max_sync;
#if defined(MY_ABC_HERE)
	int blStopSync = 0;
#endif  
	sector_t sync_blocks;
	sector_t sectors_skipped = 0;
	int chunks_skipped = 0;
	sector_t chunk_mask = conf->geo.chunk_mask;

	if (!conf->r10buf_pool)
		if (init_resync(conf))
			return 0;

#ifdef MY_ABC_HERE
	if (!blRaid10Enough(conf, NULL)) {
		blStopSync = 1;
	}
#endif  

#ifdef MY_ABC_HERE
	if (IsDiskErrorSet(mddev))
		blStopSync = 1;
#endif  

#if defined(MY_ABC_HERE)
	 
	if (blStopSync) {
		*skipped = 1;
		set_bit(MD_RECOVERY_INTR, &mddev->recovery);
		 
		mddev->recovery_cp = MaxSector;
	}
#endif  

	if (mddev->bitmap == NULL &&
	    mddev->recovery_cp == MaxSector &&
	    mddev->reshape_position == MaxSector &&
	    !test_bit(MD_RECOVERY_SYNC, &mddev->recovery) &&
	    !test_bit(MD_RECOVERY_REQUESTED, &mddev->recovery) &&
	    !test_bit(MD_RECOVERY_RESHAPE, &mddev->recovery) &&
	    conf->fullsync == 0) {
		*skipped = 1;
		return mddev->dev_sectors - sector_nr;
	}

 skipped:
	max_sector = mddev->dev_sectors;
	if (test_bit(MD_RECOVERY_SYNC, &mddev->recovery) ||
	    test_bit(MD_RECOVERY_RESHAPE, &mddev->recovery))
		max_sector = mddev->resync_max_sectors;
#if defined(MY_ABC_HERE)
	if (sector_nr >= max_sector || *skipped == 1) {
#else  
	if (sector_nr >= max_sector) {
#endif  
		 
		if (test_bit(MD_RECOVERY_RESHAPE, &mddev->recovery)) {
			end_reshape(conf);
			close_sync(conf);
			return 0;
		}

		if (mddev->curr_resync < max_sector) {  
			if (test_bit(MD_RECOVERY_SYNC, &mddev->recovery))
				bitmap_end_sync(mddev->bitmap, mddev->curr_resync,
						&sync_blocks, 1);
			else for (i = 0; i < conf->geo.raid_disks; i++) {
				sector_t sect =
					raid10_find_virt(conf, mddev->curr_resync, i);
				bitmap_end_sync(mddev->bitmap, sect,
						&sync_blocks, 1);
			}
		} else {
			 
			if ((!mddev->bitmap || conf->fullsync)
			    && conf->have_replacement
			    && test_bit(MD_RECOVERY_SYNC, &mddev->recovery)) {
				 
				for (i = 0; i < conf->geo.raid_disks; i++)
					if (conf->mirrors[i].replacement)
						conf->mirrors[i].replacement
							->recovery_offset
							= MaxSector;
			}
			conf->fullsync = 0;
		}
		bitmap_close_sync(mddev->bitmap);
		close_sync(conf);
		*skipped = 1;
		return sectors_skipped;
	}

	if (test_bit(MD_RECOVERY_RESHAPE, &mddev->recovery))
		return reshape_request(mddev, sector_nr, skipped);

	if (chunks_skipped >= conf->geo.raid_disks) {
		 
		*skipped = 1;
		return (max_sector - sector_nr) + sectors_skipped;
	}

	if (max_sector > mddev->resync_max)
		max_sector = mddev->resync_max;  

	if (conf->geo.near_copies < conf->geo.raid_disks &&
	    max_sector > (sector_nr | chunk_mask))
		max_sector = (sector_nr | chunk_mask) + 1;

	max_sync = RESYNC_PAGES << (PAGE_SHIFT-9);
	if (!test_bit(MD_RECOVERY_SYNC, &mddev->recovery)) {
		 
		int j;
		r10_bio = NULL;

		for (i = 0 ; i < conf->geo.raid_disks; i++) {
			int still_degraded;
			struct r10bio *rb2;
			sector_t sect;
			int must_sync;
			int any_working;
			struct raid10_info *mirror = &conf->mirrors[i];

			if ((mirror->rdev == NULL ||
			     test_bit(In_sync, &mirror->rdev->flags))
			    &&
			    (mirror->replacement == NULL ||
			     test_bit(Faulty,
				      &mirror->replacement->flags)))
				continue;

			still_degraded = 0;
			 
			rb2 = r10_bio;
			sect = raid10_find_virt(conf, sector_nr, i);
			if (sect >= mddev->resync_max_sectors) {
				 
				continue;
			}
			 
			must_sync = bitmap_start_sync(mddev->bitmap, sect,
						      &sync_blocks, 1);
			if (sync_blocks < max_sync)
				max_sync = sync_blocks;
			if (!must_sync &&
			    mirror->replacement == NULL &&
			    !conf->fullsync) {
				 
				chunks_skipped = -1;
				continue;
			}

			r10_bio = mempool_alloc(conf->r10buf_pool, GFP_NOIO);
			r10_bio->state = 0;
			raise_barrier(conf, rb2 != NULL);
			atomic_set(&r10_bio->remaining, 0);

			r10_bio->master_bio = (struct bio*)rb2;
			if (rb2)
				atomic_inc(&rb2->remaining);
			r10_bio->mddev = mddev;
			set_bit(R10BIO_IsRecover, &r10_bio->state);
			r10_bio->sector = sect;

			raid10_find_phys(conf, r10_bio);

			for (j = 0; j < conf->geo.raid_disks; j++)
				if (conf->mirrors[j].rdev == NULL ||
				    test_bit(Faulty, &conf->mirrors[j].rdev->flags)) {
					still_degraded = 1;
					break;
				}

			must_sync = bitmap_start_sync(mddev->bitmap, sect,
						      &sync_blocks, still_degraded);

			any_working = 0;
			for (j=0; j<conf->copies;j++) {
				int k;
				int d = r10_bio->devs[j].devnum;
				sector_t from_addr, to_addr;
				struct md_rdev *rdev;
				sector_t sector, first_bad;
				int bad_sectors;
				if (!conf->mirrors[d].rdev ||
				    !test_bit(In_sync, &conf->mirrors[d].rdev->flags))
					continue;
				 
				any_working = 1;
				rdev = conf->mirrors[d].rdev;
				sector = r10_bio->devs[j].addr;

				if (is_badblock(rdev, sector, max_sync,
						&first_bad, &bad_sectors)) {
					if (first_bad > sector)
						max_sync = first_bad - sector;
					else {
						bad_sectors -= (sector
								- first_bad);
						if (max_sync > bad_sectors)
							max_sync = bad_sectors;
						continue;
					}
				}
				bio = r10_bio->devs[0].bio;
				bio_reset(bio);
				bio->bi_next = biolist;
				biolist = bio;
				bio->bi_private = r10_bio;
				bio->bi_end_io = end_sync_read;
				bio->bi_rw = READ;
				from_addr = r10_bio->devs[j].addr;
				bio->bi_iter.bi_sector = from_addr +
					rdev->data_offset;
				bio->bi_bdev = rdev->bdev;
				atomic_inc(&rdev->nr_pending);
				 
				for (k=0; k<conf->copies; k++)
					if (r10_bio->devs[k].devnum == i)
						break;
				BUG_ON(k == conf->copies);
				to_addr = r10_bio->devs[k].addr;
				r10_bio->devs[0].devnum = d;
				r10_bio->devs[0].addr = from_addr;
				r10_bio->devs[1].devnum = i;
				r10_bio->devs[1].addr = to_addr;

				rdev = mirror->rdev;
				if (!test_bit(In_sync, &rdev->flags)) {
					bio = r10_bio->devs[1].bio;
					bio_reset(bio);
					bio->bi_next = biolist;
					biolist = bio;
					bio->bi_private = r10_bio;
					bio->bi_end_io = end_sync_write;
					bio->bi_rw = WRITE;
					bio->bi_iter.bi_sector = to_addr
						+ rdev->data_offset;
					bio->bi_bdev = rdev->bdev;
					atomic_inc(&r10_bio->remaining);
				} else
					r10_bio->devs[1].bio->bi_end_io = NULL;

				bio = r10_bio->devs[1].repl_bio;
				if (bio)
					bio->bi_end_io = NULL;
				rdev = mirror->replacement;
				 
				if (rdev == NULL || bio == NULL ||
				    test_bit(Faulty, &rdev->flags))
					break;
				bio_reset(bio);
				bio->bi_next = biolist;
				biolist = bio;
				bio->bi_private = r10_bio;
				bio->bi_end_io = end_sync_write;
				bio->bi_rw = WRITE;
				bio->bi_iter.bi_sector = to_addr +
					rdev->data_offset;
				bio->bi_bdev = rdev->bdev;
				atomic_inc(&r10_bio->remaining);
				break;
			}
			if (j == conf->copies) {
				 
				if (any_working) {
					 
					int k;
					for (k = 0; k < conf->copies; k++)
						if (r10_bio->devs[k].devnum == i)
							break;
					if (!test_bit(In_sync,
						      &mirror->rdev->flags)
					    && !rdev_set_badblocks(
						    mirror->rdev,
						    r10_bio->devs[k].addr,
						    max_sync, 0))
						any_working = 0;
					if (mirror->replacement &&
					    !rdev_set_badblocks(
						    mirror->replacement,
						    r10_bio->devs[k].addr,
						    max_sync, 0))
						any_working = 0;
				}
				if (!any_working)  {
					if (!test_and_set_bit(MD_RECOVERY_INTR,
							      &mddev->recovery))
						printk(KERN_INFO "md/raid10:%s: insufficient "
						       "working devices for recovery.\n",
						       mdname(mddev));
					mirror->recovery_disabled
						= mddev->recovery_disabled;
				}
				put_buf(r10_bio);
				if (rb2)
					atomic_dec(&rb2->remaining);
				r10_bio = rb2;
				break;
			}
		}
		if (biolist == NULL) {
			while (r10_bio) {
				struct r10bio *rb2 = r10_bio;
				r10_bio = (struct r10bio*) rb2->master_bio;
				rb2->master_bio = NULL;
				put_buf(rb2);
			}
			goto giveup;
		}
	} else {
		 
		int count = 0;

		bitmap_cond_end_sync(mddev->bitmap, sector_nr, 0);

		if (!bitmap_start_sync(mddev->bitmap, sector_nr,
				       &sync_blocks, mddev->degraded) &&
		    !conf->fullsync && !test_bit(MD_RECOVERY_REQUESTED,
						 &mddev->recovery)) {
			 
			*skipped = 1;
			return sync_blocks + sectors_skipped;
		}
		if (sync_blocks < max_sync)
			max_sync = sync_blocks;
		r10_bio = mempool_alloc(conf->r10buf_pool, GFP_NOIO);
		r10_bio->state = 0;

		r10_bio->mddev = mddev;
		atomic_set(&r10_bio->remaining, 0);
		raise_barrier(conf, 0);
		conf->next_resync = sector_nr;

		r10_bio->master_bio = NULL;
		r10_bio->sector = sector_nr;
		set_bit(R10BIO_IsSync, &r10_bio->state);
		raid10_find_phys(conf, r10_bio);
		r10_bio->sectors = (sector_nr | chunk_mask) - sector_nr + 1;

		for (i = 0; i < conf->copies; i++) {
			int d = r10_bio->devs[i].devnum;
			sector_t first_bad, sector;
			int bad_sectors;

			if (r10_bio->devs[i].repl_bio)
				r10_bio->devs[i].repl_bio->bi_end_io = NULL;

			bio = r10_bio->devs[i].bio;
			bio_reset(bio);
			bio->bi_error = -EIO;
			if (conf->mirrors[d].rdev == NULL ||
			    test_bit(Faulty, &conf->mirrors[d].rdev->flags))
				continue;
			sector = r10_bio->devs[i].addr;
			if (is_badblock(conf->mirrors[d].rdev,
					sector, max_sync,
					&first_bad, &bad_sectors)) {
				if (first_bad > sector)
					max_sync = first_bad - sector;
				else {
					bad_sectors -= (sector - first_bad);
					if (max_sync > bad_sectors)
						max_sync = bad_sectors;
					continue;
				}
			}
			atomic_inc(&conf->mirrors[d].rdev->nr_pending);
			atomic_inc(&r10_bio->remaining);
			bio->bi_next = biolist;
			biolist = bio;
			bio->bi_private = r10_bio;
			bio->bi_end_io = end_sync_read;
			bio->bi_rw = READ;
			bio->bi_iter.bi_sector = sector +
				conf->mirrors[d].rdev->data_offset;
			bio->bi_bdev = conf->mirrors[d].rdev->bdev;
			count++;

			if (conf->mirrors[d].replacement == NULL ||
			    test_bit(Faulty,
				     &conf->mirrors[d].replacement->flags))
				continue;

			bio = r10_bio->devs[i].repl_bio;
			bio_reset(bio);
			bio->bi_error = -EIO;

			sector = r10_bio->devs[i].addr;
			atomic_inc(&conf->mirrors[d].rdev->nr_pending);
			bio->bi_next = biolist;
			biolist = bio;
			bio->bi_private = r10_bio;
			bio->bi_end_io = end_sync_write;
			bio->bi_rw = WRITE;
			bio->bi_iter.bi_sector = sector +
				conf->mirrors[d].replacement->data_offset;
			bio->bi_bdev = conf->mirrors[d].replacement->bdev;
			count++;
		}

		if (count < 2) {
			for (i=0; i<conf->copies; i++) {
				int d = r10_bio->devs[i].devnum;
				if (r10_bio->devs[i].bio->bi_end_io)
					rdev_dec_pending(conf->mirrors[d].rdev,
							 mddev);
				if (r10_bio->devs[i].repl_bio &&
				    r10_bio->devs[i].repl_bio->bi_end_io)
					rdev_dec_pending(
						conf->mirrors[d].replacement,
						mddev);
			}
			put_buf(r10_bio);
			biolist = NULL;
			goto giveup;
		}
	}

	nr_sectors = 0;
	if (sector_nr + max_sync < max_sector)
		max_sector = sector_nr + max_sync;
	do {
		struct page *page;
		int len = PAGE_SIZE;
		if (sector_nr + (len>>9) > max_sector)
			len = (max_sector - sector_nr) << 9;
		if (len == 0)
			break;
		for (bio= biolist ; bio ; bio=bio->bi_next) {
			struct bio *bio2;
			page = bio->bi_io_vec[bio->bi_vcnt].bv_page;
			if (bio_add_page(bio, page, len, 0))
				continue;

			bio->bi_io_vec[bio->bi_vcnt].bv_page = page;
			for (bio2 = biolist;
			     bio2 && bio2 != bio;
			     bio2 = bio2->bi_next) {
				 
				bio2->bi_vcnt--;
				bio2->bi_iter.bi_size -= len;
				bio_clear_flag(bio2, BIO_SEG_VALID);
			}
			goto bio_full;
		}
		nr_sectors += len>>9;
		sector_nr += len>>9;
	} while (biolist->bi_vcnt < RESYNC_PAGES);
 bio_full:
	r10_bio->sectors = nr_sectors;

	while (biolist) {
		bio = biolist;
		biolist = biolist->bi_next;

		bio->bi_next = NULL;
		r10_bio = bio->bi_private;
		r10_bio->sectors = nr_sectors;

		if (bio->bi_end_io == end_sync_read) {
			md_sync_acct(bio->bi_bdev, nr_sectors);
			bio->bi_error = 0;
			generic_make_request(bio);
		}
	}

	if (sectors_skipped)
		 
		md_done_sync(mddev, sectors_skipped, 1);

	return sectors_skipped + nr_sectors;
 giveup:
	 
	if (sector_nr + max_sync < max_sector)
		max_sector = sector_nr + max_sync;

	sectors_skipped += (max_sector - sector_nr);
	chunks_skipped ++;
	sector_nr = max_sector;
	goto skipped;
}

static sector_t
raid10_size(struct mddev *mddev, sector_t sectors, int raid_disks)
{
	sector_t size;
	struct r10conf *conf = mddev->private;

	if (!raid_disks)
		raid_disks = min(conf->geo.raid_disks,
				 conf->prev.raid_disks);
	if (!sectors)
		sectors = conf->dev_sectors;

	size = sectors >> conf->geo.chunk_shift;
	sector_div(size, conf->geo.far_copies);
	size = size * raid_disks;
	sector_div(size, conf->geo.near_copies);

	return size << conf->geo.chunk_shift;
}

static void calc_sectors(struct r10conf *conf, sector_t size)
{
	 
	size = size >> conf->geo.chunk_shift;
	sector_div(size, conf->geo.far_copies);
	size = size * conf->geo.raid_disks;
	sector_div(size, conf->geo.near_copies);
	 
	size = size * conf->copies;

	size = DIV_ROUND_UP_SECTOR_T(size, conf->geo.raid_disks);

	conf->dev_sectors = size << conf->geo.chunk_shift;

	if (conf->geo.far_offset)
		conf->geo.stride = 1 << conf->geo.chunk_shift;
	else {
		sector_div(size, conf->geo.far_copies);
		conf->geo.stride = size << conf->geo.chunk_shift;
	}
}

enum geo_type {geo_new, geo_old, geo_start};
static int setup_geo(struct geom *geo, struct mddev *mddev, enum geo_type new)
{
	int nc, fc, fo;
	int layout, chunk, disks;
	switch (new) {
	case geo_old:
		layout = mddev->layout;
		chunk = mddev->chunk_sectors;
		disks = mddev->raid_disks - mddev->delta_disks;
		break;
	case geo_new:
		layout = mddev->new_layout;
		chunk = mddev->new_chunk_sectors;
		disks = mddev->raid_disks;
		break;
	default:  
	case geo_start:  
		layout = mddev->new_layout;
		chunk = mddev->new_chunk_sectors;
		disks = mddev->raid_disks + mddev->delta_disks;
		break;
	}
	if (layout >> 19)
		return -1;
	if (chunk < (PAGE_SIZE >> 9) ||
	    !is_power_of_2(chunk))
		return -2;
	nc = layout & 255;
	fc = (layout >> 8) & 255;
	fo = layout & (1<<16);
	geo->raid_disks = disks;
	geo->near_copies = nc;
	geo->far_copies = fc;
	geo->far_offset = fo;
	switch (layout >> 17) {
	case 0:	 
		geo->far_set_size = disks;
		break;
	case 1:  
		geo->far_set_size = disks/fc;
		WARN(geo->far_set_size < fc,
		     "This RAID10 layout does not provide data safety - please backup and create new array\n");
		break;
	case 2:  
		geo->far_set_size = fc * nc;
		break;
	default:  
		return -1;
	}
	geo->chunk_mask = chunk - 1;
	geo->chunk_shift = ffz(~chunk);
	return nc*fc;
}

static struct r10conf *setup_conf(struct mddev *mddev)
{
	struct r10conf *conf = NULL;
	int err = -EINVAL;
	struct geom geo;
	int copies;

	copies = setup_geo(&geo, mddev, geo_new);

	if (copies == -2) {
		printk(KERN_ERR "md/raid10:%s: chunk size must be "
		       "at least PAGE_SIZE(%ld) and be a power of 2.\n",
		       mdname(mddev), PAGE_SIZE);
		goto out;
	}

	if (copies < 2 || copies > mddev->raid_disks) {
		printk(KERN_ERR "md/raid10:%s: unsupported raid10 layout: 0x%8x\n",
		       mdname(mddev), mddev->new_layout);
		goto out;
	}

	err = -ENOMEM;
	conf = kzalloc(sizeof(struct r10conf), GFP_KERNEL);
	if (!conf)
		goto out;

	conf->mirrors = kzalloc(sizeof(struct raid10_info)*(mddev->raid_disks +
							    max(0,-mddev->delta_disks)),
				GFP_KERNEL);
	if (!conf->mirrors)
		goto out;

	conf->tmppage = alloc_page(GFP_KERNEL);
	if (!conf->tmppage)
		goto out;

	conf->geo = geo;
	conf->copies = copies;
	conf->r10bio_pool = mempool_create(NR_RAID10_BIOS, r10bio_pool_alloc,
					   r10bio_pool_free, conf);
	if (!conf->r10bio_pool)
		goto out;

	calc_sectors(conf, mddev->dev_sectors);
	if (mddev->reshape_position == MaxSector) {
		conf->prev = conf->geo;
		conf->reshape_progress = MaxSector;
	} else {
		if (setup_geo(&conf->prev, mddev, geo_old) != conf->copies) {
			err = -EINVAL;
			goto out;
		}
		conf->reshape_progress = mddev->reshape_position;
		if (conf->prev.far_offset)
			conf->prev.stride = 1 << conf->prev.chunk_shift;
		else
			 
			conf->prev.stride = conf->dev_sectors;
	}
	conf->reshape_safe = conf->reshape_progress;
	spin_lock_init(&conf->device_lock);
	INIT_LIST_HEAD(&conf->retry_list);
	INIT_LIST_HEAD(&conf->bio_end_io_list);

	spin_lock_init(&conf->resync_lock);
	init_waitqueue_head(&conf->wait_barrier);

	conf->thread = md_register_thread(raid10d, mddev, "raid10");
	if (!conf->thread)
		goto out;

	conf->mddev = mddev;
	return conf;

 out:
	if (err == -ENOMEM)
		printk(KERN_ERR "md/raid10:%s: couldn't allocate memory.\n",
		       mdname(mddev));
	if (conf) {
		mempool_destroy(conf->r10bio_pool);
		kfree(conf->mirrors);
		safe_put_page(conf->tmppage);
		kfree(conf);
	}
	return ERR_PTR(err);
}

static int run(struct mddev *mddev)
{
	struct r10conf *conf;
	int i, disk_idx, chunk_size;
	struct raid10_info *disk;
	struct md_rdev *rdev;
	sector_t size;
	sector_t min_offset_diff = 0;
	int first = 1;
	bool discard_supported = false;

	if (mddev->private == NULL) {
		conf = setup_conf(mddev);
		if (IS_ERR(conf))
			return PTR_ERR(conf);
		mddev->private = conf;
	}
	conf = mddev->private;
	if (!conf)
		goto out;

	mddev->thread = conf->thread;
	conf->thread = NULL;

	chunk_size = mddev->chunk_sectors << 9;
	if (mddev->queue) {
		blk_queue_max_discard_sectors(mddev->queue,
					      mddev->chunk_sectors);
		blk_queue_max_write_same_sectors(mddev->queue, 0);
		blk_queue_io_min(mddev->queue, chunk_size);
		if (conf->geo.raid_disks % conf->geo.near_copies)
			blk_queue_io_opt(mddev->queue, chunk_size * conf->geo.raid_disks);
		else
			blk_queue_io_opt(mddev->queue, chunk_size *
					 (conf->geo.raid_disks / conf->geo.near_copies));
	}

	rdev_for_each(rdev, mddev) {
		long long diff;
		struct request_queue *q;

		disk_idx = rdev->raid_disk;
		if (disk_idx < 0)
			continue;
		if (disk_idx >= conf->geo.raid_disks &&
		    disk_idx >= conf->prev.raid_disks)
			continue;
		disk = conf->mirrors + disk_idx;

		if (test_bit(Replacement, &rdev->flags)) {
			if (disk->replacement)
				goto out_free_conf;
			disk->replacement = rdev;
		} else {
			if (disk->rdev)
				goto out_free_conf;
			disk->rdev = rdev;
		}
		q = bdev_get_queue(rdev->bdev);
		diff = (rdev->new_data_offset - rdev->data_offset);
		if (!mddev->reshape_backwards)
			diff = -diff;
		if (diff < 0)
			diff = 0;
		if (first || diff < min_offset_diff)
			min_offset_diff = diff;

		if (mddev->gendisk)
			disk_stack_limits(mddev->gendisk, rdev->bdev,
					  rdev->data_offset << 9);

		disk->head_position = 0;

		if (blk_queue_discard(bdev_get_queue(rdev->bdev)))
			discard_supported = true;
	}

	if (mddev->queue) {
		if (discard_supported)
			queue_flag_set_unlocked(QUEUE_FLAG_DISCARD,
						mddev->queue);
		else
			queue_flag_clear_unlocked(QUEUE_FLAG_DISCARD,
						  mddev->queue);
	}
	 
#if defined(MY_ABC_HERE)
	 
	if (!blRaid10Enough(conf, NULL)) {
#else  
	if (!enough(conf, -1)) {
#endif  
#ifdef MY_ABC_HERE
		mddev->nodev_and_crashed = 1;
#endif  
		printk(KERN_ERR "md/raid10:%s: not enough operational mirrors.\n",
		       mdname(mddev));
#ifdef MY_ABC_HERE
		 
#else  
		goto out_free_conf;
#endif  
	}

	if (conf->reshape_progress != MaxSector) {
		 
		if (conf->geo.far_copies != 1 &&
		    conf->geo.far_offset == 0)
			goto out_free_conf;
		if (conf->prev.far_copies != 1 &&
		    conf->prev.far_offset == 0)
			goto out_free_conf;
	}

	mddev->degraded = 0;
	for (i = 0;
	     i < conf->geo.raid_disks
		     || i < conf->prev.raid_disks;
	     i++) {

		disk = conf->mirrors + i;

		if (!disk->rdev && disk->replacement) {
			 
			disk->rdev = disk->replacement;
			disk->replacement = NULL;
			clear_bit(Replacement, &disk->rdev->flags);
		}

		if (!disk->rdev ||
		    !test_bit(In_sync, &disk->rdev->flags)) {
			disk->head_position = 0;
			mddev->degraded++;
			if (disk->rdev &&
			    disk->rdev->saved_raid_disk < 0)
				conf->fullsync = 1;
		}
		disk->recovery_disabled = mddev->recovery_disabled - 1;
	}

	if (mddev->recovery_cp != MaxSector)
		printk(KERN_NOTICE "md/raid10:%s: not clean"
		       " -- starting background reconstruction\n",
		       mdname(mddev));
	printk(KERN_INFO
		"md/raid10:%s: active with %d out of %d devices\n",
		mdname(mddev), conf->geo.raid_disks - mddev->degraded,
		conf->geo.raid_disks);
	 
	mddev->dev_sectors = conf->dev_sectors;
	size = raid10_size(mddev, 0, 0);
	md_set_array_sectors(mddev, size);
	mddev->resync_max_sectors = size;

	if (mddev->queue) {
		int stripe = conf->geo.raid_disks *
			((mddev->chunk_sectors << 9) / PAGE_SIZE);

		stripe /= conf->geo.near_copies;
		if (mddev->queue->backing_dev_info.ra_pages < 2 * stripe)
			mddev->queue->backing_dev_info.ra_pages = 2 * stripe;
	}

	if (md_integrity_register(mddev))
		goto out_free_conf;

	if (conf->reshape_progress != MaxSector) {
		unsigned long before_length, after_length;

		before_length = ((1 << conf->prev.chunk_shift) *
				 conf->prev.far_copies);
		after_length = ((1 << conf->geo.chunk_shift) *
				conf->geo.far_copies);

		if (max(before_length, after_length) > min_offset_diff) {
			 
			printk("md/raid10: offset difference not enough to continue reshape\n");
			goto out_free_conf;
		}
		conf->offset_diff = min_offset_diff;

		clear_bit(MD_RECOVERY_SYNC, &mddev->recovery);
		clear_bit(MD_RECOVERY_CHECK, &mddev->recovery);
		set_bit(MD_RECOVERY_RESHAPE, &mddev->recovery);
		set_bit(MD_RECOVERY_RUNNING, &mddev->recovery);
		mddev->sync_thread = md_register_thread(md_do_sync, mddev,
							"reshape");
	}

	return 0;

out_free_conf:
	md_unregister_thread(&mddev->thread);
	mempool_destroy(conf->r10bio_pool);
	safe_put_page(conf->tmppage);
	kfree(conf->mirrors);
	kfree(conf);
	mddev->private = NULL;
out:
	return -EIO;
}

static void raid10_free(struct mddev *mddev, void *priv)
{
	struct r10conf *conf = priv;

	mempool_destroy(conf->r10bio_pool);
	safe_put_page(conf->tmppage);
	kfree(conf->mirrors);
	kfree(conf->mirrors_old);
	kfree(conf->mirrors_new);
	kfree(conf);
}

static void raid10_quiesce(struct mddev *mddev, int state)
{
	struct r10conf *conf = mddev->private;

	switch(state) {
	case 1:
		raise_barrier(conf, 0);
		break;
	case 0:
		lower_barrier(conf);
		break;
	}
}

static int raid10_resize(struct mddev *mddev, sector_t sectors)
{
	 
	struct r10conf *conf = mddev->private;
	sector_t oldsize, size;

	if (mddev->reshape_position != MaxSector)
		return -EBUSY;

	if (conf->geo.far_copies > 1 && !conf->geo.far_offset)
		return -EINVAL;

	oldsize = raid10_size(mddev, 0, 0);
	size = raid10_size(mddev, sectors, 0);
	if (mddev->external_size &&
	    mddev->array_sectors > size)
		return -EINVAL;
	if (mddev->bitmap) {
		int ret = bitmap_resize(mddev->bitmap, size, 0, 0);
		if (ret)
			return ret;
	}
	md_set_array_sectors(mddev, size);
	set_capacity(mddev->gendisk, mddev->array_sectors);
	revalidate_disk(mddev->gendisk);
	if (sectors > mddev->dev_sectors &&
	    mddev->recovery_cp > oldsize) {
		mddev->recovery_cp = oldsize;
		set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
	}
	calc_sectors(conf, sectors);
	mddev->dev_sectors = conf->dev_sectors;
	mddev->resync_max_sectors = size;
	return 0;
}

static void *raid10_takeover_raid0(struct mddev *mddev, sector_t size, int devs)
{
	struct md_rdev *rdev;
	struct r10conf *conf;

	if (mddev->degraded > 0) {
		printk(KERN_ERR "md/raid10:%s: Error: degraded raid0!\n",
		       mdname(mddev));
		return ERR_PTR(-EINVAL);
	}
	sector_div(size, devs);

	mddev->new_level = 10;
	 
	mddev->new_layout = (1<<8) + 2;
	mddev->new_chunk_sectors = mddev->chunk_sectors;
	mddev->delta_disks = mddev->raid_disks;
	mddev->raid_disks *= 2;
	 
	mddev->recovery_cp = MaxSector;
	mddev->dev_sectors = size;

	conf = setup_conf(mddev);
	if (!IS_ERR(conf)) {
		rdev_for_each(rdev, mddev)
			if (rdev->raid_disk >= 0) {
				rdev->new_raid_disk = rdev->raid_disk * 2;
				rdev->sectors = size;
			}
		conf->barrier = 1;
	}

	return conf;
}

static void *raid10_takeover(struct mddev *mddev)
{
	struct r0conf *raid0_conf;

	if (mddev->level == 0) {
		 
		raid0_conf = mddev->private;
		if (raid0_conf->nr_strip_zones > 1) {
			printk(KERN_ERR "md/raid10:%s: cannot takeover raid 0"
			       " with more than one zone.\n",
			       mdname(mddev));
			return ERR_PTR(-EINVAL);
		}
		return raid10_takeover_raid0(mddev,
			raid0_conf->strip_zone->zone_end,
			raid0_conf->strip_zone->nb_dev);
	}
	return ERR_PTR(-EINVAL);
}

static int raid10_check_reshape(struct mddev *mddev)
{
	 
	struct r10conf *conf = mddev->private;
	struct geom geo;

	if (conf->geo.far_copies != 1 && !conf->geo.far_offset)
		return -EINVAL;

	if (setup_geo(&geo, mddev, geo_start) != conf->copies)
		 
		return -EINVAL;
	if (geo.far_copies > 1 && !geo.far_offset)
		 
		return -EINVAL;

	if (mddev->array_sectors & geo.chunk_mask)
			 
			return -EINVAL;

	if (!enough(conf, -1))
		return -EINVAL;

	kfree(conf->mirrors_new);
	conf->mirrors_new = NULL;
	if (mddev->delta_disks > 0) {
		 
		conf->mirrors_new = kzalloc(
			sizeof(struct raid10_info)
			*(mddev->raid_disks +
			  mddev->delta_disks),
			GFP_KERNEL);
		if (!conf->mirrors_new)
			return -ENOMEM;
	}
	return 0;
}

static int calc_degraded(struct r10conf *conf)
{
	int degraded, degraded2;
	int i;

	rcu_read_lock();
	degraded = 0;
	 
	for (i = 0; i < conf->prev.raid_disks; i++) {
		struct md_rdev *rdev = rcu_dereference(conf->mirrors[i].rdev);
		if (!rdev || test_bit(Faulty, &rdev->flags))
			degraded++;
		else if (!test_bit(In_sync, &rdev->flags))
			 
			degraded++;
	}
	rcu_read_unlock();
	if (conf->geo.raid_disks == conf->prev.raid_disks)
		return degraded;
	rcu_read_lock();
	degraded2 = 0;
	for (i = 0; i < conf->geo.raid_disks; i++) {
		struct md_rdev *rdev = rcu_dereference(conf->mirrors[i].rdev);
		if (!rdev || test_bit(Faulty, &rdev->flags))
			degraded2++;
		else if (!test_bit(In_sync, &rdev->flags)) {
			 
			if (conf->geo.raid_disks <= conf->prev.raid_disks)
				degraded2++;
		}
	}
	rcu_read_unlock();
	if (degraded2 > degraded)
		return degraded2;
	return degraded;
}

static int raid10_start_reshape(struct mddev *mddev)
{
	 
	unsigned long before_length, after_length;
	sector_t min_offset_diff = 0;
	int first = 1;
	struct geom new;
	struct r10conf *conf = mddev->private;
	struct md_rdev *rdev;
	int spares = 0;
	int ret;

	if (test_bit(MD_RECOVERY_RUNNING, &mddev->recovery))
		return -EBUSY;

	if (setup_geo(&new, mddev, geo_start) != conf->copies)
		return -EINVAL;

	before_length = ((1 << conf->prev.chunk_shift) *
			 conf->prev.far_copies);
	after_length = ((1 << conf->geo.chunk_shift) *
			conf->geo.far_copies);

	rdev_for_each(rdev, mddev) {
		if (!test_bit(In_sync, &rdev->flags)
		    && !test_bit(Faulty, &rdev->flags))
			spares++;
		if (rdev->raid_disk >= 0) {
			long long diff = (rdev->new_data_offset
					  - rdev->data_offset);
			if (!mddev->reshape_backwards)
				diff = -diff;
			if (diff < 0)
				diff = 0;
			if (first || diff < min_offset_diff)
				min_offset_diff = diff;
		}
	}

	if (max(before_length, after_length) > min_offset_diff)
		return -EINVAL;

	if (spares < mddev->delta_disks)
		return -EINVAL;

	conf->offset_diff = min_offset_diff;
	spin_lock_irq(&conf->device_lock);
	if (conf->mirrors_new) {
		memcpy(conf->mirrors_new, conf->mirrors,
		       sizeof(struct raid10_info)*conf->prev.raid_disks);
		smp_mb();
		kfree(conf->mirrors_old);
		conf->mirrors_old = conf->mirrors;
		conf->mirrors = conf->mirrors_new;
		conf->mirrors_new = NULL;
	}
	setup_geo(&conf->geo, mddev, geo_start);
	smp_mb();
	if (mddev->reshape_backwards) {
		sector_t size = raid10_size(mddev, 0, 0);
		if (size < mddev->array_sectors) {
			spin_unlock_irq(&conf->device_lock);
			printk(KERN_ERR "md/raid10:%s: array size must be reduce before number of disks\n",
			       mdname(mddev));
			return -EINVAL;
		}
		mddev->resync_max_sectors = size;
		conf->reshape_progress = size;
	} else
		conf->reshape_progress = 0;
	conf->reshape_safe = conf->reshape_progress;
	spin_unlock_irq(&conf->device_lock);

	if (mddev->delta_disks && mddev->bitmap) {
		ret = bitmap_resize(mddev->bitmap,
				    raid10_size(mddev, 0,
						conf->geo.raid_disks),
				    0, 0);
		if (ret)
			goto abort;
	}
	if (mddev->delta_disks > 0) {
		rdev_for_each(rdev, mddev)
			if (rdev->raid_disk < 0 &&
			    !test_bit(Faulty, &rdev->flags)) {
				if (raid10_add_disk(mddev, rdev) == 0) {
					if (rdev->raid_disk >=
					    conf->prev.raid_disks)
						set_bit(In_sync, &rdev->flags);
					else
						rdev->recovery_offset = 0;

					if (sysfs_link_rdev(mddev, rdev))
						 ;
				}
			} else if (rdev->raid_disk >= conf->prev.raid_disks
				   && !test_bit(Faulty, &rdev->flags)) {
				 
				set_bit(In_sync, &rdev->flags);
			}
	}
	 
	spin_lock_irq(&conf->device_lock);
	mddev->degraded = calc_degraded(conf);
	spin_unlock_irq(&conf->device_lock);
	mddev->raid_disks = conf->geo.raid_disks;
	mddev->reshape_position = conf->reshape_progress;
	set_bit(MD_CHANGE_DEVS, &mddev->flags);

	clear_bit(MD_RECOVERY_SYNC, &mddev->recovery);
	clear_bit(MD_RECOVERY_CHECK, &mddev->recovery);
	clear_bit(MD_RECOVERY_DONE, &mddev->recovery);
	set_bit(MD_RECOVERY_RESHAPE, &mddev->recovery);
	set_bit(MD_RECOVERY_RUNNING, &mddev->recovery);

	mddev->sync_thread = md_register_thread(md_do_sync, mddev,
						"reshape");
	if (!mddev->sync_thread) {
		ret = -EAGAIN;
		goto abort;
	}
	conf->reshape_checkpoint = jiffies;
	md_wakeup_thread(mddev->sync_thread);
	md_new_event(mddev);
	return 0;

abort:
	mddev->recovery = 0;
	spin_lock_irq(&conf->device_lock);
	conf->geo = conf->prev;
	mddev->raid_disks = conf->geo.raid_disks;
	rdev_for_each(rdev, mddev)
		rdev->new_data_offset = rdev->data_offset;
	smp_wmb();
	conf->reshape_progress = MaxSector;
	conf->reshape_safe = MaxSector;
	mddev->reshape_position = MaxSector;
	spin_unlock_irq(&conf->device_lock);
	return ret;
}

static sector_t last_dev_address(sector_t s, struct geom *geo)
{
	s = (s | geo->chunk_mask) + 1;
	s >>= geo->chunk_shift;
	s *= geo->near_copies;
	s = DIV_ROUND_UP_SECTOR_T(s, geo->raid_disks);
	s *= geo->far_copies;
	s <<= geo->chunk_shift;
	return s;
}

static sector_t first_dev_address(sector_t s, struct geom *geo)
{
	s >>= geo->chunk_shift;
	s *= geo->near_copies;
	sector_div(s, geo->raid_disks);
	s *= geo->far_copies;
	s <<= geo->chunk_shift;
	return s;
}

static sector_t reshape_request(struct mddev *mddev, sector_t sector_nr,
				int *skipped)
{
	 
	struct r10conf *conf = mddev->private;
	struct r10bio *r10_bio;
	sector_t next, safe, last;
	int max_sectors;
	int nr_sectors;
	int s;
	struct md_rdev *rdev;
	int need_flush = 0;
	struct bio *blist;
	struct bio *bio, *read_bio;
	int sectors_done = 0;

	if (sector_nr == 0) {
		 
		if (mddev->reshape_backwards &&
		    conf->reshape_progress < raid10_size(mddev, 0, 0)) {
			sector_nr = (raid10_size(mddev, 0, 0)
				     - conf->reshape_progress);
		} else if (!mddev->reshape_backwards &&
			   conf->reshape_progress > 0)
			sector_nr = conf->reshape_progress;
		if (sector_nr) {
			mddev->curr_resync_completed = sector_nr;
			sysfs_notify(&mddev->kobj, NULL, "sync_completed");
			*skipped = 1;
			return sector_nr;
		}
	}

	if (mddev->reshape_backwards) {
		 
		next = first_dev_address(conf->reshape_progress - 1,
					 &conf->geo);

		safe = last_dev_address(conf->reshape_safe - 1,
					&conf->prev);

		if (next + conf->offset_diff < safe)
			need_flush = 1;

		last = conf->reshape_progress - 1;
		sector_nr = last & ~(sector_t)(conf->geo.chunk_mask
					       & conf->prev.chunk_mask);
		if (sector_nr + RESYNC_BLOCK_SIZE/512 < last)
			sector_nr = last + 1 - RESYNC_BLOCK_SIZE/512;
	} else {
		 
		next = last_dev_address(conf->reshape_progress, &conf->geo);

		safe = first_dev_address(conf->reshape_safe, &conf->prev);

		if (next > safe + conf->offset_diff)
			need_flush = 1;

		sector_nr = conf->reshape_progress;
		last  = sector_nr | (conf->geo.chunk_mask
				     & conf->prev.chunk_mask);

		if (sector_nr + RESYNC_BLOCK_SIZE/512 <= last)
			last = sector_nr + RESYNC_BLOCK_SIZE/512 - 1;
	}

	if (need_flush ||
	    time_after(jiffies, conf->reshape_checkpoint + 10*HZ)) {
		 
		wait_barrier(conf);
		mddev->reshape_position = conf->reshape_progress;
		if (mddev->reshape_backwards)
			mddev->curr_resync_completed = raid10_size(mddev, 0, 0)
				- conf->reshape_progress;
		else
			mddev->curr_resync_completed = conf->reshape_progress;
		conf->reshape_checkpoint = jiffies;
		set_bit(MD_CHANGE_DEVS, &mddev->flags);
		md_wakeup_thread(mddev->thread);
		wait_event(mddev->sb_wait, mddev->flags == 0 ||
			   test_bit(MD_RECOVERY_INTR, &mddev->recovery));
		if (test_bit(MD_RECOVERY_INTR, &mddev->recovery)) {
			allow_barrier(conf);
			return sectors_done;
		}
		conf->reshape_safe = mddev->reshape_position;
		allow_barrier(conf);
	}

read_more:
	 
	r10_bio = mempool_alloc(conf->r10buf_pool, GFP_NOIO);
	r10_bio->state = 0;
	raise_barrier(conf, sectors_done != 0);
	atomic_set(&r10_bio->remaining, 0);
	r10_bio->mddev = mddev;
	r10_bio->sector = sector_nr;
	set_bit(R10BIO_IsReshape, &r10_bio->state);
	r10_bio->sectors = last - sector_nr + 1;
	rdev = read_balance(conf, r10_bio, &max_sectors);
	BUG_ON(!test_bit(R10BIO_Previous, &r10_bio->state));

	if (!rdev) {
		 
		mempool_free(r10_bio, conf->r10buf_pool);
		set_bit(MD_RECOVERY_INTR, &mddev->recovery);
		return sectors_done;
	}

	read_bio = bio_alloc_mddev(GFP_KERNEL, RESYNC_PAGES, mddev);

	read_bio->bi_bdev = rdev->bdev;
	read_bio->bi_iter.bi_sector = (r10_bio->devs[r10_bio->read_slot].addr
			       + rdev->data_offset);
	read_bio->bi_private = r10_bio;
	read_bio->bi_end_io = end_sync_read;
	read_bio->bi_rw = READ;
	read_bio->bi_flags &= (~0UL << BIO_RESET_BITS);
	read_bio->bi_error = 0;
	read_bio->bi_vcnt = 0;
	read_bio->bi_iter.bi_size = 0;
	r10_bio->master_bio = read_bio;
	r10_bio->read_slot = r10_bio->devs[r10_bio->read_slot].devnum;

	__raid10_find_phys(&conf->geo, r10_bio);

	blist = read_bio;
	read_bio->bi_next = NULL;

	for (s = 0; s < conf->copies*2; s++) {
		struct bio *b;
		int d = r10_bio->devs[s/2].devnum;
		struct md_rdev *rdev2;
		if (s&1) {
			rdev2 = conf->mirrors[d].replacement;
			b = r10_bio->devs[s/2].repl_bio;
		} else {
			rdev2 = conf->mirrors[d].rdev;
			b = r10_bio->devs[s/2].bio;
		}
		if (!rdev2 || test_bit(Faulty, &rdev2->flags))
			continue;

		bio_reset(b);
		b->bi_bdev = rdev2->bdev;
		b->bi_iter.bi_sector = r10_bio->devs[s/2].addr +
			rdev2->new_data_offset;
		b->bi_private = r10_bio;
		b->bi_end_io = end_reshape_write;
		b->bi_rw = WRITE;
		b->bi_next = blist;
		blist = b;
	}

	nr_sectors = 0;
	for (s = 0 ; s < max_sectors; s += PAGE_SIZE >> 9) {
		struct page *page = r10_bio->devs[0].bio->bi_io_vec[s/(PAGE_SIZE>>9)].bv_page;
		int len = (max_sectors - s) << 9;
		if (len > PAGE_SIZE)
			len = PAGE_SIZE;
		for (bio = blist; bio ; bio = bio->bi_next) {
			struct bio *bio2;
			if (bio_add_page(bio, page, len, 0))
				continue;

			for (bio2 = blist;
			     bio2 && bio2 != bio;
			     bio2 = bio2->bi_next) {
				 
				bio2->bi_vcnt--;
				bio2->bi_iter.bi_size -= len;
				bio_clear_flag(bio2, BIO_SEG_VALID);
			}
			goto bio_full;
		}
		sector_nr += len >> 9;
		nr_sectors += len >> 9;
	}
bio_full:
	r10_bio->sectors = nr_sectors;

	md_sync_acct(read_bio->bi_bdev, r10_bio->sectors);
	atomic_inc(&r10_bio->remaining);
	read_bio->bi_next = NULL;
	generic_make_request(read_bio);
	sector_nr += nr_sectors;
	sectors_done += nr_sectors;
	if (sector_nr <= last)
		goto read_more;

	if (mddev->reshape_backwards)
		conf->reshape_progress -= sectors_done;
	else
		conf->reshape_progress += sectors_done;

	return sectors_done;
}

static void end_reshape_request(struct r10bio *r10_bio);
static int handle_reshape_read_error(struct mddev *mddev,
				     struct r10bio *r10_bio);
static void reshape_request_write(struct mddev *mddev, struct r10bio *r10_bio)
{
	 
	struct r10conf *conf = mddev->private;
	int s;

	if (!test_bit(R10BIO_Uptodate, &r10_bio->state))
		if (handle_reshape_read_error(mddev, r10_bio) < 0) {
			 
			md_done_sync(mddev, r10_bio->sectors, 0);
			return;
		}

	atomic_set(&r10_bio->remaining, 1);
	for (s = 0; s < conf->copies*2; s++) {
		struct bio *b;
		int d = r10_bio->devs[s/2].devnum;
		struct md_rdev *rdev;
		if (s&1) {
			rdev = conf->mirrors[d].replacement;
			b = r10_bio->devs[s/2].repl_bio;
		} else {
			rdev = conf->mirrors[d].rdev;
			b = r10_bio->devs[s/2].bio;
		}
		if (!rdev || test_bit(Faulty, &rdev->flags))
			continue;
		atomic_inc(&rdev->nr_pending);
		md_sync_acct(b->bi_bdev, r10_bio->sectors);
		atomic_inc(&r10_bio->remaining);
		b->bi_next = NULL;
		generic_make_request(b);
	}
	end_reshape_request(r10_bio);
}

static void end_reshape(struct r10conf *conf)
{
	if (test_bit(MD_RECOVERY_INTR, &conf->mddev->recovery))
		return;

	spin_lock_irq(&conf->device_lock);
	conf->prev = conf->geo;
	md_finish_reshape(conf->mddev);
	smp_wmb();
	conf->reshape_progress = MaxSector;
	conf->reshape_safe = MaxSector;
	spin_unlock_irq(&conf->device_lock);

	if (conf->mddev->queue) {
		int stripe = conf->geo.raid_disks *
			((conf->mddev->chunk_sectors << 9) / PAGE_SIZE);
		stripe /= conf->geo.near_copies;
		if (conf->mddev->queue->backing_dev_info.ra_pages < 2 * stripe)
			conf->mddev->queue->backing_dev_info.ra_pages = 2 * stripe;
	}
	conf->fullsync = 0;
}

static int handle_reshape_read_error(struct mddev *mddev,
				     struct r10bio *r10_bio)
{
	 
	int sectors = r10_bio->sectors;
	struct r10conf *conf = mddev->private;
	struct {
		struct r10bio r10_bio;
		struct r10dev devs[conf->copies];
	} on_stack;
	struct r10bio *r10b = &on_stack.r10_bio;
	int slot = 0;
	int idx = 0;
	struct bio_vec *bvec = r10_bio->master_bio->bi_io_vec;

	r10b->sector = r10_bio->sector;
	__raid10_find_phys(&conf->prev, r10b);

	while (sectors) {
		int s = sectors;
		int success = 0;
		int first_slot = slot;

		if (s > (PAGE_SIZE >> 9))
			s = PAGE_SIZE >> 9;

		while (!success) {
			int d = r10b->devs[slot].devnum;
			struct md_rdev *rdev = conf->mirrors[d].rdev;
			sector_t addr;
			if (rdev == NULL ||
			    test_bit(Faulty, &rdev->flags) ||
			    !test_bit(In_sync, &rdev->flags))
				goto failed;

			addr = r10b->devs[slot].addr + idx * PAGE_SIZE;
			success = sync_page_io(rdev,
					       addr,
					       s << 9,
					       bvec[idx].bv_page,
					       READ, false);
			if (success)
				break;
		failed:
			slot++;
			if (slot >= conf->copies)
				slot = 0;
			if (slot == first_slot)
				break;
		}
		if (!success) {
			 
			set_bit(MD_RECOVERY_INTR,
				&mddev->recovery);
			return -EIO;
		}
		sectors -= s;
		idx++;
	}
	return 0;
}

static void end_reshape_write(struct bio *bio)
{
	struct r10bio *r10_bio = bio->bi_private;
	struct mddev *mddev = r10_bio->mddev;
	struct r10conf *conf = mddev->private;
	int d;
	int slot;
	int repl;
	struct md_rdev *rdev = NULL;

	d = find_bio_disk(conf, r10_bio, bio, &slot, &repl);
	if (repl)
		rdev = conf->mirrors[d].replacement;
	if (!rdev) {
		smp_mb();
		rdev = conf->mirrors[d].rdev;
	}

	if (bio->bi_error) {
		 
		md_error(mddev, rdev);
	}

	rdev_dec_pending(rdev, mddev);
	end_reshape_request(r10_bio);
}

static void end_reshape_request(struct r10bio *r10_bio)
{
	if (!atomic_dec_and_test(&r10_bio->remaining))
		return;
	md_done_sync(r10_bio->mddev, r10_bio->sectors, 1);
	bio_put(r10_bio->master_bio);
	put_buf(r10_bio);
}

static void raid10_finish_reshape(struct mddev *mddev)
{
	struct r10conf *conf = mddev->private;

	if (test_bit(MD_RECOVERY_INTR, &mddev->recovery))
		return;

	if (mddev->delta_disks > 0) {
		sector_t size = raid10_size(mddev, 0, 0);
		md_set_array_sectors(mddev, size);
		if (mddev->recovery_cp > mddev->resync_max_sectors) {
			mddev->recovery_cp = mddev->resync_max_sectors;
			set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
		}
		mddev->resync_max_sectors = size;
		set_capacity(mddev->gendisk, mddev->array_sectors);
		revalidate_disk(mddev->gendisk);
	} else {
		int d;
		for (d = conf->geo.raid_disks ;
		     d < conf->geo.raid_disks - mddev->delta_disks;
		     d++) {
			struct md_rdev *rdev = conf->mirrors[d].rdev;
			if (rdev)
				clear_bit(In_sync, &rdev->flags);
			rdev = conf->mirrors[d].replacement;
			if (rdev)
				clear_bit(In_sync, &rdev->flags);
		}
	}
	mddev->layout = mddev->new_layout;
	mddev->chunk_sectors = 1 << conf->geo.chunk_shift;
	mddev->reshape_position = MaxSector;
	mddev->delta_disks = 0;
	mddev->reshape_backwards = 0;
}

static struct md_personality raid10_personality =
{
	.name		= "raid10",
	.level		= 10,
	.owner		= THIS_MODULE,
	.make_request	= make_request,
	.run		= run,
	.free		= raid10_free,
	.status		= status,
#ifdef MY_ABC_HERE
	.error_handler	= syno_error_for_internal,
	.syno_error_handler = syno_error_for_hotplug,
#else  
	.error_handler	= error,
#endif  
	.hot_add_disk	= raid10_add_disk,
	.hot_remove_disk= raid10_remove_disk,
	.spare_active	= raid10_spare_active,
	.sync_request	= sync_request,
	.quiesce	= raid10_quiesce,
	.size		= raid10_size,
	.resize		= raid10_resize,
#ifdef MY_ABC_HERE
	.ismaxdegrade = SynoIsRaidReachMaxDegrade,
	.syno_set_rdev_auto_remap = SynoSetRdevAutoRemap,
#endif  
	.takeover	= raid10_takeover,
	.check_reshape	= raid10_check_reshape,
	.start_reshape	= raid10_start_reshape,
	.finish_reshape	= raid10_finish_reshape,
	.congested	= raid10_congested,
};

static int __init raid_init(void)
{
	return register_md_personality(&raid10_personality);
}

static void raid_exit(void)
{
	unregister_md_personality(&raid10_personality);
}

module_init(raid_init);
module_exit(raid_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RAID10 (striped mirror) personality for MD");
MODULE_ALIAS("md-personality-9");  
MODULE_ALIAS("md-raid10");
MODULE_ALIAS("md-level-10");

module_param(max_queued_requests, int, S_IRUGO|S_IWUSR);
