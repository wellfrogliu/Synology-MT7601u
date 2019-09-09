#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/blkdev.h>
#include <linux/raid/md_u.h>
#include <linux/seq_file.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "md.h"
#include "linear.h"

static inline struct dev_info *which_dev(struct mddev *mddev, sector_t sector)
{
	int lo, mid, hi;
	struct linear_conf *conf;

	lo = 0;
	hi = mddev->raid_disks - 1;
	conf = mddev->private;

	while (hi > lo) {

		mid = (hi + lo) / 2;
		if (sector < conf->disks[mid].end_sector)
			hi = mid;
		else
			lo = mid + 1;
	}

	return conf->disks + lo;
}

static int linear_congested(struct mddev *mddev, int bits)
{
	struct linear_conf *conf;
	int i, ret = 0;

	rcu_read_lock();
	conf = rcu_dereference(mddev->private);
#ifdef MY_ABC_HERE
	if (mddev->degraded) {
		return ret;
	}

	for (i = 0; i < conf->raid_disks && !ret ; i++) {
		struct md_rdev *rdev = rcu_dereference(conf->disks[i].rdev);
		struct request_queue *q = NULL;

		if (!rdev) {
			continue;
		}

		q = bdev_get_queue(rdev->bdev);
		ret |= bdi_congested(&q->backing_dev_info, bits);
	}
#else  
	for (i = 0; i < conf->raid_disks && !ret ; i++) {
		struct request_queue *q = bdev_get_queue(conf->disks[i].rdev->bdev);
		ret |= bdi_congested(&q->backing_dev_info, bits);
	}
#endif  

	rcu_read_unlock();
	return ret;
}

static sector_t linear_size(struct mddev *mddev, sector_t sectors, int raid_disks)
{
	struct linear_conf *conf;
	sector_t array_sectors;

	conf = mddev->private;
	WARN_ONCE(sectors || raid_disks,
		  "%s does not support generic reshape\n", __func__);
	array_sectors = conf->array_sectors;

	return array_sectors;
}

static struct linear_conf *linear_conf(struct mddev *mddev, int raid_disks)
{
	struct linear_conf *conf;
	struct md_rdev *rdev;
	int i, cnt;
	bool discard_supported = false;

	conf = kzalloc (sizeof (*conf) + raid_disks*sizeof(struct dev_info),
			GFP_KERNEL);
	if (!conf)
		return NULL;

	cnt = 0;
	conf->array_sectors = 0;

	rdev_for_each(rdev, mddev) {
		int j = rdev->raid_disk;
		struct dev_info *disk = conf->disks + j;
		sector_t sectors;

		if (j < 0 || j >= raid_disks || disk->rdev) {
			printk(KERN_ERR "md/linear:%s: disk numbering problem. Aborting!\n",
			       mdname(mddev));
			goto out;
		}

		disk->rdev = rdev;
		if (mddev->chunk_sectors) {
			sectors = rdev->sectors;
			sector_div(sectors, mddev->chunk_sectors);
			rdev->sectors = sectors * mddev->chunk_sectors;
		}

		disk_stack_limits(mddev->gendisk, rdev->bdev,
				  rdev->data_offset << 9);

		conf->array_sectors += rdev->sectors;
		cnt++;

		if (blk_queue_discard(bdev_get_queue(rdev->bdev)))
			discard_supported = true;
	}
	if (cnt != raid_disks) {
#ifdef MY_ABC_HERE
		 
		mddev->degraded = mddev->raid_disks - cnt;
#ifdef MY_ABC_HERE
		mddev->nodev_and_crashed = 1;
#endif  
		printk(KERN_ERR "md/linear:%s: not enough drives present.\n",
		       mdname(mddev));
		return conf;
#else  
		printk(KERN_ERR "md/linear:%s: not enough drives present. Aborting!\n",
		       mdname(mddev));
		goto out;
#endif  
	}

	if (!discard_supported)
		queue_flag_clear_unlocked(QUEUE_FLAG_DISCARD, mddev->queue);
	else
		queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, mddev->queue);

	conf->disks[0].end_sector = conf->disks[0].rdev->sectors;

	for (i = 1; i < raid_disks; i++)
		conf->disks[i].end_sector =
			conf->disks[i-1].end_sector +
			conf->disks[i].rdev->sectors;

	conf->raid_disks = raid_disks;

	return conf;

out:
	kfree(conf);
	return NULL;
}

static int linear_run (struct mddev *mddev)
{
	struct linear_conf *conf;
	int ret;

	if (md_check_no_bitmap(mddev))
		return -EINVAL;
#ifdef MY_ABC_HERE
	mddev->degraded = 0;
#endif  
	conf = linear_conf(mddev, mddev->raid_disks);

	if (!conf)
		return 1;
	mddev->private = conf;
	md_set_array_sectors(mddev, linear_size(mddev, 0, 0));

	ret =  md_integrity_register(mddev);
	if (ret) {
		kfree(conf);
		mddev->private = NULL;
	}
	return ret;
}

static int linear_add(struct mddev *mddev, struct md_rdev *rdev)
{
	 
	struct linear_conf *newconf, *oldconf;

	if (rdev->saved_raid_disk != mddev->raid_disks)
		return -EINVAL;

	rdev->raid_disk = rdev->saved_raid_disk;
	rdev->saved_raid_disk = -1;

	newconf = linear_conf(mddev,mddev->raid_disks+1);

	if (!newconf)
		return -ENOMEM;

	mddev_suspend(mddev);
	oldconf = rcu_dereference(mddev->private);
	mddev->raid_disks++;
	WARN_ONCE(mddev->raid_disks != newconf->raid_disks,
		"copied raid_disks doesn't match mddev->raid_disks");
	rcu_assign_pointer(mddev->private, newconf);
	md_set_array_sectors(mddev, linear_size(mddev, 0, 0));
	set_capacity(mddev->gendisk, mddev->array_sectors);
	mddev_resume(mddev);
	revalidate_disk(mddev->gendisk);
	kfree_rcu(oldconf, rcu);
	return 0;
}

static void linear_free(struct mddev *mddev, void *priv)
{
	struct linear_conf *conf = priv;

	kfree(conf);
}

#ifdef MY_ABC_HERE
 
static void
SynoLinearEndRequest(struct bio *bio)
{
	int bio_error = bio->bi_error;
	struct mddev *mddev = NULL;
	struct md_rdev *rdev = NULL;
	struct bio *data_bio;

	data_bio = bio->bi_private;

	rdev = (struct md_rdev *)data_bio->bi_next;
	mddev = rdev->mddev;

	bio->bi_end_io = data_bio->bi_end_io;
	bio->bi_private = data_bio->bi_private;

	if (bio_error) {
#ifdef MY_ABC_HERE
		if (IsDeviceDisappear(rdev->bdev)) {
			syno_md_error(mddev, rdev);
		} else {
#ifdef MY_ABC_HERE
#ifdef MY_ABC_HERE
			if (bio_flagged(bio, BIO_AUTO_REMAP)) {
				SynoReportBadSector(bio->bi_iter.bi_sector, bio->bi_rw, mddev->md_minor, bio->bi_bdev, __FUNCTION__);
			}
#else  
			SynoReportBadSector(bio->bi_iter.bi_sector, bio->bi_rw, mddev->md_minor, bio->bi_bdev, __FUNCTION__);
#endif  
#endif  
			md_error(mddev, rdev);
		}
#else  
		md_error(mddev, rdev);
#endif  
	}

	atomic_dec(&rdev->nr_pending);
	bio_put(data_bio);
	 
	bio_endio(bio);
}
#endif  

static void linear_make_request(struct mddev *mddev, struct bio *bio)
{
	char b[BDEVNAME_SIZE];
	struct dev_info *tmp_dev;
	struct bio *split;
	sector_t start_sector, end_sector, data_offset;
#ifdef MY_ABC_HERE
	struct bio *data_bio;
#endif  

	if (unlikely(bio->bi_rw & REQ_FLUSH)) {
		md_flush_request(mddev, bio);
		return;
	}

	do {
#ifdef MY_ABC_HERE
		 
#ifdef MY_ABC_HERE
		if (mddev->nodev_and_crashed) {
#else  
		if (mddev->degraded) {
#endif  
			bio->bi_error = -EIO;
			bio_endio(bio);
			return;
		}
#endif  
		tmp_dev = which_dev(mddev, bio->bi_iter.bi_sector);
		start_sector = tmp_dev->end_sector - tmp_dev->rdev->sectors;
		end_sector = tmp_dev->end_sector;
		data_offset = tmp_dev->rdev->data_offset;
		bio->bi_bdev = tmp_dev->rdev->bdev;

		if (unlikely(bio->bi_iter.bi_sector >= end_sector ||
			     bio->bi_iter.bi_sector < start_sector))
			goto out_of_bounds;

		if (unlikely(bio_end_sector(bio) > end_sector)) {
			 
			split = bio_split(bio, end_sector -
					  bio->bi_iter.bi_sector,
					  GFP_NOIO, fs_bio_set);
			bio_chain(split, bio);
		} else {
			split = bio;
		}

		split->bi_iter.bi_sector = split->bi_iter.bi_sector -
			start_sector + data_offset;

#ifdef MY_ABC_HERE
		data_bio = bio_clone(split, GFP_NOIO);

		if (data_bio) {
			atomic_inc(&tmp_dev->rdev->nr_pending);
			data_bio->bi_end_io = split->bi_end_io;
			data_bio->bi_private = split->bi_private;
			data_bio->bi_next = (void *)tmp_dev->rdev;

			split->bi_end_io = SynoLinearEndRequest;
			split->bi_private = data_bio;
		}
#endif  

		if (unlikely((split->bi_rw & REQ_DISCARD) &&
			 !blk_queue_discard(bdev_get_queue(split->bi_bdev)))) {
			 
			bio_endio(split);
		} else
			generic_make_request(split);
	} while (split != bio);
	return;

out_of_bounds:
	printk(KERN_ERR
	       "md/linear:%s: make_request: Sector %llu out of bounds on "
	       "dev %s: %llu sectors, offset %llu\n",
	       mdname(mddev),
	       (unsigned long long)bio->bi_iter.bi_sector,
	       bdevname(tmp_dev->rdev->bdev, b),
	       (unsigned long long)tmp_dev->rdev->sectors,
	       (unsigned long long)start_sector);
	bio_io_error(bio);
}

#ifdef MY_ABC_HERE
static void
syno_linear_status(struct seq_file *seq, struct mddev *mddev)
{
	struct linear_conf *conf;
	struct md_rdev *rdev;
	int j;

	seq_printf(seq, " %dk rounding", mddev->chunk_sectors / 2);
	seq_printf(seq, " [%d/%d] [", mddev->raid_disks, mddev->raid_disks - mddev->degraded);
	rcu_read_lock();
	conf = rcu_dereference(mddev->private);
	for (j = 0; j < mddev->raid_disks; j++)
	{
		rdev = rcu_dereference(conf->disks[j].rdev);
#ifdef MY_ABC_HERE
		if (rdev &&
			!test_bit(Faulty, &rdev->flags)) {
#else  
		if(rdev) {
#endif  
#ifdef MY_ABC_HERE
			seq_printf (seq, "%s", 
						test_bit(In_sync, &rdev->flags) ? 
						(test_bit(DiskError, &rdev->flags) ? "E" : "U") : "_");
#else  
			seq_printf (seq, "%s", "U");
#endif  
		} else {
			seq_printf (seq, "%s", "_");
		}
	}
	rcu_read_unlock();
	seq_printf (seq, "]");
}
#else  
static void linear_status (struct seq_file *seq, struct mddev *mddev)
{

	seq_printf(seq, " %dk rounding", mddev->chunk_sectors / 2);
}
#endif  

static void linear_quiesce(struct mddev *mddev, int state)
{
}

#ifdef MY_ABC_HERE
static int
SynoLinearRemoveDisk(struct mddev *mddev, struct md_rdev *rdev)
{
	int err = 0;
	char nm[20];
	struct linear_conf *conf = mddev->private;
	int number = rdev->raid_disk;

	if (!rdev) {
		goto END;
	}

	conf->disks[number].rdev = NULL;
	synchronize_rcu();
	if (atomic_read(&rdev->nr_pending)) {
		 
		err = -EBUSY;
		conf->disks[number].rdev = rdev;
		goto END;
	}

	sprintf(nm,"rd%d", number);
	sysfs_remove_link(&mddev->kobj, nm);
	rdev->raid_disk = -1;
END:
	return err;
}

static void
SynoLinearError(struct mddev *mddev, struct md_rdev *rdev)
{
	if (test_and_clear_bit(In_sync, &rdev->flags)) {
		if (mddev->degraded < mddev->raid_disks) {
			SYNO_UPDATE_SB_WORK *update_sb = NULL;
			mddev->degraded++;
#ifdef MY_ABC_HERE
			mddev->nodev_and_crashed = 1;
#endif  
			set_bit(Faulty, &rdev->flags);
#ifdef MY_ABC_HERE
			clear_bit(DiskError, &rdev->flags);
#endif  

			if (NULL == (update_sb = kzalloc(sizeof(SYNO_UPDATE_SB_WORK), GFP_ATOMIC))) {
				WARN_ON(!update_sb);
				goto END;
			}

			INIT_WORK(&update_sb->work, SynoUpdateSBTask);
			update_sb->mddev = mddev;
			schedule_work(&update_sb->work);
			set_bit(MD_CHANGE_DEVS, &mddev->flags);
		}
	}
END:
	return;
}

static void
SynoLinearErrorInternal(struct mddev *mddev, struct md_rdev *rdev)
{
#ifdef MY_ABC_HERE
	if (!test_bit(DiskError, &rdev->flags)) {
		SYNO_UPDATE_SB_WORK *update_sb = NULL;

		set_bit(DiskError, &rdev->flags);
		if (NULL == (update_sb = kzalloc(sizeof(SYNO_UPDATE_SB_WORK), GFP_ATOMIC))) {
			WARN_ON(!update_sb);
			goto END;
		}

		INIT_WORK(&update_sb->work, SynoUpdateSBTask);
		update_sb->mddev = mddev;
		schedule_work(&update_sb->work);
		set_bit(MD_CHANGE_DEVS, &mddev->flags);
	}

END:
#endif  
	return;
}
#endif  

static struct md_personality linear_personality =
{
	.name		= "linear",
	.level		= LEVEL_LINEAR,
	.owner		= THIS_MODULE,
	.make_request	= linear_make_request,
	.run		= linear_run,
	.free		= linear_free,
#ifdef MY_ABC_HERE
	.status		= syno_linear_status,
#else  
	.status		= linear_status,
#endif  
	.hot_add_disk	= linear_add,
#ifdef MY_ABC_HERE
	.hot_remove_disk    = SynoLinearRemoveDisk,
	.error_handler      = SynoLinearErrorInternal,
	.syno_error_handler = SynoLinearError,
#endif  
	.size		= linear_size,
	.quiesce	= linear_quiesce,
	.congested	= linear_congested,
};

static int __init linear_init (void)
{
	return register_md_personality (&linear_personality);
}

static void linear_exit (void)
{
	unregister_md_personality (&linear_personality);
}

module_init(linear_init);
module_exit(linear_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Linear device concatenation personality for MD");
MODULE_ALIAS("md-personality-1");  
MODULE_ALIAS("md-linear");
MODULE_ALIAS("md-level--1");
