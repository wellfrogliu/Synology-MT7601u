#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/bootmem.h>	 
#include <linux/gcd.h>
#include <linux/lcm.h>
#include <linux/jiffies.h>
#include <linux/gfp.h>

#include "blk.h"

unsigned long blk_max_low_pfn;
EXPORT_SYMBOL(blk_max_low_pfn);

unsigned long blk_max_pfn;

void blk_queue_prep_rq(struct request_queue *q, prep_rq_fn *pfn)
{
	q->prep_rq_fn = pfn;
}
EXPORT_SYMBOL(blk_queue_prep_rq);

void blk_queue_unprep_rq(struct request_queue *q, unprep_rq_fn *ufn)
{
	q->unprep_rq_fn = ufn;
}
EXPORT_SYMBOL(blk_queue_unprep_rq);

void blk_queue_softirq_done(struct request_queue *q, softirq_done_fn *fn)
{
	q->softirq_done_fn = fn;
}
EXPORT_SYMBOL(blk_queue_softirq_done);

void blk_queue_rq_timeout(struct request_queue *q, unsigned int timeout)
{
	q->rq_timeout = timeout;
}
EXPORT_SYMBOL_GPL(blk_queue_rq_timeout);

void blk_queue_rq_timed_out(struct request_queue *q, rq_timed_out_fn *fn)
{
	q->rq_timed_out_fn = fn;
}
EXPORT_SYMBOL_GPL(blk_queue_rq_timed_out);

void blk_queue_lld_busy(struct request_queue *q, lld_busy_fn *fn)
{
	q->lld_busy_fn = fn;
}
EXPORT_SYMBOL_GPL(blk_queue_lld_busy);

void blk_set_default_limits(struct queue_limits *lim)
{
	lim->max_segments = BLK_MAX_SEGMENTS;
	lim->max_integrity_segments = 0;
	lim->seg_boundary_mask = BLK_SEG_BOUNDARY_MASK;
	lim->virt_boundary_mask = 0;
	lim->max_segment_size = BLK_MAX_SEGMENT_SIZE;
	lim->max_sectors = lim->max_hw_sectors = BLK_SAFE_MAX_SECTORS;
	lim->max_dev_sectors = 0;
	lim->chunk_sectors = 0;
	lim->max_write_same_sectors = 0;
	lim->max_discard_sectors = 0;
	lim->max_hw_discard_sectors = 0;
	lim->discard_granularity = 0;
	lim->discard_alignment = 0;
	lim->discard_misaligned = 0;
	lim->discard_zeroes_data = 0;
	lim->logical_block_size = lim->physical_block_size = lim->io_min = 512;
	lim->bounce_pfn = (unsigned long)(BLK_BOUNCE_ANY >> PAGE_SHIFT);
	lim->alignment_offset = 0;
	lim->io_opt = 0;
	lim->misaligned = 0;
	lim->cluster = 1;
}
EXPORT_SYMBOL(blk_set_default_limits);

void blk_set_stacking_limits(struct queue_limits *lim)
{
	blk_set_default_limits(lim);

	lim->discard_zeroes_data = 1;
	lim->max_segments = USHRT_MAX;
	lim->max_hw_sectors = UINT_MAX;
	lim->max_segment_size = UINT_MAX;
	lim->max_sectors = UINT_MAX;
	lim->max_dev_sectors = UINT_MAX;
	lim->max_write_same_sectors = UINT_MAX;
}
EXPORT_SYMBOL(blk_set_stacking_limits);

void blk_queue_make_request(struct request_queue *q, make_request_fn *mfn)
{
	 
	q->nr_requests = BLKDEV_MAX_RQ;

	q->make_request_fn = mfn;
	blk_queue_dma_alignment(q, 511);
	blk_queue_congestion_threshold(q);
	q->nr_batching = BLK_BATCH_REQ;

	blk_set_default_limits(&q->limits);

	blk_queue_bounce_limit(q, BLK_BOUNCE_HIGH);
}
EXPORT_SYMBOL(blk_queue_make_request);

void blk_queue_bounce_limit(struct request_queue *q, u64 max_addr)
{
	unsigned long b_pfn = max_addr >> PAGE_SHIFT;
	int dma = 0;

	q->bounce_gfp = GFP_NOIO;
#if BITS_PER_LONG == 64
	 
	if (b_pfn < (min_t(u64, 0xffffffffUL, BLK_BOUNCE_HIGH) >> PAGE_SHIFT))
		dma = 1;
	q->limits.bounce_pfn = max(max_low_pfn, b_pfn);
#else
	if (b_pfn < blk_max_low_pfn)
		dma = 1;
	q->limits.bounce_pfn = b_pfn;
#endif
	if (dma) {
		init_emergency_isa_pool();
		q->bounce_gfp = GFP_NOIO | GFP_DMA;
		q->limits.bounce_pfn = b_pfn;
	}
}
EXPORT_SYMBOL(blk_queue_bounce_limit);

void blk_queue_max_hw_sectors(struct request_queue *q, unsigned int max_hw_sectors)
{
	struct queue_limits *limits = &q->limits;
	unsigned int max_sectors;

	if ((max_hw_sectors << 9) < PAGE_CACHE_SIZE) {
		max_hw_sectors = 1 << (PAGE_CACHE_SHIFT - 9);
		printk(KERN_INFO "%s: set to minimum %d\n",
		       __func__, max_hw_sectors);
	}

	limits->max_hw_sectors = max_hw_sectors;
	max_sectors = min_not_zero(max_hw_sectors, limits->max_dev_sectors);
	max_sectors = min_t(unsigned int, max_sectors, BLK_DEF_MAX_SECTORS);
	limits->max_sectors = max_sectors;
}
EXPORT_SYMBOL(blk_queue_max_hw_sectors);

void blk_queue_chunk_sectors(struct request_queue *q, unsigned int chunk_sectors)
{
	BUG_ON(!is_power_of_2(chunk_sectors));
	q->limits.chunk_sectors = chunk_sectors;
}
EXPORT_SYMBOL(blk_queue_chunk_sectors);

void blk_queue_max_discard_sectors(struct request_queue *q,
		unsigned int max_discard_sectors)
{
	q->limits.max_hw_discard_sectors = max_discard_sectors;
	q->limits.max_discard_sectors = max_discard_sectors;
}
EXPORT_SYMBOL(blk_queue_max_discard_sectors);

void blk_queue_max_write_same_sectors(struct request_queue *q,
				      unsigned int max_write_same_sectors)
{
	q->limits.max_write_same_sectors = max_write_same_sectors;
}
EXPORT_SYMBOL(blk_queue_max_write_same_sectors);

void blk_queue_max_segments(struct request_queue *q, unsigned short max_segments)
{
	if (!max_segments) {
		max_segments = 1;
		printk(KERN_INFO "%s: set to minimum %d\n",
		       __func__, max_segments);
	}

	q->limits.max_segments = max_segments;
}
EXPORT_SYMBOL(blk_queue_max_segments);

void blk_queue_max_segment_size(struct request_queue *q, unsigned int max_size)
{
	if (max_size < PAGE_CACHE_SIZE) {
		max_size = PAGE_CACHE_SIZE;
		printk(KERN_INFO "%s: set to minimum %d\n",
		       __func__, max_size);
	}

	q->limits.max_segment_size = max_size;
}
EXPORT_SYMBOL(blk_queue_max_segment_size);

#ifdef MY_ABC_HERE
 
void syno_limits_logical_block_size(struct queue_limits *limits, unsigned short size)
{
	limits->logical_block_size = size;

	if (limits->physical_block_size < size)
		limits->physical_block_size = size;

	if (limits->io_min < limits->physical_block_size)
		limits->io_min = limits->physical_block_size;
}
EXPORT_SYMBOL(syno_limits_logical_block_size);
#endif  

void blk_queue_logical_block_size(struct request_queue *q, unsigned short size)
{
#ifdef MY_ABC_HERE
	syno_limits_logical_block_size(&q->limits, size);
#else
	q->limits.logical_block_size = size;

	if (q->limits.physical_block_size < size)
		q->limits.physical_block_size = size;

	if (q->limits.io_min < q->limits.physical_block_size)
		q->limits.io_min = q->limits.physical_block_size;
#endif  
}
EXPORT_SYMBOL(blk_queue_logical_block_size);

void blk_queue_physical_block_size(struct request_queue *q, unsigned int size)
{
	q->limits.physical_block_size = size;

	if (q->limits.physical_block_size < q->limits.logical_block_size)
		q->limits.physical_block_size = q->limits.logical_block_size;

	if (q->limits.io_min < q->limits.physical_block_size)
		q->limits.io_min = q->limits.physical_block_size;
}
EXPORT_SYMBOL(blk_queue_physical_block_size);

void blk_queue_alignment_offset(struct request_queue *q, unsigned int offset)
{
	q->limits.alignment_offset =
		offset & (q->limits.physical_block_size - 1);
	q->limits.misaligned = 0;
}
EXPORT_SYMBOL(blk_queue_alignment_offset);

void blk_limits_io_min(struct queue_limits *limits, unsigned int min)
{
	limits->io_min = min;

	if (limits->io_min < limits->logical_block_size)
		limits->io_min = limits->logical_block_size;

	if (limits->io_min < limits->physical_block_size)
		limits->io_min = limits->physical_block_size;
}
EXPORT_SYMBOL(blk_limits_io_min);

void blk_queue_io_min(struct request_queue *q, unsigned int min)
{
	blk_limits_io_min(&q->limits, min);
}
EXPORT_SYMBOL(blk_queue_io_min);

void blk_limits_io_opt(struct queue_limits *limits, unsigned int opt)
{
	limits->io_opt = opt;
}
EXPORT_SYMBOL(blk_limits_io_opt);

void blk_queue_io_opt(struct request_queue *q, unsigned int opt)
{
	blk_limits_io_opt(&q->limits, opt);
}
EXPORT_SYMBOL(blk_queue_io_opt);

void blk_queue_stack_limits(struct request_queue *t, struct request_queue *b)
{
	blk_stack_limits(&t->limits, &b->limits, 0);
}
EXPORT_SYMBOL(blk_queue_stack_limits);

int blk_stack_limits(struct queue_limits *t, struct queue_limits *b,
		     sector_t start)
{
	unsigned int top, bottom, alignment, ret = 0;

	t->max_sectors = min_not_zero(t->max_sectors, b->max_sectors);
	t->max_hw_sectors = min_not_zero(t->max_hw_sectors, b->max_hw_sectors);
	t->max_dev_sectors = min_not_zero(t->max_dev_sectors, b->max_dev_sectors);
	t->max_write_same_sectors = min(t->max_write_same_sectors,
					b->max_write_same_sectors);
	t->bounce_pfn = min_not_zero(t->bounce_pfn, b->bounce_pfn);

	t->seg_boundary_mask = min_not_zero(t->seg_boundary_mask,
					    b->seg_boundary_mask);
	t->virt_boundary_mask = min_not_zero(t->virt_boundary_mask,
					    b->virt_boundary_mask);

	t->max_segments = min_not_zero(t->max_segments, b->max_segments);
	t->max_integrity_segments = min_not_zero(t->max_integrity_segments,
						 b->max_integrity_segments);

	t->max_segment_size = min_not_zero(t->max_segment_size,
					   b->max_segment_size);

	t->misaligned |= b->misaligned;

	alignment = queue_limit_alignment_offset(b, start);

	if (t->alignment_offset != alignment) {

		top = max(t->physical_block_size, t->io_min)
			+ t->alignment_offset;
		bottom = max(b->physical_block_size, b->io_min) + alignment;

		if (max(top, bottom) % min(top, bottom)) {
			t->misaligned = 1;
			ret = -1;
		}
	}

	t->logical_block_size = max(t->logical_block_size,
				    b->logical_block_size);

	t->physical_block_size = max(t->physical_block_size,
				     b->physical_block_size);

	t->io_min = max(t->io_min, b->io_min);
	t->io_opt = lcm_not_zero(t->io_opt, b->io_opt);

	t->cluster &= b->cluster;
	t->discard_zeroes_data &= b->discard_zeroes_data;

	if (t->physical_block_size & (t->logical_block_size - 1)) {
		t->physical_block_size = t->logical_block_size;
		t->misaligned = 1;
		ret = -1;
	}

	if (t->io_min & (t->physical_block_size - 1)) {
		t->io_min = t->physical_block_size;
		t->misaligned = 1;
		ret = -1;
	}

	if (t->io_opt & (t->physical_block_size - 1)) {
		t->io_opt = 0;
		t->misaligned = 1;
		ret = -1;
	}

	t->raid_partial_stripes_expensive =
		max(t->raid_partial_stripes_expensive,
		    b->raid_partial_stripes_expensive);

	t->alignment_offset = lcm_not_zero(t->alignment_offset, alignment)
		% max(t->physical_block_size, t->io_min);

	if (t->alignment_offset & (t->logical_block_size - 1)) {
		t->misaligned = 1;
		ret = -1;
	}

	if (b->discard_granularity) {
		alignment = queue_limit_discard_alignment(b, start);

		if (t->discard_granularity != 0 &&
		    t->discard_alignment != alignment) {
			top = t->discard_granularity + t->discard_alignment;
			bottom = b->discard_granularity + alignment;

			if ((max(top, bottom) % min(top, bottom)) != 0)
				t->discard_misaligned = 1;
		}

		t->max_discard_sectors = min_not_zero(t->max_discard_sectors,
						      b->max_discard_sectors);
		t->max_hw_discard_sectors = min_not_zero(t->max_hw_discard_sectors,
							 b->max_hw_discard_sectors);
		t->discard_granularity = max(t->discard_granularity,
					     b->discard_granularity);
		t->discard_alignment = lcm_not_zero(t->discard_alignment, alignment) %
			t->discard_granularity;
	}

	return ret;
}
EXPORT_SYMBOL(blk_stack_limits);

int bdev_stack_limits(struct queue_limits *t, struct block_device *bdev,
		      sector_t start)
{
	struct request_queue *bq = bdev_get_queue(bdev);

	start += get_start_sect(bdev);

	return blk_stack_limits(t, &bq->limits, start);
}
EXPORT_SYMBOL(bdev_stack_limits);

void disk_stack_limits(struct gendisk *disk, struct block_device *bdev,
		       sector_t offset)
{
	struct request_queue *t = disk->queue;

	if (bdev_stack_limits(&t->limits, bdev, offset >> 9) < 0) {
		char top[BDEVNAME_SIZE], bottom[BDEVNAME_SIZE];

		disk_name(disk, 0, top);
		bdevname(bdev, bottom);

		printk(KERN_NOTICE "%s: Warning: Device %s is misaligned\n",
		       top, bottom);
	}
}
EXPORT_SYMBOL(disk_stack_limits);

void blk_queue_dma_pad(struct request_queue *q, unsigned int mask)
{
	q->dma_pad_mask = mask;
}
EXPORT_SYMBOL(blk_queue_dma_pad);

void blk_queue_update_dma_pad(struct request_queue *q, unsigned int mask)
{
	if (mask > q->dma_pad_mask)
		q->dma_pad_mask = mask;
}
EXPORT_SYMBOL(blk_queue_update_dma_pad);

int blk_queue_dma_drain(struct request_queue *q,
			       dma_drain_needed_fn *dma_drain_needed,
			       void *buf, unsigned int size)
{
	if (queue_max_segments(q) < 2)
		return -EINVAL;
	 
	blk_queue_max_segments(q, queue_max_segments(q) - 1);
	q->dma_drain_needed = dma_drain_needed;
	q->dma_drain_buffer = buf;
	q->dma_drain_size = size;

	return 0;
}
EXPORT_SYMBOL_GPL(blk_queue_dma_drain);

void blk_queue_segment_boundary(struct request_queue *q, unsigned long mask)
{
	if (mask < PAGE_CACHE_SIZE - 1) {
		mask = PAGE_CACHE_SIZE - 1;
		printk(KERN_INFO "%s: set to minimum %lx\n",
		       __func__, mask);
	}

	q->limits.seg_boundary_mask = mask;
}
EXPORT_SYMBOL(blk_queue_segment_boundary);

void blk_queue_virt_boundary(struct request_queue *q, unsigned long mask)
{
	q->limits.virt_boundary_mask = mask;
}
EXPORT_SYMBOL(blk_queue_virt_boundary);

void blk_queue_dma_alignment(struct request_queue *q, int mask)
{
	q->dma_alignment = mask;
}
EXPORT_SYMBOL(blk_queue_dma_alignment);

void blk_queue_update_dma_alignment(struct request_queue *q, int mask)
{
	BUG_ON(mask > PAGE_SIZE);

	if (mask > q->dma_alignment)
		q->dma_alignment = mask;
}
EXPORT_SYMBOL(blk_queue_update_dma_alignment);

void blk_queue_flush_queueable(struct request_queue *q, bool queueable)
{
	spin_lock_irq(q->queue_lock);
	if (queueable)
		clear_bit(QUEUE_FLAG_FLUSH_NQ, &q->queue_flags);
	else
		set_bit(QUEUE_FLAG_FLUSH_NQ, &q->queue_flags);
	spin_unlock_irq(q->queue_lock);
}
EXPORT_SYMBOL_GPL(blk_queue_flush_queueable);

void blk_set_queue_depth(struct request_queue *q, unsigned int depth)
{
	q->queue_depth = depth;
	wbt_set_queue_depth(q->rq_wb, depth);
}
EXPORT_SYMBOL(blk_set_queue_depth);

void blk_queue_write_cache(struct request_queue *q, bool wc, bool fua)
{
	spin_lock_irq(q->queue_lock);
	if (wc)
		queue_flag_set(QUEUE_FLAG_WC, q);
	else
		queue_flag_clear(QUEUE_FLAG_WC, q);
	if (fua)
		queue_flag_set(QUEUE_FLAG_FUA, q);
	else
		queue_flag_clear(QUEUE_FLAG_FUA, q);
	spin_unlock_irq(q->queue_lock);

	wbt_set_write_cache(q->rq_wb, test_bit(QUEUE_FLAG_WC, &q->queue_flags));
}
EXPORT_SYMBOL_GPL(blk_queue_write_cache);

static int __init blk_settings_init(void)
{
	blk_max_low_pfn = max_low_pfn - 1;
	blk_max_pfn = max_pfn - 1;
	return 0;
}
subsys_initcall(blk_settings_init);
