#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/writeback.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/fault-inject.h>
#include <linux/list_sort.h>
#include <linux/delay.h>
#include <linux/ratelimit.h>
#include <linux/pm_runtime.h>
#include <linux/blk-cgroup.h>
#include <linux/wbt.h>

#define CREATE_TRACE_POINTS
#include <trace/events/block.h>

#include "blk.h"
#include "blk-mq.h"

#ifdef MY_ABC_HERE
#include <linux/synolib.h>
#endif  

EXPORT_TRACEPOINT_SYMBOL_GPL(block_bio_remap);
EXPORT_TRACEPOINT_SYMBOL_GPL(block_rq_remap);
EXPORT_TRACEPOINT_SYMBOL_GPL(block_bio_complete);
EXPORT_TRACEPOINT_SYMBOL_GPL(block_split);
EXPORT_TRACEPOINT_SYMBOL_GPL(block_unplug);

DEFINE_IDA(blk_queue_ida);

struct kmem_cache *request_cachep = NULL;

struct kmem_cache *blk_requestq_cachep;

static struct workqueue_struct *kblockd_workqueue;

static void blk_clear_congested(struct request_list *rl, int sync)
{
#ifdef CONFIG_CGROUP_WRITEBACK
	clear_wb_congested(rl->blkg->wb_congested, sync);
#else
	 
	if (rl == &rl->q->root_rl)
		clear_wb_congested(rl->q->backing_dev_info.wb.congested, sync);
#endif
}

static void blk_set_congested(struct request_list *rl, int sync)
{
#ifdef CONFIG_CGROUP_WRITEBACK
	set_wb_congested(rl->blkg->wb_congested, sync);
#else
	 
	if (rl == &rl->q->root_rl)
		set_wb_congested(rl->q->backing_dev_info.wb.congested, sync);
#endif
}

void blk_queue_congestion_threshold(struct request_queue *q)
{
	int nr;

	nr = q->nr_requests - (q->nr_requests / 8) + 1;
	if (nr > q->nr_requests)
		nr = q->nr_requests;
	q->nr_congestion_on = nr;

	nr = q->nr_requests - (q->nr_requests / 8) - (q->nr_requests / 16) - 1;
	if (nr < 1)
		nr = 1;
	q->nr_congestion_off = nr;
}

struct backing_dev_info *blk_get_backing_dev_info(struct block_device *bdev)
{
	struct request_queue *q = bdev_get_queue(bdev);

	return &q->backing_dev_info;
}
EXPORT_SYMBOL(blk_get_backing_dev_info);

void blk_rq_init(struct request_queue *q, struct request *rq)
{
	memset(rq, 0, sizeof(*rq));

	INIT_LIST_HEAD(&rq->queuelist);
	INIT_LIST_HEAD(&rq->timeout_list);
	rq->cpu = -1;
	rq->q = q;
	rq->__sector = (sector_t) -1;
	INIT_HLIST_NODE(&rq->hash);
	RB_CLEAR_NODE(&rq->rb_node);
	rq->cmd = rq->__cmd;
	rq->cmd_len = BLK_MAX_CDB;
	rq->tag = -1;
	rq->start_time = jiffies;
	set_start_time_ns(rq);
	rq->part = NULL;
}
EXPORT_SYMBOL(blk_rq_init);

static void req_bio_endio(struct request *rq, struct bio *bio,
			  unsigned int nbytes, int error)
{
	if (error)
		bio->bi_error = error;

	if (unlikely(rq->cmd_flags & REQ_QUIET))
		bio_set_flag(bio, BIO_QUIET);

	bio_advance(bio, nbytes);

	if (bio->bi_iter.bi_size == 0 && !(rq->cmd_flags & REQ_FLUSH_SEQ))
		bio_endio(bio);
}

void blk_dump_rq_flags(struct request *rq, char *msg)
{
	int bit;

	printk(KERN_INFO "%s: dev %s: type=%x, flags=%llx\n", msg,
		rq->rq_disk ? rq->rq_disk->disk_name : "?", rq->cmd_type,
		(unsigned long long) rq->cmd_flags);

	printk(KERN_INFO "  sector %llu, nr/cnr %u/%u\n",
	       (unsigned long long)blk_rq_pos(rq),
	       blk_rq_sectors(rq), blk_rq_cur_sectors(rq));
	printk(KERN_INFO "  bio %p, biotail %p, len %u\n",
	       rq->bio, rq->biotail, blk_rq_bytes(rq));

	if (rq->cmd_type == REQ_TYPE_BLOCK_PC) {
		printk(KERN_INFO "  cdb: ");
		for (bit = 0; bit < BLK_MAX_CDB; bit++)
			printk("%02x ", rq->cmd[bit]);
		printk("\n");
	}
}
EXPORT_SYMBOL(blk_dump_rq_flags);

static void blk_delay_work(struct work_struct *work)
{
	struct request_queue *q;

	q = container_of(work, struct request_queue, delay_work.work);
	spin_lock_irq(q->queue_lock);
	__blk_run_queue(q);
	spin_unlock_irq(q->queue_lock);
}

void blk_delay_queue(struct request_queue *q, unsigned long msecs)
{
	if (likely(!blk_queue_dead(q)))
		queue_delayed_work(kblockd_workqueue, &q->delay_work,
				   msecs_to_jiffies(msecs));
}
EXPORT_SYMBOL(blk_delay_queue);

void blk_start_queue_async(struct request_queue *q)
{
	queue_flag_clear(QUEUE_FLAG_STOPPED, q);
	blk_run_queue_async(q);
}
EXPORT_SYMBOL(blk_start_queue_async);

void blk_start_queue(struct request_queue *q)
{
	WARN_ON(!irqs_disabled());

	queue_flag_clear(QUEUE_FLAG_STOPPED, q);
	__blk_run_queue(q);
}
EXPORT_SYMBOL(blk_start_queue);

void blk_stop_queue(struct request_queue *q)
{
	cancel_delayed_work(&q->delay_work);
	queue_flag_set(QUEUE_FLAG_STOPPED, q);
}
EXPORT_SYMBOL(blk_stop_queue);

void blk_sync_queue(struct request_queue *q)
{
	del_timer_sync(&q->timeout);

	if (q->mq_ops) {
		struct blk_mq_hw_ctx *hctx;
		int i;

		queue_for_each_hw_ctx(q, hctx, i) {
			cancel_delayed_work_sync(&hctx->run_work);
			cancel_delayed_work_sync(&hctx->delay_work);
		}
	} else {
		cancel_delayed_work_sync(&q->delay_work);
	}
}
EXPORT_SYMBOL(blk_sync_queue);

inline void __blk_run_queue_uncond(struct request_queue *q)
{
	if (unlikely(blk_queue_dead(q)))
		return;

	q->request_fn_active++;
	q->request_fn(q);
	q->request_fn_active--;
}
EXPORT_SYMBOL_GPL(__blk_run_queue_uncond);

void __blk_run_queue(struct request_queue *q)
{
	if (unlikely(blk_queue_stopped(q)))
		return;

	__blk_run_queue_uncond(q);
}
EXPORT_SYMBOL(__blk_run_queue);

void blk_run_queue_async(struct request_queue *q)
{
	if (likely(!blk_queue_stopped(q) && !blk_queue_dead(q)))
		mod_delayed_work(kblockd_workqueue, &q->delay_work, 0);
}
EXPORT_SYMBOL(blk_run_queue_async);

void blk_run_queue(struct request_queue *q)
{
	unsigned long flags;

	spin_lock_irqsave(q->queue_lock, flags);
	__blk_run_queue(q);
	spin_unlock_irqrestore(q->queue_lock, flags);
}
EXPORT_SYMBOL(blk_run_queue);

void blk_put_queue(struct request_queue *q)
{
	kobject_put(&q->kobj);
}
EXPORT_SYMBOL(blk_put_queue);

static void __blk_drain_queue(struct request_queue *q, bool drain_all)
	__releases(q->queue_lock)
	__acquires(q->queue_lock)
{
	int i;

	lockdep_assert_held(q->queue_lock);

	while (true) {
		bool drain = false;

		if (q->elevator)
			elv_drain_elevator(q);

		blkcg_drain_queue(q);

		if (!list_empty(&q->queue_head) && q->request_fn)
			__blk_run_queue(q);

		drain |= q->nr_rqs_elvpriv;
		drain |= q->request_fn_active;

		if (drain_all) {
			struct blk_flush_queue *fq = blk_get_flush_queue(q, NULL);
			drain |= !list_empty(&q->queue_head);
			for (i = 0; i < 2; i++) {
				drain |= q->nr_rqs[i];
				drain |= q->in_flight[i];
				if (fq)
				    drain |= !list_empty(&fq->flush_queue[i]);
			}
		}

		if (!drain)
			break;

		spin_unlock_irq(q->queue_lock);

		msleep(10);

		spin_lock_irq(q->queue_lock);
	}

	if (q->request_fn) {
		struct request_list *rl;

		blk_queue_for_each_rl(rl, q)
			for (i = 0; i < ARRAY_SIZE(rl->wait); i++)
				wake_up_all(&rl->wait[i]);
	}
}

void blk_queue_bypass_start(struct request_queue *q)
{
	spin_lock_irq(q->queue_lock);
	q->bypass_depth++;
	queue_flag_set(QUEUE_FLAG_BYPASS, q);
	spin_unlock_irq(q->queue_lock);

	if (blk_queue_init_done(q)) {
		spin_lock_irq(q->queue_lock);
		__blk_drain_queue(q, false);
		spin_unlock_irq(q->queue_lock);

		synchronize_rcu();
	}
}
EXPORT_SYMBOL_GPL(blk_queue_bypass_start);

void blk_queue_bypass_end(struct request_queue *q)
{
	spin_lock_irq(q->queue_lock);
	if (!--q->bypass_depth)
		queue_flag_clear(QUEUE_FLAG_BYPASS, q);
	WARN_ON_ONCE(q->bypass_depth < 0);
	spin_unlock_irq(q->queue_lock);
}
EXPORT_SYMBOL_GPL(blk_queue_bypass_end);

void blk_set_queue_dying(struct request_queue *q)
{
	spin_lock_irq(q->queue_lock);
	queue_flag_set(QUEUE_FLAG_DYING, q);
	spin_unlock_irq(q->queue_lock);

	if (q->mq_ops)
		blk_mq_wake_waiters(q);
	else {
		struct request_list *rl;

		blk_queue_for_each_rl(rl, q) {
			if (rl->rq_pool) {
				wake_up(&rl->wait[BLK_RW_SYNC]);
				wake_up(&rl->wait[BLK_RW_ASYNC]);
			}
		}
	}
}
EXPORT_SYMBOL_GPL(blk_set_queue_dying);

void blk_cleanup_queue(struct request_queue *q)
{
	spinlock_t *lock = q->queue_lock;

	mutex_lock(&q->sysfs_lock);
	blk_set_queue_dying(q);
	spin_lock_irq(lock);

	q->bypass_depth++;
	queue_flag_set(QUEUE_FLAG_BYPASS, q);

	queue_flag_set(QUEUE_FLAG_NOMERGES, q);
	queue_flag_set(QUEUE_FLAG_NOXMERGES, q);
	queue_flag_set(QUEUE_FLAG_DYING, q);
	spin_unlock_irq(lock);
	mutex_unlock(&q->sysfs_lock);

	blk_freeze_queue(q);
	spin_lock_irq(lock);
	if (!q->mq_ops)
		__blk_drain_queue(q, true);
	queue_flag_set(QUEUE_FLAG_DEAD, q);
	spin_unlock_irq(lock);

	blk_flush_integrity();

	del_timer_sync(&q->backing_dev_info.laptop_mode_wb_timer);
	blk_sync_queue(q);

	if (q->mq_ops)
		blk_mq_free_queue(q);
	percpu_ref_exit(&q->q_usage_counter);

	spin_lock_irq(lock);
	if (q->queue_lock != &q->__queue_lock)
		q->queue_lock = &q->__queue_lock;
	spin_unlock_irq(lock);

	bdi_unregister(&q->backing_dev_info);

	blk_put_queue(q);
}
EXPORT_SYMBOL(blk_cleanup_queue);

static void *alloc_request_struct(gfp_t gfp_mask, void *data)
{
	int nid = (int)(long)data;
	return kmem_cache_alloc_node(request_cachep, gfp_mask, nid);
}

static void free_request_struct(void *element, void *unused)
{
	kmem_cache_free(request_cachep, element);
}

int blk_init_rl(struct request_list *rl, struct request_queue *q,
		gfp_t gfp_mask)
{
	if (unlikely(rl->rq_pool))
		return 0;

	rl->q = q;
	rl->count[BLK_RW_SYNC] = rl->count[BLK_RW_ASYNC] = 0;
	rl->starved[BLK_RW_SYNC] = rl->starved[BLK_RW_ASYNC] = 0;
	init_waitqueue_head(&rl->wait[BLK_RW_SYNC]);
	init_waitqueue_head(&rl->wait[BLK_RW_ASYNC]);

	rl->rq_pool = mempool_create_node(BLKDEV_MIN_RQ, alloc_request_struct,
					  free_request_struct,
					  (void *)(long)q->node, gfp_mask,
					  q->node);
	if (!rl->rq_pool)
		return -ENOMEM;

	return 0;
}

void blk_exit_rl(struct request_list *rl)
{
	if (rl->rq_pool)
		mempool_destroy(rl->rq_pool);
}

struct request_queue *blk_alloc_queue(gfp_t gfp_mask)
{
	return blk_alloc_queue_node(gfp_mask, NUMA_NO_NODE);
}
EXPORT_SYMBOL(blk_alloc_queue);

int blk_queue_enter(struct request_queue *q, gfp_t gfp)
{
	while (true) {
		int ret;

		if (percpu_ref_tryget_live(&q->q_usage_counter))
			return 0;

		if (!gfpflags_allow_blocking(gfp))
			return -EBUSY;

		ret = wait_event_interruptible(q->mq_freeze_wq,
				!atomic_read(&q->mq_freeze_depth) ||
				blk_queue_dying(q));
		if (blk_queue_dying(q))
			return -ENODEV;
		if (ret)
			return ret;
	}
}

void blk_queue_exit(struct request_queue *q)
{
	percpu_ref_put(&q->q_usage_counter);
}

static void blk_queue_usage_counter_release(struct percpu_ref *ref)
{
	struct request_queue *q =
		container_of(ref, struct request_queue, q_usage_counter);

	wake_up_all(&q->mq_freeze_wq);
}

struct request_queue *blk_alloc_queue_node(gfp_t gfp_mask, int node_id)
{
	struct request_queue *q;
	int err;

	q = kmem_cache_alloc_node(blk_requestq_cachep,
				gfp_mask | __GFP_ZERO, node_id);
	if (!q)
		return NULL;

	q->id = ida_simple_get(&blk_queue_ida, 0, 0, gfp_mask);
	if (q->id < 0)
		goto fail_q;

	q->bio_split = bioset_create(BIO_POOL_SIZE, 0);
	if (!q->bio_split)
		goto fail_id;

	q->backing_dev_info.ra_pages =
			(VM_MAX_READAHEAD * 1024) / PAGE_CACHE_SIZE;
	q->backing_dev_info.capabilities = BDI_CAP_CGROUP_WRITEBACK;
	q->backing_dev_info.name = "block";
	q->node = node_id;

	err = bdi_init(&q->backing_dev_info);
	if (err)
		goto fail_split;

	setup_timer(&q->backing_dev_info.laptop_mode_wb_timer,
		    laptop_mode_timer_fn, (unsigned long) q);
	setup_timer(&q->timeout, blk_rq_timed_out_timer, (unsigned long) q);
	INIT_LIST_HEAD(&q->queue_head);
	INIT_LIST_HEAD(&q->timeout_list);
	INIT_LIST_HEAD(&q->icq_list);
#ifdef CONFIG_BLK_CGROUP
	INIT_LIST_HEAD(&q->blkg_list);
#endif
	INIT_DELAYED_WORK(&q->delay_work, blk_delay_work);

	kobject_init(&q->kobj, &blk_queue_ktype);

	mutex_init(&q->sysfs_lock);
	spin_lock_init(&q->__queue_lock);

	q->queue_lock = &q->__queue_lock;

	q->bypass_depth = 1;
	__set_bit(QUEUE_FLAG_BYPASS, &q->queue_flags);

	init_waitqueue_head(&q->mq_freeze_wq);

	if (percpu_ref_init(&q->q_usage_counter,
				blk_queue_usage_counter_release,
				PERCPU_REF_INIT_ATOMIC, GFP_KERNEL))
		goto fail_bdi;

	if (blkcg_init_queue(q))
		goto fail_ref;

	return q;

fail_ref:
	percpu_ref_exit(&q->q_usage_counter);
fail_bdi:
	bdi_destroy(&q->backing_dev_info);
fail_split:
	bioset_free(q->bio_split);
fail_id:
	ida_simple_remove(&blk_queue_ida, q->id);
fail_q:
	kmem_cache_free(blk_requestq_cachep, q);
	return NULL;
}
EXPORT_SYMBOL(blk_alloc_queue_node);

struct request_queue *blk_init_queue(request_fn_proc *rfn, spinlock_t *lock)
{
	return blk_init_queue_node(rfn, lock, NUMA_NO_NODE);
}
EXPORT_SYMBOL(blk_init_queue);

struct request_queue *
blk_init_queue_node(request_fn_proc *rfn, spinlock_t *lock, int node_id)
{
	struct request_queue *uninit_q, *q;

	uninit_q = blk_alloc_queue_node(GFP_KERNEL, node_id);
	if (!uninit_q)
		return NULL;

	q = blk_init_allocated_queue(uninit_q, rfn, lock);
	if (!q)
		blk_cleanup_queue(uninit_q);

	return q;
}
EXPORT_SYMBOL(blk_init_queue_node);

static blk_qc_t blk_queue_bio(struct request_queue *q, struct bio *bio);

struct request_queue *
blk_init_allocated_queue(struct request_queue *q, request_fn_proc *rfn,
			 spinlock_t *lock)
{
	if (!q)
		return NULL;

	q->fq = blk_alloc_flush_queue(q, NUMA_NO_NODE, 0);
	if (!q->fq)
		return NULL;

	if (blk_init_rl(&q->root_rl, q, GFP_KERNEL))
		goto fail;

	q->request_fn		= rfn;
	q->prep_rq_fn		= NULL;
	q->unprep_rq_fn		= NULL;
	q->queue_flags		|= QUEUE_FLAG_DEFAULT;

	if (lock)
		q->queue_lock		= lock;

	blk_queue_make_request(q, blk_queue_bio);

	q->sg_reserved_size = INT_MAX;

	mutex_lock(&q->sysfs_lock);

	if (elevator_init(q, NULL)) {
		mutex_unlock(&q->sysfs_lock);
		goto fail;
	}

	mutex_unlock(&q->sysfs_lock);

	return q;

fail:
	blk_free_flush_queue(q->fq);
	wbt_exit(q->rq_wb);
	q->rq_wb = NULL;
	return NULL;
}
EXPORT_SYMBOL(blk_init_allocated_queue);

bool blk_get_queue(struct request_queue *q)
{
	if (likely(!blk_queue_dying(q))) {
		__blk_get_queue(q);
		return true;
	}

	return false;
}
EXPORT_SYMBOL(blk_get_queue);

static inline void blk_free_request(struct request_list *rl, struct request *rq)
{
	if (rq->cmd_flags & REQ_ELVPRIV) {
		elv_put_request(rl->q, rq);
		if (rq->elv.icq)
			put_io_context(rq->elv.icq->ioc);
	}

	mempool_free(rq, rl->rq_pool);
}

static inline int ioc_batching(struct request_queue *q, struct io_context *ioc)
{
	if (!ioc)
		return 0;

	return ioc->nr_batch_requests == q->nr_batching ||
		(ioc->nr_batch_requests > 0
		&& time_before(jiffies, ioc->last_waited + BLK_BATCH_TIME));
}

static void ioc_set_batching(struct request_queue *q, struct io_context *ioc)
{
	if (!ioc || ioc_batching(q, ioc))
		return;

	ioc->nr_batch_requests = q->nr_batching;
	ioc->last_waited = jiffies;
}

static void __freed_request(struct request_list *rl, int sync)
{
	struct request_queue *q = rl->q;

	if (rl->count[sync] < queue_congestion_off_threshold(q))
		blk_clear_congested(rl, sync);

	if (rl->count[sync] + 1 <= q->nr_requests) {
		if (waitqueue_active(&rl->wait[sync]))
			wake_up(&rl->wait[sync]);

		blk_clear_rl_full(rl, sync);
	}
}

static void freed_request(struct request_list *rl, unsigned int flags)
{
	struct request_queue *q = rl->q;
	int sync = rw_is_sync(flags);

	q->nr_rqs[sync]--;
	rl->count[sync]--;
	if (flags & REQ_ELVPRIV)
		q->nr_rqs_elvpriv--;

	__freed_request(rl, sync);

	if (unlikely(rl->starved[sync ^ 1]))
		__freed_request(rl, sync ^ 1);
}

int blk_update_nr_requests(struct request_queue *q, unsigned int nr)
{
	struct request_list *rl;
	int on_thresh, off_thresh;

	spin_lock_irq(q->queue_lock);
	q->nr_requests = nr;
	blk_queue_congestion_threshold(q);
	on_thresh = queue_congestion_on_threshold(q);
	off_thresh = queue_congestion_off_threshold(q);

	blk_queue_for_each_rl(rl, q) {
		if (rl->count[BLK_RW_SYNC] >= on_thresh)
			blk_set_congested(rl, BLK_RW_SYNC);
		else if (rl->count[BLK_RW_SYNC] < off_thresh)
			blk_clear_congested(rl, BLK_RW_SYNC);

		if (rl->count[BLK_RW_ASYNC] >= on_thresh)
			blk_set_congested(rl, BLK_RW_ASYNC);
		else if (rl->count[BLK_RW_ASYNC] < off_thresh)
			blk_clear_congested(rl, BLK_RW_ASYNC);

		if (rl->count[BLK_RW_SYNC] >= q->nr_requests) {
			blk_set_rl_full(rl, BLK_RW_SYNC);
		} else {
			blk_clear_rl_full(rl, BLK_RW_SYNC);
			wake_up(&rl->wait[BLK_RW_SYNC]);
		}

		if (rl->count[BLK_RW_ASYNC] >= q->nr_requests) {
			blk_set_rl_full(rl, BLK_RW_ASYNC);
		} else {
			blk_clear_rl_full(rl, BLK_RW_ASYNC);
			wake_up(&rl->wait[BLK_RW_ASYNC]);
		}
	}

	spin_unlock_irq(q->queue_lock);
	return 0;
}

static bool blk_rq_should_init_elevator(struct bio *bio)
{
	if (!bio)
		return true;

	if (bio->bi_rw & (REQ_FLUSH | REQ_FUA))
		return false;

	return true;
}

static struct io_context *rq_ioc(struct bio *bio)
{
#ifdef CONFIG_BLK_CGROUP
	if (bio && bio->bi_ioc)
		return bio->bi_ioc;
#endif
	return current->io_context;
}

static struct request *__get_request(struct request_list *rl, int rw_flags,
				     struct bio *bio, gfp_t gfp_mask)
{
	struct request_queue *q = rl->q;
	struct request *rq;
	struct elevator_type *et = q->elevator->type;
	struct io_context *ioc = rq_ioc(bio);
	struct io_cq *icq = NULL;
	const bool is_sync = rw_is_sync(rw_flags) != 0;
	int may_queue;

	if (unlikely(blk_queue_dying(q)))
		return ERR_PTR(-ENODEV);

	may_queue = elv_may_queue(q, rw_flags);
	if (may_queue == ELV_MQUEUE_NO)
		goto rq_starved;

	if (rl->count[is_sync]+1 >= queue_congestion_on_threshold(q)) {
		if (rl->count[is_sync]+1 >= q->nr_requests) {
			 
			if (!blk_rl_full(rl, is_sync)) {
				ioc_set_batching(q, ioc);
				blk_set_rl_full(rl, is_sync);
			} else {
				if (may_queue != ELV_MQUEUE_MUST
						&& !ioc_batching(q, ioc)) {
					 
					return ERR_PTR(-ENOMEM);
				}
			}
		}
		blk_set_congested(rl, is_sync);
	}

	if (rl->count[is_sync] >= (3 * q->nr_requests / 2))
		return ERR_PTR(-ENOMEM);

	q->nr_rqs[is_sync]++;
	rl->count[is_sync]++;
	rl->starved[is_sync] = 0;

	if (blk_rq_should_init_elevator(bio) && !blk_queue_bypass(q)) {
		rw_flags |= REQ_ELVPRIV;
		q->nr_rqs_elvpriv++;
		if (et->icq_cache && ioc)
			icq = ioc_lookup_icq(ioc, q);
	}

	if (blk_queue_io_stat(q))
		rw_flags |= REQ_IO_STAT;
	spin_unlock_irq(q->queue_lock);

	rq = mempool_alloc(rl->rq_pool, gfp_mask);
	if (!rq)
		goto fail_alloc;

	blk_rq_init(q, rq);
	blk_rq_set_rl(rq, rl);
	rq->cmd_flags = rw_flags | REQ_ALLOCED;

	if (rw_flags & REQ_ELVPRIV) {
		if (unlikely(et->icq_cache && !icq)) {
			if (ioc)
				icq = ioc_create_icq(ioc, q, gfp_mask);
			if (!icq)
				goto fail_elvpriv;
		}

		rq->elv.icq = icq;
		if (unlikely(elv_set_request(q, rq, bio, gfp_mask)))
			goto fail_elvpriv;

		if (icq)
			get_io_context(icq->ioc);
	}
out:
	 
	if (ioc_batching(q, ioc))
		ioc->nr_batch_requests--;

	trace_block_getrq(q, bio, rw_flags & 1);
	return rq;

fail_elvpriv:
	 
	printk_ratelimited(KERN_WARNING "%s: dev %s: request aux data allocation failed, iosched may be disturbed\n",
			   __func__, dev_name(q->backing_dev_info.dev));

	rq->cmd_flags &= ~REQ_ELVPRIV;
	rq->elv.icq = NULL;

	spin_lock_irq(q->queue_lock);
	q->nr_rqs_elvpriv--;
	spin_unlock_irq(q->queue_lock);
	goto out;

fail_alloc:
	 
	spin_lock_irq(q->queue_lock);
	freed_request(rl, rw_flags);

rq_starved:
	if (unlikely(rl->count[is_sync] == 0))
		rl->starved[is_sync] = 1;
	return ERR_PTR(-ENOMEM);
}

static struct request *get_request(struct request_queue *q, int rw_flags,
				   struct bio *bio, gfp_t gfp_mask)
{
	const bool is_sync = rw_is_sync(rw_flags) != 0;
	DEFINE_WAIT(wait);
	struct request_list *rl;
	struct request *rq;

	rl = blk_get_rl(q, bio);	 
retry:
	rq = __get_request(rl, rw_flags, bio, gfp_mask);
	if (!IS_ERR(rq))
		return rq;

	if (!gfpflags_allow_blocking(gfp_mask) || unlikely(blk_queue_dying(q))) {
		blk_put_rl(rl);
		return rq;
	}

	prepare_to_wait_exclusive(&rl->wait[is_sync], &wait,
				  TASK_UNINTERRUPTIBLE);

	trace_block_sleeprq(q, bio, rw_flags & 1);

	spin_unlock_irq(q->queue_lock);
	io_schedule();

	ioc_set_batching(q, current->io_context);

	spin_lock_irq(q->queue_lock);
	finish_wait(&rl->wait[is_sync], &wait);

	goto retry;
}

static struct request *blk_old_get_request(struct request_queue *q, int rw,
		gfp_t gfp_mask)
{
	struct request *rq;

	BUG_ON(rw != READ && rw != WRITE);

	create_io_context(gfp_mask, q->node);

	spin_lock_irq(q->queue_lock);
	rq = get_request(q, rw, NULL, gfp_mask);
	if (IS_ERR(rq))
		spin_unlock_irq(q->queue_lock);
	 
	return rq;
}

struct request *blk_get_request(struct request_queue *q, int rw, gfp_t gfp_mask)
{
	if (q->mq_ops)
		return blk_mq_alloc_request(q, rw, gfp_mask, false);
	else
		return blk_old_get_request(q, rw, gfp_mask);
}
EXPORT_SYMBOL(blk_get_request);

struct request *blk_make_request(struct request_queue *q, struct bio *bio,
				 gfp_t gfp_mask)
{
	struct request *rq = blk_get_request(q, bio_data_dir(bio), gfp_mask);

	if (IS_ERR(rq))
		return rq;

	blk_rq_set_block_pc(rq);

	for_each_bio(bio) {
		struct bio *bounce_bio = bio;
		int ret;

		blk_queue_bounce(q, &bounce_bio);
		ret = blk_rq_append_bio(q, rq, bounce_bio);
		if (unlikely(ret)) {
			blk_put_request(rq);
			return ERR_PTR(ret);
		}
	}

	return rq;
}
EXPORT_SYMBOL(blk_make_request);

void blk_rq_set_block_pc(struct request *rq)
{
	rq->cmd_type = REQ_TYPE_BLOCK_PC;
	rq->__data_len = 0;
	rq->__sector = (sector_t) -1;
	rq->bio = rq->biotail = NULL;
	memset(rq->__cmd, 0, sizeof(rq->__cmd));
}
EXPORT_SYMBOL(blk_rq_set_block_pc);

void blk_requeue_request(struct request_queue *q, struct request *rq)
{
	blk_delete_timer(rq);
	blk_clear_rq_complete(rq);
	trace_block_rq_requeue(q, rq);
	wbt_requeue(q->rq_wb, &rq->wb_stat);

	if (rq->cmd_flags & REQ_QUEUED)
		blk_queue_end_tag(q, rq);

	BUG_ON(blk_queued_rq(rq));

	elv_requeue_request(q, rq);
}
EXPORT_SYMBOL(blk_requeue_request);

static void add_acct_request(struct request_queue *q, struct request *rq,
			     int where)
{
	blk_account_io_start(rq, true);
	__elv_add_request(q, rq, where);
}

static void part_round_stats_single(int cpu, struct hd_struct *part,
				    unsigned long now)
{
	int inflight;

	if (now == part->stamp)
		return;

	inflight = part_in_flight(part);
	if (inflight) {
		__part_stat_add(cpu, part, time_in_queue,
				inflight * (now - part->stamp));
		__part_stat_add(cpu, part, io_ticks, (now - part->stamp));
	}
	part->stamp = now;
}

void part_round_stats(int cpu, struct hd_struct *part)
{
	unsigned long now = jiffies;

	if (part->partno)
		part_round_stats_single(cpu, &part_to_disk(part)->part0, now);
	part_round_stats_single(cpu, part, now);
}
EXPORT_SYMBOL_GPL(part_round_stats);

#ifdef CONFIG_PM
static void blk_pm_put_request(struct request *rq)
{
	if (rq->q->dev && !(rq->cmd_flags & REQ_PM) && !--rq->q->nr_pending)
		pm_runtime_mark_last_busy(rq->q->dev);
}
#else
static inline void blk_pm_put_request(struct request *rq) {}
#endif

void __blk_put_request(struct request_queue *q, struct request *req)
{
	if (unlikely(!q))
		return;

	if (q->mq_ops) {
		blk_mq_free_request(req);
		return;
	}

	blk_pm_put_request(req);

	elv_completed_request(q, req);

	WARN_ON(req->bio != NULL);

	wbt_done(q->rq_wb, &req->wb_stat);

	if (req->cmd_flags & REQ_ALLOCED) {
		unsigned int flags = req->cmd_flags;
		struct request_list *rl = blk_rq_rl(req);

		BUG_ON(!list_empty(&req->queuelist));
		BUG_ON(ELV_ON_HASH(req));

		blk_free_request(rl, req);
		freed_request(rl, flags);
		blk_put_rl(rl);
	}
}
EXPORT_SYMBOL_GPL(__blk_put_request);

void blk_put_request(struct request *req)
{
	struct request_queue *q = req->q;

	if (q->mq_ops)
		blk_mq_free_request(req);
	else {
		unsigned long flags;

		spin_lock_irqsave(q->queue_lock, flags);
		__blk_put_request(q, req);
		spin_unlock_irqrestore(q->queue_lock, flags);
	}
}
EXPORT_SYMBOL(blk_put_request);

void blk_add_request_payload(struct request *rq, struct page *page,
		unsigned int len)
{
	struct bio *bio = rq->bio;

	bio->bi_io_vec->bv_page = page;
	bio->bi_io_vec->bv_offset = 0;
	bio->bi_io_vec->bv_len = len;

	bio->bi_iter.bi_size = len;
	bio->bi_vcnt = 1;
	bio->bi_phys_segments = 1;

	rq->__data_len = rq->resid_len = len;
	rq->nr_phys_segments = 1;
}
EXPORT_SYMBOL_GPL(blk_add_request_payload);

bool bio_attempt_back_merge(struct request_queue *q, struct request *req,
			    struct bio *bio)
{
	const int ff = bio->bi_rw & REQ_FAILFAST_MASK;

	if (!ll_back_merge_fn(q, req, bio))
		return false;

	trace_block_bio_backmerge(q, req, bio);

	if ((req->cmd_flags & REQ_FAILFAST_MASK) != ff)
		blk_rq_set_mixed_merge(req);

	req->biotail->bi_next = bio;
	req->biotail = bio;
	req->__data_len += bio->bi_iter.bi_size;
	req->ioprio = ioprio_best(req->ioprio, bio_prio(bio));

	blk_account_io_start(req, false);
	return true;
}

bool bio_attempt_front_merge(struct request_queue *q, struct request *req,
			     struct bio *bio)
{
	const int ff = bio->bi_rw & REQ_FAILFAST_MASK;

	if (!ll_front_merge_fn(q, req, bio))
		return false;

	trace_block_bio_frontmerge(q, req, bio);

	if ((req->cmd_flags & REQ_FAILFAST_MASK) != ff)
		blk_rq_set_mixed_merge(req);

	bio->bi_next = req->bio;
	req->bio = bio;

	req->__sector = bio->bi_iter.bi_sector;
	req->__data_len += bio->bi_iter.bi_size;
	req->ioprio = ioprio_best(req->ioprio, bio_prio(bio));

	blk_account_io_start(req, false);
	return true;
}

bool blk_attempt_plug_merge(struct request_queue *q, struct bio *bio,
			    unsigned int *request_count,
			    struct request **same_queue_rq)
{
	struct blk_plug *plug;
	struct request *rq;
	bool ret = false;
	struct list_head *plug_list;

	plug = current->plug;
	if (!plug)
		goto out;
	*request_count = 0;

	if (q->mq_ops)
		plug_list = &plug->mq_list;
	else
		plug_list = &plug->list;

	list_for_each_entry_reverse(rq, plug_list, queuelist) {
		int el_ret;

		if (rq->q == q) {
			(*request_count)++;
			 
			if (same_queue_rq)
				*same_queue_rq = rq;
		}

		if (rq->q != q || !blk_rq_merge_ok(rq, bio))
			continue;

		el_ret = blk_try_merge(rq, bio);
		if (el_ret == ELEVATOR_BACK_MERGE) {
			ret = bio_attempt_back_merge(q, rq, bio);
			if (ret)
				break;
		} else if (el_ret == ELEVATOR_FRONT_MERGE) {
			ret = bio_attempt_front_merge(q, rq, bio);
			if (ret)
				break;
		}
	}
out:
	return ret;
}

unsigned int blk_plug_queued_count(struct request_queue *q)
{
	struct blk_plug *plug;
	struct request *rq;
	struct list_head *plug_list;
	unsigned int ret = 0;

	plug = current->plug;
	if (!plug)
		goto out;

	if (q->mq_ops)
		plug_list = &plug->mq_list;
	else
		plug_list = &plug->list;

	list_for_each_entry(rq, plug_list, queuelist) {
		if (rq->q == q)
			ret++;
	}
out:
	return ret;
}

void init_request_from_bio(struct request *req, struct bio *bio)
{
	req->cmd_type = REQ_TYPE_FS;

	req->cmd_flags |= bio->bi_rw & REQ_COMMON_MASK;
	if (bio->bi_rw & REQ_RAHEAD)
		req->cmd_flags |= REQ_FAILFAST_MASK;

	req->errors = 0;
	req->__sector = bio->bi_iter.bi_sector;
	req->ioprio = bio_prio(bio);
	blk_rq_bio_prep(req->q, req, bio);
}

static blk_qc_t blk_queue_bio(struct request_queue *q, struct bio *bio)
{
	const bool sync = !!(bio->bi_rw & REQ_SYNC);
	struct blk_plug *plug;
	int el_ret, rw_flags, where = ELEVATOR_INSERT_SORT;
	struct request *req;
	unsigned int request_count = 0;
	unsigned int wb_acct;

	blk_queue_bounce(q, &bio);

	blk_queue_split(q, &bio, q->bio_split);

	if (bio_integrity_enabled(bio) && bio_integrity_prep(bio)) {
		bio->bi_error = -EIO;
		bio_endio(bio);
		return BLK_QC_T_NONE;
	}

	if (bio->bi_rw & (REQ_FLUSH | REQ_FUA)) {
		spin_lock_irq(q->queue_lock);
		where = ELEVATOR_INSERT_FLUSH;
		goto get_rq;
	}

	if (!blk_queue_nomerges(q)) {
		if (blk_attempt_plug_merge(q, bio, &request_count, NULL))
			return BLK_QC_T_NONE;
	} else
		request_count = blk_plug_queued_count(q);

	spin_lock_irq(q->queue_lock);

	el_ret = elv_merge(q, &req, bio);
	if (el_ret == ELEVATOR_BACK_MERGE) {
		if (bio_attempt_back_merge(q, req, bio)) {
			elv_bio_merged(q, req, bio);
			if (!attempt_back_merge(q, req))
				elv_merged_request(q, req, el_ret);
			goto out_unlock;
		}
	} else if (el_ret == ELEVATOR_FRONT_MERGE) {
		if (bio_attempt_front_merge(q, req, bio)) {
			elv_bio_merged(q, req, bio);
			if (!attempt_front_merge(q, req))
				elv_merged_request(q, req, el_ret);
			goto out_unlock;
		}
	}

get_rq:
	wb_acct = wbt_wait(q->rq_wb, bio->bi_rw, q->queue_lock);

	rw_flags = bio_data_dir(bio);
	if (sync)
		rw_flags |= REQ_SYNC;

	req = get_request(q, rw_flags, bio, GFP_NOIO);
	if (IS_ERR(req)) {
		__wbt_done(q->rq_wb, wb_acct);
		bio->bi_error = PTR_ERR(req);
		bio_endio(bio);
		goto out_unlock;
	}

	wbt_track(&req->wb_stat, wb_acct);

	init_request_from_bio(req, bio);

	if (test_bit(QUEUE_FLAG_SAME_COMP, &q->queue_flags))
		req->cpu = raw_smp_processor_id();

	plug = current->plug;
	if (plug) {
		 
		if (!request_count)
			trace_block_plug(q);
		else {
			if (request_count >= BLK_MAX_REQUEST_COUNT) {
				blk_flush_plug_list(plug, false);
				trace_block_plug(q);
			}
		}
		list_add_tail(&req->queuelist, &plug->list);
		blk_account_io_start(req, true);
	} else {
		spin_lock_irq(q->queue_lock);
		add_acct_request(q, req, where);
		__blk_run_queue(q);
out_unlock:
		spin_unlock_irq(q->queue_lock);
	}

	return BLK_QC_T_NONE;
}

static inline void blk_partition_remap(struct bio *bio)
{
	struct block_device *bdev = bio->bi_bdev;

	if (bio_sectors(bio) && bdev != bdev->bd_contains) {
		struct hd_struct *p = bdev->bd_part;

		bio->bi_iter.bi_sector += p->start_sect;
		bio->bi_bdev = bdev->bd_contains;

		trace_block_bio_remap(bdev_get_queue(bio->bi_bdev), bio,
				      bdev->bd_dev,
				      bio->bi_iter.bi_sector - p->start_sect);
	}
}

static void handle_bad_sector(struct bio *bio)
{
	char b[BDEVNAME_SIZE];
#ifdef MY_ABC_HERE
    if (printk_ratelimit()) {
#endif  
	printk(KERN_INFO "attempt to access beyond end of device\n");
	printk(KERN_INFO "%s: rw=%ld, want=%Lu, limit=%Lu\n",
			bdevname(bio->bi_bdev, b),
			bio->bi_rw,
			(unsigned long long)bio_end_sector(bio),
			(long long)(i_size_read(bio->bi_bdev->bd_inode) >> 9));
#ifdef MY_ABC_HERE
    }
#endif  
}

#ifdef CONFIG_FAIL_MAKE_REQUEST

static DECLARE_FAULT_ATTR(fail_make_request);

static int __init setup_fail_make_request(char *str)
{
	return setup_fault_attr(&fail_make_request, str);
}
__setup("fail_make_request=", setup_fail_make_request);

static bool should_fail_request(struct hd_struct *part, unsigned int bytes)
{
	return part->make_it_fail && should_fail(&fail_make_request, bytes);
}

static int __init fail_make_request_debugfs(void)
{
	struct dentry *dir = fault_create_debugfs_attr("fail_make_request",
						NULL, &fail_make_request);

	return PTR_ERR_OR_ZERO(dir);
}

late_initcall(fail_make_request_debugfs);

#else  

static inline bool should_fail_request(struct hd_struct *part,
					unsigned int bytes)
{
	return false;
}

#endif  

static inline int bio_check_eod(struct bio *bio, unsigned int nr_sectors)
{
	sector_t maxsector;

	if (!nr_sectors)
		return 0;

	maxsector = i_size_read(bio->bi_bdev->bd_inode) >> 9;
	if (maxsector) {
		sector_t sector = bio->bi_iter.bi_sector;

		if (maxsector < nr_sectors || maxsector - nr_sectors < sector) {
			 
			handle_bad_sector(bio);
			return 1;
		}
	}

	return 0;
}

static noinline_for_stack bool
generic_make_request_checks(struct bio *bio)
{
	struct request_queue *q;
	int nr_sectors = bio_sectors(bio);
	int err = -EIO;
	char b[BDEVNAME_SIZE];
	struct hd_struct *part;

	might_sleep();

	if (bio_check_eod(bio, nr_sectors))
		goto end_io;

	q = bdev_get_queue(bio->bi_bdev);
	if (unlikely(!q)) {
		printk(KERN_ERR
		       "generic_make_request: Trying to access "
			"nonexistent block-device %s (%Lu)\n",
			bdevname(bio->bi_bdev, b),
			(long long) bio->bi_iter.bi_sector);
		goto end_io;
	}

	part = bio->bi_bdev->bd_part;
	if (should_fail_request(part, bio->bi_iter.bi_size) ||
	    should_fail_request(&part_to_disk(part)->part0,
				bio->bi_iter.bi_size))
		goto end_io;

	blk_partition_remap(bio);

	if (bio_check_eod(bio, nr_sectors))
		goto end_io;

	if ((bio->bi_rw & (REQ_FLUSH | REQ_FUA)) &&
	    !test_bit(QUEUE_FLAG_WC, &q->queue_flags)) {
		bio->bi_rw &= ~(REQ_FLUSH | REQ_FUA);
		if (!nr_sectors) {
			err = 0;
			goto end_io;
		}
	}

	if ((bio->bi_rw & REQ_DISCARD) &&
	    (!blk_queue_discard(q) ||
	     ((bio->bi_rw & REQ_SECURE) && !blk_queue_secdiscard(q)))) {
		err = -EOPNOTSUPP;
		goto end_io;
	}

	if (bio->bi_rw & REQ_WRITE_SAME && !bdev_write_same(bio->bi_bdev)) {
		err = -EOPNOTSUPP;
		goto end_io;
	}

	create_io_context(GFP_ATOMIC, q->node);

	if (!blkcg_bio_issue_check(q, bio))
		return false;

	trace_block_bio_queue(q, bio);
	return true;

end_io:
	bio->bi_error = err;
	bio_endio(bio);
	return false;
}

blk_qc_t generic_make_request(struct bio *bio)
{
	struct bio_list bio_list_on_stack;
	blk_qc_t ret = BLK_QC_T_NONE;

	if (!generic_make_request_checks(bio))
		goto out;

	if (current->bio_list) {
		bio_list_add(current->bio_list, bio);
		goto out;
	}

	BUG_ON(bio->bi_next);
	bio_list_init(&bio_list_on_stack);
	current->bio_list = &bio_list_on_stack;
	do {
		struct request_queue *q = bdev_get_queue(bio->bi_bdev);

		if (likely(blk_queue_enter(q, __GFP_DIRECT_RECLAIM) == 0)) {

			ret = q->make_request_fn(q, bio);

			blk_queue_exit(q);

			bio = bio_list_pop(current->bio_list);
		} else {
			struct bio *bio_next = bio_list_pop(current->bio_list);

			bio_io_error(bio);
			bio = bio_next;
		}
	} while (bio);
	current->bio_list = NULL;  

out:
	return ret;
}
EXPORT_SYMBOL(generic_make_request);

blk_qc_t submit_bio(int rw, struct bio *bio)
{
	bio->bi_rw |= rw;

	if (bio_has_data(bio)) {
		unsigned int count;

		if (unlikely(rw & REQ_WRITE_SAME))
			count = bdev_logical_block_size(bio->bi_bdev) >> 9;
		else
			count = bio_sectors(bio);

		if (rw & WRITE) {
			count_vm_events(PGPGOUT, count);
		} else {
			task_io_account_read(bio->bi_iter.bi_size);
			count_vm_events(PGPGIN, count);
		}

		if (unlikely(block_dump)) {
			char b[BDEVNAME_SIZE];
			printk(KERN_DEBUG "%s(%d): %s block %Lu on %s (%u sectors)\n",
			current->comm, task_pid_nr(current),
				(rw & WRITE) ? "WRITE" : "READ",
				(unsigned long long)bio->bi_iter.bi_sector,
				bdevname(bio->bi_bdev, b),
				count);
		}

#ifdef MY_ABC_HERE
		if (0 < gSynoHibernationLogLevel) {
			char b[BDEVNAME_SIZE];
			syno_do_hibernation_bio_log(bdevname(bio->bi_bdev, b));
		}
#endif  

	}

	return generic_make_request(bio);
}
EXPORT_SYMBOL(submit_bio);

static int blk_cloned_rq_check_limits(struct request_queue *q,
				      struct request *rq)
{
	if (blk_rq_sectors(rq) > blk_queue_get_max_sectors(q, rq->cmd_flags)) {
		printk(KERN_ERR "%s: over max size limit.\n", __func__);
		return -EIO;
	}

	blk_recalc_rq_segments(rq);
	if (rq->nr_phys_segments > queue_max_segments(q)) {
		printk(KERN_ERR "%s: over max segments limit.\n", __func__);
		return -EIO;
	}

	return 0;
}

int blk_insert_cloned_request(struct request_queue *q, struct request *rq)
{
	unsigned long flags;
	int where = ELEVATOR_INSERT_BACK;

	if (blk_cloned_rq_check_limits(q, rq))
		return -EIO;

	if (rq->rq_disk &&
	    should_fail_request(&rq->rq_disk->part0, blk_rq_bytes(rq)))
		return -EIO;

	if (q->mq_ops) {
		if (blk_queue_io_stat(q))
			blk_account_io_start(rq, true);
		blk_mq_insert_request(rq, false, true, false);
		return 0;
	}

	spin_lock_irqsave(q->queue_lock, flags);
	if (unlikely(blk_queue_dying(q))) {
		spin_unlock_irqrestore(q->queue_lock, flags);
		return -ENODEV;
	}

	BUG_ON(blk_queued_rq(rq));

	if (rq->cmd_flags & (REQ_FLUSH|REQ_FUA))
		where = ELEVATOR_INSERT_FLUSH;

	add_acct_request(q, rq, where);
	if (where == ELEVATOR_INSERT_FLUSH)
		__blk_run_queue(q);
	spin_unlock_irqrestore(q->queue_lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(blk_insert_cloned_request);

unsigned int blk_rq_err_bytes(const struct request *rq)
{
	unsigned int ff = rq->cmd_flags & REQ_FAILFAST_MASK;
	unsigned int bytes = 0;
	struct bio *bio;

	if (!(rq->cmd_flags & REQ_MIXED_MERGE))
		return blk_rq_bytes(rq);

	for (bio = rq->bio; bio; bio = bio->bi_next) {
		if ((bio->bi_rw & ff) != ff)
			break;
		bytes += bio->bi_iter.bi_size;
	}

	BUG_ON(blk_rq_bytes(rq) && !bytes);
	return bytes;
}
EXPORT_SYMBOL_GPL(blk_rq_err_bytes);

void blk_account_io_completion(struct request *req, unsigned int bytes)
{
	if (blk_do_io_stat(req)) {
		const int rw = rq_data_dir(req);
		struct hd_struct *part;
		int cpu;

		cpu = part_stat_lock();
		part = req->part;
		part_stat_add(cpu, part, sectors[rw], bytes >> 9);
		part_stat_unlock();
	}
}

void blk_account_io_done(struct request *req)
{
	 
	if (blk_do_io_stat(req) && !(req->cmd_flags & REQ_FLUSH_SEQ)) {
		unsigned long duration = jiffies - req->start_time;
		const int rw = rq_data_dir(req);
		struct hd_struct *part;
		int cpu;

		cpu = part_stat_lock();
		part = req->part;

		part_stat_inc(cpu, part, ios[rw]);
		part_stat_add(cpu, part, ticks[rw], duration);
		part_round_stats(cpu, part);
		part_dec_in_flight(part, rw);

		hd_struct_put(part);
		part_stat_unlock();
	}
}

#ifdef CONFIG_PM
 
static struct request *blk_pm_peek_request(struct request_queue *q,
					   struct request *rq)
{
	if (q->dev && (q->rpm_status == RPM_SUSPENDED ||
	    (q->rpm_status != RPM_ACTIVE && !(rq->cmd_flags & REQ_PM))))
		return NULL;
	else
		return rq;
}
#else
static inline struct request *blk_pm_peek_request(struct request_queue *q,
						  struct request *rq)
{
	return rq;
}
#endif

void blk_account_io_start(struct request *rq, bool new_io)
{
	struct hd_struct *part;
	int rw = rq_data_dir(rq);
	int cpu;

	if (!blk_do_io_stat(rq))
		return;

	cpu = part_stat_lock();

	if (!new_io) {
		part = rq->part;
		part_stat_inc(cpu, part, merges[rw]);
	} else {
		part = disk_map_sector_rcu(rq->rq_disk, blk_rq_pos(rq));
		if (!hd_struct_try_get(part)) {
			 
			part = &rq->rq_disk->part0;
			hd_struct_get(part);
		}
		part_round_stats(cpu, part);
		part_inc_in_flight(part, rw);
		rq->part = part;
	}

	part_stat_unlock();
}

struct request *blk_peek_request(struct request_queue *q)
{
	struct request *rq;
	int ret;

	while ((rq = __elv_next_request(q)) != NULL) {

		rq = blk_pm_peek_request(q, rq);
		if (!rq)
			break;

		if (!(rq->cmd_flags & REQ_STARTED)) {
			 
			if (rq->cmd_flags & REQ_SORTED)
				elv_activate_rq(q, rq);

			rq->cmd_flags |= REQ_STARTED;
			trace_block_rq_issue(q, rq);
		}

		if (!q->boundary_rq || q->boundary_rq == rq) {
			q->end_sector = rq_end_sector(rq);
			q->boundary_rq = NULL;
		}

		if (rq->cmd_flags & REQ_DONTPREP)
			break;

		if (q->dma_drain_size && blk_rq_bytes(rq)) {
			 
			rq->nr_phys_segments++;
		}

		if (!q->prep_rq_fn)
			break;

		ret = q->prep_rq_fn(q, rq);
		if (ret == BLKPREP_OK) {
			break;
		} else if (ret == BLKPREP_DEFER) {
			 
			if (q->dma_drain_size && blk_rq_bytes(rq) &&
			    !(rq->cmd_flags & REQ_DONTPREP)) {
				 
				--rq->nr_phys_segments;
			}

			rq = NULL;
			break;
		} else if (ret == BLKPREP_KILL) {
			rq->cmd_flags |= REQ_QUIET;
			 
			blk_start_request(rq);
			__blk_end_request_all(rq, -EIO);
		} else {
			printk(KERN_ERR "%s: bad return=%d\n", __func__, ret);
			break;
		}
	}

	return rq;
}
EXPORT_SYMBOL(blk_peek_request);

void blk_dequeue_request(struct request *rq)
{
	struct request_queue *q = rq->q;

	BUG_ON(list_empty(&rq->queuelist));
	BUG_ON(ELV_ON_HASH(rq));

	list_del_init(&rq->queuelist);

	if (blk_account_rq(rq)) {
		q->in_flight[rq_is_sync(rq)]++;
		set_io_start_time_ns(rq);
	}
}

void blk_start_request(struct request *req)
{
	blk_dequeue_request(req);

	wbt_issue(req->q->rq_wb, &req->wb_stat);

	req->resid_len = blk_rq_bytes(req);
	if (unlikely(blk_bidi_rq(req)))
		req->next_rq->resid_len = blk_rq_bytes(req->next_rq);

	BUG_ON(test_bit(REQ_ATOM_COMPLETE, &req->atomic_flags));
	blk_add_timer(req);
}
EXPORT_SYMBOL(blk_start_request);

struct request *blk_fetch_request(struct request_queue *q)
{
	struct request *rq;

	rq = blk_peek_request(q);
	if (rq)
		blk_start_request(rq);
	return rq;
}
EXPORT_SYMBOL(blk_fetch_request);

bool blk_update_request(struct request *req, int error, unsigned int nr_bytes)
{
	int total_bytes;

#ifdef MY_ABC_HERE
	static unsigned long long blk_rq_pos_last = 0;
#endif  

	trace_block_rq_complete(req->q, req, nr_bytes);

	blk_stat_add(&req->q->rq_stats[rq_data_dir(req)], req);

	if (!req->bio)
		return false;

	if (req->cmd_type == REQ_TYPE_FS)
		req->errors = 0;

	if (error && req->cmd_type == REQ_TYPE_FS &&
	    !(req->cmd_flags & REQ_QUIET)) {
		char *error_type;

		switch (error) {
		case -ENOLINK:
			error_type = "recoverable transport";
			break;
		case -EREMOTEIO:
			error_type = "critical target";
			break;
		case -EBADE:
			error_type = "critical nexus";
			break;
		case -ETIMEDOUT:
			error_type = "timeout";
			break;
		case -ENOSPC:
			error_type = "critical space allocation";
			break;
		case -ENODATA:
			error_type = "critical medium";
			break;
		case -EIO:
		default:
			error_type = "I/O";
			break;
		}
#ifdef MY_ABC_HERE
		if (blk_rq_pos_last == (unsigned long long)blk_rq_pos(req)) {
			printk_ratelimited(KERN_ERR "%s: %s error, dev %s, sector %llu\n",
					__func__, error_type, req->rq_disk ?
					req->rq_disk->disk_name : "?",
					blk_rq_pos_last);
		} else {
			blk_rq_pos_last = (unsigned long long)blk_rq_pos(req);
			printk_ratelimited(KERN_ERR "%s: %s error, dev %s, sector in range %llu + 0-2(%d)\n",
					__func__, error_type, req->rq_disk ?
					req->rq_disk->disk_name : "?",
					(blk_rq_pos_last >> CONFIG_SYNO_IO_ERROR_LIMIT_MSG_SHIFT) << CONFIG_SYNO_IO_ERROR_LIMIT_MSG_SHIFT,
					CONFIG_SYNO_IO_ERROR_LIMIT_MSG_SHIFT);
		}
#else
		printk_ratelimited(KERN_ERR "%s: %s error, dev %s, sector %llu\n",
				   __func__, error_type, req->rq_disk ?
				   req->rq_disk->disk_name : "?",
				   (unsigned long long)blk_rq_pos(req));
#endif  
	}

	blk_account_io_completion(req, nr_bytes);

	total_bytes = 0;
	while (req->bio) {
		struct bio *bio = req->bio;
		unsigned bio_bytes = min(bio->bi_iter.bi_size, nr_bytes);

		if (bio_bytes == bio->bi_iter.bi_size)
			req->bio = bio->bi_next;

		req_bio_endio(req, bio, bio_bytes, error);

		total_bytes += bio_bytes;
		nr_bytes -= bio_bytes;

		if (!nr_bytes)
			break;
	}

	if (!req->bio) {
		 
		req->__data_len = 0;
		return false;
	}

	req->__data_len -= total_bytes;

	if (req->cmd_type == REQ_TYPE_FS)
		req->__sector += total_bytes >> 9;

	if (req->cmd_flags & REQ_MIXED_MERGE) {
		req->cmd_flags &= ~REQ_FAILFAST_MASK;
		req->cmd_flags |= req->bio->bi_rw & REQ_FAILFAST_MASK;
	}

	if (blk_rq_bytes(req) < blk_rq_cur_bytes(req)) {
		blk_dump_rq_flags(req, "request botched");
		req->__data_len = blk_rq_cur_bytes(req);
	}

	blk_recalc_rq_segments(req);

	return true;
}
EXPORT_SYMBOL_GPL(blk_update_request);

static bool blk_update_bidi_request(struct request *rq, int error,
				    unsigned int nr_bytes,
				    unsigned int bidi_bytes)
{
	if (blk_update_request(rq, error, nr_bytes))
		return true;

	if (unlikely(blk_bidi_rq(rq)) &&
	    blk_update_request(rq->next_rq, error, bidi_bytes))
		return true;

	if (blk_queue_add_random(rq->q))
		add_disk_randomness(rq->rq_disk);

	return false;
}

void blk_unprep_request(struct request *req)
{
	struct request_queue *q = req->q;

	req->cmd_flags &= ~REQ_DONTPREP;
	if (q->unprep_rq_fn)
		q->unprep_rq_fn(q, req);
}
EXPORT_SYMBOL_GPL(blk_unprep_request);

void blk_finish_request(struct request *req, int error)
{
	if (req->cmd_flags & REQ_QUEUED)
		blk_queue_end_tag(req->q, req);

	BUG_ON(blk_queued_rq(req));

	if (unlikely(laptop_mode) && req->cmd_type == REQ_TYPE_FS)
		laptop_io_completion(&req->q->backing_dev_info);

	blk_delete_timer(req);

	if (req->cmd_flags & REQ_DONTPREP)
		blk_unprep_request(req);

	blk_account_io_done(req);

	if (req->end_io) {
		wbt_done(req->q->rq_wb, &req->wb_stat);
		req->end_io(req, error);
	} else {
		if (blk_bidi_rq(req))
			__blk_put_request(req->next_rq->q, req->next_rq);

		__blk_put_request(req->q, req);
	}
}
EXPORT_SYMBOL(blk_finish_request);

static bool blk_end_bidi_request(struct request *rq, int error,
				 unsigned int nr_bytes, unsigned int bidi_bytes)
{
	struct request_queue *q = rq->q;
	unsigned long flags;

	if (blk_update_bidi_request(rq, error, nr_bytes, bidi_bytes))
		return true;

	spin_lock_irqsave(q->queue_lock, flags);
	blk_finish_request(rq, error);
	spin_unlock_irqrestore(q->queue_lock, flags);

	return false;
}

bool __blk_end_bidi_request(struct request *rq, int error,
				   unsigned int nr_bytes, unsigned int bidi_bytes)
{
	if (blk_update_bidi_request(rq, error, nr_bytes, bidi_bytes))
		return true;

	blk_finish_request(rq, error);

	return false;
}

bool blk_end_request(struct request *rq, int error, unsigned int nr_bytes)
{
	return blk_end_bidi_request(rq, error, nr_bytes, 0);
}
EXPORT_SYMBOL(blk_end_request);

void blk_end_request_all(struct request *rq, int error)
{
	bool pending;
	unsigned int bidi_bytes = 0;

	if (unlikely(blk_bidi_rq(rq)))
		bidi_bytes = blk_rq_bytes(rq->next_rq);

	pending = blk_end_bidi_request(rq, error, blk_rq_bytes(rq), bidi_bytes);
	BUG_ON(pending);
}
EXPORT_SYMBOL(blk_end_request_all);

bool blk_end_request_cur(struct request *rq, int error)
{
	return blk_end_request(rq, error, blk_rq_cur_bytes(rq));
}
EXPORT_SYMBOL(blk_end_request_cur);

bool blk_end_request_err(struct request *rq, int error)
{
	WARN_ON(error >= 0);
	return blk_end_request(rq, error, blk_rq_err_bytes(rq));
}
EXPORT_SYMBOL_GPL(blk_end_request_err);

bool __blk_end_request(struct request *rq, int error, unsigned int nr_bytes)
{
	return __blk_end_bidi_request(rq, error, nr_bytes, 0);
}
EXPORT_SYMBOL(__blk_end_request);

void __blk_end_request_all(struct request *rq, int error)
{
	bool pending;
	unsigned int bidi_bytes = 0;

	if (unlikely(blk_bidi_rq(rq)))
		bidi_bytes = blk_rq_bytes(rq->next_rq);

	pending = __blk_end_bidi_request(rq, error, blk_rq_bytes(rq), bidi_bytes);
	BUG_ON(pending);
}
EXPORT_SYMBOL(__blk_end_request_all);

bool __blk_end_request_cur(struct request *rq, int error)
{
	return __blk_end_request(rq, error, blk_rq_cur_bytes(rq));
}
EXPORT_SYMBOL(__blk_end_request_cur);

bool __blk_end_request_err(struct request *rq, int error)
{
	WARN_ON(error >= 0);
	return __blk_end_request(rq, error, blk_rq_err_bytes(rq));
}
EXPORT_SYMBOL_GPL(__blk_end_request_err);

void blk_rq_bio_prep(struct request_queue *q, struct request *rq,
		     struct bio *bio)
{
	 
	rq->cmd_flags |= bio->bi_rw & REQ_WRITE;

	if (bio_has_data(bio))
		rq->nr_phys_segments = bio_phys_segments(q, bio);

	rq->__data_len = bio->bi_iter.bi_size;
	rq->bio = rq->biotail = bio;

	if (bio->bi_bdev)
		rq->rq_disk = bio->bi_bdev->bd_disk;
}

#if ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE
 
void rq_flush_dcache_pages(struct request *rq)
{
	struct req_iterator iter;
	struct bio_vec bvec;

	rq_for_each_segment(bvec, rq, iter)
		flush_dcache_page(bvec.bv_page);
}
EXPORT_SYMBOL_GPL(rq_flush_dcache_pages);
#endif

int blk_lld_busy(struct request_queue *q)
{
	if (q->lld_busy_fn)
		return q->lld_busy_fn(q);

	return 0;
}
EXPORT_SYMBOL_GPL(blk_lld_busy);

void blk_rq_unprep_clone(struct request *rq)
{
	struct bio *bio;

	while ((bio = rq->bio) != NULL) {
		rq->bio = bio->bi_next;

		bio_put(bio);
	}
}
EXPORT_SYMBOL_GPL(blk_rq_unprep_clone);

static void __blk_rq_prep_clone(struct request *dst, struct request *src)
{
	dst->cpu = src->cpu;
	dst->cmd_flags |= (src->cmd_flags & REQ_CLONE_MASK) | REQ_NOMERGE;
	dst->cmd_type = src->cmd_type;
	dst->__sector = blk_rq_pos(src);
	dst->__data_len = blk_rq_bytes(src);
	dst->nr_phys_segments = src->nr_phys_segments;
	dst->ioprio = src->ioprio;
	dst->extra_len = src->extra_len;
}

int blk_rq_prep_clone(struct request *rq, struct request *rq_src,
		      struct bio_set *bs, gfp_t gfp_mask,
		      int (*bio_ctr)(struct bio *, struct bio *, void *),
		      void *data)
{
	struct bio *bio, *bio_src;

	if (!bs)
		bs = fs_bio_set;

	__rq_for_each_bio(bio_src, rq_src) {
		bio = bio_clone_fast(bio_src, gfp_mask, bs);
		if (!bio)
			goto free_and_out;

		if (bio_ctr && bio_ctr(bio, bio_src, data))
			goto free_and_out;

		if (rq->bio) {
			rq->biotail->bi_next = bio;
			rq->biotail = bio;
		} else
			rq->bio = rq->biotail = bio;
	}

	__blk_rq_prep_clone(rq, rq_src);

	return 0;

free_and_out:
	if (bio)
		bio_put(bio);
	blk_rq_unprep_clone(rq);

	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(blk_rq_prep_clone);

int kblockd_schedule_work(struct work_struct *work)
{
	return queue_work(kblockd_workqueue, work);
}
EXPORT_SYMBOL(kblockd_schedule_work);

int kblockd_schedule_delayed_work(struct delayed_work *dwork,
				  unsigned long delay)
{
	return queue_delayed_work(kblockd_workqueue, dwork, delay);
}
EXPORT_SYMBOL(kblockd_schedule_delayed_work);

int kblockd_schedule_delayed_work_on(int cpu, struct delayed_work *dwork,
				     unsigned long delay)
{
	return queue_delayed_work_on(cpu, kblockd_workqueue, dwork, delay);
}
EXPORT_SYMBOL(kblockd_schedule_delayed_work_on);

void blk_start_plug(struct blk_plug *plug)
{
	struct task_struct *tsk = current;

	if (tsk->plug)
		return;

	INIT_LIST_HEAD(&plug->list);
	INIT_LIST_HEAD(&plug->mq_list);
	INIT_LIST_HEAD(&plug->cb_list);
	 
	tsk->plug = plug;
}
EXPORT_SYMBOL(blk_start_plug);

static int plug_rq_cmp(void *priv, struct list_head *a, struct list_head *b)
{
	struct request *rqa = container_of(a, struct request, queuelist);
	struct request *rqb = container_of(b, struct request, queuelist);

	return !(rqa->q < rqb->q ||
		(rqa->q == rqb->q && blk_rq_pos(rqa) < blk_rq_pos(rqb)));
}

static void queue_unplugged(struct request_queue *q, unsigned int depth,
			    bool from_schedule)
	__releases(q->queue_lock)
{
	trace_block_unplug(q, depth, !from_schedule);

	if (from_schedule)
		blk_run_queue_async(q);
	else
		__blk_run_queue(q);
	spin_unlock(q->queue_lock);
}

static void flush_plug_callbacks(struct blk_plug *plug, bool from_schedule)
{
	LIST_HEAD(callbacks);

	while (!list_empty(&plug->cb_list)) {
		list_splice_init(&plug->cb_list, &callbacks);

		while (!list_empty(&callbacks)) {
			struct blk_plug_cb *cb = list_first_entry(&callbacks,
							  struct blk_plug_cb,
							  list);
			list_del(&cb->list);
			cb->callback(cb, from_schedule);
		}
	}
}

struct blk_plug_cb *blk_check_plugged(blk_plug_cb_fn unplug, void *data,
				      int size)
{
	struct blk_plug *plug = current->plug;
	struct blk_plug_cb *cb;

	if (!plug)
		return NULL;

	list_for_each_entry(cb, &plug->cb_list, list)
		if (cb->callback == unplug && cb->data == data)
			return cb;

	BUG_ON(size < sizeof(*cb));
	cb = kzalloc(size, GFP_ATOMIC);
	if (cb) {
		cb->data = data;
		cb->callback = unplug;
		list_add(&cb->list, &plug->cb_list);
	}
	return cb;
}
EXPORT_SYMBOL(blk_check_plugged);

void blk_flush_plug_list(struct blk_plug *plug, bool from_schedule)
{
	struct request_queue *q;
	unsigned long flags;
	struct request *rq;
	LIST_HEAD(list);
	unsigned int depth;

	flush_plug_callbacks(plug, from_schedule);

	if (!list_empty(&plug->mq_list))
		blk_mq_flush_plug_list(plug, from_schedule);

	if (list_empty(&plug->list))
		return;

	list_splice_init(&plug->list, &list);

	list_sort(NULL, &list, plug_rq_cmp);

	q = NULL;
	depth = 0;

	local_irq_save(flags);
	while (!list_empty(&list)) {
		rq = list_entry_rq(list.next);
		list_del_init(&rq->queuelist);
		BUG_ON(!rq->q);
		if (rq->q != q) {
			 
			if (q)
				queue_unplugged(q, depth, from_schedule);
			q = rq->q;
			depth = 0;
			spin_lock(q->queue_lock);
		}

		if (unlikely(blk_queue_dying(q))) {
			__blk_end_request_all(rq, -ENODEV);
			continue;
		}

		if (rq->cmd_flags & (REQ_FLUSH | REQ_FUA))
			__elv_add_request(q, rq, ELEVATOR_INSERT_FLUSH);
		else
			__elv_add_request(q, rq, ELEVATOR_INSERT_SORT_MERGE);

		depth++;
	}

	if (q)
		queue_unplugged(q, depth, from_schedule);

	local_irq_restore(flags);
}

void blk_finish_plug(struct blk_plug *plug)
{
	if (plug != current->plug)
		return;
	blk_flush_plug_list(plug, false);

	current->plug = NULL;
}
EXPORT_SYMBOL(blk_finish_plug);

bool blk_poll(struct request_queue *q, blk_qc_t cookie)
{
	struct blk_plug *plug;
	long state;

	if (!q->mq_ops || !q->mq_ops->poll || !blk_qc_t_valid(cookie) ||
	    !test_bit(QUEUE_FLAG_POLL, &q->queue_flags))
		return false;

	plug = current->plug;
	if (plug)
		blk_flush_plug_list(plug, false);

	state = current->state;
	while (!need_resched()) {
		unsigned int queue_num = blk_qc_t_to_queue_num(cookie);
		struct blk_mq_hw_ctx *hctx = q->queue_hw_ctx[queue_num];
		int ret;

		hctx->poll_invoked++;

		ret = q->mq_ops->poll(hctx, blk_qc_t_to_tag(cookie));
		if (ret > 0) {
			hctx->poll_success++;
			set_current_state(TASK_RUNNING);
			return true;
		}

		if (signal_pending_state(state, current))
			set_current_state(TASK_RUNNING);

		if (current->state == TASK_RUNNING)
			return true;
		if (ret < 0)
			break;
		cpu_relax();
	}

	return false;
}

#ifdef CONFIG_PM
 
void blk_pm_runtime_init(struct request_queue *q, struct device *dev)
{
	q->dev = dev;
	q->rpm_status = RPM_ACTIVE;
	pm_runtime_set_autosuspend_delay(q->dev, -1);
	pm_runtime_use_autosuspend(q->dev);
}
EXPORT_SYMBOL(blk_pm_runtime_init);

int blk_pre_runtime_suspend(struct request_queue *q)
{
	int ret = 0;

	if (!q->dev)
		return ret;

	spin_lock_irq(q->queue_lock);
	if (q->nr_pending) {
		ret = -EBUSY;
		pm_runtime_mark_last_busy(q->dev);
	} else {
		q->rpm_status = RPM_SUSPENDING;
	}
	spin_unlock_irq(q->queue_lock);
	return ret;
}
EXPORT_SYMBOL(blk_pre_runtime_suspend);

void blk_post_runtime_suspend(struct request_queue *q, int err)
{
	if (!q->dev)
		return;

	spin_lock_irq(q->queue_lock);
	if (!err) {
		q->rpm_status = RPM_SUSPENDED;
	} else {
		q->rpm_status = RPM_ACTIVE;
		pm_runtime_mark_last_busy(q->dev);
	}
	spin_unlock_irq(q->queue_lock);
}
EXPORT_SYMBOL(blk_post_runtime_suspend);

void blk_pre_runtime_resume(struct request_queue *q)
{
	if (!q->dev)
		return;

	spin_lock_irq(q->queue_lock);
	q->rpm_status = RPM_RESUMING;
	spin_unlock_irq(q->queue_lock);
}
EXPORT_SYMBOL(blk_pre_runtime_resume);

void blk_post_runtime_resume(struct request_queue *q, int err)
{
	if (!q->dev)
		return;

	spin_lock_irq(q->queue_lock);
	if (!err) {
		q->rpm_status = RPM_ACTIVE;
		__blk_run_queue(q);
		pm_runtime_mark_last_busy(q->dev);
		pm_request_autosuspend(q->dev);
	} else {
		q->rpm_status = RPM_SUSPENDED;
	}
	spin_unlock_irq(q->queue_lock);
}
EXPORT_SYMBOL(blk_post_runtime_resume);
#endif
#ifdef MY_ABC_HERE
void syno_flashcache_return_error(struct bio *bio)
{
	 
	if (bio_flagged(bio, BIO_MD_RETURN_ERROR)) {
		printk(KERN_DEBUG "Get flashcache access md error, return error code\n");
		bio->bi_error = -EIO;
		bio_endio(bio);
	} else {
		bio->bi_error = -EIO;
		bio_endio(bio);
	}
}
EXPORT_SYMBOL(syno_flashcache_return_error);
#endif  

int __init blk_dev_init(void)
{
	BUILD_BUG_ON(__REQ_NR_BITS > 8 *
			FIELD_SIZEOF(struct request, cmd_flags));

	kblockd_workqueue = alloc_workqueue("kblockd",
					    WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if (!kblockd_workqueue)
		panic("Failed to create kblockd\n");

	request_cachep = kmem_cache_create("blkdev_requests",
			sizeof(struct request), 0, SLAB_PANIC, NULL);

	blk_requestq_cachep = kmem_cache_create("blkdev_queue",
			sizeof(struct request_queue), 0, SLAB_PANIC, NULL);

	return 0;
}
