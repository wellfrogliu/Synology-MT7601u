#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/kthread.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/tracepoint.h>
#include <linux/device.h>
#include <linux/memcontrol.h>
#include "internal.h"

#define MIN_WRITEBACK_PAGES	(4096UL >> (PAGE_CACHE_SHIFT - 10))

#ifdef MY_ABC_HERE
#include <linux/synolib.h>
#endif  

struct wb_completion {
	atomic_t		cnt;
};

struct wb_writeback_work {
	long nr_pages;
	struct super_block *sb;
	unsigned long *older_than_this;
	enum writeback_sync_modes sync_mode;
	unsigned int tagged_writepages:1;
	unsigned int for_kupdate:1;
	unsigned int range_cyclic:1;
	unsigned int for_background:1;
	unsigned int for_sync:1;	 
	unsigned int auto_free:1;	 
	enum wb_reason reason;		 

	struct list_head list;		 
	struct wb_completion *done;	 
};

#define DEFINE_WB_COMPLETION_ONSTACK(cmpl)				\
	struct wb_completion cmpl = {					\
		.cnt		= ATOMIC_INIT(1),			\
	}

unsigned int dirtytime_expire_interval = 12 * 60 * 60;

static inline struct inode *wb_inode(struct list_head *head)
{
	return list_entry(head, struct inode, i_io_list);
}

#define CREATE_TRACE_POINTS
#include <trace/events/writeback.h>

EXPORT_TRACEPOINT_SYMBOL_GPL(wbc_writepage);

static bool wb_io_lists_populated(struct bdi_writeback *wb)
{
	if (wb_has_dirty_io(wb)) {
		return false;
	} else {
		set_bit(WB_has_dirty_io, &wb->state);
		WARN_ON_ONCE(!wb->avg_write_bandwidth);
		atomic_long_add(wb->avg_write_bandwidth,
				&wb->bdi->tot_write_bandwidth);
		return true;
	}
}

static void wb_io_lists_depopulated(struct bdi_writeback *wb)
{
	if (wb_has_dirty_io(wb) && list_empty(&wb->b_dirty) &&
	    list_empty(&wb->b_io) && list_empty(&wb->b_more_io)) {
		clear_bit(WB_has_dirty_io, &wb->state);
		WARN_ON_ONCE(atomic_long_sub_return(wb->avg_write_bandwidth,
					&wb->bdi->tot_write_bandwidth) < 0);
	}
}

static bool inode_io_list_move_locked(struct inode *inode,
				      struct bdi_writeback *wb,
				      struct list_head *head)
{
	assert_spin_locked(&wb->list_lock);

	list_move(&inode->i_io_list, head);

	if (head != &wb->b_dirty_time)
		return wb_io_lists_populated(wb);

	wb_io_lists_depopulated(wb);
	return false;
}

static void inode_io_list_del_locked(struct inode *inode,
				     struct bdi_writeback *wb)
{
	assert_spin_locked(&wb->list_lock);

	list_del_init(&inode->i_io_list);
	wb_io_lists_depopulated(wb);
}

static void wb_wakeup(struct bdi_writeback *wb)
{
	spin_lock_bh(&wb->work_lock);
	if (test_bit(WB_registered, &wb->state))
		mod_delayed_work(bdi_wq, &wb->dwork, 0);
	spin_unlock_bh(&wb->work_lock);
}

static void wb_queue_work(struct bdi_writeback *wb,
			  struct wb_writeback_work *work)
{
	trace_writeback_queue(wb, work);

	spin_lock_bh(&wb->work_lock);
	if (!test_bit(WB_registered, &wb->state))
		goto out_unlock;
	if (work->done)
		atomic_inc(&work->done->cnt);
	list_add_tail(&work->list, &wb->work_list);
	mod_delayed_work(bdi_wq, &wb->dwork, 0);
out_unlock:
	spin_unlock_bh(&wb->work_lock);
}

static void wb_wait_for_completion(struct backing_dev_info *bdi,
				   struct wb_completion *done)
{
	atomic_dec(&done->cnt);		 
	wait_event(bdi->wb_waitq, !atomic_read(&done->cnt));
}

#ifdef CONFIG_CGROUP_WRITEBACK

#define WB_FRN_TIME_SHIFT	13	 
#define WB_FRN_TIME_AVG_SHIFT	3	 
#define WB_FRN_TIME_CUT_DIV	2	 
#define WB_FRN_TIME_PERIOD	(2 * (1 << WB_FRN_TIME_SHIFT))	 

#define WB_FRN_HIST_SLOTS	16	 
#define WB_FRN_HIST_UNIT	(WB_FRN_TIME_PERIOD / WB_FRN_HIST_SLOTS)
					 
#define WB_FRN_HIST_THR_SLOTS	(WB_FRN_HIST_SLOTS / 2)
					 
#define WB_FRN_HIST_MAX_SLOTS	(WB_FRN_HIST_THR_SLOTS / 2 + 1)
					 
static atomic_t isw_nr_in_flight = ATOMIC_INIT(0);
static struct workqueue_struct *isw_wq;

void __inode_attach_wb(struct inode *inode, struct page *page)
{
	struct backing_dev_info *bdi = inode_to_bdi(inode);
	struct bdi_writeback *wb = NULL;

	if (inode_cgwb_enabled(inode)) {
		struct cgroup_subsys_state *memcg_css;

		if (page) {
			memcg_css = mem_cgroup_css_from_page(page);
			wb = wb_get_create(bdi, memcg_css, GFP_ATOMIC);
		} else {
			 
			memcg_css = task_get_css(current, memory_cgrp_id);
			wb = wb_get_create(bdi, memcg_css, GFP_ATOMIC);
			css_put(memcg_css);
		}
	}

	if (!wb)
		wb = &bdi->wb;

	if (unlikely(cmpxchg(&inode->i_wb, NULL, wb)))
		wb_put(wb);
}

static struct bdi_writeback *
locked_inode_to_wb_and_lock_list(struct inode *inode)
	__releases(&inode->i_lock)
	__acquires(&wb->list_lock)
{
	while (true) {
		struct bdi_writeback *wb = inode_to_wb(inode);

		wb_get(wb);
		spin_unlock(&inode->i_lock);
		spin_lock(&wb->list_lock);

		if (likely(wb == inode->i_wb)) {
			wb_put(wb);	 
			return wb;
		}

		spin_unlock(&wb->list_lock);
		wb_put(wb);
		cpu_relax();
		spin_lock(&inode->i_lock);
	}
}

static struct bdi_writeback *inode_to_wb_and_lock_list(struct inode *inode)
	__acquires(&wb->list_lock)
{
	spin_lock(&inode->i_lock);
	return locked_inode_to_wb_and_lock_list(inode);
}

struct inode_switch_wbs_context {
	struct inode		*inode;
	struct bdi_writeback	*new_wb;

	struct rcu_head		rcu_head;
	struct work_struct	work;
};

static void inode_switch_wbs_work_fn(struct work_struct *work)
{
	struct inode_switch_wbs_context *isw =
		container_of(work, struct inode_switch_wbs_context, work);
	struct inode *inode = isw->inode;
	struct address_space *mapping = inode->i_mapping;
	struct bdi_writeback *old_wb = inode->i_wb;
	struct bdi_writeback *new_wb = isw->new_wb;
	struct radix_tree_iter iter;
	bool switched = false;
	void **slot;

	if (old_wb < new_wb) {
		spin_lock(&old_wb->list_lock);
		spin_lock_nested(&new_wb->list_lock, SINGLE_DEPTH_NESTING);
	} else {
		spin_lock(&new_wb->list_lock);
		spin_lock_nested(&old_wb->list_lock, SINGLE_DEPTH_NESTING);
	}
	spin_lock(&inode->i_lock);
	spin_lock_irq(&mapping->tree_lock);

	if (unlikely(inode->i_state & I_FREEING))
		goto skip_switch;

	radix_tree_for_each_tagged(slot, &mapping->page_tree, &iter, 0,
				   PAGECACHE_TAG_DIRTY) {
		struct page *page = radix_tree_deref_slot_protected(slot,
							&mapping->tree_lock);
		if (likely(page) && PageDirty(page)) {
			__dec_wb_stat(old_wb, WB_RECLAIMABLE);
			__inc_wb_stat(new_wb, WB_RECLAIMABLE);
		}
	}

	radix_tree_for_each_tagged(slot, &mapping->page_tree, &iter, 0,
				   PAGECACHE_TAG_WRITEBACK) {
		struct page *page = radix_tree_deref_slot_protected(slot,
							&mapping->tree_lock);
		if (likely(page)) {
			WARN_ON_ONCE(!PageWriteback(page));
			__dec_wb_stat(old_wb, WB_WRITEBACK);
			__inc_wb_stat(new_wb, WB_WRITEBACK);
		}
	}

	wb_get(new_wb);

	if (!list_empty(&inode->i_io_list)) {
		struct inode *pos;

		inode_io_list_del_locked(inode, old_wb);
		inode->i_wb = new_wb;
		list_for_each_entry(pos, &new_wb->b_dirty, i_io_list)
			if (time_after_eq(inode->dirtied_when,
					  pos->dirtied_when))
				break;
		inode_io_list_move_locked(inode, new_wb, pos->i_io_list.prev);
	} else {
		inode->i_wb = new_wb;
	}

	inode->i_wb_frn_winner = 0;
	inode->i_wb_frn_avg_time = 0;
	inode->i_wb_frn_history = 0;
	switched = true;
skip_switch:
	 
	smp_store_release(&inode->i_state, inode->i_state & ~I_WB_SWITCH);

	spin_unlock_irq(&mapping->tree_lock);
	spin_unlock(&inode->i_lock);
	spin_unlock(&new_wb->list_lock);
	spin_unlock(&old_wb->list_lock);

	if (switched) {
		wb_wakeup(new_wb);
		wb_put(old_wb);
	}
	wb_put(new_wb);

	iput(inode);
	kfree(isw);

	atomic_dec(&isw_nr_in_flight);
}

static void inode_switch_wbs_rcu_fn(struct rcu_head *rcu_head)
{
	struct inode_switch_wbs_context *isw = container_of(rcu_head,
				struct inode_switch_wbs_context, rcu_head);

	INIT_WORK(&isw->work, inode_switch_wbs_work_fn);
	queue_work(isw_wq, &isw->work);
}

static void inode_switch_wbs(struct inode *inode, int new_wb_id)
{
	struct backing_dev_info *bdi = inode_to_bdi(inode);
	struct cgroup_subsys_state *memcg_css;
	struct inode_switch_wbs_context *isw;

	if (inode->i_state & I_WB_SWITCH)
		return;

	isw = kzalloc(sizeof(*isw), GFP_ATOMIC);
	if (!isw)
		return;

	rcu_read_lock();
	memcg_css = css_from_id(new_wb_id, &memory_cgrp_subsys);
	if (memcg_css)
		isw->new_wb = wb_get_create(bdi, memcg_css, GFP_ATOMIC);
	rcu_read_unlock();
	if (!isw->new_wb)
		goto out_free;

	spin_lock(&inode->i_lock);
	if (!(inode->i_sb->s_flags & MS_ACTIVE) ||
	    inode->i_state & (I_WB_SWITCH | I_FREEING) ||
	    inode_to_wb(inode) == isw->new_wb) {
		spin_unlock(&inode->i_lock);
		goto out_free;
	}
	inode->i_state |= I_WB_SWITCH;
	spin_unlock(&inode->i_lock);

	ihold(inode);
	isw->inode = inode;

	atomic_inc(&isw_nr_in_flight);

	call_rcu(&isw->rcu_head, inode_switch_wbs_rcu_fn);
	return;

out_free:
	if (isw->new_wb)
		wb_put(isw->new_wb);
	kfree(isw);
}

void wbc_attach_and_unlock_inode(struct writeback_control *wbc,
				 struct inode *inode)
{
	if (!inode_cgwb_enabled(inode)) {
		spin_unlock(&inode->i_lock);
		return;
	}

	wbc->wb = inode_to_wb(inode);
	wbc->inode = inode;

	wbc->wb_id = wbc->wb->memcg_css->id;
	wbc->wb_lcand_id = inode->i_wb_frn_winner;
	wbc->wb_tcand_id = 0;
	wbc->wb_bytes = 0;
	wbc->wb_lcand_bytes = 0;
	wbc->wb_tcand_bytes = 0;

	wb_get(wbc->wb);
	spin_unlock(&inode->i_lock);

	if (unlikely(wb_dying(wbc->wb)))
		inode_switch_wbs(inode, wbc->wb_id);
}

void wbc_detach_inode(struct writeback_control *wbc)
{
	struct bdi_writeback *wb = wbc->wb;
	struct inode *inode = wbc->inode;
	unsigned long avg_time, max_bytes, max_time;
	u16 history;
	int max_id;

	if (!wb)
		return;

	history = inode->i_wb_frn_history;
	avg_time = inode->i_wb_frn_avg_time;

	if (wbc->wb_bytes >= wbc->wb_lcand_bytes &&
	    wbc->wb_bytes >= wbc->wb_tcand_bytes) {
		max_id = wbc->wb_id;
		max_bytes = wbc->wb_bytes;
	} else if (wbc->wb_lcand_bytes >= wbc->wb_tcand_bytes) {
		max_id = wbc->wb_lcand_id;
		max_bytes = wbc->wb_lcand_bytes;
	} else {
		max_id = wbc->wb_tcand_id;
		max_bytes = wbc->wb_tcand_bytes;
	}

	max_time = DIV_ROUND_UP((max_bytes >> PAGE_SHIFT) << WB_FRN_TIME_SHIFT,
				wb->avg_write_bandwidth);
	if (avg_time)
		avg_time += (max_time >> WB_FRN_TIME_AVG_SHIFT) -
			    (avg_time >> WB_FRN_TIME_AVG_SHIFT);
	else
		avg_time = max_time;	 

	if (max_time >= avg_time / WB_FRN_TIME_CUT_DIV) {
		int slots;

		slots = min(DIV_ROUND_UP(max_time, WB_FRN_HIST_UNIT),
			    (unsigned long)WB_FRN_HIST_MAX_SLOTS);
		history <<= slots;
		if (wbc->wb_id != max_id)
			history |= (1U << slots) - 1;

		if (hweight32(history) > WB_FRN_HIST_THR_SLOTS)
			inode_switch_wbs(inode, max_id);
	}

	inode->i_wb_frn_winner = max_id;
	inode->i_wb_frn_avg_time = min(avg_time, (unsigned long)U16_MAX);
	inode->i_wb_frn_history = history;

	wb_put(wbc->wb);
	wbc->wb = NULL;
}

void wbc_account_io(struct writeback_control *wbc, struct page *page,
		    size_t bytes)
{
	int id;

	if (!wbc->wb)
		return;

	rcu_read_lock();
	id = mem_cgroup_css_from_page(page)->id;
	rcu_read_unlock();

	if (id == wbc->wb_id) {
		wbc->wb_bytes += bytes;
		return;
	}

	if (id == wbc->wb_lcand_id)
		wbc->wb_lcand_bytes += bytes;

	if (!wbc->wb_tcand_bytes)
		wbc->wb_tcand_id = id;
	if (id == wbc->wb_tcand_id)
		wbc->wb_tcand_bytes += bytes;
	else
		wbc->wb_tcand_bytes -= min(bytes, wbc->wb_tcand_bytes);
}
EXPORT_SYMBOL_GPL(wbc_account_io);

int inode_congested(struct inode *inode, int cong_bits)
{
	 
	if (inode && inode_to_wb_is_valid(inode)) {
		struct bdi_writeback *wb;
		bool locked, congested;

		wb = unlocked_inode_to_wb_begin(inode, &locked);
		congested = wb_congested(wb, cong_bits);
		unlocked_inode_to_wb_end(inode, locked);
		return congested;
	}

	return wb_congested(&inode_to_bdi(inode)->wb, cong_bits);
}
EXPORT_SYMBOL_GPL(inode_congested);

static long wb_split_bdi_pages(struct bdi_writeback *wb, long nr_pages)
{
	unsigned long this_bw = wb->avg_write_bandwidth;
	unsigned long tot_bw = atomic_long_read(&wb->bdi->tot_write_bandwidth);

	if (nr_pages == LONG_MAX)
		return LONG_MAX;

	if (!tot_bw || this_bw >= tot_bw)
		return nr_pages;
	else
		return DIV_ROUND_UP_ULL((u64)nr_pages * this_bw, tot_bw);
}

static void bdi_split_work_to_wbs(struct backing_dev_info *bdi,
				  struct wb_writeback_work *base_work,
				  bool skip_if_busy)
{
	struct bdi_writeback *last_wb = NULL;
	struct bdi_writeback *wb = list_entry(&bdi->wb_list,
					      struct bdi_writeback, bdi_node);

	might_sleep();
restart:
	rcu_read_lock();
	list_for_each_entry_continue_rcu(wb, &bdi->wb_list, bdi_node) {
		DEFINE_WB_COMPLETION_ONSTACK(fallback_work_done);
		struct wb_writeback_work fallback_work;
		struct wb_writeback_work *work;
		long nr_pages;

		if (last_wb) {
			wb_put(last_wb);
			last_wb = NULL;
		}

		if (!wb_has_dirty_io(wb) &&
		    (base_work->sync_mode == WB_SYNC_NONE ||
		     list_empty(&wb->b_dirty_time)))
			continue;
		if (skip_if_busy && writeback_in_progress(wb))
			continue;

		nr_pages = wb_split_bdi_pages(wb, base_work->nr_pages);

		work = kmalloc(sizeof(*work), GFP_ATOMIC);
		if (work) {
			*work = *base_work;
			work->nr_pages = nr_pages;
			work->auto_free = 1;
			wb_queue_work(wb, work);
			continue;
		}

		work = &fallback_work;
		*work = *base_work;
		work->nr_pages = nr_pages;
		work->auto_free = 0;
		work->done = &fallback_work_done;

		wb_queue_work(wb, work);

		wb_get(wb);
		last_wb = wb;

		rcu_read_unlock();
		wb_wait_for_completion(bdi, &fallback_work_done);
		goto restart;
	}
	rcu_read_unlock();

	if (last_wb)
		wb_put(last_wb);
}

void cgroup_writeback_umount(void)
{
	if (atomic_read(&isw_nr_in_flight)) {
		synchronize_rcu();
		flush_workqueue(isw_wq);
	}
}

static int __init cgroup_writeback_init(void)
{
	isw_wq = alloc_workqueue("inode_switch_wbs", 0, 0);
	if (!isw_wq)
		return -ENOMEM;
	return 0;
}
fs_initcall(cgroup_writeback_init);

#else	 

static struct bdi_writeback *
locked_inode_to_wb_and_lock_list(struct inode *inode)
	__releases(&inode->i_lock)
	__acquires(&wb->list_lock)
{
	struct bdi_writeback *wb = inode_to_wb(inode);

	spin_unlock(&inode->i_lock);
	spin_lock(&wb->list_lock);
	return wb;
}

static struct bdi_writeback *inode_to_wb_and_lock_list(struct inode *inode)
	__acquires(&wb->list_lock)
{
	struct bdi_writeback *wb = inode_to_wb(inode);

	spin_lock(&wb->list_lock);
	return wb;
}

static long wb_split_bdi_pages(struct bdi_writeback *wb, long nr_pages)
{
	return nr_pages;
}

static void bdi_split_work_to_wbs(struct backing_dev_info *bdi,
				  struct wb_writeback_work *base_work,
				  bool skip_if_busy)
{
	might_sleep();

	if (!skip_if_busy || !writeback_in_progress(&bdi->wb)) {
		base_work->auto_free = 0;
		wb_queue_work(&bdi->wb, base_work);
	}
}

#endif	 

void wb_start_writeback(struct bdi_writeback *wb, long nr_pages,
			bool range_cyclic, enum wb_reason reason)
{
	struct wb_writeback_work *work;

	if (!wb_has_dirty_io(wb))
		return;

	work = kzalloc(sizeof(*work), GFP_ATOMIC);
	if (!work) {
		trace_writeback_nowork(wb);
		wb_wakeup(wb);
		return;
	}

	work->sync_mode	= WB_SYNC_NONE;
	work->nr_pages	= nr_pages;
	work->range_cyclic = range_cyclic;
	work->reason	= reason;
	work->auto_free	= 1;

	wb_queue_work(wb, work);
}

void wb_start_background_writeback(struct bdi_writeback *wb)
{
	 
	trace_writeback_wake_background(wb);
	wb_wakeup(wb);
}

void inode_io_list_del(struct inode *inode)
{
	struct bdi_writeback *wb;

	wb = inode_to_wb_and_lock_list(inode);
	inode_io_list_del_locked(inode, wb);
	spin_unlock(&wb->list_lock);
}

static void redirty_tail(struct inode *inode, struct bdi_writeback *wb)
{
	if (!list_empty(&wb->b_dirty)) {
		struct inode *tail;

		tail = wb_inode(wb->b_dirty.next);
		if (time_before(inode->dirtied_when, tail->dirtied_when))
			inode->dirtied_when = jiffies;
	}
	inode_io_list_move_locked(inode, wb, &wb->b_dirty);
}

static void requeue_io(struct inode *inode, struct bdi_writeback *wb)
{
	inode_io_list_move_locked(inode, wb, &wb->b_more_io);
}

static void inode_sync_complete(struct inode *inode)
{
	inode->i_state &= ~I_SYNC;
	 
	inode_add_lru(inode);
	 
	smp_mb();
	wake_up_bit(&inode->i_state, __I_SYNC);
}

static bool inode_dirtied_after(struct inode *inode, unsigned long t)
{
	bool ret = time_after(inode->dirtied_when, t);
#ifndef CONFIG_64BIT
	 
	ret = ret && time_before_eq(inode->dirtied_when, jiffies);
#endif
	return ret;
}

#define EXPIRE_DIRTY_ATIME 0x0001

static int move_expired_inodes(struct list_head *delaying_queue,
			       struct list_head *dispatch_queue,
			       int flags,
			       struct wb_writeback_work *work)
{
	unsigned long *older_than_this = NULL;
	unsigned long expire_time;
	LIST_HEAD(tmp);
	struct list_head *pos, *node;
	struct super_block *sb = NULL;
	struct inode *inode;
	int do_sb_sort = 0;
	int moved = 0;

	if ((flags & EXPIRE_DIRTY_ATIME) == 0)
		older_than_this = work->older_than_this;
	else if (!work->for_sync) {
		expire_time = jiffies - (dirtytime_expire_interval * HZ);
		older_than_this = &expire_time;
	}
	while (!list_empty(delaying_queue)) {
		inode = wb_inode(delaying_queue->prev);
		if (older_than_this &&
		    inode_dirtied_after(inode, *older_than_this))
			break;
		list_move(&inode->i_io_list, &tmp);
		moved++;
		if (flags & EXPIRE_DIRTY_ATIME)
			set_bit(__I_DIRTY_TIME_EXPIRED, &inode->i_state);
		if (sb_is_blkdev_sb(inode->i_sb))
			continue;
		if (sb && sb != inode->i_sb)
			do_sb_sort = 1;
		sb = inode->i_sb;
	}

	if (!do_sb_sort) {
		list_splice(&tmp, dispatch_queue);
		goto out;
	}

	while (!list_empty(&tmp)) {
		sb = wb_inode(tmp.prev)->i_sb;
		list_for_each_prev_safe(pos, node, &tmp) {
			inode = wb_inode(pos);
			if (inode->i_sb == sb)
				list_move(&inode->i_io_list, dispatch_queue);
		}
	}
out:
	return moved;
}

static void queue_io(struct bdi_writeback *wb, struct wb_writeback_work *work)
{
	int moved;

	assert_spin_locked(&wb->list_lock);
	list_splice_init(&wb->b_more_io, &wb->b_io);
	moved = move_expired_inodes(&wb->b_dirty, &wb->b_io, 0, work);
	moved += move_expired_inodes(&wb->b_dirty_time, &wb->b_io,
				     EXPIRE_DIRTY_ATIME, work);
	if (moved)
		wb_io_lists_populated(wb);
	trace_writeback_queue_io(wb, work, moved);
}

static int write_inode(struct inode *inode, struct writeback_control *wbc)
{
	int ret;

	if (inode->i_sb->s_op->write_inode && !is_bad_inode(inode)) {
		trace_writeback_write_inode_start(inode, wbc);
		ret = inode->i_sb->s_op->write_inode(inode, wbc);
		trace_writeback_write_inode(inode, wbc);
		return ret;
	}
	return 0;
}

static void __inode_wait_for_writeback(struct inode *inode)
	__releases(inode->i_lock)
	__acquires(inode->i_lock)
{
	DEFINE_WAIT_BIT(wq, &inode->i_state, __I_SYNC);
	wait_queue_head_t *wqh;

	wqh = bit_waitqueue(&inode->i_state, __I_SYNC);
	while (inode->i_state & I_SYNC) {
		spin_unlock(&inode->i_lock);
		__wait_on_bit(wqh, &wq, bit_wait,
			      TASK_UNINTERRUPTIBLE);
		spin_lock(&inode->i_lock);
	}
}

void inode_wait_for_writeback(struct inode *inode)
{
	spin_lock(&inode->i_lock);
	__inode_wait_for_writeback(inode);
	spin_unlock(&inode->i_lock);
}

static void inode_sleep_on_writeback(struct inode *inode)
	__releases(inode->i_lock)
{
	DEFINE_WAIT(wait);
	wait_queue_head_t *wqh = bit_waitqueue(&inode->i_state, __I_SYNC);
	int sleep;

	prepare_to_wait(wqh, &wait, TASK_UNINTERRUPTIBLE);
	sleep = inode->i_state & I_SYNC;
	spin_unlock(&inode->i_lock);
	if (sleep)
		schedule();
	finish_wait(wqh, &wait);
}

static void requeue_inode(struct inode *inode, struct bdi_writeback *wb,
			  struct writeback_control *wbc)
{
	if (inode->i_state & I_FREEING)
		return;

	if ((inode->i_state & I_DIRTY) &&
	    (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages))
		inode->dirtied_when = jiffies;

	if (wbc->pages_skipped) {
		 
		redirty_tail(inode, wb);
		return;
	}

	if (mapping_tagged(inode->i_mapping, PAGECACHE_TAG_DIRTY)) {
		 
		if (wbc->nr_to_write <= 0) {
			 
			requeue_io(inode, wb);
		} else {
			 
			redirty_tail(inode, wb);
		}
	} else if (inode->i_state & I_DIRTY) {
		 
		redirty_tail(inode, wb);
	} else if (inode->i_state & I_DIRTY_TIME) {
		inode->dirtied_when = jiffies;
		inode_io_list_move_locked(inode, wb, &wb->b_dirty_time);
	} else {
		 
		inode_io_list_del_locked(inode, wb);
	}
}

static int
__writeback_single_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct address_space *mapping = inode->i_mapping;
	long nr_to_write = wbc->nr_to_write;
	unsigned dirty;
	int ret;

	WARN_ON(!(inode->i_state & I_SYNC));

	trace_writeback_single_inode_start(inode, wbc, nr_to_write);

	ret = do_writepages(mapping, wbc);

	if (wbc->sync_mode == WB_SYNC_ALL && !wbc->for_sync) {
		int err = filemap_fdatawait(mapping);
		if (ret == 0)
			ret = err;
	}

	spin_lock(&inode->i_lock);

	dirty = inode->i_state & I_DIRTY;
	if (inode->i_state & I_DIRTY_TIME) {
		if ((dirty & (I_DIRTY_SYNC | I_DIRTY_DATASYNC)) ||
		    unlikely(inode->i_state & I_DIRTY_TIME_EXPIRED) ||
		    unlikely(time_after(jiffies,
					(inode->dirtied_time_when +
					 dirtytime_expire_interval * HZ)))) {
			dirty |= I_DIRTY_TIME | I_DIRTY_TIME_EXPIRED;
			trace_writeback_lazytime(inode);
		}
	} else
		inode->i_state &= ~I_DIRTY_TIME_EXPIRED;
	inode->i_state &= ~dirty;

	smp_mb();

	if (mapping_tagged(mapping, PAGECACHE_TAG_DIRTY))
		inode->i_state |= I_DIRTY_PAGES;

	spin_unlock(&inode->i_lock);

	if (dirty & I_DIRTY_TIME)
		mark_inode_dirty_sync(inode);
	 
	if (dirty & ~I_DIRTY_PAGES) {
		int err = write_inode(inode, wbc);
		if (ret == 0)
			ret = err;
	}
	trace_writeback_single_inode(inode, wbc, nr_to_write);
	return ret;
}

static int writeback_single_inode(struct inode *inode,
				  struct writeback_control *wbc)
{
	struct bdi_writeback *wb;
	int ret = 0;

	spin_lock(&inode->i_lock);
	if (!atomic_read(&inode->i_count))
		WARN_ON(!(inode->i_state & (I_WILL_FREE|I_FREEING)));
	else
		WARN_ON(inode->i_state & I_WILL_FREE);

	if (inode->i_state & I_SYNC) {
		if (wbc->sync_mode != WB_SYNC_ALL)
			goto out;
		 
		__inode_wait_for_writeback(inode);
	}
	WARN_ON(inode->i_state & I_SYNC);
	 
	if (!(inode->i_state & I_DIRTY_ALL) &&
	    (wbc->sync_mode != WB_SYNC_ALL ||
	     !mapping_tagged(inode->i_mapping, PAGECACHE_TAG_WRITEBACK)))
		goto out;
	inode->i_state |= I_SYNC;
	wbc_attach_and_unlock_inode(wbc, inode);

	ret = __writeback_single_inode(inode, wbc);

	wbc_detach_inode(wbc);

	wb = inode_to_wb_and_lock_list(inode);
	spin_lock(&inode->i_lock);
	 
	if (!(inode->i_state & I_DIRTY_ALL))
		inode_io_list_del_locked(inode, wb);
	spin_unlock(&wb->list_lock);
	inode_sync_complete(inode);
out:
	spin_unlock(&inode->i_lock);
	return ret;
}

static long writeback_chunk_size(struct bdi_writeback *wb,
				 struct wb_writeback_work *work)
{
	long pages;

	if (work->sync_mode == WB_SYNC_ALL || work->tagged_writepages)
		pages = LONG_MAX;
	else {
		pages = min(wb->avg_write_bandwidth / 2,
			    global_wb_domain.dirty_limit / DIRTY_SCOPE);
		pages = min(pages, work->nr_pages);
		pages = round_down(pages + MIN_WRITEBACK_PAGES,
				   MIN_WRITEBACK_PAGES);
	}

	return pages;
}

static long writeback_sb_inodes(struct super_block *sb,
				struct bdi_writeback *wb,
				struct wb_writeback_work *work)
{
	struct writeback_control wbc = {
		.sync_mode		= work->sync_mode,
		.tagged_writepages	= work->tagged_writepages,
		.for_kupdate		= work->for_kupdate,
		.for_background		= work->for_background,
		.for_sync		= work->for_sync,
		.range_cyclic		= work->range_cyclic,
		.range_start		= 0,
		.range_end		= LLONG_MAX,
	};
	unsigned long start_time = jiffies;
	long write_chunk;
	long wrote = 0;   

	while (!list_empty(&wb->b_io)) {
		struct inode *inode = wb_inode(wb->b_io.prev);
		struct bdi_writeback *tmp_wb;

		if (inode->i_sb != sb) {
			if (work->sb) {
				 
				redirty_tail(inode, wb);
				continue;
			}

			break;
		}

		spin_lock(&inode->i_lock);
		if (inode->i_state & (I_NEW | I_FREEING | I_WILL_FREE)) {
			spin_unlock(&inode->i_lock);
			redirty_tail(inode, wb);
			continue;
		}
		if ((inode->i_state & I_SYNC) && wbc.sync_mode != WB_SYNC_ALL) {
			 
			spin_unlock(&inode->i_lock);
			requeue_io(inode, wb);
			trace_writeback_sb_inodes_requeue(inode);
			continue;
		}
		spin_unlock(&wb->list_lock);

		if (inode->i_state & I_SYNC) {
			 
			inode_sleep_on_writeback(inode);
			 
			spin_lock(&wb->list_lock);
			continue;
		}
		inode->i_state |= I_SYNC;
		wbc_attach_and_unlock_inode(&wbc, inode);

		write_chunk = writeback_chunk_size(wb, work);
		wbc.nr_to_write = write_chunk;
		wbc.pages_skipped = 0;

		__writeback_single_inode(inode, &wbc);

		wbc_detach_inode(&wbc);
		work->nr_pages -= write_chunk - wbc.nr_to_write;
		wrote += write_chunk - wbc.nr_to_write;

		if (need_resched()) {
			 
			blk_flush_plug(current);
			cond_resched();
		}

		tmp_wb = inode_to_wb_and_lock_list(inode);
		spin_lock(&inode->i_lock);
		if (!(inode->i_state & I_DIRTY_ALL))
			wrote++;
		requeue_inode(inode, tmp_wb, &wbc);
		inode_sync_complete(inode);
		spin_unlock(&inode->i_lock);

		if (unlikely(tmp_wb != wb)) {
			spin_unlock(&tmp_wb->list_lock);
			spin_lock(&wb->list_lock);
		}

		if (wrote) {
			if (time_is_before_jiffies(start_time + HZ / 10UL))
				break;
			if (work->nr_pages <= 0)
				break;
		}
	}
	return wrote;
}

static long __writeback_inodes_wb(struct bdi_writeback *wb,
				  struct wb_writeback_work *work)
{
	unsigned long start_time = jiffies;
	long wrote = 0;

	while (!list_empty(&wb->b_io)) {
		struct inode *inode = wb_inode(wb->b_io.prev);
		struct super_block *sb = inode->i_sb;

		if (!trylock_super(sb)) {
			 
			redirty_tail(inode, wb);
			continue;
		}
		wrote += writeback_sb_inodes(sb, wb, work);
		up_read(&sb->s_umount);

		if (wrote) {
			if (time_is_before_jiffies(start_time + HZ / 10UL))
				break;
			if (work->nr_pages <= 0)
				break;
		}
	}
	 
	return wrote;
}

static long writeback_inodes_wb(struct bdi_writeback *wb, long nr_pages,
				enum wb_reason reason)
{
	struct wb_writeback_work work = {
		.nr_pages	= nr_pages,
		.sync_mode	= WB_SYNC_NONE,
		.range_cyclic	= 1,
		.reason		= reason,
	};
	struct blk_plug plug;

	blk_start_plug(&plug);
	spin_lock(&wb->list_lock);
	if (list_empty(&wb->b_io))
		queue_io(wb, &work);
	__writeback_inodes_wb(wb, &work);
	spin_unlock(&wb->list_lock);
	blk_finish_plug(&plug);

	return nr_pages - work.nr_pages;
}

static long wb_writeback(struct bdi_writeback *wb,
			 struct wb_writeback_work *work)
{
	unsigned long wb_start = jiffies;
	long nr_pages = work->nr_pages;
	unsigned long oldest_jif;
	struct inode *inode;
	long progress;
	struct blk_plug plug;

	oldest_jif = jiffies;
	work->older_than_this = &oldest_jif;

	blk_start_plug(&plug);
	spin_lock(&wb->list_lock);
	for (;;) {
		 
		if (work->nr_pages <= 0)
			break;

		if ((work->for_background || work->for_kupdate) &&
		    !list_empty(&wb->work_list))
			break;

		if (work->for_background && !wb_over_bg_thresh(wb))
			break;

		if (work->for_kupdate) {
			oldest_jif = jiffies -
				msecs_to_jiffies(dirty_expire_interval * 10);
		} else if (work->for_background)
			oldest_jif = jiffies;

		trace_writeback_start(wb, work);
		if (list_empty(&wb->b_io))
			queue_io(wb, work);
		if (work->sb)
			progress = writeback_sb_inodes(work->sb, wb, work);
		else
			progress = __writeback_inodes_wb(wb, work);
		trace_writeback_written(wb, work);

		wb_update_bandwidth(wb, wb_start);

		if (progress)
			continue;
		 
		if (list_empty(&wb->b_more_io))
			break;
		 
		if (!list_empty(&wb->b_more_io))  {
			trace_writeback_wait(wb, work);
			inode = wb_inode(wb->b_more_io.prev);
			spin_lock(&inode->i_lock);
			spin_unlock(&wb->list_lock);
			 
			inode_sleep_on_writeback(inode);
			spin_lock(&wb->list_lock);
		}
	}
	spin_unlock(&wb->list_lock);
	blk_finish_plug(&plug);

	return nr_pages - work->nr_pages;
}

static struct wb_writeback_work *get_next_work_item(struct bdi_writeback *wb)
{
	struct wb_writeback_work *work = NULL;

	spin_lock_bh(&wb->work_lock);
	if (!list_empty(&wb->work_list)) {
		work = list_entry(wb->work_list.next,
				  struct wb_writeback_work, list);
		list_del_init(&work->list);
	}
	spin_unlock_bh(&wb->work_lock);
	return work;
}

static unsigned long get_nr_dirty_pages(void)
{
	return global_page_state(NR_FILE_DIRTY) +
		global_page_state(NR_UNSTABLE_NFS) +
		get_nr_dirty_inodes();
}

static long wb_check_background_flush(struct bdi_writeback *wb)
{
	if (wb_over_bg_thresh(wb)) {

		struct wb_writeback_work work = {
			.nr_pages	= LONG_MAX,
			.sync_mode	= WB_SYNC_NONE,
			.for_background	= 1,
			.range_cyclic	= 1,
			.reason		= WB_REASON_BACKGROUND,
		};

		return wb_writeback(wb, &work);
	}

	return 0;
}

static long wb_check_old_data_flush(struct bdi_writeback *wb)
{
	unsigned long expired;
	long nr_pages;

	if (!dirty_writeback_interval)
		return 0;

	expired = wb->last_old_flush +
			msecs_to_jiffies(dirty_writeback_interval * 10);
	if (time_before(jiffies, expired))
		return 0;

	wb->last_old_flush = jiffies;
	nr_pages = get_nr_dirty_pages();

	if (nr_pages) {
		struct wb_writeback_work work = {
			.nr_pages	= nr_pages,
			.sync_mode	= WB_SYNC_NONE,
			.for_kupdate	= 1,
			.range_cyclic	= 1,
			.reason		= WB_REASON_PERIODIC,
		};

		return wb_writeback(wb, &work);
	}

	return 0;
}

static long wb_do_writeback(struct bdi_writeback *wb)
{
	struct wb_writeback_work *work;
	long wrote = 0;

	set_bit(WB_writeback_running, &wb->state);
	while ((work = get_next_work_item(wb)) != NULL) {
		struct wb_completion *done = work->done;

		trace_writeback_exec(wb, work);

		wrote += wb_writeback(wb, work);

		if (work->auto_free)
			kfree(work);
		if (done && atomic_dec_and_test(&done->cnt))
			wake_up_all(&wb->bdi->wb_waitq);
	}

	wrote += wb_check_old_data_flush(wb);
	wrote += wb_check_background_flush(wb);
	clear_bit(WB_writeback_running, &wb->state);

	return wrote;
}

void wb_workfn(struct work_struct *work)
{
	struct bdi_writeback *wb = container_of(to_delayed_work(work),
						struct bdi_writeback, dwork);
	long pages_written;

	set_worker_desc("flush-%s", dev_name(wb->bdi->dev));
	current->flags |= PF_SWAPWRITE;

	if (likely(!current_is_workqueue_rescuer() ||
		   !test_bit(WB_registered, &wb->state))) {
		 
		do {
			pages_written = wb_do_writeback(wb);
			trace_writeback_pages_written(pages_written);
		} while (!list_empty(&wb->work_list));
	} else {
		 
		pages_written = writeback_inodes_wb(wb, 1024,
						    WB_REASON_FORKER_THREAD);
		trace_writeback_pages_written(pages_written);
	}

	if (!list_empty(&wb->work_list))
		mod_delayed_work(bdi_wq, &wb->dwork, 0);
	else if (wb_has_dirty_io(wb) && dirty_writeback_interval)
		wb_wakeup_delayed(wb);

	current->flags &= ~PF_SWAPWRITE;
}

void wakeup_flusher_threads(long nr_pages, enum wb_reason reason)
{
	struct backing_dev_info *bdi;

	if (!nr_pages)
		nr_pages = get_nr_dirty_pages();

	rcu_read_lock();
	list_for_each_entry_rcu(bdi, &bdi_list, bdi_list) {
		struct bdi_writeback *wb;

		if (!bdi_has_dirty_io(bdi))
			continue;

		list_for_each_entry_rcu(wb, &bdi->wb_list, bdi_node)
			wb_start_writeback(wb, wb_split_bdi_pages(wb, nr_pages),
					   false, reason);
	}
	rcu_read_unlock();
}

static void wakeup_dirtytime_writeback(struct work_struct *w);
static DECLARE_DELAYED_WORK(dirtytime_work, wakeup_dirtytime_writeback);

static void wakeup_dirtytime_writeback(struct work_struct *w)
{
	struct backing_dev_info *bdi;

	rcu_read_lock();
	list_for_each_entry_rcu(bdi, &bdi_list, bdi_list) {
		struct bdi_writeback *wb;

		list_for_each_entry_rcu(wb, &bdi->wb_list, bdi_node)
			if (!list_empty(&wb->b_dirty_time))
				wb_wakeup(wb);
	}
	rcu_read_unlock();
	schedule_delayed_work(&dirtytime_work, dirtytime_expire_interval * HZ);
}

static int __init start_dirtytime_writeback(void)
{
	schedule_delayed_work(&dirtytime_work, dirtytime_expire_interval * HZ);
	return 0;
}
__initcall(start_dirtytime_writeback);

int dirtytime_interval_handler(struct ctl_table *table, int write,
			       void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret == 0 && write)
		mod_delayed_work(system_wq, &dirtytime_work, 0);
	return ret;
}

static noinline void block_dump___mark_inode_dirty(struct inode *inode)
{
	if (inode->i_ino || strcmp(inode->i_sb->s_id, "bdev")) {
		struct dentry *dentry;
		const char *name = "?";

		dentry = d_find_alias(inode);
		if (dentry) {
			spin_lock(&dentry->d_lock);
			name = (const char *) dentry->d_name.name;
		}
		printk(KERN_DEBUG
		       "%s(%d): dirtied inode %lu (%s) on %s\n",
		       current->comm, task_pid_nr(current), inode->i_ino,
		       name, inode->i_sb->s_id);
		if (dentry) {
			spin_unlock(&dentry->d_lock);
			dput(dentry);
		}
	}
}

void __mark_inode_dirty(struct inode *inode, int flags)
{
#define I_DIRTY_INODE (I_DIRTY_SYNC | I_DIRTY_DATASYNC)
	struct super_block *sb = inode->i_sb;
	int dirtytime;

	trace_writeback_mark_inode_dirty(inode, flags);

	if (flags & (I_DIRTY_SYNC | I_DIRTY_DATASYNC | I_DIRTY_TIME)) {
		trace_writeback_dirty_inode_start(inode, flags);

		if (sb->s_op->dirty_inode)
			sb->s_op->dirty_inode(inode, flags);

		trace_writeback_dirty_inode(inode, flags);
	}
	if (flags & I_DIRTY_INODE)
		flags &= ~I_DIRTY_TIME;
	dirtytime = flags & I_DIRTY_TIME;

	smp_mb();

	if (((inode->i_state & flags) == flags) ||
	    (dirtytime && (inode->i_state & I_DIRTY_INODE)))
		return;

	if (unlikely(block_dump))
		block_dump___mark_inode_dirty(inode);

#ifdef MY_ABC_HERE
	if (0 < gSynoHibernationLogLevel) {
		syno_do_hibernation_inode_log(inode);
	}
#endif  

	spin_lock(&inode->i_lock);
	if (dirtytime && (inode->i_state & I_DIRTY_INODE))
		goto out_unlock_inode;
	if ((inode->i_state & flags) != flags) {
		const int was_dirty = inode->i_state & I_DIRTY;

		inode_attach_wb(inode, NULL);

		if (flags & I_DIRTY_INODE)
			inode->i_state &= ~I_DIRTY_TIME;
		inode->i_state |= flags;

		if (inode->i_state & I_SYNC)
			goto out_unlock_inode;

		if (!S_ISBLK(inode->i_mode)) {
			if (inode_unhashed(inode))
				goto out_unlock_inode;
		}
		if (inode->i_state & I_FREEING)
			goto out_unlock_inode;

		if (!was_dirty) {
			struct bdi_writeback *wb;
			struct list_head *dirty_list;
			bool wakeup_bdi = false;

			wb = locked_inode_to_wb_and_lock_list(inode);

			WARN(bdi_cap_writeback_dirty(wb->bdi) &&
			     !test_bit(WB_registered, &wb->state),
			     "bdi-%s not registered\n", wb->bdi->name);

			inode->dirtied_when = jiffies;
			if (dirtytime)
				inode->dirtied_time_when = jiffies;

			if (inode->i_state & (I_DIRTY_INODE | I_DIRTY_PAGES))
				dirty_list = &wb->b_dirty;
			else
				dirty_list = &wb->b_dirty_time;

			wakeup_bdi = inode_io_list_move_locked(inode, wb,
							       dirty_list);

			spin_unlock(&wb->list_lock);
			trace_writeback_dirty_inode_enqueue(inode);

			if (bdi_cap_writeback_dirty(wb->bdi) && wakeup_bdi)
				wb_wakeup_delayed(wb);
			return;
		}
	}
out_unlock_inode:
	spin_unlock(&inode->i_lock);

#undef I_DIRTY_INODE
}
EXPORT_SYMBOL(__mark_inode_dirty);

static void wait_sb_inodes(struct super_block *sb)
{
	struct inode *inode, *old_inode = NULL;

	WARN_ON(!rwsem_is_locked(&sb->s_umount));

	mutex_lock(&sb->s_sync_lock);
	spin_lock(&sb->s_inode_list_lock);

	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		struct address_space *mapping = inode->i_mapping;

		spin_lock(&inode->i_lock);
		if ((inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW)) ||
		    (mapping->nrpages == 0)) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		__iget(inode);
		spin_unlock(&inode->i_lock);
		spin_unlock(&sb->s_inode_list_lock);

		iput(old_inode);
		old_inode = inode;

		filemap_fdatawait_keep_errors(mapping);

		cond_resched();

		spin_lock(&sb->s_inode_list_lock);
	}
	spin_unlock(&sb->s_inode_list_lock);
	iput(old_inode);
	mutex_unlock(&sb->s_sync_lock);
}

static void __writeback_inodes_sb_nr(struct super_block *sb, unsigned long nr,
				     enum wb_reason reason, bool skip_if_busy)
{
	DEFINE_WB_COMPLETION_ONSTACK(done);
	struct wb_writeback_work work = {
		.sb			= sb,
		.sync_mode		= WB_SYNC_NONE,
		.tagged_writepages	= 1,
		.done			= &done,
		.nr_pages		= nr,
		.reason			= reason,
	};
	struct backing_dev_info *bdi = sb->s_bdi;

	if (!bdi_has_dirty_io(bdi) || bdi == &noop_backing_dev_info)
		return;
	WARN_ON(!rwsem_is_locked(&sb->s_umount));

	bdi_split_work_to_wbs(sb->s_bdi, &work, skip_if_busy);
	wb_wait_for_completion(bdi, &done);
}

void writeback_inodes_sb_nr(struct super_block *sb,
			    unsigned long nr,
			    enum wb_reason reason)
{
	__writeback_inodes_sb_nr(sb, nr, reason, false);
}
EXPORT_SYMBOL(writeback_inodes_sb_nr);

void writeback_inodes_sb(struct super_block *sb, enum wb_reason reason)
{
	return writeback_inodes_sb_nr(sb, get_nr_dirty_pages(), reason);
}
EXPORT_SYMBOL(writeback_inodes_sb);

bool try_to_writeback_inodes_sb_nr(struct super_block *sb, unsigned long nr,
				   enum wb_reason reason)
{
	if (!down_read_trylock(&sb->s_umount))
		return false;

	__writeback_inodes_sb_nr(sb, nr, reason, true);
	up_read(&sb->s_umount);
	return true;
}
EXPORT_SYMBOL(try_to_writeback_inodes_sb_nr);

bool try_to_writeback_inodes_sb(struct super_block *sb, enum wb_reason reason)
{
	return try_to_writeback_inodes_sb_nr(sb, get_nr_dirty_pages(), reason);
}
EXPORT_SYMBOL(try_to_writeback_inodes_sb);

void sync_inodes_sb(struct super_block *sb)
{
	DEFINE_WB_COMPLETION_ONSTACK(done);
	struct wb_writeback_work work = {
		.sb		= sb,
		.sync_mode	= WB_SYNC_ALL,
		.nr_pages	= LONG_MAX,
		.range_cyclic	= 0,
		.done		= &done,
		.reason		= WB_REASON_SYNC,
		.for_sync	= 1,
	};
	struct backing_dev_info *bdi = sb->s_bdi;

	if (bdi == &noop_backing_dev_info)
		return;
	WARN_ON(!rwsem_is_locked(&sb->s_umount));

	bdi_split_work_to_wbs(bdi, &work, false);
	wb_wait_for_completion(bdi, &done);

	wait_sb_inodes(sb);
}
EXPORT_SYMBOL(sync_inodes_sb);

int write_inode_now(struct inode *inode, int sync)
{
	struct writeback_control wbc = {
		.nr_to_write = LONG_MAX,
		.sync_mode = sync ? WB_SYNC_ALL : WB_SYNC_NONE,
		.range_start = 0,
		.range_end = LLONG_MAX,
	};

	if (!mapping_cap_writeback_dirty(inode->i_mapping))
		wbc.nr_to_write = 0;

	might_sleep();
	return writeback_single_inode(inode, &wbc);
}
EXPORT_SYMBOL(write_inode_now);

int sync_inode(struct inode *inode, struct writeback_control *wbc)
{
	return writeback_single_inode(inode, wbc);
}
EXPORT_SYMBOL(sync_inode);

int sync_inode_metadata(struct inode *inode, int wait)
{
	struct writeback_control wbc = {
		.sync_mode = wait ? WB_SYNC_ALL : WB_SYNC_NONE,
		.nr_to_write = 0,  
	};

	return sync_inode(inode, &wbc);
}
EXPORT_SYMBOL(sync_inode_metadata);
