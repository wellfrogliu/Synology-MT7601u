#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/capability.h>
#include <linux/blkdev.h>
#include <linux/file.h>
#include <linux/quotaops.h>
#include <linux/highmem.h>
#include <linux/export.h>
#include <linux/backing-dev.h>
#include <linux/writeback.h>
#include <linux/hash.h>
#include <linux/suspend.h>
#include <linux/buffer_head.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/bio.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/bitops.h>
#include <linux/mpage.h>
#include <linux/bit_spinlock.h>
#include <trace/events/block.h>

static int fsync_buffers_list(spinlock_t *lock, struct list_head *list);
static int submit_bh_wbc(int rw, struct buffer_head *bh,
			 unsigned long bio_flags,
			 struct writeback_control *wbc);

#define BH_ENTRY(list) list_entry((list), struct buffer_head, b_assoc_buffers)

void init_buffer(struct buffer_head *bh, bh_end_io_t *handler, void *private)
{
	bh->b_end_io = handler;
	bh->b_private = private;
}
EXPORT_SYMBOL(init_buffer);

inline void touch_buffer(struct buffer_head *bh)
{
	trace_block_touch_buffer(bh);
	mark_page_accessed(bh->b_page);
}
EXPORT_SYMBOL(touch_buffer);

void __lock_buffer(struct buffer_head *bh)
{
	wait_on_bit_lock_io(&bh->b_state, BH_Lock, TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(__lock_buffer);

void unlock_buffer(struct buffer_head *bh)
{
	clear_bit_unlock(BH_Lock, &bh->b_state);
	smp_mb__after_atomic();
	wake_up_bit(&bh->b_state, BH_Lock);
}
EXPORT_SYMBOL(unlock_buffer);

void buffer_check_dirty_writeback(struct page *page,
				     bool *dirty, bool *writeback)
{
	struct buffer_head *head, *bh;
	*dirty = false;
	*writeback = false;

	BUG_ON(!PageLocked(page));

	if (!page_has_buffers(page))
		return;

	if (PageWriteback(page))
		*writeback = true;

	head = page_buffers(page);
	bh = head;
	do {
		if (buffer_locked(bh))
			*writeback = true;

		if (buffer_dirty(bh))
			*dirty = true;

		bh = bh->b_this_page;
	} while (bh != head);
}
EXPORT_SYMBOL(buffer_check_dirty_writeback);

void __wait_on_buffer(struct buffer_head * bh)
{
	wait_on_bit_io(&bh->b_state, BH_Lock, TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(__wait_on_buffer);

static void
__clear_page_buffers(struct page *page)
{
	ClearPagePrivate(page);
	set_page_private(page, 0);
	page_cache_release(page);
}

static void buffer_io_error(struct buffer_head *bh, char *msg)
{
	char b[BDEVNAME_SIZE];

	if (!test_bit(BH_Quiet, &bh->b_state))
#ifdef MY_ABC_HERE
	{
		static unsigned long long b_blocknr_last = 0;

		if (b_blocknr_last == (unsigned long long)bh->b_blocknr) {
			printk_ratelimited(KERN_ERR
					"Buffer I/O error on dev %s, logical block %llu%s\n",
					bdevname(bh->b_bdev, b),
					b_blocknr_last, msg);
		} else {
			b_blocknr_last = (unsigned long long)bh->b_blocknr;
			printk_ratelimited(KERN_ERR
					"Buffer I/O error on dev %s, logical block in range %llu + 0-2(%d) %s\n",
					bdevname(bh->b_bdev, b),
					(b_blocknr_last >> CONFIG_SYNO_IO_ERROR_LIMIT_MSG_SHIFT) << CONFIG_SYNO_IO_ERROR_LIMIT_MSG_SHIFT,
					CONFIG_SYNO_IO_ERROR_LIMIT_MSG_SHIFT, msg);
		}
	}
#else
	printk_ratelimited(KERN_ERR
			"Buffer I/O error on dev %s, logical block %llu%s\n",
			bdevname(bh->b_bdev, b),
			(unsigned long long)bh->b_blocknr, msg);
#endif  
}

static void __end_buffer_read_notouch(struct buffer_head *bh, int uptodate)
{
	if (uptodate) {
		set_buffer_uptodate(bh);
	} else {
		 
		clear_buffer_uptodate(bh);
	}
	unlock_buffer(bh);
}

void end_buffer_read_sync(struct buffer_head *bh, int uptodate)
{
	__end_buffer_read_notouch(bh, uptodate);
	put_bh(bh);
}
EXPORT_SYMBOL(end_buffer_read_sync);

void end_buffer_write_sync(struct buffer_head *bh, int uptodate)
{
	if (uptodate) {
		set_buffer_uptodate(bh);
	} else {
		buffer_io_error(bh, ", lost sync page write");
		set_buffer_write_io_error(bh);
		clear_buffer_uptodate(bh);
	}
	unlock_buffer(bh);
	put_bh(bh);
}
EXPORT_SYMBOL(end_buffer_write_sync);

static struct buffer_head *
__find_get_block_slow(struct block_device *bdev, sector_t block)
{
	struct inode *bd_inode = bdev->bd_inode;
	struct address_space *bd_mapping = bd_inode->i_mapping;
	struct buffer_head *ret = NULL;
	pgoff_t index;
	struct buffer_head *bh;
	struct buffer_head *head;
	struct page *page;
	int all_mapped = 1;

	index = block >> (PAGE_CACHE_SHIFT - bd_inode->i_blkbits);
	page = find_get_page_flags(bd_mapping, index, FGP_ACCESSED);
	if (!page)
		goto out;

	spin_lock(&bd_mapping->private_lock);
	if (!page_has_buffers(page))
		goto out_unlock;
	head = page_buffers(page);
	bh = head;
	do {
		if (!buffer_mapped(bh))
			all_mapped = 0;
		else if (bh->b_blocknr == block) {
			ret = bh;
			get_bh(bh);
			goto out_unlock;
		}
		bh = bh->b_this_page;
	} while (bh != head);

	if (all_mapped) {
		char b[BDEVNAME_SIZE];

		printk("__find_get_block_slow() failed. "
			"block=%llu, b_blocknr=%llu\n",
			(unsigned long long)block,
			(unsigned long long)bh->b_blocknr);
		printk("b_state=0x%08lx, b_size=%zu\n",
			bh->b_state, bh->b_size);
		printk("device %s blocksize: %d\n", bdevname(bdev, b),
			1 << bd_inode->i_blkbits);
	}
out_unlock:
	spin_unlock(&bd_mapping->private_lock);
	page_cache_release(page);
out:
	return ret;
}

static void free_more_memory(void)
{
	struct zone *zone;
	int nid;

	wakeup_flusher_threads(1024, WB_REASON_FREE_MORE_MEM);
	yield();

	for_each_online_node(nid) {
		(void)first_zones_zonelist(node_zonelist(nid, GFP_NOFS),
						gfp_zone(GFP_NOFS), NULL,
						&zone);
		if (zone)
			try_to_free_pages(node_zonelist(nid, GFP_NOFS), 0,
						GFP_NOFS, NULL);
	}
}

static void end_buffer_async_read(struct buffer_head *bh, int uptodate)
{
	unsigned long flags;
	struct buffer_head *first;
	struct buffer_head *tmp;
	struct page *page;
	int page_uptodate = 1;

	BUG_ON(!buffer_async_read(bh));

	page = bh->b_page;
	if (uptodate) {
		set_buffer_uptodate(bh);
	} else {
		clear_buffer_uptodate(bh);
		buffer_io_error(bh, ", async page read");
		SetPageError(page);
	}

	first = page_buffers(page);
	local_irq_save(flags);
	bit_spin_lock(BH_Uptodate_Lock, &first->b_state);
	clear_buffer_async_read(bh);
	unlock_buffer(bh);
	tmp = bh;
	do {
		if (!buffer_uptodate(tmp))
			page_uptodate = 0;
		if (buffer_async_read(tmp)) {
			BUG_ON(!buffer_locked(tmp));
			goto still_busy;
		}
		tmp = tmp->b_this_page;
	} while (tmp != bh);
	bit_spin_unlock(BH_Uptodate_Lock, &first->b_state);
	local_irq_restore(flags);

	if (page_uptodate && !PageError(page))
		SetPageUptodate(page);
	unlock_page(page);
	return;

still_busy:
	bit_spin_unlock(BH_Uptodate_Lock, &first->b_state);
	local_irq_restore(flags);
	return;
}

void end_buffer_async_write(struct buffer_head *bh, int uptodate)
{
	unsigned long flags;
	struct buffer_head *first;
	struct buffer_head *tmp;
	struct page *page;

	BUG_ON(!buffer_async_write(bh));

	page = bh->b_page;
	if (uptodate) {
		set_buffer_uptodate(bh);
	} else {
		buffer_io_error(bh, ", lost async page write");
		set_bit(AS_EIO, &page->mapping->flags);
		set_buffer_write_io_error(bh);
		clear_buffer_uptodate(bh);
		SetPageError(page);
	}

	first = page_buffers(page);
	local_irq_save(flags);
	bit_spin_lock(BH_Uptodate_Lock, &first->b_state);

	clear_buffer_async_write(bh);
	unlock_buffer(bh);
	tmp = bh->b_this_page;
	while (tmp != bh) {
		if (buffer_async_write(tmp)) {
			BUG_ON(!buffer_locked(tmp));
			goto still_busy;
		}
		tmp = tmp->b_this_page;
	}
	bit_spin_unlock(BH_Uptodate_Lock, &first->b_state);
	local_irq_restore(flags);
	end_page_writeback(page);
	return;

still_busy:
	bit_spin_unlock(BH_Uptodate_Lock, &first->b_state);
	local_irq_restore(flags);
	return;
}
EXPORT_SYMBOL(end_buffer_async_write);

static void mark_buffer_async_read(struct buffer_head *bh)
{
	bh->b_end_io = end_buffer_async_read;
	set_buffer_async_read(bh);
}

static void mark_buffer_async_write_endio(struct buffer_head *bh,
					  bh_end_io_t *handler)
{
	bh->b_end_io = handler;
	set_buffer_async_write(bh);
}

void mark_buffer_async_write(struct buffer_head *bh)
{
	mark_buffer_async_write_endio(bh, end_buffer_async_write);
}
EXPORT_SYMBOL(mark_buffer_async_write);

static void __remove_assoc_queue(struct buffer_head *bh)
{
	list_del_init(&bh->b_assoc_buffers);
	WARN_ON(!bh->b_assoc_map);
	if (buffer_write_io_error(bh))
		set_bit(AS_EIO, &bh->b_assoc_map->flags);
	bh->b_assoc_map = NULL;
}

int inode_has_buffers(struct inode *inode)
{
	return !list_empty(&inode->i_data.private_list);
}

static int osync_buffers_list(spinlock_t *lock, struct list_head *list)
{
	struct buffer_head *bh;
	struct list_head *p;
	int err = 0;

	spin_lock(lock);
repeat:
	list_for_each_prev(p, list) {
		bh = BH_ENTRY(p);
		if (buffer_locked(bh)) {
			get_bh(bh);
			spin_unlock(lock);
			wait_on_buffer(bh);
			if (!buffer_uptodate(bh))
				err = -EIO;
			brelse(bh);
			spin_lock(lock);
			goto repeat;
		}
	}
	spin_unlock(lock);
	return err;
}

static void do_thaw_one(struct super_block *sb, void *unused)
{
	char b[BDEVNAME_SIZE];
	while (sb->s_bdev && !thaw_bdev(sb->s_bdev, sb))
		printk(KERN_WARNING "Emergency Thaw on %s\n",
		       bdevname(sb->s_bdev, b));
}

static void do_thaw_all(struct work_struct *work)
{
	iterate_supers(do_thaw_one, NULL);
	kfree(work);
	printk(KERN_WARNING "Emergency Thaw complete\n");
}

void emergency_thaw_all(void)
{
	struct work_struct *work;

	work = kmalloc(sizeof(*work), GFP_ATOMIC);
	if (work) {
		INIT_WORK(work, do_thaw_all);
		schedule_work(work);
	}
}

int sync_mapping_buffers(struct address_space *mapping)
{
	struct address_space *buffer_mapping = mapping->private_data;

	if (buffer_mapping == NULL || list_empty(&mapping->private_list))
		return 0;

	return fsync_buffers_list(&buffer_mapping->private_lock,
					&mapping->private_list);
}
EXPORT_SYMBOL(sync_mapping_buffers);

void write_boundary_block(struct block_device *bdev,
			sector_t bblock, unsigned blocksize)
{
	struct buffer_head *bh = __find_get_block(bdev, bblock + 1, blocksize);
	if (bh) {
		if (buffer_dirty(bh))
			ll_rw_block(WRITE, 1, &bh);
		put_bh(bh);
	}
}

void mark_buffer_dirty_inode(struct buffer_head *bh, struct inode *inode)
{
	struct address_space *mapping = inode->i_mapping;
	struct address_space *buffer_mapping = bh->b_page->mapping;

	mark_buffer_dirty(bh);
	if (!mapping->private_data) {
		mapping->private_data = buffer_mapping;
	} else {
		BUG_ON(mapping->private_data != buffer_mapping);
	}
	if (!bh->b_assoc_map) {
		spin_lock(&buffer_mapping->private_lock);
		list_move_tail(&bh->b_assoc_buffers,
				&mapping->private_list);
		bh->b_assoc_map = mapping;
		spin_unlock(&buffer_mapping->private_lock);
	}
}
EXPORT_SYMBOL(mark_buffer_dirty_inode);

static void __set_page_dirty(struct page *page, struct address_space *mapping,
			     struct mem_cgroup *memcg, int warn)
{
	unsigned long flags;

	spin_lock_irqsave(&mapping->tree_lock, flags);
	if (page->mapping) {	 
		WARN_ON_ONCE(warn && !PageUptodate(page));
		account_page_dirtied(page, mapping, memcg);
		radix_tree_tag_set(&mapping->page_tree,
				page_index(page), PAGECACHE_TAG_DIRTY);
	}
	spin_unlock_irqrestore(&mapping->tree_lock, flags);
}

int __set_page_dirty_buffers(struct page *page)
{
	int newly_dirty;
	struct mem_cgroup *memcg;
	struct address_space *mapping = page_mapping(page);

	if (unlikely(!mapping))
		return !TestSetPageDirty(page);

	spin_lock(&mapping->private_lock);
	if (page_has_buffers(page)) {
		struct buffer_head *head = page_buffers(page);
		struct buffer_head *bh = head;

		do {
			set_buffer_dirty(bh);
			bh = bh->b_this_page;
		} while (bh != head);
	}
	 
	memcg = mem_cgroup_begin_page_stat(page);
	newly_dirty = !TestSetPageDirty(page);
	spin_unlock(&mapping->private_lock);

	if (newly_dirty)
		__set_page_dirty(page, mapping, memcg, 1);

	mem_cgroup_end_page_stat(memcg);

	if (newly_dirty)
		__mark_inode_dirty(mapping->host, I_DIRTY_PAGES);

	return newly_dirty;
}
EXPORT_SYMBOL(__set_page_dirty_buffers);

static int fsync_buffers_list(spinlock_t *lock, struct list_head *list)
{
	struct buffer_head *bh;
	struct list_head tmp;
	struct address_space *mapping;
	int err = 0, err2;
	struct blk_plug plug;

	INIT_LIST_HEAD(&tmp);
	blk_start_plug(&plug);

	spin_lock(lock);
	while (!list_empty(list)) {
		bh = BH_ENTRY(list->next);
		mapping = bh->b_assoc_map;
		__remove_assoc_queue(bh);
		 
		smp_mb();
		if (buffer_dirty(bh) || buffer_locked(bh)) {
			list_add(&bh->b_assoc_buffers, &tmp);
			bh->b_assoc_map = mapping;
			if (buffer_dirty(bh)) {
				get_bh(bh);
				spin_unlock(lock);
				 
				write_dirty_buffer(bh, WRITE_SYNC);

				brelse(bh);
				spin_lock(lock);
			}
		}
	}

	spin_unlock(lock);
	blk_finish_plug(&plug);
	spin_lock(lock);

	while (!list_empty(&tmp)) {
		bh = BH_ENTRY(tmp.prev);
		get_bh(bh);
		mapping = bh->b_assoc_map;
		__remove_assoc_queue(bh);
		 
		smp_mb();
		if (buffer_dirty(bh)) {
			list_add(&bh->b_assoc_buffers,
				 &mapping->private_list);
			bh->b_assoc_map = mapping;
		}
		spin_unlock(lock);
		wait_on_buffer(bh);
		if (!buffer_uptodate(bh))
			err = -EIO;
		brelse(bh);
		spin_lock(lock);
	}
	
	spin_unlock(lock);
	err2 = osync_buffers_list(lock, list);
	if (err)
		return err;
	else
		return err2;
}

void invalidate_inode_buffers(struct inode *inode)
{
	if (inode_has_buffers(inode)) {
		struct address_space *mapping = &inode->i_data;
		struct list_head *list = &mapping->private_list;
		struct address_space *buffer_mapping = mapping->private_data;

		spin_lock(&buffer_mapping->private_lock);
		while (!list_empty(list))
			__remove_assoc_queue(BH_ENTRY(list->next));
		spin_unlock(&buffer_mapping->private_lock);
	}
}
EXPORT_SYMBOL(invalidate_inode_buffers);

int remove_inode_buffers(struct inode *inode)
{
	int ret = 1;

	if (inode_has_buffers(inode)) {
		struct address_space *mapping = &inode->i_data;
		struct list_head *list = &mapping->private_list;
		struct address_space *buffer_mapping = mapping->private_data;

		spin_lock(&buffer_mapping->private_lock);
		while (!list_empty(list)) {
			struct buffer_head *bh = BH_ENTRY(list->next);
			if (buffer_dirty(bh)) {
				ret = 0;
				break;
			}
			__remove_assoc_queue(bh);
		}
		spin_unlock(&buffer_mapping->private_lock);
	}
	return ret;
}

struct buffer_head *alloc_page_buffers(struct page *page, unsigned long size,
		int retry)
{
	struct buffer_head *bh, *head;
	long offset;

try_again:
	head = NULL;
	offset = PAGE_SIZE;
	while ((offset -= size) >= 0) {
		bh = alloc_buffer_head(GFP_NOFS);
		if (!bh)
			goto no_grow;

		bh->b_this_page = head;
		bh->b_blocknr = -1;
		head = bh;

		bh->b_size = size;

		set_bh_page(bh, page, offset);
	}
	return head;
 
no_grow:
	if (head) {
		do {
			bh = head;
			head = head->b_this_page;
			free_buffer_head(bh);
		} while (head);
	}

	if (!retry)
		return NULL;

	free_more_memory();
	goto try_again;
}
EXPORT_SYMBOL_GPL(alloc_page_buffers);

static inline void
link_dev_buffers(struct page *page, struct buffer_head *head)
{
	struct buffer_head *bh, *tail;

	bh = head;
	do {
		tail = bh;
		bh = bh->b_this_page;
	} while (bh);
	tail->b_this_page = head;
	attach_page_buffers(page, head);
}

static sector_t blkdev_max_block(struct block_device *bdev, unsigned int size)
{
	sector_t retval = ~((sector_t)0);
	loff_t sz = i_size_read(bdev->bd_inode);

	if (sz) {
		unsigned int sizebits = blksize_bits(size);
		retval = (sz >> sizebits);
	}
	return retval;
}

static sector_t
init_page_buffers(struct page *page, struct block_device *bdev,
			sector_t block, int size)
{
	struct buffer_head *head = page_buffers(page);
	struct buffer_head *bh = head;
	int uptodate = PageUptodate(page);
	sector_t end_block = blkdev_max_block(I_BDEV(bdev->bd_inode), size);

	do {
		if (!buffer_mapped(bh)) {
			init_buffer(bh, NULL, NULL);
			bh->b_bdev = bdev;
			bh->b_blocknr = block;
			if (uptodate)
				set_buffer_uptodate(bh);
			if (block < end_block)
				set_buffer_mapped(bh);
		}
		block++;
		bh = bh->b_this_page;
	} while (bh != head);

	return end_block;
}

static int
grow_dev_page(struct block_device *bdev, sector_t block,
	      pgoff_t index, int size, int sizebits, gfp_t gfp)
{
	struct inode *inode = bdev->bd_inode;
	struct page *page;
	struct buffer_head *bh;
	sector_t end_block;
	int ret = 0;		 
	gfp_t gfp_mask;

	gfp_mask = mapping_gfp_constraint(inode->i_mapping, ~__GFP_FS) | gfp;

	gfp_mask |= __GFP_NOFAIL;

	page = find_or_create_page(inode->i_mapping, index, gfp_mask);
	if (!page)
		return ret;

	BUG_ON(!PageLocked(page));

	if (page_has_buffers(page)) {
		bh = page_buffers(page);
		if (bh->b_size == size) {
			end_block = init_page_buffers(page, bdev,
						(sector_t)index << sizebits,
						size);
			goto done;
		}
		if (!try_to_free_buffers(page))
			goto failed;
	}

	bh = alloc_page_buffers(page, size, 0);
	if (!bh)
		goto failed;

	spin_lock(&inode->i_mapping->private_lock);
	link_dev_buffers(page, bh);
	end_block = init_page_buffers(page, bdev, (sector_t)index << sizebits,
			size);
	spin_unlock(&inode->i_mapping->private_lock);
done:
	ret = (block < end_block) ? 1 : -ENXIO;
failed:
	unlock_page(page);
	page_cache_release(page);
	return ret;
}

static int
grow_buffers(struct block_device *bdev, sector_t block, int size, gfp_t gfp)
{
	pgoff_t index;
	int sizebits;

	sizebits = -1;
	do {
		sizebits++;
	} while ((size << sizebits) < PAGE_SIZE);

	index = block >> sizebits;

	if (unlikely(index != block >> sizebits)) {
		char b[BDEVNAME_SIZE];

		printk(KERN_ERR "%s: requested out-of-range block %llu for "
			"device %s\n",
			__func__, (unsigned long long)block,
			bdevname(bdev, b));
		return -EIO;
	}

	return grow_dev_page(bdev, block, index, size, sizebits, gfp);
}

struct buffer_head *
__getblk_slow(struct block_device *bdev, sector_t block,
	     unsigned size, gfp_t gfp)
{
	 
	if (unlikely(size & (bdev_logical_block_size(bdev)-1) ||
			(size < 512 || size > PAGE_SIZE))) {
		printk(KERN_ERR "getblk(): invalid block size %d requested\n",
					size);
		printk(KERN_ERR "logical block size: %d\n",
					bdev_logical_block_size(bdev));

		dump_stack();
		return NULL;
	}

	for (;;) {
		struct buffer_head *bh;
		int ret;

		bh = __find_get_block(bdev, block, size);
		if (bh)
			return bh;

		ret = grow_buffers(bdev, block, size, gfp);
		if (ret < 0)
			return NULL;
		if (ret == 0)
			free_more_memory();
	}
}
EXPORT_SYMBOL(__getblk_slow);

void mark_buffer_dirty(struct buffer_head *bh)
{
	WARN_ON_ONCE(!buffer_uptodate(bh));

	trace_block_dirty_buffer(bh);

	if (buffer_dirty(bh)) {
		smp_mb();
		if (buffer_dirty(bh))
			return;
	}

	if (!test_set_buffer_dirty(bh)) {
		struct page *page = bh->b_page;
		struct address_space *mapping = NULL;
		struct mem_cgroup *memcg;

		memcg = mem_cgroup_begin_page_stat(page);
		if (!TestSetPageDirty(page)) {
			mapping = page_mapping(page);
			if (mapping)
				__set_page_dirty(page, mapping, memcg, 0);
		}
		mem_cgroup_end_page_stat(memcg);
		if (mapping)
			__mark_inode_dirty(mapping->host, I_DIRTY_PAGES);
	}
}
EXPORT_SYMBOL(mark_buffer_dirty);

void __brelse(struct buffer_head * buf)
{
	if (atomic_read(&buf->b_count)) {
		put_bh(buf);
		return;
	}
	WARN(1, KERN_ERR "VFS: brelse: Trying to free free buffer\n");
}
EXPORT_SYMBOL(__brelse);

void __bforget(struct buffer_head *bh)
{
	clear_buffer_dirty(bh);
	if (bh->b_assoc_map) {
		struct address_space *buffer_mapping = bh->b_page->mapping;

		spin_lock(&buffer_mapping->private_lock);
		list_del_init(&bh->b_assoc_buffers);
		bh->b_assoc_map = NULL;
		spin_unlock(&buffer_mapping->private_lock);
	}
	__brelse(bh);
}
EXPORT_SYMBOL(__bforget);

static struct buffer_head *__bread_slow(struct buffer_head *bh)
{
	lock_buffer(bh);
	if (buffer_uptodate(bh)) {
		unlock_buffer(bh);
		return bh;
	} else {
		get_bh(bh);
		bh->b_end_io = end_buffer_read_sync;
		submit_bh(READ, bh);
		wait_on_buffer(bh);
		if (buffer_uptodate(bh))
			return bh;
	}
	brelse(bh);
	return NULL;
}

#define BH_LRU_SIZE	16

struct bh_lru {
	struct buffer_head *bhs[BH_LRU_SIZE];
};

static DEFINE_PER_CPU(struct bh_lru, bh_lrus) = {{ NULL }};

#ifdef CONFIG_SMP
#define bh_lru_lock()	local_irq_disable()
#define bh_lru_unlock()	local_irq_enable()
#else
#define bh_lru_lock()	preempt_disable()
#define bh_lru_unlock()	preempt_enable()
#endif

static inline void check_irqs_on(void)
{
#ifdef irqs_disabled
	BUG_ON(irqs_disabled());
#endif
}

static void bh_lru_install(struct buffer_head *bh)
{
	struct buffer_head *evictee = NULL;

	check_irqs_on();
	bh_lru_lock();
	if (__this_cpu_read(bh_lrus.bhs[0]) != bh) {
		struct buffer_head *bhs[BH_LRU_SIZE];
		int in;
		int out = 0;

		get_bh(bh);
		bhs[out++] = bh;
		for (in = 0; in < BH_LRU_SIZE; in++) {
			struct buffer_head *bh2 =
				__this_cpu_read(bh_lrus.bhs[in]);

			if (bh2 == bh) {
				__brelse(bh2);
			} else {
				if (out >= BH_LRU_SIZE) {
					BUG_ON(evictee != NULL);
					evictee = bh2;
				} else {
					bhs[out++] = bh2;
				}
			}
		}
		while (out < BH_LRU_SIZE)
			bhs[out++] = NULL;
		memcpy(this_cpu_ptr(&bh_lrus.bhs), bhs, sizeof(bhs));
	}
	bh_lru_unlock();

	if (evictee)
		__brelse(evictee);
}

static struct buffer_head *
lookup_bh_lru(struct block_device *bdev, sector_t block, unsigned size)
{
	struct buffer_head *ret = NULL;
	unsigned int i;

	check_irqs_on();
	bh_lru_lock();
	for (i = 0; i < BH_LRU_SIZE; i++) {
		struct buffer_head *bh = __this_cpu_read(bh_lrus.bhs[i]);

		if (bh && bh->b_blocknr == block && bh->b_bdev == bdev &&
		    bh->b_size == size) {
			if (i) {
				while (i) {
					__this_cpu_write(bh_lrus.bhs[i],
						__this_cpu_read(bh_lrus.bhs[i - 1]));
					i--;
				}
				__this_cpu_write(bh_lrus.bhs[0], bh);
			}
			get_bh(bh);
			ret = bh;
			break;
		}
	}
	bh_lru_unlock();
	return ret;
}

struct buffer_head *
__find_get_block(struct block_device *bdev, sector_t block, unsigned size)
{
	struct buffer_head *bh = lookup_bh_lru(bdev, block, size);

	if (bh == NULL) {
		 
		bh = __find_get_block_slow(bdev, block);
		if (bh)
			bh_lru_install(bh);
	} else
		touch_buffer(bh);

	return bh;
}
EXPORT_SYMBOL(__find_get_block);

struct buffer_head *
__getblk_gfp(struct block_device *bdev, sector_t block,
	     unsigned size, gfp_t gfp)
{
	struct buffer_head *bh = __find_get_block(bdev, block, size);

	might_sleep();
	if (bh == NULL)
		bh = __getblk_slow(bdev, block, size, gfp);
	return bh;
}
EXPORT_SYMBOL(__getblk_gfp);

void __breadahead(struct block_device *bdev, sector_t block, unsigned size)
{
	struct buffer_head *bh = __getblk(bdev, block, size);
	if (likely(bh)) {
		ll_rw_block(READA, 1, &bh);
		brelse(bh);
	}
}
EXPORT_SYMBOL(__breadahead);

struct buffer_head *
__bread_gfp(struct block_device *bdev, sector_t block,
		   unsigned size, gfp_t gfp)
{
	struct buffer_head *bh = __getblk_gfp(bdev, block, size, gfp);

	if (likely(bh) && !buffer_uptodate(bh))
		bh = __bread_slow(bh);
	return bh;
}
EXPORT_SYMBOL(__bread_gfp);

static void invalidate_bh_lru(void *arg)
{
	struct bh_lru *b = &get_cpu_var(bh_lrus);
	int i;

	for (i = 0; i < BH_LRU_SIZE; i++) {
		brelse(b->bhs[i]);
		b->bhs[i] = NULL;
	}
	put_cpu_var(bh_lrus);
}

static bool has_bh_in_lru(int cpu, void *dummy)
{
	struct bh_lru *b = per_cpu_ptr(&bh_lrus, cpu);
	int i;
	
	for (i = 0; i < BH_LRU_SIZE; i++) {
		if (b->bhs[i])
			return 1;
	}

	return 0;
}

void invalidate_bh_lrus(void)
{
	on_each_cpu_cond(has_bh_in_lru, invalidate_bh_lru, NULL, 1, GFP_KERNEL);
}
EXPORT_SYMBOL_GPL(invalidate_bh_lrus);

void set_bh_page(struct buffer_head *bh,
		struct page *page, unsigned long offset)
{
	bh->b_page = page;
	BUG_ON(offset >= PAGE_SIZE);
	if (PageHighMem(page))
		 
		bh->b_data = (char *)(0 + offset);
	else
		bh->b_data = page_address(page) + offset;
}
EXPORT_SYMBOL(set_bh_page);

#define BUFFER_FLAGS_DISCARD \
	(1 << BH_Mapped | 1 << BH_New | 1 << BH_Req | \
	 1 << BH_Delay | 1 << BH_Unwritten)

static void discard_buffer(struct buffer_head * bh)
{
	unsigned long b_state, b_state_old;

	lock_buffer(bh);
	clear_buffer_dirty(bh);
	bh->b_bdev = NULL;
	b_state = bh->b_state;
	for (;;) {
		b_state_old = cmpxchg(&bh->b_state, b_state,
				      (b_state & ~BUFFER_FLAGS_DISCARD));
		if (b_state_old == b_state)
			break;
		b_state = b_state_old;
	}
	unlock_buffer(bh);
}

void block_invalidatepage(struct page *page, unsigned int offset,
			  unsigned int length)
{
	struct buffer_head *head, *bh, *next;
	unsigned int curr_off = 0;
	unsigned int stop = length + offset;

	BUG_ON(!PageLocked(page));
	if (!page_has_buffers(page))
		goto out;

	BUG_ON(stop > PAGE_CACHE_SIZE || stop < length);

	head = page_buffers(page);
	bh = head;
	do {
		unsigned int next_off = curr_off + bh->b_size;
		next = bh->b_this_page;

		if (next_off > stop)
			goto out;

		if (offset <= curr_off)
			discard_buffer(bh);
		curr_off = next_off;
		bh = next;
	} while (bh != head);

	if (offset == 0)
		try_to_release_page(page, 0);
out:
	return;
}
EXPORT_SYMBOL(block_invalidatepage);

void create_empty_buffers(struct page *page,
			unsigned long blocksize, unsigned long b_state)
{
	struct buffer_head *bh, *head, *tail;

	head = alloc_page_buffers(page, blocksize, 1);
	bh = head;
	do {
		bh->b_state |= b_state;
		tail = bh;
		bh = bh->b_this_page;
	} while (bh);
	tail->b_this_page = head;

	spin_lock(&page->mapping->private_lock);
	if (PageUptodate(page) || PageDirty(page)) {
		bh = head;
		do {
			if (PageDirty(page))
				set_buffer_dirty(bh);
			if (PageUptodate(page))
				set_buffer_uptodate(bh);
			bh = bh->b_this_page;
		} while (bh != head);
	}
	attach_page_buffers(page, head);
	spin_unlock(&page->mapping->private_lock);
}
EXPORT_SYMBOL(create_empty_buffers);

void unmap_underlying_metadata(struct block_device *bdev, sector_t block)
{
	struct buffer_head *old_bh;

	might_sleep();

	old_bh = __find_get_block_slow(bdev, block);
	if (old_bh) {
		clear_buffer_dirty(old_bh);
		wait_on_buffer(old_bh);
		clear_buffer_req(old_bh);
		__brelse(old_bh);
	}
}
EXPORT_SYMBOL(unmap_underlying_metadata);

static inline int block_size_bits(unsigned int blocksize)
{
	return ilog2(blocksize);
}

static struct buffer_head *create_page_buffers(struct page *page, struct inode *inode, unsigned int b_state)
{
	BUG_ON(!PageLocked(page));

	if (!page_has_buffers(page))
		create_empty_buffers(page, 1 << ACCESS_ONCE(inode->i_blkbits), b_state);
	return page_buffers(page);
}

static int __block_write_full_page(struct inode *inode, struct page *page,
			get_block_t *get_block, struct writeback_control *wbc,
			bh_end_io_t *handler)
{
	int err;
	sector_t block;
	sector_t last_block;
	struct buffer_head *bh, *head;
	unsigned int blocksize, bbits;
	int nr_underway = 0;
	int write_op = wbc_to_write_cmd(wbc);

	head = create_page_buffers(page, inode,
					(1 << BH_Dirty)|(1 << BH_Uptodate));

	bh = head;
	blocksize = bh->b_size;
	bbits = block_size_bits(blocksize);

	block = (sector_t)page->index << (PAGE_CACHE_SHIFT - bbits);
	last_block = (i_size_read(inode) - 1) >> bbits;

	do {
		if (block > last_block) {
			 
			clear_buffer_dirty(bh);
			set_buffer_uptodate(bh);
		} else if ((!buffer_mapped(bh) || buffer_delay(bh)) &&
			   buffer_dirty(bh)) {
			WARN_ON(bh->b_size != blocksize);
			err = get_block(inode, block, bh, 1);
			if (err)
				goto recover;
			clear_buffer_delay(bh);
			if (buffer_new(bh)) {
				 
				clear_buffer_new(bh);
				unmap_underlying_metadata(bh->b_bdev,
							bh->b_blocknr);
			}
		}
		bh = bh->b_this_page;
		block++;
	} while (bh != head);

	do {
		if (!buffer_mapped(bh))
			continue;
		 
		if (wbc->sync_mode != WB_SYNC_NONE) {
			lock_buffer(bh);
		} else if (!trylock_buffer(bh)) {
			redirty_page_for_writepage(wbc, page);
			continue;
		}
		if (test_clear_buffer_dirty(bh)) {
			mark_buffer_async_write_endio(bh, handler);
		} else {
			unlock_buffer(bh);
		}
	} while ((bh = bh->b_this_page) != head);

	BUG_ON(PageWriteback(page));
	set_page_writeback(page);

	do {
		struct buffer_head *next = bh->b_this_page;
		if (buffer_async_write(bh)) {
			submit_bh_wbc(write_op, bh, 0, wbc);
			nr_underway++;
		}
		bh = next;
	} while (bh != head);
	unlock_page(page);

	err = 0;
done:
	if (nr_underway == 0) {
		 
		end_page_writeback(page);

	}
	return err;

recover:
	 
	bh = head;
	 
	do {
		if (buffer_mapped(bh) && buffer_dirty(bh) &&
		    !buffer_delay(bh)) {
			lock_buffer(bh);
			mark_buffer_async_write_endio(bh, handler);
		} else {
			 
			clear_buffer_dirty(bh);
		}
	} while ((bh = bh->b_this_page) != head);
	SetPageError(page);
	BUG_ON(PageWriteback(page));
	mapping_set_error(page->mapping, err);
	set_page_writeback(page);
	do {
		struct buffer_head *next = bh->b_this_page;
		if (buffer_async_write(bh)) {
			clear_buffer_dirty(bh);
			submit_bh_wbc(write_op, bh, 0, wbc);
			nr_underway++;
		}
		bh = next;
	} while (bh != head);
	unlock_page(page);
	goto done;
}

void page_zero_new_buffers(struct page *page, unsigned from, unsigned to)
{
	unsigned int block_start, block_end;
	struct buffer_head *head, *bh;

	BUG_ON(!PageLocked(page));
	if (!page_has_buffers(page))
		return;

	bh = head = page_buffers(page);
	block_start = 0;
	do {
		block_end = block_start + bh->b_size;

		if (buffer_new(bh)) {
			if (block_end > from && block_start < to) {
				if (!PageUptodate(page)) {
					unsigned start, size;

					start = max(from, block_start);
					size = min(to, block_end) - start;

					zero_user(page, start, size);
					set_buffer_uptodate(bh);
				}

				clear_buffer_new(bh);
				mark_buffer_dirty(bh);
			}
		}

		block_start = block_end;
		bh = bh->b_this_page;
	} while (bh != head);
}
EXPORT_SYMBOL(page_zero_new_buffers);

int __block_write_begin(struct page *page, loff_t pos, unsigned len,
		get_block_t *get_block)
{
	unsigned from = pos & (PAGE_CACHE_SIZE - 1);
	unsigned to = from + len;
	struct inode *inode = page->mapping->host;
	unsigned block_start, block_end;
	sector_t block;
	int err = 0;
	unsigned blocksize, bbits;
	struct buffer_head *bh, *head, *wait[2], **wait_bh=wait;

	BUG_ON(!PageLocked(page));
	BUG_ON(from > PAGE_CACHE_SIZE);
	BUG_ON(to > PAGE_CACHE_SIZE);
	BUG_ON(from > to);

	head = create_page_buffers(page, inode, 0);
	blocksize = head->b_size;
	bbits = block_size_bits(blocksize);

	block = (sector_t)page->index << (PAGE_CACHE_SHIFT - bbits);

	for(bh = head, block_start = 0; bh != head || !block_start;
	    block++, block_start=block_end, bh = bh->b_this_page) {
		block_end = block_start + blocksize;
		if (block_end <= from || block_start >= to) {
			if (PageUptodate(page)) {
				if (!buffer_uptodate(bh))
					set_buffer_uptodate(bh);
			}
			continue;
		}
		if (buffer_new(bh))
			clear_buffer_new(bh);
		if (!buffer_mapped(bh)) {
			WARN_ON(bh->b_size != blocksize);
			err = get_block(inode, block, bh, 1);
			if (err)
				break;
			if (buffer_new(bh)) {
				unmap_underlying_metadata(bh->b_bdev,
							bh->b_blocknr);
				if (PageUptodate(page)) {
					clear_buffer_new(bh);
					set_buffer_uptodate(bh);
					mark_buffer_dirty(bh);
					continue;
				}
				if (block_end > to || block_start < from)
					zero_user_segments(page,
						to, block_end,
						block_start, from);
				continue;
			}
		}
		if (PageUptodate(page)) {
			if (!buffer_uptodate(bh))
				set_buffer_uptodate(bh);
			continue; 
		}
		if (!buffer_uptodate(bh) && !buffer_delay(bh) &&
		    !buffer_unwritten(bh) &&
		     (block_start < from || block_end > to)) {
			ll_rw_block(READ, 1, &bh);
			*wait_bh++=bh;
		}
	}
	 
	while(wait_bh > wait) {
		wait_on_buffer(*--wait_bh);
		if (!buffer_uptodate(*wait_bh))
			err = -EIO;
	}
	if (unlikely(err))
		page_zero_new_buffers(page, from, to);
	return err;
}
EXPORT_SYMBOL(__block_write_begin);

static int __block_commit_write(struct inode *inode, struct page *page,
		unsigned from, unsigned to)
{
	unsigned block_start, block_end;
	int partial = 0;
	unsigned blocksize;
	struct buffer_head *bh, *head;

	bh = head = page_buffers(page);
	blocksize = bh->b_size;

	block_start = 0;
	do {
		block_end = block_start + blocksize;
		if (block_end <= from || block_start >= to) {
			if (!buffer_uptodate(bh))
				partial = 1;
		} else {
			set_buffer_uptodate(bh);
			mark_buffer_dirty(bh);
		}
		clear_buffer_new(bh);

		block_start = block_end;
		bh = bh->b_this_page;
	} while (bh != head);

	if (!partial)
		SetPageUptodate(page);
	return 0;
}

int block_write_begin(struct address_space *mapping, loff_t pos, unsigned len,
		unsigned flags, struct page **pagep, get_block_t *get_block)
{
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	struct page *page;
	int status;

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;

	status = __block_write_begin(page, pos, len, get_block);
	if (unlikely(status)) {
		unlock_page(page);
		page_cache_release(page);
		page = NULL;
	}

	*pagep = page;
	return status;
}
EXPORT_SYMBOL(block_write_begin);

int block_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;
	unsigned start;

	start = pos & (PAGE_CACHE_SIZE - 1);

	if (unlikely(copied < len)) {
		 
		if (!PageUptodate(page))
			copied = 0;

		page_zero_new_buffers(page, start+copied, start+len);
	}
	flush_dcache_page(page);

	__block_commit_write(inode, page, start, start+copied);

	return copied;
}
EXPORT_SYMBOL(block_write_end);

int generic_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;
	loff_t old_size = inode->i_size;
	int i_size_changed = 0;

	copied = block_write_end(file, mapping, pos, len, copied, page, fsdata);

	if (pos+copied > inode->i_size) {
		i_size_write(inode, pos+copied);
		i_size_changed = 1;
	}

	unlock_page(page);
	page_cache_release(page);

	if (old_size < pos)
		pagecache_isize_extended(inode, old_size, pos);
	 
	if (i_size_changed)
		mark_inode_dirty(inode);

	return copied;
}
EXPORT_SYMBOL(generic_write_end);

int block_is_partially_uptodate(struct page *page, unsigned long from,
					unsigned long count)
{
	unsigned block_start, block_end, blocksize;
	unsigned to;
	struct buffer_head *bh, *head;
	int ret = 1;

	if (!page_has_buffers(page))
		return 0;

	head = page_buffers(page);
	blocksize = head->b_size;
	to = min_t(unsigned, PAGE_CACHE_SIZE - from, count);
	to = from + to;
	if (from < blocksize && to > PAGE_CACHE_SIZE - blocksize)
		return 0;

	bh = head;
	block_start = 0;
	do {
		block_end = block_start + blocksize;
		if (block_end > from && block_start < to) {
			if (!buffer_uptodate(bh)) {
				ret = 0;
				break;
			}
			if (block_end >= to)
				break;
		}
		block_start = block_end;
		bh = bh->b_this_page;
	} while (bh != head);

	return ret;
}
EXPORT_SYMBOL(block_is_partially_uptodate);

int block_read_full_page(struct page *page, get_block_t *get_block)
{
	struct inode *inode = page->mapping->host;
	sector_t iblock, lblock;
	struct buffer_head *bh, *head, *arr[MAX_BUF_PER_PAGE];
	unsigned int blocksize, bbits;
	int nr, i;
	int fully_mapped = 1;

	head = create_page_buffers(page, inode, 0);
	blocksize = head->b_size;
	bbits = block_size_bits(blocksize);

	iblock = (sector_t)page->index << (PAGE_CACHE_SHIFT - bbits);
	lblock = (i_size_read(inode)+blocksize-1) >> bbits;
	bh = head;
	nr = 0;
	i = 0;

	do {
		if (buffer_uptodate(bh))
			continue;

		if (!buffer_mapped(bh)) {
			int err = 0;

			fully_mapped = 0;
			if (iblock < lblock) {
				WARN_ON(bh->b_size != blocksize);
				err = get_block(inode, iblock, bh, 0);
				if (err)
					SetPageError(page);
			}
			if (!buffer_mapped(bh)) {
				zero_user(page, i * blocksize, blocksize);
				if (!err)
					set_buffer_uptodate(bh);
				continue;
			}
			 
			if (buffer_uptodate(bh))
				continue;
		}
		arr[nr++] = bh;
	} while (i++, iblock++, (bh = bh->b_this_page) != head);

	if (fully_mapped)
		SetPageMappedToDisk(page);

	if (!nr) {
		 
		if (!PageError(page))
			SetPageUptodate(page);
		unlock_page(page);
		return 0;
	}

	for (i = 0; i < nr; i++) {
		bh = arr[i];
		lock_buffer(bh);
		mark_buffer_async_read(bh);
	}

	for (i = 0; i < nr; i++) {
		bh = arr[i];
		if (buffer_uptodate(bh))
			end_buffer_async_read(bh, 1);
		else
			submit_bh(READ, bh);
	}
	return 0;
}
EXPORT_SYMBOL(block_read_full_page);

int generic_cont_expand_simple(struct inode *inode, loff_t size)
{
	struct address_space *mapping = inode->i_mapping;
	struct page *page;
	void *fsdata;
	int err;

	err = inode_newsize_ok(inode, size);
	if (err)
		goto out;

	err = pagecache_write_begin(NULL, mapping, size, 0,
				AOP_FLAG_UNINTERRUPTIBLE|AOP_FLAG_CONT_EXPAND,
				&page, &fsdata);
	if (err)
		goto out;

	err = pagecache_write_end(NULL, mapping, size, 0, 0, page, fsdata);
	BUG_ON(err > 0);

out:
	return err;
}
EXPORT_SYMBOL(generic_cont_expand_simple);

static int cont_expand_zero(struct file *file, struct address_space *mapping,
			    loff_t pos, loff_t *bytes)
{
	struct inode *inode = mapping->host;
	unsigned blocksize = 1 << inode->i_blkbits;
	struct page *page;
	void *fsdata;
	pgoff_t index, curidx;
	loff_t curpos;
	unsigned zerofrom, offset, len;
	int err = 0;

	index = pos >> PAGE_CACHE_SHIFT;
	offset = pos & ~PAGE_CACHE_MASK;

	while (index > (curidx = (curpos = *bytes)>>PAGE_CACHE_SHIFT)) {
		zerofrom = curpos & ~PAGE_CACHE_MASK;
		if (zerofrom & (blocksize-1)) {
			*bytes |= (blocksize-1);
			(*bytes)++;
		}
		len = PAGE_CACHE_SIZE - zerofrom;

		err = pagecache_write_begin(file, mapping, curpos, len,
						AOP_FLAG_UNINTERRUPTIBLE,
						&page, &fsdata);
		if (err)
			goto out;
		zero_user(page, zerofrom, len);
		err = pagecache_write_end(file, mapping, curpos, len, len,
						page, fsdata);
		if (err < 0)
			goto out;
		BUG_ON(err != len);
		err = 0;

		balance_dirty_pages_ratelimited(mapping);

		if (unlikely(fatal_signal_pending(current))) {
			err = -EINTR;
			goto out;
		}
	}

	if (index == curidx) {
		zerofrom = curpos & ~PAGE_CACHE_MASK;
		 
		if (offset <= zerofrom) {
			goto out;
		}
		if (zerofrom & (blocksize-1)) {
			*bytes |= (blocksize-1);
			(*bytes)++;
		}
		len = offset - zerofrom;

		err = pagecache_write_begin(file, mapping, curpos, len,
						AOP_FLAG_UNINTERRUPTIBLE,
						&page, &fsdata);
		if (err)
			goto out;
		zero_user(page, zerofrom, len);
		err = pagecache_write_end(file, mapping, curpos, len, len,
						page, fsdata);
		if (err < 0)
			goto out;
		BUG_ON(err != len);
		err = 0;
	}
out:
	return err;
}

int cont_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata,
			get_block_t *get_block, loff_t *bytes)
{
	struct inode *inode = mapping->host;
	unsigned blocksize = 1 << inode->i_blkbits;
	unsigned zerofrom;
	int err;

	err = cont_expand_zero(file, mapping, pos, bytes);
	if (err)
		return err;

	zerofrom = *bytes & ~PAGE_CACHE_MASK;
	if (pos+len > *bytes && zerofrom & (blocksize-1)) {
		*bytes |= (blocksize-1);
		(*bytes)++;
	}

	return block_write_begin(mapping, pos, len, flags, pagep, get_block);
}
EXPORT_SYMBOL(cont_write_begin);

int block_commit_write(struct page *page, unsigned from, unsigned to)
{
	struct inode *inode = page->mapping->host;
	__block_commit_write(inode,page,from,to);
	return 0;
}
EXPORT_SYMBOL(block_commit_write);

int block_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf,
			 get_block_t get_block)
{
	struct page *page = vmf->page;
	struct inode *inode = file_inode(vma->vm_file);
	unsigned long end;
	loff_t size;
	int ret;

	lock_page(page);
	size = i_size_read(inode);
	if ((page->mapping != inode->i_mapping) ||
	    (page_offset(page) > size)) {
		 
		ret = -EFAULT;
		goto out_unlock;
	}

	if (((page->index + 1) << PAGE_CACHE_SHIFT) > size)
		end = size & ~PAGE_CACHE_MASK;
	else
		end = PAGE_CACHE_SIZE;

	ret = __block_write_begin(page, 0, end, get_block);
	if (!ret)
		ret = block_commit_write(page, 0, end);

	if (unlikely(ret < 0))
		goto out_unlock;
	set_page_dirty(page);
	wait_for_stable_page(page);
	return 0;
out_unlock:
	unlock_page(page);
	return ret;
}
EXPORT_SYMBOL(block_page_mkwrite);

static void end_buffer_read_nobh(struct buffer_head *bh, int uptodate)
{
	__end_buffer_read_notouch(bh, uptodate);
}

static void attach_nobh_buffers(struct page *page, struct buffer_head *head)
{
	struct buffer_head *bh;

	BUG_ON(!PageLocked(page));

	spin_lock(&page->mapping->private_lock);
	bh = head;
	do {
		if (PageDirty(page))
			set_buffer_dirty(bh);
		if (!bh->b_this_page)
			bh->b_this_page = head;
		bh = bh->b_this_page;
	} while (bh != head);
	attach_page_buffers(page, head);
	spin_unlock(&page->mapping->private_lock);
}

int nobh_write_begin(struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata,
			get_block_t *get_block)
{
	struct inode *inode = mapping->host;
	const unsigned blkbits = inode->i_blkbits;
	const unsigned blocksize = 1 << blkbits;
	struct buffer_head *head, *bh;
	struct page *page;
	pgoff_t index;
	unsigned from, to;
	unsigned block_in_page;
	unsigned block_start, block_end;
	sector_t block_in_file;
	int nr_reads = 0;
	int ret = 0;
	int is_mapped_to_disk = 1;

	index = pos >> PAGE_CACHE_SHIFT;
	from = pos & (PAGE_CACHE_SIZE - 1);
	to = from + len;

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;
	*pagep = page;
	*fsdata = NULL;

	if (page_has_buffers(page)) {
		ret = __block_write_begin(page, pos, len, get_block);
		if (unlikely(ret))
			goto out_release;
		return ret;
	}

	if (PageMappedToDisk(page))
		return 0;

	head = alloc_page_buffers(page, blocksize, 0);
	if (!head) {
		ret = -ENOMEM;
		goto out_release;
	}

	block_in_file = (sector_t)page->index << (PAGE_CACHE_SHIFT - blkbits);

	for (block_start = 0, block_in_page = 0, bh = head;
		  block_start < PAGE_CACHE_SIZE;
		  block_in_page++, block_start += blocksize, bh = bh->b_this_page) {
		int create;

		block_end = block_start + blocksize;
		bh->b_state = 0;
		create = 1;
		if (block_start >= to)
			create = 0;
		ret = get_block(inode, block_in_file + block_in_page,
					bh, create);
		if (ret)
			goto failed;
		if (!buffer_mapped(bh))
			is_mapped_to_disk = 0;
		if (buffer_new(bh))
			unmap_underlying_metadata(bh->b_bdev, bh->b_blocknr);
		if (PageUptodate(page)) {
			set_buffer_uptodate(bh);
			continue;
		}
		if (buffer_new(bh) || !buffer_mapped(bh)) {
			zero_user_segments(page, block_start, from,
							to, block_end);
			continue;
		}
		if (buffer_uptodate(bh))
			continue;	 
		if (block_start < from || block_end > to) {
			lock_buffer(bh);
			bh->b_end_io = end_buffer_read_nobh;
			submit_bh(READ, bh);
			nr_reads++;
		}
	}

	if (nr_reads) {
		 
		for (bh = head; bh; bh = bh->b_this_page) {
			wait_on_buffer(bh);
			if (!buffer_uptodate(bh))
				ret = -EIO;
		}
		if (ret)
			goto failed;
	}

	if (is_mapped_to_disk)
		SetPageMappedToDisk(page);

	*fsdata = head;  

	return 0;

failed:
	BUG_ON(!ret);
	 
	attach_nobh_buffers(page, head);
	page_zero_new_buffers(page, from, to);

out_release:
	unlock_page(page);
	page_cache_release(page);
	*pagep = NULL;

	return ret;
}
EXPORT_SYMBOL(nobh_write_begin);

int nobh_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata)
{
	struct inode *inode = page->mapping->host;
	struct buffer_head *head = fsdata;
	struct buffer_head *bh;
	BUG_ON(fsdata != NULL && page_has_buffers(page));

	if (unlikely(copied < len) && head)
		attach_nobh_buffers(page, head);
	if (page_has_buffers(page))
		return generic_write_end(file, mapping, pos, len,
					copied, page, fsdata);

	SetPageUptodate(page);
	set_page_dirty(page);
	if (pos+copied > inode->i_size) {
		i_size_write(inode, pos+copied);
		mark_inode_dirty(inode);
	}

	unlock_page(page);
	page_cache_release(page);

	while (head) {
		bh = head;
		head = head->b_this_page;
		free_buffer_head(bh);
	}

	return copied;
}
EXPORT_SYMBOL(nobh_write_end);

int nobh_writepage(struct page *page, get_block_t *get_block,
			struct writeback_control *wbc)
{
	struct inode * const inode = page->mapping->host;
	loff_t i_size = i_size_read(inode);
	const pgoff_t end_index = i_size >> PAGE_CACHE_SHIFT;
	unsigned offset;
	int ret;

	if (page->index < end_index)
		goto out;

	offset = i_size & (PAGE_CACHE_SIZE-1);
	if (page->index >= end_index+1 || !offset) {
		 
#if 0
		 
		if (page->mapping->a_ops->invalidatepage)
			page->mapping->a_ops->invalidatepage(page, offset);
#endif
		unlock_page(page);
		return 0;  
	}

	zero_user_segment(page, offset, PAGE_CACHE_SIZE);
out:
	ret = mpage_writepage(page, get_block, wbc);
	if (ret == -EAGAIN)
		ret = __block_write_full_page(inode, page, get_block, wbc,
					      end_buffer_async_write);
	return ret;
}
EXPORT_SYMBOL(nobh_writepage);

int nobh_truncate_page(struct address_space *mapping,
			loff_t from, get_block_t *get_block)
{
	pgoff_t index = from >> PAGE_CACHE_SHIFT;
	unsigned offset = from & (PAGE_CACHE_SIZE-1);
	unsigned blocksize;
	sector_t iblock;
	unsigned length, pos;
	struct inode *inode = mapping->host;
	struct page *page;
	struct buffer_head map_bh;
	int err;

	blocksize = 1 << inode->i_blkbits;
	length = offset & (blocksize - 1);

	if (!length)
		return 0;

	length = blocksize - length;
	iblock = (sector_t)index << (PAGE_CACHE_SHIFT - inode->i_blkbits);

	page = grab_cache_page(mapping, index);
	err = -ENOMEM;
	if (!page)
		goto out;

	if (page_has_buffers(page)) {
has_buffers:
		unlock_page(page);
		page_cache_release(page);
		return block_truncate_page(mapping, from, get_block);
	}

	pos = blocksize;
	while (offset >= pos) {
		iblock++;
		pos += blocksize;
	}

	map_bh.b_size = blocksize;
	map_bh.b_state = 0;
	err = get_block(inode, iblock, &map_bh, 0);
	if (err)
		goto unlock;
	 
	if (!buffer_mapped(&map_bh))
		goto unlock;

	if (!PageUptodate(page)) {
		err = mapping->a_ops->readpage(NULL, page);
		if (err) {
			page_cache_release(page);
			goto out;
		}
		lock_page(page);
		if (!PageUptodate(page)) {
			err = -EIO;
			goto unlock;
		}
		if (page_has_buffers(page))
			goto has_buffers;
	}
	zero_user(page, offset, length);
	set_page_dirty(page);
	err = 0;

unlock:
	unlock_page(page);
	page_cache_release(page);
out:
	return err;
}
EXPORT_SYMBOL(nobh_truncate_page);

int block_truncate_page(struct address_space *mapping,
			loff_t from, get_block_t *get_block)
{
	pgoff_t index = from >> PAGE_CACHE_SHIFT;
	unsigned offset = from & (PAGE_CACHE_SIZE-1);
	unsigned blocksize;
	sector_t iblock;
	unsigned length, pos;
	struct inode *inode = mapping->host;
	struct page *page;
	struct buffer_head *bh;
	int err;

	blocksize = 1 << inode->i_blkbits;
	length = offset & (blocksize - 1);

	if (!length)
		return 0;

	length = blocksize - length;
	iblock = (sector_t)index << (PAGE_CACHE_SHIFT - inode->i_blkbits);
	
	page = grab_cache_page(mapping, index);
	err = -ENOMEM;
	if (!page)
		goto out;

	if (!page_has_buffers(page))
		create_empty_buffers(page, blocksize, 0);

	bh = page_buffers(page);
	pos = blocksize;
	while (offset >= pos) {
		bh = bh->b_this_page;
		iblock++;
		pos += blocksize;
	}

	err = 0;
	if (!buffer_mapped(bh)) {
		WARN_ON(bh->b_size != blocksize);
		err = get_block(inode, iblock, bh, 0);
		if (err)
			goto unlock;
		 
		if (!buffer_mapped(bh))
			goto unlock;
	}

	if (PageUptodate(page))
		set_buffer_uptodate(bh);

	if (!buffer_uptodate(bh) && !buffer_delay(bh) && !buffer_unwritten(bh)) {
		err = -EIO;
		ll_rw_block(READ, 1, &bh);
		wait_on_buffer(bh);
		 
		if (!buffer_uptodate(bh))
			goto unlock;
	}

	zero_user(page, offset, length);
	mark_buffer_dirty(bh);
	err = 0;

unlock:
	unlock_page(page);
	page_cache_release(page);
out:
	return err;
}
EXPORT_SYMBOL(block_truncate_page);

int block_write_full_page(struct page *page, get_block_t *get_block,
			struct writeback_control *wbc)
{
	struct inode * const inode = page->mapping->host;
	loff_t i_size = i_size_read(inode);
	const pgoff_t end_index = i_size >> PAGE_CACHE_SHIFT;
	unsigned offset;

	if (page->index < end_index)
		return __block_write_full_page(inode, page, get_block, wbc,
					       end_buffer_async_write);

	offset = i_size & (PAGE_CACHE_SIZE-1);
	if (page->index >= end_index+1 || !offset) {
		 
		do_invalidatepage(page, 0, PAGE_CACHE_SIZE);
		unlock_page(page);
		return 0;  
	}

	zero_user_segment(page, offset, PAGE_CACHE_SIZE);
	return __block_write_full_page(inode, page, get_block, wbc,
							end_buffer_async_write);
}
EXPORT_SYMBOL(block_write_full_page);

sector_t generic_block_bmap(struct address_space *mapping, sector_t block,
			    get_block_t *get_block)
{
	struct buffer_head tmp;
	struct inode *inode = mapping->host;
	tmp.b_state = 0;
	tmp.b_blocknr = 0;
	tmp.b_size = 1 << inode->i_blkbits;
	get_block(inode, block, &tmp, 0);
	return tmp.b_blocknr;
}
EXPORT_SYMBOL(generic_block_bmap);

static void end_bio_bh_io_sync(struct bio *bio)
{
	struct buffer_head *bh = bio->bi_private;

	if (unlikely(bio_flagged(bio, BIO_QUIET)))
		set_bit(BH_Quiet, &bh->b_state);

	bh->b_end_io(bh, !bio->bi_error);
	bio_put(bio);
}

void guard_bio_eod(int rw, struct bio *bio)
{
	sector_t maxsector;
	struct bio_vec *bvec = &bio->bi_io_vec[bio->bi_vcnt - 1];
	unsigned truncated_bytes;

	maxsector = i_size_read(bio->bi_bdev->bd_inode) >> 9;
	if (!maxsector)
		return;

	if (unlikely(bio->bi_iter.bi_sector >= maxsector))
		return;

	maxsector -= bio->bi_iter.bi_sector;
	if (likely((bio->bi_iter.bi_size >> 9) <= maxsector))
		return;

	truncated_bytes = bio->bi_iter.bi_size - (maxsector << 9);

	bio->bi_iter.bi_size -= truncated_bytes;
	bvec->bv_len -= truncated_bytes;

	if ((rw & RW_MASK) == READ) {
		zero_user(bvec->bv_page, bvec->bv_offset + bvec->bv_len,
				truncated_bytes);
	}
}

static int submit_bh_wbc(int rw, struct buffer_head *bh,
			 unsigned long bio_flags, struct writeback_control *wbc)
{
	struct bio *bio;

	BUG_ON(!buffer_locked(bh));
	BUG_ON(!buffer_mapped(bh));
	BUG_ON(!bh->b_end_io);
	BUG_ON(buffer_delay(bh));
	BUG_ON(buffer_unwritten(bh));

	if (test_set_buffer_req(bh) && (rw & WRITE))
		clear_buffer_write_io_error(bh);

	bio = bio_alloc(GFP_NOIO, 1);

	if (wbc) {
		wbc_init_bio(wbc, bio);
		wbc_account_io(wbc, bh->b_page, bh->b_size);
	}

	bio->bi_iter.bi_sector = bh->b_blocknr * (bh->b_size >> 9);
	bio->bi_bdev = bh->b_bdev;

	bio_add_page(bio, bh->b_page, bh->b_size, bh_offset(bh));
	BUG_ON(bio->bi_iter.bi_size != bh->b_size);

	bio->bi_end_io = end_bio_bh_io_sync;
	bio->bi_private = bh;
	bio->bi_flags |= bio_flags;

	guard_bio_eod(rw, bio);

	if (buffer_meta(bh))
		rw |= REQ_META;
	if (buffer_prio(bh))
		rw |= REQ_PRIO;

	submit_bio(rw, bio);
	return 0;
}

int _submit_bh(int rw, struct buffer_head *bh, unsigned long bio_flags)
{
	return submit_bh_wbc(rw, bh, bio_flags, NULL);
}
EXPORT_SYMBOL_GPL(_submit_bh);

int submit_bh(int rw, struct buffer_head *bh)
{
	return submit_bh_wbc(rw, bh, 0, NULL);
}
EXPORT_SYMBOL(submit_bh);

void ll_rw_block(int rw, int nr, struct buffer_head *bhs[])
{
	int i;

	for (i = 0; i < nr; i++) {
		struct buffer_head *bh = bhs[i];

		if (!trylock_buffer(bh))
			continue;
		if (rw == WRITE) {
			if (test_clear_buffer_dirty(bh)) {
				bh->b_end_io = end_buffer_write_sync;
				get_bh(bh);
				submit_bh(WRITE, bh);
				continue;
			}
		} else {
			if (!buffer_uptodate(bh)) {
				bh->b_end_io = end_buffer_read_sync;
				get_bh(bh);
				submit_bh(rw, bh);
				continue;
			}
		}
		unlock_buffer(bh);
	}
}
EXPORT_SYMBOL(ll_rw_block);

void write_dirty_buffer(struct buffer_head *bh, int rw)
{
	lock_buffer(bh);
	if (!test_clear_buffer_dirty(bh)) {
		unlock_buffer(bh);
		return;
	}
	bh->b_end_io = end_buffer_write_sync;
	get_bh(bh);
	submit_bh(rw, bh);
}
EXPORT_SYMBOL(write_dirty_buffer);

int __sync_dirty_buffer(struct buffer_head *bh, int rw)
{
	int ret = 0;

	WARN_ON(atomic_read(&bh->b_count) < 1);
	lock_buffer(bh);
	if (test_clear_buffer_dirty(bh)) {
		get_bh(bh);
		bh->b_end_io = end_buffer_write_sync;
		ret = submit_bh(rw, bh);
		wait_on_buffer(bh);
		if (!ret && !buffer_uptodate(bh))
			ret = -EIO;
	} else {
		unlock_buffer(bh);
	}
	return ret;
}
EXPORT_SYMBOL(__sync_dirty_buffer);

int sync_dirty_buffer(struct buffer_head *bh)
{
	return __sync_dirty_buffer(bh, WRITE_SYNC);
}
EXPORT_SYMBOL(sync_dirty_buffer);

static inline int buffer_busy(struct buffer_head *bh)
{
	return atomic_read(&bh->b_count) |
		(bh->b_state & ((1 << BH_Dirty) | (1 << BH_Lock)));
}

static int
drop_buffers(struct page *page, struct buffer_head **buffers_to_free)
{
	struct buffer_head *head = page_buffers(page);
	struct buffer_head *bh;

	bh = head;
	do {
		if (buffer_write_io_error(bh) && page->mapping)
			set_bit(AS_EIO, &page->mapping->flags);
		if (buffer_busy(bh))
			goto failed;
		bh = bh->b_this_page;
	} while (bh != head);

	do {
		struct buffer_head *next = bh->b_this_page;

		if (bh->b_assoc_map)
			__remove_assoc_queue(bh);
		bh = next;
	} while (bh != head);
	*buffers_to_free = head;
	__clear_page_buffers(page);
	return 1;
failed:
	return 0;
}

int try_to_free_buffers(struct page *page)
{
	struct address_space * const mapping = page->mapping;
	struct buffer_head *buffers_to_free = NULL;
	int ret = 0;

	BUG_ON(!PageLocked(page));
	if (PageWriteback(page))
		return 0;

	if (mapping == NULL) {		 
		ret = drop_buffers(page, &buffers_to_free);
		goto out;
	}

	spin_lock(&mapping->private_lock);
	ret = drop_buffers(page, &buffers_to_free);

	if (ret)
		cancel_dirty_page(page);
	spin_unlock(&mapping->private_lock);
out:
	if (buffers_to_free) {
		struct buffer_head *bh = buffers_to_free;

		do {
			struct buffer_head *next = bh->b_this_page;
			free_buffer_head(bh);
			bh = next;
		} while (bh != buffers_to_free);
	}
	return ret;
}
EXPORT_SYMBOL(try_to_free_buffers);

SYSCALL_DEFINE2(bdflush, int, func, long, data)
{
	static int msg_count;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (msg_count < 5) {
		msg_count++;
		printk(KERN_INFO
			"warning: process `%s' used the obsolete bdflush"
			" system call\n", current->comm);
		printk(KERN_INFO "Fix your initscripts?\n");
	}

	if (func == 1)
		do_exit(0);
	return 0;
}

static struct kmem_cache *bh_cachep __read_mostly;

static unsigned long max_buffer_heads;

int buffer_heads_over_limit;

struct bh_accounting {
	int nr;			 
	int ratelimit;		 
};

static DEFINE_PER_CPU(struct bh_accounting, bh_accounting) = {0, 0};

static void recalc_bh_state(void)
{
	int i;
	int tot = 0;

	if (__this_cpu_inc_return(bh_accounting.ratelimit) - 1 < 4096)
		return;
	__this_cpu_write(bh_accounting.ratelimit, 0);
	for_each_online_cpu(i)
		tot += per_cpu(bh_accounting, i).nr;
	buffer_heads_over_limit = (tot > max_buffer_heads);
}

struct buffer_head *alloc_buffer_head(gfp_t gfp_flags)
{
	struct buffer_head *ret = kmem_cache_zalloc(bh_cachep, gfp_flags);
	if (ret) {
		INIT_LIST_HEAD(&ret->b_assoc_buffers);
		preempt_disable();
		__this_cpu_inc(bh_accounting.nr);
		recalc_bh_state();
		preempt_enable();
	}
	return ret;
}
EXPORT_SYMBOL(alloc_buffer_head);

void free_buffer_head(struct buffer_head *bh)
{
	BUG_ON(!list_empty(&bh->b_assoc_buffers));
	kmem_cache_free(bh_cachep, bh);
	preempt_disable();
	__this_cpu_dec(bh_accounting.nr);
	recalc_bh_state();
	preempt_enable();
}
EXPORT_SYMBOL(free_buffer_head);

static void buffer_exit_cpu(int cpu)
{
	int i;
	struct bh_lru *b = &per_cpu(bh_lrus, cpu);

	for (i = 0; i < BH_LRU_SIZE; i++) {
		brelse(b->bhs[i]);
		b->bhs[i] = NULL;
	}
	this_cpu_add(bh_accounting.nr, per_cpu(bh_accounting, cpu).nr);
	per_cpu(bh_accounting, cpu).nr = 0;
}

static int buffer_cpu_notify(struct notifier_block *self,
			      unsigned long action, void *hcpu)
{
	if (action == CPU_DEAD || action == CPU_DEAD_FROZEN)
		buffer_exit_cpu((unsigned long)hcpu);
	return NOTIFY_OK;
}

int bh_uptodate_or_lock(struct buffer_head *bh)
{
	if (!buffer_uptodate(bh)) {
		lock_buffer(bh);
		if (!buffer_uptodate(bh))
			return 0;
		unlock_buffer(bh);
	}
	return 1;
}
EXPORT_SYMBOL(bh_uptodate_or_lock);

int bh_submit_read(struct buffer_head *bh)
{
	BUG_ON(!buffer_locked(bh));

	if (buffer_uptodate(bh)) {
		unlock_buffer(bh);
		return 0;
	}

	get_bh(bh);
	bh->b_end_io = end_buffer_read_sync;
	submit_bh(READ, bh);
	wait_on_buffer(bh);
	if (buffer_uptodate(bh))
		return 0;
	return -EIO;
}
EXPORT_SYMBOL(bh_submit_read);

void __init buffer_init(void)
{
	unsigned long nrpages;

	bh_cachep = kmem_cache_create("buffer_head",
			sizeof(struct buffer_head), 0,
				(SLAB_RECLAIM_ACCOUNT|SLAB_PANIC|
				SLAB_MEM_SPREAD),
				NULL);

	nrpages = (nr_free_buffer_pages() * 10) / 100;
	max_buffer_heads = nrpages * (PAGE_SIZE / sizeof(struct buffer_head));
	hotcpu_notifier(buffer_cpu_notify, 0);
}
