#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/export.h>
#include <linux/compiler.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/kernel_stat.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/hash.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>
#include <linux/security.h>
#include <linux/cpuset.h>
#include <linux/hardirq.h>  
#include <linux/hugetlb.h>
#include <linux/memcontrol.h>
#include <linux/cleancache.h>
#include <linux/rmap.h>
#include "internal.h"

#define CREATE_TRACE_POINTS
#include <trace/events/filemap.h>

#include <linux/buffer_head.h>  

#include <asm/mman.h>

#ifdef MY_ABC_HERE
#include <linux/tcp.h>
#include <net/tcp.h>
#endif  

static int page_cache_tree_insert(struct address_space *mapping,
				  struct page *page, void **shadowp)
{
	struct radix_tree_node *node;
	void **slot;
	int error;

	error = __radix_tree_create(&mapping->page_tree, page->index,
				    &node, &slot);
	if (error)
		return error;
	if (*slot) {
		void *p;

		p = radix_tree_deref_slot_protected(slot, &mapping->tree_lock);
		if (!radix_tree_exceptional_entry(p))
			return -EEXIST;
		if (shadowp)
			*shadowp = p;
		mapping->nrshadows--;
		if (node)
			workingset_node_shadows_dec(node);
	}
	radix_tree_replace_slot(slot, page);
	mapping->nrpages++;
	if (node) {
		workingset_node_pages_inc(node);
		 
		if (!list_empty(&node->private_list))
			list_lru_del(&workingset_shadow_nodes,
				     &node->private_list);
	}
	return 0;
}

static void page_cache_tree_delete(struct address_space *mapping,
				   struct page *page, void *shadow)
{
	struct radix_tree_node *node;
	unsigned long index;
	unsigned int offset;
	unsigned int tag;
	void **slot;

	VM_BUG_ON(!PageLocked(page));

	__radix_tree_lookup(&mapping->page_tree, page->index, &node, &slot);

	if (!node) {
		 
		shadow = NULL;
	}

	if (shadow) {
		mapping->nrshadows++;
		 
		smp_wmb();
	}
	mapping->nrpages--;

	if (!node) {
		 
		mapping->page_tree.gfp_mask &= __GFP_BITS_MASK;
		radix_tree_replace_slot(slot, shadow);
		return;
	}

	index = page->index;
	offset = index & RADIX_TREE_MAP_MASK;
	for (tag = 0; tag < RADIX_TREE_MAX_TAGS; tag++) {
		if (test_bit(offset, node->tags[tag]))
			radix_tree_tag_clear(&mapping->page_tree, index, tag);
	}

	radix_tree_replace_slot(slot, shadow);
	workingset_node_pages_dec(node);
	if (shadow)
		workingset_node_shadows_inc(node);
	else
		if (__radix_tree_delete_node(&mapping->page_tree, node))
			return;

	if (!workingset_node_pages(node) &&
	    list_empty(&node->private_list)) {
		node->private_data = mapping;
		list_lru_add(&workingset_shadow_nodes, &node->private_list);
	}
}

void __delete_from_page_cache(struct page *page, void *shadow,
			      struct mem_cgroup *memcg)
{
	struct address_space *mapping = page->mapping;

	trace_mm_filemap_delete_from_page_cache(page);
	 
	if (PageUptodate(page) && PageMappedToDisk(page))
		cleancache_put_page(page);
	else
		cleancache_invalidate_page(mapping, page);

	page_cache_tree_delete(mapping, page, shadow);

	page->mapping = NULL;
	 
	if (!PageHuge(page))
		__dec_zone_page_state(page, NR_FILE_PAGES);
	if (PageSwapBacked(page))
		__dec_zone_page_state(page, NR_SHMEM);
	BUG_ON(page_mapped(page));

	if (WARN_ON_ONCE(PageDirty(page)))
		account_page_cleaned(page, mapping, memcg,
				     inode_to_wb(mapping->host));
}

void delete_from_page_cache(struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct mem_cgroup *memcg;
	unsigned long flags;

	void (*freepage)(struct page *);

	BUG_ON(!PageLocked(page));

	freepage = mapping->a_ops->freepage;

	memcg = mem_cgroup_begin_page_stat(page);
	spin_lock_irqsave(&mapping->tree_lock, flags);
	__delete_from_page_cache(page, NULL, memcg);
	spin_unlock_irqrestore(&mapping->tree_lock, flags);
	mem_cgroup_end_page_stat(memcg);

	if (freepage)
		freepage(page);
	page_cache_release(page);
}
EXPORT_SYMBOL(delete_from_page_cache);

static int filemap_check_errors(struct address_space *mapping)
{
	int ret = 0;
	 
	if (test_bit(AS_ENOSPC, &mapping->flags) &&
	    test_and_clear_bit(AS_ENOSPC, &mapping->flags))
		ret = -ENOSPC;
	if (test_bit(AS_EIO, &mapping->flags) &&
	    test_and_clear_bit(AS_EIO, &mapping->flags))
		ret = -EIO;
	return ret;
}

int __filemap_fdatawrite_range(struct address_space *mapping, loff_t start,
				loff_t end, int sync_mode)
{
	int ret;
	struct writeback_control wbc = {
		.sync_mode = sync_mode,
		.nr_to_write = LONG_MAX,
		.range_start = start,
		.range_end = end,
	};

	if (!mapping_cap_writeback_dirty(mapping))
		return 0;

	wbc_attach_fdatawrite_inode(&wbc, mapping->host);
	ret = do_writepages(mapping, &wbc);
	wbc_detach_inode(&wbc);
	return ret;
}

static inline int __filemap_fdatawrite(struct address_space *mapping,
	int sync_mode)
{
	return __filemap_fdatawrite_range(mapping, 0, LLONG_MAX, sync_mode);
}

int filemap_fdatawrite(struct address_space *mapping)
{
	return __filemap_fdatawrite(mapping, WB_SYNC_ALL);
}
EXPORT_SYMBOL(filemap_fdatawrite);

int filemap_fdatawrite_range(struct address_space *mapping, loff_t start,
				loff_t end)
{
	return __filemap_fdatawrite_range(mapping, start, end, WB_SYNC_ALL);
}
EXPORT_SYMBOL(filemap_fdatawrite_range);

int filemap_flush(struct address_space *mapping)
{
	return __filemap_fdatawrite(mapping, WB_SYNC_NONE);
}
EXPORT_SYMBOL(filemap_flush);

static int __filemap_fdatawait_range(struct address_space *mapping,
				     loff_t start_byte, loff_t end_byte)
{
	pgoff_t index = start_byte >> PAGE_CACHE_SHIFT;
	pgoff_t end = end_byte >> PAGE_CACHE_SHIFT;
	struct pagevec pvec;
	int nr_pages;
	int ret = 0;

	if (end_byte < start_byte)
		goto out;

	pagevec_init(&pvec, 0);
	while ((index <= end) &&
			(nr_pages = pagevec_lookup_tag(&pvec, mapping, &index,
			PAGECACHE_TAG_WRITEBACK,
			min(end - index, (pgoff_t)PAGEVEC_SIZE-1) + 1)) != 0) {
		unsigned i;

		for (i = 0; i < nr_pages; i++) {
			struct page *page = pvec.pages[i];

			if (page->index > end)
				continue;

			wait_on_page_writeback(page);
			if (TestClearPageError(page))
				ret = -EIO;
		}
		pagevec_release(&pvec);
		cond_resched();
	}
out:
	return ret;
}

int filemap_fdatawait_range(struct address_space *mapping, loff_t start_byte,
			    loff_t end_byte)
{
	int ret, ret2;

	ret = __filemap_fdatawait_range(mapping, start_byte, end_byte);
	ret2 = filemap_check_errors(mapping);
	if (!ret)
		ret = ret2;

	return ret;
}
EXPORT_SYMBOL(filemap_fdatawait_range);

void filemap_fdatawait_keep_errors(struct address_space *mapping)
{
	loff_t i_size = i_size_read(mapping->host);

	if (i_size == 0)
		return;

	__filemap_fdatawait_range(mapping, 0, i_size - 1);
}

int filemap_fdatawait(struct address_space *mapping)
{
	loff_t i_size = i_size_read(mapping->host);

	if (i_size == 0)
		return 0;

	return filemap_fdatawait_range(mapping, 0, i_size - 1);
}
EXPORT_SYMBOL(filemap_fdatawait);

int filemap_write_and_wait(struct address_space *mapping)
{
	int err = 0;

	if (mapping->nrpages) {
		err = filemap_fdatawrite(mapping);
		 
		if (err != -EIO) {
			int err2 = filemap_fdatawait(mapping);
			if (!err)
				err = err2;
		}
	} else {
		err = filemap_check_errors(mapping);
	}
	return err;
}
EXPORT_SYMBOL(filemap_write_and_wait);

int filemap_write_and_wait_range(struct address_space *mapping,
				 loff_t lstart, loff_t lend)
{
	int err = 0;

	if (mapping->nrpages) {
		err = __filemap_fdatawrite_range(mapping, lstart, lend,
						 WB_SYNC_ALL);
		 
		if (err != -EIO) {
			int err2 = filemap_fdatawait_range(mapping,
						lstart, lend);
			if (!err)
				err = err2;
		}
	} else {
		err = filemap_check_errors(mapping);
	}
	return err;
}
EXPORT_SYMBOL(filemap_write_and_wait_range);

int replace_page_cache_page(struct page *old, struct page *new, gfp_t gfp_mask)
{
	int error;

	VM_BUG_ON_PAGE(!PageLocked(old), old);
	VM_BUG_ON_PAGE(!PageLocked(new), new);
	VM_BUG_ON_PAGE(new->mapping, new);

	error = radix_tree_preload(gfp_mask & ~__GFP_HIGHMEM);
	if (!error) {
		struct address_space *mapping = old->mapping;
		void (*freepage)(struct page *);
		struct mem_cgroup *memcg;
		unsigned long flags;

		pgoff_t offset = old->index;
		freepage = mapping->a_ops->freepage;

		page_cache_get(new);
		new->mapping = mapping;
		new->index = offset;

		memcg = mem_cgroup_begin_page_stat(old);
		spin_lock_irqsave(&mapping->tree_lock, flags);
		__delete_from_page_cache(old, NULL, memcg);
		error = page_cache_tree_insert(mapping, new, NULL);
		BUG_ON(error);

		if (!PageHuge(new))
			__inc_zone_page_state(new, NR_FILE_PAGES);
		if (PageSwapBacked(new))
			__inc_zone_page_state(new, NR_SHMEM);
		spin_unlock_irqrestore(&mapping->tree_lock, flags);
		mem_cgroup_end_page_stat(memcg);
		mem_cgroup_replace_page(old, new);
		radix_tree_preload_end();
		if (freepage)
			freepage(old);
		page_cache_release(old);
	}

	return error;
}
EXPORT_SYMBOL_GPL(replace_page_cache_page);

static int __add_to_page_cache_locked(struct page *page,
				      struct address_space *mapping,
				      pgoff_t offset, gfp_t gfp_mask,
				      void **shadowp)
{
	int huge = PageHuge(page);
	struct mem_cgroup *memcg;
	int error;

	VM_BUG_ON_PAGE(!PageLocked(page), page);
	VM_BUG_ON_PAGE(PageSwapBacked(page), page);

	if (!huge) {
		error = mem_cgroup_try_charge(page, current->mm,
					      gfp_mask, &memcg);
		if (error)
			return error;
	}

	error = radix_tree_maybe_preload(gfp_mask & ~__GFP_HIGHMEM);
	if (error) {
		if (!huge)
			mem_cgroup_cancel_charge(page, memcg);
		return error;
	}

	page_cache_get(page);
	page->mapping = mapping;
	page->index = offset;

	spin_lock_irq(&mapping->tree_lock);
	error = page_cache_tree_insert(mapping, page, shadowp);
	radix_tree_preload_end();
	if (unlikely(error))
		goto err_insert;

	if (!huge)
		__inc_zone_page_state(page, NR_FILE_PAGES);
	spin_unlock_irq(&mapping->tree_lock);
	if (!huge)
		mem_cgroup_commit_charge(page, memcg, false);
	trace_mm_filemap_add_to_page_cache(page);
	return 0;
err_insert:
	page->mapping = NULL;
	 
	spin_unlock_irq(&mapping->tree_lock);
	if (!huge)
		mem_cgroup_cancel_charge(page, memcg);
	page_cache_release(page);
	return error;
}

int add_to_page_cache_locked(struct page *page, struct address_space *mapping,
		pgoff_t offset, gfp_t gfp_mask)
{
	return __add_to_page_cache_locked(page, mapping, offset,
					  gfp_mask, NULL);
}
EXPORT_SYMBOL(add_to_page_cache_locked);

int add_to_page_cache_lru(struct page *page, struct address_space *mapping,
				pgoff_t offset, gfp_t gfp_mask)
{
	void *shadow = NULL;
	int ret;

	__set_page_locked(page);
	ret = __add_to_page_cache_locked(page, mapping, offset,
					 gfp_mask, &shadow);
	if (unlikely(ret))
		__clear_page_locked(page);
	else {
		 
		if (shadow && workingset_refault(shadow)) {
			SetPageActive(page);
			workingset_activation(page);
		} else
			ClearPageActive(page);
		lru_cache_add(page);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(add_to_page_cache_lru);

#ifdef CONFIG_NUMA
struct page *__page_cache_alloc(gfp_t gfp)
{
	int n;
	struct page *page;

	if (cpuset_do_page_mem_spread()) {
		unsigned int cpuset_mems_cookie;
		do {
			cpuset_mems_cookie = read_mems_allowed_begin();
			n = cpuset_mem_spread_node();
			page = __alloc_pages_node(n, gfp, 0);
		} while (!page && read_mems_allowed_retry(cpuset_mems_cookie));

		return page;
	}
	return alloc_pages(gfp, 0);
}
EXPORT_SYMBOL(__page_cache_alloc);
#endif

wait_queue_head_t *page_waitqueue(struct page *page)
{
	const struct zone *zone = page_zone(page);

	return &zone->wait_table[hash_ptr(page, zone->wait_table_bits)];
}
EXPORT_SYMBOL(page_waitqueue);

void wait_on_page_bit(struct page *page, int bit_nr)
{
	DEFINE_WAIT_BIT(wait, &page->flags, bit_nr);

	if (test_bit(bit_nr, &page->flags))
		__wait_on_bit(page_waitqueue(page), &wait, bit_wait_io,
							TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(wait_on_page_bit);

int wait_on_page_bit_killable(struct page *page, int bit_nr)
{
	DEFINE_WAIT_BIT(wait, &page->flags, bit_nr);

	if (!test_bit(bit_nr, &page->flags))
		return 0;

	return __wait_on_bit(page_waitqueue(page), &wait,
			     bit_wait_io, TASK_KILLABLE);
}

int wait_on_page_bit_killable_timeout(struct page *page,
				       int bit_nr, unsigned long timeout)
{
	DEFINE_WAIT_BIT(wait, &page->flags, bit_nr);

	wait.key.timeout = jiffies + timeout;
	if (!test_bit(bit_nr, &page->flags))
		return 0;
	return __wait_on_bit(page_waitqueue(page), &wait,
			     bit_wait_io_timeout, TASK_KILLABLE);
}
EXPORT_SYMBOL_GPL(wait_on_page_bit_killable_timeout);

void add_page_wait_queue(struct page *page, wait_queue_t *waiter)
{
	wait_queue_head_t *q = page_waitqueue(page);
	unsigned long flags;

	spin_lock_irqsave(&q->lock, flags);
	__add_wait_queue(q, waiter);
	spin_unlock_irqrestore(&q->lock, flags);
}
EXPORT_SYMBOL_GPL(add_page_wait_queue);

void unlock_page(struct page *page)
{
	VM_BUG_ON_PAGE(!PageLocked(page), page);
	clear_bit_unlock(PG_locked, &page->flags);
	smp_mb__after_atomic();
	wake_up_page(page, PG_locked);
}
EXPORT_SYMBOL(unlock_page);

void end_page_writeback(struct page *page)
{
	 
	if (PageReclaim(page)) {
		ClearPageReclaim(page);
		rotate_reclaimable_page(page);
	}

	if (!test_clear_page_writeback(page))
		BUG();

	smp_mb__after_atomic();
	wake_up_page(page, PG_writeback);
}
EXPORT_SYMBOL(end_page_writeback);

void page_endio(struct page *page, int rw, int err)
{
	if (rw == READ) {
		if (!err) {
			SetPageUptodate(page);
		} else {
			ClearPageUptodate(page);
			SetPageError(page);
		}
		unlock_page(page);
	} else {  
		if (err) {
			struct address_space *mapping;

			SetPageError(page);
			mapping = page_mapping(page);
			if (mapping)
				mapping_set_error(mapping, err);
		}
		end_page_writeback(page);
	}
}
EXPORT_SYMBOL_GPL(page_endio);

void __lock_page(struct page *page)
{
	DEFINE_WAIT_BIT(wait, &page->flags, PG_locked);

	__wait_on_bit_lock(page_waitqueue(page), &wait, bit_wait_io,
							TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(__lock_page);

int __lock_page_killable(struct page *page)
{
	DEFINE_WAIT_BIT(wait, &page->flags, PG_locked);

	return __wait_on_bit_lock(page_waitqueue(page), &wait,
					bit_wait_io, TASK_KILLABLE);
}
EXPORT_SYMBOL_GPL(__lock_page_killable);

int __lock_page_or_retry(struct page *page, struct mm_struct *mm,
			 unsigned int flags)
{
	if (flags & FAULT_FLAG_ALLOW_RETRY) {
		 
		if (flags & FAULT_FLAG_RETRY_NOWAIT)
			return 0;

		up_read(&mm->mmap_sem);
		if (flags & FAULT_FLAG_KILLABLE)
			wait_on_page_locked_killable(page);
		else
			wait_on_page_locked(page);
		return 0;
	} else {
		if (flags & FAULT_FLAG_KILLABLE) {
			int ret;

			ret = __lock_page_killable(page);
			if (ret) {
				up_read(&mm->mmap_sem);
				return 0;
			}
		} else
			__lock_page(page);
		return 1;
	}
}

pgoff_t page_cache_next_hole(struct address_space *mapping,
			     pgoff_t index, unsigned long max_scan)
{
	unsigned long i;

	for (i = 0; i < max_scan; i++) {
		struct page *page;

		page = radix_tree_lookup(&mapping->page_tree, index);
		if (!page || radix_tree_exceptional_entry(page))
			break;
		index++;
		if (index == 0)
			break;
	}

	return index;
}
EXPORT_SYMBOL(page_cache_next_hole);

pgoff_t page_cache_prev_hole(struct address_space *mapping,
			     pgoff_t index, unsigned long max_scan)
{
	unsigned long i;

	for (i = 0; i < max_scan; i++) {
		struct page *page;

		page = radix_tree_lookup(&mapping->page_tree, index);
		if (!page || radix_tree_exceptional_entry(page))
			break;
		index--;
		if (index == ULONG_MAX)
			break;
	}

	return index;
}
EXPORT_SYMBOL(page_cache_prev_hole);

struct page *find_get_entry(struct address_space *mapping, pgoff_t offset)
{
	void **pagep;
	struct page *page;

	rcu_read_lock();
repeat:
	page = NULL;
	pagep = radix_tree_lookup_slot(&mapping->page_tree, offset);
	if (pagep) {
		page = radix_tree_deref_slot(pagep);
		if (unlikely(!page))
			goto out;
		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page))
				goto repeat;
			 
			goto out;
		}
		if (!page_cache_get_speculative(page))
			goto repeat;

		if (unlikely(page != *pagep)) {
			page_cache_release(page);
			goto repeat;
		}
	}
out:
	rcu_read_unlock();

	return page;
}
EXPORT_SYMBOL(find_get_entry);

struct page *find_lock_entry(struct address_space *mapping, pgoff_t offset)
{
	struct page *page;

repeat:
	page = find_get_entry(mapping, offset);
	if (page && !radix_tree_exception(page)) {
		lock_page(page);
		 
		if (unlikely(page->mapping != mapping)) {
			unlock_page(page);
			page_cache_release(page);
			goto repeat;
		}
		VM_BUG_ON_PAGE(page->index != offset, page);
	}
	return page;
}
EXPORT_SYMBOL(find_lock_entry);

struct page *pagecache_get_page(struct address_space *mapping, pgoff_t offset,
	int fgp_flags, gfp_t gfp_mask)
{
	struct page *page;

repeat:
	page = find_get_entry(mapping, offset);
	if (radix_tree_exceptional_entry(page))
		page = NULL;
	if (!page)
		goto no_page;

	if (fgp_flags & FGP_LOCK) {
		if (fgp_flags & FGP_NOWAIT) {
			if (!trylock_page(page)) {
				page_cache_release(page);
				return NULL;
			}
		} else {
			lock_page(page);
		}

		if (unlikely(page->mapping != mapping)) {
			unlock_page(page);
			page_cache_release(page);
			goto repeat;
		}
		VM_BUG_ON_PAGE(page->index != offset, page);
	}

	if (page && (fgp_flags & FGP_ACCESSED))
		mark_page_accessed(page);

no_page:
	if (!page && (fgp_flags & FGP_CREAT)) {
		int err;
		if ((fgp_flags & FGP_WRITE) && mapping_cap_account_dirty(mapping))
			gfp_mask |= __GFP_WRITE;
		if (fgp_flags & FGP_NOFS)
			gfp_mask &= ~__GFP_FS;

		page = __page_cache_alloc(gfp_mask);
		if (!page)
			return NULL;

		if (WARN_ON_ONCE(!(fgp_flags & FGP_LOCK)))
			fgp_flags |= FGP_LOCK;

		if (fgp_flags & FGP_ACCESSED)
			__SetPageReferenced(page);

		err = add_to_page_cache_lru(page, mapping, offset,
				gfp_mask & GFP_RECLAIM_MASK);
		if (unlikely(err)) {
			page_cache_release(page);
			page = NULL;
			if (err == -EEXIST)
				goto repeat;
		}
	}

	return page;
}
EXPORT_SYMBOL(pagecache_get_page);

unsigned find_get_entries(struct address_space *mapping,
			  pgoff_t start, unsigned int nr_entries,
			  struct page **entries, pgoff_t *indices)
{
	void **slot;
	unsigned int ret = 0;
	struct radix_tree_iter iter;

	if (!nr_entries)
		return 0;

	rcu_read_lock();
restart:
	radix_tree_for_each_slot(slot, &mapping->page_tree, &iter, start) {
		struct page *page;
repeat:
		page = radix_tree_deref_slot(slot);
		if (unlikely(!page))
			continue;
		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page))
				goto restart;
			 
			goto export;
		}
		if (!page_cache_get_speculative(page))
			goto repeat;

		if (unlikely(page != *slot)) {
			page_cache_release(page);
			goto repeat;
		}
export:
		indices[ret] = iter.index;
		entries[ret] = page;
		if (++ret == nr_entries)
			break;
	}
	rcu_read_unlock();
	return ret;
}

unsigned find_get_pages(struct address_space *mapping, pgoff_t start,
			    unsigned int nr_pages, struct page **pages)
{
	struct radix_tree_iter iter;
	void **slot;
	unsigned ret = 0;

	if (unlikely(!nr_pages))
		return 0;

	rcu_read_lock();
restart:
	radix_tree_for_each_slot(slot, &mapping->page_tree, &iter, start) {
		struct page *page;
repeat:
		page = radix_tree_deref_slot(slot);
		if (unlikely(!page))
			continue;

		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page)) {
				 
				WARN_ON(iter.index);
				goto restart;
			}
			 
			continue;
		}

		if (!page_cache_get_speculative(page))
			goto repeat;

		if (unlikely(page != *slot)) {
			page_cache_release(page);
			goto repeat;
		}

		pages[ret] = page;
		if (++ret == nr_pages)
			break;
	}

	rcu_read_unlock();
	return ret;
}

unsigned find_get_pages_contig(struct address_space *mapping, pgoff_t index,
			       unsigned int nr_pages, struct page **pages)
{
	struct radix_tree_iter iter;
	void **slot;
	unsigned int ret = 0;

	if (unlikely(!nr_pages))
		return 0;

	rcu_read_lock();
restart:
	radix_tree_for_each_contig(slot, &mapping->page_tree, &iter, index) {
		struct page *page;
repeat:
		page = radix_tree_deref_slot(slot);
		 
		if (unlikely(!page))
			break;

		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page)) {
				 
				goto restart;
			}
			 
			break;
		}

		if (!page_cache_get_speculative(page))
			goto repeat;

		if (unlikely(page != *slot)) {
			page_cache_release(page);
			goto repeat;
		}

		if (page->mapping == NULL || page->index != iter.index) {
			page_cache_release(page);
			break;
		}

		pages[ret] = page;
		if (++ret == nr_pages)
			break;
	}
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL(find_get_pages_contig);

unsigned find_get_pages_tag(struct address_space *mapping, pgoff_t *index,
			int tag, unsigned int nr_pages, struct page **pages)
{
	struct radix_tree_iter iter;
	void **slot;
	unsigned ret = 0;

	if (unlikely(!nr_pages))
		return 0;

	rcu_read_lock();
restart:
	radix_tree_for_each_tagged(slot, &mapping->page_tree,
				   &iter, *index, tag) {
		struct page *page;
repeat:
		page = radix_tree_deref_slot(slot);
		if (unlikely(!page))
			continue;

		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page)) {
				 
				goto restart;
			}
			 
			continue;
		}

		if (!page_cache_get_speculative(page))
			goto repeat;

		if (unlikely(page != *slot)) {
			page_cache_release(page);
			goto repeat;
		}

		pages[ret] = page;
		if (++ret == nr_pages)
			break;
	}

	rcu_read_unlock();

	if (ret)
		*index = pages[ret - 1]->index + 1;

	return ret;
}
EXPORT_SYMBOL(find_get_pages_tag);

static void shrink_readahead_size_eio(struct file *filp,
					struct file_ra_state *ra)
{
	ra->ra_pages /= 4;
}

static ssize_t do_generic_file_read(struct file *filp, loff_t *ppos,
		struct iov_iter *iter, ssize_t written)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct file_ra_state *ra = &filp->f_ra;
	pgoff_t index;
	pgoff_t last_index;
	pgoff_t prev_index;
	unsigned long offset;       
	unsigned int prev_offset;
	int error = 0;

	index = *ppos >> PAGE_CACHE_SHIFT;
	prev_index = ra->prev_pos >> PAGE_CACHE_SHIFT;
	prev_offset = ra->prev_pos & (PAGE_CACHE_SIZE-1);
	last_index = (*ppos + iter->count + PAGE_CACHE_SIZE-1) >> PAGE_CACHE_SHIFT;
	offset = *ppos & ~PAGE_CACHE_MASK;

	for (;;) {
		struct page *page;
		pgoff_t end_index;
		loff_t isize;
		unsigned long nr, ret;

		cond_resched();
find_page:
		if (fatal_signal_pending(current)) {
			error = -EINTR;
			goto out;
		}

		page = find_get_page(mapping, index);
		if (!page) {
			page_cache_sync_readahead(mapping,
					ra, filp,
					index, last_index - index);
			page = find_get_page(mapping, index);
			if (unlikely(page == NULL))
				goto no_cached_page;
		}
		if (PageReadahead(page)) {
			page_cache_async_readahead(mapping,
					ra, filp, page,
					index, last_index - index);
		}
		if (!PageUptodate(page)) {
			if (inode->i_blkbits == PAGE_CACHE_SHIFT ||
					!mapping->a_ops->is_partially_uptodate)
				goto page_not_up_to_date;
			if (!trylock_page(page))
				goto page_not_up_to_date;
			 
			if (!page->mapping)
				goto page_not_up_to_date_locked;
			if (!mapping->a_ops->is_partially_uptodate(page,
							offset, iter->count))
				goto page_not_up_to_date_locked;
			unlock_page(page);
		}
page_ok:
		 
		isize = i_size_read(inode);
		end_index = (isize - 1) >> PAGE_CACHE_SHIFT;
		if (unlikely(!isize || index > end_index)) {
			page_cache_release(page);
			goto out;
		}

		nr = PAGE_CACHE_SIZE;
		if (index == end_index) {
			nr = ((isize - 1) & ~PAGE_CACHE_MASK) + 1;
			if (nr <= offset) {
				page_cache_release(page);
				goto out;
			}
		}
		nr = nr - offset;

		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		if (prev_index != index || offset != prev_offset)
			mark_page_accessed(page);
		prev_index = index;

		ret = copy_page_to_iter(page, offset, nr, iter);
		offset += ret;
		index += offset >> PAGE_CACHE_SHIFT;
		offset &= ~PAGE_CACHE_MASK;
		prev_offset = offset;

		page_cache_release(page);
		written += ret;
		if (!iov_iter_count(iter))
			goto out;
		if (ret < nr) {
			error = -EFAULT;
			goto out;
		}
		continue;

page_not_up_to_date:
		 
		error = lock_page_killable(page);
		if (unlikely(error))
			goto readpage_error;

page_not_up_to_date_locked:
		 
		if (!page->mapping) {
			unlock_page(page);
			page_cache_release(page);
			continue;
		}

		if (PageUptodate(page)) {
			unlock_page(page);
			goto page_ok;
		}

readpage:
		 
		ClearPageError(page);
		 
		error = mapping->a_ops->readpage(filp, page);

		if (unlikely(error)) {
			if (error == AOP_TRUNCATED_PAGE) {
				page_cache_release(page);
				error = 0;
				goto find_page;
			}
			goto readpage_error;
		}

		if (!PageUptodate(page)) {
			error = lock_page_killable(page);
			if (unlikely(error))
				goto readpage_error;
			if (!PageUptodate(page)) {
				if (page->mapping == NULL) {
					 
					unlock_page(page);
					page_cache_release(page);
					goto find_page;
				}
				unlock_page(page);
				shrink_readahead_size_eio(filp, ra);
				error = -EIO;
				goto readpage_error;
			}
			unlock_page(page);
		}

		goto page_ok;

readpage_error:
		 
		page_cache_release(page);
		goto out;

no_cached_page:
		 
		page = page_cache_alloc_cold(mapping);
		if (!page) {
			error = -ENOMEM;
			goto out;
		}
		error = add_to_page_cache_lru(page, mapping, index,
				mapping_gfp_constraint(mapping, GFP_KERNEL));
		if (error) {
			page_cache_release(page);
			if (error == -EEXIST) {
				error = 0;
				goto find_page;
			}
			goto out;
		}
		goto readpage;
	}

out:
	ra->prev_pos = prev_index;
	ra->prev_pos <<= PAGE_CACHE_SHIFT;
	ra->prev_pos |= prev_offset;

	*ppos = ((loff_t)index << PAGE_CACHE_SHIFT) + offset;
	file_accessed(filp);
	return written ? written : error;
}

ssize_t
generic_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	ssize_t retval = 0;
	loff_t *ppos = &iocb->ki_pos;
	loff_t pos = *ppos;

	if (iocb->ki_flags & IOCB_DIRECT) {
		struct address_space *mapping = file->f_mapping;
		struct inode *inode = mapping->host;
		size_t count = iov_iter_count(iter);
		loff_t size;

		if (!count)
			goto out;  
		size = i_size_read(inode);
		retval = filemap_write_and_wait_range(mapping, pos,
					pos + count - 1);
		if (!retval) {
			struct iov_iter data = *iter;
			retval = mapping->a_ops->direct_IO(iocb, &data, pos);
		}

		if (retval > 0) {
			*ppos = pos + retval;
			iov_iter_advance(iter, retval);
		}

		if (retval < 0 || !iov_iter_count(iter) || *ppos >= size ||
		    IS_DAX(inode)) {
			file_accessed(file);
			goto out;
		}
	}

	retval = do_generic_file_read(file, ppos, iter, retval);
out:
	return retval;
}
EXPORT_SYMBOL(generic_file_read_iter);

#ifdef CONFIG_MMU
 
static int page_cache_read(struct file *file, pgoff_t offset)
{
	struct address_space *mapping = file->f_mapping;
	struct page *page;
	int ret;

	do {
		page = page_cache_alloc_cold(mapping);
		if (!page)
			return -ENOMEM;

		ret = add_to_page_cache_lru(page, mapping, offset,
				mapping_gfp_constraint(mapping, GFP_KERNEL));
		if (ret == 0)
			ret = mapping->a_ops->readpage(file, page);
		else if (ret == -EEXIST)
			ret = 0;  

		page_cache_release(page);

	} while (ret == AOP_TRUNCATED_PAGE);

	return ret;
}

#define MMAP_LOTSAMISS  (100)

static void do_sync_mmap_readahead(struct vm_area_struct *vma,
				   struct file_ra_state *ra,
				   struct file *file,
				   pgoff_t offset)
{
	struct address_space *mapping = file->f_mapping;

	if (vma->vm_flags & VM_RAND_READ)
		return;
	if (!ra->ra_pages)
		return;

	if (vma->vm_flags & VM_SEQ_READ) {
		page_cache_sync_readahead(mapping, ra, file, offset,
					  ra->ra_pages);
		return;
	}

	if (ra->mmap_miss < MMAP_LOTSAMISS * 10)
		ra->mmap_miss++;

	if (ra->mmap_miss > MMAP_LOTSAMISS)
		return;

	ra->start = max_t(long, 0, offset - ra->ra_pages / 2);
	ra->size = ra->ra_pages;
	ra->async_size = ra->ra_pages / 4;
	ra_submit(ra, mapping, file);
}

static void do_async_mmap_readahead(struct vm_area_struct *vma,
				    struct file_ra_state *ra,
				    struct file *file,
				    struct page *page,
				    pgoff_t offset)
{
	struct address_space *mapping = file->f_mapping;

	if (vma->vm_flags & VM_RAND_READ)
		return;
	if (ra->mmap_miss > 0)
		ra->mmap_miss--;
	if (PageReadahead(page))
		page_cache_async_readahead(mapping, ra, file,
					   page, offset, ra->ra_pages);
}

int filemap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	int error;
	struct file *file = vma->vm_file;
	struct address_space *mapping = file->f_mapping;
	struct file_ra_state *ra = &file->f_ra;
	struct inode *inode = mapping->host;
	pgoff_t offset = vmf->pgoff;
	struct page *page;
	loff_t size;
	int ret = 0;

	size = round_up(i_size_read(inode), PAGE_CACHE_SIZE);
	if (offset >= size >> PAGE_CACHE_SHIFT)
		return VM_FAULT_SIGBUS;

	page = find_get_page(mapping, offset);
	if (likely(page) && !(vmf->flags & FAULT_FLAG_TRIED)) {
		 
		do_async_mmap_readahead(vma, ra, file, page, offset);
	} else if (!page) {
		 
		do_sync_mmap_readahead(vma, ra, file, offset);
		count_vm_event(PGMAJFAULT);
		mem_cgroup_count_vm_event(vma->vm_mm, PGMAJFAULT);
		ret = VM_FAULT_MAJOR;
retry_find:
		page = find_get_page(mapping, offset);
		if (!page)
			goto no_cached_page;
	}

	if (!lock_page_or_retry(page, vma->vm_mm, vmf->flags)) {
		page_cache_release(page);
		return ret | VM_FAULT_RETRY;
	}

	if (unlikely(page->mapping != mapping)) {
		unlock_page(page);
		put_page(page);
		goto retry_find;
	}
	VM_BUG_ON_PAGE(page->index != offset, page);

	if (unlikely(!PageUptodate(page)))
		goto page_not_uptodate;

	size = round_up(i_size_read(inode), PAGE_CACHE_SIZE);
	if (unlikely(offset >= size >> PAGE_CACHE_SHIFT)) {
		unlock_page(page);
		page_cache_release(page);
		return VM_FAULT_SIGBUS;
	}

	vmf->page = page;
	return ret | VM_FAULT_LOCKED;

no_cached_page:
	 
	error = page_cache_read(file, offset);

	if (error >= 0)
		goto retry_find;

	if (error == -ENOMEM)
		return VM_FAULT_OOM;
	return VM_FAULT_SIGBUS;

page_not_uptodate:
	 
	ClearPageError(page);
	error = mapping->a_ops->readpage(file, page);
	if (!error) {
		wait_on_page_locked(page);
		if (!PageUptodate(page))
			error = -EIO;
	}
	page_cache_release(page);

	if (!error || error == AOP_TRUNCATED_PAGE)
		goto retry_find;

	shrink_readahead_size_eio(file, ra);
	return VM_FAULT_SIGBUS;
}
EXPORT_SYMBOL(filemap_fault);

void filemap_map_pages(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct radix_tree_iter iter;
	void **slot;
	struct file *file = vma->vm_file;
	struct address_space *mapping = file->f_mapping;
	loff_t size;
	struct page *page;
	unsigned long address = (unsigned long) vmf->virtual_address;
	unsigned long addr;
	pte_t *pte;

	rcu_read_lock();
	radix_tree_for_each_slot(slot, &mapping->page_tree, &iter, vmf->pgoff) {
		if (iter.index > vmf->max_pgoff)
			break;
repeat:
		page = radix_tree_deref_slot(slot);
		if (unlikely(!page))
			goto next;
		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page))
				break;
			else
				goto next;
		}

		if (!page_cache_get_speculative(page))
			goto repeat;

		if (unlikely(page != *slot)) {
			page_cache_release(page);
			goto repeat;
		}

		if (!PageUptodate(page) ||
				PageReadahead(page) ||
				PageHWPoison(page))
			goto skip;
		if (!trylock_page(page))
			goto skip;

		if (page->mapping != mapping || !PageUptodate(page))
			goto unlock;

		size = round_up(i_size_read(mapping->host), PAGE_CACHE_SIZE);
		if (page->index >= size >> PAGE_CACHE_SHIFT)
			goto unlock;

		pte = vmf->pte + page->index - vmf->pgoff;
		if (!pte_none(*pte))
			goto unlock;

		if (file->f_ra.mmap_miss > 0)
			file->f_ra.mmap_miss--;
		addr = address + (page->index - vmf->pgoff) * PAGE_SIZE;
		do_set_pte(vma, addr, page, pte, false, false);
		unlock_page(page);
		goto next;
unlock:
		unlock_page(page);
skip:
		page_cache_release(page);
next:
		if (iter.index == vmf->max_pgoff)
			break;
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL(filemap_map_pages);

int filemap_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	struct inode *inode = file_inode(vma->vm_file);
	int ret = VM_FAULT_LOCKED;

	sb_start_pagefault(inode->i_sb);
#ifdef CONFIG_AUFS_FHSM
	vma_file_update_time(vma);
#else
	file_update_time(vma->vm_file);
#endif  
	lock_page(page);
	if (page->mapping != inode->i_mapping) {
		unlock_page(page);
		ret = VM_FAULT_NOPAGE;
		goto out;
	}
	 
	set_page_dirty(page);
	wait_for_stable_page(page);
out:
	sb_end_pagefault(inode->i_sb);
	return ret;
}
EXPORT_SYMBOL(filemap_page_mkwrite);

const struct vm_operations_struct generic_file_vm_ops = {
	.fault		= filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite	= filemap_page_mkwrite,
};

int generic_file_mmap(struct file * file, struct vm_area_struct * vma)
{
	struct address_space *mapping = file->f_mapping;

	if (!mapping->a_ops->readpage)
		return -ENOEXEC;
	file_accessed(file);
	vma->vm_ops = &generic_file_vm_ops;
	return 0;
}

int generic_file_readonly_mmap(struct file *file, struct vm_area_struct *vma)
{
	if ((vma->vm_flags & VM_SHARED) && (vma->vm_flags & VM_MAYWRITE))
		return -EINVAL;
	return generic_file_mmap(file, vma);
}
#else
int generic_file_mmap(struct file * file, struct vm_area_struct * vma)
{
	return -ENOSYS;
}
int generic_file_readonly_mmap(struct file * file, struct vm_area_struct * vma)
{
	return -ENOSYS;
}
#endif  

EXPORT_SYMBOL(generic_file_mmap);
EXPORT_SYMBOL(generic_file_readonly_mmap);

static struct page *wait_on_page_read(struct page *page)
{
	if (!IS_ERR(page)) {
		wait_on_page_locked(page);
		if (!PageUptodate(page)) {
			page_cache_release(page);
			page = ERR_PTR(-EIO);
		}
	}
	return page;
}

static struct page *__read_cache_page(struct address_space *mapping,
				pgoff_t index,
				int (*filler)(void *, struct page *),
				void *data,
				gfp_t gfp)
{
	struct page *page;
	int err;
repeat:
	page = find_get_page(mapping, index);
	if (!page) {
		page = __page_cache_alloc(gfp | __GFP_COLD);
		if (!page)
			return ERR_PTR(-ENOMEM);
		err = add_to_page_cache_lru(page, mapping, index, gfp);
		if (unlikely(err)) {
			page_cache_release(page);
			if (err == -EEXIST)
				goto repeat;
			 
			return ERR_PTR(err);
		}
		err = filler(data, page);
		if (err < 0) {
			page_cache_release(page);
			page = ERR_PTR(err);
		} else {
			page = wait_on_page_read(page);
		}
	}
	return page;
}

static struct page *do_read_cache_page(struct address_space *mapping,
				pgoff_t index,
				int (*filler)(void *, struct page *),
				void *data,
				gfp_t gfp)

{
	struct page *page;
	int err;

retry:
	page = __read_cache_page(mapping, index, filler, data, gfp);
	if (IS_ERR(page))
		return page;
	if (PageUptodate(page))
		goto out;

	lock_page(page);
	if (!page->mapping) {
		unlock_page(page);
		page_cache_release(page);
		goto retry;
	}
	if (PageUptodate(page)) {
		unlock_page(page);
		goto out;
	}
	err = filler(data, page);
	if (err < 0) {
		page_cache_release(page);
		return ERR_PTR(err);
	} else {
		page = wait_on_page_read(page);
		if (IS_ERR(page))
			return page;
	}
out:
	mark_page_accessed(page);
	return page;
}

struct page *read_cache_page(struct address_space *mapping,
				pgoff_t index,
				int (*filler)(void *, struct page *),
				void *data)
{
	return do_read_cache_page(mapping, index, filler, data, mapping_gfp_mask(mapping));
}
EXPORT_SYMBOL(read_cache_page);

struct page *read_cache_page_gfp(struct address_space *mapping,
				pgoff_t index,
				gfp_t gfp)
{
	filler_t *filler = (filler_t *)mapping->a_ops->readpage;

	return do_read_cache_page(mapping, index, filler, NULL, gfp);
}
EXPORT_SYMBOL(read_cache_page_gfp);

inline ssize_t generic_write_checks(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	unsigned long limit = rlimit(RLIMIT_FSIZE);
	loff_t pos;

	if (!iov_iter_count(from))
		return 0;

	if (iocb->ki_flags & IOCB_APPEND)
		iocb->ki_pos = i_size_read(inode);

	pos = iocb->ki_pos;

	if (limit != RLIM_INFINITY) {
		if (iocb->ki_pos >= limit) {
			send_sig(SIGXFSZ, current, 0);
			return -EFBIG;
		}
		iov_iter_truncate(from, limit - (unsigned long)pos);
	}

	if (unlikely(pos + iov_iter_count(from) > MAX_NON_LFS &&
				!(file->f_flags & O_LARGEFILE))) {
		if (pos >= MAX_NON_LFS)
			return -EFBIG;
		iov_iter_truncate(from, MAX_NON_LFS - (unsigned long)pos);
	}

	if (unlikely(pos >= inode->i_sb->s_maxbytes))
		return -EFBIG;

	iov_iter_truncate(from, inode->i_sb->s_maxbytes - pos);
	return iov_iter_count(from);
}
EXPORT_SYMBOL(generic_write_checks);

int pagecache_write_begin(struct file *file, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned flags,
				struct page **pagep, void **fsdata)
{
	const struct address_space_operations *aops = mapping->a_ops;

	return aops->write_begin(file, mapping, pos, len, flags,
							pagep, fsdata);
}
EXPORT_SYMBOL(pagecache_write_begin);

int pagecache_write_end(struct file *file, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned copied,
				struct page *page, void *fsdata)
{
	const struct address_space_operations *aops = mapping->a_ops;

	return aops->write_end(file, mapping, pos, len, copied, page, fsdata);
}
EXPORT_SYMBOL(pagecache_write_end);

#ifdef MY_ABC_HERE
static int sock2iov(struct socket *sock, struct kvec *iov,
			int page_count, int start_page, size_t bytes_to_received, size_t *bytes_received)
{
	int             kmsg_ret = 0;
	long            rcvtimeo = 0;
	struct msghdr   msg = {0};

	msg.msg_flags = MSG_KERNSPACE;
	rcvtimeo = sock->sk->sk_rcvtimeo;
	sock->sk->sk_rcvtimeo = 64 * HZ;

	kmsg_ret = kernel_recvmsg(
			sock, &msg, &iov[start_page], page_count, bytes_to_received,
			MSG_WAITALL | MSG_NOCATCHSIGNAL);

	sock->sk->sk_rcvtimeo = rcvtimeo;
	if (kmsg_ret >= 0) {
		*bytes_received = (size_t) kmsg_ret;
		if (kmsg_ret == bytes_to_received) {
			 
			kmsg_ret = 0;
		} else {
			kmsg_ret = -EPIPE;
		}
	}

	return kmsg_ret;
}

int do_recvfile(struct file *file, struct socket *sock, loff_t pos,
			size_t count, size_t * rbytes, size_t * wbytes)
{
	int                    err = 0;
	int                    pages_allocated = 0;
	int                    page_index = 0;
	int                    flags = AOP_FLAG_UNINTERRUPTIBLE | AOP_FLAG_RECVFILE | AOP_FLAG_NOFS;
	int                    write_end_ret = 0, failed_write_flag = 0;
	loff_t                 firstPagePos = 0, lastPagePos = 0;
	unsigned               firstPageBytes = 0, lastPageBytes = 0;
	unsigned               bytes = 0;
	pgoff_t                offset = (pos & (PAGE_CACHE_SIZE - 1));
	void                  *fsdata = NULL;  
	size_t                 bytes_received = 0, bytes_wrote = 0;
	ssize_t                bytes_to_received = 0;
	struct kvec            iov[MAX_PAGES_PER_RECVFILE + 1];
	struct page           *page = NULL;
	struct page           *rgPageList[MAX_PAGES_PER_RECVFILE + 1];
	struct address_space  *mapping = file->f_mapping;

	if ((!mapping->a_ops->write_begin || !mapping->a_ops->write_end)) {
		printk("write_begin() or write_end() or syno_recvfile() are not implemented\n");
		goto done;
	}
	if (mapping->a_ops->recvfile_da_check && mapping->a_ops->recvfile_da_check(mapping->host->i_sb)) {
		flags |= AOP_FLAG_RECVFILE_NONDA;
	}

	do {
		bytes = min_t(unsigned int, PAGE_CACHE_SIZE - offset, count);

		err = mapping->a_ops->write_begin(
					file, mapping, pos, bytes, flags,
					&page, &fsdata);
		if (err) {
			goto release_pages;
		}

		rgPageList[pages_allocated] = page;
		if (!pages_allocated) {
			firstPageBytes = bytes;
			firstPagePos = pos;
		}
		if (bytes == count) {
			lastPageBytes = bytes;
			lastPagePos = pos;
		}
		iov[pages_allocated].iov_base = kmap(page) + offset;
		iov[pages_allocated].iov_len = bytes;
		pages_allocated++;

		BUG_ON(pages_allocated > MAX_PAGES_PER_RECVFILE + 1);

		count -= bytes;
		pos += bytes;
		bytes_to_received += bytes;
		offset = 0;
		flags |= AOP_FLAG_RECVFILE_ECRYPTFS_NO_TRUNCATE;
	} while (count);

	err = sock2iov(sock, iov, pages_allocated, 0, bytes_to_received, &bytes_received);

release_pages:
	*rbytes = bytes_received;
	bytes_wrote = bytes_received;
	if (unlikely(mapping->a_ops->aggregate_write_end)) {
		for (page_index = 0; page_index < pages_allocated; page_index++) {
			kunmap(rgPageList[page_index]);
		}
		write_end_ret = mapping->a_ops->aggregate_write_end(
				file, mapping, firstPagePos,
				bytes_to_received, bytes_to_received,
				rgPageList, NULL, pages_allocated);
		 
		if (0 > write_end_ret) {
			bytes_wrote = 0;
			if (!err) {
				err = write_end_ret;
			}
		}
	} else {
		 
		if (flags & AOP_FLAG_RECVFILE_NONDA)
			fsdata = (void *)1;  
		for (page_index = 0; page_index < pages_allocated; page_index++) {
			page = rgPageList[page_index];
			kunmap(page);
			if (!page_index) {
				bytes = firstPageBytes;
				pos = firstPagePos;
			} else if (page_index == pages_allocated - 1) {
				bytes = lastPageBytes;
				pos = lastPagePos;
			} else {
				pos += bytes;
				bytes = PAGE_CACHE_SIZE;
			}
			write_end_ret = mapping->a_ops->write_end(file, mapping, pos,
								bytes, bytes, page, fsdata);
			 
			if (0 > write_end_ret) {
				if (!failed_write_flag) {
					failed_write_flag = 1;
					if (page_index) {
						bytes_wrote = firstPageBytes + ((page_index-1) * PAGE_CACHE_SIZE);
						if (bytes_wrote > bytes_received)
							bytes_wrote = bytes_received;
					} else {
						bytes_wrote = 0;
					}
				}
				if (!err) {
					err = write_end_ret;
				}
			}
		}
	}
	*wbytes = bytes_wrote;
	balance_dirty_pages_ratelimited(mapping);

done:
	return err?err:bytes_received;
}
extern int aggregate_fd;
extern spinlock_t aggregate_lock;
extern atomic_t syno_aggregate_recvfile_count;

int do_aggregate_recvfile(struct file *file, struct socket *sock, loff_t pos,
			size_t count, size_t * rbytes, size_t * wbytes, unsigned flush_only)
{
	int                    err = 0;
	int                    page_index = 0;
	int                    write_end_ret = 0;
	int                    page_alloc_last_time;
	int                    isPageAlign = 1;
	unsigned               bytes = 0;
	pgoff_t                offset = (pos & (PAGE_CACHE_SIZE - 1));
	void                  *fsdata = NULL;  
	size_t                 bytes_received = 0, bytes_wrote = 0;
	ssize_t                bytes_to_received = 0;
	struct page           *page = NULL;
	struct address_space  *mapping = file->f_mapping;
	struct inode          *inode = mapping->host;
	static int             pages_allocated = 0;
	static loff_t          rgPos[MAX_PAGES_PER_AGGREGATE_RECVFILE + 1];
	static unsigned        rgBytes[MAX_PAGES_PER_AGGREGATE_RECVFILE + 1];
	static struct kvec     iov[MAX_PAGES_PER_AGGREGATE_RECVFILE + 1];
	static struct page    *rgPageList[MAX_PAGES_PER_AGGREGATE_RECVFILE + 1];

	if (!mapping->a_ops->write_begin || !mapping->a_ops->aggregate_write_end) {
		printk("write_begin() or aggregate_write_end() is not implemented\n");
		dump_stack();
		goto done;
	}
	if (flush_only) {
		if (!pages_allocated) {
			goto done;
		}
		goto release_pages;
	}
	if (count == 0) {
		goto done;
	}
	if (offset || (count & (PAGE_CACHE_SIZE - 1))) {
		isPageAlign = 0;
	}

	page_alloc_last_time = pages_allocated;
	do {
		bytes = min_t(unsigned int, PAGE_CACHE_SIZE - offset, count);

		err = mapping->a_ops->write_begin(
					file, mapping, pos, bytes, AOP_FLAG_UNINTERRUPTIBLE | AOP_FLAG_RECVFILE | AOP_FLAG_NOFS,
					&page, &fsdata);
		if (err) {
			goto release_pages;
		}

		rgPageList[pages_allocated] = page;
		rgPos[pages_allocated] = pos;
		rgBytes[pages_allocated] = bytes;
		iov[pages_allocated].iov_base = kmap(page) + offset;
		iov[pages_allocated].iov_len = bytes;
		pages_allocated++;

		BUG_ON(pages_allocated > MAX_PAGES_PER_AGGREGATE_RECVFILE + 1);

		count -= bytes;
		pos += bytes;
		bytes_to_received += bytes;
		offset = 0;
	} while (count);

	err = sock2iov(sock, iov, pages_allocated-page_alloc_last_time,
			page_alloc_last_time, bytes_to_received, &bytes_received);

	if (!err && isPageAlign && (pages_allocated <= MAX_PAGES_PER_AGGREGATE_RECVFILE - MAX_PAGES_PER_RECVFILE)) {
		*rbytes = bytes_received;
		*wbytes = bytes_received;

		return bytes_received;
	}
release_pages:

	*rbytes = bytes_received;
	*wbytes = bytes_received;
	for (page_index = 0; page_index < pages_allocated; page_index++) {
		bytes_wrote += rgBytes[page_index];
		kunmap(rgPageList[page_index]);
	}
	write_end_ret = mapping->a_ops->aggregate_write_end(
			file, mapping, rgPos[0],
			bytes_wrote, bytes_wrote,
			rgPageList, NULL, pages_allocated);
	 
	if (0 > write_end_ret) {
		*wbytes = 0;
		if (!err) {
			err = write_end_ret;
		}
	}

	pages_allocated = 0;
	aggregate_fd = -1;
	inode->aggregate_flag &= ~AGGREGATE_RECVFILE_DOING;

	balance_dirty_pages_ratelimited(mapping);

done:
	return err?err:bytes_received;
}

void aggregate_recvfile_flush_only(struct file *file)
{
	struct socket *sock = NULL;
	size_t bytes_received;
	size_t bytes_written;

	do_aggregate_recvfile(file, sock, 0, 0, &bytes_received, &bytes_written, 1);
}
EXPORT_SYMBOL(aggregate_recvfile_flush_only);

int flush_aggregate_recvfile(int fd)
{
	int ret = 0;
	struct inode *inode = NULL;
	struct file *file = NULL;                 

	if (-1 != fd) {
		file = fget(fd);
	} else {
		file = fget(aggregate_fd);
	}
	if (!file || !file->f_mapping->a_ops->aggregate_write_end) {
		goto out;
	}
	if (!(file->f_mode & FMODE_WRITE)) {
		ret = -EBADF;
		goto out;
	}
	inode = file->f_path.dentry->d_inode->i_mapping->host;
	spin_lock(&aggregate_lock);
	inode->aggregate_flag |= AGGREGATE_RECVFILE_FLUSH;
	if (AGGREGATE_RECVFILE_DOING & inode->aggregate_flag) {
		while (atomic_read(&syno_aggregate_recvfile_count)) {
			spin_unlock(&aggregate_lock);
			schedule_timeout_uninterruptible(HZ/2);
			spin_lock(&aggregate_lock);
		}
		atomic_inc(&syno_aggregate_recvfile_count);
		spin_unlock(&aggregate_lock);
		aggregate_recvfile_flush_only(file);
		atomic_dec(&syno_aggregate_recvfile_count);
	} else {
		spin_unlock(&aggregate_lock);
	}
	inode->aggregate_flag &= ~AGGREGATE_RECVFILE_FLUSH;

out:
	if (file)
		fput(file);

	return ret;
}
EXPORT_SYMBOL(flush_aggregate_recvfile);
#endif  

ssize_t
generic_file_direct_write(struct kiocb *iocb, struct iov_iter *from, loff_t pos)
{
	struct file	*file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode	*inode = mapping->host;
	ssize_t		written;
	size_t		write_len;
	pgoff_t		end;
	struct iov_iter data;

	write_len = iov_iter_count(from);
	end = (pos + write_len - 1) >> PAGE_CACHE_SHIFT;

	written = filemap_write_and_wait_range(mapping, pos, pos + write_len - 1);
	if (written)
		goto out;

	if (mapping->nrpages) {
		written = invalidate_inode_pages2_range(mapping,
					pos >> PAGE_CACHE_SHIFT, end);
		 
		if (written) {
			if (written == -EBUSY)
				return 0;
			goto out;
		}
	}

	data = *from;
	written = mapping->a_ops->direct_IO(iocb, &data, pos);

	if (mapping->nrpages) {
		invalidate_inode_pages2_range(mapping,
					      pos >> PAGE_CACHE_SHIFT, end);
	}

	if (written > 0) {
		pos += written;
		iov_iter_advance(from, written);
		if (pos > i_size_read(inode) && !S_ISBLK(inode->i_mode)) {
			i_size_write(inode, pos);
			mark_inode_dirty(inode);
		}
		iocb->ki_pos = pos;
	}
out:
	return written;
}
EXPORT_SYMBOL(generic_file_direct_write);

struct page *grab_cache_page_write_begin(struct address_space *mapping,
					pgoff_t index, unsigned flags)
{
	struct page *page;
	int fgp_flags = FGP_LOCK|FGP_ACCESSED|FGP_WRITE|FGP_CREAT;

	if (flags & AOP_FLAG_NOFS)
		fgp_flags |= FGP_NOFS;

	page = pagecache_get_page(mapping, index, fgp_flags,
			mapping_gfp_mask(mapping));
	if (page)
		wait_for_stable_page(page);

	return page;
}
EXPORT_SYMBOL(grab_cache_page_write_begin);

ssize_t generic_perform_write(struct file *file,
				struct iov_iter *i, loff_t pos)
{
	struct address_space *mapping = file->f_mapping;
	const struct address_space_operations *a_ops = mapping->a_ops;
	long status = 0;
	ssize_t written = 0;
	unsigned int flags = 0;

	if (!iter_is_iovec(i))
		flags |= AOP_FLAG_UNINTERRUPTIBLE;

	do {
		struct page *page;
		unsigned long offset;	 
		unsigned long bytes;	 
		size_t copied;		 
		void *fsdata;

		offset = (pos & (PAGE_CACHE_SIZE - 1));
		bytes = min_t(unsigned long, PAGE_CACHE_SIZE - offset,
						iov_iter_count(i));

again:
		 
		if (unlikely(iov_iter_fault_in_readable(i, bytes))) {
			status = -EFAULT;
			break;
		}

		if (fatal_signal_pending(current)) {
			status = -EINTR;
			break;
		}

		status = a_ops->write_begin(file, mapping, pos, bytes, flags,
						&page, &fsdata);
		if (unlikely(status < 0))
			break;

		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		copied = iov_iter_copy_from_user_atomic(page, i, offset, bytes);
		flush_dcache_page(page);

		status = a_ops->write_end(file, mapping, pos, bytes, copied,
						page, fsdata);
		if (unlikely(status < 0))
			break;
		copied = status;

		cond_resched();

		iov_iter_advance(i, copied);
		if (unlikely(copied == 0)) {
			 
			bytes = min_t(unsigned long, PAGE_CACHE_SIZE - offset,
						iov_iter_single_seg_count(i));
			goto again;
		}
		pos += copied;
		written += copied;

		balance_dirty_pages_ratelimited(mapping);
	} while (iov_iter_count(i));

	return written ? written : status;
}
EXPORT_SYMBOL(generic_perform_write);

ssize_t __generic_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct address_space * mapping = file->f_mapping;
	struct inode 	*inode = mapping->host;
	ssize_t		written = 0;
	ssize_t		err;
	ssize_t		status;

	current->backing_dev_info = inode_to_bdi(inode);
	err = file_remove_privs(file);
	if (err)
		goto out;

	err = file_update_time(file);
	if (err)
		goto out;

	if (iocb->ki_flags & IOCB_DIRECT) {
		loff_t pos, endbyte;

		written = generic_file_direct_write(iocb, from, iocb->ki_pos);
		 
		if (written < 0 || !iov_iter_count(from) || IS_DAX(inode))
			goto out;

		status = generic_perform_write(file, from, pos = iocb->ki_pos);
		 
		if (unlikely(status < 0)) {
			err = status;
			goto out;
		}
		 
		endbyte = pos + status - 1;
		err = filemap_write_and_wait_range(mapping, pos, endbyte);
		if (err == 0) {
			iocb->ki_pos = endbyte + 1;
			written += status;
			invalidate_mapping_pages(mapping,
						 pos >> PAGE_CACHE_SHIFT,
						 endbyte >> PAGE_CACHE_SHIFT);
		} else {
			 
		}
	} else {
		written = generic_perform_write(file, from, iocb->ki_pos);
		if (likely(written > 0))
			iocb->ki_pos += written;
	}
out:
	current->backing_dev_info = NULL;
	return written ? written : err;
}
EXPORT_SYMBOL(__generic_file_write_iter);

ssize_t generic_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ssize_t ret;

	inode_lock(inode);
	ret = generic_write_checks(iocb, from);
	if (ret > 0)
		ret = __generic_file_write_iter(iocb, from);
	inode_unlock(inode);

	if (ret > 0) {
		ssize_t err;

		err = generic_write_sync(file, iocb->ki_pos - ret, ret);
		if (err < 0)
			ret = err;
	}
	return ret;
}
EXPORT_SYMBOL(generic_file_write_iter);

int try_to_release_page(struct page *page, gfp_t gfp_mask)
{
	struct address_space * const mapping = page->mapping;

	BUG_ON(!PageLocked(page));
	if (PageWriteback(page))
		return 0;

	if (mapping && mapping->a_ops->releasepage)
		return mapping->a_ops->releasepage(page, gfp_mask);
	return try_to_free_buffers(page);
}

EXPORT_SYMBOL(try_to_release_page);
