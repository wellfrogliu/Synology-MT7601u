#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/kernel.h>
#include <linux/backing-dev.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/export.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/pagevec.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/buffer_head.h>	 
#include <linux/cleancache.h>
#include <linux/rmap.h>
#include "internal.h"

static void clear_exceptional_entry(struct address_space *mapping,
				    pgoff_t index, void *entry)
{
	struct radix_tree_node *node;
	void **slot;

	if (shmem_mapping(mapping))
		return;

	spin_lock_irq(&mapping->tree_lock);
	 
	if (!__radix_tree_lookup(&mapping->page_tree, index, &node, &slot))
		goto unlock;
	if (*slot != entry)
		goto unlock;
	radix_tree_replace_slot(slot, NULL);
	mapping->nrshadows--;
	if (!node)
		goto unlock;
	workingset_node_shadows_dec(node);
	 
	if (!workingset_node_shadows(node) &&
	    !list_empty(&node->private_list))
		list_lru_del(&workingset_shadow_nodes, &node->private_list);
	__radix_tree_delete_node(&mapping->page_tree, node);
unlock:
	spin_unlock_irq(&mapping->tree_lock);
}

void do_invalidatepage(struct page *page, unsigned int offset,
		       unsigned int length)
{
	void (*invalidatepage)(struct page *, unsigned int, unsigned int);

	invalidatepage = page->mapping->a_ops->invalidatepage;
#ifdef CONFIG_BLOCK
	if (!invalidatepage)
		invalidatepage = block_invalidatepage;
#endif
	if (invalidatepage)
		(*invalidatepage)(page, offset, length);
}

static int
truncate_complete_page(struct address_space *mapping, struct page *page)
{
	if (page->mapping != mapping)
		return -EIO;

	if (page_has_private(page))
		do_invalidatepage(page, 0, PAGE_CACHE_SIZE);

	cancel_dirty_page(page);
	ClearPageMappedToDisk(page);
	delete_from_page_cache(page);
	return 0;
}

static int
invalidate_complete_page(struct address_space *mapping, struct page *page)
{
	int ret;

	if (page->mapping != mapping)
		return 0;

	if (page_has_private(page) && !try_to_release_page(page, 0))
		return 0;

	ret = remove_mapping(mapping, page);

	return ret;
}

int truncate_inode_page(struct address_space *mapping, struct page *page)
{
	if (page_mapped(page)) {
		unmap_mapping_range(mapping,
				   (loff_t)page->index << PAGE_CACHE_SHIFT,
				   PAGE_CACHE_SIZE, 0);
	}
	return truncate_complete_page(mapping, page);
}

int generic_error_remove_page(struct address_space *mapping, struct page *page)
{
	if (!mapping)
		return -EINVAL;
	 
	if (!S_ISREG(mapping->host->i_mode))
		return -EIO;
	return truncate_inode_page(mapping, page);
}
EXPORT_SYMBOL(generic_error_remove_page);

int invalidate_inode_page(struct page *page)
{
	struct address_space *mapping = page_mapping(page);
	if (!mapping)
		return 0;
	if (PageDirty(page) || PageWriteback(page))
		return 0;
	if (page_mapped(page))
		return 0;
	return invalidate_complete_page(mapping, page);
}

void truncate_inode_pages_range(struct address_space *mapping,
				loff_t lstart, loff_t lend)
{
	pgoff_t		start;		 
	pgoff_t		end;		 
	unsigned int	partial_start;	 
	unsigned int	partial_end;	 
	struct pagevec	pvec;
	pgoff_t		indices[PAGEVEC_SIZE];
	pgoff_t		index;
	int		i;

	cleancache_invalidate_inode(mapping);
	if (mapping->nrpages == 0 && mapping->nrshadows == 0)
		return;

	partial_start = lstart & (PAGE_CACHE_SIZE - 1);
	partial_end = (lend + 1) & (PAGE_CACHE_SIZE - 1);

	start = (lstart + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	if (lend == -1)
		 
		end = -1;
	else
		end = (lend + 1) >> PAGE_CACHE_SHIFT;

	pagevec_init(&pvec, 0);
	index = start;
	while (index < end && pagevec_lookup_entries(&pvec, mapping, index,
			min(end - index, (pgoff_t)PAGEVEC_SIZE),
			indices)) {
		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i];

			index = indices[i];
			if (index >= end)
				break;

			if (radix_tree_exceptional_entry(page)) {
				clear_exceptional_entry(mapping, index, page);
				continue;
			}

			if (!trylock_page(page))
				continue;
			WARN_ON(page->index != index);
			if (PageWriteback(page)) {
				unlock_page(page);
				continue;
			}
			truncate_inode_page(mapping, page);
			unlock_page(page);
		}
		pagevec_remove_exceptionals(&pvec);
		pagevec_release(&pvec);
		cond_resched();
		index++;
	}

	if (partial_start) {
		struct page *page = find_lock_page(mapping, start - 1);
		if (page) {
			unsigned int top = PAGE_CACHE_SIZE;
			if (start > end) {
				 
				top = partial_end;
				partial_end = 0;
			}
			wait_on_page_writeback(page);
			zero_user_segment(page, partial_start, top);
			cleancache_invalidate_page(mapping, page);
			if (page_has_private(page))
				do_invalidatepage(page, partial_start,
						  top - partial_start);
			unlock_page(page);
			page_cache_release(page);
		}
	}
	if (partial_end) {
		struct page *page = find_lock_page(mapping, end);
		if (page) {
			wait_on_page_writeback(page);
			zero_user_segment(page, 0, partial_end);
			cleancache_invalidate_page(mapping, page);
			if (page_has_private(page))
				do_invalidatepage(page, 0,
						  partial_end);
			unlock_page(page);
			page_cache_release(page);
		}
	}
	 
	if (start >= end)
		return;

	index = start;
	for ( ; ; ) {
		cond_resched();
		if (!pagevec_lookup_entries(&pvec, mapping, index,
			min(end - index, (pgoff_t)PAGEVEC_SIZE), indices)) {
			 
			if (index == start)
				break;
			 
			index = start;
			continue;
		}
		if (index == start && indices[0] >= end) {
			 
			pagevec_remove_exceptionals(&pvec);
			pagevec_release(&pvec);
			break;
		}
		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i];

			index = indices[i];
			if (index >= end) {
				 
				index = start - 1;
				break;
			}

			if (radix_tree_exceptional_entry(page)) {
				clear_exceptional_entry(mapping, index, page);
				continue;
			}

			lock_page(page);
			WARN_ON(page->index != index);
			wait_on_page_writeback(page);
			truncate_inode_page(mapping, page);
			unlock_page(page);
		}
		pagevec_remove_exceptionals(&pvec);
		pagevec_release(&pvec);
		index++;
	}
	cleancache_invalidate_inode(mapping);
}
EXPORT_SYMBOL(truncate_inode_pages_range);

void truncate_inode_pages(struct address_space *mapping, loff_t lstart)
{
	truncate_inode_pages_range(mapping, lstart, (loff_t)-1);
}
EXPORT_SYMBOL(truncate_inode_pages);

void truncate_inode_pages_final(struct address_space *mapping)
{
	unsigned long nrshadows;
	unsigned long nrpages;

	mapping_set_exiting(mapping);

	nrpages = mapping->nrpages;
	smp_rmb();
	nrshadows = mapping->nrshadows;

	if (nrpages || nrshadows) {
		 
		spin_lock_irq(&mapping->tree_lock);
		spin_unlock_irq(&mapping->tree_lock);

		truncate_inode_pages(mapping, 0);
	}
}
EXPORT_SYMBOL(truncate_inode_pages_final);

unsigned long invalidate_mapping_pages(struct address_space *mapping,
		pgoff_t start, pgoff_t end)
{
	pgoff_t indices[PAGEVEC_SIZE];
	struct pagevec pvec;
	pgoff_t index = start;
	unsigned long ret;
	unsigned long count = 0;
	int i;

	pagevec_init(&pvec, 0);
	while (index <= end && pagevec_lookup_entries(&pvec, mapping, index,
			min(end - index, (pgoff_t)PAGEVEC_SIZE - 1) + 1,
			indices)) {
		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i];

			index = indices[i];
			if (index > end)
				break;

			if (radix_tree_exceptional_entry(page)) {
				clear_exceptional_entry(mapping, index, page);
				continue;
			}

			if (!trylock_page(page))
				continue;
			WARN_ON(page->index != index);
			ret = invalidate_inode_page(page);
			unlock_page(page);
			 
			if (!ret)
				deactivate_file_page(page);
			count += ret;
		}
		pagevec_remove_exceptionals(&pvec);
		pagevec_release(&pvec);
		cond_resched();
		index++;
	}
	return count;
}
EXPORT_SYMBOL(invalidate_mapping_pages);

static int
invalidate_complete_page2(struct address_space *mapping, struct page *page)
{
	struct mem_cgroup *memcg;
	unsigned long flags;

	if (page->mapping != mapping)
		return 0;

	if (page_has_private(page) && !try_to_release_page(page, GFP_KERNEL))
		return 0;

	memcg = mem_cgroup_begin_page_stat(page);
	spin_lock_irqsave(&mapping->tree_lock, flags);
	if (PageDirty(page))
		goto failed;

	BUG_ON(page_has_private(page));
	__delete_from_page_cache(page, NULL, memcg);
	spin_unlock_irqrestore(&mapping->tree_lock, flags);
	mem_cgroup_end_page_stat(memcg);

	if (mapping->a_ops->freepage)
		mapping->a_ops->freepage(page);

	page_cache_release(page);	 
	return 1;
failed:
	spin_unlock_irqrestore(&mapping->tree_lock, flags);
	mem_cgroup_end_page_stat(memcg);
	return 0;
}

static int do_launder_page(struct address_space *mapping, struct page *page)
{
	if (!PageDirty(page))
		return 0;
	if (page->mapping != mapping || mapping->a_ops->launder_page == NULL)
		return 0;
	return mapping->a_ops->launder_page(page);
}

int invalidate_inode_pages2_range(struct address_space *mapping,
				  pgoff_t start, pgoff_t end)
{
	pgoff_t indices[PAGEVEC_SIZE];
	struct pagevec pvec;
	pgoff_t index;
	int i;
	int ret = 0;
	int ret2 = 0;
	int did_range_unmap = 0;

	cleancache_invalidate_inode(mapping);
	pagevec_init(&pvec, 0);
	index = start;
	while (index <= end && pagevec_lookup_entries(&pvec, mapping, index,
			min(end - index, (pgoff_t)PAGEVEC_SIZE - 1) + 1,
			indices)) {
		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i];

			index = indices[i];
			if (index > end)
				break;

			if (radix_tree_exceptional_entry(page)) {
				clear_exceptional_entry(mapping, index, page);
				continue;
			}

			lock_page(page);
			WARN_ON(page->index != index);
			if (page->mapping != mapping) {
				unlock_page(page);
				continue;
			}
			wait_on_page_writeback(page);
			if (page_mapped(page)) {
				if (!did_range_unmap) {
					 
					unmap_mapping_range(mapping,
					   (loff_t)index << PAGE_CACHE_SHIFT,
					   (loff_t)(1 + end - index)
							 << PAGE_CACHE_SHIFT,
					    0);
					did_range_unmap = 1;
				} else {
					 
					unmap_mapping_range(mapping,
					   (loff_t)index << PAGE_CACHE_SHIFT,
					   PAGE_CACHE_SIZE, 0);
				}
			}
			BUG_ON(page_mapped(page));
			ret2 = do_launder_page(mapping, page);
			if (ret2 == 0) {
				if (!invalidate_complete_page2(mapping, page))
					ret2 = -EBUSY;
			}
			if (ret2 < 0)
				ret = ret2;
			unlock_page(page);
		}
		pagevec_remove_exceptionals(&pvec);
		pagevec_release(&pvec);
		cond_resched();
		index++;
	}
	cleancache_invalidate_inode(mapping);
	return ret;
}
EXPORT_SYMBOL_GPL(invalidate_inode_pages2_range);

int invalidate_inode_pages2(struct address_space *mapping)
{
	return invalidate_inode_pages2_range(mapping, 0, -1);
}
EXPORT_SYMBOL_GPL(invalidate_inode_pages2);

void truncate_pagecache(struct inode *inode, loff_t newsize)
{
	struct address_space *mapping = inode->i_mapping;
	loff_t holebegin = round_up(newsize, PAGE_SIZE);

	unmap_mapping_range(mapping, holebegin, 0, 1);
	truncate_inode_pages(mapping, newsize);
	unmap_mapping_range(mapping, holebegin, 0, 1);
}
EXPORT_SYMBOL(truncate_pagecache);

void truncate_setsize(struct inode *inode, loff_t newsize)
{
	loff_t oldsize = inode->i_size;

	i_size_write(inode, newsize);
	if (newsize > oldsize)
		pagecache_isize_extended(inode, oldsize, newsize);
	truncate_pagecache(inode, newsize);
}
EXPORT_SYMBOL(truncate_setsize);

#ifdef MY_ABC_HERE
void ecryptfs_truncate_setsize(struct inode *inode, loff_t newsize)
{
	loff_t oldsize;

	oldsize = inode->i_size;
	i_size_write(inode, newsize);

	if (oldsize > newsize) {
		truncate_pagecache(inode, newsize);
	}
}
EXPORT_SYMBOL(ecryptfs_truncate_setsize);
#endif  

void pagecache_isize_extended(struct inode *inode, loff_t from, loff_t to)
{
	int bsize = 1 << inode->i_blkbits;
	loff_t rounded_from;
	struct page *page;
	pgoff_t index;

	WARN_ON(to > inode->i_size);

	if (from >= to || bsize == PAGE_CACHE_SIZE)
		return;
	 
	rounded_from = round_up(from, bsize);
	if (to <= rounded_from || !(rounded_from & (PAGE_CACHE_SIZE - 1)))
		return;

	index = from >> PAGE_CACHE_SHIFT;
	page = find_lock_page(inode->i_mapping, index);
	 
	if (!page)
		return;
	 
	if (page_mkclean(page))
		set_page_dirty(page);
	unlock_page(page);
	page_cache_release(page);
}
EXPORT_SYMBOL(pagecache_isize_extended);

void truncate_pagecache_range(struct inode *inode, loff_t lstart, loff_t lend)
{
	struct address_space *mapping = inode->i_mapping;
	loff_t unmap_start = round_up(lstart, PAGE_SIZE);
	loff_t unmap_end = round_down(1 + lend, PAGE_SIZE) - 1;
	 
	if ((u64)unmap_end > (u64)unmap_start)
		unmap_mapping_range(mapping, unmap_start,
				    1 + unmap_end - unmap_start, 0);
	truncate_inode_pages_range(mapping, lstart, lend);
}
EXPORT_SYMBOL(truncate_pagecache_range);
