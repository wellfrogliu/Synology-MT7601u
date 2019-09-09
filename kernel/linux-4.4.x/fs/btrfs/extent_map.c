#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/hardirq.h>
#include "ctree.h"
#include "extent_map.h"
#ifdef MY_ABC_HERE
#include "btrfs_inode.h"
#endif  
#include "compression.h"

static struct kmem_cache *extent_map_cache;

int __init extent_map_init(void)
{
	extent_map_cache = kmem_cache_create("btrfs_extent_map",
			sizeof(struct extent_map), 0,
			SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, NULL);
	if (!extent_map_cache)
		return -ENOMEM;
	return 0;
}

void extent_map_exit(void)
{
	kmem_cache_destroy(extent_map_cache);
}

void extent_map_tree_init(struct extent_map_tree *tree)
{
#ifdef MY_ABC_HERE
	atomic_set(&tree->nr_extent_maps, 0);
	INIT_LIST_HEAD(&tree->not_modified_extents);
	INIT_LIST_HEAD(&tree->syno_modified_extents);
#endif  
	tree->map = RB_ROOT;
	INIT_LIST_HEAD(&tree->modified_extents);
	rwlock_init(&tree->lock);
}

struct extent_map *alloc_extent_map(void)
{
	struct extent_map *em;
	em = kmem_cache_zalloc(extent_map_cache, GFP_NOFS);
	if (!em)
		return NULL;
	RB_CLEAR_NODE(&em->rb_node);
	em->flags = 0;
	em->compress_type = BTRFS_COMPRESS_NONE;
	em->generation = 0;
	atomic_set(&em->refs, 1);
	INIT_LIST_HEAD(&em->list);
#ifdef MY_ABC_HERE
	INIT_LIST_HEAD(&em->free_list);
#endif  
	return em;
}

void free_extent_map(struct extent_map *em)
{
	if (!em)
		return;
	WARN_ON(atomic_read(&em->refs) == 0);
	if (atomic_dec_and_test(&em->refs)) {
		WARN_ON(extent_map_in_tree(em));
		WARN_ON(!list_empty(&em->list));
#ifdef MY_ABC_HERE
		WARN_ON(!list_empty(&em->free_list));
#endif  
		if (test_bit(EXTENT_FLAG_FS_MAPPING, &em->flags))
			kfree(em->map_lookup);
		kmem_cache_free(extent_map_cache, em);
	}
}

static u64 range_end(u64 start, u64 len)
{
	if (start + len < start)
		return (u64)-1;
	return start + len;
}

static int tree_insert(struct rb_root *root, struct extent_map *em)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct extent_map *entry = NULL;
	struct rb_node *orig_parent = NULL;
	u64 end = range_end(em->start, em->len);

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct extent_map, rb_node);

		if (em->start < entry->start)
			p = &(*p)->rb_left;
		else if (em->start >= extent_map_end(entry))
			p = &(*p)->rb_right;
		else
			return -EEXIST;
	}

	orig_parent = parent;
	while (parent && em->start >= extent_map_end(entry)) {
		parent = rb_next(parent);
		entry = rb_entry(parent, struct extent_map, rb_node);
	}
	if (parent)
		if (end > entry->start && em->start < extent_map_end(entry))
			return -EEXIST;

	parent = orig_parent;
	entry = rb_entry(parent, struct extent_map, rb_node);
	while (parent && em->start < entry->start) {
		parent = rb_prev(parent);
		entry = rb_entry(parent, struct extent_map, rb_node);
	}
	if (parent)
		if (end > entry->start && em->start < extent_map_end(entry))
			return -EEXIST;

	rb_link_node(&em->rb_node, orig_parent, p);
	rb_insert_color(&em->rb_node, root);
	return 0;
}

static struct rb_node *__tree_search(struct rb_root *root, u64 offset,
				     struct rb_node **prev_ret,
				     struct rb_node **next_ret)
{
	struct rb_node *n = root->rb_node;
	struct rb_node *prev = NULL;
	struct rb_node *orig_prev = NULL;
	struct extent_map *entry;
	struct extent_map *prev_entry = NULL;

	while (n) {
		entry = rb_entry(n, struct extent_map, rb_node);
		prev = n;
		prev_entry = entry;

		if (offset < entry->start)
			n = n->rb_left;
		else if (offset >= extent_map_end(entry))
			n = n->rb_right;
		else
			return n;
	}

	if (prev_ret) {
		orig_prev = prev;
		while (prev && offset >= extent_map_end(prev_entry)) {
			prev = rb_next(prev);
			prev_entry = rb_entry(prev, struct extent_map, rb_node);
		}
		*prev_ret = prev;
		prev = orig_prev;
	}

	if (next_ret) {
		prev_entry = rb_entry(prev, struct extent_map, rb_node);
		while (prev && offset < prev_entry->start) {
			prev = rb_prev(prev);
			prev_entry = rb_entry(prev, struct extent_map, rb_node);
		}
		*next_ret = prev;
	}
	return NULL;
}

static int mergable_maps(struct extent_map *prev, struct extent_map *next)
{
	if (test_bit(EXTENT_FLAG_PINNED, &prev->flags))
		return 0;

	if (test_bit(EXTENT_FLAG_COMPRESSED, &prev->flags))
		return 0;

	if (test_bit(EXTENT_FLAG_LOGGING, &prev->flags) ||
	    test_bit(EXTENT_FLAG_LOGGING, &next->flags))
		return 0;

	if (!list_empty(&prev->list) || !list_empty(&next->list))
		return 0;

	if (extent_map_end(prev) == next->start &&
	    prev->flags == next->flags &&
	    prev->bdev == next->bdev &&
	    ((next->block_start == EXTENT_MAP_HOLE &&
	      prev->block_start == EXTENT_MAP_HOLE) ||
	     (next->block_start == EXTENT_MAP_INLINE &&
	      prev->block_start == EXTENT_MAP_INLINE) ||
	     (next->block_start == EXTENT_MAP_DELALLOC &&
	      prev->block_start == EXTENT_MAP_DELALLOC) ||
	     (next->block_start < EXTENT_MAP_LAST_BYTE - 1 &&
	      next->block_start == extent_map_block_end(prev)))) {
		return 1;
	}
	return 0;
}

#ifdef MY_ABC_HERE
static void check_and_insert_extent_map_to_global_extent(struct extent_map_tree *tree, struct extent_map *em, int modified)
{
	u64 rootid = 0;

	atomic_inc(&tree->nr_extent_maps);
	if (tree->inode && tree->inode->root && !btrfs_is_free_space_inode(&tree->inode->vfs_inode)) {
		rootid = tree->inode->root->objectid;
		if (rootid == BTRFS_FS_TREE_OBJECTID ||
			(rootid >= BTRFS_FIRST_FREE_OBJECTID && rootid <= BTRFS_LAST_FREE_OBJECTID)) {
			atomic_inc(&tree->inode->root->fs_info->nr_extent_maps);
			if (!modified) {
				list_move_tail(&em->free_list, &tree->not_modified_extents);
			} else {
				list_move_tail(&em->free_list, &tree->syno_modified_extents);
			}
			if (list_empty(&tree->inode->free_extent_map_inode)) {
				spin_lock(&tree->inode->root->fs_info->extent_map_inode_list_lock);
				list_move_tail(&tree->inode->free_extent_map_inode, &tree->inode->root->fs_info->extent_map_inode_list);
				spin_unlock(&tree->inode->root->fs_info->extent_map_inode_list_lock);
			}
		}
	}
}
static void check_and_decrease_global_extent(struct extent_map_tree *tree, struct extent_map *em)
{
	u64 rootid = 0;

	WARN_ON(atomic_read(&tree->nr_extent_maps) == 0);
	atomic_dec(&tree->nr_extent_maps);
	if (!list_empty(&em->free_list)) {
		list_del_init(&em->free_list);
	}
	if (tree->inode && tree->inode->root && !btrfs_is_free_space_inode(&tree->inode->vfs_inode)) {
		rootid = tree->inode->root->objectid;
		if (rootid == BTRFS_FS_TREE_OBJECTID ||
			(rootid >= BTRFS_FIRST_FREE_OBJECTID && rootid <= BTRFS_LAST_FREE_OBJECTID)) {
			WARN_ON(atomic_read(&(tree->inode->root->fs_info->nr_extent_maps)) == 0);
			atomic_dec(&tree->inode->root->fs_info->nr_extent_maps);
			if (atomic_read(&tree->nr_extent_maps) == 0 && !list_empty(&tree->inode->free_extent_map_inode)) {
				spin_lock(&tree->inode->root->fs_info->extent_map_inode_list_lock);
				if (atomic_read(&tree->inode->free_extent_map_counts) == 0) {
					list_del_init(&tree->inode->free_extent_map_inode);
				}
				spin_unlock(&tree->inode->root->fs_info->extent_map_inode_list_lock);
			}
		}
	}
}
#endif  

static void try_merge_map(struct extent_map_tree *tree, struct extent_map *em)
{
	struct extent_map *merge = NULL;
	struct rb_node *rb;

	if (em->start != 0) {
		rb = rb_prev(&em->rb_node);
		if (rb)
			merge = rb_entry(rb, struct extent_map, rb_node);
		if (rb && mergable_maps(merge, em)) {
			em->start = merge->start;
			em->orig_start = merge->orig_start;
			em->len += merge->len;
			em->block_len += merge->block_len;
			em->block_start = merge->block_start;
			em->mod_len = (em->mod_len + em->mod_start) - merge->mod_start;
			em->mod_start = merge->mod_start;
			em->generation = max(em->generation, merge->generation);

			rb_erase(&merge->rb_node, &tree->map);
			RB_CLEAR_NODE(&merge->rb_node);
#ifdef MY_ABC_HERE
			check_and_decrease_global_extent(tree, merge);
#endif  
			free_extent_map(merge);
		}
	}

	rb = rb_next(&em->rb_node);
	if (rb)
		merge = rb_entry(rb, struct extent_map, rb_node);
	if (rb && mergable_maps(em, merge)) {
		em->len += merge->len;
		em->block_len += merge->block_len;
		rb_erase(&merge->rb_node, &tree->map);
		RB_CLEAR_NODE(&merge->rb_node);
		em->mod_len = (merge->mod_start + merge->mod_len) - em->mod_start;
		em->generation = max(em->generation, merge->generation);
#ifdef MY_ABC_HERE
		check_and_decrease_global_extent(tree, merge);
#endif  
		free_extent_map(merge);
	}
}

int unpin_extent_cache(struct extent_map_tree *tree, u64 start, u64 len,
		       u64 gen)
{
	int ret = 0;
	struct extent_map *em;
	bool prealloc = false;

	write_lock(&tree->lock);
	em = lookup_extent_mapping(tree, start, len);

	WARN_ON(!em || em->start != start);

	if (!em)
		goto out;

	em->generation = gen;
	clear_bit(EXTENT_FLAG_PINNED, &em->flags);
	em->mod_start = em->start;
	em->mod_len = em->len;

	if (test_bit(EXTENT_FLAG_FILLING, &em->flags)) {
		prealloc = true;
		clear_bit(EXTENT_FLAG_FILLING, &em->flags);
	}

	try_merge_map(tree, em);

	if (prealloc) {
		em->mod_start = em->start;
		em->mod_len = em->len;
	}

	free_extent_map(em);
out:
	write_unlock(&tree->lock);
	return ret;

}

void clear_em_logging(struct extent_map_tree *tree, struct extent_map *em)
{
	clear_bit(EXTENT_FLAG_LOGGING, &em->flags);
	if (extent_map_in_tree(em))
		try_merge_map(tree, em);
}

static inline void setup_extent_mapping(struct extent_map_tree *tree,
					struct extent_map *em,
					int modified)
{
	atomic_inc(&em->refs);
	em->mod_start = em->start;
	em->mod_len = em->len;

	if (modified)
		list_move(&em->list, &tree->modified_extents);
	else
		try_merge_map(tree, em);
}

int add_extent_mapping(struct extent_map_tree *tree,
		       struct extent_map *em, int modified)
{
	int ret = 0;

	ret = tree_insert(&tree->map, em);
	if (ret)
		goto out;

#ifdef MY_ABC_HERE
	check_and_insert_extent_map_to_global_extent(tree, em, modified);
#endif  
	setup_extent_mapping(tree, em, modified);
out:
	return ret;
}

static struct extent_map *
__lookup_extent_mapping(struct extent_map_tree *tree,
			u64 start, u64 len, int strict)
{
	struct extent_map *em;
	struct rb_node *rb_node;
	struct rb_node *prev = NULL;
	struct rb_node *next = NULL;
	u64 end = range_end(start, len);

	rb_node = __tree_search(&tree->map, start, &prev, &next);
	if (!rb_node) {
		if (prev)
			rb_node = prev;
		else if (next)
			rb_node = next;
		else
			return NULL;
	}

	em = rb_entry(rb_node, struct extent_map, rb_node);

	if (strict && !(end > em->start && start < extent_map_end(em)))
		return NULL;

	atomic_inc(&em->refs);
	return em;
}

struct extent_map *lookup_extent_mapping(struct extent_map_tree *tree,
					 u64 start, u64 len)
{
	return __lookup_extent_mapping(tree, start, len, 1);
}

struct extent_map *search_extent_mapping(struct extent_map_tree *tree,
					 u64 start, u64 len)
{
	return __lookup_extent_mapping(tree, start, len, 0);
}

int remove_extent_mapping(struct extent_map_tree *tree, struct extent_map *em)
{
	int ret = 0;

	WARN_ON(test_bit(EXTENT_FLAG_PINNED, &em->flags));

	rb_erase(&em->rb_node, &tree->map);
	if (!test_bit(EXTENT_FLAG_LOGGING, &em->flags))
		list_del_init(&em->list);
	RB_CLEAR_NODE(&em->rb_node);

#ifdef MY_ABC_HERE
	check_and_decrease_global_extent(tree, em);
#endif  
	return ret;
}

void replace_extent_mapping(struct extent_map_tree *tree,
			    struct extent_map *cur,
			    struct extent_map *new,
			    int modified)
{
	WARN_ON(test_bit(EXTENT_FLAG_PINNED, &cur->flags));
	ASSERT(extent_map_in_tree(cur));
	if (!test_bit(EXTENT_FLAG_LOGGING, &cur->flags))
		list_del_init(&cur->list);
	rb_replace_node(&cur->rb_node, &new->rb_node, &tree->map);
	RB_CLEAR_NODE(&cur->rb_node);

#ifdef MY_ABC_HERE
	check_and_decrease_global_extent(tree, cur);
	check_and_insert_extent_map_to_global_extent(tree, new, modified);
#endif

	setup_extent_mapping(tree, new, modified);
}
