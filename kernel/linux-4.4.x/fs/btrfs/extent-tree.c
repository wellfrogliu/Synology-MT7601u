#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/sort.h>
#include <linux/rcupdate.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/ratelimit.h>
#include <linux/percpu_counter.h>
#include "hash.h"
#include "tree-log.h"
#include "disk-io.h"
#include "print-tree.h"
#include "volumes.h"
#include "raid56.h"
#include "locking.h"
#include "free-space-cache.h"
#include "free-space-tree.h"
#include "math.h"
#include "sysfs.h"
#include "qgroup.h"

#undef SCRAMBLE_DELAYED_REFS

#ifdef MY_ABC_HERE
#define READA_BLOCK_GROUP_THREAD_MAX 10
#endif  

enum {
	CHUNK_ALLOC_NO_FORCE = 0,
	CHUNK_ALLOC_LIMITED = 1,
	CHUNK_ALLOC_FORCE = 2,
};

enum {
	RESERVE_FREE = 0,
	RESERVE_ALLOC = 1,
	RESERVE_ALLOC_NO_ACCOUNT = 2,
};

static int update_block_group(struct btrfs_trans_handle *trans,
			      struct btrfs_root *root, u64 bytenr,
			      u64 num_bytes, int alloc);
static int __btrfs_free_extent(struct btrfs_trans_handle *trans,
				struct btrfs_root *root,
				struct btrfs_delayed_ref_node *node, u64 parent,
				u64 root_objectid, u64 owner_objectid,
				u64 owner_offset, int refs_to_drop,
				struct btrfs_delayed_extent_op *extra_op);
static void __run_delayed_extent_op(struct btrfs_delayed_extent_op *extent_op,
				    struct extent_buffer *leaf,
				    struct btrfs_extent_item *ei);
static int alloc_reserved_file_extent(struct btrfs_trans_handle *trans,
				      struct btrfs_root *root,
				      u64 parent, u64 root_objectid,
				      u64 flags, u64 owner, u64 offset,
				      struct btrfs_key *ins, int ref_mod);
static int alloc_reserved_tree_block(struct btrfs_trans_handle *trans,
				     struct btrfs_root *root,
				     u64 parent, u64 root_objectid,
				     u64 flags, struct btrfs_disk_key *key,
				     int level, struct btrfs_key *ins);
static int do_chunk_alloc(struct btrfs_trans_handle *trans,
			  struct btrfs_root *extent_root, u64 flags,
			  int force);
static int find_next_key(struct btrfs_path *path, int level,
			 struct btrfs_key *key);
static void dump_space_info(struct btrfs_space_info *info, u64 bytes,
			    int dump_block_groups);
static int btrfs_update_reserved_bytes(struct btrfs_block_group_cache *cache,
				       u64 num_bytes, int reserve,
				       int delalloc);
static int block_rsv_use_bytes(struct btrfs_block_rsv *block_rsv,
			       u64 num_bytes);
int btrfs_pin_extent(struct btrfs_root *root,
		     u64 bytenr, u64 num_bytes, int reserved);

static noinline int
block_group_cache_done(struct btrfs_block_group_cache *cache)
{
	smp_mb();
	return cache->cached == BTRFS_CACHE_FINISHED ||
		cache->cached == BTRFS_CACHE_ERROR;
}

static int block_group_bits(struct btrfs_block_group_cache *cache, u64 bits)
{
	return (cache->flags & bits) == bits;
}

void btrfs_get_block_group(struct btrfs_block_group_cache *cache)
{
	atomic_inc(&cache->count);
}

void btrfs_put_block_group(struct btrfs_block_group_cache *cache)
{
	if (atomic_dec_and_test(&cache->count)) {
		WARN_ON(cache->pinned > 0);
		WARN_ON(cache->reserved > 0);
		kfree(cache->free_space_ctl);
		kfree(cache);
	}
}

static int btrfs_add_block_group_cache(struct btrfs_fs_info *info,
				struct btrfs_block_group_cache *block_group)
{
	struct rb_node **p;
	struct rb_node *parent = NULL;
	struct btrfs_block_group_cache *cache;

	spin_lock(&info->block_group_cache_lock);
	p = &info->block_group_cache_tree.rb_node;

	while (*p) {
		parent = *p;
		cache = rb_entry(parent, struct btrfs_block_group_cache,
				 cache_node);
		if (block_group->key.objectid < cache->key.objectid) {
			p = &(*p)->rb_left;
		} else if (block_group->key.objectid > cache->key.objectid) {
			p = &(*p)->rb_right;
		} else {
			spin_unlock(&info->block_group_cache_lock);
			return -EEXIST;
		}
	}

	rb_link_node(&block_group->cache_node, parent, p);
	rb_insert_color(&block_group->cache_node,
			&info->block_group_cache_tree);

	if (info->first_logical_byte > block_group->key.objectid)
		info->first_logical_byte = block_group->key.objectid;

	spin_unlock(&info->block_group_cache_lock);

	return 0;
}

static struct btrfs_block_group_cache *
block_group_cache_tree_search(struct btrfs_fs_info *info, u64 bytenr,
			      int contains)
{
	struct btrfs_block_group_cache *cache, *ret = NULL;
	struct rb_node *n;
	u64 end, start;

	spin_lock(&info->block_group_cache_lock);
	n = info->block_group_cache_tree.rb_node;

	while (n) {
		cache = rb_entry(n, struct btrfs_block_group_cache,
				 cache_node);
		end = cache->key.objectid + cache->key.offset - 1;
		start = cache->key.objectid;

		if (bytenr < start) {
			if (!contains && (!ret || start < ret->key.objectid))
				ret = cache;
			n = n->rb_left;
		} else if (bytenr > start) {
			if (contains && bytenr <= end) {
				ret = cache;
				break;
			}
			n = n->rb_right;
		} else {
			ret = cache;
			break;
		}
	}
	if (ret) {
		btrfs_get_block_group(ret);
		if (bytenr == 0 && info->first_logical_byte > ret->key.objectid)
			info->first_logical_byte = ret->key.objectid;
	}
	spin_unlock(&info->block_group_cache_lock);

	return ret;
}

static int add_excluded_extent(struct btrfs_root *root,
			       u64 start, u64 num_bytes)
{
	u64 end = start + num_bytes - 1;
	set_extent_bits(&root->fs_info->freed_extents[0],
			start, end, EXTENT_UPTODATE);
	set_extent_bits(&root->fs_info->freed_extents[1],
			start, end, EXTENT_UPTODATE);
	return 0;
}

static void free_excluded_extents(struct btrfs_root *root,
				  struct btrfs_block_group_cache *cache)
{
	u64 start, end;

	start = cache->key.objectid;
	end = start + cache->key.offset - 1;

	clear_extent_bits(&root->fs_info->freed_extents[0],
			  start, end, EXTENT_UPTODATE);
	clear_extent_bits(&root->fs_info->freed_extents[1],
			  start, end, EXTENT_UPTODATE);
}

static int exclude_super_stripes(struct btrfs_root *root,
				 struct btrfs_block_group_cache *cache)
{
	u64 bytenr;
	u64 *logical;
	int stripe_len;
	int i, nr, ret;

	if (cache->key.objectid < BTRFS_SUPER_INFO_OFFSET) {
		stripe_len = BTRFS_SUPER_INFO_OFFSET - cache->key.objectid;
		cache->bytes_super += stripe_len;
		ret = add_excluded_extent(root, cache->key.objectid,
					  stripe_len);
		if (ret)
			return ret;
	}

	for (i = 0; i < BTRFS_SUPER_MIRROR_MAX; i++) {
		bytenr = btrfs_sb_offset(i);
		ret = btrfs_rmap_block(&root->fs_info->mapping_tree,
				       cache->key.objectid, bytenr,
				       0, &logical, &nr, &stripe_len);
		if (ret)
			return ret;

		while (nr--) {
			u64 start, len;

			if (logical[nr] > cache->key.objectid +
			    cache->key.offset)
				continue;

			if (logical[nr] + stripe_len <= cache->key.objectid)
				continue;

			start = logical[nr];
			if (start < cache->key.objectid) {
				start = cache->key.objectid;
				len = (logical[nr] + stripe_len) - start;
			} else {
				len = min_t(u64, stripe_len,
					    cache->key.objectid +
					    cache->key.offset - start);
			}

			cache->bytes_super += len;
			ret = add_excluded_extent(root, start, len);
			if (ret) {
				kfree(logical);
				return ret;
			}
		}

		kfree(logical);
	}
	return 0;
}

static struct btrfs_caching_control *
get_caching_control(struct btrfs_block_group_cache *cache)
{
	struct btrfs_caching_control *ctl;

	spin_lock(&cache->lock);
	if (!cache->caching_ctl) {
		spin_unlock(&cache->lock);
		return NULL;
	}

	ctl = cache->caching_ctl;
	atomic_inc(&ctl->count);
	spin_unlock(&cache->lock);
	return ctl;
}

static void put_caching_control(struct btrfs_caching_control *ctl)
{
	if (atomic_dec_and_test(&ctl->count))
		kfree(ctl);
}

#ifdef CONFIG_BTRFS_DEBUG
static void fragment_free_space(struct btrfs_root *root,
				struct btrfs_block_group_cache *block_group)
{
	u64 start = block_group->key.objectid;
	u64 len = block_group->key.offset;
	u64 chunk = block_group->flags & BTRFS_BLOCK_GROUP_METADATA ?
		root->nodesize : root->sectorsize;
	u64 step = chunk << 1;

	while (len > chunk) {
		btrfs_remove_free_space(block_group, start, chunk);
		start += step;
		if (len < step)
			len = 0;
		else
			len -= step;
	}
}
#endif

u64 add_new_free_space(struct btrfs_block_group_cache *block_group,
		       struct btrfs_fs_info *info, u64 start, u64 end)
{
	u64 extent_start, extent_end, size, total_added = 0;
	int ret;

	while (start < end) {
		ret = find_first_extent_bit(info->pinned_extents, start,
					    &extent_start, &extent_end,
					    EXTENT_DIRTY | EXTENT_UPTODATE,
					    NULL);
		if (ret)
			break;

		if (extent_start <= start) {
			start = extent_end + 1;
		} else if (extent_start > start && extent_start < end) {
			size = extent_start - start;
			total_added += size;
			ret = btrfs_add_free_space(block_group, start,
						   size);
			BUG_ON(ret);  
			start = extent_end + 1;
		} else {
			break;
		}
	}

	if (start < end) {
		size = end - start;
		total_added += size;
		ret = btrfs_add_free_space(block_group, start, size);
		BUG_ON(ret);  
	}

	return total_added;
}

static int load_extent_tree_free(struct btrfs_caching_control *caching_ctl)
{
	struct btrfs_block_group_cache *block_group;
	struct btrfs_fs_info *fs_info;
	struct btrfs_root *extent_root;
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	struct btrfs_key key;
	u64 total_found = 0;
	u64 last = 0;
	u32 nritems;
	int ret;
	bool wakeup = true;

	block_group = caching_ctl->block_group;
	fs_info = block_group->fs_info;
	extent_root = fs_info->extent_root;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	last = max_t(u64, block_group->key.objectid, BTRFS_SUPER_INFO_OFFSET);

#ifdef CONFIG_BTRFS_DEBUG
	 
	if (btrfs_should_fragment_free_space(extent_root, block_group))
		wakeup = false;
#endif
	 
	path->skip_locking = 1;
	path->search_commit_root = 1;
	path->reada = READA_FORWARD;

	key.objectid = last;
	key.offset = 0;
	key.type = BTRFS_EXTENT_ITEM_KEY;

next:
	ret = btrfs_search_slot(NULL, extent_root, &key, path, 0, 0);
	if (ret < 0)
		goto out;

	leaf = path->nodes[0];
	nritems = btrfs_header_nritems(leaf);

	while (1) {
		if (btrfs_fs_closing(fs_info) > 1) {
			last = (u64)-1;
			break;
		}

		if (path->slots[0] < nritems) {
			btrfs_item_key_to_cpu(leaf, &key, path->slots[0]);
		} else {
			ret = find_next_key(path, 0, &key);
			if (ret)
				break;

			if (need_resched() ||
			    rwsem_is_contended(&fs_info->commit_root_sem)) {
				if (wakeup)
					caching_ctl->progress = last;
				btrfs_release_path(path);
				up_read(&fs_info->commit_root_sem);
				mutex_unlock(&caching_ctl->mutex);
				cond_resched();
				mutex_lock(&caching_ctl->mutex);
				down_read(&fs_info->commit_root_sem);
				goto next;
			}

			ret = btrfs_next_leaf(extent_root, path);
			if (ret < 0)
				goto out;
			if (ret)
				break;
			leaf = path->nodes[0];
			nritems = btrfs_header_nritems(leaf);
			continue;
		}

		if (key.objectid < last) {
			key.objectid = last;
			key.offset = 0;
			key.type = BTRFS_EXTENT_ITEM_KEY;

			if (wakeup)
				caching_ctl->progress = last;
			btrfs_release_path(path);
			goto next;
		}

		if (key.objectid < block_group->key.objectid) {
			path->slots[0]++;
			continue;
		}

		if (key.objectid >= block_group->key.objectid +
		    block_group->key.offset)
			break;

		if (key.type == BTRFS_EXTENT_ITEM_KEY ||
		    key.type == BTRFS_METADATA_ITEM_KEY) {
			total_found += add_new_free_space(block_group,
							  fs_info, last,
							  key.objectid);
			if (key.type == BTRFS_METADATA_ITEM_KEY)
				last = key.objectid +
					fs_info->tree_root->nodesize;
			else
				last = key.objectid + key.offset;

			if (total_found > CACHING_CTL_WAKE_UP) {
				total_found = 0;
				if (wakeup)
					wake_up(&caching_ctl->wait);
			}
		}
		path->slots[0]++;
	}
	ret = 0;

	total_found += add_new_free_space(block_group, fs_info, last,
					  block_group->key.objectid +
					  block_group->key.offset);
	caching_ctl->progress = (u64)-1;

out:
	btrfs_free_path(path);
	return ret;
}

static noinline void caching_thread(struct btrfs_work *work)
{
	struct btrfs_block_group_cache *block_group;
	struct btrfs_fs_info *fs_info;
	struct btrfs_caching_control *caching_ctl;
	int ret;

	caching_ctl = container_of(work, struct btrfs_caching_control, work);
	block_group = caching_ctl->block_group;
	fs_info = block_group->fs_info;

	mutex_lock(&caching_ctl->mutex);
	down_read(&fs_info->commit_root_sem);

	if (btrfs_fs_compat_ro(fs_info, FREE_SPACE_TREE))
		ret = load_free_space_tree(caching_ctl);
	else
		ret = load_extent_tree_free(caching_ctl);

	spin_lock(&block_group->lock);
	block_group->caching_ctl = NULL;
	block_group->cached = ret ? BTRFS_CACHE_ERROR : BTRFS_CACHE_FINISHED;
	spin_unlock(&block_group->lock);

#ifdef CONFIG_BTRFS_DEBUG
	if (btrfs_should_fragment_free_space(extent_root, block_group)) {
		u64 bytes_used;

		spin_lock(&block_group->space_info->lock);
		spin_lock(&block_group->lock);
		bytes_used = block_group->key.offset -
			btrfs_block_group_used(&block_group->item);
		block_group->space_info->bytes_used += bytes_used >> 1;
		spin_unlock(&block_group->lock);
		spin_unlock(&block_group->space_info->lock);
		fragment_free_space(extent_root, block_group);
	}
#endif

	caching_ctl->progress = (u64)-1;

	up_read(&fs_info->commit_root_sem);
	free_excluded_extents(fs_info->extent_root, block_group);
	mutex_unlock(&caching_ctl->mutex);

	wake_up(&caching_ctl->wait);

	put_caching_control(caching_ctl);
	btrfs_put_block_group(block_group);
}

static int cache_block_group(struct btrfs_block_group_cache *cache,
			     int load_cache_only)
{
	DEFINE_WAIT(wait);
	struct btrfs_fs_info *fs_info = cache->fs_info;
	struct btrfs_caching_control *caching_ctl;
	int ret = 0;

	caching_ctl = kzalloc(sizeof(*caching_ctl), GFP_NOFS);
	if (!caching_ctl)
		return -ENOMEM;

	INIT_LIST_HEAD(&caching_ctl->list);
	mutex_init(&caching_ctl->mutex);
	init_waitqueue_head(&caching_ctl->wait);
	caching_ctl->block_group = cache;
	caching_ctl->progress = cache->key.objectid;
	atomic_set(&caching_ctl->count, 1);
	btrfs_init_work(&caching_ctl->work, btrfs_cache_helper,
			caching_thread, NULL, NULL);

	spin_lock(&cache->lock);
	 
	while (cache->cached == BTRFS_CACHE_FAST) {
		struct btrfs_caching_control *ctl;

		ctl = cache->caching_ctl;
		atomic_inc(&ctl->count);
		prepare_to_wait(&ctl->wait, &wait, TASK_UNINTERRUPTIBLE);
		spin_unlock(&cache->lock);

		schedule();

		finish_wait(&ctl->wait, &wait);
		put_caching_control(ctl);
		spin_lock(&cache->lock);
	}

	if (cache->cached != BTRFS_CACHE_NO) {
		spin_unlock(&cache->lock);
		kfree(caching_ctl);
		return 0;
	}
	WARN_ON(cache->caching_ctl);
	cache->caching_ctl = caching_ctl;
	cache->cached = BTRFS_CACHE_FAST;
	spin_unlock(&cache->lock);

	if (fs_info->mount_opt & BTRFS_MOUNT_SPACE_CACHE) {
		mutex_lock(&caching_ctl->mutex);
		ret = load_free_space_cache(fs_info, cache);

		spin_lock(&cache->lock);
		if (ret == 1) {
			cache->caching_ctl = NULL;
			cache->cached = BTRFS_CACHE_FINISHED;
			cache->last_byte_to_unpin = (u64)-1;
			caching_ctl->progress = (u64)-1;
		} else {
			if (load_cache_only) {
				cache->caching_ctl = NULL;
				cache->cached = BTRFS_CACHE_NO;
			} else {
				cache->cached = BTRFS_CACHE_STARTED;
				cache->has_caching_ctl = 1;
			}
		}
		spin_unlock(&cache->lock);
#ifdef CONFIG_BTRFS_DEBUG
		if (ret == 1 &&
		    btrfs_should_fragment_free_space(fs_info->extent_root,
						     cache)) {
			u64 bytes_used;

			spin_lock(&cache->space_info->lock);
			spin_lock(&cache->lock);
			bytes_used = cache->key.offset -
				btrfs_block_group_used(&cache->item);
			cache->space_info->bytes_used += bytes_used >> 1;
			spin_unlock(&cache->lock);
			spin_unlock(&cache->space_info->lock);
			fragment_free_space(fs_info->extent_root, cache);
		}
#endif
		mutex_unlock(&caching_ctl->mutex);

		wake_up(&caching_ctl->wait);
		if (ret == 1) {
			put_caching_control(caching_ctl);
			free_excluded_extents(fs_info->extent_root, cache);
			return 0;
		}
	} else {
		 
		spin_lock(&cache->lock);
		if (load_cache_only) {
			cache->caching_ctl = NULL;
			cache->cached = BTRFS_CACHE_NO;
		} else {
			cache->cached = BTRFS_CACHE_STARTED;
			cache->has_caching_ctl = 1;
		}
		spin_unlock(&cache->lock);
		wake_up(&caching_ctl->wait);
	}

	if (load_cache_only) {
		put_caching_control(caching_ctl);
		return 0;
	}

	down_write(&fs_info->commit_root_sem);
	atomic_inc(&caching_ctl->count);
	list_add_tail(&caching_ctl->list, &fs_info->caching_block_groups);
	up_write(&fs_info->commit_root_sem);

	btrfs_get_block_group(cache);

	btrfs_queue_work(fs_info->caching_workers, &caching_ctl->work);

	return ret;
}

static struct btrfs_block_group_cache *
btrfs_lookup_first_block_group(struct btrfs_fs_info *info, u64 bytenr)
{
	struct btrfs_block_group_cache *cache;

	cache = block_group_cache_tree_search(info, bytenr, 0);

	return cache;
}

struct btrfs_block_group_cache *btrfs_lookup_block_group(
						 struct btrfs_fs_info *info,
						 u64 bytenr)
{
	struct btrfs_block_group_cache *cache;

	cache = block_group_cache_tree_search(info, bytenr, 1);

	return cache;
}

static struct btrfs_space_info *__find_space_info(struct btrfs_fs_info *info,
						  u64 flags)
{
	struct list_head *head = &info->space_info;
	struct btrfs_space_info *found;

	flags &= BTRFS_BLOCK_GROUP_TYPE_MASK;

	rcu_read_lock();
	list_for_each_entry_rcu(found, head, list) {
		if (found->flags & flags) {
			rcu_read_unlock();
			return found;
		}
	}
	rcu_read_unlock();
	return NULL;
}

void btrfs_clear_space_info_full(struct btrfs_fs_info *info)
{
	struct list_head *head = &info->space_info;
	struct btrfs_space_info *found;

	rcu_read_lock();
	list_for_each_entry_rcu(found, head, list)
		found->full = 0;
	rcu_read_unlock();
}

int btrfs_lookup_data_extent(struct btrfs_root *root, u64 start, u64 len)
{
	int ret;
	struct btrfs_key key;
	struct btrfs_path *path;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	key.objectid = start;
	key.offset = len;
	key.type = BTRFS_EXTENT_ITEM_KEY;
	ret = btrfs_search_slot(NULL, root->fs_info->extent_root, &key, path,
				0, 0);
	btrfs_free_path(path);
	return ret;
}

int btrfs_lookup_extent_info(struct btrfs_trans_handle *trans,
			     struct btrfs_root *root, u64 bytenr,
			     u64 offset, int metadata, u64 *refs, u64 *flags)
{
	struct btrfs_delayed_ref_head *head;
	struct btrfs_delayed_ref_root *delayed_refs;
	struct btrfs_path *path;
	struct btrfs_extent_item *ei;
	struct extent_buffer *leaf;
	struct btrfs_key key;
	u32 item_size;
	u64 num_refs;
	u64 extent_flags;
	int ret;

	if (metadata && !btrfs_fs_incompat(root->fs_info, SKINNY_METADATA)) {
		offset = root->nodesize;
		metadata = 0;
	}

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	if (!trans) {
		path->skip_locking = 1;
		path->search_commit_root = 1;
	}

search_again:
	key.objectid = bytenr;
	key.offset = offset;
	if (metadata)
		key.type = BTRFS_METADATA_ITEM_KEY;
	else
		key.type = BTRFS_EXTENT_ITEM_KEY;

	ret = btrfs_search_slot(trans, root->fs_info->extent_root,
				&key, path, 0, 0);
	if (ret < 0)
		goto out_free;

	if (ret > 0 && metadata && key.type == BTRFS_METADATA_ITEM_KEY) {
		if (path->slots[0]) {
			path->slots[0]--;
			btrfs_item_key_to_cpu(path->nodes[0], &key,
					      path->slots[0]);
			if (key.objectid == bytenr &&
			    key.type == BTRFS_EXTENT_ITEM_KEY &&
			    key.offset == root->nodesize)
				ret = 0;
		}
	}

	if (ret == 0) {
		leaf = path->nodes[0];
		item_size = btrfs_item_size_nr(leaf, path->slots[0]);
		if (item_size >= sizeof(*ei)) {
			ei = btrfs_item_ptr(leaf, path->slots[0],
					    struct btrfs_extent_item);
			num_refs = btrfs_extent_refs(leaf, ei);
			extent_flags = btrfs_extent_flags(leaf, ei);
		} else {
#ifdef BTRFS_COMPAT_EXTENT_TREE_V0
			struct btrfs_extent_item_v0 *ei0;
			BUG_ON(item_size != sizeof(*ei0));
			ei0 = btrfs_item_ptr(leaf, path->slots[0],
					     struct btrfs_extent_item_v0);
			num_refs = btrfs_extent_refs_v0(leaf, ei0);
			 
			extent_flags = BTRFS_BLOCK_FLAG_FULL_BACKREF;
#else
			BUG();
#endif
		}
		BUG_ON(num_refs == 0);
	} else {
		num_refs = 0;
		extent_flags = 0;
		ret = 0;
	}

	if (!trans)
		goto out;

	delayed_refs = &trans->transaction->delayed_refs;
	spin_lock(&delayed_refs->lock);
	head = btrfs_find_delayed_ref_head(trans, bytenr);
	if (head) {
		if (!mutex_trylock(&head->mutex)) {
			atomic_inc(&head->node.refs);
			spin_unlock(&delayed_refs->lock);

			btrfs_release_path(path);

			mutex_lock(&head->mutex);
			mutex_unlock(&head->mutex);
			btrfs_put_delayed_ref(&head->node);
			goto search_again;
		}
		spin_lock(&head->lock);
		if (head->extent_op && head->extent_op->update_flags)
			extent_flags |= head->extent_op->flags_to_set;
		else
			BUG_ON(num_refs == 0);

		num_refs += head->node.ref_mod;
		spin_unlock(&head->lock);
		mutex_unlock(&head->mutex);
	}
	spin_unlock(&delayed_refs->lock);
out:
	WARN_ON(num_refs == 0);
	if (refs)
		*refs = num_refs;
	if (flags)
		*flags = extent_flags;
out_free:
	btrfs_free_path(path);
	return ret;
}

#ifdef BTRFS_COMPAT_EXTENT_TREE_V0
static int convert_extent_item_v0(struct btrfs_trans_handle *trans,
				  struct btrfs_root *root,
				  struct btrfs_path *path,
				  u64 owner, u32 extra_size)
{
	struct btrfs_extent_item *item;
	struct btrfs_extent_item_v0 *ei0;
	struct btrfs_extent_ref_v0 *ref0;
	struct btrfs_tree_block_info *bi;
	struct extent_buffer *leaf;
	struct btrfs_key key;
	struct btrfs_key found_key;
	u32 new_size = sizeof(*item);
	u64 refs;
	int ret;

	leaf = path->nodes[0];
	BUG_ON(btrfs_item_size_nr(leaf, path->slots[0]) != sizeof(*ei0));

	btrfs_item_key_to_cpu(leaf, &key, path->slots[0]);
	ei0 = btrfs_item_ptr(leaf, path->slots[0],
			     struct btrfs_extent_item_v0);
	refs = btrfs_extent_refs_v0(leaf, ei0);

	if (owner == (u64)-1) {
		while (1) {
			if (path->slots[0] >= btrfs_header_nritems(leaf)) {
				ret = btrfs_next_leaf(root, path);
				if (ret < 0)
					return ret;
				BUG_ON(ret > 0);  
				leaf = path->nodes[0];
			}
			btrfs_item_key_to_cpu(leaf, &found_key,
					      path->slots[0]);
			BUG_ON(key.objectid != found_key.objectid);
			if (found_key.type != BTRFS_EXTENT_REF_V0_KEY) {
				path->slots[0]++;
				continue;
			}
			ref0 = btrfs_item_ptr(leaf, path->slots[0],
					      struct btrfs_extent_ref_v0);
			owner = btrfs_ref_objectid_v0(leaf, ref0);
			break;
		}
	}
	btrfs_release_path(path);

	if (owner < BTRFS_FIRST_FREE_OBJECTID)
		new_size += sizeof(*bi);

	new_size -= sizeof(*ei0);
	ret = btrfs_search_slot(trans, root, &key, path,
				new_size + extra_size, 1);
	if (ret < 0)
		return ret;
	BUG_ON(ret);  

	btrfs_extend_item(root, path, new_size);

	leaf = path->nodes[0];
	item = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_extent_item);
	btrfs_set_extent_refs(leaf, item, refs);
	 
	btrfs_set_extent_generation(leaf, item, 0);
	if (owner < BTRFS_FIRST_FREE_OBJECTID) {
		btrfs_set_extent_flags(leaf, item,
				       BTRFS_EXTENT_FLAG_TREE_BLOCK |
				       BTRFS_BLOCK_FLAG_FULL_BACKREF);
		bi = (struct btrfs_tree_block_info *)(item + 1);
		 
		memset_extent_buffer(leaf, 0, (unsigned long)bi, sizeof(*bi));
		btrfs_set_tree_block_level(leaf, bi, (int)owner);
	} else {
		btrfs_set_extent_flags(leaf, item, BTRFS_EXTENT_FLAG_DATA);
	}
	btrfs_mark_buffer_dirty(leaf);
	return 0;
}
#endif

static u64 hash_extent_data_ref(u64 root_objectid, u64 owner, u64 offset)
{
	u32 high_crc = ~(u32)0;
	u32 low_crc = ~(u32)0;
	__le64 lenum;

	lenum = cpu_to_le64(root_objectid);
	high_crc = btrfs_crc32c(high_crc, &lenum, sizeof(lenum));
	lenum = cpu_to_le64(owner);
	low_crc = btrfs_crc32c(low_crc, &lenum, sizeof(lenum));
	lenum = cpu_to_le64(offset);
	low_crc = btrfs_crc32c(low_crc, &lenum, sizeof(lenum));

	return ((u64)high_crc << 31) ^ (u64)low_crc;
}

static u64 hash_extent_data_ref_item(struct extent_buffer *leaf,
				     struct btrfs_extent_data_ref *ref)
{
	return hash_extent_data_ref(btrfs_extent_data_ref_root(leaf, ref),
				    btrfs_extent_data_ref_objectid(leaf, ref),
				    btrfs_extent_data_ref_offset(leaf, ref));
}

static int match_extent_data_ref(struct extent_buffer *leaf,
				 struct btrfs_extent_data_ref *ref,
				 u64 root_objectid, u64 owner, u64 offset)
{
	if (btrfs_extent_data_ref_root(leaf, ref) != root_objectid ||
	    btrfs_extent_data_ref_objectid(leaf, ref) != owner ||
	    btrfs_extent_data_ref_offset(leaf, ref) != offset)
		return 0;
	return 1;
}

static noinline int lookup_extent_data_ref(struct btrfs_trans_handle *trans,
					   struct btrfs_root *root,
					   struct btrfs_path *path,
					   u64 bytenr, u64 parent,
					   u64 root_objectid,
					   u64 owner, u64 offset)
{
	struct btrfs_key key;
	struct btrfs_extent_data_ref *ref;
	struct extent_buffer *leaf;
	u32 nritems;
	int ret;
	int recow;
	int err = -ENOENT;

	key.objectid = bytenr;
	if (parent) {
		key.type = BTRFS_SHARED_DATA_REF_KEY;
		key.offset = parent;
	} else {
		key.type = BTRFS_EXTENT_DATA_REF_KEY;
		key.offset = hash_extent_data_ref(root_objectid,
						  owner, offset);
	}
again:
	recow = 0;
	ret = btrfs_search_slot(trans, root, &key, path, -1, 1);
	if (ret < 0) {
		err = ret;
		goto fail;
	}

	if (parent) {
		if (!ret)
			return 0;
#ifdef BTRFS_COMPAT_EXTENT_TREE_V0
		key.type = BTRFS_EXTENT_REF_V0_KEY;
		btrfs_release_path(path);
		ret = btrfs_search_slot(trans, root, &key, path, -1, 1);
		if (ret < 0) {
			err = ret;
			goto fail;
		}
		if (!ret)
			return 0;
#endif
		goto fail;
	}

	leaf = path->nodes[0];
	nritems = btrfs_header_nritems(leaf);
	while (1) {
		if (path->slots[0] >= nritems) {
			ret = btrfs_next_leaf(root, path);
			if (ret < 0)
				err = ret;
			if (ret)
				goto fail;

			leaf = path->nodes[0];
			nritems = btrfs_header_nritems(leaf);
			recow = 1;
		}

		btrfs_item_key_to_cpu(leaf, &key, path->slots[0]);
		if (key.objectid != bytenr ||
		    key.type != BTRFS_EXTENT_DATA_REF_KEY)
			goto fail;

		ref = btrfs_item_ptr(leaf, path->slots[0],
				     struct btrfs_extent_data_ref);

		if (match_extent_data_ref(leaf, ref, root_objectid,
					  owner, offset)) {
			if (recow) {
				btrfs_release_path(path);
				goto again;
			}
			err = 0;
			break;
		}
		path->slots[0]++;
	}
fail:
	return err;
}

static noinline int insert_extent_data_ref(struct btrfs_trans_handle *trans,
					   struct btrfs_root *root,
					   struct btrfs_path *path,
					   u64 bytenr, u64 parent,
					   u64 root_objectid, u64 owner,
					   u64 offset, int refs_to_add)
{
	struct btrfs_key key;
	struct extent_buffer *leaf;
	u32 size;
	u32 num_refs;
	int ret;

	key.objectid = bytenr;
	if (parent) {
		key.type = BTRFS_SHARED_DATA_REF_KEY;
		key.offset = parent;
		size = sizeof(struct btrfs_shared_data_ref);
	} else {
		key.type = BTRFS_EXTENT_DATA_REF_KEY;
		key.offset = hash_extent_data_ref(root_objectid,
						  owner, offset);
		size = sizeof(struct btrfs_extent_data_ref);
	}

	ret = btrfs_insert_empty_item(trans, root, path, &key, size);
	if (ret && ret != -EEXIST)
		goto fail;

	leaf = path->nodes[0];
	if (parent) {
		struct btrfs_shared_data_ref *ref;
		ref = btrfs_item_ptr(leaf, path->slots[0],
				     struct btrfs_shared_data_ref);
		if (ret == 0) {
			btrfs_set_shared_data_ref_count(leaf, ref, refs_to_add);
		} else {
			num_refs = btrfs_shared_data_ref_count(leaf, ref);
			num_refs += refs_to_add;
			btrfs_set_shared_data_ref_count(leaf, ref, num_refs);
		}
	} else {
		struct btrfs_extent_data_ref *ref;
		while (ret == -EEXIST) {
			ref = btrfs_item_ptr(leaf, path->slots[0],
					     struct btrfs_extent_data_ref);
			if (match_extent_data_ref(leaf, ref, root_objectid,
						  owner, offset))
				break;
			btrfs_release_path(path);
			key.offset++;
			ret = btrfs_insert_empty_item(trans, root, path, &key,
						      size);
			if (ret && ret != -EEXIST)
				goto fail;

			leaf = path->nodes[0];
		}
		ref = btrfs_item_ptr(leaf, path->slots[0],
				     struct btrfs_extent_data_ref);
		if (ret == 0) {
			btrfs_set_extent_data_ref_root(leaf, ref,
						       root_objectid);
			btrfs_set_extent_data_ref_objectid(leaf, ref, owner);
			btrfs_set_extent_data_ref_offset(leaf, ref, offset);
			btrfs_set_extent_data_ref_count(leaf, ref, refs_to_add);
		} else {
			num_refs = btrfs_extent_data_ref_count(leaf, ref);
			num_refs += refs_to_add;
			btrfs_set_extent_data_ref_count(leaf, ref, num_refs);
		}
	}
	btrfs_mark_buffer_dirty(leaf);
	ret = 0;
fail:
	btrfs_release_path(path);
	return ret;
}

static noinline int remove_extent_data_ref(struct btrfs_trans_handle *trans,
					   struct btrfs_root *root,
					   struct btrfs_path *path,
					   int refs_to_drop, int *last_ref)
{
	struct btrfs_key key;
	struct btrfs_extent_data_ref *ref1 = NULL;
	struct btrfs_shared_data_ref *ref2 = NULL;
	struct extent_buffer *leaf;
	u32 num_refs = 0;
	int ret = 0;

	leaf = path->nodes[0];
	btrfs_item_key_to_cpu(leaf, &key, path->slots[0]);

	if (key.type == BTRFS_EXTENT_DATA_REF_KEY) {
		ref1 = btrfs_item_ptr(leaf, path->slots[0],
				      struct btrfs_extent_data_ref);
		num_refs = btrfs_extent_data_ref_count(leaf, ref1);
	} else if (key.type == BTRFS_SHARED_DATA_REF_KEY) {
		ref2 = btrfs_item_ptr(leaf, path->slots[0],
				      struct btrfs_shared_data_ref);
		num_refs = btrfs_shared_data_ref_count(leaf, ref2);
#ifdef BTRFS_COMPAT_EXTENT_TREE_V0
	} else if (key.type == BTRFS_EXTENT_REF_V0_KEY) {
		struct btrfs_extent_ref_v0 *ref0;
		ref0 = btrfs_item_ptr(leaf, path->slots[0],
				      struct btrfs_extent_ref_v0);
		num_refs = btrfs_ref_count_v0(leaf, ref0);
#endif
	} else {
		BUG();
	}

	BUG_ON(num_refs < refs_to_drop);
	num_refs -= refs_to_drop;

	if (num_refs == 0) {
		ret = btrfs_del_item(trans, root, path);
		*last_ref = 1;
	} else {
		if (key.type == BTRFS_EXTENT_DATA_REF_KEY)
			btrfs_set_extent_data_ref_count(leaf, ref1, num_refs);
		else if (key.type == BTRFS_SHARED_DATA_REF_KEY)
			btrfs_set_shared_data_ref_count(leaf, ref2, num_refs);
#ifdef BTRFS_COMPAT_EXTENT_TREE_V0
		else {
			struct btrfs_extent_ref_v0 *ref0;
			ref0 = btrfs_item_ptr(leaf, path->slots[0],
					struct btrfs_extent_ref_v0);
			btrfs_set_ref_count_v0(leaf, ref0, num_refs);
		}
#endif
		btrfs_mark_buffer_dirty(leaf);
	}
	return ret;
}

static noinline u32 extent_data_ref_count(struct btrfs_path *path,
					  struct btrfs_extent_inline_ref *iref)
{
	struct btrfs_key key;
	struct extent_buffer *leaf;
	struct btrfs_extent_data_ref *ref1;
	struct btrfs_shared_data_ref *ref2;
	u32 num_refs = 0;

	leaf = path->nodes[0];
	btrfs_item_key_to_cpu(leaf, &key, path->slots[0]);
	if (iref) {
		if (btrfs_extent_inline_ref_type(leaf, iref) ==
		    BTRFS_EXTENT_DATA_REF_KEY) {
			ref1 = (struct btrfs_extent_data_ref *)(&iref->offset);
			num_refs = btrfs_extent_data_ref_count(leaf, ref1);
		} else {
			ref2 = (struct btrfs_shared_data_ref *)(iref + 1);
			num_refs = btrfs_shared_data_ref_count(leaf, ref2);
		}
	} else if (key.type == BTRFS_EXTENT_DATA_REF_KEY) {
		ref1 = btrfs_item_ptr(leaf, path->slots[0],
				      struct btrfs_extent_data_ref);
		num_refs = btrfs_extent_data_ref_count(leaf, ref1);
	} else if (key.type == BTRFS_SHARED_DATA_REF_KEY) {
		ref2 = btrfs_item_ptr(leaf, path->slots[0],
				      struct btrfs_shared_data_ref);
		num_refs = btrfs_shared_data_ref_count(leaf, ref2);
#ifdef BTRFS_COMPAT_EXTENT_TREE_V0
	} else if (key.type == BTRFS_EXTENT_REF_V0_KEY) {
		struct btrfs_extent_ref_v0 *ref0;
		ref0 = btrfs_item_ptr(leaf, path->slots[0],
				      struct btrfs_extent_ref_v0);
		num_refs = btrfs_ref_count_v0(leaf, ref0);
#endif
	} else {
		WARN_ON(1);
	}
	return num_refs;
}

static noinline int lookup_tree_block_ref(struct btrfs_trans_handle *trans,
					  struct btrfs_root *root,
					  struct btrfs_path *path,
					  u64 bytenr, u64 parent,
					  u64 root_objectid)
{
	struct btrfs_key key;
	int ret;

	key.objectid = bytenr;
	if (parent) {
		key.type = BTRFS_SHARED_BLOCK_REF_KEY;
		key.offset = parent;
	} else {
		key.type = BTRFS_TREE_BLOCK_REF_KEY;
		key.offset = root_objectid;
	}

	ret = btrfs_search_slot(trans, root, &key, path, -1, 1);
	if (ret > 0)
		ret = -ENOENT;
#ifdef BTRFS_COMPAT_EXTENT_TREE_V0
	if (ret == -ENOENT && parent) {
		btrfs_release_path(path);
		key.type = BTRFS_EXTENT_REF_V0_KEY;
		ret = btrfs_search_slot(trans, root, &key, path, -1, 1);
		if (ret > 0)
			ret = -ENOENT;
	}
#endif
	return ret;
}

static noinline int insert_tree_block_ref(struct btrfs_trans_handle *trans,
					  struct btrfs_root *root,
					  struct btrfs_path *path,
					  u64 bytenr, u64 parent,
					  u64 root_objectid)
{
	struct btrfs_key key;
	int ret;

	key.objectid = bytenr;
	if (parent) {
		key.type = BTRFS_SHARED_BLOCK_REF_KEY;
		key.offset = parent;
	} else {
		key.type = BTRFS_TREE_BLOCK_REF_KEY;
		key.offset = root_objectid;
	}

	ret = btrfs_insert_empty_item(trans, root, path, &key, 0);
	btrfs_release_path(path);
	return ret;
}

static inline int extent_ref_type(u64 parent, u64 owner)
{
	int type;
	if (owner < BTRFS_FIRST_FREE_OBJECTID) {
		if (parent > 0)
			type = BTRFS_SHARED_BLOCK_REF_KEY;
		else
			type = BTRFS_TREE_BLOCK_REF_KEY;
	} else {
		if (parent > 0)
			type = BTRFS_SHARED_DATA_REF_KEY;
		else
			type = BTRFS_EXTENT_DATA_REF_KEY;
	}
	return type;
}

static int find_next_key(struct btrfs_path *path, int level,
			 struct btrfs_key *key)

{
	for (; level < BTRFS_MAX_LEVEL; level++) {
		if (!path->nodes[level])
			break;
		if (path->slots[level] + 1 >=
		    btrfs_header_nritems(path->nodes[level]))
			continue;
		if (level == 0)
			btrfs_item_key_to_cpu(path->nodes[level], key,
					      path->slots[level] + 1);
		else
			btrfs_node_key_to_cpu(path->nodes[level], key,
					      path->slots[level] + 1);
		return 0;
	}
	return 1;
}

static noinline_for_stack
int lookup_inline_extent_backref(struct btrfs_trans_handle *trans,
				 struct btrfs_root *root,
				 struct btrfs_path *path,
				 struct btrfs_extent_inline_ref **ref_ret,
				 u64 bytenr, u64 num_bytes,
				 u64 parent, u64 root_objectid,
				 u64 owner, u64 offset, int insert)
{
	struct btrfs_key key;
	struct extent_buffer *leaf;
	struct btrfs_extent_item *ei;
	struct btrfs_extent_inline_ref *iref;
	u64 flags;
	u64 item_size;
	unsigned long ptr;
	unsigned long end;
	int extra_size;
	int type;
	int want;
	int ret;
	int err = 0;
	bool skinny_metadata = btrfs_fs_incompat(root->fs_info,
						 SKINNY_METADATA);

	key.objectid = bytenr;
	key.type = BTRFS_EXTENT_ITEM_KEY;
	key.offset = num_bytes;

	want = extent_ref_type(parent, owner);
	if (insert) {
		extra_size = btrfs_extent_inline_ref_size(want);
		path->keep_locks = 1;
	} else
		extra_size = -1;

	if (skinny_metadata && owner < BTRFS_FIRST_FREE_OBJECTID) {
		key.type = BTRFS_METADATA_ITEM_KEY;
		key.offset = owner;
	}

again:
	ret = btrfs_search_slot(trans, root, &key, path, extra_size, 1);
	if (ret < 0) {
		err = ret;
		goto out;
	}

	if (ret > 0 && skinny_metadata) {
		skinny_metadata = false;
		if (path->slots[0]) {
			path->slots[0]--;
			btrfs_item_key_to_cpu(path->nodes[0], &key,
					      path->slots[0]);
			if (key.objectid == bytenr &&
			    key.type == BTRFS_EXTENT_ITEM_KEY &&
			    key.offset == num_bytes)
				ret = 0;
		}
		if (ret) {
			key.objectid = bytenr;
			key.type = BTRFS_EXTENT_ITEM_KEY;
			key.offset = num_bytes;
			btrfs_release_path(path);
			goto again;
		}
	}

	if (ret && !insert) {
		err = -ENOENT;
		goto out;
	} else if (WARN_ON(ret)) {
		err = -EIO;
		goto out;
	}

	leaf = path->nodes[0];
	item_size = btrfs_item_size_nr(leaf, path->slots[0]);
#ifdef BTRFS_COMPAT_EXTENT_TREE_V0
	if (item_size < sizeof(*ei)) {
		if (!insert) {
			err = -ENOENT;
			goto out;
		}
		ret = convert_extent_item_v0(trans, root, path, owner,
					     extra_size);
		if (ret < 0) {
			err = ret;
			goto out;
		}
		leaf = path->nodes[0];
		item_size = btrfs_item_size_nr(leaf, path->slots[0]);
	}
#endif
	BUG_ON(item_size < sizeof(*ei));

	ei = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_extent_item);
	flags = btrfs_extent_flags(leaf, ei);

	ptr = (unsigned long)(ei + 1);
	end = (unsigned long)ei + item_size;

	if (flags & BTRFS_EXTENT_FLAG_TREE_BLOCK && !skinny_metadata) {
		ptr += sizeof(struct btrfs_tree_block_info);
		BUG_ON(ptr > end);
	}

	err = -ENOENT;
	while (1) {
		if (ptr >= end) {
			WARN_ON(ptr > end);
			break;
		}
		iref = (struct btrfs_extent_inline_ref *)ptr;
		type = btrfs_extent_inline_ref_type(leaf, iref);
		if (want < type)
			break;
		if (want > type) {
			ptr += btrfs_extent_inline_ref_size(type);
			continue;
		}

		if (type == BTRFS_EXTENT_DATA_REF_KEY) {
			struct btrfs_extent_data_ref *dref;
			dref = (struct btrfs_extent_data_ref *)(&iref->offset);
			if (match_extent_data_ref(leaf, dref, root_objectid,
						  owner, offset)) {
				err = 0;
				break;
			}
			if (hash_extent_data_ref_item(leaf, dref) <
			    hash_extent_data_ref(root_objectid, owner, offset))
				break;
		} else {
			u64 ref_offset;
			ref_offset = btrfs_extent_inline_ref_offset(leaf, iref);
			if (parent > 0) {
				if (parent == ref_offset) {
					err = 0;
					break;
				}
				if (ref_offset < parent)
					break;
			} else {
				if (root_objectid == ref_offset) {
					err = 0;
					break;
				}
				if (ref_offset < root_objectid)
					break;
			}
		}
		ptr += btrfs_extent_inline_ref_size(type);
	}
	if (err == -ENOENT && insert) {
		if (item_size + extra_size >=
		    BTRFS_MAX_EXTENT_ITEM_SIZE(root)) {
			err = -EAGAIN;
			goto out;
		}
		 
		if (find_next_key(path, 0, &key) == 0 &&
		    key.objectid == bytenr &&
		    key.type < BTRFS_BLOCK_GROUP_ITEM_KEY) {
			err = -EAGAIN;
			goto out;
		}
	}
	*ref_ret = (struct btrfs_extent_inline_ref *)ptr;
out:
	if (insert) {
		path->keep_locks = 0;
		btrfs_unlock_up_safe(path, 1);
	}
	return err;
}

static noinline_for_stack
void setup_inline_extent_backref(struct btrfs_root *root,
				 struct btrfs_path *path,
				 struct btrfs_extent_inline_ref *iref,
				 u64 parent, u64 root_objectid,
				 u64 owner, u64 offset, int refs_to_add,
				 struct btrfs_delayed_extent_op *extent_op)
{
	struct extent_buffer *leaf;
	struct btrfs_extent_item *ei;
	unsigned long ptr;
	unsigned long end;
	unsigned long item_offset;
	u64 refs;
	int size;
	int type;

	leaf = path->nodes[0];
	ei = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_extent_item);
	item_offset = (unsigned long)iref - (unsigned long)ei;

	type = extent_ref_type(parent, owner);
	size = btrfs_extent_inline_ref_size(type);

	btrfs_extend_item(root, path, size);

	ei = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_extent_item);
	refs = btrfs_extent_refs(leaf, ei);
	refs += refs_to_add;
	btrfs_set_extent_refs(leaf, ei, refs);
	if (extent_op)
		__run_delayed_extent_op(extent_op, leaf, ei);

	ptr = (unsigned long)ei + item_offset;
	end = (unsigned long)ei + btrfs_item_size_nr(leaf, path->slots[0]);
	if (ptr < end - size)
		memmove_extent_buffer(leaf, ptr + size, ptr,
				      end - size - ptr);

	iref = (struct btrfs_extent_inline_ref *)ptr;
	btrfs_set_extent_inline_ref_type(leaf, iref, type);
	if (type == BTRFS_EXTENT_DATA_REF_KEY) {
		struct btrfs_extent_data_ref *dref;
		dref = (struct btrfs_extent_data_ref *)(&iref->offset);
		btrfs_set_extent_data_ref_root(leaf, dref, root_objectid);
		btrfs_set_extent_data_ref_objectid(leaf, dref, owner);
		btrfs_set_extent_data_ref_offset(leaf, dref, offset);
		btrfs_set_extent_data_ref_count(leaf, dref, refs_to_add);
	} else if (type == BTRFS_SHARED_DATA_REF_KEY) {
		struct btrfs_shared_data_ref *sref;
		sref = (struct btrfs_shared_data_ref *)(iref + 1);
		btrfs_set_shared_data_ref_count(leaf, sref, refs_to_add);
		btrfs_set_extent_inline_ref_offset(leaf, iref, parent);
	} else if (type == BTRFS_SHARED_BLOCK_REF_KEY) {
		btrfs_set_extent_inline_ref_offset(leaf, iref, parent);
	} else {
		btrfs_set_extent_inline_ref_offset(leaf, iref, root_objectid);
	}
	btrfs_mark_buffer_dirty(leaf);
}

static int lookup_extent_backref(struct btrfs_trans_handle *trans,
				 struct btrfs_root *root,
				 struct btrfs_path *path,
				 struct btrfs_extent_inline_ref **ref_ret,
				 u64 bytenr, u64 num_bytes, u64 parent,
				 u64 root_objectid, u64 owner, u64 offset)
{
	int ret;

	ret = lookup_inline_extent_backref(trans, root, path, ref_ret,
					   bytenr, num_bytes, parent,
					   root_objectid, owner, offset, 0);
	if (ret != -ENOENT)
		return ret;

	btrfs_release_path(path);
	*ref_ret = NULL;

	if (owner < BTRFS_FIRST_FREE_OBJECTID) {
		ret = lookup_tree_block_ref(trans, root, path, bytenr, parent,
					    root_objectid);
	} else {
		ret = lookup_extent_data_ref(trans, root, path, bytenr, parent,
					     root_objectid, owner, offset);
	}
	return ret;
}

static noinline_for_stack
void update_inline_extent_backref(struct btrfs_root *root,
				  struct btrfs_path *path,
				  struct btrfs_extent_inline_ref *iref,
				  int refs_to_mod,
				  struct btrfs_delayed_extent_op *extent_op,
				  int *last_ref)
{
	struct extent_buffer *leaf;
	struct btrfs_extent_item *ei;
	struct btrfs_extent_data_ref *dref = NULL;
	struct btrfs_shared_data_ref *sref = NULL;
	unsigned long ptr;
	unsigned long end;
	u32 item_size;
	int size;
	int type;
	u64 refs;

	leaf = path->nodes[0];
	ei = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_extent_item);
	refs = btrfs_extent_refs(leaf, ei);
	WARN_ON(refs_to_mod < 0 && refs + refs_to_mod <= 0);
	refs += refs_to_mod;
	btrfs_set_extent_refs(leaf, ei, refs);
	if (extent_op)
		__run_delayed_extent_op(extent_op, leaf, ei);

	type = btrfs_extent_inline_ref_type(leaf, iref);

	if (type == BTRFS_EXTENT_DATA_REF_KEY) {
		dref = (struct btrfs_extent_data_ref *)(&iref->offset);
		refs = btrfs_extent_data_ref_count(leaf, dref);
	} else if (type == BTRFS_SHARED_DATA_REF_KEY) {
		sref = (struct btrfs_shared_data_ref *)(iref + 1);
		refs = btrfs_shared_data_ref_count(leaf, sref);
	} else {
		refs = 1;
		BUG_ON(refs_to_mod != -1);
	}

	BUG_ON(refs_to_mod < 0 && refs < -refs_to_mod);
	refs += refs_to_mod;

	if (refs > 0) {
		if (type == BTRFS_EXTENT_DATA_REF_KEY)
			btrfs_set_extent_data_ref_count(leaf, dref, refs);
		else
			btrfs_set_shared_data_ref_count(leaf, sref, refs);
	} else {
		*last_ref = 1;
		size =  btrfs_extent_inline_ref_size(type);
		item_size = btrfs_item_size_nr(leaf, path->slots[0]);
		ptr = (unsigned long)iref;
		end = (unsigned long)ei + item_size;
		if (ptr + size < end)
			memmove_extent_buffer(leaf, ptr, ptr + size,
					      end - ptr - size);
		item_size -= size;
		btrfs_truncate_item(root, path, item_size, 1);
	}
	btrfs_mark_buffer_dirty(leaf);
}

static noinline_for_stack
int insert_inline_extent_backref(struct btrfs_trans_handle *trans,
				 struct btrfs_root *root,
				 struct btrfs_path *path,
				 u64 bytenr, u64 num_bytes, u64 parent,
				 u64 root_objectid, u64 owner,
				 u64 offset, int refs_to_add,
				 struct btrfs_delayed_extent_op *extent_op)
{
	struct btrfs_extent_inline_ref *iref;
	int ret;

	ret = lookup_inline_extent_backref(trans, root, path, &iref,
					   bytenr, num_bytes, parent,
					   root_objectid, owner, offset, 1);
	if (ret == 0) {
		BUG_ON(owner < BTRFS_FIRST_FREE_OBJECTID);
		update_inline_extent_backref(root, path, iref,
					     refs_to_add, extent_op, NULL);
	} else if (ret == -ENOENT) {
		setup_inline_extent_backref(root, path, iref, parent,
					    root_objectid, owner, offset,
					    refs_to_add, extent_op);
		ret = 0;
	}
	return ret;
}

static int insert_extent_backref(struct btrfs_trans_handle *trans,
				 struct btrfs_root *root,
				 struct btrfs_path *path,
				 u64 bytenr, u64 parent, u64 root_objectid,
				 u64 owner, u64 offset, int refs_to_add)
{
	int ret;
	if (owner < BTRFS_FIRST_FREE_OBJECTID) {
		BUG_ON(refs_to_add != 1);
		ret = insert_tree_block_ref(trans, root, path, bytenr,
					    parent, root_objectid);
	} else {
		ret = insert_extent_data_ref(trans, root, path, bytenr,
					     parent, root_objectid,
					     owner, offset, refs_to_add);
	}
	return ret;
}

static int remove_extent_backref(struct btrfs_trans_handle *trans,
				 struct btrfs_root *root,
				 struct btrfs_path *path,
				 struct btrfs_extent_inline_ref *iref,
				 int refs_to_drop, int is_data, int *last_ref)
{
	int ret = 0;

	BUG_ON(!is_data && refs_to_drop != 1);
	if (iref) {
		update_inline_extent_backref(root, path, iref,
					     -refs_to_drop, NULL, last_ref);
	} else if (is_data) {
		ret = remove_extent_data_ref(trans, root, path, refs_to_drop,
					     last_ref);
	} else {
		*last_ref = 1;
		ret = btrfs_del_item(trans, root, path);
	}
	return ret;
}

#define in_range(b, first, len)        ((b) >= (first) && (b) < (first) + (len))
static int btrfs_issue_discard(struct block_device *bdev, u64 start, u64 len,
			       u64 *discarded_bytes)
{
	int j, ret = 0;
	u64 bytes_left, end;
	u64 aligned_start = ALIGN(start, 1 << 9);

	if (WARN_ON(start != aligned_start)) {
		len -= aligned_start - start;
		len = round_down(len, 1 << 9);
		start = aligned_start;
	}

	*discarded_bytes = 0;

	if (!len)
		return 0;

	end = start + len;
	bytes_left = len;

	for (j = 0; j < BTRFS_SUPER_MIRROR_MAX; j++) {
		u64 sb_start = btrfs_sb_offset(j);
		u64 sb_end = sb_start + BTRFS_SUPER_INFO_SIZE;
		u64 size = sb_start - start;

		if (!in_range(sb_start, start, bytes_left) &&
		    !in_range(sb_end, start, bytes_left) &&
		    !in_range(start, sb_start, BTRFS_SUPER_INFO_SIZE))
			continue;

		if (sb_start <= start) {
			start += sb_end - start;
			if (start > end) {
				bytes_left = 0;
				break;
			}
			bytes_left = end - start;
			continue;
		}

		if (size) {
			ret = blkdev_issue_discard(bdev, start >> 9, size >> 9,
						   GFP_NOFS, 0);
			if (!ret)
				*discarded_bytes += size;
			else if (ret != -EOPNOTSUPP)
				return ret;
		}

		start = sb_end;
		if (start > end) {
			bytes_left = 0;
			break;
		}
		bytes_left = end - start;
	}

	if (bytes_left) {
		ret = blkdev_issue_discard(bdev, start >> 9, bytes_left >> 9,
					   GFP_NOFS, 0);
		if (!ret)
			*discarded_bytes += bytes_left;
	}
	return ret;
}

int btrfs_discard_extent(struct btrfs_root *root, u64 bytenr,
			 u64 num_bytes, u64 *actual_bytes)
{
	int ret;
	u64 discarded_bytes = 0;
	struct btrfs_bio *bbio = NULL;

	ret = btrfs_map_block(root->fs_info, REQ_DISCARD,
			      bytenr, &num_bytes, &bbio, 0);
	 
	if (!ret) {
		struct btrfs_bio_stripe *stripe = bbio->stripes;
		int i;

		for (i = 0; i < bbio->num_stripes; i++, stripe++) {
			u64 bytes;
			if (!stripe->dev->can_discard)
				continue;

			ret = btrfs_issue_discard(stripe->dev->bdev,
						  stripe->physical,
						  stripe->length,
						  &bytes);
			if (!ret)
				discarded_bytes += bytes;
			else if (ret != -EOPNOTSUPP)
				break;  

			ret = 0;
		}
		btrfs_put_bbio(bbio);
	}

	if (actual_bytes)
		*actual_bytes = discarded_bytes;

	if (ret == -EOPNOTSUPP)
		ret = 0;
	return ret;
}

int btrfs_inc_extent_ref(struct btrfs_trans_handle *trans,
			 struct btrfs_root *root,
			 u64 bytenr, u64 num_bytes, u64 parent,
			 u64 root_objectid, u64 owner, u64 offset)
{
	int ret;
	struct btrfs_fs_info *fs_info = root->fs_info;

	BUG_ON(owner < BTRFS_FIRST_FREE_OBJECTID &&
	       root_objectid == BTRFS_TREE_LOG_OBJECTID);

	if (owner < BTRFS_FIRST_FREE_OBJECTID) {
		ret = btrfs_add_delayed_tree_ref(fs_info, trans, bytenr,
					num_bytes,
					parent, root_objectid, (int)owner,
					BTRFS_ADD_DELAYED_REF, NULL);
	} else {
		ret = btrfs_add_delayed_data_ref(fs_info, trans, bytenr,
					num_bytes, parent, root_objectid,
					owner, offset, 0,
					BTRFS_ADD_DELAYED_REF, NULL);
	}
	return ret;
}

static int __btrfs_inc_extent_ref(struct btrfs_trans_handle *trans,
				  struct btrfs_root *root,
				  struct btrfs_delayed_ref_node *node,
				  u64 parent, u64 root_objectid,
				  u64 owner, u64 offset, int refs_to_add,
				  struct btrfs_delayed_extent_op *extent_op)
{
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	struct btrfs_extent_item *item;
	struct btrfs_key key;
	u64 bytenr = node->bytenr;
	u64 num_bytes = node->num_bytes;
	u64 refs;
	int ret;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	path->reada = READA_FORWARD;
	path->leave_spinning = 1;
	 
	ret = insert_inline_extent_backref(trans, fs_info->extent_root, path,
					   bytenr, num_bytes, parent,
					   root_objectid, owner, offset,
					   refs_to_add, extent_op);
	if ((ret < 0 && ret != -EAGAIN) || !ret)
		goto out;

	leaf = path->nodes[0];
	btrfs_item_key_to_cpu(leaf, &key, path->slots[0]);
	item = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_extent_item);
	refs = btrfs_extent_refs(leaf, item);
	btrfs_set_extent_refs(leaf, item, refs + refs_to_add);
	if (extent_op)
		__run_delayed_extent_op(extent_op, leaf, item);

	btrfs_mark_buffer_dirty(leaf);
	btrfs_release_path(path);

	path->reada = READA_FORWARD;
	path->leave_spinning = 1;
	 
	ret = insert_extent_backref(trans, root->fs_info->extent_root,
				    path, bytenr, parent, root_objectid,
				    owner, offset, refs_to_add);
	if (ret)
		btrfs_abort_transaction(trans, root, ret);
out:
	btrfs_free_path(path);
	return ret;
}

static int run_delayed_data_ref(struct btrfs_trans_handle *trans,
				struct btrfs_root *root,
				struct btrfs_delayed_ref_node *node,
				struct btrfs_delayed_extent_op *extent_op,
				int insert_reserved)
{
	int ret = 0;
	struct btrfs_delayed_data_ref *ref;
	struct btrfs_key ins;
	u64 parent = 0;
	u64 ref_root = 0;
	u64 flags = 0;

	ins.objectid = node->bytenr;
	ins.offset = node->num_bytes;
	ins.type = BTRFS_EXTENT_ITEM_KEY;

	ref = btrfs_delayed_node_to_data_ref(node);
	trace_run_delayed_data_ref(node, ref, node->action);

	if (node->type == BTRFS_SHARED_DATA_REF_KEY)
		parent = ref->parent;
	ref_root = ref->root;

	if (node->action == BTRFS_ADD_DELAYED_REF && insert_reserved) {
		if (extent_op)
			flags |= extent_op->flags_to_set;
		ret = alloc_reserved_file_extent(trans, root,
						 parent, ref_root, flags,
						 ref->objectid, ref->offset,
						 &ins, node->ref_mod);
	} else if (node->action == BTRFS_ADD_DELAYED_REF) {
		ret = __btrfs_inc_extent_ref(trans, root, node, parent,
					     ref_root, ref->objectid,
					     ref->offset, node->ref_mod,
					     extent_op);
	} else if (node->action == BTRFS_DROP_DELAYED_REF) {
		ret = __btrfs_free_extent(trans, root, node, parent,
					  ref_root, ref->objectid,
					  ref->offset, node->ref_mod,
					  extent_op);
	} else {
		BUG();
	}
	return ret;
}

static void __run_delayed_extent_op(struct btrfs_delayed_extent_op *extent_op,
				    struct extent_buffer *leaf,
				    struct btrfs_extent_item *ei)
{
	u64 flags = btrfs_extent_flags(leaf, ei);
	if (extent_op->update_flags) {
		flags |= extent_op->flags_to_set;
		btrfs_set_extent_flags(leaf, ei, flags);
	}

	if (extent_op->update_key) {
		struct btrfs_tree_block_info *bi;
		BUG_ON(!(flags & BTRFS_EXTENT_FLAG_TREE_BLOCK));
		bi = (struct btrfs_tree_block_info *)(ei + 1);
		btrfs_set_tree_block_key(leaf, bi, &extent_op->key);
	}
}

static int run_delayed_extent_op(struct btrfs_trans_handle *trans,
				 struct btrfs_root *root,
				 struct btrfs_delayed_ref_node *node,
				 struct btrfs_delayed_extent_op *extent_op)
{
	struct btrfs_key key;
	struct btrfs_path *path;
	struct btrfs_extent_item *ei;
	struct extent_buffer *leaf;
	u32 item_size;
	int ret;
	int err = 0;
	int metadata = !extent_op->is_data;

	if (trans->aborted)
		return 0;

	if (metadata && !btrfs_fs_incompat(root->fs_info, SKINNY_METADATA))
		metadata = 0;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	key.objectid = node->bytenr;

	if (metadata) {
		key.type = BTRFS_METADATA_ITEM_KEY;
		key.offset = extent_op->level;
	} else {
		key.type = BTRFS_EXTENT_ITEM_KEY;
		key.offset = node->num_bytes;
	}

again:
	path->reada = READA_FORWARD;
	path->leave_spinning = 1;
	ret = btrfs_search_slot(trans, root->fs_info->extent_root, &key,
				path, 0, 1);
	if (ret < 0) {
		err = ret;
		goto out;
	}
	if (ret > 0) {
		if (metadata) {
			if (path->slots[0] > 0) {
				path->slots[0]--;
				btrfs_item_key_to_cpu(path->nodes[0], &key,
						      path->slots[0]);
				if (key.objectid == node->bytenr &&
				    key.type == BTRFS_EXTENT_ITEM_KEY &&
				    key.offset == node->num_bytes)
					ret = 0;
			}
			if (ret > 0) {
				btrfs_release_path(path);
				metadata = 0;

				key.objectid = node->bytenr;
				key.offset = node->num_bytes;
				key.type = BTRFS_EXTENT_ITEM_KEY;
				goto again;
			}
		} else {
			err = -EIO;
			goto out;
		}
	}

	leaf = path->nodes[0];
	item_size = btrfs_item_size_nr(leaf, path->slots[0]);
#ifdef BTRFS_COMPAT_EXTENT_TREE_V0
	if (item_size < sizeof(*ei)) {
		ret = convert_extent_item_v0(trans, root->fs_info->extent_root,
					     path, (u64)-1, 0);
		if (ret < 0) {
			err = ret;
			goto out;
		}
		leaf = path->nodes[0];
		item_size = btrfs_item_size_nr(leaf, path->slots[0]);
	}
#endif
	BUG_ON(item_size < sizeof(*ei));
	ei = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_extent_item);
	__run_delayed_extent_op(extent_op, leaf, ei);

	btrfs_mark_buffer_dirty(leaf);
out:
	btrfs_free_path(path);
	return err;
}

static int run_delayed_tree_ref(struct btrfs_trans_handle *trans,
				struct btrfs_root *root,
				struct btrfs_delayed_ref_node *node,
				struct btrfs_delayed_extent_op *extent_op,
				int insert_reserved)
{
	int ret = 0;
	struct btrfs_delayed_tree_ref *ref;
	struct btrfs_key ins;
	u64 parent = 0;
	u64 ref_root = 0;
	bool skinny_metadata = btrfs_fs_incompat(root->fs_info,
						 SKINNY_METADATA);

	ref = btrfs_delayed_node_to_tree_ref(node);
	trace_run_delayed_tree_ref(node, ref, node->action);

	if (node->type == BTRFS_SHARED_BLOCK_REF_KEY)
		parent = ref->parent;
	ref_root = ref->root;

	ins.objectid = node->bytenr;
	if (skinny_metadata) {
		ins.offset = ref->level;
		ins.type = BTRFS_METADATA_ITEM_KEY;
	} else {
		ins.offset = node->num_bytes;
		ins.type = BTRFS_EXTENT_ITEM_KEY;
	}

	BUG_ON(node->ref_mod != 1);
	if (node->action == BTRFS_ADD_DELAYED_REF && insert_reserved) {
		BUG_ON(!extent_op || !extent_op->update_flags);
		ret = alloc_reserved_tree_block(trans, root,
						parent, ref_root,
						extent_op->flags_to_set,
						&extent_op->key,
						ref->level, &ins);
	} else if (node->action == BTRFS_ADD_DELAYED_REF) {
		ret = __btrfs_inc_extent_ref(trans, root, node,
					     parent, ref_root,
					     ref->level, 0, 1,
					     extent_op);
	} else if (node->action == BTRFS_DROP_DELAYED_REF) {
		ret = __btrfs_free_extent(trans, root, node,
					  parent, ref_root,
					  ref->level, 0, 1, extent_op);
	} else {
		BUG();
	}
	return ret;
}

static int run_one_delayed_ref(struct btrfs_trans_handle *trans,
			       struct btrfs_root *root,
			       struct btrfs_delayed_ref_node *node,
			       struct btrfs_delayed_extent_op *extent_op,
			       int insert_reserved)
{
	int ret = 0;

	if (trans->aborted) {
		if (insert_reserved)
			btrfs_pin_extent(root, node->bytenr,
					 node->num_bytes, 1);
		return 0;
	}

	if (btrfs_delayed_ref_is_head(node)) {
		struct btrfs_delayed_ref_head *head;
		 
		BUG_ON(extent_op);
		head = btrfs_delayed_node_to_head(node);
		trace_run_delayed_ref_head(node, head, node->action);

		if (insert_reserved) {
			btrfs_pin_extent(root, node->bytenr,
					 node->num_bytes, 1);
			if (head->is_data) {
				ret = btrfs_del_csums(trans, root,
						      node->bytenr,
						      node->num_bytes);
			}
		}

		btrfs_qgroup_free_delayed_ref(root->fs_info,
					      head->qgroup_ref_root,
					      head->qgroup_reserved);
		return ret;
	}

	if (node->type == BTRFS_TREE_BLOCK_REF_KEY ||
	    node->type == BTRFS_SHARED_BLOCK_REF_KEY)
		ret = run_delayed_tree_ref(trans, root, node, extent_op,
					   insert_reserved);
	else if (node->type == BTRFS_EXTENT_DATA_REF_KEY ||
		 node->type == BTRFS_SHARED_DATA_REF_KEY)
		ret = run_delayed_data_ref(trans, root, node, extent_op,
					   insert_reserved);
	else
		BUG();
	return ret;
}

static inline struct btrfs_delayed_ref_node *
select_delayed_ref(struct btrfs_delayed_ref_head *head)
{
	struct btrfs_delayed_ref_node *ref;

	if (list_empty(&head->ref_list))
		return NULL;

	if (!list_empty(&head->ref_add_list))
		return list_first_entry(&head->ref_add_list,
				struct btrfs_delayed_ref_node, add_list);

	ref = list_first_entry(&head->ref_list, struct btrfs_delayed_ref_node,
			       list);
	ASSERT(list_empty(&ref->add_list));
	return ref;
}

static noinline int __btrfs_run_delayed_refs(struct btrfs_trans_handle *trans,
					     struct btrfs_root *root,
					     unsigned long nr)
{
	struct btrfs_delayed_ref_root *delayed_refs;
	struct btrfs_delayed_ref_node *ref;
	struct btrfs_delayed_ref_head *locked_ref = NULL;
	struct btrfs_delayed_extent_op *extent_op;
	struct btrfs_fs_info *fs_info = root->fs_info;
	ktime_t start = ktime_get();
	int ret;
	unsigned long count = 0;
	unsigned long actual_count = 0;
	int must_insert_reserved = 0;

	delayed_refs = &trans->transaction->delayed_refs;
	while (1) {
		if (!locked_ref) {
			if (count >= nr)
				break;

			spin_lock(&delayed_refs->lock);
			locked_ref = btrfs_select_ref_head(trans);
			if (!locked_ref) {
				spin_unlock(&delayed_refs->lock);
				break;
			}

			ret = btrfs_delayed_ref_lock(trans, locked_ref);
			spin_unlock(&delayed_refs->lock);
			 
			if (ret == -EAGAIN) {
				locked_ref = NULL;
				count++;
				continue;
			}
		}

		spin_lock(&locked_ref->lock);
		btrfs_merge_delayed_refs(trans, fs_info, delayed_refs,
					 locked_ref);

		ref = select_delayed_ref(locked_ref);

		if (ref && ref->seq &&
		    btrfs_check_delayed_seq(fs_info, delayed_refs, ref->seq)) {
			spin_unlock(&locked_ref->lock);
			spin_lock(&delayed_refs->lock);
			locked_ref->processing = 0;
			delayed_refs->num_heads_ready++;
			spin_unlock(&delayed_refs->lock);
			btrfs_delayed_ref_unlock(locked_ref);
			locked_ref = NULL;
			cond_resched();
			count++;
			continue;
		}

		must_insert_reserved = locked_ref->must_insert_reserved;
		locked_ref->must_insert_reserved = 0;

		extent_op = locked_ref->extent_op;
		locked_ref->extent_op = NULL;

		if (!ref) {

			ref = &locked_ref->node;

			if (extent_op && must_insert_reserved) {
				btrfs_free_delayed_extent_op(extent_op);
				extent_op = NULL;
			}

			if (extent_op) {
				spin_unlock(&locked_ref->lock);
				ret = run_delayed_extent_op(trans, root,
							    ref, extent_op);
				btrfs_free_delayed_extent_op(extent_op);

				if (ret) {
					 
					if (must_insert_reserved)
						locked_ref->must_insert_reserved = 1;
					spin_lock(&delayed_refs->lock);
					locked_ref->processing = 0;
					delayed_refs->num_heads_ready++;
					spin_unlock(&delayed_refs->lock);
					btrfs_debug(fs_info, "run_delayed_extent_op returned %d", ret);
					btrfs_delayed_ref_unlock(locked_ref);
					return ret;
				}
				continue;
			}

			spin_unlock(&locked_ref->lock);
			spin_lock(&delayed_refs->lock);
			spin_lock(&locked_ref->lock);
			if (!list_empty(&locked_ref->ref_list) ||
			    locked_ref->extent_op) {
				spin_unlock(&locked_ref->lock);
				spin_unlock(&delayed_refs->lock);
				continue;
			}
			ref->in_tree = 0;
			delayed_refs->num_heads--;
			rb_erase(&locked_ref->href_node,
				 &delayed_refs->href_root);
			spin_unlock(&delayed_refs->lock);
		} else {
			actual_count++;
			ref->in_tree = 0;
			list_del(&ref->list);
			if (!list_empty(&ref->add_list))
				list_del(&ref->add_list);
		}
		atomic_dec(&delayed_refs->num_entries);

		if (!btrfs_delayed_ref_is_head(ref)) {
			 
			switch (ref->action) {
			case BTRFS_ADD_DELAYED_REF:
			case BTRFS_ADD_DELAYED_EXTENT:
				locked_ref->node.ref_mod -= ref->ref_mod;
				break;
			case BTRFS_DROP_DELAYED_REF:
				locked_ref->node.ref_mod += ref->ref_mod;
				break;
			default:
				WARN_ON(1);
			}
		}
		spin_unlock(&locked_ref->lock);

		ret = run_one_delayed_ref(trans, root, ref, extent_op,
					  must_insert_reserved);

		btrfs_free_delayed_extent_op(extent_op);
		if (ret) {
			spin_lock(&delayed_refs->lock);
			locked_ref->processing = 0;
			delayed_refs->num_heads_ready++;
			spin_unlock(&delayed_refs->lock);
			btrfs_delayed_ref_unlock(locked_ref);
			btrfs_put_delayed_ref(ref);
			btrfs_debug(fs_info, "run_one_delayed_ref returned %d", ret);
			return ret;
		}

		if (btrfs_delayed_ref_is_head(ref)) {
			if (locked_ref->is_data &&
			    locked_ref->total_ref_mod < 0) {
				spin_lock(&delayed_refs->lock);
				delayed_refs->pending_csums -= ref->num_bytes;
				spin_unlock(&delayed_refs->lock);
			}
			btrfs_delayed_ref_unlock(locked_ref);
			locked_ref = NULL;
		}
		btrfs_put_delayed_ref(ref);
		count++;
		cond_resched();
	}

	if (actual_count > 0) {
		u64 runtime = ktime_to_ns(ktime_sub(ktime_get(), start));
		u64 avg;

		spin_lock(&delayed_refs->lock);
		avg = fs_info->avg_delayed_ref_runtime * 3 + runtime;
		fs_info->avg_delayed_ref_runtime = avg >> 2;	 
		spin_unlock(&delayed_refs->lock);
	}
	return 0;
}

#ifdef SCRAMBLE_DELAYED_REFS
 
static u64 find_middle(struct rb_root *root)
{
	struct rb_node *n = root->rb_node;
	struct btrfs_delayed_ref_node *entry;
	int alt = 1;
	u64 middle;
	u64 first = 0, last = 0;

	n = rb_first(root);
	if (n) {
		entry = rb_entry(n, struct btrfs_delayed_ref_node, rb_node);
		first = entry->bytenr;
	}
	n = rb_last(root);
	if (n) {
		entry = rb_entry(n, struct btrfs_delayed_ref_node, rb_node);
		last = entry->bytenr;
	}
	n = root->rb_node;

	while (n) {
		entry = rb_entry(n, struct btrfs_delayed_ref_node, rb_node);
		WARN_ON(!entry->in_tree);

		middle = entry->bytenr;

		if (alt)
			n = n->rb_left;
		else
			n = n->rb_right;

		alt = 1 - alt;
	}
	return middle;
}
#endif

static inline u64 heads_to_leaves(struct btrfs_root *root, u64 heads)
{
	u64 num_bytes;

	num_bytes = heads * (sizeof(struct btrfs_extent_item) +
			     sizeof(struct btrfs_extent_inline_ref));
	if (!btrfs_fs_incompat(root->fs_info, SKINNY_METADATA))
		num_bytes += heads * sizeof(struct btrfs_tree_block_info);

	return div_u64(num_bytes, BTRFS_LEAF_DATA_SIZE(root));
}

u64 btrfs_csum_bytes_to_leaves(struct btrfs_root *root, u64 csum_bytes)
{
	u64 csum_size;
	u64 num_csums_per_leaf;
	u64 num_csums;

	csum_size = BTRFS_LEAF_DATA_SIZE(root) - sizeof(struct btrfs_item);
	num_csums_per_leaf = div64_u64(csum_size,
			(u64)btrfs_super_csum_size(root->fs_info->super_copy));
	num_csums = div64_u64(csum_bytes, root->sectorsize);
	num_csums += num_csums_per_leaf - 1;
	num_csums = div64_u64(num_csums, num_csums_per_leaf);
	return num_csums;
}

int btrfs_check_space_for_delayed_refs(struct btrfs_trans_handle *trans,
				       struct btrfs_root *root)
{
	struct btrfs_block_rsv *global_rsv;
	u64 num_heads = trans->transaction->delayed_refs.num_heads_ready;
	u64 csum_bytes = trans->transaction->delayed_refs.pending_csums;
	u64 num_dirty_bgs = trans->transaction->num_dirty_bgs;
	u64 num_bytes, num_dirty_bgs_bytes;
	int ret = 0;

	num_bytes = btrfs_calc_trans_metadata_size(root, 1);
	num_heads = heads_to_leaves(root, num_heads);
	if (num_heads > 1)
		num_bytes += (num_heads - 1) * root->nodesize;
	num_bytes <<= 1;
	num_bytes += btrfs_csum_bytes_to_leaves(root, csum_bytes) * root->nodesize;
	num_dirty_bgs_bytes = btrfs_calc_trans_metadata_size(root,
							     num_dirty_bgs);
	global_rsv = &root->fs_info->global_block_rsv;

	if (global_rsv->space_info->full) {
		num_dirty_bgs_bytes <<= 1;
		num_bytes <<= 1;
	}

	spin_lock(&global_rsv->lock);
	if (global_rsv->reserved <= num_bytes + num_dirty_bgs_bytes)
		ret = 1;
	spin_unlock(&global_rsv->lock);
	return ret;
}

int btrfs_should_throttle_delayed_refs(struct btrfs_trans_handle *trans,
				       struct btrfs_root *root)
{
	struct btrfs_fs_info *fs_info = root->fs_info;
	u64 num_entries =
		atomic_read(&trans->transaction->delayed_refs.num_entries);
	u64 avg_runtime;
	u64 val;

	smp_mb();
	avg_runtime = fs_info->avg_delayed_ref_runtime;
	val = num_entries * avg_runtime;
	if (num_entries * avg_runtime >= NSEC_PER_SEC)
		return 1;
	if (val >= NSEC_PER_SEC / 2)
		return 2;

	return btrfs_check_space_for_delayed_refs(trans, root);
}

struct async_delayed_refs {
	struct btrfs_root *root;
	u64 transid;
	int count;
	int error;
	int sync;
	struct completion wait;
	struct btrfs_work work;
};

static void delayed_ref_async_start(struct btrfs_work *work)
{
	struct async_delayed_refs *async;
	struct btrfs_trans_handle *trans;
	int ret;

	async = container_of(work, struct async_delayed_refs, work);

#ifdef MY_ABC_HERE
#else
	 
	if (btrfs_transaction_blocked(async->root->fs_info))
		goto done;
#endif  

	trans = btrfs_join_transaction(async->root);
	if (IS_ERR(trans)) {
		async->error = PTR_ERR(trans);
		goto done;
	}

	trans->sync = true;

#ifdef MY_ABC_HERE
#else
	 
	if (trans->transid > async->transid)
		goto end;
#endif  

	ret = btrfs_run_delayed_refs(trans, async->root, async->count);
	if (ret)
		async->error = ret;
#ifdef MY_ABC_HERE
#else
end:
#endif  
	ret = btrfs_end_transaction(trans, async->root);
	if (ret && !async->error)
		async->error = ret;
done:
	if (async->sync)
		complete(&async->wait);
	else
		kfree(async);
}

int btrfs_async_run_delayed_refs(struct btrfs_root *root,
				 unsigned long count, u64 transid, int wait)
{
	struct async_delayed_refs *async;
	int ret;

	async = kmalloc(sizeof(*async), GFP_NOFS);
	if (!async)
		return -ENOMEM;

	async->root = root->fs_info->tree_root;
	async->count = count;
	async->error = 0;
	async->transid = transid;
	if (wait)
		async->sync = 1;
	else
		async->sync = 0;
	init_completion(&async->wait);

	btrfs_init_work(&async->work, btrfs_extent_refs_helper,
			delayed_ref_async_start, NULL, NULL);

	btrfs_queue_work(root->fs_info->extent_workers, &async->work);

	if (wait) {
		wait_for_completion(&async->wait);
		ret = async->error;
		kfree(async);
		return ret;
	}
	return 0;
}

int btrfs_run_delayed_refs(struct btrfs_trans_handle *trans,
			   struct btrfs_root *root, unsigned long count)
{
	struct rb_node *node;
	struct btrfs_delayed_ref_root *delayed_refs;
	struct btrfs_delayed_ref_head *head;
	int ret;
	int run_all = count == (unsigned long)-1;
	bool can_flush_pending_bgs = trans->can_flush_pending_bgs;

	if (trans->aborted)
		return 0;

	if (root->fs_info->creating_free_space_tree)
		return 0;

	if (root == root->fs_info->extent_root)
		root = root->fs_info->tree_root;

	delayed_refs = &trans->transaction->delayed_refs;
	if (count == 0)
		count = atomic_read(&delayed_refs->num_entries) * 2;

again:
#ifdef SCRAMBLE_DELAYED_REFS
	delayed_refs->run_delayed_start = find_middle(&delayed_refs->root);
#endif
	trans->can_flush_pending_bgs = false;
	ret = __btrfs_run_delayed_refs(trans, root, count);
	if (ret < 0) {
		btrfs_abort_transaction(trans, root, ret);
		return ret;
	}

	if (run_all) {
		if (!list_empty(&trans->new_bgs))
			btrfs_create_pending_block_groups(trans, root);

		spin_lock(&delayed_refs->lock);
		node = rb_first(&delayed_refs->href_root);
		if (!node) {
			spin_unlock(&delayed_refs->lock);
			goto out;
		}
		count = (unsigned long)-1;

		while (node) {
			head = rb_entry(node, struct btrfs_delayed_ref_head,
					href_node);
			if (btrfs_delayed_ref_is_head(&head->node)) {
				struct btrfs_delayed_ref_node *ref;

				ref = &head->node;
				atomic_inc(&ref->refs);

				spin_unlock(&delayed_refs->lock);
				 
				mutex_lock(&head->mutex);
				mutex_unlock(&head->mutex);

				btrfs_put_delayed_ref(ref);
				cond_resched();
				goto again;
			} else {
				WARN_ON(1);
			}
			node = rb_next(node);
		}
		spin_unlock(&delayed_refs->lock);
		cond_resched();
		goto again;
	}
out:
	assert_qgroups_uptodate(trans);
	trans->can_flush_pending_bgs = can_flush_pending_bgs;
	return 0;
}

int btrfs_set_disk_extent_flags(struct btrfs_trans_handle *trans,
				struct btrfs_root *root,
				u64 bytenr, u64 num_bytes, u64 flags,
				int level, int is_data)
{
	struct btrfs_delayed_extent_op *extent_op;
	int ret;

	extent_op = btrfs_alloc_delayed_extent_op();
	if (!extent_op)
		return -ENOMEM;

	extent_op->flags_to_set = flags;
	extent_op->update_flags = true;
	extent_op->update_key = false;
	extent_op->is_data = is_data ? true : false;
	extent_op->level = level;

	ret = btrfs_add_delayed_extent_op(root->fs_info, trans, bytenr,
					  num_bytes, extent_op);
	if (ret)
		btrfs_free_delayed_extent_op(extent_op);
	return ret;
}

static noinline int check_delayed_ref(struct btrfs_trans_handle *trans,
				      struct btrfs_root *root,
				      struct btrfs_path *path,
				      u64 objectid, u64 offset, u64 bytenr)
{
	struct btrfs_delayed_ref_head *head;
	struct btrfs_delayed_ref_node *ref;
	struct btrfs_delayed_data_ref *data_ref;
	struct btrfs_delayed_ref_root *delayed_refs;
	int ret = 0;

	delayed_refs = &trans->transaction->delayed_refs;
	spin_lock(&delayed_refs->lock);
	head = btrfs_find_delayed_ref_head(trans, bytenr);
	if (!head) {
		spin_unlock(&delayed_refs->lock);
		return 0;
	}

	if (!mutex_trylock(&head->mutex)) {
		atomic_inc(&head->node.refs);
		spin_unlock(&delayed_refs->lock);

		btrfs_release_path(path);

		mutex_lock(&head->mutex);
		mutex_unlock(&head->mutex);
		btrfs_put_delayed_ref(&head->node);
		return -EAGAIN;
	}
	spin_unlock(&delayed_refs->lock);

	spin_lock(&head->lock);
	list_for_each_entry(ref, &head->ref_list, list) {
		 
		if (ref->type != BTRFS_EXTENT_DATA_REF_KEY) {
			ret = 1;
			break;
		}

		data_ref = btrfs_delayed_node_to_data_ref(ref);

		if (data_ref->root != root->root_key.objectid ||
		    data_ref->objectid != objectid ||
		    data_ref->offset != offset) {
			ret = 1;
			break;
		}
	}
	spin_unlock(&head->lock);
	mutex_unlock(&head->mutex);
	return ret;
}

static noinline int check_committed_ref(struct btrfs_trans_handle *trans,
					struct btrfs_root *root,
					struct btrfs_path *path,
					u64 objectid, u64 offset, u64 bytenr)
{
	struct btrfs_root *extent_root = root->fs_info->extent_root;
	struct extent_buffer *leaf;
	struct btrfs_extent_data_ref *ref;
	struct btrfs_extent_inline_ref *iref;
	struct btrfs_extent_item *ei;
	struct btrfs_key key;
	u32 item_size;
	int ret;

	key.objectid = bytenr;
	key.offset = (u64)-1;
	key.type = BTRFS_EXTENT_ITEM_KEY;

	ret = btrfs_search_slot(NULL, extent_root, &key, path, 0, 0);
	if (ret < 0)
		goto out;
	BUG_ON(ret == 0);  

	ret = -ENOENT;
	if (path->slots[0] == 0)
		goto out;

	path->slots[0]--;
	leaf = path->nodes[0];
	btrfs_item_key_to_cpu(leaf, &key, path->slots[0]);

	if (key.objectid != bytenr || key.type != BTRFS_EXTENT_ITEM_KEY)
		goto out;

	ret = 1;
	item_size = btrfs_item_size_nr(leaf, path->slots[0]);
#ifdef BTRFS_COMPAT_EXTENT_TREE_V0
	if (item_size < sizeof(*ei)) {
		WARN_ON(item_size != sizeof(struct btrfs_extent_item_v0));
		goto out;
	}
#endif
	ei = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_extent_item);

	if (item_size != sizeof(*ei) +
	    btrfs_extent_inline_ref_size(BTRFS_EXTENT_DATA_REF_KEY))
		goto out;

	if (btrfs_extent_generation(leaf, ei) <=
	    btrfs_root_last_snapshot(&root->root_item))
		goto out;

	iref = (struct btrfs_extent_inline_ref *)(ei + 1);
	if (btrfs_extent_inline_ref_type(leaf, iref) !=
	    BTRFS_EXTENT_DATA_REF_KEY)
		goto out;

	ref = (struct btrfs_extent_data_ref *)(&iref->offset);
	if (btrfs_extent_refs(leaf, ei) !=
	    btrfs_extent_data_ref_count(leaf, ref) ||
	    btrfs_extent_data_ref_root(leaf, ref) !=
	    root->root_key.objectid ||
	    btrfs_extent_data_ref_objectid(leaf, ref) != objectid ||
	    btrfs_extent_data_ref_offset(leaf, ref) != offset)
		goto out;

	ret = 0;
out:
	return ret;
}

int btrfs_cross_ref_exist(struct btrfs_trans_handle *trans,
			  struct btrfs_root *root,
			  u64 objectid, u64 offset, u64 bytenr)
{
	struct btrfs_path *path;
	int ret;
	int ret2;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOENT;

	do {
		ret = check_committed_ref(trans, root, path, objectid,
					  offset, bytenr);
		if (ret && ret != -ENOENT)
			goto out;

		ret2 = check_delayed_ref(trans, root, path, objectid,
					 offset, bytenr);
	} while (ret2 == -EAGAIN);

	if (ret2 && ret2 != -ENOENT) {
		ret = ret2;
		goto out;
	}

	if (ret != -ENOENT || ret2 != -ENOENT)
		ret = 0;
out:
	btrfs_free_path(path);
	if (root->root_key.objectid == BTRFS_DATA_RELOC_TREE_OBJECTID)
		WARN_ON(ret > 0);
	return ret;
}

static int __btrfs_mod_ref(struct btrfs_trans_handle *trans,
			   struct btrfs_root *root,
			   struct extent_buffer *buf,
			   int full_backref, int inc)
{
	u64 bytenr;
	u64 num_bytes;
	u64 parent;
	u64 ref_root;
	u32 nritems;
	struct btrfs_key key;
	struct btrfs_file_extent_item *fi;
	int i;
	int level;
	int ret = 0;
	int (*process_func)(struct btrfs_trans_handle *, struct btrfs_root *,
			    u64, u64, u64, u64, u64, u64);

	if (btrfs_test_is_dummy_root(root))
		return 0;

	ref_root = btrfs_header_owner(buf);
	nritems = btrfs_header_nritems(buf);
	level = btrfs_header_level(buf);

	if (!test_bit(BTRFS_ROOT_REF_COWS, &root->state) && level == 0)
		return 0;

	if (inc)
		process_func = btrfs_inc_extent_ref;
	else
		process_func = btrfs_free_extent;

	if (full_backref)
		parent = buf->start;
	else
		parent = 0;

	for (i = 0; i < nritems; i++) {
		if (level == 0) {
			btrfs_item_key_to_cpu(buf, &key, i);
			if (key.type != BTRFS_EXTENT_DATA_KEY)
				continue;
			fi = btrfs_item_ptr(buf, i,
					    struct btrfs_file_extent_item);
			if (btrfs_file_extent_type(buf, fi) ==
			    BTRFS_FILE_EXTENT_INLINE)
				continue;
			bytenr = btrfs_file_extent_disk_bytenr(buf, fi);
			if (bytenr == 0)
				continue;

			num_bytes = btrfs_file_extent_disk_num_bytes(buf, fi);
			key.offset -= btrfs_file_extent_offset(buf, fi);
			ret = process_func(trans, root, bytenr, num_bytes,
					   parent, ref_root, key.objectid,
					   key.offset);
			if (ret)
				goto fail;
		} else {
			bytenr = btrfs_node_blockptr(buf, i);
			num_bytes = root->nodesize;
			ret = process_func(trans, root, bytenr, num_bytes,
					   parent, ref_root, level - 1, 0);
			if (ret)
				goto fail;
		}
	}
	return 0;
fail:
	return ret;
}

int btrfs_inc_ref(struct btrfs_trans_handle *trans, struct btrfs_root *root,
		  struct extent_buffer *buf, int full_backref)
{
	return __btrfs_mod_ref(trans, root, buf, full_backref, 1);
}

int btrfs_dec_ref(struct btrfs_trans_handle *trans, struct btrfs_root *root,
		  struct extent_buffer *buf, int full_backref)
{
	return __btrfs_mod_ref(trans, root, buf, full_backref, 0);
}

static int write_one_cache_group(struct btrfs_trans_handle *trans,
				 struct btrfs_root *root,
				 struct btrfs_path *path,
				 struct btrfs_block_group_cache *cache)
{
	int ret;
	struct btrfs_root *extent_root = root->fs_info->extent_root;
	unsigned long bi;
	struct extent_buffer *leaf;

	ret = btrfs_search_slot(trans, extent_root, &cache->key, path, 0, 1);
	if (ret) {
		if (ret > 0)
			ret = -ENOENT;
		goto fail;
	}

	leaf = path->nodes[0];
	bi = btrfs_item_ptr_offset(leaf, path->slots[0]);
	write_extent_buffer(leaf, &cache->item, bi, sizeof(cache->item));
	btrfs_mark_buffer_dirty(leaf);
fail:
	btrfs_release_path(path);
	return ret;

}

static struct btrfs_block_group_cache *
next_block_group(struct btrfs_root *root,
		 struct btrfs_block_group_cache *cache)
{
	struct rb_node *node;

	spin_lock(&root->fs_info->block_group_cache_lock);

	if (RB_EMPTY_NODE(&cache->cache_node)) {
		const u64 next_bytenr = cache->key.objectid + cache->key.offset;

		spin_unlock(&root->fs_info->block_group_cache_lock);
		btrfs_put_block_group(cache);
		cache = btrfs_lookup_first_block_group(root->fs_info,
						       next_bytenr);
		return cache;
	}
	node = rb_next(&cache->cache_node);
	btrfs_put_block_group(cache);
	if (node) {
		cache = rb_entry(node, struct btrfs_block_group_cache,
				 cache_node);
		btrfs_get_block_group(cache);
	} else
		cache = NULL;
	spin_unlock(&root->fs_info->block_group_cache_lock);
	return cache;
}

static int cache_save_setup(struct btrfs_block_group_cache *block_group,
			    struct btrfs_trans_handle *trans,
			    struct btrfs_path *path)
{
	struct btrfs_root *root = block_group->fs_info->tree_root;
	struct inode *inode = NULL;
	u64 alloc_hint = 0;
	int dcs = BTRFS_DC_ERROR;
	u64 num_pages = 0;
	int retries = 0;
	int ret = 0;

	if (block_group->key.offset < (100 * SZ_1M)) {
		spin_lock(&block_group->lock);
		block_group->disk_cache_state = BTRFS_DC_WRITTEN;
		spin_unlock(&block_group->lock);
		return 0;
	}

	if (trans->aborted)
		return 0;
again:
	inode = lookup_free_space_inode(root, block_group, path);
	if (IS_ERR(inode) && PTR_ERR(inode) != -ENOENT) {
		ret = PTR_ERR(inode);
		btrfs_release_path(path);
		goto out;
	}

	if (IS_ERR(inode)) {
		BUG_ON(retries);
		retries++;

		if (block_group->ro)
			goto out_free;

		ret = create_free_space_inode(root, trans, block_group, path);
		if (ret)
			goto out_free;
		goto again;
	}

	if (block_group->cache_generation == trans->transid &&
	    i_size_read(inode)) {
		dcs = BTRFS_DC_SETUP;
		goto out_put;
	}

	BTRFS_I(inode)->generation = 0;
	ret = btrfs_update_inode(trans, root, inode);
	if (ret) {
		 
		btrfs_abort_transaction(trans, root, ret);
		goto out_put;
	}
	WARN_ON(ret);

	if (i_size_read(inode) > 0) {
		ret = btrfs_check_trunc_cache_free_space(root,
					&root->fs_info->global_block_rsv);
		if (ret)
			goto out_put;

		ret = btrfs_truncate_free_space_cache(root, trans, NULL, inode);
		if (ret)
			goto out_put;
	}

	spin_lock(&block_group->lock);
	if (block_group->cached != BTRFS_CACHE_FINISHED ||
#ifdef MY_ABC_HERE
		 
		block_group->fs_info->log_root_recovering ||
#endif  
	    !btrfs_test_opt(root, SPACE_CACHE)) {
		 
		dcs = BTRFS_DC_WRITTEN;
		spin_unlock(&block_group->lock);
		goto out_put;
	}
	spin_unlock(&block_group->lock);

	if (test_bit(BTRFS_TRANS_CACHE_ENOSPC, &trans->transaction->flags)) {
		ret = -ENOSPC;
		goto out_put;
	}

	num_pages = div_u64(block_group->key.offset, SZ_256M);
	if (!num_pages)
		num_pages = 1;

	num_pages *= 16;
	num_pages *= PAGE_CACHE_SIZE;

	ret = btrfs_check_data_free_space(inode, 0, num_pages);
	if (ret)
		goto out_put;

	ret = btrfs_prealloc_file_range_trans(inode, trans, 0, 0, num_pages,
					      num_pages, num_pages,
					      &alloc_hint);
	 
	if (!ret)
		dcs = BTRFS_DC_SETUP;
	else if (ret == -ENOSPC)
		set_bit(BTRFS_TRANS_CACHE_ENOSPC, &trans->transaction->flags);
	btrfs_free_reserved_data_space(inode, 0, num_pages);

out_put:
	iput(inode);
out_free:
	btrfs_release_path(path);
out:
	spin_lock(&block_group->lock);
	if (!ret && dcs == BTRFS_DC_SETUP)
		block_group->cache_generation = trans->transid;
	block_group->disk_cache_state = dcs;
	spin_unlock(&block_group->lock);

	return ret;
}

int btrfs_setup_space_cache(struct btrfs_trans_handle *trans,
			    struct btrfs_root *root)
{
	struct btrfs_block_group_cache *cache, *tmp;
	struct btrfs_transaction *cur_trans = trans->transaction;
	struct btrfs_path *path;

	if (list_empty(&cur_trans->dirty_bgs) ||
	    !btrfs_test_opt(root, SPACE_CACHE))
		return 0;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	list_for_each_entry_safe(cache, tmp, &cur_trans->dirty_bgs,
				 dirty_list) {
		if (cache->disk_cache_state == BTRFS_DC_CLEAR)
			cache_save_setup(cache, trans, path);
	}

	btrfs_free_path(path);
	return 0;
}

int btrfs_start_dirty_block_groups(struct btrfs_trans_handle *trans,
				   struct btrfs_root *root)
{
	struct btrfs_block_group_cache *cache;
	struct btrfs_transaction *cur_trans = trans->transaction;
	int ret = 0;
	int should_put;
	struct btrfs_path *path = NULL;
	LIST_HEAD(dirty);
	struct list_head *io = &cur_trans->io_bgs;
	int num_started = 0;
	int loops = 0;

	spin_lock(&cur_trans->dirty_bgs_lock);
	if (list_empty(&cur_trans->dirty_bgs)) {
		spin_unlock(&cur_trans->dirty_bgs_lock);
		return 0;
	}
	list_splice_init(&cur_trans->dirty_bgs, &dirty);
	spin_unlock(&cur_trans->dirty_bgs_lock);

again:
	 
	btrfs_create_pending_block_groups(trans, root);

	if (!path) {
		path = btrfs_alloc_path();
		if (!path)
			return -ENOMEM;
	}

	mutex_lock(&trans->transaction->cache_write_mutex);
	while (!list_empty(&dirty)) {
		cache = list_first_entry(&dirty,
					 struct btrfs_block_group_cache,
					 dirty_list);
		 
		if (!list_empty(&cache->io_list)) {
			list_del_init(&cache->io_list);
			btrfs_wait_cache_io(root, trans, cache,
					    &cache->io_ctl, path,
					    cache->key.objectid);
			btrfs_put_block_group(cache);
		}

		spin_lock(&cur_trans->dirty_bgs_lock);
		list_del_init(&cache->dirty_list);
		spin_unlock(&cur_trans->dirty_bgs_lock);

		should_put = 1;

		cache_save_setup(cache, trans, path);

		if (cache->disk_cache_state == BTRFS_DC_SETUP) {
			cache->io_ctl.inode = NULL;
			ret = btrfs_write_out_cache(root, trans, cache, path);
			if (ret == 0 && cache->io_ctl.inode) {
				num_started++;
				should_put = 0;

				list_add_tail(&cache->io_list, io);
			} else {
				 
				ret = 0;
			}
		}
		if (!ret) {
			ret = write_one_cache_group(trans, root, path, cache);
			 
			if (ret == -ENOENT) {
				ret = 0;
				spin_lock(&cur_trans->dirty_bgs_lock);
				if (list_empty(&cache->dirty_list)) {
					list_add_tail(&cache->dirty_list,
						      &cur_trans->dirty_bgs);
					btrfs_get_block_group(cache);
				}
				spin_unlock(&cur_trans->dirty_bgs_lock);
			} else if (ret) {
				btrfs_abort_transaction(trans, root, ret);
			}
		}

		if (should_put)
			btrfs_put_block_group(cache);

		if (ret)
			break;

		mutex_unlock(&trans->transaction->cache_write_mutex);
		mutex_lock(&trans->transaction->cache_write_mutex);
	}
	mutex_unlock(&trans->transaction->cache_write_mutex);

	ret = btrfs_run_delayed_refs(trans, root, 0);
	if (!ret && loops == 0) {
		loops++;
		spin_lock(&cur_trans->dirty_bgs_lock);
		list_splice_init(&cur_trans->dirty_bgs, &dirty);
		 
		if (!list_empty(&dirty)) {
			spin_unlock(&cur_trans->dirty_bgs_lock);
			goto again;
		}
		spin_unlock(&cur_trans->dirty_bgs_lock);
	}

	btrfs_free_path(path);
	return ret;
}

int btrfs_write_dirty_block_groups(struct btrfs_trans_handle *trans,
				   struct btrfs_root *root)
{
	struct btrfs_block_group_cache *cache;
	struct btrfs_transaction *cur_trans = trans->transaction;
	int ret = 0;
	int should_put;
	struct btrfs_path *path;
	struct list_head *io = &cur_trans->io_bgs;
	int num_started = 0;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	spin_lock(&cur_trans->dirty_bgs_lock);
	while (!list_empty(&cur_trans->dirty_bgs)) {
		cache = list_first_entry(&cur_trans->dirty_bgs,
					 struct btrfs_block_group_cache,
					 dirty_list);

		if (!list_empty(&cache->io_list)) {
			spin_unlock(&cur_trans->dirty_bgs_lock);
			list_del_init(&cache->io_list);
			btrfs_wait_cache_io(root, trans, cache,
					    &cache->io_ctl, path,
					    cache->key.objectid);
			btrfs_put_block_group(cache);
			spin_lock(&cur_trans->dirty_bgs_lock);
		}

		list_del_init(&cache->dirty_list);
		spin_unlock(&cur_trans->dirty_bgs_lock);
		should_put = 1;

		cache_save_setup(cache, trans, path);

		if (!ret)
			ret = btrfs_run_delayed_refs(trans, root, (unsigned long) -1);

		if (!ret && cache->disk_cache_state == BTRFS_DC_SETUP) {
			cache->io_ctl.inode = NULL;
			ret = btrfs_write_out_cache(root, trans, cache, path);
			if (ret == 0 && cache->io_ctl.inode) {
				num_started++;
				should_put = 0;
				list_add_tail(&cache->io_list, io);
			} else {
				 
				ret = 0;
			}
		}
		if (!ret) {
			ret = write_one_cache_group(trans, root, path, cache);
			 
			if (ret == -ENOENT) {
				wait_event(cur_trans->writer_wait,
				   atomic_read(&cur_trans->num_writers) == 1);
				ret = write_one_cache_group(trans, root, path,
							    cache);
			}
			if (ret)
				btrfs_abort_transaction(trans, root, ret);
		}

		if (should_put)
			btrfs_put_block_group(cache);
		spin_lock(&cur_trans->dirty_bgs_lock);
	}
	spin_unlock(&cur_trans->dirty_bgs_lock);

	while (!list_empty(io)) {
		cache = list_first_entry(io, struct btrfs_block_group_cache,
					 io_list);
		list_del_init(&cache->io_list);
		btrfs_wait_cache_io(root, trans, cache,
				    &cache->io_ctl, path, cache->key.objectid);
		btrfs_put_block_group(cache);
	}

	btrfs_free_path(path);
	return ret;
}

int btrfs_extent_readonly(struct btrfs_root *root, u64 bytenr)
{
	struct btrfs_block_group_cache *block_group;
	int readonly = 0;

	block_group = btrfs_lookup_block_group(root->fs_info, bytenr);
	if (!block_group || block_group->ro)
		readonly = 1;
	if (block_group)
		btrfs_put_block_group(block_group);
	return readonly;
}

bool btrfs_inc_nocow_writers(struct btrfs_fs_info *fs_info, u64 bytenr)
{
	struct btrfs_block_group_cache *bg;
	bool ret = true;

	bg = btrfs_lookup_block_group(fs_info, bytenr);
	if (!bg)
		return false;

	spin_lock(&bg->lock);
	if (bg->ro)
		ret = false;
	else
		atomic_inc(&bg->nocow_writers);
	spin_unlock(&bg->lock);

	if (!ret)
		btrfs_put_block_group(bg);

	return ret;

}

void btrfs_dec_nocow_writers(struct btrfs_fs_info *fs_info, u64 bytenr)
{
	struct btrfs_block_group_cache *bg;

	bg = btrfs_lookup_block_group(fs_info, bytenr);
	ASSERT(bg);
	if (atomic_dec_and_test(&bg->nocow_writers))
		wake_up_atomic_t(&bg->nocow_writers);
	 
	btrfs_put_block_group(bg);
	btrfs_put_block_group(bg);
}

static int btrfs_wait_nocow_writers_atomic_t(atomic_t *a)
{
	schedule();
	return 0;
}

void btrfs_wait_nocow_writers(struct btrfs_block_group_cache *bg)
{
	wait_on_atomic_t(&bg->nocow_writers,
			 btrfs_wait_nocow_writers_atomic_t,
			 TASK_UNINTERRUPTIBLE);
}

static const char *alloc_name(u64 flags)
{
	switch (flags) {
	case BTRFS_BLOCK_GROUP_METADATA|BTRFS_BLOCK_GROUP_DATA:
		return "mixed";
	case BTRFS_BLOCK_GROUP_METADATA:
		return "metadata";
	case BTRFS_BLOCK_GROUP_DATA:
		return "data";
	case BTRFS_BLOCK_GROUP_SYSTEM:
		return "system";
	default:
		WARN_ON(1);
		return "invalid-combination";
	};
}

static int update_space_info(struct btrfs_fs_info *info, u64 flags,
			     u64 total_bytes, u64 bytes_used,
			     struct btrfs_space_info **space_info)
{
	struct btrfs_space_info *found;
	int i;
	int factor;
	int ret;

	if (flags & (BTRFS_BLOCK_GROUP_DUP | BTRFS_BLOCK_GROUP_RAID1 |
		     BTRFS_BLOCK_GROUP_RAID10))
		factor = 2;
	else
		factor = 1;

	found = __find_space_info(info, flags);
	if (found) {
		spin_lock(&found->lock);
		found->total_bytes += total_bytes;
		found->disk_total += total_bytes * factor;
		found->bytes_used += bytes_used;
		found->disk_used += bytes_used * factor;
		if (total_bytes > 0)
			found->full = 0;
		spin_unlock(&found->lock);
		*space_info = found;
		return 0;
	}
	found = kzalloc(sizeof(*found), GFP_NOFS);
	if (!found)
		return -ENOMEM;

	ret = percpu_counter_init(&found->total_bytes_pinned, 0, GFP_KERNEL);
	if (ret) {
		kfree(found);
		return ret;
	}

	for (i = 0; i < BTRFS_NR_RAID_TYPES; i++)
		INIT_LIST_HEAD(&found->block_groups[i]);
	init_rwsem(&found->groups_sem);
	spin_lock_init(&found->lock);
	found->flags = flags & BTRFS_BLOCK_GROUP_TYPE_MASK;
	found->total_bytes = total_bytes;
	found->disk_total = total_bytes * factor;
	found->bytes_used = bytes_used;
	found->disk_used = bytes_used * factor;
	found->bytes_pinned = 0;
	found->bytes_reserved = 0;
	found->bytes_readonly = 0;
	found->bytes_may_use = 0;
	found->full = 0;
	found->max_extent_size = 0;
	found->force_alloc = CHUNK_ALLOC_NO_FORCE;
	found->chunk_alloc = 0;
	found->flush = 0;
	init_waitqueue_head(&found->wait);
	INIT_LIST_HEAD(&found->ro_bgs);

	ret = kobject_init_and_add(&found->kobj, &space_info_ktype,
				    info->space_info_kobj, "%s",
				    alloc_name(found->flags));
	if (ret) {
		kfree(found);
		return ret;
	}

	*space_info = found;
	list_add_rcu(&found->list, &info->space_info);
	if (flags & BTRFS_BLOCK_GROUP_DATA)
		info->data_sinfo = found;

	return ret;
}

static void set_avail_alloc_bits(struct btrfs_fs_info *fs_info, u64 flags)
{
	u64 extra_flags = chunk_to_extended(flags) &
				BTRFS_EXTENDED_PROFILE_MASK;

	write_seqlock(&fs_info->profiles_lock);
	if (flags & BTRFS_BLOCK_GROUP_DATA)
		fs_info->avail_data_alloc_bits |= extra_flags;
	if (flags & BTRFS_BLOCK_GROUP_METADATA)
		fs_info->avail_metadata_alloc_bits |= extra_flags;
	if (flags & BTRFS_BLOCK_GROUP_SYSTEM)
		fs_info->avail_system_alloc_bits |= extra_flags;
	write_sequnlock(&fs_info->profiles_lock);
}

static u64 get_restripe_target(struct btrfs_fs_info *fs_info, u64 flags)
{
	struct btrfs_balance_control *bctl = fs_info->balance_ctl;
	u64 target = 0;

	if (!bctl)
		return 0;

	if (flags & BTRFS_BLOCK_GROUP_DATA &&
	    bctl->data.flags & BTRFS_BALANCE_ARGS_CONVERT) {
		target = BTRFS_BLOCK_GROUP_DATA | bctl->data.target;
	} else if (flags & BTRFS_BLOCK_GROUP_SYSTEM &&
		   bctl->sys.flags & BTRFS_BALANCE_ARGS_CONVERT) {
		target = BTRFS_BLOCK_GROUP_SYSTEM | bctl->sys.target;
	} else if (flags & BTRFS_BLOCK_GROUP_METADATA &&
		   bctl->meta.flags & BTRFS_BALANCE_ARGS_CONVERT) {
		target = BTRFS_BLOCK_GROUP_METADATA | bctl->meta.target;
	}

	return target;
}

static u64 btrfs_reduce_alloc_profile(struct btrfs_root *root, u64 flags)
{
	u64 num_devices = root->fs_info->fs_devices->rw_devices;
	u64 target;
	u64 raid_type;
	u64 allowed = 0;

	spin_lock(&root->fs_info->balance_lock);
	target = get_restripe_target(root->fs_info, flags);
	if (target) {
		 
		if ((flags & target) & BTRFS_EXTENDED_PROFILE_MASK) {
			spin_unlock(&root->fs_info->balance_lock);
			return extended_to_chunk(target);
		}
	}
	spin_unlock(&root->fs_info->balance_lock);

	for (raid_type = 0; raid_type < BTRFS_NR_RAID_TYPES; raid_type++) {
		if (num_devices >= btrfs_raid_array[raid_type].devs_min)
			allowed |= btrfs_raid_group[raid_type];
	}
	allowed &= flags;

	if (allowed & BTRFS_BLOCK_GROUP_RAID6)
		allowed = BTRFS_BLOCK_GROUP_RAID6;
	else if (allowed & BTRFS_BLOCK_GROUP_RAID5)
		allowed = BTRFS_BLOCK_GROUP_RAID5;
	else if (allowed & BTRFS_BLOCK_GROUP_RAID10)
		allowed = BTRFS_BLOCK_GROUP_RAID10;
	else if (allowed & BTRFS_BLOCK_GROUP_RAID1)
		allowed = BTRFS_BLOCK_GROUP_RAID1;
	else if (allowed & BTRFS_BLOCK_GROUP_RAID0)
		allowed = BTRFS_BLOCK_GROUP_RAID0;

	flags &= ~BTRFS_BLOCK_GROUP_PROFILE_MASK;

	return extended_to_chunk(flags | allowed);
}

static u64 get_alloc_profile(struct btrfs_root *root, u64 orig_flags)
{
	unsigned seq;
	u64 flags;

	do {
		flags = orig_flags;
		seq = read_seqbegin(&root->fs_info->profiles_lock);

		if (flags & BTRFS_BLOCK_GROUP_DATA)
			flags |= root->fs_info->avail_data_alloc_bits;
		else if (flags & BTRFS_BLOCK_GROUP_SYSTEM)
			flags |= root->fs_info->avail_system_alloc_bits;
		else if (flags & BTRFS_BLOCK_GROUP_METADATA)
			flags |= root->fs_info->avail_metadata_alloc_bits;
	} while (read_seqretry(&root->fs_info->profiles_lock, seq));

	return btrfs_reduce_alloc_profile(root, flags);
}

u64 btrfs_get_alloc_profile(struct btrfs_root *root, int data)
{
	u64 flags;
	u64 ret;

	if (data)
		flags = BTRFS_BLOCK_GROUP_DATA;
	else if (root == root->fs_info->chunk_root)
		flags = BTRFS_BLOCK_GROUP_SYSTEM;
	else
		flags = BTRFS_BLOCK_GROUP_METADATA;

	ret = get_alloc_profile(root, flags);
	return ret;
}

int btrfs_alloc_data_chunk_ondemand(struct inode *inode, u64 bytes)
{
	struct btrfs_space_info *data_sinfo;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_fs_info *fs_info = root->fs_info;
	u64 used;
	int ret = 0;
	int need_commit = 2;
	int have_pinned_space;

	bytes = ALIGN(bytes, root->sectorsize);

	if (btrfs_is_free_space_inode(inode)) {
		need_commit = 0;
		ASSERT(current->journal_info);
	}

	data_sinfo = fs_info->data_sinfo;
	if (!data_sinfo)
		goto alloc;

again:
	 
	spin_lock(&data_sinfo->lock);
	used = data_sinfo->bytes_used + data_sinfo->bytes_reserved +
		data_sinfo->bytes_pinned + data_sinfo->bytes_readonly +
		data_sinfo->bytes_may_use;

	if (used + bytes > data_sinfo->total_bytes) {
		struct btrfs_trans_handle *trans;

		if (!data_sinfo->full) {
			u64 alloc_target;

			data_sinfo->force_alloc = CHUNK_ALLOC_FORCE;
			spin_unlock(&data_sinfo->lock);
alloc:
			alloc_target = btrfs_get_alloc_profile(root, 1);
			 
			trans = btrfs_join_transaction(root);
			if (IS_ERR(trans))
				return PTR_ERR(trans);

			ret = do_chunk_alloc(trans, root->fs_info->extent_root,
					     alloc_target,
					     CHUNK_ALLOC_NO_FORCE);
			btrfs_end_transaction(trans, root);
			if (ret < 0) {
				if (ret != -ENOSPC)
					return ret;
				else {
					have_pinned_space = 1;
					goto commit_trans;
				}
			}

			if (!data_sinfo)
				data_sinfo = fs_info->data_sinfo;

			goto again;
		}

		have_pinned_space = percpu_counter_compare(
			&data_sinfo->total_bytes_pinned,
			used + bytes - data_sinfo->total_bytes);
		spin_unlock(&data_sinfo->lock);

commit_trans:
		if (need_commit &&
		    !atomic_read(&root->fs_info->open_ioctl_trans)) {
			need_commit--;

			if (need_commit > 0) {
				btrfs_start_delalloc_roots(fs_info, 0, -1);
				btrfs_wait_ordered_roots(fs_info, -1, 0, (u64)-1);
			}

			trans = btrfs_join_transaction(root);
			if (IS_ERR(trans))
				return PTR_ERR(trans);
			if (have_pinned_space >= 0 ||
			    test_bit(BTRFS_TRANS_HAVE_FREE_BGS,
				     &trans->transaction->flags) ||
			    need_commit > 0) {
				ret = btrfs_commit_transaction(trans, root);
				if (ret)
					return ret;
				 
				mutex_lock(&root->fs_info->cleaner_delayed_iput_mutex);
				mutex_unlock(&root->fs_info->cleaner_delayed_iput_mutex);
				goto again;
			} else {
				btrfs_end_transaction(trans, root);
			}
		}

		trace_btrfs_space_reservation(root->fs_info,
					      "space_info:enospc",
					      data_sinfo->flags, bytes, 1);
		return -ENOSPC;
	}
	data_sinfo->bytes_may_use += bytes;
	trace_btrfs_space_reservation(root->fs_info, "space_info",
				      data_sinfo->flags, bytes, 1);
	spin_unlock(&data_sinfo->lock);

	return ret;
}

int btrfs_check_data_free_space(struct inode *inode, u64 start, u64 len)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int ret;

	len = round_up(start + len, root->sectorsize) -
	      round_down(start, root->sectorsize);
	start = round_down(start, root->sectorsize);

	ret = btrfs_alloc_data_chunk_ondemand(inode, len);
	if (ret < 0)
		return ret;

	ret = btrfs_qgroup_reserve_data(inode, start, len);
	if (ret)
		btrfs_free_reserved_data_space_noquota(inode, start, len);
	return ret;
}

void btrfs_free_reserved_data_space_noquota(struct inode *inode, u64 start,
					    u64 len)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_space_info *data_sinfo;

	len = round_up(start + len, root->sectorsize) -
	      round_down(start, root->sectorsize);
	start = round_down(start, root->sectorsize);

	data_sinfo = root->fs_info->data_sinfo;
	spin_lock(&data_sinfo->lock);
	if (WARN_ON(data_sinfo->bytes_may_use < len))
		data_sinfo->bytes_may_use = 0;
	else
		data_sinfo->bytes_may_use -= len;
	trace_btrfs_space_reservation(root->fs_info, "space_info",
				      data_sinfo->flags, len, 0);
	spin_unlock(&data_sinfo->lock);
}

void btrfs_free_reserved_data_space(struct inode *inode, u64 start, u64 len)
{
	btrfs_free_reserved_data_space_noquota(inode, start, len);
	btrfs_qgroup_free_data(inode, start, len);
}

#ifdef MY_ABC_HERE
#else
static void force_metadata_allocation(struct btrfs_fs_info *info)
{
	struct list_head *head = &info->space_info;
	struct btrfs_space_info *found;

	rcu_read_lock();
	list_for_each_entry_rcu(found, head, list) {
		if (found->flags & BTRFS_BLOCK_GROUP_METADATA)
			found->force_alloc = CHUNK_ALLOC_FORCE;
	}
	rcu_read_unlock();
}
#endif  

static inline u64 calc_global_rsv_need_space(struct btrfs_block_rsv *global)
{
	return (global->size << 1);
}

static int should_alloc_chunk(struct btrfs_root *root,
			      struct btrfs_space_info *sinfo, int force)
{
	struct btrfs_block_rsv *global_rsv = &root->fs_info->global_block_rsv;
	u64 num_bytes = sinfo->total_bytes - sinfo->bytes_readonly;
	u64 num_allocated = sinfo->bytes_used + sinfo->bytes_reserved;
	u64 thresh;

	if (force == CHUNK_ALLOC_FORCE)
		return 1;

	if (sinfo->flags & BTRFS_BLOCK_GROUP_METADATA)
		num_allocated += calc_global_rsv_need_space(global_rsv);

	if (force == CHUNK_ALLOC_LIMITED) {
		thresh = btrfs_super_total_bytes(root->fs_info->super_copy);
		thresh = max_t(u64, SZ_64M, div_factor_fine(thresh, 1));

		if (num_bytes - num_allocated < thresh)
			return 1;
	}

	if (num_allocated + SZ_2M < div_factor(num_bytes, 8))
		return 0;
	return 1;
}

static u64 get_profile_num_devs(struct btrfs_root *root, u64 type)
{
	u64 num_dev;

	if (type & (BTRFS_BLOCK_GROUP_RAID10 |
		    BTRFS_BLOCK_GROUP_RAID0 |
		    BTRFS_BLOCK_GROUP_RAID5 |
		    BTRFS_BLOCK_GROUP_RAID6))
		num_dev = root->fs_info->fs_devices->rw_devices;
	else if (type & BTRFS_BLOCK_GROUP_RAID1)
		num_dev = 2;
	else
		num_dev = 1;	 

	return num_dev;
}

void check_system_chunk(struct btrfs_trans_handle *trans,
			struct btrfs_root *root,
			u64 type)
{
	struct btrfs_space_info *info;
	u64 left;
	u64 thresh;
	int ret = 0;
	u64 num_devs;

	ASSERT(mutex_is_locked(&root->fs_info->chunk_mutex));

	info = __find_space_info(root->fs_info, BTRFS_BLOCK_GROUP_SYSTEM);
	spin_lock(&info->lock);
	left = info->total_bytes - info->bytes_used - info->bytes_pinned -
		info->bytes_reserved - info->bytes_readonly -
		info->bytes_may_use;
	spin_unlock(&info->lock);

	num_devs = get_profile_num_devs(root, type);

	thresh = btrfs_calc_trunc_metadata_size(root, num_devs) +
		btrfs_calc_trans_metadata_size(root, 1);

	if (left < thresh && btrfs_test_opt(root, ENOSPC_DEBUG)) {
		btrfs_info(root->fs_info, "left=%llu, need=%llu, flags=%llu",
			left, thresh, type);
		dump_space_info(info, 0, 0);
	}

	if (left < thresh) {
		u64 flags;

		flags = btrfs_get_alloc_profile(root->fs_info->chunk_root, 0);
		 
		ret = btrfs_alloc_chunk(trans, root, flags);
	}

	if (!ret) {
		ret = btrfs_block_rsv_add(root->fs_info->chunk_root,
					  &root->fs_info->chunk_block_rsv,
					  thresh, BTRFS_RESERVE_NO_FLUSH);
		if (!ret)
			trans->chunk_bytes_reserved += thresh;
	}
}

#ifdef MY_ABC_HERE
static void check_metadata_chunk(struct btrfs_trans_handle *trans,
			       struct btrfs_root *root, u64 data_total_bytes)
{
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_space_info *space_info = __find_space_info(fs_info, BTRFS_BLOCK_GROUP_METADATA);

	if (data_total_bytes > (space_info->total_bytes)*(fs_info->metadata_ratio))
		btrfs_alloc_chunk(trans, root, btrfs_get_alloc_profile(root, 0));
}
#endif  

static int do_chunk_alloc(struct btrfs_trans_handle *trans,
			  struct btrfs_root *extent_root, u64 flags, int force)
{
	struct btrfs_space_info *space_info;
	struct btrfs_fs_info *fs_info = extent_root->fs_info;
	int wait_for_alloc = 0;
	int ret = 0;

	if (trans->allocating_chunk)
		return -ENOSPC;

	space_info = __find_space_info(extent_root->fs_info, flags);
	if (!space_info) {
		ret = update_space_info(extent_root->fs_info, flags,
					0, 0, &space_info);
		BUG_ON(ret);  
	}
	BUG_ON(!space_info);  

again:
	spin_lock(&space_info->lock);
	if (force < space_info->force_alloc)
		force = space_info->force_alloc;
	if (space_info->full) {
		if (should_alloc_chunk(extent_root, space_info, force))
			ret = -ENOSPC;
		else
			ret = 0;
		spin_unlock(&space_info->lock);
		return ret;
	}

	if (!should_alloc_chunk(extent_root, space_info, force)) {
		spin_unlock(&space_info->lock);
		return 0;
	} else if (space_info->chunk_alloc) {
		wait_for_alloc = 1;
	} else {
		space_info->chunk_alloc = 1;
	}

	spin_unlock(&space_info->lock);

	mutex_lock(&fs_info->chunk_mutex);

	if (wait_for_alloc) {
		mutex_unlock(&fs_info->chunk_mutex);
		wait_for_alloc = 0;
		goto again;
	}

	trans->allocating_chunk = true;

	if (btrfs_mixed_space_info(space_info))
		flags |= (BTRFS_BLOCK_GROUP_DATA | BTRFS_BLOCK_GROUP_METADATA);

	if (flags & BTRFS_BLOCK_GROUP_DATA && fs_info->metadata_ratio) {
#ifdef MY_ABC_HERE
		check_metadata_chunk(trans, extent_root, space_info->total_bytes);
#else
		fs_info->data_chunk_allocations++;
		if (!(fs_info->data_chunk_allocations %
		      fs_info->metadata_ratio))
			force_metadata_allocation(fs_info);
#endif  
	}

	check_system_chunk(trans, extent_root, flags);

	ret = btrfs_alloc_chunk(trans, extent_root, flags);
	trans->allocating_chunk = false;

	spin_lock(&space_info->lock);
	if (ret < 0 && ret != -ENOSPC)
		goto out;
	if (ret)
		space_info->full = 1;
	else
		ret = 1;

	space_info->force_alloc = CHUNK_ALLOC_NO_FORCE;
out:
	space_info->chunk_alloc = 0;
	spin_unlock(&space_info->lock);
	mutex_unlock(&fs_info->chunk_mutex);
	 
	if (trans->can_flush_pending_bgs &&
	    trans->chunk_bytes_reserved >= (u64)SZ_2M) {
		btrfs_create_pending_block_groups(trans, trans->root);
		btrfs_trans_release_chunk_metadata(trans);
	}
	return ret;
}

static int can_overcommit(struct btrfs_root *root,
			  struct btrfs_space_info *space_info, u64 bytes,
			  enum btrfs_reserve_flush_enum flush)
{
	struct btrfs_block_rsv *global_rsv = &root->fs_info->global_block_rsv;
	u64 profile = btrfs_get_alloc_profile(root, 0);
	u64 space_size;
	u64 avail;
	u64 used;

#ifdef MY_ABC_HERE
	used = space_info->bytes_used + space_info->bytes_reserved +
		space_info->bytes_readonly;
#else
	used = space_info->bytes_used + space_info->bytes_reserved +
		space_info->bytes_pinned + space_info->bytes_readonly;
#endif  

	spin_lock(&global_rsv->lock);
	space_size = calc_global_rsv_need_space(global_rsv);
	spin_unlock(&global_rsv->lock);
	if (used + space_size >= space_info->total_bytes)
		return 0;

#ifdef MY_ABC_HERE
	used += space_info->bytes_may_use + space_info->bytes_pinned;
#else
	used += space_info->bytes_may_use;
#endif  

	spin_lock(&root->fs_info->free_chunk_lock);
	avail = root->fs_info->free_chunk_space;
	spin_unlock(&root->fs_info->free_chunk_lock);

	if (profile & (BTRFS_BLOCK_GROUP_DUP |
		       BTRFS_BLOCK_GROUP_RAID1 |
		       BTRFS_BLOCK_GROUP_RAID10))
		avail >>= 1;

	if (flush == BTRFS_RESERVE_FLUSH_ALL)
		avail >>= 3;
	else
		avail >>= 1;

	if (used + bytes < space_info->total_bytes + avail)
		return 1;
	return 0;
}

static void btrfs_writeback_inodes_sb_nr(struct btrfs_root *root,
					 unsigned long nr_pages, int nr_items)
{
	struct super_block *sb = root->fs_info->sb;

	if (down_read_trylock(&sb->s_umount)) {
		writeback_inodes_sb_nr(sb, nr_pages, WB_REASON_FS_FREE_SPACE);
		up_read(&sb->s_umount);
	} else {
		 
		btrfs_start_delalloc_roots(root->fs_info, 0, nr_items);
		if (!current->journal_info)
			btrfs_wait_ordered_roots(root->fs_info, nr_items,
						 0, (u64)-1);
	}
}

static inline int calc_reclaim_items_nr(struct btrfs_root *root, u64 to_reclaim)
{
	u64 bytes;
	int nr;

	bytes = btrfs_calc_trans_metadata_size(root, 1);
	nr = (int)div64_u64(to_reclaim, bytes);
	if (!nr)
		nr = 1;
	return nr;
}

#define EXTENT_SIZE_PER_ITEM	SZ_256K

static void shrink_delalloc(struct btrfs_root *root, u64 to_reclaim, u64 orig,
			    bool wait_ordered)
{
	struct btrfs_block_rsv *block_rsv;
	struct btrfs_space_info *space_info;
	struct btrfs_trans_handle *trans;
	u64 delalloc_bytes;
	u64 max_reclaim;
	long time_left;
	unsigned long nr_pages;
	int loops;
	int items;
	enum btrfs_reserve_flush_enum flush;

	items = calc_reclaim_items_nr(root, to_reclaim);
	to_reclaim = (u64)items * EXTENT_SIZE_PER_ITEM;

	trans = (struct btrfs_trans_handle *)current->journal_info;
	block_rsv = &root->fs_info->delalloc_block_rsv;
	space_info = block_rsv->space_info;

	delalloc_bytes = percpu_counter_sum_positive(
						&root->fs_info->delalloc_bytes);
	if (delalloc_bytes == 0) {
		if (trans)
			return;
		if (wait_ordered)
			btrfs_wait_ordered_roots(root->fs_info, items,
						 0, (u64)-1);
		return;
	}

	loops = 0;
	while (delalloc_bytes && loops < 3) {
		max_reclaim = min(delalloc_bytes, to_reclaim);
		nr_pages = max_reclaim >> PAGE_CACHE_SHIFT;
		btrfs_writeback_inodes_sb_nr(root, nr_pages, items);
		 
		max_reclaim = atomic_read(&root->fs_info->async_delalloc_pages);
		if (!max_reclaim)
			goto skip_async;

		if (max_reclaim <= nr_pages)
			max_reclaim = 0;
		else
			max_reclaim -= nr_pages;

		wait_event(root->fs_info->async_submit_wait,
			   atomic_read(&root->fs_info->async_delalloc_pages) <=
			   (int)max_reclaim);
skip_async:
		if (!trans)
			flush = BTRFS_RESERVE_FLUSH_ALL;
		else
			flush = BTRFS_RESERVE_NO_FLUSH;
		spin_lock(&space_info->lock);
		if (can_overcommit(root, space_info, orig, flush)) {
			spin_unlock(&space_info->lock);
			break;
		}
		spin_unlock(&space_info->lock);

		loops++;
		if (wait_ordered && !trans) {
			btrfs_wait_ordered_roots(root->fs_info, items,
						 0, (u64)-1);
		} else {
			time_left = schedule_timeout_killable(1);
			if (time_left)
				break;
		}
		delalloc_bytes = percpu_counter_sum_positive(
						&root->fs_info->delalloc_bytes);
	}
}

static int may_commit_transaction(struct btrfs_root *root,
				  struct btrfs_space_info *space_info,
				  u64 bytes, int force)
{
	struct btrfs_block_rsv *delayed_rsv = &root->fs_info->delayed_block_rsv;
	struct btrfs_trans_handle *trans;

	trans = (struct btrfs_trans_handle *)current->journal_info;
	if (trans)
		return -EAGAIN;

	if (force)
		goto commit;

	if (percpu_counter_compare(&space_info->total_bytes_pinned,
				   bytes) >= 0)
		goto commit;

	if (space_info != delayed_rsv->space_info)
		return -ENOSPC;

	spin_lock(&delayed_rsv->lock);
	if (percpu_counter_compare(&space_info->total_bytes_pinned,
				   bytes - delayed_rsv->size) >= 0) {
		spin_unlock(&delayed_rsv->lock);
		return -ENOSPC;
	}
	spin_unlock(&delayed_rsv->lock);

commit:
	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans))
		return -ENOSPC;

	return btrfs_commit_transaction(trans, root);
}

enum flush_state {
	FLUSH_DELAYED_ITEMS_NR	=	1,
	FLUSH_DELAYED_ITEMS	=	2,
	FLUSH_DELALLOC		=	3,
	FLUSH_DELALLOC_WAIT	=	4,
	ALLOC_CHUNK		=	5,
	COMMIT_TRANS		=	6,
};

static int flush_space(struct btrfs_root *root,
		       struct btrfs_space_info *space_info, u64 num_bytes,
		       u64 orig_bytes, int state)
{
	struct btrfs_trans_handle *trans;
	int nr;
	int ret = 0;

	switch (state) {
	case FLUSH_DELAYED_ITEMS_NR:
	case FLUSH_DELAYED_ITEMS:
		if (state == FLUSH_DELAYED_ITEMS_NR)
			nr = calc_reclaim_items_nr(root, num_bytes) * 2;
		else
			nr = -1;

		trans = btrfs_join_transaction(root);
		if (IS_ERR(trans)) {
			ret = PTR_ERR(trans);
			break;
		}
		ret = btrfs_run_delayed_items_nr(trans, root, nr);
		btrfs_end_transaction(trans, root);
		break;
	case FLUSH_DELALLOC:
	case FLUSH_DELALLOC_WAIT:
		shrink_delalloc(root, num_bytes * 2, orig_bytes,
				state == FLUSH_DELALLOC_WAIT);
		break;
	case ALLOC_CHUNK:
		trans = btrfs_join_transaction(root);
		if (IS_ERR(trans)) {
			ret = PTR_ERR(trans);
			break;
		}
		ret = do_chunk_alloc(trans, root->fs_info->extent_root,
				     btrfs_get_alloc_profile(root, 0),
				     CHUNK_ALLOC_NO_FORCE);
		btrfs_end_transaction(trans, root);
		if (ret == -ENOSPC)
			ret = 0;
		break;
	case COMMIT_TRANS:
		ret = may_commit_transaction(root, space_info, orig_bytes, 0);
		break;
	default:
		ret = -ENOSPC;
		break;
	}

	return ret;
}

static inline u64
btrfs_calc_reclaim_metadata_size(struct btrfs_root *root,
				 struct btrfs_space_info *space_info)
{
	u64 used;
	u64 expected;
	u64 to_reclaim;

	to_reclaim = min_t(u64, num_online_cpus() * SZ_1M, SZ_16M);
	spin_lock(&space_info->lock);
	if (can_overcommit(root, space_info, to_reclaim,
			   BTRFS_RESERVE_FLUSH_ALL)) {
		to_reclaim = 0;
		goto out;
	}

	used = space_info->bytes_used + space_info->bytes_reserved +
	       space_info->bytes_pinned + space_info->bytes_readonly +
	       space_info->bytes_may_use;
	if (can_overcommit(root, space_info, SZ_1M, BTRFS_RESERVE_FLUSH_ALL))
		expected = div_factor_fine(space_info->total_bytes, 95);
	else
		expected = div_factor_fine(space_info->total_bytes, 90);

	if (used > expected)
		to_reclaim = used - expected;
	else
		to_reclaim = 0;
	to_reclaim = min(to_reclaim, space_info->bytes_may_use +
				     space_info->bytes_reserved);
out:
	spin_unlock(&space_info->lock);

	return to_reclaim;
}

static inline int need_do_async_reclaim(struct btrfs_space_info *space_info,
					struct btrfs_fs_info *fs_info, u64 used)
{
	u64 thresh = div_factor_fine(space_info->total_bytes, 98);

	if ((space_info->bytes_used + space_info->bytes_reserved) >= thresh)
		return 0;

	return (used >= thresh && !btrfs_fs_closing(fs_info) &&
		!test_bit(BTRFS_FS_STATE_REMOUNTING, &fs_info->fs_state));
}

static int btrfs_need_do_async_reclaim(struct btrfs_space_info *space_info,
				       struct btrfs_fs_info *fs_info,
				       int flush_state)
{
	u64 used;

	spin_lock(&space_info->lock);
	 
	if (flush_state > COMMIT_TRANS && space_info->full) {
		spin_unlock(&space_info->lock);
		return 0;
	}

	used = space_info->bytes_used + space_info->bytes_reserved +
	       space_info->bytes_pinned + space_info->bytes_readonly +
	       space_info->bytes_may_use;
	if (need_do_async_reclaim(space_info, fs_info, used)) {
		spin_unlock(&space_info->lock);
		return 1;
	}
	spin_unlock(&space_info->lock);

	return 0;
}

static void btrfs_async_reclaim_metadata_space(struct work_struct *work)
{
	struct btrfs_fs_info *fs_info;
	struct btrfs_space_info *space_info;
	u64 to_reclaim;
	int flush_state;

	fs_info = container_of(work, struct btrfs_fs_info, async_reclaim_work);
	space_info = __find_space_info(fs_info, BTRFS_BLOCK_GROUP_METADATA);

	to_reclaim = btrfs_calc_reclaim_metadata_size(fs_info->fs_root,
						      space_info);
	if (!to_reclaim)
		return;

	flush_state = FLUSH_DELAYED_ITEMS_NR;
	do {
		flush_space(fs_info->fs_root, space_info, to_reclaim,
			    to_reclaim, flush_state);
		flush_state++;
		if (!btrfs_need_do_async_reclaim(space_info, fs_info,
						 flush_state))
			return;
	} while (flush_state < COMMIT_TRANS);
}

void btrfs_init_async_reclaim_work(struct work_struct *work)
{
	INIT_WORK(work, btrfs_async_reclaim_metadata_space);
}

static int reserve_metadata_bytes(struct btrfs_root *root,
				  struct btrfs_block_rsv *block_rsv,
				  u64 orig_bytes,
				  enum btrfs_reserve_flush_enum flush)
{
	struct btrfs_space_info *space_info = block_rsv->space_info;
	u64 used;
	u64 num_bytes = orig_bytes;
	int flush_state = FLUSH_DELAYED_ITEMS_NR;
	int ret = 0;
	bool flushing = false;

again:
	ret = 0;
	spin_lock(&space_info->lock);
	 
	while (flush == BTRFS_RESERVE_FLUSH_ALL && !flushing &&
	       space_info->flush) {
		spin_unlock(&space_info->lock);
		 
		if (current->journal_info)
			return -EAGAIN;
		ret = wait_event_killable(space_info->wait, !space_info->flush);
		 
		if (ret)
			return -EINTR;

		spin_lock(&space_info->lock);
	}

	ret = -ENOSPC;
	used = space_info->bytes_used + space_info->bytes_reserved +
		space_info->bytes_pinned + space_info->bytes_readonly +
		space_info->bytes_may_use;

	if (used <= space_info->total_bytes) {
		if (used + orig_bytes <= space_info->total_bytes) {
			space_info->bytes_may_use += orig_bytes;
			trace_btrfs_space_reservation(root->fs_info,
				"space_info", space_info->flags, orig_bytes, 1);
			ret = 0;
		} else {
			 
			num_bytes = orig_bytes;
		}
	} else {
		 
		num_bytes = used - space_info->total_bytes +
			(orig_bytes * 2);
	}

	if (ret && can_overcommit(root, space_info, orig_bytes, flush)) {
		space_info->bytes_may_use += orig_bytes;
		trace_btrfs_space_reservation(root->fs_info, "space_info",
					      space_info->flags, orig_bytes,
					      1);
		ret = 0;
	}

	if (ret && flush != BTRFS_RESERVE_NO_FLUSH) {
		flushing = true;
		space_info->flush = 1;
	} else if (!ret && space_info->flags & BTRFS_BLOCK_GROUP_METADATA) {
		used += orig_bytes;
		 
		if (!root->fs_info->log_root_recovering &&
#ifdef MY_ABC_HERE
			!root->fs_info->avoid_fs_root_null_pointer_dereference &&
#endif  
		    need_do_async_reclaim(space_info, root->fs_info, used) &&
		    !work_busy(&root->fs_info->async_reclaim_work))
			queue_work(system_unbound_wq,
				   &root->fs_info->async_reclaim_work);
	}
	spin_unlock(&space_info->lock);

	if (!ret || flush == BTRFS_RESERVE_NO_FLUSH)
		goto out;

	ret = flush_space(root, space_info, num_bytes, orig_bytes,
			  flush_state);
	flush_state++;

	if (flush == BTRFS_RESERVE_FLUSH_LIMIT &&
	    (flush_state == FLUSH_DELALLOC ||
	     flush_state == FLUSH_DELALLOC_WAIT))
		flush_state = ALLOC_CHUNK;

	if (!ret)
		goto again;
	else if (flush == BTRFS_RESERVE_FLUSH_LIMIT &&
		 flush_state < COMMIT_TRANS)
		goto again;
	else if (flush == BTRFS_RESERVE_FLUSH_ALL &&
		 flush_state <= COMMIT_TRANS)
		goto again;

out:
	if (ret == -ENOSPC &&
	    unlikely(root->orphan_cleanup_state == ORPHAN_CLEANUP_STARTED)) {
		struct btrfs_block_rsv *global_rsv =
			&root->fs_info->global_block_rsv;

		if (block_rsv != global_rsv &&
		    !block_rsv_use_bytes(global_rsv, orig_bytes))
			ret = 0;
	}
	if (ret == -ENOSPC)
		trace_btrfs_space_reservation(root->fs_info,
					      "space_info:enospc",
					      space_info->flags, orig_bytes, 1);
	if (flushing) {
		spin_lock(&space_info->lock);
		space_info->flush = 0;
		wake_up_all(&space_info->wait);
		spin_unlock(&space_info->lock);
	}
	return ret;
}

static struct btrfs_block_rsv *get_block_rsv(
					const struct btrfs_trans_handle *trans,
					const struct btrfs_root *root)
{
	struct btrfs_block_rsv *block_rsv = NULL;

	if (test_bit(BTRFS_ROOT_REF_COWS, &root->state) ||
	    (root == root->fs_info->csum_root && trans->adding_csums) ||
	     (root == root->fs_info->uuid_root))
		block_rsv = trans->block_rsv;

	if (!block_rsv)
		block_rsv = root->block_rsv;

	if (!block_rsv)
		block_rsv = &root->fs_info->empty_block_rsv;

	return block_rsv;
}

static int block_rsv_use_bytes(struct btrfs_block_rsv *block_rsv,
			       u64 num_bytes)
{
	int ret = -ENOSPC;
	spin_lock(&block_rsv->lock);
	if (block_rsv->reserved >= num_bytes) {
		block_rsv->reserved -= num_bytes;
		if (block_rsv->reserved < block_rsv->size)
			block_rsv->full = 0;
		ret = 0;
	}
	spin_unlock(&block_rsv->lock);
	return ret;
}

static void block_rsv_add_bytes(struct btrfs_block_rsv *block_rsv,
				u64 num_bytes, int update_size)
{
	spin_lock(&block_rsv->lock);
	block_rsv->reserved += num_bytes;
	if (update_size)
		block_rsv->size += num_bytes;
	else if (block_rsv->reserved >= block_rsv->size)
		block_rsv->full = 1;
	spin_unlock(&block_rsv->lock);
}

int btrfs_cond_migrate_bytes(struct btrfs_fs_info *fs_info,
			     struct btrfs_block_rsv *dest, u64 num_bytes,
			     int min_factor)
{
	struct btrfs_block_rsv *global_rsv = &fs_info->global_block_rsv;
	u64 min_bytes;

	if (global_rsv->space_info != dest->space_info)
		return -ENOSPC;

	spin_lock(&global_rsv->lock);
	min_bytes = div_factor(global_rsv->size, min_factor);
	if (global_rsv->reserved < min_bytes + num_bytes) {
		spin_unlock(&global_rsv->lock);
		return -ENOSPC;
	}
	global_rsv->reserved -= num_bytes;
	if (global_rsv->reserved < global_rsv->size)
		global_rsv->full = 0;
	spin_unlock(&global_rsv->lock);

	block_rsv_add_bytes(dest, num_bytes, 1);
	return 0;
}

static void block_rsv_release_bytes(struct btrfs_fs_info *fs_info,
				    struct btrfs_block_rsv *block_rsv,
				    struct btrfs_block_rsv *dest, u64 num_bytes)
{
	struct btrfs_space_info *space_info = block_rsv->space_info;

	spin_lock(&block_rsv->lock);
	if (num_bytes == (u64)-1)
		num_bytes = block_rsv->size;
	block_rsv->size -= num_bytes;
	if (block_rsv->reserved >= block_rsv->size) {
		num_bytes = block_rsv->reserved - block_rsv->size;
		block_rsv->reserved = block_rsv->size;
		block_rsv->full = 1;
	} else {
		num_bytes = 0;
	}
	spin_unlock(&block_rsv->lock);

	if (num_bytes > 0) {
		if (dest) {
			spin_lock(&dest->lock);
			if (!dest->full) {
				u64 bytes_to_add;

				bytes_to_add = dest->size - dest->reserved;
				bytes_to_add = min(num_bytes, bytes_to_add);
				dest->reserved += bytes_to_add;
				if (dest->reserved >= dest->size)
					dest->full = 1;
				num_bytes -= bytes_to_add;
			}
			spin_unlock(&dest->lock);
		}
		if (num_bytes) {
			spin_lock(&space_info->lock);
			space_info->bytes_may_use -= num_bytes;
			trace_btrfs_space_reservation(fs_info, "space_info",
					space_info->flags, num_bytes, 0);
			spin_unlock(&space_info->lock);
		}
	}
}

static int block_rsv_migrate_bytes(struct btrfs_block_rsv *src,
				   struct btrfs_block_rsv *dst, u64 num_bytes)
{
	int ret;

	ret = block_rsv_use_bytes(src, num_bytes);
	if (ret)
		return ret;

	block_rsv_add_bytes(dst, num_bytes, 1);
	return 0;
}

void btrfs_init_block_rsv(struct btrfs_block_rsv *rsv, unsigned short type)
{
	memset(rsv, 0, sizeof(*rsv));
	spin_lock_init(&rsv->lock);
	rsv->type = type;
}

struct btrfs_block_rsv *btrfs_alloc_block_rsv(struct btrfs_root *root,
					      unsigned short type)
{
	struct btrfs_block_rsv *block_rsv;
	struct btrfs_fs_info *fs_info = root->fs_info;

	block_rsv = kmalloc(sizeof(*block_rsv), GFP_NOFS);
	if (!block_rsv)
		return NULL;

	btrfs_init_block_rsv(block_rsv, type);
	block_rsv->space_info = __find_space_info(fs_info,
						  BTRFS_BLOCK_GROUP_METADATA);
	return block_rsv;
}

void btrfs_free_block_rsv(struct btrfs_root *root,
			  struct btrfs_block_rsv *rsv)
{
	if (!rsv)
		return;
	btrfs_block_rsv_release(root, rsv, (u64)-1);
	kfree(rsv);
}

void __btrfs_free_block_rsv(struct btrfs_block_rsv *rsv)
{
	kfree(rsv);
}

int btrfs_block_rsv_add(struct btrfs_root *root,
			struct btrfs_block_rsv *block_rsv, u64 num_bytes,
			enum btrfs_reserve_flush_enum flush)
{
	int ret;

	if (num_bytes == 0)
		return 0;

	ret = reserve_metadata_bytes(root, block_rsv, num_bytes, flush);
	if (!ret) {
		block_rsv_add_bytes(block_rsv, num_bytes, 1);
		return 0;
	}

	return ret;
}

int btrfs_block_rsv_check(struct btrfs_root *root,
			  struct btrfs_block_rsv *block_rsv, int min_factor)
{
	u64 num_bytes = 0;
	int ret = -ENOSPC;

	if (!block_rsv)
		return 0;

	spin_lock(&block_rsv->lock);
	num_bytes = div_factor(block_rsv->size, min_factor);
	if (block_rsv->reserved >= num_bytes)
		ret = 0;
	spin_unlock(&block_rsv->lock);

	return ret;
}

int btrfs_block_rsv_refill(struct btrfs_root *root,
			   struct btrfs_block_rsv *block_rsv, u64 min_reserved,
			   enum btrfs_reserve_flush_enum flush)
{
	u64 num_bytes = 0;
	int ret = -ENOSPC;

	if (!block_rsv)
		return 0;

	spin_lock(&block_rsv->lock);
	num_bytes = min_reserved;
	if (block_rsv->reserved >= num_bytes)
		ret = 0;
	else
		num_bytes -= block_rsv->reserved;
	spin_unlock(&block_rsv->lock);

	if (!ret)
		return 0;

	ret = reserve_metadata_bytes(root, block_rsv, num_bytes, flush);
	if (!ret) {
		block_rsv_add_bytes(block_rsv, num_bytes, 0);
		return 0;
	}

	return ret;
}

int btrfs_block_rsv_migrate(struct btrfs_block_rsv *src_rsv,
			    struct btrfs_block_rsv *dst_rsv,
			    u64 num_bytes)
{
	return block_rsv_migrate_bytes(src_rsv, dst_rsv, num_bytes);
}

void btrfs_block_rsv_release(struct btrfs_root *root,
			     struct btrfs_block_rsv *block_rsv,
			     u64 num_bytes)
{
	struct btrfs_block_rsv *global_rsv = &root->fs_info->global_block_rsv;
	if (global_rsv == block_rsv ||
	    block_rsv->space_info != global_rsv->space_info)
		global_rsv = NULL;
	block_rsv_release_bytes(root->fs_info, block_rsv, global_rsv,
				num_bytes);
}

static void update_global_block_rsv(struct btrfs_fs_info *fs_info)
{
	struct btrfs_block_rsv *block_rsv = &fs_info->global_block_rsv;
	struct btrfs_space_info *sinfo = block_rsv->space_info;
	u64 num_bytes;

	num_bytes = btrfs_root_used(&fs_info->extent_root->root_item) +
		btrfs_root_used(&fs_info->csum_root->root_item) +
		btrfs_root_used(&fs_info->tree_root->root_item);
	num_bytes = max_t(u64, num_bytes, SZ_16M);

	spin_lock(&sinfo->lock);
	spin_lock(&block_rsv->lock);

#ifdef MY_ABC_HERE
	if (fs_info->super_copy->total_bytes > 80ULL * 1024 * 1024 * 1024) {
		num_bytes = max_t(u64, num_bytes, 256 * 1024 * 1024);
	}
#endif  
	block_rsv->size = min_t(u64, num_bytes, SZ_512M);

	if (block_rsv->reserved < block_rsv->size) {
		num_bytes = sinfo->bytes_used + sinfo->bytes_pinned +
			sinfo->bytes_reserved + sinfo->bytes_readonly +
			sinfo->bytes_may_use;
		if (sinfo->total_bytes > num_bytes) {
			num_bytes = sinfo->total_bytes - num_bytes;
			num_bytes = min(num_bytes,
					block_rsv->size - block_rsv->reserved);
			block_rsv->reserved += num_bytes;
			sinfo->bytes_may_use += num_bytes;
			trace_btrfs_space_reservation(fs_info, "space_info",
						      sinfo->flags, num_bytes,
						      1);
		}
	} else if (block_rsv->reserved > block_rsv->size) {
		num_bytes = block_rsv->reserved - block_rsv->size;
		sinfo->bytes_may_use -= num_bytes;
		trace_btrfs_space_reservation(fs_info, "space_info",
				      sinfo->flags, num_bytes, 0);
		block_rsv->reserved = block_rsv->size;
	}

	if (block_rsv->reserved == block_rsv->size)
		block_rsv->full = 1;
	else
		block_rsv->full = 0;

	spin_unlock(&block_rsv->lock);
	spin_unlock(&sinfo->lock);
}

static void init_global_block_rsv(struct btrfs_fs_info *fs_info)
{
	struct btrfs_space_info *space_info;

	space_info = __find_space_info(fs_info, BTRFS_BLOCK_GROUP_SYSTEM);
	fs_info->chunk_block_rsv.space_info = space_info;

	space_info = __find_space_info(fs_info, BTRFS_BLOCK_GROUP_METADATA);
	fs_info->global_block_rsv.space_info = space_info;
	fs_info->delalloc_block_rsv.space_info = space_info;
	fs_info->trans_block_rsv.space_info = space_info;
	fs_info->empty_block_rsv.space_info = space_info;
	fs_info->delayed_block_rsv.space_info = space_info;

	fs_info->extent_root->block_rsv = &fs_info->global_block_rsv;
	fs_info->csum_root->block_rsv = &fs_info->global_block_rsv;
	fs_info->dev_root->block_rsv = &fs_info->global_block_rsv;
	fs_info->tree_root->block_rsv = &fs_info->global_block_rsv;
	if (fs_info->quota_root)
		fs_info->quota_root->block_rsv = &fs_info->global_block_rsv;
	fs_info->chunk_root->block_rsv = &fs_info->chunk_block_rsv;

	update_global_block_rsv(fs_info);
}

static void release_global_block_rsv(struct btrfs_fs_info *fs_info)
{
	block_rsv_release_bytes(fs_info, &fs_info->global_block_rsv, NULL,
				(u64)-1);
	WARN_ON(fs_info->delalloc_block_rsv.size > 0);
	WARN_ON(fs_info->delalloc_block_rsv.reserved > 0);
	WARN_ON(fs_info->trans_block_rsv.size > 0);
	WARN_ON(fs_info->trans_block_rsv.reserved > 0);
	WARN_ON(fs_info->chunk_block_rsv.size > 0);
	WARN_ON(fs_info->chunk_block_rsv.reserved > 0);
	WARN_ON(fs_info->delayed_block_rsv.size > 0);
	WARN_ON(fs_info->delayed_block_rsv.reserved > 0);
}

void btrfs_trans_release_metadata(struct btrfs_trans_handle *trans,
				  struct btrfs_root *root)
{
	if (!trans->block_rsv)
		return;

	if (!trans->bytes_reserved)
		return;

	trace_btrfs_space_reservation(root->fs_info, "transaction",
				      trans->transid, trans->bytes_reserved, 0);
	btrfs_block_rsv_release(root, trans->block_rsv, trans->bytes_reserved);
	trans->bytes_reserved = 0;
}

void btrfs_trans_release_chunk_metadata(struct btrfs_trans_handle *trans)
{
	struct btrfs_fs_info *fs_info = trans->root->fs_info;

	if (!trans->chunk_bytes_reserved)
		return;

	WARN_ON_ONCE(!list_empty(&trans->new_bgs));

	block_rsv_release_bytes(fs_info, &fs_info->chunk_block_rsv, NULL,
				trans->chunk_bytes_reserved);
	trans->chunk_bytes_reserved = 0;
}

int btrfs_orphan_reserve_metadata(struct btrfs_trans_handle *trans,
				  struct inode *inode)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	 
	struct btrfs_block_rsv *src_rsv = trans->block_rsv;
	struct btrfs_block_rsv *dst_rsv = root->orphan_block_rsv;

	u64 num_bytes = btrfs_calc_trans_metadata_size(root, 1);
	trace_btrfs_space_reservation(root->fs_info, "orphan",
				      btrfs_ino(inode), num_bytes, 1);
	return block_rsv_migrate_bytes(src_rsv, dst_rsv, num_bytes);
}

void btrfs_orphan_release_metadata(struct inode *inode)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	u64 num_bytes = btrfs_calc_trans_metadata_size(root, 1);
	trace_btrfs_space_reservation(root->fs_info, "orphan",
				      btrfs_ino(inode), num_bytes, 0);
	btrfs_block_rsv_release(root, root->orphan_block_rsv, num_bytes);
}

int btrfs_subvolume_reserve_metadata(struct btrfs_root *root,
				     struct btrfs_block_rsv *rsv,
				     int items,
				     u64 *qgroup_reserved,
				     bool use_global_rsv)
{
	u64 num_bytes;
	int ret;
	struct btrfs_block_rsv *global_rsv = &root->fs_info->global_block_rsv;

	if (root->fs_info->quota_enabled) {
		 
		num_bytes = 3 * root->nodesize;
		ret = btrfs_qgroup_reserve_meta(root, num_bytes);
		if (ret)
			return ret;
	} else {
		num_bytes = 0;
	}

	*qgroup_reserved = num_bytes;

	num_bytes = btrfs_calc_trans_metadata_size(root, items);
	rsv->space_info = __find_space_info(root->fs_info,
					    BTRFS_BLOCK_GROUP_METADATA);
	ret = btrfs_block_rsv_add(root, rsv, num_bytes,
				  BTRFS_RESERVE_FLUSH_ALL);

	if (ret == -ENOSPC && use_global_rsv)
		ret = btrfs_block_rsv_migrate(global_rsv, rsv, num_bytes);

	if (ret && *qgroup_reserved)
		btrfs_qgroup_free_meta(root, *qgroup_reserved);

	return ret;
}

void btrfs_subvolume_release_metadata(struct btrfs_root *root,
				      struct btrfs_block_rsv *rsv,
				      u64 qgroup_reserved)
{
	btrfs_block_rsv_release(root, rsv, (u64)-1);
}

static unsigned drop_outstanding_extent(struct inode *inode, u64 num_bytes)
{
	unsigned drop_inode_space = 0;
	unsigned dropped_extents = 0;
	unsigned num_extents = 0;

	num_extents = (unsigned)div64_u64(num_bytes +
					  BTRFS_MAX_EXTENT_SIZE - 1,
					  BTRFS_MAX_EXTENT_SIZE);
	ASSERT(num_extents);
	ASSERT(BTRFS_I(inode)->outstanding_extents >= num_extents);
	BTRFS_I(inode)->outstanding_extents -= num_extents;

	if (BTRFS_I(inode)->outstanding_extents == 0 &&
	    test_and_clear_bit(BTRFS_INODE_DELALLOC_META_RESERVED,
			       &BTRFS_I(inode)->runtime_flags))
		drop_inode_space = 1;

	if (BTRFS_I(inode)->outstanding_extents >=
	    BTRFS_I(inode)->reserved_extents)
		return drop_inode_space;

	dropped_extents = BTRFS_I(inode)->reserved_extents -
		BTRFS_I(inode)->outstanding_extents;
	BTRFS_I(inode)->reserved_extents -= dropped_extents;
	return dropped_extents + drop_inode_space;
}

static u64 calc_csum_metadata_size(struct inode *inode, u64 num_bytes,
				   int reserve)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	u64 old_csums, num_csums;

	if (BTRFS_I(inode)->flags & BTRFS_INODE_NODATASUM &&
	    BTRFS_I(inode)->csum_bytes == 0)
		return 0;

	old_csums = btrfs_csum_bytes_to_leaves(root, BTRFS_I(inode)->csum_bytes);
	if (reserve)
		BTRFS_I(inode)->csum_bytes += num_bytes;
	else
		BTRFS_I(inode)->csum_bytes -= num_bytes;
	num_csums = btrfs_csum_bytes_to_leaves(root, BTRFS_I(inode)->csum_bytes);

	if (old_csums == num_csums)
		return 0;

	if (reserve)
		return btrfs_calc_trans_metadata_size(root,
						      num_csums - old_csums);

	return btrfs_calc_trans_metadata_size(root, old_csums - num_csums);
}

int btrfs_delalloc_reserve_metadata(struct inode *inode, u64 num_bytes)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_block_rsv *block_rsv = &root->fs_info->delalloc_block_rsv;
	u64 to_reserve = 0;
	u64 csum_bytes;
	unsigned nr_extents = 0;
	int extra_reserve = 0;
	enum btrfs_reserve_flush_enum flush = BTRFS_RESERVE_FLUSH_ALL;
	int ret = 0;
	bool delalloc_lock = true;
	u64 to_free = 0;
	unsigned dropped;

	if (btrfs_is_free_space_inode(inode)) {
		flush = BTRFS_RESERVE_NO_FLUSH;
		delalloc_lock = false;
	}

	if (flush != BTRFS_RESERVE_NO_FLUSH &&
	    btrfs_transaction_in_commit(root->fs_info))
		schedule_timeout(1);

	if (delalloc_lock)
		mutex_lock(&BTRFS_I(inode)->delalloc_mutex);

	num_bytes = ALIGN(num_bytes, root->sectorsize);

	spin_lock(&BTRFS_I(inode)->lock);
	nr_extents = (unsigned)div64_u64(num_bytes +
					 BTRFS_MAX_EXTENT_SIZE - 1,
					 BTRFS_MAX_EXTENT_SIZE);
	BTRFS_I(inode)->outstanding_extents += nr_extents;
	nr_extents = 0;

	if (BTRFS_I(inode)->outstanding_extents >
	    BTRFS_I(inode)->reserved_extents)
		nr_extents = BTRFS_I(inode)->outstanding_extents -
			BTRFS_I(inode)->reserved_extents;

	if (!test_bit(BTRFS_INODE_DELALLOC_META_RESERVED,
		      &BTRFS_I(inode)->runtime_flags)) {
		nr_extents++;
		extra_reserve = 1;
	}

	to_reserve = btrfs_calc_trans_metadata_size(root, nr_extents);
	to_reserve += calc_csum_metadata_size(inode, num_bytes, 1);
	csum_bytes = BTRFS_I(inode)->csum_bytes;
	spin_unlock(&BTRFS_I(inode)->lock);

	if (root->fs_info->quota_enabled) {
		ret = btrfs_qgroup_reserve_meta(root,
				nr_extents * root->nodesize);
		if (ret)
			goto out_fail;
	}

	ret = reserve_metadata_bytes(root, block_rsv, to_reserve, flush);
	if (unlikely(ret)) {
		btrfs_qgroup_free_meta(root, nr_extents * root->nodesize);
		goto out_fail;
	}

	spin_lock(&BTRFS_I(inode)->lock);
	if (extra_reserve) {
		set_bit(BTRFS_INODE_DELALLOC_META_RESERVED,
			&BTRFS_I(inode)->runtime_flags);
		nr_extents--;
	}
	BTRFS_I(inode)->reserved_extents += nr_extents;
	spin_unlock(&BTRFS_I(inode)->lock);

	if (delalloc_lock)
		mutex_unlock(&BTRFS_I(inode)->delalloc_mutex);

	if (to_reserve)
		trace_btrfs_space_reservation(root->fs_info, "delalloc",
					      btrfs_ino(inode), to_reserve, 1);
	block_rsv_add_bytes(block_rsv, to_reserve, 1);

	return 0;

out_fail:
	spin_lock(&BTRFS_I(inode)->lock);
	dropped = drop_outstanding_extent(inode, num_bytes);
	 
	if (BTRFS_I(inode)->csum_bytes == csum_bytes) {
		calc_csum_metadata_size(inode, num_bytes, 0);
	} else {
		u64 orig_csum_bytes = BTRFS_I(inode)->csum_bytes;
		u64 bytes;

		bytes = csum_bytes - BTRFS_I(inode)->csum_bytes;
		BTRFS_I(inode)->csum_bytes = csum_bytes;
		to_free = calc_csum_metadata_size(inode, bytes, 0);

		BTRFS_I(inode)->csum_bytes = csum_bytes - num_bytes;
		bytes = csum_bytes - orig_csum_bytes;
		bytes = calc_csum_metadata_size(inode, bytes, 0);

		BTRFS_I(inode)->csum_bytes = orig_csum_bytes - num_bytes;
		if (bytes > to_free)
			to_free = bytes - to_free;
		else
			to_free = 0;
	}
	spin_unlock(&BTRFS_I(inode)->lock);
	if (dropped)
		to_free += btrfs_calc_trans_metadata_size(root, dropped);

	if (to_free) {
		btrfs_block_rsv_release(root, block_rsv, to_free);
		trace_btrfs_space_reservation(root->fs_info, "delalloc",
					      btrfs_ino(inode), to_free, 0);
	}
	if (delalloc_lock)
		mutex_unlock(&BTRFS_I(inode)->delalloc_mutex);
	return ret;
}

void btrfs_delalloc_release_metadata(struct inode *inode, u64 num_bytes)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	u64 to_free = 0;
	unsigned dropped;

	num_bytes = ALIGN(num_bytes, root->sectorsize);
	spin_lock(&BTRFS_I(inode)->lock);
	dropped = drop_outstanding_extent(inode, num_bytes);

	if (num_bytes)
		to_free = calc_csum_metadata_size(inode, num_bytes, 0);
	spin_unlock(&BTRFS_I(inode)->lock);
	if (dropped > 0)
		to_free += btrfs_calc_trans_metadata_size(root, dropped);

	if (btrfs_test_is_dummy_root(root))
		return;

	trace_btrfs_space_reservation(root->fs_info, "delalloc",
				      btrfs_ino(inode), to_free, 0);

	btrfs_block_rsv_release(root, &root->fs_info->delalloc_block_rsv,
				to_free);
}

int btrfs_delalloc_reserve_space(struct inode *inode, u64 start, u64 len)
{
	int ret;

	ret = btrfs_check_data_free_space(inode, start, len);
	if (ret < 0)
		return ret;
	ret = btrfs_delalloc_reserve_metadata(inode, len);
	if (ret < 0)
		btrfs_free_reserved_data_space(inode, start, len);
	return ret;
}

void btrfs_delalloc_release_space(struct inode *inode, u64 start, u64 len)
{
	btrfs_delalloc_release_metadata(inode, len);
	btrfs_free_reserved_data_space(inode, start, len);
}

#ifdef MY_ABC_HERE
static int should_add_to_unused_bgs(struct btrfs_fs_info *fs_info, u64 flags)
{
	struct btrfs_space_info *space_info_metadata, *space_info_data;

	if (!(flags & BTRFS_BLOCK_GROUP_METADATA))
		return 1;

	space_info_metadata = __find_space_info(fs_info, BTRFS_BLOCK_GROUP_METADATA);
	space_info_data = __find_space_info(fs_info, BTRFS_BLOCK_GROUP_DATA);
	if (space_info_data->total_bytes > (space_info_metadata->total_bytes)*(fs_info->metadata_ratio))
		return 0;
	return 1;
}
#endif  

static int update_block_group(struct btrfs_trans_handle *trans,
			      struct btrfs_root *root, u64 bytenr,
			      u64 num_bytes, int alloc)
{
	struct btrfs_block_group_cache *cache = NULL;
	struct btrfs_fs_info *info = root->fs_info;
	u64 total = num_bytes;
	u64 old_val;
	u64 byte_in_group;
	int factor;

	spin_lock(&info->delalloc_root_lock);
	old_val = btrfs_super_bytes_used(info->super_copy);
	if (alloc)
		old_val += num_bytes;
	else
		old_val -= num_bytes;
	btrfs_set_super_bytes_used(info->super_copy, old_val);
	spin_unlock(&info->delalloc_root_lock);

	while (total) {
		cache = btrfs_lookup_block_group(info, bytenr);
		if (!cache)
			return -ENOENT;
		if (cache->flags & (BTRFS_BLOCK_GROUP_DUP |
				    BTRFS_BLOCK_GROUP_RAID1 |
				    BTRFS_BLOCK_GROUP_RAID10))
			factor = 2;
		else
			factor = 1;
		 
		if (!alloc && cache->cached == BTRFS_CACHE_NO)
			cache_block_group(cache, 1);

		byte_in_group = bytenr - cache->key.objectid;
		WARN_ON(byte_in_group > cache->key.offset);

		spin_lock(&cache->space_info->lock);
		spin_lock(&cache->lock);

		if (btrfs_test_opt(root, SPACE_CACHE) &&
		    cache->disk_cache_state < BTRFS_DC_CLEAR)
			cache->disk_cache_state = BTRFS_DC_CLEAR;

		old_val = btrfs_block_group_used(&cache->item);
		num_bytes = min(total, cache->key.offset - byte_in_group);
		if (alloc) {
			old_val += num_bytes;
			btrfs_set_block_group_used(&cache->item, old_val);
			cache->reserved -= num_bytes;
			cache->space_info->bytes_reserved -= num_bytes;
			cache->space_info->bytes_used += num_bytes;
			cache->space_info->disk_used += num_bytes * factor;
			spin_unlock(&cache->lock);
			spin_unlock(&cache->space_info->lock);
		} else {
			old_val -= num_bytes;
			btrfs_set_block_group_used(&cache->item, old_val);
			cache->pinned += num_bytes;
			cache->space_info->bytes_pinned += num_bytes;
			cache->space_info->bytes_used -= num_bytes;
			cache->space_info->disk_used -= num_bytes * factor;
			spin_unlock(&cache->lock);
			spin_unlock(&cache->space_info->lock);

			set_extent_dirty(info->pinned_extents,
					 bytenr, bytenr + num_bytes - 1,
					 GFP_NOFS | __GFP_NOFAIL);
		}

		spin_lock(&trans->transaction->dirty_bgs_lock);
		if (list_empty(&cache->dirty_list)) {
			list_add_tail(&cache->dirty_list,
				      &trans->transaction->dirty_bgs);
				trans->transaction->num_dirty_bgs++;
			btrfs_get_block_group(cache);
		}
		spin_unlock(&trans->transaction->dirty_bgs_lock);

#ifdef MY_ABC_HERE
		if (!alloc && old_val == 0 && should_add_to_unused_bgs(info, cache->flags)) {
#else
		if (!alloc && old_val == 0) {
#endif  
			spin_lock(&info->unused_bgs_lock);
			if (list_empty(&cache->bg_list)) {
				btrfs_get_block_group(cache);
				list_add_tail(&cache->bg_list,
					      &info->unused_bgs);
			}
			spin_unlock(&info->unused_bgs_lock);
		}

		btrfs_put_block_group(cache);
		total -= num_bytes;
		bytenr += num_bytes;
	}
	return 0;
}

static u64 first_logical_byte(struct btrfs_root *root, u64 search_start)
{
	struct btrfs_block_group_cache *cache;
	u64 bytenr;

	spin_lock(&root->fs_info->block_group_cache_lock);
	bytenr = root->fs_info->first_logical_byte;
	spin_unlock(&root->fs_info->block_group_cache_lock);

	if (bytenr < (u64)-1)
		return bytenr;

	cache = btrfs_lookup_first_block_group(root->fs_info, search_start);
	if (!cache)
		return 0;

	bytenr = cache->key.objectid;
	btrfs_put_block_group(cache);

	return bytenr;
}

static int pin_down_extent(struct btrfs_root *root,
			   struct btrfs_block_group_cache *cache,
			   u64 bytenr, u64 num_bytes, int reserved)
{
	spin_lock(&cache->space_info->lock);
	spin_lock(&cache->lock);
	cache->pinned += num_bytes;
	cache->space_info->bytes_pinned += num_bytes;
	if (reserved) {
		cache->reserved -= num_bytes;
		cache->space_info->bytes_reserved -= num_bytes;
	}
	spin_unlock(&cache->lock);
	spin_unlock(&cache->space_info->lock);

	set_extent_dirty(root->fs_info->pinned_extents, bytenr,
			 bytenr + num_bytes - 1, GFP_NOFS | __GFP_NOFAIL);
	if (reserved)
		trace_btrfs_reserved_extent_free(root, bytenr, num_bytes);
	return 0;
}

int btrfs_pin_extent(struct btrfs_root *root,
		     u64 bytenr, u64 num_bytes, int reserved)
{
	struct btrfs_block_group_cache *cache;

	cache = btrfs_lookup_block_group(root->fs_info, bytenr);
	BUG_ON(!cache);  

	pin_down_extent(root, cache, bytenr, num_bytes, reserved);

	btrfs_put_block_group(cache);
	return 0;
}

int btrfs_pin_extent_for_log_replay(struct btrfs_root *root,
				    u64 bytenr, u64 num_bytes)
{
	struct btrfs_block_group_cache *cache;
	int ret;

	cache = btrfs_lookup_block_group(root->fs_info, bytenr);
	if (!cache)
		return -EINVAL;

	cache_block_group(cache, 1);

	pin_down_extent(root, cache, bytenr, num_bytes, 0);

	ret = btrfs_remove_free_space(cache, bytenr, num_bytes);
	btrfs_put_block_group(cache);
	return ret;
}

static int __exclude_logged_extent(struct btrfs_root *root, u64 start, u64 num_bytes)
{
	int ret;
	struct btrfs_block_group_cache *block_group;
	struct btrfs_caching_control *caching_ctl;

	block_group = btrfs_lookup_block_group(root->fs_info, start);
	if (!block_group)
		return -EINVAL;

	cache_block_group(block_group, 0);
	caching_ctl = get_caching_control(block_group);

	if (!caching_ctl) {
		 
		BUG_ON(!block_group_cache_done(block_group));
		ret = btrfs_remove_free_space(block_group, start, num_bytes);
	} else {
		mutex_lock(&caching_ctl->mutex);

		if (start >= caching_ctl->progress) {
			ret = add_excluded_extent(root, start, num_bytes);
		} else if (start + num_bytes <= caching_ctl->progress) {
			ret = btrfs_remove_free_space(block_group,
						      start, num_bytes);
		} else {
			num_bytes = caching_ctl->progress - start;
			ret = btrfs_remove_free_space(block_group,
						      start, num_bytes);
			if (ret)
				goto out_lock;

			num_bytes = (start + num_bytes) -
				caching_ctl->progress;
			start = caching_ctl->progress;
			ret = add_excluded_extent(root, start, num_bytes);
		}
out_lock:
		mutex_unlock(&caching_ctl->mutex);
		put_caching_control(caching_ctl);
	}
	btrfs_put_block_group(block_group);
	return ret;
}

int btrfs_exclude_logged_extents(struct btrfs_root *log,
				 struct extent_buffer *eb)
{
	struct btrfs_file_extent_item *item;
	struct btrfs_key key;
	int found_type;
	int i;

	if (!btrfs_fs_incompat(log->fs_info, MIXED_GROUPS))
		return 0;

	for (i = 0; i < btrfs_header_nritems(eb); i++) {
		btrfs_item_key_to_cpu(eb, &key, i);
		if (key.type != BTRFS_EXTENT_DATA_KEY)
			continue;
		item = btrfs_item_ptr(eb, i, struct btrfs_file_extent_item);
		found_type = btrfs_file_extent_type(eb, item);
		if (found_type == BTRFS_FILE_EXTENT_INLINE)
			continue;
		if (btrfs_file_extent_disk_bytenr(eb, item) == 0)
			continue;
		key.objectid = btrfs_file_extent_disk_bytenr(eb, item);
		key.offset = btrfs_file_extent_disk_num_bytes(eb, item);
		__exclude_logged_extent(log, key.objectid, key.offset);
	}

	return 0;
}

static void
btrfs_inc_block_group_reservations(struct btrfs_block_group_cache *bg)
{
	atomic_inc(&bg->reservations);
}

void btrfs_dec_block_group_reservations(struct btrfs_fs_info *fs_info,
					const u64 start)
{
	struct btrfs_block_group_cache *bg;

	bg = btrfs_lookup_block_group(fs_info, start);
	ASSERT(bg);
	if (atomic_dec_and_test(&bg->reservations))
		wake_up_atomic_t(&bg->reservations);
	btrfs_put_block_group(bg);
}

static int btrfs_wait_bg_reservations_atomic_t(atomic_t *a)
{
	schedule();
	return 0;
}

void btrfs_wait_block_group_reservations(struct btrfs_block_group_cache *bg)
{
	struct btrfs_space_info *space_info = bg->space_info;

	ASSERT(bg->ro);

	if (!(bg->flags & BTRFS_BLOCK_GROUP_DATA))
		return;

	down_write(&space_info->groups_sem);
	up_write(&space_info->groups_sem);

	wait_on_atomic_t(&bg->reservations,
			 btrfs_wait_bg_reservations_atomic_t,
			 TASK_UNINTERRUPTIBLE);
}

static int btrfs_update_reserved_bytes(struct btrfs_block_group_cache *cache,
				       u64 num_bytes, int reserve, int delalloc)
{
	struct btrfs_space_info *space_info = cache->space_info;
	int ret = 0;

	spin_lock(&space_info->lock);
	spin_lock(&cache->lock);
	if (reserve != RESERVE_FREE) {
		if (cache->ro) {
			ret = -EAGAIN;
		} else {
			cache->reserved += num_bytes;
			space_info->bytes_reserved += num_bytes;
			if (reserve == RESERVE_ALLOC) {
				trace_btrfs_space_reservation(cache->fs_info,
						"space_info", space_info->flags,
						num_bytes, 0);
				space_info->bytes_may_use -= num_bytes;
			}

			if (delalloc)
				cache->delalloc_bytes += num_bytes;
		}
	} else {
		if (cache->ro)
			space_info->bytes_readonly += num_bytes;
		cache->reserved -= num_bytes;
		space_info->bytes_reserved -= num_bytes;

		if (delalloc)
			cache->delalloc_bytes -= num_bytes;
	}
	spin_unlock(&cache->lock);
	spin_unlock(&space_info->lock);
	return ret;
}

void btrfs_prepare_extent_commit(struct btrfs_trans_handle *trans,
				struct btrfs_root *root)
{
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_caching_control *next;
	struct btrfs_caching_control *caching_ctl;
	struct btrfs_block_group_cache *cache;

	down_write(&fs_info->commit_root_sem);

	list_for_each_entry_safe(caching_ctl, next,
				 &fs_info->caching_block_groups, list) {
		cache = caching_ctl->block_group;
		if (block_group_cache_done(cache)) {
			cache->last_byte_to_unpin = (u64)-1;
			list_del_init(&caching_ctl->list);
			put_caching_control(caching_ctl);
		} else {
			cache->last_byte_to_unpin = caching_ctl->progress;
		}
	}

	if (fs_info->pinned_extents == &fs_info->freed_extents[0])
		fs_info->pinned_extents = &fs_info->freed_extents[1];
	else
		fs_info->pinned_extents = &fs_info->freed_extents[0];

	up_write(&fs_info->commit_root_sem);

	update_global_block_rsv(fs_info);
}

static struct btrfs_free_cluster *
fetch_cluster_info(struct btrfs_root *root, struct btrfs_space_info *space_info,
		   u64 *empty_cluster)
{
	struct btrfs_free_cluster *ret = NULL;
	bool ssd = btrfs_test_opt(root, SSD);

	*empty_cluster = 0;
	if (btrfs_mixed_space_info(space_info))
		return ret;

	if (ssd)
		*empty_cluster = SZ_2M;
	if (space_info->flags & BTRFS_BLOCK_GROUP_METADATA) {
		ret = &root->fs_info->meta_alloc_cluster;
		if (!ssd)
			*empty_cluster = SZ_64K;
	} else if ((space_info->flags & BTRFS_BLOCK_GROUP_DATA) && ssd) {
		ret = &root->fs_info->data_alloc_cluster;
	}

	return ret;
}

static int unpin_extent_range(struct btrfs_root *root, u64 start, u64 end,
			      const bool return_free_space)
{
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_block_group_cache *cache = NULL;
	struct btrfs_space_info *space_info;
	struct btrfs_block_rsv *global_rsv = &fs_info->global_block_rsv;
	struct btrfs_free_cluster *cluster = NULL;
	u64 len;
	u64 total_unpinned = 0;
	u64 empty_cluster = 0;
	bool readonly;

	while (start <= end) {
		readonly = false;
		if (!cache ||
		    start >= cache->key.objectid + cache->key.offset) {
			if (cache)
				btrfs_put_block_group(cache);
			total_unpinned = 0;
			cache = btrfs_lookup_block_group(fs_info, start);
			BUG_ON(!cache);  

			cluster = fetch_cluster_info(root,
						     cache->space_info,
						     &empty_cluster);
			empty_cluster <<= 1;
		}

		len = cache->key.objectid + cache->key.offset - start;
		len = min(len, end + 1 - start);

		if (start < cache->last_byte_to_unpin) {
			len = min(len, cache->last_byte_to_unpin - start);
			if (return_free_space)
				btrfs_add_free_space(cache, start, len);
		}

		start += len;
		total_unpinned += len;
		space_info = cache->space_info;

		if (cluster && cluster->fragmented &&
		    total_unpinned > empty_cluster) {
			spin_lock(&cluster->lock);
			cluster->fragmented = 0;
			spin_unlock(&cluster->lock);
		}

		spin_lock(&space_info->lock);
		spin_lock(&cache->lock);
		cache->pinned -= len;
		space_info->bytes_pinned -= len;
		space_info->max_extent_size = 0;
		percpu_counter_add(&space_info->total_bytes_pinned, -len);
		if (cache->ro) {
			space_info->bytes_readonly += len;
			readonly = true;
		}
		spin_unlock(&cache->lock);
		if (!readonly && global_rsv->space_info == space_info) {
			spin_lock(&global_rsv->lock);
			if (!global_rsv->full) {
				len = min(len, global_rsv->size -
					  global_rsv->reserved);
				global_rsv->reserved += len;
				space_info->bytes_may_use += len;
				if (global_rsv->reserved >= global_rsv->size)
					global_rsv->full = 1;
			}
			spin_unlock(&global_rsv->lock);
		}
		spin_unlock(&space_info->lock);
	}

	if (cache)
		btrfs_put_block_group(cache);
	return 0;
}

int btrfs_finish_extent_commit(struct btrfs_trans_handle *trans,
			       struct btrfs_root *root)
{
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_block_group_cache *block_group, *tmp;
	struct list_head *deleted_bgs;
	struct extent_io_tree *unpin;
	u64 start;
	u64 end;
	int ret;

	if (fs_info->pinned_extents == &fs_info->freed_extents[0])
		unpin = &fs_info->freed_extents[1];
	else
		unpin = &fs_info->freed_extents[0];

	while (!trans->aborted) {
		mutex_lock(&fs_info->unused_bg_unpin_mutex);
		ret = find_first_extent_bit(unpin, 0, &start, &end,
					    EXTENT_DIRTY, NULL);
		if (ret) {
			mutex_unlock(&fs_info->unused_bg_unpin_mutex);
			break;
		}

		if (btrfs_test_opt(root, DISCARD))
			ret = btrfs_discard_extent(root, start,
						   end + 1 - start, NULL);

		clear_extent_dirty(unpin, start, end);
		unpin_extent_range(root, start, end, true);
		mutex_unlock(&fs_info->unused_bg_unpin_mutex);
		cond_resched();
	}

	deleted_bgs = &trans->transaction->deleted_bgs;
	list_for_each_entry_safe(block_group, tmp, deleted_bgs, bg_list) {
		u64 trimmed = 0;

		ret = -EROFS;
		if (!trans->aborted)
			ret = btrfs_discard_extent(root,
						   block_group->key.objectid,
						   block_group->key.offset,
						   &trimmed);

		list_del_init(&block_group->bg_list);
		btrfs_put_block_group_trimming(block_group);
		btrfs_put_block_group(block_group);

		if (ret) {
			const char *errstr = btrfs_decode_error(ret);
			btrfs_warn(fs_info,
				   "Discard failed while removing blockgroup: errno=%d %s\n",
				   ret, errstr);
		}
	}

	return 0;
}

static void add_pinned_bytes(struct btrfs_fs_info *fs_info, u64 num_bytes,
			     u64 owner, u64 root_objectid)
{
	struct btrfs_space_info *space_info;
	u64 flags;

	if (owner < BTRFS_FIRST_FREE_OBJECTID) {
		if (root_objectid == BTRFS_CHUNK_TREE_OBJECTID)
			flags = BTRFS_BLOCK_GROUP_SYSTEM;
		else
			flags = BTRFS_BLOCK_GROUP_METADATA;
	} else {
		flags = BTRFS_BLOCK_GROUP_DATA;
	}

	space_info = __find_space_info(fs_info, flags);
	BUG_ON(!space_info);  
	percpu_counter_add(&space_info->total_bytes_pinned, num_bytes);
}

static int __btrfs_free_extent(struct btrfs_trans_handle *trans,
				struct btrfs_root *root,
				struct btrfs_delayed_ref_node *node, u64 parent,
				u64 root_objectid, u64 owner_objectid,
				u64 owner_offset, int refs_to_drop,
				struct btrfs_delayed_extent_op *extent_op)
{
	struct btrfs_key key;
	struct btrfs_path *path;
	struct btrfs_fs_info *info = root->fs_info;
	struct btrfs_root *extent_root = info->extent_root;
	struct extent_buffer *leaf;
	struct btrfs_extent_item *ei;
	struct btrfs_extent_inline_ref *iref;
	int ret;
	int is_data;
	int extent_slot = 0;
	int found_extent = 0;
	int num_to_del = 1;
	u32 item_size;
	u64 refs;
	u64 bytenr = node->bytenr;
	u64 num_bytes = node->num_bytes;
	int last_ref = 0;
	bool skinny_metadata = btrfs_fs_incompat(root->fs_info,
						 SKINNY_METADATA);

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	path->reada = READA_FORWARD;
	path->leave_spinning = 1;

	is_data = owner_objectid >= BTRFS_FIRST_FREE_OBJECTID;
	BUG_ON(!is_data && refs_to_drop != 1);

	if (is_data)
		skinny_metadata = 0;

	ret = lookup_extent_backref(trans, extent_root, path, &iref,
				    bytenr, num_bytes, parent,
				    root_objectid, owner_objectid,
				    owner_offset);
	if (ret == 0) {
		extent_slot = path->slots[0];
		while (extent_slot >= 0) {
			btrfs_item_key_to_cpu(path->nodes[0], &key,
					      extent_slot);
			if (key.objectid != bytenr)
				break;
			if (key.type == BTRFS_EXTENT_ITEM_KEY &&
			    key.offset == num_bytes) {
				found_extent = 1;
				break;
			}
			if (key.type == BTRFS_METADATA_ITEM_KEY &&
			    key.offset == owner_objectid) {
				found_extent = 1;
				break;
			}
			if (path->slots[0] - extent_slot > 5)
				break;
			extent_slot--;
		}
#ifdef BTRFS_COMPAT_EXTENT_TREE_V0
		item_size = btrfs_item_size_nr(path->nodes[0], extent_slot);
		if (found_extent && item_size < sizeof(*ei))
			found_extent = 0;
#endif
		if (!found_extent) {
			BUG_ON(iref);
			ret = remove_extent_backref(trans, extent_root, path,
						    NULL, refs_to_drop,
						    is_data, &last_ref);
			if (ret) {
				btrfs_abort_transaction(trans, extent_root, ret);
				goto out;
			}
			btrfs_release_path(path);
			path->leave_spinning = 1;

			key.objectid = bytenr;
			key.type = BTRFS_EXTENT_ITEM_KEY;
			key.offset = num_bytes;

			if (!is_data && skinny_metadata) {
				key.type = BTRFS_METADATA_ITEM_KEY;
				key.offset = owner_objectid;
			}

			ret = btrfs_search_slot(trans, extent_root,
						&key, path, -1, 1);
			if (ret > 0 && skinny_metadata && path->slots[0]) {
				 
				path->slots[0]--;
				btrfs_item_key_to_cpu(path->nodes[0], &key,
						      path->slots[0]);
				if (key.objectid == bytenr &&
				    key.type == BTRFS_EXTENT_ITEM_KEY &&
				    key.offset == num_bytes)
					ret = 0;
			}

			if (ret > 0 && skinny_metadata) {
				skinny_metadata = false;
				key.objectid = bytenr;
				key.type = BTRFS_EXTENT_ITEM_KEY;
				key.offset = num_bytes;
				btrfs_release_path(path);
				ret = btrfs_search_slot(trans, extent_root,
							&key, path, -1, 1);
			}

			if (ret) {
				btrfs_err(info, "umm, got %d back from search, was looking for %llu",
					ret, bytenr);
				if (ret > 0)
					btrfs_print_leaf(extent_root,
							 path->nodes[0]);
			}
			if (ret < 0) {
				btrfs_abort_transaction(trans, extent_root, ret);
				goto out;
			}
			extent_slot = path->slots[0];
		}
	} else if (WARN_ON(ret == -ENOENT)) {
		btrfs_print_leaf(extent_root, path->nodes[0]);
		btrfs_err(info,
			"unable to find ref byte nr %llu parent %llu root %llu  owner %llu offset %llu",
			bytenr, parent, root_objectid, owner_objectid,
			owner_offset);
		btrfs_abort_transaction(trans, extent_root, ret);
		goto out;
	} else {
		btrfs_abort_transaction(trans, extent_root, ret);
		goto out;
	}

	leaf = path->nodes[0];
	item_size = btrfs_item_size_nr(leaf, extent_slot);
#ifdef BTRFS_COMPAT_EXTENT_TREE_V0
	if (item_size < sizeof(*ei)) {
		BUG_ON(found_extent || extent_slot != path->slots[0]);
		ret = convert_extent_item_v0(trans, extent_root, path,
					     owner_objectid, 0);
		if (ret < 0) {
			btrfs_abort_transaction(trans, extent_root, ret);
			goto out;
		}

		btrfs_release_path(path);
		path->leave_spinning = 1;

		key.objectid = bytenr;
		key.type = BTRFS_EXTENT_ITEM_KEY;
		key.offset = num_bytes;

		ret = btrfs_search_slot(trans, extent_root, &key, path,
					-1, 1);
		if (ret) {
			btrfs_err(info, "umm, got %d back from search, was looking for %llu",
				ret, bytenr);
			btrfs_print_leaf(extent_root, path->nodes[0]);
		}
		if (ret < 0) {
			btrfs_abort_transaction(trans, extent_root, ret);
			goto out;
		}

		extent_slot = path->slots[0];
		leaf = path->nodes[0];
		item_size = btrfs_item_size_nr(leaf, extent_slot);
	}
#endif
	BUG_ON(item_size < sizeof(*ei));
	ei = btrfs_item_ptr(leaf, extent_slot,
			    struct btrfs_extent_item);
	if (owner_objectid < BTRFS_FIRST_FREE_OBJECTID &&
	    key.type == BTRFS_EXTENT_ITEM_KEY) {
		struct btrfs_tree_block_info *bi;
		BUG_ON(item_size < sizeof(*ei) + sizeof(*bi));
		bi = (struct btrfs_tree_block_info *)(ei + 1);
		WARN_ON(owner_objectid != btrfs_tree_block_level(leaf, bi));
	}

	refs = btrfs_extent_refs(leaf, ei);
	if (refs < refs_to_drop) {
		btrfs_err(info, "trying to drop %d refs but we only have %Lu "
			  "for bytenr %Lu", refs_to_drop, refs, bytenr);
		ret = -EINVAL;
		btrfs_abort_transaction(trans, extent_root, ret);
		goto out;
	}
	refs -= refs_to_drop;

	if (refs > 0) {
		if (extent_op)
			__run_delayed_extent_op(extent_op, leaf, ei);
		 
		if (iref) {
			BUG_ON(!found_extent);
		} else {
			btrfs_set_extent_refs(leaf, ei, refs);
			btrfs_mark_buffer_dirty(leaf);
		}
		if (found_extent) {
			ret = remove_extent_backref(trans, extent_root, path,
						    iref, refs_to_drop,
						    is_data, &last_ref);
			if (ret) {
				btrfs_abort_transaction(trans, extent_root, ret);
				goto out;
			}
		}
		add_pinned_bytes(root->fs_info, -num_bytes, owner_objectid,
				 root_objectid);
	} else {
		if (found_extent) {
			BUG_ON(is_data && refs_to_drop !=
			       extent_data_ref_count(path, iref));
			if (iref) {
				BUG_ON(path->slots[0] != extent_slot);
			} else {
				BUG_ON(path->slots[0] != extent_slot + 1);
				path->slots[0] = extent_slot;
				num_to_del = 2;
			}
		}

		last_ref = 1;
		ret = btrfs_del_items(trans, extent_root, path, path->slots[0],
				      num_to_del);
		if (ret) {
			btrfs_abort_transaction(trans, extent_root, ret);
			goto out;
		}
		btrfs_release_path(path);

		if (is_data) {
			ret = btrfs_del_csums(trans, root, bytenr, num_bytes);
			if (ret) {
				btrfs_abort_transaction(trans, extent_root, ret);
				goto out;
			}
		}

		ret = add_to_free_space_tree(trans, root->fs_info, bytenr,
					     num_bytes);
		if (ret) {
			btrfs_abort_transaction(trans, extent_root, ret);
			goto out;
		}

		ret = update_block_group(trans, root, bytenr, num_bytes, 0);
		if (ret) {
			btrfs_abort_transaction(trans, extent_root, ret);
			goto out;
		}
	}
	btrfs_release_path(path);

out:
	btrfs_free_path(path);
	return ret;
}

static noinline int check_ref_cleanup(struct btrfs_trans_handle *trans,
				      struct btrfs_root *root, u64 bytenr)
{
	struct btrfs_delayed_ref_head *head;
	struct btrfs_delayed_ref_root *delayed_refs;
	int ret = 0;

	delayed_refs = &trans->transaction->delayed_refs;
	spin_lock(&delayed_refs->lock);
	head = btrfs_find_delayed_ref_head(trans, bytenr);
	if (!head)
		goto out_delayed_unlock;

	spin_lock(&head->lock);
	if (!list_empty(&head->ref_list))
		goto out;

	if (head->extent_op) {
		if (!head->must_insert_reserved)
			goto out;
		btrfs_free_delayed_extent_op(head->extent_op);
		head->extent_op = NULL;
	}

	if (!mutex_trylock(&head->mutex))
		goto out;

	head->node.in_tree = 0;
	rb_erase(&head->href_node, &delayed_refs->href_root);

	atomic_dec(&delayed_refs->num_entries);

	delayed_refs->num_heads--;
	if (head->processing == 0)
		delayed_refs->num_heads_ready--;
	head->processing = 0;
	spin_unlock(&head->lock);
	spin_unlock(&delayed_refs->lock);

	BUG_ON(head->extent_op);
	if (head->must_insert_reserved)
		ret = 1;

	mutex_unlock(&head->mutex);
	btrfs_put_delayed_ref(&head->node);
	return ret;
out:
	spin_unlock(&head->lock);

out_delayed_unlock:
	spin_unlock(&delayed_refs->lock);
	return 0;
}

void btrfs_free_tree_block(struct btrfs_trans_handle *trans,
			   struct btrfs_root *root,
			   struct extent_buffer *buf,
			   u64 parent, int last_ref)
{
	int pin = 1;
	int ret;

	if (root->root_key.objectid != BTRFS_TREE_LOG_OBJECTID) {
		ret = btrfs_add_delayed_tree_ref(root->fs_info, trans,
					buf->start, buf->len,
					parent, root->root_key.objectid,
					btrfs_header_level(buf),
					BTRFS_DROP_DELAYED_REF, NULL);
		BUG_ON(ret);  
	}

	if (!last_ref)
		return;

	if (btrfs_header_generation(buf) == trans->transid) {
		struct btrfs_block_group_cache *cache;

		if (root->root_key.objectid != BTRFS_TREE_LOG_OBJECTID) {
			ret = check_ref_cleanup(trans, root, buf->start);
			if (!ret)
				goto out;
		}

		cache = btrfs_lookup_block_group(root->fs_info, buf->start);

		if (btrfs_header_flag(buf, BTRFS_HEADER_FLAG_WRITTEN)) {
			pin_down_extent(root, cache, buf->start, buf->len, 1);
			btrfs_put_block_group(cache);
			goto out;
		}

		WARN_ON(test_bit(EXTENT_BUFFER_DIRTY, &buf->bflags));

		btrfs_add_free_space(cache, buf->start, buf->len);
		btrfs_update_reserved_bytes(cache, buf->len, RESERVE_FREE, 0);
		btrfs_put_block_group(cache);
		trace_btrfs_reserved_extent_free(root, buf->start, buf->len);
		pin = 0;
	}
out:
	if (pin)
		add_pinned_bytes(root->fs_info, buf->len,
				 btrfs_header_level(buf),
				 root->root_key.objectid);

	clear_bit(EXTENT_BUFFER_CORRUPT, &buf->bflags);
}

int btrfs_free_extent(struct btrfs_trans_handle *trans, struct btrfs_root *root,
		      u64 bytenr, u64 num_bytes, u64 parent, u64 root_objectid,
		      u64 owner, u64 offset)
{
	int ret;
	struct btrfs_fs_info *fs_info = root->fs_info;

	if (btrfs_test_is_dummy_root(root))
		return 0;

	add_pinned_bytes(root->fs_info, num_bytes, owner, root_objectid);

	if (root_objectid == BTRFS_TREE_LOG_OBJECTID) {
		WARN_ON(owner >= BTRFS_FIRST_FREE_OBJECTID);
		 
		btrfs_pin_extent(root, bytenr, num_bytes, 1);
		ret = 0;
	} else if (owner < BTRFS_FIRST_FREE_OBJECTID) {
		ret = btrfs_add_delayed_tree_ref(fs_info, trans, bytenr,
					num_bytes,
					parent, root_objectid, (int)owner,
					BTRFS_DROP_DELAYED_REF, NULL);
	} else {
		ret = btrfs_add_delayed_data_ref(fs_info, trans, bytenr,
						num_bytes,
						parent, root_objectid, owner,
						offset, 0,
						BTRFS_DROP_DELAYED_REF, NULL);
	}
	return ret;
}

static noinline void
wait_block_group_cache_progress(struct btrfs_block_group_cache *cache,
				u64 num_bytes)
{
	struct btrfs_caching_control *caching_ctl;

	caching_ctl = get_caching_control(cache);
	if (!caching_ctl)
		return;

	wait_event(caching_ctl->wait, block_group_cache_done(cache) ||
		   (cache->free_space_ctl->free_space >= num_bytes));

	put_caching_control(caching_ctl);
}

static noinline int
wait_block_group_cache_done(struct btrfs_block_group_cache *cache)
{
	struct btrfs_caching_control *caching_ctl;
	int ret = 0;

	caching_ctl = get_caching_control(cache);
	if (!caching_ctl)
		return (cache->cached == BTRFS_CACHE_ERROR) ? -EIO : 0;

	wait_event(caching_ctl->wait, block_group_cache_done(cache));
	if (cache->cached == BTRFS_CACHE_ERROR)
		ret = -EIO;
	put_caching_control(caching_ctl);
	return ret;
}

int __get_raid_index(u64 flags)
{
	if (flags & BTRFS_BLOCK_GROUP_RAID10)
		return BTRFS_RAID_RAID10;
	else if (flags & BTRFS_BLOCK_GROUP_RAID1)
		return BTRFS_RAID_RAID1;
	else if (flags & BTRFS_BLOCK_GROUP_DUP)
		return BTRFS_RAID_DUP;
	else if (flags & BTRFS_BLOCK_GROUP_RAID0)
		return BTRFS_RAID_RAID0;
	else if (flags & BTRFS_BLOCK_GROUP_RAID5)
		return BTRFS_RAID_RAID5;
	else if (flags & BTRFS_BLOCK_GROUP_RAID6)
		return BTRFS_RAID_RAID6;

	return BTRFS_RAID_SINGLE;  
}

int get_block_group_index(struct btrfs_block_group_cache *cache)
{
	return __get_raid_index(cache->flags);
}

static const char *btrfs_raid_type_names[BTRFS_NR_RAID_TYPES] = {
	[BTRFS_RAID_RAID10]	= "raid10",
	[BTRFS_RAID_RAID1]	= "raid1",
	[BTRFS_RAID_DUP]	= "dup",
	[BTRFS_RAID_RAID0]	= "raid0",
	[BTRFS_RAID_SINGLE]	= "single",
	[BTRFS_RAID_RAID5]	= "raid5",
	[BTRFS_RAID_RAID6]	= "raid6",
};

static const char *get_raid_name(enum btrfs_raid_types type)
{
	if (type >= BTRFS_NR_RAID_TYPES)
		return NULL;

	return btrfs_raid_type_names[type];
}

enum btrfs_loop_type {
	LOOP_CACHING_NOWAIT = 0,
	LOOP_CACHING_WAIT = 1,
	LOOP_ALLOC_CHUNK = 2,
	LOOP_NO_EMPTY_SIZE = 3,
};

static inline void
btrfs_lock_block_group(struct btrfs_block_group_cache *cache,
		       int delalloc)
{
	if (delalloc)
		down_read(&cache->data_rwsem);
}

static inline void
btrfs_grab_block_group(struct btrfs_block_group_cache *cache,
		       int delalloc)
{
	btrfs_get_block_group(cache);
	if (delalloc)
		down_read(&cache->data_rwsem);
}

static struct btrfs_block_group_cache *
btrfs_lock_cluster(struct btrfs_block_group_cache *block_group,
		   struct btrfs_free_cluster *cluster,
		   int delalloc)
{
	struct btrfs_block_group_cache *used_bg = NULL;

	spin_lock(&cluster->refill_lock);
	while (1) {
		used_bg = cluster->block_group;
		if (!used_bg)
			return NULL;

		if (used_bg == block_group)
			return used_bg;

		btrfs_get_block_group(used_bg);

		if (!delalloc)
			return used_bg;

		if (down_read_trylock(&used_bg->data_rwsem))
			return used_bg;

		spin_unlock(&cluster->refill_lock);

		down_read(&used_bg->data_rwsem);

		spin_lock(&cluster->refill_lock);
		if (used_bg == cluster->block_group)
			return used_bg;

		up_read(&used_bg->data_rwsem);
		btrfs_put_block_group(used_bg);
	}
}

static inline void
btrfs_release_block_group(struct btrfs_block_group_cache *cache,
			 int delalloc)
{
	if (delalloc)
		up_read(&cache->data_rwsem);
	btrfs_put_block_group(cache);
}

static noinline int find_free_extent(struct btrfs_root *orig_root,
				     u64 num_bytes, u64 empty_size,
				     u64 hint_byte, struct btrfs_key *ins,
				     u64 flags, int delalloc)
{
	int ret = 0;
	struct btrfs_root *root = orig_root->fs_info->extent_root;
	struct btrfs_free_cluster *last_ptr = NULL;
	struct btrfs_block_group_cache *block_group = NULL;
	u64 search_start = 0;
	u64 max_extent_size = 0;
	u64 empty_cluster = 0;
	struct btrfs_space_info *space_info;
	int loop = 0;
	int index = __get_raid_index(flags);
	int alloc_type = (flags & BTRFS_BLOCK_GROUP_DATA) ?
		RESERVE_ALLOC_NO_ACCOUNT : RESERVE_ALLOC;
	bool failed_cluster_refill = false;
	bool failed_alloc = false;
	bool use_cluster = true;
	bool have_caching_bg = false;
	bool orig_have_caching_bg = false;
	bool full_search = false;

	WARN_ON(num_bytes < root->sectorsize);
	ins->type = BTRFS_EXTENT_ITEM_KEY;
	ins->objectid = 0;
	ins->offset = 0;

	trace_find_free_extent(orig_root, num_bytes, empty_size, flags);

	space_info = __find_space_info(root->fs_info, flags);
	if (!space_info) {
		btrfs_err(root->fs_info, "No space info for %llu", flags);
		return -ENOSPC;
	}

	if (unlikely(space_info->max_extent_size)) {
		spin_lock(&space_info->lock);
		if (space_info->max_extent_size &&
		    num_bytes > space_info->max_extent_size) {
			ins->offset = space_info->max_extent_size;
			spin_unlock(&space_info->lock);
			return -ENOSPC;
		} else if (space_info->max_extent_size) {
			use_cluster = false;
		}
		spin_unlock(&space_info->lock);
	}

	last_ptr = fetch_cluster_info(orig_root, space_info, &empty_cluster);
	if (last_ptr) {
		spin_lock(&last_ptr->lock);
		if (last_ptr->block_group)
			hint_byte = last_ptr->window_start;
		if (last_ptr->fragmented) {
			 
			hint_byte = last_ptr->window_start;
			use_cluster = false;
		}
		spin_unlock(&last_ptr->lock);
	}

	search_start = max(search_start, first_logical_byte(root, 0));
	search_start = max(search_start, hint_byte);
	if (search_start == hint_byte) {
		block_group = btrfs_lookup_block_group(root->fs_info,
						       search_start);
		 
		if (block_group && block_group_bits(block_group, flags) &&
		    block_group->cached != BTRFS_CACHE_NO) {
			down_read(&space_info->groups_sem);
			if (list_empty(&block_group->list) ||
			    block_group->ro) {
				 
				btrfs_put_block_group(block_group);
				up_read(&space_info->groups_sem);
			} else {
				index = get_block_group_index(block_group);
				btrfs_lock_block_group(block_group, delalloc);
				goto have_block_group;
			}
		} else if (block_group) {
			btrfs_put_block_group(block_group);
		}
	}
search:
	have_caching_bg = false;
	if (index == 0 || index == __get_raid_index(flags))
		full_search = true;
	down_read(&space_info->groups_sem);
	list_for_each_entry(block_group, &space_info->block_groups[index],
			    list) {
		u64 offset;
		int cached;

		btrfs_grab_block_group(block_group, delalloc);
		search_start = block_group->key.objectid;

		if (!block_group_bits(block_group, flags)) {
		    u64 extra = BTRFS_BLOCK_GROUP_DUP |
				BTRFS_BLOCK_GROUP_RAID1 |
				BTRFS_BLOCK_GROUP_RAID5 |
				BTRFS_BLOCK_GROUP_RAID6 |
				BTRFS_BLOCK_GROUP_RAID10;

			if ((flags & extra) && !(block_group->flags & extra))
				goto loop;
		}

have_block_group:
		cached = block_group_cache_done(block_group);
		if (unlikely(!cached)) {
			have_caching_bg = true;
			ret = cache_block_group(block_group, 0);
			BUG_ON(ret < 0);
			ret = 0;
		}

		if (unlikely(block_group->cached == BTRFS_CACHE_ERROR))
			goto loop;
		if (unlikely(block_group->ro))
			goto loop;

		if (last_ptr && use_cluster) {
			struct btrfs_block_group_cache *used_block_group;
			unsigned long aligned_cluster;
			 
			used_block_group = btrfs_lock_cluster(block_group,
							      last_ptr,
							      delalloc);
			if (!used_block_group)
				goto refill_cluster;

			if (used_block_group != block_group &&
			    (used_block_group->ro ||
			     !block_group_bits(used_block_group, flags)))
				goto release_cluster;

			offset = btrfs_alloc_from_cluster(used_block_group,
						last_ptr,
						num_bytes,
						used_block_group->key.objectid,
						&max_extent_size);
			if (offset) {
				 
				spin_unlock(&last_ptr->refill_lock);
				trace_btrfs_reserve_extent_cluster(root,
						used_block_group,
						search_start, num_bytes);
				if (used_block_group != block_group) {
					btrfs_release_block_group(block_group,
								  delalloc);
					block_group = used_block_group;
				}
				goto checks;
			}

			WARN_ON(last_ptr->block_group != used_block_group);
release_cluster:
			 
			if (loop >= LOOP_NO_EMPTY_SIZE &&
			    used_block_group != block_group) {
				spin_unlock(&last_ptr->refill_lock);
				btrfs_release_block_group(used_block_group,
							  delalloc);
				goto unclustered_alloc;
			}

			btrfs_return_cluster_to_free_space(NULL, last_ptr);

			if (used_block_group != block_group)
				btrfs_release_block_group(used_block_group,
							  delalloc);
refill_cluster:
			if (loop >= LOOP_NO_EMPTY_SIZE) {
				spin_unlock(&last_ptr->refill_lock);
				goto unclustered_alloc;
			}

			aligned_cluster = max_t(unsigned long,
						empty_cluster + empty_size,
					      block_group->full_stripe_len);

			ret = btrfs_find_space_cluster(root, block_group,
						       last_ptr, search_start,
						       num_bytes,
						       aligned_cluster);
			if (ret == 0) {
				 
				offset = btrfs_alloc_from_cluster(block_group,
							last_ptr,
							num_bytes,
							search_start,
							&max_extent_size);
				if (offset) {
					 
					spin_unlock(&last_ptr->refill_lock);
					trace_btrfs_reserve_extent_cluster(root,
						block_group, search_start,
						num_bytes);
					goto checks;
				}
			} else if (!cached && loop > LOOP_CACHING_NOWAIT
				   && !failed_cluster_refill) {
				spin_unlock(&last_ptr->refill_lock);

				failed_cluster_refill = true;
				wait_block_group_cache_progress(block_group,
				       num_bytes + empty_cluster + empty_size);
				goto have_block_group;
			}

			btrfs_return_cluster_to_free_space(NULL, last_ptr);
			spin_unlock(&last_ptr->refill_lock);
			goto loop;
		}

unclustered_alloc:
		 
		if (unlikely(last_ptr)) {
			spin_lock(&last_ptr->lock);
			last_ptr->fragmented = 1;
			spin_unlock(&last_ptr->lock);
		}
		if (cached) {
			struct btrfs_free_space_ctl *ctl =
				block_group->free_space_ctl;

			spin_lock(&ctl->tree_lock);
			if (ctl->free_space <
			    num_bytes + empty_cluster + empty_size) {
				if (ctl->free_space > max_extent_size)
					max_extent_size = ctl->free_space;
				spin_unlock(&ctl->tree_lock);
				goto loop;
			}
			spin_unlock(&ctl->tree_lock);
		}

		offset = btrfs_find_space_for_alloc(block_group, search_start,
						    num_bytes, empty_size,
						    &max_extent_size);
		 
		if (!offset && !failed_alloc && !cached &&
		    loop > LOOP_CACHING_NOWAIT) {
			wait_block_group_cache_progress(block_group,
						num_bytes + empty_size);
			failed_alloc = true;
			goto have_block_group;
		} else if (!offset) {
			goto loop;
		}
checks:
		search_start = ALIGN(offset, root->stripesize);

		if (search_start + num_bytes >
		    block_group->key.objectid + block_group->key.offset) {
			btrfs_add_free_space(block_group, offset, num_bytes);
			goto loop;
		}

		if (offset < search_start)
			btrfs_add_free_space(block_group, offset,
					     search_start - offset);
		BUG_ON(offset > search_start);

		ret = btrfs_update_reserved_bytes(block_group, num_bytes,
						  alloc_type, delalloc);
		if (ret == -EAGAIN) {
			btrfs_add_free_space(block_group, offset, num_bytes);
			goto loop;
		}
		btrfs_inc_block_group_reservations(block_group);

		ins->objectid = search_start;
		ins->offset = num_bytes;

		trace_btrfs_reserve_extent(orig_root, block_group,
					   search_start, num_bytes);
		btrfs_release_block_group(block_group, delalloc);
		break;
loop:
		failed_cluster_refill = false;
		failed_alloc = false;
		BUG_ON(index != get_block_group_index(block_group));
		btrfs_release_block_group(block_group, delalloc);
#ifdef MY_ABC_HERE
		cond_resched();
#endif  
	}
	up_read(&space_info->groups_sem);

	if ((loop == LOOP_CACHING_NOWAIT) && have_caching_bg
		&& !orig_have_caching_bg)
		orig_have_caching_bg = true;

	if (!ins->objectid && loop >= LOOP_CACHING_WAIT && have_caching_bg)
		goto search;

	if (!ins->objectid && ++index < BTRFS_NR_RAID_TYPES)
		goto search;

	if (!ins->objectid && loop < LOOP_NO_EMPTY_SIZE) {
		index = 0;
		if (loop == LOOP_CACHING_NOWAIT) {
			 
			if (orig_have_caching_bg || !full_search)
				loop = LOOP_CACHING_WAIT;
			else
				loop = LOOP_ALLOC_CHUNK;
		} else {
			loop++;
		}

		if (loop == LOOP_ALLOC_CHUNK) {
			struct btrfs_trans_handle *trans;
			int exist = 0;

			trans = current->journal_info;
			if (trans)
				exist = 1;
			else
				trans = btrfs_join_transaction(root);

			if (IS_ERR(trans)) {
				ret = PTR_ERR(trans);
				goto out;
			}

			ret = do_chunk_alloc(trans, root, flags,
					     CHUNK_ALLOC_FORCE);

			if (ret == -ENOSPC)
				loop = LOOP_NO_EMPTY_SIZE;

			if (ret < 0 && ret != -ENOSPC)
				btrfs_abort_transaction(trans,
							root, ret);
			else
				ret = 0;
			if (!exist)
				btrfs_end_transaction(trans, root);
			if (ret)
				goto out;
		}

		if (loop == LOOP_NO_EMPTY_SIZE) {
			 
			if (empty_size == 0 &&
			    empty_cluster == 0) {
				ret = -ENOSPC;
				goto out;
			}
			empty_size = 0;
			empty_cluster = 0;
		}

		goto search;
	} else if (!ins->objectid) {
		ret = -ENOSPC;
	} else if (ins->objectid) {
		if (!use_cluster && last_ptr) {
			spin_lock(&last_ptr->lock);
			last_ptr->window_start = ins->objectid;
			spin_unlock(&last_ptr->lock);
		}
		ret = 0;
	}
out:
	if (ret == -ENOSPC) {
		spin_lock(&space_info->lock);
		space_info->max_extent_size = max_extent_size;
		spin_unlock(&space_info->lock);
		ins->offset = max_extent_size;
	}
	return ret;
}

static void dump_space_info(struct btrfs_space_info *info, u64 bytes,
			    int dump_block_groups)
{
	struct btrfs_block_group_cache *cache;
	int index = 0;

	spin_lock(&info->lock);
	printk(KERN_INFO "BTRFS: space_info %llu has %llu free, is %sfull\n",
	       info->flags,
	       info->total_bytes - info->bytes_used - info->bytes_pinned -
	       info->bytes_reserved - info->bytes_readonly,
	       (info->full) ? "" : "not ");
	printk(KERN_INFO "BTRFS: space_info total=%llu, used=%llu, pinned=%llu, "
	       "reserved=%llu, may_use=%llu, readonly=%llu\n",
	       info->total_bytes, info->bytes_used, info->bytes_pinned,
	       info->bytes_reserved, info->bytes_may_use,
	       info->bytes_readonly);
	spin_unlock(&info->lock);

	if (!dump_block_groups)
		return;

	down_read(&info->groups_sem);
again:
	list_for_each_entry(cache, &info->block_groups[index], list) {
		spin_lock(&cache->lock);
		printk(KERN_INFO "BTRFS: "
			   "block group %llu has %llu bytes, "
			   "%llu used %llu pinned %llu reserved %s\n",
		       cache->key.objectid, cache->key.offset,
		       btrfs_block_group_used(&cache->item), cache->pinned,
		       cache->reserved, cache->ro ? "[readonly]" : "");
		btrfs_dump_free_space(cache, bytes);
		spin_unlock(&cache->lock);
	}
	if (++index < BTRFS_NR_RAID_TYPES)
		goto again;
	up_read(&info->groups_sem);
}

int btrfs_reserve_extent(struct btrfs_root *root,
			 u64 num_bytes, u64 min_alloc_size,
			 u64 empty_size, u64 hint_byte,
			 struct btrfs_key *ins, int is_data, int delalloc)
{
	bool final_tried = num_bytes == min_alloc_size;
	u64 flags;
	int ret;

	flags = btrfs_get_alloc_profile(root, is_data);
again:
	WARN_ON(num_bytes < root->sectorsize);
	ret = find_free_extent(root, num_bytes, empty_size, hint_byte, ins,
			       flags, delalloc);
	if (!ret && !is_data) {
		btrfs_dec_block_group_reservations(root->fs_info,
						   ins->objectid);
	} else if (ret == -ENOSPC) {
		if (!final_tried && ins->offset) {
			num_bytes = min(num_bytes >> 1, ins->offset);
			num_bytes = round_down(num_bytes, root->sectorsize);
			num_bytes = max(num_bytes, min_alloc_size);
			if (num_bytes == min_alloc_size)
				final_tried = true;
			goto again;
		} else if (btrfs_test_opt(root, ENOSPC_DEBUG)) {
			struct btrfs_space_info *sinfo;

			sinfo = __find_space_info(root->fs_info, flags);
			btrfs_err(root->fs_info, "allocation failed flags %llu, wanted %llu",
				flags, num_bytes);
			if (sinfo)
				dump_space_info(sinfo, num_bytes, 1);
		}
	}

	return ret;
}

static int __btrfs_free_reserved_extent(struct btrfs_root *root,
					u64 start, u64 len,
					int pin, int delalloc)
{
	struct btrfs_block_group_cache *cache;
	int ret = 0;

	cache = btrfs_lookup_block_group(root->fs_info, start);
	if (!cache) {
		btrfs_err(root->fs_info, "Unable to find block group for %llu",
			start);
		return -ENOSPC;
	}

	if (pin)
		pin_down_extent(root, cache, start, len, 1);
	else {
		if (btrfs_test_opt(root, DISCARD))
			ret = btrfs_discard_extent(root, start, len, NULL);
		btrfs_add_free_space(cache, start, len);
		btrfs_update_reserved_bytes(cache, len, RESERVE_FREE, delalloc);
	}

	btrfs_put_block_group(cache);

	trace_btrfs_reserved_extent_free(root, start, len);

	return ret;
}

int btrfs_free_reserved_extent(struct btrfs_root *root,
			       u64 start, u64 len, int delalloc)
{
	return __btrfs_free_reserved_extent(root, start, len, 0, delalloc);
}

int btrfs_free_and_pin_reserved_extent(struct btrfs_root *root,
				       u64 start, u64 len)
{
	return __btrfs_free_reserved_extent(root, start, len, 1, 0);
}

static int alloc_reserved_file_extent(struct btrfs_trans_handle *trans,
				      struct btrfs_root *root,
				      u64 parent, u64 root_objectid,
				      u64 flags, u64 owner, u64 offset,
				      struct btrfs_key *ins, int ref_mod)
{
	int ret;
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_extent_item *extent_item;
	struct btrfs_extent_inline_ref *iref;
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	int type;
	u32 size;

	if (parent > 0)
		type = BTRFS_SHARED_DATA_REF_KEY;
	else
		type = BTRFS_EXTENT_DATA_REF_KEY;

	size = sizeof(*extent_item) + btrfs_extent_inline_ref_size(type);

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	path->leave_spinning = 1;
	ret = btrfs_insert_empty_item(trans, fs_info->extent_root, path,
				      ins, size);
	if (ret) {
		btrfs_free_path(path);
		return ret;
	}

	leaf = path->nodes[0];
	extent_item = btrfs_item_ptr(leaf, path->slots[0],
				     struct btrfs_extent_item);
	btrfs_set_extent_refs(leaf, extent_item, ref_mod);
	btrfs_set_extent_generation(leaf, extent_item, trans->transid);
	btrfs_set_extent_flags(leaf, extent_item,
			       flags | BTRFS_EXTENT_FLAG_DATA);

	iref = (struct btrfs_extent_inline_ref *)(extent_item + 1);
	btrfs_set_extent_inline_ref_type(leaf, iref, type);
	if (parent > 0) {
		struct btrfs_shared_data_ref *ref;
		ref = (struct btrfs_shared_data_ref *)(iref + 1);
		btrfs_set_extent_inline_ref_offset(leaf, iref, parent);
		btrfs_set_shared_data_ref_count(leaf, ref, ref_mod);
	} else {
		struct btrfs_extent_data_ref *ref;
		ref = (struct btrfs_extent_data_ref *)(&iref->offset);
		btrfs_set_extent_data_ref_root(leaf, ref, root_objectid);
		btrfs_set_extent_data_ref_objectid(leaf, ref, owner);
		btrfs_set_extent_data_ref_offset(leaf, ref, offset);
		btrfs_set_extent_data_ref_count(leaf, ref, ref_mod);
	}

	btrfs_mark_buffer_dirty(path->nodes[0]);
	btrfs_free_path(path);

	ret = remove_from_free_space_tree(trans, fs_info, ins->objectid,
					  ins->offset);
	if (ret)
		return ret;

	ret = update_block_group(trans, root, ins->objectid, ins->offset, 1);
	if (ret) {  
		btrfs_err(fs_info, "update block group failed for %llu %llu",
			ins->objectid, ins->offset);
		BUG();
	}
	trace_btrfs_reserved_extent_alloc(root, ins->objectid, ins->offset);
	return ret;
}

static int alloc_reserved_tree_block(struct btrfs_trans_handle *trans,
				     struct btrfs_root *root,
				     u64 parent, u64 root_objectid,
				     u64 flags, struct btrfs_disk_key *key,
				     int level, struct btrfs_key *ins)
{
	int ret;
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_extent_item *extent_item;
	struct btrfs_tree_block_info *block_info;
	struct btrfs_extent_inline_ref *iref;
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	u32 size = sizeof(*extent_item) + sizeof(*iref);
	u64 num_bytes = ins->offset;
	bool skinny_metadata = btrfs_fs_incompat(root->fs_info,
						 SKINNY_METADATA);

	if (!skinny_metadata)
		size += sizeof(*block_info);

	path = btrfs_alloc_path();
	if (!path) {
		btrfs_free_and_pin_reserved_extent(root, ins->objectid,
						   root->nodesize);
		return -ENOMEM;
	}

	path->leave_spinning = 1;
	ret = btrfs_insert_empty_item(trans, fs_info->extent_root, path,
				      ins, size);
	if (ret) {
		btrfs_free_path(path);
		btrfs_free_and_pin_reserved_extent(root, ins->objectid,
						   root->nodesize);
		return ret;
	}

	leaf = path->nodes[0];
	extent_item = btrfs_item_ptr(leaf, path->slots[0],
				     struct btrfs_extent_item);
	btrfs_set_extent_refs(leaf, extent_item, 1);
	btrfs_set_extent_generation(leaf, extent_item, trans->transid);
	btrfs_set_extent_flags(leaf, extent_item,
			       flags | BTRFS_EXTENT_FLAG_TREE_BLOCK);

	if (skinny_metadata) {
		iref = (struct btrfs_extent_inline_ref *)(extent_item + 1);
		num_bytes = root->nodesize;
	} else {
		block_info = (struct btrfs_tree_block_info *)(extent_item + 1);
		btrfs_set_tree_block_key(leaf, block_info, key);
		btrfs_set_tree_block_level(leaf, block_info, level);
		iref = (struct btrfs_extent_inline_ref *)(block_info + 1);
	}

	if (parent > 0) {
		BUG_ON(!(flags & BTRFS_BLOCK_FLAG_FULL_BACKREF));
		btrfs_set_extent_inline_ref_type(leaf, iref,
						 BTRFS_SHARED_BLOCK_REF_KEY);
		btrfs_set_extent_inline_ref_offset(leaf, iref, parent);
	} else {
		btrfs_set_extent_inline_ref_type(leaf, iref,
						 BTRFS_TREE_BLOCK_REF_KEY);
		btrfs_set_extent_inline_ref_offset(leaf, iref, root_objectid);
	}

	btrfs_mark_buffer_dirty(leaf);
	btrfs_free_path(path);

	ret = remove_from_free_space_tree(trans, fs_info, ins->objectid,
					  num_bytes);
	if (ret)
		return ret;

	ret = update_block_group(trans, root, ins->objectid, root->nodesize,
				 1);
	if (ret) {  
		btrfs_err(fs_info, "update block group failed for %llu %llu",
			ins->objectid, ins->offset);
		BUG();
	}

	trace_btrfs_reserved_extent_alloc(root, ins->objectid, root->nodesize);
	return ret;
}

int btrfs_alloc_reserved_file_extent(struct btrfs_trans_handle *trans,
				     struct btrfs_root *root,
				     u64 root_objectid, u64 owner,
				     u64 offset, u64 ram_bytes,
				     struct btrfs_key *ins)
{
	int ret;

	BUG_ON(root_objectid == BTRFS_TREE_LOG_OBJECTID);

	ret = btrfs_add_delayed_data_ref(root->fs_info, trans, ins->objectid,
					 ins->offset, 0,
					 root_objectid, owner, offset,
					 ram_bytes, BTRFS_ADD_DELAYED_EXTENT,
					 NULL);
	return ret;
}

int btrfs_alloc_logged_file_extent(struct btrfs_trans_handle *trans,
				   struct btrfs_root *root,
				   u64 root_objectid, u64 owner, u64 offset,
				   struct btrfs_key *ins)
{
	int ret;
	struct btrfs_block_group_cache *block_group;

	if (!btrfs_fs_incompat(root->fs_info, MIXED_GROUPS)) {
		ret = __exclude_logged_extent(root, ins->objectid, ins->offset);
		if (ret)
			return ret;
	}

	block_group = btrfs_lookup_block_group(root->fs_info, ins->objectid);
	if (!block_group)
		return -EINVAL;

	ret = btrfs_update_reserved_bytes(block_group, ins->offset,
					  RESERVE_ALLOC_NO_ACCOUNT, 0);
	BUG_ON(ret);  
	ret = alloc_reserved_file_extent(trans, root, 0, root_objectid,
					 0, owner, offset, ins, 1);
	btrfs_put_block_group(block_group);
	return ret;
}

static struct extent_buffer *
btrfs_init_new_buffer(struct btrfs_trans_handle *trans, struct btrfs_root *root,
		      u64 bytenr, int level)
{
	struct extent_buffer *buf;

	buf = btrfs_find_create_tree_block(root, bytenr);
	if (IS_ERR(buf))
		return buf;

	btrfs_set_header_generation(buf, trans->transid);
	btrfs_set_buffer_lockdep_class(root->root_key.objectid, buf, level);
	btrfs_tree_lock(buf);
	clean_tree_block(trans, root->fs_info, buf);
	clear_bit(EXTENT_BUFFER_STALE, &buf->bflags);

	btrfs_set_lock_blocking(buf);
	set_extent_buffer_uptodate(buf);

	if (root->root_key.objectid == BTRFS_TREE_LOG_OBJECTID) {
		buf->log_index = root->log_transid % 2;
		 
		if (buf->log_index == 0)
			set_extent_dirty(&root->dirty_log_pages, buf->start,
					buf->start + buf->len - 1, GFP_NOFS);
		else
			set_extent_new(&root->dirty_log_pages, buf->start,
					buf->start + buf->len - 1);
	} else {
		buf->log_index = -1;
		set_extent_dirty(&trans->transaction->dirty_pages, buf->start,
			 buf->start + buf->len - 1, GFP_NOFS);
	}
	trans->dirty = true;
	 
	return buf;
}

static struct btrfs_block_rsv *
use_block_rsv(struct btrfs_trans_handle *trans,
	      struct btrfs_root *root, u32 blocksize)
{
	struct btrfs_block_rsv *block_rsv;
	struct btrfs_block_rsv *global_rsv = &root->fs_info->global_block_rsv;
	int ret;
	bool global_updated = false;

	block_rsv = get_block_rsv(trans, root);

	if (unlikely(block_rsv->size == 0))
		goto try_reserve;
again:
	ret = block_rsv_use_bytes(block_rsv, blocksize);
	if (!ret)
		return block_rsv;

	if (block_rsv->failfast)
		return ERR_PTR(ret);

	if (block_rsv->type == BTRFS_BLOCK_RSV_GLOBAL && !global_updated) {
		global_updated = true;
		update_global_block_rsv(root->fs_info);
		goto again;
	}

	if (btrfs_test_opt(root, ENOSPC_DEBUG)) {
		static DEFINE_RATELIMIT_STATE(_rs,
				DEFAULT_RATELIMIT_INTERVAL * 10,
				  1);
		if (__ratelimit(&_rs))
			WARN(1, KERN_DEBUG
				"BTRFS: block rsv returned %d\n", ret);
	}
try_reserve:
	ret = reserve_metadata_bytes(root, block_rsv, blocksize,
				     BTRFS_RESERVE_NO_FLUSH);
	if (!ret)
		return block_rsv;
	 
	if (block_rsv->type != BTRFS_BLOCK_RSV_GLOBAL &&
	    block_rsv->space_info == global_rsv->space_info) {
		ret = block_rsv_use_bytes(global_rsv, blocksize);
		if (!ret)
			return global_rsv;
	}
	return ERR_PTR(ret);
}

static void unuse_block_rsv(struct btrfs_fs_info *fs_info,
			    struct btrfs_block_rsv *block_rsv, u32 blocksize)
{
	block_rsv_add_bytes(block_rsv, blocksize, 0);
	block_rsv_release_bytes(fs_info, block_rsv, NULL, 0);
}

struct extent_buffer *btrfs_alloc_tree_block(struct btrfs_trans_handle *trans,
					struct btrfs_root *root,
					u64 parent, u64 root_objectid,
					struct btrfs_disk_key *key, int level,
					u64 hint, u64 empty_size)
{
	struct btrfs_key ins;
	struct btrfs_block_rsv *block_rsv;
	struct extent_buffer *buf;
	struct btrfs_delayed_extent_op *extent_op;
	u64 flags = 0;
	int ret;
	u32 blocksize = root->nodesize;
	bool skinny_metadata = btrfs_fs_incompat(root->fs_info,
						 SKINNY_METADATA);

	if (btrfs_test_is_dummy_root(root)) {
		buf = btrfs_init_new_buffer(trans, root, root->alloc_bytenr,
					    level);
		if (!IS_ERR(buf))
			root->alloc_bytenr += blocksize;
		return buf;
	}

	block_rsv = use_block_rsv(trans, root, blocksize);
	if (IS_ERR(block_rsv))
		return ERR_CAST(block_rsv);

	ret = btrfs_reserve_extent(root, blocksize, blocksize,
				   empty_size, hint, &ins, 0, 0);
	if (ret)
		goto out_unuse;

	buf = btrfs_init_new_buffer(trans, root, ins.objectid, level);
	if (IS_ERR(buf)) {
		ret = PTR_ERR(buf);
		goto out_free_reserved;
	}

	if (root_objectid == BTRFS_TREE_RELOC_OBJECTID) {
		if (parent == 0)
			parent = ins.objectid;
		flags |= BTRFS_BLOCK_FLAG_FULL_BACKREF;
	} else
		BUG_ON(parent > 0);

	if (root_objectid != BTRFS_TREE_LOG_OBJECTID) {
		extent_op = btrfs_alloc_delayed_extent_op();
		if (!extent_op) {
			ret = -ENOMEM;
			goto out_free_buf;
		}
		if (key)
			memcpy(&extent_op->key, key, sizeof(extent_op->key));
		else
			memset(&extent_op->key, 0, sizeof(extent_op->key));
		extent_op->flags_to_set = flags;
		extent_op->update_key = skinny_metadata ? false : true;
		extent_op->update_flags = true;
		extent_op->is_data = false;
		extent_op->level = level;

		ret = btrfs_add_delayed_tree_ref(root->fs_info, trans,
						 ins.objectid, ins.offset,
						 parent, root_objectid, level,
						 BTRFS_ADD_DELAYED_EXTENT,
						 extent_op);
		if (ret)
			goto out_free_delayed;
	}
	return buf;

out_free_delayed:
	btrfs_free_delayed_extent_op(extent_op);
out_free_buf:
	free_extent_buffer(buf);
out_free_reserved:
	btrfs_free_reserved_extent(root, ins.objectid, ins.offset, 0);
out_unuse:
	unuse_block_rsv(root->fs_info, block_rsv, blocksize);
	return ERR_PTR(ret);
}

struct walk_control {
	u64 refs[BTRFS_MAX_LEVEL];
	u64 flags[BTRFS_MAX_LEVEL];
	struct btrfs_key update_progress;
	int stage;
	int level;
	int shared_level;
	int update_ref;
	int keep_locks;
	int reada_slot;
	int reada_count;
	int for_reloc;
};

#define DROP_REFERENCE	1
#define UPDATE_BACKREF	2

static noinline void reada_walk_down(struct btrfs_trans_handle *trans,
				     struct btrfs_root *root,
				     struct walk_control *wc,
				     struct btrfs_path *path)
{
	u64 bytenr;
	u64 generation;
	u64 refs;
	u64 flags;
	u32 nritems;
	u32 blocksize;
	struct btrfs_key key;
	struct extent_buffer *eb;
	int ret;
	int slot;
	int nread = 0;

	if (path->slots[wc->level] < wc->reada_slot) {
		wc->reada_count = wc->reada_count * 2 / 3;
		wc->reada_count = max(wc->reada_count, 2);
	} else {
		wc->reada_count = wc->reada_count * 3 / 2;
		wc->reada_count = min_t(int, wc->reada_count,
					BTRFS_NODEPTRS_PER_BLOCK(root));
	}

	eb = path->nodes[wc->level];
	nritems = btrfs_header_nritems(eb);
	blocksize = root->nodesize;

	for (slot = path->slots[wc->level]; slot < nritems; slot++) {
		if (nread >= wc->reada_count)
			break;

		cond_resched();
		bytenr = btrfs_node_blockptr(eb, slot);
		generation = btrfs_node_ptr_generation(eb, slot);

		if (slot == path->slots[wc->level])
			goto reada;

		if (wc->stage == UPDATE_BACKREF &&
		    generation <= root->root_key.offset)
			continue;

		ret = btrfs_lookup_extent_info(trans, root, bytenr,
					       wc->level - 1, 1, &refs,
					       &flags);
		 
		if (ret < 0)
			continue;
		BUG_ON(refs == 0);

		if (wc->stage == DROP_REFERENCE) {
			if (refs == 1)
				goto reada;

			if (wc->level == 1 &&
			    (flags & BTRFS_BLOCK_FLAG_FULL_BACKREF))
				continue;
			if (!wc->update_ref ||
			    generation <= root->root_key.offset)
				continue;
			btrfs_node_key_to_cpu(eb, &key, slot);
			ret = btrfs_comp_cpu_keys(&key,
						  &wc->update_progress);
			if (ret < 0)
				continue;
		} else {
			if (wc->level == 1 &&
			    (flags & BTRFS_BLOCK_FLAG_FULL_BACKREF))
				continue;
		}
reada:
		readahead_tree_block(root, bytenr);
		nread++;
	}
	wc->reada_slot = slot;
}

static int record_one_subtree_extent(struct btrfs_trans_handle *trans,
				     struct btrfs_root *root, u64 bytenr,
				     u64 num_bytes)
{
	struct btrfs_qgroup_extent_record *qrecord;
	struct btrfs_delayed_ref_root *delayed_refs;

	qrecord = kmalloc(sizeof(*qrecord), GFP_NOFS);
	if (!qrecord)
		return -ENOMEM;

	qrecord->bytenr = bytenr;
	qrecord->num_bytes = num_bytes;
	qrecord->old_roots = NULL;

	delayed_refs = &trans->transaction->delayed_refs;
	spin_lock(&delayed_refs->lock);
	if (btrfs_qgroup_insert_dirty_extent(delayed_refs, qrecord))
		kfree(qrecord);
	spin_unlock(&delayed_refs->lock);

	return 0;
}

static int account_leaf_items(struct btrfs_trans_handle *trans,
			      struct btrfs_root *root,
			      struct extent_buffer *eb)
{
	int nr = btrfs_header_nritems(eb);
	int i, extent_type, ret;
	struct btrfs_key key;
	struct btrfs_file_extent_item *fi;
	u64 bytenr, num_bytes;

	if (!root->fs_info->quota_enabled)
		return 0;

	for (i = 0; i < nr; i++) {
		btrfs_item_key_to_cpu(eb, &key, i);

		if (key.type != BTRFS_EXTENT_DATA_KEY)
			continue;

		fi = btrfs_item_ptr(eb, i, struct btrfs_file_extent_item);
		 
		extent_type = btrfs_file_extent_type(eb, fi);

		if (extent_type == BTRFS_FILE_EXTENT_INLINE)
			continue;

		bytenr = btrfs_file_extent_disk_bytenr(eb, fi);
		if (!bytenr)
			continue;

		num_bytes = btrfs_file_extent_disk_num_bytes(eb, fi);

		ret = record_one_subtree_extent(trans, root, bytenr, num_bytes);
		if (ret)
			return ret;
	}
	return 0;
}

static int adjust_slots_upwards(struct btrfs_root *root,
				struct btrfs_path *path, int root_level)
{
	int level = 0;
	int nr, slot;
	struct extent_buffer *eb;

	if (root_level == 0)
		return 1;

	while (level <= root_level) {
		eb = path->nodes[level];
		nr = btrfs_header_nritems(eb);
		path->slots[level]++;
		slot = path->slots[level];
		if (slot >= nr || level == 0) {
			 
			if (level != root_level) {
				btrfs_tree_unlock_rw(eb, path->locks[level]);
				path->locks[level] = 0;

				free_extent_buffer(eb);
				path->nodes[level] = NULL;
				path->slots[level] = 0;
			}
		} else {
			 
			break;
		}

		level++;
	}

	eb = path->nodes[root_level];
	if (path->slots[root_level] >= btrfs_header_nritems(eb))
		return 1;

	return 0;
}

static int account_shared_subtree(struct btrfs_trans_handle *trans,
				  struct btrfs_root *root,
				  struct extent_buffer *root_eb,
				  u64 root_gen,
				  int root_level)
{
	int ret = 0;
	int level;
	struct extent_buffer *eb = root_eb;
	struct btrfs_path *path = NULL;

	BUG_ON(root_level < 0 || root_level > BTRFS_MAX_LEVEL);
	BUG_ON(root_eb == NULL);

	if (!root->fs_info->quota_enabled)
		return 0;

	if (!extent_buffer_uptodate(root_eb)) {
		ret = btrfs_read_buffer(root_eb, root_gen);
		if (ret)
			goto out;
	}

	if (root_level == 0) {
		ret = account_leaf_items(trans, root, root_eb);
		goto out;
	}

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	extent_buffer_get(root_eb);  
	path->nodes[root_level] = root_eb;
	path->slots[root_level] = 0;
	path->locks[root_level] = 0;  
walk_down:
	level = root_level;
	while (level >= 0) {
		if (path->nodes[level] == NULL) {
			int parent_slot;
			u64 child_gen;
			u64 child_bytenr;

			eb = path->nodes[level + 1];
			parent_slot = path->slots[level + 1];
			child_bytenr = btrfs_node_blockptr(eb, parent_slot);
			child_gen = btrfs_node_ptr_generation(eb, parent_slot);

			eb = read_tree_block(root, child_bytenr, child_gen);
			if (IS_ERR(eb)) {
				ret = PTR_ERR(eb);
				goto out;
			} else if (!extent_buffer_uptodate(eb)) {
				free_extent_buffer(eb);
				ret = -EIO;
				goto out;
			}

			path->nodes[level] = eb;
			path->slots[level] = 0;

			btrfs_tree_read_lock(eb);
			btrfs_set_lock_blocking_rw(eb, BTRFS_READ_LOCK);
			path->locks[level] = BTRFS_READ_LOCK_BLOCKING;

			ret = record_one_subtree_extent(trans, root, child_bytenr,
							root->nodesize);
			if (ret)
				goto out;
		}

		if (level == 0) {
			ret = account_leaf_items(trans, root, path->nodes[level]);
			if (ret)
				goto out;

			ret = adjust_slots_upwards(root, path, root_level);
			if (ret)
				break;

			goto walk_down;
		}

		level--;
	}

	ret = 0;
out:
	btrfs_free_path(path);

	return ret;
}

static noinline int walk_down_proc(struct btrfs_trans_handle *trans,
				   struct btrfs_root *root,
				   struct btrfs_path *path,
				   struct walk_control *wc, int lookup_info)
{
	int level = wc->level;
	struct extent_buffer *eb = path->nodes[level];
	u64 flag = BTRFS_BLOCK_FLAG_FULL_BACKREF;
	int ret;

	if (wc->stage == UPDATE_BACKREF &&
	    btrfs_header_owner(eb) != root->root_key.objectid)
		return 1;

	if (lookup_info &&
	    ((wc->stage == DROP_REFERENCE && wc->refs[level] != 1) ||
	     (wc->stage == UPDATE_BACKREF && !(wc->flags[level] & flag)))) {
		BUG_ON(!path->locks[level]);
		ret = btrfs_lookup_extent_info(trans, root,
					       eb->start, level, 1,
					       &wc->refs[level],
					       &wc->flags[level]);
		BUG_ON(ret == -ENOMEM);
		if (ret)
			return ret;
		BUG_ON(wc->refs[level] == 0);
	}

	if (wc->stage == DROP_REFERENCE) {
		if (wc->refs[level] > 1)
			return 1;

		if (path->locks[level] && !wc->keep_locks) {
			btrfs_tree_unlock_rw(eb, path->locks[level]);
			path->locks[level] = 0;
		}
		return 0;
	}

	if (!(wc->flags[level] & flag)) {
		BUG_ON(!path->locks[level]);
		ret = btrfs_inc_ref(trans, root, eb, 1);
		BUG_ON(ret);  
		ret = btrfs_dec_ref(trans, root, eb, 0);
		BUG_ON(ret);  
		ret = btrfs_set_disk_extent_flags(trans, root, eb->start,
						  eb->len, flag,
						  btrfs_header_level(eb), 0);
		BUG_ON(ret);  
		wc->flags[level] |= flag;
	}

	if (path->locks[level] && level > 0) {
		btrfs_tree_unlock_rw(eb, path->locks[level]);
		path->locks[level] = 0;
	}
	return 0;
}

static noinline int do_walk_down(struct btrfs_trans_handle *trans,
				 struct btrfs_root *root,
				 struct btrfs_path *path,
				 struct walk_control *wc, int *lookup_info)
{
	u64 bytenr;
	u64 generation;
	u64 parent;
	u32 blocksize;
	struct btrfs_key key;
	struct extent_buffer *next;
	int level = wc->level;
	int reada = 0;
	int ret = 0;
	bool need_account = false;

	generation = btrfs_node_ptr_generation(path->nodes[level],
					       path->slots[level]);
	 
	if (wc->stage == UPDATE_BACKREF &&
	    generation <= root->root_key.offset) {
		*lookup_info = 1;
		return 1;
	}

	bytenr = btrfs_node_blockptr(path->nodes[level], path->slots[level]);
	blocksize = root->nodesize;

	next = btrfs_find_tree_block(root->fs_info, bytenr);
	if (!next) {
		next = btrfs_find_create_tree_block(root, bytenr);
		if (IS_ERR(next))
			return PTR_ERR(next);

		btrfs_set_buffer_lockdep_class(root->root_key.objectid, next,
					       level - 1);
		reada = 1;
	}
	btrfs_tree_lock(next);
	btrfs_set_lock_blocking(next);

	ret = btrfs_lookup_extent_info(trans, root, bytenr, level - 1, 1,
				       &wc->refs[level - 1],
				       &wc->flags[level - 1]);
	if (ret < 0)
		goto out_unlock;

	if (unlikely(wc->refs[level - 1] == 0)) {
		btrfs_err(root->fs_info, "Missing references.");
		ret = -EIO;
		goto out_unlock;
	}
	*lookup_info = 0;

	if (wc->stage == DROP_REFERENCE) {
		if (wc->refs[level - 1] > 1) {
			need_account = true;
			if (level == 1 &&
			    (wc->flags[0] & BTRFS_BLOCK_FLAG_FULL_BACKREF))
				goto skip;

			if (!wc->update_ref ||
			    generation <= root->root_key.offset)
				goto skip;

			btrfs_node_key_to_cpu(path->nodes[level], &key,
					      path->slots[level]);
			ret = btrfs_comp_cpu_keys(&key, &wc->update_progress);
			if (ret < 0)
				goto skip;

			wc->stage = UPDATE_BACKREF;
			wc->shared_level = level - 1;
		}
	} else {
		if (level == 1 &&
		    (wc->flags[0] & BTRFS_BLOCK_FLAG_FULL_BACKREF))
			goto skip;
	}

	if (!btrfs_buffer_uptodate(next, generation, 0)) {
		btrfs_tree_unlock(next);
		free_extent_buffer(next);
		next = NULL;
		*lookup_info = 1;
	}

	if (!next) {
		if (reada && level == 1)
			reada_walk_down(trans, root, wc, path);
		next = read_tree_block(root, bytenr, generation);
		if (IS_ERR(next)) {
			return PTR_ERR(next);
		} else if (!extent_buffer_uptodate(next)) {
			free_extent_buffer(next);
			return -EIO;
		}
		btrfs_tree_lock(next);
		btrfs_set_lock_blocking(next);
	}

	level--;
	ASSERT(level == btrfs_header_level(next));
	if (level != btrfs_header_level(next)) {
		btrfs_err(root->fs_info, "mismatched level");
		ret = -EIO;
		goto out_unlock;
	}
	path->nodes[level] = next;
	path->slots[level] = 0;
	path->locks[level] = BTRFS_WRITE_LOCK_BLOCKING;
	wc->level = level;
	if (wc->level == 1)
		wc->reada_slot = 0;
	return 0;
skip:
	wc->refs[level - 1] = 0;
	wc->flags[level - 1] = 0;
	if (wc->stage == DROP_REFERENCE) {
		if (wc->flags[level] & BTRFS_BLOCK_FLAG_FULL_BACKREF) {
			parent = path->nodes[level]->start;
		} else {
			ASSERT(root->root_key.objectid ==
			       btrfs_header_owner(path->nodes[level]));
			if (root->root_key.objectid !=
			    btrfs_header_owner(path->nodes[level])) {
				btrfs_err(root->fs_info,
						"mismatched block owner");
				ret = -EIO;
				goto out_unlock;
			}
			parent = 0;
		}

		if (need_account) {
			ret = account_shared_subtree(trans, root, next,
						     generation, level - 1);
			if (ret) {
				btrfs_err_rl(root->fs_info,
					"Error "
					"%d accounting shared subtree. Quota "
					"is out of sync, rescan required.",
					ret);
			}
		}
		ret = btrfs_free_extent(trans, root, bytenr, blocksize, parent,
				root->root_key.objectid, level - 1, 0);
		if (ret)
			goto out_unlock;
	}

	*lookup_info = 1;
	ret = 1;

out_unlock:
	btrfs_tree_unlock(next);
	free_extent_buffer(next);

	return ret;
}

static noinline int walk_up_proc(struct btrfs_trans_handle *trans,
				 struct btrfs_root *root,
				 struct btrfs_path *path,
				 struct walk_control *wc)
{
	int ret;
	int level = wc->level;
	struct extent_buffer *eb = path->nodes[level];
	u64 parent = 0;

	if (wc->stage == UPDATE_BACKREF) {
		BUG_ON(wc->shared_level < level);
		if (level < wc->shared_level)
			goto out;

		ret = find_next_key(path, level + 1, &wc->update_progress);
		if (ret > 0)
			wc->update_ref = 0;

		wc->stage = DROP_REFERENCE;
		wc->shared_level = -1;
		path->slots[level] = 0;

		if (!path->locks[level]) {
			BUG_ON(level == 0);
			btrfs_tree_lock(eb);
			btrfs_set_lock_blocking(eb);
			path->locks[level] = BTRFS_WRITE_LOCK_BLOCKING;

			ret = btrfs_lookup_extent_info(trans, root,
						       eb->start, level, 1,
						       &wc->refs[level],
						       &wc->flags[level]);
			if (ret < 0) {
				btrfs_tree_unlock_rw(eb, path->locks[level]);
				path->locks[level] = 0;
				return ret;
			}
			BUG_ON(wc->refs[level] == 0);
			if (wc->refs[level] == 1) {
				btrfs_tree_unlock_rw(eb, path->locks[level]);
				path->locks[level] = 0;
				return 1;
			}
		}
	}

	BUG_ON(wc->refs[level] > 1 && !path->locks[level]);

	if (wc->refs[level] == 1) {
		if (level == 0) {
			if (wc->flags[level] & BTRFS_BLOCK_FLAG_FULL_BACKREF)
				ret = btrfs_dec_ref(trans, root, eb, 1);
			else
				ret = btrfs_dec_ref(trans, root, eb, 0);
			BUG_ON(ret);  
			ret = account_leaf_items(trans, root, eb);
			if (ret) {
				btrfs_err_rl(root->fs_info,
					"error "
					"%d accounting leaf items. Quota "
					"is out of sync, rescan required.",
					ret);
			}
		}
		 
		if (!path->locks[level] &&
		    btrfs_header_generation(eb) == trans->transid) {
			btrfs_tree_lock(eb);
			btrfs_set_lock_blocking(eb);
			path->locks[level] = BTRFS_WRITE_LOCK_BLOCKING;
		}
		clean_tree_block(trans, root->fs_info, eb);
	}

	if (eb == root->node) {
		if (wc->flags[level] & BTRFS_BLOCK_FLAG_FULL_BACKREF)
			parent = eb->start;
		else
			BUG_ON(root->root_key.objectid !=
			       btrfs_header_owner(eb));
	} else {
		if (wc->flags[level + 1] & BTRFS_BLOCK_FLAG_FULL_BACKREF)
			parent = path->nodes[level + 1]->start;
		else
			BUG_ON(root->root_key.objectid !=
			       btrfs_header_owner(path->nodes[level + 1]));
	}

	btrfs_free_tree_block(trans, root, eb, parent, wc->refs[level] == 1);
out:
	wc->refs[level] = 0;
	wc->flags[level] = 0;
	return 0;
}

static noinline int walk_down_tree(struct btrfs_trans_handle *trans,
				   struct btrfs_root *root,
				   struct btrfs_path *path,
				   struct walk_control *wc)
{
	int level = wc->level;
	int lookup_info = 1;
	int ret;

	while (level >= 0) {
		ret = walk_down_proc(trans, root, path, wc, lookup_info);
		if (ret > 0)
			break;

		if (level == 0)
			break;

		if (path->slots[level] >=
		    btrfs_header_nritems(path->nodes[level]))
			break;

		ret = do_walk_down(trans, root, path, wc, &lookup_info);
		if (ret > 0) {
			path->slots[level]++;
			continue;
		} else if (ret < 0)
			return ret;
		level = wc->level;
	}
	return 0;
}

static noinline int walk_up_tree(struct btrfs_trans_handle *trans,
				 struct btrfs_root *root,
				 struct btrfs_path *path,
				 struct walk_control *wc, int max_level)
{
	int level = wc->level;
	int ret;

	path->slots[level] = btrfs_header_nritems(path->nodes[level]);
	while (level < max_level && path->nodes[level]) {
		wc->level = level;
		if (path->slots[level] + 1 <
		    btrfs_header_nritems(path->nodes[level])) {
			path->slots[level]++;
			return 0;
		} else {
			ret = walk_up_proc(trans, root, path, wc);
			if (ret > 0)
				return 0;

			if (path->locks[level]) {
				btrfs_tree_unlock_rw(path->nodes[level],
						     path->locks[level]);
				path->locks[level] = 0;
			}
			free_extent_buffer(path->nodes[level]);
			path->nodes[level] = NULL;
			level++;
		}
	}
	return 1;
}

int btrfs_drop_snapshot(struct btrfs_root *root,
			 struct btrfs_block_rsv *block_rsv, int update_ref,
			 int for_reloc)
{
	struct btrfs_path *path;
	struct btrfs_trans_handle *trans;
	struct btrfs_root *tree_root = root->fs_info->tree_root;
	struct btrfs_root_item *root_item = &root->root_item;
	struct walk_control *wc;
	struct btrfs_key key;
	int err = 0;
	int ret;
	int level;
	bool root_dropped = false;
#ifdef MY_ABC_HERE
	struct btrfs_fs_info *fs_info = root->fs_info;
	u64 qgroupid = root->root_key.objectid;
#endif  

	btrfs_debug(root->fs_info, "Drop subvolume %llu", root->objectid);

	path = btrfs_alloc_path();
	if (!path) {
		err = -ENOMEM;
		goto out;
	}

	wc = kzalloc(sizeof(*wc), GFP_NOFS);
	if (!wc) {
		btrfs_free_path(path);
		err = -ENOMEM;
		goto out;
	}

	trans = btrfs_start_transaction(tree_root, 0);
	if (IS_ERR(trans)) {
		err = PTR_ERR(trans);
		goto out_free;
	}

	if (block_rsv)
		trans->block_rsv = block_rsv;

	if (btrfs_disk_key_objectid(&root_item->drop_progress) == 0) {
		level = btrfs_header_level(root->node);
		path->nodes[level] = btrfs_lock_root_node(root);
		btrfs_set_lock_blocking(path->nodes[level]);
		path->slots[level] = 0;
		path->locks[level] = BTRFS_WRITE_LOCK_BLOCKING;
		memset(&wc->update_progress, 0,
		       sizeof(wc->update_progress));
	} else {
		btrfs_disk_key_to_cpu(&key, &root_item->drop_progress);
		memcpy(&wc->update_progress, &key,
		       sizeof(wc->update_progress));

		level = root_item->drop_level;
		BUG_ON(level == 0);
		path->lowest_level = level;
		ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
		path->lowest_level = 0;
		if (ret < 0) {
			err = ret;
			goto out_end_trans;
		}
		WARN_ON(ret > 0);

		btrfs_unlock_up_safe(path, 0);

		level = btrfs_header_level(root->node);
		while (1) {
			btrfs_tree_lock(path->nodes[level]);
			btrfs_set_lock_blocking(path->nodes[level]);
			path->locks[level] = BTRFS_WRITE_LOCK_BLOCKING;

			ret = btrfs_lookup_extent_info(trans, root,
						path->nodes[level]->start,
						level, 1, &wc->refs[level],
						&wc->flags[level]);
			if (ret < 0) {
				err = ret;
				goto out_end_trans;
			}
			BUG_ON(wc->refs[level] == 0);

			if (level == root_item->drop_level)
				break;

			btrfs_tree_unlock(path->nodes[level]);
			path->locks[level] = 0;
			WARN_ON(wc->refs[level] != 1);
			level--;
		}
	}

	wc->level = level;
	wc->shared_level = -1;
	wc->stage = DROP_REFERENCE;
	wc->update_ref = update_ref;
	wc->keep_locks = 0;
	wc->for_reloc = for_reloc;
	wc->reada_count = BTRFS_NODEPTRS_PER_BLOCK(root);

	while (1) {

		ret = walk_down_tree(trans, root, path, wc);
		if (ret < 0) {
			err = ret;
			break;
		}

		ret = walk_up_tree(trans, root, path, wc, BTRFS_MAX_LEVEL);
		if (ret < 0) {
			err = ret;
			break;
		}

		if (ret > 0) {
			BUG_ON(wc->stage != DROP_REFERENCE);
			break;
		}

		if (wc->stage == DROP_REFERENCE) {
			level = wc->level;
			btrfs_node_key(path->nodes[level],
				       &root_item->drop_progress,
				       path->slots[level]);
			root_item->drop_level = level;
		}

		BUG_ON(wc->level == 0);
		if (btrfs_should_end_transaction(trans, tree_root) ||
		    (!for_reloc && btrfs_need_cleaner_sleep(root))) {
			ret = btrfs_update_root(trans, tree_root,
						&root->root_key,
						root_item);
			if (ret) {
				btrfs_abort_transaction(trans, tree_root, ret);
				err = ret;
				goto out_end_trans;
			}

			btrfs_end_transaction_throttle(trans, tree_root);
			if (!for_reloc && btrfs_need_cleaner_sleep(root)) {
				pr_debug("BTRFS: drop snapshot early exit\n");
				err = -EAGAIN;
				goto out_free;
			}

			trans = btrfs_start_transaction(tree_root, 0);
			if (IS_ERR(trans)) {
				err = PTR_ERR(trans);
				goto out_free;
			}
			if (block_rsv)
				trans->block_rsv = block_rsv;
		}
	}
	btrfs_release_path(path);
	if (err)
		goto out_end_trans;

#ifdef MY_ABC_HERE
	if (fs_info->quota_enabled && !for_reloc) {
		ret = btrfs_remove_qgroup(trans, fs_info, qgroupid);
		if (0 != ret) {
			if (-ENOENT == ret) {
				btrfs_err(fs_info, "cannot find qgroup item, qgroupid=%llu !\n", qgroupid);
			} else if (-EBUSY == ret) {
				btrfs_err(fs_info, "cannot remove qgroup item, it relates to other qgroup, qgroupid=%llu !\n", qgroupid);
			} else {
				btrfs_abort_transaction(trans, tree_root, ret);
				err = ret;
				goto out_end_trans;
			}
		}
	}
#endif  

	ret = btrfs_del_root(trans, tree_root, &root->root_key);
	if (ret) {
		btrfs_abort_transaction(trans, tree_root, ret);
		goto out_end_trans;
	}

	if (root->root_key.objectid != BTRFS_TREE_RELOC_OBJECTID) {
		ret = btrfs_find_root(tree_root, &root->root_key, path,
				      NULL, NULL);
		if (ret < 0) {
			btrfs_abort_transaction(trans, tree_root, ret);
			err = ret;
			goto out_end_trans;
		} else if (ret > 0) {
			 
			btrfs_del_orphan_item(trans, tree_root,
					      root->root_key.objectid);
		}
	}

	if (test_bit(BTRFS_ROOT_IN_RADIX, &root->state)) {
		btrfs_add_dropped_root(trans, root);
	} else {
		free_extent_buffer(root->node);
		free_extent_buffer(root->commit_root);
		btrfs_put_fs_root(root);
	}
	root_dropped = true;
out_end_trans:
	btrfs_end_transaction_throttle(trans, tree_root);
out_free:
	kfree(wc);
	btrfs_free_path(path);
out:
	 
	if (!for_reloc && root_dropped == false)
		btrfs_add_dead_root(root);
	if (err && err != -EAGAIN)
		btrfs_handle_fs_error(root->fs_info, err, NULL);
	return err;
}

int btrfs_drop_subtree(struct btrfs_trans_handle *trans,
			struct btrfs_root *root,
			struct extent_buffer *node,
			struct extent_buffer *parent)
{
	struct btrfs_path *path;
	struct walk_control *wc;
	int level;
	int parent_level;
	int ret = 0;
	int wret;

	BUG_ON(root->root_key.objectid != BTRFS_TREE_RELOC_OBJECTID);

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	wc = kzalloc(sizeof(*wc), GFP_NOFS);
	if (!wc) {
		btrfs_free_path(path);
		return -ENOMEM;
	}

	btrfs_assert_tree_locked(parent);
	parent_level = btrfs_header_level(parent);
	extent_buffer_get(parent);
	path->nodes[parent_level] = parent;
	path->slots[parent_level] = btrfs_header_nritems(parent);

	btrfs_assert_tree_locked(node);
	level = btrfs_header_level(node);
	path->nodes[level] = node;
	path->slots[level] = 0;
	path->locks[level] = BTRFS_WRITE_LOCK_BLOCKING;

	wc->refs[parent_level] = 1;
	wc->flags[parent_level] = BTRFS_BLOCK_FLAG_FULL_BACKREF;
	wc->level = level;
	wc->shared_level = -1;
	wc->stage = DROP_REFERENCE;
	wc->update_ref = 0;
	wc->keep_locks = 1;
	wc->for_reloc = 1;
	wc->reada_count = BTRFS_NODEPTRS_PER_BLOCK(root);

	while (1) {
		wret = walk_down_tree(trans, root, path, wc);
		if (wret < 0) {
			ret = wret;
			break;
		}

		wret = walk_up_tree(trans, root, path, wc, parent_level);
		if (wret < 0)
			ret = wret;
		if (wret != 0)
			break;
	}

	kfree(wc);
	btrfs_free_path(path);
	return ret;
}

static u64 update_block_group_flags(struct btrfs_root *root, u64 flags)
{
	u64 num_devices;
	u64 stripped;

	stripped = get_restripe_target(root->fs_info, flags);
	if (stripped)
		return extended_to_chunk(stripped);

	num_devices = root->fs_info->fs_devices->rw_devices;

	stripped = BTRFS_BLOCK_GROUP_RAID0 |
		BTRFS_BLOCK_GROUP_RAID5 | BTRFS_BLOCK_GROUP_RAID6 |
		BTRFS_BLOCK_GROUP_RAID1 | BTRFS_BLOCK_GROUP_RAID10;

	if (num_devices == 1) {
		stripped |= BTRFS_BLOCK_GROUP_DUP;
		stripped = flags & ~stripped;

		if (flags & BTRFS_BLOCK_GROUP_RAID0)
			return stripped;

		if (flags & (BTRFS_BLOCK_GROUP_RAID1 |
			     BTRFS_BLOCK_GROUP_RAID10))
			return stripped | BTRFS_BLOCK_GROUP_DUP;
	} else {
		 
		if (flags & stripped)
			return flags;

		stripped |= BTRFS_BLOCK_GROUP_DUP;
		stripped = flags & ~stripped;

		if (flags & BTRFS_BLOCK_GROUP_DUP)
			return stripped | BTRFS_BLOCK_GROUP_RAID1;

	}

	return flags;
}

static int inc_block_group_ro(struct btrfs_block_group_cache *cache, int force)
{
	struct btrfs_space_info *sinfo = cache->space_info;
	u64 num_bytes;
	u64 min_allocable_bytes;
	int ret = -ENOSPC;

	if ((sinfo->flags &
	     (BTRFS_BLOCK_GROUP_SYSTEM | BTRFS_BLOCK_GROUP_METADATA)) &&
	    !force)
		min_allocable_bytes = SZ_1M;
	else
		min_allocable_bytes = 0;

	spin_lock(&sinfo->lock);
	spin_lock(&cache->lock);

	if (cache->ro) {
		cache->ro++;
		ret = 0;
		goto out;
	}

	num_bytes = cache->key.offset - cache->reserved - cache->pinned -
		    cache->bytes_super - btrfs_block_group_used(&cache->item);

	if (sinfo->bytes_used + sinfo->bytes_reserved + sinfo->bytes_pinned +
	    sinfo->bytes_may_use + sinfo->bytes_readonly + num_bytes +
	    min_allocable_bytes <= sinfo->total_bytes) {
		sinfo->bytes_readonly += num_bytes;
		cache->ro++;
		list_add_tail(&cache->ro_list, &sinfo->ro_bgs);
		ret = 0;
	}
out:
	spin_unlock(&cache->lock);
	spin_unlock(&sinfo->lock);
	return ret;
}

int btrfs_inc_block_group_ro(struct btrfs_root *root,
			     struct btrfs_block_group_cache *cache)

{
	struct btrfs_trans_handle *trans;
	u64 alloc_flags;
	int ret;

again:
	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	mutex_lock(&root->fs_info->ro_block_group_mutex);
	if (test_bit(BTRFS_TRANS_DIRTY_BG_RUN, &trans->transaction->flags)) {
		u64 transid = trans->transid;

		mutex_unlock(&root->fs_info->ro_block_group_mutex);
		btrfs_end_transaction(trans, root);

		ret = btrfs_wait_for_commit(root, transid);
		if (ret)
			return ret;
		goto again;
	}

	alloc_flags = update_block_group_flags(root, cache->flags);
	if (alloc_flags != cache->flags) {
		ret = do_chunk_alloc(trans, root, alloc_flags,
				     CHUNK_ALLOC_FORCE);
		 
		if (ret == -ENOSPC)
			ret = 0;
		if (ret < 0)
			goto out;
	}

	ret = inc_block_group_ro(cache, 0);
	if (!ret)
		goto out;
	alloc_flags = get_alloc_profile(root, cache->space_info->flags);
	ret = do_chunk_alloc(trans, root, alloc_flags,
			     CHUNK_ALLOC_FORCE);
	if (ret < 0)
		goto out;
	ret = inc_block_group_ro(cache, 0);
out:
	if (cache->flags & BTRFS_BLOCK_GROUP_SYSTEM) {
		alloc_flags = update_block_group_flags(root, cache->flags);
		lock_chunks(root->fs_info->chunk_root);
		check_system_chunk(trans, root, alloc_flags);
		unlock_chunks(root->fs_info->chunk_root);
	}
	mutex_unlock(&root->fs_info->ro_block_group_mutex);

	btrfs_end_transaction(trans, root);
	return ret;
}

int btrfs_force_chunk_alloc(struct btrfs_trans_handle *trans,
			    struct btrfs_root *root, u64 type)
{
	u64 alloc_flags = get_alloc_profile(root, type);
	return do_chunk_alloc(trans, root, alloc_flags,
			      CHUNK_ALLOC_FORCE);
}

u64 btrfs_account_ro_block_groups_free_space(struct btrfs_space_info *sinfo)
{
	struct btrfs_block_group_cache *block_group;
	u64 free_bytes = 0;
	int factor;

	if (list_empty(&sinfo->ro_bgs))
		return 0;

	spin_lock(&sinfo->lock);
	list_for_each_entry(block_group, &sinfo->ro_bgs, ro_list) {
		spin_lock(&block_group->lock);

		if (!block_group->ro) {
			spin_unlock(&block_group->lock);
			continue;
		}

		if (block_group->flags & (BTRFS_BLOCK_GROUP_RAID1 |
					  BTRFS_BLOCK_GROUP_RAID10 |
					  BTRFS_BLOCK_GROUP_DUP))
			factor = 2;
		else
			factor = 1;

		free_bytes += (block_group->key.offset -
			       btrfs_block_group_used(&block_group->item)) *
			       factor;

		spin_unlock(&block_group->lock);
	}
	spin_unlock(&sinfo->lock);

	return free_bytes;
}

void btrfs_dec_block_group_ro(struct btrfs_root *root,
			      struct btrfs_block_group_cache *cache)
{
	struct btrfs_space_info *sinfo = cache->space_info;
	u64 num_bytes;

	BUG_ON(!cache->ro);

	spin_lock(&sinfo->lock);
	spin_lock(&cache->lock);
	if (!--cache->ro) {
		num_bytes = cache->key.offset - cache->reserved -
			    cache->pinned - cache->bytes_super -
			    btrfs_block_group_used(&cache->item);
		sinfo->bytes_readonly -= num_bytes;
		list_del_init(&cache->ro_list);
	}
	spin_unlock(&cache->lock);
	spin_unlock(&sinfo->lock);
}

int btrfs_can_relocate(struct btrfs_root *root, u64 bytenr)
{
	struct btrfs_block_group_cache *block_group;
	struct btrfs_space_info *space_info;
	struct btrfs_fs_devices *fs_devices = root->fs_info->fs_devices;
	struct btrfs_device *device;
	struct btrfs_trans_handle *trans;
	u64 min_free;
	u64 dev_min = 1;
	u64 dev_nr = 0;
	u64 target;
	int debug;
	int index;
	int full = 0;
	int ret = 0;

	debug = btrfs_test_opt(root, ENOSPC_DEBUG);

	block_group = btrfs_lookup_block_group(root->fs_info, bytenr);

	if (!block_group) {
		if (debug)
			btrfs_warn(root->fs_info,
				   "can't find block group for bytenr %llu",
				   bytenr);
		return -1;
	}

	min_free = btrfs_block_group_used(&block_group->item);

	if (!min_free)
		goto out;

	space_info = block_group->space_info;
	spin_lock(&space_info->lock);

	full = space_info->full;

	if ((space_info->total_bytes != block_group->key.offset) &&
	    (space_info->bytes_used + space_info->bytes_reserved +
	     space_info->bytes_pinned + space_info->bytes_readonly +
	     min_free < space_info->total_bytes)) {
		spin_unlock(&space_info->lock);
		goto out;
	}
	spin_unlock(&space_info->lock);

	ret = -1;

	target = get_restripe_target(root->fs_info, block_group->flags);
	if (target) {
		index = __get_raid_index(extended_to_chunk(target));
	} else {
		 
		if (full) {
			if (debug)
				btrfs_warn(root->fs_info,
					"no space to alloc new chunk for block group %llu",
					block_group->key.objectid);
			goto out;
		}

		index = get_block_group_index(block_group);
	}

	if (index == BTRFS_RAID_RAID10) {
		dev_min = 4;
		 
		min_free >>= 1;
	} else if (index == BTRFS_RAID_RAID1) {
		dev_min = 2;
	} else if (index == BTRFS_RAID_DUP) {
		 
		min_free <<= 1;
	} else if (index == BTRFS_RAID_RAID0) {
		dev_min = fs_devices->rw_devices;
		min_free = div64_u64(min_free, dev_min);
	}

	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out;
	}

	mutex_lock(&root->fs_info->chunk_mutex);
	list_for_each_entry(device, &fs_devices->alloc_list, dev_alloc_list) {
		u64 dev_offset;

		if (device->total_bytes > device->bytes_used + min_free &&
		    !device->is_tgtdev_for_dev_replace) {
			ret = find_free_dev_extent(trans, device, min_free,
						   &dev_offset, NULL);
			if (!ret)
				dev_nr++;

			if (dev_nr >= dev_min)
				break;

			ret = -1;
		}
	}
	if (debug && ret == -1)
		btrfs_warn(root->fs_info,
			"no space to allocate a new chunk for block group %llu",
			block_group->key.objectid);
	mutex_unlock(&root->fs_info->chunk_mutex);
	btrfs_end_transaction(trans, root);
out:
	btrfs_put_block_group(block_group);
	return ret;
}

static int find_first_block_group(struct btrfs_root *root,
		struct btrfs_path *path, struct btrfs_key *key)
{
	int ret = 0;
	struct btrfs_key found_key;
	struct extent_buffer *leaf;
	int slot;

	ret = btrfs_search_slot(NULL, root, key, path, 0, 0);
	if (ret < 0)
		goto out;

	while (1) {
		slot = path->slots[0];
		leaf = path->nodes[0];
		if (slot >= btrfs_header_nritems(leaf)) {
			ret = btrfs_next_leaf(root, path);
			if (ret == 0)
				continue;
			if (ret < 0)
				goto out;
			break;
		}
		btrfs_item_key_to_cpu(leaf, &found_key, slot);

		if (found_key.objectid >= key->objectid &&
		    found_key.type == BTRFS_BLOCK_GROUP_ITEM_KEY) {
			ret = 0;
			goto out;
		}
		path->slots[0]++;
	}
out:
	return ret;
}

void btrfs_put_block_group_cache(struct btrfs_fs_info *info)
{
	struct btrfs_block_group_cache *block_group;
	u64 last = 0;

	while (1) {
		struct inode *inode;

		block_group = btrfs_lookup_first_block_group(info, last);
		while (block_group) {
			spin_lock(&block_group->lock);
			if (block_group->iref)
				break;
			spin_unlock(&block_group->lock);
			block_group = next_block_group(info->tree_root,
						       block_group);
		}
		if (!block_group) {
			if (last == 0)
				break;
			last = 0;
			continue;
		}

		inode = block_group->inode;
		block_group->iref = 0;
		block_group->inode = NULL;
		spin_unlock(&block_group->lock);
		iput(inode);
		last = block_group->key.objectid + block_group->key.offset;
		btrfs_put_block_group(block_group);
	}
}

int btrfs_free_block_groups(struct btrfs_fs_info *info)
{
	struct btrfs_block_group_cache *block_group;
	struct btrfs_space_info *space_info;
	struct btrfs_caching_control *caching_ctl;
	struct rb_node *n;

	down_write(&info->commit_root_sem);
	while (!list_empty(&info->caching_block_groups)) {
		caching_ctl = list_entry(info->caching_block_groups.next,
					 struct btrfs_caching_control, list);
		list_del(&caching_ctl->list);
		put_caching_control(caching_ctl);
	}
	up_write(&info->commit_root_sem);

	spin_lock(&info->unused_bgs_lock);
	while (!list_empty(&info->unused_bgs)) {
		block_group = list_first_entry(&info->unused_bgs,
					       struct btrfs_block_group_cache,
					       bg_list);
		list_del_init(&block_group->bg_list);
		btrfs_put_block_group(block_group);
	}
	spin_unlock(&info->unused_bgs_lock);

	spin_lock(&info->block_group_cache_lock);
	while ((n = rb_last(&info->block_group_cache_tree)) != NULL) {
		block_group = rb_entry(n, struct btrfs_block_group_cache,
				       cache_node);
		rb_erase(&block_group->cache_node,
			 &info->block_group_cache_tree);
		RB_CLEAR_NODE(&block_group->cache_node);
		spin_unlock(&info->block_group_cache_lock);

		down_write(&block_group->space_info->groups_sem);
		list_del(&block_group->list);
		up_write(&block_group->space_info->groups_sem);

		if (block_group->cached == BTRFS_CACHE_STARTED)
			wait_block_group_cache_done(block_group);

		if (block_group->cached == BTRFS_CACHE_NO ||
		    block_group->cached == BTRFS_CACHE_ERROR)
			free_excluded_extents(info->extent_root, block_group);

		btrfs_remove_free_space_cache(block_group);
		btrfs_put_block_group(block_group);

		spin_lock(&info->block_group_cache_lock);
	}
	spin_unlock(&info->block_group_cache_lock);

	synchronize_rcu();

	release_global_block_rsv(info);

	while (!list_empty(&info->space_info)) {
		int i;

		space_info = list_entry(info->space_info.next,
					struct btrfs_space_info,
					list);
		if (btrfs_test_opt(info->tree_root, ENOSPC_DEBUG)) {
			if (WARN_ON(space_info->bytes_pinned > 0 ||
			    space_info->bytes_reserved > 0 ||
			    space_info->bytes_may_use > 0)) {
				dump_space_info(space_info, 0, 0);
			}
		}
		list_del(&space_info->list);
		for (i = 0; i < BTRFS_NR_RAID_TYPES; i++) {
			struct kobject *kobj;
			kobj = space_info->block_group_kobjs[i];
			space_info->block_group_kobjs[i] = NULL;
			if (kobj) {
				kobject_del(kobj);
				kobject_put(kobj);
			}
		}
		kobject_del(&space_info->kobj);
		kobject_put(&space_info->kobj);
	}
	return 0;
}

static void __link_block_group(struct btrfs_space_info *space_info,
			       struct btrfs_block_group_cache *cache)
{
	int index = get_block_group_index(cache);
	bool first = false;

	down_write(&space_info->groups_sem);
	if (list_empty(&space_info->block_groups[index]))
		first = true;
	list_add_tail(&cache->list, &space_info->block_groups[index]);
	up_write(&space_info->groups_sem);

	if (first) {
		struct raid_kobject *rkobj;
		int ret;

		rkobj = kzalloc(sizeof(*rkobj), GFP_NOFS);
		if (!rkobj)
			goto out_err;
		rkobj->raid_type = index;
		kobject_init(&rkobj->kobj, &btrfs_raid_ktype);
		ret = kobject_add(&rkobj->kobj, &space_info->kobj,
				  "%s", get_raid_name(index));
		if (ret) {
			kobject_put(&rkobj->kobj);
			goto out_err;
		}
		space_info->block_group_kobjs[index] = &rkobj->kobj;
	}

	return;
out_err:
	pr_warn("BTRFS: failed to add kobject for block cache. ignoring.\n");
}

static struct btrfs_block_group_cache *
btrfs_create_block_group_cache(struct btrfs_root *root, u64 start, u64 size)
{
	struct btrfs_block_group_cache *cache;

	cache = kzalloc(sizeof(*cache), GFP_NOFS);
	if (!cache)
		return NULL;

	cache->free_space_ctl = kzalloc(sizeof(*cache->free_space_ctl),
					GFP_NOFS);
	if (!cache->free_space_ctl) {
		kfree(cache);
		return NULL;
	}

	cache->key.objectid = start;
	cache->key.offset = size;
	cache->key.type = BTRFS_BLOCK_GROUP_ITEM_KEY;

	cache->sectorsize = root->sectorsize;
	cache->fs_info = root->fs_info;
	cache->full_stripe_len = btrfs_full_stripe_len(root,
					       &root->fs_info->mapping_tree,
					       start);
	set_free_space_tree_thresholds(cache);

	atomic_set(&cache->count, 1);
	spin_lock_init(&cache->lock);
	init_rwsem(&cache->data_rwsem);
	INIT_LIST_HEAD(&cache->list);
	INIT_LIST_HEAD(&cache->cluster_list);
	INIT_LIST_HEAD(&cache->bg_list);
	INIT_LIST_HEAD(&cache->ro_list);
	INIT_LIST_HEAD(&cache->dirty_list);
	INIT_LIST_HEAD(&cache->io_list);
	btrfs_init_free_space_ctl(cache);
	atomic_set(&cache->trimming, 0);
	mutex_init(&cache->free_space_lock);

	return cache;
}

#ifdef MY_ABC_HERE
static void reada_root(struct btrfs_root *root)
{
	struct extent_buffer *node;
	int level;
	u64 search;
	u32 nr = 0;
	u32 nritems;

	node = btrfs_root_node(root);
	level = btrfs_header_level(node);
	if (level == 0)
		goto out;

	nritems = btrfs_header_nritems(node);
	while (nr < nritems) {
		search = btrfs_node_blockptr(node, nr);
		readahead_tree_block(root, search);
		nr++;
	}

out:
	free_extent_buffer(node);
}

struct reada_path {
	struct btrfs_root *root;
	struct btrfs_key key;
	struct btrfs_work work;
};

static void reada_path_start(struct btrfs_work *work)
{
	struct reada_path *reada_path;
	struct btrfs_path *path;
	struct btrfs_fs_info *fs_info;

	reada_path = container_of(work, struct reada_path, work);
	fs_info = reada_path->root->fs_info;
	path = btrfs_alloc_path();
	if (!path)
		goto done;

	btrfs_search_slot(NULL, reada_path->root, &reada_path->key, path, 0, 0);

	btrfs_free_path(path);
done:
	kfree(reada_path);
	atomic_dec(&fs_info->reada_block_group_threads);
}

static void reada_block_group_item(struct btrfs_fs_info *fs_info, struct btrfs_path *hint_path)
{
	struct reada_path *reada_path;
	struct extent_buffer *leaf;
	int slot;
	int i;

	if (!hint_path->nodes[0])
		return;

	for (i = 0; i + atomic_read(&fs_info->reada_block_group_threads) < READA_BLOCK_GROUP_THREAD_MAX; i++) {
		slot = hint_path->slots[0];
		leaf = hint_path->nodes[0];

		if (!btrfs_header_nritems(leaf))
			goto stop_readahead;

		reada_path = kmalloc(sizeof(struct reada_path), GFP_NOFS);
		if (!reada_path)
			goto stop_readahead;

		reada_path->root = fs_info->extent_root;
		btrfs_item_key_to_cpu(leaf, &reada_path->key, slot);

		btrfs_init_work(&reada_path->work, btrfs_reada_path_start_helper, reada_path_start, NULL, NULL);
		btrfs_queue_work(fs_info->reada_path_workers, &reada_path->work);
		atomic_inc(&fs_info->reada_block_group_threads);

		if (slot + 1 < btrfs_header_nritems(leaf))
			hint_path->slots[0]++;
		else if (btrfs_next_leaf(fs_info->block_group_hint_root, hint_path))
			goto stop_readahead;
	}
	return;

stop_readahead:
	btrfs_release_path(hint_path);
	return;
}
#endif  

int btrfs_read_block_groups(struct btrfs_root *root)
{
	struct btrfs_path *path;
	int ret;
	struct btrfs_block_group_cache *cache;
	struct btrfs_fs_info *info = root->fs_info;
	struct btrfs_space_info *space_info;
	struct btrfs_key key;
	struct btrfs_key found_key;
	struct extent_buffer *leaf;
	int need_clear = 0;
	u64 cache_gen;
#ifdef MY_ABC_HERE
	struct btrfs_path *hint_path;
#endif  
	u64 feature;
	int mixed;

	feature = btrfs_super_incompat_flags(info->super_copy);
	mixed = !!(feature & BTRFS_FEATURE_INCOMPAT_MIXED_GROUPS);

	root = info->extent_root;
	key.objectid = 0;
	key.offset = 0;
	key.type = BTRFS_BLOCK_GROUP_ITEM_KEY;
	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;
	path->reada = READA_FORWARD;
#ifdef MY_ABC_HERE
	hint_path = btrfs_alloc_path();
	if (!hint_path) {
		ret = -ENOMEM;
		goto error;
	}
	hint_path->reada = READA_FORWARD;
#endif  

	cache_gen = btrfs_super_cache_generation(root->fs_info->super_copy);
	if (btrfs_test_opt(root, SPACE_CACHE) &&
	    btrfs_super_generation(root->fs_info->super_copy) != cache_gen)
		need_clear = 1;
	if (btrfs_test_opt(root, CLEAR_CACHE))
		need_clear = 1;

#ifdef MY_ABC_HERE
	atomic_set(&info->reada_block_group_threads, 0);
	reada_root(root);
	if (info->block_group_hint_root) {
		reada_root(info->block_group_hint_root);
		ret = btrfs_search_slot(NULL, info->block_group_hint_root, &key, hint_path, 0, 0);
		if (ret < 0)
			btrfs_release_path(hint_path);
	}
#endif  

	while (1) {
#ifdef MY_ABC_HERE
		if (info->block_group_hint_root && info->reada_path_workers)
			reada_block_group_item(info, hint_path);
#endif  
		ret = find_first_block_group(root, path, &key);
		if (ret > 0)
			break;
		if (ret != 0)
			goto error;

		leaf = path->nodes[0];
		btrfs_item_key_to_cpu(leaf, &found_key, path->slots[0]);

		cache = btrfs_create_block_group_cache(root, found_key.objectid,
						       found_key.offset);
		if (!cache) {
			ret = -ENOMEM;
			goto error;
		}

		if (need_clear) {
			 
			if (btrfs_test_opt(root, SPACE_CACHE))
				cache->disk_cache_state = BTRFS_DC_CLEAR;
		}

		read_extent_buffer(leaf, &cache->item,
				   btrfs_item_ptr_offset(leaf, path->slots[0]),
				   sizeof(cache->item));
		cache->flags = btrfs_block_group_flags(&cache->item);
		if (!mixed &&
		    ((cache->flags & BTRFS_BLOCK_GROUP_METADATA) &&
		    (cache->flags & BTRFS_BLOCK_GROUP_DATA))) {
			btrfs_err(info,
"bg %llu is a mixed block group but filesystem hasn't enabled mixed block groups",
				  cache->key.objectid);
			ret = -EINVAL;
			goto error;
		}

		key.objectid = found_key.objectid + found_key.offset;
		btrfs_release_path(path);

		ret = exclude_super_stripes(root, cache);
		if (ret) {
			 
			free_excluded_extents(root, cache);
			btrfs_put_block_group(cache);
			goto error;
		}

		if (found_key.offset == btrfs_block_group_used(&cache->item)) {
			cache->last_byte_to_unpin = (u64)-1;
			cache->cached = BTRFS_CACHE_FINISHED;
			free_excluded_extents(root, cache);
		} else if (btrfs_block_group_used(&cache->item) == 0) {
			cache->last_byte_to_unpin = (u64)-1;
			cache->cached = BTRFS_CACHE_FINISHED;
			add_new_free_space(cache, root->fs_info,
					   found_key.objectid,
					   found_key.objectid +
					   found_key.offset);
			free_excluded_extents(root, cache);
		}

		ret = btrfs_add_block_group_cache(root->fs_info, cache);
		if (ret) {
			btrfs_remove_free_space_cache(cache);
			btrfs_put_block_group(cache);
			goto error;
		}

		ret = update_space_info(info, cache->flags, found_key.offset,
					btrfs_block_group_used(&cache->item),
					&space_info);
		if (ret) {
			btrfs_remove_free_space_cache(cache);
			spin_lock(&info->block_group_cache_lock);
			rb_erase(&cache->cache_node,
				 &info->block_group_cache_tree);
			RB_CLEAR_NODE(&cache->cache_node);
			spin_unlock(&info->block_group_cache_lock);
			btrfs_put_block_group(cache);
			goto error;
		}

		cache->space_info = space_info;
		spin_lock(&cache->space_info->lock);
		cache->space_info->bytes_readonly += cache->bytes_super;
		spin_unlock(&cache->space_info->lock);

		__link_block_group(space_info, cache);

		set_avail_alloc_bits(root->fs_info, cache->flags);
		if (btrfs_chunk_readonly(root, cache->key.objectid)) {
			inc_block_group_ro(cache, 1);
#ifdef MY_ABC_HERE
		} else if (btrfs_block_group_used(&cache->item) == 0 && should_add_to_unused_bgs(root->fs_info, cache->flags)) {
#else
		} else if (btrfs_block_group_used(&cache->item) == 0) {
#endif  
			spin_lock(&info->unused_bgs_lock);
			 
			if (list_empty(&cache->bg_list)) {
				btrfs_get_block_group(cache);
				list_add_tail(&cache->bg_list,
					      &info->unused_bgs);
			}
			spin_unlock(&info->unused_bgs_lock);
		}
	}

	list_for_each_entry_rcu(space_info, &root->fs_info->space_info, list) {
		if (!(get_alloc_profile(root, space_info->flags) &
		      (BTRFS_BLOCK_GROUP_RAID10 |
		       BTRFS_BLOCK_GROUP_RAID1 |
		       BTRFS_BLOCK_GROUP_RAID5 |
		       BTRFS_BLOCK_GROUP_RAID6 |
		       BTRFS_BLOCK_GROUP_DUP)))
			continue;
		 
		list_for_each_entry(cache,
				&space_info->block_groups[BTRFS_RAID_RAID0],
				list)
			inc_block_group_ro(cache, 1);
		list_for_each_entry(cache,
				&space_info->block_groups[BTRFS_RAID_SINGLE],
				list)
			inc_block_group_ro(cache, 1);
	}

	init_global_block_rsv(info);
	ret = 0;
error:
	btrfs_free_path(path);
#ifdef MY_ABC_HERE
	btrfs_free_path(hint_path);
#endif  
	return ret;
}

void btrfs_create_pending_block_groups(struct btrfs_trans_handle *trans,
				       struct btrfs_root *root)
{
	struct btrfs_block_group_cache *block_group, *tmp;
	struct btrfs_root *extent_root = root->fs_info->extent_root;
	struct btrfs_block_group_item item;
	struct btrfs_key key;
	int ret = 0;
	bool can_flush_pending_bgs = trans->can_flush_pending_bgs;
#ifdef MY_ABC_HERE
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_root *block_group_hint_root;

	if (!fs_info->block_group_hint_root && !fs_info->no_block_group_hint) {
		spin_lock(&fs_info->block_group_hint_tree_lock);
		if (!fs_info->block_group_hint_root) {
			block_group_hint_root = btrfs_create_tree(trans, fs_info, BTRFS_BLOCK_GROUP_HINT_TREE_OBJECTID);
			if (!IS_ERR_OR_NULL(block_group_hint_root)) {
				fs_info->block_group_hint_root = block_group_hint_root;
			} else {
				btrfs_err(fs_info, "Failed to create block group hint tree\n");
			}
		}
		spin_unlock(&fs_info->block_group_hint_tree_lock);
	}
#endif  

	trans->can_flush_pending_bgs = false;
	list_for_each_entry_safe(block_group, tmp, &trans->new_bgs, bg_list) {
		if (ret)
			goto next;

		spin_lock(&block_group->lock);
		memcpy(&item, &block_group->item, sizeof(item));
		memcpy(&key, &block_group->key, sizeof(key));
		spin_unlock(&block_group->lock);

		ret = btrfs_insert_item(trans, extent_root, &key, &item,
					sizeof(item));
		if (ret)
			btrfs_abort_transaction(trans, extent_root, ret);

#ifdef MY_ABC_HERE
		if (fs_info->block_group_hint_root) {
			ret = btrfs_insert_item(trans, fs_info->block_group_hint_root, &key, &item,
					sizeof(item));
			if (ret) {
				btrfs_err(fs_info, "Failed to insert block group item %llu-%llu into hint tree, err = %d\n",
						key.objectid, key.offset, ret);
				WARN_ON(1);
			}
		}
#endif  

		ret = btrfs_finish_chunk_alloc(trans, extent_root,
					       key.objectid, key.offset);
		if (ret)
			btrfs_abort_transaction(trans, extent_root, ret);
		add_block_group_free_space(trans, root->fs_info, block_group);
		 
next:
		list_del_init(&block_group->bg_list);
	}
	trans->can_flush_pending_bgs = can_flush_pending_bgs;
}

int btrfs_make_block_group(struct btrfs_trans_handle *trans,
			   struct btrfs_root *root, u64 bytes_used,
			   u64 type, u64 chunk_objectid, u64 chunk_offset,
			   u64 size)
{
	int ret;
	struct btrfs_root *extent_root;
	struct btrfs_block_group_cache *cache;

	extent_root = root->fs_info->extent_root;

	btrfs_set_log_full_commit(root->fs_info, trans);

	cache = btrfs_create_block_group_cache(root, chunk_offset, size);
	if (!cache)
		return -ENOMEM;

	btrfs_set_block_group_used(&cache->item, bytes_used);
	btrfs_set_block_group_chunk_objectid(&cache->item, chunk_objectid);
	btrfs_set_block_group_flags(&cache->item, type);

	cache->flags = type;
	cache->last_byte_to_unpin = (u64)-1;
	cache->cached = BTRFS_CACHE_FINISHED;
	cache->needs_free_space = 1;
	ret = exclude_super_stripes(root, cache);
	if (ret) {
		 
		free_excluded_extents(root, cache);
		btrfs_put_block_group(cache);
		return ret;
	}

	add_new_free_space(cache, root->fs_info, chunk_offset,
			   chunk_offset + size);

	free_excluded_extents(root, cache);

#ifdef CONFIG_BTRFS_DEBUG
	if (btrfs_should_fragment_free_space(root, cache)) {
		u64 new_bytes_used = size - bytes_used;

		bytes_used += new_bytes_used >> 1;
		fragment_free_space(root, cache);
	}
#endif
	 
	ret = update_space_info(root->fs_info, cache->flags, 0, 0,
				&cache->space_info);
	if (ret) {
		btrfs_remove_free_space_cache(cache);
		btrfs_put_block_group(cache);
		return ret;
	}

	ret = btrfs_add_block_group_cache(root->fs_info, cache);
	if (ret) {
		btrfs_remove_free_space_cache(cache);
		btrfs_put_block_group(cache);
		return ret;
	}

	ret = update_space_info(root->fs_info, cache->flags, size, bytes_used,
				&cache->space_info);
	if (ret) {
		btrfs_remove_free_space_cache(cache);
		spin_lock(&root->fs_info->block_group_cache_lock);
		rb_erase(&cache->cache_node,
			 &root->fs_info->block_group_cache_tree);
		RB_CLEAR_NODE(&cache->cache_node);
		spin_unlock(&root->fs_info->block_group_cache_lock);
		btrfs_put_block_group(cache);
		return ret;
	}
	update_global_block_rsv(root->fs_info);

	spin_lock(&cache->space_info->lock);
	cache->space_info->bytes_readonly += cache->bytes_super;
	spin_unlock(&cache->space_info->lock);

	__link_block_group(cache->space_info, cache);

	list_add_tail(&cache->bg_list, &trans->new_bgs);

	set_avail_alloc_bits(extent_root->fs_info, type);

	return 0;
}

static void clear_avail_alloc_bits(struct btrfs_fs_info *fs_info, u64 flags)
{
	u64 extra_flags = chunk_to_extended(flags) &
				BTRFS_EXTENDED_PROFILE_MASK;

	write_seqlock(&fs_info->profiles_lock);
	if (flags & BTRFS_BLOCK_GROUP_DATA)
		fs_info->avail_data_alloc_bits &= ~extra_flags;
	if (flags & BTRFS_BLOCK_GROUP_METADATA)
		fs_info->avail_metadata_alloc_bits &= ~extra_flags;
	if (flags & BTRFS_BLOCK_GROUP_SYSTEM)
		fs_info->avail_system_alloc_bits &= ~extra_flags;
	write_sequnlock(&fs_info->profiles_lock);
}

int btrfs_remove_block_group(struct btrfs_trans_handle *trans,
			     struct btrfs_root *root, u64 group_start,
			     struct extent_map *em)
{
	struct btrfs_path *path;
	struct btrfs_block_group_cache *block_group;
	struct btrfs_free_cluster *cluster;
	struct btrfs_root *tree_root = root->fs_info->tree_root;
	struct btrfs_key key;
	struct inode *inode;
	struct kobject *kobj = NULL;
	int ret;
	int index;
	int factor;
	struct btrfs_caching_control *caching_ctl = NULL;
	bool remove_em;
#ifdef MY_ABC_HERE
	struct btrfs_fs_info *fs_info = root->fs_info;
#endif  

	root = root->fs_info->extent_root;

	block_group = btrfs_lookup_block_group(root->fs_info, group_start);
	BUG_ON(!block_group);
	BUG_ON(!block_group->ro);

	free_excluded_extents(root, block_group);

	memcpy(&key, &block_group->key, sizeof(key));
	index = get_block_group_index(block_group);
	if (block_group->flags & (BTRFS_BLOCK_GROUP_DUP |
				  BTRFS_BLOCK_GROUP_RAID1 |
				  BTRFS_BLOCK_GROUP_RAID10))
		factor = 2;
	else
		factor = 1;

	cluster = &root->fs_info->data_alloc_cluster;
	spin_lock(&cluster->refill_lock);
	btrfs_return_cluster_to_free_space(block_group, cluster);
	spin_unlock(&cluster->refill_lock);

	cluster = &root->fs_info->meta_alloc_cluster;
	spin_lock(&cluster->refill_lock);
	btrfs_return_cluster_to_free_space(block_group, cluster);
	spin_unlock(&cluster->refill_lock);

	path = btrfs_alloc_path();
	if (!path) {
		ret = -ENOMEM;
		goto out;
	}

	inode = lookup_free_space_inode(tree_root, block_group, path);

	mutex_lock(&trans->transaction->cache_write_mutex);
	 
	spin_lock(&trans->transaction->dirty_bgs_lock);
	if (!list_empty(&block_group->io_list)) {
		list_del_init(&block_group->io_list);

		WARN_ON(!IS_ERR(inode) && inode != block_group->io_ctl.inode);

		spin_unlock(&trans->transaction->dirty_bgs_lock);
		btrfs_wait_cache_io(root, trans, block_group,
				    &block_group->io_ctl, path,
				    block_group->key.objectid);
		btrfs_put_block_group(block_group);
		spin_lock(&trans->transaction->dirty_bgs_lock);
	}

	if (!list_empty(&block_group->dirty_list)) {
		list_del_init(&block_group->dirty_list);
		btrfs_put_block_group(block_group);
	}
	spin_unlock(&trans->transaction->dirty_bgs_lock);
	mutex_unlock(&trans->transaction->cache_write_mutex);

	if (!IS_ERR(inode)) {
		ret = btrfs_orphan_add(trans, inode);
		if (ret) {
			btrfs_add_delayed_iput(inode);
			goto out;
		}
		clear_nlink(inode);
		 
		spin_lock(&block_group->lock);
		if (block_group->iref) {
			block_group->iref = 0;
			block_group->inode = NULL;
			spin_unlock(&block_group->lock);
			iput(inode);
		} else {
			spin_unlock(&block_group->lock);
		}
		 
		btrfs_add_delayed_iput(inode);
	}

	key.objectid = BTRFS_FREE_SPACE_OBJECTID;
	key.offset = block_group->key.objectid;
	key.type = 0;

	ret = btrfs_search_slot(trans, tree_root, &key, path, -1, 1);
	if (ret < 0)
		goto out;
	if (ret > 0)
		btrfs_release_path(path);
	if (ret == 0) {
		ret = btrfs_del_item(trans, tree_root, path);
		if (ret)
			goto out;
		btrfs_release_path(path);
	}

	spin_lock(&root->fs_info->block_group_cache_lock);
	rb_erase(&block_group->cache_node,
		 &root->fs_info->block_group_cache_tree);
	RB_CLEAR_NODE(&block_group->cache_node);

	if (root->fs_info->first_logical_byte == block_group->key.objectid)
		root->fs_info->first_logical_byte = (u64)-1;
	spin_unlock(&root->fs_info->block_group_cache_lock);

	down_write(&block_group->space_info->groups_sem);
	 
	list_del_init(&block_group->list);
	if (list_empty(&block_group->space_info->block_groups[index])) {
		kobj = block_group->space_info->block_group_kobjs[index];
		block_group->space_info->block_group_kobjs[index] = NULL;
		clear_avail_alloc_bits(root->fs_info, block_group->flags);
	}
	up_write(&block_group->space_info->groups_sem);
	if (kobj) {
		kobject_del(kobj);
		kobject_put(kobj);
	}

	if (block_group->has_caching_ctl)
		caching_ctl = get_caching_control(block_group);
	if (block_group->cached == BTRFS_CACHE_STARTED)
		wait_block_group_cache_done(block_group);
	if (block_group->has_caching_ctl) {
		down_write(&root->fs_info->commit_root_sem);
		if (!caching_ctl) {
			struct btrfs_caching_control *ctl;

			list_for_each_entry(ctl,
				    &root->fs_info->caching_block_groups, list)
				if (ctl->block_group == block_group) {
					caching_ctl = ctl;
					atomic_inc(&caching_ctl->count);
					break;
				}
		}
		if (caching_ctl)
			list_del_init(&caching_ctl->list);
		up_write(&root->fs_info->commit_root_sem);
		if (caching_ctl) {
			 
			put_caching_control(caching_ctl);
			put_caching_control(caching_ctl);
		}
	}

	spin_lock(&trans->transaction->dirty_bgs_lock);
	if (!list_empty(&block_group->dirty_list)) {
		WARN_ON(1);
	}
	if (!list_empty(&block_group->io_list)) {
		WARN_ON(1);
	}
	spin_unlock(&trans->transaction->dirty_bgs_lock);
	btrfs_remove_free_space_cache(block_group);

	spin_lock(&block_group->space_info->lock);
	list_del_init(&block_group->ro_list);

	if (btrfs_test_opt(root, ENOSPC_DEBUG)) {
		WARN_ON(block_group->space_info->total_bytes
			< block_group->key.offset);
		WARN_ON(block_group->space_info->bytes_readonly
			< block_group->key.offset);
		WARN_ON(block_group->space_info->disk_total
			< block_group->key.offset * factor);
	}
	block_group->space_info->total_bytes -= block_group->key.offset;
	block_group->space_info->bytes_readonly -= block_group->key.offset;
	block_group->space_info->disk_total -= block_group->key.offset * factor;

	spin_unlock(&block_group->space_info->lock);

	memcpy(&key, &block_group->key, sizeof(key));

	lock_chunks(root);
	if (!list_empty(&em->list)) {
		 
		free_extent_map(em);
	}
	spin_lock(&block_group->lock);
	block_group->removed = 1;
	 
	remove_em = (atomic_read(&block_group->trimming) == 0);
	 
	if (!remove_em) {
		 
		list_move_tail(&em->list, &root->fs_info->pinned_chunks);
	}
	spin_unlock(&block_group->lock);

	if (remove_em) {
		struct extent_map_tree *em_tree;

		em_tree = &root->fs_info->mapping_tree.map_tree;
		write_lock(&em_tree->lock);
		 
		remove_extent_mapping(em_tree, em);
		write_unlock(&em_tree->lock);
		 
		free_extent_map(em);
	}

	unlock_chunks(root);

	ret = remove_block_group_free_space(trans, root->fs_info, block_group);
	if (ret)
		goto out;

	btrfs_put_block_group(block_group);
	btrfs_put_block_group(block_group);

	ret = btrfs_search_slot(trans, root, &key, path, -1, 1);
	if (ret > 0)
		ret = -EIO;
	if (ret < 0)
		goto out;

	ret = btrfs_del_item(trans, root, path);

#ifdef MY_ABC_HERE
	if (fs_info->block_group_hint_root) {
		int search_ret;
		btrfs_release_path(path);
		search_ret = btrfs_search_slot(trans, fs_info->block_group_hint_root, &key, path, -1, 1);
		if (!search_ret)
			btrfs_del_item(trans, fs_info->block_group_hint_root, path);
	}
#endif  

out:
	btrfs_free_path(path);
	return ret;
}

struct btrfs_trans_handle *
btrfs_start_trans_remove_block_group(struct btrfs_fs_info *fs_info,
				     const u64 chunk_offset)
{
	struct extent_map_tree *em_tree = &fs_info->mapping_tree.map_tree;
	struct extent_map *em;
	struct map_lookup *map;
	unsigned int num_items;

	read_lock(&em_tree->lock);
	em = lookup_extent_mapping(em_tree, chunk_offset, 1);
	read_unlock(&em_tree->lock);
	ASSERT(em && em->start == chunk_offset);

	map = em->map_lookup;
	num_items = 3 + map->num_stripes;
	free_extent_map(em);

	return btrfs_start_transaction_fallback_global_rsv(fs_info->extent_root,
							   num_items, 1);
}

void btrfs_delete_unused_bgs(struct btrfs_fs_info *fs_info)
{
	struct btrfs_block_group_cache *block_group;
	struct btrfs_space_info *space_info;
	struct btrfs_root *root = fs_info->extent_root;
	struct btrfs_trans_handle *trans;
	int ret = 0;

	if (!fs_info->open)
		return;

	spin_lock(&fs_info->unused_bgs_lock);
	while (!list_empty(&fs_info->unused_bgs)) {
		u64 start, end;
		int trimming;

		block_group = list_first_entry(&fs_info->unused_bgs,
					       struct btrfs_block_group_cache,
					       bg_list);
		list_del_init(&block_group->bg_list);

		space_info = block_group->space_info;

		if (ret || btrfs_mixed_space_info(space_info)) {
			btrfs_put_block_group(block_group);
			continue;
		}
		spin_unlock(&fs_info->unused_bgs_lock);

		mutex_lock(&fs_info->delete_unused_bgs_mutex);

		down_write(&space_info->groups_sem);
		spin_lock(&block_group->lock);
		if (block_group->reserved ||
		    btrfs_block_group_used(&block_group->item) ||
		    block_group->ro ||
		    list_is_singular(&block_group->list)) {
			 
			spin_unlock(&block_group->lock);
			up_write(&space_info->groups_sem);
			goto next;
		}
		spin_unlock(&block_group->lock);

		ret = inc_block_group_ro(block_group, 0);
		up_write(&space_info->groups_sem);
		if (ret < 0) {
			ret = 0;
			goto next;
		}

		trans = btrfs_start_trans_remove_block_group(fs_info,
						     block_group->key.objectid);
		if (IS_ERR(trans)) {
			btrfs_dec_block_group_ro(root, block_group);
			ret = PTR_ERR(trans);
			goto next;
		}

		start = block_group->key.objectid;
		end = start + block_group->key.offset - 1;
		 
		mutex_lock(&fs_info->unused_bg_unpin_mutex);
		ret = clear_extent_bits(&fs_info->freed_extents[0], start, end,
				  EXTENT_DIRTY);
		if (ret) {
			mutex_unlock(&fs_info->unused_bg_unpin_mutex);
			btrfs_dec_block_group_ro(root, block_group);
			goto end_trans;
		}
		ret = clear_extent_bits(&fs_info->freed_extents[1], start, end,
				  EXTENT_DIRTY);
		if (ret) {
			mutex_unlock(&fs_info->unused_bg_unpin_mutex);
			btrfs_dec_block_group_ro(root, block_group);
			goto end_trans;
		}
		mutex_unlock(&fs_info->unused_bg_unpin_mutex);

		spin_lock(&space_info->lock);
		spin_lock(&block_group->lock);

		space_info->bytes_pinned -= block_group->pinned;
		space_info->bytes_readonly += block_group->pinned;
		percpu_counter_add(&space_info->total_bytes_pinned,
				   -block_group->pinned);
		block_group->pinned = 0;

		spin_unlock(&block_group->lock);
		spin_unlock(&space_info->lock);

		trimming = btrfs_test_opt(root, DISCARD);

		if (trimming)
			btrfs_get_block_group_trimming(block_group);

		ret = btrfs_remove_chunk(trans, root,
					 block_group->key.objectid);

		if (ret) {
			if (trimming)
				btrfs_put_block_group_trimming(block_group);
			goto end_trans;
		}

		if (trimming) {
			spin_lock(&fs_info->unused_bgs_lock);
			 
			list_move(&block_group->bg_list,
				  &trans->transaction->deleted_bgs);
			spin_unlock(&fs_info->unused_bgs_lock);
			btrfs_get_block_group(block_group);
		}
end_trans:
		btrfs_end_transaction(trans, root);
next:
		mutex_unlock(&fs_info->delete_unused_bgs_mutex);
		btrfs_put_block_group(block_group);
		spin_lock(&fs_info->unused_bgs_lock);
	}
	spin_unlock(&fs_info->unused_bgs_lock);
}

int btrfs_init_space_info(struct btrfs_fs_info *fs_info)
{
	struct btrfs_space_info *space_info;
	struct btrfs_super_block *disk_super;
	u64 features;
	u64 flags;
	int mixed = 0;
	int ret;

	disk_super = fs_info->super_copy;
	if (!btrfs_super_root(disk_super))
		return -EINVAL;

	features = btrfs_super_incompat_flags(disk_super);
	if (features & BTRFS_FEATURE_INCOMPAT_MIXED_GROUPS)
		mixed = 1;

	flags = BTRFS_BLOCK_GROUP_SYSTEM;
	ret = update_space_info(fs_info, flags, 0, 0, &space_info);
	if (ret)
		goto out;

	if (mixed) {
		flags = BTRFS_BLOCK_GROUP_METADATA | BTRFS_BLOCK_GROUP_DATA;
		ret = update_space_info(fs_info, flags, 0, 0, &space_info);
	} else {
		flags = BTRFS_BLOCK_GROUP_METADATA;
		ret = update_space_info(fs_info, flags, 0, 0, &space_info);
		if (ret)
			goto out;

		flags = BTRFS_BLOCK_GROUP_DATA;
		ret = update_space_info(fs_info, flags, 0, 0, &space_info);
	}
out:
	return ret;
}

int btrfs_error_unpin_extent_range(struct btrfs_root *root, u64 start, u64 end)
{
	return unpin_extent_range(root, start, end, false);
}

#ifdef MY_ABC_HERE
#else
 
static int btrfs_trim_free_extents(struct btrfs_device *device,
				   u64 minlen, u64 *trimmed)
{
	u64 start = 0, len = 0;
	int ret;

	*trimmed = 0;

	if (!device->writeable)
		return 0;

	if (device->total_bytes <= device->bytes_used)
		return 0;

	ret = 0;

	while (1) {
		struct btrfs_fs_info *fs_info = device->dev_root->fs_info;
		struct btrfs_transaction *trans;
		u64 bytes;

		ret = mutex_lock_interruptible(&fs_info->chunk_mutex);
		if (ret)
			return ret;

		down_read(&fs_info->commit_root_sem);

		spin_lock(&fs_info->trans_lock);
		trans = fs_info->running_transaction;
		if (trans)
			atomic_inc(&trans->use_count);
		spin_unlock(&fs_info->trans_lock);

		ret = find_free_dev_extent_start(trans, device, minlen, start,
						 &start, &len);
		if (trans)
			btrfs_put_transaction(trans);

		if (ret) {
			up_read(&fs_info->commit_root_sem);
			mutex_unlock(&fs_info->chunk_mutex);
			if (ret == -ENOSPC)
				ret = 0;
			break;
		}

		ret = btrfs_issue_discard(device->bdev, start, len, &bytes);
		up_read(&fs_info->commit_root_sem);
		mutex_unlock(&fs_info->chunk_mutex);

		if (ret)
			break;

		start += len;
		*trimmed += bytes;

		if (fatal_signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}

		cond_resched();
	}

	return ret;
}
#endif  

int btrfs_trim_fs(struct btrfs_root *root, struct fstrim_range *range)
{
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_block_group_cache *cache = NULL;
#ifdef MY_ABC_HERE
#else
	struct btrfs_device *device;
	struct list_head *devices;
#endif  
	u64 group_trimmed;
	u64 start;
	u64 end;
	u64 trimmed = 0;
	u64 total_bytes = btrfs_super_total_bytes(fs_info->super_copy);
	int ret = 0;

	if (range->len == total_bytes)
		cache = btrfs_lookup_first_block_group(fs_info, range->start);
	else
		cache = btrfs_lookup_block_group(fs_info, range->start);

	while (cache) {
		if (cache->key.objectid >= (range->start + range->len)) {
			btrfs_put_block_group(cache);
			break;
		}

		start = max(range->start, cache->key.objectid);
		end = min(range->start + range->len,
				cache->key.objectid + cache->key.offset);

#ifdef MY_ABC_HERE
		if (end - start >= range->minlen &&
				!(cache->flags & BTRFS_BLOCK_GROUP_SYSTEM)) {
#else
		if (end - start >= range->minlen) {
#endif  
			if (!block_group_cache_done(cache)) {
				ret = cache_block_group(cache, 0);
				if (ret) {
					btrfs_put_block_group(cache);
					break;
				}
				ret = wait_block_group_cache_done(cache);
				if (ret) {
					btrfs_put_block_group(cache);
					break;
				}
			}
			ret = btrfs_trim_block_group(cache,
						     &group_trimmed,
						     start,
						     end,
						     range->minlen);

			trimmed += group_trimmed;
			if (ret) {
				btrfs_put_block_group(cache);
				break;
			}
		}

		cache = next_block_group(fs_info->tree_root, cache);
	}

#ifdef MY_ABC_HERE
#else
	mutex_lock(&root->fs_info->fs_devices->device_list_mutex);
	devices = &root->fs_info->fs_devices->alloc_list;
	list_for_each_entry(device, devices, dev_alloc_list) {
		ret = btrfs_trim_free_extents(device, range->minlen,
					      &group_trimmed);
		if (ret)
			break;

		trimmed += group_trimmed;
	}
	mutex_unlock(&root->fs_info->fs_devices->device_list_mutex);
#endif  

	range->len = trimmed;
	return ret;
}

void btrfs_end_write_no_snapshoting(struct btrfs_root *root)
{
	percpu_counter_dec(&root->subv_writers->counter);
	 
	smp_mb();
	if (waitqueue_active(&root->subv_writers->wait))
		wake_up(&root->subv_writers->wait);
}

int btrfs_start_write_no_snapshoting(struct btrfs_root *root)
{
	if (atomic_read(&root->will_be_snapshoted))
		return 0;

	percpu_counter_inc(&root->subv_writers->counter);
	 
	smp_mb();
	if (atomic_read(&root->will_be_snapshoted)) {
		btrfs_end_write_no_snapshoting(root);
		return 0;
	}
	return 1;
}

static int wait_snapshoting_atomic_t(atomic_t *a)
{
	schedule();
	return 0;
}

void btrfs_wait_for_snapshot_creation(struct btrfs_root *root)
{
	while (true) {
		int ret;

		ret = btrfs_start_write_no_snapshoting(root);
		if (ret)
			break;
		wait_on_atomic_t(&root->will_be_snapshoted,
				 wait_snapshoting_atomic_t,
				 TASK_UNINTERRUPTIBLE);
	}
}
