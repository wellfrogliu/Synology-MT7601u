#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/list_sort.h>
#include "tree-log.h"
#include "disk-io.h"
#include "locking.h"
#include "print-tree.h"
#include "backref.h"
#include "hash.h"
#include "compression.h"

#define LOG_INODE_ALL 0
#define LOG_INODE_EXISTS 1

#define LOG_WALK_PIN_ONLY 0
#define LOG_WALK_REPLAY_INODES 1
#define LOG_WALK_REPLAY_DIR_INDEX 2
#define LOG_WALK_REPLAY_ALL 3

static int btrfs_log_inode(struct btrfs_trans_handle *trans,
			   struct btrfs_root *root, struct inode *inode,
			   int inode_only,
			   const loff_t start,
			   const loff_t end,
			   struct btrfs_log_ctx *ctx);
static int link_to_fixup_dir(struct btrfs_trans_handle *trans,
			     struct btrfs_root *root,
			     struct btrfs_path *path, u64 objectid);
static noinline int replay_dir_deletes(struct btrfs_trans_handle *trans,
				       struct btrfs_root *root,
				       struct btrfs_root *log,
				       struct btrfs_path *path,
				       u64 dirid, int del_all);

static int start_log_trans(struct btrfs_trans_handle *trans,
			   struct btrfs_root *root,
			   struct btrfs_log_ctx *ctx)
{
	int ret = 0;

	mutex_lock(&root->log_mutex);

	if (root->log_root) {
		if (btrfs_need_log_full_commit(root->fs_info, trans)) {
			ret = -EAGAIN;
			goto out;
		}

		if (!root->log_start_pid) {
			clear_bit(BTRFS_ROOT_MULTI_LOG_TASKS, &root->state);
			root->log_start_pid = current->pid;
		} else if (root->log_start_pid != current->pid) {
			set_bit(BTRFS_ROOT_MULTI_LOG_TASKS, &root->state);
		}
	} else {
		mutex_lock(&root->fs_info->tree_log_mutex);
		if (!root->fs_info->log_root_tree)
			ret = btrfs_init_log_root_tree(trans, root->fs_info);
		mutex_unlock(&root->fs_info->tree_log_mutex);
		if (ret)
			goto out;

		ret = btrfs_add_log_tree(trans, root);
		if (ret)
			goto out;

		clear_bit(BTRFS_ROOT_MULTI_LOG_TASKS, &root->state);
		root->log_start_pid = current->pid;
	}

	atomic_inc(&root->log_batch);
	atomic_inc(&root->log_writers);
	if (ctx) {
		int index = root->log_transid % 2;
		list_add_tail(&ctx->list, &root->log_ctxs[index]);
#ifdef MY_ABC_HERE
#else
		ctx->log_transid = root->log_transid;
#endif  
	}

out:
	mutex_unlock(&root->log_mutex);
	return ret;
}

static int join_running_log_trans(struct btrfs_root *root)
{
	int ret = -ENOENT;

	smp_mb();
	if (!root->log_root)
		return -ENOENT;

	mutex_lock(&root->log_mutex);
	if (root->log_root) {
		ret = 0;
		atomic_inc(&root->log_writers);
	}
	mutex_unlock(&root->log_mutex);
	return ret;
}

int btrfs_pin_log_trans(struct btrfs_root *root)
{
	int ret = -ENOENT;

	mutex_lock(&root->log_mutex);
	atomic_inc(&root->log_writers);
	mutex_unlock(&root->log_mutex);
	return ret;
}

void btrfs_end_log_trans(struct btrfs_root *root)
{
	if (atomic_dec_and_test(&root->log_writers)) {
		 
		if (waitqueue_active(&root->log_writer_wait))
			wake_up(&root->log_writer_wait);
	}
}

struct walk_control {
	 
	int free;

	int write;

	int wait;

	int pin;

	int stage;

	struct btrfs_root *replay_dest;

	struct btrfs_trans_handle *trans;

	int (*process_func)(struct btrfs_root *log, struct extent_buffer *eb,
			    struct walk_control *wc, u64 gen);
};

static int process_one_buffer(struct btrfs_root *log,
			      struct extent_buffer *eb,
			      struct walk_control *wc, u64 gen)
{
	int ret = 0;

	if (btrfs_fs_incompat(log->fs_info, MIXED_GROUPS)) {
		ret = btrfs_read_buffer(eb, gen);
		if (ret)
			return ret;
	}

	if (wc->pin)
		ret = btrfs_pin_extent_for_log_replay(log->fs_info->extent_root,
						      eb->start, eb->len);

	if (!ret && btrfs_buffer_uptodate(eb, gen, 0)) {
		if (wc->pin && btrfs_header_level(eb) == 0)
			ret = btrfs_exclude_logged_extents(log, eb);
		if (wc->write)
			btrfs_write_tree_block(eb);
		if (wc->wait)
			btrfs_wait_tree_block_writeback(eb);
	}
	return ret;
}

static noinline int overwrite_item(struct btrfs_trans_handle *trans,
				   struct btrfs_root *root,
				   struct btrfs_path *path,
				   struct extent_buffer *eb, int slot,
				   struct btrfs_key *key)
{
	int ret;
	u32 item_size;
	u64 saved_i_size = 0;
	int save_old_i_size = 0;
	unsigned long src_ptr;
	unsigned long dst_ptr;
	int overwrite_root = 0;
	bool inode_item = key->type == BTRFS_INODE_ITEM_KEY;

	if (root->root_key.objectid != BTRFS_TREE_LOG_OBJECTID)
		overwrite_root = 1;

	item_size = btrfs_item_size_nr(eb, slot);
	src_ptr = btrfs_item_ptr_offset(eb, slot);

	ret = btrfs_search_slot(NULL, root, key, path, 0, 0);
	if (ret < 0)
		return ret;

	if (ret == 0) {
		char *src_copy;
		char *dst_copy;
		u32 dst_size = btrfs_item_size_nr(path->nodes[0],
						  path->slots[0]);
		if (dst_size != item_size)
			goto insert;

		if (item_size == 0) {
			btrfs_release_path(path);
			return 0;
		}
		dst_copy = kmalloc(item_size, GFP_NOFS);
		src_copy = kmalloc(item_size, GFP_NOFS);
		if (!dst_copy || !src_copy) {
			btrfs_release_path(path);
			kfree(dst_copy);
			kfree(src_copy);
			return -ENOMEM;
		}

		read_extent_buffer(eb, src_copy, src_ptr, item_size);

		dst_ptr = btrfs_item_ptr_offset(path->nodes[0], path->slots[0]);
		read_extent_buffer(path->nodes[0], dst_copy, dst_ptr,
				   item_size);
		ret = memcmp(dst_copy, src_copy, item_size);

		kfree(dst_copy);
		kfree(src_copy);
		 
		if (ret == 0) {
			btrfs_release_path(path);
			return 0;
		}

		if (inode_item) {
			struct btrfs_inode_item *item;
			u64 nbytes;
			u32 mode;

			item = btrfs_item_ptr(path->nodes[0], path->slots[0],
					      struct btrfs_inode_item);
			nbytes = btrfs_inode_nbytes(path->nodes[0], item);
			item = btrfs_item_ptr(eb, slot,
					      struct btrfs_inode_item);
			btrfs_set_inode_nbytes(eb, item, nbytes);

			mode = btrfs_inode_mode(eb, item);
			if (S_ISDIR(mode))
				btrfs_set_inode_size(eb, item, 0);
		}
	} else if (inode_item) {
		struct btrfs_inode_item *item;
		u32 mode;

		item = btrfs_item_ptr(eb, slot, struct btrfs_inode_item);
		btrfs_set_inode_nbytes(eb, item, 0);

		mode = btrfs_inode_mode(eb, item);
		if (S_ISDIR(mode))
			btrfs_set_inode_size(eb, item, 0);
	}
insert:
	btrfs_release_path(path);
	 
	path->skip_release_on_error = 1;
	ret = btrfs_insert_empty_item(trans, root, path,
				      key, item_size);
	path->skip_release_on_error = 0;

	if (ret == -EEXIST || ret == -EOVERFLOW) {
		u32 found_size;
		found_size = btrfs_item_size_nr(path->nodes[0],
						path->slots[0]);
		if (found_size > item_size)
			btrfs_truncate_item(root, path, item_size, 1);
		else if (found_size < item_size)
			btrfs_extend_item(root, path,
					  item_size - found_size);
	} else if (ret) {
		return ret;
	}
	dst_ptr = btrfs_item_ptr_offset(path->nodes[0],
					path->slots[0]);

	if (key->type == BTRFS_INODE_ITEM_KEY && ret == -EEXIST) {
		struct btrfs_inode_item *src_item;
		struct btrfs_inode_item *dst_item;

		src_item = (struct btrfs_inode_item *)src_ptr;
		dst_item = (struct btrfs_inode_item *)dst_ptr;

		if (btrfs_inode_generation(eb, src_item) == 0) {
			struct extent_buffer *dst_eb = path->nodes[0];
			const u64 ino_size = btrfs_inode_size(eb, src_item);

			if (S_ISREG(btrfs_inode_mode(eb, src_item)) &&
			    S_ISREG(btrfs_inode_mode(dst_eb, dst_item)) &&
			    ino_size != 0) {
				struct btrfs_map_token token;

				btrfs_init_map_token(&token);
				btrfs_set_token_inode_size(dst_eb, dst_item,
							   ino_size, &token);
			}
			goto no_copy;
		}

		if (overwrite_root &&
		    S_ISDIR(btrfs_inode_mode(eb, src_item)) &&
		    S_ISDIR(btrfs_inode_mode(path->nodes[0], dst_item))) {
			save_old_i_size = 1;
			saved_i_size = btrfs_inode_size(path->nodes[0],
							dst_item);
		}
	}

	copy_extent_buffer(path->nodes[0], eb, dst_ptr,
			   src_ptr, item_size);

	if (save_old_i_size) {
		struct btrfs_inode_item *dst_item;
		dst_item = (struct btrfs_inode_item *)dst_ptr;
		btrfs_set_inode_size(path->nodes[0], dst_item, saved_i_size);
	}

	if (key->type == BTRFS_INODE_ITEM_KEY) {
		struct btrfs_inode_item *dst_item;
		dst_item = (struct btrfs_inode_item *)dst_ptr;
		if (btrfs_inode_generation(path->nodes[0], dst_item) == 0) {
			btrfs_set_inode_generation(path->nodes[0], dst_item,
						   trans->transid);
		}
	}
no_copy:
	btrfs_mark_buffer_dirty(path->nodes[0]);
	btrfs_release_path(path);
	return 0;
}

static noinline struct inode *read_one_inode(struct btrfs_root *root,
					     u64 objectid)
{
	struct btrfs_key key;
	struct inode *inode;

	key.objectid = objectid;
	key.type = BTRFS_INODE_ITEM_KEY;
	key.offset = 0;
	inode = btrfs_iget(root->fs_info->sb, &key, root, NULL);
	if (IS_ERR(inode)) {
		inode = NULL;
	} else if (is_bad_inode(inode)) {
		iput(inode);
		inode = NULL;
	}
	return inode;
}

static noinline int replay_one_extent(struct btrfs_trans_handle *trans,
				      struct btrfs_root *root,
				      struct btrfs_path *path,
				      struct extent_buffer *eb, int slot,
				      struct btrfs_key *key)
{
	int found_type;
	u64 extent_end;
	u64 start = key->offset;
	u64 nbytes = 0;
	struct btrfs_file_extent_item *item;
	struct inode *inode = NULL;
	unsigned long size;
	int ret = 0;

	item = btrfs_item_ptr(eb, slot, struct btrfs_file_extent_item);
	found_type = btrfs_file_extent_type(eb, item);

	if (found_type == BTRFS_FILE_EXTENT_REG ||
	    found_type == BTRFS_FILE_EXTENT_PREALLOC) {
		nbytes = btrfs_file_extent_num_bytes(eb, item);
		extent_end = start + nbytes;

		if (btrfs_file_extent_disk_bytenr(eb, item) == 0)
			nbytes = 0;
	} else if (found_type == BTRFS_FILE_EXTENT_INLINE) {
		size = btrfs_file_extent_inline_len(eb, slot, item);
		nbytes = btrfs_file_extent_ram_bytes(eb, item);
		extent_end = ALIGN(start + size, root->sectorsize);
	} else {
		ret = 0;
		goto out;
	}

	inode = read_one_inode(root, key->objectid);
	if (!inode) {
		ret = -EIO;
		goto out;
	}

	ret = btrfs_lookup_file_extent(trans, root, path, btrfs_ino(inode),
				       start, 0);

	if (ret == 0 &&
	    (found_type == BTRFS_FILE_EXTENT_REG ||
	     found_type == BTRFS_FILE_EXTENT_PREALLOC)) {
		struct btrfs_file_extent_item cmp1;
		struct btrfs_file_extent_item cmp2;
		struct btrfs_file_extent_item *existing;
		struct extent_buffer *leaf;

		leaf = path->nodes[0];
		existing = btrfs_item_ptr(leaf, path->slots[0],
					  struct btrfs_file_extent_item);

		read_extent_buffer(eb, &cmp1, (unsigned long)item,
				   sizeof(cmp1));
		read_extent_buffer(leaf, &cmp2, (unsigned long)existing,
				   sizeof(cmp2));

		if (memcmp(&cmp1, &cmp2, sizeof(cmp1)) == 0) {
			btrfs_release_path(path);
			goto out;
		}
	}
	btrfs_release_path(path);

	ret = btrfs_drop_extents(trans, root, inode, start, extent_end, 1);
	if (ret)
		goto out;

	if (found_type == BTRFS_FILE_EXTENT_REG ||
	    found_type == BTRFS_FILE_EXTENT_PREALLOC) {
		u64 offset;
		unsigned long dest_offset;
		struct btrfs_key ins;

		ret = btrfs_insert_empty_item(trans, root, path, key,
					      sizeof(*item));
		if (ret)
			goto out;
		dest_offset = btrfs_item_ptr_offset(path->nodes[0],
						    path->slots[0]);
		copy_extent_buffer(path->nodes[0], eb, dest_offset,
				(unsigned long)item,  sizeof(*item));

		ins.objectid = btrfs_file_extent_disk_bytenr(eb, item);
		ins.offset = btrfs_file_extent_disk_num_bytes(eb, item);
		ins.type = BTRFS_EXTENT_ITEM_KEY;
		offset = key->offset - btrfs_file_extent_offset(eb, item);

		if (ins.objectid > 0) {
			u64 csum_start;
			u64 csum_end;
			LIST_HEAD(ordered_sums);
			 
			ret = btrfs_lookup_data_extent(root, ins.objectid,
						ins.offset);
			if (ret == 0) {
				ret = btrfs_inc_extent_ref(trans, root,
						ins.objectid, ins.offset,
						0, root->root_key.objectid,
						key->objectid, offset);
				if (ret)
					goto out;
			} else {
				 
				ret = btrfs_alloc_logged_file_extent(trans,
						root, root->root_key.objectid,
						key->objectid, offset, &ins);
				if (ret)
					goto out;
			}
			btrfs_release_path(path);

			if (btrfs_file_extent_compression(eb, item)) {
				csum_start = ins.objectid;
				csum_end = csum_start + ins.offset;
			} else {
				csum_start = ins.objectid +
					btrfs_file_extent_offset(eb, item);
				csum_end = csum_start +
					btrfs_file_extent_num_bytes(eb, item);
			}

			ret = btrfs_lookup_csums_range(root->log_root,
						csum_start, csum_end - 1,
						&ordered_sums, 0);
			if (ret)
				goto out;
			 
			while (!list_empty(&ordered_sums)) {
				struct btrfs_ordered_sum *sums;
				sums = list_entry(ordered_sums.next,
						struct btrfs_ordered_sum,
						list);
				if (!ret)
					ret = btrfs_del_csums(trans,
						      root->fs_info->csum_root,
						      sums->bytenr,
						      sums->len);
				if (!ret)
					ret = btrfs_csum_file_blocks(trans,
						root->fs_info->csum_root,
						sums);
				list_del(&sums->list);
				kfree(sums);
			}
			if (ret)
				goto out;
		} else {
			btrfs_release_path(path);
		}
	} else if (found_type == BTRFS_FILE_EXTENT_INLINE) {
		 
		ret = overwrite_item(trans, root, path, eb, slot, key);
		if (ret)
			goto out;
	}

	inode_add_bytes(inode, nbytes);
	ret = btrfs_update_inode(trans, root, inode);
out:
	if (inode)
		iput(inode);
	return ret;
}

static noinline int drop_one_dir_item(struct btrfs_trans_handle *trans,
				      struct btrfs_root *root,
				      struct btrfs_path *path,
				      struct inode *dir,
				      struct btrfs_dir_item *di)
{
	struct inode *inode;
	char *name;
	int name_len;
	struct extent_buffer *leaf;
	struct btrfs_key location;
	int ret;

	leaf = path->nodes[0];

	btrfs_dir_item_key_to_cpu(leaf, di, &location);
	name_len = btrfs_dir_name_len(leaf, di);
	name = kmalloc(name_len, GFP_NOFS);
	if (!name)
		return -ENOMEM;

	read_extent_buffer(leaf, name, (unsigned long)(di + 1), name_len);
	btrfs_release_path(path);

	inode = read_one_inode(root, location.objectid);
	if (!inode) {
		ret = -EIO;
		goto out;
	}

	ret = link_to_fixup_dir(trans, root, path, location.objectid);
	if (ret)
		goto out;

	ret = btrfs_unlink_inode(trans, root, dir, inode, name, name_len);
	if (ret)
		goto out;
	else
		ret = btrfs_run_delayed_items(trans, root);
out:
	kfree(name);
	iput(inode);
	return ret;
}

static noinline int inode_in_dir(struct btrfs_root *root,
				 struct btrfs_path *path,
				 u64 dirid, u64 objectid, u64 index,
				 const char *name, int name_len)
{
	struct btrfs_dir_item *di;
	struct btrfs_key location;
	int match = 0;

	di = btrfs_lookup_dir_index_item(NULL, root, path, dirid,
					 index, name, name_len, 0);
	if (di && !IS_ERR(di)) {
		btrfs_dir_item_key_to_cpu(path->nodes[0], di, &location);
		if (location.objectid != objectid)
			goto out;
	} else
		goto out;
	btrfs_release_path(path);

	di = btrfs_lookup_dir_item(NULL, root, path, dirid, name, name_len, 0);
	if (di && !IS_ERR(di)) {
		btrfs_dir_item_key_to_cpu(path->nodes[0], di, &location);
		if (location.objectid != objectid)
			goto out;
	} else
		goto out;
	match = 1;
out:
	btrfs_release_path(path);
	return match;
}

static noinline int backref_in_log(struct btrfs_root *log,
				   struct btrfs_key *key,
				   u64 ref_objectid,
				   const char *name, int namelen)
{
	struct btrfs_path *path;
	struct btrfs_inode_ref *ref;
	unsigned long ptr;
	unsigned long ptr_end;
	unsigned long name_ptr;
	int found_name_len;
	int item_size;
	int ret;
	int match = 0;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	ret = btrfs_search_slot(NULL, log, key, path, 0, 0);
	if (ret != 0)
		goto out;

	ptr = btrfs_item_ptr_offset(path->nodes[0], path->slots[0]);

	if (key->type == BTRFS_INODE_EXTREF_KEY) {
		if (btrfs_find_name_in_ext_backref(path, ref_objectid,
						   name, namelen, NULL))
			match = 1;

		goto out;
	}

	item_size = btrfs_item_size_nr(path->nodes[0], path->slots[0]);
	ptr_end = ptr + item_size;
	while (ptr < ptr_end) {
		ref = (struct btrfs_inode_ref *)ptr;
		found_name_len = btrfs_inode_ref_name_len(path->nodes[0], ref);
		if (found_name_len == namelen) {
			name_ptr = (unsigned long)(ref + 1);
			ret = memcmp_extent_buffer(path->nodes[0], name,
						   name_ptr, namelen);
			if (ret == 0) {
				match = 1;
				goto out;
			}
		}
		ptr = (unsigned long)(ref + 1) + found_name_len;
	}
out:
	btrfs_free_path(path);
	return match;
}

static inline int __add_inode_ref(struct btrfs_trans_handle *trans,
				  struct btrfs_root *root,
				  struct btrfs_path *path,
				  struct btrfs_root *log_root,
				  struct inode *dir, struct inode *inode,
				  struct extent_buffer *eb,
				  u64 inode_objectid, u64 parent_objectid,
				  u64 ref_index, char *name, int namelen,
#ifdef MY_ABC_HERE
				  int *search_done, int only_search)
#else
				  int *search_done)
#endif  
{
	int ret;
	char *victim_name;
	int victim_name_len;
	struct extent_buffer *leaf;
	struct btrfs_dir_item *di;
	struct btrfs_key search_key;
	struct btrfs_inode_extref *extref;

#ifdef MY_ABC_HERE
	if (*search_done) {
		goto check_extref;
	}
#endif  

again:
	 
	search_key.objectid = inode_objectid;
	search_key.type = BTRFS_INODE_REF_KEY;
	search_key.offset = parent_objectid;
	ret = btrfs_search_slot(NULL, root, &search_key, path, 0, 0);
	if (ret == 0) {
		struct btrfs_inode_ref *victim_ref;
		unsigned long ptr;
		unsigned long ptr_end;

		leaf = path->nodes[0];

		if (search_key.objectid == search_key.offset)
			return 1;

		ptr = btrfs_item_ptr_offset(leaf, path->slots[0]);
		ptr_end = ptr + btrfs_item_size_nr(leaf, path->slots[0]);
		while (ptr < ptr_end) {
			victim_ref = (struct btrfs_inode_ref *)ptr;
			victim_name_len = btrfs_inode_ref_name_len(leaf,
								   victim_ref);
			victim_name = kmalloc(victim_name_len, GFP_NOFS);
			if (!victim_name)
				return -ENOMEM;

			read_extent_buffer(leaf, victim_name,
					   (unsigned long)(victim_ref + 1),
					   victim_name_len);

			if (!backref_in_log(log_root, &search_key,
					    parent_objectid,
					    victim_name,
					    victim_name_len)) {
				inc_nlink(inode);
				btrfs_release_path(path);

				ret = btrfs_unlink_inode(trans, root, dir,
							 inode, victim_name,
							 victim_name_len);
				kfree(victim_name);
				if (ret)
					return ret;
				ret = btrfs_run_delayed_items(trans, root);
				if (ret)
					return ret;
				*search_done = 1;
				goto again;
			}
			kfree(victim_name);

			ptr = (unsigned long)(victim_ref + 1) + victim_name_len;
		}

		*search_done = 1;
	}
	btrfs_release_path(path);

#ifdef MY_ABC_HERE
check_extref:
#endif  
	 
	extref = btrfs_lookup_inode_extref(NULL, root, path, name, namelen,
					   inode_objectid, parent_objectid, 0,
					   0);
	if (!IS_ERR_OR_NULL(extref)) {
		u32 item_size;
		u32 cur_offset = 0;
		unsigned long base;
		struct inode *victim_parent;

		leaf = path->nodes[0];

		item_size = btrfs_item_size_nr(leaf, path->slots[0]);
		base = btrfs_item_ptr_offset(leaf, path->slots[0]);

		while (cur_offset < item_size) {
			extref = (struct btrfs_inode_extref *)(base + cur_offset);

			victim_name_len = btrfs_inode_extref_name_len(leaf, extref);

			if (btrfs_inode_extref_parent(leaf, extref) != parent_objectid)
				goto next;

			victim_name = kmalloc(victim_name_len, GFP_NOFS);
			if (!victim_name)
				return -ENOMEM;
			read_extent_buffer(leaf, victim_name, (unsigned long)&extref->name,
					   victim_name_len);

			search_key.objectid = inode_objectid;
			search_key.type = BTRFS_INODE_EXTREF_KEY;
			search_key.offset = btrfs_extref_hash(parent_objectid,
							      victim_name,
							      victim_name_len);
			ret = 0;
			if (!backref_in_log(log_root, &search_key,
					    parent_objectid, victim_name,
					    victim_name_len)) {
				ret = -ENOENT;
				victim_parent = read_one_inode(root,
							       parent_objectid);
				if (victim_parent) {
					inc_nlink(inode);
					btrfs_release_path(path);

					ret = btrfs_unlink_inode(trans, root,
								 victim_parent,
								 inode,
								 victim_name,
								 victim_name_len);
					if (!ret)
						ret = btrfs_run_delayed_items(
								  trans, root);
				}
				iput(victim_parent);
				kfree(victim_name);
				if (ret)
					return ret;
				*search_done = 1;
				goto again;
			}
			kfree(victim_name);
			if (ret)
				return ret;
next:
			cur_offset += victim_name_len + sizeof(*extref);
		}
		*search_done = 1;
	}
	btrfs_release_path(path);

#ifdef MY_ABC_HERE
	if (only_search) {
		return 0;
	}
#endif  
	 
	di = btrfs_lookup_dir_index_item(trans, root, path, btrfs_ino(dir),
					 ref_index, name, namelen, 0);
	if (di && !IS_ERR(di)) {
		ret = drop_one_dir_item(trans, root, path, dir, di);
		if (ret)
			return ret;
	}
	btrfs_release_path(path);

	di = btrfs_lookup_dir_item(trans, root, path, btrfs_ino(dir),
				   name, namelen, 0);
	if (di && !IS_ERR(di)) {
		ret = drop_one_dir_item(trans, root, path, dir, di);
		if (ret)
			return ret;
	}
	btrfs_release_path(path);

	return 0;
}

static int extref_get_fields(struct extent_buffer *eb, unsigned long ref_ptr,
			     u32 *namelen, char **name, u64 *index,
			     u64 *parent_objectid)
{
	struct btrfs_inode_extref *extref;

	extref = (struct btrfs_inode_extref *)ref_ptr;

	*namelen = btrfs_inode_extref_name_len(eb, extref);
	*name = kmalloc(*namelen, GFP_NOFS);
	if (*name == NULL)
		return -ENOMEM;

	read_extent_buffer(eb, *name, (unsigned long)&extref->name,
			   *namelen);

	*index = btrfs_inode_extref_index(eb, extref);
	if (parent_objectid)
		*parent_objectid = btrfs_inode_extref_parent(eb, extref);

	return 0;
}

static int ref_get_fields(struct extent_buffer *eb, unsigned long ref_ptr,
			  u32 *namelen, char **name, u64 *index)
{
	struct btrfs_inode_ref *ref;

	ref = (struct btrfs_inode_ref *)ref_ptr;

	*namelen = btrfs_inode_ref_name_len(eb, ref);
	*name = kmalloc(*namelen, GFP_NOFS);
	if (*name == NULL)
		return -ENOMEM;

	read_extent_buffer(eb, *name, (unsigned long)(ref + 1), *namelen);

	*index = btrfs_inode_ref_index(eb, ref);

	return 0;
}

static noinline int add_inode_ref(struct btrfs_trans_handle *trans,
				  struct btrfs_root *root,
				  struct btrfs_root *log,
				  struct btrfs_path *path,
				  struct extent_buffer *eb, int slot,
				  struct btrfs_key *key)
{
	struct inode *dir = NULL;
	struct inode *inode = NULL;
	unsigned long ref_ptr;
	unsigned long ref_end;
	char *name = NULL;
	int namelen;
	int ret;
	int search_done = 0;
	int log_ref_ver = 0;
	u64 parent_objectid;
	u64 inode_objectid;
	u64 ref_index = 0;
	int ref_struct_size;

	ref_ptr = btrfs_item_ptr_offset(eb, slot);
	ref_end = ref_ptr + btrfs_item_size_nr(eb, slot);

	if (key->type == BTRFS_INODE_EXTREF_KEY) {
		struct btrfs_inode_extref *r;

		ref_struct_size = sizeof(struct btrfs_inode_extref);
		log_ref_ver = 1;
		r = (struct btrfs_inode_extref *)ref_ptr;
		parent_objectid = btrfs_inode_extref_parent(eb, r);
	} else {
		ref_struct_size = sizeof(struct btrfs_inode_ref);
		parent_objectid = key->offset;
	}
	inode_objectid = key->objectid;

	dir = read_one_inode(root, parent_objectid);
	if (!dir) {
		ret = -ENOENT;
		goto out;
	}

	inode = read_one_inode(root, inode_objectid);
	if (!inode) {
		ret = -EIO;
		goto out;
	}

	while (ref_ptr < ref_end) {
		if (log_ref_ver) {
			ret = extref_get_fields(eb, ref_ptr, &namelen, &name,
						&ref_index, &parent_objectid);
			 
			if (!dir)
				dir = read_one_inode(root, parent_objectid);
			if (!dir) {
				ret = -ENOENT;
				goto out;
			}
		} else {
			ret = ref_get_fields(eb, ref_ptr, &namelen, &name,
					     &ref_index);
		}
		if (ret)
			goto out;

#ifdef MY_ABC_HERE
		ret = __add_inode_ref(trans, root, path, log,
					  dir, inode, eb,
					  inode_objectid,
					  parent_objectid,
					  ref_index, name, namelen,
					  &search_done, 1);
		if (ret) {
			if (ret == 1)
				ret = 0;
			goto out;
		}
#endif  

		if (!inode_in_dir(root, path, btrfs_ino(dir), btrfs_ino(inode),
				  ref_index, name, namelen)) {
			 
#ifdef MY_ABC_HERE
#else
			if (!search_done) {
#endif  
				ret = __add_inode_ref(trans, root, path, log,
						      dir, inode, eb,
						      inode_objectid,
						      parent_objectid,
						      ref_index, name, namelen,
#ifdef MY_ABC_HERE
						      &search_done, 0);
#else
						      &search_done);
#endif  
				if (ret) {
					if (ret == 1)
						ret = 0;
					goto out;
				}
#ifdef MY_ABC_HERE
#else
			}
#endif  

			ret = btrfs_add_link(trans, dir, inode, name, namelen,
					     0, ref_index);
			if (ret)
				goto out;

			btrfs_update_inode(trans, root, inode);
		}

		ref_ptr = (unsigned long)(ref_ptr + ref_struct_size) + namelen;
		kfree(name);
		name = NULL;
		if (log_ref_ver) {
			iput(dir);
			dir = NULL;
		}
	}

	ret = overwrite_item(trans, root, path, eb, slot, key);
out:
	btrfs_release_path(path);
	kfree(name);
	iput(dir);
	iput(inode);
	return ret;
}

static int insert_orphan_item(struct btrfs_trans_handle *trans,
			      struct btrfs_root *root, u64 ino)
{
	int ret;

	ret = btrfs_insert_orphan_item(trans, root, ino);
	if (ret == -EEXIST)
		ret = 0;

	return ret;
}

static int count_inode_extrefs(struct btrfs_root *root,
			       struct inode *inode, struct btrfs_path *path)
{
	int ret = 0;
	int name_len;
	unsigned int nlink = 0;
	u32 item_size;
	u32 cur_offset = 0;
	u64 inode_objectid = btrfs_ino(inode);
	u64 offset = 0;
	unsigned long ptr;
	struct btrfs_inode_extref *extref;
	struct extent_buffer *leaf;

	while (1) {
		ret = btrfs_find_one_extref(root, inode_objectid, offset, path,
					    &extref, &offset);
		if (ret)
			break;

		leaf = path->nodes[0];
		item_size = btrfs_item_size_nr(leaf, path->slots[0]);
		ptr = btrfs_item_ptr_offset(leaf, path->slots[0]);
		cur_offset = 0;

		while (cur_offset < item_size) {
			extref = (struct btrfs_inode_extref *) (ptr + cur_offset);
			name_len = btrfs_inode_extref_name_len(leaf, extref);

			nlink++;

			cur_offset += name_len + sizeof(*extref);
		}

		offset++;
		btrfs_release_path(path);
	}
	btrfs_release_path(path);

	if (ret < 0 && ret != -ENOENT)
		return ret;
	return nlink;
}

static int count_inode_refs(struct btrfs_root *root,
			       struct inode *inode, struct btrfs_path *path)
{
	int ret;
	struct btrfs_key key;
	unsigned int nlink = 0;
	unsigned long ptr;
	unsigned long ptr_end;
	int name_len;
	u64 ino = btrfs_ino(inode);

	key.objectid = ino;
	key.type = BTRFS_INODE_REF_KEY;
	key.offset = (u64)-1;

	while (1) {
		ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
		if (ret < 0)
			break;
		if (ret > 0) {
			if (path->slots[0] == 0)
				break;
			path->slots[0]--;
		}
process_slot:
		btrfs_item_key_to_cpu(path->nodes[0], &key,
				      path->slots[0]);
		if (key.objectid != ino ||
		    key.type != BTRFS_INODE_REF_KEY)
			break;
		ptr = btrfs_item_ptr_offset(path->nodes[0], path->slots[0]);
		ptr_end = ptr + btrfs_item_size_nr(path->nodes[0],
						   path->slots[0]);
		while (ptr < ptr_end) {
			struct btrfs_inode_ref *ref;

			ref = (struct btrfs_inode_ref *)ptr;
			name_len = btrfs_inode_ref_name_len(path->nodes[0],
							    ref);
			ptr = (unsigned long)(ref + 1) + name_len;
			nlink++;
		}

		if (key.offset == 0)
			break;
		if (path->slots[0] > 0) {
			path->slots[0]--;
			goto process_slot;
		}
		key.offset--;
		btrfs_release_path(path);
	}
	btrfs_release_path(path);

	return nlink;
}

static noinline int fixup_inode_link_count(struct btrfs_trans_handle *trans,
					   struct btrfs_root *root,
					   struct inode *inode)
{
	struct btrfs_path *path;
	int ret;
	u64 nlink = 0;
	u64 ino = btrfs_ino(inode);

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	ret = count_inode_refs(root, inode, path);
	if (ret < 0)
		goto out;

	nlink = ret;

	ret = count_inode_extrefs(root, inode, path);
	if (ret < 0)
		goto out;

	nlink += ret;

	ret = 0;

	if (nlink != inode->i_nlink) {
		set_nlink(inode, nlink);
		btrfs_update_inode(trans, root, inode);
	}
	BTRFS_I(inode)->index_cnt = (u64)-1;

	if (inode->i_nlink == 0) {
		if (S_ISDIR(inode->i_mode)) {
			ret = replay_dir_deletes(trans, root, NULL, path,
						 ino, 1);
			if (ret)
				goto out;
		}
		ret = insert_orphan_item(trans, root, ino);
	}

out:
	btrfs_free_path(path);
	return ret;
}

static noinline int fixup_inode_link_counts(struct btrfs_trans_handle *trans,
					    struct btrfs_root *root,
					    struct btrfs_path *path)
{
	int ret;
	struct btrfs_key key;
	struct inode *inode;

	key.objectid = BTRFS_TREE_LOG_FIXUP_OBJECTID;
	key.type = BTRFS_ORPHAN_ITEM_KEY;
	key.offset = (u64)-1;
	while (1) {
		ret = btrfs_search_slot(trans, root, &key, path, -1, 1);
		if (ret < 0)
			break;

		if (ret == 1) {
			if (path->slots[0] == 0)
				break;
			path->slots[0]--;
		}

		btrfs_item_key_to_cpu(path->nodes[0], &key, path->slots[0]);
		if (key.objectid != BTRFS_TREE_LOG_FIXUP_OBJECTID ||
		    key.type != BTRFS_ORPHAN_ITEM_KEY)
			break;

		ret = btrfs_del_item(trans, root, path);
		if (ret)
			goto out;

		btrfs_release_path(path);
		inode = read_one_inode(root, key.offset);
		if (!inode)
			return -EIO;

		ret = fixup_inode_link_count(trans, root, inode);
		iput(inode);
		if (ret)
			goto out;

		key.offset = (u64)-1;
	}
	ret = 0;
out:
	btrfs_release_path(path);
	return ret;
}

static noinline int link_to_fixup_dir(struct btrfs_trans_handle *trans,
				      struct btrfs_root *root,
				      struct btrfs_path *path,
				      u64 objectid)
{
	struct btrfs_key key;
	int ret = 0;
	struct inode *inode;

	inode = read_one_inode(root, objectid);
	if (!inode)
		return -EIO;

	key.objectid = BTRFS_TREE_LOG_FIXUP_OBJECTID;
	key.type = BTRFS_ORPHAN_ITEM_KEY;
	key.offset = objectid;

	ret = btrfs_insert_empty_item(trans, root, path, &key, 0);

	btrfs_release_path(path);
	if (ret == 0) {
		if (!inode->i_nlink)
			set_nlink(inode, 1);
		else
			inc_nlink(inode);
		ret = btrfs_update_inode(trans, root, inode);
	} else if (ret == -EEXIST) {
		ret = 0;
	} else {
		BUG();  
	}
	iput(inode);

	return ret;
}

static noinline int insert_one_name(struct btrfs_trans_handle *trans,
				    struct btrfs_root *root,
				    u64 dirid, u64 index,
				    char *name, int name_len,
				    struct btrfs_key *location)
{
	struct inode *inode;
	struct inode *dir;
	int ret;

	inode = read_one_inode(root, location->objectid);
	if (!inode)
		return -ENOENT;

	dir = read_one_inode(root, dirid);
	if (!dir) {
		iput(inode);
		return -EIO;
	}

	ret = btrfs_add_link(trans, dir, inode, name, name_len, 1, index);

	iput(inode);
	iput(dir);
	return ret;
}

static bool name_in_log_ref(struct btrfs_root *log_root,
			    const char *name, const int name_len,
			    const u64 dirid, const u64 ino)
{
	struct btrfs_key search_key;

	search_key.objectid = ino;
	search_key.type = BTRFS_INODE_REF_KEY;
	search_key.offset = dirid;
	if (backref_in_log(log_root, &search_key, dirid, name, name_len))
		return true;

	search_key.type = BTRFS_INODE_EXTREF_KEY;
	search_key.offset = btrfs_extref_hash(dirid, name, name_len);
	if (backref_in_log(log_root, &search_key, dirid, name, name_len))
		return true;

	return false;
}

static noinline int replay_one_name(struct btrfs_trans_handle *trans,
				    struct btrfs_root *root,
				    struct btrfs_path *path,
				    struct extent_buffer *eb,
				    struct btrfs_dir_item *di,
				    struct btrfs_key *key)
{
	char *name;
	int name_len;
	struct btrfs_dir_item *dst_di;
	struct btrfs_key found_key;
	struct btrfs_key log_key;
	struct inode *dir;
	u8 log_type;
	int exists;
	int ret = 0;
	bool update_size = (key->type == BTRFS_DIR_INDEX_KEY);
	bool name_added = false;

	dir = read_one_inode(root, key->objectid);
	if (!dir)
		return -EIO;

	name_len = btrfs_dir_name_len(eb, di);
	name = kmalloc(name_len, GFP_NOFS);
	if (!name) {
		ret = -ENOMEM;
		goto out;
	}

	log_type = btrfs_dir_type(eb, di);
	read_extent_buffer(eb, name, (unsigned long)(di + 1),
		   name_len);

	btrfs_dir_item_key_to_cpu(eb, di, &log_key);
	exists = btrfs_lookup_inode(trans, root, path, &log_key, 0);
	if (exists == 0)
		exists = 1;
	else
		exists = 0;
	btrfs_release_path(path);

	if (key->type == BTRFS_DIR_ITEM_KEY) {
		dst_di = btrfs_lookup_dir_item(trans, root, path, key->objectid,
				       name, name_len, 1);
	} else if (key->type == BTRFS_DIR_INDEX_KEY) {
		dst_di = btrfs_lookup_dir_index_item(trans, root, path,
						     key->objectid,
						     key->offset, name,
						     name_len, 1);
	} else {
		 
		ret = -EINVAL;
		goto out;
	}
	if (IS_ERR_OR_NULL(dst_di)) {
		 
		if (key->type != BTRFS_DIR_INDEX_KEY)
			goto out;
		goto insert;
	}

	btrfs_dir_item_key_to_cpu(path->nodes[0], dst_di, &found_key);
	 
	if (found_key.objectid == log_key.objectid &&
	    found_key.type == log_key.type &&
	    found_key.offset == log_key.offset &&
	    btrfs_dir_type(path->nodes[0], dst_di) == log_type) {
		update_size = false;
		goto out;
	}

	if (!exists)
		goto out;

	ret = drop_one_dir_item(trans, root, path, dir, dst_di);
	if (ret)
		goto out;

	if (key->type == BTRFS_DIR_INDEX_KEY)
		goto insert;
out:
	btrfs_release_path(path);
	if (!ret && update_size) {
		btrfs_i_size_write(dir, dir->i_size + name_len * 2);
		ret = btrfs_update_inode(trans, root, dir);
	}
	kfree(name);
	iput(dir);
	if (!ret && name_added)
		ret = 1;
	return ret;

insert:
	if (name_in_log_ref(root->log_root, name, name_len,
			    key->objectid, log_key.objectid)) {
		 
		ret = 0;
		update_size = false;
		goto out;
	}
	btrfs_release_path(path);
	ret = insert_one_name(trans, root, key->objectid, key->offset,
			      name, name_len, &log_key);
	if (ret && ret != -ENOENT && ret != -EEXIST)
		goto out;
	if (!ret)
		name_added = true;
	update_size = false;
	ret = 0;
	goto out;
}

static noinline int replay_one_dir_item(struct btrfs_trans_handle *trans,
					struct btrfs_root *root,
					struct btrfs_path *path,
					struct extent_buffer *eb, int slot,
					struct btrfs_key *key)
{
	int ret = 0;
	u32 item_size = btrfs_item_size_nr(eb, slot);
	struct btrfs_dir_item *di;
	int name_len;
	unsigned long ptr;
	unsigned long ptr_end;
	struct btrfs_path *fixup_path = NULL;

	ptr = btrfs_item_ptr_offset(eb, slot);
	ptr_end = ptr + item_size;
	while (ptr < ptr_end) {
		di = (struct btrfs_dir_item *)ptr;
		if (verify_dir_item(root, eb, di))
			return -EIO;
		name_len = btrfs_dir_name_len(eb, di);
		ret = replay_one_name(trans, root, path, eb, di, key);
		if (ret < 0)
			break;
		ptr = (unsigned long)(di + 1);
		ptr += name_len;

		if (ret == 1 && btrfs_dir_type(eb, di) != BTRFS_FT_DIR) {
			struct btrfs_key di_key;

			if (!fixup_path) {
				fixup_path = btrfs_alloc_path();
				if (!fixup_path) {
					ret = -ENOMEM;
					break;
				}
			}

			btrfs_dir_item_key_to_cpu(eb, di, &di_key);
			ret = link_to_fixup_dir(trans, root, fixup_path,
						di_key.objectid);
			if (ret)
				break;
		}
		ret = 0;
	}
	btrfs_free_path(fixup_path);
	return ret;
}

static noinline int find_dir_range(struct btrfs_root *root,
				   struct btrfs_path *path,
				   u64 dirid, int key_type,
				   u64 *start_ret, u64 *end_ret)
{
	struct btrfs_key key;
	u64 found_end;
	struct btrfs_dir_log_item *item;
	int ret;
	int nritems;

	if (*start_ret == (u64)-1)
		return 1;

	key.objectid = dirid;
	key.type = key_type;
	key.offset = *start_ret;

	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret < 0)
		goto out;
	if (ret > 0) {
		if (path->slots[0] == 0)
			goto out;
		path->slots[0]--;
	}
	if (ret != 0)
		btrfs_item_key_to_cpu(path->nodes[0], &key, path->slots[0]);

	if (key.type != key_type || key.objectid != dirid) {
		ret = 1;
		goto next;
	}
	item = btrfs_item_ptr(path->nodes[0], path->slots[0],
			      struct btrfs_dir_log_item);
	found_end = btrfs_dir_log_end(path->nodes[0], item);

	if (*start_ret >= key.offset && *start_ret <= found_end) {
		ret = 0;
		*start_ret = key.offset;
		*end_ret = found_end;
		goto out;
	}
	ret = 1;
next:
	 
	nritems = btrfs_header_nritems(path->nodes[0]);
	path->slots[0]++;
	if (path->slots[0] >= nritems) {
		ret = btrfs_next_leaf(root, path);
		if (ret)
			goto out;
	}

	btrfs_item_key_to_cpu(path->nodes[0], &key, path->slots[0]);

	if (key.type != key_type || key.objectid != dirid) {
		ret = 1;
		goto out;
	}
	item = btrfs_item_ptr(path->nodes[0], path->slots[0],
			      struct btrfs_dir_log_item);
	found_end = btrfs_dir_log_end(path->nodes[0], item);
	*start_ret = key.offset;
	*end_ret = found_end;
	ret = 0;
out:
	btrfs_release_path(path);
	return ret;
}

static noinline int check_item_in_log(struct btrfs_trans_handle *trans,
				      struct btrfs_root *root,
				      struct btrfs_root *log,
				      struct btrfs_path *path,
				      struct btrfs_path *log_path,
				      struct inode *dir,
				      struct btrfs_key *dir_key)
{
	int ret;
	struct extent_buffer *eb;
	int slot;
	u32 item_size;
	struct btrfs_dir_item *di;
	struct btrfs_dir_item *log_di;
	int name_len;
	unsigned long ptr;
	unsigned long ptr_end;
	char *name;
	struct inode *inode;
	struct btrfs_key location;

again:
	eb = path->nodes[0];
	slot = path->slots[0];
	item_size = btrfs_item_size_nr(eb, slot);
	ptr = btrfs_item_ptr_offset(eb, slot);
	ptr_end = ptr + item_size;
	while (ptr < ptr_end) {
		di = (struct btrfs_dir_item *)ptr;
		if (verify_dir_item(root, eb, di)) {
			ret = -EIO;
			goto out;
		}

		name_len = btrfs_dir_name_len(eb, di);
		name = kmalloc(name_len, GFP_NOFS);
		if (!name) {
			ret = -ENOMEM;
			goto out;
		}
		read_extent_buffer(eb, name, (unsigned long)(di + 1),
				  name_len);
		log_di = NULL;
		if (log && dir_key->type == BTRFS_DIR_ITEM_KEY) {
			log_di = btrfs_lookup_dir_item(trans, log, log_path,
						       dir_key->objectid,
						       name, name_len, 0);
		} else if (log && dir_key->type == BTRFS_DIR_INDEX_KEY) {
			log_di = btrfs_lookup_dir_index_item(trans, log,
						     log_path,
						     dir_key->objectid,
						     dir_key->offset,
						     name, name_len, 0);
		}
		if (!log_di || (IS_ERR(log_di) && PTR_ERR(log_di) == -ENOENT)) {
			btrfs_dir_item_key_to_cpu(eb, di, &location);
			btrfs_release_path(path);
			btrfs_release_path(log_path);
			inode = read_one_inode(root, location.objectid);
			if (!inode) {
				kfree(name);
				return -EIO;
			}

			ret = link_to_fixup_dir(trans, root,
						path, location.objectid);
			if (ret) {
				kfree(name);
				iput(inode);
				goto out;
			}

			inc_nlink(inode);
			ret = btrfs_unlink_inode(trans, root, dir, inode,
						 name, name_len);
			if (!ret)
				ret = btrfs_run_delayed_items(trans, root);
			kfree(name);
			iput(inode);
			if (ret)
				goto out;

			ret = btrfs_search_slot(NULL, root, dir_key, path,
						0, 0);
			if (ret == 0)
				goto again;
			ret = 0;
			goto out;
		} else if (IS_ERR(log_di)) {
			kfree(name);
			return PTR_ERR(log_di);
		}
		btrfs_release_path(log_path);
		kfree(name);

		ptr = (unsigned long)(di + 1);
		ptr += name_len;
	}
	ret = 0;
out:
	btrfs_release_path(path);
	btrfs_release_path(log_path);
	return ret;
}

static int replay_xattr_deletes(struct btrfs_trans_handle *trans,
			      struct btrfs_root *root,
			      struct btrfs_root *log,
			      struct btrfs_path *path,
			      const u64 ino)
{
	struct btrfs_key search_key;
	struct btrfs_path *log_path;
	int i;
	int nritems;
	int ret;

	log_path = btrfs_alloc_path();
	if (!log_path)
		return -ENOMEM;

	search_key.objectid = ino;
	search_key.type = BTRFS_XATTR_ITEM_KEY;
	search_key.offset = 0;
again:
	ret = btrfs_search_slot(NULL, root, &search_key, path, 0, 0);
	if (ret < 0)
		goto out;
process_leaf:
	nritems = btrfs_header_nritems(path->nodes[0]);
	for (i = path->slots[0]; i < nritems; i++) {
		struct btrfs_key key;
		struct btrfs_dir_item *di;
		struct btrfs_dir_item *log_di;
		u32 total_size;
		u32 cur;

		btrfs_item_key_to_cpu(path->nodes[0], &key, i);
		if (key.objectid != ino || key.type != BTRFS_XATTR_ITEM_KEY) {
			ret = 0;
			goto out;
		}

		di = btrfs_item_ptr(path->nodes[0], i, struct btrfs_dir_item);
		total_size = btrfs_item_size_nr(path->nodes[0], i);
		cur = 0;
		while (cur < total_size) {
			u16 name_len = btrfs_dir_name_len(path->nodes[0], di);
			u16 data_len = btrfs_dir_data_len(path->nodes[0], di);
			u32 this_len = sizeof(*di) + name_len + data_len;
			char *name;

			name = kmalloc(name_len, GFP_NOFS);
			if (!name) {
				ret = -ENOMEM;
				goto out;
			}
			read_extent_buffer(path->nodes[0], name,
					   (unsigned long)(di + 1), name_len);

			log_di = btrfs_lookup_xattr(NULL, log, log_path, ino,
						    name, name_len, 0);
			btrfs_release_path(log_path);
			if (!log_di) {
				 
				btrfs_release_path(path);
				di = btrfs_lookup_xattr(trans, root, path, ino,
							name, name_len, -1);
				kfree(name);
				if (IS_ERR(di)) {
					ret = PTR_ERR(di);
					goto out;
				}
				ASSERT(di);
				ret = btrfs_delete_one_dir_name(trans, root,
								path, di);
				if (ret)
					goto out;
				btrfs_release_path(path);
				search_key = key;
				goto again;
			}
			kfree(name);
			if (IS_ERR(log_di)) {
				ret = PTR_ERR(log_di);
				goto out;
			}
			cur += this_len;
			di = (struct btrfs_dir_item *)((char *)di + this_len);
		}
	}
	ret = btrfs_next_leaf(root, path);
	if (ret > 0)
		ret = 0;
	else if (ret == 0)
		goto process_leaf;
out:
	btrfs_free_path(log_path);
	btrfs_release_path(path);
	return ret;
}

static noinline int replay_dir_deletes(struct btrfs_trans_handle *trans,
				       struct btrfs_root *root,
				       struct btrfs_root *log,
				       struct btrfs_path *path,
				       u64 dirid, int del_all)
{
	u64 range_start;
	u64 range_end;
	int key_type = BTRFS_DIR_LOG_ITEM_KEY;
	int ret = 0;
	struct btrfs_key dir_key;
	struct btrfs_key found_key;
	struct btrfs_path *log_path;
	struct inode *dir;

	dir_key.objectid = dirid;
	dir_key.type = BTRFS_DIR_ITEM_KEY;
	log_path = btrfs_alloc_path();
	if (!log_path)
		return -ENOMEM;

	dir = read_one_inode(root, dirid);
	 
	if (!dir) {
		btrfs_free_path(log_path);
		return 0;
	}
again:
	range_start = 0;
	range_end = 0;
	while (1) {
		if (del_all)
			range_end = (u64)-1;
		else {
			ret = find_dir_range(log, path, dirid, key_type,
					     &range_start, &range_end);
			if (ret != 0)
				break;
		}

		dir_key.offset = range_start;
		while (1) {
			int nritems;
			ret = btrfs_search_slot(NULL, root, &dir_key, path,
						0, 0);
			if (ret < 0)
				goto out;

			nritems = btrfs_header_nritems(path->nodes[0]);
			if (path->slots[0] >= nritems) {
				ret = btrfs_next_leaf(root, path);
				if (ret)
					break;
			}
			btrfs_item_key_to_cpu(path->nodes[0], &found_key,
					      path->slots[0]);
			if (found_key.objectid != dirid ||
			    found_key.type != dir_key.type)
				goto next_type;

			if (found_key.offset > range_end)
				break;

			ret = check_item_in_log(trans, root, log, path,
						log_path, dir,
						&found_key);
			if (ret)
				goto out;
			if (found_key.offset == (u64)-1)
				break;
			dir_key.offset = found_key.offset + 1;
		}
		btrfs_release_path(path);
		if (range_end == (u64)-1)
			break;
		range_start = range_end + 1;
	}

next_type:
	ret = 0;
	if (key_type == BTRFS_DIR_LOG_ITEM_KEY) {
		key_type = BTRFS_DIR_LOG_INDEX_KEY;
		dir_key.type = BTRFS_DIR_INDEX_KEY;
		btrfs_release_path(path);
		goto again;
	}
out:
	btrfs_release_path(path);
	btrfs_free_path(log_path);
	iput(dir);
	return ret;
}

static int replay_one_buffer(struct btrfs_root *log, struct extent_buffer *eb,
			     struct walk_control *wc, u64 gen)
{
	int nritems;
	struct btrfs_path *path;
	struct btrfs_root *root = wc->replay_dest;
	struct btrfs_key key;
	int level;
	int i;
	int ret;

	ret = btrfs_read_buffer(eb, gen);
	if (ret)
		return ret;

	level = btrfs_header_level(eb);

	if (level != 0)
		return 0;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	nritems = btrfs_header_nritems(eb);
	for (i = 0; i < nritems; i++) {
		btrfs_item_key_to_cpu(eb, &key, i);

		if (key.type == BTRFS_INODE_ITEM_KEY &&
		    wc->stage == LOG_WALK_REPLAY_INODES) {
			struct btrfs_inode_item *inode_item;
			u32 mode;

			inode_item = btrfs_item_ptr(eb, i,
					    struct btrfs_inode_item);
			ret = replay_xattr_deletes(wc->trans, root, log,
						   path, key.objectid);
			if (ret)
				break;
			mode = btrfs_inode_mode(eb, inode_item);
			if (S_ISDIR(mode)) {
				ret = replay_dir_deletes(wc->trans,
					 root, log, path, key.objectid, 0);
				if (ret)
					break;
			}
			ret = overwrite_item(wc->trans, root, path,
					     eb, i, &key);
			if (ret)
				break;

			if (S_ISREG(mode)) {
				ret = insert_orphan_item(wc->trans, root,
							 key.objectid);
				if (ret)
					break;
			}

			ret = link_to_fixup_dir(wc->trans, root,
						path, key.objectid);
			if (ret)
				break;
		}

		if (key.type == BTRFS_DIR_INDEX_KEY &&
		    wc->stage == LOG_WALK_REPLAY_DIR_INDEX) {
			ret = replay_one_dir_item(wc->trans, root, path,
						  eb, i, &key);
			if (ret)
				break;
		}

		if (wc->stage < LOG_WALK_REPLAY_ALL)
			continue;

		if (key.type == BTRFS_XATTR_ITEM_KEY) {
			ret = overwrite_item(wc->trans, root, path,
					     eb, i, &key);
			if (ret)
				break;
		} else if (key.type == BTRFS_INODE_REF_KEY ||
			   key.type == BTRFS_INODE_EXTREF_KEY) {
			ret = add_inode_ref(wc->trans, root, log, path,
					    eb, i, &key);
			if (ret && ret != -ENOENT)
				break;
			ret = 0;
		} else if (key.type == BTRFS_EXTENT_DATA_KEY) {
			ret = replay_one_extent(wc->trans, root, path,
						eb, i, &key);
			if (ret)
				break;
		} else if (key.type == BTRFS_DIR_ITEM_KEY) {
			ret = replay_one_dir_item(wc->trans, root, path,
						  eb, i, &key);
			if (ret)
				break;
		}
	}
	btrfs_free_path(path);
	return ret;
}

static noinline int walk_down_log_tree(struct btrfs_trans_handle *trans,
				   struct btrfs_root *root,
				   struct btrfs_path *path, int *level,
				   struct walk_control *wc)
{
	u64 root_owner;
	u64 bytenr;
	u64 ptr_gen;
	struct extent_buffer *next;
	struct extent_buffer *cur;
	struct extent_buffer *parent;
	u32 blocksize;
	int ret = 0;

	WARN_ON(*level < 0);
	WARN_ON(*level >= BTRFS_MAX_LEVEL);

	while (*level > 0) {
		WARN_ON(*level < 0);
		WARN_ON(*level >= BTRFS_MAX_LEVEL);
		cur = path->nodes[*level];

		WARN_ON(btrfs_header_level(cur) != *level);

		if (path->slots[*level] >=
		    btrfs_header_nritems(cur))
			break;

		bytenr = btrfs_node_blockptr(cur, path->slots[*level]);
		ptr_gen = btrfs_node_ptr_generation(cur, path->slots[*level]);
		blocksize = root->nodesize;

		parent = path->nodes[*level];
		root_owner = btrfs_header_owner(parent);

		next = btrfs_find_create_tree_block(root, bytenr);
		if (IS_ERR(next))
			return PTR_ERR(next);

		if (*level == 1) {
			ret = wc->process_func(root, next, wc, ptr_gen);
			if (ret) {
				free_extent_buffer(next);
				return ret;
			}

			path->slots[*level]++;
			if (wc->free) {
				ret = btrfs_read_buffer(next, ptr_gen);
				if (ret) {
					free_extent_buffer(next);
					return ret;
				}

				if (trans) {
					btrfs_tree_lock(next);
					btrfs_set_lock_blocking(next);
					clean_tree_block(trans, root->fs_info,
							next);
					btrfs_wait_tree_block_writeback(next);
					btrfs_tree_unlock(next);
				}

				WARN_ON(root_owner !=
					BTRFS_TREE_LOG_OBJECTID);
				ret = btrfs_free_and_pin_reserved_extent(root,
							 bytenr, blocksize);
				if (ret) {
					free_extent_buffer(next);
					return ret;
				}
			}
			free_extent_buffer(next);
			continue;
		}
		ret = btrfs_read_buffer(next, ptr_gen);
		if (ret) {
			free_extent_buffer(next);
			return ret;
		}

		WARN_ON(*level <= 0);
		if (path->nodes[*level-1])
			free_extent_buffer(path->nodes[*level-1]);
		path->nodes[*level-1] = next;
		*level = btrfs_header_level(next);
		path->slots[*level] = 0;
		cond_resched();
	}
	WARN_ON(*level < 0);
	WARN_ON(*level >= BTRFS_MAX_LEVEL);

	path->slots[*level] = btrfs_header_nritems(path->nodes[*level]);

	cond_resched();
	return 0;
}

static noinline int walk_up_log_tree(struct btrfs_trans_handle *trans,
				 struct btrfs_root *root,
				 struct btrfs_path *path, int *level,
				 struct walk_control *wc)
{
	u64 root_owner;
	int i;
	int slot;
	int ret;

	for (i = *level; i < BTRFS_MAX_LEVEL - 1 && path->nodes[i]; i++) {
		slot = path->slots[i];
		if (slot + 1 < btrfs_header_nritems(path->nodes[i])) {
			path->slots[i]++;
			*level = i;
			WARN_ON(*level == 0);
			return 0;
		} else {
			struct extent_buffer *parent;
			if (path->nodes[*level] == root->node)
				parent = path->nodes[*level];
			else
				parent = path->nodes[*level + 1];

			root_owner = btrfs_header_owner(parent);
			ret = wc->process_func(root, path->nodes[*level], wc,
				 btrfs_header_generation(path->nodes[*level]));
			if (ret)
				return ret;

			if (wc->free) {
				struct extent_buffer *next;

				next = path->nodes[*level];

				if (trans) {
					btrfs_tree_lock(next);
					btrfs_set_lock_blocking(next);
					clean_tree_block(trans, root->fs_info,
							next);
					btrfs_wait_tree_block_writeback(next);
					btrfs_tree_unlock(next);
				}

				WARN_ON(root_owner != BTRFS_TREE_LOG_OBJECTID);
				ret = btrfs_free_and_pin_reserved_extent(root,
						path->nodes[*level]->start,
						path->nodes[*level]->len);
				if (ret)
					return ret;
			}
			free_extent_buffer(path->nodes[*level]);
			path->nodes[*level] = NULL;
			*level = i + 1;
		}
	}
	return 1;
}

static int walk_log_tree(struct btrfs_trans_handle *trans,
			 struct btrfs_root *log, struct walk_control *wc)
{
	int ret = 0;
	int wret;
	int level;
	struct btrfs_path *path;
	int orig_level;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	level = btrfs_header_level(log->node);
	orig_level = level;
	path->nodes[level] = log->node;
	extent_buffer_get(log->node);
	path->slots[level] = 0;

	while (1) {
		wret = walk_down_log_tree(trans, log, path, &level, wc);
		if (wret > 0)
			break;
		if (wret < 0) {
			ret = wret;
			goto out;
		}

		wret = walk_up_log_tree(trans, log, path, &level, wc);
		if (wret > 0)
			break;
		if (wret < 0) {
			ret = wret;
			goto out;
		}
	}

	if (path->nodes[orig_level]) {
		ret = wc->process_func(log, path->nodes[orig_level], wc,
			 btrfs_header_generation(path->nodes[orig_level]));
		if (ret)
			goto out;
		if (wc->free) {
			struct extent_buffer *next;

			next = path->nodes[orig_level];

			if (trans) {
				btrfs_tree_lock(next);
				btrfs_set_lock_blocking(next);
				clean_tree_block(trans, log->fs_info, next);
				btrfs_wait_tree_block_writeback(next);
				btrfs_tree_unlock(next);
			}

			WARN_ON(log->root_key.objectid !=
				BTRFS_TREE_LOG_OBJECTID);
			ret = btrfs_free_and_pin_reserved_extent(log, next->start,
							 next->len);
			if (ret)
				goto out;
		}
	}

out:
	btrfs_free_path(path);
	return ret;
}

static int update_log_root(struct btrfs_trans_handle *trans,
			   struct btrfs_root *log)
{
	int ret;

	if (log->log_transid == 1) {
		 
		ret = btrfs_insert_root(trans, log->fs_info->log_root_tree,
				&log->root_key, &log->root_item);
	} else {
		ret = btrfs_update_root(trans, log->fs_info->log_root_tree,
				&log->root_key, &log->root_item);
	}
	return ret;
}

static void wait_log_commit(struct btrfs_root *root, int transid)
{
	DEFINE_WAIT(wait);
	int index = transid % 2;

	do {
		prepare_to_wait(&root->log_commit_wait[index],
				&wait, TASK_UNINTERRUPTIBLE);
		mutex_unlock(&root->log_mutex);

#ifdef MY_ABC_HERE
		if (root->log_transid < transid + 2 &&
#else
		if (root->log_transid_committed < transid &&
#endif  
		    atomic_read(&root->log_commit[index]))
			schedule();

		finish_wait(&root->log_commit_wait[index], &wait);
		mutex_lock(&root->log_mutex);
#ifdef MY_ABC_HERE
	} while (root->log_transid < transid + 2 &&
#else
	} while (root->log_transid_committed < transid &&
#endif  
		 atomic_read(&root->log_commit[index]));
}

static void wait_for_writer(struct btrfs_root *root)
{
	DEFINE_WAIT(wait);

	while (atomic_read(&root->log_writers)) {
		prepare_to_wait(&root->log_writer_wait,
				&wait, TASK_UNINTERRUPTIBLE);
		mutex_unlock(&root->log_mutex);
		if (atomic_read(&root->log_writers))
			schedule();
		finish_wait(&root->log_writer_wait, &wait);
		mutex_lock(&root->log_mutex);
	}
}

static inline void btrfs_remove_log_ctx(struct btrfs_root *root,
					struct btrfs_log_ctx *ctx)
{
	if (!ctx)
		return;

	mutex_lock(&root->log_mutex);
	list_del_init(&ctx->list);
	mutex_unlock(&root->log_mutex);
}

static inline void btrfs_remove_all_log_ctxs(struct btrfs_root *root,
					     int index, int error)
{
	struct btrfs_log_ctx *ctx;
	struct btrfs_log_ctx *safe;

	list_for_each_entry_safe(ctx, safe, &root->log_ctxs[index], list) {
		list_del_init(&ctx->list);
		ctx->log_ret = error;
	}

	INIT_LIST_HEAD(&root->log_ctxs[index]);
}

int btrfs_sync_log(struct btrfs_trans_handle *trans,
		   struct btrfs_root *root, struct btrfs_log_ctx *ctx)
{
	int index1;
	int index2;
	int mark;
	int ret;
	struct btrfs_root *log = root->log_root;
	struct btrfs_root *log_root_tree = root->fs_info->log_root_tree;
	int log_transid = 0;
	struct btrfs_log_ctx root_log_ctx;
	struct blk_plug plug;

	mutex_lock(&root->log_mutex);
#ifdef MY_ABC_HERE
	log_transid = root->log_transid;
	index1 = root->log_transid % 2;
	if (atomic_read(&root->log_commit[index1])) {
		wait_log_commit(root, root->log_transid);
		mutex_unlock(&root->log_mutex);
		return ctx->log_ret;
	}
	atomic_set(&root->log_commit[index1], 1);

	if (atomic_read(&root->log_commit[(index1 + 1) % 2]))
		wait_log_commit(root, root->log_transid - 1);
#else
	log_transid = ctx->log_transid;
	if (root->log_transid_committed >= log_transid) {
		mutex_unlock(&root->log_mutex);
		return ctx->log_ret;
	}

	index1 = log_transid % 2;
	if (atomic_read(&root->log_commit[index1])) {
		wait_log_commit(root, log_transid);
		mutex_unlock(&root->log_mutex);
		return ctx->log_ret;
	}
	ASSERT(log_transid == root->log_transid);
	atomic_set(&root->log_commit[index1], 1);

	if (atomic_read(&root->log_commit[(index1 + 1) % 2]))
		wait_log_commit(root, log_transid - 1);
#endif  

	while (1) {
		int batch = atomic_read(&root->log_batch);
		 
		if (!btrfs_test_opt(root, SSD) &&
		    test_bit(BTRFS_ROOT_MULTI_LOG_TASKS, &root->state)) {
			mutex_unlock(&root->log_mutex);
			schedule_timeout_uninterruptible(1);
			mutex_lock(&root->log_mutex);
		}
		wait_for_writer(root);
		if (batch == atomic_read(&root->log_batch))
			break;
	}

	if (btrfs_need_log_full_commit(root->fs_info, trans)) {
		ret = -EAGAIN;
		btrfs_free_logged_extents(log, log_transid);
		mutex_unlock(&root->log_mutex);
		goto out;
	}

	if (log_transid % 2 == 0)
		mark = EXTENT_DIRTY;
	else
		mark = EXTENT_NEW;

	blk_start_plug(&plug);
	ret = btrfs_write_marked_extents(log, &log->dirty_log_pages, mark);
	if (ret) {
		blk_finish_plug(&plug);
		btrfs_abort_transaction(trans, root, ret);
		btrfs_free_logged_extents(log, log_transid);
		btrfs_set_log_full_commit(root->fs_info, trans);
		mutex_unlock(&root->log_mutex);
		goto out;
	}

	btrfs_set_root_node(&log->root_item, log->node);

	root->log_transid++;
	log->log_transid = root->log_transid;
	root->log_start_pid = 0;
	 
	mutex_unlock(&root->log_mutex);

#ifdef MY_ABC_HERE
#else
	btrfs_init_log_ctx(&root_log_ctx);
#endif  

	mutex_lock(&log_root_tree->log_mutex);
	atomic_inc(&log_root_tree->log_batch);
	atomic_inc(&log_root_tree->log_writers);

#ifdef MY_ABC_HERE
#else
	index2 = log_root_tree->log_transid % 2;
	list_add_tail(&root_log_ctx.list, &log_root_tree->log_ctxs[index2]);
	root_log_ctx.log_transid = log_root_tree->log_transid;
#endif  

	mutex_unlock(&log_root_tree->log_mutex);

	ret = update_log_root(trans, log);

	mutex_lock(&log_root_tree->log_mutex);
	if (atomic_dec_and_test(&log_root_tree->log_writers)) {
		 
		if (waitqueue_active(&log_root_tree->log_writer_wait))
			wake_up(&log_root_tree->log_writer_wait);
	}

	if (ret) {
#ifdef MY_ABC_HERE
#else
		if (!list_empty(&root_log_ctx.list))
			list_del_init(&root_log_ctx.list);
#endif  

		blk_finish_plug(&plug);
		btrfs_set_log_full_commit(root->fs_info, trans);

		if (ret != -ENOSPC) {
			btrfs_abort_transaction(trans, root, ret);
			mutex_unlock(&log_root_tree->log_mutex);
			goto out;
		}
		btrfs_wait_marked_extents(log, &log->dirty_log_pages, mark);
		btrfs_free_logged_extents(log, log_transid);
		mutex_unlock(&log_root_tree->log_mutex);
		ret = -EAGAIN;
		goto out;
	}

#ifdef MY_ABC_HERE
	index2 = log_root_tree->log_transid % 2;

	btrfs_init_log_ctx(&root_log_ctx);
	list_add_tail(&root_log_ctx.list, &log_root_tree->log_ctxs[index2]);
#else
	if (log_root_tree->log_transid_committed >= root_log_ctx.log_transid) {
		blk_finish_plug(&plug);
		list_del_init(&root_log_ctx.list);
		mutex_unlock(&log_root_tree->log_mutex);
		ret = root_log_ctx.log_ret;
		goto out;
	}

	index2 = root_log_ctx.log_transid % 2;
#endif  
	if (atomic_read(&log_root_tree->log_commit[index2])) {
		blk_finish_plug(&plug);
		ret = btrfs_wait_marked_extents(log, &log->dirty_log_pages,
						mark);
		btrfs_wait_logged_extents(trans, log, log_transid);
		wait_log_commit(log_root_tree,
#ifdef MY_ABC_HERE
				log_root_tree->log_transid);
#else
				root_log_ctx.log_transid);
#endif  
		mutex_unlock(&log_root_tree->log_mutex);
		if (!ret)
			ret = root_log_ctx.log_ret;
		goto out;
	}
#ifdef MY_ABC_HERE
#else
	ASSERT(root_log_ctx.log_transid == log_root_tree->log_transid);
#endif  
	atomic_set(&log_root_tree->log_commit[index2], 1);

	if (atomic_read(&log_root_tree->log_commit[(index2 + 1) % 2])) {
		wait_log_commit(log_root_tree,
#ifdef MY_ABC_HERE
				log_root_tree->log_transid - 1);
#else
				root_log_ctx.log_transid - 1);
#endif  
	}

	wait_for_writer(log_root_tree);

	if (btrfs_need_log_full_commit(root->fs_info, trans)) {
		blk_finish_plug(&plug);
		btrfs_wait_marked_extents(log, &log->dirty_log_pages, mark);
		btrfs_free_logged_extents(log, log_transid);
		mutex_unlock(&log_root_tree->log_mutex);
		ret = -EAGAIN;
		goto out_wake_log_root;
	}

	ret = btrfs_write_marked_extents(log_root_tree,
					 &log_root_tree->dirty_log_pages,
					 EXTENT_DIRTY | EXTENT_NEW);
	blk_finish_plug(&plug);
	if (ret) {
		btrfs_set_log_full_commit(root->fs_info, trans);
		btrfs_abort_transaction(trans, root, ret);
		btrfs_free_logged_extents(log, log_transid);
		mutex_unlock(&log_root_tree->log_mutex);
		goto out_wake_log_root;
	}
	ret = btrfs_wait_marked_extents(log, &log->dirty_log_pages, mark);
	if (!ret)
		ret = btrfs_wait_marked_extents(log_root_tree,
						&log_root_tree->dirty_log_pages,
						EXTENT_NEW | EXTENT_DIRTY);
	if (ret) {
		btrfs_set_log_full_commit(root->fs_info, trans);
		btrfs_free_logged_extents(log, log_transid);
		mutex_unlock(&log_root_tree->log_mutex);
		goto out_wake_log_root;
	}
	btrfs_wait_logged_extents(trans, log, log_transid);

	btrfs_set_super_log_root(root->fs_info->super_for_commit,
				log_root_tree->node->start);
	btrfs_set_super_log_root_level(root->fs_info->super_for_commit,
				btrfs_header_level(log_root_tree->node));

	log_root_tree->log_transid++;
	mutex_unlock(&log_root_tree->log_mutex);

	ret = write_ctree_super(trans, root->fs_info->tree_root, 1);
	if (ret) {
		btrfs_set_log_full_commit(root->fs_info, trans);
		btrfs_abort_transaction(trans, root, ret);
		goto out_wake_log_root;
	}

	mutex_lock(&root->log_mutex);
	if (root->last_log_commit < log_transid)
		root->last_log_commit = log_transid;
	mutex_unlock(&root->log_mutex);

out_wake_log_root:
	mutex_lock(&log_root_tree->log_mutex);
	btrfs_remove_all_log_ctxs(log_root_tree, index2, ret);

#ifdef MY_ABC_HERE
	 
	smp_wmb();

	atomic_set(&log_root_tree->log_commit[index2], 0);
	smp_mb();
	mutex_unlock(&log_root_tree->log_mutex);
#else
	log_root_tree->log_transid_committed++;
	atomic_set(&log_root_tree->log_commit[index2], 0);
	mutex_unlock(&log_root_tree->log_mutex);
#endif  

	if (waitqueue_active(&log_root_tree->log_commit_wait[index2]))
		wake_up(&log_root_tree->log_commit_wait[index2]);
out:
#ifdef MY_ABC_HERE
	mutex_lock(&root->log_mutex);
	btrfs_remove_all_log_ctxs(root, index1, ret);
	smp_wmb();
	atomic_set(&root->log_commit[index1], 0);
	smp_mb();
	mutex_unlock(&root->log_mutex);
#else
	mutex_lock(&root->log_mutex);
	btrfs_remove_all_log_ctxs(root, index1, ret);
	root->log_transid_committed++;
	atomic_set(&root->log_commit[index1], 0);
	mutex_unlock(&root->log_mutex);
#endif  

	if (waitqueue_active(&root->log_commit_wait[index1]))
		wake_up(&root->log_commit_wait[index1]);
	return ret;
}

static void free_log_tree(struct btrfs_trans_handle *trans,
			  struct btrfs_root *log)
{
	int ret;
	u64 start;
	u64 end;
	struct walk_control wc = {
		.free = 1,
		.process_func = process_one_buffer
	};

	ret = walk_log_tree(trans, log, &wc);
	 
#ifdef MY_ABC_HERE
	if (ret && trans)
#else
	if (ret)
#endif  
		btrfs_abort_transaction(trans, log, ret);

	while (1) {
		ret = find_first_extent_bit(&log->dirty_log_pages,
				0, &start, &end, EXTENT_DIRTY | EXTENT_NEW,
				NULL);
		if (ret)
			break;

		clear_extent_bits(&log->dirty_log_pages, start, end,
				  EXTENT_DIRTY | EXTENT_NEW);
	}

	btrfs_free_logged_extents(log, 0);
	btrfs_free_logged_extents(log, 1);

	free_extent_buffer(log->node);
	kfree(log);
}

int btrfs_free_log(struct btrfs_trans_handle *trans, struct btrfs_root *root)
{
	if (root->log_root) {
		free_log_tree(trans, root->log_root);
		root->log_root = NULL;
	}
	return 0;
}

int btrfs_free_log_root_tree(struct btrfs_trans_handle *trans,
			     struct btrfs_fs_info *fs_info)
{
	if (fs_info->log_root_tree) {
		free_log_tree(trans, fs_info->log_root_tree);
		fs_info->log_root_tree = NULL;
	}
	return 0;
}

int btrfs_del_dir_entries_in_log(struct btrfs_trans_handle *trans,
				 struct btrfs_root *root,
				 const char *name, int name_len,
				 struct inode *dir, u64 index)
{
	struct btrfs_root *log;
	struct btrfs_dir_item *di;
	struct btrfs_path *path;
	int ret;
	int err = 0;
	int bytes_del = 0;
	u64 dir_ino = btrfs_ino(dir);

	if (BTRFS_I(dir)->logged_trans < trans->transid)
		return 0;

	ret = join_running_log_trans(root);
	if (ret)
		return 0;

	mutex_lock(&BTRFS_I(dir)->log_mutex);

	log = root->log_root;
	path = btrfs_alloc_path();
	if (!path) {
		err = -ENOMEM;
		goto out_unlock;
	}

	di = btrfs_lookup_dir_item(trans, log, path, dir_ino,
				   name, name_len, -1);
	if (IS_ERR(di)) {
		err = PTR_ERR(di);
		goto fail;
	}
	if (di) {
		ret = btrfs_delete_one_dir_name(trans, log, path, di);
		bytes_del += name_len;
		if (ret) {
			err = ret;
			goto fail;
		}
	}
	btrfs_release_path(path);
	di = btrfs_lookup_dir_index_item(trans, log, path, dir_ino,
					 index, name, name_len, -1);
	if (IS_ERR(di)) {
		err = PTR_ERR(di);
		goto fail;
	}
	if (di) {
		ret = btrfs_delete_one_dir_name(trans, log, path, di);
		bytes_del += name_len;
		if (ret) {
			err = ret;
			goto fail;
		}
	}

	if (bytes_del) {
		struct btrfs_key key;

		key.objectid = dir_ino;
		key.offset = 0;
		key.type = BTRFS_INODE_ITEM_KEY;
		btrfs_release_path(path);

		ret = btrfs_search_slot(trans, log, &key, path, 0, 1);
		if (ret < 0) {
			err = ret;
			goto fail;
		}
		if (ret == 0) {
			struct btrfs_inode_item *item;
			u64 i_size;

			item = btrfs_item_ptr(path->nodes[0], path->slots[0],
					      struct btrfs_inode_item);
			i_size = btrfs_inode_size(path->nodes[0], item);
			if (i_size > bytes_del)
				i_size -= bytes_del;
			else
				i_size = 0;
			btrfs_set_inode_size(path->nodes[0], item, i_size);
			btrfs_mark_buffer_dirty(path->nodes[0]);
		} else
			ret = 0;
		btrfs_release_path(path);
	}
fail:
	btrfs_free_path(path);
out_unlock:
	mutex_unlock(&BTRFS_I(dir)->log_mutex);
	if (ret == -ENOSPC) {
		btrfs_set_log_full_commit(root->fs_info, trans);
		ret = 0;
	} else if (ret < 0)
		btrfs_abort_transaction(trans, root, ret);

	btrfs_end_log_trans(root);

	return err;
}

int btrfs_del_inode_ref_in_log(struct btrfs_trans_handle *trans,
			       struct btrfs_root *root,
			       const char *name, int name_len,
			       struct inode *inode, u64 dirid)
{
	struct btrfs_root *log;
	u64 index;
	int ret;

	if (BTRFS_I(inode)->logged_trans < trans->transid)
		return 0;

	ret = join_running_log_trans(root);
	if (ret)
		return 0;
	log = root->log_root;
	mutex_lock(&BTRFS_I(inode)->log_mutex);

	ret = btrfs_del_inode_ref(trans, log, name, name_len, btrfs_ino(inode),
				  dirid, &index);
	mutex_unlock(&BTRFS_I(inode)->log_mutex);
	if (ret == -ENOSPC) {
		btrfs_set_log_full_commit(root->fs_info, trans);
		ret = 0;
	} else if (ret < 0 && ret != -ENOENT)
		btrfs_abort_transaction(trans, root, ret);
	btrfs_end_log_trans(root);

	return ret;
}

static noinline int insert_dir_log_key(struct btrfs_trans_handle *trans,
				       struct btrfs_root *log,
				       struct btrfs_path *path,
				       int key_type, u64 dirid,
				       u64 first_offset, u64 last_offset)
{
	int ret;
	struct btrfs_key key;
	struct btrfs_dir_log_item *item;

	key.objectid = dirid;
	key.offset = first_offset;
	if (key_type == BTRFS_DIR_ITEM_KEY)
		key.type = BTRFS_DIR_LOG_ITEM_KEY;
	else
		key.type = BTRFS_DIR_LOG_INDEX_KEY;
	ret = btrfs_insert_empty_item(trans, log, path, &key, sizeof(*item));
	if (ret)
		return ret;

	item = btrfs_item_ptr(path->nodes[0], path->slots[0],
			      struct btrfs_dir_log_item);
	btrfs_set_dir_log_end(path->nodes[0], item, last_offset);
	btrfs_mark_buffer_dirty(path->nodes[0]);
	btrfs_release_path(path);
	return 0;
}

static noinline int log_dir_items(struct btrfs_trans_handle *trans,
			  struct btrfs_root *root, struct inode *inode,
			  struct btrfs_path *path,
			  struct btrfs_path *dst_path, int key_type,
			  struct btrfs_log_ctx *ctx,
			  u64 min_offset, u64 *last_offset_ret)
{
	struct btrfs_key min_key;
	struct btrfs_root *log = root->log_root;
	struct extent_buffer *src;
	int err = 0;
	int ret;
	int i;
	int nritems;
	u64 first_offset = min_offset;
	u64 last_offset = (u64)-1;
	u64 ino = btrfs_ino(inode);
#ifdef MY_ABC_HERE
	int retry_count = 10;
#endif  

	log = root->log_root;

#ifdef MY_ABC_HERE
again:
#endif  
	min_key.objectid = ino;
	min_key.type = key_type;
	min_key.offset = min_offset;

	ret = btrfs_search_forward(root, &min_key, path, trans->transid);

	if (ret != 0 || min_key.objectid != ino || min_key.type != key_type) {
		min_key.objectid = ino;
		min_key.type = key_type;
		min_key.offset = (u64)-1;
		btrfs_release_path(path);
		ret = btrfs_search_slot(NULL, root, &min_key, path, 0, 0);
		if (ret < 0) {
			btrfs_release_path(path);
			return ret;
		}
		ret = btrfs_previous_item(root, path, ino, key_type);

		if (ret == 0) {
			struct btrfs_key tmp;
			btrfs_item_key_to_cpu(path->nodes[0], &tmp,
					      path->slots[0]);
			if (key_type == tmp.type)
				first_offset = max(min_offset, tmp.offset) + 1;
		}
		goto done;
	}

	ret = btrfs_previous_item(root, path, ino, key_type);
	if (ret == 0) {
		struct btrfs_key tmp;
		btrfs_item_key_to_cpu(path->nodes[0], &tmp, path->slots[0]);
		if (key_type == tmp.type) {
			first_offset = tmp.offset;
			ret = overwrite_item(trans, log, dst_path,
					     path->nodes[0], path->slots[0],
					     &tmp);
			if (ret) {
				err = ret;
				goto done;
			}
		}
	}
	btrfs_release_path(path);

	ret = btrfs_search_slot(NULL, root, &min_key, path, 0, 0);
#ifdef MY_ABC_HERE
	if (ret != 0 && retry_count-- > 0) {
		btrfs_release_path(path);
		goto again;
	}
#endif  
	if (WARN_ON(ret != 0))
		goto done;

	while (1) {
		struct btrfs_key tmp;
		src = path->nodes[0];
		nritems = btrfs_header_nritems(src);
		for (i = path->slots[0]; i < nritems; i++) {
			struct btrfs_dir_item *di;

			btrfs_item_key_to_cpu(src, &min_key, i);

			if (min_key.objectid != ino || min_key.type != key_type)
				goto done;
			ret = overwrite_item(trans, log, dst_path, src, i,
					     &min_key);
			if (ret) {
				err = ret;
				goto done;
			}

			di = btrfs_item_ptr(src, i, struct btrfs_dir_item);
			btrfs_dir_item_key_to_cpu(src, di, &tmp);
			if (ctx &&
			    (btrfs_dir_transid(src, di) == trans->transid ||
			     btrfs_dir_type(src, di) == BTRFS_FT_DIR) &&
			    tmp.type != BTRFS_ROOT_ITEM_KEY)
				ctx->log_new_dentries = true;
		}
		path->slots[0] = nritems;

		ret = btrfs_next_leaf(root, path);
		if (ret == 1) {
			last_offset = (u64)-1;
			goto done;
		}
		btrfs_item_key_to_cpu(path->nodes[0], &tmp, path->slots[0]);
		if (tmp.objectid != ino || tmp.type != key_type) {
			last_offset = (u64)-1;
			goto done;
		}
		if (btrfs_header_generation(path->nodes[0]) != trans->transid) {
			ret = overwrite_item(trans, log, dst_path,
					     path->nodes[0], path->slots[0],
					     &tmp);
			if (ret)
				err = ret;
			else
				last_offset = tmp.offset;
			goto done;
		}
	}
done:
	btrfs_release_path(path);
	btrfs_release_path(dst_path);

	if (err == 0) {
		*last_offset_ret = last_offset;
		 
		ret = insert_dir_log_key(trans, log, path, key_type,
					 ino, first_offset, last_offset);
		if (ret)
			err = ret;
	}
	return err;
}

static noinline int log_directory_changes(struct btrfs_trans_handle *trans,
			  struct btrfs_root *root, struct inode *inode,
			  struct btrfs_path *path,
			  struct btrfs_path *dst_path,
			  struct btrfs_log_ctx *ctx)
{
	u64 min_key;
	u64 max_key;
	int ret;
	int key_type = BTRFS_DIR_ITEM_KEY;

again:
	min_key = 0;
	max_key = 0;
	while (1) {
		ret = log_dir_items(trans, root, inode, path,
				    dst_path, key_type, ctx, min_key,
				    &max_key);
		if (ret)
			return ret;
		if (max_key == (u64)-1)
			break;
		min_key = max_key + 1;
	}

	if (key_type == BTRFS_DIR_ITEM_KEY) {
		key_type = BTRFS_DIR_INDEX_KEY;
		goto again;
	}
	return 0;
}

static int drop_objectid_items(struct btrfs_trans_handle *trans,
				  struct btrfs_root *log,
				  struct btrfs_path *path,
				  u64 objectid, int max_key_type)
{
	int ret;
	struct btrfs_key key;
	struct btrfs_key found_key;
	int start_slot;

	key.objectid = objectid;
	key.type = max_key_type;
	key.offset = (u64)-1;

	while (1) {
		ret = btrfs_search_slot(trans, log, &key, path, -1, 1);
		BUG_ON(ret == 0);  
		if (ret < 0)
			break;

		if (path->slots[0] == 0)
			break;

		path->slots[0]--;
		btrfs_item_key_to_cpu(path->nodes[0], &found_key,
				      path->slots[0]);

		if (found_key.objectid != objectid)
			break;

		found_key.offset = 0;
		found_key.type = 0;
		ret = btrfs_bin_search(path->nodes[0], &found_key, 0,
				       &start_slot);

		ret = btrfs_del_items(trans, log, path, start_slot,
				      path->slots[0] - start_slot + 1);
		 
		if (ret || start_slot != 0)
			break;
		btrfs_release_path(path);
	}
	btrfs_release_path(path);
	if (ret > 0)
		ret = 0;
	return ret;
}

static void fill_inode_item(struct btrfs_trans_handle *trans,
			    struct extent_buffer *leaf,
			    struct btrfs_inode_item *item,
			    struct inode *inode, int log_inode_only,
			    u64 logged_isize)
{
	struct btrfs_map_token token;

	btrfs_init_map_token(&token);

	if (log_inode_only) {
		 
		btrfs_set_token_inode_generation(leaf, item, 0, &token);
		btrfs_set_token_inode_size(leaf, item, logged_isize, &token);
	} else {
		btrfs_set_token_inode_generation(leaf, item,
						 BTRFS_I(inode)->generation,
						 &token);
		btrfs_set_token_inode_size(leaf, item, inode->i_size, &token);
	}

	btrfs_set_token_inode_uid(leaf, item, i_uid_read(inode), &token);
	btrfs_set_token_inode_gid(leaf, item, i_gid_read(inode), &token);
	btrfs_set_token_inode_mode(leaf, item, inode->i_mode, &token);
	btrfs_set_token_inode_nlink(leaf, item, inode->i_nlink, &token);

	btrfs_set_token_timespec_sec(leaf, &item->atime,
				     inode->i_atime.tv_sec, &token);
	btrfs_set_token_timespec_nsec(leaf, &item->atime,
				      inode->i_atime.tv_nsec, &token);

	btrfs_set_token_timespec_sec(leaf, &item->mtime,
				     inode->i_mtime.tv_sec, &token);
	btrfs_set_token_timespec_nsec(leaf, &item->mtime,
				      inode->i_mtime.tv_nsec, &token);

	btrfs_set_token_timespec_sec(leaf, &item->ctime,
				     inode->i_ctime.tv_sec, &token);
	btrfs_set_token_timespec_nsec(leaf, &item->ctime,
				      inode->i_ctime.tv_nsec, &token);

	btrfs_set_token_inode_nbytes(leaf, item, inode_get_bytes(inode),
				     &token);

	btrfs_set_token_inode_sequence(leaf, item, inode->i_version, &token);
	btrfs_set_token_inode_transid(leaf, item, trans->transid, &token);
	btrfs_set_token_inode_rdev(leaf, item, inode->i_rdev, &token);
	btrfs_set_token_inode_flags(leaf, item, BTRFS_I(inode)->flags, &token);
	btrfs_set_token_inode_block_group(leaf, item, 0, &token);
}

static int log_inode_item(struct btrfs_trans_handle *trans,
			  struct btrfs_root *log, struct btrfs_path *path,
			  struct inode *inode)
{
	struct btrfs_inode_item *inode_item;
	int ret;

	ret = btrfs_insert_empty_item(trans, log, path,
				      &BTRFS_I(inode)->location,
				      sizeof(*inode_item));
	if (ret && ret != -EEXIST)
		return ret;
	inode_item = btrfs_item_ptr(path->nodes[0], path->slots[0],
				    struct btrfs_inode_item);
	fill_inode_item(trans, path->nodes[0], inode_item, inode, 0, 0);
	btrfs_release_path(path);
	return 0;
}

static noinline int copy_items(struct btrfs_trans_handle *trans,
			       struct inode *inode,
			       struct btrfs_path *dst_path,
			       struct btrfs_path *src_path, u64 *last_extent,
			       int start_slot, int nr, int inode_only,
			       u64 logged_isize)
{
	unsigned long src_offset;
	unsigned long dst_offset;
	struct btrfs_root *log = BTRFS_I(inode)->root->log_root;
	struct btrfs_file_extent_item *extent;
	struct btrfs_inode_item *inode_item;
	struct extent_buffer *src = src_path->nodes[0];
	struct btrfs_key first_key, last_key, key;
	int ret;
	struct btrfs_key *ins_keys;
	u32 *ins_sizes;
	char *ins_data;
	int i;
	struct list_head ordered_sums;
	int skip_csum = BTRFS_I(inode)->flags & BTRFS_INODE_NODATASUM;
	bool has_extents = false;
	bool need_find_last_extent = true;
	bool done = false;

	INIT_LIST_HEAD(&ordered_sums);

	ins_data = kmalloc(nr * sizeof(struct btrfs_key) +
			   nr * sizeof(u32), GFP_NOFS);
	if (!ins_data)
		return -ENOMEM;

	first_key.objectid = (u64)-1;

	ins_sizes = (u32 *)ins_data;
	ins_keys = (struct btrfs_key *)(ins_data + nr * sizeof(u32));

	for (i = 0; i < nr; i++) {
		ins_sizes[i] = btrfs_item_size_nr(src, i + start_slot);
		btrfs_item_key_to_cpu(src, ins_keys + i, i + start_slot);
	}
	ret = btrfs_insert_empty_items(trans, log, dst_path,
				       ins_keys, ins_sizes, nr);
	if (ret) {
		kfree(ins_data);
		return ret;
	}

	for (i = 0; i < nr; i++, dst_path->slots[0]++) {
		dst_offset = btrfs_item_ptr_offset(dst_path->nodes[0],
						   dst_path->slots[0]);

		src_offset = btrfs_item_ptr_offset(src, start_slot + i);

		if ((i == (nr - 1)))
			last_key = ins_keys[i];

		if (ins_keys[i].type == BTRFS_INODE_ITEM_KEY) {
			inode_item = btrfs_item_ptr(dst_path->nodes[0],
						    dst_path->slots[0],
						    struct btrfs_inode_item);
			fill_inode_item(trans, dst_path->nodes[0], inode_item,
					inode, inode_only == LOG_INODE_EXISTS,
					logged_isize);
		} else {
			copy_extent_buffer(dst_path->nodes[0], src, dst_offset,
					   src_offset, ins_sizes[i]);
		}

		if (ins_keys[i].type == BTRFS_EXTENT_DATA_KEY) {
			has_extents = true;
			if (first_key.objectid == (u64)-1)
				first_key = ins_keys[i];
		} else {
			need_find_last_extent = false;
		}

		if (ins_keys[i].type == BTRFS_EXTENT_DATA_KEY &&
		    !skip_csum) {
			int found_type;
			extent = btrfs_item_ptr(src, start_slot + i,
						struct btrfs_file_extent_item);

			if (btrfs_file_extent_generation(src, extent) < trans->transid)
				continue;

			found_type = btrfs_file_extent_type(src, extent);
			if (found_type == BTRFS_FILE_EXTENT_REG) {
				u64 ds, dl, cs, cl;
				ds = btrfs_file_extent_disk_bytenr(src,
								extent);
				 
				if (ds == 0)
					continue;

				dl = btrfs_file_extent_disk_num_bytes(src,
								extent);
				cs = btrfs_file_extent_offset(src, extent);
				cl = btrfs_file_extent_num_bytes(src,
								extent);
				if (btrfs_file_extent_compression(src,
								  extent)) {
					cs = 0;
					cl = dl;
				}

				ret = btrfs_lookup_csums_range(
						log->fs_info->csum_root,
						ds + cs, ds + cs + cl - 1,
						&ordered_sums, 0);
				if (ret) {
					btrfs_release_path(dst_path);
					kfree(ins_data);
					return ret;
				}
			}
		}
	}

	btrfs_mark_buffer_dirty(dst_path->nodes[0]);
	btrfs_release_path(dst_path);
	kfree(ins_data);

	ret = 0;
	while (!list_empty(&ordered_sums)) {
		struct btrfs_ordered_sum *sums = list_entry(ordered_sums.next,
						   struct btrfs_ordered_sum,
						   list);
		if (!ret)
			ret = btrfs_csum_file_blocks(trans, log, sums);
		list_del(&sums->list);
		kfree(sums);
	}

	if (!has_extents)
		return ret;

	if (need_find_last_extent && *last_extent == first_key.offset) {
		 
		need_find_last_extent = false;
	}

	if (need_find_last_extent) {
		u64 len;

		ret = btrfs_prev_leaf(BTRFS_I(inode)->root, src_path);
		if (ret < 0)
			return ret;
		if (ret)
			goto fill_holes;
		if (src_path->slots[0])
			src_path->slots[0]--;
		src = src_path->nodes[0];
		btrfs_item_key_to_cpu(src, &key, src_path->slots[0]);
		if (key.objectid != btrfs_ino(inode) ||
		    key.type != BTRFS_EXTENT_DATA_KEY)
			goto fill_holes;
		extent = btrfs_item_ptr(src, src_path->slots[0],
					struct btrfs_file_extent_item);
		if (btrfs_file_extent_type(src, extent) ==
		    BTRFS_FILE_EXTENT_INLINE) {
			len = btrfs_file_extent_inline_len(src,
							   src_path->slots[0],
							   extent);
			*last_extent = ALIGN(key.offset + len,
					     log->sectorsize);
		} else {
			len = btrfs_file_extent_num_bytes(src, extent);
			*last_extent = key.offset + len;
		}
	}
fill_holes:
	 
	if (need_find_last_extent) {
		 
		btrfs_release_path(src_path);
		ret = btrfs_search_slot(NULL, BTRFS_I(inode)->root, &first_key,
					src_path, 0, 0);
		if (ret < 0)
			return ret;
		ASSERT(ret == 0);
		src = src_path->nodes[0];
		i = src_path->slots[0];
	} else {
		i = start_slot;
	}

	while (!done) {
		u64 offset, len;
		u64 extent_end;

		if (i >= btrfs_header_nritems(src_path->nodes[0])) {
			ret = btrfs_next_leaf(BTRFS_I(inode)->root, src_path);
			if (ret < 0)
				return ret;
			ASSERT(ret == 0);
			src = src_path->nodes[0];
			i = 0;
		}

		btrfs_item_key_to_cpu(src, &key, i);
		if (!btrfs_comp_cpu_keys(&key, &last_key))
			done = true;
		if (key.objectid != btrfs_ino(inode) ||
		    key.type != BTRFS_EXTENT_DATA_KEY) {
			i++;
			continue;
		}
		extent = btrfs_item_ptr(src, i, struct btrfs_file_extent_item);
		if (btrfs_file_extent_type(src, extent) ==
		    BTRFS_FILE_EXTENT_INLINE) {
			len = btrfs_file_extent_inline_len(src, i, extent);
			extent_end = ALIGN(key.offset + len, log->sectorsize);
		} else {
			len = btrfs_file_extent_num_bytes(src, extent);
			extent_end = key.offset + len;
		}
		i++;

		if (*last_extent == key.offset) {
			*last_extent = extent_end;
			continue;
		}
		offset = *last_extent;
		len = key.offset - *last_extent;
		ret = btrfs_insert_file_extent(trans, log, btrfs_ino(inode),
					       offset, 0, 0, len, 0, len, 0,
					       0, 0);
		if (ret)
			break;
		*last_extent = extent_end;
	}
	 
	if (!ret && need_find_last_extent)
		ret = 1;
	return ret;
}

static int extent_cmp(void *priv, struct list_head *a, struct list_head *b)
{
	struct extent_map *em1, *em2;

	em1 = list_entry(a, struct extent_map, list);
	em2 = list_entry(b, struct extent_map, list);

	if (em1->start < em2->start)
		return -1;
	else if (em1->start > em2->start)
		return 1;
	return 0;
}

static int wait_ordered_extents(struct btrfs_trans_handle *trans,
				struct inode *inode,
				struct btrfs_root *root,
				const struct extent_map *em,
				const struct list_head *logged_list,
				bool *ordered_io_error)
{
	struct btrfs_ordered_extent *ordered;
	struct btrfs_root *log = root->log_root;
	u64 mod_start = em->mod_start;
	u64 mod_len = em->mod_len;
	const bool skip_csum = BTRFS_I(inode)->flags & BTRFS_INODE_NODATASUM;
	u64 csum_offset;
	u64 csum_len;
	LIST_HEAD(ordered_sums);
	int ret = 0;

	*ordered_io_error = false;

	if (test_bit(EXTENT_FLAG_PREALLOC, &em->flags) ||
	    em->block_start == EXTENT_MAP_HOLE)
		return 0;

	list_for_each_entry(ordered, logged_list, log_list) {
		struct btrfs_ordered_sum *sum;

		if (!mod_len)
			break;

		if (ordered->file_offset + ordered->len <= mod_start ||
		    mod_start + mod_len <= ordered->file_offset)
			continue;

		if (!test_bit(BTRFS_ORDERED_IO_DONE, &ordered->flags) &&
		    !test_bit(BTRFS_ORDERED_IOERR, &ordered->flags) &&
		    !test_bit(BTRFS_ORDERED_DIRECT, &ordered->flags)) {
			const u64 start = ordered->file_offset;
			const u64 end = ordered->file_offset + ordered->len - 1;

			WARN_ON(ordered->inode != inode);
			filemap_fdatawrite_range(inode->i_mapping, start, end);
		}

		wait_event(ordered->wait,
			   (test_bit(BTRFS_ORDERED_IO_DONE, &ordered->flags) ||
			    test_bit(BTRFS_ORDERED_IOERR, &ordered->flags)));

		if (test_bit(BTRFS_ORDERED_IOERR, &ordered->flags)) {
			 
			btrfs_inode_check_errors(inode);
			*ordered_io_error = true;
			break;
		}
		 
		if (ordered->file_offset > mod_start) {
			if (ordered->file_offset + ordered->len >=
			    mod_start + mod_len)
				mod_len = ordered->file_offset - mod_start;
			 
		} else {
			if (ordered->file_offset + ordered->len <
			    mod_start + mod_len) {
				mod_len = (mod_start + mod_len) -
					(ordered->file_offset + ordered->len);
				mod_start = ordered->file_offset +
					ordered->len;
			} else {
				mod_len = 0;
			}
		}

		if (skip_csum)
			continue;

		if (test_and_set_bit(BTRFS_ORDERED_LOGGED_CSUM,
				     &ordered->flags))
			continue;

		list_for_each_entry(sum, &ordered->list, list) {
			ret = btrfs_csum_file_blocks(trans, log, sum);
			if (ret)
				break;
		}
	}

	if (*ordered_io_error || !mod_len || ret || skip_csum)
		return ret;

	if (em->compress_type) {
		csum_offset = 0;
		csum_len = max(em->block_len, em->orig_block_len);
	} else {
		csum_offset = mod_start - em->start;
		csum_len = mod_len;
	}

	ret = btrfs_lookup_csums_range(log->fs_info->csum_root,
				       em->block_start + csum_offset,
				       em->block_start + csum_offset +
				       csum_len - 1, &ordered_sums, 0);
	if (ret)
		return ret;

	while (!list_empty(&ordered_sums)) {
		struct btrfs_ordered_sum *sums = list_entry(ordered_sums.next,
						   struct btrfs_ordered_sum,
						   list);
		if (!ret)
			ret = btrfs_csum_file_blocks(trans, log, sums);
		list_del(&sums->list);
		kfree(sums);
	}

	return ret;
}

static int log_one_extent(struct btrfs_trans_handle *trans,
			  struct inode *inode, struct btrfs_root *root,
			  const struct extent_map *em,
			  struct btrfs_path *path,
			  const struct list_head *logged_list,
			  struct btrfs_log_ctx *ctx)
{
	struct btrfs_root *log = root->log_root;
	struct btrfs_file_extent_item *fi;
	struct extent_buffer *leaf;
	struct btrfs_map_token token;
	struct btrfs_key key;
	u64 extent_offset = em->start - em->orig_start;
	u64 block_len;
	int ret;
	int extent_inserted = 0;
	bool ordered_io_err = false;

	ret = wait_ordered_extents(trans, inode, root, em, logged_list,
				   &ordered_io_err);
	if (ret)
		return ret;

	if (ordered_io_err) {
		ctx->io_err = -EIO;
		return 0;
	}

	btrfs_init_map_token(&token);

	ret = __btrfs_drop_extents(trans, log, inode, path, em->start,
				   em->start + em->len, NULL, 0, 1,
				   sizeof(*fi), &extent_inserted);
	if (ret)
		return ret;

	if (!extent_inserted) {
		key.objectid = btrfs_ino(inode);
		key.type = BTRFS_EXTENT_DATA_KEY;
		key.offset = em->start;

		ret = btrfs_insert_empty_item(trans, log, path, &key,
					      sizeof(*fi));
		if (ret)
			return ret;
	}
	leaf = path->nodes[0];
	fi = btrfs_item_ptr(leaf, path->slots[0],
			    struct btrfs_file_extent_item);

	btrfs_set_token_file_extent_generation(leaf, fi, trans->transid,
					       &token);
	if (test_bit(EXTENT_FLAG_PREALLOC, &em->flags))
		btrfs_set_token_file_extent_type(leaf, fi,
						 BTRFS_FILE_EXTENT_PREALLOC,
						 &token);
	else
		btrfs_set_token_file_extent_type(leaf, fi,
						 BTRFS_FILE_EXTENT_REG,
						 &token);

	block_len = max(em->block_len, em->orig_block_len);
	if (em->compress_type != BTRFS_COMPRESS_NONE) {
		btrfs_set_token_file_extent_disk_bytenr(leaf, fi,
							em->block_start,
							&token);
		btrfs_set_token_file_extent_disk_num_bytes(leaf, fi, block_len,
							   &token);
	} else if (em->block_start < EXTENT_MAP_LAST_BYTE) {
		btrfs_set_token_file_extent_disk_bytenr(leaf, fi,
							em->block_start -
							extent_offset, &token);
		btrfs_set_token_file_extent_disk_num_bytes(leaf, fi, block_len,
							   &token);
	} else {
		btrfs_set_token_file_extent_disk_bytenr(leaf, fi, 0, &token);
		btrfs_set_token_file_extent_disk_num_bytes(leaf, fi, 0,
							   &token);
	}

	btrfs_set_token_file_extent_offset(leaf, fi, extent_offset, &token);
	btrfs_set_token_file_extent_num_bytes(leaf, fi, em->len, &token);
	btrfs_set_token_file_extent_ram_bytes(leaf, fi, em->ram_bytes, &token);
	btrfs_set_token_file_extent_compression(leaf, fi, em->compress_type,
						&token);
	btrfs_set_token_file_extent_encryption(leaf, fi, 0, &token);
	btrfs_set_token_file_extent_other_encoding(leaf, fi, 0, &token);
	btrfs_mark_buffer_dirty(leaf);

	btrfs_release_path(path);

	return ret;
}

static int btrfs_log_changed_extents(struct btrfs_trans_handle *trans,
				     struct btrfs_root *root,
				     struct inode *inode,
				     struct btrfs_path *path,
				     struct list_head *logged_list,
				     struct btrfs_log_ctx *ctx,
				     const u64 start,
				     const u64 end)
{
	struct extent_map *em, *n;
	struct list_head extents;
	struct extent_map_tree *tree = &BTRFS_I(inode)->extent_tree;
	u64 test_gen;
	int ret = 0;
	int num = 0;

	INIT_LIST_HEAD(&extents);

	down_write(&BTRFS_I(inode)->dio_sem);
	write_lock(&tree->lock);
	test_gen = root->fs_info->last_trans_committed;

	list_for_each_entry_safe(em, n, &tree->modified_extents, list) {
		list_del_init(&em->list);

		if (++num > 32768) {
			list_del_init(&tree->modified_extents);
			ret = -EFBIG;
			goto process;
		}

		if (em->generation <= test_gen)
			continue;
		 
		atomic_inc(&em->refs);
		set_bit(EXTENT_FLAG_LOGGING, &em->flags);
		list_add_tail(&em->list, &extents);
		num++;
	}

	list_sort(NULL, &extents, extent_cmp);
	btrfs_get_logged_extents(inode, logged_list, start, end);
	 
	ret = btrfs_inode_check_errors(inode);
	if (ret)
		ctx->io_err = ret;
process:
	while (!list_empty(&extents)) {
		em = list_entry(extents.next, struct extent_map, list);

		list_del_init(&em->list);

		if (ret) {
			clear_em_logging(tree, em);
			free_extent_map(em);
			continue;
		}

		write_unlock(&tree->lock);

		ret = log_one_extent(trans, inode, root, em, path, logged_list,
				     ctx);
		write_lock(&tree->lock);
		clear_em_logging(tree, em);
		free_extent_map(em);
	}
	WARN_ON(!list_empty(&extents));
	write_unlock(&tree->lock);
	up_write(&BTRFS_I(inode)->dio_sem);

	btrfs_release_path(path);
	return ret;
}

static int logged_inode_size(struct btrfs_root *log, struct inode *inode,
			     struct btrfs_path *path, u64 *size_ret)
{
	struct btrfs_key key;
	int ret;

	key.objectid = btrfs_ino(inode);
	key.type = BTRFS_INODE_ITEM_KEY;
	key.offset = 0;

	ret = btrfs_search_slot(NULL, log, &key, path, 0, 0);
	if (ret < 0) {
		return ret;
	} else if (ret > 0) {
		*size_ret = 0;
	} else {
		struct btrfs_inode_item *item;

		item = btrfs_item_ptr(path->nodes[0], path->slots[0],
				      struct btrfs_inode_item);
		*size_ret = btrfs_inode_size(path->nodes[0], item);
	}

	btrfs_release_path(path);
	return 0;
}

static int btrfs_log_all_xattrs(struct btrfs_trans_handle *trans,
				struct btrfs_root *root,
				struct inode *inode,
				struct btrfs_path *path,
				struct btrfs_path *dst_path)
{
	int ret;
	struct btrfs_key key;
	const u64 ino = btrfs_ino(inode);
	int ins_nr = 0;
	int start_slot = 0;

	key.objectid = ino;
	key.type = BTRFS_XATTR_ITEM_KEY;
	key.offset = 0;

	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret < 0)
		return ret;

	while (true) {
		int slot = path->slots[0];
		struct extent_buffer *leaf = path->nodes[0];
		int nritems = btrfs_header_nritems(leaf);

		if (slot >= nritems) {
			if (ins_nr > 0) {
				u64 last_extent = 0;

				ret = copy_items(trans, inode, dst_path, path,
						 &last_extent, start_slot,
						 ins_nr, 1, 0);
				 
				ASSERT(ret <= 0);
				if (ret < 0)
					return ret;
				ins_nr = 0;
			}
			ret = btrfs_next_leaf(root, path);
			if (ret < 0)
				return ret;
			else if (ret > 0)
				break;
			continue;
		}

		btrfs_item_key_to_cpu(leaf, &key, slot);
		if (key.objectid != ino || key.type != BTRFS_XATTR_ITEM_KEY)
			break;

		if (ins_nr == 0)
			start_slot = slot;
		ins_nr++;
		path->slots[0]++;
		cond_resched();
	}
	if (ins_nr > 0) {
		u64 last_extent = 0;

		ret = copy_items(trans, inode, dst_path, path,
				 &last_extent, start_slot,
				 ins_nr, 1, 0);
		 
		ASSERT(ret <= 0);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int btrfs_log_trailing_hole(struct btrfs_trans_handle *trans,
				   struct btrfs_root *root,
				   struct inode *inode,
				   struct btrfs_path *path)
{
	int ret;
	struct btrfs_key key;
	u64 hole_start;
	u64 hole_size;
	struct extent_buffer *leaf;
	struct btrfs_root *log = root->log_root;
	const u64 ino = btrfs_ino(inode);
	const u64 i_size = i_size_read(inode);

	if (!btrfs_fs_incompat(root->fs_info, NO_HOLES))
		return 0;

	key.objectid = ino;
	key.type = BTRFS_EXTENT_DATA_KEY;
	key.offset = (u64)-1;

	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	ASSERT(ret != 0);
	if (ret < 0)
		return ret;

	ASSERT(path->slots[0] > 0);
	path->slots[0]--;
	leaf = path->nodes[0];
	btrfs_item_key_to_cpu(leaf, &key, path->slots[0]);

	if (key.objectid != ino || key.type != BTRFS_EXTENT_DATA_KEY) {
		 
		hole_start = 0;
		hole_size = i_size;
	} else {
		struct btrfs_file_extent_item *extent;
		u64 len;

		if (key.offset >= i_size)
			return 0;

		extent = btrfs_item_ptr(leaf, path->slots[0],
					struct btrfs_file_extent_item);

		if (btrfs_file_extent_type(leaf, extent) ==
		    BTRFS_FILE_EXTENT_INLINE) {
			len = btrfs_file_extent_inline_len(leaf,
							   path->slots[0],
							   extent);
			ASSERT(len == i_size);
			return 0;
		}

		len = btrfs_file_extent_num_bytes(leaf, extent);
		 
		if (key.offset + len > i_size)
			return 0;
		hole_start = key.offset + len;
		hole_size = i_size - hole_start;
	}
	btrfs_release_path(path);

	if (hole_size == 0)
		return 0;

	hole_size = ALIGN(hole_size, root->sectorsize);
	ret = btrfs_insert_file_extent(trans, log, ino, hole_start, 0, 0,
				       hole_size, 0, hole_size, 0, 0, 0);
	return ret;
}

static int btrfs_check_ref_name_override(struct extent_buffer *eb,
					 const int slot,
					 const struct btrfs_key *key,
					 struct inode *inode)
{
	int ret;
	struct btrfs_path *search_path;
	char *name = NULL;
	u32 name_len = 0;
	u32 item_size = btrfs_item_size_nr(eb, slot);
	u32 cur_offset = 0;
	unsigned long ptr = btrfs_item_ptr_offset(eb, slot);

	search_path = btrfs_alloc_path();
	if (!search_path)
		return -ENOMEM;
	search_path->search_commit_root = 1;
	search_path->skip_locking = 1;

	while (cur_offset < item_size) {
		u64 parent;
		u32 this_name_len;
		u32 this_len;
		unsigned long name_ptr;
		struct btrfs_dir_item *di;

		if (key->type == BTRFS_INODE_REF_KEY) {
			struct btrfs_inode_ref *iref;

			iref = (struct btrfs_inode_ref *)(ptr + cur_offset);
			parent = key->offset;
			this_name_len = btrfs_inode_ref_name_len(eb, iref);
			name_ptr = (unsigned long)(iref + 1);
			this_len = sizeof(*iref) + this_name_len;
		} else {
			struct btrfs_inode_extref *extref;

			extref = (struct btrfs_inode_extref *)(ptr +
							       cur_offset);
			parent = btrfs_inode_extref_parent(eb, extref);
			this_name_len = btrfs_inode_extref_name_len(eb, extref);
			name_ptr = (unsigned long)&extref->name;
			this_len = sizeof(*extref) + this_name_len;
		}

		if (this_name_len > name_len) {
			char *new_name;

			new_name = krealloc(name, this_name_len, GFP_NOFS);
			if (!new_name) {
				ret = -ENOMEM;
				goto out;
			}
			name_len = this_name_len;
			name = new_name;
		}

		read_extent_buffer(eb, name, name_ptr, this_name_len);
		di = btrfs_lookup_dir_item(NULL, BTRFS_I(inode)->root,
					   search_path, parent,
					   name, this_name_len, 0);
		if (di && !IS_ERR(di)) {
			ret = 1;
			goto out;
		} else if (IS_ERR(di)) {
			ret = PTR_ERR(di);
			goto out;
		}
		btrfs_release_path(search_path);

		cur_offset += this_len;
	}
	ret = 0;
out:
	btrfs_free_path(search_path);
	kfree(name);
	return ret;
}

static int btrfs_log_inode(struct btrfs_trans_handle *trans,
			   struct btrfs_root *root, struct inode *inode,
			   int inode_only,
			   const loff_t start,
			   const loff_t end,
			   struct btrfs_log_ctx *ctx)
{
	struct btrfs_path *path;
	struct btrfs_path *dst_path;
	struct btrfs_key min_key;
	struct btrfs_key max_key;
	struct btrfs_root *log = root->log_root;
	struct extent_buffer *src = NULL;
	LIST_HEAD(logged_list);
	u64 last_extent = 0;
	int err = 0;
	int ret;
	int nritems;
	int ins_start_slot = 0;
	int ins_nr;
	bool fast_search = false;
	u64 ino = btrfs_ino(inode);
	struct extent_map_tree *em_tree = &BTRFS_I(inode)->extent_tree;
	u64 logged_isize = 0;
	bool need_log_inode_item = true;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;
	dst_path = btrfs_alloc_path();
	if (!dst_path) {
		btrfs_free_path(path);
		return -ENOMEM;
	}

	min_key.objectid = ino;
	min_key.type = BTRFS_INODE_ITEM_KEY;
	min_key.offset = 0;

	max_key.objectid = ino;

	if (S_ISDIR(inode->i_mode) ||
	    (!test_bit(BTRFS_INODE_NEEDS_FULL_SYNC,
		       &BTRFS_I(inode)->runtime_flags) &&
	     inode_only == LOG_INODE_EXISTS))
		max_key.type = BTRFS_XATTR_ITEM_KEY;
	else
		max_key.type = (u8)-1;
	max_key.offset = (u64)-1;

	if (S_ISDIR(inode->i_mode) ||
	    BTRFS_I(inode)->generation > root->fs_info->last_trans_committed)
		ret = btrfs_commit_inode_delayed_items(trans, inode);
	else
		ret = btrfs_commit_inode_delayed_inode(inode);

	if (ret) {
		btrfs_free_path(path);
		btrfs_free_path(dst_path);
		return ret;
	}

	mutex_lock(&BTRFS_I(inode)->log_mutex);

	if (S_ISDIR(inode->i_mode)) {
		int max_key_type = BTRFS_DIR_LOG_INDEX_KEY;

		if (inode_only == LOG_INODE_EXISTS)
			max_key_type = BTRFS_XATTR_ITEM_KEY;
		ret = drop_objectid_items(trans, log, path, ino, max_key_type);
	} else {
		if (inode_only == LOG_INODE_EXISTS) {
			 
			err = logged_inode_size(log, inode, path,
						&logged_isize);
			if (err)
				goto out_unlock;
		}
		if (test_bit(BTRFS_INODE_NEEDS_FULL_SYNC,
			     &BTRFS_I(inode)->runtime_flags)) {
			if (inode_only == LOG_INODE_EXISTS) {
				max_key.type = BTRFS_XATTR_ITEM_KEY;
				ret = drop_objectid_items(trans, log, path, ino,
							  max_key.type);
			} else {
				clear_bit(BTRFS_INODE_NEEDS_FULL_SYNC,
					  &BTRFS_I(inode)->runtime_flags);
				clear_bit(BTRFS_INODE_COPY_EVERYTHING,
					  &BTRFS_I(inode)->runtime_flags);
				while(1) {
					ret = btrfs_truncate_inode_items(trans,
							 log, inode, 0, 0);
					if (ret != -EAGAIN)
						break;
				}
			}
		} else if (test_and_clear_bit(BTRFS_INODE_COPY_EVERYTHING,
					      &BTRFS_I(inode)->runtime_flags) ||
			   inode_only == LOG_INODE_EXISTS) {
			if (inode_only == LOG_INODE_ALL)
				fast_search = true;
			max_key.type = BTRFS_XATTR_ITEM_KEY;
			ret = drop_objectid_items(trans, log, path, ino,
						  max_key.type);
		} else {
			if (inode_only == LOG_INODE_ALL)
				fast_search = true;
			goto log_extents;
		}

	}
	if (ret) {
		err = ret;
		goto out_unlock;
	}

	while (1) {
		ins_nr = 0;
		ret = btrfs_search_forward(root, &min_key,
					   path, trans->transid);
		if (ret != 0)
			break;
again:
		 
		if (min_key.objectid != ino)
			break;
		if (min_key.type > max_key.type)
			break;

		if (min_key.type == BTRFS_INODE_ITEM_KEY)
			need_log_inode_item = false;

		if ((min_key.type == BTRFS_INODE_REF_KEY ||
		     min_key.type == BTRFS_INODE_EXTREF_KEY) &&
		    BTRFS_I(inode)->generation == trans->transid) {
			ret = btrfs_check_ref_name_override(path->nodes[0],
							    path->slots[0],
							    &min_key, inode);
			if (ret < 0) {
				err = ret;
				goto out_unlock;
			} else if (ret > 0) {
				err = 1;
				btrfs_set_log_full_commit(root->fs_info, trans);
				goto out_unlock;
			}
		}

		if (min_key.type == BTRFS_XATTR_ITEM_KEY) {
			if (ins_nr == 0)
				goto next_slot;
			ret = copy_items(trans, inode, dst_path, path,
					 &last_extent, ins_start_slot,
					 ins_nr, inode_only, logged_isize);
			if (ret < 0) {
				err = ret;
				goto out_unlock;
			}
			ins_nr = 0;
			if (ret) {
				btrfs_release_path(path);
				continue;
			}
			goto next_slot;
		}

		src = path->nodes[0];
		if (ins_nr && ins_start_slot + ins_nr == path->slots[0]) {
			ins_nr++;
			goto next_slot;
		} else if (!ins_nr) {
			ins_start_slot = path->slots[0];
			ins_nr = 1;
			goto next_slot;
		}

		ret = copy_items(trans, inode, dst_path, path, &last_extent,
				 ins_start_slot, ins_nr, inode_only,
				 logged_isize);
		if (ret < 0) {
			err = ret;
			goto out_unlock;
		}
		if (ret) {
			ins_nr = 0;
			btrfs_release_path(path);
			continue;
		}
		ins_nr = 1;
		ins_start_slot = path->slots[0];
next_slot:

		nritems = btrfs_header_nritems(path->nodes[0]);
		path->slots[0]++;
		if (path->slots[0] < nritems) {
			btrfs_item_key_to_cpu(path->nodes[0], &min_key,
					      path->slots[0]);
			goto again;
		}
		if (ins_nr) {
			ret = copy_items(trans, inode, dst_path, path,
					 &last_extent, ins_start_slot,
					 ins_nr, inode_only, logged_isize);
			if (ret < 0) {
				err = ret;
				goto out_unlock;
			}
			ret = 0;
			ins_nr = 0;
		}
		btrfs_release_path(path);

		if (min_key.offset < (u64)-1) {
			min_key.offset++;
		} else if (min_key.type < max_key.type) {
			min_key.type++;
			min_key.offset = 0;
		} else {
			break;
		}
	}
	if (ins_nr) {
		ret = copy_items(trans, inode, dst_path, path, &last_extent,
				 ins_start_slot, ins_nr, inode_only,
				 logged_isize);
		if (ret < 0) {
			err = ret;
			goto out_unlock;
		}
		ret = 0;
		ins_nr = 0;
	}

	btrfs_release_path(path);
	btrfs_release_path(dst_path);
	err = btrfs_log_all_xattrs(trans, root, inode, path, dst_path);
	if (err)
		goto out_unlock;
	if (max_key.type >= BTRFS_EXTENT_DATA_KEY && !fast_search) {
		btrfs_release_path(path);
		btrfs_release_path(dst_path);
		err = btrfs_log_trailing_hole(trans, root, inode, path);
		if (err)
			goto out_unlock;
	}
log_extents:
	btrfs_release_path(path);
	btrfs_release_path(dst_path);
	if (need_log_inode_item) {
		err = log_inode_item(trans, log, dst_path, inode);
		if (err)
			goto out_unlock;
	}
	if (fast_search) {
		ret = btrfs_log_changed_extents(trans, root, inode, dst_path,
						&logged_list, ctx, start, end);
		if (ret) {
			err = ret;
			goto out_unlock;
		}
	} else if (inode_only == LOG_INODE_ALL) {
		struct extent_map *em, *n;

		write_lock(&em_tree->lock);
		 
		list_for_each_entry_safe(em, n, &em_tree->modified_extents,
					 list) {
			const u64 mod_end = em->mod_start + em->mod_len - 1;

			if (em->mod_start >= start && mod_end <= end)
				list_del_init(&em->list);
		}
		write_unlock(&em_tree->lock);
	}

	if (inode_only == LOG_INODE_ALL && S_ISDIR(inode->i_mode)) {
		ret = log_directory_changes(trans, root, inode, path, dst_path,
					    ctx);
		if (ret) {
			err = ret;
			goto out_unlock;
		}
	}

	spin_lock(&BTRFS_I(inode)->lock);
	BTRFS_I(inode)->logged_trans = trans->transid;
	BTRFS_I(inode)->last_log_commit = BTRFS_I(inode)->last_sub_trans;
	spin_unlock(&BTRFS_I(inode)->lock);
out_unlock:
	if (unlikely(err))
		btrfs_put_logged_extents(&logged_list);
	else
		btrfs_submit_logged_extents(&logged_list, log);
	mutex_unlock(&BTRFS_I(inode)->log_mutex);

	btrfs_free_path(path);
	btrfs_free_path(dst_path);
	return err;
}

static bool btrfs_must_commit_transaction(struct btrfs_trans_handle *trans,
					  struct inode *inode)
{
	struct btrfs_fs_info *fs_info = BTRFS_I(inode)->root->fs_info;
	bool ret = false;

	mutex_lock(&BTRFS_I(inode)->log_mutex);
	if (BTRFS_I(inode)->last_unlink_trans > fs_info->last_trans_committed) {
		 
		btrfs_set_log_full_commit(fs_info, trans);
		ret = true;
	}
	mutex_unlock(&BTRFS_I(inode)->log_mutex);

	return ret;
}

static noinline int check_parent_dirs_for_sync(struct btrfs_trans_handle *trans,
					       struct inode *inode,
					       struct dentry *parent,
					       struct super_block *sb,
					       u64 last_committed)
{
	int ret = 0;
	struct dentry *old_parent = NULL;
	struct inode *orig_inode = inode;

	if (S_ISREG(inode->i_mode) &&
	    BTRFS_I(inode)->generation <= last_committed &&
	    BTRFS_I(inode)->last_unlink_trans <= last_committed)
			goto out;

	if (!S_ISDIR(inode->i_mode)) {
		if (!parent || d_really_is_negative(parent) || sb != d_inode(parent)->i_sb)
			goto out;
		inode = d_inode(parent);
	}

	while (1) {
		 
		if (inode != orig_inode)
			BTRFS_I(inode)->logged_trans = trans->transid;
		smp_mb();

		if (btrfs_must_commit_transaction(trans, inode)) {
			ret = 1;
			break;
		}

		if (!parent || d_really_is_negative(parent) || sb != d_inode(parent)->i_sb)
			break;

		if (IS_ROOT(parent))
			break;

		parent = dget_parent(parent);
		dput(old_parent);
		old_parent = parent;
		inode = d_inode(parent);

	}
	dput(old_parent);
out:
	return ret;
}

struct btrfs_dir_list {
	u64 ino;
	struct list_head list;
};

static int log_new_dir_dentries(struct btrfs_trans_handle *trans,
				struct btrfs_root *root,
				struct inode *start_inode,
				struct btrfs_log_ctx *ctx)
{
	struct btrfs_root *log = root->log_root;
	struct btrfs_path *path;
	LIST_HEAD(dir_list);
	struct btrfs_dir_list *dir_elem;
	int ret = 0;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	dir_elem = kmalloc(sizeof(*dir_elem), GFP_NOFS);
	if (!dir_elem) {
		btrfs_free_path(path);
		return -ENOMEM;
	}
	dir_elem->ino = btrfs_ino(start_inode);
	list_add_tail(&dir_elem->list, &dir_list);

	while (!list_empty(&dir_list)) {
		struct extent_buffer *leaf;
		struct btrfs_key min_key;
		int nritems;
		int i;

		dir_elem = list_first_entry(&dir_list, struct btrfs_dir_list,
					    list);
		if (ret)
			goto next_dir_inode;

		min_key.objectid = dir_elem->ino;
		min_key.type = BTRFS_DIR_ITEM_KEY;
		min_key.offset = 0;
again:
		btrfs_release_path(path);
		ret = btrfs_search_forward(log, &min_key, path, trans->transid);
		if (ret < 0) {
			goto next_dir_inode;
		} else if (ret > 0) {
			ret = 0;
			goto next_dir_inode;
		}

process_leaf:
		leaf = path->nodes[0];
		nritems = btrfs_header_nritems(leaf);
		for (i = path->slots[0]; i < nritems; i++) {
			struct btrfs_dir_item *di;
			struct btrfs_key di_key;
			struct inode *di_inode;
			struct btrfs_dir_list *new_dir_elem;
			int log_mode = LOG_INODE_EXISTS;
			int type;

			btrfs_item_key_to_cpu(leaf, &min_key, i);
			if (min_key.objectid != dir_elem->ino ||
			    min_key.type != BTRFS_DIR_ITEM_KEY)
				goto next_dir_inode;

			di = btrfs_item_ptr(leaf, i, struct btrfs_dir_item);
			type = btrfs_dir_type(leaf, di);
			if (btrfs_dir_transid(leaf, di) < trans->transid &&
			    type != BTRFS_FT_DIR)
				continue;
			btrfs_dir_item_key_to_cpu(leaf, di, &di_key);
			if (di_key.type == BTRFS_ROOT_ITEM_KEY)
				continue;

#ifdef MY_ABC_HERE
			btrfs_release_path(path);
#endif  
			di_inode = btrfs_iget(root->fs_info->sb, &di_key,
					      root, NULL);
			if (IS_ERR(di_inode)) {
				ret = PTR_ERR(di_inode);
				goto next_dir_inode;
			}

			if (btrfs_inode_in_log(di_inode, trans->transid)) {
				iput(di_inode);
#ifdef MY_ABC_HERE
				break;
#else
				continue;
#endif  
			}

			ctx->log_new_dentries = false;
			if (type == BTRFS_FT_DIR || type == BTRFS_FT_SYMLINK)
				log_mode = LOG_INODE_ALL;
#ifdef MY_ABC_HERE
#else
			btrfs_release_path(path);
#endif  
			ret = btrfs_log_inode(trans, root, di_inode,
					      log_mode, 0, LLONG_MAX, ctx);
			if (!ret &&
			    btrfs_must_commit_transaction(trans, di_inode))
				ret = 1;
			iput(di_inode);
			if (ret)
				goto next_dir_inode;
			if (ctx->log_new_dentries) {
				new_dir_elem = kmalloc(sizeof(*new_dir_elem),
						       GFP_NOFS);
				if (!new_dir_elem) {
					ret = -ENOMEM;
					goto next_dir_inode;
				}
				new_dir_elem->ino = di_key.objectid;
				list_add_tail(&new_dir_elem->list, &dir_list);
			}
			break;
		}
		if (i == nritems) {
			ret = btrfs_next_leaf(log, path);
			if (ret < 0) {
				goto next_dir_inode;
			} else if (ret > 0) {
				ret = 0;
				goto next_dir_inode;
			}
			goto process_leaf;
		}
		if (min_key.offset < (u64)-1) {
			min_key.offset++;
			goto again;
		}
next_dir_inode:
		list_del(&dir_elem->list);
		kfree(dir_elem);
	}

	btrfs_free_path(path);
	return ret;
}

static int btrfs_log_all_parents(struct btrfs_trans_handle *trans,
				 struct inode *inode,
				 struct btrfs_log_ctx *ctx)
{
	int ret;
	struct btrfs_path *path;
	struct btrfs_key key;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	const u64 ino = btrfs_ino(inode);

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;
	path->skip_locking = 1;
	path->search_commit_root = 1;

	key.objectid = ino;
	key.type = BTRFS_INODE_REF_KEY;
	key.offset = 0;
	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret < 0)
		goto out;

	while (true) {
		struct extent_buffer *leaf = path->nodes[0];
		int slot = path->slots[0];
		u32 cur_offset = 0;
		u32 item_size;
		unsigned long ptr;

		if (slot >= btrfs_header_nritems(leaf)) {
			ret = btrfs_next_leaf(root, path);
			if (ret < 0)
				goto out;
			else if (ret > 0)
				break;
			continue;
		}

		btrfs_item_key_to_cpu(leaf, &key, slot);
		 
		if (key.objectid != ino || key.type > BTRFS_INODE_EXTREF_KEY)
			break;

		item_size = btrfs_item_size_nr(leaf, slot);
		ptr = btrfs_item_ptr_offset(leaf, slot);
		while (cur_offset < item_size) {
			struct btrfs_key inode_key;
			struct inode *dir_inode;

			inode_key.type = BTRFS_INODE_ITEM_KEY;
			inode_key.offset = 0;

			if (key.type == BTRFS_INODE_EXTREF_KEY) {
				struct btrfs_inode_extref *extref;

				extref = (struct btrfs_inode_extref *)
					(ptr + cur_offset);
				inode_key.objectid = btrfs_inode_extref_parent(
					leaf, extref);
				cur_offset += sizeof(*extref);
				cur_offset += btrfs_inode_extref_name_len(leaf,
					extref);
			} else {
				inode_key.objectid = key.offset;
				cur_offset = item_size;
			}

			dir_inode = btrfs_iget(root->fs_info->sb, &inode_key,
					       root, NULL);
			 
			if (IS_ERR(dir_inode))
				continue;

			if (ctx)
				ctx->log_new_dentries = false;
			ret = btrfs_log_inode(trans, root, dir_inode,
					      LOG_INODE_ALL, 0, LLONG_MAX, ctx);
			if (!ret &&
			    btrfs_must_commit_transaction(trans, dir_inode))
				ret = 1;
			if (!ret && ctx && ctx->log_new_dentries)
				ret = log_new_dir_dentries(trans, root,
							   dir_inode, ctx);
			iput(dir_inode);
			if (ret)
				goto out;
		}
		path->slots[0]++;
	}
	ret = 0;
out:
	btrfs_free_path(path);
	return ret;
}

static int btrfs_log_inode_parent(struct btrfs_trans_handle *trans,
			    	  struct btrfs_root *root, struct inode *inode,
				  struct dentry *parent,
				  const loff_t start,
				  const loff_t end,
				  int exists_only,
				  struct btrfs_log_ctx *ctx)
{
	int inode_only = exists_only ? LOG_INODE_EXISTS : LOG_INODE_ALL;
	struct super_block *sb;
	struct dentry *old_parent = NULL;
	int ret = 0;
	u64 last_committed = root->fs_info->last_trans_committed;
	bool log_dentries = false;
	struct inode *orig_inode = inode;

	sb = inode->i_sb;

	if (btrfs_test_opt(root, NOTREELOG)) {
		ret = 1;
		goto end_no_trans;
	}

	if (root->fs_info->last_trans_log_full_commit >
	    root->fs_info->last_trans_committed) {
		ret = 1;
		goto end_no_trans;
	}

	if (root != BTRFS_I(inode)->root ||
	    btrfs_root_refs(&root->root_item) == 0) {
		ret = 1;
		goto end_no_trans;
	}

	ret = check_parent_dirs_for_sync(trans, inode, parent,
					 sb, last_committed);
	if (ret)
		goto end_no_trans;

	if (btrfs_inode_in_log(inode, trans->transid)) {
		ret = BTRFS_NO_LOG_SYNC;
		goto end_no_trans;
	}

	ret = start_log_trans(trans, root, ctx);
	if (ret)
		goto end_no_trans;

	ret = btrfs_log_inode(trans, root, inode, inode_only, start, end, ctx);
	if (ret)
		goto end_trans;

	if (S_ISREG(inode->i_mode) &&
	    BTRFS_I(inode)->generation <= last_committed &&
	    BTRFS_I(inode)->last_unlink_trans <= last_committed) {
		ret = 0;
		goto end_trans;
	}

	if (S_ISDIR(inode->i_mode) && ctx && ctx->log_new_dentries)
		log_dentries = true;

	if (BTRFS_I(inode)->last_unlink_trans > last_committed) {
		ret = btrfs_log_all_parents(trans, orig_inode, ctx);
		if (ret)
			goto end_trans;
	}

	while (1) {
		if (!parent || d_really_is_negative(parent) || sb != d_inode(parent)->i_sb)
			break;

		inode = d_inode(parent);
		if (root != BTRFS_I(inode)->root)
			break;

		if (BTRFS_I(inode)->generation > last_committed) {
			ret = btrfs_log_inode(trans, root, inode,
					      LOG_INODE_EXISTS,
					      0, LLONG_MAX, ctx);
			if (ret)
				goto end_trans;
		}
		if (IS_ROOT(parent))
			break;

		parent = dget_parent(parent);
		dput(old_parent);
		old_parent = parent;
	}
	if (log_dentries)
		ret = log_new_dir_dentries(trans, root, orig_inode, ctx);
	else
		ret = 0;
end_trans:
	dput(old_parent);
	if (ret < 0) {
		btrfs_set_log_full_commit(root->fs_info, trans);
		ret = 1;
	}

	if (ret)
		btrfs_remove_log_ctx(root, ctx);
	btrfs_end_log_trans(root);
end_no_trans:
	return ret;
}

int btrfs_log_dentry_safe(struct btrfs_trans_handle *trans,
			  struct btrfs_root *root, struct dentry *dentry,
			  const loff_t start,
			  const loff_t end,
			  struct btrfs_log_ctx *ctx)
{
	struct dentry *parent = dget_parent(dentry);
	int ret;

	ret = btrfs_log_inode_parent(trans, root, d_inode(dentry), parent,
				     start, end, 0, ctx);
	dput(parent);

	return ret;
}

int btrfs_recover_log_trees(struct btrfs_root *log_root_tree)
{
	int ret;
	struct btrfs_path *path;
	struct btrfs_trans_handle *trans;
	struct btrfs_key key;
	struct btrfs_key found_key;
	struct btrfs_key tmp_key;
	struct btrfs_root *log;
	struct btrfs_fs_info *fs_info = log_root_tree->fs_info;
	struct walk_control wc = {
		.process_func = process_one_buffer,
		.stage = 0,
	};

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	fs_info->log_root_recovering = 1;

	trans = btrfs_start_transaction(fs_info->tree_root, 0);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto error;
	}

	wc.trans = trans;
	wc.pin = 1;

	ret = walk_log_tree(trans, log_root_tree, &wc);
	if (ret) {
		btrfs_handle_fs_error(fs_info, ret, "Failed to pin buffers while "
			    "recovering log root tree.");
		goto error;
	}

again:
	key.objectid = BTRFS_TREE_LOG_OBJECTID;
	key.offset = (u64)-1;
	key.type = BTRFS_ROOT_ITEM_KEY;

	while (1) {
		ret = btrfs_search_slot(NULL, log_root_tree, &key, path, 0, 0);

		if (ret < 0) {
			btrfs_handle_fs_error(fs_info, ret,
				    "Couldn't find tree log root.");
			goto error;
		}
		if (ret > 0) {
			if (path->slots[0] == 0)
				break;
			path->slots[0]--;
		}
		btrfs_item_key_to_cpu(path->nodes[0], &found_key,
				      path->slots[0]);
		btrfs_release_path(path);
		if (found_key.objectid != BTRFS_TREE_LOG_OBJECTID)
			break;

		log = btrfs_read_fs_root(log_root_tree, &found_key);
		if (IS_ERR(log)) {
			ret = PTR_ERR(log);
			btrfs_handle_fs_error(fs_info, ret,
				    "Couldn't read tree log root.");
			goto error;
		}

		tmp_key.objectid = found_key.offset;
		tmp_key.type = BTRFS_ROOT_ITEM_KEY;
		tmp_key.offset = (u64)-1;

		wc.replay_dest = btrfs_read_fs_root_no_name(fs_info, &tmp_key);
		if (IS_ERR(wc.replay_dest)) {
			ret = PTR_ERR(wc.replay_dest);
			free_extent_buffer(log->node);
			free_extent_buffer(log->commit_root);
			kfree(log);
			btrfs_handle_fs_error(fs_info, ret, "Couldn't read target root "
				    "for tree log recovery.");
			goto error;
		}

		wc.replay_dest->log_root = log;
		btrfs_record_root_in_trans(trans, wc.replay_dest);
#ifdef MY_ABC_HERE
		if (wc.stage == LOG_WALK_REPLAY_ALL) {
			ret = btrfs_run_delayed_items(trans, wc.replay_dest);
			if (ret)
				goto error;
		}
#endif  
		ret = walk_log_tree(trans, log, &wc);

		if (!ret && wc.stage == LOG_WALK_REPLAY_ALL) {
			ret = fixup_inode_link_counts(trans, wc.replay_dest,
						      path);
		}

		key.offset = found_key.offset - 1;
		wc.replay_dest->log_root = NULL;
		free_extent_buffer(log->node);
		free_extent_buffer(log->commit_root);
		kfree(log);

		if (ret)
			goto error;

		if (found_key.offset == 0)
			break;
	}
	btrfs_release_path(path);

	if (wc.pin) {
		wc.pin = 0;
		wc.process_func = replay_one_buffer;
		wc.stage = LOG_WALK_REPLAY_INODES;
		goto again;
	}
	 
	if (wc.stage < LOG_WALK_REPLAY_ALL) {
		wc.stage++;
		goto again;
	}

	btrfs_free_path(path);

	ret = btrfs_commit_transaction(trans, fs_info->tree_root);
	if (ret)
		return ret;

	free_extent_buffer(log_root_tree->node);
	log_root_tree->log_root = NULL;
	fs_info->log_root_recovering = 0;
	kfree(log_root_tree);

	return 0;
error:
	if (wc.trans)
		btrfs_end_transaction(wc.trans, fs_info->tree_root);
	btrfs_free_path(path);
	return ret;
}

void btrfs_record_unlink_dir(struct btrfs_trans_handle *trans,
			     struct inode *dir, struct inode *inode,
			     int for_rename)
{
	 
	mutex_lock(&BTRFS_I(inode)->log_mutex);
	BTRFS_I(inode)->last_unlink_trans = trans->transid;
	mutex_unlock(&BTRFS_I(inode)->log_mutex);

	smp_mb();
	if (BTRFS_I(dir)->logged_trans == trans->transid)
		return;

	if (BTRFS_I(inode)->logged_trans == trans->transid)
		return;

	if (for_rename)
		goto record;

	return;

record:
	mutex_lock(&BTRFS_I(dir)->log_mutex);
	BTRFS_I(dir)->last_unlink_trans = trans->transid;
	mutex_unlock(&BTRFS_I(dir)->log_mutex);
}

void btrfs_record_snapshot_destroy(struct btrfs_trans_handle *trans,
				   struct inode *dir)
{
	mutex_lock(&BTRFS_I(dir)->log_mutex);
	BTRFS_I(dir)->last_unlink_trans = trans->transid;
	mutex_unlock(&BTRFS_I(dir)->log_mutex);
}

int btrfs_log_new_name(struct btrfs_trans_handle *trans,
			struct inode *inode, struct inode *old_dir,
			struct dentry *parent)
{
	struct btrfs_root * root = BTRFS_I(inode)->root;

	if (S_ISREG(inode->i_mode))
		BTRFS_I(inode)->last_unlink_trans = trans->transid;

	if (BTRFS_I(inode)->logged_trans <=
	    root->fs_info->last_trans_committed &&
	    (!old_dir || BTRFS_I(old_dir)->logged_trans <=
		    root->fs_info->last_trans_committed))
		return 0;

	return btrfs_log_inode_parent(trans, root, inode, parent, 0,
				      LLONG_MAX, 1, NULL);
}
