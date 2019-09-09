#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/buffer_head.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
#include <linux/mpage.h>
#include <linux/swap.h>
#include <linux/writeback.h>
#include <linux/statfs.h>
#include <linux/compat.h>
#include <linux/bit_spinlock.h>
#include <linux/xattr.h>
#include <linux/posix_acl.h>
#include <linux/falloc.h>
#include <linux/slab.h>
#include <linux/ratelimit.h>
#include <linux/mount.h>
#include <linux/btrfs.h>
#include <linux/blkdev.h>
#include <linux/posix_acl_xattr.h>
#include <linux/uio.h>
#include "ctree.h"
#include "disk-io.h"
#include "transaction.h"
#include "btrfs_inode.h"
#include "print-tree.h"
#include "ordered-data.h"
#include "xattr.h"
#include "tree-log.h"
#include "volumes.h"
#include "compression.h"
#include "locking.h"
#include "free-space-cache.h"
#include "inode-map.h"
#include "backref.h"
#include "hash.h"
#include "props.h"
#include "qgroup.h"

struct btrfs_iget_args {
	struct btrfs_key *location;
	struct btrfs_root *root;
};

struct btrfs_dio_data {
	u64 outstanding_extents;
	u64 reserve;
	u64 unsubmitted_oe_range_start;
	u64 unsubmitted_oe_range_end;
};

static const struct inode_operations btrfs_dir_inode_operations;
static const struct inode_operations btrfs_symlink_inode_operations;
static const struct inode_operations btrfs_dir_ro_inode_operations;
static const struct inode_operations btrfs_special_inode_operations;
static const struct inode_operations btrfs_file_inode_operations;
static const struct address_space_operations btrfs_aops;
static const struct address_space_operations btrfs_symlink_aops;
static const struct file_operations btrfs_dir_file_operations;
static const struct extent_io_ops btrfs_extent_io_ops;

static struct kmem_cache *btrfs_inode_cachep;
struct kmem_cache *btrfs_trans_handle_cachep;
struct kmem_cache *btrfs_transaction_cachep;
struct kmem_cache *btrfs_path_cachep;
struct kmem_cache *btrfs_free_space_cachep;

#define S_SHIFT 12
static const unsigned char btrfs_type_by_mode[S_IFMT >> S_SHIFT] = {
	[S_IFREG >> S_SHIFT]	= BTRFS_FT_REG_FILE,
	[S_IFDIR >> S_SHIFT]	= BTRFS_FT_DIR,
	[S_IFCHR >> S_SHIFT]	= BTRFS_FT_CHRDEV,
	[S_IFBLK >> S_SHIFT]	= BTRFS_FT_BLKDEV,
	[S_IFIFO >> S_SHIFT]	= BTRFS_FT_FIFO,
	[S_IFSOCK >> S_SHIFT]	= BTRFS_FT_SOCK,
	[S_IFLNK >> S_SHIFT]	= BTRFS_FT_SYMLINK,
};

static int btrfs_setsize(struct inode *inode, struct iattr *attr);
static int btrfs_truncate(struct inode *inode);
static int btrfs_finish_ordered_io(struct btrfs_ordered_extent *ordered_extent);
static noinline int cow_file_range(struct inode *inode,
				   struct page *locked_page,
				   u64 start, u64 end, int *page_started,
				   unsigned long *nr_written, int unlock);
static struct extent_map *create_pinned_em(struct inode *inode, u64 start,
					   u64 len, u64 orig_start,
					   u64 block_start, u64 block_len,
					   u64 orig_block_len, u64 ram_bytes,
					   int type);

static int btrfs_dirty_inode(struct inode *inode);

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
static int btrfs_syno_init_attr(struct btrfs_trans_handle *trans, struct inode *inode)
{
	int err = -EINVAL;
#ifdef MY_ABC_HERE
	struct btrfs_timespec crtime;
#endif  
#ifdef MY_ABC_HERE
	__le32 archive_bit;
#endif  

#ifdef MY_ABC_HERE
	inode->i_create_time = inode->i_mtime;
	crtime.sec = cpu_to_le64(inode->i_create_time.tv_sec);
	crtime.nsec = cpu_to_le32(inode->i_create_time.tv_nsec);
	err = __btrfs_setxattr(trans, inode, XATTR_SYNO_PREFIX XATTR_SYNO_CREATE_TIME,
						  &crtime, sizeof(crtime), XATTR_CREATE);
	if (err)
		goto out;
#endif  

#ifdef MY_ABC_HERE
	inode->i_archive_bit = ALL_SYNO_ARCHIVE;
	archive_bit = cpu_to_le32(inode->i_archive_bit);
	err = __btrfs_setxattr(trans, inode, XATTR_SYNO_PREFIX XATTR_SYNO_ARCHIVE_BIT,
					       &archive_bit, sizeof(archive_bit), XATTR_CREATE);
#endif  
out:
	return err;
}
#endif  

#ifdef MY_ABC_HERE
static int btrfs_syno_set_crtime(struct dentry *dentry, struct timespec *time)
{
	int err;
	struct btrfs_timespec crtime;
	struct inode *inode = d_inode(dentry);

	if (!inode->i_op->setxattr) {
		 
		printk(KERN_ERR "BTRFS:Can't set create time on dir_ro_inode %s\n", dentry->d_name.name);
		return -EOPNOTSUPP;
	}
	crtime.sec = cpu_to_le64(time->tv_sec);
	crtime.nsec = cpu_to_le32(time->tv_nsec);
	err = inode->i_op->setxattr(dentry, XATTR_SYNO_PREFIX XATTR_SYNO_CREATE_TIME,
						 &crtime, sizeof(crtime), 0);
	return err;
}
#endif  

#ifdef MY_ABC_HERE
static int btrfs_syno_set_archive_bit(struct dentry *dentry, u32 archive_bit)
{
	int err;
	__le32 archive_le32;
	struct inode *inode = d_inode(dentry);

	if (!inode->i_op->setxattr) {
		printk(KERN_ERR "BTRFS:Can't set archive bit on dir_ro_inode %s\n", dentry->d_name.name);
		return -EOPNOTSUPP;
	}

	archive_le32 = cpu_to_le32(archive_bit);
	err = inode->i_op->setxattr(dentry, XATTR_SYNO_PREFIX XATTR_SYNO_ARCHIVE_BIT,
					     &archive_le32, sizeof(archive_le32), 0);
	return err;
}
#endif  

#ifdef MY_ABC_HERE
static int btrfs_syno_set_archive_ver(struct dentry *dentry, u32 version)
{
	struct inode *inode = d_inode(dentry);
	struct syno_xattr_archive_version value;
	int err;

	if (!inode->i_op->setxattr) {
		printk(KERN_ERR "BTRFS:Can't set archive ver on dir_ro_inode %s\n", dentry->d_name.name);
		return -EOPNOTSUPP;
	}
	value.v_magic = cpu_to_le16(0x2552);
	value.v_struct_version = cpu_to_le16(1);
	value.v_archive_version = cpu_to_le32(version);
	err = inode->i_op->setxattr(dentry, XATTR_SYNO_PREFIX XATTR_SYNO_ARCHIVE_VERSION,
						 &value, sizeof(value), 0);
	return err;
}

static int btrfs_syno_get_archive_ver(struct dentry *dentry, u32 *version)
{
	struct inode *inode = d_inode(dentry);
	struct syno_xattr_archive_version value;
	int err;

	if (IS_ARCHIVE_VERSION_CACHED(inode)) {
		*version = inode->i_archive_version;
		return 0;
	}

	err = __btrfs_getxattr(inode, XATTR_SYNO_PREFIX XATTR_SYNO_ARCHIVE_VERSION, &value, sizeof(value));
	if (0 < err) {
		inode->i_archive_version = le32_to_cpu(value.v_archive_version);
	} else if (-ENODATA == err) {
		inode->i_archive_version = 0;
	} else {
		*version = 0;
		return err;
	}
	*version = inode->i_archive_version;
	inode->i_flags |= S_ARCHIVE_VERSION_CACHED;
	return 0;
}
#endif  

#ifdef CONFIG_BTRFS_FS_RUN_SANITY_TESTS
void btrfs_test_inode_set_ops(struct inode *inode)
{
	BTRFS_I(inode)->io_tree.ops = &btrfs_extent_io_ops;
}
#endif

static int btrfs_init_inode_security(struct btrfs_trans_handle *trans,
				     struct inode *inode,  struct inode *dir,
				     const struct qstr *qstr)
{
	int err;

	err = btrfs_init_acl(trans, inode, dir);
	if (!err)
		err = btrfs_xattr_security_init(trans, inode, dir, qstr);
	return err;
}

static int insert_inline_extent(struct btrfs_trans_handle *trans,
				struct btrfs_path *path, int extent_inserted,
				struct btrfs_root *root, struct inode *inode,
				u64 start, size_t size, size_t compressed_size,
				int compress_type,
				struct page **compressed_pages)
{
	struct extent_buffer *leaf;
	struct page *page = NULL;
	char *kaddr;
	unsigned long ptr;
	struct btrfs_file_extent_item *ei;
	int err = 0;
	int ret;
	size_t cur_size = size;
	unsigned long offset;

	if (compressed_size && compressed_pages)
		cur_size = compressed_size;

	inode_add_bytes(inode, size);

	if (!extent_inserted) {
		struct btrfs_key key;
		size_t datasize;

		key.objectid = btrfs_ino(inode);
		key.offset = start;
		key.type = BTRFS_EXTENT_DATA_KEY;

		datasize = btrfs_file_extent_calc_inline_size(cur_size);
		path->leave_spinning = 1;
		ret = btrfs_insert_empty_item(trans, root, path, &key,
					      datasize);
		if (ret) {
			err = ret;
			goto fail;
		}
	}
	leaf = path->nodes[0];
	ei = btrfs_item_ptr(leaf, path->slots[0],
			    struct btrfs_file_extent_item);
	btrfs_set_file_extent_generation(leaf, ei, trans->transid);
	btrfs_set_file_extent_type(leaf, ei, BTRFS_FILE_EXTENT_INLINE);
	btrfs_set_file_extent_encryption(leaf, ei, 0);
	btrfs_set_file_extent_other_encoding(leaf, ei, 0);
	btrfs_set_file_extent_ram_bytes(leaf, ei, size);
	ptr = btrfs_file_extent_inline_start(ei);

	if (compress_type != BTRFS_COMPRESS_NONE) {
		struct page *cpage;
		int i = 0;
		while (compressed_size > 0) {
			cpage = compressed_pages[i];
			cur_size = min_t(unsigned long, compressed_size,
				       PAGE_CACHE_SIZE);

			kaddr = kmap_atomic(cpage);
			write_extent_buffer(leaf, kaddr, ptr, cur_size);
			kunmap_atomic(kaddr);

			i++;
			ptr += cur_size;
			compressed_size -= cur_size;
		}
		btrfs_set_file_extent_compression(leaf, ei,
						  compress_type);
	} else {
		page = find_get_page(inode->i_mapping,
				     start >> PAGE_CACHE_SHIFT);
		btrfs_set_file_extent_compression(leaf, ei, 0);
		kaddr = kmap_atomic(page);
		offset = start & (PAGE_CACHE_SIZE - 1);
		write_extent_buffer(leaf, kaddr + offset, ptr, size);
		kunmap_atomic(kaddr);
		page_cache_release(page);
	}
	btrfs_mark_buffer_dirty(leaf);
	btrfs_release_path(path);

	BTRFS_I(inode)->disk_i_size = inode->i_size;
	ret = btrfs_update_inode(trans, root, inode);

	return ret;
fail:
	return err;
}

static noinline int cow_file_range_inline(struct btrfs_root *root,
					  struct inode *inode, u64 start,
					  u64 end, size_t compressed_size,
					  int compress_type,
					  struct page **compressed_pages)
{
	struct btrfs_trans_handle *trans;
	u64 isize = i_size_read(inode);
	u64 actual_end = min(end + 1, isize);
	u64 inline_len = actual_end - start;
	u64 aligned_end = ALIGN(end, root->sectorsize);
	u64 data_len = inline_len;
	int ret;
	struct btrfs_path *path;
	int extent_inserted = 0;
	u32 extent_item_size;

	if (compressed_size)
		data_len = compressed_size;

	if (start > 0 ||
	    actual_end > PAGE_CACHE_SIZE ||
	    data_len > BTRFS_MAX_INLINE_DATA_SIZE(root) ||
	    (!compressed_size &&
	    (actual_end & (root->sectorsize - 1)) == 0) ||
	    end + 1 < isize ||
	    data_len > root->fs_info->max_inline) {
		return 1;
	}

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans)) {
		btrfs_free_path(path);
		return PTR_ERR(trans);
	}
	trans->block_rsv = &root->fs_info->delalloc_block_rsv;

	if (compressed_size && compressed_pages)
		extent_item_size = btrfs_file_extent_calc_inline_size(
		   compressed_size);
	else
		extent_item_size = btrfs_file_extent_calc_inline_size(
		    inline_len);

	ret = __btrfs_drop_extents(trans, root, inode, path,
				   start, aligned_end, NULL,
				   1, 1, extent_item_size, &extent_inserted);
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto out;
	}

	if (isize > actual_end)
		inline_len = min_t(u64, isize, actual_end);
	ret = insert_inline_extent(trans, path, extent_inserted,
				   root, inode, start,
				   inline_len, compressed_size,
				   compress_type, compressed_pages);
	if (ret && ret != -ENOSPC) {
		btrfs_abort_transaction(trans, root, ret);
		goto out;
	} else if (ret == -ENOSPC) {
		ret = 1;
		goto out;
	}

	set_bit(BTRFS_INODE_NEEDS_FULL_SYNC, &BTRFS_I(inode)->runtime_flags);
	btrfs_delalloc_release_metadata(inode, end + 1 - start);
	btrfs_drop_extent_cache(inode, start, aligned_end - 1, 0);
out:
	 
	btrfs_qgroup_free_data(inode, 0, PAGE_CACHE_SIZE);
	btrfs_free_path(path);
	btrfs_end_transaction(trans, root);
	return ret;
}

struct async_extent {
	u64 start;
	u64 ram_size;
	u64 compressed_size;
	struct page **pages;
	unsigned long nr_pages;
	int compress_type;
	struct list_head list;
};

struct async_cow {
	struct inode *inode;
	struct btrfs_root *root;
	struct page *locked_page;
	u64 start;
	u64 end;
	struct list_head extents;
	struct btrfs_work work;
};

static noinline int add_async_extent(struct async_cow *cow,
				     u64 start, u64 ram_size,
				     u64 compressed_size,
				     struct page **pages,
				     unsigned long nr_pages,
				     int compress_type)
{
	struct async_extent *async_extent;

	async_extent = kmalloc(sizeof(*async_extent), GFP_NOFS);
	BUG_ON(!async_extent);  
	async_extent->start = start;
	async_extent->ram_size = ram_size;
	async_extent->compressed_size = compressed_size;
	async_extent->pages = pages;
	async_extent->nr_pages = nr_pages;
	async_extent->compress_type = compress_type;
	list_add_tail(&async_extent->list, &cow->extents);
	return 0;
}

static inline int inode_need_compress(struct inode *inode)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;

	if (btrfs_test_opt(root, FORCE_COMPRESS))
		return 1;
	 
	if (BTRFS_I(inode)->flags & BTRFS_INODE_NOCOMPRESS)
		return 0;
	if (btrfs_test_opt(root, COMPRESS) ||
	    BTRFS_I(inode)->flags & BTRFS_INODE_COMPRESS ||
	    BTRFS_I(inode)->force_compress)
		return 1;
	return 0;
}

static noinline void compress_file_range(struct inode *inode,
					struct page *locked_page,
					u64 start, u64 end,
					struct async_cow *async_cow,
					int *num_added)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	u64 num_bytes;
	u64 blocksize = root->sectorsize;
	u64 actual_end;
	u64 isize = i_size_read(inode);
	int ret = 0;
	struct page **pages = NULL;
	unsigned long nr_pages;
	unsigned long nr_pages_ret = 0;
	unsigned long total_compressed = 0;
	unsigned long total_in = 0;
	unsigned long max_compressed = SZ_128K;
	unsigned long max_uncompressed = SZ_128K;
	int i;
	int will_compress;
	int compress_type = root->fs_info->compress_type;
	int redirty = 0;

	if ((end - start + 1) < SZ_16K &&
	    (start > 0 || end + 1 < BTRFS_I(inode)->disk_i_size))
		btrfs_add_inode_defrag(NULL, inode);

	actual_end = min_t(u64, isize, end + 1);
again:
	will_compress = 0;
	nr_pages = (end >> PAGE_CACHE_SHIFT) - (start >> PAGE_CACHE_SHIFT) + 1;
	nr_pages = min_t(unsigned long, nr_pages, SZ_128K / PAGE_CACHE_SIZE);

	if (actual_end <= start)
		goto cleanup_and_bail_uncompressed;

	total_compressed = actual_end - start;

	if (total_compressed <= blocksize &&
	   (start > 0 || end + 1 < BTRFS_I(inode)->disk_i_size))
		goto cleanup_and_bail_uncompressed;

	total_compressed = min(total_compressed, max_uncompressed);
	num_bytes = ALIGN(end - start + 1, blocksize);
	num_bytes = max(blocksize,  num_bytes);
	total_in = 0;
	ret = 0;

	if (inode_need_compress(inode)) {
		WARN_ON(pages);
		pages = kcalloc(nr_pages, sizeof(struct page *), GFP_NOFS);
		if (!pages) {
			 
			goto cont;
		}

		if (BTRFS_I(inode)->force_compress)
			compress_type = BTRFS_I(inode)->force_compress;

		extent_range_clear_dirty_for_io(inode, start, end);
		redirty = 1;
		ret = btrfs_compress_pages(compress_type,
					   inode->i_mapping, start,
					   total_compressed, pages,
					   nr_pages, &nr_pages_ret,
					   &total_in,
					   &total_compressed,
					   max_compressed);

		if (!ret) {
			unsigned long offset = total_compressed &
				(PAGE_CACHE_SIZE - 1);
			struct page *page = pages[nr_pages_ret - 1];
			char *kaddr;

			if (offset) {
				kaddr = kmap_atomic(page);
				memset(kaddr + offset, 0,
				       PAGE_CACHE_SIZE - offset);
				kunmap_atomic(kaddr);
			}
			will_compress = 1;
		}
	}
cont:
	if (start == 0) {
		 
		if (ret || total_in < (actual_end - start)) {
			 
			ret = cow_file_range_inline(root, inode, start, end,
						    0, 0, NULL);
		} else {
			 
			ret = cow_file_range_inline(root, inode, start, end,
						    total_compressed,
						    compress_type, pages);
		}
		if (ret <= 0) {
			unsigned long clear_flags = EXTENT_DELALLOC |
				EXTENT_DEFRAG;
			unsigned long page_error_op;

			clear_flags |= (ret < 0) ? EXTENT_DO_ACCOUNTING : 0;
			page_error_op = ret < 0 ? PAGE_SET_ERROR : 0;

			extent_clear_unlock_delalloc(inode, start, end, NULL,
						     clear_flags, PAGE_UNLOCK |
						     PAGE_CLEAR_DIRTY |
						     PAGE_SET_WRITEBACK |
						     page_error_op |
						     PAGE_END_WRITEBACK);
			goto free_pages_out;
		}
	}

	if (will_compress) {
		 
		total_compressed = ALIGN(total_compressed, blocksize);

		total_in = ALIGN(total_in, PAGE_CACHE_SIZE);
		if (total_compressed >= total_in) {
			will_compress = 0;
		} else {
			num_bytes = total_in;
		}
	}
	if (!will_compress && pages) {
		 
		for (i = 0; i < nr_pages_ret; i++) {
			WARN_ON(pages[i]->mapping);
			page_cache_release(pages[i]);
		}
		kfree(pages);
		pages = NULL;
		total_compressed = 0;
		nr_pages_ret = 0;

		if (!btrfs_test_opt(root, FORCE_COMPRESS) &&
		    !(BTRFS_I(inode)->force_compress)) {
			BTRFS_I(inode)->flags |= BTRFS_INODE_NOCOMPRESS;
		}
	}
	if (will_compress) {
		*num_added += 1;

		add_async_extent(async_cow, start, num_bytes,
				 total_compressed, pages, nr_pages_ret,
				 compress_type);

		if (start + num_bytes < end) {
			start += num_bytes;
			pages = NULL;
			cond_resched();
			goto again;
		}
	} else {
cleanup_and_bail_uncompressed:
		 
		if (page_offset(locked_page) >= start &&
		    page_offset(locked_page) <= end) {
			__set_page_dirty_nobuffers(locked_page);
			 
		}
		if (redirty)
			extent_range_redirty_for_io(inode, start, end);
		add_async_extent(async_cow, start, end - start + 1,
				 0, NULL, 0, BTRFS_COMPRESS_NONE);
		*num_added += 1;
	}

	return;

free_pages_out:
	for (i = 0; i < nr_pages_ret; i++) {
		WARN_ON(pages[i]->mapping);
		page_cache_release(pages[i]);
	}
	kfree(pages);
}

static void free_async_extent_pages(struct async_extent *async_extent)
{
	int i;

	if (!async_extent->pages)
		return;

	for (i = 0; i < async_extent->nr_pages; i++) {
		WARN_ON(async_extent->pages[i]->mapping);
		page_cache_release(async_extent->pages[i]);
	}
	kfree(async_extent->pages);
	async_extent->nr_pages = 0;
	async_extent->pages = NULL;
}

static noinline void submit_compressed_extents(struct inode *inode,
					      struct async_cow *async_cow)
{
	struct async_extent *async_extent;
	u64 alloc_hint = 0;
	struct btrfs_key ins;
	struct extent_map *em;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct extent_map_tree *em_tree = &BTRFS_I(inode)->extent_tree;
	struct extent_io_tree *io_tree;
	int ret = 0;

again:
	while (!list_empty(&async_cow->extents)) {
		async_extent = list_entry(async_cow->extents.next,
					  struct async_extent, list);
		list_del(&async_extent->list);

		io_tree = &BTRFS_I(inode)->io_tree;

retry:
		 
		if (!async_extent->pages) {
			int page_started = 0;
			unsigned long nr_written = 0;

			lock_extent(io_tree, async_extent->start,
					 async_extent->start +
					 async_extent->ram_size - 1);

			ret = cow_file_range(inode, async_cow->locked_page,
					     async_extent->start,
					     async_extent->start +
					     async_extent->ram_size - 1,
					     &page_started, &nr_written, 0);

			if (!page_started && !ret)
				extent_write_locked_range(io_tree,
						  inode, async_extent->start,
						  async_extent->start +
						  async_extent->ram_size - 1,
						  btrfs_get_extent,
						  WB_SYNC_ALL);
			else if (ret)
				unlock_page(async_cow->locked_page);
			kfree(async_extent);
			cond_resched();
			continue;
		}

		lock_extent(io_tree, async_extent->start,
			    async_extent->start + async_extent->ram_size - 1);

		ret = btrfs_reserve_extent(root,
					   async_extent->compressed_size,
					   async_extent->compressed_size,
					   0, alloc_hint, &ins, 1, 1);
		if (ret) {
			free_async_extent_pages(async_extent);

			if (ret == -ENOSPC) {
				unlock_extent(io_tree, async_extent->start,
					      async_extent->start +
					      async_extent->ram_size - 1);

				extent_range_redirty_for_io(inode,
						async_extent->start,
						async_extent->start +
						async_extent->ram_size - 1);

				goto retry;
			}
			goto out_free;
		}
		 
		btrfs_drop_extent_cache(inode, async_extent->start,
					async_extent->start +
					async_extent->ram_size - 1, 0);

		em = alloc_extent_map();
		if (!em) {
			ret = -ENOMEM;
			goto out_free_reserve;
		}
		em->start = async_extent->start;
		em->len = async_extent->ram_size;
		em->orig_start = em->start;
		em->mod_start = em->start;
		em->mod_len = em->len;

		em->block_start = ins.objectid;
		em->block_len = ins.offset;
		em->orig_block_len = ins.offset;
		em->ram_bytes = async_extent->ram_size;
		em->bdev = root->fs_info->fs_devices->latest_bdev;
		em->compress_type = async_extent->compress_type;
		set_bit(EXTENT_FLAG_PINNED, &em->flags);
		set_bit(EXTENT_FLAG_COMPRESSED, &em->flags);
		em->generation = -1;

		while (1) {
			write_lock(&em_tree->lock);
			ret = add_extent_mapping(em_tree, em, 1);
			write_unlock(&em_tree->lock);
			if (ret != -EEXIST) {
				free_extent_map(em);
				break;
			}
			btrfs_drop_extent_cache(inode, async_extent->start,
						async_extent->start +
						async_extent->ram_size - 1, 0);
		}

		if (ret)
			goto out_free_reserve;

		ret = btrfs_add_ordered_extent_compress(inode,
						async_extent->start,
						ins.objectid,
						async_extent->ram_size,
						ins.offset,
						BTRFS_ORDERED_COMPRESSED,
						async_extent->compress_type);
		if (ret) {
			btrfs_drop_extent_cache(inode, async_extent->start,
						async_extent->start +
						async_extent->ram_size - 1, 0);
			goto out_free_reserve;
		}
		btrfs_dec_block_group_reservations(root->fs_info, ins.objectid);

		extent_clear_unlock_delalloc(inode, async_extent->start,
				async_extent->start +
				async_extent->ram_size - 1,
				NULL, EXTENT_LOCKED | EXTENT_DELALLOC,
				PAGE_UNLOCK | PAGE_CLEAR_DIRTY |
				PAGE_SET_WRITEBACK);
		ret = btrfs_submit_compressed_write(inode,
				    async_extent->start,
				    async_extent->ram_size,
				    ins.objectid,
				    ins.offset, async_extent->pages,
				    async_extent->nr_pages);
		if (ret) {
			struct extent_io_tree *tree = &BTRFS_I(inode)->io_tree;
			struct page *p = async_extent->pages[0];
			const u64 start = async_extent->start;
			const u64 end = start + async_extent->ram_size - 1;

			p->mapping = inode->i_mapping;
			tree->ops->writepage_end_io_hook(p, start, end,
							 NULL, 0);
			p->mapping = NULL;
			extent_clear_unlock_delalloc(inode, start, end, NULL, 0,
						     PAGE_END_WRITEBACK |
						     PAGE_SET_ERROR);
			free_async_extent_pages(async_extent);
		}
		alloc_hint = ins.objectid + ins.offset;
		kfree(async_extent);
		cond_resched();
	}
	return;
out_free_reserve:
	btrfs_dec_block_group_reservations(root->fs_info, ins.objectid);
	btrfs_free_reserved_extent(root, ins.objectid, ins.offset, 1);
out_free:
	extent_clear_unlock_delalloc(inode, async_extent->start,
				     async_extent->start +
				     async_extent->ram_size - 1,
				     NULL, EXTENT_LOCKED | EXTENT_DELALLOC |
				     EXTENT_DEFRAG | EXTENT_DO_ACCOUNTING,
				     PAGE_UNLOCK | PAGE_CLEAR_DIRTY |
				     PAGE_SET_WRITEBACK | PAGE_END_WRITEBACK |
				     PAGE_SET_ERROR);
	free_async_extent_pages(async_extent);
	kfree(async_extent);
	goto again;
}

static u64 get_extent_allocation_hint(struct inode *inode, u64 start,
				      u64 num_bytes)
{
	struct extent_map_tree *em_tree = &BTRFS_I(inode)->extent_tree;
	struct extent_map *em;
	u64 alloc_hint = 0;

	read_lock(&em_tree->lock);
	em = search_extent_mapping(em_tree, start, num_bytes);
	if (em) {
		 
		if (em->block_start >= EXTENT_MAP_LAST_BYTE) {
			free_extent_map(em);
			em = search_extent_mapping(em_tree, 0, 0);
			if (em && em->block_start < EXTENT_MAP_LAST_BYTE)
				alloc_hint = em->block_start;
			if (em)
				free_extent_map(em);
		} else {
			alloc_hint = em->block_start;
			free_extent_map(em);
		}
	}
	read_unlock(&em_tree->lock);

	return alloc_hint;
}

static noinline int cow_file_range(struct inode *inode,
				   struct page *locked_page,
				   u64 start, u64 end, int *page_started,
				   unsigned long *nr_written,
				   int unlock)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	u64 alloc_hint = 0;
	u64 num_bytes;
	unsigned long ram_size;
	u64 disk_num_bytes;
	u64 cur_alloc_size;
	u64 blocksize = root->sectorsize;
	struct btrfs_key ins;
	struct extent_map *em;
	struct extent_map_tree *em_tree = &BTRFS_I(inode)->extent_tree;
	int ret = 0;

	if (btrfs_is_free_space_inode(inode)) {
		WARN_ON_ONCE(1);
		ret = -EINVAL;
		goto out_unlock;
	}

	num_bytes = ALIGN(end - start + 1, blocksize);
	num_bytes = max(blocksize,  num_bytes);
	disk_num_bytes = num_bytes;

	if (num_bytes < SZ_64K &&
	    (start > 0 || end + 1 < BTRFS_I(inode)->disk_i_size))
		btrfs_add_inode_defrag(NULL, inode);

	if (start == 0) {
		 
		ret = cow_file_range_inline(root, inode, start, end, 0, 0,
					    NULL);
		if (ret == 0) {
			extent_clear_unlock_delalloc(inode, start, end, NULL,
				     EXTENT_LOCKED | EXTENT_DELALLOC |
				     EXTENT_DEFRAG, PAGE_UNLOCK |
				     PAGE_CLEAR_DIRTY | PAGE_SET_WRITEBACK |
				     PAGE_END_WRITEBACK);

			*nr_written = *nr_written +
			     (end - start + PAGE_CACHE_SIZE) / PAGE_CACHE_SIZE;
			*page_started = 1;
			goto out;
		} else if (ret < 0) {
			goto out_unlock;
		}
	}

	BUG_ON(disk_num_bytes >
	       btrfs_super_total_bytes(root->fs_info->super_copy));

	alloc_hint = get_extent_allocation_hint(inode, start, num_bytes);
	btrfs_drop_extent_cache(inode, start, start + num_bytes - 1, 0);

	while (disk_num_bytes > 0) {
		unsigned long op;

		cur_alloc_size = disk_num_bytes;
		ret = btrfs_reserve_extent(root, cur_alloc_size,
					   root->sectorsize, 0, alloc_hint,
					   &ins, 1, 1);
		if (ret < 0)
			goto out_unlock;

		em = alloc_extent_map();
		if (!em) {
			ret = -ENOMEM;
			goto out_reserve;
		}
		em->start = start;
		em->orig_start = em->start;
		ram_size = ins.offset;
		em->len = ins.offset;
		em->mod_start = em->start;
		em->mod_len = em->len;

		em->block_start = ins.objectid;
		em->block_len = ins.offset;
		em->orig_block_len = ins.offset;
		em->ram_bytes = ram_size;
		em->bdev = root->fs_info->fs_devices->latest_bdev;
		set_bit(EXTENT_FLAG_PINNED, &em->flags);
		em->generation = -1;

		while (1) {
			write_lock(&em_tree->lock);
			ret = add_extent_mapping(em_tree, em, 1);
			write_unlock(&em_tree->lock);
			if (ret != -EEXIST) {
				free_extent_map(em);
				break;
			}
			btrfs_drop_extent_cache(inode, start,
						start + ram_size - 1, 0);
		}
		if (ret)
			goto out_reserve;

		cur_alloc_size = ins.offset;
		ret = btrfs_add_ordered_extent(inode, start, ins.objectid,
					       ram_size, cur_alloc_size, 0);
		if (ret)
			goto out_drop_extent_cache;

		if (root->root_key.objectid ==
		    BTRFS_DATA_RELOC_TREE_OBJECTID) {
			ret = btrfs_reloc_clone_csums(inode, start,
						      cur_alloc_size);
			if (ret)
				goto out_drop_extent_cache;
		}

		btrfs_dec_block_group_reservations(root->fs_info, ins.objectid);

		if (disk_num_bytes < cur_alloc_size)
			break;

		op = unlock ? PAGE_UNLOCK : 0;
		op |= PAGE_SET_PRIVATE2;

		extent_clear_unlock_delalloc(inode, start,
					     start + ram_size - 1, locked_page,
					     EXTENT_LOCKED | EXTENT_DELALLOC,
					     op);
		disk_num_bytes -= cur_alloc_size;
		num_bytes -= cur_alloc_size;
		alloc_hint = ins.objectid + ins.offset;
		start += cur_alloc_size;
	}
out:
	return ret;

out_drop_extent_cache:
	btrfs_drop_extent_cache(inode, start, start + ram_size - 1, 0);
out_reserve:
	btrfs_dec_block_group_reservations(root->fs_info, ins.objectid);
	btrfs_free_reserved_extent(root, ins.objectid, ins.offset, 1);
out_unlock:
	extent_clear_unlock_delalloc(inode, start, end, locked_page,
				     EXTENT_LOCKED | EXTENT_DO_ACCOUNTING |
				     EXTENT_DELALLOC | EXTENT_DEFRAG,
				     PAGE_UNLOCK | PAGE_CLEAR_DIRTY |
				     PAGE_SET_WRITEBACK | PAGE_END_WRITEBACK);
	goto out;
}

static noinline void async_cow_start(struct btrfs_work *work)
{
	struct async_cow *async_cow;
	int num_added = 0;
	async_cow = container_of(work, struct async_cow, work);

	compress_file_range(async_cow->inode, async_cow->locked_page,
			    async_cow->start, async_cow->end, async_cow,
			    &num_added);
	if (num_added == 0) {
		btrfs_add_delayed_iput(async_cow->inode);
		async_cow->inode = NULL;
	}
}

static noinline void async_cow_submit(struct btrfs_work *work)
{
	struct async_cow *async_cow;
	struct btrfs_root *root;
	unsigned long nr_pages;

	async_cow = container_of(work, struct async_cow, work);

	root = async_cow->root;
	nr_pages = (async_cow->end - async_cow->start + PAGE_CACHE_SIZE) >>
		PAGE_CACHE_SHIFT;

	if (atomic_sub_return(nr_pages, &root->fs_info->async_delalloc_pages) <
	    5 * SZ_1M &&
	    waitqueue_active(&root->fs_info->async_submit_wait))
		wake_up(&root->fs_info->async_submit_wait);

	if (async_cow->inode)
		submit_compressed_extents(async_cow->inode, async_cow);
}

static noinline void async_cow_free(struct btrfs_work *work)
{
	struct async_cow *async_cow;
	async_cow = container_of(work, struct async_cow, work);
	if (async_cow->inode)
		btrfs_add_delayed_iput(async_cow->inode);
	kfree(async_cow);
}

static int cow_file_range_async(struct inode *inode, struct page *locked_page,
				u64 start, u64 end, int *page_started,
				unsigned long *nr_written)
{
	struct async_cow *async_cow;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	unsigned long nr_pages;
	u64 cur_end;
	int limit = 10 * SZ_1M;

	clear_extent_bit(&BTRFS_I(inode)->io_tree, start, end, EXTENT_LOCKED,
			 1, 0, NULL, GFP_NOFS);
	while (start < end) {
		async_cow = kmalloc(sizeof(*async_cow), GFP_NOFS);
		BUG_ON(!async_cow);  
		async_cow->inode = igrab(inode);
		async_cow->root = root;
		async_cow->locked_page = locked_page;
		async_cow->start = start;

		if (BTRFS_I(inode)->flags & BTRFS_INODE_NOCOMPRESS &&
		    !btrfs_test_opt(root, FORCE_COMPRESS))
			cur_end = end;
		else
			cur_end = min(end, start + SZ_512K - 1);

		async_cow->end = cur_end;
		INIT_LIST_HEAD(&async_cow->extents);

		btrfs_init_work(&async_cow->work,
				btrfs_delalloc_helper,
				async_cow_start, async_cow_submit,
				async_cow_free);

		nr_pages = (cur_end - start + PAGE_CACHE_SIZE) >>
			PAGE_CACHE_SHIFT;
		atomic_add(nr_pages, &root->fs_info->async_delalloc_pages);

		btrfs_queue_work(root->fs_info->delalloc_workers,
				 &async_cow->work);

		if (atomic_read(&root->fs_info->async_delalloc_pages) > limit) {
			wait_event(root->fs_info->async_submit_wait,
			   (atomic_read(&root->fs_info->async_delalloc_pages) <
			    limit));
		}

		while (atomic_read(&root->fs_info->async_submit_draining) &&
		      atomic_read(&root->fs_info->async_delalloc_pages)) {
			wait_event(root->fs_info->async_submit_wait,
			  (atomic_read(&root->fs_info->async_delalloc_pages) ==
			   0));
		}

		*nr_written += nr_pages;
		start = cur_end + 1;
	}
	*page_started = 1;
	return 0;
}

static noinline int csum_exist_in_range(struct btrfs_root *root,
					u64 bytenr, u64 num_bytes)
{
	int ret;
	struct btrfs_ordered_sum *sums;
	LIST_HEAD(list);

	ret = btrfs_lookup_csums_range(root->fs_info->csum_root, bytenr,
				       bytenr + num_bytes - 1, &list, 0);
	if (ret == 0 && list_empty(&list))
		return 0;

	while (!list_empty(&list)) {
		sums = list_entry(list.next, struct btrfs_ordered_sum, list);
		list_del(&sums->list);
		kfree(sums);
	}
	return 1;
}

static noinline int run_delalloc_nocow(struct inode *inode,
				       struct page *locked_page,
			      u64 start, u64 end, int *page_started, int force,
			      unsigned long *nr_written)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_trans_handle *trans;
	struct extent_buffer *leaf;
	struct btrfs_path *path;
	struct btrfs_file_extent_item *fi;
	struct btrfs_key found_key;
	u64 cow_start;
	u64 cur_offset;
	u64 extent_end;
	u64 extent_offset;
	u64 disk_bytenr;
	u64 num_bytes;
	u64 disk_num_bytes;
	u64 ram_bytes;
	int extent_type;
	int ret, err;
	int type;
	int nocow;
	int check_prev = 1;
	bool nolock;
	u64 ino = btrfs_ino(inode);

	path = btrfs_alloc_path();
	if (!path) {
		extent_clear_unlock_delalloc(inode, start, end, locked_page,
					     EXTENT_LOCKED | EXTENT_DELALLOC |
					     EXTENT_DO_ACCOUNTING |
					     EXTENT_DEFRAG, PAGE_UNLOCK |
					     PAGE_CLEAR_DIRTY |
					     PAGE_SET_WRITEBACK |
					     PAGE_END_WRITEBACK);
		return -ENOMEM;
	}

	nolock = btrfs_is_free_space_inode(inode);

	if (nolock)
		trans = btrfs_join_transaction_nolock(root);
	else
		trans = btrfs_join_transaction(root);

	if (IS_ERR(trans)) {
		extent_clear_unlock_delalloc(inode, start, end, locked_page,
					     EXTENT_LOCKED | EXTENT_DELALLOC |
					     EXTENT_DO_ACCOUNTING |
					     EXTENT_DEFRAG, PAGE_UNLOCK |
					     PAGE_CLEAR_DIRTY |
					     PAGE_SET_WRITEBACK |
					     PAGE_END_WRITEBACK);
		btrfs_free_path(path);
		return PTR_ERR(trans);
	}

	trans->block_rsv = &root->fs_info->delalloc_block_rsv;

	cow_start = (u64)-1;
	cur_offset = start;
	while (1) {
		ret = btrfs_lookup_file_extent(trans, root, path, ino,
					       cur_offset, 0);
		if (ret < 0)
			goto error;
		if (ret > 0 && path->slots[0] > 0 && check_prev) {
			leaf = path->nodes[0];
			btrfs_item_key_to_cpu(leaf, &found_key,
					      path->slots[0] - 1);
			if (found_key.objectid == ino &&
			    found_key.type == BTRFS_EXTENT_DATA_KEY)
				path->slots[0]--;
		}
		check_prev = 0;
next_slot:
		leaf = path->nodes[0];
		if (path->slots[0] >= btrfs_header_nritems(leaf)) {
			ret = btrfs_next_leaf(root, path);
			if (ret < 0)
				goto error;
			if (ret > 0)
				break;
			leaf = path->nodes[0];
		}

		nocow = 0;
		disk_bytenr = 0;
		num_bytes = 0;
		btrfs_item_key_to_cpu(leaf, &found_key, path->slots[0]);

		if (found_key.objectid > ino)
			break;
		if (WARN_ON_ONCE(found_key.objectid < ino) ||
		    found_key.type < BTRFS_EXTENT_DATA_KEY) {
			path->slots[0]++;
			goto next_slot;
		}
		if (found_key.type > BTRFS_EXTENT_DATA_KEY ||
		    found_key.offset > end)
			break;

		if (found_key.offset > cur_offset) {
			extent_end = found_key.offset;
			extent_type = 0;
			goto out_check;
		}

		fi = btrfs_item_ptr(leaf, path->slots[0],
				    struct btrfs_file_extent_item);
		extent_type = btrfs_file_extent_type(leaf, fi);

		ram_bytes = btrfs_file_extent_ram_bytes(leaf, fi);
		if (extent_type == BTRFS_FILE_EXTENT_REG ||
		    extent_type == BTRFS_FILE_EXTENT_PREALLOC) {
			disk_bytenr = btrfs_file_extent_disk_bytenr(leaf, fi);
			extent_offset = btrfs_file_extent_offset(leaf, fi);
			extent_end = found_key.offset +
				btrfs_file_extent_num_bytes(leaf, fi);
			disk_num_bytes =
				btrfs_file_extent_disk_num_bytes(leaf, fi);
			if (extent_end <= start) {
				path->slots[0]++;
				goto next_slot;
			}
			if (disk_bytenr == 0)
				goto out_check;
			if (btrfs_file_extent_compression(leaf, fi) ||
			    btrfs_file_extent_encryption(leaf, fi) ||
			    btrfs_file_extent_other_encoding(leaf, fi))
				goto out_check;
			if (extent_type == BTRFS_FILE_EXTENT_REG && !force)
				goto out_check;
			if (btrfs_extent_readonly(root, disk_bytenr))
				goto out_check;
			if (btrfs_cross_ref_exist(trans, root, ino,
						  found_key.offset -
						  extent_offset, disk_bytenr))
				goto out_check;
			disk_bytenr += extent_offset;
			disk_bytenr += cur_offset - found_key.offset;
			num_bytes = min(end + 1, extent_end) - cur_offset;
			 
			if (!nolock) {
				err = btrfs_start_write_no_snapshoting(root);
				if (!err)
					goto out_check;
			}
			 
#ifdef MY_ABC_HERE
			if (csum_exist_in_range(root, disk_bytenr, num_bytes)) {
				if (!nolock) {
					btrfs_end_write_no_snapshoting(root);
				}
				goto out_check;
			}
#else
			if (csum_exist_in_range(root, disk_bytenr, num_bytes))
				goto out_check;
#endif  
#ifdef MY_ABC_HERE
			if (!btrfs_inc_nocow_writers(root->fs_info, disk_bytenr)) {
				if (!nolock) {
					btrfs_end_write_no_snapshoting(root);
				}
				goto out_check;
			}
#else
			if (!btrfs_inc_nocow_writers(root->fs_info,
						     disk_bytenr))
				goto out_check;
#endif  
			nocow = 1;
		} else if (extent_type == BTRFS_FILE_EXTENT_INLINE) {
			extent_end = found_key.offset +
				btrfs_file_extent_inline_len(leaf,
						     path->slots[0], fi);
			extent_end = ALIGN(extent_end, root->sectorsize);
		} else {
			BUG_ON(1);
		}
out_check:
		if (extent_end <= start) {
			path->slots[0]++;
			if (!nolock && nocow)
				btrfs_end_write_no_snapshoting(root);
			if (nocow)
				btrfs_dec_nocow_writers(root->fs_info,
							disk_bytenr);
			goto next_slot;
		}
		if (!nocow) {
			if (cow_start == (u64)-1)
				cow_start = cur_offset;
			cur_offset = extent_end;
			if (cur_offset > end)
				break;
			path->slots[0]++;
			goto next_slot;
		}

		btrfs_release_path(path);
		if (cow_start != (u64)-1) {
			ret = cow_file_range(inode, locked_page,
					     cow_start, found_key.offset - 1,
					     page_started, nr_written, 1);
			if (ret) {
				if (!nolock && nocow)
					btrfs_end_write_no_snapshoting(root);
				if (nocow)
					btrfs_dec_nocow_writers(root->fs_info,
								disk_bytenr);
				goto error;
			}
			cow_start = (u64)-1;
		}

		if (extent_type == BTRFS_FILE_EXTENT_PREALLOC) {
			struct extent_map *em;
			struct extent_map_tree *em_tree;
			em_tree = &BTRFS_I(inode)->extent_tree;
			em = alloc_extent_map();
			BUG_ON(!em);  
			em->start = cur_offset;
			em->orig_start = found_key.offset - extent_offset;
			em->len = num_bytes;
			em->block_len = num_bytes;
			em->block_start = disk_bytenr;
			em->orig_block_len = disk_num_bytes;
			em->ram_bytes = ram_bytes;
			em->bdev = root->fs_info->fs_devices->latest_bdev;
			em->mod_start = em->start;
			em->mod_len = em->len;
			set_bit(EXTENT_FLAG_PINNED, &em->flags);
			set_bit(EXTENT_FLAG_FILLING, &em->flags);
			em->generation = -1;
			while (1) {
				write_lock(&em_tree->lock);
				ret = add_extent_mapping(em_tree, em, 1);
				write_unlock(&em_tree->lock);
				if (ret != -EEXIST) {
					free_extent_map(em);
					break;
				}
				btrfs_drop_extent_cache(inode, em->start,
						em->start + em->len - 1, 0);
			}
			type = BTRFS_ORDERED_PREALLOC;
		} else {
			type = BTRFS_ORDERED_NOCOW;
		}

		ret = btrfs_add_ordered_extent(inode, cur_offset, disk_bytenr,
					       num_bytes, num_bytes, type);
		if (nocow)
			btrfs_dec_nocow_writers(root->fs_info, disk_bytenr);
		BUG_ON(ret);  

		if (root->root_key.objectid ==
		    BTRFS_DATA_RELOC_TREE_OBJECTID) {
			ret = btrfs_reloc_clone_csums(inode, cur_offset,
						      num_bytes);
			if (ret) {
				if (!nolock && nocow)
					btrfs_end_write_no_snapshoting(root);
				goto error;
			}
		}

		extent_clear_unlock_delalloc(inode, cur_offset,
					     cur_offset + num_bytes - 1,
					     locked_page, EXTENT_LOCKED |
					     EXTENT_DELALLOC, PAGE_UNLOCK |
					     PAGE_SET_PRIVATE2);
		if (!nolock && nocow)
			btrfs_end_write_no_snapshoting(root);
		cur_offset = extent_end;
		if (cur_offset > end)
			break;
	}
	btrfs_release_path(path);

	if (cur_offset <= end && cow_start == (u64)-1) {
		cow_start = cur_offset;
		cur_offset = end;
	}

	if (cow_start != (u64)-1) {
		ret = cow_file_range(inode, locked_page, cow_start, end,
				     page_started, nr_written, 1);
		if (ret)
			goto error;
	}

error:
	err = btrfs_end_transaction(trans, root);
	if (!ret)
		ret = err;

	if (ret && cur_offset < end)
		extent_clear_unlock_delalloc(inode, cur_offset, end,
					     locked_page, EXTENT_LOCKED |
					     EXTENT_DELALLOC | EXTENT_DEFRAG |
					     EXTENT_DO_ACCOUNTING, PAGE_UNLOCK |
					     PAGE_CLEAR_DIRTY |
					     PAGE_SET_WRITEBACK |
					     PAGE_END_WRITEBACK);
	btrfs_free_path(path);
	return ret;
}

static inline int need_force_cow(struct inode *inode, u64 start, u64 end)
{

	if (!(BTRFS_I(inode)->flags & BTRFS_INODE_NODATACOW) &&
	    !(BTRFS_I(inode)->flags & BTRFS_INODE_PREALLOC))
		return 0;

	if (BTRFS_I(inode)->defrag_bytes &&
	    test_range_bit(&BTRFS_I(inode)->io_tree, start, end,
			   EXTENT_DEFRAG, 0, NULL))
		return 1;

	return 0;
}

static int run_delalloc_range(struct inode *inode, struct page *locked_page,
			      u64 start, u64 end, int *page_started,
			      unsigned long *nr_written)
{
	int ret;
	int force_cow = need_force_cow(inode, start, end);

	if (BTRFS_I(inode)->flags & BTRFS_INODE_NODATACOW && !force_cow) {
		ret = run_delalloc_nocow(inode, locked_page, start, end,
					 page_started, 1, nr_written);
	} else if (BTRFS_I(inode)->flags & BTRFS_INODE_PREALLOC && !force_cow) {
		ret = run_delalloc_nocow(inode, locked_page, start, end,
					 page_started, 0, nr_written);
	} else if (!inode_need_compress(inode)) {
		ret = cow_file_range(inode, locked_page, start, end,
				      page_started, nr_written, 1);
	} else {
		set_bit(BTRFS_INODE_HAS_ASYNC_EXTENT,
			&BTRFS_I(inode)->runtime_flags);
		ret = cow_file_range_async(inode, locked_page, start, end,
					   page_started, nr_written);
	}
	return ret;
}

static void btrfs_split_extent_hook(struct inode *inode,
				    struct extent_state *orig, u64 split)
{
	u64 size;

	if (!(orig->state & EXTENT_DELALLOC))
		return;

	size = orig->end - orig->start + 1;
	if (size > BTRFS_MAX_EXTENT_SIZE) {
		u64 num_extents;
		u64 new_size;

		new_size = orig->end - split + 1;
		num_extents = div64_u64(new_size + BTRFS_MAX_EXTENT_SIZE - 1,
					BTRFS_MAX_EXTENT_SIZE);
		new_size = split - orig->start;
		num_extents += div64_u64(new_size + BTRFS_MAX_EXTENT_SIZE - 1,
					BTRFS_MAX_EXTENT_SIZE);
		if (div64_u64(size + BTRFS_MAX_EXTENT_SIZE - 1,
			      BTRFS_MAX_EXTENT_SIZE) >= num_extents)
			return;
	}

	spin_lock(&BTRFS_I(inode)->lock);
	BTRFS_I(inode)->outstanding_extents++;
	spin_unlock(&BTRFS_I(inode)->lock);
}

static void btrfs_merge_extent_hook(struct inode *inode,
				    struct extent_state *new,
				    struct extent_state *other)
{
	u64 new_size, old_size;
	u64 num_extents;

	if (!(other->state & EXTENT_DELALLOC))
		return;

	if (new->start > other->start)
		new_size = new->end - other->start + 1;
	else
		new_size = other->end - new->start + 1;

	if (new_size <= BTRFS_MAX_EXTENT_SIZE) {
		spin_lock(&BTRFS_I(inode)->lock);
		BTRFS_I(inode)->outstanding_extents--;
		spin_unlock(&BTRFS_I(inode)->lock);
		return;
	}

	old_size = other->end - other->start + 1;
	num_extents = div64_u64(old_size + BTRFS_MAX_EXTENT_SIZE - 1,
				BTRFS_MAX_EXTENT_SIZE);
	old_size = new->end - new->start + 1;
	num_extents += div64_u64(old_size + BTRFS_MAX_EXTENT_SIZE - 1,
				 BTRFS_MAX_EXTENT_SIZE);

	if (div64_u64(new_size + BTRFS_MAX_EXTENT_SIZE - 1,
		      BTRFS_MAX_EXTENT_SIZE) >= num_extents)
		return;

	spin_lock(&BTRFS_I(inode)->lock);
	BTRFS_I(inode)->outstanding_extents--;
	spin_unlock(&BTRFS_I(inode)->lock);
}

static void btrfs_add_delalloc_inodes(struct btrfs_root *root,
				      struct inode *inode)
{
	spin_lock(&root->delalloc_lock);
	if (list_empty(&BTRFS_I(inode)->delalloc_inodes)) {
		list_add_tail(&BTRFS_I(inode)->delalloc_inodes,
			      &root->delalloc_inodes);
		set_bit(BTRFS_INODE_IN_DELALLOC_LIST,
			&BTRFS_I(inode)->runtime_flags);
		root->nr_delalloc_inodes++;
#ifdef MY_ABC_HERE
		root->fs_info->delalloc_inodes_nr++;
#endif  
		if (root->nr_delalloc_inodes == 1) {
			spin_lock(&root->fs_info->delalloc_root_lock);
			BUG_ON(!list_empty(&root->delalloc_root));
			list_add_tail(&root->delalloc_root,
				      &root->fs_info->delalloc_roots);
			spin_unlock(&root->fs_info->delalloc_root_lock);
		}
	}
	spin_unlock(&root->delalloc_lock);
}

static void btrfs_del_delalloc_inode(struct btrfs_root *root,
				     struct inode *inode)
{
	spin_lock(&root->delalloc_lock);
	if (!list_empty(&BTRFS_I(inode)->delalloc_inodes)) {
		list_del_init(&BTRFS_I(inode)->delalloc_inodes);
		clear_bit(BTRFS_INODE_IN_DELALLOC_LIST,
			  &BTRFS_I(inode)->runtime_flags);
		root->nr_delalloc_inodes--;
#ifdef MY_ABC_HERE
		root->fs_info->delalloc_inodes_nr--;
#endif  
		if (!root->nr_delalloc_inodes) {
			spin_lock(&root->fs_info->delalloc_root_lock);
			BUG_ON(list_empty(&root->delalloc_root));
			list_del_init(&root->delalloc_root);
			spin_unlock(&root->fs_info->delalloc_root_lock);
		}
	}
	spin_unlock(&root->delalloc_lock);
}

static void btrfs_set_bit_hook(struct inode *inode,
			       struct extent_state *state, unsigned *bits)
{

	if ((*bits & EXTENT_DEFRAG) && !(*bits & EXTENT_DELALLOC))
		WARN_ON(1);
	 
	if (!(state->state & EXTENT_DELALLOC) && (*bits & EXTENT_DELALLOC)) {
		struct btrfs_root *root = BTRFS_I(inode)->root;
		u64 len = state->end + 1 - state->start;
		bool do_list = !btrfs_is_free_space_inode(inode);

		if (*bits & EXTENT_FIRST_DELALLOC) {
			*bits &= ~EXTENT_FIRST_DELALLOC;
		} else {
			spin_lock(&BTRFS_I(inode)->lock);
			BTRFS_I(inode)->outstanding_extents++;
			spin_unlock(&BTRFS_I(inode)->lock);
		}

		if (btrfs_test_is_dummy_root(root))
			return;

		__percpu_counter_add(&root->fs_info->delalloc_bytes, len,
				     root->fs_info->delalloc_batch);
		spin_lock(&BTRFS_I(inode)->lock);
		BTRFS_I(inode)->delalloc_bytes += len;
		if (*bits & EXTENT_DEFRAG)
			BTRFS_I(inode)->defrag_bytes += len;
		if (do_list && !test_bit(BTRFS_INODE_IN_DELALLOC_LIST,
					 &BTRFS_I(inode)->runtime_flags))
			btrfs_add_delalloc_inodes(root, inode);
		spin_unlock(&BTRFS_I(inode)->lock);
	}
}

static void btrfs_clear_bit_hook(struct inode *inode,
				 struct extent_state *state,
				 unsigned *bits)
{
	u64 len = state->end + 1 - state->start;
	u64 num_extents = div64_u64(len + BTRFS_MAX_EXTENT_SIZE -1,
				    BTRFS_MAX_EXTENT_SIZE);

	spin_lock(&BTRFS_I(inode)->lock);
	if ((state->state & EXTENT_DEFRAG) && (*bits & EXTENT_DEFRAG))
		BTRFS_I(inode)->defrag_bytes -= len;
	spin_unlock(&BTRFS_I(inode)->lock);

	if ((state->state & EXTENT_DELALLOC) && (*bits & EXTENT_DELALLOC)) {
		struct btrfs_root *root = BTRFS_I(inode)->root;
		bool do_list = !btrfs_is_free_space_inode(inode);

		if (*bits & EXTENT_FIRST_DELALLOC) {
			*bits &= ~EXTENT_FIRST_DELALLOC;
		} else if (!(*bits & EXTENT_DO_ACCOUNTING)) {
			spin_lock(&BTRFS_I(inode)->lock);
			BTRFS_I(inode)->outstanding_extents -= num_extents;
			spin_unlock(&BTRFS_I(inode)->lock);
		}

		if (*bits & EXTENT_DO_ACCOUNTING &&
		    root != root->fs_info->tree_root)
			btrfs_delalloc_release_metadata(inode, len);

		if (btrfs_test_is_dummy_root(root))
			return;

		if (root->root_key.objectid != BTRFS_DATA_RELOC_TREE_OBJECTID
		    && do_list && !(state->state & EXTENT_NORESERVE))
			btrfs_free_reserved_data_space_noquota(inode,
					state->start, len);

		__percpu_counter_add(&root->fs_info->delalloc_bytes, -len,
				     root->fs_info->delalloc_batch);
		spin_lock(&BTRFS_I(inode)->lock);
		BTRFS_I(inode)->delalloc_bytes -= len;
		if (do_list && BTRFS_I(inode)->delalloc_bytes == 0 &&
		    test_bit(BTRFS_INODE_IN_DELALLOC_LIST,
			     &BTRFS_I(inode)->runtime_flags))
			btrfs_del_delalloc_inode(root, inode);
		spin_unlock(&BTRFS_I(inode)->lock);
	}
}

int btrfs_merge_bio_hook(int rw, struct page *page, unsigned long offset,
			 size_t size, struct bio *bio,
			 unsigned long bio_flags)
{
	struct btrfs_root *root = BTRFS_I(page->mapping->host)->root;
	u64 logical = (u64)bio->bi_iter.bi_sector << 9;
	u64 length = 0;
	u64 map_length;
	int ret;

	if (bio_flags & EXTENT_BIO_COMPRESSED)
		return 0;

	length = bio->bi_iter.bi_size;
	map_length = length;
	ret = btrfs_map_block(root->fs_info, rw, logical,
			      &map_length, NULL, 0);
	 
	BUG_ON(ret < 0);
	if (map_length < length + size)
		return 1;
	return 0;
}

static int __btrfs_submit_bio_start(struct inode *inode, int rw,
				    struct bio *bio, int mirror_num,
				    unsigned long bio_flags,
				    u64 bio_offset)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int ret = 0;

	ret = btrfs_csum_one_bio(root, inode, bio, 0, 0);
	BUG_ON(ret);  
	return 0;
}

static int __btrfs_submit_bio_done(struct inode *inode, int rw, struct bio *bio,
			  int mirror_num, unsigned long bio_flags,
			  u64 bio_offset)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int ret;

	ret = btrfs_map_bio(root, rw, bio, mirror_num, 1);
	if (ret) {
		bio->bi_error = ret;
		bio_endio(bio);
	}
	return ret;
}

static int btrfs_submit_bio_hook(struct inode *inode, int rw, struct bio *bio,
			  int mirror_num, unsigned long bio_flags,
			  u64 bio_offset)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	enum btrfs_wq_endio_type metadata = BTRFS_WQ_ENDIO_DATA;
	int ret = 0;
	int skip_sum;
	int async = !atomic_read(&BTRFS_I(inode)->sync_writers);

	skip_sum = BTRFS_I(inode)->flags & BTRFS_INODE_NODATASUM;

	if (btrfs_is_free_space_inode(inode))
		metadata = BTRFS_WQ_ENDIO_FREE_SPACE;

	if (!(rw & REQ_WRITE)) {
		ret = btrfs_bio_wq_end_io(root->fs_info, bio, metadata);
		if (ret)
			goto out;

		if (bio_flags & EXTENT_BIO_COMPRESSED) {
			ret = btrfs_submit_compressed_read(inode, bio,
							   mirror_num,
							   bio_flags);
			goto out;
		} else if (!skip_sum) {
			ret = btrfs_lookup_bio_sums(root, inode, bio, NULL);
			if (ret)
				goto out;
		}
		goto mapit;
	} else if (async && !skip_sum) {
		 
		if (root->root_key.objectid == BTRFS_DATA_RELOC_TREE_OBJECTID)
			goto mapit;
		 
		ret = btrfs_wq_submit_bio(BTRFS_I(inode)->root->fs_info,
				   inode, rw, bio, mirror_num,
				   bio_flags, bio_offset,
				   __btrfs_submit_bio_start,
				   __btrfs_submit_bio_done);
		goto out;
	} else if (!skip_sum) {
		ret = btrfs_csum_one_bio(root, inode, bio, 0, 0);
		if (ret)
			goto out;
	}

mapit:
	ret = btrfs_map_bio(root, rw, bio, mirror_num, 0);

out:
	if (ret < 0) {
		bio->bi_error = ret;
		bio_endio(bio);
	}
	return ret;
}

static noinline int add_pending_csums(struct btrfs_trans_handle *trans,
			     struct inode *inode, u64 file_offset,
			     struct list_head *list)
{
	struct btrfs_ordered_sum *sum;

	list_for_each_entry(sum, list, list) {
		trans->adding_csums = 1;
		btrfs_csum_file_blocks(trans,
		       BTRFS_I(inode)->root->fs_info->csum_root, sum);
		trans->adding_csums = 0;
	}
	return 0;
}

int btrfs_set_extent_delalloc(struct inode *inode, u64 start, u64 end,
			      struct extent_state **cached_state)
{
	WARN_ON((end & (PAGE_CACHE_SIZE - 1)) == 0);
	return set_extent_delalloc(&BTRFS_I(inode)->io_tree, start, end,
				   cached_state);
}

struct btrfs_writepage_fixup {
	struct page *page;
	struct btrfs_work work;
};

static void btrfs_writepage_fixup_worker(struct btrfs_work *work)
{
	struct btrfs_writepage_fixup *fixup;
	struct btrfs_ordered_extent *ordered;
	struct extent_state *cached_state = NULL;
	struct page *page;
	struct inode *inode;
	u64 page_start;
	u64 page_end;
	int ret;

	fixup = container_of(work, struct btrfs_writepage_fixup, work);
	page = fixup->page;
again:
	lock_page(page);
	if (!page->mapping || !PageDirty(page) || !PageChecked(page)) {
		ClearPageChecked(page);
		goto out_page;
	}

	inode = page->mapping->host;
	page_start = page_offset(page);
	page_end = page_offset(page) + PAGE_CACHE_SIZE - 1;

	lock_extent_bits(&BTRFS_I(inode)->io_tree, page_start, page_end,
			 &cached_state);

	if (PagePrivate2(page))
		goto out;

	ordered = btrfs_lookup_ordered_extent(inode, page_start);
	if (ordered) {
		unlock_extent_cached(&BTRFS_I(inode)->io_tree, page_start,
				     page_end, &cached_state, GFP_NOFS);
		unlock_page(page);
		btrfs_start_ordered_extent(inode, ordered, 1);
		btrfs_put_ordered_extent(ordered);
		goto again;
	}

	ret = btrfs_delalloc_reserve_space(inode, page_start,
					   PAGE_CACHE_SIZE);
	if (ret) {
		mapping_set_error(page->mapping, ret);
		end_extent_writepage(page, ret, page_start, page_end);
		ClearPageChecked(page);
		goto out;
	 }

	btrfs_set_extent_delalloc(inode, page_start, page_end, &cached_state);
	ClearPageChecked(page);
	set_page_dirty(page);
out:
	unlock_extent_cached(&BTRFS_I(inode)->io_tree, page_start, page_end,
			     &cached_state, GFP_NOFS);
out_page:
	unlock_page(page);
	page_cache_release(page);
	kfree(fixup);
}

static int btrfs_writepage_start_hook(struct page *page, u64 start, u64 end)
{
	struct inode *inode = page->mapping->host;
	struct btrfs_writepage_fixup *fixup;
	struct btrfs_root *root = BTRFS_I(inode)->root;

	if (TestClearPagePrivate2(page))
		return 0;

	if (PageChecked(page))
		return -EAGAIN;

	fixup = kzalloc(sizeof(*fixup), GFP_NOFS);
	if (!fixup)
		return -EAGAIN;

	SetPageChecked(page);
	page_cache_get(page);
	btrfs_init_work(&fixup->work, btrfs_fixup_helper,
			btrfs_writepage_fixup_worker, NULL, NULL);
	fixup->page = page;
	btrfs_queue_work(root->fs_info->fixup_workers, &fixup->work);
	return -EBUSY;
}

static int insert_reserved_file_extent(struct btrfs_trans_handle *trans,
				       struct inode *inode, u64 file_pos,
				       u64 disk_bytenr, u64 disk_num_bytes,
				       u64 num_bytes, u64 ram_bytes,
				       u8 compression, u8 encryption,
				       u16 other_encoding, int extent_type)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_file_extent_item *fi;
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	struct btrfs_key ins;
	int extent_inserted = 0;
	int ret;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	ret = __btrfs_drop_extents(trans, root, inode, path, file_pos,
				   file_pos + num_bytes, NULL, 0,
				   1, sizeof(*fi), &extent_inserted);
	if (ret)
		goto out;

	if (!extent_inserted) {
		ins.objectid = btrfs_ino(inode);
		ins.offset = file_pos;
		ins.type = BTRFS_EXTENT_DATA_KEY;

		path->leave_spinning = 1;
		ret = btrfs_insert_empty_item(trans, root, path, &ins,
					      sizeof(*fi));
		if (ret)
			goto out;
	}
	leaf = path->nodes[0];
	fi = btrfs_item_ptr(leaf, path->slots[0],
			    struct btrfs_file_extent_item);
	btrfs_set_file_extent_generation(leaf, fi, trans->transid);
	btrfs_set_file_extent_type(leaf, fi, extent_type);
	btrfs_set_file_extent_disk_bytenr(leaf, fi, disk_bytenr);
	btrfs_set_file_extent_disk_num_bytes(leaf, fi, disk_num_bytes);
	btrfs_set_file_extent_offset(leaf, fi, 0);
	btrfs_set_file_extent_num_bytes(leaf, fi, num_bytes);
	btrfs_set_file_extent_ram_bytes(leaf, fi, ram_bytes);
	btrfs_set_file_extent_compression(leaf, fi, compression);
	btrfs_set_file_extent_encryption(leaf, fi, encryption);
	btrfs_set_file_extent_other_encoding(leaf, fi, other_encoding);

	btrfs_mark_buffer_dirty(leaf);
	btrfs_release_path(path);

	inode_add_bytes(inode, num_bytes);

	ins.objectid = disk_bytenr;
	ins.offset = disk_num_bytes;
	ins.type = BTRFS_EXTENT_ITEM_KEY;
	ret = btrfs_alloc_reserved_file_extent(trans, root,
					root->root_key.objectid,
					btrfs_ino(inode), file_pos,
					ram_bytes, &ins);
	 
	btrfs_qgroup_release_data(inode, file_pos, ram_bytes);
out:
	btrfs_free_path(path);

	return ret;
}

struct sa_defrag_extent_backref {
	struct rb_node node;
	struct old_sa_defrag_extent *old;
	u64 root_id;
	u64 inum;
	u64 file_pos;
	u64 extent_offset;
	u64 num_bytes;
	u64 generation;
};

struct old_sa_defrag_extent {
	struct list_head list;
	struct new_sa_defrag_extent *new;

	u64 extent_offset;
	u64 bytenr;
	u64 offset;
	u64 len;
	int count;
};

struct new_sa_defrag_extent {
	struct rb_root root;
	struct list_head head;
	struct btrfs_path *path;
	struct inode *inode;
	u64 file_pos;
	u64 len;
	u64 bytenr;
	u64 disk_len;
	u8 compress_type;
};

static int backref_comp(struct sa_defrag_extent_backref *b1,
			struct sa_defrag_extent_backref *b2)
{
	if (b1->root_id < b2->root_id)
		return -1;
	else if (b1->root_id > b2->root_id)
		return 1;

	if (b1->inum < b2->inum)
		return -1;
	else if (b1->inum > b2->inum)
		return 1;

	if (b1->file_pos < b2->file_pos)
		return -1;
	else if (b1->file_pos > b2->file_pos)
		return 1;

	return 0;
}

static void backref_insert(struct rb_root *root,
			   struct sa_defrag_extent_backref *backref)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct sa_defrag_extent_backref *entry;
	int ret;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct sa_defrag_extent_backref, node);

		ret = backref_comp(backref, entry);
		if (ret < 0)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}

	rb_link_node(&backref->node, parent, p);
	rb_insert_color(&backref->node, root);
}

static noinline int record_one_backref(u64 inum, u64 offset, u64 root_id,
				       void *ctx)
{
	struct btrfs_file_extent_item *extent;
	struct btrfs_fs_info *fs_info;
	struct old_sa_defrag_extent *old = ctx;
	struct new_sa_defrag_extent *new = old->new;
	struct btrfs_path *path = new->path;
	struct btrfs_key key;
	struct btrfs_root *root;
	struct sa_defrag_extent_backref *backref;
	struct extent_buffer *leaf;
	struct inode *inode = new->inode;
	int slot;
	int ret;
	u64 extent_offset;
	u64 num_bytes;

	if (BTRFS_I(inode)->root->root_key.objectid == root_id &&
	    inum == btrfs_ino(inode))
		return 0;

	key.objectid = root_id;
	key.type = BTRFS_ROOT_ITEM_KEY;
	key.offset = (u64)-1;

	fs_info = BTRFS_I(inode)->root->fs_info;
	root = btrfs_read_fs_root_no_name(fs_info, &key);
	if (IS_ERR(root)) {
		if (PTR_ERR(root) == -ENOENT)
			return 0;
		WARN_ON(1);
		pr_debug("inum=%llu, offset=%llu, root_id=%llu\n",
			 inum, offset, root_id);
		return PTR_ERR(root);
	}

	key.objectid = inum;
	key.type = BTRFS_EXTENT_DATA_KEY;
	if (offset > (u64)-1 << 32)
		key.offset = 0;
	else
		key.offset = offset;

	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (WARN_ON(ret < 0))
		return ret;
	ret = 0;

	while (1) {
		cond_resched();

		leaf = path->nodes[0];
		slot = path->slots[0];

		if (slot >= btrfs_header_nritems(leaf)) {
			ret = btrfs_next_leaf(root, path);
			if (ret < 0) {
				goto out;
			} else if (ret > 0) {
				ret = 0;
				goto out;
			}
			continue;
		}

		path->slots[0]++;

		btrfs_item_key_to_cpu(leaf, &key, slot);

		if (key.objectid > inum)
			goto out;

		if (key.objectid < inum || key.type != BTRFS_EXTENT_DATA_KEY)
			continue;

		extent = btrfs_item_ptr(leaf, slot,
					struct btrfs_file_extent_item);

		if (btrfs_file_extent_disk_bytenr(leaf, extent) != old->bytenr)
			continue;

		if (key.offset != offset)
			continue;

		extent_offset = btrfs_file_extent_offset(leaf, extent);
		num_bytes = btrfs_file_extent_num_bytes(leaf, extent);

		if (extent_offset >= old->extent_offset + old->offset +
		    old->len || extent_offset + num_bytes <=
		    old->extent_offset + old->offset)
			continue;
		break;
	}

	backref = kmalloc(sizeof(*backref), GFP_NOFS);
	if (!backref) {
		ret = -ENOENT;
		goto out;
	}

	backref->root_id = root_id;
	backref->inum = inum;
	backref->file_pos = offset;
	backref->num_bytes = num_bytes;
	backref->extent_offset = extent_offset;
	backref->generation = btrfs_file_extent_generation(leaf, extent);
	backref->old = old;
	backref_insert(&new->root, backref);
	old->count++;
out:
	btrfs_release_path(path);
	WARN_ON(ret);
	return ret;
}

static noinline bool record_extent_backrefs(struct btrfs_path *path,
				   struct new_sa_defrag_extent *new)
{
	struct btrfs_fs_info *fs_info = BTRFS_I(new->inode)->root->fs_info;
	struct old_sa_defrag_extent *old, *tmp;
	int ret;

	new->path = path;

	list_for_each_entry_safe(old, tmp, &new->head, list) {
		ret = iterate_inodes_from_logical(old->bytenr +
						  old->extent_offset, fs_info,
						  path, record_one_backref,
						  old);
		if (ret < 0 && ret != -ENOENT)
			return false;

		if (!old->count) {
			list_del(&old->list);
			kfree(old);
		}
	}

	if (list_empty(&new->head))
		return false;

	return true;
}

static int relink_is_mergable(struct extent_buffer *leaf,
			      struct btrfs_file_extent_item *fi,
			      struct new_sa_defrag_extent *new)
{
	if (btrfs_file_extent_disk_bytenr(leaf, fi) != new->bytenr)
		return 0;

	if (btrfs_file_extent_type(leaf, fi) != BTRFS_FILE_EXTENT_REG)
		return 0;

	if (btrfs_file_extent_compression(leaf, fi) != new->compress_type)
		return 0;

	if (btrfs_file_extent_encryption(leaf, fi) ||
	    btrfs_file_extent_other_encoding(leaf, fi))
		return 0;

	return 1;
}

static noinline int relink_extent_backref(struct btrfs_path *path,
				 struct sa_defrag_extent_backref *prev,
				 struct sa_defrag_extent_backref *backref)
{
	struct btrfs_file_extent_item *extent;
	struct btrfs_file_extent_item *item;
	struct btrfs_ordered_extent *ordered;
	struct btrfs_trans_handle *trans;
	struct btrfs_fs_info *fs_info;
	struct btrfs_root *root;
	struct btrfs_key key;
	struct extent_buffer *leaf;
	struct old_sa_defrag_extent *old = backref->old;
	struct new_sa_defrag_extent *new = old->new;
	struct inode *src_inode = new->inode;
	struct inode *inode;
	struct extent_state *cached = NULL;
	int ret = 0;
	u64 start;
	u64 len;
	u64 lock_start;
	u64 lock_end;
	bool merge = false;
	int index;

	if (prev && prev->root_id == backref->root_id &&
	    prev->inum == backref->inum &&
	    prev->file_pos + prev->num_bytes == backref->file_pos)
		merge = true;

	key.objectid = backref->root_id;
	key.type = BTRFS_ROOT_ITEM_KEY;
	key.offset = (u64)-1;

	fs_info = BTRFS_I(src_inode)->root->fs_info;
	index = srcu_read_lock(&fs_info->subvol_srcu);

	root = btrfs_read_fs_root_no_name(fs_info, &key);
	if (IS_ERR(root)) {
		srcu_read_unlock(&fs_info->subvol_srcu, index);
		if (PTR_ERR(root) == -ENOENT)
			return 0;
		return PTR_ERR(root);
	}

	if (btrfs_root_readonly(root)) {
		srcu_read_unlock(&fs_info->subvol_srcu, index);
		return 0;
	}

	key.objectid = backref->inum;
	key.type = BTRFS_INODE_ITEM_KEY;
	key.offset = 0;

	inode = btrfs_iget(fs_info->sb, &key, root, NULL);
	if (IS_ERR(inode)) {
		srcu_read_unlock(&fs_info->subvol_srcu, index);
		return 0;
	}

	srcu_read_unlock(&fs_info->subvol_srcu, index);

	lock_start = backref->file_pos;
	lock_end = backref->file_pos + backref->num_bytes - 1;
	lock_extent_bits(&BTRFS_I(inode)->io_tree, lock_start, lock_end,
			 &cached);

	ordered = btrfs_lookup_first_ordered_extent(inode, lock_end);
	if (ordered) {
		btrfs_put_ordered_extent(ordered);
		goto out_unlock;
	}

	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out_unlock;
	}

	key.objectid = backref->inum;
	key.type = BTRFS_EXTENT_DATA_KEY;
	key.offset = backref->file_pos;

	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret < 0) {
		goto out_free_path;
	} else if (ret > 0) {
		ret = 0;
		goto out_free_path;
	}

	extent = btrfs_item_ptr(path->nodes[0], path->slots[0],
				struct btrfs_file_extent_item);

	if (btrfs_file_extent_generation(path->nodes[0], extent) !=
	    backref->generation)
		goto out_free_path;

	btrfs_release_path(path);

	start = backref->file_pos;
	if (backref->extent_offset < old->extent_offset + old->offset)
		start += old->extent_offset + old->offset -
			 backref->extent_offset;

	len = min(backref->extent_offset + backref->num_bytes,
		  old->extent_offset + old->offset + old->len);
	len -= max(backref->extent_offset, old->extent_offset + old->offset);

	ret = btrfs_drop_extents(trans, root, inode, start,
				 start + len, 1);
	if (ret)
		goto out_free_path;
again:
	key.objectid = btrfs_ino(inode);
	key.type = BTRFS_EXTENT_DATA_KEY;
	key.offset = start;

	path->leave_spinning = 1;
	if (merge) {
		struct btrfs_file_extent_item *fi;
		u64 extent_len;
		struct btrfs_key found_key;

		ret = btrfs_search_slot(trans, root, &key, path, 0, 1);
		if (ret < 0)
			goto out_free_path;

		path->slots[0]--;
		leaf = path->nodes[0];
		btrfs_item_key_to_cpu(leaf, &found_key, path->slots[0]);

		fi = btrfs_item_ptr(leaf, path->slots[0],
				    struct btrfs_file_extent_item);
		extent_len = btrfs_file_extent_num_bytes(leaf, fi);

		if (extent_len + found_key.offset == start &&
		    relink_is_mergable(leaf, fi, new)) {
			btrfs_set_file_extent_num_bytes(leaf, fi,
							extent_len + len);
			btrfs_mark_buffer_dirty(leaf);
			inode_add_bytes(inode, len);

			ret = 1;
			goto out_free_path;
		} else {
			merge = false;
			btrfs_release_path(path);
			goto again;
		}
	}

	ret = btrfs_insert_empty_item(trans, root, path, &key,
					sizeof(*extent));
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto out_free_path;
	}

	leaf = path->nodes[0];
	item = btrfs_item_ptr(leaf, path->slots[0],
				struct btrfs_file_extent_item);
	btrfs_set_file_extent_disk_bytenr(leaf, item, new->bytenr);
	btrfs_set_file_extent_disk_num_bytes(leaf, item, new->disk_len);
	btrfs_set_file_extent_offset(leaf, item, start - new->file_pos);
	btrfs_set_file_extent_num_bytes(leaf, item, len);
	btrfs_set_file_extent_ram_bytes(leaf, item, new->len);
	btrfs_set_file_extent_generation(leaf, item, trans->transid);
	btrfs_set_file_extent_type(leaf, item, BTRFS_FILE_EXTENT_REG);
	btrfs_set_file_extent_compression(leaf, item, new->compress_type);
	btrfs_set_file_extent_encryption(leaf, item, 0);
	btrfs_set_file_extent_other_encoding(leaf, item, 0);

	btrfs_mark_buffer_dirty(leaf);
	inode_add_bytes(inode, len);
	btrfs_release_path(path);

	ret = btrfs_inc_extent_ref(trans, root, new->bytenr,
			new->disk_len, 0,
			backref->root_id, backref->inum,
			new->file_pos);	 
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto out_free_path;
	}

	ret = 1;
out_free_path:
	btrfs_release_path(path);
	path->leave_spinning = 0;
	btrfs_end_transaction(trans, root);
out_unlock:
	unlock_extent_cached(&BTRFS_I(inode)->io_tree, lock_start, lock_end,
			     &cached, GFP_NOFS);
	iput(inode);
	return ret;
}

static void free_sa_defrag_extent(struct new_sa_defrag_extent *new)
{
	struct old_sa_defrag_extent *old, *tmp;

	if (!new)
		return;

	list_for_each_entry_safe(old, tmp, &new->head, list) {
		kfree(old);
	}
	kfree(new);
}

static void relink_file_extents(struct new_sa_defrag_extent *new)
{
	struct btrfs_path *path;
	struct sa_defrag_extent_backref *backref;
	struct sa_defrag_extent_backref *prev = NULL;
	struct inode *inode;
	struct btrfs_root *root;
	struct rb_node *node;
	int ret;

	inode = new->inode;
	root = BTRFS_I(inode)->root;

	path = btrfs_alloc_path();
	if (!path)
		return;

	if (!record_extent_backrefs(path, new)) {
		btrfs_free_path(path);
		goto out;
	}
	btrfs_release_path(path);

	while (1) {
		node = rb_first(&new->root);
		if (!node)
			break;
		rb_erase(node, &new->root);

		backref = rb_entry(node, struct sa_defrag_extent_backref, node);

		ret = relink_extent_backref(path, prev, backref);
		WARN_ON(ret < 0);

		kfree(prev);

		if (ret == 1)
			prev = backref;
		else
			prev = NULL;
		cond_resched();
	}
	kfree(prev);

	btrfs_free_path(path);
out:
	free_sa_defrag_extent(new);

	atomic_dec(&root->fs_info->defrag_running);
	wake_up(&root->fs_info->transaction_wait);
}

static struct new_sa_defrag_extent *
record_old_file_extents(struct inode *inode,
			struct btrfs_ordered_extent *ordered)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_path *path;
	struct btrfs_key key;
	struct old_sa_defrag_extent *old;
	struct new_sa_defrag_extent *new;
	int ret;

	new = kmalloc(sizeof(*new), GFP_NOFS);
	if (!new)
		return NULL;

	new->inode = inode;
	new->file_pos = ordered->file_offset;
	new->len = ordered->len;
	new->bytenr = ordered->start;
	new->disk_len = ordered->disk_len;
	new->compress_type = ordered->compress_type;
	new->root = RB_ROOT;
	INIT_LIST_HEAD(&new->head);

	path = btrfs_alloc_path();
	if (!path)
		goto out_kfree;

	key.objectid = btrfs_ino(inode);
	key.type = BTRFS_EXTENT_DATA_KEY;
	key.offset = new->file_pos;

	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret < 0)
		goto out_free_path;
	if (ret > 0 && path->slots[0] > 0)
		path->slots[0]--;

	while (1) {
		struct btrfs_file_extent_item *extent;
		struct extent_buffer *l;
		int slot;
		u64 num_bytes;
		u64 offset;
		u64 end;
		u64 disk_bytenr;
		u64 extent_offset;

		l = path->nodes[0];
		slot = path->slots[0];

		if (slot >= btrfs_header_nritems(l)) {
			ret = btrfs_next_leaf(root, path);
			if (ret < 0)
				goto out_free_path;
			else if (ret > 0)
				break;
			continue;
		}

		btrfs_item_key_to_cpu(l, &key, slot);

		if (key.objectid != btrfs_ino(inode))
			break;
		if (key.type != BTRFS_EXTENT_DATA_KEY)
			break;
		if (key.offset >= new->file_pos + new->len)
			break;

		extent = btrfs_item_ptr(l, slot, struct btrfs_file_extent_item);

		num_bytes = btrfs_file_extent_num_bytes(l, extent);
		if (key.offset + num_bytes < new->file_pos)
			goto next;

		disk_bytenr = btrfs_file_extent_disk_bytenr(l, extent);
		if (!disk_bytenr)
			goto next;

		extent_offset = btrfs_file_extent_offset(l, extent);

		old = kmalloc(sizeof(*old), GFP_NOFS);
		if (!old)
			goto out_free_path;

		offset = max(new->file_pos, key.offset);
		end = min(new->file_pos + new->len, key.offset + num_bytes);

		old->bytenr = disk_bytenr;
		old->extent_offset = extent_offset;
		old->offset = offset - key.offset;
		old->len = end - offset;
		old->new = new;
		old->count = 0;
		list_add_tail(&old->list, &new->head);
next:
		path->slots[0]++;
		cond_resched();
	}

	btrfs_free_path(path);
	atomic_inc(&root->fs_info->defrag_running);

	return new;

out_free_path:
	btrfs_free_path(path);
out_kfree:
	free_sa_defrag_extent(new);
	return NULL;
}

static void btrfs_release_delalloc_bytes(struct btrfs_root *root,
					 u64 start, u64 len)
{
	struct btrfs_block_group_cache *cache;

	cache = btrfs_lookup_block_group(root->fs_info, start);
	ASSERT(cache);

	spin_lock(&cache->lock);
	cache->delalloc_bytes -= len;
	spin_unlock(&cache->lock);

	btrfs_put_block_group(cache);
}

static int btrfs_finish_ordered_io(struct btrfs_ordered_extent *ordered_extent)
{
	struct inode *inode = ordered_extent->inode;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_trans_handle *trans = NULL;
	struct extent_io_tree *io_tree = &BTRFS_I(inode)->io_tree;
	struct extent_state *cached_state = NULL;
	struct new_sa_defrag_extent *new = NULL;
	int compress_type = 0;
	int ret = 0;
	u64 logical_len = ordered_extent->len;
	bool nolock;
	bool truncated = false;

	nolock = btrfs_is_free_space_inode(inode);

	if (test_bit(BTRFS_ORDERED_IOERR, &ordered_extent->flags)) {
		ret = -EIO;
		goto out;
	}

	btrfs_free_io_failure_record(inode, ordered_extent->file_offset,
				     ordered_extent->file_offset +
				     ordered_extent->len - 1);

	if (test_bit(BTRFS_ORDERED_TRUNCATED, &ordered_extent->flags)) {
		truncated = true;
		logical_len = ordered_extent->truncated_len;
		 
		if (!logical_len)
			goto out;
	}

	if (test_bit(BTRFS_ORDERED_NOCOW, &ordered_extent->flags)) {
		BUG_ON(!list_empty(&ordered_extent->list));  

		btrfs_qgroup_free_data(inode, ordered_extent->file_offset,
				       ordered_extent->len);
		btrfs_ordered_update_i_size(inode, 0, ordered_extent);
		if (nolock)
			trans = btrfs_join_transaction_nolock(root);
		else
			trans = btrfs_join_transaction(root);
		if (IS_ERR(trans)) {
			ret = PTR_ERR(trans);
			trans = NULL;
			goto out;
		}
		trans->block_rsv = &root->fs_info->delalloc_block_rsv;
		ret = btrfs_update_inode_fallback(trans, root, inode);
		if (ret)  
			btrfs_abort_transaction(trans, root, ret);
		goto out;
	}

	lock_extent_bits(io_tree, ordered_extent->file_offset,
			 ordered_extent->file_offset + ordered_extent->len - 1,
			 &cached_state);

	ret = test_range_bit(io_tree, ordered_extent->file_offset,
			ordered_extent->file_offset + ordered_extent->len - 1,
			EXTENT_DEFRAG, 1, cached_state);
	if (ret) {
		u64 last_snapshot = btrfs_root_last_snapshot(&root->root_item);
		if (0 && last_snapshot >= BTRFS_I(inode)->generation)
			 
			new = record_old_file_extents(inode, ordered_extent);

		clear_extent_bit(io_tree, ordered_extent->file_offset,
			ordered_extent->file_offset + ordered_extent->len - 1,
			EXTENT_DEFRAG, 0, 0, &cached_state, GFP_NOFS);
	}

	if (nolock)
		trans = btrfs_join_transaction_nolock(root);
	else
		trans = btrfs_join_transaction(root);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		trans = NULL;
		goto out_unlock;
	}

	trans->block_rsv = &root->fs_info->delalloc_block_rsv;

	if (test_bit(BTRFS_ORDERED_COMPRESSED, &ordered_extent->flags))
		compress_type = ordered_extent->compress_type;
	if (test_bit(BTRFS_ORDERED_PREALLOC, &ordered_extent->flags)) {
		BUG_ON(compress_type);
		ret = btrfs_mark_extent_written(trans, inode,
						ordered_extent->file_offset,
						ordered_extent->file_offset +
						logical_len);
	} else {
		BUG_ON(root == root->fs_info->tree_root);
		ret = insert_reserved_file_extent(trans, inode,
						ordered_extent->file_offset,
						ordered_extent->start,
						ordered_extent->disk_len,
						logical_len, logical_len,
						compress_type, 0, 0,
						BTRFS_FILE_EXTENT_REG);
		if (!ret)
			btrfs_release_delalloc_bytes(root,
						     ordered_extent->start,
						     ordered_extent->disk_len);
	}
	unpin_extent_cache(&BTRFS_I(inode)->extent_tree,
			   ordered_extent->file_offset, ordered_extent->len,
			   trans->transid);
	if (ret < 0) {
		btrfs_abort_transaction(trans, root, ret);
		goto out_unlock;
	}

	add_pending_csums(trans, inode, ordered_extent->file_offset,
			  &ordered_extent->list);

	btrfs_ordered_update_i_size(inode, 0, ordered_extent);
	ret = btrfs_update_inode_fallback(trans, root, inode);
	if (ret) {  
		btrfs_abort_transaction(trans, root, ret);
		goto out_unlock;
	}
	ret = 0;
out_unlock:
	unlock_extent_cached(io_tree, ordered_extent->file_offset,
			     ordered_extent->file_offset +
			     ordered_extent->len - 1, &cached_state, GFP_NOFS);
out:
	if (root != root->fs_info->tree_root)
		btrfs_delalloc_release_metadata(inode, ordered_extent->len);
	if (trans)
		btrfs_end_transaction(trans, root);

	if (ret || truncated) {
		u64 start, end;

		if (truncated)
			start = ordered_extent->file_offset + logical_len;
		else
			start = ordered_extent->file_offset;
		end = ordered_extent->file_offset + ordered_extent->len - 1;
		clear_extent_uptodate(io_tree, start, end, NULL, GFP_NOFS);

		btrfs_drop_extent_cache(inode, start, end, 0);

		if ((ret || !logical_len) &&
		    !test_bit(BTRFS_ORDERED_NOCOW, &ordered_extent->flags) &&
		    !test_bit(BTRFS_ORDERED_PREALLOC, &ordered_extent->flags))
			btrfs_free_reserved_extent(root, ordered_extent->start,
						   ordered_extent->disk_len, 1);
	}

	btrfs_remove_ordered_extent(inode, ordered_extent);

	if (new) {
		if (ret) {
			free_sa_defrag_extent(new);
			atomic_dec(&root->fs_info->defrag_running);
		} else {
			relink_file_extents(new);
		}
	}

	btrfs_put_ordered_extent(ordered_extent);
	 
	btrfs_put_ordered_extent(ordered_extent);

	return ret;
}

static void finish_ordered_fn(struct btrfs_work *work)
{
	struct btrfs_ordered_extent *ordered_extent;
	ordered_extent = container_of(work, struct btrfs_ordered_extent, work);
	btrfs_finish_ordered_io(ordered_extent);
}

static int btrfs_writepage_end_io_hook(struct page *page, u64 start, u64 end,
				struct extent_state *state, int uptodate)
{
	struct inode *inode = page->mapping->host;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_ordered_extent *ordered_extent = NULL;
	struct btrfs_workqueue *wq;
	btrfs_work_func_t func;

	trace_btrfs_writepage_end_io_hook(page, start, end, uptodate);

	ClearPagePrivate2(page);
	if (!btrfs_dec_test_ordered_pending(inode, &ordered_extent, start,
					    end - start + 1, uptodate))
		return 0;

	if (btrfs_is_free_space_inode(inode)) {
		wq = root->fs_info->endio_freespace_worker;
		func = btrfs_freespace_write_helper;
	} else {
		wq = root->fs_info->endio_write_workers;
		func = btrfs_endio_write_helper;
	}

	btrfs_init_work(&ordered_extent->work, func, finish_ordered_fn, NULL,
			NULL);
	btrfs_queue_work(wq, &ordered_extent->work);

	return 0;
}

static int __readpage_endio_check(struct inode *inode,
				  struct btrfs_io_bio *io_bio,
				  int icsum, struct page *page,
				  int pgoff, u64 start, size_t len)
{
	char *kaddr;
	u32 csum_expected;
	u32 csum = ~(u32)0;

	csum_expected = *(((u32 *)io_bio->csum) + icsum);

	kaddr = kmap_atomic(page);
	csum = btrfs_csum_data(kaddr + pgoff, csum,  len);
	btrfs_csum_final(csum, (char *)&csum);
	if (csum != csum_expected)
		goto zeroit;

	kunmap_atomic(kaddr);
	return 0;
zeroit:
	btrfs_warn_rl(BTRFS_I(inode)->root->fs_info,
		"csum failed ino %llu off %llu csum %u expected csum %u",
			   btrfs_ino(inode), start, csum, csum_expected);
	memset(kaddr + pgoff, 1, len);
	flush_dcache_page(page);
	kunmap_atomic(kaddr);
	if (csum_expected == 0)
		return 0;
	return -EIO;
}

static int btrfs_readpage_end_io_hook(struct btrfs_io_bio *io_bio,
				      u64 phy_offset, struct page *page,
				      u64 start, u64 end, int mirror)
{
	size_t offset = start - page_offset(page);
	struct inode *inode = page->mapping->host;
	struct extent_io_tree *io_tree = &BTRFS_I(inode)->io_tree;
	struct btrfs_root *root = BTRFS_I(inode)->root;

	if (PageChecked(page)) {
		ClearPageChecked(page);
		return 0;
	}

	if (BTRFS_I(inode)->flags & BTRFS_INODE_NODATASUM)
		return 0;

	if (root->root_key.objectid == BTRFS_DATA_RELOC_TREE_OBJECTID &&
	    test_range_bit(io_tree, start, end, EXTENT_NODATASUM, 1, NULL)) {
		clear_extent_bits(io_tree, start, end, EXTENT_NODATASUM);
		return 0;
	}

	phy_offset >>= inode->i_sb->s_blocksize_bits;
	return __readpage_endio_check(inode, io_bio, phy_offset, page, offset,
				      start, (size_t)(end - start + 1));
}

void btrfs_add_delayed_iput(struct inode *inode)
{
	struct btrfs_fs_info *fs_info = BTRFS_I(inode)->root->fs_info;
	struct btrfs_inode *binode = BTRFS_I(inode);

	if (atomic_add_unless(&inode->i_count, -1, 1))
		return;

	spin_lock(&fs_info->delayed_iput_lock);
	if (binode->delayed_iput_count == 0) {
		ASSERT(list_empty(&binode->delayed_iput));
		list_add_tail(&binode->delayed_iput, &fs_info->delayed_iputs);
	} else {
		binode->delayed_iput_count++;
	}
	spin_unlock(&fs_info->delayed_iput_lock);
}

void btrfs_run_delayed_iputs(struct btrfs_root *root)
{
	struct btrfs_fs_info *fs_info = root->fs_info;

	spin_lock(&fs_info->delayed_iput_lock);
	while (!list_empty(&fs_info->delayed_iputs)) {
		struct btrfs_inode *inode;

		inode = list_first_entry(&fs_info->delayed_iputs,
				struct btrfs_inode, delayed_iput);
		if (inode->delayed_iput_count) {
			inode->delayed_iput_count--;
			list_move_tail(&inode->delayed_iput,
					&fs_info->delayed_iputs);
		} else {
			list_del_init(&inode->delayed_iput);
		}
		spin_unlock(&fs_info->delayed_iput_lock);
		iput(&inode->vfs_inode);
		spin_lock(&fs_info->delayed_iput_lock);
	}
	spin_unlock(&fs_info->delayed_iput_lock);
}

void btrfs_orphan_commit_root(struct btrfs_trans_handle *trans,
			      struct btrfs_root *root)
{
	struct btrfs_block_rsv *block_rsv;
	int ret;

	if (atomic_read(&root->orphan_inodes) ||
	    root->orphan_cleanup_state != ORPHAN_CLEANUP_DONE)
		return;

	spin_lock(&root->orphan_lock);
	if (atomic_read(&root->orphan_inodes)) {
		spin_unlock(&root->orphan_lock);
		return;
	}

	if (root->orphan_cleanup_state != ORPHAN_CLEANUP_DONE) {
		spin_unlock(&root->orphan_lock);
		return;
	}

	block_rsv = root->orphan_block_rsv;
	root->orphan_block_rsv = NULL;
	spin_unlock(&root->orphan_lock);

	if (test_bit(BTRFS_ROOT_ORPHAN_ITEM_INSERTED, &root->state) &&
	    btrfs_root_refs(&root->root_item) > 0) {
		ret = btrfs_del_orphan_item(trans, root->fs_info->tree_root,
					    root->root_key.objectid);
		if (ret)
			btrfs_abort_transaction(trans, root, ret);
		else
			clear_bit(BTRFS_ROOT_ORPHAN_ITEM_INSERTED,
				  &root->state);
	}

	if (block_rsv) {
		WARN_ON(block_rsv->size > 0);
		btrfs_free_block_rsv(root, block_rsv);
	}
}

int btrfs_orphan_add(struct btrfs_trans_handle *trans, struct inode *inode)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_block_rsv *block_rsv = NULL;
	int reserve = 0;
	int insert = 0;
	int ret;

	if (!root->orphan_block_rsv) {
		block_rsv = btrfs_alloc_block_rsv(root, BTRFS_BLOCK_RSV_TEMP);
		if (!block_rsv)
			return -ENOMEM;
	}

	spin_lock(&root->orphan_lock);
	if (!root->orphan_block_rsv) {
		root->orphan_block_rsv = block_rsv;
	} else if (block_rsv) {
		btrfs_free_block_rsv(root, block_rsv);
		block_rsv = NULL;
	}

	if (!test_and_set_bit(BTRFS_INODE_HAS_ORPHAN_ITEM,
			      &BTRFS_I(inode)->runtime_flags)) {
#if 0
		 
		if (!xchg(&root->orphan_item_inserted, 1))
			insert = 2;
		else
			insert = 1;
#endif
		insert = 1;
		atomic_inc(&root->orphan_inodes);
	}

	if (!test_and_set_bit(BTRFS_INODE_ORPHAN_META_RESERVED,
			      &BTRFS_I(inode)->runtime_flags))
		reserve = 1;
	spin_unlock(&root->orphan_lock);

	if (reserve) {
		ret = btrfs_orphan_reserve_metadata(trans, inode);
		ASSERT(!ret);
		if (ret) {
			atomic_dec(&root->orphan_inodes);
			clear_bit(BTRFS_INODE_ORPHAN_META_RESERVED,
				  &BTRFS_I(inode)->runtime_flags);
			if (insert)
				clear_bit(BTRFS_INODE_HAS_ORPHAN_ITEM,
					  &BTRFS_I(inode)->runtime_flags);
			return ret;
		}
	}

	if (insert >= 1) {
		ret = btrfs_insert_orphan_item(trans, root, btrfs_ino(inode));
		if (ret) {
			atomic_dec(&root->orphan_inodes);
			if (reserve) {
				clear_bit(BTRFS_INODE_ORPHAN_META_RESERVED,
					  &BTRFS_I(inode)->runtime_flags);
				btrfs_orphan_release_metadata(inode);
			}
			if (ret != -EEXIST) {
				clear_bit(BTRFS_INODE_HAS_ORPHAN_ITEM,
					  &BTRFS_I(inode)->runtime_flags);
				btrfs_abort_transaction(trans, root, ret);
				return ret;
			}
		}
		ret = 0;
	}

	if (insert >= 2) {
		ret = btrfs_insert_orphan_item(trans, root->fs_info->tree_root,
					       root->root_key.objectid);
		if (ret && ret != -EEXIST) {
			btrfs_abort_transaction(trans, root, ret);
			return ret;
		}
	}
	return 0;
}

static int btrfs_orphan_del(struct btrfs_trans_handle *trans,
			    struct inode *inode)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int delete_item = 0;
	int release_rsv = 0;
	int ret = 0;

	spin_lock(&root->orphan_lock);
	if (test_and_clear_bit(BTRFS_INODE_HAS_ORPHAN_ITEM,
			       &BTRFS_I(inode)->runtime_flags))
		delete_item = 1;

	if (test_and_clear_bit(BTRFS_INODE_ORPHAN_META_RESERVED,
			       &BTRFS_I(inode)->runtime_flags))
		release_rsv = 1;
	spin_unlock(&root->orphan_lock);

	if (delete_item) {
		atomic_dec(&root->orphan_inodes);
		if (trans)
			ret = btrfs_del_orphan_item(trans, root,
						    btrfs_ino(inode));
	}

	if (release_rsv)
		btrfs_orphan_release_metadata(inode);

	return ret;
}

int btrfs_orphan_cleanup(struct btrfs_root *root)
{
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	struct btrfs_key key, found_key;
	struct btrfs_trans_handle *trans;
	struct inode *inode;
	u64 last_objectid = 0;
	int ret = 0, nr_unlink = 0, nr_truncate = 0;

	if (cmpxchg(&root->orphan_cleanup_state, 0, ORPHAN_CLEANUP_STARTED))
		return 0;

	path = btrfs_alloc_path();
	if (!path) {
		ret = -ENOMEM;
		goto out;
	}
	path->reada = READA_BACK;

	key.objectid = BTRFS_ORPHAN_OBJECTID;
	key.type = BTRFS_ORPHAN_ITEM_KEY;
	key.offset = (u64)-1;

	while (1) {
		ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
		if (ret < 0)
			goto out;

		if (ret > 0) {
			ret = 0;
			if (path->slots[0] == 0)
				break;
			path->slots[0]--;
		}

		leaf = path->nodes[0];
		btrfs_item_key_to_cpu(leaf, &found_key, path->slots[0]);

		if (found_key.objectid != BTRFS_ORPHAN_OBJECTID)
			break;
		if (found_key.type != BTRFS_ORPHAN_ITEM_KEY)
			break;

		btrfs_release_path(path);

		if (found_key.offset == last_objectid) {
			btrfs_err(root->fs_info,
				"Error removing orphan entry, stopping orphan cleanup");
			ret = -EINVAL;
			goto out;
		}

		last_objectid = found_key.offset;

		found_key.objectid = found_key.offset;
		found_key.type = BTRFS_INODE_ITEM_KEY;
		found_key.offset = 0;
		inode = btrfs_iget(root->fs_info->sb, &found_key, root, NULL);
		ret = PTR_ERR_OR_ZERO(inode);
		if (ret && ret != -ESTALE)
			goto out;

		if (ret == -ESTALE && root == root->fs_info->tree_root) {
			struct btrfs_root *dead_root;
			struct btrfs_fs_info *fs_info = root->fs_info;
			int is_dead_root = 0;

			spin_lock(&fs_info->trans_lock);
			list_for_each_entry(dead_root, &fs_info->dead_roots,
					    root_list) {
				if (dead_root->root_key.objectid ==
				    found_key.objectid) {
					is_dead_root = 1;
					break;
				}
			}
			spin_unlock(&fs_info->trans_lock);
			if (is_dead_root) {
				 
				key.offset = found_key.objectid - 1;
				continue;
			}
		}
		 
		if (ret == -ESTALE) {
			trans = btrfs_start_transaction(root, 1);
			if (IS_ERR(trans)) {
				ret = PTR_ERR(trans);
				goto out;
			}
			btrfs_debug(root->fs_info, "auto deleting %Lu",
				found_key.objectid);
			ret = btrfs_del_orphan_item(trans, root,
						    found_key.objectid);
			btrfs_end_transaction(trans, root);
			if (ret)
				goto out;
			continue;
		}

		set_bit(BTRFS_INODE_HAS_ORPHAN_ITEM,
			&BTRFS_I(inode)->runtime_flags);
		atomic_inc(&root->orphan_inodes);

		if (inode->i_nlink) {
			if (WARN_ON(!S_ISREG(inode->i_mode))) {
				iput(inode);
				continue;
			}
			nr_truncate++;

			trans = btrfs_start_transaction(root, 1);
			if (IS_ERR(trans)) {
				iput(inode);
				ret = PTR_ERR(trans);
				goto out;
			}
			ret = btrfs_orphan_add(trans, inode);
			btrfs_end_transaction(trans, root);
			if (ret) {
				iput(inode);
				goto out;
			}

			ret = btrfs_truncate(inode);
			if (ret)
				btrfs_orphan_del(NULL, inode);
		} else {
			nr_unlink++;
		}

		iput(inode);
		if (ret)
			goto out;
	}
	 
	btrfs_release_path(path);

	root->orphan_cleanup_state = ORPHAN_CLEANUP_DONE;

	if (root->orphan_block_rsv)
		btrfs_block_rsv_release(root, root->orphan_block_rsv,
					(u64)-1);

	if (root->orphan_block_rsv ||
	    test_bit(BTRFS_ROOT_ORPHAN_ITEM_INSERTED, &root->state)) {
		trans = btrfs_join_transaction(root);
		if (!IS_ERR(trans))
			btrfs_end_transaction(trans, root);
	}

	if (nr_unlink)
		btrfs_debug(root->fs_info, "unlinked %d orphans", nr_unlink);
	if (nr_truncate)
		btrfs_debug(root->fs_info, "truncated %d orphans", nr_truncate);

out:
	if (ret)
		btrfs_err(root->fs_info,
			"could not do orphan cleanup %d", ret);
	btrfs_free_path(path);
	return ret;
}

static noinline int acls_after_inode_item(struct extent_buffer *leaf,
					  int slot, u64 objectid,
					  int *first_xattr_slot)
{
	u32 nritems = btrfs_header_nritems(leaf);
	struct btrfs_key found_key;
	static u64 xattr_access = 0;
	static u64 xattr_default = 0;
	int scanned = 0;

	if (!xattr_access) {
		xattr_access = btrfs_name_hash(POSIX_ACL_XATTR_ACCESS,
					strlen(POSIX_ACL_XATTR_ACCESS));
		xattr_default = btrfs_name_hash(POSIX_ACL_XATTR_DEFAULT,
					strlen(POSIX_ACL_XATTR_DEFAULT));
	}

	slot++;
	*first_xattr_slot = -1;
	while (slot < nritems) {
		btrfs_item_key_to_cpu(leaf, &found_key, slot);

		if (found_key.objectid != objectid)
			return 0;

		if (found_key.type == BTRFS_XATTR_ITEM_KEY) {
			if (*first_xattr_slot == -1)
				*first_xattr_slot = slot;
			if (found_key.offset == xattr_access ||
			    found_key.offset == xattr_default)
				return 1;
		}

		if (found_key.type > BTRFS_XATTR_ITEM_KEY)
			return 0;

		slot++;
		scanned++;

		if (scanned >= 8)
			break;
	}
	 
	if (*first_xattr_slot == -1)
		*first_xattr_slot = slot;
	return 1;
}

static void btrfs_read_locked_inode(struct inode *inode)
{
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	struct btrfs_inode_item *inode_item;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_key location;
	unsigned long ptr;
	int maybe_acls;
	u32 rdev;
	int ret;
	bool filled = false;
	int first_xattr_slot;

	ret = btrfs_fill_inode(inode, &rdev);
	if (!ret)
		filled = true;

	path = btrfs_alloc_path();
	if (!path)
		goto make_bad;

	memcpy(&location, &BTRFS_I(inode)->location, sizeof(location));

	ret = btrfs_lookup_inode(NULL, root, path, &location, 0);
	if (ret)
		goto make_bad;

	leaf = path->nodes[0];

	if (filled)
		goto cache_index;

	inode_item = btrfs_item_ptr(leaf, path->slots[0],
				    struct btrfs_inode_item);
	inode->i_mode = btrfs_inode_mode(leaf, inode_item);
	set_nlink(inode, btrfs_inode_nlink(leaf, inode_item));
	i_uid_write(inode, btrfs_inode_uid(leaf, inode_item));
	i_gid_write(inode, btrfs_inode_gid(leaf, inode_item));
	btrfs_i_size_write(inode, btrfs_inode_size(leaf, inode_item));

	inode->i_atime.tv_sec = btrfs_timespec_sec(leaf, &inode_item->atime);
	inode->i_atime.tv_nsec = btrfs_timespec_nsec(leaf, &inode_item->atime);

	inode->i_mtime.tv_sec = btrfs_timespec_sec(leaf, &inode_item->mtime);
	inode->i_mtime.tv_nsec = btrfs_timespec_nsec(leaf, &inode_item->mtime);

	inode->i_ctime.tv_sec = btrfs_timespec_sec(leaf, &inode_item->ctime);
	inode->i_ctime.tv_nsec = btrfs_timespec_nsec(leaf, &inode_item->ctime);

	BTRFS_I(inode)->i_otime.tv_sec =
		btrfs_timespec_sec(leaf, &inode_item->otime);
	BTRFS_I(inode)->i_otime.tv_nsec =
		btrfs_timespec_nsec(leaf, &inode_item->otime);

	inode_set_bytes(inode, btrfs_inode_nbytes(leaf, inode_item));
	BTRFS_I(inode)->generation = btrfs_inode_generation(leaf, inode_item);
	BTRFS_I(inode)->last_trans = btrfs_inode_transid(leaf, inode_item);

	inode->i_version = btrfs_inode_sequence(leaf, inode_item);
	inode->i_generation = BTRFS_I(inode)->generation;
	inode->i_rdev = 0;
	rdev = btrfs_inode_rdev(leaf, inode_item);

	BTRFS_I(inode)->index_cnt = (u64)-1;
	BTRFS_I(inode)->flags = btrfs_inode_flags(leaf, inode_item);

cache_index:
	 
	if (BTRFS_I(inode)->last_trans == root->fs_info->generation)
		set_bit(BTRFS_INODE_NEEDS_FULL_SYNC,
			&BTRFS_I(inode)->runtime_flags);

	BTRFS_I(inode)->last_unlink_trans = BTRFS_I(inode)->last_trans;

	path->slots[0]++;
	if (inode->i_nlink != 1 ||
	    path->slots[0] >= btrfs_header_nritems(leaf))
		goto cache_acl;

	btrfs_item_key_to_cpu(leaf, &location, path->slots[0]);
	if (location.objectid != btrfs_ino(inode))
		goto cache_acl;

	ptr = btrfs_item_ptr_offset(leaf, path->slots[0]);
	if (location.type == BTRFS_INODE_REF_KEY) {
		struct btrfs_inode_ref *ref;

		ref = (struct btrfs_inode_ref *)ptr;
		BTRFS_I(inode)->dir_index = btrfs_inode_ref_index(leaf, ref);
	} else if (location.type == BTRFS_INODE_EXTREF_KEY) {
		struct btrfs_inode_extref *extref;

		extref = (struct btrfs_inode_extref *)ptr;
		BTRFS_I(inode)->dir_index = btrfs_inode_extref_index(leaf,
								     extref);
	}
cache_acl:
	 
	maybe_acls = acls_after_inode_item(leaf, path->slots[0],
					   btrfs_ino(inode), &first_xattr_slot);
	if (first_xattr_slot != -1) {
		path->slots[0] = first_xattr_slot;
		ret = btrfs_load_inode_props(inode, path);
		if (ret)
			btrfs_err(root->fs_info,
				  "error loading props for ino %llu (root %llu): %d",
				  btrfs_ino(inode),
				  root->root_key.objectid, ret);
	}
	btrfs_free_path(path);

	if (!maybe_acls)
		cache_no_acl(inode);

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		inode->i_mapping->a_ops = &btrfs_aops;
		BTRFS_I(inode)->io_tree.ops = &btrfs_extent_io_ops;
		inode->i_fop = &btrfs_file_operations;
		inode->i_op = &btrfs_file_inode_operations;
		break;
	case S_IFDIR:
		inode->i_fop = &btrfs_dir_file_operations;
		if (root == root->fs_info->tree_root)
			inode->i_op = &btrfs_dir_ro_inode_operations;
		else
			inode->i_op = &btrfs_dir_inode_operations;
		break;
	case S_IFLNK:
		inode->i_op = &btrfs_symlink_inode_operations;
		inode->i_mapping->a_ops = &btrfs_symlink_aops;
		break;
	default:
		inode->i_op = &btrfs_special_inode_operations;
		init_special_inode(inode, inode->i_mode, rdev);
		break;
	}

	btrfs_update_iflags(inode);
	return;

make_bad:
	btrfs_free_path(path);
	make_bad_inode(inode);
}

static void fill_inode_item(struct btrfs_trans_handle *trans,
			    struct extent_buffer *leaf,
			    struct btrfs_inode_item *item,
			    struct inode *inode)
{
	struct btrfs_map_token token;

	btrfs_init_map_token(&token);

	btrfs_set_token_inode_uid(leaf, item, i_uid_read(inode), &token);
	btrfs_set_token_inode_gid(leaf, item, i_gid_read(inode), &token);
	btrfs_set_token_inode_size(leaf, item, BTRFS_I(inode)->disk_i_size,
				   &token);
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

	btrfs_set_token_timespec_sec(leaf, &item->otime,
				     BTRFS_I(inode)->i_otime.tv_sec, &token);
	btrfs_set_token_timespec_nsec(leaf, &item->otime,
				      BTRFS_I(inode)->i_otime.tv_nsec, &token);

	btrfs_set_token_inode_nbytes(leaf, item, inode_get_bytes(inode),
				     &token);
	btrfs_set_token_inode_generation(leaf, item, BTRFS_I(inode)->generation,
					 &token);
	btrfs_set_token_inode_sequence(leaf, item, inode->i_version, &token);
	btrfs_set_token_inode_transid(leaf, item, trans->transid, &token);
	btrfs_set_token_inode_rdev(leaf, item, inode->i_rdev, &token);
	btrfs_set_token_inode_flags(leaf, item, BTRFS_I(inode)->flags, &token);
	btrfs_set_token_inode_block_group(leaf, item, 0, &token);
}

static noinline int btrfs_update_inode_item(struct btrfs_trans_handle *trans,
				struct btrfs_root *root, struct inode *inode)
{
	struct btrfs_inode_item *inode_item;
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	int ret;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	path->leave_spinning = 1;
	ret = btrfs_lookup_inode(trans, root, path, &BTRFS_I(inode)->location,
				 1);
	if (ret) {
		if (ret > 0)
			ret = -ENOENT;
		goto failed;
	}

	leaf = path->nodes[0];
	inode_item = btrfs_item_ptr(leaf, path->slots[0],
				    struct btrfs_inode_item);

	fill_inode_item(trans, leaf, inode_item, inode);
	btrfs_mark_buffer_dirty(leaf);
	btrfs_set_inode_last_trans(trans, inode);
	ret = 0;
failed:
	btrfs_free_path(path);
	return ret;
}

noinline int btrfs_update_inode(struct btrfs_trans_handle *trans,
				struct btrfs_root *root, struct inode *inode)
{
	int ret;

	if (!btrfs_is_free_space_inode(inode)
	    && root->root_key.objectid != BTRFS_DATA_RELOC_TREE_OBJECTID
	    && !root->fs_info->log_root_recovering) {
		btrfs_update_root_times(trans, root);

		ret = btrfs_delayed_update_inode(trans, root, inode);
		if (!ret)
			btrfs_set_inode_last_trans(trans, inode);
		return ret;
	}

	return btrfs_update_inode_item(trans, root, inode);
}

noinline int btrfs_update_inode_fallback(struct btrfs_trans_handle *trans,
					 struct btrfs_root *root,
					 struct inode *inode)
{
	int ret;

	ret = btrfs_update_inode(trans, root, inode);
	if (ret == -ENOSPC)
		return btrfs_update_inode_item(trans, root, inode);
	return ret;
}

static int __btrfs_unlink_inode(struct btrfs_trans_handle *trans,
				struct btrfs_root *root,
				struct inode *dir, struct inode *inode,
				const char *name, int name_len)
{
	struct btrfs_path *path;
	int ret = 0;
	struct extent_buffer *leaf;
	struct btrfs_dir_item *di;
	struct btrfs_key key;
	u64 index;
	u64 ino = btrfs_ino(inode);
	u64 dir_ino = btrfs_ino(dir);

	path = btrfs_alloc_path();
	if (!path) {
		ret = -ENOMEM;
		goto out;
	}

	path->leave_spinning = 1;
	di = btrfs_lookup_dir_item(trans, root, path, dir_ino,
				    name, name_len, -1);
	if (IS_ERR(di)) {
		ret = PTR_ERR(di);
		goto err;
	}
	if (!di) {
		ret = -ENOENT;
		goto err;
	}
	leaf = path->nodes[0];
	btrfs_dir_item_key_to_cpu(leaf, di, &key);
	ret = btrfs_delete_one_dir_name(trans, root, path, di);
	if (ret)
		goto err;
	btrfs_release_path(path);

	if (BTRFS_I(inode)->dir_index) {
		ret = btrfs_delayed_delete_inode_ref(inode);
		if (!ret) {
			index = BTRFS_I(inode)->dir_index;
			goto skip_backref;
		}
	}

	ret = btrfs_del_inode_ref(trans, root, name, name_len, ino,
				  dir_ino, &index);
	if (ret) {
		btrfs_info(root->fs_info,
			"failed to delete reference to %.*s, inode %llu parent %llu",
			name_len, name, ino, dir_ino);
		btrfs_abort_transaction(trans, root, ret);
		goto err;
	}
skip_backref:
	ret = btrfs_delete_delayed_dir_index(trans, root, dir, index);
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto err;
	}

	ret = btrfs_del_inode_ref_in_log(trans, root, name, name_len,
					 inode, dir_ino);
	if (ret != 0 && ret != -ENOENT) {
		btrfs_abort_transaction(trans, root, ret);
		goto err;
	}

	ret = btrfs_del_dir_entries_in_log(trans, root, name, name_len,
					   dir, index);
	if (ret == -ENOENT)
		ret = 0;
	else if (ret)
		btrfs_abort_transaction(trans, root, ret);
err:
	btrfs_free_path(path);
	if (ret)
		goto out;

	btrfs_i_size_write(dir, dir->i_size - name_len * 2);
	inode_inc_iversion(inode);
	inode_inc_iversion(dir);
	inode->i_ctime = dir->i_mtime =
		dir->i_ctime = current_fs_time(inode->i_sb);
	ret = btrfs_update_inode(trans, root, dir);
out:
	return ret;
}

int btrfs_unlink_inode(struct btrfs_trans_handle *trans,
		       struct btrfs_root *root,
		       struct inode *dir, struct inode *inode,
		       const char *name, int name_len)
{
	int ret;
	ret = __btrfs_unlink_inode(trans, root, dir, inode, name, name_len);
	if (!ret) {
		drop_nlink(inode);
		ret = btrfs_update_inode(trans, root, inode);
	}
	return ret;
}

static struct btrfs_trans_handle *__unlink_start_trans(struct inode *dir)
{
	struct btrfs_root *root = BTRFS_I(dir)->root;

	return btrfs_start_transaction_fallback_global_rsv(root, 5, 5);
}

static int btrfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct btrfs_root *root = BTRFS_I(dir)->root;
	struct btrfs_trans_handle *trans;
	struct inode *inode = d_inode(dentry);
	int ret;

	trans = __unlink_start_trans(dir);
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	btrfs_record_unlink_dir(trans, dir, d_inode(dentry), 0);

	ret = btrfs_unlink_inode(trans, root, dir, d_inode(dentry),
				 dentry->d_name.name, dentry->d_name.len);
	if (ret)
		goto out;

	if (inode->i_nlink == 0) {
		ret = btrfs_orphan_add(trans, inode);
		if (ret)
			goto out;
	}

out:
	btrfs_end_transaction(trans, root);
	btrfs_btree_balance_dirty(root);
	return ret;
}

int btrfs_unlink_subvol(struct btrfs_trans_handle *trans,
			struct btrfs_root *root,
			struct inode *dir, u64 objectid,
			const char *name, int name_len)
{
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	struct btrfs_dir_item *di;
	struct btrfs_key key;
	u64 index;
	int ret;
	u64 dir_ino = btrfs_ino(dir);

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	di = btrfs_lookup_dir_item(trans, root, path, dir_ino,
				   name, name_len, -1);
	if (IS_ERR_OR_NULL(di)) {
		if (!di)
			ret = -ENOENT;
		else
			ret = PTR_ERR(di);
		goto out;
	}

	leaf = path->nodes[0];
	btrfs_dir_item_key_to_cpu(leaf, di, &key);
	WARN_ON(key.type != BTRFS_ROOT_ITEM_KEY || key.objectid != objectid);
	ret = btrfs_delete_one_dir_name(trans, root, path, di);
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto out;
	}
	btrfs_release_path(path);

	ret = btrfs_del_root_ref(trans, root->fs_info->tree_root,
				 objectid, root->root_key.objectid,
				 dir_ino, &index, name, name_len);
	if (ret < 0) {
		if (ret != -ENOENT) {
			btrfs_abort_transaction(trans, root, ret);
			goto out;
		}
		di = btrfs_search_dir_index_item(root, path, dir_ino,
						 name, name_len);
		if (IS_ERR_OR_NULL(di)) {
			if (!di)
				ret = -ENOENT;
			else
				ret = PTR_ERR(di);
			btrfs_abort_transaction(trans, root, ret);
			goto out;
		}

		leaf = path->nodes[0];
		btrfs_item_key_to_cpu(leaf, &key, path->slots[0]);
		btrfs_release_path(path);
		index = key.offset;
	}
	btrfs_release_path(path);

	ret = btrfs_delete_delayed_dir_index(trans, root, dir, index);
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto out;
	}

	btrfs_i_size_write(dir, dir->i_size - name_len * 2);
	inode_inc_iversion(dir);
	dir->i_mtime = dir->i_ctime = current_fs_time(dir->i_sb);
	ret = btrfs_update_inode_fallback(trans, root, dir);
	if (ret)
		btrfs_abort_transaction(trans, root, ret);
out:
	btrfs_free_path(path);
	return ret;
}

static int btrfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	int err = 0;
	struct btrfs_root *root = BTRFS_I(dir)->root;
	struct btrfs_trans_handle *trans;

	if (inode->i_size > BTRFS_EMPTY_DIR_SIZE)
		return -ENOTEMPTY;
	if (btrfs_ino(inode) == BTRFS_FIRST_FREE_OBJECTID)
		return -EPERM;

	trans = __unlink_start_trans(dir);
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	if (unlikely(btrfs_ino(inode) == BTRFS_EMPTY_SUBVOL_DIR_OBJECTID)) {
		err = btrfs_unlink_subvol(trans, root, dir,
					  BTRFS_I(inode)->location.objectid,
					  dentry->d_name.name,
					  dentry->d_name.len);
		goto out;
	}

	err = btrfs_orphan_add(trans, inode);
	if (err)
		goto out;

	err = btrfs_unlink_inode(trans, root, dir, d_inode(dentry),
				 dentry->d_name.name, dentry->d_name.len);
	if (!err)
		btrfs_i_size_write(inode, 0);
out:
	btrfs_end_transaction(trans, root);
	btrfs_btree_balance_dirty(root);

	return err;
}

static int truncate_space_check(struct btrfs_trans_handle *trans,
				struct btrfs_root *root,
				u64 bytes_deleted)
{
	int ret;

	bytes_deleted = btrfs_csum_bytes_to_leaves(root, bytes_deleted);
	bytes_deleted *= root->nodesize;
	ret = btrfs_block_rsv_add(root, &root->fs_info->trans_block_rsv,
				  bytes_deleted, BTRFS_RESERVE_NO_FLUSH);
	if (!ret) {
		trace_btrfs_space_reservation(root->fs_info, "transaction",
					      trans->transid,
					      bytes_deleted, 1);
		trans->bytes_reserved += bytes_deleted;
	}
	return ret;

}

static int truncate_inline_extent(struct inode *inode,
				  struct btrfs_path *path,
				  struct btrfs_key *found_key,
				  const u64 item_end,
				  const u64 new_size)
{
	struct extent_buffer *leaf = path->nodes[0];
	int slot = path->slots[0];
	struct btrfs_file_extent_item *fi;
	u32 size = (u32)(new_size - found_key->offset);
	struct btrfs_root *root = BTRFS_I(inode)->root;

	fi = btrfs_item_ptr(leaf, slot, struct btrfs_file_extent_item);

	if (btrfs_file_extent_compression(leaf, fi) != BTRFS_COMPRESS_NONE) {
		loff_t offset = new_size;
		loff_t page_end = ALIGN(offset, PAGE_CACHE_SIZE);

		btrfs_release_path(path);
		return btrfs_truncate_page(inode, offset, page_end - offset, 0);
	}

	btrfs_set_file_extent_ram_bytes(leaf, fi, size);
	size = btrfs_file_extent_calc_inline_size(size);
	btrfs_truncate_item(root, path, size, 1);

	if (test_bit(BTRFS_ROOT_REF_COWS, &root->state))
		inode_sub_bytes(inode, item_end + 1 - new_size);

	return 0;
}

int btrfs_truncate_inode_items(struct btrfs_trans_handle *trans,
			       struct btrfs_root *root,
			       struct inode *inode,
			       u64 new_size, u32 min_type)
{
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	struct btrfs_file_extent_item *fi;
	struct btrfs_key key;
	struct btrfs_key found_key;
	u64 extent_start = 0;
	u64 extent_num_bytes = 0;
	u64 extent_offset = 0;
	u64 item_end = 0;
	u64 last_size = new_size;
	u32 found_type = (u8)-1;
	int found_extent;
	int del_item;
	int pending_del_nr = 0;
	int pending_del_slot = 0;
	int extent_type = -1;
	int ret;
	int err = 0;
	u64 ino = btrfs_ino(inode);
	u64 bytes_deleted = 0;
	bool be_nice = 0;
	bool should_throttle = 0;
	bool should_end = 0;

	BUG_ON(new_size > 0 && min_type != BTRFS_EXTENT_DATA_KEY);

	if (!btrfs_is_free_space_inode(inode) &&
	    test_bit(BTRFS_ROOT_REF_COWS, &root->state))
		be_nice = 1;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;
	path->reada = READA_BACK;

	if (test_bit(BTRFS_ROOT_REF_COWS, &root->state) ||
	    root == root->fs_info->tree_root)
		btrfs_drop_extent_cache(inode, ALIGN(new_size,
					root->sectorsize), (u64)-1, 0);

	if (min_type == 0 && root == BTRFS_I(inode)->root)
		btrfs_kill_delayed_inode_items(inode);

	key.objectid = ino;
	key.offset = (u64)-1;
	key.type = (u8)-1;

search_again:
	 
	if (be_nice && bytes_deleted > SZ_32M) {
		if (btrfs_should_end_transaction(trans, root)) {
			err = -EAGAIN;
			goto error;
		}
	}

	path->leave_spinning = 1;
	ret = btrfs_search_slot(trans, root, &key, path, -1, 1);
	if (ret < 0) {
		err = ret;
		goto out;
	}

	if (ret > 0) {
		 
		if (path->slots[0] == 0)
			goto out;
		path->slots[0]--;
	}

	while (1) {
		fi = NULL;
		leaf = path->nodes[0];
		btrfs_item_key_to_cpu(leaf, &found_key, path->slots[0]);
		found_type = found_key.type;

		if (found_key.objectid != ino)
			break;

		if (found_type < min_type)
			break;

		item_end = found_key.offset;
		if (found_type == BTRFS_EXTENT_DATA_KEY) {
			fi = btrfs_item_ptr(leaf, path->slots[0],
					    struct btrfs_file_extent_item);
			extent_type = btrfs_file_extent_type(leaf, fi);
			if (extent_type != BTRFS_FILE_EXTENT_INLINE) {
				item_end +=
				    btrfs_file_extent_num_bytes(leaf, fi);
			} else if (extent_type == BTRFS_FILE_EXTENT_INLINE) {
				item_end += btrfs_file_extent_inline_len(leaf,
							 path->slots[0], fi);
			}
			item_end--;
		}
		if (found_type > min_type) {
			del_item = 1;
		} else {
			if (item_end < new_size)
				break;
			if (found_key.offset >= new_size)
				del_item = 1;
			else
				del_item = 0;
		}
		found_extent = 0;
		 
		if (found_type != BTRFS_EXTENT_DATA_KEY)
			goto delete;

		if (del_item)
			last_size = found_key.offset;
		else
			last_size = new_size;

		if (extent_type != BTRFS_FILE_EXTENT_INLINE) {
			u64 num_dec;
			extent_start = btrfs_file_extent_disk_bytenr(leaf, fi);
			if (!del_item) {
				u64 orig_num_bytes =
					btrfs_file_extent_num_bytes(leaf, fi);
				extent_num_bytes = ALIGN(new_size -
						found_key.offset,
						root->sectorsize);
				btrfs_set_file_extent_num_bytes(leaf, fi,
							 extent_num_bytes);
				num_dec = (orig_num_bytes -
					   extent_num_bytes);
				if (test_bit(BTRFS_ROOT_REF_COWS,
					     &root->state) &&
				    extent_start != 0)
					inode_sub_bytes(inode, num_dec);
				btrfs_mark_buffer_dirty(leaf);
			} else {
				extent_num_bytes =
					btrfs_file_extent_disk_num_bytes(leaf,
									 fi);
				extent_offset = found_key.offset -
					btrfs_file_extent_offset(leaf, fi);

				num_dec = btrfs_file_extent_num_bytes(leaf, fi);
				if (extent_start != 0) {
					found_extent = 1;
					if (test_bit(BTRFS_ROOT_REF_COWS,
						     &root->state))
						inode_sub_bytes(inode, num_dec);
				}
			}
		} else if (extent_type == BTRFS_FILE_EXTENT_INLINE) {
			 
			if (!del_item &&
			    btrfs_file_extent_encryption(leaf, fi) == 0 &&
			    btrfs_file_extent_other_encoding(leaf, fi) == 0) {

				if (btrfs_file_extent_compression(leaf, fi) !=
				    BTRFS_COMPRESS_NONE && pending_del_nr) {
					err = btrfs_del_items(trans, root, path,
							      pending_del_slot,
							      pending_del_nr);
					if (err) {
						btrfs_abort_transaction(trans,
									root,
									err);
						goto error;
					}
					pending_del_nr = 0;
				}

				err = truncate_inline_extent(inode, path,
							     &found_key,
							     item_end,
							     new_size);
				if (err) {
					btrfs_abort_transaction(trans,
								root, err);
					goto error;
				}
			} else if (test_bit(BTRFS_ROOT_REF_COWS,
					    &root->state)) {
				inode_sub_bytes(inode, item_end + 1 - new_size);
			}
		}
delete:
		if (del_item) {
			if (!pending_del_nr) {
				 
				pending_del_slot = path->slots[0];
				pending_del_nr = 1;
			} else if (pending_del_nr &&
				   path->slots[0] + 1 == pending_del_slot) {
				 
				pending_del_nr++;
				pending_del_slot = path->slots[0];
			} else {
				BUG();
			}
		} else {
			break;
		}
		should_throttle = 0;

		if (found_extent &&
		    (test_bit(BTRFS_ROOT_REF_COWS, &root->state) ||
		     root == root->fs_info->tree_root)) {
			btrfs_set_path_blocking(path);
			bytes_deleted += extent_num_bytes;
			ret = btrfs_free_extent(trans, root, extent_start,
						extent_num_bytes, 0,
						btrfs_header_owner(leaf),
						ino, extent_offset);
			BUG_ON(ret);
			if (btrfs_should_throttle_delayed_refs(trans, root))
				btrfs_async_run_delayed_refs(root,
					trans->delayed_ref_updates * 2,
					trans->transid, 0);
			if (be_nice) {
				if (truncate_space_check(trans, root,
							 extent_num_bytes)) {
					should_end = 1;
				}
				if (btrfs_should_throttle_delayed_refs(trans,
								       root)) {
					should_throttle = 1;
				}
			}
		}

		if (found_type == BTRFS_INODE_ITEM_KEY)
			break;

		if (path->slots[0] == 0 ||
		    path->slots[0] != pending_del_slot ||
		    should_throttle || should_end) {
			if (pending_del_nr) {
				ret = btrfs_del_items(trans, root, path,
						pending_del_slot,
						pending_del_nr);
				if (ret) {
					btrfs_abort_transaction(trans,
								root, ret);
					goto error;
				}
				pending_del_nr = 0;
			}
			btrfs_release_path(path);
			if (should_throttle) {
				unsigned long updates = trans->delayed_ref_updates;
				if (updates) {
					trans->delayed_ref_updates = 0;
					ret = btrfs_run_delayed_refs(trans, root, updates * 2);
					if (ret && !err)
						err = ret;
				}
			}
			 
			if (should_end) {
				err = -EAGAIN;
				goto error;
			}
			goto search_again;
		} else {
			path->slots[0]--;
		}
	}
out:
	if (pending_del_nr) {
		ret = btrfs_del_items(trans, root, path, pending_del_slot,
				      pending_del_nr);
		if (ret)
			btrfs_abort_transaction(trans, root, ret);
	}
error:
	if (root->root_key.objectid != BTRFS_TREE_LOG_OBJECTID)
		btrfs_ordered_update_i_size(inode, last_size, NULL);

	btrfs_free_path(path);

	if (be_nice && bytes_deleted > SZ_32M) {
		unsigned long updates = trans->delayed_ref_updates;
		if (updates) {
			trans->delayed_ref_updates = 0;
			ret = btrfs_run_delayed_refs(trans, root, updates * 2);
			if (ret && !err)
				err = ret;
		}
	}
	return err;
}

int btrfs_truncate_page(struct inode *inode, loff_t from, loff_t len,
			int front)
{
	struct address_space *mapping = inode->i_mapping;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct extent_io_tree *io_tree = &BTRFS_I(inode)->io_tree;
	struct btrfs_ordered_extent *ordered;
	struct extent_state *cached_state = NULL;
	char *kaddr;
	u32 blocksize = root->sectorsize;
	pgoff_t index = from >> PAGE_CACHE_SHIFT;
	unsigned offset = from & (PAGE_CACHE_SIZE-1);
	struct page *page;
	gfp_t mask = btrfs_alloc_write_mask(mapping);
	int ret = 0;
	u64 page_start;
	u64 page_end;

	if ((offset & (blocksize - 1)) == 0 &&
	    (!len || ((len & (blocksize - 1)) == 0)))
		goto out;
	ret = btrfs_delalloc_reserve_space(inode,
			round_down(from, PAGE_CACHE_SIZE), PAGE_CACHE_SIZE);
	if (ret)
		goto out;

again:
	page = find_or_create_page(mapping, index, mask);
	if (!page) {
		btrfs_delalloc_release_space(inode,
				round_down(from, PAGE_CACHE_SIZE),
				PAGE_CACHE_SIZE);
		ret = -ENOMEM;
		goto out;
	}

	page_start = page_offset(page);
	page_end = page_start + PAGE_CACHE_SIZE - 1;

	if (!PageUptodate(page)) {
		ret = btrfs_readpage(NULL, page);
		lock_page(page);
		if (page->mapping != mapping) {
			unlock_page(page);
			page_cache_release(page);
			goto again;
		}
		if (!PageUptodate(page)) {
			ret = -EIO;
			goto out_unlock;
		}
	}
	wait_on_page_writeback(page);

	lock_extent_bits(io_tree, page_start, page_end, &cached_state);
	set_page_extent_mapped(page);

	ordered = btrfs_lookup_ordered_extent(inode, page_start);
	if (ordered) {
		unlock_extent_cached(io_tree, page_start, page_end,
				     &cached_state, GFP_NOFS);
		unlock_page(page);
		page_cache_release(page);
		btrfs_start_ordered_extent(inode, ordered, 1);
		btrfs_put_ordered_extent(ordered);
		goto again;
	}

	clear_extent_bit(&BTRFS_I(inode)->io_tree, page_start, page_end,
			  EXTENT_DIRTY | EXTENT_DELALLOC |
			  EXTENT_DO_ACCOUNTING | EXTENT_DEFRAG,
			  0, 0, &cached_state, GFP_NOFS);

	ret = btrfs_set_extent_delalloc(inode, page_start, page_end,
					&cached_state);
	if (ret) {
		unlock_extent_cached(io_tree, page_start, page_end,
				     &cached_state, GFP_NOFS);
		goto out_unlock;
	}

	if (offset != PAGE_CACHE_SIZE) {
		if (!len)
			len = PAGE_CACHE_SIZE - offset;
		kaddr = kmap(page);
		if (front)
			memset(kaddr, 0, offset);
		else
			memset(kaddr + offset, 0, len);
		flush_dcache_page(page);
		kunmap(page);
	}
	ClearPageChecked(page);
	set_page_dirty(page);
	unlock_extent_cached(io_tree, page_start, page_end, &cached_state,
			     GFP_NOFS);

out_unlock:
	if (ret)
		btrfs_delalloc_release_space(inode, page_start,
					     PAGE_CACHE_SIZE);
	unlock_page(page);
	page_cache_release(page);
out:
	return ret;
}

static int maybe_insert_hole(struct btrfs_root *root, struct inode *inode,
			     u64 offset, u64 len)
{
	struct btrfs_trans_handle *trans;
	int ret;

	if (btrfs_fs_incompat(root->fs_info, NO_HOLES)) {
		BTRFS_I(inode)->last_trans = root->fs_info->generation;
		BTRFS_I(inode)->last_sub_trans = root->log_transid;
		BTRFS_I(inode)->last_log_commit = root->last_log_commit;
		return 0;
	}

	trans = btrfs_start_transaction(root, 3);
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	ret = btrfs_drop_extents(trans, root, inode, offset, offset + len, 1);
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		btrfs_end_transaction(trans, root);
		return ret;
	}

	ret = btrfs_insert_file_extent(trans, root, btrfs_ino(inode), offset,
				       0, 0, len, 0, len, 0, 0, 0);
	if (ret)
		btrfs_abort_transaction(trans, root, ret);
	else
		btrfs_update_inode(trans, root, inode);
	btrfs_end_transaction(trans, root);
	return ret;
}

int btrfs_cont_expand(struct inode *inode, loff_t oldsize, loff_t size)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct extent_io_tree *io_tree = &BTRFS_I(inode)->io_tree;
	struct extent_map *em = NULL;
	struct extent_state *cached_state = NULL;
	struct extent_map_tree *em_tree = &BTRFS_I(inode)->extent_tree;
	u64 hole_start = ALIGN(oldsize, root->sectorsize);
	u64 block_end = ALIGN(size, root->sectorsize);
	u64 last_byte;
	u64 cur_offset;
	u64 hole_size;
	int err = 0;

	err = btrfs_truncate_page(inode, oldsize, 0, 0);
	if (err)
		return err;

	if (size <= hole_start)
		return 0;

	while (1) {
		struct btrfs_ordered_extent *ordered;

		lock_extent_bits(io_tree, hole_start, block_end - 1,
				 &cached_state);
		ordered = btrfs_lookup_ordered_range(inode, hole_start,
						     block_end - hole_start);
		if (!ordered)
			break;
		unlock_extent_cached(io_tree, hole_start, block_end - 1,
				     &cached_state, GFP_NOFS);
		btrfs_start_ordered_extent(inode, ordered, 1);
		btrfs_put_ordered_extent(ordered);
	}

	cur_offset = hole_start;
	while (1) {
		em = btrfs_get_extent(inode, NULL, 0, cur_offset,
				block_end - cur_offset, 0);
		if (IS_ERR(em)) {
			err = PTR_ERR(em);
			em = NULL;
			break;
		}
		last_byte = min(extent_map_end(em), block_end);
		last_byte = ALIGN(last_byte , root->sectorsize);
		if (!test_bit(EXTENT_FLAG_PREALLOC, &em->flags)) {
			struct extent_map *hole_em;
			hole_size = last_byte - cur_offset;

			err = maybe_insert_hole(root, inode, cur_offset,
						hole_size);
			if (err)
				break;
			btrfs_drop_extent_cache(inode, cur_offset,
						cur_offset + hole_size - 1, 0);
			hole_em = alloc_extent_map();
			if (!hole_em) {
				set_bit(BTRFS_INODE_NEEDS_FULL_SYNC,
					&BTRFS_I(inode)->runtime_flags);
				goto next;
			}
			hole_em->start = cur_offset;
			hole_em->len = hole_size;
			hole_em->orig_start = cur_offset;

			hole_em->block_start = EXTENT_MAP_HOLE;
			hole_em->block_len = 0;
			hole_em->orig_block_len = 0;
			hole_em->ram_bytes = hole_size;
			hole_em->bdev = root->fs_info->fs_devices->latest_bdev;
			hole_em->compress_type = BTRFS_COMPRESS_NONE;
			hole_em->generation = root->fs_info->generation;

			while (1) {
				write_lock(&em_tree->lock);
				err = add_extent_mapping(em_tree, hole_em, 1);
				write_unlock(&em_tree->lock);
				if (err != -EEXIST)
					break;
				btrfs_drop_extent_cache(inode, cur_offset,
							cur_offset +
							hole_size - 1, 0);
			}
			free_extent_map(hole_em);
		}
next:
		free_extent_map(em);
		em = NULL;
		cur_offset = last_byte;
		if (cur_offset >= block_end)
			break;
	}
	free_extent_map(em);
	unlock_extent_cached(io_tree, hole_start, block_end - 1, &cached_state,
			     GFP_NOFS);
	return err;
}

static int btrfs_setsize(struct inode *inode, struct iattr *attr)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_trans_handle *trans;
	loff_t oldsize = i_size_read(inode);
	loff_t newsize = attr->ia_size;
	int mask = attr->ia_valid;
	int ret;

	if (newsize != oldsize) {
		inode_inc_iversion(inode);
		if (!(mask & (ATTR_CTIME | ATTR_MTIME)))
			inode->i_ctime = inode->i_mtime =
				current_fs_time(inode->i_sb);
	}

	if (newsize > oldsize) {
		truncate_pagecache(inode, newsize);
		 
		btrfs_wait_for_snapshot_creation(root);
		ret = btrfs_cont_expand(inode, oldsize, newsize);
		if (ret) {
			btrfs_end_write_no_snapshoting(root);
			return ret;
		}

		trans = btrfs_start_transaction(root, 1);
		if (IS_ERR(trans)) {
			btrfs_end_write_no_snapshoting(root);
			return PTR_ERR(trans);
		}

		i_size_write(inode, newsize);
		btrfs_ordered_update_i_size(inode, i_size_read(inode), NULL);
		ret = btrfs_update_inode(trans, root, inode);
		btrfs_end_write_no_snapshoting(root);
		btrfs_end_transaction(trans, root);
	} else {

		if (newsize == 0)
			set_bit(BTRFS_INODE_ORDERED_DATA_CLOSE,
				&BTRFS_I(inode)->runtime_flags);

		trans = btrfs_start_transaction(root, 2);
		if (IS_ERR(trans))
			return PTR_ERR(trans);

		ret = btrfs_orphan_add(trans, inode);
		btrfs_end_transaction(trans, root);
		if (ret)
			return ret;

		truncate_setsize(inode, newsize);

		btrfs_inode_block_unlocked_dio(inode);
		inode_dio_wait(inode);
		btrfs_inode_resume_unlocked_dio(inode);

		ret = btrfs_truncate(inode);
		if (ret && inode->i_nlink) {
			int err;

			trans = btrfs_join_transaction(root);
			if (IS_ERR(trans)) {
				btrfs_orphan_del(NULL, inode);
				return ret;
			}
			i_size_write(inode, BTRFS_I(inode)->disk_i_size);
			err = btrfs_orphan_del(trans, inode);
			if (err)
				btrfs_abort_transaction(trans, root, err);
			btrfs_end_transaction(trans, root);
		}
	}

	return ret;
}

static int btrfs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int err;

	if (btrfs_root_readonly(root))
		return -EROFS;

	err = inode_change_ok(inode, attr);
	if (err)
		return err;

	if (S_ISREG(inode->i_mode) && (attr->ia_valid & ATTR_SIZE)) {
		err = btrfs_setsize(inode, attr);
		if (err)
			return err;
	}

	if (attr->ia_valid) {
		setattr_copy(inode, attr);
		inode_inc_iversion(inode);
		err = btrfs_dirty_inode(inode);

		if (!err && attr->ia_valid & ATTR_MODE)
			err = posix_acl_chmod(inode, inode->i_mode);
	}

	return err;
}

static void evict_inode_truncate_pages(struct inode *inode)
{
	struct extent_io_tree *io_tree = &BTRFS_I(inode)->io_tree;
	struct extent_map_tree *map_tree = &BTRFS_I(inode)->extent_tree;
	struct rb_node *node;
#ifdef MY_ABC_HERE
	struct btrfs_fs_info *fs_info = BTRFS_I(inode)->root->fs_info;
#endif  

	ASSERT(inode->i_state & I_FREEING);
	truncate_inode_pages_final(&inode->i_data);

#ifdef MY_ABC_HERE
	spin_lock(&fs_info->extent_map_inode_list_lock);
	WARN_ON(atomic_read(&BTRFS_I(inode)->free_extent_map_counts) != 0);
	list_del_init(&BTRFS_I(inode)->free_extent_map_inode);
	spin_unlock(&fs_info->extent_map_inode_list_lock);
#endif
	write_lock(&map_tree->lock);
	while (!RB_EMPTY_ROOT(&map_tree->map)) {
		struct extent_map *em;

		node = rb_first(&map_tree->map);
		em = rb_entry(node, struct extent_map, rb_node);
		clear_bit(EXTENT_FLAG_PINNED, &em->flags);
		clear_bit(EXTENT_FLAG_LOGGING, &em->flags);
		remove_extent_mapping(map_tree, em);
		free_extent_map(em);
		if (need_resched()) {
			write_unlock(&map_tree->lock);
			cond_resched();
			write_lock(&map_tree->lock);
		}
	}
	write_unlock(&map_tree->lock);

	spin_lock(&io_tree->lock);
	while (!RB_EMPTY_ROOT(&io_tree->state)) {
		struct extent_state *state;
		struct extent_state *cached_state = NULL;
		u64 start;
		u64 end;

		node = rb_first(&io_tree->state);
		state = rb_entry(node, struct extent_state, rb_node);

#ifdef MY_ABC_HERE
		 
		if (unlikely(test_bit(BTRFS_FS_STATE_ERROR, &fs_info->fs_state))) {
			rb_erase(node, &io_tree->state);
			RB_CLEAR_NODE(node);
			free_extent_state(state);
			continue;
		}
#endif  

		start = state->start;
		end = state->end;
		spin_unlock(&io_tree->lock);

		lock_extent_bits(io_tree, start, end, &cached_state);

		if (state->state & EXTENT_DELALLOC)
			btrfs_qgroup_free_data(inode, start, end - start + 1);

		clear_extent_bit(io_tree, start, end,
				 EXTENT_LOCKED | EXTENT_DIRTY |
				 EXTENT_DELALLOC | EXTENT_DO_ACCOUNTING |
				 EXTENT_DEFRAG, 1, 1,
				 &cached_state, GFP_NOFS);

		cond_resched();
		spin_lock(&io_tree->lock);
	}
	spin_unlock(&io_tree->lock);
}

void btrfs_evict_inode(struct inode *inode)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_block_rsv *rsv, *global_rsv;
	int steal_from_global = 0;
	u64 min_size = btrfs_calc_trunc_metadata_size(root, 1);
	int ret;

	trace_btrfs_inode_evict(inode);

	evict_inode_truncate_pages(inode);

#ifdef MY_ABC_HERE
	if (unlikely(test_bit(BTRFS_FS_STATE_ERROR, &root->fs_info->fs_state)))
		goto no_delete;
#endif  

	if (inode->i_nlink &&
	    ((btrfs_root_refs(&root->root_item) != 0 &&
	      root->root_key.objectid != BTRFS_ROOT_TREE_OBJECTID) ||
	     btrfs_is_free_space_inode(inode)))
		goto no_delete;

	if (is_bad_inode(inode)) {
		btrfs_orphan_del(NULL, inode);
		goto no_delete;
	}
	 
	if (!special_file(inode->i_mode))
		btrfs_wait_ordered_range(inode, 0, (u64)-1);

	btrfs_free_io_failure_record(inode, 0, (u64)-1);

	if (root->fs_info->log_root_recovering) {
		BUG_ON(test_bit(BTRFS_INODE_HAS_ORPHAN_ITEM,
				 &BTRFS_I(inode)->runtime_flags));
		goto no_delete;
	}

	if (inode->i_nlink > 0) {
		BUG_ON(btrfs_root_refs(&root->root_item) != 0 &&
		       root->root_key.objectid != BTRFS_ROOT_TREE_OBJECTID);
		goto no_delete;
	}

	ret = btrfs_commit_inode_delayed_inode(inode);
	if (ret) {
		btrfs_orphan_del(NULL, inode);
		goto no_delete;
	}

	rsv = btrfs_alloc_block_rsv(root, BTRFS_BLOCK_RSV_TEMP);
	if (!rsv) {
		btrfs_orphan_del(NULL, inode);
		goto no_delete;
	}
	rsv->size = min_size;
	rsv->failfast = 1;
	global_rsv = &root->fs_info->global_block_rsv;

	btrfs_i_size_write(inode, 0);

	while (1) {
		ret = btrfs_block_rsv_refill(root, rsv, min_size,
					     BTRFS_RESERVE_FLUSH_LIMIT);

		if (ret)
			steal_from_global++;
		else
			steal_from_global = 0;
		ret = 0;

		if (steal_from_global > 2) {
			btrfs_warn(root->fs_info,
				"Could not get space for a delete, will truncate on mount %d",
				ret);
			btrfs_orphan_del(NULL, inode);
			btrfs_free_block_rsv(root, rsv);
			goto no_delete;
		}

		trans = btrfs_join_transaction(root);
		if (IS_ERR(trans)) {
			btrfs_orphan_del(NULL, inode);
			btrfs_free_block_rsv(root, rsv);
			goto no_delete;
		}

		if (steal_from_global) {
			if (!btrfs_check_space_for_delayed_refs(trans, root))
				ret = btrfs_block_rsv_migrate(global_rsv, rsv,
							      min_size);
			else
				ret = -ENOSPC;
		}

		if (ret) {
			ret = btrfs_commit_transaction(trans, root);
			if (ret) {
				btrfs_orphan_del(NULL, inode);
				btrfs_free_block_rsv(root, rsv);
				goto no_delete;
			}
			continue;
		} else {
			steal_from_global = 0;
		}

		trans->block_rsv = rsv;

		ret = btrfs_truncate_inode_items(trans, root, inode, 0, 0);
		if (ret != -ENOSPC && ret != -EAGAIN)
			break;

		trans->block_rsv = &root->fs_info->trans_block_rsv;
		btrfs_end_transaction(trans, root);
		trans = NULL;
		btrfs_btree_balance_dirty(root);
	}

	btrfs_free_block_rsv(root, rsv);

	if (ret == 0) {
		trans->block_rsv = root->orphan_block_rsv;
		btrfs_orphan_del(trans, inode);
	} else {
		btrfs_orphan_del(NULL, inode);
	}

	trans->block_rsv = &root->fs_info->trans_block_rsv;
	if (!(root == root->fs_info->tree_root ||
	      root->root_key.objectid == BTRFS_TREE_RELOC_OBJECTID))
		btrfs_return_ino(root, btrfs_ino(inode));

	btrfs_end_transaction(trans, root);
	btrfs_btree_balance_dirty(root);
no_delete:
	btrfs_remove_delayed_node(inode);
	clear_inode(inode);
}

static int btrfs_inode_by_name(struct inode *dir, struct dentry *dentry,
			       struct btrfs_key *location)
{
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	struct btrfs_dir_item *di;
	struct btrfs_path *path;
	struct btrfs_root *root = BTRFS_I(dir)->root;
	int ret = 0;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	di = btrfs_lookup_dir_item(NULL, root, path, btrfs_ino(dir), name,
				    namelen, 0);
	if (IS_ERR(di))
		ret = PTR_ERR(di);

	if (IS_ERR_OR_NULL(di))
		goto out_err;

	btrfs_dir_item_key_to_cpu(path->nodes[0], di, location);
out:
	btrfs_free_path(path);
	return ret;
out_err:
	location->objectid = 0;
	goto out;
}

static int fixup_tree_root_location(struct btrfs_root *root,
				    struct inode *dir,
				    struct dentry *dentry,
				    struct btrfs_key *location,
				    struct btrfs_root **sub_root)
{
	struct btrfs_path *path;
	struct btrfs_root *new_root;
	struct btrfs_root_ref *ref;
	struct extent_buffer *leaf;
	struct btrfs_key key;
	int ret;
	int err = 0;

	path = btrfs_alloc_path();
	if (!path) {
		err = -ENOMEM;
		goto out;
	}

	err = -ENOENT;
	key.objectid = BTRFS_I(dir)->root->root_key.objectid;
	key.type = BTRFS_ROOT_REF_KEY;
	key.offset = location->objectid;

	ret = btrfs_search_slot(NULL, root->fs_info->tree_root, &key, path,
				0, 0);
	if (ret) {
		if (ret < 0)
			err = ret;
		goto out;
	}

	leaf = path->nodes[0];
	ref = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_root_ref);
	if (btrfs_root_ref_dirid(leaf, ref) != btrfs_ino(dir) ||
	    btrfs_root_ref_name_len(leaf, ref) != dentry->d_name.len)
		goto out;

	ret = memcmp_extent_buffer(leaf, dentry->d_name.name,
				   (unsigned long)(ref + 1),
				   dentry->d_name.len);
	if (ret)
		goto out;

	btrfs_release_path(path);

	new_root = btrfs_read_fs_root_no_name(root->fs_info, location);
	if (IS_ERR(new_root)) {
		err = PTR_ERR(new_root);
		goto out;
	}

	*sub_root = new_root;
	location->objectid = btrfs_root_dirid(&new_root->root_item);
	location->type = BTRFS_INODE_ITEM_KEY;
	location->offset = 0;
	err = 0;
out:
	btrfs_free_path(path);
	return err;
}

static void inode_tree_add(struct inode *inode)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_inode *entry;
	struct rb_node **p;
	struct rb_node *parent;
	struct rb_node *new = &BTRFS_I(inode)->rb_node;
	u64 ino = btrfs_ino(inode);

	if (inode_unhashed(inode))
		return;
	parent = NULL;
	spin_lock(&root->inode_lock);
	p = &root->inode_tree.rb_node;
	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct btrfs_inode, rb_node);

		if (ino < btrfs_ino(&entry->vfs_inode))
			p = &parent->rb_left;
		else if (ino > btrfs_ino(&entry->vfs_inode))
			p = &parent->rb_right;
		else {
			WARN_ON(!(entry->vfs_inode.i_state &
				  (I_WILL_FREE | I_FREEING)));
			rb_replace_node(parent, new, &root->inode_tree);
			RB_CLEAR_NODE(parent);
			spin_unlock(&root->inode_lock);
			return;
		}
	}
	rb_link_node(new, parent, p);
	rb_insert_color(new, &root->inode_tree);
	spin_unlock(&root->inode_lock);
}

static void inode_tree_del(struct inode *inode)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int empty = 0;

	spin_lock(&root->inode_lock);
	if (!RB_EMPTY_NODE(&BTRFS_I(inode)->rb_node)) {
		rb_erase(&BTRFS_I(inode)->rb_node, &root->inode_tree);
		RB_CLEAR_NODE(&BTRFS_I(inode)->rb_node);
		empty = RB_EMPTY_ROOT(&root->inode_tree);
	}
	spin_unlock(&root->inode_lock);

	if (empty && btrfs_root_refs(&root->root_item) == 0) {
		synchronize_srcu(&root->fs_info->subvol_srcu);
		spin_lock(&root->inode_lock);
		empty = RB_EMPTY_ROOT(&root->inode_tree);
		spin_unlock(&root->inode_lock);
		if (empty)
			btrfs_add_dead_root(root);
	}
}

void btrfs_invalidate_inodes(struct btrfs_root *root)
{
	struct rb_node *node;
	struct rb_node *prev;
	struct btrfs_inode *entry;
	struct inode *inode;
	u64 objectid = 0;

	if (!test_bit(BTRFS_FS_STATE_ERROR, &root->fs_info->fs_state))
		WARN_ON(btrfs_root_refs(&root->root_item) != 0);

	spin_lock(&root->inode_lock);
again:
	node = root->inode_tree.rb_node;
	prev = NULL;
	while (node) {
		prev = node;
		entry = rb_entry(node, struct btrfs_inode, rb_node);

		if (objectid < btrfs_ino(&entry->vfs_inode))
			node = node->rb_left;
		else if (objectid > btrfs_ino(&entry->vfs_inode))
			node = node->rb_right;
		else
			break;
	}
	if (!node) {
		while (prev) {
			entry = rb_entry(prev, struct btrfs_inode, rb_node);
			if (objectid <= btrfs_ino(&entry->vfs_inode)) {
				node = prev;
				break;
			}
			prev = rb_next(prev);
		}
	}
	while (node) {
		entry = rb_entry(node, struct btrfs_inode, rb_node);
		objectid = btrfs_ino(&entry->vfs_inode) + 1;
		inode = igrab(&entry->vfs_inode);
		if (inode) {
			spin_unlock(&root->inode_lock);
			if (atomic_read(&inode->i_count) > 1)
				d_prune_aliases(inode);
			 
			iput(inode);
			cond_resched();
			spin_lock(&root->inode_lock);
			goto again;
		}

		if (cond_resched_lock(&root->inode_lock))
			goto again;

		node = rb_next(node);
	}
	spin_unlock(&root->inode_lock);
}

static int btrfs_init_locked_inode(struct inode *inode, void *p)
{
	struct btrfs_iget_args *args = p;
	inode->i_ino = args->location->objectid;
	memcpy(&BTRFS_I(inode)->location, args->location,
	       sizeof(*args->location));
	BTRFS_I(inode)->root = args->root;
	return 0;
}

static int btrfs_find_actor(struct inode *inode, void *opaque)
{
	struct btrfs_iget_args *args = opaque;
	return args->location->objectid == BTRFS_I(inode)->location.objectid &&
		args->root == BTRFS_I(inode)->root;
}

static struct inode *btrfs_iget_locked(struct super_block *s,
				       struct btrfs_key *location,
				       struct btrfs_root *root)
{
	struct inode *inode;
	struct btrfs_iget_args args;
	unsigned long hashval = btrfs_inode_hash(location->objectid, root);

	args.location = location;
	args.root = root;

	inode = iget5_locked(s, hashval, btrfs_find_actor,
			     btrfs_init_locked_inode,
			     (void *)&args);
	return inode;
}

struct inode *btrfs_iget(struct super_block *s, struct btrfs_key *location,
			 struct btrfs_root *root, int *new)
{
	struct inode *inode;
#ifdef MY_ABC_HERE
	int err;
	__le32 archive_bit;
#endif  

	inode = btrfs_iget_locked(s, location, root);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (inode->i_state & I_NEW) {
		btrfs_read_locked_inode(inode);
		if (!is_bad_inode(inode)) {
			inode_tree_add(inode);
			unlock_new_inode(inode);
			if (new)
				*new = 1;
#ifdef MY_ABC_HERE
			err = __btrfs_getxattr(inode, XATTR_SYNO_PREFIX XATTR_SYNO_ARCHIVE_BIT,
								   &archive_bit, sizeof(archive_bit));
			if (0 < err)
				inode->i_archive_bit = le32_to_cpu(archive_bit);
			else
				inode->i_archive_bit = 0;
#endif  
		} else {
			unlock_new_inode(inode);
			iput(inode);
			inode = ERR_PTR(-ESTALE);
		}
	}

	return inode;
}

static struct inode *new_simple_dir(struct super_block *s,
				    struct btrfs_key *key,
				    struct btrfs_root *root)
{
	struct inode *inode = new_inode(s);

	if (!inode)
		return ERR_PTR(-ENOMEM);

	BTRFS_I(inode)->root = root;
	memcpy(&BTRFS_I(inode)->location, key, sizeof(*key));
	set_bit(BTRFS_INODE_DUMMY, &BTRFS_I(inode)->runtime_flags);

	inode->i_ino = BTRFS_EMPTY_SUBVOL_DIR_OBJECTID;
	inode->i_op = &btrfs_dir_ro_inode_operations;
	inode->i_fop = &simple_dir_operations;
	inode->i_mode = S_IFDIR | S_IRUGO | S_IWUSR | S_IXUGO;
	inode->i_mtime = current_fs_time(inode->i_sb);
	inode->i_atime = inode->i_mtime;
	inode->i_ctime = inode->i_mtime;
	BTRFS_I(inode)->i_otime = inode->i_mtime;

	return inode;
}

struct inode *btrfs_lookup_dentry(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode;
	struct btrfs_root *root = BTRFS_I(dir)->root;
	struct btrfs_root *sub_root = root;
	struct btrfs_key location;
	int index;
	int ret = 0;

	if (dentry->d_name.len > BTRFS_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	ret = btrfs_inode_by_name(dir, dentry, &location);
	if (ret < 0)
		return ERR_PTR(ret);

	if (location.objectid == 0)
		return ERR_PTR(-ENOENT);

	if (location.type == BTRFS_INODE_ITEM_KEY) {
		inode = btrfs_iget(dir->i_sb, &location, root, NULL);
		return inode;
	}

	BUG_ON(location.type != BTRFS_ROOT_ITEM_KEY);

	index = srcu_read_lock(&root->fs_info->subvol_srcu);
	ret = fixup_tree_root_location(root, dir, dentry,
				       &location, &sub_root);
	if (ret < 0) {
		if (ret != -ENOENT)
			inode = ERR_PTR(ret);
		else
			inode = new_simple_dir(dir->i_sb, &location, sub_root);
	} else {
		inode = btrfs_iget(dir->i_sb, &location, sub_root, NULL);
	}
	srcu_read_unlock(&root->fs_info->subvol_srcu, index);

	if (!IS_ERR(inode) && root != sub_root) {
		down_read(&root->fs_info->cleanup_work_sem);
		if (!(inode->i_sb->s_flags & MS_RDONLY))
			ret = btrfs_orphan_cleanup(sub_root);
		up_read(&root->fs_info->cleanup_work_sem);
		if (ret) {
			iput(inode);
			inode = ERR_PTR(ret);
		}
	}

	return inode;
}

static int btrfs_dentry_delete(const struct dentry *dentry)
{
	struct btrfs_root *root;
	struct inode *inode = d_inode(dentry);

	if (!inode && !IS_ROOT(dentry))
		inode = d_inode(dentry->d_parent);

	if (inode) {
		root = BTRFS_I(inode)->root;
		if (btrfs_root_refs(&root->root_item) == 0)
			return 1;

		if (btrfs_ino(inode) == BTRFS_EMPTY_SUBVOL_DIR_OBJECTID)
			return 1;
	}
	return 0;
}

static void btrfs_dentry_release(struct dentry *dentry)
{
	kfree(dentry->d_fsdata);
}

static struct dentry *btrfs_lookup(struct inode *dir, struct dentry *dentry,
				   unsigned int flags)
{
	struct inode *inode;

	inode = btrfs_lookup_dentry(dir, dentry);
	if (IS_ERR(inode)) {
		if (PTR_ERR(inode) == -ENOENT)
			inode = NULL;
		else
			return ERR_CAST(inode);
	}

	return d_splice_alias(inode, dentry);
}

unsigned char btrfs_filetype_table[] = {
	DT_UNKNOWN, DT_REG, DT_DIR, DT_CHR, DT_BLK, DT_FIFO, DT_SOCK, DT_LNK
};

static int btrfs_real_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_item *item;
	struct btrfs_dir_item *di;
	struct btrfs_key key;
	struct btrfs_key found_key;
	struct btrfs_path *path;
	struct list_head ins_list;
	struct list_head del_list;
	int ret;
	struct extent_buffer *leaf;
	int slot;
	unsigned char d_type;
	int over = 0;
	u32 di_cur;
	u32 di_total;
	u32 di_len;
	int key_type = BTRFS_DIR_INDEX_KEY;
	char tmp_name[32];
	char *name_ptr;
	int name_len;
	int is_curr = 0;	 
	bool emitted;

	if (root->fs_info->tree_root == root)
		key_type = BTRFS_DIR_ITEM_KEY;

	if (!dir_emit_dots(file, ctx))
		return 0;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	path->reada = READA_FORWARD;

	if (key_type == BTRFS_DIR_INDEX_KEY) {
		INIT_LIST_HEAD(&ins_list);
		INIT_LIST_HEAD(&del_list);
		btrfs_get_delayed_items(inode, &ins_list, &del_list);
	}

	key.type = key_type;
	key.offset = ctx->pos;
	key.objectid = btrfs_ino(inode);

	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret < 0)
		goto err;

	emitted = false;
	while (1) {
		leaf = path->nodes[0];
		slot = path->slots[0];
		if (slot >= btrfs_header_nritems(leaf)) {
			ret = btrfs_next_leaf(root, path);
			if (ret < 0)
				goto err;
			else if (ret > 0)
				break;
			continue;
		}

		item = btrfs_item_nr(slot);
		btrfs_item_key_to_cpu(leaf, &found_key, slot);

		if (found_key.objectid != key.objectid)
			break;
		if (found_key.type != key_type)
			break;
		if (found_key.offset < ctx->pos)
			goto next;
		if (key_type == BTRFS_DIR_INDEX_KEY &&
		    btrfs_should_delete_dir_index(&del_list,
						  found_key.offset))
			goto next;

		ctx->pos = found_key.offset;
		is_curr = 1;

		di = btrfs_item_ptr(leaf, slot, struct btrfs_dir_item);
		di_cur = 0;
		di_total = btrfs_item_size(leaf, item);

		while (di_cur < di_total) {
			struct btrfs_key location;

			if (verify_dir_item(root, leaf, di))
				break;

			name_len = btrfs_dir_name_len(leaf, di);
			if (name_len <= sizeof(tmp_name)) {
				name_ptr = tmp_name;
			} else {
				name_ptr = kmalloc(name_len, GFP_KERNEL);
				if (!name_ptr) {
					ret = -ENOMEM;
					goto err;
				}
			}
			read_extent_buffer(leaf, name_ptr,
					   (unsigned long)(di + 1), name_len);

			d_type = btrfs_filetype_table[btrfs_dir_type(leaf, di)];
			btrfs_dir_item_key_to_cpu(leaf, di, &location);

			if (location.type == BTRFS_ROOT_ITEM_KEY &&
			    location.objectid == root->root_key.objectid) {
				over = 0;
				goto skip;
			}
#ifdef MY_ABC_HERE
			if (location.type == BTRFS_ROOT_ITEM_KEY) {
				struct btrfs_root *subvol_root = btrfs_read_fs_root_no_name(root->fs_info, &location);
				if (!IS_ERR(subvol_root) && btrfs_root_hide(subvol_root)) {
					over = 0;
					goto skip;
				}
			}
#endif  
			over = !dir_emit(ctx, name_ptr, name_len,
				       location.objectid, d_type);

skip:
			if (name_ptr != tmp_name)
				kfree(name_ptr);

			if (over)
				goto nopos;
			emitted = true;
			di_len = btrfs_dir_name_len(leaf, di) +
				 btrfs_dir_data_len(leaf, di) + sizeof(*di);
			di_cur += di_len;
			di = (struct btrfs_dir_item *)((char *)di + di_len);
		}
next:
		path->slots[0]++;
	}

	if (key_type == BTRFS_DIR_INDEX_KEY) {
		if (is_curr)
			ctx->pos++;
		ret = btrfs_readdir_delayed_dir_index(ctx, &ins_list, &emitted);
		if (ret)
			goto nopos;
	}

	if (ctx->pos > 2 && !emitted)
		goto nopos;

	ctx->pos++;

	if (key_type == BTRFS_DIR_INDEX_KEY) {
		if (ctx->pos >= INT_MAX)
			ctx->pos = LLONG_MAX;
		else
			ctx->pos = INT_MAX;
	}
nopos:
	ret = 0;
err:
	if (key_type == BTRFS_DIR_INDEX_KEY)
		btrfs_put_delayed_items(&ins_list, &del_list);
	btrfs_free_path(path);
	return ret;
}

int btrfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_trans_handle *trans;
	int ret = 0;
	bool nolock = false;

	if (test_bit(BTRFS_INODE_DUMMY, &BTRFS_I(inode)->runtime_flags))
		return 0;

	if (btrfs_fs_closing(root->fs_info) && btrfs_is_free_space_inode(inode))
		nolock = true;

	if (wbc->sync_mode == WB_SYNC_ALL) {
		if (nolock)
			trans = btrfs_join_transaction_nolock(root);
		else
			trans = btrfs_join_transaction(root);
		if (IS_ERR(trans))
			return PTR_ERR(trans);
		ret = btrfs_commit_transaction(trans, root);
	}
	return ret;
}

static int btrfs_dirty_inode(struct inode *inode)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_trans_handle *trans;
	int ret;

	if (test_bit(BTRFS_INODE_DUMMY, &BTRFS_I(inode)->runtime_flags))
		return 0;

	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	ret = btrfs_update_inode(trans, root, inode);
	if (ret && ret == -ENOSPC) {
		 
		btrfs_end_transaction(trans, root);
		trans = btrfs_start_transaction(root, 1);
		if (IS_ERR(trans))
			return PTR_ERR(trans);

		ret = btrfs_update_inode(trans, root, inode);
	}
	btrfs_end_transaction(trans, root);
	if (BTRFS_I(inode)->delayed_node)
		btrfs_balance_delayed_items(root);

	return ret;
}

static int btrfs_update_time(struct inode *inode, struct timespec *now,
			     int flags)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;

	if (btrfs_root_readonly(root))
		return -EROFS;

	if (flags & S_VERSION)
		inode_inc_iversion(inode);
	if (flags & S_CTIME)
		inode->i_ctime = *now;
	if (flags & S_MTIME)
		inode->i_mtime = *now;
	if (flags & S_ATIME)
		inode->i_atime = *now;
	return btrfs_dirty_inode(inode);
}

static int btrfs_set_inode_index_count(struct inode *inode)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_key key, found_key;
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	int ret;

	key.objectid = btrfs_ino(inode);
	key.type = BTRFS_DIR_INDEX_KEY;
	key.offset = (u64)-1;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret < 0)
		goto out;
	 
	if (ret == 0)
		goto out;
	ret = 0;

	if (path->slots[0] == 0) {
		BTRFS_I(inode)->index_cnt = 2;
		goto out;
	}

	path->slots[0]--;

	leaf = path->nodes[0];
	btrfs_item_key_to_cpu(leaf, &found_key, path->slots[0]);

	if (found_key.objectid != btrfs_ino(inode) ||
	    found_key.type != BTRFS_DIR_INDEX_KEY) {
		BTRFS_I(inode)->index_cnt = 2;
		goto out;
	}

	BTRFS_I(inode)->index_cnt = found_key.offset + 1;
out:
	btrfs_free_path(path);
	return ret;
}

int btrfs_set_inode_index(struct inode *dir, u64 *index)
{
	int ret = 0;

	if (BTRFS_I(dir)->index_cnt == (u64)-1) {
		ret = btrfs_inode_delayed_dir_index_count(dir);
		if (ret) {
			ret = btrfs_set_inode_index_count(dir);
			if (ret)
				return ret;
		}
	}

	*index = BTRFS_I(dir)->index_cnt;
	BTRFS_I(dir)->index_cnt++;

	return ret;
}

static int btrfs_insert_inode_locked(struct inode *inode)
{
	struct btrfs_iget_args args;
	args.location = &BTRFS_I(inode)->location;
	args.root = BTRFS_I(inode)->root;

	return insert_inode_locked4(inode,
		   btrfs_inode_hash(inode->i_ino, BTRFS_I(inode)->root),
		   btrfs_find_actor, &args);
}

static struct inode *btrfs_new_inode(struct btrfs_trans_handle *trans,
				     struct btrfs_root *root,
				     struct inode *dir,
				     const char *name, int name_len,
				     u64 ref_objectid, u64 objectid,
				     umode_t mode, u64 *index)
{
	struct inode *inode;
	struct btrfs_inode_item *inode_item;
	struct btrfs_key *location;
	struct btrfs_path *path;
	struct btrfs_inode_ref *ref;
	struct btrfs_key key[2];
	u32 sizes[2];
	int nitems = name ? 2 : 1;
	unsigned long ptr;
	int ret;

	path = btrfs_alloc_path();
	if (!path)
		return ERR_PTR(-ENOMEM);

	inode = new_inode(root->fs_info->sb);
	if (!inode) {
		btrfs_free_path(path);
		return ERR_PTR(-ENOMEM);
	}

	if (!name)
		set_nlink(inode, 0);

	inode->i_ino = objectid;

	if (dir && name) {
		trace_btrfs_inode_request(dir);

		ret = btrfs_set_inode_index(dir, index);
		if (ret) {
			btrfs_free_path(path);
			iput(inode);
			return ERR_PTR(ret);
		}
	} else if (dir) {
		*index = 0;
	}
	 
	BTRFS_I(inode)->index_cnt = 2;
	BTRFS_I(inode)->dir_index = *index;
	BTRFS_I(inode)->root = root;
	BTRFS_I(inode)->generation = trans->transid;
	inode->i_generation = BTRFS_I(inode)->generation;

	set_bit(BTRFS_INODE_NEEDS_FULL_SYNC, &BTRFS_I(inode)->runtime_flags);

	key[0].objectid = objectid;
	key[0].type = BTRFS_INODE_ITEM_KEY;
	key[0].offset = 0;

	sizes[0] = sizeof(struct btrfs_inode_item);

	if (name) {
		 
		key[1].objectid = objectid;
		key[1].type = BTRFS_INODE_REF_KEY;
		key[1].offset = ref_objectid;

		sizes[1] = name_len + sizeof(*ref);
	}

	location = &BTRFS_I(inode)->location;
	location->objectid = objectid;
	location->offset = 0;
	location->type = BTRFS_INODE_ITEM_KEY;

	ret = btrfs_insert_inode_locked(inode);
	if (ret < 0)
		goto fail;

	path->leave_spinning = 1;
	ret = btrfs_insert_empty_items(trans, root, path, key, sizes, nitems);
	if (ret != 0)
		goto fail_unlock;

	inode_init_owner(inode, dir, mode);
	inode_set_bytes(inode, 0);

	inode->i_mtime = current_fs_time(inode->i_sb);
	inode->i_atime = inode->i_mtime;
	inode->i_ctime = inode->i_mtime;
	BTRFS_I(inode)->i_otime = inode->i_mtime;

	inode_item = btrfs_item_ptr(path->nodes[0], path->slots[0],
				  struct btrfs_inode_item);
	memset_extent_buffer(path->nodes[0], 0, (unsigned long)inode_item,
			     sizeof(*inode_item));
	fill_inode_item(trans, path->nodes[0], inode_item, inode);

	if (name) {
		ref = btrfs_item_ptr(path->nodes[0], path->slots[0] + 1,
				     struct btrfs_inode_ref);
		btrfs_set_inode_ref_name_len(path->nodes[0], ref, name_len);
		btrfs_set_inode_ref_index(path->nodes[0], ref, *index);
		ptr = (unsigned long)(ref + 1);
		write_extent_buffer(path->nodes[0], name, ptr, name_len);
	}

	btrfs_mark_buffer_dirty(path->nodes[0]);
	btrfs_free_path(path);

	btrfs_inherit_iflags(inode, dir);

	if (S_ISREG(mode)) {
		if (btrfs_test_opt(root, NODATASUM))
			BTRFS_I(inode)->flags |= BTRFS_INODE_NODATASUM;
		if (btrfs_test_opt(root, NODATACOW))
			BTRFS_I(inode)->flags |= BTRFS_INODE_NODATACOW |
				BTRFS_INODE_NODATASUM;
	}

	inode_tree_add(inode);

	trace_btrfs_inode_new(inode);
	btrfs_set_inode_last_trans(trans, inode);

	btrfs_update_root_times(trans, root);

	ret = btrfs_inode_inherit_props(trans, inode, dir);
	if (ret)
		btrfs_err(root->fs_info,
			  "error inheriting props for ino %llu (root %llu): %d",
			  btrfs_ino(inode), root->root_key.objectid, ret);

	return inode;

fail_unlock:
	unlock_new_inode(inode);
fail:
	if (dir && name)
		BTRFS_I(dir)->index_cnt--;
	btrfs_free_path(path);
	iput(inode);
	return ERR_PTR(ret);
}

static inline u8 btrfs_inode_type(struct inode *inode)
{
	return btrfs_type_by_mode[(inode->i_mode & S_IFMT) >> S_SHIFT];
}

int btrfs_add_link(struct btrfs_trans_handle *trans,
		   struct inode *parent_inode, struct inode *inode,
		   const char *name, int name_len, int add_backref, u64 index)
{
	int ret = 0;
	struct btrfs_key key;
	struct btrfs_root *root = BTRFS_I(parent_inode)->root;
	u64 ino = btrfs_ino(inode);
	u64 parent_ino = btrfs_ino(parent_inode);

	if (unlikely(ino == BTRFS_FIRST_FREE_OBJECTID)) {
		memcpy(&key, &BTRFS_I(inode)->root->root_key, sizeof(key));
	} else {
		key.objectid = ino;
		key.type = BTRFS_INODE_ITEM_KEY;
		key.offset = 0;
	}

	if (unlikely(ino == BTRFS_FIRST_FREE_OBJECTID)) {
		ret = btrfs_add_root_ref(trans, root->fs_info->tree_root,
					 key.objectid, root->root_key.objectid,
					 parent_ino, index, name, name_len);
	} else if (add_backref) {
		ret = btrfs_insert_inode_ref(trans, root, name, name_len, ino,
					     parent_ino, index);
	}

	if (ret)
		return ret;

	ret = btrfs_insert_dir_item(trans, root, name, name_len,
				    parent_inode, &key,
				    btrfs_inode_type(inode), index);
	if (ret == -EEXIST || ret == -EOVERFLOW)
		goto fail_dir_item;
	else if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		return ret;
	}

	btrfs_i_size_write(parent_inode, parent_inode->i_size +
			   name_len * 2);
	inode_inc_iversion(parent_inode);
	parent_inode->i_mtime = parent_inode->i_ctime =
		current_fs_time(parent_inode->i_sb);
	ret = btrfs_update_inode(trans, root, parent_inode);
	if (ret)
		btrfs_abort_transaction(trans, root, ret);
	return ret;

fail_dir_item:
	if (unlikely(ino == BTRFS_FIRST_FREE_OBJECTID)) {
		u64 local_index;
		int err;
		err = btrfs_del_root_ref(trans, root->fs_info->tree_root,
				 key.objectid, root->root_key.objectid,
				 parent_ino, &local_index, name, name_len);

	} else if (add_backref) {
		u64 local_index;
		int err;

		err = btrfs_del_inode_ref(trans, root, name, name_len,
					  ino, parent_ino, &local_index);
	}
	return ret;
}

static int btrfs_add_nondir(struct btrfs_trans_handle *trans,
			    struct inode *dir, struct dentry *dentry,
			    struct inode *inode, int backref, u64 index)
{
	int err = btrfs_add_link(trans, dir, inode,
				 dentry->d_name.name, dentry->d_name.len,
				 backref, index);
	if (err > 0)
		err = -EEXIST;
	return err;
}

static int btrfs_mknod(struct inode *dir, struct dentry *dentry,
			umode_t mode, dev_t rdev)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_root *root = BTRFS_I(dir)->root;
	struct inode *inode = NULL;
	int err;
	int drop_inode = 0;
	u64 objectid;
	u64 index = 0;
#if defined(MY_ABC_HERE)
	int credit_for_syno = 0;
#endif  

#ifdef MY_ABC_HERE
	 
	if (test_bit(BTRFS_INODE_HAS_PROPS, &BTRFS_I(dir)->runtime_flags))
		credit_for_syno++;
#endif  

#if defined(MY_ABC_HERE)
	trans = btrfs_start_transaction(root, 5 + credit_for_syno);
#else
	trans = btrfs_start_transaction(root, 5);
#endif  
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	err = btrfs_find_free_ino(root, &objectid);
	if (err)
		goto out_unlock;

	inode = btrfs_new_inode(trans, root, dir, dentry->d_name.name,
				dentry->d_name.len, btrfs_ino(dir), objectid,
				mode, &index);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_unlock;
	}

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	err = btrfs_syno_init_attr(trans, inode);
	if (err) {
		drop_inode = 1;
		goto out_unlock;
	}
#endif  

	inode->i_op = &btrfs_special_inode_operations;
	init_special_inode(inode, inode->i_mode, rdev);

	err = btrfs_init_inode_security(trans, inode, dir, &dentry->d_name);
	if (err)
		goto out_unlock_inode;

	err = btrfs_add_nondir(trans, dir, dentry, inode, 0, index);
	if (err) {
		goto out_unlock_inode;
	} else {
		btrfs_update_inode(trans, root, inode);
		unlock_new_inode(inode);
		d_instantiate(dentry, inode);
	}

out_unlock:
	btrfs_end_transaction(trans, root);
	btrfs_balance_delayed_items(root);
	btrfs_btree_balance_dirty(root);
	if (drop_inode) {
		inode_dec_link_count(inode);
		iput(inode);
	}
	return err;

out_unlock_inode:
	drop_inode = 1;
	unlock_new_inode(inode);
	goto out_unlock;

}

static int btrfs_create(struct inode *dir, struct dentry *dentry,
			umode_t mode, bool excl)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_root *root = BTRFS_I(dir)->root;
	struct inode *inode = NULL;
	int drop_inode_on_err = 0;
	int err;
	u64 objectid;
	u64 index = 0;
#if defined(MY_ABC_HERE)
	int credit_for_syno = 0;
#endif  

#ifdef MY_ABC_HERE
	 
	if (test_bit(BTRFS_INODE_HAS_PROPS, &BTRFS_I(dir)->runtime_flags))
		credit_for_syno++;
#endif  
	 
#if defined(MY_ABC_HERE)
	trans = btrfs_start_transaction(root, 5 + credit_for_syno);
#else
	trans = btrfs_start_transaction(root, 5);
#endif  
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	err = btrfs_find_free_ino(root, &objectid);
	if (err)
		goto out_unlock;

	inode = btrfs_new_inode(trans, root, dir, dentry->d_name.name,
				dentry->d_name.len, btrfs_ino(dir), objectid,
				mode, &index);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_unlock;
	}
	drop_inode_on_err = 1;
	 
	inode->i_fop = &btrfs_file_operations;
	inode->i_op = &btrfs_file_inode_operations;
	inode->i_mapping->a_ops = &btrfs_aops;

	err = btrfs_init_inode_security(trans, inode, dir, &dentry->d_name);
	if (err)
		goto out_unlock_inode;

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	err = btrfs_syno_init_attr(trans, inode);
	if (err) {
		goto out_unlock;
	}
#endif  

	err = btrfs_update_inode(trans, root, inode);
	if (err)
		goto out_unlock_inode;

	err = btrfs_add_nondir(trans, dir, dentry, inode, 0, index);
	if (err)
		goto out_unlock_inode;

	BTRFS_I(inode)->io_tree.ops = &btrfs_extent_io_ops;
	unlock_new_inode(inode);
	d_instantiate(dentry, inode);

out_unlock:
	btrfs_end_transaction(trans, root);
	if (err && drop_inode_on_err) {
		inode_dec_link_count(inode);
		iput(inode);
	}
	btrfs_balance_delayed_items(root);
	btrfs_btree_balance_dirty(root);
	return err;

out_unlock_inode:
	unlock_new_inode(inode);
	goto out_unlock;

}

static int btrfs_link(struct dentry *old_dentry, struct inode *dir,
		      struct dentry *dentry)
{
	struct btrfs_trans_handle *trans = NULL;
	struct btrfs_root *root = BTRFS_I(dir)->root;
	struct inode *inode = d_inode(old_dentry);
	u64 index;
	int err;
	int drop_inode = 0;

	if (root->objectid != BTRFS_I(inode)->root->objectid)
		return -EXDEV;

	if (inode->i_nlink >= BTRFS_LINK_MAX)
		return -EMLINK;

	err = btrfs_set_inode_index(dir, &index);
	if (err)
		goto fail;

	trans = btrfs_start_transaction(root, 5);
	if (IS_ERR(trans)) {
		err = PTR_ERR(trans);
		trans = NULL;
		goto fail;
	}

	BTRFS_I(inode)->dir_index = 0ULL;
	inc_nlink(inode);
	inode_inc_iversion(inode);
	inode->i_ctime = current_fs_time(inode->i_sb);
	ihold(inode);
	set_bit(BTRFS_INODE_COPY_EVERYTHING, &BTRFS_I(inode)->runtime_flags);

	err = btrfs_add_nondir(trans, dir, dentry, inode, 1, index);

	if (err) {
		drop_inode = 1;
	} else {
		struct dentry *parent = dentry->d_parent;
		err = btrfs_update_inode(trans, root, inode);
		if (err)
			goto fail;
		if (inode->i_nlink == 1) {
			 
			err = btrfs_orphan_del(trans, inode);
			if (err)
				goto fail;
		}
		d_instantiate(dentry, inode);
		btrfs_log_new_name(trans, inode, NULL, parent);
	}

	btrfs_balance_delayed_items(root);
fail:
	if (trans)
		btrfs_end_transaction(trans, root);
	if (drop_inode) {
		inode_dec_link_count(inode);
		iput(inode);
	}
	btrfs_btree_balance_dirty(root);
	return err;
}

static int btrfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode = NULL;
	struct btrfs_trans_handle *trans;
	struct btrfs_root *root = BTRFS_I(dir)->root;
	int err = 0;
	int drop_on_err = 0;
	u64 objectid = 0;
	u64 index = 0;
#if defined(MY_ABC_HERE)
	int credit_for_syno = 0;
#endif  

#ifdef MY_ABC_HERE
	 
	if (test_bit(BTRFS_INODE_HAS_PROPS, &BTRFS_I(dir)->runtime_flags))
		credit_for_syno++;
#endif  
	 
#if defined(MY_ABC_HERE)
	trans = btrfs_start_transaction(root, 5 + credit_for_syno);
#else
	trans = btrfs_start_transaction(root, 5);
#endif  
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	err = btrfs_find_free_ino(root, &objectid);
	if (err)
		goto out_fail;

	inode = btrfs_new_inode(trans, root, dir, dentry->d_name.name,
				dentry->d_name.len, btrfs_ino(dir), objectid,
				S_IFDIR | mode, &index);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_fail;
	}

	drop_on_err = 1;
	 
	inode->i_op = &btrfs_dir_inode_operations;
	inode->i_fop = &btrfs_dir_file_operations;

	err = btrfs_init_inode_security(trans, inode, dir, &dentry->d_name);
	if (err)
		goto out_fail_inode;

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	err = btrfs_syno_init_attr(trans, inode);
	if (err) {
		goto out_fail;
	}
#endif  

	btrfs_i_size_write(inode, 0);
	err = btrfs_update_inode(trans, root, inode);
	if (err)
		goto out_fail_inode;

	err = btrfs_add_link(trans, dir, inode, dentry->d_name.name,
			     dentry->d_name.len, 0, index);
	if (err)
		goto out_fail_inode;

	d_instantiate(dentry, inode);
	 
	unlock_new_inode(inode);
	drop_on_err = 0;

out_fail:
	btrfs_end_transaction(trans, root);
	if (drop_on_err) {
		inode_dec_link_count(inode);
		iput(inode);
	}
	btrfs_balance_delayed_items(root);
	btrfs_btree_balance_dirty(root);
	return err;

out_fail_inode:
	unlock_new_inode(inode);
	goto out_fail;
}

static struct extent_map *next_extent_map(struct extent_map *em)
{
	struct rb_node *next;

	next = rb_next(&em->rb_node);
	if (!next)
		return NULL;
	return container_of(next, struct extent_map, rb_node);
}

static struct extent_map *prev_extent_map(struct extent_map *em)
{
	struct rb_node *prev;

	prev = rb_prev(&em->rb_node);
	if (!prev)
		return NULL;
	return container_of(prev, struct extent_map, rb_node);
}

static int merge_extent_mapping(struct extent_map_tree *em_tree,
				struct extent_map *existing,
				struct extent_map *em,
				u64 map_start)
{
	struct extent_map *prev;
	struct extent_map *next;
	u64 start;
	u64 end;
	u64 start_diff;

	BUG_ON(map_start < em->start || map_start >= extent_map_end(em));

	if (existing->start > map_start) {
		next = existing;
		prev = prev_extent_map(next);
	} else {
		prev = existing;
		next = next_extent_map(prev);
	}

	start = prev ? extent_map_end(prev) : em->start;
	start = max_t(u64, start, em->start);
	end = next ? next->start : extent_map_end(em);
	end = min_t(u64, end, extent_map_end(em));
	start_diff = start - em->start;
	em->start = start;
	em->len = end - start;
	if (em->block_start < EXTENT_MAP_LAST_BYTE &&
	    !test_bit(EXTENT_FLAG_COMPRESSED, &em->flags)) {
		em->block_start += start_diff;
		em->block_len -= start_diff;
	}
	return add_extent_mapping(em_tree, em, 0);
}

static noinline int uncompress_inline(struct btrfs_path *path,
				      struct page *page,
				      size_t pg_offset, u64 extent_offset,
				      struct btrfs_file_extent_item *item)
{
	int ret;
	struct extent_buffer *leaf = path->nodes[0];
	char *tmp;
	size_t max_size;
	unsigned long inline_size;
	unsigned long ptr;
	int compress_type;

	WARN_ON(pg_offset != 0);
	compress_type = btrfs_file_extent_compression(leaf, item);
	max_size = btrfs_file_extent_ram_bytes(leaf, item);
	inline_size = btrfs_file_extent_inline_item_len(leaf,
					btrfs_item_nr(path->slots[0]));
	tmp = kmalloc(inline_size, GFP_NOFS);
	if (!tmp)
		return -ENOMEM;
	ptr = btrfs_file_extent_inline_start(item);

	read_extent_buffer(leaf, tmp, ptr, inline_size);

	max_size = min_t(unsigned long, PAGE_CACHE_SIZE, max_size);
	ret = btrfs_decompress(compress_type, tmp, page,
			       extent_offset, inline_size, max_size);
	kfree(tmp);
	return ret;
}

struct extent_map *btrfs_get_extent(struct inode *inode, struct page *page,
				    size_t pg_offset, u64 start, u64 len,
				    int create)
{
	int ret;
	int err = 0;
	u64 extent_start = 0;
	u64 extent_end = 0;
	u64 objectid = btrfs_ino(inode);
	u32 found_type;
	struct btrfs_path *path = NULL;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_file_extent_item *item;
	struct extent_buffer *leaf;
	struct btrfs_key found_key;
	struct extent_map *em = NULL;
	struct extent_map_tree *em_tree = &BTRFS_I(inode)->extent_tree;
	struct extent_io_tree *io_tree = &BTRFS_I(inode)->io_tree;
	struct btrfs_trans_handle *trans = NULL;
	const bool new_inline = !page || create;

again:
	read_lock(&em_tree->lock);
	em = lookup_extent_mapping(em_tree, start, len);
	if (em)
		em->bdev = root->fs_info->fs_devices->latest_bdev;
	read_unlock(&em_tree->lock);

	if (em) {
		if (em->start > start || em->start + em->len <= start)
			free_extent_map(em);
		else if (em->block_start == EXTENT_MAP_INLINE && page)
			free_extent_map(em);
		else
			goto out;
	}
	em = alloc_extent_map();
	if (!em) {
		err = -ENOMEM;
		goto out;
	}
	em->bdev = root->fs_info->fs_devices->latest_bdev;
	em->start = EXTENT_MAP_HOLE;
	em->orig_start = EXTENT_MAP_HOLE;
	em->len = (u64)-1;
	em->block_len = (u64)-1;

	if (!path) {
		path = btrfs_alloc_path();
		if (!path) {
			err = -ENOMEM;
			goto out;
		}
		 
		path->reada = READA_FORWARD;
	}

	ret = btrfs_lookup_file_extent(trans, root, path,
				       objectid, start, trans != NULL);
	if (ret < 0) {
		err = ret;
		goto out;
	}

	if (ret != 0) {
		if (path->slots[0] == 0)
			goto not_found;
		path->slots[0]--;
	}

	leaf = path->nodes[0];
	item = btrfs_item_ptr(leaf, path->slots[0],
			      struct btrfs_file_extent_item);
	 
	btrfs_item_key_to_cpu(leaf, &found_key, path->slots[0]);
	found_type = found_key.type;
	if (found_key.objectid != objectid ||
	    found_type != BTRFS_EXTENT_DATA_KEY) {
		 
		extent_end = start;
		goto next;
	}

	found_type = btrfs_file_extent_type(leaf, item);
	extent_start = found_key.offset;
	if (found_type == BTRFS_FILE_EXTENT_REG ||
	    found_type == BTRFS_FILE_EXTENT_PREALLOC) {
		extent_end = extent_start +
		       btrfs_file_extent_num_bytes(leaf, item);
	} else if (found_type == BTRFS_FILE_EXTENT_INLINE) {
		size_t size;
		size = btrfs_file_extent_inline_len(leaf, path->slots[0], item);
		extent_end = ALIGN(extent_start + size, root->sectorsize);
	}
next:
	if (start >= extent_end) {
		path->slots[0]++;
		if (path->slots[0] >= btrfs_header_nritems(leaf)) {
			ret = btrfs_next_leaf(root, path);
			if (ret < 0) {
				err = ret;
				goto out;
			}
			if (ret > 0)
				goto not_found;
			leaf = path->nodes[0];
		}
		btrfs_item_key_to_cpu(leaf, &found_key, path->slots[0]);
		if (found_key.objectid != objectid ||
		    found_key.type != BTRFS_EXTENT_DATA_KEY)
			goto not_found;
		if (start + len <= found_key.offset)
			goto not_found;
		if (start > found_key.offset)
			goto next;
		em->start = start;
		em->orig_start = start;
		em->len = found_key.offset - start;
		goto not_found_em;
	}

	btrfs_extent_item_to_extent_map(inode, path, item, new_inline, em);

	if (found_type == BTRFS_FILE_EXTENT_REG ||
	    found_type == BTRFS_FILE_EXTENT_PREALLOC) {
		goto insert;
	} else if (found_type == BTRFS_FILE_EXTENT_INLINE) {
		unsigned long ptr;
		char *map;
		size_t size;
		size_t extent_offset;
		size_t copy_size;

		if (new_inline)
			goto out;

		size = btrfs_file_extent_inline_len(leaf, path->slots[0], item);
		extent_offset = page_offset(page) + pg_offset - extent_start;
		copy_size = min_t(u64, PAGE_CACHE_SIZE - pg_offset,
				size - extent_offset);
		em->start = extent_start + extent_offset;
		em->len = ALIGN(copy_size, root->sectorsize);
		em->orig_block_len = em->len;
		em->orig_start = em->start;
		ptr = btrfs_file_extent_inline_start(item) + extent_offset;
		if (create == 0 && !PageUptodate(page)) {
			if (btrfs_file_extent_compression(leaf, item) !=
			    BTRFS_COMPRESS_NONE) {
				ret = uncompress_inline(path, page, pg_offset,
							extent_offset, item);
				if (ret) {
					err = ret;
					goto out;
				}
			} else {
				map = kmap(page);
				read_extent_buffer(leaf, map + pg_offset, ptr,
						   copy_size);
				if (pg_offset + copy_size < PAGE_CACHE_SIZE) {
					memset(map + pg_offset + copy_size, 0,
					       PAGE_CACHE_SIZE - pg_offset -
					       copy_size);
				}
				kunmap(page);
			}
			flush_dcache_page(page);
		} else if (create && PageUptodate(page)) {
			BUG();
			if (!trans) {
				kunmap(page);
				free_extent_map(em);
				em = NULL;

				btrfs_release_path(path);
				trans = btrfs_join_transaction(root);

				if (IS_ERR(trans))
					return ERR_CAST(trans);
				goto again;
			}
			map = kmap(page);
			write_extent_buffer(leaf, map + pg_offset, ptr,
					    copy_size);
			kunmap(page);
			btrfs_mark_buffer_dirty(leaf);
		}
		set_extent_uptodate(io_tree, em->start,
				    extent_map_end(em) - 1, NULL, GFP_NOFS);
		goto insert;
	}
not_found:
	em->start = start;
	em->orig_start = start;
	em->len = len;
not_found_em:
	em->block_start = EXTENT_MAP_HOLE;
	set_bit(EXTENT_FLAG_VACANCY, &em->flags);
insert:
	btrfs_release_path(path);
	if (em->start > start || extent_map_end(em) <= start) {
		btrfs_err(root->fs_info, "bad extent! em: [%llu %llu] passed [%llu %llu]",
			em->start, em->len, start, len);
		err = -EIO;
		goto out;
	}

	err = 0;
	write_lock(&em_tree->lock);
	ret = add_extent_mapping(em_tree, em, 0);
	 
	if (ret == -EEXIST) {
		struct extent_map *existing;

		ret = 0;

		existing = search_extent_mapping(em_tree, start, len);
		 
		if (existing->start == em->start &&
		    extent_map_end(existing) >= extent_map_end(em) &&
		    em->block_start == existing->block_start) {
			 
			free_extent_map(em);
			em = existing;
			err = 0;

		} else if (start >= extent_map_end(existing) ||
		    start <= existing->start) {
			 
			err = merge_extent_mapping(em_tree, existing,
						   em, start);
			free_extent_map(existing);
			if (err) {
				free_extent_map(em);
				em = NULL;
			}
		} else {
			free_extent_map(em);
			em = existing;
			err = 0;
		}
	}
	write_unlock(&em_tree->lock);
out:

	trace_btrfs_get_extent(root, em);

	btrfs_free_path(path);
	if (trans) {
		ret = btrfs_end_transaction(trans, root);
		if (!err)
			err = ret;
	}
	if (err) {
		free_extent_map(em);
		return ERR_PTR(err);
	}
	BUG_ON(!em);  
	return em;
}

struct extent_map *btrfs_get_extent_fiemap(struct inode *inode, struct page *page,
					   size_t pg_offset, u64 start, u64 len,
					   int create)
{
	struct extent_map *em;
	struct extent_map *hole_em = NULL;
	u64 range_start = start;
	u64 end;
	u64 found;
	u64 found_end;
	int err = 0;

	em = btrfs_get_extent(inode, page, pg_offset, start, len, create);
	if (IS_ERR(em))
		return em;
	if (em) {
		 
		if (em->block_start != EXTENT_MAP_HOLE &&
		    !test_bit(EXTENT_FLAG_PREALLOC, &em->flags))
			return em;
		else
			hole_em = em;
	}

	end = start + len;
	if (end < start)
		end = (u64)-1;
	else
		end -= 1;

	em = NULL;

	found = count_range_bits(&BTRFS_I(inode)->io_tree, &range_start,
				 end, len, EXTENT_DELALLOC, 1);
	found_end = range_start + found;
	if (found_end < range_start)
		found_end = (u64)-1;

	if (range_start > end || found_end <= start) {
		em = hole_em;
		hole_em = NULL;
		goto out;
	}

	range_start = max(start, range_start);
	found = found_end - range_start;

	if (found > 0) {
		u64 hole_start = start;
		u64 hole_len = len;

		em = alloc_extent_map();
		if (!em) {
			err = -ENOMEM;
			goto out;
		}
		 
		if (hole_em) {
			u64 calc_end = extent_map_end(hole_em);

			if (calc_end <= start || (hole_em->start > end)) {
				free_extent_map(hole_em);
				hole_em = NULL;
			} else {
				hole_start = max(hole_em->start, start);
				hole_len = calc_end - hole_start;
			}
		}
		em->bdev = NULL;
		if (hole_em && range_start > hole_start) {
			 
			em->len = min(hole_len,
				      range_start - hole_start);
			em->start = hole_start;
			em->orig_start = hole_start;
			 
			em->block_start = hole_em->block_start;
			em->block_len = hole_len;
			if (test_bit(EXTENT_FLAG_PREALLOC, &hole_em->flags))
				set_bit(EXTENT_FLAG_PREALLOC, &em->flags);
		} else {
			em->start = range_start;
			em->len = found;
			em->orig_start = range_start;
			em->block_start = EXTENT_MAP_DELALLOC;
			em->block_len = found;
		}
	} else if (hole_em) {
		return hole_em;
	}
out:

	free_extent_map(hole_em);
	if (err) {
		free_extent_map(em);
		return ERR_PTR(err);
	}
	return em;
}

static struct extent_map *btrfs_create_dio_extent(struct inode *inode,
						  const u64 start,
						  const u64 len,
						  const u64 orig_start,
						  const u64 block_start,
						  const u64 block_len,
						  const u64 orig_block_len,
						  const u64 ram_bytes,
						  const int type)
{
	struct extent_map *em = NULL;
	int ret;

	down_read(&BTRFS_I(inode)->dio_sem);
	if (type != BTRFS_ORDERED_NOCOW) {
		em = create_pinned_em(inode, start, len, orig_start,
				      block_start, block_len, orig_block_len,
				      ram_bytes, type);
		if (IS_ERR(em))
			goto out;
	}
	ret = btrfs_add_ordered_extent_dio(inode, start, block_start,
					   len, block_len, type);
	if (ret) {
		if (em) {
			free_extent_map(em);
			btrfs_drop_extent_cache(inode, start,
						start + len - 1, 0);
		}
		em = ERR_PTR(ret);
	}
 out:
	up_read(&BTRFS_I(inode)->dio_sem);

	return em;
}

static struct extent_map *btrfs_new_extent_direct(struct inode *inode,
						  u64 start, u64 len)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct extent_map *em;
	struct btrfs_key ins;
	u64 alloc_hint;
	int ret;

	alloc_hint = get_extent_allocation_hint(inode, start, len);
	ret = btrfs_reserve_extent(root, len, root->sectorsize, 0,
				   alloc_hint, &ins, 1, 1);
	if (ret)
		return ERR_PTR(ret);

	em = btrfs_create_dio_extent(inode, start, ins.offset, start,
				     ins.objectid, ins.offset, ins.offset,
				     ins.offset, 0);
	btrfs_dec_block_group_reservations(root->fs_info, ins.objectid);
	if (IS_ERR(em))
		btrfs_free_reserved_extent(root, ins.objectid, ins.offset, 1);

	return em;
}

noinline int can_nocow_extent(struct inode *inode, u64 offset, u64 *len,
			      u64 *orig_start, u64 *orig_block_len,
			      u64 *ram_bytes)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_path *path;
	int ret;
	struct extent_buffer *leaf;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct extent_io_tree *io_tree = &BTRFS_I(inode)->io_tree;
	struct btrfs_file_extent_item *fi;
	struct btrfs_key key;
	u64 disk_bytenr;
	u64 backref_offset;
	u64 extent_end;
	u64 num_bytes;
	int slot;
	int found_type;
	bool nocow = (BTRFS_I(inode)->flags & BTRFS_INODE_NODATACOW);

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	ret = btrfs_lookup_file_extent(NULL, root, path, btrfs_ino(inode),
				       offset, 0);
	if (ret < 0)
		goto out;

	slot = path->slots[0];
	if (ret == 1) {
		if (slot == 0) {
			 
			ret = 0;
			goto out;
		}
		slot--;
	}
	ret = 0;
	leaf = path->nodes[0];
	btrfs_item_key_to_cpu(leaf, &key, slot);
	if (key.objectid != btrfs_ino(inode) ||
	    key.type != BTRFS_EXTENT_DATA_KEY) {
		 
		goto out;
	}

	if (key.offset > offset) {
		 
		goto out;
	}

	fi = btrfs_item_ptr(leaf, slot, struct btrfs_file_extent_item);
	found_type = btrfs_file_extent_type(leaf, fi);
	if (found_type != BTRFS_FILE_EXTENT_REG &&
	    found_type != BTRFS_FILE_EXTENT_PREALLOC) {
		 
		goto out;
	}

	if (!nocow && found_type == BTRFS_FILE_EXTENT_REG)
		goto out;

	extent_end = key.offset + btrfs_file_extent_num_bytes(leaf, fi);
	if (extent_end <= offset)
		goto out;

	disk_bytenr = btrfs_file_extent_disk_bytenr(leaf, fi);
	if (disk_bytenr == 0)
		goto out;

	if (btrfs_file_extent_compression(leaf, fi) ||
	    btrfs_file_extent_encryption(leaf, fi) ||
	    btrfs_file_extent_other_encoding(leaf, fi))
		goto out;

	backref_offset = btrfs_file_extent_offset(leaf, fi);

	if (orig_start) {
		*orig_start = key.offset - backref_offset;
		*orig_block_len = btrfs_file_extent_disk_num_bytes(leaf, fi);
		*ram_bytes = btrfs_file_extent_ram_bytes(leaf, fi);
	}

	if (btrfs_extent_readonly(root, disk_bytenr))
		goto out;

	num_bytes = min(offset + *len, extent_end) - offset;
	if (!nocow && found_type == BTRFS_FILE_EXTENT_PREALLOC) {
		u64 range_end;

		range_end = round_up(offset + num_bytes, root->sectorsize) - 1;
		ret = test_range_bit(io_tree, offset, range_end,
				     EXTENT_DELALLOC, 0, NULL);
		if (ret) {
			ret = -EAGAIN;
			goto out;
		}
	}

	btrfs_release_path(path);

	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans)) {
		ret = 0;
		goto out;
	}

	ret = btrfs_cross_ref_exist(trans, root, btrfs_ino(inode),
				    key.offset - backref_offset, disk_bytenr);
	btrfs_end_transaction(trans, root);
	if (ret) {
		ret = 0;
		goto out;
	}

	disk_bytenr += backref_offset;
	disk_bytenr += offset - key.offset;
	if (csum_exist_in_range(root, disk_bytenr, num_bytes))
				goto out;
	 
	*len = num_bytes;
	ret = 1;
out:
	btrfs_free_path(path);
	return ret;
}

bool btrfs_page_exists_in_range(struct inode *inode, loff_t start, loff_t end)
{
	struct radix_tree_root *root = &inode->i_mapping->page_tree;
	int found = false;
	void **pagep = NULL;
	struct page *page = NULL;
	int start_idx;
	int end_idx;

	start_idx = start >> PAGE_CACHE_SHIFT;

	end_idx = end >> PAGE_CACHE_SHIFT;

	rcu_read_lock();

	while (page == NULL &&
	       radix_tree_gang_lookup_slot(root, &pagep, NULL, start_idx, 1)) {
		page = radix_tree_deref_slot(pagep);
		if (unlikely(!page))
			break;

		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page)) {
				page = NULL;
				continue;
			}
			 
			page = NULL;
			break;  
		}

		if (!page_cache_get_speculative(page)) {
			page = NULL;
			continue;
		}

		if (unlikely(page != *pagep)) {
			page_cache_release(page);
			page = NULL;
		}
	}

	if (page) {
		if (page->index <= end_idx)
			found = true;
		page_cache_release(page);
	}

	rcu_read_unlock();
	return found;
}

static int lock_extent_direct(struct inode *inode, u64 lockstart, u64 lockend,
			      struct extent_state **cached_state, int writing)
{
	struct btrfs_ordered_extent *ordered;
	int ret = 0;

	while (1) {
		lock_extent_bits(&BTRFS_I(inode)->io_tree, lockstart, lockend,
				 cached_state);
		 
		ordered = btrfs_lookup_ordered_range(inode, lockstart,
						     lockend - lockstart + 1);

		if (!ordered &&
		    (!writing ||
		     !btrfs_page_exists_in_range(inode, lockstart, lockend)))
			break;

		unlock_extent_cached(&BTRFS_I(inode)->io_tree, lockstart, lockend,
				     cached_state, GFP_NOFS);

		if (ordered) {
			 
			if (writing ||
			    test_bit(BTRFS_ORDERED_DIRECT, &ordered->flags))
				btrfs_start_ordered_extent(inode, ordered, 1);
			else
				ret = -ENOTBLK;
			btrfs_put_ordered_extent(ordered);
		} else {
			 
			ret = -ENOTBLK;
		}

		if (ret)
			break;

		cond_resched();
	}

	return ret;
}

static struct extent_map *create_pinned_em(struct inode *inode, u64 start,
					   u64 len, u64 orig_start,
					   u64 block_start, u64 block_len,
					   u64 orig_block_len, u64 ram_bytes,
					   int type)
{
	struct extent_map_tree *em_tree;
	struct extent_map *em;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int ret;

	em_tree = &BTRFS_I(inode)->extent_tree;
	em = alloc_extent_map();
	if (!em)
		return ERR_PTR(-ENOMEM);

	em->start = start;
	em->orig_start = orig_start;
	em->mod_start = start;
	em->mod_len = len;
	em->len = len;
	em->block_len = block_len;
	em->block_start = block_start;
	em->bdev = root->fs_info->fs_devices->latest_bdev;
	em->orig_block_len = orig_block_len;
	em->ram_bytes = ram_bytes;
	em->generation = -1;
	set_bit(EXTENT_FLAG_PINNED, &em->flags);
	if (type == BTRFS_ORDERED_PREALLOC)
		set_bit(EXTENT_FLAG_FILLING, &em->flags);

	do {
		btrfs_drop_extent_cache(inode, em->start,
				em->start + em->len - 1, 0);
		write_lock(&em_tree->lock);
		ret = add_extent_mapping(em_tree, em, 1);
		write_unlock(&em_tree->lock);
	} while (ret == -EEXIST);

	if (ret) {
		free_extent_map(em);
		return ERR_PTR(ret);
	}

	return em;
}

static void adjust_dio_outstanding_extents(struct inode *inode,
					   struct btrfs_dio_data *dio_data,
					   const u64 len)
{
	unsigned num_extents;

	num_extents = (unsigned) div64_u64(len + BTRFS_MAX_EXTENT_SIZE - 1,
					   BTRFS_MAX_EXTENT_SIZE);
	 
	if (dio_data->outstanding_extents >= num_extents) {
		dio_data->outstanding_extents -= num_extents;
	} else {
		 
		u64 num_needed = num_extents - dio_data->outstanding_extents;

		spin_lock(&BTRFS_I(inode)->lock);
		BTRFS_I(inode)->outstanding_extents += num_needed;
		spin_unlock(&BTRFS_I(inode)->lock);
	}
}

static int btrfs_get_blocks_direct(struct inode *inode, sector_t iblock,
				   struct buffer_head *bh_result, int create)
{
	struct extent_map *em;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct extent_state *cached_state = NULL;
	struct btrfs_dio_data *dio_data = NULL;
	u64 start = iblock << inode->i_blkbits;
	u64 lockstart, lockend;
	u64 len = bh_result->b_size;
	int unlock_bits = EXTENT_LOCKED;
	int ret = 0;

	if (create)
		unlock_bits |= EXTENT_DIRTY;
	else
		len = min_t(u64, len, root->sectorsize);

	lockstart = start;
	lockend = start + len - 1;

	if (current->journal_info) {
		 
		dio_data = current->journal_info;
		current->journal_info = NULL;
	}

	if (lock_extent_direct(inode, lockstart, lockend, &cached_state,
			       create)) {
		ret = -ENOTBLK;
		goto err;
	}

	em = btrfs_get_extent(inode, NULL, 0, start, len, 0);
	if (IS_ERR(em)) {
		ret = PTR_ERR(em);
		goto unlock_err;
	}

	if (test_bit(EXTENT_FLAG_COMPRESSED, &em->flags) ||
	    em->block_start == EXTENT_MAP_INLINE) {
		free_extent_map(em);
		ret = -ENOTBLK;
		goto unlock_err;
	}

	if (!create && (em->block_start == EXTENT_MAP_HOLE ||
			test_bit(EXTENT_FLAG_PREALLOC, &em->flags))) {
		free_extent_map(em);
		goto unlock_err;
	}

	if (!create) {
		len = min(len, em->len - (start - em->start));
		lockstart = start + len;
		goto unlock;
	}

	if (test_bit(EXTENT_FLAG_PREALLOC, &em->flags) ||
	    ((BTRFS_I(inode)->flags & BTRFS_INODE_NODATACOW) &&
	     em->block_start != EXTENT_MAP_HOLE)) {
		int type;
		u64 block_start, orig_start, orig_block_len, ram_bytes;

		if (test_bit(EXTENT_FLAG_PREALLOC, &em->flags))
			type = BTRFS_ORDERED_PREALLOC;
		else
			type = BTRFS_ORDERED_NOCOW;
		len = min(len, em->len - (start - em->start));
		block_start = em->block_start + (start - em->start);

		if (can_nocow_extent(inode, start, &len, &orig_start,
				     &orig_block_len, &ram_bytes) == 1 &&
		    btrfs_inc_nocow_writers(root->fs_info, block_start)) {
			struct extent_map *em2;

			em2 = btrfs_create_dio_extent(inode, start, len,
						      orig_start, block_start,
						      len, orig_block_len,
						      ram_bytes, type);
			btrfs_dec_nocow_writers(root->fs_info, block_start);
			if (type == BTRFS_ORDERED_PREALLOC) {
				free_extent_map(em);
				em = em2;
			}
			if (em2 && IS_ERR(em2)) {
				ret = PTR_ERR(em2);
				goto unlock_err;
			}
			goto unlock;
		}
	}

	len = bh_result->b_size;
	free_extent_map(em);
	em = btrfs_new_extent_direct(inode, start, len);
	if (IS_ERR(em)) {
		ret = PTR_ERR(em);
		goto unlock_err;
	}
	len = min(len, em->len - (start - em->start));
unlock:
	bh_result->b_blocknr = (em->block_start + (start - em->start)) >>
		inode->i_blkbits;
	bh_result->b_size = len;
	bh_result->b_bdev = em->bdev;
	set_buffer_mapped(bh_result);
	if (create) {
		if (!test_bit(EXTENT_FLAG_PREALLOC, &em->flags))
			set_buffer_new(bh_result);

		if (start + len > i_size_read(inode))
			i_size_write(inode, start + len);

		adjust_dio_outstanding_extents(inode, dio_data, len);
		btrfs_free_reserved_data_space(inode, start, len);
		WARN_ON(dio_data->reserve < len);
		dio_data->reserve -= len;
		dio_data->unsubmitted_oe_range_end = start + len;
		current->journal_info = dio_data;
	}

	if (lockstart < lockend) {
		clear_extent_bit(&BTRFS_I(inode)->io_tree, lockstart,
				 lockend, unlock_bits, 1, 0,
				 &cached_state, GFP_NOFS);
	} else {
		free_extent_state(cached_state);
	}

	free_extent_map(em);

	return 0;

unlock_err:
	clear_extent_bit(&BTRFS_I(inode)->io_tree, lockstart, lockend,
			 unlock_bits, 1, 0, &cached_state, GFP_NOFS);
err:
	if (dio_data)
		current->journal_info = dio_data;
	 
	if (create && dio_data)
		adjust_dio_outstanding_extents(inode, dio_data, len);

	return ret;
}

static inline int submit_dio_repair_bio(struct inode *inode, struct bio *bio,
					int rw, int mirror_num)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int ret;

	BUG_ON(rw & REQ_WRITE);

	bio_get(bio);

	ret = btrfs_bio_wq_end_io(root->fs_info, bio,
				  BTRFS_WQ_ENDIO_DIO_REPAIR);
	if (ret)
		goto err;

	ret = btrfs_map_bio(root, rw, bio, mirror_num, 0);
err:
	bio_put(bio);
	return ret;
}

static int btrfs_check_dio_repairable(struct inode *inode,
				      struct bio *failed_bio,
				      struct io_failure_record *failrec,
				      int failed_mirror)
{
	int num_copies;

	num_copies = btrfs_num_copies(BTRFS_I(inode)->root->fs_info,
				      failrec->logical, failrec->len);
	if (num_copies == 1) {
		 
		pr_debug("Check DIO Repairable: cannot repair, num_copies=%d, next_mirror %d, failed_mirror %d\n",
			 num_copies, failrec->this_mirror, failed_mirror);
		return 0;
	}

	failrec->failed_mirror = failed_mirror;
	failrec->this_mirror++;
	if (failrec->this_mirror == failed_mirror)
		failrec->this_mirror++;

	if (failrec->this_mirror > num_copies) {
		pr_debug("Check DIO Repairable: (fail) num_copies=%d, next_mirror %d, failed_mirror %d\n",
			 num_copies, failrec->this_mirror, failed_mirror);
		return 0;
	}

	return 1;
}

static int dio_read_error(struct inode *inode, struct bio *failed_bio,
			  struct page *page, u64 start, u64 end,
			  int failed_mirror, bio_end_io_t *repair_endio,
			  void *repair_arg)
{
	struct io_failure_record *failrec;
	struct bio *bio;
	int isector;
	int read_mode;
	int ret;

	BUG_ON(failed_bio->bi_rw & REQ_WRITE);

	ret = btrfs_get_io_failure_record(inode, start, end, &failrec);
	if (ret)
		return ret;

	ret = btrfs_check_dio_repairable(inode, failed_bio, failrec,
					 failed_mirror);
	if (!ret) {
		free_io_failure(inode, failrec);
		return -EIO;
	}

	if (failed_bio->bi_vcnt > 1)
		read_mode = READ_SYNC | REQ_FAILFAST_DEV;
	else
		read_mode = READ_SYNC;

	isector = start - btrfs_io_bio(failed_bio)->logical;
	isector >>= inode->i_sb->s_blocksize_bits;
	bio = btrfs_create_repair_bio(inode, failed_bio, failrec, page,
				      0, isector, repair_endio, repair_arg);
	if (!bio) {
		free_io_failure(inode, failrec);
		return -EIO;
	}

	btrfs_debug(BTRFS_I(inode)->root->fs_info,
		    "Repair DIO Read Error: submitting new dio read[%#x] to this_mirror=%d, in_validation=%d\n",
		    read_mode, failrec->this_mirror, failrec->in_validation);

	ret = submit_dio_repair_bio(inode, bio, read_mode,
				    failrec->this_mirror);
	if (ret) {
		free_io_failure(inode, failrec);
		bio_put(bio);
	}

	return ret;
}

struct btrfs_retry_complete {
	struct completion done;
	struct inode *inode;
	u64 start;
	int uptodate;
};

static void btrfs_retry_endio_nocsum(struct bio *bio)
{
	struct btrfs_retry_complete *done = bio->bi_private;
	struct bio_vec *bvec;
	int i;

	if (bio->bi_error)
		goto end;

	done->uptodate = 1;
	bio_for_each_segment_all(bvec, bio, i)
		clean_io_failure(done->inode, done->start, bvec->bv_page, 0);
end:
	complete(&done->done);
	bio_put(bio);
}

static int __btrfs_correct_data_nocsum(struct inode *inode,
				       struct btrfs_io_bio *io_bio)
{
	struct bio_vec *bvec;
	struct btrfs_retry_complete done;
	u64 start;
	int i;
	int ret;

	start = io_bio->logical;
	done.inode = inode;

	bio_for_each_segment_all(bvec, &io_bio->bio, i) {
try_again:
		done.uptodate = 0;
		done.start = start;
		init_completion(&done.done);

		ret = dio_read_error(inode, &io_bio->bio, bvec->bv_page, start,
				     start + bvec->bv_len - 1,
				     io_bio->mirror_num,
				     btrfs_retry_endio_nocsum, &done);
		if (ret)
			return ret;

		wait_for_completion(&done.done);

		if (!done.uptodate) {
			 
			goto try_again;
		}

		start += bvec->bv_len;
	}

	return 0;
}

static void btrfs_retry_endio(struct bio *bio)
{
	struct btrfs_retry_complete *done = bio->bi_private;
	struct btrfs_io_bio *io_bio = btrfs_io_bio(bio);
	struct bio_vec *bvec;
	int uptodate;
	int ret;
	int i;

	if (bio->bi_error)
		goto end;

	uptodate = 1;
	bio_for_each_segment_all(bvec, bio, i) {
		ret = __readpage_endio_check(done->inode, io_bio, i,
					     bvec->bv_page, 0,
					     done->start, bvec->bv_len);
		if (!ret)
			clean_io_failure(done->inode, done->start,
					 bvec->bv_page, 0);
		else
			uptodate = 0;
	}

	done->uptodate = uptodate;
end:
	complete(&done->done);
	bio_put(bio);
}

static int __btrfs_subio_endio_read(struct inode *inode,
				    struct btrfs_io_bio *io_bio, int err)
{
	struct bio_vec *bvec;
	struct btrfs_retry_complete done;
	u64 start;
	u64 offset = 0;
	int i;
	int ret;

	err = 0;
	start = io_bio->logical;
	done.inode = inode;

	bio_for_each_segment_all(bvec, &io_bio->bio, i) {
		ret = __readpage_endio_check(inode, io_bio, i, bvec->bv_page,
					     0, start, bvec->bv_len);
		if (likely(!ret))
			goto next;
try_again:
		done.uptodate = 0;
		done.start = start;
		init_completion(&done.done);

		ret = dio_read_error(inode, &io_bio->bio, bvec->bv_page, start,
				     start + bvec->bv_len - 1,
				     io_bio->mirror_num,
				     btrfs_retry_endio, &done);
		if (ret) {
			err = ret;
			goto next;
		}

		wait_for_completion(&done.done);

		if (!done.uptodate) {
			 
			goto try_again;
		}
next:
		offset += bvec->bv_len;
		start += bvec->bv_len;
	}

	return err;
}

static int btrfs_subio_endio_read(struct inode *inode,
				  struct btrfs_io_bio *io_bio, int err)
{
	bool skip_csum = BTRFS_I(inode)->flags & BTRFS_INODE_NODATASUM;

	if (skip_csum) {
		if (unlikely(err))
			return __btrfs_correct_data_nocsum(inode, io_bio);
		else
			return 0;
	} else {
		return __btrfs_subio_endio_read(inode, io_bio, err);
	}
}

static void btrfs_endio_direct_read(struct bio *bio)
{
	struct btrfs_dio_private *dip = bio->bi_private;
	struct inode *inode = dip->inode;
	struct bio *dio_bio;
	struct btrfs_io_bio *io_bio = btrfs_io_bio(bio);
	int err = bio->bi_error;

	if (dip->flags & BTRFS_DIO_ORIG_BIO_SUBMITTED)
		err = btrfs_subio_endio_read(inode, io_bio, err);

	unlock_extent(&BTRFS_I(inode)->io_tree, dip->logical_offset,
		      dip->logical_offset + dip->bytes - 1);
	dio_bio = dip->dio_bio;

	kfree(dip);

	dio_bio->bi_error = bio->bi_error;
	dio_end_io(dio_bio, bio->bi_error);

	if (io_bio->end_io)
		io_bio->end_io(io_bio, err);
	bio_put(bio);
}

static void btrfs_endio_direct_write_update_ordered(struct inode *inode,
						    const u64 offset,
						    const u64 bytes,
						    const int uptodate)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_ordered_extent *ordered = NULL;
	u64 ordered_offset = offset;
	u64 ordered_bytes = bytes;
	int ret;

again:
	ret = btrfs_dec_test_first_ordered_pending(inode, &ordered,
						   &ordered_offset,
						   ordered_bytes,
						   uptodate);
	if (!ret)
		goto out_test;

	btrfs_init_work(&ordered->work, btrfs_endio_write_helper,
			finish_ordered_fn, NULL, NULL);
	btrfs_queue_work(root->fs_info->endio_write_workers,
			 &ordered->work);
out_test:
	 
	if (ordered_offset < offset + bytes) {
		ordered_bytes = offset + bytes - ordered_offset;
		ordered = NULL;
		goto again;
	}
}

static void btrfs_endio_direct_write(struct bio *bio)
{
	struct btrfs_dio_private *dip = bio->bi_private;
	struct bio *dio_bio = dip->dio_bio;

	btrfs_endio_direct_write_update_ordered(dip->inode,
						dip->logical_offset,
						dip->bytes,
						!bio->bi_error);

	kfree(dip);

	dio_bio->bi_error = bio->bi_error;
	dio_end_io(dio_bio, bio->bi_error);
	bio_put(bio);
}

static int __btrfs_submit_bio_start_direct_io(struct inode *inode, int rw,
				    struct bio *bio, int mirror_num,
				    unsigned long bio_flags, u64 offset)
{
	int ret;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	ret = btrfs_csum_one_bio(root, inode, bio, offset, 1);
	BUG_ON(ret);  
	return 0;
}

static void btrfs_end_dio_bio(struct bio *bio)
{
	struct btrfs_dio_private *dip = bio->bi_private;
	int err = bio->bi_error;

	if (err)
		btrfs_warn(BTRFS_I(dip->inode)->root->fs_info,
			   "direct IO failed ino %llu rw %lu sector %#Lx len %u err no %d",
			   btrfs_ino(dip->inode), bio->bi_rw,
			   (unsigned long long)bio->bi_iter.bi_sector,
			   bio->bi_iter.bi_size, err);

	if (dip->subio_endio)
		err = dip->subio_endio(dip->inode, btrfs_io_bio(bio), err);

	if (err) {
		dip->errors = 1;

		smp_mb__before_atomic();
	}

	if (!atomic_dec_and_test(&dip->pending_bios))
		goto out;

	if (dip->errors) {
		bio_io_error(dip->orig_bio);
	} else {
		dip->dio_bio->bi_error = 0;
		bio_endio(dip->orig_bio);
	}
out:
	bio_put(bio);
}

static struct bio *btrfs_dio_bio_alloc(struct block_device *bdev,
				       u64 first_sector, gfp_t gfp_flags)
{
	struct bio *bio;
	bio = btrfs_bio_alloc(bdev, first_sector, BIO_MAX_PAGES, gfp_flags);
	if (bio)
		bio_associate_current(bio);
	return bio;
}

static inline int btrfs_lookup_and_bind_dio_csum(struct btrfs_root *root,
						 struct inode *inode,
						 struct btrfs_dio_private *dip,
						 struct bio *bio,
						 u64 file_offset)
{
	struct btrfs_io_bio *io_bio = btrfs_io_bio(bio);
	struct btrfs_io_bio *orig_io_bio = btrfs_io_bio(dip->orig_bio);
	int ret;

	if (dip->logical_offset == file_offset) {
		ret = btrfs_lookup_bio_sums_dio(root, inode, dip->orig_bio,
						file_offset);
		if (ret)
			return ret;
	}

	if (bio == dip->orig_bio)
		return 0;

	file_offset -= dip->logical_offset;
	file_offset >>= inode->i_sb->s_blocksize_bits;
	io_bio->csum = (u8 *)(((u32 *)orig_io_bio->csum) + file_offset);

	return 0;
}

static inline int __btrfs_submit_dio_bio(struct bio *bio, struct inode *inode,
					 int rw, u64 file_offset, int skip_sum,
					 int async_submit)
{
	struct btrfs_dio_private *dip = bio->bi_private;
	int write = rw & REQ_WRITE;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int ret;

	if (async_submit)
		async_submit = !atomic_read(&BTRFS_I(inode)->sync_writers);

	bio_get(bio);

	if (!write) {
		ret = btrfs_bio_wq_end_io(root->fs_info, bio,
				BTRFS_WQ_ENDIO_DATA);
		if (ret)
			goto err;
	}

	if (skip_sum)
		goto map;

	if (write && async_submit) {
		ret = btrfs_wq_submit_bio(root->fs_info,
				   inode, rw, bio, 0, 0,
				   file_offset,
				   __btrfs_submit_bio_start_direct_io,
				   __btrfs_submit_bio_done);
		goto err;
	} else if (write) {
		 
		ret = btrfs_csum_one_bio(root, inode, bio, file_offset, 1);
		if (ret)
			goto err;
	} else {
		ret = btrfs_lookup_and_bind_dio_csum(root, inode, dip, bio,
						     file_offset);
		if (ret)
			goto err;
	}
map:
	ret = btrfs_map_bio(root, rw, bio, 0, async_submit);
err:
	bio_put(bio);
	return ret;
}

static int btrfs_submit_direct_hook(int rw, struct btrfs_dio_private *dip,
				    int skip_sum)
{
	struct inode *inode = dip->inode;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct bio *bio;
	struct bio *orig_bio = dip->orig_bio;
	struct bio_vec *bvec = orig_bio->bi_io_vec;
	u64 start_sector = orig_bio->bi_iter.bi_sector;
	u64 file_offset = dip->logical_offset;
	u64 submit_len = 0;
	u64 map_length;
	int nr_pages = 0;
	int ret;
	int async_submit = 0;

	map_length = orig_bio->bi_iter.bi_size;
	ret = btrfs_map_block(root->fs_info, rw, start_sector << 9,
			      &map_length, NULL, 0);
	if (ret)
		return -EIO;

	if (map_length >= orig_bio->bi_iter.bi_size) {
		bio = orig_bio;
		dip->flags |= BTRFS_DIO_ORIG_BIO_SUBMITTED;
		goto submit;
	}

	if (btrfs_get_alloc_profile(root, 1) & BTRFS_BLOCK_GROUP_RAID56_MASK)
		async_submit = 0;
	else
		async_submit = 1;

	bio = btrfs_dio_bio_alloc(orig_bio->bi_bdev, start_sector, GFP_NOFS);
	if (!bio)
		return -ENOMEM;

	bio->bi_private = dip;
	bio->bi_end_io = btrfs_end_dio_bio;
	btrfs_io_bio(bio)->logical = file_offset;
	atomic_inc(&dip->pending_bios);

	while (bvec <= (orig_bio->bi_io_vec + orig_bio->bi_vcnt - 1)) {
		if (map_length < submit_len + bvec->bv_len ||
		    bio_add_page(bio, bvec->bv_page, bvec->bv_len,
				 bvec->bv_offset) < bvec->bv_len) {
			 
			atomic_inc(&dip->pending_bios);
			ret = __btrfs_submit_dio_bio(bio, inode, rw,
						     file_offset, skip_sum,
						     async_submit);
			if (ret) {
				bio_put(bio);
				atomic_dec(&dip->pending_bios);
				goto out_err;
			}

			start_sector += submit_len >> 9;
			file_offset += submit_len;

			submit_len = 0;
			nr_pages = 0;

			bio = btrfs_dio_bio_alloc(orig_bio->bi_bdev,
						  start_sector, GFP_NOFS);
			if (!bio)
				goto out_err;
			bio->bi_private = dip;
			bio->bi_end_io = btrfs_end_dio_bio;
			btrfs_io_bio(bio)->logical = file_offset;

			map_length = orig_bio->bi_iter.bi_size;
			ret = btrfs_map_block(root->fs_info, rw,
					      start_sector << 9,
					      &map_length, NULL, 0);
			if (ret) {
				bio_put(bio);
				goto out_err;
			}
		} else {
			submit_len += bvec->bv_len;
			nr_pages++;
			bvec++;
		}
	}

submit:
	ret = __btrfs_submit_dio_bio(bio, inode, rw, file_offset, skip_sum,
				     async_submit);
	if (!ret)
		return 0;

	bio_put(bio);
out_err:
	dip->errors = 1;
	 
	smp_mb__before_atomic();
	if (atomic_dec_and_test(&dip->pending_bios))
		bio_io_error(dip->orig_bio);

	return 0;
}

static void btrfs_submit_direct(int rw, struct bio *dio_bio,
				struct inode *inode, loff_t file_offset)
{
	struct btrfs_dio_private *dip = NULL;
	struct bio *io_bio = NULL;
	struct btrfs_io_bio *btrfs_bio;
	int skip_sum;
	int write = rw & REQ_WRITE;
	int ret = 0;

	skip_sum = BTRFS_I(inode)->flags & BTRFS_INODE_NODATASUM;

	io_bio = btrfs_bio_clone(dio_bio, GFP_NOFS);
	if (!io_bio) {
		ret = -ENOMEM;
		goto free_ordered;
	}

	dip = kzalloc(sizeof(*dip), GFP_NOFS);
	if (!dip) {
		ret = -ENOMEM;
		goto free_ordered;
	}

	dip->private = dio_bio->bi_private;
	dip->inode = inode;
	dip->logical_offset = file_offset;
	dip->bytes = dio_bio->bi_iter.bi_size;
	dip->disk_bytenr = (u64)dio_bio->bi_iter.bi_sector << 9;
	io_bio->bi_private = dip;
	dip->orig_bio = io_bio;
	dip->dio_bio = dio_bio;
	atomic_set(&dip->pending_bios, 0);
	btrfs_bio = btrfs_io_bio(io_bio);
	btrfs_bio->logical = file_offset;

	if (write) {
		io_bio->bi_end_io = btrfs_endio_direct_write;
	} else {
		io_bio->bi_end_io = btrfs_endio_direct_read;
		dip->subio_endio = btrfs_subio_endio_read;
	}

	if (write) {
		struct btrfs_dio_data *dio_data = current->journal_info;

		dio_data->unsubmitted_oe_range_end = dip->logical_offset +
			dip->bytes;
		dio_data->unsubmitted_oe_range_start =
			dio_data->unsubmitted_oe_range_end;
	}

	ret = btrfs_submit_direct_hook(rw, dip, skip_sum);
	if (!ret)
		return;

	if (btrfs_bio->end_io)
		btrfs_bio->end_io(btrfs_bio, ret);

free_ordered:
	 
	if (io_bio && dip) {
		io_bio->bi_error = -EIO;
		bio_endio(io_bio);
		 
		dip = NULL;
		io_bio = NULL;
	} else {
		if (write)
			btrfs_endio_direct_write_update_ordered(inode,
						file_offset,
						dio_bio->bi_iter.bi_size,
						0);
		else
			unlock_extent(&BTRFS_I(inode)->io_tree, file_offset,
			      file_offset + dio_bio->bi_iter.bi_size - 1);

		dio_bio->bi_error = -EIO;
		 
		dio_end_io(dio_bio, ret);
	}
	if (io_bio)
		bio_put(io_bio);
	kfree(dip);
}

static ssize_t check_direct_IO(struct btrfs_root *root, struct kiocb *iocb,
			const struct iov_iter *iter, loff_t offset)
{
	int seg;
	int i;
	unsigned blocksize_mask = root->sectorsize - 1;
	ssize_t retval = -EINVAL;

	if (offset & blocksize_mask)
		goto out;

	if (iov_iter_alignment(iter) & blocksize_mask)
		goto out;

	if (iov_iter_rw(iter) == WRITE)
		return 0;
	 
	for (seg = 0; seg < iter->nr_segs; seg++) {
		for (i = seg + 1; i < iter->nr_segs; i++) {
			if (iter->iov[seg].iov_base == iter->iov[i].iov_base)
				goto out;
		}
	}
	retval = 0;
out:
	return retval;
}

static ssize_t btrfs_direct_IO(struct kiocb *iocb, struct iov_iter *iter,
			       loff_t offset)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_dio_data dio_data = { 0 };
	size_t count = 0;
	int flags = 0;
	bool wakeup = true;
	bool relock = false;
	ssize_t ret;

	if (check_direct_IO(BTRFS_I(inode)->root, iocb, iter, offset))
		return 0;

	inode_dio_begin(inode);
	smp_mb__after_atomic();

	count = iov_iter_count(iter);
	if (test_bit(BTRFS_INODE_HAS_ASYNC_EXTENT,
		     &BTRFS_I(inode)->runtime_flags))
		filemap_fdatawrite_range(inode->i_mapping, offset,
					 offset + count - 1);

	if (iov_iter_rw(iter) == WRITE) {
		 
		if (offset + count <= inode->i_size) {
			inode_unlock(inode);
			relock = true;
		}
		ret = btrfs_delalloc_reserve_space(inode, offset, count);
		if (ret)
			goto out;
		dio_data.outstanding_extents = div64_u64(count +
						BTRFS_MAX_EXTENT_SIZE - 1,
						BTRFS_MAX_EXTENT_SIZE);

		dio_data.reserve = round_up(count, root->sectorsize);
		dio_data.unsubmitted_oe_range_start = (u64)offset;
		dio_data.unsubmitted_oe_range_end = (u64)offset;
		current->journal_info = &dio_data;
	} else if (test_bit(BTRFS_INODE_READDIO_NEED_LOCK,
				     &BTRFS_I(inode)->runtime_flags)) {
		inode_dio_end(inode);
		flags = DIO_LOCKING | DIO_SKIP_HOLES;
		wakeup = false;
	}

	ret = __blockdev_direct_IO(iocb, inode,
				   BTRFS_I(inode)->root->fs_info->fs_devices->latest_bdev,
				   iter, offset, btrfs_get_blocks_direct, NULL,
				   btrfs_submit_direct, flags);
	if (iov_iter_rw(iter) == WRITE) {
		current->journal_info = NULL;
		if (ret < 0 && ret != -EIOCBQUEUED) {
			if (dio_data.reserve)
				btrfs_delalloc_release_space(inode, offset,
							     dio_data.reserve);
			 
			if (dio_data.unsubmitted_oe_range_start <
			    dio_data.unsubmitted_oe_range_end)
				btrfs_endio_direct_write_update_ordered(inode,
					dio_data.unsubmitted_oe_range_start,
					dio_data.unsubmitted_oe_range_end -
					dio_data.unsubmitted_oe_range_start,
					0);
		} else if (ret >= 0 && (size_t)ret < count)
			btrfs_delalloc_release_space(inode, offset,
						     count - (size_t)ret);
	}
out:
	if (wakeup)
		inode_dio_end(inode);
	if (relock)
		inode_lock(inode);

	return ret;
}

#define BTRFS_FIEMAP_FLAGS	(FIEMAP_FLAG_SYNC)

static int btrfs_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
		__u64 start, __u64 len)
{
	int	ret;

	ret = fiemap_check_flags(fieinfo, BTRFS_FIEMAP_FLAGS);
	if (ret)
		return ret;

	return extent_fiemap(inode, fieinfo, start, len, btrfs_get_extent_fiemap);
}

int btrfs_readpage(struct file *file, struct page *page)
{
	struct extent_io_tree *tree;
	tree = &BTRFS_I(page->mapping->host)->io_tree;
	return extent_read_full_page(tree, page, btrfs_get_extent, 0);
}

static int btrfs_writepage(struct page *page, struct writeback_control *wbc)
{
	struct extent_io_tree *tree;
	struct inode *inode = page->mapping->host;
	int ret;

	if (current->flags & PF_MEMALLOC) {
		redirty_page_for_writepage(wbc, page);
		unlock_page(page);
		return 0;
	}

	if (!igrab(inode)) {
		redirty_page_for_writepage(wbc, page);
		return AOP_WRITEPAGE_ACTIVATE;
	}
	tree = &BTRFS_I(page->mapping->host)->io_tree;
	ret = extent_write_full_page(tree, page, btrfs_get_extent, wbc);
	btrfs_add_delayed_iput(inode);
	return ret;
}

static int btrfs_writepages(struct address_space *mapping,
			    struct writeback_control *wbc)
{
	struct extent_io_tree *tree;

	tree = &BTRFS_I(mapping->host)->io_tree;
	return extent_writepages(tree, mapping, btrfs_get_extent, wbc);
}

static int
btrfs_readpages(struct file *file, struct address_space *mapping,
		struct list_head *pages, unsigned nr_pages)
{
	struct extent_io_tree *tree;
	tree = &BTRFS_I(mapping->host)->io_tree;
	return extent_readpages(tree, mapping, pages, nr_pages,
				btrfs_get_extent);
}
static int __btrfs_releasepage(struct page *page, gfp_t gfp_flags)
{
	struct extent_io_tree *tree;
	struct extent_map_tree *map;
	int ret;

	tree = &BTRFS_I(page->mapping->host)->io_tree;
	map = &BTRFS_I(page->mapping->host)->extent_tree;
	ret = try_release_extent_mapping(map, tree, page, gfp_flags);
	if (ret == 1) {
		ClearPagePrivate(page);
		set_page_private(page, 0);
		page_cache_release(page);
	}
	return ret;
}

static int btrfs_releasepage(struct page *page, gfp_t gfp_flags)
{
	if (PageWriteback(page) || PageDirty(page))
		return 0;
	return __btrfs_releasepage(page, gfp_flags & GFP_NOFS);
}

static void btrfs_invalidatepage(struct page *page, unsigned int offset,
				 unsigned int length)
{
	struct inode *inode = page->mapping->host;
	struct extent_io_tree *tree;
	struct btrfs_ordered_extent *ordered;
	struct extent_state *cached_state = NULL;
	u64 page_start = page_offset(page);
	u64 page_end = page_start + PAGE_CACHE_SIZE - 1;
	int inode_evicting = inode->i_state & I_FREEING;

	wait_on_page_writeback(page);

	tree = &BTRFS_I(inode)->io_tree;
	if (offset) {
		btrfs_releasepage(page, GFP_NOFS);
		return;
	}

	if (!inode_evicting)
		lock_extent_bits(tree, page_start, page_end, &cached_state);
	ordered = btrfs_lookup_ordered_extent(inode, page_start);
	if (ordered) {
		 
		if (!inode_evicting)
			clear_extent_bit(tree, page_start, page_end,
					 EXTENT_DIRTY | EXTENT_DELALLOC |
					 EXTENT_LOCKED | EXTENT_DO_ACCOUNTING |
					 EXTENT_DEFRAG, 1, 0, &cached_state,
					 GFP_NOFS);
		 
		if (TestClearPagePrivate2(page)) {
			struct btrfs_ordered_inode_tree *tree;
			u64 new_len;

			tree = &BTRFS_I(inode)->ordered_tree;

			spin_lock_irq(&tree->lock);
			set_bit(BTRFS_ORDERED_TRUNCATED, &ordered->flags);
			new_len = page_start - ordered->file_offset;
			if (new_len < ordered->truncated_len)
				ordered->truncated_len = new_len;
			spin_unlock_irq(&tree->lock);

			if (btrfs_dec_test_ordered_pending(inode, &ordered,
							   page_start,
							   PAGE_CACHE_SIZE, 1))
				btrfs_finish_ordered_io(ordered);
		}
		btrfs_put_ordered_extent(ordered);
		if (!inode_evicting) {
			cached_state = NULL;
			lock_extent_bits(tree, page_start, page_end,
					 &cached_state);
		}
	}

	if (PageDirty(page))
		btrfs_qgroup_free_data(inode, page_start, PAGE_SIZE);
	if (!inode_evicting) {
		clear_extent_bit(tree, page_start, page_end,
				 EXTENT_LOCKED | EXTENT_DIRTY |
				 EXTENT_DELALLOC | EXTENT_DO_ACCOUNTING |
				 EXTENT_DEFRAG, 1, 1,
				 &cached_state, GFP_NOFS);

		__btrfs_releasepage(page, GFP_NOFS);
	}

	ClearPageChecked(page);
	if (PagePrivate(page)) {
		ClearPagePrivate(page);
		set_page_private(page, 0);
		page_cache_release(page);
	}
}

int btrfs_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	struct inode *inode = file_inode(vma->vm_file);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct extent_io_tree *io_tree = &BTRFS_I(inode)->io_tree;
	struct btrfs_ordered_extent *ordered;
	struct extent_state *cached_state = NULL;
	char *kaddr;
	unsigned long zero_start;
	loff_t size;
	int ret;
	int reserved = 0;
	u64 page_start;
	u64 page_end;

	sb_start_pagefault(inode->i_sb);
	page_start = page_offset(page);
	page_end = page_start + PAGE_CACHE_SIZE - 1;

	ret = btrfs_delalloc_reserve_space(inode, page_start,
					   PAGE_CACHE_SIZE);
	if (!ret) {
		ret = file_update_time(vma->vm_file);
		reserved = 1;
	}
	if (ret) {
		if (ret == -ENOMEM)
			ret = VM_FAULT_OOM;
		else  
			ret = VM_FAULT_SIGBUS;
		if (reserved)
			goto out;
		goto out_noreserve;
	}

	ret = VM_FAULT_NOPAGE;  
again:
	lock_page(page);
	size = i_size_read(inode);

	if ((page->mapping != inode->i_mapping) ||
	    (page_start >= size)) {
		 
		goto out_unlock;
	}
	wait_on_page_writeback(page);

	lock_extent_bits(io_tree, page_start, page_end, &cached_state);
	set_page_extent_mapped(page);

	ordered = btrfs_lookup_ordered_extent(inode, page_start);
	if (ordered) {
		unlock_extent_cached(io_tree, page_start, page_end,
				     &cached_state, GFP_NOFS);
		unlock_page(page);
		btrfs_start_ordered_extent(inode, ordered, 1);
		btrfs_put_ordered_extent(ordered);
		goto again;
	}

	clear_extent_bit(&BTRFS_I(inode)->io_tree, page_start, page_end,
			  EXTENT_DIRTY | EXTENT_DELALLOC |
			  EXTENT_DO_ACCOUNTING | EXTENT_DEFRAG,
			  0, 0, &cached_state, GFP_NOFS);

	ret = btrfs_set_extent_delalloc(inode, page_start, page_end,
					&cached_state);
	if (ret) {
		unlock_extent_cached(io_tree, page_start, page_end,
				     &cached_state, GFP_NOFS);
		ret = VM_FAULT_SIGBUS;
		goto out_unlock;
	}
	ret = 0;

	if (page_start + PAGE_CACHE_SIZE > size)
		zero_start = size & ~PAGE_CACHE_MASK;
	else
		zero_start = PAGE_CACHE_SIZE;

	if (zero_start != PAGE_CACHE_SIZE) {
		kaddr = kmap(page);
		memset(kaddr + zero_start, 0, PAGE_CACHE_SIZE - zero_start);
		flush_dcache_page(page);
		kunmap(page);
	}
	ClearPageChecked(page);
	set_page_dirty(page);
	SetPageUptodate(page);

	BTRFS_I(inode)->last_trans = root->fs_info->generation;
	BTRFS_I(inode)->last_sub_trans = BTRFS_I(inode)->root->log_transid;
	BTRFS_I(inode)->last_log_commit = BTRFS_I(inode)->root->last_log_commit;

	unlock_extent_cached(io_tree, page_start, page_end, &cached_state, GFP_NOFS);

out_unlock:
	if (!ret) {
		sb_end_pagefault(inode->i_sb);
		return VM_FAULT_LOCKED;
	}
	unlock_page(page);
out:
	btrfs_delalloc_release_space(inode, page_start, PAGE_CACHE_SIZE);
out_noreserve:
	sb_end_pagefault(inode->i_sb);
	return ret;
}

static int btrfs_truncate(struct inode *inode)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_block_rsv *rsv;
	int ret = 0;
	int err = 0;
	struct btrfs_trans_handle *trans;
	u64 mask = root->sectorsize - 1;
	u64 min_size = btrfs_calc_trunc_metadata_size(root, 1);

	ret = btrfs_wait_ordered_range(inode, inode->i_size & (~mask),
				       (u64)-1);
	if (ret)
		return ret;

	rsv = btrfs_alloc_block_rsv(root, BTRFS_BLOCK_RSV_TEMP);
	if (!rsv)
		return -ENOMEM;
	rsv->size = min_size;
	rsv->failfast = 1;

	trans = btrfs_start_transaction(root, 2);
	if (IS_ERR(trans)) {
		err = PTR_ERR(trans);
		goto out;
	}

	ret = btrfs_block_rsv_migrate(&root->fs_info->trans_block_rsv, rsv,
				      min_size);
	BUG_ON(ret);

	set_bit(BTRFS_INODE_NEEDS_FULL_SYNC, &BTRFS_I(inode)->runtime_flags);
	trans->block_rsv = rsv;

	while (1) {
		ret = btrfs_truncate_inode_items(trans, root, inode,
						 inode->i_size,
						 BTRFS_EXTENT_DATA_KEY);
		if (ret != -ENOSPC && ret != -EAGAIN) {
			err = ret;
			break;
		}

		trans->block_rsv = &root->fs_info->trans_block_rsv;
		ret = btrfs_update_inode(trans, root, inode);
		if (ret) {
			err = ret;
			break;
		}

		btrfs_end_transaction(trans, root);
		btrfs_btree_balance_dirty(root);

		trans = btrfs_start_transaction(root, 2);
		if (IS_ERR(trans)) {
			ret = err = PTR_ERR(trans);
			trans = NULL;
			break;
		}

		ret = btrfs_block_rsv_migrate(&root->fs_info->trans_block_rsv,
					      rsv, min_size);
		BUG_ON(ret);	 
		trans->block_rsv = rsv;
	}

	if (ret == 0 && inode->i_nlink > 0) {
		trans->block_rsv = root->orphan_block_rsv;
		ret = btrfs_orphan_del(trans, inode);
		if (ret)
			err = ret;
	}

	if (trans) {
		trans->block_rsv = &root->fs_info->trans_block_rsv;
		ret = btrfs_update_inode(trans, root, inode);
		if (ret && !err)
			err = ret;

		ret = btrfs_end_transaction(trans, root);
		btrfs_btree_balance_dirty(root);
	}

out:
	btrfs_free_block_rsv(root, rsv);

	if (ret && !err)
		err = ret;

	return err;
}

int btrfs_create_subvol_root(struct btrfs_trans_handle *trans,
			     struct btrfs_root *new_root,
			     struct btrfs_root *parent_root,
			     u64 new_dirid)
{
	struct inode *inode;
	int err;
	u64 index = 0;

	inode = btrfs_new_inode(trans, new_root, NULL, "..", 2,
				new_dirid, new_dirid,
				S_IFDIR | (~current_umask() & S_IRWXUGO),
				&index);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	err = btrfs_syno_init_attr(trans, inode);
	if (err)
		goto out;
#endif  

	inode->i_op = &btrfs_dir_inode_operations;
	inode->i_fop = &btrfs_dir_file_operations;

	set_nlink(inode, 1);
	btrfs_i_size_write(inode, 0);
	unlock_new_inode(inode);

	err = btrfs_subvol_inherit_props(trans, new_root, parent_root);
	if (err)
		btrfs_err(new_root->fs_info,
			  "error inheriting subvolume %llu properties: %d",
			  new_root->root_key.objectid, err);

	err = btrfs_update_inode(trans, new_root, inode);

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
out:
#endif
	iput(inode);
	return err;
}

struct inode *btrfs_alloc_inode(struct super_block *sb)
{
	struct btrfs_inode *ei;
	struct inode *inode;

	ei = kmem_cache_alloc(btrfs_inode_cachep, GFP_NOFS);
	if (!ei)
		return NULL;

	ei->root = NULL;
	ei->generation = 0;
	ei->last_trans = 0;
	ei->last_sub_trans = 0;
	ei->logged_trans = 0;
	ei->delalloc_bytes = 0;
	ei->defrag_bytes = 0;
	ei->disk_i_size = 0;
	ei->flags = 0;
	ei->csum_bytes = 0;
	ei->index_cnt = (u64)-1;
	ei->dir_index = 0;
	ei->last_unlink_trans = 0;
	ei->last_log_commit = 0;
	ei->delayed_iput_count = 0;

	spin_lock_init(&ei->lock);
	ei->outstanding_extents = 0;
	ei->reserved_extents = 0;

	ei->runtime_flags = 0;
	ei->force_compress = BTRFS_COMPRESS_NONE;

	ei->delayed_node = NULL;

	ei->i_otime.tv_sec = 0;
	ei->i_otime.tv_nsec = 0;

	inode = &ei->vfs_inode;
	extent_map_tree_init(&ei->extent_tree);
#ifdef MY_ABC_HERE
	ei->extent_tree.inode = ei;
	INIT_LIST_HEAD(&ei->free_extent_map_inode);
	atomic_set(&ei->free_extent_map_counts, 0);
#endif  
	extent_io_tree_init(&ei->io_tree, &inode->i_data);
	extent_io_tree_init(&ei->io_failure_tree, &inode->i_data);
	ei->io_tree.track_uptodate = 1;
	ei->io_failure_tree.track_uptodate = 1;
	atomic_set(&ei->sync_writers, 0);
	mutex_init(&ei->log_mutex);
	mutex_init(&ei->delalloc_mutex);
	btrfs_ordered_inode_tree_init(&ei->ordered_tree);
	INIT_LIST_HEAD(&ei->delalloc_inodes);
	INIT_LIST_HEAD(&ei->delayed_iput);
	RB_CLEAR_NODE(&ei->rb_node);
	init_rwsem(&ei->dio_sem);

	return inode;
}

#ifdef CONFIG_BTRFS_FS_RUN_SANITY_TESTS
void btrfs_test_destroy_inode(struct inode *inode)
{
	btrfs_drop_extent_cache(inode, 0, (u64)-1, 0);
	kmem_cache_free(btrfs_inode_cachep, BTRFS_I(inode));
}
#endif

static void btrfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(btrfs_inode_cachep, BTRFS_I(inode));
}

void btrfs_destroy_inode(struct inode *inode)
{
	struct btrfs_ordered_extent *ordered;
	struct btrfs_root *root = BTRFS_I(inode)->root;

	WARN_ON(!hlist_empty(&inode->i_dentry));
	WARN_ON(inode->i_data.nrpages);
	WARN_ON(BTRFS_I(inode)->outstanding_extents);
	WARN_ON(BTRFS_I(inode)->reserved_extents);
	WARN_ON(BTRFS_I(inode)->delalloc_bytes);
	WARN_ON(BTRFS_I(inode)->csum_bytes);
	WARN_ON(BTRFS_I(inode)->defrag_bytes);

	if (!root)
		goto free;

	if (test_bit(BTRFS_INODE_HAS_ORPHAN_ITEM,
		     &BTRFS_I(inode)->runtime_flags)) {
		btrfs_info(root->fs_info, "inode %llu still on the orphan list",
			btrfs_ino(inode));
		atomic_dec(&root->orphan_inodes);
	}

	while (1) {
		ordered = btrfs_lookup_first_ordered_extent(inode, (u64)-1);
		if (!ordered)
			break;
		else {
			btrfs_err(root->fs_info, "found ordered extent %llu %llu on inode cleanup",
				ordered->file_offset, ordered->len);
			btrfs_remove_ordered_extent(inode, ordered);
			btrfs_put_ordered_extent(ordered);
			btrfs_put_ordered_extent(ordered);
		}
	}
	btrfs_qgroup_check_reserved_leak(inode);
	inode_tree_del(inode);
	btrfs_drop_extent_cache(inode, 0, (u64)-1, 0);
free:
	call_rcu(&inode->i_rcu, btrfs_i_callback);
}

int btrfs_drop_inode(struct inode *inode)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;

	if (root == NULL)
		return 1;

	if (btrfs_root_refs(&root->root_item) == 0)
		return 1;
	else
		return generic_drop_inode(inode);
}

static void init_once(void *foo)
{
	struct btrfs_inode *ei = (struct btrfs_inode *) foo;

	inode_init_once(&ei->vfs_inode);
}

void btrfs_destroy_cachep(void)
{
	 
	rcu_barrier();
	kmem_cache_destroy(btrfs_inode_cachep);
	kmem_cache_destroy(btrfs_trans_handle_cachep);
	kmem_cache_destroy(btrfs_transaction_cachep);
	kmem_cache_destroy(btrfs_path_cachep);
	kmem_cache_destroy(btrfs_free_space_cachep);
}

int btrfs_init_cachep(void)
{
	btrfs_inode_cachep = kmem_cache_create("btrfs_inode",
			sizeof(struct btrfs_inode), 0,
			SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, init_once);
	if (!btrfs_inode_cachep)
		goto fail;

	btrfs_trans_handle_cachep = kmem_cache_create("btrfs_trans_handle",
			sizeof(struct btrfs_trans_handle), 0,
			SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, NULL);
	if (!btrfs_trans_handle_cachep)
		goto fail;

	btrfs_transaction_cachep = kmem_cache_create("btrfs_transaction",
			sizeof(struct btrfs_transaction), 0,
			SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, NULL);
	if (!btrfs_transaction_cachep)
		goto fail;

	btrfs_path_cachep = kmem_cache_create("btrfs_path",
			sizeof(struct btrfs_path), 0,
			SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, NULL);
	if (!btrfs_path_cachep)
		goto fail;

	btrfs_free_space_cachep = kmem_cache_create("btrfs_free_space",
			sizeof(struct btrfs_free_space), 0,
			SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, NULL);
	if (!btrfs_free_space_cachep)
		goto fail;

	return 0;
fail:
	btrfs_destroy_cachep();
	return -ENOMEM;
}

static int btrfs_getattr(struct vfsmount *mnt,
			 struct dentry *dentry, struct kstat *stat)
{
	u64 delalloc_bytes;
	struct inode *inode = d_inode(dentry);
	u32 blocksize = inode->i_sb->s_blocksize;

	generic_fillattr(inode, stat);
	stat->dev = BTRFS_I(inode)->root->anon_dev;
	stat->blksize = PAGE_CACHE_SIZE;

	spin_lock(&BTRFS_I(inode)->lock);
	delalloc_bytes = BTRFS_I(inode)->delalloc_bytes;
	spin_unlock(&BTRFS_I(inode)->lock);
	stat->blocks = (ALIGN(inode_get_bytes(inode), blocksize) +
			ALIGN(delalloc_bytes, blocksize)) >> 9;
	return 0;
}

#ifdef MY_ABC_HERE
int btrfs_syno_getattr(struct dentry *d, struct kstat *stat, int flags)
{
	int err = 0;
#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	struct inode *inode = d->d_inode;
#endif

#ifdef MY_ABC_HERE
	if (flags & SYNOST_CREATE_TIME) {
		struct btrfs_timespec crtime;

		if (0 == (inode->i_flags & S_CREATE_TIME_CACHED)) {
			err = __btrfs_getxattr(inode, XATTR_SYNO_PREFIX XATTR_SYNO_CREATE_TIME,
								   &crtime, sizeof(crtime));
			if (0 < err) {
				inode->i_create_time.tv_sec = le64_to_cpu(crtime.sec);
				inode->i_create_time.tv_nsec = le32_to_cpu(crtime.nsec);
			} else if (-ENODATA == err) {
				inode->i_create_time.tv_sec = 0;
				inode->i_create_time.tv_nsec = 0;
			} else {
				return err;
			}
			inode->i_flags |= S_CREATE_TIME_CACHED;
		}
		stat->syno_create_time = inode->i_create_time;
		err = 0;
	}
#endif  

#ifdef MY_ABC_HERE
	if (flags & SYNOST_ARCHIVE_BIT) {
		stat->syno_archive_bit = inode->i_archive_bit;
	}
#endif  

#ifdef MY_ABC_HERE
	if (flags & SYNOST_ARCHIVE_VER) {
		err = btrfs_syno_get_archive_ver(d, &stat->syno_archive_version);
	}
#endif  

	return err;
}
#endif  

static int btrfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			   struct inode *new_dir, struct dentry *new_dentry)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_root *root = BTRFS_I(old_dir)->root;
	struct btrfs_root *dest = BTRFS_I(new_dir)->root;
	struct inode *new_inode = d_inode(new_dentry);
	struct inode *old_inode = d_inode(old_dentry);
	u64 index = 0;
	u64 root_objectid;
	int ret;
	u64 old_ino = btrfs_ino(old_inode);
	bool log_pinned = false;

	if (btrfs_ino(new_dir) == BTRFS_EMPTY_SUBVOL_DIR_OBJECTID)
		return -EPERM;

	if (old_ino != BTRFS_FIRST_FREE_OBJECTID && root != dest)
		return -EXDEV;

	if (old_ino == BTRFS_EMPTY_SUBVOL_DIR_OBJECTID ||
	    (new_inode && btrfs_ino(new_inode) == BTRFS_FIRST_FREE_OBJECTID))
		return -ENOTEMPTY;

	if (S_ISDIR(old_inode->i_mode) && new_inode &&
	    new_inode->i_size > BTRFS_EMPTY_DIR_SIZE)
		return -ENOTEMPTY;

	ret = btrfs_check_dir_item_collision(dest, new_dir->i_ino,
			     new_dentry->d_name.name,
			     new_dentry->d_name.len);

	if (ret) {
		if (ret == -EEXIST) {
			 
			if (WARN_ON(!new_inode)) {
				return ret;
			}
		} else {
			 
			return ret;
		}
	}
	ret = 0;

	if (new_inode && S_ISREG(old_inode->i_mode) && new_inode->i_size)
		filemap_flush(old_inode->i_mapping);

	if (old_ino == BTRFS_FIRST_FREE_OBJECTID)
		down_read(&root->fs_info->subvol_sem);
	 
	trans = btrfs_start_transaction(root, 11);
	if (IS_ERR(trans)) {
                ret = PTR_ERR(trans);
                goto out_notrans;
        }

	if (dest != root)
		btrfs_record_root_in_trans(trans, dest);

	ret = btrfs_set_inode_index(new_dir, &index);
	if (ret)
		goto out_fail;

	BTRFS_I(old_inode)->dir_index = 0ULL;
	if (unlikely(old_ino == BTRFS_FIRST_FREE_OBJECTID)) {
		 
		btrfs_set_log_full_commit(root->fs_info, trans);
	} else {
		btrfs_pin_log_trans(root);
		log_pinned = true;
		ret = btrfs_insert_inode_ref(trans, dest,
					     new_dentry->d_name.name,
					     new_dentry->d_name.len,
					     old_ino,
					     btrfs_ino(new_dir), index);
		if (ret)
			goto out_fail;
	}

	inode_inc_iversion(old_dir);
	inode_inc_iversion(new_dir);
	inode_inc_iversion(old_inode);
	old_dir->i_ctime = old_dir->i_mtime =
	new_dir->i_ctime = new_dir->i_mtime =
	old_inode->i_ctime = current_fs_time(old_dir->i_sb);

	if (old_dentry->d_parent != new_dentry->d_parent)
		btrfs_record_unlink_dir(trans, old_dir, old_inode, 1);

	if (unlikely(old_ino == BTRFS_FIRST_FREE_OBJECTID)) {
		root_objectid = BTRFS_I(old_inode)->root->root_key.objectid;
		ret = btrfs_unlink_subvol(trans, root, old_dir, root_objectid,
					old_dentry->d_name.name,
					old_dentry->d_name.len);
	} else {
		ret = __btrfs_unlink_inode(trans, root, old_dir,
					d_inode(old_dentry),
					old_dentry->d_name.name,
					old_dentry->d_name.len);
		if (!ret)
			ret = btrfs_update_inode(trans, root, old_inode);
	}
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto out_fail;
	}

	if (new_inode) {
		inode_inc_iversion(new_inode);
		new_inode->i_ctime = current_fs_time(new_inode->i_sb);
		if (unlikely(btrfs_ino(new_inode) ==
			     BTRFS_EMPTY_SUBVOL_DIR_OBJECTID)) {
			root_objectid = BTRFS_I(new_inode)->location.objectid;
			ret = btrfs_unlink_subvol(trans, dest, new_dir,
						root_objectid,
						new_dentry->d_name.name,
						new_dentry->d_name.len);
			BUG_ON(new_inode->i_nlink == 0);
		} else {
			ret = btrfs_unlink_inode(trans, dest, new_dir,
						 d_inode(new_dentry),
						 new_dentry->d_name.name,
						 new_dentry->d_name.len);
		}
		if (!ret && new_inode->i_nlink == 0)
			ret = btrfs_orphan_add(trans, d_inode(new_dentry));
		if (ret) {
			btrfs_abort_transaction(trans, root, ret);
			goto out_fail;
		}
	}

	ret = btrfs_add_link(trans, new_dir, old_inode,
			     new_dentry->d_name.name,
			     new_dentry->d_name.len, 0, index);
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto out_fail;
	}

	if (old_inode->i_nlink == 1)
		BTRFS_I(old_inode)->dir_index = index;

	if (log_pinned) {
		struct dentry *parent = new_dentry->d_parent;

		btrfs_log_new_name(trans, old_inode, old_dir, parent);
		btrfs_end_log_trans(root);
		log_pinned = false;
	}
out_fail:
	 
	if (ret && log_pinned) {
		if (btrfs_inode_in_log(old_dir, root->fs_info->generation) ||
		    btrfs_inode_in_log(new_dir, root->fs_info->generation) ||
		    btrfs_inode_in_log(old_inode, root->fs_info->generation) ||
		    (new_inode &&
		     btrfs_inode_in_log(new_inode, root->fs_info->generation)))
		    btrfs_set_log_full_commit(root->fs_info, trans);

		btrfs_end_log_trans(root);
		log_pinned = false;
	}
	btrfs_end_transaction(trans, root);
out_notrans:
	if (old_ino == BTRFS_FIRST_FREE_OBJECTID)
		up_read(&root->fs_info->subvol_sem);

	return ret;
}

static int btrfs_rename2(struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry,
			 unsigned int flags)
{
	if (flags & ~RENAME_NOREPLACE)
		return -EINVAL;

	return btrfs_rename(old_dir, old_dentry, new_dir, new_dentry);
}

static void btrfs_run_delalloc_work(struct btrfs_work *work)
{
	struct btrfs_delalloc_work *delalloc_work;
	struct inode *inode;

	delalloc_work = container_of(work, struct btrfs_delalloc_work,
				     work);
	inode = delalloc_work->inode;
	filemap_flush(inode->i_mapping);
	if (test_bit(BTRFS_INODE_HAS_ASYNC_EXTENT,
				&BTRFS_I(inode)->runtime_flags))
		filemap_flush(inode->i_mapping);

	if (delalloc_work->delay_iput)
		btrfs_add_delayed_iput(inode);
	else
		iput(inode);
	complete(&delalloc_work->completion);
}

struct btrfs_delalloc_work *btrfs_alloc_delalloc_work(struct inode *inode,
						    int delay_iput)
{
	struct btrfs_delalloc_work *work;

	work = kmalloc(sizeof(*work), GFP_NOFS);
	if (!work)
		return NULL;

	init_completion(&work->completion);
	INIT_LIST_HEAD(&work->list);
	work->inode = inode;
	work->delay_iput = delay_iput;
	WARN_ON_ONCE(!inode);
	btrfs_init_work(&work->work, btrfs_flush_delalloc_helper,
			btrfs_run_delalloc_work, NULL, NULL);

	return work;
}

void btrfs_wait_and_free_delalloc_work(struct btrfs_delalloc_work *work)
{
	wait_for_completion(&work->completion);
	kfree(work);
}

static int __start_delalloc_inodes(struct btrfs_root *root, int delay_iput,
				   int nr)
{
	struct btrfs_inode *binode;
	struct inode *inode;
	struct btrfs_delalloc_work *work, *next;
	struct list_head works;
	struct list_head splice;
	int ret = 0;

	INIT_LIST_HEAD(&works);
	INIT_LIST_HEAD(&splice);

	mutex_lock(&root->delalloc_mutex);
	spin_lock(&root->delalloc_lock);
	list_splice_init(&root->delalloc_inodes, &splice);
	while (!list_empty(&splice)) {
		binode = list_entry(splice.next, struct btrfs_inode,
				    delalloc_inodes);

		list_move_tail(&binode->delalloc_inodes,
			       &root->delalloc_inodes);
		inode = igrab(&binode->vfs_inode);
		if (!inode) {
			cond_resched_lock(&root->delalloc_lock);
			continue;
		}
		spin_unlock(&root->delalloc_lock);

		work = btrfs_alloc_delalloc_work(inode, delay_iput);
		if (!work) {
			if (delay_iput)
				btrfs_add_delayed_iput(inode);
			else
				iput(inode);
			ret = -ENOMEM;
			goto out;
		}
		list_add_tail(&work->list, &works);
		btrfs_queue_work(root->fs_info->flush_workers,
				 &work->work);
		ret++;
		if (nr != -1 && ret >= nr)
			goto out;
		cond_resched();
		spin_lock(&root->delalloc_lock);
	}
	spin_unlock(&root->delalloc_lock);

out:
	list_for_each_entry_safe(work, next, &works, list) {
		list_del_init(&work->list);
		btrfs_wait_and_free_delalloc_work(work);
	}

	if (!list_empty_careful(&splice)) {
		spin_lock(&root->delalloc_lock);
		list_splice_tail(&splice, &root->delalloc_inodes);
		spin_unlock(&root->delalloc_lock);
	}
	mutex_unlock(&root->delalloc_mutex);
	return ret;
}

int btrfs_start_delalloc_inodes(struct btrfs_root *root, int delay_iput)
{
	int ret;

	if (test_bit(BTRFS_FS_STATE_ERROR, &root->fs_info->fs_state))
		return -EROFS;

	ret = __start_delalloc_inodes(root, delay_iput, -1);
	if (ret > 0)
		ret = 0;
	 
	atomic_inc(&root->fs_info->async_submit_draining);
	while (atomic_read(&root->fs_info->nr_async_submits) ||
	      atomic_read(&root->fs_info->async_delalloc_pages)) {
		wait_event(root->fs_info->async_submit_wait,
		   (atomic_read(&root->fs_info->nr_async_submits) == 0 &&
		    atomic_read(&root->fs_info->async_delalloc_pages) == 0));
	}
	atomic_dec(&root->fs_info->async_submit_draining);
	return ret;
}

int btrfs_start_delalloc_roots(struct btrfs_fs_info *fs_info, int delay_iput,
			       int nr)
{
	struct btrfs_root *root;
	struct list_head splice;
	int ret;

	if (test_bit(BTRFS_FS_STATE_ERROR, &fs_info->fs_state))
		return -EROFS;

	INIT_LIST_HEAD(&splice);

	mutex_lock(&fs_info->delalloc_root_mutex);
	spin_lock(&fs_info->delalloc_root_lock);
	list_splice_init(&fs_info->delalloc_roots, &splice);
	while (!list_empty(&splice) && nr) {
		root = list_first_entry(&splice, struct btrfs_root,
					delalloc_root);
		root = btrfs_grab_fs_root(root);
		BUG_ON(!root);
		list_move_tail(&root->delalloc_root,
			       &fs_info->delalloc_roots);
		spin_unlock(&fs_info->delalloc_root_lock);

		ret = __start_delalloc_inodes(root, delay_iput, nr);
		btrfs_put_fs_root(root);
		if (ret < 0)
			goto out;

		if (nr != -1) {
			nr -= ret;
			WARN_ON(nr < 0);
		}
		spin_lock(&fs_info->delalloc_root_lock);
	}
	spin_unlock(&fs_info->delalloc_root_lock);

	ret = 0;
	atomic_inc(&fs_info->async_submit_draining);
	while (atomic_read(&fs_info->nr_async_submits) ||
	      atomic_read(&fs_info->async_delalloc_pages)) {
		wait_event(fs_info->async_submit_wait,
		   (atomic_read(&fs_info->nr_async_submits) == 0 &&
		    atomic_read(&fs_info->async_delalloc_pages) == 0));
	}
	atomic_dec(&fs_info->async_submit_draining);
out:
	if (!list_empty_careful(&splice)) {
		spin_lock(&fs_info->delalloc_root_lock);
		list_splice_tail(&splice, &fs_info->delalloc_roots);
		spin_unlock(&fs_info->delalloc_root_lock);
	}
	mutex_unlock(&fs_info->delalloc_root_mutex);
	return ret;
}

static int btrfs_symlink(struct inode *dir, struct dentry *dentry,
			 const char *symname)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_root *root = BTRFS_I(dir)->root;
	struct btrfs_path *path;
	struct btrfs_key key;
	struct inode *inode = NULL;
	int err;
	int drop_inode = 0;
	u64 objectid;
	u64 index = 0;
	int name_len;
	int datasize;
	unsigned long ptr;
	struct btrfs_file_extent_item *ei;
	struct extent_buffer *leaf;
#if defined(MY_ABC_HERE)
	int credit_for_syno = 0;
#endif  

	name_len = strlen(symname);
	if (name_len > BTRFS_MAX_INLINE_DATA_SIZE(root))
		return -ENAMETOOLONG;

#ifdef MY_ABC_HERE
	 
	if (test_bit(BTRFS_INODE_HAS_PROPS, &BTRFS_I(dir)->runtime_flags))
		credit_for_syno++;
#endif  
	 
#if defined(MY_ABC_HERE)
	trans = btrfs_start_transaction(root, 7 + credit_for_syno);
#else
	trans = btrfs_start_transaction(root, 7);
#endif  
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	err = btrfs_find_free_ino(root, &objectid);
	if (err)
		goto out_unlock;

	inode = btrfs_new_inode(trans, root, dir, dentry->d_name.name,
				dentry->d_name.len, btrfs_ino(dir), objectid,
				S_IFLNK|S_IRWXUGO, &index);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_unlock;
	}

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	err = btrfs_syno_init_attr(trans, inode);
	if (err) {
		drop_inode = 1;
		goto out_unlock;
	}
#endif  

	inode->i_fop = &btrfs_file_operations;
	inode->i_op = &btrfs_file_inode_operations;
	inode->i_mapping->a_ops = &btrfs_aops;
	BTRFS_I(inode)->io_tree.ops = &btrfs_extent_io_ops;

	err = btrfs_init_inode_security(trans, inode, dir, &dentry->d_name);
	if (err)
		goto out_unlock_inode;

	path = btrfs_alloc_path();
	if (!path) {
		err = -ENOMEM;
		goto out_unlock_inode;
	}
	key.objectid = btrfs_ino(inode);
	key.offset = 0;
	key.type = BTRFS_EXTENT_DATA_KEY;
	datasize = btrfs_file_extent_calc_inline_size(name_len);
	err = btrfs_insert_empty_item(trans, root, path, &key,
				      datasize);
	if (err) {
		btrfs_free_path(path);
		goto out_unlock_inode;
	}
	leaf = path->nodes[0];
	ei = btrfs_item_ptr(leaf, path->slots[0],
			    struct btrfs_file_extent_item);
	btrfs_set_file_extent_generation(leaf, ei, trans->transid);
	btrfs_set_file_extent_type(leaf, ei,
				   BTRFS_FILE_EXTENT_INLINE);
	btrfs_set_file_extent_encryption(leaf, ei, 0);
	btrfs_set_file_extent_compression(leaf, ei, 0);
	btrfs_set_file_extent_other_encoding(leaf, ei, 0);
	btrfs_set_file_extent_ram_bytes(leaf, ei, name_len);

	ptr = btrfs_file_extent_inline_start(ei);
	write_extent_buffer(leaf, symname, ptr, name_len);
	btrfs_mark_buffer_dirty(leaf);
	btrfs_free_path(path);

	inode->i_op = &btrfs_symlink_inode_operations;
	inode->i_mapping->a_ops = &btrfs_symlink_aops;
	inode_set_bytes(inode, name_len);
	btrfs_i_size_write(inode, name_len);
	err = btrfs_update_inode(trans, root, inode);
	 
	if (!err)
		err = btrfs_add_nondir(trans, dir, dentry, inode, 0, index);
	if (err) {
		drop_inode = 1;
		goto out_unlock_inode;
	}

	unlock_new_inode(inode);
	d_instantiate(dentry, inode);

out_unlock:
	btrfs_end_transaction(trans, root);
	if (drop_inode) {
		inode_dec_link_count(inode);
		iput(inode);
	}
	btrfs_btree_balance_dirty(root);
	return err;

out_unlock_inode:
	drop_inode = 1;
	unlock_new_inode(inode);
	goto out_unlock;
}

static int __btrfs_prealloc_file_range(struct inode *inode, int mode,
				       u64 start, u64 num_bytes, u64 min_size,
				       loff_t actual_len, u64 *alloc_hint,
				       struct btrfs_trans_handle *trans)
{
	struct extent_map_tree *em_tree = &BTRFS_I(inode)->extent_tree;
	struct extent_map *em;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_key ins;
	u64 cur_offset = start;
	u64 i_size;
	u64 cur_bytes;
	u64 last_alloc = (u64)-1;
	int ret = 0;
	bool own_trans = true;

	if (trans)
		own_trans = false;
	while (num_bytes > 0) {
		if (own_trans) {
			trans = btrfs_start_transaction(root, 3);
			if (IS_ERR(trans)) {
				ret = PTR_ERR(trans);
				break;
			}
		}

		cur_bytes = min_t(u64, num_bytes, SZ_256M);
		cur_bytes = max(cur_bytes, min_size);
		 
		cur_bytes = min(cur_bytes, last_alloc);
		ret = btrfs_reserve_extent(root, cur_bytes, min_size, 0,
					   *alloc_hint, &ins, 1, 0);
		if (ret) {
			if (own_trans)
				btrfs_end_transaction(trans, root);
			break;
		}
		btrfs_dec_block_group_reservations(root->fs_info, ins.objectid);

		last_alloc = ins.offset;
		ret = insert_reserved_file_extent(trans, inode,
						  cur_offset, ins.objectid,
						  ins.offset, ins.offset,
						  ins.offset, 0, 0, 0,
						  BTRFS_FILE_EXTENT_PREALLOC);
		if (ret) {
			btrfs_free_reserved_extent(root, ins.objectid,
						   ins.offset, 0);
			btrfs_abort_transaction(trans, root, ret);
			if (own_trans)
				btrfs_end_transaction(trans, root);
			break;
		}

		btrfs_drop_extent_cache(inode, cur_offset,
					cur_offset + ins.offset -1, 0);

		em = alloc_extent_map();
		if (!em) {
			set_bit(BTRFS_INODE_NEEDS_FULL_SYNC,
				&BTRFS_I(inode)->runtime_flags);
			goto next;
		}

		em->start = cur_offset;
		em->orig_start = cur_offset;
		em->len = ins.offset;
		em->block_start = ins.objectid;
		em->block_len = ins.offset;
		em->orig_block_len = ins.offset;
		em->ram_bytes = ins.offset;
		em->bdev = root->fs_info->fs_devices->latest_bdev;
		set_bit(EXTENT_FLAG_PREALLOC, &em->flags);
		em->generation = trans->transid;

		while (1) {
			write_lock(&em_tree->lock);
			ret = add_extent_mapping(em_tree, em, 1);
			write_unlock(&em_tree->lock);
			if (ret != -EEXIST)
				break;
			btrfs_drop_extent_cache(inode, cur_offset,
						cur_offset + ins.offset - 1,
						0);
		}
		free_extent_map(em);
next:
		num_bytes -= ins.offset;
		cur_offset += ins.offset;
		*alloc_hint = ins.objectid + ins.offset;

		inode_inc_iversion(inode);
		inode->i_ctime = current_fs_time(inode->i_sb);
		BTRFS_I(inode)->flags |= BTRFS_INODE_PREALLOC;
		if (!(mode & FALLOC_FL_KEEP_SIZE) &&
		    (actual_len > inode->i_size) &&
		    (cur_offset > inode->i_size)) {
			if (cur_offset > actual_len)
				i_size = actual_len;
			else
				i_size = cur_offset;
			i_size_write(inode, i_size);
			btrfs_ordered_update_i_size(inode, i_size, NULL);
		}

		ret = btrfs_update_inode(trans, root, inode);

		if (ret) {
			btrfs_abort_transaction(trans, root, ret);
			if (own_trans)
				btrfs_end_transaction(trans, root);
			break;
		}

		if (own_trans)
			btrfs_end_transaction(trans, root);
	}
	return ret;
}

int btrfs_prealloc_file_range(struct inode *inode, int mode,
			      u64 start, u64 num_bytes, u64 min_size,
			      loff_t actual_len, u64 *alloc_hint)
{
	return __btrfs_prealloc_file_range(inode, mode, start, num_bytes,
					   min_size, actual_len, alloc_hint,
					   NULL);
}

int btrfs_prealloc_file_range_trans(struct inode *inode,
				    struct btrfs_trans_handle *trans, int mode,
				    u64 start, u64 num_bytes, u64 min_size,
				    loff_t actual_len, u64 *alloc_hint)
{
	return __btrfs_prealloc_file_range(inode, mode, start, num_bytes,
					   min_size, actual_len, alloc_hint, trans);
}

static int btrfs_set_page_dirty(struct page *page)
{
	return __set_page_dirty_nobuffers(page);
}

static int btrfs_permission(struct inode *inode, int mask)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	umode_t mode = inode->i_mode;

	if (mask & MAY_WRITE &&
	    (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode))) {
		if (btrfs_root_readonly(root))
			return -EROFS;
		if (BTRFS_I(inode)->flags & BTRFS_INODE_READONLY)
			return -EACCES;
	}
	return generic_permission(inode, mask);
}

static int btrfs_tmpfile(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_root *root = BTRFS_I(dir)->root;
	struct inode *inode = NULL;
	u64 objectid;
	u64 index;
	int ret = 0;

	trans = btrfs_start_transaction(root, 5);
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	ret = btrfs_find_free_ino(root, &objectid);
	if (ret)
		goto out;

	inode = btrfs_new_inode(trans, root, dir, NULL, 0,
				btrfs_ino(dir), objectid, mode, &index);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		inode = NULL;
		goto out;
	}

	inode->i_fop = &btrfs_file_operations;
	inode->i_op = &btrfs_file_inode_operations;

	inode->i_mapping->a_ops = &btrfs_aops;
	BTRFS_I(inode)->io_tree.ops = &btrfs_extent_io_ops;

	ret = btrfs_init_inode_security(trans, inode, dir, NULL);
	if (ret)
		goto out_inode;

	ret = btrfs_update_inode(trans, root, inode);
	if (ret)
		goto out_inode;
	ret = btrfs_orphan_add(trans, inode);
	if (ret)
		goto out_inode;

	set_nlink(inode, 1);
	unlock_new_inode(inode);
	d_tmpfile(dentry, inode);
	mark_inode_dirty(inode);

out:
	btrfs_end_transaction(trans, root);
	if (ret)
		iput(inode);
	btrfs_balance_delayed_items(root);
	btrfs_btree_balance_dirty(root);
	return ret;

out_inode:
	unlock_new_inode(inode);
	goto out;

}

int btrfs_inode_check_errors(struct inode *inode)
{
	int ret = 0;

	if (test_bit(AS_ENOSPC, &inode->i_mapping->flags) &&
	    test_and_clear_bit(AS_ENOSPC, &inode->i_mapping->flags))
		ret = -ENOSPC;
	if (test_bit(AS_EIO, &inode->i_mapping->flags) &&
	    test_and_clear_bit(AS_EIO, &inode->i_mapping->flags))
		ret = -EIO;

	return ret;
}

static const struct inode_operations btrfs_dir_inode_operations = {
#ifdef MY_ABC_HERE
	.syno_getattr	= btrfs_syno_getattr,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_crtime = btrfs_syno_set_crtime,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_archive_bit = btrfs_syno_set_archive_bit,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_archive_ver = btrfs_syno_set_archive_ver,
	.syno_get_archive_ver = btrfs_syno_get_archive_ver,
#endif  
	.getattr	= btrfs_getattr,
	.lookup		= btrfs_lookup,
	.create		= btrfs_create,
	.unlink		= btrfs_unlink,
	.link		= btrfs_link,
	.mkdir		= btrfs_mkdir,
	.rmdir		= btrfs_rmdir,
	.rename2	= btrfs_rename2,
	.symlink	= btrfs_symlink,
	.setattr	= btrfs_setattr,
	.mknod		= btrfs_mknod,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= btrfs_listxattr,
	.removexattr	= generic_removexattr,
	.permission	= btrfs_permission,
	.get_acl	= btrfs_get_acl,
	.set_acl	= btrfs_set_acl,
	.update_time	= btrfs_update_time,
	.tmpfile        = btrfs_tmpfile,
};
static const struct inode_operations btrfs_dir_ro_inode_operations = {
#ifdef MY_ABC_HERE
	.syno_getattr	= btrfs_syno_getattr,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_crtime = btrfs_syno_set_crtime,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_archive_bit = btrfs_syno_set_archive_bit,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_archive_ver = btrfs_syno_set_archive_ver,
	.syno_get_archive_ver = btrfs_syno_get_archive_ver,
#endif  
	.lookup		= btrfs_lookup,
	.permission	= btrfs_permission,
	.get_acl	= btrfs_get_acl,
	.set_acl	= btrfs_set_acl,
	.update_time	= btrfs_update_time,
};

static const struct file_operations btrfs_dir_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate	= btrfs_real_readdir,
	.unlocked_ioctl	= btrfs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= btrfs_compat_ioctl,
#endif
	.release        = btrfs_release_file,
	.fsync		= btrfs_sync_file,
};

static const struct extent_io_ops btrfs_extent_io_ops = {
	.fill_delalloc = run_delalloc_range,
	.submit_bio_hook = btrfs_submit_bio_hook,
	.merge_bio_hook = btrfs_merge_bio_hook,
	.readpage_end_io_hook = btrfs_readpage_end_io_hook,
	.writepage_end_io_hook = btrfs_writepage_end_io_hook,
	.writepage_start_hook = btrfs_writepage_start_hook,
	.set_bit_hook = btrfs_set_bit_hook,
	.clear_bit_hook = btrfs_clear_bit_hook,
	.merge_extent_hook = btrfs_merge_extent_hook,
	.split_extent_hook = btrfs_split_extent_hook,
};

static const struct address_space_operations btrfs_aops = {
	.readpage	= btrfs_readpage,
	.writepage	= btrfs_writepage,
	.writepages	= btrfs_writepages,
	.readpages	= btrfs_readpages,
	.direct_IO	= btrfs_direct_IO,
	.invalidatepage = btrfs_invalidatepage,
	.releasepage	= btrfs_releasepage,
	.set_page_dirty	= btrfs_set_page_dirty,
	.error_remove_page = generic_error_remove_page,
};

static const struct address_space_operations btrfs_symlink_aops = {
	.readpage	= btrfs_readpage,
	.writepage	= btrfs_writepage,
	.invalidatepage = btrfs_invalidatepage,
	.releasepage	= btrfs_releasepage,
};

static const struct inode_operations btrfs_file_inode_operations = {
#ifdef MY_ABC_HERE
	.syno_getattr	= btrfs_syno_getattr,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_crtime = btrfs_syno_set_crtime,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_archive_bit = btrfs_syno_set_archive_bit,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_archive_ver = btrfs_syno_set_archive_ver,
	.syno_get_archive_ver = btrfs_syno_get_archive_ver,
#endif  
	.getattr	= btrfs_getattr,
	.setattr	= btrfs_setattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr      = btrfs_listxattr,
	.removexattr	= generic_removexattr,
	.permission	= btrfs_permission,
	.fiemap		= btrfs_fiemap,
	.get_acl	= btrfs_get_acl,
	.set_acl	= btrfs_set_acl,
	.update_time	= btrfs_update_time,
};
static const struct inode_operations btrfs_special_inode_operations = {
#ifdef MY_ABC_HERE
	.syno_getattr	= btrfs_syno_getattr,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_crtime = btrfs_syno_set_crtime,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_archive_bit = btrfs_syno_set_archive_bit,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_archive_ver = btrfs_syno_set_archive_ver,
	.syno_get_archive_ver = btrfs_syno_get_archive_ver,
#endif  
	.getattr	= btrfs_getattr,
	.setattr	= btrfs_setattr,
	.permission	= btrfs_permission,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= btrfs_listxattr,
	.removexattr	= generic_removexattr,
	.get_acl	= btrfs_get_acl,
	.set_acl	= btrfs_set_acl,
	.update_time	= btrfs_update_time,
};
static const struct inode_operations btrfs_symlink_inode_operations = {
#ifdef MY_ABC_HERE
	.syno_getattr	= btrfs_syno_getattr,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_crtime = btrfs_syno_set_crtime,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_archive_bit = btrfs_syno_set_archive_bit,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_archive_ver = btrfs_syno_set_archive_ver,
	.syno_get_archive_ver = btrfs_syno_get_archive_ver,
#endif  
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
	.getattr	= btrfs_getattr,
	.setattr	= btrfs_setattr,
	.permission	= btrfs_permission,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= btrfs_listxattr,
	.removexattr	= generic_removexattr,
	.update_time	= btrfs_update_time,
};

const struct dentry_operations btrfs_dentry_operations = {
	.d_delete	= btrfs_dentry_delete,
	.d_release	= btrfs_dentry_release,
};
