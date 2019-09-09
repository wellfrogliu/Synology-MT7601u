 
#include <linux/blkdev.h>
#include <linux/ratelimit.h>
#include "ctree.h"
#include "volumes.h"
#include "disk-io.h"
#include "ordered-data.h"
#include "transaction.h"
#include "backref.h"
#include "extent_io.h"
#include "dev-replace.h"
#include "check-integrity.h"
#include "rcu-string.h"
#include "raid56.h"

struct scrub_block;
struct scrub_ctx;

#define SCRUB_PAGES_PER_RD_BIO	32	 
#define SCRUB_PAGES_PER_WR_BIO	32	 
#define SCRUB_BIOS_PER_SCTX	64	 

#define SCRUB_MAX_PAGES_PER_BLOCK	16	 

struct scrub_recover {
	atomic_t		refs;
	struct btrfs_bio	*bbio;
	u64			map_length;
};

struct scrub_page {
	struct scrub_block	*sblock;
	struct page		*page;
	struct btrfs_device	*dev;
	struct list_head	list;
	u64			flags;   
	u64			generation;
	u64			logical;
	u64			physical;
	u64			physical_for_dev_replace;
	atomic_t		refs;
	struct {
		unsigned int	mirror_num:8;
		unsigned int	have_csum:1;
		unsigned int	io_error:1;
	};
	u8			csum[BTRFS_CSUM_SIZE];

	struct scrub_recover	*recover;
};

struct scrub_bio {
	int			index;
	struct scrub_ctx	*sctx;
	struct btrfs_device	*dev;
	struct bio		*bio;
	int			err;
	u64			logical;
	u64			physical;
#if SCRUB_PAGES_PER_WR_BIO >= SCRUB_PAGES_PER_RD_BIO
	struct scrub_page	*pagev[SCRUB_PAGES_PER_WR_BIO];
#else
	struct scrub_page	*pagev[SCRUB_PAGES_PER_RD_BIO];
#endif
	int			page_count;
	int			next_free;
	struct btrfs_work	work;
};

struct scrub_block {
	struct scrub_page	*pagev[SCRUB_MAX_PAGES_PER_BLOCK];
	int			page_count;
	atomic_t		outstanding_pages;
	atomic_t		refs;  
	struct scrub_ctx	*sctx;
	struct scrub_parity	*sparity;
	struct {
		unsigned int	header_error:1;
		unsigned int	checksum_error:1;
		unsigned int	no_io_error_seen:1;
		unsigned int	generation_error:1;  

		unsigned int	data_corrected:1;
	};
	struct btrfs_work	work;
};

struct scrub_parity {
	struct scrub_ctx	*sctx;

	struct btrfs_device	*scrub_dev;

	u64			logic_start;

	u64			logic_end;

	int			nsectors;

	int			stripe_len;

	atomic_t		refs;

	struct list_head	spages;

	struct btrfs_work	work;

	unsigned long		*dbitmap;

	unsigned long		*ebitmap;

	unsigned long		bitmap[0];
};

struct scrub_wr_ctx {
	struct scrub_bio *wr_curr_bio;
	struct btrfs_device *tgtdev;
	int pages_per_wr_bio;  
	atomic_t flush_all_writes;
	struct mutex wr_lock;
};

struct scrub_ctx {
	struct scrub_bio	*bios[SCRUB_BIOS_PER_SCTX];
	struct btrfs_root	*dev_root;
	int			first_free;
	int			curr;
	atomic_t		bios_in_flight;
	atomic_t		workers_pending;
	spinlock_t		list_lock;
	wait_queue_head_t	list_wait;
	u16			csum_size;
	struct list_head	csum_list;
	atomic_t		cancel_req;
	int			readonly;
	int			pages_per_rd_bio;
	u32			sectorsize;
	u32			nodesize;

	int			is_dev_replace;
	struct scrub_wr_ctx	wr_ctx;

	struct btrfs_scrub_progress stat;
	spinlock_t		stat_lock;

	atomic_t                refs;
};

struct scrub_fixup_nodatasum {
	struct scrub_ctx	*sctx;
	struct btrfs_device	*dev;
	u64			logical;
	struct btrfs_root	*root;
	struct btrfs_work	work;
	int			mirror_num;
};

struct scrub_nocow_inode {
	u64			inum;
	u64			offset;
	u64			root;
	struct list_head	list;
};

struct scrub_copy_nocow_ctx {
	struct scrub_ctx	*sctx;
	u64			logical;
	u64			len;
	int			mirror_num;
	u64			physical_for_dev_replace;
	struct list_head	inodes;
	struct btrfs_work	work;
};

struct scrub_warning {
	struct btrfs_path	*path;
	u64			extent_item_size;
	const char		*errstr;
	sector_t		sector;
	u64			logical;
	struct btrfs_device	*dev;
};

static void scrub_pending_bio_inc(struct scrub_ctx *sctx);
static void scrub_pending_bio_dec(struct scrub_ctx *sctx);
static void scrub_pending_trans_workers_inc(struct scrub_ctx *sctx);
static void scrub_pending_trans_workers_dec(struct scrub_ctx *sctx);
static int scrub_handle_errored_block(struct scrub_block *sblock_to_check);
static int scrub_setup_recheck_block(struct scrub_block *original_sblock,
				     struct scrub_block *sblocks_for_recheck);
static void scrub_recheck_block(struct btrfs_fs_info *fs_info,
				struct scrub_block *sblock,
				int retry_failed_mirror);
static void scrub_recheck_block_checksum(struct scrub_block *sblock);
static int scrub_repair_block_from_good_copy(struct scrub_block *sblock_bad,
					     struct scrub_block *sblock_good);
static int scrub_repair_page_from_good_copy(struct scrub_block *sblock_bad,
					    struct scrub_block *sblock_good,
					    int page_num, int force_write);
static void scrub_write_block_to_dev_replace(struct scrub_block *sblock);
static int scrub_write_page_to_dev_replace(struct scrub_block *sblock,
					   int page_num);
static int scrub_checksum_data(struct scrub_block *sblock);
static int scrub_checksum_tree_block(struct scrub_block *sblock);
static int scrub_checksum_super(struct scrub_block *sblock);
static void scrub_block_get(struct scrub_block *sblock);
static void scrub_block_put(struct scrub_block *sblock);
static void scrub_page_get(struct scrub_page *spage);
static void scrub_page_put(struct scrub_page *spage);
static void scrub_parity_get(struct scrub_parity *sparity);
static void scrub_parity_put(struct scrub_parity *sparity);
static int scrub_add_page_to_rd_bio(struct scrub_ctx *sctx,
				    struct scrub_page *spage);
static int scrub_pages(struct scrub_ctx *sctx, u64 logical, u64 len,
		       u64 physical, struct btrfs_device *dev, u64 flags,
		       u64 gen, int mirror_num, u8 *csum, int force,
		       u64 physical_for_dev_replace);
static void scrub_bio_end_io(struct bio *bio);
static void scrub_bio_end_io_worker(struct btrfs_work *work);
static void scrub_block_complete(struct scrub_block *sblock);
static void scrub_remap_extent(struct btrfs_fs_info *fs_info,
			       u64 extent_logical, u64 extent_len,
			       u64 *extent_physical,
			       struct btrfs_device **extent_dev,
			       int *extent_mirror_num);
static int scrub_setup_wr_ctx(struct scrub_ctx *sctx,
			      struct scrub_wr_ctx *wr_ctx,
			      struct btrfs_fs_info *fs_info,
			      struct btrfs_device *dev,
			      int is_dev_replace);
static void scrub_free_wr_ctx(struct scrub_wr_ctx *wr_ctx);
static int scrub_add_page_to_wr_bio(struct scrub_ctx *sctx,
				    struct scrub_page *spage);
static void scrub_wr_submit(struct scrub_ctx *sctx);
static void scrub_wr_bio_end_io(struct bio *bio);
static void scrub_wr_bio_end_io_worker(struct btrfs_work *work);
static int write_page_nocow(struct scrub_ctx *sctx,
			    u64 physical_for_dev_replace, struct page *page);
static int copy_nocow_pages_for_inode(u64 inum, u64 offset, u64 root,
				      struct scrub_copy_nocow_ctx *ctx);
static int copy_nocow_pages(struct scrub_ctx *sctx, u64 logical, u64 len,
			    int mirror_num, u64 physical_for_dev_replace);
static void copy_nocow_pages_worker(struct btrfs_work *work);
static void __scrub_blocked_if_needed(struct btrfs_fs_info *fs_info);
static void scrub_blocked_if_needed(struct btrfs_fs_info *fs_info);
static void scrub_put_ctx(struct scrub_ctx *sctx);

static void scrub_pending_bio_inc(struct scrub_ctx *sctx)
{
	atomic_inc(&sctx->refs);
	atomic_inc(&sctx->bios_in_flight);
}

static void scrub_pending_bio_dec(struct scrub_ctx *sctx)
{
	atomic_dec(&sctx->bios_in_flight);
	wake_up(&sctx->list_wait);
	scrub_put_ctx(sctx);
}

static void __scrub_blocked_if_needed(struct btrfs_fs_info *fs_info)
{
	while (atomic_read(&fs_info->scrub_pause_req)) {
		mutex_unlock(&fs_info->scrub_lock);
		wait_event(fs_info->scrub_pause_wait,
		   atomic_read(&fs_info->scrub_pause_req) == 0);
		mutex_lock(&fs_info->scrub_lock);
	}
}

static void scrub_pause_on(struct btrfs_fs_info *fs_info)
{
	atomic_inc(&fs_info->scrubs_paused);
	wake_up(&fs_info->scrub_pause_wait);
}

static void scrub_pause_off(struct btrfs_fs_info *fs_info)
{
	mutex_lock(&fs_info->scrub_lock);
	__scrub_blocked_if_needed(fs_info);
	atomic_dec(&fs_info->scrubs_paused);
	mutex_unlock(&fs_info->scrub_lock);

	wake_up(&fs_info->scrub_pause_wait);
}

static void scrub_blocked_if_needed(struct btrfs_fs_info *fs_info)
{
	scrub_pause_on(fs_info);
	scrub_pause_off(fs_info);
}

static void scrub_pending_trans_workers_inc(struct scrub_ctx *sctx)
{
	struct btrfs_fs_info *fs_info = sctx->dev_root->fs_info;

	atomic_inc(&sctx->refs);
	 
	mutex_lock(&fs_info->scrub_lock);
	atomic_inc(&fs_info->scrubs_running);
	atomic_inc(&fs_info->scrubs_paused);
	mutex_unlock(&fs_info->scrub_lock);

	wake_up(&fs_info->scrub_pause_wait);

	atomic_inc(&sctx->workers_pending);
}

static void scrub_pending_trans_workers_dec(struct scrub_ctx *sctx)
{
	struct btrfs_fs_info *fs_info = sctx->dev_root->fs_info;

	mutex_lock(&fs_info->scrub_lock);
	atomic_dec(&fs_info->scrubs_running);
	atomic_dec(&fs_info->scrubs_paused);
	mutex_unlock(&fs_info->scrub_lock);
	atomic_dec(&sctx->workers_pending);
	wake_up(&fs_info->scrub_pause_wait);
	wake_up(&sctx->list_wait);
	scrub_put_ctx(sctx);
}

static void scrub_free_csums(struct scrub_ctx *sctx)
{
	while (!list_empty(&sctx->csum_list)) {
		struct btrfs_ordered_sum *sum;
		sum = list_first_entry(&sctx->csum_list,
				       struct btrfs_ordered_sum, list);
		list_del(&sum->list);
		kfree(sum);
	}
}

static noinline_for_stack void scrub_free_ctx(struct scrub_ctx *sctx)
{
	int i;

	if (!sctx)
		return;

	scrub_free_wr_ctx(&sctx->wr_ctx);

	if (sctx->curr != -1) {
		struct scrub_bio *sbio = sctx->bios[sctx->curr];

		for (i = 0; i < sbio->page_count; i++) {
			WARN_ON(!sbio->pagev[i]->page);
			scrub_block_put(sbio->pagev[i]->sblock);
		}
		bio_put(sbio->bio);
	}

	for (i = 0; i < SCRUB_BIOS_PER_SCTX; ++i) {
		struct scrub_bio *sbio = sctx->bios[i];

		if (!sbio)
			break;
		kfree(sbio);
	}

	scrub_free_csums(sctx);
	kfree(sctx);
}

static void scrub_put_ctx(struct scrub_ctx *sctx)
{
	if (atomic_dec_and_test(&sctx->refs))
		scrub_free_ctx(sctx);
}

static noinline_for_stack
struct scrub_ctx *scrub_setup_ctx(struct btrfs_device *dev, int is_dev_replace)
{
	struct scrub_ctx *sctx;
	int		i;
	struct btrfs_fs_info *fs_info = dev->dev_root->fs_info;
	int ret;

	sctx = kzalloc(sizeof(*sctx), GFP_KERNEL);
	if (!sctx)
		goto nomem;
	atomic_set(&sctx->refs, 1);
	sctx->is_dev_replace = is_dev_replace;
	sctx->pages_per_rd_bio = SCRUB_PAGES_PER_RD_BIO;
	sctx->curr = -1;
	sctx->dev_root = dev->dev_root;
	for (i = 0; i < SCRUB_BIOS_PER_SCTX; ++i) {
		struct scrub_bio *sbio;

		sbio = kzalloc(sizeof(*sbio), GFP_KERNEL);
		if (!sbio)
			goto nomem;
		sctx->bios[i] = sbio;

		sbio->index = i;
		sbio->sctx = sctx;
		sbio->page_count = 0;
		btrfs_init_work(&sbio->work, btrfs_scrub_helper,
				scrub_bio_end_io_worker, NULL, NULL);

		if (i != SCRUB_BIOS_PER_SCTX - 1)
			sctx->bios[i]->next_free = i + 1;
		else
			sctx->bios[i]->next_free = -1;
	}
	sctx->first_free = 0;
	sctx->nodesize = dev->dev_root->nodesize;
	sctx->sectorsize = dev->dev_root->sectorsize;
	atomic_set(&sctx->bios_in_flight, 0);
	atomic_set(&sctx->workers_pending, 0);
	atomic_set(&sctx->cancel_req, 0);
	sctx->csum_size = btrfs_super_csum_size(fs_info->super_copy);
	INIT_LIST_HEAD(&sctx->csum_list);

	spin_lock_init(&sctx->list_lock);
	spin_lock_init(&sctx->stat_lock);
	init_waitqueue_head(&sctx->list_wait);

	ret = scrub_setup_wr_ctx(sctx, &sctx->wr_ctx, fs_info,
				 fs_info->dev_replace.tgtdev, is_dev_replace);
	if (ret) {
		scrub_free_ctx(sctx);
		return ERR_PTR(ret);
	}
	return sctx;

nomem:
	scrub_free_ctx(sctx);
	return ERR_PTR(-ENOMEM);
}

static int scrub_print_warning_inode(u64 inum, u64 offset, u64 root,
				     void *warn_ctx)
{
	u64 isize;
	u32 nlink;
	int ret;
	int i;
	struct extent_buffer *eb;
	struct btrfs_inode_item *inode_item;
	struct scrub_warning *swarn = warn_ctx;
	struct btrfs_fs_info *fs_info = swarn->dev->dev_root->fs_info;
	struct inode_fs_paths *ipath = NULL;
	struct btrfs_root *local_root;
	struct btrfs_key root_key;
	struct btrfs_key key;

	root_key.objectid = root;
	root_key.type = BTRFS_ROOT_ITEM_KEY;
	root_key.offset = (u64)-1;
	local_root = btrfs_read_fs_root_no_name(fs_info, &root_key);
	if (IS_ERR(local_root)) {
		ret = PTR_ERR(local_root);
		goto err;
	}

	key.objectid = inum;
	key.type = BTRFS_INODE_ITEM_KEY;
	key.offset = 0;

	ret = btrfs_search_slot(NULL, local_root, &key, swarn->path, 0, 0);
	if (ret) {
		btrfs_release_path(swarn->path);
		goto err;
	}

	eb = swarn->path->nodes[0];
	inode_item = btrfs_item_ptr(eb, swarn->path->slots[0],
					struct btrfs_inode_item);
	isize = btrfs_inode_size(eb, inode_item);
	nlink = btrfs_inode_nlink(eb, inode_item);
	btrfs_release_path(swarn->path);

	ipath = init_ipath(4096, local_root, swarn->path);
	if (IS_ERR(ipath)) {
		ret = PTR_ERR(ipath);
		ipath = NULL;
		goto err;
	}
	ret = paths_from_inode(inum, ipath);

	if (ret < 0)
		goto err;

	for (i = 0; i < ipath->fspath->elem_cnt; ++i)
		btrfs_warn_in_rcu(fs_info, "%s at logical %llu on dev "
			"%s, sector %llu, root %llu, inode %llu, offset %llu, "
			"length %llu, links %u (path: %s)", swarn->errstr,
			swarn->logical, rcu_str_deref(swarn->dev->name),
			(unsigned long long)swarn->sector, root, inum, offset,
			min(isize - offset, (u64)PAGE_SIZE), nlink,
			(char *)(unsigned long)ipath->fspath->val[i]);
	free_ipath(ipath);
	return 0;

err:
	btrfs_warn_in_rcu(fs_info, "%s at logical %llu on dev "
		"%s, sector %llu, root %llu, inode %llu, offset %llu: path "
		"resolving failed with ret=%d", swarn->errstr,
		swarn->logical, rcu_str_deref(swarn->dev->name),
		(unsigned long long)swarn->sector, root, inum, offset, ret);

	free_ipath(ipath);
	return 0;
}

static void scrub_print_warning(const char *errstr, struct scrub_block *sblock)
{
	struct btrfs_device *dev;
	struct btrfs_fs_info *fs_info;
	struct btrfs_path *path;
	struct btrfs_key found_key;
	struct extent_buffer *eb;
	struct btrfs_extent_item *ei;
	struct scrub_warning swarn;
	unsigned long ptr = 0;
	u64 extent_item_pos;
	u64 flags = 0;
	u64 ref_root;
	u32 item_size;
	u8 ref_level = 0;
	int ret;

	WARN_ON(sblock->page_count < 1);
	dev = sblock->pagev[0]->dev;
	fs_info = sblock->sctx->dev_root->fs_info;

	path = btrfs_alloc_path();
	if (!path)
		return;

	swarn.sector = (sblock->pagev[0]->physical) >> 9;
	swarn.logical = sblock->pagev[0]->logical;
	swarn.errstr = errstr;
	swarn.dev = NULL;

	ret = extent_from_logical(fs_info, swarn.logical, path, &found_key,
				  &flags);
	if (ret < 0)
		goto out;

	extent_item_pos = swarn.logical - found_key.objectid;
	swarn.extent_item_size = found_key.offset;

	eb = path->nodes[0];
	ei = btrfs_item_ptr(eb, path->slots[0], struct btrfs_extent_item);
	item_size = btrfs_item_size_nr(eb, path->slots[0]);

	if (flags & BTRFS_EXTENT_FLAG_TREE_BLOCK) {
		do {
			ret = tree_backref_for_extent(&ptr, eb, &found_key, ei,
						      item_size, &ref_root,
						      &ref_level);
			btrfs_warn_in_rcu(fs_info,
				"%s at logical %llu on dev %s, "
				"sector %llu: metadata %s (level %d) in tree "
				"%llu", errstr, swarn.logical,
				rcu_str_deref(dev->name),
				(unsigned long long)swarn.sector,
				ref_level ? "node" : "leaf",
				ret < 0 ? -1 : ref_level,
				ret < 0 ? -1 : ref_root);
		} while (ret != 1);
		btrfs_release_path(path);
	} else {
		btrfs_release_path(path);
		swarn.path = path;
		swarn.dev = dev;
		iterate_extent_inodes(fs_info, found_key.objectid,
					extent_item_pos, 1,
					scrub_print_warning_inode, &swarn);
	}

out:
	btrfs_free_path(path);
}

static int scrub_fixup_readpage(u64 inum, u64 offset, u64 root, void *fixup_ctx)
{
	struct page *page = NULL;
	unsigned long index;
	struct scrub_fixup_nodatasum *fixup = fixup_ctx;
	int ret;
	int corrected = 0;
	struct btrfs_key key;
	struct inode *inode = NULL;
	struct btrfs_fs_info *fs_info;
	u64 end = offset + PAGE_SIZE - 1;
	struct btrfs_root *local_root;
	int srcu_index;

	key.objectid = root;
	key.type = BTRFS_ROOT_ITEM_KEY;
	key.offset = (u64)-1;

	fs_info = fixup->root->fs_info;
	srcu_index = srcu_read_lock(&fs_info->subvol_srcu);

	local_root = btrfs_read_fs_root_no_name(fs_info, &key);
	if (IS_ERR(local_root)) {
		srcu_read_unlock(&fs_info->subvol_srcu, srcu_index);
		return PTR_ERR(local_root);
	}

	key.type = BTRFS_INODE_ITEM_KEY;
	key.objectid = inum;
	key.offset = 0;
	inode = btrfs_iget(fs_info->sb, &key, local_root, NULL);
	srcu_read_unlock(&fs_info->subvol_srcu, srcu_index);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	index = offset >> PAGE_CACHE_SHIFT;

	page = find_or_create_page(inode->i_mapping, index, GFP_NOFS);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}

	if (PageUptodate(page)) {
		if (PageDirty(page)) {
			 
			ret = -EIO;
			goto out;
		}
		ret = repair_io_failure(inode, offset, PAGE_SIZE,
					fixup->logical, page,
					offset - page_offset(page),
					fixup->mirror_num);
		unlock_page(page);
		corrected = !ret;
	} else {
		 
		ret = set_extent_bits(&BTRFS_I(inode)->io_tree, offset, end,
					EXTENT_DAMAGED);
		if (ret) {
			 
			WARN_ON(ret > 0);
			if (ret > 0)
				ret = -EFAULT;
			goto out;
		}

		ret = extent_read_full_page(&BTRFS_I(inode)->io_tree, page,
						btrfs_get_extent,
						fixup->mirror_num);
		wait_on_page_locked(page);

		corrected = !test_range_bit(&BTRFS_I(inode)->io_tree, offset,
						end, EXTENT_DAMAGED, 0, NULL);
		if (!corrected)
			clear_extent_bits(&BTRFS_I(inode)->io_tree, offset, end,
						EXTENT_DAMAGED);
	}

out:
	if (page)
		put_page(page);

	iput(inode);

	if (ret < 0)
		return ret;

	if (ret == 0 && corrected) {
		 
		return 1;
	}

	return -EIO;
}

static void scrub_fixup_nodatasum(struct btrfs_work *work)
{
	int ret;
	struct scrub_fixup_nodatasum *fixup;
	struct scrub_ctx *sctx;
	struct btrfs_trans_handle *trans = NULL;
	struct btrfs_path *path;
	int uncorrectable = 0;

	fixup = container_of(work, struct scrub_fixup_nodatasum, work);
	sctx = fixup->sctx;

	path = btrfs_alloc_path();
	if (!path) {
		spin_lock(&sctx->stat_lock);
		++sctx->stat.malloc_errors;
		spin_unlock(&sctx->stat_lock);
		uncorrectable = 1;
		goto out;
	}

	trans = btrfs_join_transaction(fixup->root);
	if (IS_ERR(trans)) {
		uncorrectable = 1;
		goto out;
	}

	ret = iterate_inodes_from_logical(fixup->logical, fixup->root->fs_info,
						path, scrub_fixup_readpage,
						fixup);
	if (ret < 0) {
		uncorrectable = 1;
		goto out;
	}
	WARN_ON(ret != 1);

	spin_lock(&sctx->stat_lock);
	++sctx->stat.corrected_errors;
	spin_unlock(&sctx->stat_lock);

out:
	if (trans && !IS_ERR(trans))
		btrfs_end_transaction(trans, fixup->root);
	if (uncorrectable) {
		spin_lock(&sctx->stat_lock);
		++sctx->stat.uncorrectable_errors;
		spin_unlock(&sctx->stat_lock);
		btrfs_dev_replace_stats_inc(
			&sctx->dev_root->fs_info->dev_replace.
			num_uncorrectable_read_errors);
		btrfs_err_rl_in_rcu(sctx->dev_root->fs_info,
		    "unable to fixup (nodatasum) error at logical %llu on dev %s",
			fixup->logical, rcu_str_deref(fixup->dev->name));
	}

	btrfs_free_path(path);
	kfree(fixup);

	scrub_pending_trans_workers_dec(sctx);
}

static inline void scrub_get_recover(struct scrub_recover *recover)
{
	atomic_inc(&recover->refs);
}

static inline void scrub_put_recover(struct scrub_recover *recover)
{
	if (atomic_dec_and_test(&recover->refs)) {
		btrfs_put_bbio(recover->bbio);
		kfree(recover);
	}
}

static int scrub_handle_errored_block(struct scrub_block *sblock_to_check)
{
	struct scrub_ctx *sctx = sblock_to_check->sctx;
	struct btrfs_device *dev;
	struct btrfs_fs_info *fs_info;
	u64 length;
	u64 logical;
	unsigned int failed_mirror_index;
	unsigned int is_metadata;
	unsigned int have_csum;
	struct scrub_block *sblocks_for_recheck;  
	struct scrub_block *sblock_bad;
	int ret;
	int mirror_index;
	int page_num;
	int success;
	static DEFINE_RATELIMIT_STATE(_rs, DEFAULT_RATELIMIT_INTERVAL,
				      DEFAULT_RATELIMIT_BURST);

	BUG_ON(sblock_to_check->page_count < 1);
	fs_info = sctx->dev_root->fs_info;
	if (sblock_to_check->pagev[0]->flags & BTRFS_EXTENT_FLAG_SUPER) {
		 
		spin_lock(&sctx->stat_lock);
		++sctx->stat.super_errors;
		spin_unlock(&sctx->stat_lock);
		return 0;
	}
	length = sblock_to_check->page_count * PAGE_SIZE;
	logical = sblock_to_check->pagev[0]->logical;
	BUG_ON(sblock_to_check->pagev[0]->mirror_num < 1);
	failed_mirror_index = sblock_to_check->pagev[0]->mirror_num - 1;
	is_metadata = !(sblock_to_check->pagev[0]->flags &
			BTRFS_EXTENT_FLAG_DATA);
	have_csum = sblock_to_check->pagev[0]->have_csum;
	dev = sblock_to_check->pagev[0]->dev;

	if (sctx->is_dev_replace && !is_metadata && !have_csum) {
		sblocks_for_recheck = NULL;
		goto nodatasum_case;
	}

	sblocks_for_recheck = kcalloc(BTRFS_MAX_MIRRORS,
				      sizeof(*sblocks_for_recheck), GFP_NOFS);
	if (!sblocks_for_recheck) {
		spin_lock(&sctx->stat_lock);
		sctx->stat.malloc_errors++;
		sctx->stat.read_errors++;
		sctx->stat.uncorrectable_errors++;
		spin_unlock(&sctx->stat_lock);
		btrfs_dev_stat_inc_and_print(dev, BTRFS_DEV_STAT_READ_ERRS);
		goto out;
	}

	ret = scrub_setup_recheck_block(sblock_to_check, sblocks_for_recheck);
	if (ret) {
		spin_lock(&sctx->stat_lock);
		sctx->stat.read_errors++;
		sctx->stat.uncorrectable_errors++;
		spin_unlock(&sctx->stat_lock);
		btrfs_dev_stat_inc_and_print(dev, BTRFS_DEV_STAT_READ_ERRS);
		goto out;
	}
	BUG_ON(failed_mirror_index >= BTRFS_MAX_MIRRORS);
	sblock_bad = sblocks_for_recheck + failed_mirror_index;

	scrub_recheck_block(fs_info, sblock_bad, 1);

	if (!sblock_bad->header_error && !sblock_bad->checksum_error &&
	    sblock_bad->no_io_error_seen) {
		 
		spin_lock(&sctx->stat_lock);
		sctx->stat.unverified_errors++;
		sblock_to_check->data_corrected = 1;
		spin_unlock(&sctx->stat_lock);

		if (sctx->is_dev_replace)
			scrub_write_block_to_dev_replace(sblock_bad);
		goto out;
	}

	if (!sblock_bad->no_io_error_seen) {
		spin_lock(&sctx->stat_lock);
		sctx->stat.read_errors++;
		spin_unlock(&sctx->stat_lock);
		if (__ratelimit(&_rs))
			scrub_print_warning("i/o error", sblock_to_check);
		btrfs_dev_stat_inc_and_print(dev, BTRFS_DEV_STAT_READ_ERRS);
	} else if (sblock_bad->checksum_error) {
		spin_lock(&sctx->stat_lock);
		sctx->stat.csum_errors++;
		spin_unlock(&sctx->stat_lock);
		if (__ratelimit(&_rs))
			scrub_print_warning("checksum error", sblock_to_check);
		btrfs_dev_stat_inc_and_print(dev,
					     BTRFS_DEV_STAT_CORRUPTION_ERRS);
	} else if (sblock_bad->header_error) {
		spin_lock(&sctx->stat_lock);
		sctx->stat.verify_errors++;
		spin_unlock(&sctx->stat_lock);
		if (__ratelimit(&_rs))
			scrub_print_warning("checksum/header error",
					    sblock_to_check);
		if (sblock_bad->generation_error)
			btrfs_dev_stat_inc_and_print(dev,
				BTRFS_DEV_STAT_GENERATION_ERRS);
		else
			btrfs_dev_stat_inc_and_print(dev,
				BTRFS_DEV_STAT_CORRUPTION_ERRS);
	}

	if (sctx->readonly) {
		ASSERT(!sctx->is_dev_replace);
		goto out;
	}

	if (!is_metadata && !have_csum) {
		struct scrub_fixup_nodatasum *fixup_nodatasum;

		WARN_ON(sctx->is_dev_replace);

nodatasum_case:

		fixup_nodatasum = kzalloc(sizeof(*fixup_nodatasum), GFP_NOFS);
		if (!fixup_nodatasum)
			goto did_not_correct_error;
		fixup_nodatasum->sctx = sctx;
		fixup_nodatasum->dev = dev;
		fixup_nodatasum->logical = logical;
		fixup_nodatasum->root = fs_info->extent_root;
		fixup_nodatasum->mirror_num = failed_mirror_index + 1;
		scrub_pending_trans_workers_inc(sctx);
		btrfs_init_work(&fixup_nodatasum->work, btrfs_scrub_helper,
				scrub_fixup_nodatasum, NULL, NULL);
		btrfs_queue_work(fs_info->scrub_workers,
				 &fixup_nodatasum->work);
		goto out;
	}

	for (mirror_index = 0;
	     mirror_index < BTRFS_MAX_MIRRORS &&
	     sblocks_for_recheck[mirror_index].page_count > 0;
	     mirror_index++) {
		struct scrub_block *sblock_other;

		if (mirror_index == failed_mirror_index)
			continue;
		sblock_other = sblocks_for_recheck + mirror_index;

		scrub_recheck_block(fs_info, sblock_other, 0);

		if (!sblock_other->header_error &&
		    !sblock_other->checksum_error &&
		    sblock_other->no_io_error_seen) {
			if (sctx->is_dev_replace) {
				scrub_write_block_to_dev_replace(sblock_other);
				goto corrected_error;
			} else {
				ret = scrub_repair_block_from_good_copy(
						sblock_bad, sblock_other);
				if (!ret)
					goto corrected_error;
			}
		}
	}

	if (sblock_bad->no_io_error_seen && !sctx->is_dev_replace)
		goto did_not_correct_error;

	success = 1;
	for (page_num = 0; page_num < sblock_bad->page_count;
	     page_num++) {
		struct scrub_page *page_bad = sblock_bad->pagev[page_num];
		struct scrub_block *sblock_other = NULL;

		if (!page_bad->io_error && !sctx->is_dev_replace)
			continue;

		if (page_bad->io_error) {
			for (mirror_index = 0;
			     mirror_index < BTRFS_MAX_MIRRORS &&
			     sblocks_for_recheck[mirror_index].page_count > 0;
			     mirror_index++) {
				if (!sblocks_for_recheck[mirror_index].
				    pagev[page_num]->io_error) {
					sblock_other = sblocks_for_recheck +
						       mirror_index;
					break;
				}
			}
			if (!sblock_other)
				success = 0;
		}

		if (sctx->is_dev_replace) {
			 
			if (!sblock_other)
				sblock_other = sblock_bad;

			if (scrub_write_page_to_dev_replace(sblock_other,
							    page_num) != 0) {
				btrfs_dev_replace_stats_inc(
					&sctx->dev_root->
					fs_info->dev_replace.
					num_write_errors);
				success = 0;
			}
		} else if (sblock_other) {
			ret = scrub_repair_page_from_good_copy(sblock_bad,
							       sblock_other,
							       page_num, 0);
			if (0 == ret)
				page_bad->io_error = 0;
			else
				success = 0;
		}
	}

	if (success && !sctx->is_dev_replace) {
		if (is_metadata || have_csum) {
			 
			scrub_recheck_block(fs_info, sblock_bad, 1);
			if (!sblock_bad->header_error &&
			    !sblock_bad->checksum_error &&
			    sblock_bad->no_io_error_seen)
				goto corrected_error;
			else
				goto did_not_correct_error;
		} else {
corrected_error:
			spin_lock(&sctx->stat_lock);
			sctx->stat.corrected_errors++;
			sblock_to_check->data_corrected = 1;
			spin_unlock(&sctx->stat_lock);
			btrfs_err_rl_in_rcu(fs_info,
				"fixed up error at logical %llu on dev %s",
				logical, rcu_str_deref(dev->name));
		}
	} else {
did_not_correct_error:
		spin_lock(&sctx->stat_lock);
		sctx->stat.uncorrectable_errors++;
		spin_unlock(&sctx->stat_lock);
		btrfs_err_rl_in_rcu(fs_info,
			"unable to fixup (regular) error at logical %llu on dev %s",
			logical, rcu_str_deref(dev->name));
	}

out:
	if (sblocks_for_recheck) {
		for (mirror_index = 0; mirror_index < BTRFS_MAX_MIRRORS;
		     mirror_index++) {
			struct scrub_block *sblock = sblocks_for_recheck +
						     mirror_index;
			struct scrub_recover *recover;
			int page_index;

			for (page_index = 0; page_index < sblock->page_count;
			     page_index++) {
				sblock->pagev[page_index]->sblock = NULL;
				recover = sblock->pagev[page_index]->recover;
				if (recover) {
					scrub_put_recover(recover);
					sblock->pagev[page_index]->recover =
									NULL;
				}
				scrub_page_put(sblock->pagev[page_index]);
			}
		}
		kfree(sblocks_for_recheck);
	}

	return 0;
}

static inline int scrub_nr_raid_mirrors(struct btrfs_bio *bbio)
{
	if (bbio->map_type & BTRFS_BLOCK_GROUP_RAID5)
		return 2;
	else if (bbio->map_type & BTRFS_BLOCK_GROUP_RAID6)
		return 3;
	else
		return (int)bbio->num_stripes;
}

static inline void scrub_stripe_index_and_offset(u64 logical, u64 map_type,
						 u64 *raid_map,
						 u64 mapped_length,
						 int nstripes, int mirror,
						 int *stripe_index,
						 u64 *stripe_offset)
{
	int i;

	if (map_type & BTRFS_BLOCK_GROUP_RAID56_MASK) {
		 
		for (i = 0; i < nstripes; i++) {
			if (raid_map[i] == RAID6_Q_STRIPE ||
			    raid_map[i] == RAID5_P_STRIPE)
				continue;

			if (logical >= raid_map[i] &&
			    logical < raid_map[i] + mapped_length)
				break;
		}

		*stripe_index = i;
		*stripe_offset = logical - raid_map[i];
	} else {
		 
		*stripe_index = mirror;
		*stripe_offset = 0;
	}
}

static int scrub_setup_recheck_block(struct scrub_block *original_sblock,
				     struct scrub_block *sblocks_for_recheck)
{
	struct scrub_ctx *sctx = original_sblock->sctx;
	struct btrfs_fs_info *fs_info = sctx->dev_root->fs_info;
	u64 length = original_sblock->page_count * PAGE_SIZE;
	u64 logical = original_sblock->pagev[0]->logical;
	u64 generation = original_sblock->pagev[0]->generation;
	u64 flags = original_sblock->pagev[0]->flags;
	u64 have_csum = original_sblock->pagev[0]->have_csum;
	struct scrub_recover *recover;
	struct btrfs_bio *bbio;
	u64 sublen;
	u64 mapped_length;
	u64 stripe_offset;
	int stripe_index;
	int page_index = 0;
	int mirror_index;
	int nmirrors;
	int ret;

	while (length > 0) {
		sublen = min_t(u64, length, PAGE_SIZE);
		mapped_length = sublen;
		bbio = NULL;

		ret = btrfs_map_sblock(fs_info, REQ_GET_READ_MIRRORS, logical,
				       &mapped_length, &bbio, 0, 1);
		if (ret || !bbio || mapped_length < sublen) {
			btrfs_put_bbio(bbio);
			return -EIO;
		}

		recover = kzalloc(sizeof(struct scrub_recover), GFP_NOFS);
		if (!recover) {
			btrfs_put_bbio(bbio);
			return -ENOMEM;
		}

		atomic_set(&recover->refs, 1);
		recover->bbio = bbio;
		recover->map_length = mapped_length;

		BUG_ON(page_index >= SCRUB_MAX_PAGES_PER_BLOCK);

		nmirrors = min(scrub_nr_raid_mirrors(bbio), BTRFS_MAX_MIRRORS);

		for (mirror_index = 0; mirror_index < nmirrors;
		     mirror_index++) {
			struct scrub_block *sblock;
			struct scrub_page *page;

			sblock = sblocks_for_recheck + mirror_index;
			sblock->sctx = sctx;

			page = kzalloc(sizeof(*page), GFP_NOFS);
			if (!page) {
leave_nomem:
				spin_lock(&sctx->stat_lock);
				sctx->stat.malloc_errors++;
				spin_unlock(&sctx->stat_lock);
				scrub_put_recover(recover);
				return -ENOMEM;
			}
			scrub_page_get(page);
			sblock->pagev[page_index] = page;
			page->sblock = sblock;
			page->flags = flags;
			page->generation = generation;
			page->logical = logical;
			page->have_csum = have_csum;
			if (have_csum)
				memcpy(page->csum,
				       original_sblock->pagev[0]->csum,
				       sctx->csum_size);

			scrub_stripe_index_and_offset(logical,
						      bbio->map_type,
						      bbio->raid_map,
						      mapped_length,
						      bbio->num_stripes -
						      bbio->num_tgtdevs,
						      mirror_index,
						      &stripe_index,
						      &stripe_offset);
			page->physical = bbio->stripes[stripe_index].physical +
					 stripe_offset;
			page->dev = bbio->stripes[stripe_index].dev;

			BUG_ON(page_index >= original_sblock->page_count);
			page->physical_for_dev_replace =
				original_sblock->pagev[page_index]->
				physical_for_dev_replace;
			 
			page->mirror_num = mirror_index + 1;
			sblock->page_count++;
			page->page = alloc_page(GFP_NOFS);
			if (!page->page)
				goto leave_nomem;

			scrub_get_recover(recover);
			page->recover = recover;
		}
		scrub_put_recover(recover);
		length -= sublen;
		logical += sublen;
		page_index++;
	}

	return 0;
}

struct scrub_bio_ret {
	struct completion event;
	int error;
};

static void scrub_bio_wait_endio(struct bio *bio)
{
	struct scrub_bio_ret *ret = bio->bi_private;

	ret->error = bio->bi_error;
	complete(&ret->event);
}

static inline int scrub_is_page_on_raid56(struct scrub_page *page)
{
	return page->recover &&
	       (page->recover->bbio->map_type & BTRFS_BLOCK_GROUP_RAID56_MASK);
}

static int scrub_submit_raid56_bio_wait(struct btrfs_fs_info *fs_info,
					struct bio *bio,
					struct scrub_page *page)
{
	struct scrub_bio_ret done;
	int ret;

	init_completion(&done.event);
	done.error = 0;
	bio->bi_iter.bi_sector = page->logical >> 9;
	bio->bi_private = &done;
	bio->bi_end_io = scrub_bio_wait_endio;

	ret = raid56_parity_recover(fs_info->fs_root, bio, page->recover->bbio,
				    page->recover->map_length,
				    page->mirror_num, 0);
	if (ret)
		return ret;

	wait_for_completion(&done.event);
	if (done.error)
		return -EIO;

	return 0;
}

static void scrub_recheck_block(struct btrfs_fs_info *fs_info,
				struct scrub_block *sblock,
				int retry_failed_mirror)
{
	int page_num;

	sblock->no_io_error_seen = 1;

	for (page_num = 0; page_num < sblock->page_count; page_num++) {
		struct bio *bio;
		struct scrub_page *page = sblock->pagev[page_num];

		if (page->dev->bdev == NULL) {
			page->io_error = 1;
			sblock->no_io_error_seen = 0;
			continue;
		}

		WARN_ON(!page->page);
		bio = btrfs_io_bio_alloc(GFP_NOFS, 1);
		if (!bio) {
			page->io_error = 1;
			sblock->no_io_error_seen = 0;
			continue;
		}
		bio->bi_bdev = page->dev->bdev;

		bio_add_page(bio, page->page, PAGE_SIZE, 0);
		if (!retry_failed_mirror && scrub_is_page_on_raid56(page)) {
			if (scrub_submit_raid56_bio_wait(fs_info, bio, page))
				sblock->no_io_error_seen = 0;
		} else {
			bio->bi_iter.bi_sector = page->physical >> 9;
			if (btrfsic_submit_bio_wait(READ, bio))
				sblock->no_io_error_seen = 0;
		}

		bio_put(bio);
	}

	if (sblock->no_io_error_seen)
		scrub_recheck_block_checksum(sblock);
}

static inline int scrub_check_fsid(u8 fsid[],
				   struct scrub_page *spage)
{
	struct btrfs_fs_devices *fs_devices = spage->dev->fs_devices;
	int ret;

	ret = memcmp(fsid, fs_devices->fsid, BTRFS_UUID_SIZE);
	return !ret;
}

static void scrub_recheck_block_checksum(struct scrub_block *sblock)
{
	sblock->header_error = 0;
	sblock->checksum_error = 0;
	sblock->generation_error = 0;

	if (sblock->pagev[0]->flags & BTRFS_EXTENT_FLAG_DATA)
		scrub_checksum_data(sblock);
	else
		scrub_checksum_tree_block(sblock);
}

static int scrub_repair_block_from_good_copy(struct scrub_block *sblock_bad,
					     struct scrub_block *sblock_good)
{
	int page_num;
	int ret = 0;

	for (page_num = 0; page_num < sblock_bad->page_count; page_num++) {
		int ret_sub;

		ret_sub = scrub_repair_page_from_good_copy(sblock_bad,
							   sblock_good,
							   page_num, 1);
		if (ret_sub)
			ret = ret_sub;
	}

	return ret;
}

static int scrub_repair_page_from_good_copy(struct scrub_block *sblock_bad,
					    struct scrub_block *sblock_good,
					    int page_num, int force_write)
{
	struct scrub_page *page_bad = sblock_bad->pagev[page_num];
	struct scrub_page *page_good = sblock_good->pagev[page_num];

	BUG_ON(page_bad->page == NULL);
	BUG_ON(page_good->page == NULL);
	if (force_write || sblock_bad->header_error ||
	    sblock_bad->checksum_error || page_bad->io_error) {
		struct bio *bio;
		int ret;

		if (!page_bad->dev->bdev) {
			btrfs_warn_rl(sblock_bad->sctx->dev_root->fs_info,
				"scrub_repair_page_from_good_copy(bdev == NULL) "
				"is unexpected");
			return -EIO;
		}

		bio = btrfs_io_bio_alloc(GFP_NOFS, 1);
		if (!bio)
			return -EIO;
		bio->bi_bdev = page_bad->dev->bdev;
		bio->bi_iter.bi_sector = page_bad->physical >> 9;

		ret = bio_add_page(bio, page_good->page, PAGE_SIZE, 0);
		if (PAGE_SIZE != ret) {
			bio_put(bio);
			return -EIO;
		}

		if (btrfsic_submit_bio_wait(WRITE, bio)) {
			btrfs_dev_stat_inc_and_print(page_bad->dev,
				BTRFS_DEV_STAT_WRITE_ERRS);
			btrfs_dev_replace_stats_inc(
				&sblock_bad->sctx->dev_root->fs_info->
				dev_replace.num_write_errors);
			bio_put(bio);
			return -EIO;
		}
		bio_put(bio);
	}

	return 0;
}

static void scrub_write_block_to_dev_replace(struct scrub_block *sblock)
{
	int page_num;

	if (sblock->sparity)
		return;

	for (page_num = 0; page_num < sblock->page_count; page_num++) {
		int ret;

		ret = scrub_write_page_to_dev_replace(sblock, page_num);
		if (ret)
			btrfs_dev_replace_stats_inc(
				&sblock->sctx->dev_root->fs_info->dev_replace.
				num_write_errors);
	}
}

static int scrub_write_page_to_dev_replace(struct scrub_block *sblock,
					   int page_num)
{
	struct scrub_page *spage = sblock->pagev[page_num];

	BUG_ON(spage->page == NULL);
	if (spage->io_error) {
		void *mapped_buffer = kmap_atomic(spage->page);

		memset(mapped_buffer, 0, PAGE_CACHE_SIZE);
		flush_dcache_page(spage->page);
		kunmap_atomic(mapped_buffer);
	}
	return scrub_add_page_to_wr_bio(sblock->sctx, spage);
}

static int scrub_add_page_to_wr_bio(struct scrub_ctx *sctx,
				    struct scrub_page *spage)
{
	struct scrub_wr_ctx *wr_ctx = &sctx->wr_ctx;
	struct scrub_bio *sbio;
	int ret;

	mutex_lock(&wr_ctx->wr_lock);
again:
	if (!wr_ctx->wr_curr_bio) {
		wr_ctx->wr_curr_bio = kzalloc(sizeof(*wr_ctx->wr_curr_bio),
					      GFP_KERNEL);
		if (!wr_ctx->wr_curr_bio) {
			mutex_unlock(&wr_ctx->wr_lock);
			return -ENOMEM;
		}
		wr_ctx->wr_curr_bio->sctx = sctx;
		wr_ctx->wr_curr_bio->page_count = 0;
	}
	sbio = wr_ctx->wr_curr_bio;
	if (sbio->page_count == 0) {
		struct bio *bio;

		sbio->physical = spage->physical_for_dev_replace;
		sbio->logical = spage->logical;
		sbio->dev = wr_ctx->tgtdev;
		bio = sbio->bio;
		if (!bio) {
			bio = btrfs_io_bio_alloc(GFP_KERNEL,
					wr_ctx->pages_per_wr_bio);
			if (!bio) {
				mutex_unlock(&wr_ctx->wr_lock);
				return -ENOMEM;
			}
			sbio->bio = bio;
		}

		bio->bi_private = sbio;
		bio->bi_end_io = scrub_wr_bio_end_io;
		bio->bi_bdev = sbio->dev->bdev;
		bio->bi_iter.bi_sector = sbio->physical >> 9;
		sbio->err = 0;
	} else if (sbio->physical + sbio->page_count * PAGE_SIZE !=
		   spage->physical_for_dev_replace ||
		   sbio->logical + sbio->page_count * PAGE_SIZE !=
		   spage->logical) {
		scrub_wr_submit(sctx);
		goto again;
	}

	ret = bio_add_page(sbio->bio, spage->page, PAGE_SIZE, 0);
	if (ret != PAGE_SIZE) {
		if (sbio->page_count < 1) {
			bio_put(sbio->bio);
			sbio->bio = NULL;
			mutex_unlock(&wr_ctx->wr_lock);
			return -EIO;
		}
		scrub_wr_submit(sctx);
		goto again;
	}

	sbio->pagev[sbio->page_count] = spage;
	scrub_page_get(spage);
	sbio->page_count++;
	if (sbio->page_count == wr_ctx->pages_per_wr_bio)
		scrub_wr_submit(sctx);
	mutex_unlock(&wr_ctx->wr_lock);

	return 0;
}

static void scrub_wr_submit(struct scrub_ctx *sctx)
{
	struct scrub_wr_ctx *wr_ctx = &sctx->wr_ctx;
	struct scrub_bio *sbio;

	if (!wr_ctx->wr_curr_bio)
		return;

	sbio = wr_ctx->wr_curr_bio;
	wr_ctx->wr_curr_bio = NULL;
	WARN_ON(!sbio->bio->bi_bdev);
	scrub_pending_bio_inc(sctx);
	 
	btrfsic_submit_bio(WRITE, sbio->bio);
}

static void scrub_wr_bio_end_io(struct bio *bio)
{
	struct scrub_bio *sbio = bio->bi_private;
	struct btrfs_fs_info *fs_info = sbio->dev->dev_root->fs_info;

	sbio->err = bio->bi_error;
	sbio->bio = bio;

	btrfs_init_work(&sbio->work, btrfs_scrubwrc_helper,
			 scrub_wr_bio_end_io_worker, NULL, NULL);
	btrfs_queue_work(fs_info->scrub_wr_completion_workers, &sbio->work);
}

static void scrub_wr_bio_end_io_worker(struct btrfs_work *work)
{
	struct scrub_bio *sbio = container_of(work, struct scrub_bio, work);
	struct scrub_ctx *sctx = sbio->sctx;
	int i;

	WARN_ON(sbio->page_count > SCRUB_PAGES_PER_WR_BIO);
	if (sbio->err) {
		struct btrfs_dev_replace *dev_replace =
			&sbio->sctx->dev_root->fs_info->dev_replace;

		for (i = 0; i < sbio->page_count; i++) {
			struct scrub_page *spage = sbio->pagev[i];

			spage->io_error = 1;
			btrfs_dev_replace_stats_inc(&dev_replace->
						    num_write_errors);
		}
	}

	for (i = 0; i < sbio->page_count; i++)
		scrub_page_put(sbio->pagev[i]);

	bio_put(sbio->bio);
	kfree(sbio);
	scrub_pending_bio_dec(sctx);
}

static int scrub_checksum(struct scrub_block *sblock)
{
	u64 flags;
	int ret;

	sblock->header_error = 0;
	sblock->generation_error = 0;
	sblock->checksum_error = 0;

	WARN_ON(sblock->page_count < 1);
	flags = sblock->pagev[0]->flags;
	ret = 0;
	if (flags & BTRFS_EXTENT_FLAG_DATA)
		ret = scrub_checksum_data(sblock);
	else if (flags & BTRFS_EXTENT_FLAG_TREE_BLOCK)
		ret = scrub_checksum_tree_block(sblock);
	else if (flags & BTRFS_EXTENT_FLAG_SUPER)
		(void)scrub_checksum_super(sblock);
	else
		WARN_ON(1);
	if (ret)
		scrub_handle_errored_block(sblock);

	return ret;
}

static int scrub_checksum_data(struct scrub_block *sblock)
{
	struct scrub_ctx *sctx = sblock->sctx;
	u8 csum[BTRFS_CSUM_SIZE];
	u8 *on_disk_csum;
	struct page *page;
	void *buffer;
	u32 crc = ~(u32)0;
	u64 len;
	int index;

	BUG_ON(sblock->page_count < 1);
	if (!sblock->pagev[0]->have_csum)
		return 0;

	on_disk_csum = sblock->pagev[0]->csum;
	page = sblock->pagev[0]->page;
	buffer = kmap_atomic(page);

	len = sctx->sectorsize;
	index = 0;
	for (;;) {
		u64 l = min_t(u64, len, PAGE_SIZE);

		crc = btrfs_csum_data(buffer, crc, l);
		kunmap_atomic(buffer);
		len -= l;
		if (len == 0)
			break;
		index++;
		BUG_ON(index >= sblock->page_count);
		BUG_ON(!sblock->pagev[index]->page);
		page = sblock->pagev[index]->page;
		buffer = kmap_atomic(page);
	}

	btrfs_csum_final(crc, csum);
	if (memcmp(csum, on_disk_csum, sctx->csum_size))
		sblock->checksum_error = 1;

	return sblock->checksum_error;
}

static int scrub_checksum_tree_block(struct scrub_block *sblock)
{
	struct scrub_ctx *sctx = sblock->sctx;
	struct btrfs_header *h;
	struct btrfs_root *root = sctx->dev_root;
	struct btrfs_fs_info *fs_info = root->fs_info;
	u8 calculated_csum[BTRFS_CSUM_SIZE];
	u8 on_disk_csum[BTRFS_CSUM_SIZE];
	struct page *page;
	void *mapped_buffer;
	u64 mapped_size;
	void *p;
	u32 crc = ~(u32)0;
	u64 len;
	int index;

	BUG_ON(sblock->page_count < 1);
	page = sblock->pagev[0]->page;
	mapped_buffer = kmap_atomic(page);
	h = (struct btrfs_header *)mapped_buffer;
	memcpy(on_disk_csum, h->csum, sctx->csum_size);

	if (sblock->pagev[0]->logical != btrfs_stack_header_bytenr(h))
		sblock->header_error = 1;

	if (sblock->pagev[0]->generation != btrfs_stack_header_generation(h)) {
		sblock->header_error = 1;
		sblock->generation_error = 1;
	}

	if (!scrub_check_fsid(h->fsid, sblock->pagev[0]))
		sblock->header_error = 1;

	if (memcmp(h->chunk_tree_uuid, fs_info->chunk_tree_uuid,
		   BTRFS_UUID_SIZE))
		sblock->header_error = 1;

	len = sctx->nodesize - BTRFS_CSUM_SIZE;
	mapped_size = PAGE_SIZE - BTRFS_CSUM_SIZE;
	p = ((u8 *)mapped_buffer) + BTRFS_CSUM_SIZE;
	index = 0;
	for (;;) {
		u64 l = min_t(u64, len, mapped_size);

		crc = btrfs_csum_data(p, crc, l);
		kunmap_atomic(mapped_buffer);
		len -= l;
		if (len == 0)
			break;
		index++;
		BUG_ON(index >= sblock->page_count);
		BUG_ON(!sblock->pagev[index]->page);
		page = sblock->pagev[index]->page;
		mapped_buffer = kmap_atomic(page);
		mapped_size = PAGE_SIZE;
		p = mapped_buffer;
	}

	btrfs_csum_final(crc, calculated_csum);
	if (memcmp(calculated_csum, on_disk_csum, sctx->csum_size))
		sblock->checksum_error = 1;

	return sblock->header_error || sblock->checksum_error;
}

static int scrub_checksum_super(struct scrub_block *sblock)
{
	struct btrfs_super_block *s;
	struct scrub_ctx *sctx = sblock->sctx;
	u8 calculated_csum[BTRFS_CSUM_SIZE];
	u8 on_disk_csum[BTRFS_CSUM_SIZE];
	struct page *page;
	void *mapped_buffer;
	u64 mapped_size;
	void *p;
	u32 crc = ~(u32)0;
	int fail_gen = 0;
	int fail_cor = 0;
	u64 len;
	int index;

	BUG_ON(sblock->page_count < 1);
	page = sblock->pagev[0]->page;
	mapped_buffer = kmap_atomic(page);
	s = (struct btrfs_super_block *)mapped_buffer;
	memcpy(on_disk_csum, s->csum, sctx->csum_size);

	if (sblock->pagev[0]->logical != btrfs_super_bytenr(s))
		++fail_cor;

	if (sblock->pagev[0]->generation != btrfs_super_generation(s))
		++fail_gen;

	if (!scrub_check_fsid(s->fsid, sblock->pagev[0]))
		++fail_cor;

	len = BTRFS_SUPER_INFO_SIZE - BTRFS_CSUM_SIZE;
	mapped_size = PAGE_SIZE - BTRFS_CSUM_SIZE;
	p = ((u8 *)mapped_buffer) + BTRFS_CSUM_SIZE;
	index = 0;
	for (;;) {
		u64 l = min_t(u64, len, mapped_size);

		crc = btrfs_csum_data(p, crc, l);
		kunmap_atomic(mapped_buffer);
		len -= l;
		if (len == 0)
			break;
		index++;
		BUG_ON(index >= sblock->page_count);
		BUG_ON(!sblock->pagev[index]->page);
		page = sblock->pagev[index]->page;
		mapped_buffer = kmap_atomic(page);
		mapped_size = PAGE_SIZE;
		p = mapped_buffer;
	}

	btrfs_csum_final(crc, calculated_csum);
	if (memcmp(calculated_csum, on_disk_csum, sctx->csum_size))
		++fail_cor;

	if (fail_cor + fail_gen) {
		 
		spin_lock(&sctx->stat_lock);
		++sctx->stat.super_errors;
		spin_unlock(&sctx->stat_lock);
		if (fail_cor)
			btrfs_dev_stat_inc_and_print(sblock->pagev[0]->dev,
				BTRFS_DEV_STAT_CORRUPTION_ERRS);
		else
			btrfs_dev_stat_inc_and_print(sblock->pagev[0]->dev,
				BTRFS_DEV_STAT_GENERATION_ERRS);
	}

	return fail_cor + fail_gen;
}

static void scrub_block_get(struct scrub_block *sblock)
{
	atomic_inc(&sblock->refs);
}

static void scrub_block_put(struct scrub_block *sblock)
{
	if (atomic_dec_and_test(&sblock->refs)) {
		int i;

		if (sblock->sparity)
			scrub_parity_put(sblock->sparity);

		for (i = 0; i < sblock->page_count; i++)
			scrub_page_put(sblock->pagev[i]);
		kfree(sblock);
	}
}

static void scrub_page_get(struct scrub_page *spage)
{
	atomic_inc(&spage->refs);
}

static void scrub_page_put(struct scrub_page *spage)
{
	if (atomic_dec_and_test(&spage->refs)) {
		if (spage->page)
			__free_page(spage->page);
		kfree(spage);
	}
}

static void scrub_submit(struct scrub_ctx *sctx)
{
	struct scrub_bio *sbio;

	if (sctx->curr == -1)
		return;

	sbio = sctx->bios[sctx->curr];
	sctx->curr = -1;
	scrub_pending_bio_inc(sctx);
	btrfsic_submit_bio(READ, sbio->bio);
}

static int scrub_add_page_to_rd_bio(struct scrub_ctx *sctx,
				    struct scrub_page *spage)
{
	struct scrub_block *sblock = spage->sblock;
	struct scrub_bio *sbio;
	int ret;

again:
	 
	while (sctx->curr == -1) {
		spin_lock(&sctx->list_lock);
		sctx->curr = sctx->first_free;
		if (sctx->curr != -1) {
			sctx->first_free = sctx->bios[sctx->curr]->next_free;
			sctx->bios[sctx->curr]->next_free = -1;
			sctx->bios[sctx->curr]->page_count = 0;
			spin_unlock(&sctx->list_lock);
		} else {
			spin_unlock(&sctx->list_lock);
			wait_event(sctx->list_wait, sctx->first_free != -1);
		}
	}
	sbio = sctx->bios[sctx->curr];
	if (sbio->page_count == 0) {
		struct bio *bio;

		sbio->physical = spage->physical;
		sbio->logical = spage->logical;
		sbio->dev = spage->dev;
		bio = sbio->bio;
		if (!bio) {
			bio = btrfs_io_bio_alloc(GFP_KERNEL,
					sctx->pages_per_rd_bio);
			if (!bio)
				return -ENOMEM;
			sbio->bio = bio;
		}

		bio->bi_private = sbio;
		bio->bi_end_io = scrub_bio_end_io;
		bio->bi_bdev = sbio->dev->bdev;
		bio->bi_iter.bi_sector = sbio->physical >> 9;
		sbio->err = 0;
	} else if (sbio->physical + sbio->page_count * PAGE_SIZE !=
		   spage->physical ||
		   sbio->logical + sbio->page_count * PAGE_SIZE !=
		   spage->logical ||
		   sbio->dev != spage->dev) {
		scrub_submit(sctx);
		goto again;
	}

	sbio->pagev[sbio->page_count] = spage;
	ret = bio_add_page(sbio->bio, spage->page, PAGE_SIZE, 0);
	if (ret != PAGE_SIZE) {
		if (sbio->page_count < 1) {
			bio_put(sbio->bio);
			sbio->bio = NULL;
			return -EIO;
		}
		scrub_submit(sctx);
		goto again;
	}

	scrub_block_get(sblock);  
	atomic_inc(&sblock->outstanding_pages);
	sbio->page_count++;
	if (sbio->page_count == sctx->pages_per_rd_bio)
		scrub_submit(sctx);

	return 0;
}

static void scrub_missing_raid56_end_io(struct bio *bio)
{
	struct scrub_block *sblock = bio->bi_private;
	struct btrfs_fs_info *fs_info = sblock->sctx->dev_root->fs_info;

	if (bio->bi_error)
		sblock->no_io_error_seen = 0;

	bio_put(bio);

	btrfs_queue_work(fs_info->scrub_workers, &sblock->work);
}

static void scrub_missing_raid56_worker(struct btrfs_work *work)
{
	struct scrub_block *sblock = container_of(work, struct scrub_block, work);
	struct scrub_ctx *sctx = sblock->sctx;
	u64 logical;
	struct btrfs_device *dev;

	logical = sblock->pagev[0]->logical;
	dev = sblock->pagev[0]->dev;

	if (sblock->no_io_error_seen)
		scrub_recheck_block_checksum(sblock);

	if (!sblock->no_io_error_seen) {
		spin_lock(&sctx->stat_lock);
		sctx->stat.read_errors++;
		spin_unlock(&sctx->stat_lock);
		btrfs_err_rl_in_rcu(sctx->dev_root->fs_info,
			"IO error rebuilding logical %llu for dev %s",
			logical, rcu_str_deref(dev->name));
	} else if (sblock->header_error || sblock->checksum_error) {
		spin_lock(&sctx->stat_lock);
		sctx->stat.uncorrectable_errors++;
		spin_unlock(&sctx->stat_lock);
		btrfs_err_rl_in_rcu(sctx->dev_root->fs_info,
			"failed to rebuild valid logical %llu for dev %s",
			logical, rcu_str_deref(dev->name));
	} else {
		scrub_write_block_to_dev_replace(sblock);
	}

	scrub_block_put(sblock);

	if (sctx->is_dev_replace &&
	    atomic_read(&sctx->wr_ctx.flush_all_writes)) {
		mutex_lock(&sctx->wr_ctx.wr_lock);
		scrub_wr_submit(sctx);
		mutex_unlock(&sctx->wr_ctx.wr_lock);
	}

	scrub_pending_bio_dec(sctx);
}

static void scrub_missing_raid56_pages(struct scrub_block *sblock)
{
	struct scrub_ctx *sctx = sblock->sctx;
	struct btrfs_fs_info *fs_info = sctx->dev_root->fs_info;
	u64 length = sblock->page_count * PAGE_SIZE;
	u64 logical = sblock->pagev[0]->logical;
	struct btrfs_bio *bbio = NULL;
	struct bio *bio;
	struct btrfs_raid_bio *rbio;
	int ret;
	int i;

	ret = btrfs_map_sblock(fs_info, REQ_GET_READ_MIRRORS, logical, &length,
			       &bbio, 0, 1);
	if (ret || !bbio || !bbio->raid_map)
		goto bbio_out;

	if (WARN_ON(!sctx->is_dev_replace ||
		    !(bbio->map_type & BTRFS_BLOCK_GROUP_RAID56_MASK))) {
		 
		goto bbio_out;
	}

	bio = btrfs_io_bio_alloc(GFP_NOFS, 0);
	if (!bio)
		goto bbio_out;

	bio->bi_iter.bi_sector = logical >> 9;
	bio->bi_private = sblock;
	bio->bi_end_io = scrub_missing_raid56_end_io;

	rbio = raid56_alloc_missing_rbio(sctx->dev_root, bio, bbio, length);
	if (!rbio)
		goto rbio_out;

	for (i = 0; i < sblock->page_count; i++) {
		struct scrub_page *spage = sblock->pagev[i];

		raid56_add_scrub_pages(rbio, spage->page, spage->logical);
	}

	btrfs_init_work(&sblock->work, btrfs_scrub_helper,
			scrub_missing_raid56_worker, NULL, NULL);
	scrub_block_get(sblock);
	scrub_pending_bio_inc(sctx);
	raid56_submit_missing_rbio(rbio);
	return;

rbio_out:
	bio_put(bio);
bbio_out:
	btrfs_put_bbio(bbio);
	spin_lock(&sctx->stat_lock);
	sctx->stat.malloc_errors++;
	spin_unlock(&sctx->stat_lock);
}

static int scrub_pages(struct scrub_ctx *sctx, u64 logical, u64 len,
		       u64 physical, struct btrfs_device *dev, u64 flags,
		       u64 gen, int mirror_num, u8 *csum, int force,
		       u64 physical_for_dev_replace)
{
	struct scrub_block *sblock;
	int index;

	sblock = kzalloc(sizeof(*sblock), GFP_KERNEL);
	if (!sblock) {
		spin_lock(&sctx->stat_lock);
		sctx->stat.malloc_errors++;
		spin_unlock(&sctx->stat_lock);
		return -ENOMEM;
	}

	atomic_set(&sblock->refs, 1);
	sblock->sctx = sctx;
	sblock->no_io_error_seen = 1;

	for (index = 0; len > 0; index++) {
		struct scrub_page *spage;
		u64 l = min_t(u64, len, PAGE_SIZE);

		spage = kzalloc(sizeof(*spage), GFP_KERNEL);
		if (!spage) {
leave_nomem:
			spin_lock(&sctx->stat_lock);
			sctx->stat.malloc_errors++;
			spin_unlock(&sctx->stat_lock);
			scrub_block_put(sblock);
			return -ENOMEM;
		}
		BUG_ON(index >= SCRUB_MAX_PAGES_PER_BLOCK);
		scrub_page_get(spage);
		sblock->pagev[index] = spage;
		spage->sblock = sblock;
		spage->dev = dev;
		spage->flags = flags;
		spage->generation = gen;
		spage->logical = logical;
		spage->physical = physical;
		spage->physical_for_dev_replace = physical_for_dev_replace;
		spage->mirror_num = mirror_num;
		if (csum) {
			spage->have_csum = 1;
			memcpy(spage->csum, csum, sctx->csum_size);
		} else {
			spage->have_csum = 0;
		}
		sblock->page_count++;
		spage->page = alloc_page(GFP_KERNEL);
		if (!spage->page)
			goto leave_nomem;
		len -= l;
		logical += l;
		physical += l;
		physical_for_dev_replace += l;
	}

	WARN_ON(sblock->page_count == 0);
	if (dev->missing) {
		 
		scrub_missing_raid56_pages(sblock);
	} else {
		for (index = 0; index < sblock->page_count; index++) {
			struct scrub_page *spage = sblock->pagev[index];
			int ret;

			ret = scrub_add_page_to_rd_bio(sctx, spage);
			if (ret) {
				scrub_block_put(sblock);
				return ret;
			}
		}

		if (force)
			scrub_submit(sctx);
	}

	scrub_block_put(sblock);
	return 0;
}

static void scrub_bio_end_io(struct bio *bio)
{
	struct scrub_bio *sbio = bio->bi_private;
	struct btrfs_fs_info *fs_info = sbio->dev->dev_root->fs_info;

	sbio->err = bio->bi_error;
	sbio->bio = bio;

	btrfs_queue_work(fs_info->scrub_workers, &sbio->work);
}

static void scrub_bio_end_io_worker(struct btrfs_work *work)
{
	struct scrub_bio *sbio = container_of(work, struct scrub_bio, work);
	struct scrub_ctx *sctx = sbio->sctx;
	int i;

	BUG_ON(sbio->page_count > SCRUB_PAGES_PER_RD_BIO);
	if (sbio->err) {
		for (i = 0; i < sbio->page_count; i++) {
			struct scrub_page *spage = sbio->pagev[i];

			spage->io_error = 1;
			spage->sblock->no_io_error_seen = 0;
		}
	}

	for (i = 0; i < sbio->page_count; i++) {
		struct scrub_page *spage = sbio->pagev[i];
		struct scrub_block *sblock = spage->sblock;

		if (atomic_dec_and_test(&sblock->outstanding_pages))
			scrub_block_complete(sblock);
		scrub_block_put(sblock);
	}

	bio_put(sbio->bio);
	sbio->bio = NULL;
	spin_lock(&sctx->list_lock);
	sbio->next_free = sctx->first_free;
	sctx->first_free = sbio->index;
	spin_unlock(&sctx->list_lock);

	if (sctx->is_dev_replace &&
	    atomic_read(&sctx->wr_ctx.flush_all_writes)) {
		mutex_lock(&sctx->wr_ctx.wr_lock);
		scrub_wr_submit(sctx);
		mutex_unlock(&sctx->wr_ctx.wr_lock);
	}

	scrub_pending_bio_dec(sctx);
}

static inline void __scrub_mark_bitmap(struct scrub_parity *sparity,
				       unsigned long *bitmap,
				       u64 start, u64 len)
{
	u32 offset;
	int nsectors;
	int sectorsize = sparity->sctx->dev_root->sectorsize;

	if (len >= sparity->stripe_len) {
		bitmap_set(bitmap, 0, sparity->nsectors);
		return;
	}

	start -= sparity->logic_start;
	start = div_u64_rem(start, sparity->stripe_len, &offset);
	offset /= sectorsize;
	nsectors = (int)len / sectorsize;

	if (offset + nsectors <= sparity->nsectors) {
		bitmap_set(bitmap, offset, nsectors);
		return;
	}

	bitmap_set(bitmap, offset, sparity->nsectors - offset);
	bitmap_set(bitmap, 0, nsectors - (sparity->nsectors - offset));
}

static inline void scrub_parity_mark_sectors_error(struct scrub_parity *sparity,
						   u64 start, u64 len)
{
	__scrub_mark_bitmap(sparity, sparity->ebitmap, start, len);
}

static inline void scrub_parity_mark_sectors_data(struct scrub_parity *sparity,
						  u64 start, u64 len)
{
	__scrub_mark_bitmap(sparity, sparity->dbitmap, start, len);
}

static void scrub_block_complete(struct scrub_block *sblock)
{
	int corrupted = 0;

	if (!sblock->no_io_error_seen) {
		corrupted = 1;
		scrub_handle_errored_block(sblock);
	} else {
		 
		corrupted = scrub_checksum(sblock);
		if (!corrupted && sblock->sctx->is_dev_replace)
			scrub_write_block_to_dev_replace(sblock);
	}

	if (sblock->sparity && corrupted && !sblock->data_corrected) {
		u64 start = sblock->pagev[0]->logical;
		u64 end = sblock->pagev[sblock->page_count - 1]->logical +
			  PAGE_SIZE;

		scrub_parity_mark_sectors_error(sblock->sparity,
						start, end - start);
	}
}

static int scrub_find_csum(struct scrub_ctx *sctx, u64 logical, u8 *csum)
{
	struct btrfs_ordered_sum *sum = NULL;
	unsigned long index;
	unsigned long num_sectors;

	while (!list_empty(&sctx->csum_list)) {
		sum = list_first_entry(&sctx->csum_list,
				       struct btrfs_ordered_sum, list);
		if (sum->bytenr > logical)
			return 0;
		if (sum->bytenr + sum->len > logical)
			break;

		++sctx->stat.csum_discards;
		list_del(&sum->list);
		kfree(sum);
		sum = NULL;
	}
	if (!sum)
		return 0;

	index = ((u32)(logical - sum->bytenr)) / sctx->sectorsize;
	num_sectors = sum->len / sctx->sectorsize;
	memcpy(csum, sum->sums + index, sctx->csum_size);
	if (index == num_sectors - 1) {
		list_del(&sum->list);
		kfree(sum);
	}
	return 1;
}

static int scrub_extent(struct scrub_ctx *sctx, u64 logical, u64 len,
			u64 physical, struct btrfs_device *dev, u64 flags,
			u64 gen, int mirror_num, u64 physical_for_dev_replace)
{
	int ret;
	u8 csum[BTRFS_CSUM_SIZE];
	u32 blocksize;

	if (flags & BTRFS_EXTENT_FLAG_DATA) {
		blocksize = sctx->sectorsize;
		spin_lock(&sctx->stat_lock);
		sctx->stat.data_extents_scrubbed++;
		sctx->stat.data_bytes_scrubbed += len;
		spin_unlock(&sctx->stat_lock);
	} else if (flags & BTRFS_EXTENT_FLAG_TREE_BLOCK) {
		blocksize = sctx->nodesize;
		spin_lock(&sctx->stat_lock);
		sctx->stat.tree_extents_scrubbed++;
		sctx->stat.tree_bytes_scrubbed += len;
		spin_unlock(&sctx->stat_lock);
	} else {
		blocksize = sctx->sectorsize;
		WARN_ON(1);
	}

	while (len) {
		u64 l = min_t(u64, len, blocksize);
		int have_csum = 0;

		if (flags & BTRFS_EXTENT_FLAG_DATA) {
			 
			have_csum = scrub_find_csum(sctx, logical, csum);
			if (have_csum == 0)
				++sctx->stat.no_csum;
			if (sctx->is_dev_replace && !have_csum) {
				ret = copy_nocow_pages(sctx, logical, l,
						       mirror_num,
						      physical_for_dev_replace);
				goto behind_scrub_pages;
			}
		}
		ret = scrub_pages(sctx, logical, l, physical, dev, flags, gen,
				  mirror_num, have_csum ? csum : NULL, 0,
				  physical_for_dev_replace);
behind_scrub_pages:
		if (ret)
			return ret;
		len -= l;
		logical += l;
		physical += l;
		physical_for_dev_replace += l;
	}
	return 0;
}

static int scrub_pages_for_parity(struct scrub_parity *sparity,
				  u64 logical, u64 len,
				  u64 physical, struct btrfs_device *dev,
				  u64 flags, u64 gen, int mirror_num, u8 *csum)
{
	struct scrub_ctx *sctx = sparity->sctx;
	struct scrub_block *sblock;
	int index;

	sblock = kzalloc(sizeof(*sblock), GFP_KERNEL);
	if (!sblock) {
		spin_lock(&sctx->stat_lock);
		sctx->stat.malloc_errors++;
		spin_unlock(&sctx->stat_lock);
		return -ENOMEM;
	}

	atomic_set(&sblock->refs, 1);
	sblock->sctx = sctx;
	sblock->no_io_error_seen = 1;
	sblock->sparity = sparity;
	scrub_parity_get(sparity);

	for (index = 0; len > 0; index++) {
		struct scrub_page *spage;
		u64 l = min_t(u64, len, PAGE_SIZE);

		spage = kzalloc(sizeof(*spage), GFP_KERNEL);
		if (!spage) {
leave_nomem:
			spin_lock(&sctx->stat_lock);
			sctx->stat.malloc_errors++;
			spin_unlock(&sctx->stat_lock);
			scrub_block_put(sblock);
			return -ENOMEM;
		}
		BUG_ON(index >= SCRUB_MAX_PAGES_PER_BLOCK);
		 
		scrub_page_get(spage);
		sblock->pagev[index] = spage;
		 
		scrub_page_get(spage);
		list_add_tail(&spage->list, &sparity->spages);
		spage->sblock = sblock;
		spage->dev = dev;
		spage->flags = flags;
		spage->generation = gen;
		spage->logical = logical;
		spage->physical = physical;
		spage->mirror_num = mirror_num;
		if (csum) {
			spage->have_csum = 1;
			memcpy(spage->csum, csum, sctx->csum_size);
		} else {
			spage->have_csum = 0;
		}
		sblock->page_count++;
		spage->page = alloc_page(GFP_KERNEL);
		if (!spage->page)
			goto leave_nomem;
		len -= l;
		logical += l;
		physical += l;
	}

	WARN_ON(sblock->page_count == 0);
	for (index = 0; index < sblock->page_count; index++) {
		struct scrub_page *spage = sblock->pagev[index];
		int ret;

		ret = scrub_add_page_to_rd_bio(sctx, spage);
		if (ret) {
			scrub_block_put(sblock);
			return ret;
		}
	}

	scrub_block_put(sblock);
	return 0;
}

static int scrub_extent_for_parity(struct scrub_parity *sparity,
				   u64 logical, u64 len,
				   u64 physical, struct btrfs_device *dev,
				   u64 flags, u64 gen, int mirror_num)
{
	struct scrub_ctx *sctx = sparity->sctx;
	int ret;
	u8 csum[BTRFS_CSUM_SIZE];
	u32 blocksize;

	if (dev->missing) {
		scrub_parity_mark_sectors_error(sparity, logical, len);
		return 0;
	}

	if (flags & BTRFS_EXTENT_FLAG_DATA) {
		blocksize = sctx->sectorsize;
	} else if (flags & BTRFS_EXTENT_FLAG_TREE_BLOCK) {
		blocksize = sctx->nodesize;
	} else {
		blocksize = sctx->sectorsize;
		WARN_ON(1);
	}

	while (len) {
		u64 l = min_t(u64, len, blocksize);
		int have_csum = 0;

		if (flags & BTRFS_EXTENT_FLAG_DATA) {
			 
			have_csum = scrub_find_csum(sctx, logical, csum);
			if (have_csum == 0)
				goto skip;
		}
		ret = scrub_pages_for_parity(sparity, logical, l, physical, dev,
					     flags, gen, mirror_num,
					     have_csum ? csum : NULL);
		if (ret)
			return ret;
skip:
		len -= l;
		logical += l;
		physical += l;
	}
	return 0;
}

static int get_raid56_logic_offset(u64 physical, int num,
				   struct map_lookup *map, u64 *offset,
				   u64 *stripe_start)
{
	int i;
	int j = 0;
	u64 stripe_nr;
	u64 last_offset;
	u32 stripe_index;
	u32 rot;

	last_offset = (physical - map->stripes[num].physical) *
		      nr_data_stripes(map);
	if (stripe_start)
		*stripe_start = last_offset;

	*offset = last_offset;
	for (i = 0; i < nr_data_stripes(map); i++) {
		*offset = last_offset + i * map->stripe_len;

		stripe_nr = div_u64(*offset, map->stripe_len);
		stripe_nr = div_u64(stripe_nr, nr_data_stripes(map));

		stripe_nr = div_u64_rem(stripe_nr, map->num_stripes, &rot);
		 
		rot += i;
		stripe_index = rot % map->num_stripes;
		if (stripe_index == num)
			return 0;
		if (stripe_index < num)
			j++;
	}
	*offset = last_offset + j * map->stripe_len;
	return 1;
}

static void scrub_free_parity(struct scrub_parity *sparity)
{
	struct scrub_ctx *sctx = sparity->sctx;
	struct scrub_page *curr, *next;
	int nbits;

	nbits = bitmap_weight(sparity->ebitmap, sparity->nsectors);
	if (nbits) {
		spin_lock(&sctx->stat_lock);
		sctx->stat.read_errors += nbits;
		sctx->stat.uncorrectable_errors += nbits;
		spin_unlock(&sctx->stat_lock);
	}

	list_for_each_entry_safe(curr, next, &sparity->spages, list) {
		list_del_init(&curr->list);
		scrub_page_put(curr);
	}

	kfree(sparity);
}

static void scrub_parity_bio_endio_worker(struct btrfs_work *work)
{
	struct scrub_parity *sparity = container_of(work, struct scrub_parity,
						    work);
	struct scrub_ctx *sctx = sparity->sctx;

	scrub_free_parity(sparity);
	scrub_pending_bio_dec(sctx);
}

static void scrub_parity_bio_endio(struct bio *bio)
{
	struct scrub_parity *sparity = (struct scrub_parity *)bio->bi_private;

	if (bio->bi_error)
		bitmap_or(sparity->ebitmap, sparity->ebitmap, sparity->dbitmap,
			  sparity->nsectors);

	bio_put(bio);

	btrfs_init_work(&sparity->work, btrfs_scrubparity_helper,
			scrub_parity_bio_endio_worker, NULL, NULL);
	btrfs_queue_work(sparity->sctx->dev_root->fs_info->scrub_parity_workers,
			 &sparity->work);
}

static void scrub_parity_check_and_repair(struct scrub_parity *sparity)
{
	struct scrub_ctx *sctx = sparity->sctx;
	struct bio *bio;
	struct btrfs_raid_bio *rbio;
	struct scrub_page *spage;
	struct btrfs_bio *bbio = NULL;
	u64 length;
	int ret;

	if (!bitmap_andnot(sparity->dbitmap, sparity->dbitmap, sparity->ebitmap,
			   sparity->nsectors))
		goto out;

	length = sparity->logic_end - sparity->logic_start;
	ret = btrfs_map_sblock(sctx->dev_root->fs_info, WRITE,
			       sparity->logic_start,
			       &length, &bbio, 0, 1);
	if (ret || !bbio || !bbio->raid_map)
		goto bbio_out;

	bio = btrfs_io_bio_alloc(GFP_NOFS, 0);
	if (!bio)
		goto bbio_out;

	bio->bi_iter.bi_sector = sparity->logic_start >> 9;
	bio->bi_private = sparity;
	bio->bi_end_io = scrub_parity_bio_endio;

	rbio = raid56_parity_alloc_scrub_rbio(sctx->dev_root, bio, bbio,
					      length, sparity->scrub_dev,
					      sparity->dbitmap,
					      sparity->nsectors);
	if (!rbio)
		goto rbio_out;

	list_for_each_entry(spage, &sparity->spages, list)
		raid56_add_scrub_pages(rbio, spage->page, spage->logical);

	scrub_pending_bio_inc(sctx);
	raid56_parity_submit_scrub_rbio(rbio);
	return;

rbio_out:
	bio_put(bio);
bbio_out:
	btrfs_put_bbio(bbio);
	bitmap_or(sparity->ebitmap, sparity->ebitmap, sparity->dbitmap,
		  sparity->nsectors);
	spin_lock(&sctx->stat_lock);
	sctx->stat.malloc_errors++;
	spin_unlock(&sctx->stat_lock);
out:
	scrub_free_parity(sparity);
}

static inline int scrub_calc_parity_bitmap_len(int nsectors)
{
	return DIV_ROUND_UP(nsectors, BITS_PER_LONG) * sizeof(long);
}

static void scrub_parity_get(struct scrub_parity *sparity)
{
	atomic_inc(&sparity->refs);
}

static void scrub_parity_put(struct scrub_parity *sparity)
{
	if (!atomic_dec_and_test(&sparity->refs))
		return;

	scrub_parity_check_and_repair(sparity);
}

static noinline_for_stack int scrub_raid56_parity(struct scrub_ctx *sctx,
						  struct map_lookup *map,
						  struct btrfs_device *sdev,
						  struct btrfs_path *path,
						  u64 logic_start,
						  u64 logic_end)
{
	struct btrfs_fs_info *fs_info = sctx->dev_root->fs_info;
	struct btrfs_root *root = fs_info->extent_root;
	struct btrfs_root *csum_root = fs_info->csum_root;
	struct btrfs_extent_item *extent;
	struct btrfs_bio *bbio = NULL;
	u64 flags;
	int ret;
	int slot;
	struct extent_buffer *l;
	struct btrfs_key key;
	u64 generation;
	u64 extent_logical;
	u64 extent_physical;
	u64 extent_len;
	u64 mapped_length;
	struct btrfs_device *extent_dev;
	struct scrub_parity *sparity;
	int nsectors;
	int bitmap_len;
	int extent_mirror_num;
	int stop_loop = 0;

	nsectors = div_u64(map->stripe_len, root->sectorsize);
	bitmap_len = scrub_calc_parity_bitmap_len(nsectors);
	sparity = kzalloc(sizeof(struct scrub_parity) + 2 * bitmap_len,
			  GFP_NOFS);
	if (!sparity) {
		spin_lock(&sctx->stat_lock);
		sctx->stat.malloc_errors++;
		spin_unlock(&sctx->stat_lock);
		return -ENOMEM;
	}

	sparity->stripe_len = map->stripe_len;
	sparity->nsectors = nsectors;
	sparity->sctx = sctx;
	sparity->scrub_dev = sdev;
	sparity->logic_start = logic_start;
	sparity->logic_end = logic_end;
	atomic_set(&sparity->refs, 1);
	INIT_LIST_HEAD(&sparity->spages);
	sparity->dbitmap = sparity->bitmap;
	sparity->ebitmap = (void *)sparity->bitmap + bitmap_len;

	ret = 0;
	while (logic_start < logic_end) {
		if (btrfs_fs_incompat(fs_info, SKINNY_METADATA))
			key.type = BTRFS_METADATA_ITEM_KEY;
		else
			key.type = BTRFS_EXTENT_ITEM_KEY;
		key.objectid = logic_start;
		key.offset = (u64)-1;

		ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
		if (ret < 0)
			goto out;

		if (ret > 0) {
			ret = btrfs_previous_extent_item(root, path, 0);
			if (ret < 0)
				goto out;
			if (ret > 0) {
				btrfs_release_path(path);
				ret = btrfs_search_slot(NULL, root, &key,
							path, 0, 0);
				if (ret < 0)
					goto out;
			}
		}

		stop_loop = 0;
		while (1) {
			u64 bytes;

			l = path->nodes[0];
			slot = path->slots[0];
			if (slot >= btrfs_header_nritems(l)) {
				ret = btrfs_next_leaf(root, path);
				if (ret == 0)
					continue;
				if (ret < 0)
					goto out;

				stop_loop = 1;
				break;
			}
			btrfs_item_key_to_cpu(l, &key, slot);

			if (key.type != BTRFS_EXTENT_ITEM_KEY &&
			    key.type != BTRFS_METADATA_ITEM_KEY)
				goto next;

			if (key.type == BTRFS_METADATA_ITEM_KEY)
				bytes = root->nodesize;
			else
				bytes = key.offset;

			if (key.objectid + bytes <= logic_start)
				goto next;

			if (key.objectid >= logic_end) {
				stop_loop = 1;
				break;
			}

			while (key.objectid >= logic_start + map->stripe_len)
				logic_start += map->stripe_len;

			extent = btrfs_item_ptr(l, slot,
						struct btrfs_extent_item);
			flags = btrfs_extent_flags(l, extent);
			generation = btrfs_extent_generation(l, extent);

			if ((flags & BTRFS_EXTENT_FLAG_TREE_BLOCK) &&
			    (key.objectid < logic_start ||
			     key.objectid + bytes >
			     logic_start + map->stripe_len)) {
				btrfs_err(fs_info, "scrub: tree block %llu spanning stripes, ignored. logical=%llu",
					  key.objectid, logic_start);
				spin_lock(&sctx->stat_lock);
				sctx->stat.uncorrectable_errors++;
				spin_unlock(&sctx->stat_lock);
				goto next;
			}
again:
			extent_logical = key.objectid;
			extent_len = bytes;

			if (extent_logical < logic_start) {
				extent_len -= logic_start - extent_logical;
				extent_logical = logic_start;
			}

			if (extent_logical + extent_len >
			    logic_start + map->stripe_len)
				extent_len = logic_start + map->stripe_len -
					     extent_logical;

			scrub_parity_mark_sectors_data(sparity, extent_logical,
						       extent_len);

			mapped_length = extent_len;
			bbio = NULL;
			ret = btrfs_map_block(fs_info, READ, extent_logical,
					      &mapped_length, &bbio, 0);
			if (!ret) {
				if (!bbio || mapped_length < extent_len)
					ret = -EIO;
			}
			if (ret) {
				btrfs_put_bbio(bbio);
				goto out;
			}
			extent_physical = bbio->stripes[0].physical;
			extent_mirror_num = bbio->mirror_num;
			extent_dev = bbio->stripes[0].dev;
			btrfs_put_bbio(bbio);

			ret = btrfs_lookup_csums_range(csum_root,
						extent_logical,
						extent_logical + extent_len - 1,
						&sctx->csum_list, 1);
			if (ret)
				goto out;

			ret = scrub_extent_for_parity(sparity, extent_logical,
						      extent_len,
						      extent_physical,
						      extent_dev, flags,
						      generation,
						      extent_mirror_num);

			scrub_free_csums(sctx);

			if (ret)
				goto out;

			if (extent_logical + extent_len <
			    key.objectid + bytes) {
				logic_start += map->stripe_len;

				if (logic_start >= logic_end) {
					stop_loop = 1;
					break;
				}

				if (logic_start < key.objectid + bytes) {
					cond_resched();
					goto again;
				}
			}
next:
			path->slots[0]++;
		}

		btrfs_release_path(path);

		if (stop_loop)
			break;

		logic_start += map->stripe_len;
	}
out:
	if (ret < 0)
		scrub_parity_mark_sectors_error(sparity, logic_start,
						logic_end - logic_start);
	scrub_parity_put(sparity);
	scrub_submit(sctx);
	mutex_lock(&sctx->wr_ctx.wr_lock);
	scrub_wr_submit(sctx);
	mutex_unlock(&sctx->wr_ctx.wr_lock);

	btrfs_release_path(path);
	return ret < 0 ? ret : 0;
}

static noinline_for_stack int scrub_stripe(struct scrub_ctx *sctx,
					   struct map_lookup *map,
					   struct btrfs_device *scrub_dev,
					   int num, u64 base, u64 length,
					   int is_dev_replace)
{
	struct btrfs_path *path, *ppath;
	struct btrfs_fs_info *fs_info = sctx->dev_root->fs_info;
	struct btrfs_root *root = fs_info->extent_root;
	struct btrfs_root *csum_root = fs_info->csum_root;
	struct btrfs_extent_item *extent;
	struct blk_plug plug;
	u64 flags;
	int ret;
	int slot;
	u64 nstripes;
	struct extent_buffer *l;
	u64 physical;
	u64 logical;
	u64 logic_end;
	u64 physical_end;
	u64 generation;
	int mirror_num;
	struct reada_control *reada1;
	struct reada_control *reada2;
	struct btrfs_key key;
	struct btrfs_key key_end;
	u64 increment = map->stripe_len;
	u64 offset;
	u64 extent_logical;
	u64 extent_physical;
	u64 extent_len;
	u64 stripe_logical;
	u64 stripe_end;
	struct btrfs_device *extent_dev;
	int extent_mirror_num;
	int stop_loop = 0;

	physical = map->stripes[num].physical;
	offset = 0;
	nstripes = div_u64(length, map->stripe_len);
	if (map->type & BTRFS_BLOCK_GROUP_RAID0) {
		offset = map->stripe_len * num;
		increment = map->stripe_len * map->num_stripes;
		mirror_num = 1;
	} else if (map->type & BTRFS_BLOCK_GROUP_RAID10) {
		int factor = map->num_stripes / map->sub_stripes;
		offset = map->stripe_len * (num / map->sub_stripes);
		increment = map->stripe_len * factor;
		mirror_num = num % map->sub_stripes + 1;
	} else if (map->type & BTRFS_BLOCK_GROUP_RAID1) {
		increment = map->stripe_len;
		mirror_num = num % map->num_stripes + 1;
	} else if (map->type & BTRFS_BLOCK_GROUP_DUP) {
		increment = map->stripe_len;
		mirror_num = num % map->num_stripes + 1;
	} else if (map->type & BTRFS_BLOCK_GROUP_RAID56_MASK) {
		get_raid56_logic_offset(physical, num, map, &offset, NULL);
		increment = map->stripe_len * nr_data_stripes(map);
		mirror_num = 1;
	} else {
		increment = map->stripe_len;
		mirror_num = 1;
	}

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	ppath = btrfs_alloc_path();
	if (!ppath) {
		btrfs_free_path(path);
		return -ENOMEM;
	}

	path->search_commit_root = 1;
	path->skip_locking = 1;

	ppath->search_commit_root = 1;
	ppath->skip_locking = 1;
	 
	logical = base + offset;
	physical_end = physical + nstripes * map->stripe_len;
	if (map->type & BTRFS_BLOCK_GROUP_RAID56_MASK) {
		get_raid56_logic_offset(physical_end, num,
					map, &logic_end, NULL);
		logic_end += base;
	} else {
		logic_end = logical + increment * nstripes;
	}
	wait_event(sctx->list_wait,
		   atomic_read(&sctx->bios_in_flight) == 0);
	scrub_blocked_if_needed(fs_info);

	key.objectid = logical;
	key.type = BTRFS_EXTENT_ITEM_KEY;
	key.offset = (u64)0;
	key_end.objectid = logic_end;
	key_end.type = BTRFS_METADATA_ITEM_KEY;
	key_end.offset = (u64)-1;
	reada1 = btrfs_reada_add(root, &key, &key_end);

	key.objectid = BTRFS_EXTENT_CSUM_OBJECTID;
	key.type = BTRFS_EXTENT_CSUM_KEY;
	key.offset = logical;
	key_end.objectid = BTRFS_EXTENT_CSUM_OBJECTID;
	key_end.type = BTRFS_EXTENT_CSUM_KEY;
	key_end.offset = logic_end;
	reada2 = btrfs_reada_add(csum_root, &key, &key_end);

	if (!IS_ERR(reada1))
		btrfs_reada_wait(reada1);
	if (!IS_ERR(reada2))
		btrfs_reada_wait(reada2);

	blk_start_plug(&plug);

	ret = 0;
	while (physical < physical_end) {
		 
		if (atomic_read(&fs_info->scrub_cancel_req) ||
		    atomic_read(&sctx->cancel_req)) {
			ret = -ECANCELED;
			goto out;
		}
		 
		if (atomic_read(&fs_info->scrub_pause_req)) {
			 
			atomic_set(&sctx->wr_ctx.flush_all_writes, 1);
			scrub_submit(sctx);
			mutex_lock(&sctx->wr_ctx.wr_lock);
			scrub_wr_submit(sctx);
			mutex_unlock(&sctx->wr_ctx.wr_lock);
			wait_event(sctx->list_wait,
				   atomic_read(&sctx->bios_in_flight) == 0);
			atomic_set(&sctx->wr_ctx.flush_all_writes, 0);
			scrub_blocked_if_needed(fs_info);
		}

		if (map->type & BTRFS_BLOCK_GROUP_RAID56_MASK) {
			ret = get_raid56_logic_offset(physical, num, map,
						      &logical,
						      &stripe_logical);
			logical += base;
			if (ret) {
				 
				stripe_logical += base;
				stripe_end = stripe_logical + increment;
				ret = scrub_raid56_parity(sctx, map, scrub_dev,
							  ppath, stripe_logical,
							  stripe_end);
				if (ret)
					goto out;
				goto skip;
			}
		}

		if (btrfs_fs_incompat(fs_info, SKINNY_METADATA))
			key.type = BTRFS_METADATA_ITEM_KEY;
		else
			key.type = BTRFS_EXTENT_ITEM_KEY;
		key.objectid = logical;
		key.offset = (u64)-1;

		ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
		if (ret < 0)
			goto out;

		if (ret > 0) {
			ret = btrfs_previous_extent_item(root, path, 0);
			if (ret < 0)
				goto out;
			if (ret > 0) {
				 
				btrfs_release_path(path);
				ret = btrfs_search_slot(NULL, root, &key,
							path, 0, 0);
				if (ret < 0)
					goto out;
			}
		}

		stop_loop = 0;
		while (1) {
			u64 bytes;

			l = path->nodes[0];
			slot = path->slots[0];
			if (slot >= btrfs_header_nritems(l)) {
				ret = btrfs_next_leaf(root, path);
				if (ret == 0)
					continue;
				if (ret < 0)
					goto out;

				stop_loop = 1;
				break;
			}
			btrfs_item_key_to_cpu(l, &key, slot);

			if (key.type != BTRFS_EXTENT_ITEM_KEY &&
			    key.type != BTRFS_METADATA_ITEM_KEY)
				goto next;

			if (key.type == BTRFS_METADATA_ITEM_KEY)
				bytes = root->nodesize;
			else
				bytes = key.offset;

			if (key.objectid + bytes <= logical)
				goto next;

			if (key.objectid >= logical + map->stripe_len) {
				 
				if (key.objectid >= logic_end)
					stop_loop = 1;
				break;
			}

			extent = btrfs_item_ptr(l, slot,
						struct btrfs_extent_item);
			flags = btrfs_extent_flags(l, extent);
			generation = btrfs_extent_generation(l, extent);

			if ((flags & BTRFS_EXTENT_FLAG_TREE_BLOCK) &&
			    (key.objectid < logical ||
			     key.objectid + bytes >
			     logical + map->stripe_len)) {
				btrfs_err(fs_info,
					   "scrub: tree block %llu spanning "
					   "stripes, ignored. logical=%llu",
				       key.objectid, logical);
				spin_lock(&sctx->stat_lock);
				sctx->stat.uncorrectable_errors++;
				spin_unlock(&sctx->stat_lock);
				goto next;
			}

again:
			extent_logical = key.objectid;
			extent_len = bytes;

			if (extent_logical < logical) {
				extent_len -= logical - extent_logical;
				extent_logical = logical;
			}
			if (extent_logical + extent_len >
			    logical + map->stripe_len) {
				extent_len = logical + map->stripe_len -
					     extent_logical;
			}

			extent_physical = extent_logical - logical + physical;
			extent_dev = scrub_dev;
			extent_mirror_num = mirror_num;
			if (is_dev_replace)
				scrub_remap_extent(fs_info, extent_logical,
						   extent_len, &extent_physical,
						   &extent_dev,
						   &extent_mirror_num);

			ret = btrfs_lookup_csums_range(csum_root,
						       extent_logical,
						       extent_logical +
						       extent_len - 1,
						       &sctx->csum_list, 1);
			if (ret)
				goto out;

			ret = scrub_extent(sctx, extent_logical, extent_len,
					   extent_physical, extent_dev, flags,
					   generation, extent_mirror_num,
					   extent_logical - logical + physical);

			scrub_free_csums(sctx);

			if (ret)
				goto out;

			if (extent_logical + extent_len <
			    key.objectid + bytes) {
				if (map->type & BTRFS_BLOCK_GROUP_RAID56_MASK) {
					 
loop:
					physical += map->stripe_len;
					ret = get_raid56_logic_offset(physical,
							num, map, &logical,
							&stripe_logical);
					logical += base;

					if (ret && physical < physical_end) {
						stripe_logical += base;
						stripe_end = stripe_logical +
								increment;
						ret = scrub_raid56_parity(sctx,
							map, scrub_dev, ppath,
							stripe_logical,
							stripe_end);
						if (ret)
							goto out;
						goto loop;
					}
				} else {
					physical += map->stripe_len;
					logical += increment;
				}
				if (logical < key.objectid + bytes) {
					cond_resched();
					goto again;
				}

				if (physical >= physical_end) {
					stop_loop = 1;
					break;
				}
			}
next:
			path->slots[0]++;
		}
		btrfs_release_path(path);
skip:
		logical += increment;
		physical += map->stripe_len;
		spin_lock(&sctx->stat_lock);
		if (stop_loop)
			sctx->stat.last_physical = map->stripes[num].physical +
						   length;
		else
			sctx->stat.last_physical = physical;
		spin_unlock(&sctx->stat_lock);
		if (stop_loop)
			break;
	}
out:
	 
	scrub_submit(sctx);
	mutex_lock(&sctx->wr_ctx.wr_lock);
	scrub_wr_submit(sctx);
	mutex_unlock(&sctx->wr_ctx.wr_lock);

	blk_finish_plug(&plug);
	btrfs_free_path(path);
	btrfs_free_path(ppath);
	return ret < 0 ? ret : 0;
}

static noinline_for_stack int scrub_chunk(struct scrub_ctx *sctx,
					  struct btrfs_device *scrub_dev,
					  u64 chunk_offset, u64 length,
					  u64 dev_offset,
					  struct btrfs_block_group_cache *cache,
					  int is_dev_replace)
{
	struct btrfs_mapping_tree *map_tree =
		&sctx->dev_root->fs_info->mapping_tree;
	struct map_lookup *map;
	struct extent_map *em;
	int i;
	int ret = 0;

	read_lock(&map_tree->map_tree.lock);
	em = lookup_extent_mapping(&map_tree->map_tree, chunk_offset, 1);
	read_unlock(&map_tree->map_tree.lock);

	if (!em) {
		 
		spin_lock(&cache->lock);
		if (!cache->removed)
			ret = -EINVAL;
		spin_unlock(&cache->lock);

		return ret;
	}

	map = em->map_lookup;
	if (em->start != chunk_offset)
		goto out;

	if (em->len < length)
		goto out;

	for (i = 0; i < map->num_stripes; ++i) {
		if (map->stripes[i].dev->bdev == scrub_dev->bdev &&
		    map->stripes[i].physical == dev_offset) {
			ret = scrub_stripe(sctx, map, scrub_dev, i,
					   chunk_offset, length,
					   is_dev_replace);
			if (ret)
				goto out;
		}
	}
out:
	free_extent_map(em);

	return ret;
}

static noinline_for_stack
int scrub_enumerate_chunks(struct scrub_ctx *sctx,
			   struct btrfs_device *scrub_dev, u64 start, u64 end,
			   int is_dev_replace)
{
	struct btrfs_dev_extent *dev_extent = NULL;
	struct btrfs_path *path;
	struct btrfs_root *root = sctx->dev_root;
	struct btrfs_fs_info *fs_info = root->fs_info;
	u64 length;
	u64 chunk_offset;
	int ret = 0;
	int ro_set;
	int slot;
	struct extent_buffer *l;
	struct btrfs_key key;
	struct btrfs_key found_key;
	struct btrfs_block_group_cache *cache;
	struct btrfs_dev_replace *dev_replace = &fs_info->dev_replace;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	path->reada = READA_FORWARD;
	path->search_commit_root = 1;
	path->skip_locking = 1;

	key.objectid = scrub_dev->devid;
	key.offset = 0ull;
	key.type = BTRFS_DEV_EXTENT_KEY;

	while (1) {
		ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
		if (ret < 0)
			break;
		if (ret > 0) {
			if (path->slots[0] >=
			    btrfs_header_nritems(path->nodes[0])) {
				ret = btrfs_next_leaf(root, path);
				if (ret < 0)
					break;
				if (ret > 0) {
					ret = 0;
					break;
				}
			} else {
				ret = 0;
			}
		}

		l = path->nodes[0];
		slot = path->slots[0];

		btrfs_item_key_to_cpu(l, &found_key, slot);

		if (found_key.objectid != scrub_dev->devid)
			break;

		if (found_key.type != BTRFS_DEV_EXTENT_KEY)
			break;

		if (found_key.offset >= end)
			break;

		if (found_key.offset < key.offset)
			break;

		dev_extent = btrfs_item_ptr(l, slot, struct btrfs_dev_extent);
		length = btrfs_dev_extent_length(l, dev_extent);

		if (found_key.offset + length <= start)
			goto skip;

		chunk_offset = btrfs_dev_extent_chunk_offset(l, dev_extent);

		cache = btrfs_lookup_block_group(fs_info, chunk_offset);

		if (!cache)
			goto skip;

		scrub_pause_on(fs_info);
		ret = btrfs_inc_block_group_ro(root, cache);
		scrub_pause_off(fs_info);

		if (ret == 0) {
			ro_set = 1;
		} else if (ret == -ENOSPC) {
			 
			ro_set = 0;
		} else {
			btrfs_warn(fs_info, "failed setting block group ro, ret=%d\n",
				   ret);
			btrfs_put_block_group(cache);
			break;
		}

		dev_replace->cursor_right = found_key.offset + length;
		dev_replace->cursor_left = found_key.offset;
		dev_replace->item_needs_writeback = 1;
		ret = scrub_chunk(sctx, scrub_dev, chunk_offset, length,
				  found_key.offset, cache, is_dev_replace);

		atomic_set(&sctx->wr_ctx.flush_all_writes, 1);
		scrub_submit(sctx);
		mutex_lock(&sctx->wr_ctx.wr_lock);
		scrub_wr_submit(sctx);
		mutex_unlock(&sctx->wr_ctx.wr_lock);

		wait_event(sctx->list_wait,
			   atomic_read(&sctx->bios_in_flight) == 0);

		scrub_pause_on(fs_info);

		wait_event(sctx->list_wait,
			   atomic_read(&sctx->workers_pending) == 0);
		atomic_set(&sctx->wr_ctx.flush_all_writes, 0);

		scrub_pause_off(fs_info);

		if (ro_set)
			btrfs_dec_block_group_ro(root, cache);

		spin_lock(&cache->lock);
		if (!cache->removed && !cache->ro && cache->reserved == 0 &&
		    btrfs_block_group_used(&cache->item) == 0) {
			spin_unlock(&cache->lock);
			spin_lock(&fs_info->unused_bgs_lock);
			if (list_empty(&cache->bg_list)) {
				btrfs_get_block_group(cache);
				list_add_tail(&cache->bg_list,
					      &fs_info->unused_bgs);
			}
			spin_unlock(&fs_info->unused_bgs_lock);
		} else {
			spin_unlock(&cache->lock);
		}

		btrfs_put_block_group(cache);
		if (ret)
			break;
		if (is_dev_replace &&
		    atomic64_read(&dev_replace->num_write_errors) > 0) {
			ret = -EIO;
			break;
		}
		if (sctx->stat.malloc_errors > 0) {
			ret = -ENOMEM;
			break;
		}

		dev_replace->cursor_left = dev_replace->cursor_right;
		dev_replace->item_needs_writeback = 1;
skip:
		key.offset = found_key.offset + length;
		btrfs_release_path(path);
	}

	btrfs_free_path(path);

	return ret;
}

static noinline_for_stack int scrub_supers(struct scrub_ctx *sctx,
					   struct btrfs_device *scrub_dev)
{
	int	i;
	u64	bytenr;
	u64	gen;
	int	ret;
	struct btrfs_root *root = sctx->dev_root;

	if (test_bit(BTRFS_FS_STATE_ERROR, &root->fs_info->fs_state))
		return -EIO;

	if (scrub_dev->fs_devices != root->fs_info->fs_devices)
		gen = scrub_dev->generation;
	else
		gen = root->fs_info->last_trans_committed;

	for (i = 0; i < BTRFS_SUPER_MIRROR_MAX; i++) {
		bytenr = btrfs_sb_offset(i);
		if (bytenr + BTRFS_SUPER_INFO_SIZE >
		    scrub_dev->commit_total_bytes)
			break;

		ret = scrub_pages(sctx, bytenr, BTRFS_SUPER_INFO_SIZE, bytenr,
				  scrub_dev, BTRFS_EXTENT_FLAG_SUPER, gen, i,
				  NULL, 1, bytenr);
		if (ret)
			return ret;
	}
	wait_event(sctx->list_wait, atomic_read(&sctx->bios_in_flight) == 0);

	return 0;
}

static noinline_for_stack int scrub_workers_get(struct btrfs_fs_info *fs_info,
						int is_dev_replace)
{
	unsigned int flags = WQ_FREEZABLE | WQ_UNBOUND;
	int max_active = fs_info->thread_pool_size;

	if (fs_info->scrub_workers_refcnt == 0) {
		if (is_dev_replace)
			fs_info->scrub_workers =
				btrfs_alloc_workqueue("scrub", flags,
						      1, 4);
		else
			fs_info->scrub_workers =
				btrfs_alloc_workqueue("scrub", flags,
						      max_active, 4);
		if (!fs_info->scrub_workers)
			goto fail_scrub_workers;

		fs_info->scrub_wr_completion_workers =
			btrfs_alloc_workqueue("scrubwrc", flags,
					      max_active, 2);
		if (!fs_info->scrub_wr_completion_workers)
			goto fail_scrub_wr_completion_workers;

		fs_info->scrub_nocow_workers =
			btrfs_alloc_workqueue("scrubnc", flags, 1, 0);
		if (!fs_info->scrub_nocow_workers)
			goto fail_scrub_nocow_workers;
		fs_info->scrub_parity_workers =
			btrfs_alloc_workqueue("scrubparity", flags,
					      max_active, 2);
		if (!fs_info->scrub_parity_workers)
			goto fail_scrub_parity_workers;
	}
	++fs_info->scrub_workers_refcnt;
	return 0;

fail_scrub_parity_workers:
	btrfs_destroy_workqueue(fs_info->scrub_nocow_workers);
fail_scrub_nocow_workers:
	btrfs_destroy_workqueue(fs_info->scrub_wr_completion_workers);
fail_scrub_wr_completion_workers:
	btrfs_destroy_workqueue(fs_info->scrub_workers);
fail_scrub_workers:
	return -ENOMEM;
}

static noinline_for_stack void scrub_workers_put(struct btrfs_fs_info *fs_info)
{
	if (--fs_info->scrub_workers_refcnt == 0) {
		btrfs_destroy_workqueue(fs_info->scrub_workers);
		btrfs_destroy_workqueue(fs_info->scrub_wr_completion_workers);
		btrfs_destroy_workqueue(fs_info->scrub_nocow_workers);
		btrfs_destroy_workqueue(fs_info->scrub_parity_workers);
	}
	WARN_ON(fs_info->scrub_workers_refcnt < 0);
}

int btrfs_scrub_dev(struct btrfs_fs_info *fs_info, u64 devid, u64 start,
		    u64 end, struct btrfs_scrub_progress *progress,
		    int readonly, int is_dev_replace)
{
	struct scrub_ctx *sctx;
	int ret;
	struct btrfs_device *dev;
	struct rcu_string *name;

	if (btrfs_fs_closing(fs_info))
		return -EINVAL;

	if (fs_info->chunk_root->nodesize > BTRFS_STRIPE_LEN) {
		 
		btrfs_err(fs_info,
			   "scrub: size assumption nodesize <= BTRFS_STRIPE_LEN (%d <= %d) fails",
		       fs_info->chunk_root->nodesize, BTRFS_STRIPE_LEN);
		return -EINVAL;
	}

	if (fs_info->chunk_root->sectorsize != PAGE_SIZE) {
		 
		btrfs_err(fs_info,
			   "scrub: size assumption sectorsize != PAGE_SIZE "
			   "(%d != %lu) fails",
		       fs_info->chunk_root->sectorsize, PAGE_SIZE);
		return -EINVAL;
	}

	if (fs_info->chunk_root->nodesize >
	    PAGE_SIZE * SCRUB_MAX_PAGES_PER_BLOCK ||
	    fs_info->chunk_root->sectorsize >
	    PAGE_SIZE * SCRUB_MAX_PAGES_PER_BLOCK) {
		 
		btrfs_err(fs_info, "scrub: size assumption nodesize and sectorsize "
			   "<= SCRUB_MAX_PAGES_PER_BLOCK (%d <= %d && %d <= %d) fails",
		       fs_info->chunk_root->nodesize,
		       SCRUB_MAX_PAGES_PER_BLOCK,
		       fs_info->chunk_root->sectorsize,
		       SCRUB_MAX_PAGES_PER_BLOCK);
		return -EINVAL;
	}

	mutex_lock(&fs_info->fs_devices->device_list_mutex);
	dev = btrfs_find_device(fs_info, devid, NULL, NULL);
	if (!dev || (dev->missing && !is_dev_replace)) {
		mutex_unlock(&fs_info->fs_devices->device_list_mutex);
		return -ENODEV;
	}

	if (!is_dev_replace && !readonly && !dev->writeable) {
		mutex_unlock(&fs_info->fs_devices->device_list_mutex);
		rcu_read_lock();
		name = rcu_dereference(dev->name);
		btrfs_err(fs_info, "scrub: device %s is not writable",
			  name->str);
		rcu_read_unlock();
		return -EROFS;
	}

	mutex_lock(&fs_info->scrub_lock);
	if (!dev->in_fs_metadata || dev->is_tgtdev_for_dev_replace) {
		mutex_unlock(&fs_info->scrub_lock);
		mutex_unlock(&fs_info->fs_devices->device_list_mutex);
		return -EIO;
	}

	btrfs_dev_replace_lock(&fs_info->dev_replace, 0);
	if (dev->scrub_device ||
	    (!is_dev_replace &&
	     btrfs_dev_replace_is_ongoing(&fs_info->dev_replace))) {
		btrfs_dev_replace_unlock(&fs_info->dev_replace, 0);
		mutex_unlock(&fs_info->scrub_lock);
		mutex_unlock(&fs_info->fs_devices->device_list_mutex);
		return -EINPROGRESS;
	}
	btrfs_dev_replace_unlock(&fs_info->dev_replace, 0);

	ret = scrub_workers_get(fs_info, is_dev_replace);
	if (ret) {
		mutex_unlock(&fs_info->scrub_lock);
		mutex_unlock(&fs_info->fs_devices->device_list_mutex);
		return ret;
	}

	sctx = scrub_setup_ctx(dev, is_dev_replace);
	if (IS_ERR(sctx)) {
		mutex_unlock(&fs_info->scrub_lock);
		mutex_unlock(&fs_info->fs_devices->device_list_mutex);
		scrub_workers_put(fs_info);
		return PTR_ERR(sctx);
	}
	sctx->readonly = readonly;
	dev->scrub_device = sctx;
	mutex_unlock(&fs_info->fs_devices->device_list_mutex);

	__scrub_blocked_if_needed(fs_info);
	atomic_inc(&fs_info->scrubs_running);
	mutex_unlock(&fs_info->scrub_lock);

	if (!is_dev_replace) {
		 
		mutex_lock(&fs_info->fs_devices->device_list_mutex);
		ret = scrub_supers(sctx, dev);
		mutex_unlock(&fs_info->fs_devices->device_list_mutex);
	}

	if (!ret)
		ret = scrub_enumerate_chunks(sctx, dev, start, end,
					     is_dev_replace);

	wait_event(sctx->list_wait, atomic_read(&sctx->bios_in_flight) == 0);
	atomic_dec(&fs_info->scrubs_running);
	wake_up(&fs_info->scrub_pause_wait);

	wait_event(sctx->list_wait, atomic_read(&sctx->workers_pending) == 0);

	if (progress)
		memcpy(progress, &sctx->stat, sizeof(*progress));

	mutex_lock(&fs_info->scrub_lock);
	dev->scrub_device = NULL;
	scrub_workers_put(fs_info);
	mutex_unlock(&fs_info->scrub_lock);

	scrub_put_ctx(sctx);

	return ret;
}

void btrfs_scrub_pause(struct btrfs_root *root)
{
	struct btrfs_fs_info *fs_info = root->fs_info;

	mutex_lock(&fs_info->scrub_lock);
	atomic_inc(&fs_info->scrub_pause_req);
	while (atomic_read(&fs_info->scrubs_paused) !=
	       atomic_read(&fs_info->scrubs_running)) {
		mutex_unlock(&fs_info->scrub_lock);
		wait_event(fs_info->scrub_pause_wait,
			   atomic_read(&fs_info->scrubs_paused) ==
			   atomic_read(&fs_info->scrubs_running));
		mutex_lock(&fs_info->scrub_lock);
	}
	mutex_unlock(&fs_info->scrub_lock);
}

void btrfs_scrub_continue(struct btrfs_root *root)
{
	struct btrfs_fs_info *fs_info = root->fs_info;

	atomic_dec(&fs_info->scrub_pause_req);
	wake_up(&fs_info->scrub_pause_wait);
}

int btrfs_scrub_cancel(struct btrfs_fs_info *fs_info)
{
	mutex_lock(&fs_info->scrub_lock);
	if (!atomic_read(&fs_info->scrubs_running)) {
		mutex_unlock(&fs_info->scrub_lock);
		return -ENOTCONN;
	}

	atomic_inc(&fs_info->scrub_cancel_req);
	while (atomic_read(&fs_info->scrubs_running)) {
		mutex_unlock(&fs_info->scrub_lock);
		wait_event(fs_info->scrub_pause_wait,
			   atomic_read(&fs_info->scrubs_running) == 0);
		mutex_lock(&fs_info->scrub_lock);
	}
	atomic_dec(&fs_info->scrub_cancel_req);
	mutex_unlock(&fs_info->scrub_lock);

	return 0;
}

int btrfs_scrub_cancel_dev(struct btrfs_fs_info *fs_info,
			   struct btrfs_device *dev)
{
	struct scrub_ctx *sctx;

	mutex_lock(&fs_info->scrub_lock);
	sctx = dev->scrub_device;
	if (!sctx) {
		mutex_unlock(&fs_info->scrub_lock);
		return -ENOTCONN;
	}
	atomic_inc(&sctx->cancel_req);
	while (dev->scrub_device) {
		mutex_unlock(&fs_info->scrub_lock);
		wait_event(fs_info->scrub_pause_wait,
			   dev->scrub_device == NULL);
		mutex_lock(&fs_info->scrub_lock);
	}
	mutex_unlock(&fs_info->scrub_lock);

	return 0;
}

int btrfs_scrub_progress(struct btrfs_root *root, u64 devid,
			 struct btrfs_scrub_progress *progress)
{
	struct btrfs_device *dev;
	struct scrub_ctx *sctx = NULL;

	mutex_lock(&root->fs_info->fs_devices->device_list_mutex);
	dev = btrfs_find_device(root->fs_info, devid, NULL, NULL);
	if (dev)
		sctx = dev->scrub_device;
	if (sctx)
		memcpy(progress, &sctx->stat, sizeof(*progress));
	mutex_unlock(&root->fs_info->fs_devices->device_list_mutex);

	return dev ? (sctx ? 0 : -ENOTCONN) : -ENODEV;
}

static void scrub_remap_extent(struct btrfs_fs_info *fs_info,
			       u64 extent_logical, u64 extent_len,
			       u64 *extent_physical,
			       struct btrfs_device **extent_dev,
			       int *extent_mirror_num)
{
	u64 mapped_length;
	struct btrfs_bio *bbio = NULL;
	int ret;

	mapped_length = extent_len;
	ret = btrfs_map_block(fs_info, READ, extent_logical,
			      &mapped_length, &bbio, 0);
	if (ret || !bbio || mapped_length < extent_len ||
	    !bbio->stripes[0].dev->bdev) {
		btrfs_put_bbio(bbio);
		return;
	}

	*extent_physical = bbio->stripes[0].physical;
	*extent_mirror_num = bbio->mirror_num;
	*extent_dev = bbio->stripes[0].dev;
	btrfs_put_bbio(bbio);
}

static int scrub_setup_wr_ctx(struct scrub_ctx *sctx,
			      struct scrub_wr_ctx *wr_ctx,
			      struct btrfs_fs_info *fs_info,
			      struct btrfs_device *dev,
			      int is_dev_replace)
{
	WARN_ON(wr_ctx->wr_curr_bio != NULL);

	mutex_init(&wr_ctx->wr_lock);
	wr_ctx->wr_curr_bio = NULL;
	if (!is_dev_replace)
		return 0;

	WARN_ON(!dev->bdev);
	wr_ctx->pages_per_wr_bio = SCRUB_PAGES_PER_WR_BIO;
	wr_ctx->tgtdev = dev;
	atomic_set(&wr_ctx->flush_all_writes, 0);
	return 0;
}

static void scrub_free_wr_ctx(struct scrub_wr_ctx *wr_ctx)
{
	mutex_lock(&wr_ctx->wr_lock);
	kfree(wr_ctx->wr_curr_bio);
	wr_ctx->wr_curr_bio = NULL;
	mutex_unlock(&wr_ctx->wr_lock);
}

static int copy_nocow_pages(struct scrub_ctx *sctx, u64 logical, u64 len,
			    int mirror_num, u64 physical_for_dev_replace)
{
	struct scrub_copy_nocow_ctx *nocow_ctx;
	struct btrfs_fs_info *fs_info = sctx->dev_root->fs_info;

	nocow_ctx = kzalloc(sizeof(*nocow_ctx), GFP_NOFS);
	if (!nocow_ctx) {
		spin_lock(&sctx->stat_lock);
		sctx->stat.malloc_errors++;
		spin_unlock(&sctx->stat_lock);
		return -ENOMEM;
	}

	scrub_pending_trans_workers_inc(sctx);

	nocow_ctx->sctx = sctx;
	nocow_ctx->logical = logical;
	nocow_ctx->len = len;
	nocow_ctx->mirror_num = mirror_num;
	nocow_ctx->physical_for_dev_replace = physical_for_dev_replace;
	btrfs_init_work(&nocow_ctx->work, btrfs_scrubnc_helper,
			copy_nocow_pages_worker, NULL, NULL);
	INIT_LIST_HEAD(&nocow_ctx->inodes);
	btrfs_queue_work(fs_info->scrub_nocow_workers,
			 &nocow_ctx->work);

	return 0;
}

static int record_inode_for_nocow(u64 inum, u64 offset, u64 root, void *ctx)
{
	struct scrub_copy_nocow_ctx *nocow_ctx = ctx;
	struct scrub_nocow_inode *nocow_inode;

	nocow_inode = kzalloc(sizeof(*nocow_inode), GFP_NOFS);
	if (!nocow_inode)
		return -ENOMEM;
	nocow_inode->inum = inum;
	nocow_inode->offset = offset;
	nocow_inode->root = root;
	list_add_tail(&nocow_inode->list, &nocow_ctx->inodes);
	return 0;
}

#define COPY_COMPLETE 1

static void copy_nocow_pages_worker(struct btrfs_work *work)
{
	struct scrub_copy_nocow_ctx *nocow_ctx =
		container_of(work, struct scrub_copy_nocow_ctx, work);
	struct scrub_ctx *sctx = nocow_ctx->sctx;
	u64 logical = nocow_ctx->logical;
	u64 len = nocow_ctx->len;
	int mirror_num = nocow_ctx->mirror_num;
	u64 physical_for_dev_replace = nocow_ctx->physical_for_dev_replace;
	int ret;
	struct btrfs_trans_handle *trans = NULL;
	struct btrfs_fs_info *fs_info;
	struct btrfs_path *path;
	struct btrfs_root *root;
	int not_written = 0;

	fs_info = sctx->dev_root->fs_info;
	root = fs_info->extent_root;

	path = btrfs_alloc_path();
	if (!path) {
		spin_lock(&sctx->stat_lock);
		sctx->stat.malloc_errors++;
		spin_unlock(&sctx->stat_lock);
		not_written = 1;
		goto out;
	}

	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans)) {
		not_written = 1;
		goto out;
	}

	ret = iterate_inodes_from_logical(logical, fs_info, path,
					  record_inode_for_nocow, nocow_ctx);
	if (ret != 0 && ret != -ENOENT) {
		btrfs_warn(fs_info, "iterate_inodes_from_logical() failed: log %llu, "
			"phys %llu, len %llu, mir %u, ret %d",
			logical, physical_for_dev_replace, len, mirror_num,
			ret);
		not_written = 1;
		goto out;
	}

	btrfs_end_transaction(trans, root);
	trans = NULL;
	while (!list_empty(&nocow_ctx->inodes)) {
		struct scrub_nocow_inode *entry;
		entry = list_first_entry(&nocow_ctx->inodes,
					 struct scrub_nocow_inode,
					 list);
		list_del_init(&entry->list);
		ret = copy_nocow_pages_for_inode(entry->inum, entry->offset,
						 entry->root, nocow_ctx);
		kfree(entry);
		if (ret == COPY_COMPLETE) {
			ret = 0;
			break;
		} else if (ret) {
			break;
		}
	}
out:
	while (!list_empty(&nocow_ctx->inodes)) {
		struct scrub_nocow_inode *entry;
		entry = list_first_entry(&nocow_ctx->inodes,
					 struct scrub_nocow_inode,
					 list);
		list_del_init(&entry->list);
		kfree(entry);
	}
	if (trans && !IS_ERR(trans))
		btrfs_end_transaction(trans, root);
	if (not_written)
		btrfs_dev_replace_stats_inc(&fs_info->dev_replace.
					    num_uncorrectable_read_errors);

	btrfs_free_path(path);
	kfree(nocow_ctx);

	scrub_pending_trans_workers_dec(sctx);
}

static int check_extent_to_block(struct inode *inode, u64 start, u64 len,
				 u64 logical)
{
	struct extent_state *cached_state = NULL;
	struct btrfs_ordered_extent *ordered;
	struct extent_io_tree *io_tree;
	struct extent_map *em;
	u64 lockstart = start, lockend = start + len - 1;
	int ret = 0;

	io_tree = &BTRFS_I(inode)->io_tree;

	lock_extent_bits(io_tree, lockstart, lockend, &cached_state);
	ordered = btrfs_lookup_ordered_range(inode, lockstart, len);
	if (ordered) {
		btrfs_put_ordered_extent(ordered);
		ret = 1;
		goto out_unlock;
	}

	em = btrfs_get_extent(inode, NULL, 0, start, len, 0);
	if (IS_ERR(em)) {
		ret = PTR_ERR(em);
		goto out_unlock;
	}

	if (em->block_start > logical ||
	    em->block_start + em->block_len < logical + len) {
		free_extent_map(em);
		ret = 1;
		goto out_unlock;
	}
	free_extent_map(em);

out_unlock:
	unlock_extent_cached(io_tree, lockstart, lockend, &cached_state,
			     GFP_NOFS);
	return ret;
}

static int copy_nocow_pages_for_inode(u64 inum, u64 offset, u64 root,
				      struct scrub_copy_nocow_ctx *nocow_ctx)
{
	struct btrfs_fs_info *fs_info = nocow_ctx->sctx->dev_root->fs_info;
	struct btrfs_key key;
	struct inode *inode;
	struct page *page;
	struct btrfs_root *local_root;
	struct extent_io_tree *io_tree;
	u64 physical_for_dev_replace;
	u64 nocow_ctx_logical;
	u64 len = nocow_ctx->len;
	unsigned long index;
	int srcu_index;
	int ret = 0;
	int err = 0;

	key.objectid = root;
	key.type = BTRFS_ROOT_ITEM_KEY;
	key.offset = (u64)-1;

	srcu_index = srcu_read_lock(&fs_info->subvol_srcu);

	local_root = btrfs_read_fs_root_no_name(fs_info, &key);
	if (IS_ERR(local_root)) {
		srcu_read_unlock(&fs_info->subvol_srcu, srcu_index);
		return PTR_ERR(local_root);
	}

	key.type = BTRFS_INODE_ITEM_KEY;
	key.objectid = inum;
	key.offset = 0;
	inode = btrfs_iget(fs_info->sb, &key, local_root, NULL);
	srcu_read_unlock(&fs_info->subvol_srcu, srcu_index);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	inode_lock(inode);
	inode_dio_wait(inode);

	physical_for_dev_replace = nocow_ctx->physical_for_dev_replace;
	io_tree = &BTRFS_I(inode)->io_tree;
	nocow_ctx_logical = nocow_ctx->logical;

	ret = check_extent_to_block(inode, offset, len, nocow_ctx_logical);
	if (ret) {
		ret = ret > 0 ? 0 : ret;
		goto out;
	}

	while (len >= PAGE_CACHE_SIZE) {
		index = offset >> PAGE_CACHE_SHIFT;
again:
		page = find_or_create_page(inode->i_mapping, index, GFP_NOFS);
		if (!page) {
			btrfs_err(fs_info, "find_or_create_page() failed");
			ret = -ENOMEM;
			goto out;
		}

		if (PageUptodate(page)) {
			if (PageDirty(page))
				goto next_page;
		} else {
			ClearPageError(page);
			err = extent_read_full_page(io_tree, page,
							   btrfs_get_extent,
							   nocow_ctx->mirror_num);
			if (err) {
				ret = err;
				goto next_page;
			}

			lock_page(page);
			 
			if (page->mapping != inode->i_mapping) {
				unlock_page(page);
				page_cache_release(page);
				goto again;
			}
			if (!PageUptodate(page)) {
				ret = -EIO;
				goto next_page;
			}
		}

		ret = check_extent_to_block(inode, offset, len,
					    nocow_ctx_logical);
		if (ret) {
			ret = ret > 0 ? 0 : ret;
			goto next_page;
		}

		err = write_page_nocow(nocow_ctx->sctx,
				       physical_for_dev_replace, page);
		if (err)
			ret = err;
next_page:
		unlock_page(page);
		page_cache_release(page);

		if (ret)
			break;

		offset += PAGE_CACHE_SIZE;
		physical_for_dev_replace += PAGE_CACHE_SIZE;
		nocow_ctx_logical += PAGE_CACHE_SIZE;
		len -= PAGE_CACHE_SIZE;
	}
	ret = COPY_COMPLETE;
out:
	inode_unlock(inode);
	iput(inode);
	return ret;
}

static int write_page_nocow(struct scrub_ctx *sctx,
			    u64 physical_for_dev_replace, struct page *page)
{
	struct bio *bio;
	struct btrfs_device *dev;
	int ret;

	dev = sctx->wr_ctx.tgtdev;
	if (!dev)
		return -EIO;
	if (!dev->bdev) {
		btrfs_warn_rl(dev->dev_root->fs_info,
			"scrub write_page_nocow(bdev == NULL) is unexpected");
		return -EIO;
	}
	bio = btrfs_io_bio_alloc(GFP_NOFS, 1);
	if (!bio) {
		spin_lock(&sctx->stat_lock);
		sctx->stat.malloc_errors++;
		spin_unlock(&sctx->stat_lock);
		return -ENOMEM;
	}
	bio->bi_iter.bi_size = 0;
	bio->bi_iter.bi_sector = physical_for_dev_replace >> 9;
	bio->bi_bdev = dev->bdev;
	ret = bio_add_page(bio, page, PAGE_CACHE_SIZE, 0);
	if (ret != PAGE_CACHE_SIZE) {
leave_with_eio:
		bio_put(bio);
		btrfs_dev_stat_inc_and_print(dev, BTRFS_DEV_STAT_WRITE_ERRS);
		return -EIO;
	}

	if (btrfsic_submit_bio_wait(WRITE_SYNC, bio))
		goto leave_with_eio;

	bio_put(bio);
	return 0;
}
