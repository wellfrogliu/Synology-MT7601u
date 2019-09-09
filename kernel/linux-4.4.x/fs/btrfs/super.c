#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/blkdev.h>
#include <linux/module.h>
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
#include <linux/mount.h>
#include <linux/mpage.h>
#include <linux/swap.h>
#include <linux/writeback.h>
#include <linux/statfs.h>
#include <linux/compat.h>
#include <linux/parser.h>
#include <linux/ctype.h>
#include <linux/namei.h>
#include <linux/miscdevice.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <linux/cleancache.h>
#include <linux/ratelimit.h>
#include <linux/btrfs.h>
#include "delayed-inode.h"
#include "ctree.h"
#include "disk-io.h"
#include "transaction.h"
#include "btrfs_inode.h"
#include "print-tree.h"
#include "hash.h"
#include "props.h"
#include "xattr.h"
#include "volumes.h"
#include "export.h"
#include "compression.h"
#include "rcu-string.h"
#include "dev-replace.h"
#include "free-space-cache.h"
#include "backref.h"
#include "tests/btrfs-tests.h"

#include "qgroup.h"
#define CREATE_TRACE_POINTS
#include <trace/events/btrfs.h>

#ifdef MY_ABC_HERE
#include <linux/list_lru.h>
#endif  

static const struct super_operations btrfs_super_ops;
static struct file_system_type btrfs_fs_type;

static int btrfs_remount(struct super_block *sb, int *flags, char *data);

const char *btrfs_decode_error(int errno)
{
	char *errstr = "unknown";

	switch (errno) {
	case -EIO:
		errstr = "IO failure";
		break;
	case -ENOMEM:
		errstr = "Out of memory";
		break;
	case -EROFS:
		errstr = "Readonly filesystem";
		break;
	case -EEXIST:
		errstr = "Object already exists";
		break;
	case -ENOSPC:
		errstr = "No space left";
		break;
	case -ENOENT:
		errstr = "No such entry";
		break;
	}

	return errstr;
}

static void btrfs_handle_error(struct btrfs_fs_info *fs_info)
{
	struct super_block *sb = fs_info->sb;

	if (sb->s_flags & MS_RDONLY)
		return;

	if (test_bit(BTRFS_FS_STATE_ERROR, &fs_info->fs_state)) {
		sb->s_flags |= MS_RDONLY;
		btrfs_info(fs_info, "forced readonly");
		 
	}
}

__cold
void __btrfs_handle_fs_error(struct btrfs_fs_info *fs_info, const char *function,
		       unsigned int line, int errno, const char *fmt, ...)
{
	struct super_block *sb = fs_info->sb;
#ifdef CONFIG_PRINTK
	const char *errstr;
#endif

	if (errno == -EROFS && (sb->s_flags & MS_RDONLY))
  		return;

#ifdef CONFIG_PRINTK
	errstr = btrfs_decode_error(errno);
	if (fmt) {
		struct va_format vaf;
		va_list args;

		va_start(args, fmt);
		vaf.fmt = fmt;
		vaf.va = &args;

		printk(KERN_CRIT
			"BTRFS: error (device %s) in %s:%d: errno=%d %s (%pV)\n",
			sb->s_id, function, line, errno, errstr, &vaf);
		va_end(args);
	} else {
		printk(KERN_CRIT "BTRFS: error (device %s) in %s:%d: errno=%d %s\n",
			sb->s_id, function, line, errno, errstr);
	}
#endif

	set_bit(BTRFS_FS_STATE_ERROR, &fs_info->fs_state);

	if (sb->s_flags & MS_BORN)
		btrfs_handle_error(fs_info);
}

#ifdef CONFIG_PRINTK
static const char * const logtypes[] = {
	"emergency",
	"alert",
	"critical",
	"error",
	"warning",
	"notice",
	"info",
	"debug",
};

void btrfs_printk(const struct btrfs_fs_info *fs_info, const char *fmt, ...)
{
	struct super_block *sb = fs_info->sb;
	char lvl[4];
	struct va_format vaf;
	va_list args;
	const char *type = logtypes[4];
	int kern_level;

	va_start(args, fmt);

	kern_level = printk_get_level(fmt);
	if (kern_level) {
		size_t size = printk_skip_level(fmt) - fmt;
		memcpy(lvl, fmt,  size);
		lvl[size] = '\0';
		fmt += size;
		type = logtypes[kern_level - '0'];
	} else
		*lvl = '\0';

	vaf.fmt = fmt;
	vaf.va = &args;

	printk("%sBTRFS %s (device %s): %pV\n", lvl, type, sb->s_id, &vaf);

	va_end(args);
}
#endif

__cold
void __btrfs_abort_transaction(struct btrfs_trans_handle *trans,
			       struct btrfs_root *root, const char *function,
			       unsigned int line, int errno)
{
	trans->aborted = errno;
	 
	if (!trans->dirty && list_empty(&trans->new_bgs)) {
		const char *errstr;

		errstr = btrfs_decode_error(errno);
		btrfs_warn(root->fs_info,
		           "%s:%d: Aborting unused transaction(%s).",
		           function, line, errstr);
		return;
	}
	ACCESS_ONCE(trans->transaction->aborted) = errno;
	 
	wake_up(&root->fs_info->transaction_wait);
	wake_up(&root->fs_info->transaction_blocked_wait);
	__btrfs_handle_fs_error(root->fs_info, function, line, errno, NULL);
}
 
__cold
void __btrfs_panic(struct btrfs_fs_info *fs_info, const char *function,
		   unsigned int line, int errno, const char *fmt, ...)
{
	char *s_id = "<unknown>";
	const char *errstr;
	struct va_format vaf = { .fmt = fmt };
	va_list args;

	if (fs_info)
		s_id = fs_info->sb->s_id;

	va_start(args, fmt);
	vaf.va = &args;

	errstr = btrfs_decode_error(errno);
	if (fs_info && (fs_info->mount_opt & BTRFS_MOUNT_PANIC_ON_FATAL_ERROR))
		panic(KERN_CRIT "BTRFS panic (device %s) in %s:%d: %pV (errno=%d %s)\n",
			s_id, function, line, &vaf, errno, errstr);

	btrfs_crit(fs_info, "panic in %s:%d: %pV (errno=%d %s)",
		   function, line, &vaf, errno, errstr);
	va_end(args);
	 
}

static void btrfs_put_super(struct super_block *sb)
{
	close_ctree(btrfs_sb(sb)->tree_root);
}

enum {
	Opt_degraded, Opt_subvol, Opt_subvolid, Opt_device, Opt_nodatasum,
	Opt_nodatacow, Opt_max_inline, Opt_alloc_start, Opt_nobarrier, Opt_ssd,
	Opt_nossd, Opt_ssd_spread, Opt_thread_pool, Opt_noacl, Opt_compress,
	Opt_compress_type, Opt_compress_force, Opt_compress_force_type,
	Opt_notreelog, Opt_ratio, Opt_flushoncommit, Opt_discard,
	Opt_space_cache, Opt_space_cache_version, Opt_clear_cache,
	Opt_user_subvol_rm_allowed, Opt_enospc_debug, Opt_subvolrootid,
	Opt_defrag, Opt_inode_cache, Opt_no_space_cache, Opt_recovery,
	Opt_skip_balance, Opt_check_integrity,
	Opt_check_integrity_including_extent_data,
	Opt_check_integrity_print_mask, Opt_fatal_errors, Opt_rescan_uuid_tree,
	Opt_commit_interval, Opt_barrier, Opt_nodefrag, Opt_nodiscard,
	Opt_noenospc_debug, Opt_noflushoncommit, Opt_acl, Opt_datacow,
	Opt_datasum, Opt_treelog, Opt_noinode_cache,
#ifdef MY_ABC_HERE
	Opt_flushoncommit_threshold,
#endif  
#ifdef CONFIG_BTRFS_DEBUG
	Opt_fragment_data, Opt_fragment_metadata, Opt_fragment_all,
#endif
#ifdef MY_ABC_HERE
	Opt_no_block_group_hint,
#endif  
	Opt_err,
};

static const match_table_t tokens = {
	{Opt_degraded, "degraded"},
	{Opt_subvol, "subvol=%s"},
	{Opt_subvolid, "subvolid=%s"},
	{Opt_device, "device=%s"},
	{Opt_nodatasum, "nodatasum"},
	{Opt_datasum, "datasum"},
	{Opt_nodatacow, "nodatacow"},
	{Opt_datacow, "datacow"},
	{Opt_nobarrier, "nobarrier"},
	{Opt_barrier, "barrier"},
	{Opt_max_inline, "max_inline=%s"},
	{Opt_alloc_start, "alloc_start=%s"},
	{Opt_thread_pool, "thread_pool=%d"},
	{Opt_compress, "compress"},
	{Opt_compress_type, "compress=%s"},
	{Opt_compress_force, "compress-force"},
	{Opt_compress_force_type, "compress-force=%s"},
	{Opt_ssd, "ssd"},
	{Opt_ssd_spread, "ssd_spread"},
	{Opt_nossd, "nossd"},
	{Opt_acl, "acl"},
	{Opt_noacl, "noacl"},
	{Opt_notreelog, "notreelog"},
	{Opt_treelog, "treelog"},
	{Opt_flushoncommit, "flushoncommit"},
	{Opt_noflushoncommit, "noflushoncommit"},
#ifdef MY_ABC_HERE
	{Opt_flushoncommit_threshold, "flushoncommit_threshold=%d"},
#endif  
	{Opt_ratio, "metadata_ratio=%d"},
	{Opt_discard, "discard"},
	{Opt_nodiscard, "nodiscard"},
	{Opt_space_cache, "space_cache"},
	{Opt_space_cache_version, "space_cache=%s"},
	{Opt_clear_cache, "clear_cache"},
	{Opt_user_subvol_rm_allowed, "user_subvol_rm_allowed"},
	{Opt_enospc_debug, "enospc_debug"},
	{Opt_noenospc_debug, "noenospc_debug"},
	{Opt_subvolrootid, "subvolrootid=%d"},
	{Opt_defrag, "autodefrag"},
	{Opt_nodefrag, "noautodefrag"},
	{Opt_inode_cache, "inode_cache"},
	{Opt_noinode_cache, "noinode_cache"},
	{Opt_no_space_cache, "nospace_cache"},
	{Opt_recovery, "recovery"},
	{Opt_skip_balance, "skip_balance"},
	{Opt_check_integrity, "check_int"},
	{Opt_check_integrity_including_extent_data, "check_int_data"},
	{Opt_check_integrity_print_mask, "check_int_print_mask=%d"},
	{Opt_rescan_uuid_tree, "rescan_uuid_tree"},
	{Opt_fatal_errors, "fatal_errors=%s"},
	{Opt_commit_interval, "commit=%d"},
#ifdef CONFIG_BTRFS_DEBUG
	{Opt_fragment_data, "fragment=data"},
	{Opt_fragment_metadata, "fragment=metadata"},
	{Opt_fragment_all, "fragment=all"},
#endif
#ifdef MY_ABC_HERE
	{Opt_no_block_group_hint, "no_block_group_hint"},
#endif  
	{Opt_err, NULL},
};

int btrfs_parse_options(struct btrfs_root *root, char *options)
{
	struct btrfs_fs_info *info = root->fs_info;
	substring_t args[MAX_OPT_ARGS];
	char *p, *num, *orig = NULL;
#ifdef MY_ABC_HERE
#else
	u64 cache_gen;
#endif  
	int intarg;
	int ret = 0;
	char *compress_type;
	bool compress_force = false;
	enum btrfs_compression_type saved_compress_type;
	bool saved_compress_force;
	int no_compress = 0;

#ifdef MY_ABC_HERE
#else
	cache_gen = btrfs_super_cache_generation(root->fs_info->super_copy);
#endif  
	if (btrfs_fs_compat_ro(root->fs_info, FREE_SPACE_TREE))
		btrfs_set_opt(info->mount_opt, FREE_SPACE_TREE);
#ifdef MY_ABC_HERE
	else if (btrfs_fs_compat_ro(root->fs_info, FREE_SPACE_TREE_VALID))
		btrfs_set_opt(info->mount_opt, FREE_SPACE_TREE);
#else
	else if (cache_gen)
		btrfs_set_opt(info->mount_opt, SPACE_CACHE);
#endif  

	if (!options)
		goto out;

	options = kstrdup(options, GFP_NOFS);
	if (!options)
		return -ENOMEM;

	orig = options;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_degraded:
			btrfs_info(root->fs_info, "allowing degraded mounts");
			btrfs_set_opt(info->mount_opt, DEGRADED);
			break;
		case Opt_subvol:
		case Opt_subvolid:
		case Opt_subvolrootid:
		case Opt_device:
			 
			break;
		case Opt_nodatasum:
			btrfs_set_and_info(root, NODATASUM,
					   "setting nodatasum");
			break;
		case Opt_datasum:
			if (btrfs_test_opt(root, NODATASUM)) {
				if (btrfs_test_opt(root, NODATACOW))
					btrfs_info(root->fs_info, "setting datasum, datacow enabled");
				else
					btrfs_info(root->fs_info, "setting datasum");
			}
			btrfs_clear_opt(info->mount_opt, NODATACOW);
			btrfs_clear_opt(info->mount_opt, NODATASUM);
			break;
		case Opt_nodatacow:
			if (!btrfs_test_opt(root, NODATACOW)) {
				if (!btrfs_test_opt(root, COMPRESS) ||
				    !btrfs_test_opt(root, FORCE_COMPRESS)) {
					btrfs_info(root->fs_info,
						   "setting nodatacow, compression disabled");
				} else {
					btrfs_info(root->fs_info, "setting nodatacow");
				}
			}
			btrfs_clear_opt(info->mount_opt, COMPRESS);
			btrfs_clear_opt(info->mount_opt, FORCE_COMPRESS);
			btrfs_set_opt(info->mount_opt, NODATACOW);
			btrfs_set_opt(info->mount_opt, NODATASUM);
			break;
		case Opt_datacow:
			btrfs_clear_and_info(root, NODATACOW,
					     "setting datacow");
			break;
		case Opt_compress_force:
		case Opt_compress_force_type:
			compress_force = true;
			 
		case Opt_compress:
		case Opt_compress_type:
			saved_compress_type = btrfs_test_opt(root, COMPRESS) ?
				info->compress_type : BTRFS_COMPRESS_NONE;
			saved_compress_force =
				btrfs_test_opt(root, FORCE_COMPRESS);
			if (token == Opt_compress ||
			    token == Opt_compress_force ||
			    strcmp(args[0].from, "zlib") == 0) {
				compress_type = "zlib";
				info->compress_type = BTRFS_COMPRESS_ZLIB;
				btrfs_set_opt(info->mount_opt, COMPRESS);
				btrfs_clear_opt(info->mount_opt, NODATACOW);
				btrfs_clear_opt(info->mount_opt, NODATASUM);
				no_compress = 0;
			} else if (strcmp(args[0].from, "lzo") == 0) {
				compress_type = "lzo";
				info->compress_type = BTRFS_COMPRESS_LZO;
				btrfs_set_opt(info->mount_opt, COMPRESS);
				btrfs_clear_opt(info->mount_opt, NODATACOW);
				btrfs_clear_opt(info->mount_opt, NODATASUM);
				btrfs_set_fs_incompat(info, COMPRESS_LZO);
				no_compress = 0;
			} else if (strncmp(args[0].from, "no", 2) == 0) {
				compress_type = "no";
				btrfs_clear_opt(info->mount_opt, COMPRESS);
				btrfs_clear_opt(info->mount_opt, FORCE_COMPRESS);
				compress_force = false;
				no_compress++;
			} else {
				ret = -EINVAL;
				goto out;
			}

			if (compress_force) {
				btrfs_set_opt(info->mount_opt, FORCE_COMPRESS);
			} else {
				 
				btrfs_clear_opt(info->mount_opt, FORCE_COMPRESS);
			}
			if ((btrfs_test_opt(root, COMPRESS) &&
			     (info->compress_type != saved_compress_type ||
			      compress_force != saved_compress_force)) ||
			    (!btrfs_test_opt(root, COMPRESS) &&
			     no_compress == 1)) {
				btrfs_info(root->fs_info,
					   "%s %s compression",
					   (compress_force) ? "force" : "use",
					   compress_type);
			}
			compress_force = false;
			break;
		case Opt_ssd:
			btrfs_set_and_info(root, SSD,
					   "use ssd allocation scheme");
			break;
		case Opt_ssd_spread:
			btrfs_set_and_info(root, SSD_SPREAD,
					   "use spread ssd allocation scheme");
			btrfs_set_opt(info->mount_opt, SSD);
			break;
		case Opt_nossd:
			btrfs_set_and_info(root, NOSSD,
					     "not using ssd allocation scheme");
			btrfs_clear_opt(info->mount_opt, SSD);
			break;
		case Opt_barrier:
			btrfs_clear_and_info(root, NOBARRIER,
					     "turning on barriers");
			break;
		case Opt_nobarrier:
			btrfs_set_and_info(root, NOBARRIER,
					   "turning off barriers");
			break;
		case Opt_thread_pool:
			ret = match_int(&args[0], &intarg);
			if (ret) {
				goto out;
			} else if (intarg > 0) {
				info->thread_pool_size = intarg;
			} else {
				ret = -EINVAL;
				goto out;
			}
			break;
		case Opt_max_inline:
			num = match_strdup(&args[0]);
			if (num) {
				info->max_inline = memparse(num, NULL);
				kfree(num);

				if (info->max_inline) {
					info->max_inline = min_t(u64,
						info->max_inline,
						root->sectorsize);
				}
				btrfs_info(root->fs_info, "max_inline at %llu",
					info->max_inline);
			} else {
				ret = -ENOMEM;
				goto out;
			}
			break;
		case Opt_alloc_start:
			num = match_strdup(&args[0]);
			if (num) {
				mutex_lock(&info->chunk_mutex);
				info->alloc_start = memparse(num, NULL);
				mutex_unlock(&info->chunk_mutex);
				kfree(num);
				btrfs_info(root->fs_info, "allocations start at %llu",
					info->alloc_start);
			} else {
				ret = -ENOMEM;
				goto out;
			}
			break;
		case Opt_acl:
#ifdef CONFIG_BTRFS_FS_POSIX_ACL
			root->fs_info->sb->s_flags |= MS_POSIXACL;
			break;
#else
			btrfs_err(root->fs_info,
				"support for ACL not compiled in!");
			ret = -EINVAL;
			goto out;
#endif
		case Opt_noacl:
			root->fs_info->sb->s_flags &= ~MS_POSIXACL;
			break;
		case Opt_notreelog:
			btrfs_set_and_info(root, NOTREELOG,
					   "disabling tree log");
			break;
		case Opt_treelog:
			btrfs_clear_and_info(root, NOTREELOG,
					     "enabling tree log");
			break;
#ifdef MY_ABC_HERE
		case Opt_flushoncommit_threshold:
			ret = match_int(&args[0], &intarg);
			if (ret) {
				goto out;
			} else if (intarg >= 0) {
				info->flushoncommit_threshold = intarg;
			} else {
				ret = -EINVAL;
				goto out;
			}
			break;
#endif  
		case Opt_flushoncommit:
			btrfs_set_and_info(root, FLUSHONCOMMIT,
					   "turning on flush-on-commit");
			break;
		case Opt_noflushoncommit:
			btrfs_clear_and_info(root, FLUSHONCOMMIT,
					     "turning off flush-on-commit");
			break;
		case Opt_ratio:
			ret = match_int(&args[0], &intarg);
			if (ret) {
				goto out;
			} else if (intarg >= 0) {
				info->metadata_ratio = intarg;
				btrfs_info(root->fs_info, "metadata ratio %d",
				       info->metadata_ratio);
			} else {
				ret = -EINVAL;
				goto out;
			}
			break;
		case Opt_discard:
			btrfs_set_and_info(root, DISCARD,
					   "turning on discard");
			break;
		case Opt_nodiscard:
			btrfs_clear_and_info(root, DISCARD,
					     "turning off discard");
			break;
		case Opt_space_cache:
		case Opt_space_cache_version:
			if (token == Opt_space_cache ||
			    strcmp(args[0].from, "v1") == 0) {
				btrfs_clear_opt(root->fs_info->mount_opt,
						FREE_SPACE_TREE);
				btrfs_set_and_info(root, SPACE_CACHE,
						   "enabling disk space caching");
			} else if (strcmp(args[0].from, "v2") == 0) {
				btrfs_clear_opt(root->fs_info->mount_opt,
						SPACE_CACHE);
				btrfs_set_and_info(root, FREE_SPACE_TREE,
						   "enabling free space tree");
			} else {
				ret = -EINVAL;
				goto out;
			}
			break;
		case Opt_rescan_uuid_tree:
			btrfs_set_opt(info->mount_opt, RESCAN_UUID_TREE);
			break;
		case Opt_no_space_cache:
			if (btrfs_test_opt(root, SPACE_CACHE)) {
				btrfs_clear_and_info(root, SPACE_CACHE,
						     "disabling disk space caching");
			}
			if (btrfs_test_opt(root, FREE_SPACE_TREE)) {
				btrfs_clear_and_info(root, FREE_SPACE_TREE,
						     "disabling free space tree");
			}
			break;
		case Opt_inode_cache:
			btrfs_set_pending_and_info(info, INODE_MAP_CACHE,
					   "enabling inode map caching");
			break;
		case Opt_noinode_cache:
			btrfs_clear_pending_and_info(info, INODE_MAP_CACHE,
					     "disabling inode map caching");
			break;
		case Opt_clear_cache:
			btrfs_set_and_info(root, CLEAR_CACHE,
					   "force clearing of disk cache");
			break;
		case Opt_user_subvol_rm_allowed:
			btrfs_set_opt(info->mount_opt, USER_SUBVOL_RM_ALLOWED);
			break;
		case Opt_enospc_debug:
			btrfs_set_opt(info->mount_opt, ENOSPC_DEBUG);
			break;
		case Opt_noenospc_debug:
			btrfs_clear_opt(info->mount_opt, ENOSPC_DEBUG);
			break;
		case Opt_defrag:
			btrfs_set_and_info(root, AUTO_DEFRAG,
					   "enabling auto defrag");
			break;
		case Opt_nodefrag:
			btrfs_clear_and_info(root, AUTO_DEFRAG,
					     "disabling auto defrag");
			break;
		case Opt_recovery:
			btrfs_info(root->fs_info, "enabling auto recovery");
			btrfs_set_opt(info->mount_opt, RECOVERY);
			break;
		case Opt_skip_balance:
			btrfs_set_opt(info->mount_opt, SKIP_BALANCE);
			break;
#ifdef CONFIG_BTRFS_FS_CHECK_INTEGRITY
		case Opt_check_integrity_including_extent_data:
			btrfs_info(root->fs_info,
				   "enabling check integrity including extent data");
			btrfs_set_opt(info->mount_opt,
				      CHECK_INTEGRITY_INCLUDING_EXTENT_DATA);
			btrfs_set_opt(info->mount_opt, CHECK_INTEGRITY);
			break;
		case Opt_check_integrity:
			btrfs_info(root->fs_info, "enabling check integrity");
			btrfs_set_opt(info->mount_opt, CHECK_INTEGRITY);
			break;
		case Opt_check_integrity_print_mask:
			ret = match_int(&args[0], &intarg);
			if (ret) {
				goto out;
			} else if (intarg >= 0) {
				info->check_integrity_print_mask = intarg;
				btrfs_info(root->fs_info, "check_integrity_print_mask 0x%x",
				       info->check_integrity_print_mask);
			} else {
				ret = -EINVAL;
				goto out;
			}
			break;
#else
		case Opt_check_integrity_including_extent_data:
		case Opt_check_integrity:
		case Opt_check_integrity_print_mask:
			btrfs_err(root->fs_info,
				"support for check_integrity* not compiled in!");
			ret = -EINVAL;
			goto out;
#endif
		case Opt_fatal_errors:
			if (strcmp(args[0].from, "panic") == 0)
				btrfs_set_opt(info->mount_opt,
					      PANIC_ON_FATAL_ERROR);
			else if (strcmp(args[0].from, "bug") == 0)
				btrfs_clear_opt(info->mount_opt,
					      PANIC_ON_FATAL_ERROR);
			else {
				ret = -EINVAL;
				goto out;
			}
			break;
		case Opt_commit_interval:
			intarg = 0;
			ret = match_int(&args[0], &intarg);
			if (ret < 0) {
				btrfs_err(root->fs_info, "invalid commit interval");
				ret = -EINVAL;
				goto out;
			}
			if (intarg > 0) {
				if (intarg > 300) {
					btrfs_warn(root->fs_info, "excessive commit interval %d",
							intarg);
				}
				info->commit_interval = intarg;
			} else {
				btrfs_info(root->fs_info, "using default commit interval %ds",
				    BTRFS_DEFAULT_COMMIT_INTERVAL);
				info->commit_interval = BTRFS_DEFAULT_COMMIT_INTERVAL;
			}
			break;
#ifdef CONFIG_BTRFS_DEBUG
		case Opt_fragment_all:
			btrfs_info(root->fs_info, "fragmenting all space");
			btrfs_set_opt(info->mount_opt, FRAGMENT_DATA);
			btrfs_set_opt(info->mount_opt, FRAGMENT_METADATA);
			break;
		case Opt_fragment_metadata:
			btrfs_info(root->fs_info, "fragmenting metadata");
			btrfs_set_opt(info->mount_opt,
				      FRAGMENT_METADATA);
			break;
		case Opt_fragment_data:
			btrfs_info(root->fs_info, "fragmenting data");
			btrfs_set_opt(info->mount_opt, FRAGMENT_DATA);
			break;
#endif
#ifdef MY_ABC_HERE
		case Opt_no_block_group_hint:
			info->no_block_group_hint = 1;
			break;
#endif  
		case Opt_err:
			btrfs_info(root->fs_info, "unrecognized mount option '%s'", p);
			ret = -EINVAL;
			goto out;
		default:
			break;
		}
	}
out:
	if (btrfs_fs_compat_ro(root->fs_info, FREE_SPACE_TREE) &&
	    !btrfs_test_opt(root, FREE_SPACE_TREE) &&
	    !btrfs_test_opt(root, CLEAR_CACHE)) {
		btrfs_err(root->fs_info, "cannot disable free space tree");
		ret = -EINVAL;

	}
	if (!ret && btrfs_test_opt(root, SPACE_CACHE))
		btrfs_info(root->fs_info, "disk space caching is enabled");
	if (!ret && btrfs_test_opt(root, FREE_SPACE_TREE))
		btrfs_info(root->fs_info, "using free space tree");
	kfree(orig);
	return ret;
}

static int btrfs_parse_early_options(const char *options, fmode_t flags,
		void *holder, char **subvol_name, u64 *subvol_objectid,
		struct btrfs_fs_devices **fs_devices)
{
	substring_t args[MAX_OPT_ARGS];
	char *device_name, *opts, *orig, *p;
	char *num = NULL;
	int error = 0;

	if (!options)
		return 0;

	opts = kstrdup(options, GFP_KERNEL);
	if (!opts)
		return -ENOMEM;
	orig = opts;

	while ((p = strsep(&opts, ",")) != NULL) {
		int token;
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_subvol:
			kfree(*subvol_name);
			*subvol_name = match_strdup(&args[0]);
			if (!*subvol_name) {
				error = -ENOMEM;
				goto out;
			}
			break;
		case Opt_subvolid:
			num = match_strdup(&args[0]);
			if (num) {
				*subvol_objectid = memparse(num, NULL);
				kfree(num);
				 
				if (!*subvol_objectid)
					*subvol_objectid =
						BTRFS_FS_TREE_OBJECTID;
			} else {
				error = -EINVAL;
				goto out;
			}
			break;
		case Opt_subvolrootid:
			printk(KERN_WARNING
				"BTRFS: 'subvolrootid' mount option is deprecated and has "
				"no effect\n");
			break;
		case Opt_device:
			device_name = match_strdup(&args[0]);
			if (!device_name) {
				error = -ENOMEM;
				goto out;
			}
			error = btrfs_scan_one_device(device_name,
					flags, holder, fs_devices);
			kfree(device_name);
			if (error)
				goto out;
			break;
		default:
			break;
		}
	}

out:
	kfree(orig);
	return error;
}

static char *get_subvol_name_from_objectid(struct btrfs_fs_info *fs_info,
					   u64 subvol_objectid)
{
	struct btrfs_root *root = fs_info->tree_root;
	struct btrfs_root *fs_root;
	struct btrfs_root_ref *root_ref;
	struct btrfs_inode_ref *inode_ref;
	struct btrfs_key key;
	struct btrfs_path *path = NULL;
	char *name = NULL, *ptr;
	u64 dirid;
	int len;
	int ret;

	path = btrfs_alloc_path();
	if (!path) {
		ret = -ENOMEM;
		goto err;
	}
	path->leave_spinning = 1;

	name = kmalloc(PATH_MAX, GFP_NOFS);
	if (!name) {
		ret = -ENOMEM;
		goto err;
	}
	ptr = name + PATH_MAX - 1;
	ptr[0] = '\0';

	while (subvol_objectid != BTRFS_FS_TREE_OBJECTID) {
		key.objectid = subvol_objectid;
		key.type = BTRFS_ROOT_BACKREF_KEY;
		key.offset = (u64)-1;

		ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
		if (ret < 0) {
			goto err;
		} else if (ret > 0) {
			ret = btrfs_previous_item(root, path, subvol_objectid,
						  BTRFS_ROOT_BACKREF_KEY);
			if (ret < 0) {
				goto err;
			} else if (ret > 0) {
				ret = -ENOENT;
				goto err;
			}
		}

		btrfs_item_key_to_cpu(path->nodes[0], &key, path->slots[0]);
		subvol_objectid = key.offset;

		root_ref = btrfs_item_ptr(path->nodes[0], path->slots[0],
					  struct btrfs_root_ref);
		len = btrfs_root_ref_name_len(path->nodes[0], root_ref);
		ptr -= len + 1;
		if (ptr < name) {
			ret = -ENAMETOOLONG;
			goto err;
		}
		read_extent_buffer(path->nodes[0], ptr + 1,
				   (unsigned long)(root_ref + 1), len);
		ptr[0] = '/';
		dirid = btrfs_root_ref_dirid(path->nodes[0], root_ref);
		btrfs_release_path(path);

		key.objectid = subvol_objectid;
		key.type = BTRFS_ROOT_ITEM_KEY;
		key.offset = (u64)-1;
		fs_root = btrfs_read_fs_root_no_name(fs_info, &key);
		if (IS_ERR(fs_root)) {
			ret = PTR_ERR(fs_root);
			goto err;
		}

		while (dirid != BTRFS_FIRST_FREE_OBJECTID) {
			key.objectid = dirid;
			key.type = BTRFS_INODE_REF_KEY;
			key.offset = (u64)-1;

			ret = btrfs_search_slot(NULL, fs_root, &key, path, 0, 0);
			if (ret < 0) {
				goto err;
			} else if (ret > 0) {
				ret = btrfs_previous_item(fs_root, path, dirid,
							  BTRFS_INODE_REF_KEY);
				if (ret < 0) {
					goto err;
				} else if (ret > 0) {
					ret = -ENOENT;
					goto err;
				}
			}

			btrfs_item_key_to_cpu(path->nodes[0], &key, path->slots[0]);
			dirid = key.offset;

			inode_ref = btrfs_item_ptr(path->nodes[0],
						   path->slots[0],
						   struct btrfs_inode_ref);
			len = btrfs_inode_ref_name_len(path->nodes[0],
						       inode_ref);
			ptr -= len + 1;
			if (ptr < name) {
				ret = -ENAMETOOLONG;
				goto err;
			}
			read_extent_buffer(path->nodes[0], ptr + 1,
					   (unsigned long)(inode_ref + 1), len);
			ptr[0] = '/';
			btrfs_release_path(path);
		}
	}

	btrfs_free_path(path);
	if (ptr == name + PATH_MAX - 1) {
		name[0] = '/';
		name[1] = '\0';
	} else {
		memmove(name, ptr, name + PATH_MAX - ptr);
	}
	return name;

err:
	btrfs_free_path(path);
	kfree(name);
	return ERR_PTR(ret);
}

static int get_default_subvol_objectid(struct btrfs_fs_info *fs_info, u64 *objectid)
{
	struct btrfs_root *root = fs_info->tree_root;
	struct btrfs_dir_item *di;
	struct btrfs_path *path;
	struct btrfs_key location;
	u64 dir_id;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;
	path->leave_spinning = 1;

	dir_id = btrfs_super_root_dir(fs_info->super_copy);
	di = btrfs_lookup_dir_item(NULL, root, path, dir_id, "default", 7, 0);
	if (IS_ERR(di)) {
		btrfs_free_path(path);
		return PTR_ERR(di);
	}
	if (!di) {
		 
		btrfs_free_path(path);
		*objectid = BTRFS_FS_TREE_OBJECTID;
		return 0;
	}

	btrfs_dir_item_key_to_cpu(path->nodes[0], di, &location);
	btrfs_free_path(path);
	*objectid = location.objectid;
	return 0;
}

#ifdef MY_ABC_HERE
static void syno_load_sb_archive_ver(struct super_block *sb, struct inode *inode)
{
	struct syno_xattr_archive_version value;
	int err;

	err = __btrfs_getxattr(inode, XATTR_SYNO_PREFIX XATTR_SYNO_ARCHIVE_VERSION_VOLUME,
						   &value, sizeof(value));
	if (0 < err)
		sb->s_archive_version = le32_to_cpu(value.v_archive_version);
	else
		sb->s_archive_version = 0;
}
#endif  

static int btrfs_fill_super(struct super_block *sb,
			    struct btrfs_fs_devices *fs_devices,
			    void *data, int silent)
{
	struct inode *inode;
	struct btrfs_fs_info *fs_info = btrfs_sb(sb);
	struct btrfs_key key;
	int err;

	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_magic = BTRFS_SUPER_MAGIC;
	sb->s_op = &btrfs_super_ops;
	sb->s_d_op = &btrfs_dentry_operations;
	sb->s_export_op = &btrfs_export_ops;
	sb->s_xattr = btrfs_xattr_handlers;
	sb->s_time_gran = 1;
#ifdef CONFIG_BTRFS_FS_POSIX_ACL
	sb->s_flags |= MS_POSIXACL;
#endif
	sb->s_flags |= MS_I_VERSION;
	sb->s_iflags |= SB_I_CGROUPWB;
	err = open_ctree(sb, fs_devices, (char *)data);
	if (err) {
		printk(KERN_ERR "BTRFS: open_ctree failed\n");
		return err;
	}

	key.objectid = BTRFS_FIRST_FREE_OBJECTID;
	key.type = BTRFS_INODE_ITEM_KEY;
	key.offset = 0;
	inode = btrfs_iget(sb, &key, fs_info->fs_root, NULL);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto fail_close;
	}

	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto fail_close;
	}

#ifdef MY_ABC_HERE
	syno_load_sb_archive_ver(sb, inode);
#endif  

	save_mount_options(sb, data);
	cleancache_init_fs(sb);
	sb->s_flags |= MS_ACTIVE;
	return 0;

fail_close:
	close_ctree(fs_info->tree_root);
	return err;
}

int btrfs_sync_fs(struct super_block *sb, int wait)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_fs_info *fs_info = btrfs_sb(sb);
	struct btrfs_root *root = fs_info->tree_root;

	trace_btrfs_sync_fs(wait);

	if (!wait) {
		filemap_flush(fs_info->btree_inode->i_mapping);
		return 0;
	}

	btrfs_wait_ordered_roots(fs_info, -1, 0, (u64)-1);

	trans = btrfs_attach_transaction_barrier(root);
	if (IS_ERR(trans)) {
		 
		if (PTR_ERR(trans) == -ENOENT) {
			 
			if (fs_info->pending_changes == 0)
				return 0;
			 
			if (__sb_start_write(sb, SB_FREEZE_WRITE, false))
				__sb_end_write(sb, SB_FREEZE_WRITE);
			else
				return 0;
			trans = btrfs_start_transaction(root, 0);
		}
		if (IS_ERR(trans))
			return PTR_ERR(trans);
	}
	return btrfs_commit_transaction(trans, root);
}

static int btrfs_show_options(struct seq_file *seq, struct dentry *dentry)
{
	struct btrfs_fs_info *info = btrfs_sb(dentry->d_sb);
	struct btrfs_root *root = info->tree_root;
	char *compress_type;

	if (btrfs_test_opt(root, DEGRADED))
		seq_puts(seq, ",degraded");
	if (btrfs_test_opt(root, NODATASUM))
		seq_puts(seq, ",nodatasum");
	if (btrfs_test_opt(root, NODATACOW))
		seq_puts(seq, ",nodatacow");
	if (btrfs_test_opt(root, NOBARRIER))
		seq_puts(seq, ",nobarrier");
	if (info->max_inline != BTRFS_DEFAULT_MAX_INLINE)
		seq_printf(seq, ",max_inline=%llu", info->max_inline);
	if (info->alloc_start != 0)
		seq_printf(seq, ",alloc_start=%llu", info->alloc_start);
	if (info->thread_pool_size !=  min_t(unsigned long,
					     num_online_cpus() + 2, 8))
		seq_printf(seq, ",thread_pool=%d", info->thread_pool_size);
	if (btrfs_test_opt(root, COMPRESS)) {
		if (info->compress_type == BTRFS_COMPRESS_ZLIB)
			compress_type = "zlib";
		else
			compress_type = "lzo";
		if (btrfs_test_opt(root, FORCE_COMPRESS))
			seq_printf(seq, ",compress-force=%s", compress_type);
		else
			seq_printf(seq, ",compress=%s", compress_type);
	}
	if (btrfs_test_opt(root, NOSSD))
		seq_puts(seq, ",nossd");
	if (btrfs_test_opt(root, SSD_SPREAD))
		seq_puts(seq, ",ssd_spread");
	else if (btrfs_test_opt(root, SSD))
		seq_puts(seq, ",ssd");
	if (btrfs_test_opt(root, NOTREELOG))
		seq_puts(seq, ",notreelog");
	if (btrfs_test_opt(root, FLUSHONCOMMIT))
		seq_puts(seq, ",flushoncommit");
	if (btrfs_test_opt(root, DISCARD))
		seq_puts(seq, ",discard");
	if (!(root->fs_info->sb->s_flags & MS_POSIXACL))
		seq_puts(seq, ",noacl");
	if (btrfs_test_opt(root, SPACE_CACHE))
		seq_puts(seq, ",space_cache");
	else if (btrfs_test_opt(root, FREE_SPACE_TREE))
		seq_puts(seq, ",space_cache=v2");
	else
		seq_puts(seq, ",nospace_cache");
	if (btrfs_test_opt(root, RESCAN_UUID_TREE))
		seq_puts(seq, ",rescan_uuid_tree");
	if (btrfs_test_opt(root, CLEAR_CACHE))
		seq_puts(seq, ",clear_cache");
	if (btrfs_test_opt(root, USER_SUBVOL_RM_ALLOWED))
		seq_puts(seq, ",user_subvol_rm_allowed");
	if (btrfs_test_opt(root, ENOSPC_DEBUG))
		seq_puts(seq, ",enospc_debug");
	if (btrfs_test_opt(root, AUTO_DEFRAG))
		seq_puts(seq, ",autodefrag");
	if (btrfs_test_opt(root, INODE_MAP_CACHE))
		seq_puts(seq, ",inode_cache");
	if (btrfs_test_opt(root, SKIP_BALANCE))
		seq_puts(seq, ",skip_balance");
	if (btrfs_test_opt(root, RECOVERY))
		seq_puts(seq, ",recovery");
#ifdef CONFIG_BTRFS_FS_CHECK_INTEGRITY
	if (btrfs_test_opt(root, CHECK_INTEGRITY_INCLUDING_EXTENT_DATA))
		seq_puts(seq, ",check_int_data");
	else if (btrfs_test_opt(root, CHECK_INTEGRITY))
		seq_puts(seq, ",check_int");
	if (info->check_integrity_print_mask)
		seq_printf(seq, ",check_int_print_mask=%d",
				info->check_integrity_print_mask);
#endif
#ifdef MY_ABC_HERE
	if (info->flushoncommit_threshold)
		seq_printf(seq, ",flushoncommit_threshold=%d",
				info->flushoncommit_threshold);
#endif  
	if (info->metadata_ratio)
		seq_printf(seq, ",metadata_ratio=%d",
				info->metadata_ratio);
	if (btrfs_test_opt(root, PANIC_ON_FATAL_ERROR))
		seq_puts(seq, ",fatal_errors=panic");
	if (info->commit_interval != BTRFS_DEFAULT_COMMIT_INTERVAL)
		seq_printf(seq, ",commit=%d", info->commit_interval);
#ifdef CONFIG_BTRFS_DEBUG
	if (btrfs_test_opt(root, FRAGMENT_DATA))
		seq_puts(seq, ",fragment=data");
	if (btrfs_test_opt(root, FRAGMENT_METADATA))
		seq_puts(seq, ",fragment=metadata");
#endif
#ifdef MY_ABC_HERE
	if (info->no_block_group_hint)
		seq_puts(seq, ",no_block_group_hint");
#endif  
	seq_printf(seq, ",subvolid=%llu",
		  BTRFS_I(d_inode(dentry))->root->root_key.objectid);
	seq_puts(seq, ",subvol=");
	seq_dentry(seq, dentry, " \t\n\\");
	return 0;
}

static int btrfs_test_super(struct super_block *s, void *data)
{
	struct btrfs_fs_info *p = data;
	struct btrfs_fs_info *fs_info = btrfs_sb(s);

	return fs_info->fs_devices == p->fs_devices;
}

static int btrfs_set_super(struct super_block *s, void *data)
{
	int err = set_anon_super(s, data);
	if (!err)
		s->s_fs_info = data;
	return err;
}

static inline int is_subvolume_inode(struct inode *inode)
{
	if (inode && inode->i_ino == BTRFS_FIRST_FREE_OBJECTID)
		return 1;
	return 0;
}

static char *setup_root_args(char *args)
{
	char *buf, *dst, *sep;

	if (!args)
		return kstrdup("subvolid=0", GFP_NOFS);

	buf = dst = kmalloc(strlen(args) + strlen(",subvolid=0") + 1, GFP_NOFS);
	if (!buf)
		return NULL;

	while (1) {
		sep = strchrnul(args, ',');
		if (!strstarts(args, "subvol=") &&
		    !strstarts(args, "subvolid=")) {
			memcpy(dst, args, sep - args);
			dst += sep - args;
			*dst++ = ',';
		}
		if (*sep)
			args = sep + 1;
		else
			break;
	}
	strcpy(dst, "subvolid=0");

	return buf;
}

static struct dentry *mount_subvol(const char *subvol_name, u64 subvol_objectid,
				   int flags, const char *device_name,
				   char *data)
{
	struct dentry *root;
	struct vfsmount *mnt = NULL;
	char *newargs;
	int ret;

	newargs = setup_root_args(data);
	if (!newargs) {
		root = ERR_PTR(-ENOMEM);
		goto out;
	}

	mnt = vfs_kern_mount(&btrfs_fs_type, flags, device_name, newargs);
	if (PTR_ERR_OR_ZERO(mnt) == -EBUSY) {
		if (flags & MS_RDONLY) {
			mnt = vfs_kern_mount(&btrfs_fs_type, flags & ~MS_RDONLY,
					     device_name, newargs);
		} else {
			mnt = vfs_kern_mount(&btrfs_fs_type, flags | MS_RDONLY,
					     device_name, newargs);
			if (IS_ERR(mnt)) {
				root = ERR_CAST(mnt);
				mnt = NULL;
				goto out;
			}

			down_write(&mnt->mnt_sb->s_umount);
			ret = btrfs_remount(mnt->mnt_sb, &flags, NULL);
			up_write(&mnt->mnt_sb->s_umount);
			if (ret < 0) {
				root = ERR_PTR(ret);
				goto out;
			}
		}
	}
	if (IS_ERR(mnt)) {
		root = ERR_CAST(mnt);
		mnt = NULL;
		goto out;
	}

	if (!subvol_name) {
		if (!subvol_objectid) {
			ret = get_default_subvol_objectid(btrfs_sb(mnt->mnt_sb),
							  &subvol_objectid);
			if (ret) {
				root = ERR_PTR(ret);
				goto out;
			}
		}
		subvol_name = get_subvol_name_from_objectid(btrfs_sb(mnt->mnt_sb),
							    subvol_objectid);
		if (IS_ERR(subvol_name)) {
			root = ERR_CAST(subvol_name);
			subvol_name = NULL;
			goto out;
		}

	}

	root = mount_subtree(mnt, subvol_name);
	 
	mnt = NULL;

	if (!IS_ERR(root)) {
		struct super_block *s = root->d_sb;
		struct inode *root_inode = d_inode(root);
		u64 root_objectid = BTRFS_I(root_inode)->root->root_key.objectid;

		ret = 0;
		if (!is_subvolume_inode(root_inode)) {
			pr_err("BTRFS: '%s' is not a valid subvolume\n",
			       subvol_name);
			ret = -EINVAL;
		}
		if (subvol_objectid && root_objectid != subvol_objectid) {
			 
			pr_err("BTRFS: subvol '%s' does not match subvolid %llu\n",
			       subvol_name, subvol_objectid);
			ret = -EINVAL;
		}
		if (ret) {
			dput(root);
			root = ERR_PTR(ret);
			deactivate_locked_super(s);
		}
	}

out:
	mntput(mnt);
	kfree(newargs);
	kfree(subvol_name);
	return root;
}

static int parse_security_options(char *orig_opts,
				  struct security_mnt_opts *sec_opts)
{
	char *secdata = NULL;
	int ret = 0;

	secdata = alloc_secdata();
	if (!secdata)
		return -ENOMEM;
	ret = security_sb_copy_data(orig_opts, secdata);
	if (ret) {
		free_secdata(secdata);
		return ret;
	}
	ret = security_sb_parse_opts_str(secdata, sec_opts);
	free_secdata(secdata);
	return ret;
}

static int setup_security_options(struct btrfs_fs_info *fs_info,
				  struct super_block *sb,
				  struct security_mnt_opts *sec_opts)
{
	int ret = 0;

	ret = security_sb_set_mnt_opts(sb, sec_opts, 0, NULL);
	if (ret)
		return ret;

#ifdef CONFIG_SECURITY
	if (!fs_info->security_opts.num_mnt_opts) {
		 
		memcpy(&fs_info->security_opts, sec_opts, sizeof(*sec_opts));
	} else {
		 
		security_free_mnt_opts(sec_opts);
	}
#endif
	return ret;
}

static struct dentry *btrfs_mount(struct file_system_type *fs_type, int flags,
		const char *device_name, void *data)
{
	struct block_device *bdev = NULL;
	struct super_block *s;
	struct btrfs_fs_devices *fs_devices = NULL;
	struct btrfs_fs_info *fs_info = NULL;
	struct security_mnt_opts new_sec_opts;
	fmode_t mode = FMODE_READ;
	char *subvol_name = NULL;
	u64 subvol_objectid = 0;
	int error = 0;

	if (!(flags & MS_RDONLY))
		mode |= FMODE_WRITE;

	error = btrfs_parse_early_options(data, mode, fs_type,
					  &subvol_name, &subvol_objectid,
					  &fs_devices);
	if (error) {
		kfree(subvol_name);
		return ERR_PTR(error);
	}

	if (subvol_name || subvol_objectid != BTRFS_FS_TREE_OBJECTID) {
		 
		return mount_subvol(subvol_name, subvol_objectid, flags,
				    device_name, data);
	}

	security_init_mnt_opts(&new_sec_opts);
	if (data) {
		error = parse_security_options(data, &new_sec_opts);
		if (error)
			return ERR_PTR(error);
	}

	error = btrfs_scan_one_device(device_name, mode, fs_type, &fs_devices);
	if (error)
		goto error_sec_opts;

	fs_info = kzalloc(sizeof(struct btrfs_fs_info), GFP_NOFS);
	if (!fs_info) {
		error = -ENOMEM;
		goto error_sec_opts;
	}

	fs_info->fs_devices = fs_devices;

	fs_info->super_copy = kzalloc(BTRFS_SUPER_INFO_SIZE, GFP_NOFS);
	fs_info->super_for_commit = kzalloc(BTRFS_SUPER_INFO_SIZE, GFP_NOFS);
	security_init_mnt_opts(&fs_info->security_opts);
	if (!fs_info->super_copy || !fs_info->super_for_commit) {
		error = -ENOMEM;
		goto error_fs_info;
	}

	error = btrfs_open_devices(fs_devices, mode, fs_type);
	if (error)
		goto error_fs_info;

	if (!(flags & MS_RDONLY) && fs_devices->rw_devices == 0) {
		error = -EACCES;
		goto error_close_devices;
	}

	bdev = fs_devices->latest_bdev;
	s = sget(fs_type, btrfs_test_super, btrfs_set_super, flags | MS_NOSEC,
		 fs_info);
	if (IS_ERR(s)) {
		error = PTR_ERR(s);
		goto error_close_devices;
	}

	if (s->s_root) {
		btrfs_close_devices(fs_devices);
		free_fs_info(fs_info);
		if ((flags ^ s->s_flags) & MS_RDONLY)
			error = -EBUSY;
	} else {
		char b[BDEVNAME_SIZE];

		strlcpy(s->s_id, bdevname(bdev, b), sizeof(s->s_id));
		btrfs_sb(s)->bdev_holder = fs_type;
		error = btrfs_fill_super(s, fs_devices, data,
					 flags & MS_SILENT ? 1 : 0);
	}
	if (error) {
		deactivate_locked_super(s);
		goto error_sec_opts;
	}

	fs_info = btrfs_sb(s);
	error = setup_security_options(fs_info, s, &new_sec_opts);
	if (error) {
		deactivate_locked_super(s);
		goto error_sec_opts;
	}

	return dget(s->s_root);

error_close_devices:
	btrfs_close_devices(fs_devices);
error_fs_info:
	free_fs_info(fs_info);
error_sec_opts:
	security_free_mnt_opts(&new_sec_opts);
	return ERR_PTR(error);
}

static void btrfs_resize_thread_pool(struct btrfs_fs_info *fs_info,
				     int new_pool_size, int old_pool_size)
{
	if (new_pool_size == old_pool_size)
		return;

	fs_info->thread_pool_size = new_pool_size;

	btrfs_info(fs_info, "resize thread pool %d -> %d",
	       old_pool_size, new_pool_size);

	btrfs_workqueue_set_max(fs_info->workers, new_pool_size);
	btrfs_workqueue_set_max(fs_info->delalloc_workers, new_pool_size);
	btrfs_workqueue_set_max(fs_info->submit_workers, new_pool_size);
	btrfs_workqueue_set_max(fs_info->caching_workers, new_pool_size);
	btrfs_workqueue_set_max(fs_info->endio_workers, new_pool_size);
	btrfs_workqueue_set_max(fs_info->endio_meta_workers, new_pool_size);
	btrfs_workqueue_set_max(fs_info->endio_meta_write_workers,
				new_pool_size);
	btrfs_workqueue_set_max(fs_info->endio_write_workers, new_pool_size);
	btrfs_workqueue_set_max(fs_info->endio_freespace_worker, new_pool_size);
	btrfs_workqueue_set_max(fs_info->delayed_workers, new_pool_size);
	btrfs_workqueue_set_max(fs_info->readahead_workers, new_pool_size);
	btrfs_workqueue_set_max(fs_info->scrub_wr_completion_workers,
				new_pool_size);
}

static inline void btrfs_remount_prepare(struct btrfs_fs_info *fs_info)
{
	set_bit(BTRFS_FS_STATE_REMOUNTING, &fs_info->fs_state);
}

static inline void btrfs_remount_begin(struct btrfs_fs_info *fs_info,
				       unsigned long old_opts, int flags)
{
	if (btrfs_raw_test_opt(old_opts, AUTO_DEFRAG) &&
	    (!btrfs_raw_test_opt(fs_info->mount_opt, AUTO_DEFRAG) ||
	     (flags & MS_RDONLY))) {
		 
		wait_event(fs_info->transaction_wait,
			   (atomic_read(&fs_info->defrag_running) == 0));
		if (flags & MS_RDONLY)
			sync_filesystem(fs_info->sb);
	}
}

static inline void btrfs_remount_cleanup(struct btrfs_fs_info *fs_info,
					 unsigned long old_opts)
{
	 
	if (btrfs_raw_test_opt(old_opts, AUTO_DEFRAG) &&
	    (!btrfs_raw_test_opt(fs_info->mount_opt, AUTO_DEFRAG) ||
	     (fs_info->sb->s_flags & MS_RDONLY))) {
		btrfs_cleanup_defrag_inodes(fs_info);
	}

	clear_bit(BTRFS_FS_STATE_REMOUNTING, &fs_info->fs_state);
}

static int btrfs_remount(struct super_block *sb, int *flags, char *data)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(sb);
	struct btrfs_root *root = fs_info->tree_root;
	unsigned old_flags = sb->s_flags;
	unsigned long old_opts = fs_info->mount_opt;
	unsigned long old_compress_type = fs_info->compress_type;
	u64 old_max_inline = fs_info->max_inline;
	u64 old_alloc_start = fs_info->alloc_start;
	int old_thread_pool_size = fs_info->thread_pool_size;
	unsigned int old_metadata_ratio = fs_info->metadata_ratio;
	int ret;

	sync_filesystem(sb);
	btrfs_remount_prepare(fs_info);

	if (data) {
		struct security_mnt_opts new_sec_opts;

		security_init_mnt_opts(&new_sec_opts);
		ret = parse_security_options(data, &new_sec_opts);
		if (ret)
			goto restore;
		ret = setup_security_options(fs_info, sb,
					     &new_sec_opts);
		if (ret) {
			security_free_mnt_opts(&new_sec_opts);
			goto restore;
		}
	}

	ret = btrfs_parse_options(root, data);
	if (ret) {
		ret = -EINVAL;
		goto restore;
	}

	btrfs_remount_begin(fs_info, old_opts, *flags);
	btrfs_resize_thread_pool(fs_info,
		fs_info->thread_pool_size, old_thread_pool_size);

	if ((*flags & MS_RDONLY) == (sb->s_flags & MS_RDONLY))
		goto out;

	if (*flags & MS_RDONLY) {
		 
		cancel_work_sync(&fs_info->async_reclaim_work);

		down(&fs_info->uuid_tree_rescan_sem);
		 
		up(&fs_info->uuid_tree_rescan_sem);

		sb->s_flags |= MS_RDONLY;

		btrfs_delete_unused_bgs(fs_info);

		btrfs_dev_replace_suspend_for_unmount(fs_info);
		btrfs_scrub_cancel(fs_info);
		btrfs_pause_balance(fs_info);

		ret = btrfs_commit_super(root);
		if (ret)
			goto restore;
	} else {
		if (test_bit(BTRFS_FS_STATE_ERROR, &root->fs_info->fs_state)) {
			btrfs_err(fs_info,
				"Remounting read-write after error is not allowed");
			ret = -EINVAL;
			goto restore;
		}
		if (fs_info->fs_devices->rw_devices == 0) {
			ret = -EACCES;
			goto restore;
		}

		if (fs_info->fs_devices->missing_devices >
		     fs_info->num_tolerated_disk_barrier_failures &&
		    !(*flags & MS_RDONLY)) {
			btrfs_warn(fs_info,
				"too many missing devices, writeable remount is not allowed");
			ret = -EACCES;
			goto restore;
		}

		if (btrfs_super_log_root(fs_info->super_copy) != 0) {
			ret = -EINVAL;
			goto restore;
		}

		ret = btrfs_cleanup_fs_roots(fs_info);
		if (ret)
			goto restore;

		mutex_lock(&fs_info->cleaner_mutex);
		ret = btrfs_recover_relocation(root);
		mutex_unlock(&fs_info->cleaner_mutex);
		if (ret)
			goto restore;

		ret = btrfs_resume_balance_async(fs_info);
		if (ret)
			goto restore;

		ret = btrfs_resume_dev_replace_async(fs_info);
		if (ret) {
			btrfs_warn(fs_info, "failed to resume dev_replace");
			goto restore;
		}

		if (!fs_info->uuid_root) {
			btrfs_info(fs_info, "creating UUID tree");
			ret = btrfs_create_uuid_tree(fs_info);
			if (ret) {
				btrfs_warn(fs_info, "failed to create the UUID tree %d", ret);
				goto restore;
			}
		}
		sb->s_flags &= ~MS_RDONLY;

		fs_info->open = 1;
	}
out:
	wake_up_process(fs_info->transaction_kthread);
	btrfs_remount_cleanup(fs_info, old_opts);
	return 0;

restore:
	 
	if (sb->s_flags & MS_RDONLY)
		old_flags |= MS_RDONLY;
	sb->s_flags = old_flags;
	fs_info->mount_opt = old_opts;
	fs_info->compress_type = old_compress_type;
	fs_info->max_inline = old_max_inline;
	mutex_lock(&fs_info->chunk_mutex);
	fs_info->alloc_start = old_alloc_start;
	mutex_unlock(&fs_info->chunk_mutex);
	btrfs_resize_thread_pool(fs_info,
		old_thread_pool_size, fs_info->thread_pool_size);
	fs_info->metadata_ratio = old_metadata_ratio;
	btrfs_remount_cleanup(fs_info, old_opts);
	return ret;
}

static int btrfs_cmp_device_free_bytes(const void *dev_info1,
				       const void *dev_info2)
{
	if (((struct btrfs_device_info *)dev_info1)->max_avail >
	    ((struct btrfs_device_info *)dev_info2)->max_avail)
		return -1;
	else if (((struct btrfs_device_info *)dev_info1)->max_avail <
		 ((struct btrfs_device_info *)dev_info2)->max_avail)
		return 1;
	else
	return 0;
}

static inline void btrfs_descending_sort_devices(
					struct btrfs_device_info *devices,
					size_t nr_devices)
{
	sort(devices, nr_devices, sizeof(struct btrfs_device_info),
	     btrfs_cmp_device_free_bytes, NULL);
}

static int btrfs_calc_avail_data_space(struct btrfs_root *root, u64 *free_bytes)
{
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_device_info *devices_info;
	struct btrfs_fs_devices *fs_devices = fs_info->fs_devices;
	struct btrfs_device *device;
	u64 skip_space;
	u64 type;
	u64 avail_space;
	u64 used_space;
	u64 min_stripe_size;
	int min_stripes = 1, num_stripes = 1;
	int i = 0, nr_devices;
	int ret;

	nr_devices = fs_info->fs_devices->open_devices;
	if (!nr_devices) {
		smp_mb();
		nr_devices = fs_info->fs_devices->open_devices;
		ASSERT(nr_devices);
		if (!nr_devices) {
			*free_bytes = 0;
			return 0;
		}
	}

	devices_info = kmalloc_array(nr_devices, sizeof(*devices_info),
			       GFP_NOFS);
	if (!devices_info)
		return -ENOMEM;

	type = btrfs_get_alloc_profile(root, 1);
	if (type & BTRFS_BLOCK_GROUP_RAID0) {
		min_stripes = 2;
		num_stripes = nr_devices;
	} else if (type & BTRFS_BLOCK_GROUP_RAID1) {
		min_stripes = 2;
		num_stripes = 2;
	} else if (type & BTRFS_BLOCK_GROUP_RAID10) {
		min_stripes = 4;
		num_stripes = 4;
	}

	if (type & BTRFS_BLOCK_GROUP_DUP)
		min_stripe_size = 2 * BTRFS_STRIPE_LEN;
	else
		min_stripe_size = BTRFS_STRIPE_LEN;

	if (fs_info->alloc_start)
		mutex_lock(&fs_devices->device_list_mutex);
	rcu_read_lock();
	list_for_each_entry_rcu(device, &fs_devices->devices, dev_list) {
		if (!device->in_fs_metadata || !device->bdev ||
		    device->is_tgtdev_for_dev_replace)
			continue;

		if (i >= nr_devices)
			break;

		avail_space = device->total_bytes - device->bytes_used;

		avail_space = div_u64(avail_space, BTRFS_STRIPE_LEN);
		avail_space *= BTRFS_STRIPE_LEN;

		skip_space = SZ_1M;

		if (fs_info->alloc_start &&
		    fs_info->alloc_start + BTRFS_STRIPE_LEN <=
		    device->total_bytes) {
			rcu_read_unlock();
			skip_space = max(fs_info->alloc_start, skip_space);

			ret = btrfs_account_dev_extents_size(device, 0,
							     skip_space - 1,
							     &used_space);
			if (ret) {
				kfree(devices_info);
				mutex_unlock(&fs_devices->device_list_mutex);
				return ret;
			}

			rcu_read_lock();

			skip_space -= used_space;
		}

		if (avail_space && avail_space >= skip_space)
			avail_space -= skip_space;
		else
			avail_space = 0;

		if (avail_space < min_stripe_size)
			continue;

		devices_info[i].dev = device;
		devices_info[i].max_avail = avail_space;

		i++;
	}
	rcu_read_unlock();
	if (fs_info->alloc_start)
		mutex_unlock(&fs_devices->device_list_mutex);

	nr_devices = i;

	btrfs_descending_sort_devices(devices_info, nr_devices);

	i = nr_devices - 1;
	avail_space = 0;
	while (nr_devices >= min_stripes) {
		if (num_stripes > nr_devices)
			num_stripes = nr_devices;

		if (devices_info[i].max_avail >= min_stripe_size) {
			int j;
			u64 alloc_size;

			avail_space += devices_info[i].max_avail * num_stripes;
			alloc_size = devices_info[i].max_avail;
			for (j = i + 1 - num_stripes; j <= i; j++)
				devices_info[j].max_avail -= alloc_size;
		}
		i--;
		nr_devices--;
	}

	kfree(devices_info);
	*free_bytes = avail_space;
	return 0;
}

static int btrfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(dentry->d_sb);
	struct btrfs_super_block *disk_super = fs_info->super_copy;
	struct list_head *head = &fs_info->space_info;
	struct btrfs_space_info *found;
	u64 total_used = 0;
	u64 total_free_data = 0;
	u64 total_free_meta = 0;
	int bits = dentry->d_sb->s_blocksize_bits;
	__be32 *fsid = (__be32 *)fs_info->fsid;
	unsigned factor = 1;
	struct btrfs_block_rsv *block_rsv = &fs_info->global_block_rsv;
	int ret;
	u64 thresh = 0;
#ifdef MY_ABC_HERE
	u64 total_metadata = 0;
#endif  
	int mixed = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(found, head, list) {
		if (found->flags & BTRFS_BLOCK_GROUP_DATA) {
			int i;

			total_free_data += found->disk_total - found->disk_used;
			total_free_data -=
				btrfs_account_ro_block_groups_free_space(found);

			for (i = 0; i < BTRFS_NR_RAID_TYPES; i++) {
				if (!list_empty(&found->block_groups[i])) {
					switch (i) {
					case BTRFS_RAID_DUP:
					case BTRFS_RAID_RAID1:
					case BTRFS_RAID_RAID10:
						factor = 2;
					}
				}
			}
		}

		if (!mixed && found->flags & BTRFS_BLOCK_GROUP_METADATA) {
			if (found->flags & BTRFS_BLOCK_GROUP_DATA)
				mixed = 1;
			else
				total_free_meta += found->disk_total -
					found->disk_used;
		}
#ifdef MY_ABC_HERE
		if (found->flags & BTRFS_BLOCK_GROUP_METADATA) {
			total_metadata += found->disk_total;
		}
#endif  

		total_used += found->disk_used;
	}

	rcu_read_unlock();

	buf->f_blocks = div_u64(btrfs_super_total_bytes(disk_super), factor);
	buf->f_blocks >>= bits;
	buf->f_bfree = buf->f_blocks - (div_u64(total_used, factor) >> bits);

	spin_lock(&block_rsv->lock);
	 
	if (buf->f_bfree >= block_rsv->size >> bits)
		buf->f_bfree -= block_rsv->size >> bits;
	else
		buf->f_bfree = 0;
	spin_unlock(&block_rsv->lock);

	buf->f_bavail = div_u64(total_free_data, factor);
	ret = btrfs_calc_avail_data_space(fs_info->tree_root, &total_free_data);
	if (ret)
		return ret;
	buf->f_bavail += div_u64(total_free_data, factor);
#ifdef MY_ABC_HERE
	if (fs_info->metadata_ratio) {
		u64 reserved_for_metadata = btrfs_super_total_bytes(disk_super);

		do_div(reserved_for_metadata, fs_info->metadata_ratio);
		if (fs_info->avail_metadata_alloc_bits & BTRFS_BLOCK_GROUP_DUP)
			reserved_for_metadata *= 2;
		if (total_metadata < reserved_for_metadata) {
			if ((reserved_for_metadata-total_metadata) < buf->f_bavail)
				buf->f_bavail -= reserved_for_metadata-total_metadata;
			else
				buf->f_bavail = 0;
		}
		buf->f_blocks -= reserved_for_metadata >> bits;
		if (buf->f_bfree >= reserved_for_metadata >> bits) {
			buf->f_bfree -= reserved_for_metadata >> bits;
		} else {
			buf->f_bfree = 0;
		}
		if (buf->f_bfree > buf->f_blocks)
			buf->f_bfree = buf->f_blocks;
		else if (buf->f_bfree < (buf->f_bavail >> bits))
			buf->f_bfree = buf->f_bavail >> bits;
	}
#endif  
	buf->f_bavail = buf->f_bavail >> bits;

	thresh = 4 * 1024 * 1024;

	if (!mixed && total_free_meta - thresh < block_rsv->size)
		buf->f_bavail = 0;

	buf->f_type = BTRFS_SUPER_MAGIC;
	buf->f_bsize = dentry->d_sb->s_blocksize;
	buf->f_namelen = BTRFS_NAME_LEN;

	buf->f_fsid.val[0] = be32_to_cpu(fsid[0]) ^ be32_to_cpu(fsid[2]);
	buf->f_fsid.val[1] = be32_to_cpu(fsid[1]) ^ be32_to_cpu(fsid[3]);
	 
	buf->f_fsid.val[0] ^= BTRFS_I(d_inode(dentry))->root->objectid >> 32;
	buf->f_fsid.val[1] ^= BTRFS_I(d_inode(dentry))->root->objectid;

	return 0;
}

static void btrfs_kill_super(struct super_block *sb)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(sb);
	kill_anon_super(sb);
	free_fs_info(fs_info);
}

static struct file_system_type btrfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "btrfs",
	.mount		= btrfs_mount,
	.kill_sb	= btrfs_kill_super,
	.fs_flags	= FS_REQUIRES_DEV | FS_BINARY_MOUNTDATA,
};
MODULE_ALIAS_FS("btrfs");

static int btrfs_control_open(struct inode *inode, struct file *file)
{
	 
	file->private_data = NULL;
	return 0;
}

static long btrfs_control_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	struct btrfs_ioctl_vol_args *vol;
	struct btrfs_fs_devices *fs_devices;
	int ret = -ENOTTY;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	vol = memdup_user((void __user *)arg, sizeof(*vol));
	if (IS_ERR(vol))
		return PTR_ERR(vol);

	switch (cmd) {
	case BTRFS_IOC_SCAN_DEV:
		ret = btrfs_scan_one_device(vol->name, FMODE_READ,
					    &btrfs_fs_type, &fs_devices);
		break;
	case BTRFS_IOC_DEVICES_READY:
		ret = btrfs_scan_one_device(vol->name, FMODE_READ,
					    &btrfs_fs_type, &fs_devices);
		if (ret)
			break;
		ret = !(fs_devices->num_devices == fs_devices->total_devices);
		break;
	case BTRFS_IOC_GET_SUPPORTED_FEATURES:
		ret = btrfs_ioctl_get_supported_features((void __user*)arg);
		break;
	}

	kfree(vol);
	return ret;
}

static int btrfs_freeze(struct super_block *sb)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_root *root = btrfs_sb(sb)->tree_root;

	trans = btrfs_attach_transaction_barrier(root);
	if (IS_ERR(trans)) {
		 
		if (PTR_ERR(trans) == -ENOENT)
			return 0;
		return PTR_ERR(trans);
	}
	return btrfs_commit_transaction(trans, root);
}

static int btrfs_show_devname(struct seq_file *m, struct dentry *root)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(root->d_sb);
	struct btrfs_fs_devices *cur_devices;
	struct btrfs_device *dev, *first_dev = NULL;
	struct list_head *head;
	struct rcu_string *name;

	mutex_lock(&fs_info->fs_devices->device_list_mutex);
	cur_devices = fs_info->fs_devices;
	while (cur_devices) {
		head = &cur_devices->devices;
		list_for_each_entry(dev, head, dev_list) {
			if (dev->missing)
				continue;
			if (!dev->name)
				continue;
			if (!first_dev || dev->devid < first_dev->devid)
				first_dev = dev;
		}
		cur_devices = cur_devices->seed;
	}

	if (first_dev) {
		rcu_read_lock();
		name = rcu_dereference(first_dev->name);
		seq_escape(m, name->str, " \t\n\\");
		rcu_read_unlock();
	} else {
		WARN_ON(1);
	}
	mutex_unlock(&fs_info->fs_devices->device_list_mutex);
	return 0;
}

#ifdef MY_ABC_HERE
static int btrfs_syno_set_sb_archive_ver(struct super_block *sb, u32 archive_ver)
{
	struct dentry *dentry = sb->s_root;
	struct syno_xattr_archive_version value;
	int err;

	if (!dentry->d_inode->i_op->setxattr) {
		printk(KERN_ERR "BTRFS:Can't set archive ver on dir_ro_inode %s\n", dentry->d_name.name);
		return -EINVAL;
	}
	value.v_magic = cpu_to_le16(0x2552);
	value.v_struct_version = cpu_to_le16(1);
	value.v_archive_version = cpu_to_le32(archive_ver);
	err = __btrfs_setxattr(NULL, d_inode(dentry), XATTR_SYNO_PREFIX XATTR_SYNO_ARCHIVE_VERSION_VOLUME,
						   &value, sizeof(value), 0);
	if (!err) {
		sb->s_archive_version = archive_ver;
	}
	return err;
}

static int btrfs_syno_get_sb_archive_ver(struct super_block *sb, u32 *version)
{
	*version = sb->s_archive_version;
	return 0;
}
#endif  

#ifdef MY_ABC_HERE
static long btrfs_nr_cached_objects(struct super_block *sb, struct shrink_control *sc)
{
	return (long)atomic_read(&btrfs_sb(sb)->nr_extent_maps);
}

enum btrfs_free_extent_map_type {
	LOOP_FREE_EXTENT_NOT_MODIFIED = 1,
	LOOP_FREE_EXTENT_MODIFIED = 2,
	LOOP_FREE_EXTENT_END = 3,
};
static int btrfs_drop_extent_maps(struct inode *inode, int nr_to_drop)
{
	struct extent_map *em, *next_em = NULL;
	struct extent_map_tree *em_tree = &BTRFS_I(inode)->extent_tree;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int dropped = 0;
	u64 test_gen;
	struct list_head *head = NULL;
	int stage = 0;

	while (nr_to_drop) {
		write_lock(&em_tree->lock);
		test_gen = root->fs_info->last_trans_committed;

		if (next_em == NULL) {
			stage++;
		}

		if (stage >= LOOP_FREE_EXTENT_END) {
			write_unlock(&em_tree->lock);
			break;
		}
		if (stage == LOOP_FREE_EXTENT_NOT_MODIFIED) {
			head = &em_tree->not_modified_extents;
		} else if (stage == LOOP_FREE_EXTENT_MODIFIED) {
			head = &em_tree->syno_modified_extents;
		} else {
			write_unlock(&em_tree->lock);
			break;
		}

		if (next_em != NULL && !extent_map_in_tree(next_em)) {
			free_extent_map(next_em);
			next_em = NULL;
		}

		if (next_em == NULL) {
			if (list_empty(head)) {
				write_unlock(&em_tree->lock);
				continue;
			}
			em = list_entry(head->next, struct extent_map, free_list);
			atomic_inc(&em->refs);
			next_em = list_entry(em->free_list.next, struct extent_map, free_list);
		} else {
			em = next_em;
			next_em = list_entry(em->free_list.next, struct extent_map, free_list);
		}

		if (&next_em->free_list == head) {
			next_em = NULL;
		}
		if (next_em) {
			atomic_inc(&next_em->refs);
		}
		if (test_bit(EXTENT_FLAG_PINNED, &em->flags)) {
			free_extent_map(em);
			write_unlock(&em_tree->lock);
			continue;
		}
		if (!list_empty(&em->list) && em->generation > test_gen) {
			free_extent_map(em);
			write_unlock(&em_tree->lock);
			if (stage == LOOP_FREE_EXTENT_MODIFIED) {
				break;
			} else {
				continue;
			}
		}
		remove_extent_mapping(em_tree, em);
		write_unlock(&em_tree->lock);
		 
		free_extent_map(em);
		 
		free_extent_map(em);
		dropped++;
		nr_to_drop--;
	}
	if (next_em) {
		 
		free_extent_map(next_em);
	}
	return dropped;
}

static bool list_lru_item_empty(struct list_lru *lru, struct list_head *item)
{
	int nid = page_to_nid(virt_to_page(item));
	struct list_lru_node *nlru = &lru->node[nid];

	spin_lock(&nlru->lock);
	if (list_empty(item)) {
		spin_unlock(&nlru->lock);
		return true;
	}
	spin_unlock(&nlru->lock);
	return false;
}

static long btrfs_free_cached_objects(struct super_block *sb, struct shrink_control *sc)
{
	struct inode *inode;
	struct inode *toput_inode = NULL;
	struct btrfs_inode *binode;
	struct btrfs_fs_info *fs_info = btrfs_sb(sb);
	int nr_to_drop = sc->nr_to_scan;

	spin_lock(&fs_info->extent_map_inode_list_lock);
	list_for_each_entry(binode, &fs_info->extent_map_inode_list, free_extent_map_inode) {
		inode = &binode->vfs_inode;
		if (!list_lru_item_empty(&fs_info->sb->s_inode_lru, &inode->i_lru)) {
			continue;
		}
		spin_lock(&inode->i_lock);
		if (inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW)) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		__iget(inode);
		spin_unlock(&inode->i_lock);
		atomic_inc(&binode->free_extent_map_counts);
		if (toput_inode && (atomic_read(&BTRFS_I(toput_inode)->free_extent_map_counts) == 0) && (atomic_read(&(BTRFS_I(toput_inode)->extent_tree.nr_extent_maps)) == 0)) {
			list_del_init(&BTRFS_I(toput_inode)->free_extent_map_inode);
		}
		spin_unlock(&fs_info->extent_map_inode_list_lock);

		nr_to_drop -= btrfs_drop_extent_maps(inode, nr_to_drop);

		iput(toput_inode);
		toput_inode = inode;
		spin_lock(&fs_info->extent_map_inode_list_lock);
		WARN_ON(atomic_read(&binode->free_extent_map_counts) == 0);
		atomic_dec(&binode->free_extent_map_counts);
		if (nr_to_drop <= 0) {
			break;
		}
	}
	if (toput_inode && (atomic_read(&BTRFS_I(toput_inode)->free_extent_map_counts) == 0) && (atomic_read(&(BTRFS_I(toput_inode)->extent_tree.nr_extent_maps)) == 0)) {
		list_del_init(&BTRFS_I(toput_inode)->free_extent_map_inode);
	}
	spin_unlock(&fs_info->extent_map_inode_list_lock);
	iput(toput_inode);
	return (long)(sc->nr_to_scan - nr_to_drop);
}
#endif  

static const struct super_operations btrfs_super_ops = {
#ifdef MY_ABC_HERE
	.syno_set_sb_archive_ver = btrfs_syno_set_sb_archive_ver,
	.syno_get_sb_archive_ver = btrfs_syno_get_sb_archive_ver,
#endif  
#ifdef MY_ABC_HERE
	.nr_cached_objects = btrfs_nr_cached_objects,
	.free_cached_objects = btrfs_free_cached_objects,
#endif  
	.drop_inode	= btrfs_drop_inode,
	.evict_inode	= btrfs_evict_inode,
	.put_super	= btrfs_put_super,
	.sync_fs	= btrfs_sync_fs,
	.show_options	= btrfs_show_options,
	.show_devname	= btrfs_show_devname,
	.write_inode	= btrfs_write_inode,
	.alloc_inode	= btrfs_alloc_inode,
	.destroy_inode	= btrfs_destroy_inode,
	.statfs		= btrfs_statfs,
	.remount_fs	= btrfs_remount,
	.freeze_fs	= btrfs_freeze,
};

static const struct file_operations btrfs_ctl_fops = {
	.open = btrfs_control_open,
	.unlocked_ioctl	 = btrfs_control_ioctl,
	.compat_ioctl = btrfs_control_ioctl,
	.owner	 = THIS_MODULE,
	.llseek = noop_llseek,
};

static struct miscdevice btrfs_misc = {
	.minor		= BTRFS_MINOR,
	.name		= "btrfs-control",
	.fops		= &btrfs_ctl_fops
};

MODULE_ALIAS_MISCDEV(BTRFS_MINOR);
MODULE_ALIAS("devname:btrfs-control");

static int btrfs_interface_init(void)
{
	return misc_register(&btrfs_misc);
}

static void btrfs_interface_exit(void)
{
	misc_deregister(&btrfs_misc);
}

static void btrfs_print_mod_info(void)
{
	printk(KERN_INFO "Btrfs loaded, crc32c=%s"
#ifdef CONFIG_BTRFS_DEBUG
			", debug=on"
#endif
#ifdef CONFIG_BTRFS_ASSERT
			", assert=on"
#endif
#ifdef CONFIG_BTRFS_FS_CHECK_INTEGRITY
			", integrity-checker=on"
#endif
			"\n",
			btrfs_crc32c_impl());
}

static int btrfs_run_sanity_tests(void)
{
	int ret;

	ret = btrfs_init_test_fs();
	if (ret)
		return ret;

	ret = btrfs_test_free_space_cache();
	if (ret)
		goto out;
	ret = btrfs_test_extent_buffer_operations();
	if (ret)
		goto out;
	ret = btrfs_test_extent_io();
	if (ret)
		goto out;
	ret = btrfs_test_inodes();
	if (ret)
		goto out;
	ret = btrfs_test_qgroups();
	if (ret)
		goto out;
	ret = btrfs_test_free_space_tree();
out:
	btrfs_destroy_test_fs();
	return ret;
}

static int __init init_btrfs_fs(void)
{
	int err;

	err = btrfs_hash_init();
	if (err)
		return err;

	btrfs_props_init();

	err = btrfs_init_sysfs();
	if (err)
		goto free_hash;

	btrfs_init_compress();

	err = btrfs_init_cachep();
	if (err)
		goto free_compress;

	err = extent_io_init();
	if (err)
		goto free_cachep;

	err = extent_map_init();
	if (err)
		goto free_extent_io;

	err = ordered_data_init();
	if (err)
		goto free_extent_map;

	err = btrfs_delayed_inode_init();
	if (err)
		goto free_ordered_data;

	err = btrfs_auto_defrag_init();
	if (err)
		goto free_delayed_inode;

	err = btrfs_delayed_ref_init();
	if (err)
		goto free_auto_defrag;

	err = btrfs_prelim_ref_init();
	if (err)
		goto free_delayed_ref;

	err = btrfs_end_io_wq_init();
	if (err)
		goto free_prelim_ref;

	err = btrfs_interface_init();
	if (err)
		goto free_end_io_wq;

	btrfs_init_lockdep();

	btrfs_print_mod_info();

	err = btrfs_run_sanity_tests();
	if (err)
		goto unregister_ioctl;

	err = register_filesystem(&btrfs_fs_type);
	if (err)
		goto unregister_ioctl;

	return 0;

unregister_ioctl:
	btrfs_interface_exit();
free_end_io_wq:
	btrfs_end_io_wq_exit();
free_prelim_ref:
	btrfs_prelim_ref_exit();
free_delayed_ref:
	btrfs_delayed_ref_exit();
free_auto_defrag:
	btrfs_auto_defrag_exit();
free_delayed_inode:
	btrfs_delayed_inode_exit();
free_ordered_data:
	ordered_data_exit();
free_extent_map:
	extent_map_exit();
free_extent_io:
	extent_io_exit();
free_cachep:
	btrfs_destroy_cachep();
free_compress:
	btrfs_exit_compress();
	btrfs_exit_sysfs();
free_hash:
	btrfs_hash_exit();
	return err;
}

static void __exit exit_btrfs_fs(void)
{
	btrfs_destroy_cachep();
	btrfs_delayed_ref_exit();
	btrfs_auto_defrag_exit();
	btrfs_delayed_inode_exit();
	btrfs_prelim_ref_exit();
	ordered_data_exit();
	extent_map_exit();
	extent_io_exit();
	btrfs_interface_exit();
	btrfs_end_io_wq_exit();
	unregister_filesystem(&btrfs_fs_type);
	btrfs_exit_sysfs();
	btrfs_cleanup_fs_uuids();
	btrfs_exit_compress();
	btrfs_hash_exit();
}

late_initcall(init_btrfs_fs);
module_exit(exit_btrfs_fs)

MODULE_LICENSE("GPL");
