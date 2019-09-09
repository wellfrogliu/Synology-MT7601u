#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/types.h>
#include "ctree.h"
#include "xattr.h"

static int
btrfs_xattr_syno_set(const struct xattr_handler *handler,
				   struct dentry *dentry, const char *name,
				   const void *value, size_t size, int flags)
{
	int ret;
	struct inode *inode = d_inode(dentry);
	const char *complete_name = xattr_full_name(handler, name);

	ret = __btrfs_setxattr(NULL, inode, complete_name, value, size, flags);

	if (ret)
		goto out;
#ifdef MY_ABC_HERE
	 
	if (!strcmp(name, XATTR_SYNO_ARCHIVE_BIT)) {
		 
		if (value) {
			const __le32 *archive_bit_le32 = value;
			inode->i_archive_bit = le32_to_cpu(*archive_bit_le32);
		} else {
			inode->i_archive_bit = 0;
		}
		return ret;
	}
#endif  
#ifdef MY_ABC_HERE
	if (!strcmp(name, XATTR_SYNO_ARCHIVE_VERSION)) {
		if (value) {
			const struct syno_xattr_archive_version *arch_ver_le = value;
			inode->i_archive_version = le32_to_cpu(arch_ver_le->v_archive_version);
		} else {
			inode->i_archive_version = 0;
		}
		inode->i_flags |= S_ARCHIVE_VERSION_CACHED;
		return ret;
	}
#endif  
#ifdef MY_ABC_HERE
	if (!strcmp(name, XATTR_SYNO_CREATE_TIME)) {
		if (value) {
			const struct btrfs_timespec *crtime_le = value;
			inode->i_create_time.tv_sec = le64_to_cpu(crtime_le->sec);
			inode->i_create_time.tv_nsec = le32_to_cpu(crtime_le->nsec);
		} else {
			inode->i_create_time.tv_sec = 0;
			inode->i_create_time.tv_nsec = 0;
		}
		inode->i_flags |= S_CREATE_TIME_CACHED;
		return ret;
	}
#endif  
out:
	return ret;
}

static int btrfs_xattr_syno_get(const struct xattr_handler *handler,
				   struct dentry *dentry, const char *name,
				   void *buffer, size_t size)
{
	struct inode *inode = d_inode(dentry);

	name = xattr_full_name(handler, name);
	return __btrfs_getxattr(inode, name, buffer, size);
}

const struct xattr_handler btrfs_xattr_syno_handler = {
	.prefix	= XATTR_SYNO_PREFIX,
	.set	= btrfs_xattr_syno_set,
	.get	= btrfs_xattr_syno_get,
};
