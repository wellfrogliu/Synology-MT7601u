#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/capability.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/export.h>
#include <linux/uaccess.h>
#include <linux/writeback.h>
#include <linux/buffer_head.h>
#include <linux/falloc.h>
#ifdef MY_ABC_HERE
#include <linux/mount.h>
#endif  

#include <asm/ioctls.h>

#define FIEMAP_MAX_EXTENTS	(UINT_MAX / sizeof(struct fiemap_extent))

static long vfs_ioctl(struct file *filp, unsigned int cmd,
		      unsigned long arg)
{
	int error = -ENOTTY;

	if (!filp->f_op->unlocked_ioctl)
		goto out;

	error = filp->f_op->unlocked_ioctl(filp, cmd, arg);
	if (error == -ENOIOCTLCMD)
		error = -ENOTTY;
 out:
	return error;
}

static int ioctl_fibmap(struct file *filp, int __user *p)
{
	struct address_space *mapping = filp->f_mapping;
	int res, block;

	if (!mapping->a_ops->bmap)
		return -EINVAL;
	if (!capable(CAP_SYS_RAWIO))
		return -EPERM;
	res = get_user(block, p);
	if (res)
		return res;
	res = mapping->a_ops->bmap(mapping, block);
	return put_user(res, p);
}

#define SET_UNKNOWN_FLAGS	(FIEMAP_EXTENT_DELALLOC)
#define SET_NO_UNMOUNTED_IO_FLAGS	(FIEMAP_EXTENT_DATA_ENCRYPTED)
#define SET_NOT_ALIGNED_FLAGS	(FIEMAP_EXTENT_DATA_TAIL|FIEMAP_EXTENT_DATA_INLINE)
int fiemap_fill_next_extent(struct fiemap_extent_info *fieinfo, u64 logical,
			    u64 phys, u64 len, u32 flags)
{
	struct fiemap_extent extent;
	struct fiemap_extent __user *dest = fieinfo->fi_extents_start;

	if (fieinfo->fi_extents_max == 0) {
		fieinfo->fi_extents_mapped++;
		return (flags & FIEMAP_EXTENT_LAST) ? 1 : 0;
	}

	if (fieinfo->fi_extents_mapped >= fieinfo->fi_extents_max)
		return 1;

	if (flags & SET_UNKNOWN_FLAGS)
		flags |= FIEMAP_EXTENT_UNKNOWN;
	if (flags & SET_NO_UNMOUNTED_IO_FLAGS)
		flags |= FIEMAP_EXTENT_ENCODED;
	if (flags & SET_NOT_ALIGNED_FLAGS)
		flags |= FIEMAP_EXTENT_NOT_ALIGNED;

	memset(&extent, 0, sizeof(extent));
	extent.fe_logical = logical;
	extent.fe_physical = phys;
	extent.fe_length = len;
	extent.fe_flags = flags;

	dest += fieinfo->fi_extents_mapped;
	if (copy_to_user(dest, &extent, sizeof(extent)))
		return -EFAULT;

	fieinfo->fi_extents_mapped++;
	if (fieinfo->fi_extents_mapped == fieinfo->fi_extents_max)
		return 1;
	return (flags & FIEMAP_EXTENT_LAST) ? 1 : 0;
}
EXPORT_SYMBOL(fiemap_fill_next_extent);

int fiemap_check_flags(struct fiemap_extent_info *fieinfo, u32 fs_flags)
{
	u32 incompat_flags;

	incompat_flags = fieinfo->fi_flags & ~(FIEMAP_FLAGS_COMPAT & fs_flags);
	if (incompat_flags) {
		fieinfo->fi_flags = incompat_flags;
		return -EBADR;
	}
	return 0;
}
EXPORT_SYMBOL(fiemap_check_flags);

static int fiemap_check_ranges(struct super_block *sb,
			       u64 start, u64 len, u64 *new_len)
{
	u64 maxbytes = (u64) sb->s_maxbytes;

	*new_len = len;

	if (len == 0)
		return -EINVAL;

	if (start > maxbytes)
		return -EFBIG;

	if (len > maxbytes || (maxbytes - len) < start)
		*new_len = maxbytes - start;

	return 0;
}

static int ioctl_fiemap(struct file *filp, unsigned long arg)
{
	struct fiemap fiemap;
	struct fiemap __user *ufiemap = (struct fiemap __user *) arg;
	struct fiemap_extent_info fieinfo = { 0, };
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	u64 len;
	int error;

	if (!inode->i_op->fiemap)
		return -EOPNOTSUPP;

	if (copy_from_user(&fiemap, ufiemap, sizeof(fiemap)))
		return -EFAULT;

	if (fiemap.fm_extent_count > FIEMAP_MAX_EXTENTS)
		return -EINVAL;

	error = fiemap_check_ranges(sb, fiemap.fm_start, fiemap.fm_length,
				    &len);
	if (error)
		return error;

	fieinfo.fi_flags = fiemap.fm_flags;
	fieinfo.fi_extents_max = fiemap.fm_extent_count;
	fieinfo.fi_extents_start = ufiemap->fm_extents;

	if (fiemap.fm_extent_count != 0 &&
	    !access_ok(VERIFY_WRITE, fieinfo.fi_extents_start,
		       fieinfo.fi_extents_max * sizeof(struct fiemap_extent)))
		return -EFAULT;

	if (fieinfo.fi_flags & FIEMAP_FLAG_SYNC)
		filemap_write_and_wait(inode->i_mapping);

	error = inode->i_op->fiemap(inode, &fieinfo, fiemap.fm_start, len);
	fiemap.fm_flags = fieinfo.fi_flags;
	fiemap.fm_mapped_extents = fieinfo.fi_extents_mapped;
	if (copy_to_user(ufiemap, &fiemap, sizeof(fiemap)))
		error = -EFAULT;

	return error;
}

#ifdef MY_ABC_HERE
static long ioctl_file_clone(struct file *dst_file, unsigned long srcfd,
			     u64 off, u64 olen, u64 destoff, int check_compr)
#else
static long ioctl_file_clone(struct file *dst_file, unsigned long srcfd,
			     u64 off, u64 olen, u64 destoff)
#endif  
{
	struct fd src_file = fdget(srcfd);
	int ret;

	if (!src_file.file)
		return -EBADF;
	ret = -EXDEV;
	if (src_file.file->f_path.mnt != dst_file->f_path.mnt)
		goto fdput;
#ifdef MY_ABC_HERE
	ret = do_clone_file_range(src_file.file, off, dst_file, destoff, olen, check_compr);
#else
	ret = do_clone_file_range(src_file.file, off, dst_file, destoff, olen);
#endif  
fdput:
	fdput(src_file);
	return ret;
}

static long ioctl_file_clone_range(struct file *file, void __user *argp)
{
	struct file_clone_range args;
#ifdef MY_ABC_HERE
	int check_compr = 1;
#endif  

	if (copy_from_user(&args, argp, sizeof(args)))
		return -EFAULT;
#ifdef MY_ABC_HERE
	if (!args.src_offset && !args.src_length && !args.dest_offset)
		check_compr = 0;
	return ioctl_file_clone(file, args.src_fd, args.src_offset,
				args.src_length, args.dest_offset, check_compr);
#else
	return ioctl_file_clone(file, args.src_fd, args.src_offset,
				args.src_length, args.dest_offset);
#endif  
}

#ifdef CONFIG_BLOCK

static inline sector_t logical_to_blk(struct inode *inode, loff_t offset)
{
	return (offset >> inode->i_blkbits);
}

static inline loff_t blk_to_logical(struct inode *inode, sector_t blk)
{
	return (blk << inode->i_blkbits);
}

int __generic_block_fiemap(struct inode *inode,
			   struct fiemap_extent_info *fieinfo, loff_t start,
			   loff_t len, get_block_t *get_block)
{
	struct buffer_head map_bh;
	sector_t start_blk, last_blk;
	loff_t isize = i_size_read(inode);
	u64 logical = 0, phys = 0, size = 0;
	u32 flags = FIEMAP_EXTENT_MERGED;
	bool past_eof = false, whole_file = false;
	int ret = 0;

	ret = fiemap_check_flags(fieinfo, FIEMAP_FLAG_SYNC);
	if (ret)
		return ret;

	if (len >= isize) {
		whole_file = true;
		len = isize;
	}

	if (logical_to_blk(inode, len) == 0)
		len = blk_to_logical(inode, 1);

	start_blk = logical_to_blk(inode, start);
	last_blk = logical_to_blk(inode, start + len - 1);

	do {
		 
		memset(&map_bh, 0, sizeof(struct buffer_head));
		map_bh.b_size = len;

		ret = get_block(inode, start_blk, &map_bh, 0);
		if (ret)
			break;

		if (!buffer_mapped(&map_bh)) {
			start_blk++;

			if (!past_eof &&
			    blk_to_logical(inode, start_blk) >= isize)
				past_eof = 1;

			if (past_eof && size) {
				flags = FIEMAP_EXTENT_MERGED|FIEMAP_EXTENT_LAST;
				ret = fiemap_fill_next_extent(fieinfo, logical,
							      phys, size,
							      flags);
			} else if (size) {
				ret = fiemap_fill_next_extent(fieinfo, logical,
							      phys, size, flags);
				size = 0;
			}

			if (start_blk > last_blk || past_eof || ret)
				break;
		} else {
			 
			if (start_blk > last_blk && !whole_file) {
				ret = fiemap_fill_next_extent(fieinfo, logical,
							      phys, size,
							      flags);
				break;
			}

			if (size) {
				ret = fiemap_fill_next_extent(fieinfo, logical,
							      phys, size,
							      flags);
				if (ret)
					break;
			}

			logical = blk_to_logical(inode, start_blk);
			phys = blk_to_logical(inode, map_bh.b_blocknr);
			size = map_bh.b_size;
			flags = FIEMAP_EXTENT_MERGED;

			start_blk += logical_to_blk(inode, size);

			if (!past_eof && logical + size >= isize)
				past_eof = true;
		}
		cond_resched();
		if (fatal_signal_pending(current)) {
			ret = -EINTR;
			break;
		}

	} while (1);

	if (ret == 1)
		ret = 0;

	return ret;
}
EXPORT_SYMBOL(__generic_block_fiemap);

int generic_block_fiemap(struct inode *inode,
			 struct fiemap_extent_info *fieinfo, u64 start,
			 u64 len, get_block_t *get_block)
{
	int ret;
	inode_lock(inode);
	ret = __generic_block_fiemap(inode, fieinfo, start, len, get_block);
	inode_unlock(inode);
	return ret;
}
EXPORT_SYMBOL(generic_block_fiemap);

#endif   

int ioctl_preallocate(struct file *filp, void __user *argp)
{
	struct inode *inode = file_inode(filp);
	struct space_resv sr;

	if (copy_from_user(&sr, argp, sizeof(sr)))
		return -EFAULT;

	switch (sr.l_whence) {
	case SEEK_SET:
		break;
	case SEEK_CUR:
		sr.l_start += filp->f_pos;
		break;
	case SEEK_END:
		sr.l_start += i_size_read(inode);
		break;
	default:
		return -EINVAL;
	}

	return vfs_fallocate(filp, FALLOC_FL_KEEP_SIZE, sr.l_start, sr.l_len);
}

static int file_ioctl(struct file *filp, unsigned int cmd,
		unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	int __user *p = (int __user *)arg;

	switch (cmd) {
	case FIBMAP:
		return ioctl_fibmap(filp, p);
	case FIONREAD:
		return put_user(i_size_read(inode) - filp->f_pos, p);
	case FS_IOC_RESVSP:
	case FS_IOC_RESVSP64:
		return ioctl_preallocate(filp, p);
	}

	return vfs_ioctl(filp, cmd, arg);
}

static int ioctl_fionbio(struct file *filp, int __user *argp)
{
	unsigned int flag;
	int on, error;

	error = get_user(on, argp);
	if (error)
		return error;
	flag = O_NONBLOCK;
#ifdef __sparc__
	 
	if (O_NONBLOCK != O_NDELAY)
		flag |= O_NDELAY;
#endif
	spin_lock(&filp->f_lock);
	if (on)
		filp->f_flags |= flag;
	else
		filp->f_flags &= ~flag;
	spin_unlock(&filp->f_lock);
	return error;
}

#ifdef MY_ABC_HERE
static int archive_check_capable(struct inode *inode)
{
	if((!S_ISDIR(inode->i_mode)) && (!S_ISREG(inode->i_mode)))
		return -EPERM;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!inode->i_sb->s_op->syno_set_sb_archive_ver)
		return -EINVAL;

	if (!inode->i_sb->s_op->syno_get_sb_archive_ver)
		return -EINVAL;

	return 0;
}

static int ioctl_get_version(struct inode *inode, unsigned int *version)
{
	int error;
	struct super_block *sb = inode->i_sb;

	error = archive_check_capable(inode);
	if (error)
		return error;

	error = sb->s_op->syno_get_sb_archive_ver(sb, version);
	return error;
}

static int ioctl_set_version(struct file *filp, unsigned int version)
{
	int error;
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct super_block *sb = inode->i_sb;

	error = archive_check_capable(inode);
	if (error)
		return error;

	if ((UINT_MAX - 1) <= version) {
		return -EPERM;
	}

	error = mnt_want_write_file(filp);
	if (error)
		return error;

	mutex_lock(&sb->s_archive_mutex);
	error = sb->s_op->syno_set_sb_archive_ver(sb, version);
	mutex_unlock(&sb->s_archive_mutex);
	mnt_drop_write_file(filp);
	return error;
}

static int ioctl_inc_version(struct file *filp)
{
	unsigned int ver;
	int error;
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct super_block *sb = inode->i_sb;

	error = archive_check_capable(inode);
	if (error)
		return error;
	error = mnt_want_write_file(filp);
	if (error)
		return error;

	mutex_lock(&sb->s_archive_mutex);
	error = sb->s_op->syno_get_sb_archive_ver(sb, &ver);
	if (error)
		goto unlock;

	if ((UINT_MAX - 1) <= (ver + 1)) {
		error = -EPERM;
		goto unlock;
	}
	error = sb->s_op->syno_set_sb_archive_ver(sb, ver + 1);
unlock:
	mutex_unlock(&sb->s_archive_mutex);
	mnt_drop_write_file(filp);
	return error;
}

static int ioctl_set_file_version(struct file *filp, unsigned int version)
{
	struct inode *inode = filp->f_path.dentry->d_inode;
	int error;

	error = archive_check_capable(inode);
	if (error)
		return error;

	if (!inode->i_op->syno_set_archive_ver)
		return -EINVAL;

	error = mnt_want_write_file(filp);
	if (error)
		return error;

	error = inode->i_op->syno_set_archive_ver(filp->f_path.dentry, version);
	mnt_drop_write_file(filp);
	return error;
}
#ifdef MY_ABC_HERE
static int ioctl_get_bad_version(struct inode *inode, unsigned int *version)
{
	int error;
	struct super_block *sb = inode->i_sb;

	error = archive_check_capable(inode);
	if (error)
		return error;

	if (!sb->s_op->syno_get_sb_archive_ver1)
		return -EINVAL;

	error = inode->i_sb->s_op->syno_get_sb_archive_ver1(sb, version);
	return error;
}

static int ioctl_clear_bad_version(struct file *filp)
{
	int error;
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	unsigned int ver, ver1;

	error = archive_check_capable(inode);
	if (error)
		return error;

	if (!sb->s_op->syno_get_sb_archive_ver1)
		return -EINVAL;
	if (!sb->s_op->syno_set_sb_archive_ver1)
		return -EINVAL;

	error = mnt_want_write_file(filp);
	if (error)
		return error;

	mutex_lock(&sb->s_archive_mutex);
	error = sb->s_op->syno_get_sb_archive_ver(sb, &ver);
	if (error)
		goto unlock;

	error = sb->s_op->syno_get_sb_archive_ver1(sb, &ver1);
	if (error)
		goto unlock;

	error = sb->s_op->syno_set_sb_archive_ver(sb, max(ver, ver1) + 1);
	if (error)
		goto unlock;

	error = sb->s_op->syno_set_sb_archive_ver1(sb, 0);
unlock:
	mutex_unlock(&sb->s_archive_mutex);
	mnt_drop_write_file(filp);
	return error;
}

static int ioctl_set_bad_version(struct file *filp, unsigned int version)
{
	int error;
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct super_block *sb = inode->i_sb;

	error = archive_check_capable(inode);
	if (error)
		return error;

	if (!sb->s_op->syno_set_sb_archive_ver1)
		return -EINVAL;

	error = mnt_want_write_file(filp);
	if (error)
		return error;

	mutex_lock(&sb->s_archive_mutex);
	error = sb->s_op->syno_set_sb_archive_ver1(sb, version);
	mutex_unlock(&sb->s_archive_mutex);
	mnt_drop_write_file(filp);
	return error;
}
#endif  
#endif  

static int ioctl_fioasync(unsigned int fd, struct file *filp,
			  int __user *argp)
{
	unsigned int flag;
	int on, error;

	error = get_user(on, argp);
	if (error)
		return error;
	flag = on ? FASYNC : 0;

	if ((flag ^ filp->f_flags) & FASYNC) {
		if (filp->f_op->fasync)
			 
			error = filp->f_op->fasync(fd, filp, on);
		else
			error = -ENOTTY;
	}
	return error < 0 ? error : 0;
}

static int ioctl_fsfreeze(struct file *filp)
{
	struct super_block *sb = file_inode(filp)->i_sb;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (sb->s_op->freeze_fs == NULL && sb->s_op->freeze_super == NULL)
		return -EOPNOTSUPP;

	if (sb->s_op->freeze_super)
		return sb->s_op->freeze_super(sb);
	return freeze_super(sb);
}

static int ioctl_fsthaw(struct file *filp)
{
	struct super_block *sb = file_inode(filp)->i_sb;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (sb->s_op->thaw_super)
		return sb->s_op->thaw_super(sb);
	return thaw_super(sb);
}

int do_vfs_ioctl(struct file *filp, unsigned int fd, unsigned int cmd,
	     unsigned long arg)
{
	int error = 0;
	int __user *argp = (int __user *)arg;
	struct inode *inode = file_inode(filp);
#ifdef MY_ABC_HERE
	unsigned int ver = 0;
#endif  

	switch (cmd) {
	case FIOCLEX:
		set_close_on_exec(fd, 1);
		break;

	case FIONCLEX:
		set_close_on_exec(fd, 0);
		break;

	case FIONBIO:
		error = ioctl_fionbio(filp, argp);
		break;

	case FIOASYNC:
		error = ioctl_fioasync(fd, filp, argp);
		break;

	case FIOQSIZE:
		if (S_ISDIR(inode->i_mode) || S_ISREG(inode->i_mode) ||
		    S_ISLNK(inode->i_mode)) {
			loff_t res = inode_get_bytes(inode);
			error = copy_to_user(argp, &res, sizeof(res)) ?
					-EFAULT : 0;
		} else
			error = -ENOTTY;
		break;

	case FIFREEZE:
		error = ioctl_fsfreeze(filp);
		break;

	case FITHAW:
		error = ioctl_fsthaw(filp);
		break;

	case FS_IOC_FIEMAP:
		return ioctl_fiemap(filp, arg);

	case FIGETBSZ:
		return put_user(inode->i_sb->s_blocksize, argp);

#ifdef MY_ABC_HERE
	case FIGETVERSION:
		error = ioctl_get_version(inode, &ver);
		if (!error) {
			error = put_user(ver, (unsigned int __user *)arg) ? -EFAULT : 0;
		}
		break;
	case FISETVERSION:
		if ((error = get_user(ver, (unsigned int __user *)arg)) != 0)
			break;
		error = ioctl_set_version(filp, ver);
		break;
	case FIINCVERSION:
		error = ioctl_inc_version(filp);
		break;
	case FISETFILEVERSION:
		if ((error = get_user(ver, (unsigned int __user *)arg)) != 0)
			break;
		error = ioctl_set_file_version(filp, ver);
		break;
#ifdef MY_ABC_HERE
	case FIGETBADVERSION:
		error = ioctl_get_bad_version(inode, &ver);
		if (!error) {
			error = put_user(ver, (unsigned int __user *)arg) ? -EFAULT : 0;
		}
		break;
	case FICLEARBADVERSION:
		error = ioctl_clear_bad_version(filp);
		break;
	case FISETBADVERSION:
		if ((error = get_user(ver, (unsigned int __user *)arg)) != 0)
			break;
		error = ioctl_set_bad_version(filp, ver);
		break;
#endif  
#endif  

	case FICLONE:
#ifdef MY_ABC_HERE
		return ioctl_file_clone(filp, arg, 0, 0, 0, 1);
#else
		return ioctl_file_clone(filp, arg, 0, 0, 0);
#endif  

	case FICLONERANGE:
		return ioctl_file_clone_range(filp, argp);

	default:
		if (S_ISREG(inode->i_mode))
			error = file_ioctl(filp, cmd, arg);
		else
			error = vfs_ioctl(filp, cmd, arg);
		break;
	}
	return error;
}

SYSCALL_DEFINE3(ioctl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
{
	int error;
	struct fd f = fdget(fd);

	if (!f.file)
		return -EBADF;
	error = security_file_ioctl(f.file, cmd, arg);
	if (!error)
		error = do_vfs_ioctl(f.file, fd, cmd, arg);
	fdput(f);
	return error;
}
