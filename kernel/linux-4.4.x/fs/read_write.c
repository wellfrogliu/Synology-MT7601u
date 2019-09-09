#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/slab.h> 
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/fsnotify.h>
#include <linux/security.h>
#include <linux/export.h>
#include <linux/syscalls.h>
#include <linux/pagemap.h>
#include <linux/splice.h>
#include <linux/compat.h>
#include <linux/mount.h>
#include "internal.h"

#include <asm/uaccess.h>
#include <asm/unistd.h>
#ifdef CONFIG_SENDFILE_PATCH
    #include <net/sock.h>
#endif  

#ifdef MY_ABC_HERE
#include <linux/synolib.h>
#endif  

#ifdef MY_ABC_HERE
#include <linux/backing-dev.h>
DEFINE_SPINLOCK(aggregate_lock);
#endif  

typedef ssize_t (*io_fn_t)(struct file *, char __user *, size_t, loff_t *);
typedef ssize_t (*iter_fn_t)(struct kiocb *, struct iov_iter *);

const struct file_operations generic_ro_fops = {
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
	.mmap		= generic_file_readonly_mmap,
	.splice_read	= generic_file_splice_read,
};

EXPORT_SYMBOL(generic_ro_fops);

static inline int unsigned_offsets(struct file *file)
{
	return file->f_mode & FMODE_UNSIGNED_OFFSET;
}

loff_t vfs_setpos(struct file *file, loff_t offset, loff_t maxsize)
{
	if (offset < 0 && !unsigned_offsets(file))
		return -EINVAL;
	if (offset > maxsize)
		return -EINVAL;

	if (offset != file->f_pos) {
		file->f_pos = offset;
		file->f_version = 0;
	}
	return offset;
}
EXPORT_SYMBOL(vfs_setpos);

loff_t
generic_file_llseek_size(struct file *file, loff_t offset, int whence,
		loff_t maxsize, loff_t eof)
{
	switch (whence) {
	case SEEK_END:
		offset += eof;
		break;
	case SEEK_CUR:
		 
		if (offset == 0)
			return file->f_pos;
		 
		spin_lock(&file->f_lock);
		offset = vfs_setpos(file, file->f_pos + offset, maxsize);
		spin_unlock(&file->f_lock);
		return offset;
	case SEEK_DATA:
		 
		if (offset >= eof)
			return -ENXIO;
		break;
	case SEEK_HOLE:
		 
		if (offset >= eof)
			return -ENXIO;
		offset = eof;
		break;
	}

	return vfs_setpos(file, offset, maxsize);
}
EXPORT_SYMBOL(generic_file_llseek_size);

loff_t generic_file_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;

	return generic_file_llseek_size(file, offset, whence,
					inode->i_sb->s_maxbytes,
					i_size_read(inode));
}
EXPORT_SYMBOL(generic_file_llseek);

loff_t fixed_size_llseek(struct file *file, loff_t offset, int whence, loff_t size)
{
	switch (whence) {
	case SEEK_SET: case SEEK_CUR: case SEEK_END:
		return generic_file_llseek_size(file, offset, whence,
						size, size);
	default:
		return -EINVAL;
	}
}
EXPORT_SYMBOL(fixed_size_llseek);

loff_t noop_llseek(struct file *file, loff_t offset, int whence)
{
	return file->f_pos;
}
EXPORT_SYMBOL(noop_llseek);

loff_t no_llseek(struct file *file, loff_t offset, int whence)
{
	return -ESPIPE;
}
EXPORT_SYMBOL(no_llseek);

loff_t default_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file_inode(file);
	loff_t retval;

	inode_lock(inode);
	switch (whence) {
		case SEEK_END:
			offset += i_size_read(inode);
			break;
		case SEEK_CUR:
			if (offset == 0) {
				retval = file->f_pos;
				goto out;
			}
			offset += file->f_pos;
			break;
		case SEEK_DATA:
			 
			if (offset >= inode->i_size) {
				retval = -ENXIO;
				goto out;
			}
			break;
		case SEEK_HOLE:
			 
			if (offset >= inode->i_size) {
				retval = -ENXIO;
				goto out;
			}
			offset = inode->i_size;
			break;
	}
	retval = -EINVAL;
	if (offset >= 0 || unsigned_offsets(file)) {
		if (offset != file->f_pos) {
			file->f_pos = offset;
			file->f_version = 0;
		}
		retval = offset;
	}
out:
	inode_unlock(inode);
	return retval;
}
EXPORT_SYMBOL(default_llseek);

loff_t vfs_llseek(struct file *file, loff_t offset, int whence)
{
	loff_t (*fn)(struct file *, loff_t, int);

	fn = no_llseek;
	if (file->f_mode & FMODE_LSEEK) {
		if (file->f_op->llseek)
			fn = file->f_op->llseek;
	}
	return fn(file, offset, whence);
}
EXPORT_SYMBOL(vfs_llseek);

static inline struct fd fdget_pos(int fd)
{
	return __to_fd(__fdget_pos(fd));
}

static inline void fdput_pos(struct fd f)
{
	if (f.flags & FDPUT_POS_UNLOCK)
		mutex_unlock(&f.file->f_pos_lock);
	fdput(f);
}

SYSCALL_DEFINE3(lseek, unsigned int, fd, off_t, offset, unsigned int, whence)
{
	off_t retval;
	struct fd f = fdget_pos(fd);
	if (!f.file)
		return -EBADF;

	retval = -EINVAL;
	if (whence <= SEEK_MAX) {
		loff_t res = vfs_llseek(f.file, offset, whence);
		retval = res;
		if (res != (loff_t)retval)
			retval = -EOVERFLOW;	 
	}
	fdput_pos(f);
	return retval;
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE3(lseek, unsigned int, fd, compat_off_t, offset, unsigned int, whence)
{
	return sys_lseek(fd, offset, whence);
}
#endif

#ifdef __ARCH_WANT_SYS_LLSEEK
SYSCALL_DEFINE5(llseek, unsigned int, fd, unsigned long, offset_high,
		unsigned long, offset_low, loff_t __user *, result,
		unsigned int, whence)
{
	int retval;
	struct fd f = fdget_pos(fd);
	loff_t offset;

	if (!f.file)
		return -EBADF;

	retval = -EINVAL;
	if (whence > SEEK_MAX)
		goto out_putf;

	offset = vfs_llseek(f.file, ((loff_t) offset_high << 32) | offset_low,
			whence);

	retval = (int)offset;
	if (offset >= 0) {
		retval = -EFAULT;
		if (!copy_to_user(result, &offset, sizeof(offset)))
			retval = 0;
	}
out_putf:
	fdput_pos(f);
	return retval;
}
#endif

ssize_t vfs_iter_read(struct file *file, struct iov_iter *iter, loff_t *ppos)
{
	struct kiocb kiocb;
	ssize_t ret;

	if (!file->f_op->read_iter)
		return -EINVAL;

	init_sync_kiocb(&kiocb, file);
	kiocb.ki_pos = *ppos;

	iter->type |= READ;
	ret = file->f_op->read_iter(&kiocb, iter);
	BUG_ON(ret == -EIOCBQUEUED);
	if (ret > 0)
		*ppos = kiocb.ki_pos;
	return ret;
}
EXPORT_SYMBOL(vfs_iter_read);

ssize_t vfs_iter_write(struct file *file, struct iov_iter *iter, loff_t *ppos)
{
	struct kiocb kiocb;
	ssize_t ret;

	if (!file->f_op->write_iter)
		return -EINVAL;

	init_sync_kiocb(&kiocb, file);
	kiocb.ki_pos = *ppos;

	iter->type |= WRITE;
	ret = file->f_op->write_iter(&kiocb, iter);
	BUG_ON(ret == -EIOCBQUEUED);
	if (ret > 0)
		*ppos = kiocb.ki_pos;
	return ret;
}
EXPORT_SYMBOL(vfs_iter_write);

int rw_verify_area(int read_write, struct file *file, const loff_t *ppos, size_t count)
{
	struct inode *inode;
	loff_t pos;
	int retval = -EINVAL;

	inode = file_inode(file);
	if (unlikely((ssize_t) count < 0))
		return retval;
	pos = *ppos;
	if (unlikely(pos < 0)) {
		if (!unsigned_offsets(file))
			return retval;
		if (count >= -pos)  
			return -EOVERFLOW;
	} else if (unlikely((loff_t) (pos + count) < 0)) {
		if (!unsigned_offsets(file))
			return retval;
	}

	if (unlikely(inode->i_flctx && mandatory_lock(inode))) {
		retval = locks_mandatory_area(inode, file, pos, pos + count - 1,
				read_write == READ ? F_RDLCK : F_WRLCK);
		if (retval < 0)
			return retval;
	}
	retval = security_file_permission(file,
				read_write == READ ? MAY_READ : MAY_WRITE);
	if (retval)
		return retval;
	return count > MAX_RW_COUNT ? MAX_RW_COUNT : count;
}

static ssize_t new_sync_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
	struct iovec iov = { .iov_base = buf, .iov_len = len };
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t ret;

	init_sync_kiocb(&kiocb, filp);
	kiocb.ki_pos = *ppos;
	iov_iter_init(&iter, READ, &iov, 1, len);

	ret = filp->f_op->read_iter(&kiocb, &iter);
	BUG_ON(ret == -EIOCBQUEUED);
	*ppos = kiocb.ki_pos;
	return ret;
}

ssize_t __vfs_read(struct file *file, char __user *buf, size_t count,
		   loff_t *pos)
{
	if (file->f_op->read)
		return file->f_op->read(file, buf, count, pos);
	else if (file->f_op->read_iter)
		return new_sync_read(file, buf, count, pos);
	else
		return -EINVAL;
}
EXPORT_SYMBOL(__vfs_read);

ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret;

	if (!(file->f_mode & FMODE_READ))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_READ))
		return -EINVAL;
	if (unlikely(!access_ok(VERIFY_WRITE, buf, count)))
		return -EFAULT;

	ret = rw_verify_area(READ, file, pos, count);
	if (ret >= 0) {
		count = ret;
		ret = __vfs_read(file, buf, count, pos);
		if (ret > 0) {
			fsnotify_access(file);
			add_rchar(current, ret);
		}
		inc_syscr(current);
	}

	return ret;
}

EXPORT_SYMBOL(vfs_read);

static ssize_t new_sync_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
	struct iovec iov = { .iov_base = (void __user *)buf, .iov_len = len };
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t ret;

	init_sync_kiocb(&kiocb, filp);
	kiocb.ki_pos = *ppos;
	iov_iter_init(&iter, WRITE, &iov, 1, len);

	ret = filp->f_op->write_iter(&kiocb, &iter);
	BUG_ON(ret == -EIOCBQUEUED);
	if (ret > 0)
		*ppos = kiocb.ki_pos;
	return ret;
}

ssize_t __vfs_write(struct file *file, const char __user *p, size_t count,
		    loff_t *pos)
{
	if (file->f_op->write)
		return file->f_op->write(file, p, count, pos);
	else if (file->f_op->write_iter)
		return new_sync_write(file, p, count, pos);
	else
		return -EINVAL;
}
EXPORT_SYMBOL(__vfs_write);

#ifdef CONFIG_AUFS_FHSM
vfs_readf_t vfs_readf(struct file *file)
{
	const struct file_operations *fop = file->f_op;

	if (fop->read)
		return fop->read;
	if (fop->read_iter)
		return new_sync_read;
	return ERR_PTR(-ENOSYS);
}
EXPORT_SYMBOL_GPL(vfs_readf);
#endif  

#ifdef CONFIG_AUFS_FHSM
vfs_writef_t vfs_writef(struct file *file)
{
	const struct file_operations *fop = file->f_op;

	if (fop->write)
		return fop->write;
	if (fop->write_iter)
		return new_sync_write;
	return ERR_PTR(-ENOSYS);
}
EXPORT_SYMBOL_GPL(vfs_writef);
#endif  

ssize_t __kernel_write(struct file *file, const char *buf, size_t count, loff_t *pos)
{
	mm_segment_t old_fs;
	const char __user *p;
	ssize_t ret;

	if (!(file->f_mode & FMODE_CAN_WRITE))
		return -EINVAL;

	old_fs = get_fs();
	set_fs(get_ds());
	p = (__force const char __user *)buf;
	if (count > MAX_RW_COUNT)
		count =  MAX_RW_COUNT;
	ret = __vfs_write(file, p, count, pos);
	set_fs(old_fs);
	if (ret > 0) {
		fsnotify_modify(file);
		add_wchar(current, ret);
	}
	inc_syscw(current);
	return ret;
}

EXPORT_SYMBOL(__kernel_write);

ssize_t vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret;

	if (!(file->f_mode & FMODE_WRITE))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_WRITE))
		return -EINVAL;
	if (unlikely(!access_ok(VERIFY_READ, buf, count)))
		return -EFAULT;

	ret = rw_verify_area(WRITE, file, pos, count);
	if (ret >= 0) {
		count = ret;
		file_start_write(file);
		ret = __vfs_write(file, buf, count, pos);
		if (ret > 0) {
			fsnotify_modify(file);
			add_wchar(current, ret);
		}
		inc_syscw(current);
		file_end_write(file);
	}

	return ret;
}

EXPORT_SYMBOL(vfs_write);

static inline loff_t file_pos_read(struct file *file)
{
	return file->f_pos;
}

static inline void file_pos_write(struct file *file, loff_t pos)
{
	file->f_pos = pos;
}

SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

#ifdef MY_ABC_HERE
	if (0 < gSynoHibernationLogLevel) {
		syno_do_hibernation_fd_log(fd);
	}
#endif  

	if (f.file) {
		loff_t pos = file_pos_read(f.file);
		ret = vfs_read(f.file, buf, count, &pos);
		if (ret >= 0)
			file_pos_write(f.file, pos);
		fdput_pos(f);
	}
	return ret;
}

SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf,
		size_t, count)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

#ifdef MY_ABC_HERE
	if (0 < gSynoHibernationLogLevel) {
		syno_do_hibernation_fd_log(fd);
	}
#endif  

	if (f.file) {
		loff_t pos = file_pos_read(f.file);
		ret = vfs_write(f.file, buf, count, &pos);
		if (ret >= 0)
			file_pos_write(f.file, pos);
		fdput_pos(f);
	}

	return ret;
}

SYSCALL_DEFINE4(pread64, unsigned int, fd, char __user *, buf,
			size_t, count, loff_t, pos)
{
	struct fd f;
	ssize_t ret = -EBADF;

	if (pos < 0)
		return -EINVAL;

	f = fdget(fd);
	if (f.file) {
		ret = -ESPIPE;
		if (f.file->f_mode & FMODE_PREAD)
			ret = vfs_read(f.file, buf, count, &pos);
		fdput(f);
	}

	return ret;
}

SYSCALL_DEFINE4(pwrite64, unsigned int, fd, const char __user *, buf,
			 size_t, count, loff_t, pos)
{
	struct fd f;
	ssize_t ret = -EBADF;

	if (pos < 0)
		return -EINVAL;

	f = fdget(fd);
	if (f.file) {
		ret = -ESPIPE;
		if (f.file->f_mode & FMODE_PWRITE)  
			ret = vfs_write(f.file, buf, count, &pos);
		fdput(f);
	}

	return ret;
}

unsigned long iov_shorten(struct iovec *iov, unsigned long nr_segs, size_t to)
{
	unsigned long seg = 0;
	size_t len = 0;

	while (seg < nr_segs) {
		seg++;
		if (len + iov->iov_len >= to) {
			iov->iov_len = to - len;
			break;
		}
		len += iov->iov_len;
		iov++;
	}
	return seg;
}
EXPORT_SYMBOL(iov_shorten);

static ssize_t do_iter_readv_writev(struct file *filp, struct iov_iter *iter,
		loff_t *ppos, iter_fn_t fn)
{
	struct kiocb kiocb;
	ssize_t ret;

	init_sync_kiocb(&kiocb, filp);
	kiocb.ki_pos = *ppos;

	ret = fn(&kiocb, iter);
	BUG_ON(ret == -EIOCBQUEUED);
	*ppos = kiocb.ki_pos;
	return ret;
}

static ssize_t do_loop_readv_writev(struct file *filp, struct iov_iter *iter,
		loff_t *ppos, io_fn_t fn)
{
	ssize_t ret = 0;

	while (iov_iter_count(iter)) {
		struct iovec iovec = iov_iter_iovec(iter);
		ssize_t nr;

		nr = fn(filp, iovec.iov_base, iovec.iov_len, ppos);

		if (nr < 0) {
			if (!ret)
				ret = nr;
			break;
		}
		ret += nr;
		if (nr != iovec.iov_len)
			break;
		iov_iter_advance(iter, nr);
	}

	return ret;
}

#define vrfy_dir(type) ((type) == READ ? VERIFY_WRITE : VERIFY_READ)

ssize_t rw_copy_check_uvector(int type, const struct iovec __user * uvector,
			      unsigned long nr_segs, unsigned long fast_segs,
			      struct iovec *fast_pointer,
			      struct iovec **ret_pointer)
{
	unsigned long seg;
	ssize_t ret;
	struct iovec *iov = fast_pointer;

	if (nr_segs == 0) {
		ret = 0;
		goto out;
	}

	if (nr_segs > UIO_MAXIOV) {
		ret = -EINVAL;
		goto out;
	}
	if (nr_segs > fast_segs) {
		iov = kmalloc(nr_segs*sizeof(struct iovec), GFP_KERNEL);
		if (iov == NULL) {
			ret = -ENOMEM;
			goto out;
		}
	}
	if (copy_from_user(iov, uvector, nr_segs*sizeof(*uvector))) {
		ret = -EFAULT;
		goto out;
	}

	ret = 0;
	for (seg = 0; seg < nr_segs; seg++) {
		void __user *buf = iov[seg].iov_base;
		ssize_t len = (ssize_t)iov[seg].iov_len;

		if (len < 0) {
			ret = -EINVAL;
			goto out;
		}
		if (type >= 0
		    && unlikely(!access_ok(vrfy_dir(type), buf, len))) {
			ret = -EFAULT;
			goto out;
		}
		if (len > MAX_RW_COUNT - ret) {
			len = MAX_RW_COUNT - ret;
			iov[seg].iov_len = len;
		}
		ret += len;
	}
out:
	*ret_pointer = iov;
	return ret;
}

static ssize_t do_readv_writev(int type, struct file *file,
			       const struct iovec __user * uvector,
			       unsigned long nr_segs, loff_t *pos)
{
	size_t tot_len;
	struct iovec iovstack[UIO_FASTIOV];
	struct iovec *iov = iovstack;
	struct iov_iter iter;
	ssize_t ret;
	io_fn_t fn;
	iter_fn_t iter_fn;

	ret = import_iovec(type, uvector, nr_segs,
			   ARRAY_SIZE(iovstack), &iov, &iter);
	if (ret < 0)
		return ret;

	tot_len = iov_iter_count(&iter);
	if (!tot_len)
		goto out;
	ret = rw_verify_area(type, file, pos, tot_len);
	if (ret < 0)
		goto out;

	if (type == READ) {
		fn = file->f_op->read;
		iter_fn = file->f_op->read_iter;
	} else {
		fn = (io_fn_t)file->f_op->write;
		iter_fn = file->f_op->write_iter;
		file_start_write(file);
	}

	if (iter_fn)
		ret = do_iter_readv_writev(file, &iter, pos, iter_fn);
	else
		ret = do_loop_readv_writev(file, &iter, pos, fn);

	if (type != READ)
		file_end_write(file);

out:
	kfree(iov);
	if ((ret + (type == READ)) > 0) {
		if (type == READ)
			fsnotify_access(file);
		else
			fsnotify_modify(file);
	}
	return ret;
}

ssize_t vfs_readv(struct file *file, const struct iovec __user *vec,
		  unsigned long vlen, loff_t *pos)
{
	if (!(file->f_mode & FMODE_READ))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_READ))
		return -EINVAL;

	return do_readv_writev(READ, file, vec, vlen, pos);
}

EXPORT_SYMBOL(vfs_readv);

ssize_t vfs_writev(struct file *file, const struct iovec __user *vec,
		   unsigned long vlen, loff_t *pos)
{
	if (!(file->f_mode & FMODE_WRITE))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_WRITE))
		return -EINVAL;

	return do_readv_writev(WRITE, file, vec, vlen, pos);
}

EXPORT_SYMBOL(vfs_writev);

SYSCALL_DEFINE3(readv, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

	if (f.file) {
		loff_t pos = file_pos_read(f.file);
		ret = vfs_readv(f.file, vec, vlen, &pos);
		if (ret >= 0)
			file_pos_write(f.file, pos);
		fdput_pos(f);
	}

	if (ret > 0)
		add_rchar(current, ret);
	inc_syscr(current);
	return ret;
}

SYSCALL_DEFINE3(writev, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

	if (f.file) {
		loff_t pos = file_pos_read(f.file);
		ret = vfs_writev(f.file, vec, vlen, &pos);
		if (ret >= 0)
			file_pos_write(f.file, pos);
		fdput_pos(f);
	}

	if (ret > 0)
		add_wchar(current, ret);
	inc_syscw(current);
	return ret;
}

static inline loff_t pos_from_hilo(unsigned long high, unsigned long low)
{
#define HALF_LONG_BITS (BITS_PER_LONG / 2)
	return (((loff_t)high << HALF_LONG_BITS) << HALF_LONG_BITS) | low;
}

SYSCALL_DEFINE5(preadv, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h)
{
	loff_t pos = pos_from_hilo(pos_h, pos_l);
	struct fd f;
	ssize_t ret = -EBADF;

	if (pos < 0)
		return -EINVAL;

	f = fdget(fd);
	if (f.file) {
		ret = -ESPIPE;
		if (f.file->f_mode & FMODE_PREAD)
			ret = vfs_readv(f.file, vec, vlen, &pos);
		fdput(f);
	}

	if (ret > 0)
		add_rchar(current, ret);
	inc_syscr(current);
	return ret;
}

SYSCALL_DEFINE5(pwritev, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h)
{
	loff_t pos = pos_from_hilo(pos_h, pos_l);
	struct fd f;
	ssize_t ret = -EBADF;

	if (pos < 0)
		return -EINVAL;

	f = fdget(fd);
	if (f.file) {
		ret = -ESPIPE;
		if (f.file->f_mode & FMODE_PWRITE)
			ret = vfs_writev(f.file, vec, vlen, &pos);
		fdput(f);
	}

	if (ret > 0)
		add_wchar(current, ret);
	inc_syscw(current);
	return ret;
}

#ifdef CONFIG_COMPAT

static ssize_t compat_do_readv_writev(int type, struct file *file,
			       const struct compat_iovec __user *uvector,
			       unsigned long nr_segs, loff_t *pos)
{
	compat_ssize_t tot_len;
	struct iovec iovstack[UIO_FASTIOV];
	struct iovec *iov = iovstack;
	struct iov_iter iter;
	ssize_t ret;
	io_fn_t fn;
	iter_fn_t iter_fn;

	ret = compat_import_iovec(type, uvector, nr_segs,
				  UIO_FASTIOV, &iov, &iter);
	if (ret < 0)
		return ret;

	tot_len = iov_iter_count(&iter);
	if (!tot_len)
		goto out;
	ret = rw_verify_area(type, file, pos, tot_len);
	if (ret < 0)
		goto out;

	if (type == READ) {
		fn = file->f_op->read;
		iter_fn = file->f_op->read_iter;
	} else {
		fn = (io_fn_t)file->f_op->write;
		iter_fn = file->f_op->write_iter;
		file_start_write(file);
	}

	if (iter_fn)
		ret = do_iter_readv_writev(file, &iter, pos, iter_fn);
	else
		ret = do_loop_readv_writev(file, &iter, pos, fn);

	if (type != READ)
		file_end_write(file);

out:
	kfree(iov);
	if ((ret + (type == READ)) > 0) {
		if (type == READ)
			fsnotify_access(file);
		else
			fsnotify_modify(file);
	}
	return ret;
}

static size_t compat_readv(struct file *file,
			   const struct compat_iovec __user *vec,
			   unsigned long vlen, loff_t *pos)
{
	ssize_t ret = -EBADF;

	if (!(file->f_mode & FMODE_READ))
		goto out;

	ret = -EINVAL;
	if (!(file->f_mode & FMODE_CAN_READ))
		goto out;

	ret = compat_do_readv_writev(READ, file, vec, vlen, pos);

out:
	if (ret > 0)
		add_rchar(current, ret);
	inc_syscr(current);
	return ret;
}

COMPAT_SYSCALL_DEFINE3(readv, compat_ulong_t, fd,
		const struct compat_iovec __user *,vec,
		compat_ulong_t, vlen)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret;
	loff_t pos;

	if (!f.file)
		return -EBADF;
	pos = f.file->f_pos;
	ret = compat_readv(f.file, vec, vlen, &pos);
	if (ret >= 0)
		f.file->f_pos = pos;
	fdput_pos(f);
	return ret;
}

static long __compat_sys_preadv64(unsigned long fd,
				  const struct compat_iovec __user *vec,
				  unsigned long vlen, loff_t pos)
{
	struct fd f;
	ssize_t ret;

	if (pos < 0)
		return -EINVAL;
	f = fdget(fd);
	if (!f.file)
		return -EBADF;
	ret = -ESPIPE;
	if (f.file->f_mode & FMODE_PREAD)
		ret = compat_readv(f.file, vec, vlen, &pos);
	fdput(f);
	return ret;
}

#ifdef __ARCH_WANT_COMPAT_SYS_PREADV64
COMPAT_SYSCALL_DEFINE4(preadv64, unsigned long, fd,
		const struct compat_iovec __user *,vec,
		unsigned long, vlen, loff_t, pos)
{
	return __compat_sys_preadv64(fd, vec, vlen, pos);
}
#endif

COMPAT_SYSCALL_DEFINE5(preadv, compat_ulong_t, fd,
		const struct compat_iovec __user *,vec,
		compat_ulong_t, vlen, u32, pos_low, u32, pos_high)
{
	loff_t pos = ((loff_t)pos_high << 32) | pos_low;

	return __compat_sys_preadv64(fd, vec, vlen, pos);
}

static size_t compat_writev(struct file *file,
			    const struct compat_iovec __user *vec,
			    unsigned long vlen, loff_t *pos)
{
	ssize_t ret = -EBADF;

	if (!(file->f_mode & FMODE_WRITE))
		goto out;

	ret = -EINVAL;
	if (!(file->f_mode & FMODE_CAN_WRITE))
		goto out;

	ret = compat_do_readv_writev(WRITE, file, vec, vlen, pos);

out:
	if (ret > 0)
		add_wchar(current, ret);
	inc_syscw(current);
	return ret;
}

COMPAT_SYSCALL_DEFINE3(writev, compat_ulong_t, fd,
		const struct compat_iovec __user *, vec,
		compat_ulong_t, vlen)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret;
	loff_t pos;

	if (!f.file)
		return -EBADF;
	pos = f.file->f_pos;
	ret = compat_writev(f.file, vec, vlen, &pos);
	if (ret >= 0)
		f.file->f_pos = pos;
	fdput_pos(f);
	return ret;
}

static long __compat_sys_pwritev64(unsigned long fd,
				   const struct compat_iovec __user *vec,
				   unsigned long vlen, loff_t pos)
{
	struct fd f;
	ssize_t ret;

	if (pos < 0)
		return -EINVAL;
	f = fdget(fd);
	if (!f.file)
		return -EBADF;
	ret = -ESPIPE;
	if (f.file->f_mode & FMODE_PWRITE)
		ret = compat_writev(f.file, vec, vlen, &pos);
	fdput(f);
	return ret;
}

#ifdef __ARCH_WANT_COMPAT_SYS_PWRITEV64
COMPAT_SYSCALL_DEFINE4(pwritev64, unsigned long, fd,
		const struct compat_iovec __user *,vec,
		unsigned long, vlen, loff_t, pos)
{
	return __compat_sys_pwritev64(fd, vec, vlen, pos);
}
#endif

COMPAT_SYSCALL_DEFINE5(pwritev, compat_ulong_t, fd,
		const struct compat_iovec __user *,vec,
		compat_ulong_t, vlen, u32, pos_low, u32, pos_high)
{
	loff_t pos = ((loff_t)pos_high << 32) | pos_low;

	return __compat_sys_pwritev64(fd, vec, vlen, pos);
}
#endif

#ifdef CONFIG_SENDFILE_PATCH
extern ssize_t generic_splice_from_socket(struct file *file, struct socket *sock,
                                    loff_t *ppos, size_t count, bool ppage);
#endif
static ssize_t do_sendfile(int out_fd, int in_fd, loff_t *ppos,
		  	   size_t count, loff_t max)
{
	struct fd in, out;
	struct inode *in_inode, *out_inode;
	loff_t pos;
	loff_t out_pos;
	ssize_t retval;
	int fl;

#ifdef CONFIG_SENDFILE_PATCH
	 
	int error;
	struct socket *sock = NULL;

	error = -EBADF;
	sock = sockfd_lookup(in_fd, &error);
	if (sock) {
		if (!sock->sk)
			goto done;
		out = fdget(out_fd);

		if (out.file) {
			if (!(out.file->f_mode & FMODE_WRITE))
				goto done;
			 
			if (out.file->f_op->splice_from_socket)
				error = (int)out.file->f_op->splice_from_socket(out.file, sock, ppos, count, false);
			else
				 
				error = (int)generic_splice_from_socket(out.file, sock, ppos, count, true);
		}
done:
		if(out.file)
			fdput(out);
		fput(sock->file);
		return (ssize_t)error;
	}
#endif

	retval = -EBADF;
	in = fdget(in_fd);
	if (!in.file)
		goto out;
	if (!(in.file->f_mode & FMODE_READ))
		goto fput_in;
	retval = -ESPIPE;
	if (!ppos) {
		pos = in.file->f_pos;
	} else {
		pos = *ppos;
		if (!(in.file->f_mode & FMODE_PREAD))
			goto fput_in;
	}
	retval = rw_verify_area(READ, in.file, &pos, count);
	if (retval < 0)
		goto fput_in;
	count = retval;

	retval = -EBADF;
	out = fdget(out_fd);
	if (!out.file)
		goto fput_in;
	if (!(out.file->f_mode & FMODE_WRITE))
		goto fput_out;
	retval = -EINVAL;
	in_inode = file_inode(in.file);
	out_inode = file_inode(out.file);
	out_pos = out.file->f_pos;
	retval = rw_verify_area(WRITE, out.file, &out_pos, count);
	if (retval < 0)
		goto fput_out;
	count = retval;

	if (!max)
		max = min(in_inode->i_sb->s_maxbytes, out_inode->i_sb->s_maxbytes);

	if (unlikely(pos + count > max)) {
		retval = -EOVERFLOW;
		if (pos >= max)
			goto fput_out;
		count = max - pos;
	}

	fl = 0;
#if 0
	 
	if (in.file->f_flags & O_NONBLOCK)
		fl = SPLICE_F_NONBLOCK;
#endif
	file_start_write(out.file);
	retval = do_splice_direct(in.file, &pos, out.file, &out_pos, count, fl);
	file_end_write(out.file);

	if (retval > 0) {
		add_rchar(current, retval);
		add_wchar(current, retval);
		fsnotify_access(in.file);
		fsnotify_modify(out.file);
		out.file->f_pos = out_pos;
		if (ppos)
			*ppos = pos;
		else
			in.file->f_pos = pos;
	}

	inc_syscr(current);
	inc_syscw(current);
	if (pos > max)
		retval = -EOVERFLOW;

fput_out:
	fdput(out);
fput_in:
	fdput(in);
out:
	return retval;
}

SYSCALL_DEFINE4(sendfile, int, out_fd, int, in_fd, off_t __user *, offset, size_t, count)
{
	loff_t pos;
	off_t off;
	ssize_t ret;

	if (offset) {
		if (unlikely(get_user(off, offset)))
			return -EFAULT;
		pos = off;
		ret = do_sendfile(out_fd, in_fd, &pos, count, MAX_NON_LFS);
		if (unlikely(put_user(pos, offset)))
			return -EFAULT;
		return ret;
	}

	return do_sendfile(out_fd, in_fd, NULL, count, 0);
}

SYSCALL_DEFINE4(sendfile64, int, out_fd, int, in_fd, loff_t __user *, offset, size_t, count)
{
	loff_t pos;
	ssize_t ret;

	if (offset) {
		if (unlikely(copy_from_user(&pos, offset, sizeof(loff_t))))
			return -EFAULT;
		ret = do_sendfile(out_fd, in_fd, &pos, count, 0);
		if (unlikely(put_user(pos, offset)))
			return -EFAULT;
		return ret;
	}

	return do_sendfile(out_fd, in_fd, NULL, count, 0);
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE4(sendfile, int, out_fd, int, in_fd,
		compat_off_t __user *, offset, compat_size_t, count)
{
	loff_t pos;
	off_t off;
	ssize_t ret;

	if (offset) {
		if (unlikely(get_user(off, offset)))
			return -EFAULT;
		pos = off;
		ret = do_sendfile(out_fd, in_fd, &pos, count, MAX_NON_LFS);
		if (unlikely(put_user(pos, offset)))
			return -EFAULT;
		return ret;
	}

	return do_sendfile(out_fd, in_fd, NULL, count, 0);
}

COMPAT_SYSCALL_DEFINE4(sendfile64, int, out_fd, int, in_fd,
		compat_loff_t __user *, offset, compat_size_t, count)
{
	loff_t pos;
	ssize_t ret;

	if (offset) {
		if (unlikely(copy_from_user(&pos, offset, sizeof(loff_t))))
			return -EFAULT;
		ret = do_sendfile(out_fd, in_fd, &pos, count, 0);
		if (unlikely(put_user(pos, offset)))
			return -EFAULT;
		return ret;
	}

	return do_sendfile(out_fd, in_fd, NULL, count, 0);
}
#endif

#ifdef MY_ABC_HERE
#ifdef MY_ABC_HERE
int aggregate_fd = -1;
atomic_t syno_aggregate_recvfile_count = ATOMIC_INIT(0);

#define SZV_GLUSTERFS "glusterfs"
static int should_do_aggregate(struct file *file, int fd, loff_t pos, loff_t next_offset)
{
	int          blFlush = 0;
	struct file *aggregate_file;
	struct inode *inode;
	static struct file *last_file = NULL;

	if (!file->f_mapping->a_ops->aggregate_write_end)
		return 0;

	inode = file->f_path.dentry->d_inode->i_mapping->host;

	if (!strcmp(inode->i_sb->s_type->name, "ecryptfs"))
		return 0;

	if (0 == strcmp(SZV_GLUSTERFS, inode->i_sb->s_subtype)) {
		return 0;
	}

	spin_lock(&aggregate_lock);
	if (0 == atomic_read(&syno_aggregate_recvfile_count)) {
	 
		if (aggregate_fd == -1 || (fd == aggregate_fd && pos == next_offset && file == last_file)) {
			 
			aggregate_fd = fd;
			last_file = file;
			atomic_inc(&syno_aggregate_recvfile_count);
			inode->aggregate_flag |= AGGREGATE_RECVFILE_DOING;
			spin_unlock(&aggregate_lock);
			return 1;
		}
		 
		aggregate_file = fget(aggregate_fd);
		 
		if (aggregate_file) {
			if (last_file == aggregate_file) {
				atomic_inc(&syno_aggregate_recvfile_count);
				spin_unlock(&aggregate_lock);
				aggregate_recvfile_flush_only(aggregate_file);
				atomic_dec(&syno_aggregate_recvfile_count);
				spin_lock(&aggregate_lock);
			}
			fput(aggregate_file);
		}
		 
		if (0 == atomic_read(&syno_aggregate_recvfile_count) && aggregate_fd == -1) {
			aggregate_fd = fd;
			last_file = file;
			atomic_inc(&syno_aggregate_recvfile_count);
			inode->aggregate_flag |= AGGREGATE_RECVFILE_DOING;
			spin_unlock(&aggregate_lock);
			return 1;
		}
	}
	if (inode->aggregate_flag & AGGREGATE_RECVFILE_DOING) {
		blFlush = 1;
	}
	spin_unlock(&aggregate_lock);

	if (blFlush) {
		flush_aggregate_recvfile(fd);
	}
	return 0;
}

static int generic_write_init_and_checks(struct file* filp, loff_t pos, size_t nbytes)
{
	struct iovec iov = { .iov_base = NULL, .iov_len = nbytes };
	struct kiocb kiocb;
	struct iov_iter iter;

	init_sync_kiocb(&kiocb, filp);
	kiocb.ki_pos = pos;
	iov_iter_init(&iter, WRITE, &iov, 1, nbytes);

	return generic_write_checks(&kiocb, &iter);
}

SYSCALL_DEFINE5(recvfile, int, fd, int, s, loff_t *, offset, size_t, nbytes, size_t *, rwbytes)
{
	int             ret = 0;
	loff_t          pos = 0;                  
	size_t          bytes_received = 0;
	size_t          bytes_written = 0;
	size_t          total_received = 0;
	size_t          total_written = 0;
	struct file    *file = NULL;
	struct socket  *sock = NULL;
	struct inode   *inode = NULL;
	static loff_t   next_offset = 0;
	unsigned short  blAggregate = 0;
	unsigned short  blBufferWrite = 0;

	if (!offset) {
		ret = -EINVAL;
		goto out;
	}

	if (nbytes <= 0) {
		if (nbytes < 0) {
			ret = -EINVAL;
		}
		goto out;
	}

	if(copy_from_user(&pos, offset, sizeof(loff_t))) {
		ret = -EFAULT;
		goto out;
	}

	file = fget(fd);
	if (!file || !(file->f_mode & FMODE_WRITE)) {
		ret = -EBADF;
		goto out;
	}

	sock = sockfd_lookup(s, &ret);
	if((!sock) || ret)
		goto out;

	if(!sock->sk) {
		 
		ret = -EINVAL;
		goto out;
	}

	inode = file->f_path.dentry->d_inode->i_mapping->host;

	mutex_lock(&inode->i_mutex);
	ret = generic_write_init_and_checks(file, pos, nbytes);
	if (ret <= 0) {
		goto out;
	}

	sb_start_write(inode->i_sb);
	 
	current->backing_dev_info = inode_to_bdi(inode);
	ret = file_remove_privs(file);
	if (ret)
		goto out;

	ret = file_update_time(file);
	if (ret)
		goto out;

	blAggregate = should_do_aggregate(file, fd, pos, next_offset);
	blBufferWrite = file->f_op->syno_recvfile?1:0;
	if (unlikely(blAggregate)) {
		do {
			if (blAggregate) {
				ret = do_aggregate_recvfile(file, sock, pos, (nbytes >= MAX_RECVFILE_BUF) ?
							MAX_RECVFILE_BUF : nbytes, &bytes_received, &bytes_written, 0);
				 
				if (inode->aggregate_flag & AGGREGATE_RECVFILE_FLUSH &&
				      !(inode->aggregate_flag & AGGREGATE_RECVFILE_DOING)) {
					next_offset = pos;
					atomic_dec(&syno_aggregate_recvfile_count);
					blAggregate = 0;
				}
			} else {
				ret = do_recvfile(file, sock, pos, (nbytes > MAX_RECVFILE_BUF) ?
						   MAX_RECVFILE_BUF : nbytes, &bytes_received, &bytes_written);
			}
			total_received += bytes_received;
			total_written += bytes_written;
			if (0 >= ret) {
				break;
			}
			nbytes -= bytes_written;
			pos += bytes_written;
		} while(nbytes > 0);
		if (blAggregate) {
			next_offset = pos;
			atomic_dec(&syno_aggregate_recvfile_count);
		}
	} else {
		if (blBufferWrite) {
			do {
				ret = file->f_op->syno_recvfile(file, sock, pos, (nbytes > MAX_RECVFILE_BUF) ?
					   MAX_RECVFILE_BUF : nbytes, &bytes_received, &bytes_written);
				total_received += bytes_received;
				total_written += bytes_written;
				if (0 >= ret) {
					break;
				}
				nbytes -= bytes_written;
				pos += bytes_written;
			} while(nbytes > 0);
		} else {
			do {
				ret = do_recvfile(file, sock, pos, (nbytes > (MAX_RECVFILE_BUF - (pos & (PAGE_CACHE_SIZE - 1)))) ?
					   (MAX_RECVFILE_BUF - (pos & (PAGE_CACHE_SIZE - 1))) : nbytes, &bytes_received, &bytes_written);
				total_received += bytes_received;
				total_written += bytes_written;
				if (0 >= ret) {
					break;
				}
				nbytes -= bytes_written;
				pos += bytes_written;
			} while(nbytes > 0);
		}
	}
	sb_end_write(inode->i_sb);
	current->backing_dev_info = NULL;
	mutex_unlock(&inode->i_mutex);

	if(ret >= 0) {
		fsnotify_modify(file);
		ret = total_written;
	} else if(rwbytes) {
		if (copy_to_user(&rwbytes[0], &total_received, sizeof(size_t))) {
			ret = -ENOMEM;
			goto out;
		}
		if (copy_to_user(&rwbytes[1], &total_written, sizeof(size_t))) {
			ret = -ENOMEM;
			goto out;
		}
	}

out:
	if(file)
		fput(file);
	if(sock)
		fput(sock->file);

	return ret;
}

SYSCALL_DEFINE1(SYNOFlushAggregate, int, fd)
{
	return flush_aggregate_recvfile(fd);
}
#else
SYSCALL_DEFINE5(recvfile, int, fd, int, s, loff_t *, offset, size_t, nbytes, size_t *, rwbytes)
{
	return -EOPNOTSUPP;
}
SYSCALL_DEFINE1(SYNOFlushAggregate, int, fd)
{
	return -EOPNOTSUPP;
}
#endif  
#endif  

ssize_t vfs_copy_file_range(struct file *file_in, loff_t pos_in,
			    struct file *file_out, loff_t pos_out,
			    size_t len, unsigned int flags)
{
	struct inode *inode_in = file_inode(file_in);
	struct inode *inode_out = file_inode(file_out);
	ssize_t ret;

	if (flags != 0)
		return -EINVAL;

	ret = rw_verify_area(READ, file_in, &pos_in, len);
	if (ret >= 0)
		ret = rw_verify_area(WRITE, file_out, &pos_out, len);
	if (ret < 0)
		return ret;

	if (!(file_in->f_mode & FMODE_READ) ||
	    !(file_out->f_mode & FMODE_WRITE) ||
	    (file_out->f_flags & O_APPEND))
		return -EBADF;

	if (inode_in->i_sb != inode_out->i_sb)
		return -EXDEV;

	if (len == 0)
		return 0;

	sb_start_write(inode_out->i_sb);

	if (file_in->f_op->clone_file_range) {
#ifdef MY_ABC_HERE
		if (file_in->f_op->clone_check_compr) {
			ret = file_in->f_op->clone_check_compr(file_in, file_out);
			if (ret) {
				goto skip_clone;
			}
		}
#endif  

		ret = file_in->f_op->clone_file_range(file_in, pos_in,
				file_out, pos_out, len);
		if (ret == 0) {
			ret = len;
			goto done;
		}
	}
#ifdef MY_ABC_HERE
skip_clone:
#endif  

	if (file_out->f_op->copy_file_range) {
		ret = file_out->f_op->copy_file_range(file_in, pos_in, file_out,
						      pos_out, len, flags);
		if (ret != -EOPNOTSUPP)
			goto done;
	}

	ret = do_splice_direct(file_in, &pos_in, file_out, &pos_out,
			len > MAX_RW_COUNT ? MAX_RW_COUNT : len, 0);

done:
	if (ret > 0) {
		fsnotify_access(file_in);
		add_rchar(current, ret);
		fsnotify_modify(file_out);
		add_wchar(current, ret);
	}

	inc_syscr(current);
	inc_syscw(current);

	sb_end_write(inode_out->i_sb);

	return ret;
}
EXPORT_SYMBOL(vfs_copy_file_range);

SYSCALL_DEFINE6(copy_file_range, int, fd_in, loff_t __user *, off_in,
		int, fd_out, loff_t __user *, off_out,
		size_t, len, unsigned int, flags)
{
	loff_t pos_in;
	loff_t pos_out;
	struct fd f_in;
	struct fd f_out;
	ssize_t ret = -EBADF;

	f_in = fdget(fd_in);
	if (!f_in.file)
		goto out2;

	f_out = fdget(fd_out);
	if (!f_out.file)
		goto out1;

	ret = -EFAULT;
	if (off_in) {
		if (copy_from_user(&pos_in, off_in, sizeof(loff_t)))
			goto out;
	} else {
		pos_in = f_in.file->f_pos;
	}

	if (off_out) {
		if (copy_from_user(&pos_out, off_out, sizeof(loff_t)))
			goto out;
	} else {
		pos_out = f_out.file->f_pos;
	}

	ret = vfs_copy_file_range(f_in.file, pos_in, f_out.file, pos_out, len,
				  flags);
	if (ret > 0) {
		pos_in += ret;
		pos_out += ret;

		if (off_in) {
			if (copy_to_user(off_in, &pos_in, sizeof(loff_t)))
				ret = -EFAULT;
		} else {
			f_in.file->f_pos = pos_in;
		}

		if (off_out) {
			if (copy_to_user(off_out, &pos_out, sizeof(loff_t)))
				ret = -EFAULT;
		} else {
			f_out.file->f_pos = pos_out;
		}
	}

out:
	fdput(f_out);
out1:
	fdput(f_in);
out2:
	return ret;
}

static int clone_verify_area(struct file *file, loff_t pos, u64 len, bool write)
{
	struct inode *inode = file_inode(file);

	if (unlikely(pos < 0))
		return -EINVAL;

	 if (unlikely((loff_t) (pos + len) < 0))
		return -EINVAL;

	if (unlikely(inode->i_flctx && mandatory_lock(inode))) {
		loff_t end = len ? pos + len - 1 : OFFSET_MAX;
		int retval;

		retval = locks_mandatory_area(inode, file, pos, end,
				write ? F_WRLCK : F_RDLCK);
		if (retval < 0)
			return retval;
	}

	return security_file_permission(file, write ? MAY_WRITE : MAY_READ);
}

#ifdef MY_ABC_HERE
int vfs_clone_file_range(struct file *file_in, loff_t pos_in,
		struct file *file_out, loff_t pos_out, u64 len, int check_compr)
#else
int vfs_clone_file_range(struct file *file_in, loff_t pos_in,
		struct file *file_out, loff_t pos_out, u64 len)
#endif  
{
	struct inode *inode_in = file_inode(file_in);
	struct inode *inode_out = file_inode(file_out);
	int ret;

	if (S_ISDIR(inode_in->i_mode) || S_ISDIR(inode_out->i_mode))
		return -EISDIR;
	if (!S_ISREG(inode_in->i_mode) || !S_ISREG(inode_out->i_mode))
		return -EINVAL;

	if (inode_in->i_sb != inode_out->i_sb)
		return -EXDEV;

	if (!(file_in->f_mode & FMODE_READ) ||
	    !(file_out->f_mode & FMODE_WRITE) ||
	    (file_out->f_flags & O_APPEND))
		return -EBADF;

	if (!file_in->f_op->clone_file_range)
		return -EOPNOTSUPP;

	ret = clone_verify_area(file_in, pos_in, len, false);
	if (ret)
		return ret;

	ret = clone_verify_area(file_out, pos_out, len, true);
	if (ret)
		return ret;

	if (pos_in + len > i_size_read(inode_in))
		return -EINVAL;

#ifdef MY_ABC_HERE
	if (check_compr && file_in->f_op->clone_check_compr) {
		ret = file_in->f_op->clone_check_compr(file_in, file_out);
		if (ret) {
			return ret;
		}
	}
#endif  

	ret = file_in->f_op->clone_file_range(file_in, pos_in,
			file_out, pos_out, len);
	if (!ret) {
		fsnotify_access(file_in);
		fsnotify_modify(file_out);
	}

	return ret;
}
EXPORT_SYMBOL(vfs_clone_file_range);
