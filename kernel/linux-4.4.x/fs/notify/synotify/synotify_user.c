#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#ifdef MY_ABC_HERE
#include <linux/syscalls.h>
#endif  
#ifdef MY_ABC_HERE
#include <linux/file.h>
#include <linux/fs.h>  
#include <linux/fsnotify_backend.h>
#include <linux/idr.h>
#include <linux/init.h>  
#include <linux/synotify.h>
#include <linux/kernel.h>  
#include <linux/namei.h>  
#include <linux/sched.h>  
#include <linux/slab.h>  
#include <linux/types.h>
#include <linux/anon_inodes.h>
#include <linux/uaccess.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/mount.h>  

#include <asm/ioctls.h>

#include "synotify.h"

#define SYNOTIFY_DEFAULT_MAX_EVENTS	16384  
#define SYNOTIFY_DEFAULT_MAX_WATCHERS	8192  
#define SYNOTIFY_DEFAULT_MAX_INSTANCES	128  

extern const struct fsnotify_ops synotify_fsnotify_ops;

static struct kmem_cache *synotify_mark_cache __read_mostly;

static int round_event_name_len(struct fsnotify_event *fsn_event)
{
	struct synotify_event_info *event;

	event = SYNOTIFY_E(fsn_event);
	if (!event->full_name_len)
		return 0;
	return roundup(event->full_name_len + 1, sizeof(struct synotify_event));
}

static struct fsnotify_event *get_one_event(struct fsnotify_group *group,
					    size_t count)
{
	size_t event_size = sizeof(struct synotify_event);
	struct fsnotify_event *event;

	BUG_ON(!mutex_is_locked(&group->notification_mutex));

	pr_debug("%s: group=%p count=%zd\n", __func__, group, count);

	if (fsnotify_notify_queue_is_empty(group))
		return NULL;

	event = fsnotify_peek_first_event(group);

	event_size += round_event_name_len(event);
	if (event_size > count)
		return ERR_PTR(-EINVAL);

	return fsnotify_remove_first_event(group);
}

static inline u32 synotify_mask_to_arg(__u32 mask)
{
	return mask & SYNO_ALL_EVENTS;
}

static ssize_t copy_event_to_user(struct fsnotify_group *group,
				  struct fsnotify_event *fsn_event,
				  char __user *buf)
{
	struct synotify_event_info *event;
	struct synotify_event synotify_event;

	size_t event_size = sizeof(struct synotify_event);
	size_t name_len = 0;

	pr_debug("%s: group=%p event=%p\n", __func__, group, fsn_event);

	event = SYNOTIFY_E(fsn_event);
	 
	name_len = round_event_name_len(fsn_event);
	synotify_event.len = name_len;
	synotify_event.mask = synotify_mask_to_arg(fsn_event->mask);
	synotify_event.cookie = event->sync_cookie;

	if (copy_to_user(buf, &synotify_event, event_size))
		return -EFAULT;

	buf += event_size;

	if (name_len) {
		unsigned int len_to_zero = name_len - event->full_name_len;
		 
		if (copy_to_user(buf, event->full_name, event->full_name_len))
			return -EFAULT;
		buf += event->full_name_len;

		if (clear_user(buf, len_to_zero))
			return -EFAULT;
		buf += len_to_zero;
		event_size += name_len;
	}

	return event_size;
}

static unsigned int synotify_poll(struct file *file, poll_table *wait)
{
	struct fsnotify_group *group = file->private_data;
	int ret = 0;

	poll_wait(file, &group->notification_waitq, wait);
	mutex_lock(&group->notification_mutex);
	if (!fsnotify_notify_queue_is_empty(group))
		ret = POLLIN | POLLRDNORM;
	mutex_unlock(&group->notification_mutex);

	return ret;
}

static ssize_t synotify_read(struct file *file, char __user *buf,
			     size_t count, loff_t *pos)
{
	struct fsnotify_group *group;
	struct fsnotify_event *kevent;
	char __user *start;
	int ret;
	DEFINE_WAIT_FUNC(wait, woken_wake_function);

	start = buf;
	group = file->private_data;

	add_wait_queue(&group->notification_waitq, &wait);
	while (1) {
		mutex_lock(&group->notification_mutex);
		kevent = get_one_event(group, count);
		mutex_unlock(&group->notification_mutex);

		pr_debug("%s: group=%p kevent=%p\n", __func__, group, kevent);

		if (kevent) {
			ret = PTR_ERR(kevent);
			if (IS_ERR(kevent))
				break;
			ret = copy_event_to_user(group, kevent, buf);
			fsnotify_destroy_event(group, kevent);
			if (ret < 0)
				break;
			buf += ret;
			count -= ret;
			continue;
		}

		ret = -EAGAIN;
		if (file->f_flags & O_NONBLOCK)
			break;
		ret = -ERESTARTSYS;
		if (signal_pending(current))
			break;

		if (start != buf)
			break;

		wait_woken(&wait, TASK_INTERRUPTIBLE, MAX_SCHEDULE_TIMEOUT);
	}
	remove_wait_queue(&group->notification_waitq, &wait);

	if (start != buf && ret != -EFAULT)
		ret = buf - start;
	return ret;
}

static int synotify_release(struct inode *ignored, struct file *file)
{
	struct fsnotify_group *group = file->private_data;

	pr_debug("%s: group=%p\n", __func__, group);

	fsnotify_destroy_group(group);

	return 0;
}

static long synotify_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct fsnotify_group *group;
	struct fsnotify_event *fsn_event;
	void __user *p;
	int ret = -ENOTTY;
	size_t send_len = 0;

	group = file->private_data;
	p = (void __user *) arg;

	pr_debug("%s: group=%p cmd=%u\n", __func__, group, cmd);

	switch (cmd) {
	case FIONREAD:
		mutex_lock(&group->notification_mutex);
		list_for_each_entry(fsn_event, &group->notification_list, list) {
			send_len += sizeof(struct synotify_event);
			send_len += round_event_name_len(fsn_event);
		}
		mutex_unlock(&group->notification_mutex);
		ret = put_user(send_len, (int __user *) p);
		break;
	}

	return ret;
}

static const struct file_operations synotify_fops = {
	.poll		= synotify_poll,
	.read		= synotify_read,
	.fasync		= NULL,
	.release	= synotify_release,
	.unlocked_ioctl	= synotify_ioctl,
	.compat_ioctl	= synotify_ioctl,
	.llseek		= noop_llseek,
};

static void synotify_free_mark(struct fsnotify_mark *fsn_mark)
{
	kmem_cache_free(synotify_mark_cache, fsn_mark);
}

static int synotify_find_path(const char __user *filename,
			      struct path *path, unsigned int flags)
{
	int error;

	pr_debug("%s: filename=%p flags=%x\n", __func__, filename, flags);

	error = user_path_at(AT_FDCWD, filename, flags, path);
	if (error)
		return error;
	 
	error = inode_permission(path->dentry->d_inode, MAY_READ);
	if (error)
		path_put(path);
	return error;
}

static __u32 synotify_mark_remove_from_mask(struct fsnotify_mark *fsn_mark,
					    __u32 mask, struct fsnotify_group *group, int *destroy)
{
	__u32 oldmask;
	__u32 setmask;

	setmask = mask & ~SYNO_DONT_FOLLOW;

	spin_lock(&fsn_mark->lock);

	oldmask = fsn_mark->mask;
	fsnotify_set_mark_mask_locked(fsn_mark, (oldmask & ~setmask));
	*destroy = !fsn_mark->mask;

	spin_unlock(&fsn_mark->lock);

	return setmask & oldmask;
}

static int synotify_remove_vfsmount_mark(struct fsnotify_group *group,
					 struct vfsmount *mnt, __u32 mask)
{
	struct fsnotify_mark *fsn_mark = NULL;
	__u32 removed;
	int destroy_mark;

	mutex_lock(&group->mark_mutex);
	fsn_mark = fsnotify_find_vfsmount_mark(group, mnt);
	if (!fsn_mark) {
		mutex_unlock(&group->mark_mutex);
		return -ENOENT;
	}

	removed = synotify_mark_remove_from_mask(fsn_mark, mask, group, &destroy_mark);

	if (destroy_mark)
		fsnotify_detach_mark(fsn_mark);
	mutex_unlock(&group->mark_mutex);
	if (destroy_mark)
		fsnotify_free_mark(fsn_mark);

	fsnotify_put_mark(fsn_mark);
	 
	if (removed & real_mount(mnt)->mnt_fsnotify_mask)
		fsnotify_recalc_vfsmount_mask(mnt);

	return 0;
}

static __u32 synotify_mark_add_to_mask(struct fsnotify_mark *fsn_mark,
				       __u32 mask)
{
	__u32 oldmask = 0;
	__u32 setmask = 0;

	setmask = mask & ~SYNO_DONT_FOLLOW;

	spin_lock(&fsn_mark->lock);

	oldmask = fsn_mark->mask;
	fsnotify_set_mark_mask_locked(fsn_mark, (oldmask | setmask));

	spin_unlock(&fsn_mark->lock);

	return setmask & ~oldmask;
}

static int synotify_add_vfsmount_mark(struct fsnotify_group *group,
				      struct vfsmount *mnt, __u32 mask)
{
	struct fsnotify_mark *fsn_mark;
	__u32 added;
	int ret = 0;

	mutex_lock(&group->mark_mutex);
	fsn_mark = fsnotify_find_vfsmount_mark(group, mnt);
	if (!fsn_mark) {
		if (atomic_read(&group->num_marks) >= group->synotify_data.max_watchers) {
			mutex_unlock(&group->mark_mutex);
			return -ENOSPC;
		}

		fsn_mark = kmem_cache_alloc(synotify_mark_cache, GFP_KERNEL);
		if (!fsn_mark) {
			mutex_unlock(&group->mark_mutex);
			return -ENOMEM;
		}

		fsnotify_init_mark(fsn_mark, synotify_free_mark);
		ret = fsnotify_add_mark_locked(fsn_mark, group, NULL, mnt, 0);
		if (ret) {
			mutex_unlock(&group->mark_mutex);
			goto err;
		}
	}

	added = synotify_mark_add_to_mask(fsn_mark, mask);
	mutex_unlock(&group->mark_mutex);

	if (added & ~real_mount(mnt)->mnt_fsnotify_mask)
		fsnotify_recalc_vfsmount_mask(mnt);
err:
	fsnotify_put_mark(fsn_mark);
	return ret;
}

static int synotify_set_mark(int synotify_fd, const char __user * pathname, __u64 mask, unsigned int synotify_flag)
{
	struct vfsmount *mnt = NULL;
	struct fsnotify_group *group;
	struct path path;
	struct fd f;
	int ret = -EINVAL;
	unsigned int flags = 0;

	pr_debug("%s: synotify_fd=%d pathname=%p mask=%llx\n",__FUNCTION__, synotify_fd, pathname, mask);

	if (mask >> 32) {
		if (mask << 32)
			return ret;
		mask >>= 32;
	}

	f = fdget(synotify_fd);
	if (unlikely(!f.file))
		return -EBADF;

	if (unlikely(f.file->f_op != &synotify_fops)) {
		ret = -EINVAL;
		goto fput_and_out;
	}

	if (!(mask & SYNO_DONT_FOLLOW))
		flags |= LOOKUP_FOLLOW;

	ret = synotify_find_path(pathname, &path, flags);
	if (ret)
		goto fput_and_out;

	group = f.file->private_data;

	mnt = path.mnt;

	switch (synotify_flag & (SYNOTIFY_MARK_ADD | SYNOTIFY_MARK_REMOVE)) {
	case SYNOTIFY_MARK_ADD:
		ret = synotify_add_vfsmount_mark(group, mnt, mask);
		break;
	case SYNOTIFY_MARK_REMOVE:
		ret = synotify_remove_vfsmount_mark(group, mnt, mask);
		break;
	default:
		ret = -EINVAL;
	}

	path_put(&path);
fput_and_out:
	fdput(f);
	return ret;
}

static int __init synotify_user_setup(void)
{
	synotify_mark_cache = kmem_cache_create("synotify_mark",sizeof(struct fsnotify_mark), __alignof__(struct fsnotify_mark),SLAB_PANIC , NULL);

	return 0;
}
device_initcall(synotify_user_setup);
#endif  

#ifdef MY_ABC_HERE
 
SYSCALL_DEFINE1(SYNONotifyInit, unsigned int, flags)
{
#ifdef MY_ABC_HERE
	struct fsnotify_group *group;
	int f_flags = 0;
	int fd = 0;
	struct user_struct *user;
	struct synotify_event_info *oevent;

	pr_debug("%s: flags=%x\n",__func__, flags);

	if(flags & ~(SYNO_NONBLOCK | SYNO_CLOEXEC))
		return -EINVAL;

	if(flags & SYNO_CLOEXEC){
		f_flags |= O_CLOEXEC;
	}
	if(flags & SYNO_NONBLOCK){
		f_flags |= O_NONBLOCK;
	}

	user = get_current_user();
	if (__kuid_val(user->uid) != 0) {
		return -EPERM;
	}
	if (atomic_read(&user->synotify_instances) > SYNOTIFY_DEFAULT_MAX_INSTANCES) {
		free_uid(user);
		return -EMFILE;
	}

	group = fsnotify_alloc_group(&synotify_fsnotify_ops);
	if (IS_ERR(group)) {
		free_uid(user);
		return PTR_ERR(group);
	}

	group->synotify_data.user = user;
	atomic_inc(&user->synotify_instances);

	oevent = synotify_alloc_event(NULL, SYNO_Q_OVERFLOW, NULL, 0);
	if (unlikely(!oevent)) {
		fd = -ENOMEM;
		goto out_destroy_group;
	}
	group->overflow_event = &oevent->fse;

	group->max_events = SYNOTIFY_DEFAULT_MAX_EVENTS;
	group->synotify_data.max_watchers = SYNOTIFY_DEFAULT_MAX_WATCHERS;

	fd = anon_inode_getfd("[synotify]", &synotify_fops, group, f_flags);
	if (fd < 0)
		goto out_destroy_group;

	return fd;

out_destroy_group:
	fsnotify_destroy_group(group);
	return fd;
#else
	return -EOPNOTSUPP;
#endif  
}

SYSCALL_DEFINE3(SYNONotifyRemoveWatch, int, synotify_fd, const char __user *, pathname, __u64, mask)
{
#ifdef MY_ABC_HERE
	return synotify_set_mark(synotify_fd, pathname, mask, SYNOTIFY_MARK_REMOVE);
#else
	return -EOPNOTSUPP;
#endif  
}

SYSCALL_DEFINE3(SYNONotifyAddWatch, int, synotify_fd, const char __user *, pathname, __u64, mask)
{
#ifdef MY_ABC_HERE
	return synotify_set_mark(synotify_fd, pathname, mask, SYNOTIFY_MARK_ADD);
#else
	return -EOPNOTSUPP;
#endif  
}
#endif  
