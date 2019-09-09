#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/dcache.h>  
#include <linux/fs.h>  
#include <linux/fsnotify_backend.h>
#include <linux/inotify.h>
#include <linux/path.h>  
#include <linux/slab.h>  
#include <linux/types.h>
#include <linux/sched.h>

#include "inotify.h"

static bool event_compare(struct fsnotify_event *old_fsn,
			  struct fsnotify_event *new_fsn)
{
	struct inotify_event_info *old, *new;

	if (old_fsn->mask & FS_IN_IGNORED)
		return false;
	old = INOTIFY_E(old_fsn);
	new = INOTIFY_E(new_fsn);
	if ((old_fsn->mask == new_fsn->mask) &&
	    (old_fsn->inode == new_fsn->inode) &&
	    (old->name_len == new->name_len) &&
	    (!old->name_len || !strcmp(old->name, new->name)))
		return true;
	return false;
}

static int inotify_merge(struct list_head *list,
			  struct fsnotify_event *event)
{
	struct fsnotify_event *last_event;

	last_event = list_entry(list->prev, struct fsnotify_event, list);
	return event_compare(last_event, event);
}

int inotify_handle_event(struct fsnotify_group *group,
			 struct inode *inode,
			 struct fsnotify_mark *inode_mark,
			 struct fsnotify_mark *vfsmount_mark,
			 u32 mask, void *data, int data_type,
			 const unsigned char *file_name, u32 cookie)
{
	struct inotify_inode_mark *i_mark;
	struct inotify_event_info *event;
	struct fsnotify_event *fsn_event;
	int ret;
	int len = 0;
	int alloc_len = sizeof(struct inotify_event_info);

	BUG_ON(vfsmount_mark);

#ifdef MY_ABC_HERE
	if (data_type == FSNOTIFY_EVENT_SYNO)
		return 0;
#endif  

	if ((inode_mark->mask & FS_EXCL_UNLINK) &&
	    (data_type == FSNOTIFY_EVENT_PATH)) {
		struct path *path = data;

		if (d_unlinked(path->dentry))
			return 0;
	}
	if (file_name) {
		len = strlen(file_name);
		alloc_len += len + 1;
	}

	pr_debug("%s: group=%p inode=%p mask=%x\n", __func__, group, inode,
		 mask);

	i_mark = container_of(inode_mark, struct inotify_inode_mark,
			      fsn_mark);

	event = kmalloc(alloc_len, GFP_KERNEL);
	if (unlikely(!event))
		return -ENOMEM;

	fsn_event = &event->fse;
	fsnotify_init_event(fsn_event, inode, mask);
	event->wd = i_mark->wd;
	event->sync_cookie = cookie;
	event->name_len = len;
	if (len)
		strcpy(event->name, file_name);

	ret = fsnotify_add_event(group, fsn_event, inotify_merge);
	if (ret) {
		 
		fsnotify_destroy_event(group, fsn_event);
	}

	if (inode_mark->mask & IN_ONESHOT)
		fsnotify_destroy_mark(inode_mark, group);

	return 0;
}

static void inotify_freeing_mark(struct fsnotify_mark *fsn_mark, struct fsnotify_group *group)
{
	inotify_ignored_and_remove_idr(fsn_mark, group);
}

static int idr_callback(int id, void *p, void *data)
{
	struct fsnotify_mark *fsn_mark;
	struct inotify_inode_mark *i_mark;
	static bool warned = false;

	if (warned)
		return 0;

	warned = true;
	fsn_mark = p;
	i_mark = container_of(fsn_mark, struct inotify_inode_mark, fsn_mark);

	WARN(1, "inotify closing but id=%d for fsn_mark=%p in group=%p still in "
		"idr.  Probably leaking memory\n", id, p, data);

	if (fsn_mark)
		printk(KERN_WARNING "fsn_mark->group=%p inode=%p wd=%d\n",
			fsn_mark->group, fsn_mark->inode, i_mark->wd);
	return 0;
}

static void inotify_free_group_priv(struct fsnotify_group *group)
{
	 
	idr_for_each(&group->inotify_data.idr, idr_callback, group);
	idr_destroy(&group->inotify_data.idr);
	if (group->inotify_data.user) {
		atomic_dec(&group->inotify_data.user->inotify_devs);
		free_uid(group->inotify_data.user);
	}
}

static void inotify_free_event(struct fsnotify_event *fsn_event)
{
	kfree(INOTIFY_E(fsn_event));
}

const struct fsnotify_ops inotify_fsnotify_ops = {
	.handle_event = inotify_handle_event,
	.free_group_priv = inotify_free_group_priv,
	.free_event = inotify_free_event,
	.freeing_mark = inotify_freeing_mark,
};
