#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#ifdef MY_ABC_HERE
#include <linux/synotify.h>
#include <linux/fdtable.h>
#include <linux/fsnotify_backend.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>  
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/nsproxy.h>
#include <linux/mnt_namespace.h>

#include "synotify.h"

static int syno_fetch_mountpoint_fullpath(struct vfsmount *mnt, size_t buf_len, char *mnt_full_path)
{
	int ret = -1;
	char *mnt_dentry_path = NULL;
	char *mnt_dentry_path_buf = NULL;
	struct nsproxy *nsproxy = current->nsproxy;
	struct mnt_namespace *mnt_space = NULL;
	struct mount *root_mnt = NULL;
	struct path root_path;
	struct path mnt_path;

	mnt_dentry_path_buf = kmalloc(PATH_MAX, GFP_ATOMIC);
	if(!mnt_dentry_path_buf) {
		ret = -ENOMEM;
		goto ERR;
	}

	if (!nsproxy) {
		ret = -EINVAL;
		goto ERR;
	}

	mnt_space = nsproxy->mnt_ns;
	if (!mnt_space || !mnt_space->root) {
		ret = -EINVAL;
		goto ERR;
	}

	get_mnt_ns(mnt_space);

	root_mnt = mnt_space->root;
	memset(&root_path, 0, sizeof(struct path));
	root_path.mnt = &root_mnt->mnt;
	root_path.dentry = root_mnt->mnt.mnt_root;

	memset(&mnt_path, 0, sizeof(struct path));
	mnt_path.mnt = mnt;
	mnt_path.dentry = mnt->mnt_root;

	path_get(&mnt_path);
	path_get(&root_path);

	mnt_dentry_path = __d_path(&mnt_path, &root_path, mnt_dentry_path_buf, PATH_MAX-1);
	if(IS_ERR_OR_NULL(mnt_dentry_path)){
		goto RESOURCE_PUT;
	}

	snprintf(mnt_full_path, buf_len, "%s", mnt_dentry_path);

	ret = 0;

RESOURCE_PUT:
	path_put(&root_path);
	path_put(&mnt_path);
	put_mnt_ns(mnt_space);
ERR:
	kfree(mnt_dentry_path_buf);
	return ret;
}

static void formalize_full_path(const char *mnt_name, const char *base_name, char *full_path){
	if (mnt_name[0] == '/'){
		if(mnt_name[1] == 0){
			snprintf(full_path, PATH_MAX,"%s", base_name);
		}else{
			snprintf(full_path, PATH_MAX,"%s%s", mnt_name, base_name);
		}
	}else
		snprintf(full_path, PATH_MAX,"/%s%s", mnt_name, base_name);
}

static int SYNOFetchFullName(struct synotify_event_info *event, gfp_t gfp)
{
	char *dentry_path_buf = NULL;
	char *full_path = NULL;
	char *mnt_full_path = NULL;
	char *dentry_path = NULL;
	struct vfsmount *mnt = event->path.mnt;
	int ret = -1;

	if (event->data_type == FSNOTIFY_EVENT_NONE) {
		return 0;
	}

	if(event->data_type == FSNOTIFY_EVENT_PATH) {
		struct path root_path;
		root_path.mnt = mnt;
		root_path.dentry = mnt->mnt_root;
		dentry_path_buf = kmalloc(PATH_MAX, gfp);
		if (unlikely(!dentry_path_buf)) {
			ret = -ENOMEM;
			goto ERR;
		}
		dentry_path = __d_path(&event->path, &root_path, dentry_path_buf, PATH_MAX-1);
		if (unlikely(IS_ERR_OR_NULL(dentry_path))) {
			goto ERR;
		}
	}

	full_path = kmalloc(PATH_MAX, gfp);
	mnt_full_path = kzalloc(PATH_MAX, gfp);
	if(!full_path || !mnt_full_path){
		ret = -ENOMEM;
		goto ERR;
	}

	ret = syno_fetch_mountpoint_fullpath(mnt, PATH_MAX, mnt_full_path);
	if (ret < 0)
		goto ERR;
	if(event->data_type == FSNOTIFY_EVENT_PATH) {
		formalize_full_path(mnt_full_path, dentry_path, full_path);
	} else {
		formalize_full_path(mnt_full_path, event->file_name, full_path);
	}
	event->full_name = kstrdup(full_path, gfp);
	if (unlikely(!event->full_name)) {
		ret = -ENOMEM;
		goto ERR;
	}
	event->full_name_len = strlen(event->full_name);
	ret = 0;

ERR:
	kfree(dentry_path_buf);
	kfree(full_path);
	kfree(mnt_full_path);
	return ret;
}

static int synotify_fetch_name(struct fsnotify_event *event)
{
	return SYNOFetchFullName(SYNOTIFY_E(event), GFP_ATOMIC);
}

static bool should_merge(struct fsnotify_event *old_fsn, struct fsnotify_event *new_fsn)
{
	struct synotify_event_info *old, *new;

	pr_debug("%s: old=%p new=%p\n", __func__, old_fsn, new_fsn);
	old = SYNOTIFY_E(old_fsn);
	new = SYNOTIFY_E(new_fsn);

	if (old_fsn->mask != new_fsn->mask) return false;

	if ( (new_fsn->mask & (FS_ATTRIB | FS_ACCESS | FS_MODIFY))
			&& (old->path.mnt == new->path.mnt)
			&& (old->path.dentry == new->path.dentry))
		return true;
	return false;
}

static int synotify_merge(struct list_head *list,
					     struct fsnotify_event *event)
{
	struct fsnotify_event *last_event;
	pr_debug("%s: list=%p event=%p, mask=%x\n", __func__, list, event, event->mask);

	last_event = list_entry(list->prev, struct fsnotify_event, list);
	return should_merge(last_event, event);
}

static bool synotify_should_send_event(struct fsnotify_mark *vfsmnt_mark,
				       __u32 event_mask, int data_type)
{
	__u32 marks_mask;

	if (data_type != FSNOTIFY_EVENT_SYNO && data_type != FSNOTIFY_EVENT_PATH)
		return false;

	if (vfsmnt_mark) {
		marks_mask = vfsmnt_mark->mask;
	} else {
		BUG();
	}

	if (event_mask & marks_mask)
		return true;

	return false;
}

struct synotify_event_info *synotify_alloc_event(struct inode *inode, u32 mask,
						 struct path *path, u32 cookie)
{
	struct synotify_event_info *event;

	event = kmalloc(sizeof(struct synotify_event_info), GFP_KERNEL);
	if (!event)
		return NULL;

	fsnotify_init_event(&event->fse, inode, mask);
	if (path) {
		event->path = *path;
		path_get(&event->path);
	} else {
		event->path.mnt = NULL;
		event->path.dentry = NULL;
	}
	event->full_name = NULL;
	event->full_name_len = 0;
	event->sync_cookie = cookie;
	event->file_name = NULL;
	event->data_type = FSNOTIFY_EVENT_NONE;
	
	return event;
}

static int synotify_handle_event(struct fsnotify_group *group,
				 struct inode *inode,
				 struct fsnotify_mark *inode_mark,
				 struct fsnotify_mark *synotify_mark,
				 u32 mask, void *data, int data_type,
				 const unsigned char *file_name, u32 cookie)
{
	int ret = 0;
	struct synotify_event_info *event;
	struct fsnotify_event *fsn_event;

	if (!synotify_should_send_event(synotify_mark, mask, data_type))
		return 0;

	pr_debug("%s: group=%p inode=%p mask=%x\n", __func__, group, inode,
		 mask);

	event = synotify_alloc_event(inode, mask, data, cookie);
	if (unlikely(!event))
		return -ENOMEM;

	event->file_name = file_name;
	event->data_type = data_type;
	fsn_event = &event->fse;

	ret = fsnotify_add_event(group, fsn_event, synotify_merge);
	if (ret) {
		fsnotify_destroy_event(group, fsn_event);
		return ret > 0 ? 0 : ret;
	}

	return 0;
}

static void synotify_free_group_priv(struct fsnotify_group *group)
{
	struct user_struct *user;

	user = group->synotify_data.user;
	atomic_dec(&user->synotify_instances);
	free_uid(user);
}

static void synotify_free_event(struct fsnotify_event *fsn_event)
{
	struct synotify_event_info *event;

	event = SYNOTIFY_E(fsn_event);
	path_put(&event->path);
	kfree(event->full_name);
	kfree(event);
}

const struct fsnotify_ops synotify_fsnotify_ops = {
	.handle_event = synotify_handle_event,
	.free_group_priv = synotify_free_group_priv,
	.free_event = synotify_free_event,
	.fetch_name = synotify_fetch_name,
};
#endif  
