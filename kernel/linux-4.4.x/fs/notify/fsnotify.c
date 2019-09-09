#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/srcu.h>

#include <linux/fsnotify_backend.h>
#include "fsnotify.h"

#ifdef MY_ABC_HERE
#include <linux/nsproxy.h>
extern struct rw_semaphore namespace_sem;
#endif  

void __fsnotify_inode_delete(struct inode *inode)
{
	fsnotify_clear_marks_by_inode(inode);
}
EXPORT_SYMBOL_GPL(__fsnotify_inode_delete);

void __fsnotify_vfsmount_delete(struct vfsmount *mnt)
{
	fsnotify_clear_marks_by_mount(mnt);
}

void __fsnotify_update_child_dentry_flags(struct inode *inode)
{
	struct dentry *alias;
	int watched;

	if (!S_ISDIR(inode->i_mode))
		return;

	watched = fsnotify_inode_watches_children(inode);

	spin_lock(&inode->i_lock);
	 
	hlist_for_each_entry(alias, &inode->i_dentry, d_u.d_alias) {
		struct dentry *child;

		spin_lock(&alias->d_lock);
		list_for_each_entry(child, &alias->d_subdirs, d_child) {
			if (!child->d_inode)
				continue;

			spin_lock_nested(&child->d_lock, DENTRY_D_LOCK_NESTED);
			if (watched)
				child->d_flags |= DCACHE_FSNOTIFY_PARENT_WATCHED;
			else
				child->d_flags &= ~DCACHE_FSNOTIFY_PARENT_WATCHED;
			spin_unlock(&child->d_lock);
		}
		spin_unlock(&alias->d_lock);
	}
	spin_unlock(&inode->i_lock);
}

int __fsnotify_parent(struct path *path, struct dentry *dentry, __u32 mask)
{
	struct dentry *parent;
	struct inode *p_inode;
	int ret = 0;

	if (!dentry)
		dentry = path->dentry;

	if (!(dentry->d_flags & DCACHE_FSNOTIFY_PARENT_WATCHED))
		return 0;

	parent = dget_parent(dentry);
	p_inode = parent->d_inode;

	if (unlikely(!fsnotify_inode_watches_children(p_inode)))
		__fsnotify_update_child_dentry_flags(p_inode);
	else if (p_inode->i_fsnotify_mask & mask) {
		struct name_snapshot name;

		mask |= FS_EVENT_ON_CHILD;

		take_dentry_name_snapshot(&name, dentry);
		if (path)
			ret = fsnotify(p_inode, mask, path, FSNOTIFY_EVENT_PATH,
				       name.name, 0);
		else
			ret = fsnotify(p_inode, mask, dentry->d_inode, FSNOTIFY_EVENT_INODE,
				       name.name, 0);
		release_dentry_name_snapshot(&name);
	}

	dput(parent);

	return ret;
}
EXPORT_SYMBOL_GPL(__fsnotify_parent);

static int send_to_group(struct inode *to_tell,
			 struct fsnotify_mark *inode_mark,
			 struct fsnotify_mark *vfsmount_mark,
			 __u32 mask, void *data,
			 int data_is, u32 cookie,
			 const unsigned char *file_name)
{
	struct fsnotify_group *group = NULL;
	__u32 inode_test_mask = 0;
	__u32 vfsmount_test_mask = 0;

	if (unlikely(!inode_mark && !vfsmount_mark)) {
		BUG();
		return 0;
	}

	if (mask & FS_MODIFY) {
		if (inode_mark &&
		    !(inode_mark->flags & FSNOTIFY_MARK_FLAG_IGNORED_SURV_MODIFY))
			inode_mark->ignored_mask = 0;
		if (vfsmount_mark &&
		    !(vfsmount_mark->flags & FSNOTIFY_MARK_FLAG_IGNORED_SURV_MODIFY))
			vfsmount_mark->ignored_mask = 0;
	}

	if (inode_mark) {
		group = inode_mark->group;
		inode_test_mask = (mask & ~FS_EVENT_ON_CHILD);
		inode_test_mask &= inode_mark->mask;
		inode_test_mask &= ~inode_mark->ignored_mask;
	}

	if (vfsmount_mark) {
		vfsmount_test_mask = (mask & ~FS_EVENT_ON_CHILD);
		group = vfsmount_mark->group;
		vfsmount_test_mask &= vfsmount_mark->mask;
		vfsmount_test_mask &= ~vfsmount_mark->ignored_mask;
		if (inode_mark)
			vfsmount_test_mask &= ~inode_mark->ignored_mask;
	}

	pr_debug("%s: group=%p to_tell=%p mask=%x inode_mark=%p"
		 " inode_test_mask=%x vfsmount_mark=%p vfsmount_test_mask=%x"
		 " data=%p data_is=%d cookie=%d\n",
		 __func__, group, to_tell, mask, inode_mark,
		 inode_test_mask, vfsmount_mark, vfsmount_test_mask, data,
		 data_is, cookie);

	if (!inode_test_mask && !vfsmount_test_mask)
		return 0;

	return group->ops->handle_event(group, to_tell, inode_mark,
					vfsmount_mark, mask, data, data_is,
					file_name, cookie);
}

int fsnotify(struct inode *to_tell, __u32 mask, void *data, int data_is,
	     const unsigned char *file_name, u32 cookie)
{
	struct hlist_node *inode_node = NULL, *vfsmount_node = NULL;
	struct fsnotify_mark *inode_mark = NULL, *vfsmount_mark = NULL;
	struct fsnotify_group *inode_group, *vfsmount_group;
	struct mount *mnt;
	int idx, ret = 0;
	 
	__u32 test_mask = (mask & ~FS_EVENT_ON_CHILD);

	if (data_is == FSNOTIFY_EVENT_PATH)
		mnt = real_mount(((struct path *)data)->mnt);
	else
		mnt = NULL;

	if (hlist_empty(&to_tell->i_fsnotify_marks) &&
	    (!mnt || hlist_empty(&mnt->mnt_fsnotify_marks)))
		return 0;
	 
	if (!(mask & FS_MODIFY) &&
	    !(test_mask & to_tell->i_fsnotify_mask) &&
	    !(mnt && test_mask & mnt->mnt_fsnotify_mask))
		return 0;

	idx = srcu_read_lock(&fsnotify_mark_srcu);

	if ((mask & FS_MODIFY) ||
	    (test_mask & to_tell->i_fsnotify_mask))
		inode_node = srcu_dereference(to_tell->i_fsnotify_marks.first,
					      &fsnotify_mark_srcu);

	if (mnt && ((mask & FS_MODIFY) ||
		    (test_mask & mnt->mnt_fsnotify_mask))) {
		vfsmount_node = srcu_dereference(mnt->mnt_fsnotify_marks.first,
						 &fsnotify_mark_srcu);
		inode_node = srcu_dereference(to_tell->i_fsnotify_marks.first,
					      &fsnotify_mark_srcu);
	}

	while (inode_node || vfsmount_node) {
		inode_group = NULL;
		inode_mark = NULL;
		vfsmount_group = NULL;
		vfsmount_mark = NULL;

		if (inode_node) {
			inode_mark = hlist_entry(srcu_dereference(inode_node, &fsnotify_mark_srcu),
						 struct fsnotify_mark, obj_list);
			inode_group = inode_mark->group;
		}

		if (vfsmount_node) {
			vfsmount_mark = hlist_entry(srcu_dereference(vfsmount_node, &fsnotify_mark_srcu),
						    struct fsnotify_mark, obj_list);
			vfsmount_group = vfsmount_mark->group;
		}

		if (inode_group && vfsmount_group) {
			int cmp = fsnotify_compare_groups(inode_group,
							  vfsmount_group);
			if (cmp > 0) {
				inode_group = NULL;
				inode_mark = NULL;
			} else if (cmp < 0) {
				vfsmount_group = NULL;
				vfsmount_mark = NULL;
			}
		}
		ret = send_to_group(to_tell, inode_mark, vfsmount_mark, mask,
				    data, data_is, cookie, file_name);

		if (ret && (mask & ALL_FSNOTIFY_PERM_EVENTS))
			goto out;

		if (inode_group)
			inode_node = srcu_dereference(inode_node->next,
						      &fsnotify_mark_srcu);
		if (vfsmount_group)
			vfsmount_node = srcu_dereference(vfsmount_node->next,
							 &fsnotify_mark_srcu);
	}
	ret = 0;
out:
	srcu_read_unlock(&fsnotify_mark_srcu, idx);

	return ret;
}
EXPORT_SYMBOL_GPL(fsnotify);

#ifdef MY_ABC_HERE
 
static int notify_event(struct vfsmount *vfsmnt, struct dentry *dentry, __u32 mask)
{
	int ret = 0;
	struct path path;
	struct path root_path;
	char *dentry_path = NULL;
	char *dentry_buf = NULL;
	struct mount * mnt = NULL;
	__u32 test_mask = (mask & ~FS_EVENT_ON_CHILD);

	if (!dentry) {
		ret = -EINVAL;
		goto end;
	}
	if (!vfsmnt) {
		ret = -EINVAL;
		goto end;
	}

	mnt = real_mount(vfsmnt);
	if (!mnt) {
		ret = -EINVAL;
		goto end;
	}

	if (!(test_mask & mnt->mnt_fsnotify_mask)) {
		ret = 0;
		goto end;
	}

	memset(&path, 0, sizeof(struct path));
	memset(&root_path, 0, sizeof(struct path));

	path.mnt = vfsmnt;
	path.dentry = dentry;
	root_path.mnt = vfsmnt;
	root_path.dentry = vfsmnt->mnt_root;

	dentry_buf = kmalloc(PATH_MAX, GFP_NOFS);
	if (!dentry_buf) {
		ret = -ENOMEM;
		goto end;
	}

	dentry_path = __d_path(&path, &root_path, dentry_buf, PATH_MAX-1);
	if (IS_ERR_OR_NULL(dentry_path)) {
		ret = -1;
		goto end;
	}

	SYNOFsnotify(mask, &path, FSNOTIFY_EVENT_SYNO, dentry_path, 0);
end:
	if (dentry_buf)
		kfree(dentry_buf);
	return ret;
}

inline int SYNOFsnotify(__u32 mask, void *data, int data_is,
	     const unsigned char *file_name, u32 cookie)
{
	struct hlist_node *mount_node = NULL;
	struct fsnotify_mark *mount_mark = NULL;
	struct mount *mnt = NULL;
	int idx = 0;
	 
	__u32 test_mask = (mask & ~FS_EVENT_ON_CHILD);

	if (data_is != FSNOTIFY_EVENT_SYNO)
		return 0;

	if (!((struct path *)data)->mnt)
		return 0;

	mnt = real_mount(((struct path *)data)->mnt);
	if (!(test_mask & mnt->mnt_fsnotify_mask))
		return 0;

	idx = srcu_read_lock(&fsnotify_mark_srcu);

	mount_node = srcu_dereference(mnt->mnt_fsnotify_marks.first,
						 &fsnotify_mark_srcu);

	while (mount_node) {

		mount_mark = hlist_entry(srcu_dereference(mount_node, &fsnotify_mark_srcu),
							struct fsnotify_mark, obj_list);

		send_to_group(NULL, NULL, mount_mark, mask, data,
					    data_is, cookie, file_name);

		mount_node = srcu_dereference(mount_node->next,
							 &fsnotify_mark_srcu);
	}

	srcu_read_unlock(&fsnotify_mark_srcu, idx);

	return 0;
}

int SYNONotify(struct dentry *dentry, __u32 mask)
{
	struct list_head *head = NULL;
	struct nsproxy *nsproxy = NULL;
	int ret = 0;

	if (!dentry) {
		ret = -EINVAL;
		goto ERR;
	}

	if (!dentry->d_sb) {
		ret = -EINVAL;
		goto ERR;
	}

	nsproxy = current->nsproxy;
	if (nsproxy) {
		struct mnt_namespace *mnt_space = nsproxy->mnt_ns;
		if (mnt_space) {
			down_read(&namespace_sem);
			list_for_each(head, &mnt_space->list) {
				struct mount *mnt = list_entry(head, struct mount, mnt_list);
				if (mnt && mnt->mnt.mnt_sb == dentry->d_sb) {
					struct vfsmount *vfsmnt = &mnt->mnt;
					mntget(vfsmnt);
					notify_event(vfsmnt, dentry, mask);  
					mntput(vfsmnt);
				}
			}
			up_read(&namespace_sem);
		}
	}

ERR:
	return ret;
}
EXPORT_SYMBOL(SYNONotify);
#endif  

static __init int fsnotify_init(void)
{
	int ret;

	BUG_ON(hweight32(ALL_FSNOTIFY_EVENTS) != 23);

	ret = init_srcu_struct(&fsnotify_mark_srcu);
	if (ret)
		panic("initializing fsnotify_mark_srcu");

	return 0;
}
core_initcall(fsnotify_init);
