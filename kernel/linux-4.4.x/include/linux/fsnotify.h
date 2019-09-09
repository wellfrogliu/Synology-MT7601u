#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#ifndef _LINUX_FS_NOTIFY_H
#define _LINUX_FS_NOTIFY_H

#include <linux/fsnotify_backend.h>
#include <linux/audit.h>
#include <linux/slab.h>
#include <linux/bug.h>

#ifdef MY_ABC_HERE
#include <linux/xattr.h>
#endif  

#ifdef MY_ABC_HERE
#include <linux/mount.h>
#endif  

#ifdef MY_ABC_HERE
extern int SYNONotify(struct dentry *dentry, __u32 mask);
#endif  

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
static inline void SYNO_ArchiveModify(struct inode *inode, int set_smb_archive)
{
	struct dentry *dentry;
#ifdef MY_ABC_HERE
	u32 new_archive_bit;
	u32 old_archive_bit;
#endif  
#ifdef MY_ABC_HERE
	u32 old_version;
	u32 new_version;
	int err;
#endif  

	if (NULL == inode) {
		return;
	}
	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode) ||
		S_ISFIFO(inode->i_mode) || S_ISSOCK(inode->i_mode)) {
		return;
	}
	dentry = d_find_alias(inode);
	if (!dentry)
		return;
#ifdef MY_ABC_HERE
	mutex_lock(&inode->i_syno_mutex);
#ifdef MY_ABC_HERE
	if (IS_GLUSTER_FS(inode) || syno_op_get_archive_bit(dentry, &old_archive_bit)) {
#else
	if (syno_op_get_archive_bit(dentry, &old_archive_bit)) {
#endif  
		goto next;
	}

	if (set_smb_archive) {
		new_archive_bit = old_archive_bit | (S2_SMB_ARCHIVE|ALL_IARCHIVE);
	} else {
		new_archive_bit = old_archive_bit | ALL_IARCHIVE;
	}
	if (new_archive_bit == old_archive_bit) {
		goto next;
	}
	syno_op_set_archive_bit_nolock(dentry, new_archive_bit);
next:
	mutex_unlock(&inode->i_syno_mutex);
#endif  
#ifdef MY_ABC_HERE
	if (!inode->i_op->syno_get_archive_ver)
		goto out;

	err = inode->i_op->syno_get_archive_ver(dentry, &old_version);
	if (err)
		goto out;

	inode->i_sb->s_op->syno_get_sb_archive_ver(inode->i_sb, &new_version);
	if (err)
		goto out;

	new_version += 1;
	if (new_version != old_version)
		inode->i_op->syno_set_archive_ver(dentry, new_version);
out:
#endif  
	if (dentry) {
		dput(dentry);
	}
}
#endif  

static inline void fsnotify_d_instantiate(struct dentry *dentry,
					  struct inode *inode)
{
	__fsnotify_d_instantiate(dentry, inode);
}

static inline int fsnotify_parent(struct path *path, struct dentry *dentry, __u32 mask)
{
	if (!dentry)
		dentry = path->dentry;

	return __fsnotify_parent(path, dentry, mask);
}

static inline int fsnotify_perm(struct file *file, int mask)
{
	struct path *path = &file->f_path;
	struct inode *inode = file_inode(file);
	__u32 fsnotify_mask = 0;
	int ret;

	if (file->f_mode & FMODE_NONOTIFY)
		return 0;
	if (!(mask & (MAY_READ | MAY_OPEN)))
		return 0;
	if (mask & MAY_OPEN)
		fsnotify_mask = FS_OPEN_PERM;
	else if (mask & MAY_READ)
		fsnotify_mask = FS_ACCESS_PERM;
	else
		BUG();

	ret = fsnotify_parent(path, NULL, fsnotify_mask);
	if (ret)
		return ret;

	return fsnotify(inode, fsnotify_mask, path, FSNOTIFY_EVENT_PATH, NULL, 0);
}

static inline void fsnotify_d_move(struct dentry *dentry)
{
	 
	__fsnotify_update_dcache_flags(dentry);
}

static inline void fsnotify_link_count(struct inode *inode)
{
	fsnotify(inode, FS_ATTRIB, inode, FSNOTIFY_EVENT_INODE, NULL, 0);
}

#ifdef MY_ABC_HERE
struct synotify_rename_path {
	char *old_full_path;
	char *new_full_path;
	struct vfsmount *vfs_mnt;
	struct synotify_rename_path *next;
};
#endif  

#ifdef MY_ABC_HERE
static inline void fsnotify_move(struct inode *old_dir, struct inode *new_dir,
				 const unsigned char *old_name,
				 int isdir, struct inode *target, struct dentry *moved,
				 struct synotify_rename_path *path_list, bool is_exchange)
#else
static inline void fsnotify_move(struct inode *old_dir, struct inode *new_dir,
				 const unsigned char *old_name,
				 int isdir, struct inode *target, struct dentry *moved)
#endif  
{
	struct inode *source = moved->d_inode;
	u32 fs_cookie = fsnotify_get_cookie();
	__u32 old_dir_mask = (FS_EVENT_ON_CHILD | FS_MOVED_FROM);
	__u32 new_dir_mask = (FS_EVENT_ON_CHILD | FS_MOVED_TO);
	const unsigned char *new_name = moved->d_name.name;

	if (old_dir == new_dir)
		old_dir_mask |= FS_DN_RENAME;

	if (isdir) {
		old_dir_mask |= FS_ISDIR;
		new_dir_mask |= FS_ISDIR;
	}

#ifdef MY_ABC_HERE
	 
	while(path_list) {
		struct synotify_rename_path *tmp = path_list;
		struct path tmp_path;

		memset (&tmp_path, 0, sizeof(struct path));

		tmp_path.mnt = tmp->vfs_mnt;

		if (is_exchange) {
			SYNOFsnotify(old_dir_mask, &tmp_path, FSNOTIFY_EVENT_SYNO, tmp->new_full_path, fs_cookie);
			SYNOFsnotify(new_dir_mask, &tmp_path, FSNOTIFY_EVENT_SYNO, tmp->old_full_path, fs_cookie);
		} else {
			SYNOFsnotify(old_dir_mask, &tmp_path, FSNOTIFY_EVENT_SYNO, tmp->old_full_path, fs_cookie);
			SYNOFsnotify(new_dir_mask, &tmp_path, FSNOTIFY_EVENT_SYNO, tmp->new_full_path, fs_cookie);
		}
		path_list = path_list->next;
	}
#endif  

	fsnotify(old_dir, old_dir_mask, source, FSNOTIFY_EVENT_INODE, old_name,
		 fs_cookie);
	fsnotify(new_dir, new_dir_mask, source, FSNOTIFY_EVENT_INODE, new_name,
		 fs_cookie);

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	SYNO_ArchiveModify(old_dir, 0);
	if (old_dir != new_dir) {
		SYNO_ArchiveModify(new_dir, 0);
	}
#endif  

	if (target)
#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	{
		fsnotify_link_count(target);
		SYNO_ArchiveModify(target, 0);
	}
#else
		fsnotify_link_count(target);
#endif  

	if (source)
#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	{
		fsnotify(source, FS_MOVE_SELF, moved->d_inode, FSNOTIFY_EVENT_INODE, NULL, 0);
		SYNO_ArchiveModify(source, 1);
	}
#else
		fsnotify(source, FS_MOVE_SELF, moved->d_inode, FSNOTIFY_EVENT_INODE, NULL, 0);
#endif  
	audit_inode_child(new_dir, moved, AUDIT_TYPE_CHILD_CREATE);
}

static inline void fsnotify_inode_delete(struct inode *inode)
{
	__fsnotify_inode_delete(inode);
}

static inline void fsnotify_vfsmount_delete(struct vfsmount *mnt)
{
	__fsnotify_vfsmount_delete(mnt);
}

static inline void fsnotify_nameremove(struct dentry *dentry, int isdir)
{
	__u32 mask = FS_DELETE;

	if (isdir)
		mask |= FS_ISDIR;

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	SYNO_ArchiveModify(dentry->d_parent->d_inode, 0);
#endif  

#ifdef MY_ABC_HERE
	SYNONotify(dentry, mask);
#endif  

	fsnotify_parent(NULL, dentry, mask);
}

static inline void fsnotify_inoderemove(struct inode *inode)
{
	fsnotify(inode, FS_DELETE_SELF, inode, FSNOTIFY_EVENT_INODE, NULL, 0);
	__fsnotify_inode_delete(inode);
}

static inline void fsnotify_create(struct inode *inode, struct dentry *dentry)
{
	audit_inode_child(inode, dentry, AUDIT_TYPE_CHILD_CREATE);

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	SYNO_ArchiveModify(dentry->d_inode, 0);
#endif  

#ifdef MY_ABC_HERE
	SYNONotify(dentry, FS_CREATE);
#endif  

	fsnotify(inode, FS_CREATE, dentry->d_inode, FSNOTIFY_EVENT_INODE, dentry->d_name.name, 0);
}

static inline void fsnotify_link(struct inode *dir, struct inode *inode, struct dentry *new_dentry)
{
	fsnotify_link_count(inode);
	audit_inode_child(dir, new_dentry, AUDIT_TYPE_CHILD_CREATE);

#ifdef MY_ABC_HERE
	SYNONotify(new_dentry, FS_CREATE);
#endif  

	fsnotify(dir, FS_CREATE, inode, FSNOTIFY_EVENT_INODE, new_dentry->d_name.name, 0);
}

static inline void fsnotify_mkdir(struct inode *inode, struct dentry *dentry)
{
	__u32 mask = (FS_CREATE | FS_ISDIR);
	struct inode *d_inode = dentry->d_inode;

	audit_inode_child(inode, dentry, AUDIT_TYPE_CHILD_CREATE);

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	SYNO_ArchiveModify(d_inode, 0);
#endif  

#ifdef MY_ABC_HERE
	SYNONotify(dentry, mask);
#endif  

	fsnotify(inode, mask, d_inode, FSNOTIFY_EVENT_INODE, dentry->d_name.name, 0);
}

static inline void fsnotify_access(struct file *file)
{
	struct path *path = &file->f_path;
	struct inode *inode = file_inode(file);
	__u32 mask = FS_ACCESS;

	if (S_ISDIR(inode->i_mode))
		mask |= FS_ISDIR;

	if (!(file->f_mode & FMODE_NONOTIFY)) {
		fsnotify_parent(path, NULL, mask);
		fsnotify(inode, mask, path, FSNOTIFY_EVENT_PATH, NULL, 0);
	}
}

static inline void fsnotify_modify(struct file *file)
{
	struct path *path = &file->f_path;
	struct inode *inode = file_inode(file);
	__u32 mask = FS_MODIFY;

	if (S_ISDIR(inode->i_mode))
		mask |= FS_ISDIR;

	if (!(file->f_mode & FMODE_NONOTIFY)) {
#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
		SYNO_ArchiveModify(inode, 1);
#endif  
		fsnotify_parent(path, NULL, mask);
		fsnotify(inode, mask, path, FSNOTIFY_EVENT_PATH, NULL, 0);
	}
}

static inline void fsnotify_open(struct file *file)
{
	struct path *path = &file->f_path;
	struct inode *inode = file_inode(file);
	__u32 mask = FS_OPEN;

	if (S_ISDIR(inode->i_mode))
		mask |= FS_ISDIR;

	fsnotify_parent(path, NULL, mask);
	fsnotify(inode, mask, path, FSNOTIFY_EVENT_PATH, NULL, 0);
}

static inline void fsnotify_close(struct file *file)
{
	struct path *path = &file->f_path;
	struct inode *inode = file_inode(file);
	fmode_t mode = file->f_mode;
	__u32 mask = (mode & FMODE_WRITE) ? FS_CLOSE_WRITE : FS_CLOSE_NOWRITE;

	if (S_ISDIR(inode->i_mode))
		mask |= FS_ISDIR;

	if (!(file->f_mode & FMODE_NONOTIFY)) {
		fsnotify_parent(path, NULL, mask);
		fsnotify(inode, mask, path, FSNOTIFY_EVENT_PATH, NULL, 0);
	}
}

static inline void fsnotify_xattr(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	__u32 mask = FS_ATTRIB;

	if (S_ISDIR(inode->i_mode))
		mask |= FS_ISDIR;

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	SYNO_ArchiveModify(inode, 1);
#endif  
	fsnotify_parent(NULL, dentry, mask);

#ifdef MY_ABC_HERE
	SYNONotify(dentry, mask);
#endif  

	fsnotify(inode, mask, inode, FSNOTIFY_EVENT_INODE, NULL, 0);
}

static inline void fsnotify_change(struct dentry *dentry, unsigned int ia_valid)
{
	struct inode *inode = dentry->d_inode;
	__u32 mask = 0;

	if (ia_valid & ATTR_UID)
		mask |= FS_ATTRIB;
	if (ia_valid & ATTR_GID)
		mask |= FS_ATTRIB;
	if (ia_valid & ATTR_SIZE)
#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	{
		mask |= FS_MODIFY;
		SYNO_ArchiveModify(inode, 1);
	}
#else
		mask |= FS_MODIFY;
#endif  

	if ((ia_valid & (ATTR_ATIME | ATTR_MTIME)) == (ATTR_ATIME | ATTR_MTIME))
		mask |= FS_ATTRIB;
	else if (ia_valid & ATTR_ATIME)
		mask |= FS_ACCESS;
	else if (ia_valid & ATTR_MTIME)
		mask |= FS_MODIFY;

	if (ia_valid & ATTR_MODE)
		mask |= FS_ATTRIB;

	if (mask) {
		if (S_ISDIR(inode->i_mode))
			mask |= FS_ISDIR;

		fsnotify_parent(NULL, dentry, mask);

#ifdef MY_ABC_HERE
		SYNONotify(dentry, mask);
#endif  

		fsnotify(inode, mask, inode, FSNOTIFY_EVENT_INODE, NULL, 0);
	}
}

#endif	 
