#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef _LINUX_XATTR_H
#define _LINUX_XATTR_H

#include <linux/slab.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <uapi/linux/xattr.h>

struct inode;
struct dentry;

struct xattr_handler {
	const char *prefix;
	int flags;       
	size_t (*list)(const struct xattr_handler *, struct dentry *dentry,
		       char *list, size_t list_size, const char *name,
		       size_t name_len);
	int (*get)(const struct xattr_handler *, struct dentry *dentry,
		   const char *name, void *buffer, size_t size);
	int (*set)(const struct xattr_handler *, struct dentry *dentry,
		   const char *name, const void *buffer, size_t size,
		   int flags);
};

#ifdef MY_ABC_HERE
struct syno_xattr_archive_version {
	__le16	v_magic;
	__le16	v_struct_version;
	__le32	v_archive_version;
} __attribute__ ((__packed__));
#endif  

const char *xattr_full_name(const struct xattr_handler *, const char *);

struct xattr {
	const char *name;
	void *value;
	size_t value_len;
};

ssize_t xattr_getsecurity(struct inode *, const char *, void *, size_t);
ssize_t vfs_getxattr(struct dentry *, const char *, void *, size_t);
ssize_t vfs_listxattr(struct dentry *d, char *list, size_t size);
int __vfs_setxattr_noperm(struct dentry *, const char *, const void *, size_t, int);
int vfs_setxattr(struct dentry *, const char *, const void *, size_t, int);
int vfs_removexattr(struct dentry *, const char *);

ssize_t generic_getxattr(struct dentry *dentry, const char *name, void *buffer, size_t size);
ssize_t generic_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size);
int generic_setxattr(struct dentry *dentry, const char *name, const void *value, size_t size, int flags);
int generic_removexattr(struct dentry *dentry, const char *name);
ssize_t vfs_getxattr_alloc(struct dentry *dentry, const char *name,
			   char **xattr_value, size_t size, gfp_t flags);
int vfs_xattr_cmp(struct dentry *dentry, const char *xattr_name,
		  const char *value, size_t size, gfp_t flags);

struct simple_xattrs {
	struct list_head head;
	spinlock_t lock;
};

struct simple_xattr {
	struct list_head list;
	char *name;
	size_t size;
	char value[0];
};

static inline void simple_xattrs_init(struct simple_xattrs *xattrs)
{
	INIT_LIST_HEAD(&xattrs->head);
	spin_lock_init(&xattrs->lock);
}

static inline void simple_xattrs_free(struct simple_xattrs *xattrs)
{
	struct simple_xattr *xattr, *node;

	list_for_each_entry_safe(xattr, node, &xattrs->head, list) {
		kfree(xattr->name);
		kfree(xattr);
	}
}

struct simple_xattr *simple_xattr_alloc(const void *value, size_t size);
int simple_xattr_get(struct simple_xattrs *xattrs, const char *name,
		     void *buffer, size_t size);
int simple_xattr_set(struct simple_xattrs *xattrs, const char *name,
		     const void *value, size_t size, int flags);
int simple_xattr_remove(struct simple_xattrs *xattrs, const char *name);
ssize_t simple_xattr_list(struct simple_xattrs *xattrs, char *buffer,
			  size_t size);
void simple_xattr_list_add(struct simple_xattrs *xattrs,
			   struct simple_xattr *new_xattr);

#endif	 
