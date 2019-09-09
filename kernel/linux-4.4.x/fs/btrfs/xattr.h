#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef __XATTR__
#define __XATTR__

#include <linux/xattr.h>

#ifdef MY_ABC_HERE
extern const struct xattr_handler btrfs_xattr_syno_handler;
#endif  

extern const struct xattr_handler *btrfs_xattr_handlers[];

extern ssize_t __btrfs_getxattr(struct inode *inode, const char *name,
		void *buffer, size_t size);
extern int __btrfs_setxattr(struct btrfs_trans_handle *trans,
			    struct inode *inode, const char *name,
			    const void *value, size_t size, int flags);

extern int btrfs_xattr_security_init(struct btrfs_trans_handle *trans,
				     struct inode *inode, struct inode *dir,
				     const struct qstr *qstr);

#endif  
