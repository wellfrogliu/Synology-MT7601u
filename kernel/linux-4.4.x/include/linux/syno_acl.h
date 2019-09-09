#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef __LINUX_SYNO_ACL_H
#define __LINUX_SYNO_ACL_H

#ifdef MY_ABC_HERE
#include <linux/slab.h>
#include <uapi/linux/syno_acl_xattr_ds.h>

#define SYNO_ACL_USER		(0x01)
#define SYNO_ACL_GROUP		(0x02)
#define SYNO_ACL_EVERYONE	(0x04)
#define SYNO_ACL_OWNER	(0x08)
#define SYNO_ACL_AUTHENTICATEDUSER	(0x09)
#define SYNO_ACL_SYSTEM	(0x0A)
#define SYNO_ACL_TAG_ALL  (SYNO_ACL_USER | SYNO_ACL_GROUP | \
						   SYNO_ACL_OWNER | SYNO_ACL_EVERYONE)

#define SYNO_ACL_ALLOW		(0x01)
#define SYNO_ACL_DENY		(0x02)

struct syno_acl_entry {
	unsigned short          e_tag;
	unsigned int            e_id;
	unsigned int            e_perm;
	unsigned short          e_inherit;
	unsigned short          e_allow;
	unsigned int            e_level;
};

struct syno_acl {
	atomic_t                a_refcount;
	unsigned int            a_count;
	struct syno_acl_entry   a_entries[0];
};

#define FOREACH_SYNOACL_ENTRY(pa, acl, pe) \
	for(pa=(acl)->a_entries, pe=pa+(acl)->a_count; pa<pe; pa++)

static inline struct syno_acl *
syno_acl_dup(struct syno_acl *acl)
{
	if (acl)
		atomic_inc(&acl->a_refcount);
	return acl;
}

static inline void
syno_acl_release(struct syno_acl *acl)
{
	if (acl && atomic_dec_and_test(&acl->a_refcount))
		kfree(acl);
}

extern struct syno_acl *syno_acl_alloc(int count, gfp_t flags);
extern int syno_acl_valid(const struct syno_acl *);
extern struct syno_acl *syno_acl_realloc(struct syno_acl *acl, unsigned int counts, gfp_t flags);
extern struct syno_acl *syno_acl_clone(const struct syno_acl *acl, gfp_t flags);

extern int syno_acl_to_xattr(const struct syno_acl *acl, void *buffer, size_t size);
extern struct syno_acl *syno_acl_from_xattr(const void *value, size_t size);

static inline struct syno_acl *get_cached_syno_acl(struct inode *inode)
{
	struct syno_acl **p, *acl;

	p = &inode->i_syno_acl;
	acl = ACCESS_ONCE(*p);
	if (acl) {
		spin_lock(&inode->i_lock);
		acl = *p;
		if (acl != ACL_NOT_CACHED)
			acl = syno_acl_dup(acl);
		spin_unlock(&inode->i_lock);
	}
	return acl;
}

static inline void set_cached_syno_acl(struct inode *inode, struct syno_acl *acl)
{
	struct syno_acl *old = NULL;

	spin_lock(&inode->i_lock);
	old = inode->i_syno_acl;
	inode->i_syno_acl = acl?syno_acl_dup(acl):ACL_NOT_CACHED;
	spin_unlock(&inode->i_lock);

	if (old != ACL_NOT_CACHED)
		syno_acl_release(old);
}

extern int SYNOACLModuleStatusGet(const char *szModName);
extern void UseACLModule(const char *szModName, int isGet);

#define SYNOACLModuleGet(mod_name) do { UseACLModule(mod_name, 1); } while (0)
#define SYNOACLModulePut(mod_name) do { UseACLModule(mod_name, 0); } while (0)

#endif  
#endif   
