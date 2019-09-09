#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifdef MY_ABC_HERE
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/syno_acl.h>
#include <linux/module.h>

struct syno_acl *syno_acl_alloc(int count, gfp_t flags)
{
	const size_t size = sizeof(struct syno_acl) +
	                    count * sizeof(struct syno_acl_entry);
	struct syno_acl *acl = kmalloc(size, flags);
	if (acl) {
		atomic_set(&acl->a_refcount, 1);
		acl->a_count = count;
	}
	return acl;
}
EXPORT_SYMBOL(syno_acl_alloc);

struct syno_acl *syno_acl_clone(const struct syno_acl *acl, gfp_t flags)
{
	struct syno_acl *clone = NULL;

	if (acl) {
		int size = sizeof(struct syno_acl) + acl->a_count *
		           sizeof(struct syno_acl_entry);
		clone = kmemdup(acl, size, flags);
		if (clone)
			atomic_set(&clone->a_refcount, 1);
	}
	return clone;
}
EXPORT_SYMBOL(syno_acl_clone);

int syno_acl_valid(const struct syno_acl *acl)
{
	const struct syno_acl_entry *pa, *pe;

	FOREACH_SYNOACL_ENTRY(pa, acl, pe) {
		if (pa->e_perm & ~(SYNO_PERM_FULL_CONTROL)){
			return -EINVAL;
		}
		if (pa->e_tag & ~(SYNO_ACL_TAG_ALL)){
			return -EINVAL;
		}
		if (SYNO_ACL_ALLOW != pa->e_allow && SYNO_ACL_DENY != pa->e_allow){
			return -EINVAL;
		}
		if (pa->e_inherit & ~(SYNO_ACL_INHERIT_ALL)){
			return -EINVAL;
		}
	}

	return 0;
}
EXPORT_SYMBOL(syno_acl_valid);

struct syno_acl *syno_acl_realloc(struct syno_acl *acl, unsigned int counts, gfp_t flags)
{
	struct syno_acl *acl_re;
	const size_t size = sizeof(struct syno_acl) +
							counts * sizeof(struct syno_acl_entry);
	if (!acl) {
		return NULL;
	}
	if (atomic_read(&acl->a_refcount) != 1) {
		printk(KERN_ERR" acl reference count: %d \n ", atomic_read(&acl->a_refcount));
		return NULL;
	}

	acl_re = krealloc(acl, size, flags);
	if (acl_re) {
		acl_re->a_count = counts;
	}

	return acl_re;
}
EXPORT_SYMBOL(syno_acl_realloc);

static inline int
ace_syno_from_xattr(struct syno_acl_entry *pAce, syno_acl_xattr_entry *pEntry)
{
	unsigned short tag = le16_to_cpu(pEntry->e_tag);

	if (SYNO_ACL_XATTR_TAG_ID_GROUP & tag) {

		pAce->e_tag = SYNO_ACL_GROUP;
		pAce->e_id = le32_to_cpu(pEntry->e_id);

	} else if (SYNO_ACL_XATTR_TAG_ID_EVERYONE & tag) {

		pAce->e_tag = SYNO_ACL_EVERYONE;
		pAce->e_id = SYNO_ACL_UNDEFINED_ID;

	} else if (SYNO_ACL_XATTR_TAG_ID_USER & tag) {

		pAce->e_tag = SYNO_ACL_USER;
		pAce->e_id = le32_to_cpu(pEntry->e_id);

	} else if (SYNO_ACL_XATTR_TAG_ID_OWNER & tag) {

		pAce->e_tag = SYNO_ACL_OWNER;
		pAce->e_id = SYNO_ACL_UNDEFINED_ID;

	} else if (SYNO_ACL_XATTR_TAG_ID_AUTHENTICATEDUSER & tag) {

		pAce->e_tag = SYNO_ACL_AUTHENTICATEDUSER;
		pAce->e_id = SYNO_ACL_UNDEFINED_ID;

	} else if (SYNO_ACL_XATTR_TAG_ID_SYSTEM & tag) {

		pAce->e_tag = SYNO_ACL_SYSTEM;
		pAce->e_id = SYNO_ACL_UNDEFINED_ID;

	} else {
		return -1;
	}

	if (SYNO_ACL_XATTR_TAG_IS_DENY & tag) {
		pAce->e_allow = SYNO_ACL_DENY;
	} else if (SYNO_ACL_XATTR_TAG_IS_ALLOW & tag){
		pAce->e_allow = SYNO_ACL_ALLOW;
	} else {
		return -1;
	}

	pAce->e_perm = le32_to_cpu(pEntry->e_perm);

	pAce->e_inherit = le16_to_cpu(pEntry->e_inherit);

	pAce->e_level = le32_to_cpu(pEntry->e_level);

	return 0;
}

static inline int
ace_syno_to_xattr(const struct syno_acl_entry *pAce, syno_acl_xattr_entry *pEntry)
{
	int ret = 0;
	unsigned short tag = 0;

	switch(pAce->e_tag){
	case SYNO_ACL_GROUP:
		tag |= SYNO_ACL_XATTR_TAG_ID_GROUP;
		break;
	case SYNO_ACL_EVERYONE:
		tag |= SYNO_ACL_XATTR_TAG_ID_EVERYONE;
		break;
	case SYNO_ACL_USER:
		tag |= SYNO_ACL_XATTR_TAG_ID_USER;
		break;
	case SYNO_ACL_OWNER:
		tag |= SYNO_ACL_XATTR_TAG_ID_OWNER;
		break;
	case SYNO_ACL_AUTHENTICATEDUSER:
		tag |= SYNO_ACL_XATTR_TAG_ID_AUTHENTICATEDUSER;
		break;
	case SYNO_ACL_SYSTEM:
		tag |= SYNO_ACL_XATTR_TAG_ID_SYSTEM;
		break;
	default:
		ret = -EINVAL;
		goto Err;
	}

	switch(pAce->e_allow){
	case SYNO_ACL_DENY:
		tag |= SYNO_ACL_XATTR_TAG_IS_DENY;
		break;
	case SYNO_ACL_ALLOW:
		tag |= SYNO_ACL_XATTR_TAG_IS_ALLOW;
		break;
	default:
		ret = -EINVAL;
		goto Err;
	}

	pEntry->e_tag = cpu_to_le16(tag);
	pEntry->e_inherit  = cpu_to_le16(pAce->e_inherit);
	pEntry->e_perm = cpu_to_le32(pAce->e_perm);
	pEntry->e_id   = cpu_to_le32(pAce->e_id);
	pEntry->e_level = cpu_to_le32(pAce->e_level);

Err:
	return ret;
}

struct syno_acl *syno_acl_from_xattr(const void *value, size_t size)
{
	syno_acl_xattr_header *header;
	syno_acl_xattr_entry *entry, *end;
	int count;
	struct syno_acl *acl;
	struct syno_acl_entry *acl_e;

	if (!value)
		return NULL;
	if (size < sizeof(syno_acl_xattr_header)){
		return ERR_PTR(-EINVAL);
	}

	header = (syno_acl_xattr_header *)value;
	entry = (syno_acl_xattr_entry *)(header+1);

	if (header->a_version != cpu_to_le16(SYNO_ACL_XATTR_VERSION))
		return ERR_PTR(-EOPNOTSUPP);

	count = syno_acl_xattr_count(size);
	if (count < 0){
		return ERR_PTR(-EINVAL);
	}
	if (count == 0)
		return NULL;

	acl = syno_acl_alloc(count, GFP_KERNEL);
	if (!acl)
		return ERR_PTR(-ENOMEM);

	acl_e = acl->a_entries;
	end = entry + count;
	for (; entry != end; acl_e++, entry++) {
		if (0 > ace_syno_from_xattr(acl_e, entry)){
			goto fail;
		}
	}
	return acl;

fail:
	syno_acl_release(acl);
	return ERR_PTR(-EINVAL);
}
EXPORT_SYMBOL(syno_acl_from_xattr);

int syno_acl_to_xattr(const struct syno_acl *acl, void *buffer, size_t size)
{
	syno_acl_xattr_header *ext_acl = NULL;
	syno_acl_xattr_entry *ext_entry = NULL;
	int real_size, i;
	int ret;

	if (!acl) {
		return 0;
	}

	real_size = syno_acl_xattr_size(acl->a_count);
	if (!buffer)
		return real_size;
	if (real_size > size)
		return -ERANGE;

	ext_acl = (syno_acl_xattr_header *)buffer;
	ext_entry = ext_acl->a_entries;
	ext_acl->a_version = cpu_to_le16(SYNO_ACL_XATTR_VERSION);

	for (i = 0; i < acl->a_count; i++, ext_entry++) {
		ret = ace_syno_to_xattr(&(acl->a_entries[i]), ext_entry);
		if (0 > ret) {
			return ret;
		}
	}
	return real_size;
}
EXPORT_SYMBOL(syno_acl_to_xattr);
#endif  
