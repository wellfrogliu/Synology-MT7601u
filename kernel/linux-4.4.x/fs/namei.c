#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/init.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/fsnotify.h>
#include <linux/personality.h>
#include <linux/security.h>
#include <linux/ima.h>
#include <linux/syscalls.h>
#include <linux/mount.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/device_cgroup.h>
#include <linux/fs_struct.h>
#include <linux/posix_acl.h>
#include <linux/hash.h>
#include <asm/uaccess.h>

#ifdef MY_ABC_HERE
#include <linux/magic.h>
#endif  
#ifdef MY_ABC_HERE
#include "synoacl_int.h"
#endif  
#include "internal.h"
#include "mount.h"
#ifdef MY_ABC_HERE
extern struct rw_semaphore namespace_sem;
#endif  

#ifdef MY_ABC_HERE
int syno_utf8chr_to_utf16chr(u_int16_t *p, const u_int8_t *s, int n);
int syno_utf16chr_to_utf8chr(u_int8_t *s, u_int16_t wc, int maxlen);
u_int16_t *syno_generate_default_upcase_table(void);
u_int16_t *def_upcase_table(void);

struct utf8_table {
	int     cmask;
	int     cval;
	int     shift;
	long    lmask;
	long    lval;
};

static struct utf8_table utf8_table[] =
{
    {0x80,  0x00,   0*6,    0x7F,           0,          },
    {0xE0,  0xC0,   1*6,    0x7FF,          0x80,       },
    {0xF0,  0xE0,   2*6,    0xFFFF,         0x800,      },
    {0xF8,  0xF0,   3*6,    0x1FFFFF,       0x10000,    },
    {0xFC,  0xF8,   4*6,    0x3FFFFFF,      0x200000,   },
    {0xFE,  0xFC,   5*6,    0x7FFFFFFF,     0x4000000,  },
    {0,						        }
};

int syno_utf8chr_to_utf16chr(u_int16_t *p, const u_int8_t *s, int n)
{
	long l;
	int c0, c, nc;
	struct utf8_table *t;

	nc = 0;
	c0 = *s;
	l = c0;
	for (t = utf8_table; t->cmask; t++) {
		nc++;
		if ((c0 & t->cmask) == t->cval) {
			l &= t->lmask;
			if (l < t->lval)
				return -1;
			*p = l;
			return nc;
		}
		if (n <= nc)
			return -1;
		s++;
		c = (*s ^ 0x80) & 0xFF;
		if (c & 0xC0)
			return -1;
		l = (l << 6) | c;
	}
	return -1;
}

int syno_utf16chr_to_utf8chr(u_int8_t *s, u_int16_t wc, int maxlen)
{
	long l;
	int c, nc;
	struct utf8_table *t;

	if (s == 0)
		return 0;

	l = wc;
	nc = 0;
	for (t = utf8_table; t->cmask && maxlen; t++, maxlen--) {
		nc++;
		if (l <= t->lmask) {
			c = t->shift;
			*s = t->cval | (l >> c);
			while (c > 0) {
				c -= 6;
				if (c < 0) {
					return -1;
				}
				s++;
				*s = 0x80 | ((l >> c) & 0x3F);
			}
			return nc;
		}
	}
	return -1;
}

static u_int16_t gUC[UTF16_UPCASE_TABLE_SIZE];

void upcase_table_icu_fix(void) {
	int r = 0;
	u_int16_t *uc = gUC;

	static const int uc_icu_table[][2] =	 
	{
		{0x00B5, 0x039C}, {0x0131, 0x0049}, {0x017F, 0x0053}, {0x0195, 0x01F6},
		{0x019E, 0x0220}, {0x01BF, 0x01F7}, {0x01C5, 0x01C4}, {0x01C8, 0x01C7},
		{0x01CB, 0x01CA}, {0x01F2, 0x01F1}, {0x01F9, 0x01F8}, {0x0219, 0x0218},
		{0x021B, 0x021A}, {0x021D, 0x021C}, {0x021F, 0x021E}, {0x0223, 0x0222},
		{0x0225, 0x0224}, {0x0227, 0x0226}, {0x0229, 0x0228}, {0x022B, 0x022A},
		{0x022D, 0x022C}, {0x022F, 0x022E}, {0x0231, 0x0230}, {0x0233, 0x0232},
		{0x0280, 0x01A6}, {0x0345, 0x0399}, {0x03D0, 0x0392}, {0x03D1, 0x0398},
		{0x03D5, 0x03A6}, {0x03D6, 0x03A0}, {0x03D9, 0x03D8}, {0x03DB, 0x03DA},
		{0x03DD, 0x03DC}, {0x03DF, 0x03DE}, {0x03E1, 0x03E0}, {0x03F0, 0x039A},
		{0x03F1, 0x03A1}, {0x03F2, 0x03A3}, {0x03F5, 0x0395}, {0x0450, 0x0400},
		{0x045D, 0x040D}, {0x048B, 0x048A}, {0x048D, 0x048C}, {0x048F, 0x048E},
		{0x04C6, 0x04C5}, {0x04CA, 0x04C9}, {0x04CE, 0x04CD}, {0x04ED, 0x04EC},
		{0x0501, 0x0500}, {0x0503, 0x0502}, {0x0505, 0x0504}, {0x0507, 0x0506},
		{0x0509, 0x0508}, {0x050B, 0x050A}, {0x050D, 0x050C}, {0x050F, 0x050E},
		{0x1E9B, 0x1E60}, {0x1FBE, 0x0399},
		{0}
	};

	for (r = 0; uc_icu_table[r][0]; r++)
		uc[uc_icu_table[r][0]] = uc_icu_table[r][1];
}

u_int16_t *syno_generate_default_upcase_table(void)
{
	const int uc_run_table[][3] = {  
	{0x0061, 0x007B,  -32}, {0x0451, 0x045D, -80}, {0x1F70, 0x1F72,  74},
	{0x00E0, 0x00F7,  -32}, {0x045E, 0x0460, -80}, {0x1F72, 0x1F76,  86},
	{0x00F8, 0x00FF,  -32}, {0x0561, 0x0587, -48}, {0x1F76, 0x1F78, 100},
	{0x0256, 0x0258, -205}, {0x1F00, 0x1F08,   8}, {0x1F78, 0x1F7A, 128},
	{0x028A, 0x028C, -217}, {0x1F10, 0x1F16,   8}, {0x1F7A, 0x1F7C, 112},
	{0x03AC, 0x03AD,  -38}, {0x1F20, 0x1F28,   8}, {0x1F7C, 0x1F7E, 126},
	{0x03AD, 0x03B0,  -37}, {0x1F30, 0x1F38,   8}, {0x1FB0, 0x1FB2,   8},
	{0x03B1, 0x03C2,  -32}, {0x1F40, 0x1F46,   8}, {0x1FD0, 0x1FD2,   8},
	{0x03C2, 0x03C3,  -31}, {0x1F51, 0x1F52,   8}, {0x1FE0, 0x1FE2,   8},
	{0x03C3, 0x03CC,  -32}, {0x1F53, 0x1F54,   8}, {0x1FE5, 0x1FE6,   7},
	{0x03CC, 0x03CD,  -64}, {0x1F55, 0x1F56,   8}, {0x2170, 0x2180, -16},
	{0x03CD, 0x03CF,  -63}, {0x1F57, 0x1F58,   8}, {0x24D0, 0x24EA, -26},
	{0x0430, 0x0450,  -32}, {0x1F60, 0x1F68,   8}, {0xFF41, 0xFF5B, -32},
	{0}
	};

	const int uc_dup_table[][2] = {  
	{0x0100, 0x012F}, {0x01A0, 0x01A6}, {0x03E2, 0x03EF}, {0x04CB, 0x04CC},
	{0x0132, 0x0137}, {0x01B3, 0x01B7}, {0x0460, 0x0481}, {0x04D0, 0x04EB},
	{0x0139, 0x0149}, {0x01CD, 0x01DD}, {0x0490, 0x04BF}, {0x04EE, 0x04F5},
	{0x014A, 0x0178}, {0x01DE, 0x01EF}, {0x04BF, 0x04BF}, {0x04F8, 0x04F9},
	{0x0179, 0x017E}, {0x01F4, 0x01F5}, {0x04C1, 0x04C4}, {0x1E00, 0x1E95},
	{0x018B, 0x018B}, {0x01FA, 0x0218}, {0x04C7, 0x04C8}, {0x1EA0, 0x1EF9},
	{0}
	};

	const int uc_word_table[][2] = {  
	{0x00FF, 0x0178}, {0x01AD, 0x01AC}, {0x01F3, 0x01F1}, {0x0269, 0x0196},
	{0x0183, 0x0182}, {0x01B0, 0x01AF}, {0x0253, 0x0181}, {0x026F, 0x019C},
	{0x0185, 0x0184}, {0x01B9, 0x01B8}, {0x0254, 0x0186}, {0x0272, 0x019D},
	{0x0188, 0x0187}, {0x01BD, 0x01BC}, {0x0259, 0x018F}, {0x0275, 0x019F},
	{0x018C, 0x018B}, {0x01C6, 0x01C4}, {0x025B, 0x0190}, {0x0283, 0x01A9},
	{0x0192, 0x0191}, {0x01C9, 0x01C7}, {0x0260, 0x0193}, {0x0288, 0x01AE},
	{0x0199, 0x0198}, {0x01CC, 0x01CA}, {0x0263, 0x0194}, {0x0292, 0x01B7},
	{0x01A8, 0x01A7}, {0x01DD, 0x018E}, {0x0268, 0x0197},
	{0}
	};

	int i, r;
	u_int16_t *uc;

	uc = gUC;

	memset(uc, 0, UTF16_UPCASE_TABLE_SIZE * sizeof(u_int16_t));

	for (i = 0; i < UTF16_UPCASE_TABLE_SIZE; i++)
		uc[i] = i;
	for (r = 0; uc_run_table[r][0]; r++)
		for (i = uc_run_table[r][0]; i < uc_run_table[r][1]; i++)
			uc[i] = uc[i] + uc_run_table[r][2];
	for (r = 0; uc_dup_table[r][0]; r++)
		for (i = uc_dup_table[r][0]; i < uc_dup_table[r][1]; i += 2)
			uc[i + 1] = uc[i + 1] - 1;
	for (r = 0; uc_word_table[r][0]; r++)
		uc[uc_word_table[r][0]] = uc_word_table[r][1];
	upcase_table_icu_fix();
	return uc;
}

static u_int16_t *upcase_table = NULL;

u_int16_t *def_upcase_table(void)
{
    if(upcase_table==NULL)
        upcase_table = syno_generate_default_upcase_table();

    return upcase_table;
}

int syno_utf8_toupper(u_int8_t *to,const u_int8_t *from, int maxlen, int clenfrom, u_int16_t *upcasetable)
{
	u_int16_t *upcase_tbl;
	u_int16_t wc;
	u_int8_t *op;
	int size;

	upcase_tbl = (upcasetable==NULL) ? def_upcase_table() : upcasetable;

	op = to;
	while (clenfrom && maxlen) {
		size = syno_utf8chr_to_utf16chr(&wc, from, clenfrom);
		if (size == -1) {
			from++;
			clenfrom--;
			continue;
		} else {
			from += size;
			clenfrom -= size;
		}
		size = syno_utf16chr_to_utf8chr(op, upcase_tbl[wc], maxlen);
		if (size == -1) {
			continue;
		} else {
			op += size;
			maxlen -= size;
		}
	}
	*op = 0;
	return (op - to);
}
EXPORT_SYMBOL(syno_utf8_toupper);

int syno_utf8_strcmp(const u_int8_t *utf8str1,const u_int8_t *utf8str2,int len_utf8_str1, int len_utf8_str2, u_int16_t *upcasetable)
{
	u_int16_t *upcase_tbl;
	u_int16_t wc1, wc2;
	int size1, size2;
	int result = -1;

	upcase_tbl = (upcasetable==NULL) ? def_upcase_table() : upcasetable;

	while (len_utf8_str1 && len_utf8_str2) {
		size1 = syno_utf8chr_to_utf16chr(&wc1, utf8str1, len_utf8_str1);
		size2 = syno_utf8chr_to_utf16chr(&wc2, utf8str2, len_utf8_str2);

		if (size1 != -1 && size2 != -1) {
			if (upcase_tbl[wc1] != upcase_tbl[wc2])
				goto END;
		} else if (size1 == -1 && size2 == -1) {
			if (*utf8str1 != *utf8str2)
				goto END;
			size1 = size2 = 1;
		} else {
			goto END;
		}
		utf8str1 += size1;
		len_utf8_str1 -= size1;
		utf8str2 += size2;
		len_utf8_str2 -= size2;
	}
	if (len_utf8_str1 == 0 && len_utf8_str2 == 0)
		result = 0;
END:
	return result;
}
EXPORT_SYMBOL(syno_utf8_strcmp);
#endif  

#define EMBEDDED_NAME_MAX	(PATH_MAX - offsetof(struct filename, iname))

struct filename *
getname_flags(const char __user *filename, int flags, int *empty)
{
	struct filename *result;
	char *kname;
	int len;

	result = audit_reusename(filename);
	if (result)
		return result;

	result = __getname();
	if (unlikely(!result))
		return ERR_PTR(-ENOMEM);

	kname = (char *)result->iname;
	result->name = kname;

	len = strncpy_from_user(kname, filename, EMBEDDED_NAME_MAX);
	if (unlikely(len < 0)) {
		__putname(result);
		return ERR_PTR(len);
	}

	if (unlikely(len == EMBEDDED_NAME_MAX)) {
		const size_t size = offsetof(struct filename, iname[1]);
		kname = (char *)result;

		result = kzalloc(size, GFP_KERNEL);
		if (unlikely(!result)) {
			__putname(kname);
			return ERR_PTR(-ENOMEM);
		}
		result->name = kname;
		len = strncpy_from_user(kname, filename, PATH_MAX);
		if (unlikely(len < 0)) {
			__putname(kname);
			kfree(result);
			return ERR_PTR(len);
		}
		if (unlikely(len == PATH_MAX)) {
			__putname(kname);
			kfree(result);
			return ERR_PTR(-ENAMETOOLONG);
		}
	}

	result->refcnt = 1;
	 
	if (unlikely(!len)) {
		if (empty)
			*empty = 1;
		if (!(flags & LOOKUP_EMPTY)) {
			putname(result);
			return ERR_PTR(-ENOENT);
		}
	}

	result->uptr = filename;
	result->aname = NULL;
	audit_getname(result);
	return result;
}

struct filename *
getname(const char __user * filename)
{
	return getname_flags(filename, 0, NULL);
}

struct filename *
getname_kernel(const char * filename)
{
	struct filename *result;
	int len = strlen(filename) + 1;

	result = __getname();
	if (unlikely(!result))
		return ERR_PTR(-ENOMEM);

	if (len <= EMBEDDED_NAME_MAX) {
		result->name = (char *)result->iname;
	} else if (len <= PATH_MAX) {
		struct filename *tmp;

		tmp = kmalloc(sizeof(*tmp), GFP_KERNEL);
		if (unlikely(!tmp)) {
			__putname(result);
			return ERR_PTR(-ENOMEM);
		}
		tmp->name = (char *)result;
		result = tmp;
	} else {
		__putname(result);
		return ERR_PTR(-ENAMETOOLONG);
	}
	memcpy((char *)result->name, filename, len);
	result->uptr = NULL;
	result->aname = NULL;
	result->refcnt = 1;
	audit_getname(result);

	return result;
}

void putname(struct filename *name)
{
	BUG_ON(name->refcnt <= 0);

	if (--name->refcnt > 0)
		return;

	if (name->name != name->iname) {
		__putname(name->name);
		kfree(name);
	} else
		__putname(name);
}

static int check_acl(struct inode *inode, int mask)
{
#ifdef CONFIG_FS_POSIX_ACL
	struct posix_acl *acl;

	if (mask & MAY_NOT_BLOCK) {
		acl = get_cached_acl_rcu(inode, ACL_TYPE_ACCESS);
	        if (!acl)
	                return -EAGAIN;
		 
		if (acl == ACL_NOT_CACHED)
			return -ECHILD;
	        return posix_acl_permission(inode, acl, mask & ~MAY_NOT_BLOCK);
	}

	acl = get_acl(inode, ACL_TYPE_ACCESS);
	if (IS_ERR(acl))
		return PTR_ERR(acl);
	if (acl) {
	        int error = posix_acl_permission(inode, acl, mask);
	        posix_acl_release(acl);
	        return error;
	}
#endif

	return -EAGAIN;
}

static int acl_permission_check(struct inode *inode, int mask)
{
	unsigned int mode = inode->i_mode;

	if (likely(uid_eq(current_fsuid(), inode->i_uid)))
		mode >>= 6;
	else {
		if (IS_POSIXACL(inode) && (mode & S_IRWXG)) {
			int error = check_acl(inode, mask);
			if (error != -EAGAIN)
				return error;
		}

		if (in_group_p(inode->i_gid))
			mode >>= 3;
	}

	if ((mask & ~mode & (MAY_READ | MAY_WRITE | MAY_EXEC)) == 0)
		return 0;
	return -EACCES;
}

int generic_permission(struct inode *inode, int mask)
{
	int ret;

	ret = acl_permission_check(inode, mask);
	if (ret != -EACCES)
		return ret;

	if (S_ISDIR(inode->i_mode)) {
		 
		if (capable_wrt_inode_uidgid(inode, CAP_DAC_OVERRIDE))
			return 0;
		if (!(mask & MAY_WRITE))
			if (capable_wrt_inode_uidgid(inode,
						     CAP_DAC_READ_SEARCH))
				return 0;
		return -EACCES;
	}
	 
	if (!(mask & MAY_EXEC) || (inode->i_mode & S_IXUGO))
		if (capable_wrt_inode_uidgid(inode, CAP_DAC_OVERRIDE))
			return 0;

	mask &= MAY_READ | MAY_WRITE | MAY_EXEC;
	if (mask == MAY_READ)
		if (capable_wrt_inode_uidgid(inode, CAP_DAC_READ_SEARCH))
			return 0;

	return -EACCES;
}
EXPORT_SYMBOL(generic_permission);

static inline int do_inode_permission(struct inode *inode, int mask)
{
	if (unlikely(!(inode->i_opflags & IOP_FASTPERM))) {
		if (likely(inode->i_op->permission))
			return inode->i_op->permission(inode, mask);

		spin_lock(&inode->i_lock);
		inode->i_opflags |= IOP_FASTPERM;
		spin_unlock(&inode->i_lock);
	}
	return generic_permission(inode, mask);
}

int __inode_permission(struct inode *inode, int mask)
{
	int retval;

	if (unlikely(mask & MAY_WRITE)) {
		 
		if (IS_IMMUTABLE(inode))
			return -EACCES;
	}

	retval = do_inode_permission(inode, mask);
	if (retval)
		return retval;

	retval = devcgroup_inode_permission(inode, mask);
	if (retval)
		return retval;

	return security_inode_permission(inode, mask);
}
EXPORT_SYMBOL(__inode_permission);

static int sb_permission(struct super_block *sb, struct inode *inode, int mask)
{
	if (unlikely(mask & MAY_WRITE)) {
		umode_t mode = inode->i_mode;

		if ((sb->s_flags & MS_RDONLY) &&
		    (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)))
			return -EROFS;
	}
	return 0;
}

int inode_permission(struct inode *inode, int mask)
{
	int retval;

	retval = sb_permission(inode->i_sb, inode, mask);
	if (retval)
		return retval;
	return __inode_permission(inode, mask);
}
EXPORT_SYMBOL(inode_permission);

void path_get(const struct path *path)
{
	mntget(path->mnt);
	dget(path->dentry);
}
EXPORT_SYMBOL(path_get);

void path_put(const struct path *path)
{
	dput(path->dentry);
	mntput(path->mnt);
}
EXPORT_SYMBOL(path_put);

#define EMBEDDED_LEVELS 2
struct nameidata {
	struct path	path;
	struct qstr	last;
	struct path	root;
	struct inode	*inode;  
	unsigned int	flags;
	unsigned	seq, m_seq;
	int		last_type;
	unsigned	depth;
	int		total_link_count;
	struct saved {
		struct path link;
		void *cookie;
		const char *name;
		struct inode *inode;
		unsigned seq;
	} *stack, internal[EMBEDDED_LEVELS];
	struct filename	*name;
	struct nameidata *saved;
	unsigned	root_seq;
	int		dfd;
#ifdef MY_ABC_HERE
	unsigned char *real_filename;
	unsigned char *real_filename_cur_locate;
	unsigned int real_filename_len;
	bool is_init;
	struct path	caseless_path;
#endif  
};

static void set_nameidata(struct nameidata *p, int dfd, struct filename *name)
{
	struct nameidata *old = current->nameidata;
	p->stack = p->internal;
	p->dfd = dfd;
	p->name = name;
	p->total_link_count = old ? old->total_link_count : 0;
	p->saved = old;
	current->nameidata = p;
}

static void restore_nameidata(void)
{
	struct nameidata *now = current->nameidata, *old = now->saved;

	current->nameidata = old;
	if (old)
		old->total_link_count = now->total_link_count;
	if (now->stack != now->internal) {
		kfree(now->stack);
		now->stack = now->internal;
	}
}

static int __nd_alloc_stack(struct nameidata *nd)
{
	struct saved *p;

	if (nd->flags & LOOKUP_RCU) {
		p= kmalloc(MAXSYMLINKS * sizeof(struct saved),
				  GFP_ATOMIC);
		if (unlikely(!p))
			return -ECHILD;
	} else {
		p= kmalloc(MAXSYMLINKS * sizeof(struct saved),
				  GFP_KERNEL);
		if (unlikely(!p))
			return -ENOMEM;
	}
	memcpy(p, nd->internal, sizeof(nd->internal));
	nd->stack = p;
	return 0;
}

static bool path_connected(const struct path *path)
{
	struct vfsmount *mnt = path->mnt;

	if (mnt->mnt_root == mnt->mnt_sb->s_root)
		return true;

	return is_subdir(path->dentry, mnt->mnt_root);
}

static inline int nd_alloc_stack(struct nameidata *nd)
{
	if (likely(nd->depth != EMBEDDED_LEVELS))
		return 0;
	if (likely(nd->stack != nd->internal))
		return 0;
	return __nd_alloc_stack(nd);
}

static void drop_links(struct nameidata *nd)
{
	int i = nd->depth;
	while (i--) {
		struct saved *last = nd->stack + i;
		struct inode *inode = last->inode;
		if (last->cookie && inode->i_op->put_link) {
			inode->i_op->put_link(inode, last->cookie);
			last->cookie = NULL;
		}
	}
}

static void terminate_walk(struct nameidata *nd)
{
	drop_links(nd);
	if (!(nd->flags & LOOKUP_RCU)) {
		int i;
		path_put(&nd->path);
		for (i = 0; i < nd->depth; i++)
			path_put(&nd->stack[i].link);
		if (nd->root.mnt && !(nd->flags & LOOKUP_ROOT)) {
			path_put(&nd->root);
			nd->root.mnt = NULL;
		}
	} else {
		nd->flags &= ~LOOKUP_RCU;
		if (!(nd->flags & LOOKUP_ROOT))
			nd->root.mnt = NULL;
		rcu_read_unlock();
	}
	nd->depth = 0;
}

static bool legitimize_path(struct nameidata *nd,
			    struct path *path, unsigned seq)
{
	int res = __legitimize_mnt(path->mnt, nd->m_seq);
	if (unlikely(res)) {
		if (res > 0)
			path->mnt = NULL;
		path->dentry = NULL;
		return false;
	}
	if (unlikely(!lockref_get_not_dead(&path->dentry->d_lockref))) {
		path->dentry = NULL;
		return false;
	}
	return !read_seqcount_retry(&path->dentry->d_seq, seq);
}

static bool legitimize_links(struct nameidata *nd)
{
	int i;
	for (i = 0; i < nd->depth; i++) {
		struct saved *last = nd->stack + i;
		if (unlikely(!legitimize_path(nd, &last->link, last->seq))) {
			drop_links(nd);
			nd->depth = i + 1;
			return false;
		}
	}
	return true;
}

static int unlazy_walk(struct nameidata *nd, struct dentry *dentry, unsigned seq)
{
	struct dentry *parent = nd->path.dentry;

	BUG_ON(!(nd->flags & LOOKUP_RCU));

	nd->flags &= ~LOOKUP_RCU;
	if (unlikely(!legitimize_links(nd)))
		goto out2;
	if (unlikely(!legitimize_mnt(nd->path.mnt, nd->m_seq)))
		goto out2;
	if (unlikely(!lockref_get_not_dead(&parent->d_lockref)))
		goto out1;

	if (!dentry) {
		if (read_seqcount_retry(&parent->d_seq, nd->seq))
			goto out;
		BUG_ON(nd->inode != parent->d_inode);
	} else {
		if (!lockref_get_not_dead(&dentry->d_lockref))
			goto out;
		if (read_seqcount_retry(&dentry->d_seq, seq))
			goto drop_dentry;
	}

	if (nd->root.mnt && !(nd->flags & LOOKUP_ROOT)) {
		if (unlikely(!legitimize_path(nd, &nd->root, nd->root_seq))) {
			rcu_read_unlock();
			dput(dentry);
			return -ECHILD;
		}
	}

	rcu_read_unlock();
	return 0;

drop_dentry:
	rcu_read_unlock();
	dput(dentry);
	goto drop_root_mnt;
out2:
	nd->path.mnt = NULL;
out1:
	nd->path.dentry = NULL;
out:
	rcu_read_unlock();
drop_root_mnt:
	if (!(nd->flags & LOOKUP_ROOT))
		nd->root.mnt = NULL;
	return -ECHILD;
}

static int unlazy_link(struct nameidata *nd, struct path *link, unsigned seq)
{
	if (unlikely(!legitimize_path(nd, link, seq))) {
		drop_links(nd);
		nd->depth = 0;
		nd->flags &= ~LOOKUP_RCU;
		nd->path.mnt = NULL;
		nd->path.dentry = NULL;
		if (!(nd->flags & LOOKUP_ROOT))
			nd->root.mnt = NULL;
		rcu_read_unlock();
	} else if (likely(unlazy_walk(nd, NULL, 0)) == 0) {
		return 0;
	}
	path_put(link);
	return -ECHILD;
}

static inline int d_revalidate(struct dentry *dentry, unsigned int flags)
{
	return dentry->d_op->d_revalidate(dentry, flags);
}

static int complete_walk(struct nameidata *nd)
{
	struct dentry *dentry = nd->path.dentry;
	int status;

	if (nd->flags & LOOKUP_RCU) {
		if (!(nd->flags & LOOKUP_ROOT))
			nd->root.mnt = NULL;
		if (unlikely(unlazy_walk(nd, NULL, 0)))
			return -ECHILD;
	}

	if (likely(!(nd->flags & LOOKUP_JUMPED)))
		return 0;

	if (likely(!(dentry->d_flags & DCACHE_OP_WEAK_REVALIDATE)))
		return 0;

	status = dentry->d_op->d_weak_revalidate(dentry, nd->flags);
	if (status > 0)
		return 0;

	if (!status)
		status = -ESTALE;

	return status;
}

static void set_root(struct nameidata *nd)
{
	get_fs_root(current->fs, &nd->root);
}

static void set_root_rcu(struct nameidata *nd)
{
	struct fs_struct *fs = current->fs;
	unsigned seq;

	do {
		seq = read_seqcount_begin(&fs->seq);
		nd->root = fs->root;
		nd->root_seq = __read_seqcount_begin(&nd->root.dentry->d_seq);
	} while (read_seqcount_retry(&fs->seq, seq));
}

static void path_put_conditional(struct path *path, struct nameidata *nd)
{
	dput(path->dentry);
	if (path->mnt != nd->path.mnt)
		mntput(path->mnt);
}

static inline void path_to_nameidata(const struct path *path,
					struct nameidata *nd)
{
	if (!(nd->flags & LOOKUP_RCU)) {
		dput(nd->path.dentry);
		if (nd->path.mnt != path->mnt)
			mntput(nd->path.mnt);
	}
	nd->path.mnt = path->mnt;
	nd->path.dentry = path->dentry;
}

void nd_jump_link(struct path *path)
{
	struct nameidata *nd = current->nameidata;
	path_put(&nd->path);

	nd->path = *path;
	nd->inode = nd->path.dentry->d_inode;
	nd->flags |= LOOKUP_JUMPED;
}

static inline void put_link(struct nameidata *nd)
{
	struct saved *last = nd->stack + --nd->depth;
	struct inode *inode = last->inode;
	if (last->cookie && inode->i_op->put_link)
		inode->i_op->put_link(inode, last->cookie);
	if (!(nd->flags & LOOKUP_RCU))
		path_put(&last->link);
}

int sysctl_protected_symlinks __read_mostly = 0;
int sysctl_protected_hardlinks __read_mostly = 0;

static inline int may_follow_link(struct nameidata *nd)
{
	const struct inode *inode;
	const struct inode *parent;
	kuid_t puid;

	if (!sysctl_protected_symlinks)
		return 0;

	inode = nd->stack[0].inode;
	if (uid_eq(current_cred()->fsuid, inode->i_uid))
		return 0;

	parent = nd->inode;
	if ((parent->i_mode & (S_ISVTX|S_IWOTH)) != (S_ISVTX|S_IWOTH))
		return 0;

	puid = parent->i_uid;
	if (uid_valid(puid) && uid_eq(puid, inode->i_uid))
		return 0;

	if (nd->flags & LOOKUP_RCU)
		return -ECHILD;

	audit_log_link_denied("follow_link", &nd->stack[0].link);
	return -EACCES;
}

#ifdef MY_ABC_HERE
static bool safe_hardlink_source(struct dentry *dentry)
#else
static bool safe_hardlink_source(struct inode *inode)
#endif  
{
#ifdef MY_ABC_HERE
	struct inode *inode = dentry->d_inode;
#endif  
	umode_t mode = inode->i_mode;

	if (!S_ISREG(mode))
		return false;

	if (mode & S_ISUID)
		return false;

	if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP))
		return false;

#ifdef MY_ABC_HERE
	if (IS_SYNOACL(dentry)) {
		if (synoacl_op_perm(dentry,  MAY_READ | MAY_WRITE)) {
			return false;
		}
	} else
#endif  
	if (inode_permission(inode, MAY_READ | MAY_WRITE))
		return false;

	return true;
}

static int may_linkat(struct path *link)
{
	struct inode *inode;

	if (!sysctl_protected_hardlinks)
		return 0;

	inode = link->dentry->d_inode;

#ifdef MY_ABC_HERE
	if (inode_owner_or_capable(inode) || safe_hardlink_source(link->dentry)) {
		return 0;
	}
#else
	if (inode_owner_or_capable(inode) || safe_hardlink_source(inode))
		return 0;
#endif  

	audit_log_link_denied("linkat", link);
	return -EPERM;
}

static __always_inline
const char *get_link(struct nameidata *nd)
{
	struct saved *last = nd->stack + nd->depth - 1;
	struct dentry *dentry = last->link.dentry;
	struct inode *inode = last->inode;
	int error;
	const char *res;

	if (!(nd->flags & LOOKUP_RCU)) {
		touch_atime(&last->link);
		cond_resched();
	} else if (atime_needs_update(&last->link, inode)) {
		if (unlikely(unlazy_walk(nd, NULL, 0)))
			return ERR_PTR(-ECHILD);
		touch_atime(&last->link);
	}

	error = security_inode_follow_link(dentry, inode,
					   nd->flags & LOOKUP_RCU);
	if (unlikely(error))
		return ERR_PTR(error);

	nd->last_type = LAST_BIND;
	res = inode->i_link;
	if (!res) {
		if (nd->flags & LOOKUP_RCU) {
			if (unlikely(unlazy_walk(nd, NULL, 0)))
				return ERR_PTR(-ECHILD);
		}
		res = inode->i_op->follow_link(dentry, &last->cookie);
		if (IS_ERR_OR_NULL(res)) {
			last->cookie = NULL;
			return res;
		}
	}
	if (*res == '/') {
		if (nd->flags & LOOKUP_RCU) {
			struct dentry *d;
			if (!nd->root.mnt)
				set_root_rcu(nd);
			nd->path = nd->root;
			d = nd->path.dentry;
			nd->inode = d->d_inode;
			nd->seq = nd->root_seq;
			if (unlikely(read_seqcount_retry(&d->d_seq, nd->seq)))
				return ERR_PTR(-ECHILD);
		} else {
			if (!nd->root.mnt)
				set_root(nd);
			path_put(&nd->path);
			nd->path = nd->root;
			path_get(&nd->root);
			nd->inode = nd->path.dentry->d_inode;
		}
		nd->flags |= LOOKUP_JUMPED;
		while (unlikely(*++res == '/'))
			;
	}
	if (!*res)
		res = NULL;
	return res;
}

int follow_up(struct path *path)
{
	struct mount *mnt = real_mount(path->mnt);
	struct mount *parent;
	struct dentry *mountpoint;

	read_seqlock_excl(&mount_lock);
	parent = mnt->mnt_parent;
	if (parent == mnt) {
		read_sequnlock_excl(&mount_lock);
		return 0;
	}
	mntget(&parent->mnt);
	mountpoint = dget(mnt->mnt_mountpoint);
	read_sequnlock_excl(&mount_lock);
	dput(path->dentry);
	path->dentry = mountpoint;
	mntput(path->mnt);
	path->mnt = &parent->mnt;
	return 1;
}
EXPORT_SYMBOL(follow_up);

static int follow_automount(struct path *path, struct nameidata *nd,
			    bool *need_mntput)
{
	struct vfsmount *mnt;
	int err;

	if (!path->dentry->d_op || !path->dentry->d_op->d_automount)
		return -EREMOTE;

	if (!(nd->flags & (LOOKUP_PARENT | LOOKUP_DIRECTORY |
			   LOOKUP_OPEN | LOOKUP_CREATE | LOOKUP_AUTOMOUNT)) &&
	    path->dentry->d_inode)
		return -EISDIR;

	nd->total_link_count++;
	if (nd->total_link_count >= 40)
		return -ELOOP;

	mnt = path->dentry->d_op->d_automount(path);
	if (IS_ERR(mnt)) {
		 
		if (PTR_ERR(mnt) == -EISDIR && (nd->flags & LOOKUP_PARENT))
			return -EREMOTE;
		return PTR_ERR(mnt);
	}

	if (!mnt)  
		return 0;

	if (!*need_mntput) {
		 
		mntget(path->mnt);
		*need_mntput = true;
	}
	err = finish_automount(mnt, path);

	switch (err) {
	case -EBUSY:
		 
		return 0;
	case 0:
		path_put(path);
		path->mnt = mnt;
		path->dentry = dget(mnt->mnt_root);
		return 0;
	default:
		return err;
	}

}

static int follow_managed(struct path *path, struct nameidata *nd)
{
	struct vfsmount *mnt = path->mnt;  
	unsigned managed;
	bool need_mntput = false;
	int ret = 0;

	while (managed = ACCESS_ONCE(path->dentry->d_flags),
	       managed &= DCACHE_MANAGED_DENTRY,
	       unlikely(managed != 0)) {
		 
		if (managed & DCACHE_MANAGE_TRANSIT) {
			BUG_ON(!path->dentry->d_op);
			BUG_ON(!path->dentry->d_op->d_manage);
			ret = path->dentry->d_op->d_manage(path->dentry, false);
			if (ret < 0)
				break;
		}

		if (managed & DCACHE_MOUNTED) {
			struct vfsmount *mounted = lookup_mnt(path);
			if (mounted) {
				dput(path->dentry);
				if (need_mntput)
					mntput(path->mnt);
				path->mnt = mounted;
				path->dentry = dget(mounted->mnt_root);
				need_mntput = true;
#ifdef MY_ABC_HERE
				nd->flags |= LOOKUP_MOUNTED;
#endif  
				continue;
			}

		}

		if (managed & DCACHE_NEED_AUTOMOUNT) {
			ret = follow_automount(path, nd, &need_mntput);
			if (ret < 0)
				break;
			continue;
		}

		break;
	}

	if (need_mntput && path->mnt == mnt)
		mntput(path->mnt);
	if (ret == -EISDIR)
		ret = 0;
	if (need_mntput)
		nd->flags |= LOOKUP_JUMPED;
	if (unlikely(ret < 0))
		path_put_conditional(path, nd);
	return ret;
}

int follow_down_one(struct path *path)
{
	struct vfsmount *mounted;

	mounted = lookup_mnt(path);
	if (mounted) {
		dput(path->dentry);
		mntput(path->mnt);
		path->mnt = mounted;
		path->dentry = dget(mounted->mnt_root);
		return 1;
	}
	return 0;
}
EXPORT_SYMBOL(follow_down_one);

static inline int managed_dentry_rcu(struct dentry *dentry)
{
	return (dentry->d_flags & DCACHE_MANAGE_TRANSIT) ?
		dentry->d_op->d_manage(dentry, true) : 0;
}

static bool __follow_mount_rcu(struct nameidata *nd, struct path *path,
			       struct inode **inode, unsigned *seqp)
{
	for (;;) {
		struct mount *mounted;
		 
		switch (managed_dentry_rcu(path->dentry)) {
		case -ECHILD:
		default:
			return false;
		case -EISDIR:
			return true;
		case 0:
			break;
		}

		if (!d_mountpoint(path->dentry))
			return !(path->dentry->d_flags & DCACHE_NEED_AUTOMOUNT);

		mounted = __lookup_mnt(path->mnt, path->dentry);
		if (!mounted)
			break;
		path->mnt = &mounted->mnt;
		path->dentry = mounted->mnt.mnt_root;
		nd->flags |= LOOKUP_JUMPED;
		*seqp = read_seqcount_begin(&path->dentry->d_seq);
		 
		*inode = path->dentry->d_inode;
#ifdef MY_ABC_HERE
		nd->flags |= LOOKUP_MOUNTED;
#endif  
	}
	return !read_seqretry(&mount_lock, nd->m_seq) &&
		!(path->dentry->d_flags & DCACHE_NEED_AUTOMOUNT);
}

static int follow_dotdot_rcu(struct nameidata *nd)
{
	struct inode *inode = nd->inode;
	if (!nd->root.mnt)
		set_root_rcu(nd);

	while (1) {
		if (path_equal(&nd->path, &nd->root))
			break;
		if (nd->path.dentry != nd->path.mnt->mnt_root) {
			struct dentry *old = nd->path.dentry;
			struct dentry *parent = old->d_parent;
			unsigned seq;

			inode = parent->d_inode;
			seq = read_seqcount_begin(&parent->d_seq);
			if (unlikely(read_seqcount_retry(&old->d_seq, nd->seq)))
				return -ECHILD;
			nd->path.dentry = parent;
			nd->seq = seq;
			if (unlikely(!path_connected(&nd->path)))
				return -ENOENT;
			break;
		} else {
			struct mount *mnt = real_mount(nd->path.mnt);
			struct mount *mparent = mnt->mnt_parent;
			struct dentry *mountpoint = mnt->mnt_mountpoint;
			struct inode *inode2 = mountpoint->d_inode;
			unsigned seq = read_seqcount_begin(&mountpoint->d_seq);
			if (unlikely(read_seqretry(&mount_lock, nd->m_seq)))
				return -ECHILD;
			if (&mparent->mnt == nd->path.mnt)
				break;
			 
			nd->path.dentry = mountpoint;
			nd->path.mnt = &mparent->mnt;
			inode = inode2;
			nd->seq = seq;
		}
	}
	while (unlikely(d_mountpoint(nd->path.dentry))) {
		struct mount *mounted;
		mounted = __lookup_mnt(nd->path.mnt, nd->path.dentry);
		if (unlikely(read_seqretry(&mount_lock, nd->m_seq)))
			return -ECHILD;
		if (!mounted)
			break;
		nd->path.mnt = &mounted->mnt;
		nd->path.dentry = mounted->mnt.mnt_root;
		inode = nd->path.dentry->d_inode;
		nd->seq = read_seqcount_begin(&nd->path.dentry->d_seq);
	}
	nd->inode = inode;
	return 0;
}

int follow_down(struct path *path)
{
	unsigned managed;
	int ret;

	while (managed = ACCESS_ONCE(path->dentry->d_flags),
	       unlikely(managed & DCACHE_MANAGED_DENTRY)) {
		 
		if (managed & DCACHE_MANAGE_TRANSIT) {
			BUG_ON(!path->dentry->d_op);
			BUG_ON(!path->dentry->d_op->d_manage);
			ret = path->dentry->d_op->d_manage(
				path->dentry, false);
			if (ret < 0)
				return ret == -EISDIR ? 0 : ret;
		}

		if (managed & DCACHE_MOUNTED) {
			struct vfsmount *mounted = lookup_mnt(path);
			if (!mounted)
				break;
			dput(path->dentry);
			mntput(path->mnt);
			path->mnt = mounted;
			path->dentry = dget(mounted->mnt_root);
			continue;
		}

		break;
	}
	return 0;
}
EXPORT_SYMBOL(follow_down);

static void follow_mount(struct path *path)
{
	while (d_mountpoint(path->dentry)) {
		struct vfsmount *mounted = lookup_mnt(path);
		if (!mounted)
			break;
		dput(path->dentry);
		mntput(path->mnt);
		path->mnt = mounted;
		path->dentry = dget(mounted->mnt_root);
	}
}

static int follow_dotdot(struct nameidata *nd)
{
	if (!nd->root.mnt)
		set_root(nd);

	while(1) {
		struct dentry *old = nd->path.dentry;

		if (nd->path.dentry == nd->root.dentry &&
		    nd->path.mnt == nd->root.mnt) {
			break;
		}
		if (nd->path.dentry != nd->path.mnt->mnt_root) {
			 
			nd->path.dentry = dget_parent(nd->path.dentry);
			dput(old);
			if (unlikely(!path_connected(&nd->path)))
				return -ENOENT;
			break;
		}
		if (!follow_up(&nd->path))
			break;
	}
	follow_mount(&nd->path);
	nd->inode = nd->path.dentry->d_inode;
	return 0;
}

static struct dentry *lookup_dcache(struct qstr *name, struct dentry *dir,
				    unsigned int flags, bool *need_lookup)
{
	struct dentry *dentry;
	int error;

	*need_lookup = false;
#ifdef MY_ABC_HERE
	dentry = d_lookup_case(dir, name, (LOOKUP_CASELESS_COMPARE & flags) ? 1 : 0);
#else
	dentry = d_lookup(dir, name);
#endif  
	if (dentry) {
		if (dentry->d_flags & DCACHE_OP_REVALIDATE) {
			error = d_revalidate(dentry, flags);
			if (unlikely(error <= 0)) {
				if (error < 0) {
					dput(dentry);
					return ERR_PTR(error);
				} else {
					d_invalidate(dentry);
					dput(dentry);
					dentry = NULL;
				}
			}
		}
	}

	if (!dentry) {
		dentry = d_alloc(dir, name);
		if (unlikely(!dentry))
			return ERR_PTR(-ENOMEM);

		*need_lookup = true;
	}
	return dentry;
}

static struct dentry *lookup_real(struct inode *dir, struct dentry *dentry,
				  unsigned int flags)
{
	struct dentry *old;

	if (unlikely(IS_DEADDIR(dir))) {
		dput(dentry);
		return ERR_PTR(-ENOENT);
	}

	old = dir->i_op->lookup(dir, dentry, flags);
	if (unlikely(old)) {
		dput(dentry);
		dentry = old;
	}
	return dentry;
}

static struct dentry *__lookup_hash(struct qstr *name,
		struct dentry *base, unsigned int flags)
{
	bool need_lookup;
	struct dentry *dentry;

	dentry = lookup_dcache(name, base, flags, &need_lookup);
	if (!need_lookup)
		return dentry;

	return lookup_real(base->d_inode, dentry, flags);
}

#ifdef MY_ABC_HERE
struct dentry *lookup_hash(struct nameidata *nd)
{
	return __lookup_hash(&nd->last, nd->path.dentry, nd->flags);
}
EXPORT_SYMBOL(lookup_hash);
#endif  

static int lookup_fast(struct nameidata *nd,
		       struct path *path, struct inode **inode,
		       unsigned *seqp)
{
	struct vfsmount *mnt = nd->path.mnt;
	struct dentry *dentry, *parent = nd->path.dentry;
	int need_reval = 1;
	int status = 1;
	int err;
#ifdef MY_ABC_HERE
	int caseless = (LOOKUP_CASELESS_COMPARE & nd->flags) ? 1 : 0;
#endif  

	if (nd->flags & LOOKUP_RCU) {
		unsigned seq;
		bool negative;
#ifdef MY_ABC_HERE
		dentry = __d_lookup_rcu(parent, &nd->last, &seq, caseless);
#else
		dentry = __d_lookup_rcu(parent, &nd->last, &seq);
#endif  
		if (!dentry)
			goto unlazy;

		*inode = d_backing_inode(dentry);
		negative = d_is_negative(dentry);
		if (read_seqcount_retry(&dentry->d_seq, seq))
			return -ECHILD;

		if (__read_seqcount_retry(&parent->d_seq, nd->seq))
			return -ECHILD;

		*seqp = seq;
		if (unlikely(dentry->d_flags & DCACHE_OP_REVALIDATE)) {
			status = d_revalidate(dentry, nd->flags);
			if (unlikely(status <= 0)) {
				if (status != -ECHILD)
					need_reval = 0;
				goto unlazy;
			}
		}
		 
		if (negative)
			return -ENOENT;
		path->mnt = mnt;
		path->dentry = dentry;
		if (likely(__follow_mount_rcu(nd, path, inode, seqp)))
			return 0;
unlazy:
		if (unlazy_walk(nd, dentry, seq))
			return -ECHILD;
	} else {
#ifdef MY_ABC_HERE
		dentry = __d_lookup(parent, &nd->last, caseless);
		if (caseless) {
			if (dentry && !dentry->d_inode) {
				d_invalidate(dentry);
				dput(dentry);
				dentry = NULL;
			}
		}
#else
		dentry = __d_lookup(parent, &nd->last);
#endif  
	}

	if (unlikely(!dentry))
		goto need_lookup;

	if (unlikely(dentry->d_flags & DCACHE_OP_REVALIDATE) && need_reval)
		status = d_revalidate(dentry, nd->flags);
	if (unlikely(status <= 0)) {
		if (status < 0) {
			dput(dentry);
			return status;
		}
		d_invalidate(dentry);
		dput(dentry);
		goto need_lookup;
	}

	if (unlikely(d_is_negative(dentry))) {
		dput(dentry);
		return -ENOENT;
	}
	path->mnt = mnt;
	path->dentry = dentry;
	err = follow_managed(path, nd);
	if (likely(!err))
		*inode = d_backing_inode(path->dentry);
	return err;

need_lookup:
	return 1;
}

static int lookup_slow(struct nameidata *nd, struct path *path)
{
	struct dentry *dentry, *parent;

	parent = nd->path.dentry;
	BUG_ON(nd->inode != parent->d_inode);

	inode_lock(parent->d_inode);
	dentry = __lookup_hash(&nd->last, parent, nd->flags);
	inode_unlock(parent->d_inode);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);
	path->mnt = nd->path.mnt;
	path->dentry = dentry;
	return follow_managed(path, nd);
}

static inline int may_lookup(struct nameidata *nd)
{
#ifdef MY_ABC_HERE
	int err;
	int is_synoacl = IS_SYNOACL_INODE(nd->inode, nd->path.dentry);
#endif  
	if (nd->flags & LOOKUP_RCU) {
#ifdef MY_ABC_HERE
		if (is_synoacl) {
			err = synoacl_op_exec_perm(nd->path.dentry, nd->inode);
		} else {
			err = inode_permission(nd->inode, MAY_EXEC|MAY_NOT_BLOCK);
		}
#else
		int err = inode_permission(nd->inode, MAY_EXEC|MAY_NOT_BLOCK);
#endif  
		if (err != -ECHILD)
			return err;
		if (unlazy_walk(nd, NULL, 0))
			return -ECHILD;
	}
#ifdef MY_ABC_HERE
	if (is_synoacl) {
		err = synoacl_op_exec_perm(nd->path.dentry, nd->inode);
	} else {
		err = inode_permission(nd->inode, MAY_EXEC);
	}
	return err;
#else
	return inode_permission(nd->inode, MAY_EXEC);
#endif  
}

static inline int handle_dots(struct nameidata *nd, int type)
{
	if (type == LAST_DOTDOT) {
		if (nd->flags & LOOKUP_RCU) {
			return follow_dotdot_rcu(nd);
		} else
			return follow_dotdot(nd);
	}
	return 0;
}

static int pick_link(struct nameidata *nd, struct path *link,
		     struct inode *inode, unsigned seq)
{
	int error;
	struct saved *last;
	if (unlikely(nd->total_link_count++ >= MAXSYMLINKS)) {
		path_to_nameidata(link, nd);
		return -ELOOP;
	}
	if (!(nd->flags & LOOKUP_RCU)) {
		if (link->mnt == nd->path.mnt)
			mntget(link->mnt);
	}
	error = nd_alloc_stack(nd);
	if (unlikely(error)) {
		if (error == -ECHILD) {
			if (unlikely(unlazy_link(nd, link, seq)))
				return -ECHILD;
			error = nd_alloc_stack(nd);
		}
		if (error) {
			path_put(link);
			return error;
		}
	}

	last = nd->stack + nd->depth++;
	last->link = *link;
	last->cookie = NULL;
	last->inode = inode;
	last->seq = seq;
	return 1;
}

static inline int should_follow_link(struct nameidata *nd, struct path *link,
				     int follow,
				     struct inode *inode, unsigned seq)
{
	if (likely(!d_is_symlink(link->dentry)))
		return 0;
	if (!follow)
		return 0;
	 
	if (nd->flags & LOOKUP_RCU) {
		if (read_seqcount_retry(&link->dentry->d_seq, seq))
			return -ECHILD;
	}
	return pick_link(nd, link, inode, seq);
}

#ifdef MY_ABC_HERE
static inline int update_real_filename(struct nameidata *nd, char *target_name, int target_len)
{
	if ((nd->real_filename_len + target_len + 2) >= SYNO_SMB_PSTRING_LEN) {
		return -1;
	}
	memcpy(nd->real_filename_cur_locate, target_name, target_len);
	nd->real_filename_cur_locate += target_len;
	nd->real_filename_len += target_len;
	if (!(nd->flags & LOOKUP_TO_LASTCOMPONENT)) {
		*(nd->real_filename_cur_locate) = '/';
		nd->real_filename_cur_locate++;
		nd->real_filename_len++;
	}
	*(nd->real_filename_cur_locate) = '\0';
	 
	if (nd->flags & LOOKUP_TO_LASTCOMPONENT) {
		nd->real_filename_cur_locate++;
		nd->real_filename_len++;
	}
	return 0;
}
static inline int update_path_to_real_filename(struct nameidata *nd)
{
	int target_len = 0;
	char *target_name = NULL;
	struct mount *mnt = NULL;

	if (LAST_DOTDOT == nd->last_type || LAST_DOT == nd->last_type) {
		return 0;
	}

	if (nd->flags & LOOKUP_MOUNTED) {
		nd->flags &= ~LOOKUP_MOUNTED;
		mnt = real_mount(nd->caseless_path.mnt);
		target_name = (char *)mnt->mnt_mountpoint->d_name.name;
		target_len = mnt->mnt_mountpoint->d_name.len;
	} else {
		target_name = (char *)nd->caseless_path.dentry->d_name.name;
		target_len = nd->caseless_path.dentry->d_name.len;
	}
	if (update_real_filename(nd, target_name, target_len)) {
		return -1;
	}
	return 0;
}
#endif  

enum {WALK_GET = 1, WALK_PUT = 2};

static int walk_component(struct nameidata *nd, int flags)
{
	struct path path;
	struct inode *inode;
	unsigned seq;
	int err;
	 
	if (unlikely(nd->last_type != LAST_NORM)) {
		err = handle_dots(nd, nd->last_type);
		if (flags & WALK_PUT)
			put_link(nd);
		return err;
	}
	err = lookup_fast(nd, &path, &inode, &seq);
	if (unlikely(err)) {
		if (err < 0)
			return err;

		err = lookup_slow(nd, &path);
		if (err < 0)
			return err;

		seq = 0;	 
		err = -ENOENT;
		if (d_is_negative(path.dentry))
			goto out_path_put;
		inode = d_backing_inode(path.dentry);
	}

#ifdef MY_ABC_HERE
	if (nd->flags & LOOKUP_CASELESS_COMPARE) {
		nd->caseless_path = path;
	}
#endif  

	if (flags & WALK_PUT)
		put_link(nd);
	err = should_follow_link(nd, &path, flags & WALK_GET, inode, seq);
	if (unlikely(err))
		return err;
	path_to_nameidata(&path, nd);
	nd->inode = inode;
	nd->seq = seq;
	return 0;

out_path_put:
	path_to_nameidata(&path, nd);
	return err;
}

#ifdef CONFIG_DCACHE_WORD_ACCESS

#include <asm/word-at-a-time.h>

#ifdef CONFIG_64BIT

static inline unsigned int fold_hash(unsigned long hash)
{
	return hash_64(hash, 32);
}

#else	 

#define fold_hash(x) (x)

#endif

unsigned int full_name_hash(const unsigned char *name, unsigned int len)
{
	unsigned long a, mask;
	unsigned long hash = 0;

	for (;;) {
		a = load_unaligned_zeropad(name);
		if (len < sizeof(unsigned long))
			break;
		hash += a;
		hash *= 9;
		name += sizeof(unsigned long);
		len -= sizeof(unsigned long);
		if (!len)
			goto done;
	}
	mask = bytemask_from_count(len);
	hash += mask & a;
done:
	return fold_hash(hash);
}
EXPORT_SYMBOL(full_name_hash);

static inline u64 hash_name(const char *name)
{
	unsigned long a, b, adata, bdata, mask, hash, len;
	const struct word_at_a_time constants = WORD_AT_A_TIME_CONSTANTS;

	hash = a = 0;
	len = -sizeof(unsigned long);
	do {
		hash = (hash + a) * 9;
		len += sizeof(unsigned long);
		a = load_unaligned_zeropad(name+len);
		b = a ^ REPEAT_BYTE('/');
	} while (!(has_zero(a, &adata, &constants) | has_zero(b, &bdata, &constants)));

	adata = prep_zero_mask(a, adata, &constants);
	bdata = prep_zero_mask(b, bdata, &constants);

	mask = create_zero_mask(adata | bdata);

	hash += a & zero_bytemask(mask);
	len += find_zero(mask);
	return hashlen_create(fold_hash(hash), len);
}

#else

unsigned int full_name_hash(const unsigned char *name, unsigned int len)
{
	unsigned long hash = init_name_hash();
	while (len--)
		hash = partial_name_hash(*name++, hash);
	return end_name_hash(hash);
}
EXPORT_SYMBOL(full_name_hash);

static inline u64 hash_name(const char *name)
{
	unsigned long hash = init_name_hash();
	unsigned long len = 0, c;

	c = (unsigned char)*name;
	do {
		len++;
		hash = partial_name_hash(c, hash);
		c = (unsigned char)name[len];
	} while (c && c != '/');
	return hashlen_create(end_name_hash(hash), len);
}

#endif

static int link_path_walk(const char *name, struct nameidata *nd)
{
	int err;

#ifdef MY_ABC_HERE
	 
	int caseless_flag = nd->is_init ? (LOOKUP_CASELESS_COMPARE & nd->flags) : 0;
	int link_count = 0;

	nd->is_init = false;
	while (*name=='/') {
		if (caseless_flag && !link_count) {
			if (update_real_filename(nd, (char *) "", 0)) {
				return -ENAMETOOLONG;
			}
		}
		name++;
	}
#else
	while (*name=='/')
		name++;
#endif  
	if (!*name)
		return 0;

	for(;;) {
		u64 hash_len;
		int type;
#ifdef MY_ABC_HERE
		int slash_count = 0;
		 
		bool in_link = link_count ? true : false;

		nd->flags &= ~LOOKUP_MOUNTED;
#endif  

		err = may_lookup(nd);
 		if (err)
			return err;

		hash_len = hash_name(name);

		type = LAST_NORM;
		if (name[0] == '.') switch (hashlen_len(hash_len)) {
			case 2:
				if (name[1] == '.') {
					type = LAST_DOTDOT;
					nd->flags |= LOOKUP_JUMPED;
				}
				break;
			case 1:
				type = LAST_DOT;
		}
		if (likely(type == LAST_NORM)) {
			struct dentry *parent = nd->path.dentry;
			nd->flags &= ~LOOKUP_JUMPED;
			if (unlikely(parent->d_flags & DCACHE_OP_HASH)) {
				struct qstr this = { { .hash_len = hash_len }, .name = name };
				err = parent->d_op->d_hash(parent, &this);
				if (err < 0)
					return err;
				hash_len = this.hash_len;
				name = this.name;
			}
		}

		nd->last.hash_len = hash_len;
		nd->last.name = name;
		nd->last_type = type;

		name += hashlen_len(hash_len);

#ifdef MY_ABC_HERE
		if (!*name && caseless_flag && !in_link) {
			nd->flags |= LOOKUP_TO_LASTCOMPONENT;
		}
		if (caseless_flag && (LAST_DOTDOT == type || LAST_DOT == type) && !in_link) {
			if (update_real_filename(nd, (char *) nd->last.name, hashlen_len(nd->last.hash_len))) {
				return -ENAMETOOLONG;
			}
		}
#endif  

		if (!*name)
			goto OK;
		 
		do {
			name++;
#ifdef MY_ABC_HERE
			slash_count++;
			 
#endif  
		} while (unlikely(*name == '/'));
		if (unlikely(!*name)) {
OK:
#ifdef MY_ABC_HERE
			if (!*name && caseless_flag && !in_link) {
				nd->flags |= LOOKUP_TO_LASTCOMPONENT;
			}
#endif  
			 
			if (!nd->depth)
				return 0;
			name = nd->stack[nd->depth - 1].name;
			 
#ifdef MY_ABC_HERE
			 
			if (caseless_flag) {
				link_count--;
			}
#endif  

			if (!name)
				return 0;
			 
			err = walk_component(nd, WALK_GET | WALK_PUT);
		} else {
			err = walk_component(nd, WALK_GET);
		}
		if (err < 0)
			return err;

#ifdef MY_ABC_HERE
		if (caseless_flag && !in_link) {
			if (0 != update_path_to_real_filename(nd)) {
				return -ENAMETOOLONG;
			}
			slash_count--;  
			while (slash_count > 0) {
				if (update_real_filename(nd, (char *) "", 0)) {
					return -ENAMETOOLONG;
				}
				slash_count--;
			}
		}
#endif  

		if (err) {
			const char *s = get_link(nd);

			if (IS_ERR(s))
				return PTR_ERR(s);
			err = 0;
			if (unlikely(!s)) {
				 
				put_link(nd);
			} else {
				nd->stack[nd->depth - 1].name = name;
				name = s;
#ifdef MY_ABC_HERE
				 
				if (caseless_flag) {
					link_count++;
				}
#endif  
				continue;
			}
		}
		if (unlikely(!d_can_lookup(nd->path.dentry))) {
			if (nd->flags & LOOKUP_RCU) {
				if (unlazy_walk(nd, NULL, 0))
					return -ECHILD;
			}
			return -ENOTDIR;
		}
	}
}

static const char *path_init(struct nameidata *nd, unsigned flags)
{
	int retval = 0;
	const char *s = nd->name->name;

	nd->last_type = LAST_ROOT;  
	nd->flags = flags | LOOKUP_JUMPED | LOOKUP_PARENT;
	nd->depth = 0;
#ifdef MY_ABC_HERE
	if (flags & LOOKUP_CASELESS_COMPARE) {
		nd->real_filename_cur_locate = nd->real_filename;
		nd->real_filename_len = 0;
		nd->is_init = true;
	}
#endif  
	if (flags & LOOKUP_ROOT) {
		struct dentry *root = nd->root.dentry;
		struct inode *inode = root->d_inode;
		if (*s) {
			if (!d_can_lookup(root))
				return ERR_PTR(-ENOTDIR);
#ifdef MY_ABC_HERE
			if (IS_SYNOACL_INODE(inode, nd->root.dentry)) {
				retval = synoacl_op_exec_perm(nd->root.dentry, inode);
			} else
#endif  
			retval = inode_permission(inode, MAY_EXEC);
			if (retval)
				return ERR_PTR(retval);
		}
		nd->path = nd->root;
		nd->inode = inode;
		if (flags & LOOKUP_RCU) {
			rcu_read_lock();
			nd->seq = __read_seqcount_begin(&nd->path.dentry->d_seq);
			nd->root_seq = nd->seq;
			nd->m_seq = read_seqbegin(&mount_lock);
		} else {
			path_get(&nd->path);
		}
		return s;
	}

	nd->root.mnt = NULL;

	nd->m_seq = read_seqbegin(&mount_lock);
	if (*s == '/') {
		if (flags & LOOKUP_RCU) {
			rcu_read_lock();
			set_root_rcu(nd);
			nd->seq = nd->root_seq;
		} else {
			set_root(nd);
			path_get(&nd->root);
		}
		nd->path = nd->root;
	} else if (nd->dfd == AT_FDCWD) {
		if (flags & LOOKUP_RCU) {
			struct fs_struct *fs = current->fs;
			unsigned seq;

			rcu_read_lock();

			do {
				seq = read_seqcount_begin(&fs->seq);
				nd->path = fs->pwd;
				nd->seq = __read_seqcount_begin(&nd->path.dentry->d_seq);
			} while (read_seqcount_retry(&fs->seq, seq));
		} else {
			get_fs_pwd(current->fs, &nd->path);
		}
	} else {
		 
		struct fd f = fdget_raw(nd->dfd);
		struct dentry *dentry;

		if (!f.file)
			return ERR_PTR(-EBADF);

		dentry = f.file->f_path.dentry;

		if (*s) {
			if (!d_can_lookup(dentry)) {
				fdput(f);
				return ERR_PTR(-ENOTDIR);
			}
		}

		nd->path = f.file->f_path;
		if (flags & LOOKUP_RCU) {
			rcu_read_lock();
			nd->inode = nd->path.dentry->d_inode;
			nd->seq = read_seqcount_begin(&nd->path.dentry->d_seq);
		} else {
			path_get(&nd->path);
			nd->inode = nd->path.dentry->d_inode;
		}
		fdput(f);
		return s;
	}

	nd->inode = nd->path.dentry->d_inode;
	if (!(flags & LOOKUP_RCU))
		return s;
	if (likely(!read_seqcount_retry(&nd->path.dentry->d_seq, nd->seq)))
		return s;
	if (!(nd->flags & LOOKUP_ROOT))
		nd->root.mnt = NULL;
	rcu_read_unlock();
	return ERR_PTR(-ECHILD);
}

static const char *trailing_symlink(struct nameidata *nd)
{
	const char *s;
	int error = may_follow_link(nd);
	if (unlikely(error))
		return ERR_PTR(error);
	nd->flags |= LOOKUP_PARENT;
	nd->stack[0].name = NULL;
	s = get_link(nd);
	return s ? s : "";
}

static inline int lookup_last(struct nameidata *nd)
{
	if (nd->last_type == LAST_NORM && nd->last.name[nd->last.len])
		nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;

	nd->flags &= ~LOOKUP_PARENT;
	return walk_component(nd,
			nd->flags & LOOKUP_FOLLOW
				? nd->depth
					? WALK_PUT | WALK_GET
					: WALK_GET
				: 0);
}

static int path_lookupat(struct nameidata *nd, unsigned flags, struct path *path)
{
	const char *s = path_init(nd, flags);
	int err;
#ifdef MY_ABC_HERE
	bool update_last = true;
#endif  

	if (IS_ERR(s))
		return PTR_ERR(s);
#ifdef MY_ABC_HERE
	while (!(err = link_path_walk(s, nd))) {
		err = lookup_last(nd);
		if (err < 0)
			break;
		 
		if ((flags & LOOKUP_CASELESS_COMPARE) && update_last) {
			update_last = false;
			if (0 != update_path_to_real_filename(nd)) {
				err = -ENAMETOOLONG;
				break;
			}
		}
		if (!(err > 0))
			break;
#else
	while (!(err = link_path_walk(s, nd))
		&& ((err = lookup_last(nd)) > 0)) {
#endif  
		s = trailing_symlink(nd);
		if (IS_ERR(s)) {
			err = PTR_ERR(s);
			break;
		}
	}
	if (!err)
		err = complete_walk(nd);

	if (!err && nd->flags & LOOKUP_DIRECTORY)
		if (!d_can_lookup(nd->path.dentry))
			err = -ENOTDIR;
	if (!err) {
		*path = nd->path;
		nd->path.mnt = NULL;
		nd->path.dentry = NULL;
	}
	terminate_walk(nd);
	return err;
}

static int filename_lookup(int dfd, struct filename *name, unsigned flags,
			   struct path *path, struct path *root)
{
	int retval;
	struct nameidata nd;
	if (IS_ERR(name))
		return PTR_ERR(name);
	if (unlikely(root)) {
		nd.root = *root;
		flags |= LOOKUP_ROOT;
	}
	set_nameidata(&nd, dfd, name);
#ifdef MY_ABC_HERE
	retval = path_lookupat(&nd, flags, path);
#else
	retval = path_lookupat(&nd, flags | LOOKUP_RCU, path);
	if (unlikely(retval == -ECHILD))
		retval = path_lookupat(&nd, flags, path);
#endif  
	if (unlikely(retval == -ESTALE))
		retval = path_lookupat(&nd, flags | LOOKUP_REVAL, path);

	if (likely(!retval))
		audit_inode(name, path->dentry, flags & LOOKUP_PARENT);
	restore_nameidata();
	putname(name);
	return retval;
}

static int path_parentat(struct nameidata *nd, unsigned flags,
				struct path *parent)
{
	const char *s = path_init(nd, flags);
	int err;
	if (IS_ERR(s))
		return PTR_ERR(s);
	err = link_path_walk(s, nd);
	if (!err)
		err = complete_walk(nd);
	if (!err) {
		*parent = nd->path;
		nd->path.mnt = NULL;
		nd->path.dentry = NULL;
	}
	terminate_walk(nd);
	return err;
}

static struct filename *filename_parentat(int dfd, struct filename *name,
				unsigned int flags, struct path *parent,
				struct qstr *last, int *type)
{
	int retval;
	struct nameidata nd;

	if (IS_ERR(name))
		return name;
	set_nameidata(&nd, dfd, name);
#ifdef MY_ABC_HERE
	retval = path_parentat(&nd, flags, parent);
#else
	retval = path_parentat(&nd, flags | LOOKUP_RCU, parent);
	if (unlikely(retval == -ECHILD))
		retval = path_parentat(&nd, flags, parent);
#endif  
	if (unlikely(retval == -ESTALE))
		retval = path_parentat(&nd, flags | LOOKUP_REVAL, parent);
	if (likely(!retval)) {
		*last = nd.last;
		*type = nd.last_type;
		audit_inode(name, parent->dentry, LOOKUP_PARENT);
	} else {
		putname(name);
		name = ERR_PTR(retval);
	}
	restore_nameidata();
	return name;
}

struct dentry *kern_path_locked(const char *name, struct path *path)
{
	struct filename *filename;
	struct dentry *d;
	struct qstr last;
	int type;

	filename = filename_parentat(AT_FDCWD, getname_kernel(name), 0, path,
				    &last, &type);
	if (IS_ERR(filename))
		return ERR_CAST(filename);
	if (unlikely(type != LAST_NORM)) {
		path_put(path);
		putname(filename);
		return ERR_PTR(-EINVAL);
	}
	inode_lock_nested(path->dentry->d_inode, I_MUTEX_PARENT);
	d = __lookup_hash(&last, path->dentry, 0);
	if (IS_ERR(d)) {
		inode_unlock(path->dentry->d_inode);
		path_put(path);
	}
	putname(filename);
	return d;
}

int kern_path(const char *name, unsigned int flags, struct path *path)
{
	return filename_lookup(AT_FDCWD, getname_kernel(name),
			       flags, path, NULL);
}
EXPORT_SYMBOL(kern_path);

int vfs_path_lookup(struct dentry *dentry, struct vfsmount *mnt,
		    const char *name, unsigned int flags,
		    struct path *path)
{
	struct path root = {.mnt = mnt, .dentry = dentry};
	 
	return filename_lookup(AT_FDCWD, getname_kernel(name),
			       flags , path, &root);
}
EXPORT_SYMBOL(vfs_path_lookup);

struct dentry *lookup_one_len(const char *name, struct dentry *base, int len)
{
	struct qstr this;
	unsigned int c;
	int err;

	WARN_ON_ONCE(!inode_is_locked(base->d_inode));

	this.name = name;
	this.len = len;
	this.hash = full_name_hash(name, len);
	if (!len)
		return ERR_PTR(-EACCES);

	if (unlikely(name[0] == '.')) {
		if (len < 2 || (len == 2 && name[1] == '.'))
			return ERR_PTR(-EACCES);
	}

	while (len--) {
		c = *(const unsigned char *)name++;
		if (c == '/' || c == '\0')
			return ERR_PTR(-EACCES);
	}
	 
	if (base->d_flags & DCACHE_OP_HASH) {
		int err = base->d_op->d_hash(base, &this);
		if (err < 0)
			return ERR_PTR(err);
	}

#ifdef MY_ABC_HERE
	if (IS_SYNOACL(base)) {
		err = synoacl_op_exec_perm(base, base->d_inode);
	} else
#endif  
	err = inode_permission(base->d_inode, MAY_EXEC);
	if (err)
		return ERR_PTR(err);

	return __lookup_hash(&this, base, 0);
}
EXPORT_SYMBOL(lookup_one_len);

#ifdef MY_ABC_HERE
int syno_user_path_at(int dfd, const char __user *user_name, unsigned flags,
		 struct path *path, char **real_filename, int *real_filename_len)
{
	int retval;
	struct nameidata nd;
	struct filename *name = getname(user_name);

	BUG_ON(flags & LOOKUP_PARENT);

	nd.real_filename = *real_filename;
	nd.real_filename_cur_locate = nd.real_filename;
	nd.real_filename_len = 0;
	nd.is_init = true;

	if (IS_ERR(name))
		return PTR_ERR(name);
	set_nameidata(&nd, dfd, name);
#ifdef MY_ABC_HERE
	retval = path_lookupat(&nd, flags, path);
#else
	retval = path_lookupat(&nd, flags | LOOKUP_RCU, path);
	if (unlikely(retval == -ECHILD))
		retval = path_lookupat(&nd, flags, path);
#endif  
	if (unlikely(retval == -ESTALE))
		retval = path_lookupat(&nd, flags | LOOKUP_REVAL, path);

	if (likely(!retval))
		audit_inode(name, path->dentry, flags & LOOKUP_PARENT);
	restore_nameidata();
	putname(name);

	*real_filename_len = nd.real_filename_len;
	return retval;

}
#endif  

int user_path_at_empty(int dfd, const char __user *name, unsigned flags,
		 struct path *path, int *empty)
{
	return filename_lookup(dfd, getname_flags(name, flags, empty),
			       flags, path, NULL);
}
EXPORT_SYMBOL(user_path_at_empty);

static inline struct filename *
user_path_parent(int dfd, const char __user *path,
		 struct path *parent,
		 struct qstr *last,
		 int *type,
		 unsigned int flags)
{
	 
	return filename_parentat(dfd, getname(path), flags & LOOKUP_REVAL,
				 parent, last, type);
}

static int
mountpoint_last(struct nameidata *nd, struct path *path)
{
	int error = 0;
	struct dentry *dentry;
	struct dentry *dir = nd->path.dentry;

	if (nd->flags & LOOKUP_RCU) {
		if (unlazy_walk(nd, NULL, 0))
			return -ECHILD;
	}

	nd->flags &= ~LOOKUP_PARENT;

	if (unlikely(nd->last_type != LAST_NORM)) {
		error = handle_dots(nd, nd->last_type);
		if (error)
			return error;
		dentry = dget(nd->path.dentry);
		goto done;
	}

	inode_lock(dir->d_inode);
	dentry = d_lookup(dir, &nd->last);
	if (!dentry) {
		 
		dentry = d_alloc(dir, &nd->last);
		if (!dentry) {
			inode_unlock(dir->d_inode);
			return -ENOMEM;
		}
		dentry = lookup_real(dir->d_inode, dentry, nd->flags);
		if (IS_ERR(dentry)) {
			inode_unlock(dir->d_inode);
			return PTR_ERR(dentry);
		}
	}
	inode_unlock(dir->d_inode);

done:
	if (d_is_negative(dentry)) {
		dput(dentry);
		return -ENOENT;
	}
	if (nd->depth)
		put_link(nd);
	path->dentry = dentry;
	path->mnt = nd->path.mnt;
	error = should_follow_link(nd, path, nd->flags & LOOKUP_FOLLOW,
				   d_backing_inode(dentry), 0);
	if (unlikely(error))
		return error;
	mntget(path->mnt);
	follow_mount(path);
	return 0;
}

static int
path_mountpoint(struct nameidata *nd, unsigned flags, struct path *path)
{
	const char *s = path_init(nd, flags);
	int err;
	if (IS_ERR(s))
		return PTR_ERR(s);
	while (!(err = link_path_walk(s, nd)) &&
		(err = mountpoint_last(nd, path)) > 0) {
		s = trailing_symlink(nd);
		if (IS_ERR(s)) {
			err = PTR_ERR(s);
			break;
		}
	}
	terminate_walk(nd);
	return err;
}

static int
filename_mountpoint(int dfd, struct filename *name, struct path *path,
			unsigned int flags)
{
	struct nameidata nd;
	int error;
	if (IS_ERR(name))
		return PTR_ERR(name);
	set_nameidata(&nd, dfd, name);
#ifdef MY_ABC_HERE
	error = path_mountpoint(&nd, flags, path);
#else
	error = path_mountpoint(&nd, flags | LOOKUP_RCU, path);
	if (unlikely(error == -ECHILD))
		error = path_mountpoint(&nd, flags, path);
#endif  
	if (unlikely(error == -ESTALE))
		error = path_mountpoint(&nd, flags | LOOKUP_REVAL, path);
	if (likely(!error))
		audit_inode(name, path->dentry, 0);
	restore_nameidata();
	putname(name);
	return error;
}

int
user_path_mountpoint_at(int dfd, const char __user *name, unsigned int flags,
			struct path *path)
{
	return filename_mountpoint(dfd, getname(name), path, flags);
}

int
kern_path_mountpoint(int dfd, const char *name, struct path *path,
			unsigned int flags)
{
	return filename_mountpoint(dfd, getname_kernel(name), path, flags);
}
EXPORT_SYMBOL(kern_path_mountpoint);

int __check_sticky(struct inode *dir, struct inode *inode)
{
	kuid_t fsuid = current_fsuid();

	if (uid_eq(inode->i_uid, fsuid))
		return 0;
	if (uid_eq(dir->i_uid, fsuid))
		return 0;
	return !capable_wrt_inode_uidgid(inode, CAP_FOWNER);
}
EXPORT_SYMBOL(__check_sticky);

static int may_delete(struct inode *dir, struct dentry *victim, bool isdir)
{
	struct inode *inode = d_backing_inode(victim);
	int error;

	if (d_is_negative(victim))
		return -ENOENT;
	BUG_ON(!inode);

	BUG_ON(victim->d_parent->d_inode != dir);
	audit_inode_child(dir, victim, AUDIT_TYPE_CHILD_DELETE);

#ifdef MY_ABC_HERE
	if (IS_FS_SYNOACL(dir)) {
		error = synoacl_op_may_delete(victim, dir);
	} else
#endif  
	error = inode_permission(dir, MAY_WRITE | MAY_EXEC);
	if (error)
		return error;
	if (IS_APPEND(dir))
		return -EPERM;

#ifdef MY_ABC_HERE
	if (!IS_SYNOACL(victim->d_parent) && check_sticky(dir, inode)) {
		return -EPERM;
	}
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode) || IS_SWAPFILE(inode)) {
		return -EPERM;
	}
#else
	if (check_sticky(dir, inode) || IS_APPEND(inode) ||
	    IS_IMMUTABLE(inode) || IS_SWAPFILE(inode))
		return -EPERM;
#endif  
	if (isdir) {
		if (!d_is_dir(victim))
			return -ENOTDIR;
		if (IS_ROOT(victim))
			return -EBUSY;
	} else if (d_is_dir(victim))
		return -EISDIR;
	if (IS_DEADDIR(dir))
		return -ENOENT;
	if (victim->d_flags & DCACHE_NFSFS_RENAMED)
		return -EBUSY;
	return 0;
}

#ifdef MY_ABC_HERE
static inline int may_create(struct inode *dir, struct dentry *child, int mode)
#else
static inline int may_create(struct inode *dir, struct dentry *child)
#endif  
{
	audit_inode_child(dir, child, AUDIT_TYPE_CHILD_CREATE);
	if (child->d_inode)
		return -EEXIST;
	if (IS_DEADDIR(dir))
		return -ENOENT;

#ifdef MY_ABC_HERE
	if (IS_SYNOACL(child->d_parent)) {
		return synoacl_op_perm(child->d_parent, (S_ISDIR(mode)?MAY_APPEND:MAY_WRITE) | MAY_EXEC);
	}
#endif  
	return inode_permission(dir, MAY_WRITE | MAY_EXEC);
}

struct dentry *lock_rename(struct dentry *p1, struct dentry *p2)
{
	struct dentry *p;

	if (p1 == p2) {
		inode_lock_nested(p1->d_inode, I_MUTEX_PARENT);
		return NULL;
	}

	mutex_lock(&p1->d_inode->i_sb->s_vfs_rename_mutex);

	p = d_ancestor(p2, p1);
	if (p) {
		inode_lock_nested(p2->d_inode, I_MUTEX_PARENT);
		inode_lock_nested(p1->d_inode, I_MUTEX_CHILD);
		return p;
	}

	p = d_ancestor(p1, p2);
	if (p) {
		inode_lock_nested(p1->d_inode, I_MUTEX_PARENT);
		inode_lock_nested(p2->d_inode, I_MUTEX_CHILD);
		return p;
	}

	inode_lock_nested(p1->d_inode, I_MUTEX_PARENT);
	inode_lock_nested(p2->d_inode, I_MUTEX_PARENT2);
	return NULL;
}
EXPORT_SYMBOL(lock_rename);

void unlock_rename(struct dentry *p1, struct dentry *p2)
{
	inode_unlock(p1->d_inode);
	if (p1 != p2) {
		inode_unlock(p2->d_inode);
		mutex_unlock(&p1->d_inode->i_sb->s_vfs_rename_mutex);
	}
}
EXPORT_SYMBOL(unlock_rename);

int vfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		bool want_excl)
{
#ifdef MY_ABC_HERE
	int error = may_create(dir, dentry, S_IFREG);
#else
	int error = may_create(dir, dentry);
#endif  
	if (error)
		return error;

	if (!dir->i_op->create)
		return -EACCES;	 
	mode &= S_IALLUGO;
	mode |= S_IFREG;
	error = security_inode_create(dir, dentry, mode);
	if (error)
		return error;
	error = dir->i_op->create(dir, dentry, mode, want_excl);
	if (!error)
		fsnotify_create(dir, dentry);
#ifdef MY_ABC_HERE
	if (!error && IS_SYNOACL(dentry->d_parent)) {
		 
		synoacl_op_init(dentry);
	}
#endif  
	return error;
}
EXPORT_SYMBOL(vfs_create);

static int may_open(struct path *path, int acc_mode, int flag)
{
	struct dentry *dentry = path->dentry;
	struct inode *inode = dentry->d_inode;
	int error;

	if (!acc_mode)
		return 0;

	if (!inode)
		return -ENOENT;

	switch (inode->i_mode & S_IFMT) {
	case S_IFLNK:
		return -ELOOP;
	case S_IFDIR:
		if (acc_mode & MAY_WRITE)
			return -EISDIR;
		break;
	case S_IFBLK:
	case S_IFCHR:
		if (path->mnt->mnt_flags & MNT_NODEV)
			return -EACCES;
		 
	case S_IFIFO:
	case S_IFSOCK:
		flag &= ~O_TRUNC;
		break;
	}

#ifdef MY_ABC_HERE
	if (IS_SYNOACL(dentry)) {
		error = synoacl_op_perm(dentry, acc_mode);
	} else
#endif  
	error = inode_permission(inode, acc_mode);
	if (error)
		return error;

	if (IS_APPEND(inode)) {
		if  ((flag & O_ACCMODE) != O_RDONLY && !(flag & O_APPEND))
			return -EPERM;
		if (flag & O_TRUNC)
			return -EPERM;
	}

	if (flag & O_NOATIME && !inode_owner_or_capable(inode))
		return -EPERM;

	return 0;
}

static int handle_truncate(struct file *filp)
{
	struct path *path = &filp->f_path;
	struct inode *inode = path->dentry->d_inode;
	int error = get_write_access(inode);
	if (error)
		return error;
	 
	error = locks_verify_locked(filp);
	if (!error)
		error = security_path_truncate(path);
	if (!error) {
		error = do_truncate(path->dentry, 0,
				    ATTR_MTIME|ATTR_CTIME|ATTR_OPEN,
				    filp);
	}
	put_write_access(inode);
	return error;
}

static inline int open_to_namei_flags(int flag)
{
	if ((flag & O_ACCMODE) == 3)
		flag--;
	return flag;
}

static int may_o_create(struct path *dir, struct dentry *dentry, umode_t mode)
{
	int error = security_path_mknod(dir, dentry, mode, 0);
	if (error)
		return error;

#ifdef MY_ABC_HERE
	if (IS_SYNOACL(dir->dentry)) {
		error = synoacl_op_perm(dir->dentry, (S_ISDIR(mode)?MAY_APPEND:MAY_WRITE) | MAY_EXEC);
	} else
#endif  
	error = inode_permission(dir->dentry->d_inode, MAY_WRITE | MAY_EXEC);
	if (error)
		return error;

	return security_inode_create(dir->dentry->d_inode, dentry, mode);
}

static int atomic_open(struct nameidata *nd, struct dentry *dentry,
			struct path *path, struct file *file,
			const struct open_flags *op,
			bool got_write, bool need_lookup,
			int *opened)
{
	struct inode *dir =  nd->path.dentry->d_inode;
	unsigned open_flag = open_to_namei_flags(op->open_flag);
	umode_t mode;
	int error;
	int acc_mode;
	int create_error = 0;
	struct dentry *const DENTRY_NOT_SET = (void *) -1UL;
	bool excl;

	BUG_ON(dentry->d_inode);

	if (unlikely(IS_DEADDIR(dir))) {
		error = -ENOENT;
		goto out;
	}

	mode = op->mode;
	if ((open_flag & O_CREAT) && !IS_POSIXACL(dir))
		mode &= ~current_umask();

	excl = (open_flag & (O_EXCL | O_CREAT)) == (O_EXCL | O_CREAT);
	if (excl)
		open_flag &= ~O_TRUNC;

	if (((open_flag & (O_CREAT | O_TRUNC)) ||
	    (open_flag & O_ACCMODE) != O_RDONLY) && unlikely(!got_write)) {
		if (!(open_flag & O_CREAT)) {
			 
			goto no_open;
		} else if (open_flag & (O_EXCL | O_TRUNC)) {
			 
			create_error = -EROFS;
			goto no_open;
		} else {
			 
			create_error = -EROFS;
			open_flag &= ~O_CREAT;
		}
	}

	if (open_flag & O_CREAT) {
		error = may_o_create(&nd->path, dentry, mode);
		if (error) {
			create_error = error;
			if (open_flag & O_EXCL)
				goto no_open;
			open_flag &= ~O_CREAT;
		}
	}

	if (nd->flags & LOOKUP_DIRECTORY)
		open_flag |= O_DIRECTORY;

	file->f_path.dentry = DENTRY_NOT_SET;
	file->f_path.mnt = nd->path.mnt;
	error = dir->i_op->atomic_open(dir, dentry, file, open_flag, mode,
				      opened);
	if (error < 0) {
		if (create_error && error == -ENOENT)
			error = create_error;
		goto out;
	}

	if (error) {	 
		if (WARN_ON(file->f_path.dentry == DENTRY_NOT_SET)) {
			error = -EIO;
			goto out;
		}
		if (file->f_path.dentry) {
			dput(dentry);
			dentry = file->f_path.dentry;
		}
		if (*opened & FILE_CREATED)
			fsnotify_create(dir, dentry);
		if (!dentry->d_inode) {
			WARN_ON(*opened & FILE_CREATED);
			if (create_error) {
				error = create_error;
				goto out;
			}
		} else {
			if (excl && !(*opened & FILE_CREATED)) {
				error = -EEXIST;
				goto out;
			}
		}
		goto looked_up;
	}

	acc_mode = op->acc_mode;
	if (*opened & FILE_CREATED) {
		WARN_ON(!(open_flag & O_CREAT));
		fsnotify_create(dir, dentry);
		acc_mode = MAY_OPEN;
	}
	error = may_open(&file->f_path, acc_mode, open_flag);
	if (error)
		fput(file);

out:
	dput(dentry);
	return error;

no_open:
	if (need_lookup) {
		dentry = lookup_real(dir, dentry, nd->flags);
		if (IS_ERR(dentry))
			return PTR_ERR(dentry);
	}
	if (create_error && !dentry->d_inode) {
		error = create_error;
		goto out;
	}
looked_up:
	path->dentry = dentry;
	path->mnt = nd->path.mnt;
	return 1;
}

static int lookup_open(struct nameidata *nd, struct path *path,
			struct file *file,
			const struct open_flags *op,
			bool got_write, int *opened)
{
	struct dentry *dir = nd->path.dentry;
	struct inode *dir_inode = dir->d_inode;
	struct dentry *dentry;
	int error;
	bool need_lookup;

	*opened &= ~FILE_CREATED;
	dentry = lookup_dcache(&nd->last, dir, nd->flags, &need_lookup);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	if (!need_lookup && dentry->d_inode)
		goto out_no_open;

	if ((nd->flags & LOOKUP_OPEN) && dir_inode->i_op->atomic_open) {
		return atomic_open(nd, dentry, path, file, op, got_write,
				   need_lookup, opened);
	}

	if (need_lookup) {
		BUG_ON(dentry->d_inode);

		dentry = lookup_real(dir_inode, dentry, nd->flags);
		if (IS_ERR(dentry))
			return PTR_ERR(dentry);
	}

	if (!dentry->d_inode && (op->open_flag & O_CREAT)) {
		umode_t mode = op->mode;
		if (!IS_POSIXACL(dir->d_inode))
			mode &= ~current_umask();
		 
		if (!got_write) {
			error = -EROFS;
			goto out_dput;
		}
		*opened |= FILE_CREATED;
		error = security_path_mknod(&nd->path, dentry, mode, 0);
		if (error)
			goto out_dput;
		error = vfs_create(dir->d_inode, dentry, mode,
				   nd->flags & LOOKUP_EXCL);
		if (error)
			goto out_dput;
	}
out_no_open:
	path->dentry = dentry;
	path->mnt = nd->path.mnt;
	return 1;

out_dput:
	dput(dentry);
	return error;
}

static int do_last(struct nameidata *nd,
		   struct file *file, const struct open_flags *op,
		   int *opened)
{
	struct dentry *dir = nd->path.dentry;
	int open_flag = op->open_flag;
	bool will_truncate = (open_flag & O_TRUNC) != 0;
	bool got_write = false;
	int acc_mode = op->acc_mode;
	unsigned seq;
	struct inode *inode;
	struct path save_parent = { .dentry = NULL, .mnt = NULL };
	struct path path;
	bool retried = false;
	int error;

	nd->flags &= ~LOOKUP_PARENT;
	nd->flags |= op->intent;

	if (nd->last_type != LAST_NORM) {
		error = handle_dots(nd, nd->last_type);
		if (unlikely(error))
			return error;
		goto finish_open;
	}

	if (!(open_flag & O_CREAT)) {
		if (nd->last.name[nd->last.len])
			nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
		 
		error = lookup_fast(nd, &path, &inode, &seq);
		if (likely(!error))
			goto finish_lookup;

		if (error < 0)
			return error;

		BUG_ON(nd->inode != dir->d_inode);
	} else {
		 
		error = complete_walk(nd);
		if (error)
			return error;

		audit_inode(nd->name, dir, LOOKUP_PARENT);
		 
		if (unlikely(nd->last.name[nd->last.len]))
			return -EISDIR;
	}

retry_lookup:
	if (op->open_flag & (O_CREAT | O_TRUNC | O_WRONLY | O_RDWR)) {
		error = mnt_want_write(nd->path.mnt);
		if (!error)
			got_write = true;
		 
	}
	inode_lock(dir->d_inode);
	error = lookup_open(nd, &path, file, op, got_write, opened);
	inode_unlock(dir->d_inode);

	if (error <= 0) {
		if (error)
			goto out;

		if ((*opened & FILE_CREATED) ||
		    !S_ISREG(file_inode(file)->i_mode))
			will_truncate = false;

		audit_inode(nd->name, file->f_path.dentry, 0);
		goto opened;
	}

	if (*opened & FILE_CREATED) {
		 
		open_flag &= ~O_TRUNC;
		will_truncate = false;
		acc_mode = MAY_OPEN;
		path_to_nameidata(&path, nd);
		goto finish_open_created;
	}

	if (d_is_positive(path.dentry))
		audit_inode(nd->name, path.dentry, 0);

	if (got_write) {
		mnt_drop_write(nd->path.mnt);
		got_write = false;
	}

	if (unlikely((open_flag & (O_EXCL | O_CREAT)) == (O_EXCL | O_CREAT))) {
		path_to_nameidata(&path, nd);
		return -EEXIST;
	}

	error = follow_managed(&path, nd);
	if (unlikely(error < 0))
		return error;

	BUG_ON(nd->flags & LOOKUP_RCU);
	seq = 0;	 
	if (unlikely(d_is_negative(path.dentry))) {
		path_to_nameidata(&path, nd);
		return -ENOENT;
	}
	inode = d_backing_inode(path.dentry);
finish_lookup:
	if (nd->depth)
		put_link(nd);
	error = should_follow_link(nd, &path, nd->flags & LOOKUP_FOLLOW,
				   inode, seq);
	if (unlikely(error))
		return error;

	if ((nd->flags & LOOKUP_RCU) || nd->path.mnt != path.mnt) {
		path_to_nameidata(&path, nd);
	} else {
		save_parent.dentry = nd->path.dentry;
		save_parent.mnt = mntget(path.mnt);
		nd->path.dentry = path.dentry;

	}
	nd->inode = inode;
	nd->seq = seq;
	 
finish_open:
	error = complete_walk(nd);
	if (error) {
		path_put(&save_parent);
		return error;
	}
	audit_inode(nd->name, nd->path.dentry, 0);
	if (unlikely(d_is_symlink(nd->path.dentry)) && !(open_flag & O_PATH)) {
		error = -ELOOP;
		goto out;
	}
	error = -EISDIR;
	if ((open_flag & O_CREAT) && d_is_dir(nd->path.dentry))
		goto out;
	error = -ENOTDIR;
	if ((nd->flags & LOOKUP_DIRECTORY) && !d_can_lookup(nd->path.dentry))
		goto out;
	if (!d_is_reg(nd->path.dentry))
		will_truncate = false;

	if (will_truncate) {
		error = mnt_want_write(nd->path.mnt);
		if (error)
			goto out;
		got_write = true;
	}
finish_open_created:
	error = may_open(&nd->path, acc_mode, open_flag);
	if (error)
		goto out;

	BUG_ON(*opened & FILE_OPENED);  
	error = vfs_open(&nd->path, file, current_cred());
	if (!error) {
		*opened |= FILE_OPENED;
	} else {
		if (error == -EOPENSTALE)
			goto stale_open;
		goto out;
	}
opened:
	error = open_check_o_direct(file);
	if (error)
		goto exit_fput;
	error = ima_file_check(file, op->acc_mode, *opened);
	if (error)
		goto exit_fput;

	if (will_truncate) {
		error = handle_truncate(file);
		if (error)
			goto exit_fput;
	}
out:
	if (unlikely(error > 0)) {
		WARN_ON(1);
		error = -EINVAL;
	}
	if (got_write)
		mnt_drop_write(nd->path.mnt);
	path_put(&save_parent);
	return error;

exit_fput:
	fput(file);
	goto out;

stale_open:
	 
	if (!save_parent.dentry || retried)
		goto out;

	BUG_ON(save_parent.dentry != dir);
	path_put(&nd->path);
	nd->path = save_parent;
	nd->inode = dir->d_inode;
	save_parent.mnt = NULL;
	save_parent.dentry = NULL;
	if (got_write) {
		mnt_drop_write(nd->path.mnt);
		got_write = false;
	}
	retried = true;
	goto retry_lookup;
}

static int do_tmpfile(struct nameidata *nd, unsigned flags,
		const struct open_flags *op,
		struct file *file, int *opened)
{
	static const struct qstr name = QSTR_INIT("/", 1);
	struct dentry *child;
	struct inode *dir;
	struct path path;
	int error = path_lookupat(nd, flags | LOOKUP_DIRECTORY, &path);
	if (unlikely(error))
		return error;
	error = mnt_want_write(path.mnt);
	if (unlikely(error))
		goto out;
	dir = path.dentry->d_inode;
#ifdef MY_ABC_HERE
	if (IS_SYNOACL(path.dentry)) {
		error = synoacl_op_perm(path.dentry, MAY_WRITE | MAY_EXEC);
	} else
#endif  
	 
	error = inode_permission(dir, MAY_WRITE | MAY_EXEC);
	if (error)
		goto out2;
	if (!dir->i_op->tmpfile) {
		error = -EOPNOTSUPP;
		goto out2;
	}
	child = d_alloc(path.dentry, &name);
	if (unlikely(!child)) {
		error = -ENOMEM;
		goto out2;
	}
	dput(path.dentry);
	path.dentry = child;
	error = dir->i_op->tmpfile(dir, child, op->mode);
	if (error)
		goto out2;
	audit_inode(nd->name, child, 0);
	 
	error = may_open(&path, MAY_OPEN, op->open_flag);
	if (error)
		goto out2;
	file->f_path.mnt = path.mnt;
	error = finish_open(file, child, NULL, opened);
	if (error)
		goto out2;
	error = open_check_o_direct(file);
	if (error) {
		fput(file);
	} else if (!(op->open_flag & O_EXCL)) {
		struct inode *inode = file_inode(file);
		spin_lock(&inode->i_lock);
		inode->i_state |= I_LINKABLE;
		spin_unlock(&inode->i_lock);
	}
out2:
	mnt_drop_write(path.mnt);
out:
	path_put(&path);
	return error;
}

static struct file *path_openat(struct nameidata *nd,
			const struct open_flags *op, unsigned flags)
{
	const char *s;
	struct file *file;
	int opened = 0;
	int error;

	file = get_empty_filp();
	if (IS_ERR(file))
		return file;

	file->f_flags = op->open_flag;

	if (unlikely(file->f_flags & __O_TMPFILE)) {
		error = do_tmpfile(nd, flags, op, file, &opened);
		goto out2;
	}

	s = path_init(nd, flags);
	if (IS_ERR(s)) {
		put_filp(file);
		return ERR_CAST(s);
	}
	while (!(error = link_path_walk(s, nd)) &&
		(error = do_last(nd, file, op, &opened)) > 0) {
		nd->flags &= ~(LOOKUP_OPEN|LOOKUP_CREATE|LOOKUP_EXCL);
		s = trailing_symlink(nd);
		if (IS_ERR(s)) {
			error = PTR_ERR(s);
			break;
		}
	}
	terminate_walk(nd);
out2:
	if (!(opened & FILE_OPENED)) {
		BUG_ON(!error);
		put_filp(file);
	}
	if (unlikely(error)) {
		if (error == -EOPENSTALE) {
			if (flags & LOOKUP_RCU)
				error = -ECHILD;
			else
				error = -ESTALE;
		}
		file = ERR_PTR(error);
	}
	return file;
}

struct file *do_filp_open(int dfd, struct filename *pathname,
		const struct open_flags *op)
{
	struct nameidata nd;
	int flags = op->lookup_flags;
	struct file *filp;

	set_nameidata(&nd, dfd, pathname);
#ifdef MY_ABC_HERE
	filp = path_openat(&nd, op, flags);
#else
	filp = path_openat(&nd, op, flags | LOOKUP_RCU);
	if (unlikely(filp == ERR_PTR(-ECHILD)))
		filp = path_openat(&nd, op, flags);
#endif  
	if (unlikely(filp == ERR_PTR(-ESTALE)))
		filp = path_openat(&nd, op, flags | LOOKUP_REVAL);
	restore_nameidata();
	return filp;
}

struct file *do_file_open_root(struct dentry *dentry, struct vfsmount *mnt,
		const char *name, const struct open_flags *op)
{
	struct nameidata nd;
	struct file *file;
	struct filename *filename;
	int flags = op->lookup_flags | LOOKUP_ROOT;

	nd.root.mnt = mnt;
	nd.root.dentry = dentry;

	if (d_is_symlink(dentry) && op->intent & LOOKUP_OPEN)
		return ERR_PTR(-ELOOP);

	filename = getname_kernel(name);
	if (IS_ERR(filename))
		return ERR_CAST(filename);

	set_nameidata(&nd, -1, filename);
#ifdef MY_ABC_HERE
	file = path_openat(&nd, op, flags);
#else
	file = path_openat(&nd, op, flags | LOOKUP_RCU);
	if (unlikely(file == ERR_PTR(-ECHILD)))
		file = path_openat(&nd, op, flags);
#endif  
	if (unlikely(file == ERR_PTR(-ESTALE)))
		file = path_openat(&nd, op, flags | LOOKUP_REVAL);
	restore_nameidata();
	putname(filename);
	return file;
}

static struct dentry *filename_create(int dfd, struct filename *name,
				struct path *path, unsigned int lookup_flags)
{
	struct dentry *dentry = ERR_PTR(-EEXIST);
	struct qstr last;
	int type;
	int err2;
	int error;
	bool is_dir = (lookup_flags & LOOKUP_DIRECTORY);

	lookup_flags &= LOOKUP_REVAL;

	name = filename_parentat(dfd, name, lookup_flags, path, &last, &type);
	if (IS_ERR(name))
		return ERR_CAST(name);

	if (unlikely(type != LAST_NORM))
		goto out;

	err2 = mnt_want_write(path->mnt);
	 
	lookup_flags |= LOOKUP_CREATE | LOOKUP_EXCL;
	inode_lock_nested(path->dentry->d_inode, I_MUTEX_PARENT);
	dentry = __lookup_hash(&last, path->dentry, lookup_flags);
	if (IS_ERR(dentry))
		goto unlock;

	error = -EEXIST;
	if (d_is_positive(dentry))
		goto fail;

	if (unlikely(!is_dir && last.name[last.len])) {
		error = -ENOENT;
		goto fail;
	}
	if (unlikely(err2)) {
		error = err2;
		goto fail;
	}
	putname(name);
	return dentry;
fail:
	dput(dentry);
	dentry = ERR_PTR(error);
unlock:
	inode_unlock(path->dentry->d_inode);
	if (!err2)
		mnt_drop_write(path->mnt);
out:
	path_put(path);
	putname(name);
	return dentry;
}

struct dentry *kern_path_create(int dfd, const char *pathname,
				struct path *path, unsigned int lookup_flags)
{
	return filename_create(dfd, getname_kernel(pathname),
				path, lookup_flags);
}
EXPORT_SYMBOL(kern_path_create);

void done_path_create(struct path *path, struct dentry *dentry)
{
	dput(dentry);
	inode_unlock(path->dentry->d_inode);
	mnt_drop_write(path->mnt);
	path_put(path);
}
EXPORT_SYMBOL(done_path_create);

inline struct dentry *user_path_create(int dfd, const char __user *pathname,
				struct path *path, unsigned int lookup_flags)
{
	return filename_create(dfd, getname(pathname), path, lookup_flags);
}
EXPORT_SYMBOL(user_path_create);

int vfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
#ifdef MY_ABC_HERE
	int error = may_create(dir, dentry, mode);
#else
	int error = may_create(dir, dentry);
#endif  

	if (error)
		return error;

	if ((S_ISCHR(mode) || S_ISBLK(mode)) && !capable(CAP_MKNOD))
		return -EPERM;

	if (!dir->i_op->mknod)
		return -EPERM;

	error = devcgroup_inode_mknod(mode, dev);
	if (error)
		return error;

	error = security_inode_mknod(dir, dentry, mode, dev);
	if (error)
		return error;

	error = dir->i_op->mknod(dir, dentry, mode, dev);
	if (!error)
		fsnotify_create(dir, dentry);
	return error;
}
EXPORT_SYMBOL(vfs_mknod);

static int may_mknod(umode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFREG:
	case S_IFCHR:
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK:
	case 0:  
		return 0;
	case S_IFDIR:
		return -EPERM;
	default:
		return -EINVAL;
	}
}

SYSCALL_DEFINE4(mknodat, int, dfd, const char __user *, filename, umode_t, mode,
		unsigned, dev)
{
	struct dentry *dentry;
	struct path path;
	int error;
	unsigned int lookup_flags = 0;

	error = may_mknod(mode);
	if (error)
		return error;
retry:
	dentry = user_path_create(dfd, filename, &path, lookup_flags);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	if (!IS_POSIXACL(path.dentry->d_inode))
		mode &= ~current_umask();
	error = security_path_mknod(&path, dentry, mode, dev);
	if (error)
		goto out;
	switch (mode & S_IFMT) {
		case 0: case S_IFREG:
			error = vfs_create(path.dentry->d_inode,dentry,mode,true);
			break;
		case S_IFCHR: case S_IFBLK:
			error = vfs_mknod(path.dentry->d_inode,dentry,mode,
					new_decode_dev(dev));
			break;
		case S_IFIFO: case S_IFSOCK:
			error = vfs_mknod(path.dentry->d_inode,dentry,mode,0);
			break;
	}
out:
	done_path_create(&path, dentry);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE3(mknod, const char __user *, filename, umode_t, mode, unsigned, dev)
{
	return sys_mknodat(AT_FDCWD, filename, mode, dev);
}

int vfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
#ifdef MY_ABC_HERE
	int error = may_create(dir, dentry, S_IFDIR);
#else
	int error = may_create(dir, dentry);
#endif  
	unsigned max_links = dir->i_sb->s_max_links;

	if (error)
		return error;

	if (!dir->i_op->mkdir)
		return -EPERM;

	mode &= (S_IRWXUGO|S_ISVTX);
	error = security_inode_mkdir(dir, dentry, mode);
	if (error)
		return error;

	if (max_links && dir->i_nlink >= max_links)
		return -EMLINK;

	error = dir->i_op->mkdir(dir, dentry, mode);
	if (!error)
		fsnotify_mkdir(dir, dentry);
#ifdef MY_ABC_HERE
	if (!error && IS_SYNOACL(dentry->d_parent)) {
		 
		synoacl_op_init(dentry);
	}
#endif  
	return error;
}
EXPORT_SYMBOL(vfs_mkdir);

SYSCALL_DEFINE3(mkdirat, int, dfd, const char __user *, pathname, umode_t, mode)
{
	struct dentry *dentry;
	struct path path;
	int error;
	unsigned int lookup_flags = LOOKUP_DIRECTORY;

retry:
	dentry = user_path_create(dfd, pathname, &path, lookup_flags);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	if (!IS_POSIXACL(path.dentry->d_inode))
		mode &= ~current_umask();
	error = security_path_mkdir(&path, dentry, mode);
	if (!error)
		error = vfs_mkdir(path.dentry->d_inode, dentry, mode);
	done_path_create(&path, dentry);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE2(mkdir, const char __user *, pathname, umode_t, mode)
{
	return sys_mkdirat(AT_FDCWD, pathname, mode);
}

void dentry_unhash(struct dentry *dentry)
{
	shrink_dcache_parent(dentry);
	spin_lock(&dentry->d_lock);
	if (dentry->d_lockref.count == 1)
		__d_drop(dentry);
	spin_unlock(&dentry->d_lock);
}
EXPORT_SYMBOL(dentry_unhash);

int vfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	int error = may_delete(dir, dentry, 1);

	if (error)
		return error;

	if (!dir->i_op->rmdir)
		return -EPERM;

	dget(dentry);
	inode_lock(dentry->d_inode);

	error = -EBUSY;
	if (is_local_mountpoint(dentry))
		goto out;

	error = security_inode_rmdir(dir, dentry);
	if (error)
		goto out;

	shrink_dcache_parent(dentry);
	error = dir->i_op->rmdir(dir, dentry);
	if (error)
		goto out;

	dentry->d_inode->i_flags |= S_DEAD;
	dont_mount(dentry);
	detach_mounts(dentry);

out:
	inode_unlock(dentry->d_inode);
	dput(dentry);
	if (!error)
		d_delete(dentry);
	return error;
}
EXPORT_SYMBOL(vfs_rmdir);

static long do_rmdir(int dfd, const char __user *pathname)
{
	int error = 0;
	struct filename *name;
	struct dentry *dentry;
	struct path path;
	struct qstr last;
	int type;
	unsigned int lookup_flags = 0;
retry:
	name = user_path_parent(dfd, pathname,
				&path, &last, &type, lookup_flags);
	if (IS_ERR(name))
		return PTR_ERR(name);

	switch (type) {
	case LAST_DOTDOT:
		error = -ENOTEMPTY;
		goto exit1;
	case LAST_DOT:
		error = -EINVAL;
		goto exit1;
	case LAST_ROOT:
		error = -EBUSY;
		goto exit1;
	}

	error = mnt_want_write(path.mnt);
	if (error)
		goto exit1;

	inode_lock_nested(path.dentry->d_inode, I_MUTEX_PARENT);
	dentry = __lookup_hash(&last, path.dentry, lookup_flags);
	error = PTR_ERR(dentry);
	if (IS_ERR(dentry))
		goto exit2;
	if (!dentry->d_inode) {
		error = -ENOENT;
		goto exit3;
	}
	error = security_path_rmdir(&path, dentry);
	if (error)
		goto exit3;
	error = vfs_rmdir(path.dentry->d_inode, dentry);
exit3:
	dput(dentry);
exit2:
	inode_unlock(path.dentry->d_inode);
	mnt_drop_write(path.mnt);
exit1:
	path_put(&path);
	putname(name);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE1(rmdir, const char __user *, pathname)
{
	return do_rmdir(AT_FDCWD, pathname);
}

int vfs_unlink(struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
{
	struct inode *target = dentry->d_inode;
	int error = may_delete(dir, dentry, 0);

	if (error)
		return error;

	if (!dir->i_op->unlink)
		return -EPERM;

	inode_lock(target);
	if (is_local_mountpoint(dentry))
		error = -EBUSY;
	else {
		error = security_inode_unlink(dir, dentry);
		if (!error) {
			error = try_break_deleg(target, delegated_inode);
			if (error)
				goto out;
			error = dir->i_op->unlink(dir, dentry);
			if (!error) {
				dont_mount(dentry);
				detach_mounts(dentry);
			}
		}
	}
out:
	inode_unlock(target);

	if (!error && !(dentry->d_flags & DCACHE_NFSFS_RENAMED)) {
		fsnotify_link_count(target);
		d_delete(dentry);
	}

	return error;
}
EXPORT_SYMBOL(vfs_unlink);

static long do_unlinkat(int dfd, const char __user *pathname)
{
	int error;
	struct filename *name;
	struct dentry *dentry;
	struct path path;
	struct qstr last;
	int type;
	struct inode *inode = NULL;
	struct inode *delegated_inode = NULL;
	unsigned int lookup_flags = 0;
retry:
	name = user_path_parent(dfd, pathname,
				&path, &last, &type, lookup_flags);
	if (IS_ERR(name))
		return PTR_ERR(name);

	error = -EISDIR;
	if (type != LAST_NORM)
		goto exit1;

	error = mnt_want_write(path.mnt);
	if (error)
		goto exit1;
retry_deleg:
	inode_lock_nested(path.dentry->d_inode, I_MUTEX_PARENT);
	dentry = __lookup_hash(&last, path.dentry, lookup_flags);
	error = PTR_ERR(dentry);
	if (!IS_ERR(dentry)) {
		 
		if (last.name[last.len])
			goto slashes;
		inode = dentry->d_inode;
		if (d_is_negative(dentry))
			goto slashes;
		ihold(inode);
		error = security_path_unlink(&path, dentry);
		if (error)
			goto exit2;
		error = vfs_unlink(path.dentry->d_inode, dentry, &delegated_inode);
exit2:
		dput(dentry);
	}
	inode_unlock(path.dentry->d_inode);
	if (inode)
		iput(inode);	 
	inode = NULL;
	if (delegated_inode) {
		error = break_deleg_wait(&delegated_inode);
		if (!error)
			goto retry_deleg;
	}
	mnt_drop_write(path.mnt);
exit1:
	path_put(&path);
	putname(name);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		inode = NULL;
		goto retry;
	}
	return error;

slashes:
	if (d_is_negative(dentry))
		error = -ENOENT;
	else if (d_is_dir(dentry))
		error = -EISDIR;
	else
		error = -ENOTDIR;
	goto exit2;
}

SYSCALL_DEFINE3(unlinkat, int, dfd, const char __user *, pathname, int, flag)
{
	if ((flag & ~AT_REMOVEDIR) != 0)
		return -EINVAL;

	if (flag & AT_REMOVEDIR)
		return do_rmdir(dfd, pathname);

	return do_unlinkat(dfd, pathname);
}

SYSCALL_DEFINE1(unlink, const char __user *, pathname)
{
	return do_unlinkat(AT_FDCWD, pathname);
}

int vfs_symlink(struct inode *dir, struct dentry *dentry, const char *oldname)
{
#ifdef MY_ABC_HERE
	int error = may_create(dir, dentry, S_IFLNK);
#else
	int error = may_create(dir, dentry);
#endif  

	if (error)
		return error;

	if (!dir->i_op->symlink)
		return -EPERM;

	error = security_inode_symlink(dir, dentry, oldname);
	if (error)
		return error;

	error = dir->i_op->symlink(dir, dentry, oldname);
	if (!error)
		fsnotify_create(dir, dentry);
	return error;
}
EXPORT_SYMBOL(vfs_symlink);

SYSCALL_DEFINE3(symlinkat, const char __user *, oldname,
		int, newdfd, const char __user *, newname)
{
	int error;
	struct filename *from;
	struct dentry *dentry;
	struct path path;
	unsigned int lookup_flags = 0;

	from = getname(oldname);
	if (IS_ERR(from))
		return PTR_ERR(from);
retry:
	dentry = user_path_create(newdfd, newname, &path, lookup_flags);
	error = PTR_ERR(dentry);
	if (IS_ERR(dentry))
		goto out_putname;

	error = security_path_symlink(&path, dentry, from->name);
	if (!error)
		error = vfs_symlink(path.dentry->d_inode, dentry, from->name);
	done_path_create(&path, dentry);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out_putname:
	putname(from);
	return error;
}

SYSCALL_DEFINE2(symlink, const char __user *, oldname, const char __user *, newname)
{
	return sys_symlinkat(oldname, AT_FDCWD, newname);
}

int vfs_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry, struct inode **delegated_inode)
{
	struct inode *inode = old_dentry->d_inode;
	unsigned max_links = dir->i_sb->s_max_links;
	int error;

	if (!inode)
		return -ENOENT;

#ifdef MY_ABC_HERE
	error = may_create(dir, new_dentry, inode->i_mode);
#else
	error = may_create(dir, new_dentry);
#endif  
	if (error)
		return error;

	if (dir->i_sb != inode->i_sb)
		return -EXDEV;

	if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
		return -EPERM;
	if (!dir->i_op->link)
		return -EPERM;
	if (S_ISDIR(inode->i_mode))
		return -EPERM;

	error = security_inode_link(old_dentry, dir, new_dentry);
	if (error)
		return error;

	inode_lock(inode);
	 
	if (inode->i_nlink == 0 && !(inode->i_state & I_LINKABLE))
		error =  -ENOENT;
	else if (max_links && inode->i_nlink >= max_links)
		error = -EMLINK;
	else {
		error = try_break_deleg(inode, delegated_inode);
		if (!error)
			error = dir->i_op->link(old_dentry, dir, new_dentry);
	}

	if (!error && (inode->i_state & I_LINKABLE)) {
		spin_lock(&inode->i_lock);
		inode->i_state &= ~I_LINKABLE;
		spin_unlock(&inode->i_lock);
	}
	inode_unlock(inode);
	if (!error)
		fsnotify_link(dir, inode, new_dentry);
	return error;
}
EXPORT_SYMBOL(vfs_link);

SYSCALL_DEFINE5(linkat, int, olddfd, const char __user *, oldname,
		int, newdfd, const char __user *, newname, int, flags)
{
	struct dentry *new_dentry;
	struct path old_path, new_path;
	struct inode *delegated_inode = NULL;
	int how = 0;
	int error;

	if ((flags & ~(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH)) != 0)
		return -EINVAL;
	 
	if (flags & AT_EMPTY_PATH) {
		if (!capable(CAP_DAC_READ_SEARCH))
			return -ENOENT;
		how = LOOKUP_EMPTY;
	}

	if (flags & AT_SYMLINK_FOLLOW)
		how |= LOOKUP_FOLLOW;
retry:
	error = user_path_at(olddfd, oldname, how, &old_path);
	if (error)
		return error;

	new_dentry = user_path_create(newdfd, newname, &new_path,
					(how & LOOKUP_REVAL));
	error = PTR_ERR(new_dentry);
	if (IS_ERR(new_dentry))
		goto out;

	error = -EXDEV;
	if (old_path.mnt != new_path.mnt)
		goto out_dput;
	error = may_linkat(&old_path);
	if (unlikely(error))
		goto out_dput;
	error = security_path_link(old_path.dentry, &new_path, new_dentry);
	if (error)
		goto out_dput;
	error = vfs_link(old_path.dentry, new_path.dentry->d_inode, new_dentry, &delegated_inode);
out_dput:
	done_path_create(&new_path, new_dentry);
	if (delegated_inode) {
		error = break_deleg_wait(&delegated_inode);
		if (!error) {
			path_put(&old_path);
			goto retry;
		}
	}
	if (retry_estale(error, how)) {
		path_put(&old_path);
		how |= LOOKUP_REVAL;
		goto retry;
	}
out:
	path_put(&old_path);

	return error;
}

SYSCALL_DEFINE2(link, const char __user *, oldname, const char __user *, newname)
{
	return sys_linkat(AT_FDCWD, oldname, AT_FDCWD, newname, 0);
}

#ifdef MY_ABC_HERE
inline void free_rename_path_list(struct synotify_rename_path * rename_path_list)
{
	while(rename_path_list) {
		struct synotify_rename_path *tmp = rename_path_list;
		rename_path_list = rename_path_list->next;

		if (tmp->old_full_path)
			kfree(tmp->old_full_path);
		if (tmp->new_full_path)
			kfree(tmp->new_full_path);

		mntput(tmp->vfs_mnt);
		kfree(tmp);
	}
}

static inline struct synotify_rename_path * get_rename_path(struct vfsmount *vfsmnt, struct dentry *old_dentry, struct dentry *new_dentry)
{
	int ret = -1;
	struct synotify_rename_path * result = NULL;
	struct synotify_rename_path * rename_path = NULL;

	struct path old_path;
	struct path new_path;
	struct path root_path;
	char *old_path_buf = NULL;
	char *new_path_buf = NULL;
	char *tmp_old_full_path = NULL;
	char *tmp_new_full_path = NULL;
	char *tmp_old_path = NULL;
	char *tmp_new_path = NULL;

	if (!vfsmnt || !old_dentry || !new_dentry) {
		return NULL;
	}

	rename_path = kmalloc(sizeof(struct synotify_rename_path), GFP_NOFS);
	if (!rename_path) {
		goto end;
	}

	memset(&old_path, 0, sizeof(struct path));
	memset(&new_path, 0, sizeof(struct path));
	memset(&root_path, 0, sizeof(struct path));

	old_path.mnt = vfsmnt;
	old_path.dentry = old_dentry;
	new_path.mnt = vfsmnt;
	new_path.dentry = new_dentry;

	root_path.mnt = vfsmnt;
	root_path.dentry = vfsmnt->mnt_root;

	old_path_buf = kmalloc(PATH_MAX, GFP_NOFS);
	if (!old_path_buf) {
		goto end;
	}

	new_path_buf = kmalloc(PATH_MAX, GFP_NOFS);
	if (!new_path_buf) {
		goto end;
	}

	tmp_old_full_path = __d_path(&old_path, &root_path, old_path_buf, PATH_MAX-1);
	tmp_new_full_path = __d_path(&new_path, &root_path, new_path_buf, PATH_MAX-1);

	if (IS_ERR_OR_NULL(tmp_old_full_path) || IS_ERR_OR_NULL(tmp_new_full_path)) {
		goto end;
	}

	tmp_old_path = kstrdup(tmp_old_full_path, GFP_NOFS);
	if (!tmp_old_path) {
		goto end;
	}
	tmp_new_path = kstrdup(tmp_new_full_path, GFP_NOFS);
	if (!tmp_new_path) {
		goto end;
	}
	rename_path->old_full_path = tmp_old_path;
	rename_path->new_full_path = tmp_new_path;
	rename_path->vfs_mnt = vfsmnt;
	rename_path->next = NULL;

	result = rename_path;
	ret = 0;
end:
	if (ret != 0) {
		if (tmp_old_path)
			kfree(tmp_old_path);
		if (tmp_new_path)
			kfree(tmp_new_path);
		if (rename_path)
			kfree(rename_path);
	}

	if (old_path_buf)
		kfree(old_path_buf);
	if (new_path_buf)
		kfree(new_path_buf);

	return result;
}

inline struct synotify_rename_path * get_rename_path_list(struct dentry *old_dentry, struct dentry *new_dentry)
{
	struct nsproxy *nsproxy = current->nsproxy;
	struct mnt_namespace *mnt_space = NULL;
	struct list_head *list_head = NULL;
	struct synotify_rename_path *head = NULL;
	struct synotify_rename_path *tail = NULL;

	if (!nsproxy) {
		return NULL;
	}

	mnt_space = nsproxy->mnt_ns;
	if (!mnt_space) {
		return NULL;
	}

	down_read(&namespace_sem);
	list_for_each(list_head, &mnt_space->list) {
		struct mount *mnt = list_entry(list_head, struct mount, mnt_list);
		struct synotify_rename_path *rename_path = NULL;
		struct vfsmount *vfsmnt = NULL;

		if (!mnt) {
			continue;
		}
		if (mnt->mnt.mnt_sb != new_dentry->d_sb) {
			continue;
		}

		if (!((FS_MOVED_FROM | FS_MOVED_TO) & mnt->mnt_fsnotify_mask)) {
			continue;
		}

		vfsmnt = &mnt->mnt;
		 
		mntget(vfsmnt);

		rename_path = get_rename_path(vfsmnt, old_dentry, new_dentry);

		if (!rename_path) {
			mntput(vfsmnt);
		} else {
			if (!head) {
				head = rename_path;
				tail = rename_path;
			} else {
				tail->next = rename_path;
				tail = rename_path;
			}
		}
	}  
	up_read(&namespace_sem);

	return head;
}
#endif  

int vfs_rename(struct inode *old_dir, struct dentry *old_dentry,
	       struct inode *new_dir, struct dentry *new_dentry,
	       struct inode **delegated_inode, unsigned int flags)
{
	int error;
	bool is_dir = d_is_dir(old_dentry);
	struct inode *source = old_dentry->d_inode;
	struct inode *target = new_dentry->d_inode;
	bool new_is_dir = false;
	unsigned max_links = new_dir->i_sb->s_max_links;
	struct name_snapshot old_name;
#ifdef MY_ABC_HERE
	struct synotify_rename_path *rename_path_list = NULL;
#endif  

	if (vfs_select_inode(old_dentry, 0) == vfs_select_inode(new_dentry, 0))
		return 0;

	error = may_delete(old_dir, old_dentry, is_dir);
	if (error)
		return error;

	if (!target) {
#ifdef MY_ABC_HERE
		error = may_create(new_dir, new_dentry, source->i_mode);
#else
		error = may_create(new_dir, new_dentry);
#endif  
	} else {
		new_is_dir = d_is_dir(new_dentry);

		if (!(flags & RENAME_EXCHANGE))
			error = may_delete(new_dir, new_dentry, is_dir);
		else
			error = may_delete(new_dir, new_dentry, new_is_dir);
	}
	if (error)
		return error;

	if (!old_dir->i_op->rename && !old_dir->i_op->rename2)
		return -EPERM;

	if (flags && !old_dir->i_op->rename2)
		return -EINVAL;

	if (new_dir != old_dir) {
#ifdef MY_ABC_HERE
		if (is_dir && !(old_dentry->d_sb->s_magic == BTRFS_SUPER_MAGIC && old_dentry->d_inode->i_ino == 256)) {
#else
		if (is_dir) {
#endif  
#ifdef MY_ABC_HERE
			if (!IS_SYNOACL(old_dentry)) {
				error = inode_permission(source, MAY_WRITE);
			}
#else
			error = inode_permission(source, MAY_WRITE);
#endif  
			if (error)
				return error;
		}
#ifdef MY_ABC_HERE
		if ((flags & RENAME_EXCHANGE) && new_is_dir && !(new_dentry->d_sb->s_magic == BTRFS_SUPER_MAGIC && new_dentry->d_inode->i_ino == 256)) {
#else
		if ((flags & RENAME_EXCHANGE) && new_is_dir) {
#endif  
#ifdef MY_ABC_HERE
			if (!IS_SYNOACL(new_dentry)) {
				error = inode_permission(target, MAY_WRITE);
			}
#else
			error = inode_permission(target, MAY_WRITE);
#endif  
			if (error)
				return error;
		}
	}

	error = security_inode_rename(old_dir, old_dentry, new_dir, new_dentry,
				      flags);
	if (error)
		return error;

#ifdef MY_ABC_HERE
	rename_path_list = get_rename_path_list(old_dentry, new_dentry);
#endif  

	take_dentry_name_snapshot(&old_name, old_dentry);
	dget(new_dentry);
	if (!is_dir || (flags & RENAME_EXCHANGE))
		lock_two_nondirectories(source, target);
	else if (target)
		inode_lock(target);

	error = -EBUSY;
	if (is_local_mountpoint(old_dentry) || is_local_mountpoint(new_dentry))
		goto out;

	if (max_links && new_dir != old_dir) {
		error = -EMLINK;
		if (is_dir && !new_is_dir && new_dir->i_nlink >= max_links)
			goto out;
		if ((flags & RENAME_EXCHANGE) && !is_dir && new_is_dir &&
		    old_dir->i_nlink >= max_links)
			goto out;
	}
	if (is_dir && !(flags & RENAME_EXCHANGE) && target)
		shrink_dcache_parent(new_dentry);
	if (!is_dir) {
		error = try_break_deleg(source, delegated_inode);
		if (error)
			goto out;
	}
	if (target && !new_is_dir) {
		error = try_break_deleg(target, delegated_inode);
		if (error)
			goto out;
	}
	if (!old_dir->i_op->rename2) {
		error = old_dir->i_op->rename(old_dir, old_dentry,
					      new_dir, new_dentry);
	} else {
		WARN_ON(old_dir->i_op->rename != NULL);
		error = old_dir->i_op->rename2(old_dir, old_dentry,
					       new_dir, new_dentry, flags);
	}
	if (error)
		goto out;

	if (!(flags & RENAME_EXCHANGE) && target) {
		if (is_dir)
			target->i_flags |= S_DEAD;
		dont_mount(new_dentry);
		detach_mounts(new_dentry);
	}
	if (!(old_dir->i_sb->s_type->fs_flags & FS_RENAME_DOES_D_MOVE)) {
		if (!(flags & RENAME_EXCHANGE))
			d_move(old_dentry, new_dentry);
		else
			d_exchange(old_dentry, new_dentry);
	}
out:
	if (!is_dir || (flags & RENAME_EXCHANGE))
		unlock_two_nondirectories(source, target);
	else if (target)
		mutex_unlock(&target->i_mutex);
	dput(new_dentry);
	if (!error) {
#ifdef MY_ABC_HERE
		fsnotify_move(old_dir, new_dir, old_name.name, is_dir,
			      !(flags & RENAME_EXCHANGE) ? target : NULL, old_dentry, rename_path_list, false);
#else
		fsnotify_move(old_dir, new_dir, old_name.name, is_dir,
			      !(flags & RENAME_EXCHANGE) ? target : NULL, old_dentry);
#endif  
		if (flags & RENAME_EXCHANGE) {
#ifdef MY_ABC_HERE
			fsnotify_move(new_dir, old_dir, old_dentry->d_name.name,
					  new_is_dir, NULL, new_dentry, rename_path_list, true);
#else
			fsnotify_move(new_dir, old_dir, old_dentry->d_name.name,
				      new_is_dir, NULL, new_dentry);
#endif  
		}
	}
	release_dentry_name_snapshot(&old_name);

#ifdef MY_ABC_HERE
	free_rename_path_list(rename_path_list);
#endif  

	return error;
}
EXPORT_SYMBOL(vfs_rename);

SYSCALL_DEFINE5(renameat2, int, olddfd, const char __user *, oldname,
		int, newdfd, const char __user *, newname, unsigned int, flags)
{
	struct dentry *old_dentry, *new_dentry;
	struct dentry *trap;
	struct path old_path, new_path;
	struct qstr old_last, new_last;
	int old_type, new_type;
	struct inode *delegated_inode = NULL;
	struct filename *from;
	struct filename *to;
	unsigned int lookup_flags = 0, target_flags = LOOKUP_RENAME_TARGET;
	bool should_retry = false;
	int error;

	if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT))
		return -EINVAL;

	if ((flags & (RENAME_NOREPLACE | RENAME_WHITEOUT)) &&
	    (flags & RENAME_EXCHANGE))
		return -EINVAL;

	if ((flags & RENAME_WHITEOUT) && !capable(CAP_MKNOD))
		return -EPERM;

	if (flags & RENAME_EXCHANGE)
		target_flags = 0;

retry:
	from = user_path_parent(olddfd, oldname,
				&old_path, &old_last, &old_type, lookup_flags);
	if (IS_ERR(from)) {
		error = PTR_ERR(from);
		goto exit;
	}

	to = user_path_parent(newdfd, newname,
				&new_path, &new_last, &new_type, lookup_flags);
	if (IS_ERR(to)) {
		error = PTR_ERR(to);
		goto exit1;
	}

	error = -EXDEV;
	if (old_path.mnt != new_path.mnt)
		goto exit2;

	error = -EBUSY;
	if (old_type != LAST_NORM)
		goto exit2;

	if (flags & RENAME_NOREPLACE)
		error = -EEXIST;
	if (new_type != LAST_NORM)
		goto exit2;

	error = mnt_want_write(old_path.mnt);
	if (error)
		goto exit2;

retry_deleg:
	trap = lock_rename(new_path.dentry, old_path.dentry);

	old_dentry = __lookup_hash(&old_last, old_path.dentry, lookup_flags);
	error = PTR_ERR(old_dentry);
	if (IS_ERR(old_dentry))
		goto exit3;
	 
	error = -ENOENT;
	if (d_is_negative(old_dentry))
		goto exit4;
	new_dentry = __lookup_hash(&new_last, new_path.dentry, lookup_flags | target_flags);
	error = PTR_ERR(new_dentry);
	if (IS_ERR(new_dentry))
		goto exit4;
	error = -EEXIST;
	if ((flags & RENAME_NOREPLACE) && d_is_positive(new_dentry))
		goto exit5;
	if (flags & RENAME_EXCHANGE) {
		error = -ENOENT;
		if (d_is_negative(new_dentry))
			goto exit5;

		if (!d_is_dir(new_dentry)) {
			error = -ENOTDIR;
			if (new_last.name[new_last.len])
				goto exit5;
		}
	}
	 
	if (!d_is_dir(old_dentry)) {
		error = -ENOTDIR;
		if (old_last.name[old_last.len])
			goto exit5;
		if (!(flags & RENAME_EXCHANGE) && new_last.name[new_last.len])
			goto exit5;
	}
	 
	error = -EINVAL;
	if (old_dentry == trap)
		goto exit5;
	 
	if (!(flags & RENAME_EXCHANGE))
		error = -ENOTEMPTY;
	if (new_dentry == trap)
		goto exit5;

	error = security_path_rename(&old_path, old_dentry,
				     &new_path, new_dentry, flags);
	if (error)
		goto exit5;
	error = vfs_rename(old_path.dentry->d_inode, old_dentry,
			   new_path.dentry->d_inode, new_dentry,
			   &delegated_inode, flags);
exit5:
	dput(new_dentry);
exit4:
	dput(old_dentry);
exit3:
	unlock_rename(new_path.dentry, old_path.dentry);
	if (delegated_inode) {
		error = break_deleg_wait(&delegated_inode);
		if (!error)
			goto retry_deleg;
	}
	mnt_drop_write(old_path.mnt);
exit2:
	if (retry_estale(error, lookup_flags))
		should_retry = true;
	path_put(&new_path);
	putname(to);
exit1:
	path_put(&old_path);
	putname(from);
	if (should_retry) {
		should_retry = false;
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
exit:
	return error;
}

SYSCALL_DEFINE4(renameat, int, olddfd, const char __user *, oldname,
		int, newdfd, const char __user *, newname)
{
	return sys_renameat2(olddfd, oldname, newdfd, newname, 0);
}

SYSCALL_DEFINE2(rename, const char __user *, oldname, const char __user *, newname)
{
	return sys_renameat2(AT_FDCWD, oldname, AT_FDCWD, newname, 0);
}

int vfs_whiteout(struct inode *dir, struct dentry *dentry)
{
#ifdef MY_ABC_HERE
	int error = may_create(dir, dentry, S_IFCHR);
#else
	int error = may_create(dir, dentry);
#endif  
	if (error)
		return error;

	if (!dir->i_op->mknod)
		return -EPERM;

	return dir->i_op->mknod(dir, dentry,
				S_IFCHR | WHITEOUT_MODE, WHITEOUT_DEV);
}
EXPORT_SYMBOL(vfs_whiteout);

int readlink_copy(char __user *buffer, int buflen, const char *link)
{
	int len = PTR_ERR(link);
	if (IS_ERR(link))
		goto out;

	len = strlen(link);
	if (len > (unsigned) buflen)
		len = buflen;
	if (copy_to_user(buffer, link, len))
		len = -EFAULT;
out:
	return len;
}
EXPORT_SYMBOL(readlink_copy);

int generic_readlink(struct dentry *dentry, char __user *buffer, int buflen)
{
	void *cookie;
	struct inode *inode = d_inode(dentry);
	const char *link = inode->i_link;
	int res;

	if (!link) {
		link = inode->i_op->follow_link(dentry, &cookie);
		if (IS_ERR(link))
			return PTR_ERR(link);
	}
	res = readlink_copy(buffer, buflen, link);
	if (inode->i_op->put_link)
		inode->i_op->put_link(inode, cookie);
	return res;
}
EXPORT_SYMBOL(generic_readlink);

static const char *page_getlink(struct dentry * dentry, void **cookie)
{
	char *kaddr;
	struct page *page;
	struct address_space *mapping = dentry->d_inode->i_mapping;
	page = read_mapping_page(mapping, 0, NULL);
	if (IS_ERR(page))
		return (char*)page;
	*cookie = page;
	kaddr = kmap(page);
	nd_terminate_link(kaddr, dentry->d_inode->i_size, PAGE_SIZE - 1);
	return kaddr;
}

const char *page_follow_link_light(struct dentry *dentry, void **cookie)
{
	return page_getlink(dentry, cookie);
}
EXPORT_SYMBOL(page_follow_link_light);

void page_put_link(struct inode *unused, void *cookie)
{
	struct page *page = cookie;
	kunmap(page);
	page_cache_release(page);
}
EXPORT_SYMBOL(page_put_link);

int page_readlink(struct dentry *dentry, char __user *buffer, int buflen)
{
	void *cookie = NULL;
	int res = readlink_copy(buffer, buflen, page_getlink(dentry, &cookie));
	if (cookie)
		page_put_link(NULL, cookie);
	return res;
}
EXPORT_SYMBOL(page_readlink);

int __page_symlink(struct inode *inode, const char *symname, int len, int nofs)
{
	struct address_space *mapping = inode->i_mapping;
	struct page *page;
	void *fsdata;
	int err;
	char *kaddr;
	unsigned int flags = AOP_FLAG_UNINTERRUPTIBLE;
	if (nofs)
		flags |= AOP_FLAG_NOFS;

retry:
	err = pagecache_write_begin(NULL, mapping, 0, len-1,
				flags, &page, &fsdata);
	if (err)
		goto fail;

	kaddr = kmap_atomic(page);
	memcpy(kaddr, symname, len-1);
	kunmap_atomic(kaddr);

	err = pagecache_write_end(NULL, mapping, 0, len-1, len-1,
							page, fsdata);
	if (err < 0)
		goto fail;
	if (err < len-1)
		goto retry;

	mark_inode_dirty(inode);
	return 0;
fail:
	return err;
}
EXPORT_SYMBOL(__page_symlink);

int page_symlink(struct inode *inode, const char *symname, int len)
{
	return __page_symlink(inode, symname, len,
			!mapping_gfp_constraint(inode->i_mapping, __GFP_FS));
}
EXPORT_SYMBOL(page_symlink);

const struct inode_operations page_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
};
EXPORT_SYMBOL(page_symlink_inode_operations);
