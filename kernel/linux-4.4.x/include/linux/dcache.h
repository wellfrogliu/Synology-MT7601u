#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#ifndef __LINUX_DCACHE_H
#define __LINUX_DCACHE_H

#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/rculist_bl.h>
#include <linux/spinlock.h>
#include <linux/seqlock.h>
#include <linux/cache.h>
#include <linux/rcupdate.h>
#include <linux/lockref.h>

struct path;
struct vfsmount;

#define IS_ROOT(x) ((x) == (x)->d_parent)

#ifdef __LITTLE_ENDIAN
 #define HASH_LEN_DECLARE u32 hash; u32 len;
 #define bytemask_from_count(cnt)	(~(~0ul << (cnt)*8))
#else
 #define HASH_LEN_DECLARE u32 len; u32 hash;
 #define bytemask_from_count(cnt)	(~(~0ul >> (cnt)*8))
#endif

struct qstr {
	union {
		struct {
			HASH_LEN_DECLARE;
		};
		u64 hash_len;
	};
	const unsigned char *name;
};

#define QSTR_INIT(n,l) { { { .len = l } }, .name = n }
#define hashlen_hash(hashlen) ((u32) (hashlen))
#define hashlen_len(hashlen)  ((u32)((hashlen) >> 32))
#define hashlen_create(hash,len) (((u64)(len)<<32)|(u32)(hash))

struct dentry_stat_t {
	long nr_dentry;
	long nr_unused;
	long age_limit;           
	long want_pages;          
	long dummy[2];
};
extern struct dentry_stat_t dentry_stat;

#define init_name_hash()		0

static inline unsigned long
partial_name_hash(unsigned long c, unsigned long prevhash)
{
	return (prevhash + (c << 4) + (c >> 4)) * 11;
}

static inline unsigned long end_name_hash(unsigned long hash)
{
	return (unsigned int) hash;
}

extern unsigned int full_name_hash(const unsigned char *, unsigned int);

#ifdef CONFIG_64BIT
# define DNAME_INLINE_LEN 32  
#else
# ifdef CONFIG_SMP
#  define DNAME_INLINE_LEN 36  
# else
#  define DNAME_INLINE_LEN 40  
# endif
#endif

#define d_lock	d_lockref.lock

struct dentry {
	 
	unsigned int d_flags;		 
	seqcount_t d_seq;		 
	struct hlist_bl_node d_hash;	 
	struct dentry *d_parent;	 
	struct qstr d_name;
	struct inode *d_inode;		 
	unsigned char d_iname[DNAME_INLINE_LEN];	 

	struct lockref d_lockref;	 
	const struct dentry_operations *d_op;
	struct super_block *d_sb;	 
	unsigned long d_time;		 
	void *d_fsdata;			 

	struct list_head d_lru;		 
	struct list_head d_child;	 
	struct list_head d_subdirs;	 
	 
	union {
		struct hlist_node d_alias;	 
	 	struct rcu_head d_rcu;
	} d_u;
};

enum dentry_d_lock_class
{
	DENTRY_D_LOCK_NORMAL,  
	DENTRY_D_LOCK_NESTED
};

struct dentry_operations {
	int (*d_revalidate)(struct dentry *, unsigned int);
	int (*d_weak_revalidate)(struct dentry *, unsigned int);
	int (*d_hash)(const struct dentry *, struct qstr *);
	int (*d_compare)(const struct dentry *, const struct dentry *,
			unsigned int, const char *, const struct qstr *);
#ifdef MY_ABC_HERE
	int (*d_compare_case)(const struct dentry *, unsigned int, const char *,
			const struct qstr *, int caseless);
#endif  
	int (*d_delete)(const struct dentry *);
	void (*d_release)(struct dentry *);
	void (*d_prune)(struct dentry *);
	void (*d_iput)(struct dentry *, struct inode *);
	char *(*d_dname)(struct dentry *, char *, int);
	struct vfsmount *(*d_automount)(struct path *);
	int (*d_manage)(struct dentry *, bool);
	struct inode *(*d_select_inode)(struct dentry *, unsigned);
	struct dentry *(*d_real)(struct dentry *, struct inode *);
} ____cacheline_aligned;

#define DCACHE_OP_HASH			0x00000001
#define DCACHE_OP_COMPARE		0x00000002
#define DCACHE_OP_REVALIDATE		0x00000004
#define DCACHE_OP_DELETE		0x00000008
#define DCACHE_OP_PRUNE			0x00000010

#define	DCACHE_DISCONNECTED		0x00000020
      
#define DCACHE_REFERENCED		0x00000040  
#define DCACHE_RCUACCESS		0x00000080  

#define DCACHE_CANT_MOUNT		0x00000100
#define DCACHE_GENOCIDE			0x00000200
#define DCACHE_SHRINK_LIST		0x00000400

#define DCACHE_OP_WEAK_REVALIDATE	0x00000800

#define DCACHE_NFSFS_RENAMED		0x00001000
      
#define DCACHE_COOKIE			0x00002000  
#define DCACHE_FSNOTIFY_PARENT_WATCHED	0x00004000
      
#define DCACHE_DENTRY_KILLED		0x00008000

#define DCACHE_MOUNTED			0x00010000  
#define DCACHE_NEED_AUTOMOUNT		0x00020000  
#define DCACHE_MANAGE_TRANSIT		0x00040000  
#define DCACHE_MANAGED_DENTRY \
	(DCACHE_MOUNTED|DCACHE_NEED_AUTOMOUNT|DCACHE_MANAGE_TRANSIT)

#define DCACHE_LRU_LIST			0x00080000

#define DCACHE_ENTRY_TYPE		0x00700000
#define DCACHE_MISS_TYPE		0x00000000  
#define DCACHE_WHITEOUT_TYPE		0x00100000  
#define DCACHE_DIRECTORY_TYPE		0x00200000  
#define DCACHE_AUTODIR_TYPE		0x00300000  
#define DCACHE_REGULAR_TYPE		0x00400000  
#define DCACHE_SPECIAL_TYPE		0x00500000  
#define DCACHE_SYMLINK_TYPE		0x00600000  

#define DCACHE_MAY_FREE			0x00800000
#define DCACHE_FALLTHRU			0x01000000  
#define DCACHE_OP_SELECT_INODE		0x02000000  
#define DCACHE_OP_REAL			0x08000000

#ifdef MY_ABC_HERE
#define DCACHE_OP_COMPARE_CASE	0x10000000
#endif  

extern seqlock_t rename_lock;

#ifdef MY_ABC_HERE
extern int dentry_cmp(const struct dentry *dentry, const unsigned char *ct, unsigned tcount);
extern int dentry_string_cmp(const unsigned char *cs, const unsigned char *ct, unsigned tcount);
#endif  

extern void d_instantiate(struct dentry *, struct inode *);
extern struct dentry * d_instantiate_unique(struct dentry *, struct inode *);
extern int d_instantiate_no_diralias(struct dentry *, struct inode *);
extern void __d_drop(struct dentry *dentry);
extern void d_drop(struct dentry *dentry);
extern void d_delete(struct dentry *);
extern void d_set_d_op(struct dentry *dentry, const struct dentry_operations *op);

extern struct dentry * d_alloc(struct dentry *, const struct qstr *);
extern struct dentry * d_alloc_pseudo(struct super_block *, const struct qstr *);
extern struct dentry * d_splice_alias(struct inode *, struct dentry *);
extern struct dentry * d_add_ci(struct dentry *, struct inode *, struct qstr *);
extern struct dentry *d_find_any_alias(struct inode *inode);
extern struct dentry * d_obtain_alias(struct inode *);
extern struct dentry * d_obtain_root(struct inode *);
extern void shrink_dcache_sb(struct super_block *);
extern void shrink_dcache_parent(struct dentry *);
extern void shrink_dcache_for_umount(struct super_block *);
extern void d_invalidate(struct dentry *);

extern struct dentry * d_make_root(struct inode *);

extern void d_genocide(struct dentry *);

extern void d_tmpfile(struct dentry *, struct inode *);

extern struct dentry *d_find_alias(struct inode *);
extern void d_prune_aliases(struct inode *);

extern int have_submounts(struct dentry *);

extern void d_rehash(struct dentry *);

static inline void d_add(struct dentry *entry, struct inode *inode)
{
	d_instantiate(entry, inode);
	d_rehash(entry);
}

static inline struct dentry *d_add_unique(struct dentry *entry, struct inode *inode)
{
	struct dentry *res;

	res = d_instantiate_unique(entry, inode);
	d_rehash(res != NULL ? res : entry);
	return res;
}

extern void dentry_update_name_case(struct dentry *, struct qstr *);

extern void d_move(struct dentry *, struct dentry *);
extern void d_exchange(struct dentry *, struct dentry *);
extern struct dentry *d_ancestor(struct dentry *, struct dentry *);

extern struct dentry *d_lookup(const struct dentry *, const struct qstr *);
extern struct dentry *d_hash_and_lookup(struct dentry *, struct qstr *);
#ifdef MY_ABC_HERE
extern struct dentry *d_lookup_case(struct dentry *, struct qstr *, int caseless);
extern struct dentry *__d_lookup(const struct dentry *, const struct qstr *, int caseless);
extern struct dentry *__d_lookup_rcu(const struct dentry *parent,
				const struct qstr *name, unsigned *seq,
				int caseless);
#else
extern struct dentry *__d_lookup(const struct dentry *, const struct qstr *);
extern struct dentry *__d_lookup_rcu(const struct dentry *parent,
				const struct qstr *name, unsigned *seq);
#endif  

static inline unsigned d_count(const struct dentry *dentry)
{
	return dentry->d_lockref.count;
}

extern __printf(4, 5)
char *dynamic_dname(struct dentry *, char *, int, const char *, ...);
extern char *simple_dname(struct dentry *, char *, int);

extern char *__d_path(const struct path *, const struct path *, char *, int);
extern char *d_absolute_path(const struct path *, char *, int);
extern char *d_path(const struct path *, char *, int);
extern char *dentry_path_raw(struct dentry *, char *, int);
extern char *dentry_path(struct dentry *, char *, int);

static inline struct dentry *dget_dlock(struct dentry *dentry)
{
	if (dentry)
		dentry->d_lockref.count++;
	return dentry;
}

static inline struct dentry *dget(struct dentry *dentry)
{
	if (dentry)
		lockref_get(&dentry->d_lockref);
	return dentry;
}

extern struct dentry *dget_parent(struct dentry *dentry);

static inline int d_unhashed(const struct dentry *dentry)
{
	return hlist_bl_unhashed(&dentry->d_hash);
}

static inline int d_unlinked(const struct dentry *dentry)
{
	return d_unhashed(dentry) && !IS_ROOT(dentry);
}

static inline int cant_mount(const struct dentry *dentry)
{
	return (dentry->d_flags & DCACHE_CANT_MOUNT);
}

static inline void dont_mount(struct dentry *dentry)
{
	spin_lock(&dentry->d_lock);
	dentry->d_flags |= DCACHE_CANT_MOUNT;
	spin_unlock(&dentry->d_lock);
}

extern void dput(struct dentry *);

static inline bool d_managed(const struct dentry *dentry)
{
	return dentry->d_flags & DCACHE_MANAGED_DENTRY;
}

static inline bool d_mountpoint(const struct dentry *dentry)
{
	return dentry->d_flags & DCACHE_MOUNTED;
}

static inline unsigned __d_entry_type(const struct dentry *dentry)
{
	return dentry->d_flags & DCACHE_ENTRY_TYPE;
}

static inline bool d_is_miss(const struct dentry *dentry)
{
	return __d_entry_type(dentry) == DCACHE_MISS_TYPE;
}

static inline bool d_is_whiteout(const struct dentry *dentry)
{
	return __d_entry_type(dentry) == DCACHE_WHITEOUT_TYPE;
}

static inline bool d_can_lookup(const struct dentry *dentry)
{
	return __d_entry_type(dentry) == DCACHE_DIRECTORY_TYPE;
}

static inline bool d_is_autodir(const struct dentry *dentry)
{
	return __d_entry_type(dentry) == DCACHE_AUTODIR_TYPE;
}

static inline bool d_is_dir(const struct dentry *dentry)
{
	return d_can_lookup(dentry) || d_is_autodir(dentry);
}

static inline bool d_is_symlink(const struct dentry *dentry)
{
	return __d_entry_type(dentry) == DCACHE_SYMLINK_TYPE;
}

static inline bool d_is_reg(const struct dentry *dentry)
{
	return __d_entry_type(dentry) == DCACHE_REGULAR_TYPE;
}

static inline bool d_is_special(const struct dentry *dentry)
{
	return __d_entry_type(dentry) == DCACHE_SPECIAL_TYPE;
}

static inline bool d_is_file(const struct dentry *dentry)
{
	return d_is_reg(dentry) || d_is_special(dentry);
}

static inline bool d_is_negative(const struct dentry *dentry)
{
	 
	return d_is_miss(dentry);
}

static inline bool d_is_positive(const struct dentry *dentry)
{
	return !d_is_negative(dentry);
}

static inline bool d_really_is_negative(const struct dentry *dentry)
{
	return dentry->d_inode == NULL;
}

static inline bool d_really_is_positive(const struct dentry *dentry)
{
	return dentry->d_inode != NULL;
}

static inline int simple_positive(struct dentry *dentry)
{
	return d_really_is_positive(dentry) && !d_unhashed(dentry);
}

extern void d_set_fallthru(struct dentry *dentry);

static inline bool d_is_fallthru(const struct dentry *dentry)
{
	return dentry->d_flags & DCACHE_FALLTHRU;
}

extern int sysctl_vfs_cache_pressure;

static inline unsigned long vfs_pressure_ratio(unsigned long val)
{
	return mult_frac(val, sysctl_vfs_cache_pressure, 100);
}

static inline struct inode *d_inode(const struct dentry *dentry)
{
	return dentry->d_inode;
}

static inline struct inode *d_inode_rcu(const struct dentry *dentry)
{
	return ACCESS_ONCE(dentry->d_inode);
}

static inline struct inode *d_backing_inode(const struct dentry *upper)
{
	struct inode *inode = upper->d_inode;

	return inode;
}

static inline struct dentry *d_backing_dentry(struct dentry *upper)
{
	return upper;
}

static inline struct dentry *d_real(struct dentry *dentry)
{
	if (unlikely(dentry->d_flags & DCACHE_OP_REAL))
		return dentry->d_op->d_real(dentry, NULL);
	else
		return dentry;
}

static inline struct inode *vfs_select_inode(struct dentry *dentry,
					     unsigned open_flags)
{
	struct inode *inode = d_inode(dentry);

	if (inode && unlikely(dentry->d_flags & DCACHE_OP_SELECT_INODE))
		inode = dentry->d_op->d_select_inode(dentry, open_flags);

	return inode;
}

static inline struct inode *d_real_inode(struct dentry *dentry)
{
	return d_backing_inode(d_real(dentry));
}

struct name_snapshot {
	const char *name;
	char inline_name[DNAME_INLINE_LEN];
};
void take_dentry_name_snapshot(struct name_snapshot *, struct dentry *);
void release_dentry_name_snapshot(struct name_snapshot *);

#endif	 
