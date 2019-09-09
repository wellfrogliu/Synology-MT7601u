#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef _LINUX_HFSPLUS_FS_H
#define _LINUX_HFSPLUS_FS_H

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include "hfsplus_raw.h"

#define DBG_BNODE_REFS	0x00000001
#define DBG_BNODE_MOD	0x00000002
#define DBG_CAT_MOD	0x00000004
#define DBG_INODE	0x00000008
#define DBG_SUPER	0x00000010
#define DBG_EXTENT	0x00000020
#define DBG_BITMAP	0x00000040
#define DBG_ATTR_MOD	0x00000080
#define DBG_ACL_MOD	0x00000100

#if 0
#define DBG_MASK	(DBG_EXTENT|DBG_INODE|DBG_BNODE_MOD)
#define DBG_MASK	(DBG_BNODE_MOD|DBG_CAT_MOD|DBG_INODE)
#define DBG_MASK	(DBG_CAT_MOD|DBG_BNODE_REFS|DBG_INODE|DBG_EXTENT)
#endif
#define DBG_MASK	(0)

#define hfs_dbg(flg, fmt, ...)					\
do {								\
	if (DBG_##flg & DBG_MASK)				\
		printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__);	\
} while (0)

#define hfs_dbg_cont(flg, fmt, ...)				\
do {								\
	if (DBG_##flg & DBG_MASK)				\
		pr_cont(fmt, ##__VA_ARGS__);			\
} while (0)

#define HFSPLUS_DEF_CR_TYPE    0x3F3F3F3F   

#define HFSPLUS_TYPE_DATA 0x00
#define HFSPLUS_TYPE_RSRC 0xFF

typedef int (*btree_keycmp)(const hfsplus_btree_key *,
		const hfsplus_btree_key *);

#define NODE_HASH_SIZE	256

enum hfsplus_btree_mutex_classes {
	CATALOG_BTREE_MUTEX,
	EXTENTS_BTREE_MUTEX,
	ATTR_BTREE_MUTEX,
};

struct hfs_btree {
	struct super_block *sb;
	struct inode *inode;
	btree_keycmp keycmp;

	u32 cnid;
	u32 root;
	u32 leaf_count;
	u32 leaf_head;
	u32 leaf_tail;
	u32 node_count;
	u32 free_nodes;
	u32 attributes;

	unsigned int node_size;
	unsigned int node_size_shift;
	unsigned int max_key_len;
	unsigned int depth;

	struct mutex tree_lock;

	unsigned int pages_per_bnode;
	spinlock_t hash_lock;
	struct hfs_bnode *node_hash[NODE_HASH_SIZE];
	int node_hash_cnt;
};

struct page;

struct hfs_bnode {
	struct hfs_btree *tree;

	u32 prev;
	u32 this;
	u32 next;
	u32 parent;

	u16 num_recs;
	u8 type;
	u8 height;

	struct hfs_bnode *next_hash;
	unsigned long flags;
	wait_queue_head_t lock_wq;
	atomic_t refcnt;
	unsigned int page_offset;
	struct page *page[0];
};

#define HFS_BNODE_LOCK		0
#define HFS_BNODE_ERROR		1
#define HFS_BNODE_NEW		2
#define HFS_BNODE_DIRTY		3
#define HFS_BNODE_DELETED	4

#define HFSPLUS_EMPTY_ATTR_TREE		0
#define HFSPLUS_CREATING_ATTR_TREE	1
#define HFSPLUS_VALID_ATTR_TREE		2
#define HFSPLUS_FAILED_ATTR_TREE	3

struct hfsplus_vh;
struct hfs_btree;

struct hfsplus_sb_info {
	void *s_vhdr_buf;
	struct hfsplus_vh *s_vhdr;
	void *s_backup_vhdr_buf;
	struct hfsplus_vh *s_backup_vhdr;
	struct hfs_btree *ext_tree;
	struct hfs_btree *cat_tree;
	struct hfs_btree *attr_tree;
	atomic_t attr_tree_state;
	struct inode *alloc_file;
	struct inode *hidden_dir;
	struct nls_table *nls;

	u32 blockoffset;
	sector_t part_start;
	sector_t sect_count;
	int fs_shift;

	u32 alloc_blksz;
	int alloc_blksz_shift;
	u32 total_blocks;
	u32 data_clump_blocks, rsrc_clump_blocks;

	u32 free_blocks;
	struct mutex alloc_mutex;

	u32 next_cnid;
	u32 file_count;
	u32 folder_count;
	struct mutex vh_mutex;

	u32 creator;
	u32 type;

	umode_t umask;
	kuid_t uid;
	kgid_t gid;

	int part, session;
	unsigned long flags;

	int work_queued;                
	struct delayed_work sync_work;  
	spinlock_t work_lock;           
};

#define HFSPLUS_SB_WRITEBACKUP	0
#define HFSPLUS_SB_NODECOMPOSE	1
#define HFSPLUS_SB_FORCE	2
#define HFSPLUS_SB_HFSX		3
#define HFSPLUS_SB_CASEFOLD	4
#define HFSPLUS_SB_NOBARRIER	5

static inline struct hfsplus_sb_info *HFSPLUS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

struct hfsplus_inode_info {
	atomic_t opencnt;

	u32 first_blocks;
	u32 clump_blocks;
	u32 alloc_blocks;
	u32 cached_start;
	u32 cached_blocks;
	hfsplus_extent_rec first_extents;
	hfsplus_extent_rec cached_extents;
	unsigned int extent_state;
	struct mutex extents_lock;

	struct inode *rsrc_inode;
	__be32 create_date;

	u32 linkid;

	unsigned long flags;

	sector_t fs_blocks;
	u8 userflags;		 
	u32 subfolders;		 
	struct list_head open_dir_list;
	loff_t phys_size;

	struct inode vfs_inode;
};

#define HFSPLUS_EXT_DIRTY	0x0001
#define HFSPLUS_EXT_NEW		0x0002

#define HFSPLUS_I_RSRC		0	 
#define HFSPLUS_I_CAT_DIRTY	1	 
#define HFSPLUS_I_EXT_DIRTY	2	 
#define HFSPLUS_I_ALLOC_DIRTY	3	 
#define HFSPLUS_I_ATTR_DIRTY	4	 

#define HFSPLUS_IS_RSRC(inode) \
	test_bit(HFSPLUS_I_RSRC, &HFSPLUS_I(inode)->flags)

static inline struct hfsplus_inode_info *HFSPLUS_I(struct inode *inode)
{
	return container_of(inode, struct hfsplus_inode_info, vfs_inode);
}

static inline void hfsplus_mark_inode_dirty(struct inode *inode,
		unsigned int flag)
{
	set_bit(flag, &HFSPLUS_I(inode)->flags);
	mark_inode_dirty(inode);
}

struct hfs_find_data {
	 
	hfsplus_btree_key *search_key;
	hfsplus_btree_key *key;
	 
	struct hfs_btree *tree;
	struct hfs_bnode *bnode;
	 
	int record;
	int keyoffset, keylength;
	int entryoffset, entrylength;
};

struct hfsplus_readdir_data {
	struct list_head list;
	struct file *file;
	struct hfsplus_cat_key key;
};

static inline unsigned short hfsplus_min_io_size(struct super_block *sb)
{
	return max_t(unsigned short, bdev_logical_block_size(sb->s_bdev),
		     HFSPLUS_SECTOR_SIZE);
}

#define hfs_btree_open hfsplus_btree_open
#define hfs_btree_close hfsplus_btree_close
#define hfs_btree_write hfsplus_btree_write
#define hfs_bmap_alloc hfsplus_bmap_alloc
#define hfs_bmap_free hfsplus_bmap_free
#define hfs_bnode_read hfsplus_bnode_read
#ifdef MY_ABC_HERE
#define hfs_bnode_read_u32 hfsplus_bnode_read_u32
#endif  
#define hfs_bnode_read_u16 hfsplus_bnode_read_u16
#define hfs_bnode_read_u8 hfsplus_bnode_read_u8
#define hfs_bnode_read_key hfsplus_bnode_read_key
#define hfs_bnode_write hfsplus_bnode_write
#define hfs_bnode_write_u16 hfsplus_bnode_write_u16
#define hfs_bnode_clear hfsplus_bnode_clear
#define hfs_bnode_copy hfsplus_bnode_copy
#define hfs_bnode_move hfsplus_bnode_move
#define hfs_bnode_dump hfsplus_bnode_dump
#define hfs_bnode_unlink hfsplus_bnode_unlink
#define hfs_bnode_findhash hfsplus_bnode_findhash
#define hfs_bnode_find hfsplus_bnode_find
#define hfs_bnode_unhash hfsplus_bnode_unhash
#define hfs_bnode_free hfsplus_bnode_free
#define hfs_bnode_create hfsplus_bnode_create
#define hfs_bnode_get hfsplus_bnode_get
#define hfs_bnode_put hfsplus_bnode_put
#define hfs_brec_lenoff hfsplus_brec_lenoff
#define hfs_brec_keylen hfsplus_brec_keylen
#define hfs_brec_insert hfsplus_brec_insert
#define hfs_brec_remove hfsplus_brec_remove
#define hfs_find_init hfsplus_find_init
#define hfs_find_exit hfsplus_find_exit
#define __hfs_brec_find __hfsplus_brec_find
#define hfs_brec_find hfsplus_brec_find
#define hfs_brec_read hfsplus_brec_read
#define hfs_brec_goto hfsplus_brec_goto
#define hfs_part_find hfsplus_part_find

#define HFSPLUS_IOC_EXT2_GETFLAGS	FS_IOC_GETFLAGS
#define HFSPLUS_IOC_EXT2_SETFLAGS	FS_IOC_SETFLAGS

#define HFSPLUS_IOC_BLESS _IO('h', 0x80)

typedef int (*search_strategy_t)(struct hfs_bnode *,
				struct hfs_find_data *,
				int *, int *, int *);

#ifdef MY_ABC_HERE
int hfsplus_create_attr_tree_cache(void);
#else
int __init hfsplus_create_attr_tree_cache(void);
#endif  
void hfsplus_destroy_attr_tree_cache(void);
#ifdef MY_ABC_HERE
int hfsplus_recreate_attr_tree_cache(size_t);
size_t hfsplus_get_attr_tree_cache_size(void);
#endif  
int hfsplus_attr_bin_cmp_key(const hfsplus_btree_key *k1,
			     const hfsplus_btree_key *k2);
int hfsplus_attr_build_key(struct super_block *sb, hfsplus_btree_key *key,
			   u32 cnid, const char *name);
hfsplus_attr_entry *hfsplus_alloc_attr_entry(void);
void hfsplus_destroy_attr_entry(hfsplus_attr_entry *entry);
int hfsplus_find_attr(struct super_block *sb, u32 cnid, const char *name,
		      struct hfs_find_data *fd);
int hfsplus_attr_exists(struct inode *inode, const char *name);
int hfsplus_create_attr(struct inode *inode, const char *name,
			const void *value, size_t size);
int hfsplus_delete_attr(struct inode *inode, const char *name);
int hfsplus_delete_all_attrs(struct inode *dir, u32 cnid);

int hfsplus_block_allocate(struct super_block *sb, u32 size, u32 offset,
			   u32 *max);
int hfsplus_block_free(struct super_block *sb, u32 offset, u32 count);

u32 hfsplus_calc_btree_clump_size(u32 block_size, u32 node_size, u64 sectors,
				  int file_id);
struct hfs_btree *hfs_btree_open(struct super_block *sb, u32 id);
void hfs_btree_close(struct hfs_btree *tree);
int hfs_btree_write(struct hfs_btree *tree);
struct hfs_bnode *hfs_bmap_alloc(struct hfs_btree *tree);
void hfs_bmap_free(struct hfs_bnode *node);

void hfs_bnode_read(struct hfs_bnode *node, void *buf, int off, int len);
#ifdef MY_ABC_HERE
u32 hfs_bnode_read_u32(struct hfs_bnode *, int);
#endif  
u16 hfs_bnode_read_u16(struct hfs_bnode *node, int off);
u8 hfs_bnode_read_u8(struct hfs_bnode *node, int off);
void hfs_bnode_read_key(struct hfs_bnode *node, void *key, int off);
void hfs_bnode_write(struct hfs_bnode *node, void *buf, int off, int len);
void hfs_bnode_write_u16(struct hfs_bnode *node, int off, u16 data);
void hfs_bnode_clear(struct hfs_bnode *node, int off, int len);
void hfs_bnode_copy(struct hfs_bnode *dst_node, int dst,
		    struct hfs_bnode *src_node, int src, int len);
void hfs_bnode_move(struct hfs_bnode *node, int dst, int src, int len);
void hfs_bnode_dump(struct hfs_bnode *node);
void hfs_bnode_unlink(struct hfs_bnode *node);
struct hfs_bnode *hfs_bnode_findhash(struct hfs_btree *tree, u32 cnid);
void hfs_bnode_unhash(struct hfs_bnode *node);
struct hfs_bnode *hfs_bnode_find(struct hfs_btree *tree, u32 num);
void hfs_bnode_free(struct hfs_bnode *node);
struct hfs_bnode *hfs_bnode_create(struct hfs_btree *tree, u32 num);
void hfs_bnode_get(struct hfs_bnode *node);
void hfs_bnode_put(struct hfs_bnode *node);
bool hfs_bnode_need_zeroout(struct hfs_btree *tree);

u16 hfs_brec_lenoff(struct hfs_bnode *node, u16 rec, u16 *off);
u16 hfs_brec_keylen(struct hfs_bnode *node, u16 rec);
int hfs_brec_insert(struct hfs_find_data *fd, void *entry, int entry_len);
int hfs_brec_remove(struct hfs_find_data *fd);

int hfs_find_init(struct hfs_btree *tree, struct hfs_find_data *fd);
void hfs_find_exit(struct hfs_find_data *fd);
int hfs_find_1st_rec_by_cnid(struct hfs_bnode *bnode, struct hfs_find_data *fd,
			     int *begin, int *end, int *cur_rec);
int hfs_find_rec_by_key(struct hfs_bnode *bnode, struct hfs_find_data *fd,
			int *begin, int *end, int *cur_rec);
int __hfs_brec_find(struct hfs_bnode *bnode, struct hfs_find_data *fd,
		    search_strategy_t rec_found);
int hfs_brec_find(struct hfs_find_data *fd, search_strategy_t do_key_compare);
int hfs_brec_read(struct hfs_find_data *fd, void *rec, int rec_len);
int hfs_brec_goto(struct hfs_find_data *fd, int cnt);

int hfsplus_cat_case_cmp_key(const hfsplus_btree_key *k1,
			     const hfsplus_btree_key *k2);
int hfsplus_cat_bin_cmp_key(const hfsplus_btree_key *k1,
			    const hfsplus_btree_key *k2);
int hfsplus_cat_build_key(struct super_block *sb, hfsplus_btree_key *key,
			   u32 parent, struct qstr *str);
void hfsplus_cat_build_key_with_cnid(struct super_block *sb,
				     hfsplus_btree_key *key, u32 parent);
void hfsplus_cat_set_perms(struct inode *inode, struct hfsplus_perm *perms);
int hfsplus_find_cat(struct super_block *sb, u32 cnid,
		     struct hfs_find_data *fd);
int hfsplus_create_cat(u32 cnid, struct inode *dir, struct qstr *str,
		       struct inode *inode);
int hfsplus_delete_cat(u32 cnid, struct inode *dir, struct qstr *str);
int hfsplus_rename_cat(u32 cnid, struct inode *src_dir, struct qstr *src_name,
		       struct inode *dst_dir, struct qstr *dst_name);

extern const struct inode_operations hfsplus_dir_inode_operations;
extern const struct file_operations hfsplus_dir_operations;

int hfsplus_ext_cmp_key(const hfsplus_btree_key *k1,
			const hfsplus_btree_key *k2);
int hfsplus_ext_write_extent(struct inode *inode);
int hfsplus_get_block(struct inode *inode, sector_t iblock,
		      struct buffer_head *bh_result, int create);
int hfsplus_free_fork(struct super_block *sb, u32 cnid,
		      struct hfsplus_fork_raw *fork, int type);
int hfsplus_file_extend(struct inode *inode, bool zeroout);
void hfsplus_file_truncate(struct inode *inode);

extern const struct address_space_operations hfsplus_aops;
extern const struct address_space_operations hfsplus_btree_aops;
extern const struct dentry_operations hfsplus_dentry_operations;

struct inode *hfsplus_new_inode(struct super_block *sb, umode_t mode);
void hfsplus_delete_inode(struct inode *inode);
void hfsplus_inode_read_fork(struct inode *inode,
			     struct hfsplus_fork_raw *fork);
void hfsplus_inode_write_fork(struct inode *inode,
			      struct hfsplus_fork_raw *fork);
int hfsplus_cat_read_inode(struct inode *inode, struct hfs_find_data *fd);
int hfsplus_cat_write_inode(struct inode *inode);
int hfsplus_file_fsync(struct file *file, loff_t start, loff_t end,
		       int datasync);

long hfsplus_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);

void hfsplus_fill_defaults(struct hfsplus_sb_info *opts);
int hfsplus_parse_options_remount(char *input, int *force);
int hfsplus_parse_options(char *input, struct hfsplus_sb_info *sbi);
int hfsplus_show_options(struct seq_file *seq, struct dentry *root);

int hfs_part_find(struct super_block *sb, sector_t *part_start,
		  sector_t *part_size);

struct inode *hfsplus_iget(struct super_block *sb, unsigned long ino);
void hfsplus_mark_mdb_dirty(struct super_block *sb);

extern u16 hfsplus_case_fold_table[];
extern u16 hfsplus_decompose_table[];
extern u16 hfsplus_compose_table[];

int hfsplus_strcasecmp(const struct hfsplus_unistr *s1,
		       const struct hfsplus_unistr *s2);
int hfsplus_strcmp(const struct hfsplus_unistr *s1,
		   const struct hfsplus_unistr *s2);
int hfsplus_uni2asc(struct super_block *sb, const struct hfsplus_unistr *ustr,
		    char *astr, int *len_p);
int hfsplus_asc2uni(struct super_block *sb, struct hfsplus_unistr *ustr,
		    int max_unistr_len, const char *astr, int len);
#ifdef MY_ABC_HERE
int hfsplus_attr_uni2asc(struct super_block *,
		const struct hfsplus_unistr *, char *, int *);
int hfsplus_attr_asc2uni(struct super_block *,
		struct hfsplus_unistr *, int, const char *, int);
#endif  
int hfsplus_hash_dentry(const struct dentry *dentry, struct qstr *str);
int hfsplus_compare_dentry(const struct dentry *parent,
			   const struct dentry *dentry, unsigned int len,
			   const char *str, const struct qstr *name);

int hfsplus_submit_bio(struct super_block *sb, sector_t sector, void *buf,
		       void **data, int rw);
int hfsplus_read_wrapper(struct super_block *sb);

#define __hfsp_mt2ut(t)		(be32_to_cpu(t) - 2082844800U)
#define __hfsp_ut2mt(t)		(cpu_to_be32(t + 2082844800U))

#define hfsp_mt2ut(t)		(struct timespec){ .tv_sec = __hfsp_mt2ut(t) }
#define hfsp_ut2mt(t)		__hfsp_ut2mt((t).tv_sec)
#define hfsp_now2mt()		__hfsp_ut2mt(get_seconds())

#endif
