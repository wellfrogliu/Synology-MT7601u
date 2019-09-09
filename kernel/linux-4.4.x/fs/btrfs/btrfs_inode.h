#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef __BTRFS_I__
#define __BTRFS_I__

#include <linux/hash.h>
#include "extent_map.h"
#include "extent_io.h"
#include "ordered-data.h"
#include "delayed-inode.h"

#define BTRFS_INODE_ORDERED_DATA_CLOSE		0
#define BTRFS_INODE_ORPHAN_META_RESERVED	1
#define BTRFS_INODE_DUMMY			2
#define BTRFS_INODE_IN_DEFRAG			3
#define BTRFS_INODE_DELALLOC_META_RESERVED	4
#define BTRFS_INODE_HAS_ORPHAN_ITEM		5
#define BTRFS_INODE_HAS_ASYNC_EXTENT		6
#define BTRFS_INODE_NEEDS_FULL_SYNC		7
#define BTRFS_INODE_COPY_EVERYTHING		8
#define BTRFS_INODE_IN_DELALLOC_LIST		9
#define BTRFS_INODE_READDIO_NEED_LOCK		10
#define BTRFS_INODE_HAS_PROPS		        11
 
#define BTRFS_INODE_BTREE_ERR		        12
#define BTRFS_INODE_BTREE_LOG1_ERR		13
#define BTRFS_INODE_BTREE_LOG2_ERR		14

struct btrfs_inode {
	 
	struct btrfs_root *root;

	struct btrfs_key location;

	spinlock_t lock;

	struct extent_map_tree extent_tree;

	struct extent_io_tree io_tree;

	struct extent_io_tree io_failure_tree;

	struct mutex log_mutex;

	struct mutex delalloc_mutex;

	struct btrfs_ordered_inode_tree ordered_tree;

	struct list_head delalloc_inodes;

	struct rb_node rb_node;

	unsigned long runtime_flags;

	atomic_t sync_writers;

	u64 generation;

	u64 last_trans;

	u64 logged_trans;

	int last_sub_trans;

	int last_log_commit;

	u64 delalloc_bytes;

	u64 defrag_bytes;

	u64 disk_i_size;

	u64 index_cnt;

	u64 dir_index;

	u64 last_unlink_trans;

	u64 csum_bytes;

	u32 flags;

	unsigned outstanding_extents;
	unsigned reserved_extents;

	unsigned force_compress;

	struct btrfs_delayed_node *delayed_node;

	struct timespec i_otime;

	struct list_head delayed_iput;
	long delayed_iput_count;

	struct rw_semaphore dio_sem;

	struct inode vfs_inode;

#ifdef MY_ABC_HERE
	struct list_head free_extent_map_inode;
	atomic_t free_extent_map_counts;
#endif  

};

extern unsigned char btrfs_filetype_table[];

static inline struct btrfs_inode *BTRFS_I(struct inode *inode)
{
	return container_of(inode, struct btrfs_inode, vfs_inode);
}

static inline unsigned long btrfs_inode_hash(u64 objectid,
					     const struct btrfs_root *root)
{
	u64 h = objectid ^ (root->objectid * GOLDEN_RATIO_PRIME);

#if BITS_PER_LONG == 32
	h = (h >> 32) ^ (h & 0xffffffff);
#endif

	return (unsigned long)h;
}

static inline void btrfs_insert_inode_hash(struct inode *inode)
{
	unsigned long h = btrfs_inode_hash(inode->i_ino, BTRFS_I(inode)->root);

	__insert_inode_hash(inode, h);
}

static inline u64 btrfs_ino(struct inode *inode)
{
	u64 ino = BTRFS_I(inode)->location.objectid;

	if (!ino || BTRFS_I(inode)->location.type == BTRFS_ROOT_ITEM_KEY)
		ino = inode->i_ino;
	return ino;
}

static inline void btrfs_i_size_write(struct inode *inode, u64 size)
{
	i_size_write(inode, size);
	BTRFS_I(inode)->disk_i_size = size;
}

static inline bool btrfs_is_free_space_inode(struct inode *inode)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;

	if (root == root->fs_info->tree_root &&
	    btrfs_ino(inode) != BTRFS_BTREE_INODE_OBJECTID)
		return true;
	if (BTRFS_I(inode)->location.objectid == BTRFS_FREE_INO_OBJECTID)
		return true;
	return false;
}

static inline int btrfs_inode_in_log(struct inode *inode, u64 generation)
{
	int ret = 0;

	spin_lock(&BTRFS_I(inode)->lock);
	if (BTRFS_I(inode)->logged_trans == generation &&
	    BTRFS_I(inode)->last_sub_trans <=
	    BTRFS_I(inode)->last_log_commit &&
	    BTRFS_I(inode)->last_sub_trans <=
	    BTRFS_I(inode)->root->last_log_commit) {
		 
		smp_mb();
		if (list_empty(&BTRFS_I(inode)->extent_tree.modified_extents))
			ret = 1;
	}
	spin_unlock(&BTRFS_I(inode)->lock);
	return ret;
}

#define BTRFS_DIO_ORIG_BIO_SUBMITTED	0x1

struct btrfs_dio_private {
	struct inode *inode;
	unsigned long flags;
	u64 logical_offset;
	u64 disk_bytenr;
	u64 bytes;
	void *private;

	atomic_t pending_bios;

	int errors;

	struct bio *orig_bio;

	struct bio *dio_bio;

	int (*subio_endio)(struct inode *, struct btrfs_io_bio *, int);
};

static inline void btrfs_inode_block_unlocked_dio(struct inode *inode)
{
	set_bit(BTRFS_INODE_READDIO_NEED_LOCK, &BTRFS_I(inode)->runtime_flags);
	smp_mb();
}

static inline void btrfs_inode_resume_unlocked_dio(struct inode *inode)
{
	smp_mb__before_atomic();
	clear_bit(BTRFS_INODE_READDIO_NEED_LOCK,
		  &BTRFS_I(inode)->runtime_flags);
}

bool btrfs_page_exists_in_range(struct inode *inode, loff_t start, loff_t end);

#endif
