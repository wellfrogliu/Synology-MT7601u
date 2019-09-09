#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef _EXT4_H
#define _EXT4_H

#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/magic.h>
#include <linux/jbd2.h>
#include <linux/quota.h>
#include <linux/rwsem.h>
#include <linux/rbtree.h>
#include <linux/seqlock.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/version.h>
#include <linux/wait.h>
#include <linux/blockgroup_lock.h>
#include <linux/percpu_counter.h>
#include <linux/ratelimit.h>
#include <crypto/hash.h>
#include <linux/falloc.h>
#ifdef __KERNEL__
#include <linux/compat.h>
#endif

#undef EXT4FS_DEBUG

#ifdef EXT4FS_DEBUG
#define ext4_debug(f, a...)						\
	do {								\
		printk(KERN_DEBUG "EXT4-fs DEBUG (%s, %d): %s:",	\
			__FILE__, __LINE__, __func__);			\
		printk(KERN_DEBUG f, ## a);				\
	} while (0)
#else
#define ext4_debug(fmt, ...)	no_printk(fmt, ##__VA_ARGS__)
#endif

#define EXT_DEBUG__
#ifdef EXT_DEBUG
#define ext_debug(fmt, ...)	printk(fmt, ##__VA_ARGS__)
#else
#define ext_debug(fmt, ...)	no_printk(fmt, ##__VA_ARGS__)
#endif

typedef int ext4_grpblk_t;

typedef unsigned long long ext4_fsblk_t;

typedef __u32 ext4_lblk_t;

typedef unsigned int ext4_group_t;

enum SHIFT_DIRECTION {
	SHIFT_LEFT = 0,
	SHIFT_RIGHT,
};

#define EXT4_MB_HINT_MERGE		0x0001
 
#define EXT4_MB_HINT_RESERVED		0x0002
 
#define EXT4_MB_HINT_METADATA		0x0004
 
#define EXT4_MB_HINT_FIRST		0x0008
 
#define EXT4_MB_HINT_BEST		0x0010
 
#define EXT4_MB_HINT_DATA		0x0020
 
#define EXT4_MB_HINT_NOPREALLOC		0x0040
 
#define EXT4_MB_HINT_GROUP_ALLOC	0x0080
 
#define EXT4_MB_HINT_GOAL_ONLY		0x0100
 
#define EXT4_MB_HINT_TRY_GOAL		0x0200
 
#define EXT4_MB_DELALLOC_RESERVED	0x0400
 
#define EXT4_MB_STREAM_ALLOC		0x0800
 
#define EXT4_MB_USE_ROOT_BLOCKS		0x1000
 
#define EXT4_MB_USE_RESERVED		0x2000

struct ext4_allocation_request {
	 
	struct inode *inode;
	 
	unsigned int len;
	 
	ext4_lblk_t logical;
	 
	ext4_lblk_t lleft;
	 
	ext4_lblk_t lright;
	 
	ext4_fsblk_t goal;
	 
	ext4_fsblk_t pleft;
	 
	ext4_fsblk_t pright;
	 
	unsigned int flags;
};

#define EXT4_MAP_NEW		(1 << BH_New)
#define EXT4_MAP_MAPPED		(1 << BH_Mapped)
#define EXT4_MAP_UNWRITTEN	(1 << BH_Unwritten)
#define EXT4_MAP_BOUNDARY	(1 << BH_Boundary)
#define EXT4_MAP_FLAGS		(EXT4_MAP_NEW | EXT4_MAP_MAPPED |\
				 EXT4_MAP_UNWRITTEN | EXT4_MAP_BOUNDARY)

struct ext4_map_blocks {
	ext4_fsblk_t m_pblk;
	ext4_lblk_t m_lblk;
	unsigned int m_len;
	unsigned int m_flags;
};

#define	EXT4_IO_END_UNWRITTEN	0x0001

typedef struct ext4_io_end {
	struct list_head	list;		 
	handle_t		*handle;	 
	struct inode		*inode;		 
	struct bio		*bio;		 
	unsigned int		flag;		 
	loff_t			offset;		 
	ssize_t			size;		 
	atomic_t		count;		 
} ext4_io_end_t;

struct ext4_io_submit {
	struct writeback_control *io_wbc;
	struct bio		*io_bio;
	ext4_io_end_t		*io_end;
	sector_t		io_next_block;
};

#define	EXT4_BAD_INO		 1	 
#define EXT4_ROOT_INO		 2	 
#define EXT4_USR_QUOTA_INO	 3	 
#define EXT4_GRP_QUOTA_INO	 4	 
#define EXT4_BOOT_LOADER_INO	 5	 
#define EXT4_UNDEL_DIR_INO	 6	 
#define EXT4_RESIZE_INO		 7	 
#define EXT4_JOURNAL_INO	 8	 

#define EXT4_GOOD_OLD_FIRST_INO	11

#define EXT4_LINK_MAX		65000

#define EXT4_MIN_BLOCK_SIZE		1024
#define	EXT4_MAX_BLOCK_SIZE		65536
#define EXT4_MIN_BLOCK_LOG_SIZE		10
#define EXT4_MAX_BLOCK_LOG_SIZE		16
#define EXT4_MAX_CLUSTER_LOG_SIZE	30
#ifdef __KERNEL__
# define EXT4_BLOCK_SIZE(s)		((s)->s_blocksize)
#else
# define EXT4_BLOCK_SIZE(s)		(EXT4_MIN_BLOCK_SIZE << (s)->s_log_block_size)
#endif
#define	EXT4_ADDR_PER_BLOCK(s)		(EXT4_BLOCK_SIZE(s) / sizeof(__u32))
#define EXT4_CLUSTER_SIZE(s)		(EXT4_BLOCK_SIZE(s) << \
					 EXT4_SB(s)->s_cluster_bits)
#ifdef __KERNEL__
# define EXT4_BLOCK_SIZE_BITS(s)	((s)->s_blocksize_bits)
# define EXT4_CLUSTER_BITS(s)		(EXT4_SB(s)->s_cluster_bits)
#else
# define EXT4_BLOCK_SIZE_BITS(s)	((s)->s_log_block_size + 10)
#endif
#ifdef __KERNEL__
#define	EXT4_ADDR_PER_BLOCK_BITS(s)	(EXT4_SB(s)->s_addr_per_block_bits)
#define EXT4_INODE_SIZE(s)		(EXT4_SB(s)->s_inode_size)
#define EXT4_FIRST_INO(s)		(EXT4_SB(s)->s_first_ino)
#else
#define EXT4_INODE_SIZE(s)	(((s)->s_rev_level == EXT4_GOOD_OLD_REV) ? \
				 EXT4_GOOD_OLD_INODE_SIZE : \
				 (s)->s_inode_size)
#define EXT4_FIRST_INO(s)	(((s)->s_rev_level == EXT4_GOOD_OLD_REV) ? \
				 EXT4_GOOD_OLD_FIRST_INO : \
				 (s)->s_first_ino)
#endif
#define EXT4_BLOCK_ALIGN(size, blkbits)		ALIGN((size), (1 << (blkbits)))

#define EXT4_B2C(sbi, blk)	((blk) >> (sbi)->s_cluster_bits)
 
#define EXT4_C2B(sbi, cluster)	((cluster) << (sbi)->s_cluster_bits)
 
#define EXT4_NUM_B2C(sbi, blks)	(((blks) + (sbi)->s_cluster_ratio - 1) >> \
				 (sbi)->s_cluster_bits)
 
#define EXT4_PBLK_CMASK(s, pblk) ((pblk) &				\
				  ~((ext4_fsblk_t) (s)->s_cluster_ratio - 1))
#define EXT4_LBLK_CMASK(s, lblk) ((lblk) &				\
				  ~((ext4_lblk_t) (s)->s_cluster_ratio - 1))
 
#define EXT4_PBLK_COFF(s, pblk) ((pblk) &				\
				 ((ext4_fsblk_t) (s)->s_cluster_ratio - 1))
#define EXT4_LBLK_COFF(s, lblk) ((lblk) &				\
				 ((ext4_lblk_t) (s)->s_cluster_ratio - 1))

struct ext4_group_desc
{
	__le32	bg_block_bitmap_lo;	 
	__le32	bg_inode_bitmap_lo;	 
	__le32	bg_inode_table_lo;	 
	__le16	bg_free_blocks_count_lo; 
	__le16	bg_free_inodes_count_lo; 
	__le16	bg_used_dirs_count_lo;	 
	__le16	bg_flags;		 
	__le32  bg_exclude_bitmap_lo;    
	__le16  bg_block_bitmap_csum_lo; 
	__le16  bg_inode_bitmap_csum_lo; 
	__le16  bg_itable_unused_lo;	 
	__le16  bg_checksum;		 
	__le32	bg_block_bitmap_hi;	 
	__le32	bg_inode_bitmap_hi;	 
	__le32	bg_inode_table_hi;	 
	__le16	bg_free_blocks_count_hi; 
	__le16	bg_free_inodes_count_hi; 
	__le16	bg_used_dirs_count_hi;	 
	__le16  bg_itable_unused_hi;     
	__le32  bg_exclude_bitmap_hi;    
	__le16  bg_block_bitmap_csum_hi; 
	__le16  bg_inode_bitmap_csum_hi; 
	__u32   bg_reserved;
};

#define EXT4_BG_INODE_BITMAP_CSUM_HI_END	\
	(offsetof(struct ext4_group_desc, bg_inode_bitmap_csum_hi) + \
	 sizeof(__le16))
#define EXT4_BG_BLOCK_BITMAP_CSUM_HI_END	\
	(offsetof(struct ext4_group_desc, bg_block_bitmap_csum_hi) + \
	 sizeof(__le16))

struct flex_groups {
	atomic64_t	free_clusters;
	atomic_t	free_inodes;
	atomic_t	used_dirs;
};

#define EXT4_BG_INODE_UNINIT	0x0001  
#define EXT4_BG_BLOCK_UNINIT	0x0002  
#define EXT4_BG_INODE_ZEROED	0x0004  

#define EXT4_MIN_DESC_SIZE		32
#define EXT4_MIN_DESC_SIZE_64BIT	64
#define	EXT4_MAX_DESC_SIZE		EXT4_MIN_BLOCK_SIZE
#define EXT4_DESC_SIZE(s)		(EXT4_SB(s)->s_desc_size)
#ifdef __KERNEL__
# define EXT4_BLOCKS_PER_GROUP(s)	(EXT4_SB(s)->s_blocks_per_group)
# define EXT4_CLUSTERS_PER_GROUP(s)	(EXT4_SB(s)->s_clusters_per_group)
# define EXT4_DESC_PER_BLOCK(s)		(EXT4_SB(s)->s_desc_per_block)
# define EXT4_INODES_PER_GROUP(s)	(EXT4_SB(s)->s_inodes_per_group)
# define EXT4_DESC_PER_BLOCK_BITS(s)	(EXT4_SB(s)->s_desc_per_block_bits)
#else
# define EXT4_BLOCKS_PER_GROUP(s)	((s)->s_blocks_per_group)
# define EXT4_DESC_PER_BLOCK(s)		(EXT4_BLOCK_SIZE(s) / EXT4_DESC_SIZE(s))
# define EXT4_INODES_PER_GROUP(s)	((s)->s_inodes_per_group)
#endif

#define	EXT4_NDIR_BLOCKS		12
#define	EXT4_IND_BLOCK			EXT4_NDIR_BLOCKS
#define	EXT4_DIND_BLOCK			(EXT4_IND_BLOCK + 1)
#define	EXT4_TIND_BLOCK			(EXT4_DIND_BLOCK + 1)
#define	EXT4_N_BLOCKS			(EXT4_TIND_BLOCK + 1)

#define	EXT4_SECRM_FL			0x00000001  
#define	EXT4_UNRM_FL			0x00000002  
#define	EXT4_COMPR_FL			0x00000004  
#define EXT4_SYNC_FL			0x00000008  
#define EXT4_IMMUTABLE_FL		0x00000010  
#define EXT4_APPEND_FL			0x00000020  
#define EXT4_NODUMP_FL			0x00000040  
#define EXT4_NOATIME_FL			0x00000080  
 
#define EXT4_DIRTY_FL			0x00000100
#define EXT4_COMPRBLK_FL		0x00000200  
#define EXT4_NOCOMPR_FL			0x00000400  
	 
#define EXT4_ENCRYPT_FL			0x00000800  
 
#define EXT4_INDEX_FL			0x00001000  
#define EXT4_IMAGIC_FL			0x00002000  
#define EXT4_JOURNAL_DATA_FL		0x00004000  
#define EXT4_NOTAIL_FL			0x00008000  
#define EXT4_DIRSYNC_FL			0x00010000  
#define EXT4_TOPDIR_FL			0x00020000  
#define EXT4_HUGE_FILE_FL               0x00040000  
#define EXT4_EXTENTS_FL			0x00080000  
#define EXT4_EA_INODE_FL	        0x00200000  
#define EXT4_EOFBLOCKS_FL		0x00400000  
#define EXT4_INLINE_DATA_FL		0x10000000  
#define EXT4_PROJINHERIT_FL		0x20000000  
#define EXT4_RESERVED_FL		0x80000000  

#define EXT4_FL_USER_VISIBLE		0x004BDFFF  
#define EXT4_FL_USER_MODIFIABLE		0x004380FF  

#define EXT4_FL_INHERITED (EXT4_SECRM_FL | EXT4_UNRM_FL | EXT4_COMPR_FL |\
			   EXT4_SYNC_FL | EXT4_NODUMP_FL | EXT4_NOATIME_FL |\
			   EXT4_NOCOMPR_FL | EXT4_JOURNAL_DATA_FL |\
			   EXT4_NOTAIL_FL | EXT4_DIRSYNC_FL)

#define EXT4_REG_FLMASK (~(EXT4_DIRSYNC_FL | EXT4_TOPDIR_FL))

#define EXT4_OTHER_FLMASK (EXT4_NODUMP_FL | EXT4_NOATIME_FL)

static inline __u32 ext4_mask_flags(umode_t mode, __u32 flags)
{
	if (S_ISDIR(mode))
		return flags;
	else if (S_ISREG(mode))
		return flags & EXT4_REG_FLMASK;
	else
		return flags & EXT4_OTHER_FLMASK;
}

enum {
	EXT4_INODE_SECRM	= 0,	 
	EXT4_INODE_UNRM		= 1,	 
	EXT4_INODE_COMPR	= 2,	 
	EXT4_INODE_SYNC		= 3,	 
	EXT4_INODE_IMMUTABLE	= 4,	 
	EXT4_INODE_APPEND	= 5,	 
	EXT4_INODE_NODUMP	= 6,	 
	EXT4_INODE_NOATIME	= 7,	 
 
	EXT4_INODE_DIRTY	= 8,
	EXT4_INODE_COMPRBLK	= 9,	 
	EXT4_INODE_NOCOMPR	= 10,	 
	EXT4_INODE_ENCRYPT	= 11,	 
 
	EXT4_INODE_INDEX	= 12,	 
	EXT4_INODE_IMAGIC	= 13,	 
	EXT4_INODE_JOURNAL_DATA	= 14,	 
	EXT4_INODE_NOTAIL	= 15,	 
	EXT4_INODE_DIRSYNC	= 16,	 
	EXT4_INODE_TOPDIR	= 17,	 
	EXT4_INODE_HUGE_FILE	= 18,	 
	EXT4_INODE_EXTENTS	= 19,	 
	EXT4_INODE_EA_INODE	= 21,	 
	EXT4_INODE_EOFBLOCKS	= 22,	 
	EXT4_INODE_INLINE_DATA	= 28,	 
	EXT4_INODE_PROJINHERIT	= 29,	 
	EXT4_INODE_RESERVED	= 31,	 
};

#define TEST_FLAG_VALUE(FLAG) (EXT4_##FLAG##_FL == (1 << EXT4_INODE_##FLAG))
#define CHECK_FLAG_VALUE(FLAG) BUILD_BUG_ON(!TEST_FLAG_VALUE(FLAG))

static inline void ext4_check_flag_values(void)
{
	CHECK_FLAG_VALUE(SECRM);
	CHECK_FLAG_VALUE(UNRM);
	CHECK_FLAG_VALUE(COMPR);
	CHECK_FLAG_VALUE(SYNC);
	CHECK_FLAG_VALUE(IMMUTABLE);
	CHECK_FLAG_VALUE(APPEND);
	CHECK_FLAG_VALUE(NODUMP);
	CHECK_FLAG_VALUE(NOATIME);
	CHECK_FLAG_VALUE(DIRTY);
	CHECK_FLAG_VALUE(COMPRBLK);
	CHECK_FLAG_VALUE(NOCOMPR);
	CHECK_FLAG_VALUE(ENCRYPT);
	CHECK_FLAG_VALUE(INDEX);
	CHECK_FLAG_VALUE(IMAGIC);
	CHECK_FLAG_VALUE(JOURNAL_DATA);
	CHECK_FLAG_VALUE(NOTAIL);
	CHECK_FLAG_VALUE(DIRSYNC);
	CHECK_FLAG_VALUE(TOPDIR);
	CHECK_FLAG_VALUE(HUGE_FILE);
	CHECK_FLAG_VALUE(EXTENTS);
	CHECK_FLAG_VALUE(EA_INODE);
	CHECK_FLAG_VALUE(EOFBLOCKS);
	CHECK_FLAG_VALUE(INLINE_DATA);
	CHECK_FLAG_VALUE(PROJINHERIT);
	CHECK_FLAG_VALUE(RESERVED);
}

struct ext4_new_group_input {
	__u32 group;		 
	__u64 block_bitmap;	 
	__u64 inode_bitmap;	 
	__u64 inode_table;	 
	__u32 blocks_count;	 
	__u16 reserved_blocks;	 
	__u16 unused;
};

#if defined(__KERNEL__) && defined(CONFIG_COMPAT)
struct compat_ext4_new_group_input {
	u32 group;
	compat_u64 block_bitmap;
	compat_u64 inode_bitmap;
	compat_u64 inode_table;
	u32 blocks_count;
	u16 reserved_blocks;
	u16 unused;
};
#endif

struct ext4_new_group_data {
	__u32 group;
	__u64 block_bitmap;
	__u64 inode_bitmap;
	__u64 inode_table;
	__u32 blocks_count;
	__u16 reserved_blocks;
	__u16 unused;
	__u32 free_blocks_count;
};

enum {
	BLOCK_BITMAP = 0,	 
	INODE_BITMAP,		 
	INODE_TABLE,		 
	GROUP_TABLE_COUNT,
};

#define EXT4_GET_BLOCKS_CREATE			0x0001
	 
#define EXT4_GET_BLOCKS_UNWRIT_EXT		0x0002
#define EXT4_GET_BLOCKS_CREATE_UNWRIT_EXT	(EXT4_GET_BLOCKS_UNWRIT_EXT|\
						 EXT4_GET_BLOCKS_CREATE)
	 
#define EXT4_GET_BLOCKS_DELALLOC_RESERVE	0x0004
	 
#define EXT4_GET_BLOCKS_PRE_IO			0x0008
#define EXT4_GET_BLOCKS_CONVERT			0x0010
#define EXT4_GET_BLOCKS_IO_CREATE_EXT		(EXT4_GET_BLOCKS_PRE_IO|\
					 EXT4_GET_BLOCKS_CREATE_UNWRIT_EXT)
	 
#define EXT4_GET_BLOCKS_IO_CONVERT_EXT		(EXT4_GET_BLOCKS_CONVERT|\
					 EXT4_GET_BLOCKS_CREATE_UNWRIT_EXT)
	 
#define EXT4_GET_BLOCKS_METADATA_NOFAIL		0x0020
	 
#define EXT4_GET_BLOCKS_NO_NORMALIZE		0x0040
	 
#define EXT4_GET_BLOCKS_KEEP_SIZE		0x0080
	 
#define EXT4_GET_BLOCKS_NO_LOCK			0x0100
	 
#define EXT4_GET_BLOCKS_CONVERT_UNWRITTEN	0x0200

#define EXT4_EX_NOCACHE				0x40000000
#define EXT4_EX_FORCE_CACHE			0x20000000

#define EXT4_FREE_BLOCKS_METADATA	0x0001
#define EXT4_FREE_BLOCKS_FORGET		0x0002
#define EXT4_FREE_BLOCKS_VALIDATED	0x0004
#define EXT4_FREE_BLOCKS_NO_QUOT_UPDATE	0x0008
#define EXT4_FREE_BLOCKS_NOFREE_FIRST_CLUSTER	0x0010
#define EXT4_FREE_BLOCKS_NOFREE_LAST_CLUSTER	0x0020

#define EXT4_ENCRYPTION_MODE_INVALID		0
#define EXT4_ENCRYPTION_MODE_AES_256_XTS	1
#define EXT4_ENCRYPTION_MODE_AES_256_GCM	2
#define EXT4_ENCRYPTION_MODE_AES_256_CBC	3
#define EXT4_ENCRYPTION_MODE_AES_256_CTS	4

#include "ext4_crypto.h"

#define	EXT4_IOC_GETFLAGS		FS_IOC_GETFLAGS
#define	EXT4_IOC_SETFLAGS		FS_IOC_SETFLAGS
#define	EXT4_IOC_GETVERSION		_IOR('f', 3, long)
#define	EXT4_IOC_SETVERSION		_IOW('f', 4, long)
#define	EXT4_IOC_GETVERSION_OLD		FS_IOC_GETVERSION
#define	EXT4_IOC_SETVERSION_OLD		FS_IOC_SETVERSION
#define EXT4_IOC_GETRSVSZ		_IOR('f', 5, long)
#define EXT4_IOC_SETRSVSZ		_IOW('f', 6, long)
#define EXT4_IOC_GROUP_EXTEND		_IOW('f', 7, unsigned long)
#define EXT4_IOC_GROUP_ADD		_IOW('f', 8, struct ext4_new_group_input)
#define EXT4_IOC_MIGRATE		_IO('f', 9)
  
#define EXT4_IOC_ALLOC_DA_BLKS		_IO('f', 12)
#define EXT4_IOC_MOVE_EXT		_IOWR('f', 15, struct move_extent)
#define EXT4_IOC_RESIZE_FS		_IOW('f', 16, __u64)
#define EXT4_IOC_SWAP_BOOT		_IO('f', 17)
#define EXT4_IOC_PRECACHE_EXTENTS	_IO('f', 18)
#define EXT4_IOC_SET_ENCRYPTION_POLICY	_IOR('f', 19, struct ext4_encryption_policy)
#define EXT4_IOC_GET_ENCRYPTION_PWSALT	_IOW('f', 20, __u8[16])
#define EXT4_IOC_GET_ENCRYPTION_POLICY	_IOW('f', 21, struct ext4_encryption_policy)

#if defined(__KERNEL__) && defined(CONFIG_COMPAT)
 
#define EXT4_IOC32_GETFLAGS		FS_IOC32_GETFLAGS
#define EXT4_IOC32_SETFLAGS		FS_IOC32_SETFLAGS
#define EXT4_IOC32_GETVERSION		_IOR('f', 3, int)
#define EXT4_IOC32_SETVERSION		_IOW('f', 4, int)
#define EXT4_IOC32_GETRSVSZ		_IOR('f', 5, int)
#define EXT4_IOC32_SETRSVSZ		_IOW('f', 6, int)
#define EXT4_IOC32_GROUP_EXTEND		_IOW('f', 7, unsigned int)
#define EXT4_IOC32_GROUP_ADD		_IOW('f', 8, struct compat_ext4_new_group_input)
#define EXT4_IOC32_GETVERSION_OLD	FS_IOC32_GETVERSION
#define EXT4_IOC32_SETVERSION_OLD	FS_IOC32_SETVERSION
#endif

#define EXT4_MAX_BLOCK_FILE_PHYS	0xFFFFFFFF

struct ext4_inode {
	__le16	i_mode;		 
	__le16	i_uid;		 
	__le32	i_size_lo;	 
	__le32	i_atime;	 
	__le32	i_ctime;	 
	__le32	i_mtime;	 
	__le32	i_dtime;	 
	__le16	i_gid;		 
	__le16	i_links_count;	 
	__le32	i_blocks_lo;	 
	__le32	i_flags;	 
	union {
		struct {
			__le32  l_i_version;
		} linux1;
		struct {
			__u32  h_i_translator;
		} hurd1;
		struct {
			__u32  m_i_reserved1;
		} masix1;
	} osd1;				 
	__le32	i_block[EXT4_N_BLOCKS]; 
	__le32	i_generation;	 
	__le32	i_file_acl_lo;	 
	__le32	i_size_high;
	__le32	i_obso_faddr;	 
	union {
		struct {
			__le16	l_i_blocks_high;  
			__le16	l_i_file_acl_high;
			__le16	l_i_uid_high;	 
			__le16	l_i_gid_high;	 
			__le16	l_i_checksum_lo; 
			__le16	l_i_reserved;
		} linux2;
		struct {
			__le16	h_i_reserved1;	 
			__u16	h_i_mode_high;
			__u16	h_i_uid_high;
			__u16	h_i_gid_high;
			__u32	h_i_author;
		} hurd2;
		struct {
			__le16	h_i_reserved1;	 
			__le16	m_i_file_acl_high;
			__u32	m_i_reserved2[2];
		} masix2;
	} osd2;				 
	__le16	i_extra_isize;
	__le16	i_checksum_hi;	 
	__le32  i_ctime_extra;   
	__le32  i_mtime_extra;   
	__le32  i_atime_extra;   
	__le32  i_crtime;        
	__le32  i_crtime_extra;  
	__le32  i_version_hi;	 
	__le32	i_projid;	 
};

struct move_extent {
	__u32 reserved;		 
	__u32 donor_fd;		 
	__u64 orig_start;	 
	__u64 donor_start;	 
	__u64 len;		 
	__u64 moved_len;	 
};

#define EXT4_EPOCH_BITS 2
#define EXT4_EPOCH_MASK ((1 << EXT4_EPOCH_BITS) - 1)
#define EXT4_NSEC_MASK  (~0UL << EXT4_EPOCH_BITS)

#define EXT4_FITS_IN_INODE(ext4_inode, einode, field)	\
	((offsetof(typeof(*ext4_inode), field) +	\
	  sizeof((ext4_inode)->field))			\
	<= (EXT4_GOOD_OLD_INODE_SIZE +			\
	    (einode)->i_extra_isize))			\

static inline __le32 ext4_encode_extra_time(struct timespec *time)
{
	u32 extra = sizeof(time->tv_sec) > 4 ?
		((time->tv_sec - (s32)time->tv_sec) >> 32) & EXT4_EPOCH_MASK : 0;
	return cpu_to_le32(extra | (time->tv_nsec << EXT4_EPOCH_BITS));
}

static inline void ext4_decode_extra_time(struct timespec *time, __le32 extra)
{
	if (unlikely(sizeof(time->tv_sec) > 4 &&
			(extra & cpu_to_le32(EXT4_EPOCH_MASK)))) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,20,0)
		 
		u64 extra_bits = le32_to_cpu(extra) & EXT4_EPOCH_MASK;
		if (extra_bits == 3 && ((time->tv_sec) & 0x80000000) != 0)
			extra_bits = 0;
		time->tv_sec += extra_bits << 32;
#else
		time->tv_sec += (u64)(le32_to_cpu(extra) & EXT4_EPOCH_MASK) << 32;
#endif
	}
	time->tv_nsec = (le32_to_cpu(extra) & EXT4_NSEC_MASK) >> EXT4_EPOCH_BITS;
}

#define EXT4_INODE_SET_XTIME(xtime, inode, raw_inode)			       \
do {									       \
	(raw_inode)->xtime = cpu_to_le32((inode)->xtime.tv_sec);	       \
	if (EXT4_FITS_IN_INODE(raw_inode, EXT4_I(inode), xtime ## _extra))     \
		(raw_inode)->xtime ## _extra =				       \
				ext4_encode_extra_time(&(inode)->xtime);       \
} while (0)

#define EXT4_EINODE_SET_XTIME(xtime, einode, raw_inode)			       \
do {									       \
	if (EXT4_FITS_IN_INODE(raw_inode, einode, xtime))		       \
		(raw_inode)->xtime = cpu_to_le32((einode)->xtime.tv_sec);      \
	if (EXT4_FITS_IN_INODE(raw_inode, einode, xtime ## _extra))	       \
		(raw_inode)->xtime ## _extra =				       \
				ext4_encode_extra_time(&(einode)->xtime);      \
} while (0)

#define EXT4_INODE_GET_XTIME(xtime, inode, raw_inode)			       \
do {									       \
	(inode)->xtime.tv_sec = (signed)le32_to_cpu((raw_inode)->xtime);       \
	if (EXT4_FITS_IN_INODE(raw_inode, EXT4_I(inode), xtime ## _extra))     \
		ext4_decode_extra_time(&(inode)->xtime,			       \
				       raw_inode->xtime ## _extra);	       \
	else								       \
		(inode)->xtime.tv_nsec = 0;				       \
} while (0)

#define EXT4_EINODE_GET_XTIME(xtime, einode, raw_inode)			       \
do {									       \
	if (EXT4_FITS_IN_INODE(raw_inode, einode, xtime))		       \
		(einode)->xtime.tv_sec = 				       \
			(signed)le32_to_cpu((raw_inode)->xtime);	       \
	else								       \
		(einode)->xtime.tv_sec = 0;				       \
	if (EXT4_FITS_IN_INODE(raw_inode, einode, xtime ## _extra))	       \
		ext4_decode_extra_time(&(einode)->xtime,		       \
				       raw_inode->xtime ## _extra);	       \
	else								       \
		(einode)->xtime.tv_nsec = 0;				       \
} while (0)

#define i_disk_version osd1.linux1.l_i_version

#if defined(__KERNEL__) || defined(__linux__)
#define i_reserved1	osd1.linux1.l_i_reserved1
#define i_file_acl_high	osd2.linux2.l_i_file_acl_high
#define i_blocks_high	osd2.linux2.l_i_blocks_high
#define i_uid_low	i_uid
#define i_gid_low	i_gid
#define i_uid_high	osd2.linux2.l_i_uid_high
#define i_gid_high	osd2.linux2.l_i_gid_high
#define i_checksum_lo	osd2.linux2.l_i_checksum_lo
#ifdef MY_ABC_HERE
#define i_reserved	osd2.linux2.l_i_reserved
#endif  

#elif defined(__GNU__)

#define i_translator	osd1.hurd1.h_i_translator
#define i_uid_high	osd2.hurd2.h_i_uid_high
#define i_gid_high	osd2.hurd2.h_i_gid_high
#define i_author	osd2.hurd2.h_i_author

#elif defined(__masix__)

#define i_reserved1	osd1.masix1.m_i_reserved1
#define i_file_acl_high	osd2.masix2.m_i_file_acl_high
#define i_reserved2	osd2.masix2.m_i_reserved2

#endif  

#ifdef MY_ABC_HERE
#define ext4_archive_bit		i_checksum_hi
#endif  

#ifdef MY_ABC_HERE
#define ext3_archive_bit_lo		i_checksum_lo
#define ext3_archive_bit_high	i_reserved
#endif  

#ifdef MY_ABC_HERE
#define ext4_archive_version_bad	s_usr_quota_inum
#endif  

#ifdef MY_ABC_HERE
#define i_ext3_create_time	i_disk_version
#endif  

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
#define SYNO_HASH_MAGIC       0x01856E96       
#define s_syno_hash_magic     s_checksum
#endif  

#include "extents_status.h"

enum {
	I_DATA_SEM_NORMAL = 0,
	I_DATA_SEM_OTHER,
	I_DATA_SEM_QUOTA,
};

struct ext4_inode_info {
	__le32	i_data[15];	 
	__u32	i_dtime;
	ext4_fsblk_t	i_file_acl;

	ext4_group_t	i_block_group;
	ext4_lblk_t	i_dir_start_lookup;
#if (BITS_PER_LONG < 64)
	unsigned long	i_state_flags;		 
#endif
	unsigned long	i_flags;

	struct rw_semaphore xattr_sem;

	struct list_head i_orphan;	 

	loff_t	i_disksize;

	struct rw_semaphore i_data_sem;
	 
	struct rw_semaphore i_mmap_sem;
	struct inode vfs_inode;
	struct jbd2_inode *jinode;

	spinlock_t i_raw_lock;	 

	struct timespec i_crtime;

	struct list_head i_prealloc_list;
	spinlock_t i_prealloc_lock;

	struct ext4_es_tree i_es_tree;
	rwlock_t i_es_lock;
	struct list_head i_es_list;
	unsigned int i_es_all_nr;	 
	unsigned int i_es_shk_nr;	 
	ext4_lblk_t i_es_shrink_lblk;	 

	ext4_group_t	i_last_alloc_group;

	unsigned int i_reserved_data_blocks;
	unsigned int i_reserved_meta_blocks;
	unsigned int i_allocated_meta_blocks;
	ext4_lblk_t i_da_metadata_calc_last_lblock;
	int i_da_metadata_calc_len;

	__u16 i_extra_isize;

	u16 i_inline_off;
	u16 i_inline_size;

#ifdef CONFIG_QUOTA
	 
	qsize_t i_reserved_quota;
#endif

	spinlock_t i_completed_io_lock;
	 
	struct list_head i_rsv_conversion_list;
	 
	atomic_t i_ioend_count;	 
	atomic_t i_unwritten;  
	struct work_struct i_rsv_conversion_work;

	spinlock_t i_block_reservation_lock;

	tid_t i_sync_tid;
	tid_t i_datasync_tid;

#ifdef CONFIG_QUOTA
	struct dquot *i_dquot[MAXQUOTAS];
#endif

	__u32 i_csum_seed;

#ifdef CONFIG_EXT4_FS_ENCRYPTION
	 
	struct ext4_crypt_info *i_crypt_info;
#endif
};

#define	EXT4_VALID_FS			0x0001	 
#define	EXT4_ERROR_FS			0x0002	 
#define	EXT4_ORPHAN_FS			0x0004	 

#define EXT2_FLAGS_SIGNED_HASH		0x0001   
#define EXT2_FLAGS_UNSIGNED_HASH	0x0002   
#define EXT2_FLAGS_TEST_FILESYS		0x0004	 

#define EXT4_MOUNT_GRPID		0x00004	 
#define EXT4_MOUNT_DEBUG		0x00008	 
#define EXT4_MOUNT_ERRORS_CONT		0x00010	 
#define EXT4_MOUNT_ERRORS_RO		0x00020	 
#define EXT4_MOUNT_ERRORS_PANIC		0x00040	 
#define EXT4_MOUNT_ERRORS_MASK		0x00070
#define EXT4_MOUNT_MINIX_DF		0x00080	 
#define EXT4_MOUNT_NOLOAD		0x00100	 
#ifdef CONFIG_FS_DAX
#define EXT4_MOUNT_DAX			0x00200	 
#else
#define EXT4_MOUNT_DAX			0
#endif
#define EXT4_MOUNT_DATA_FLAGS		0x00C00	 
#define EXT4_MOUNT_JOURNAL_DATA		0x00400	 
#define EXT4_MOUNT_ORDERED_DATA		0x00800	 
#define EXT4_MOUNT_WRITEBACK_DATA	0x00C00	 
#define EXT4_MOUNT_UPDATE_JOURNAL	0x01000	 
#define EXT4_MOUNT_NO_UID32		0x02000   
#define EXT4_MOUNT_XATTR_USER		0x04000	 
#define EXT4_MOUNT_POSIX_ACL		0x08000	 
#define EXT4_MOUNT_NO_AUTO_DA_ALLOC	0x10000	 
#define EXT4_MOUNT_BARRIER		0x20000  
#define EXT4_MOUNT_QUOTA		0x80000  
#define EXT4_MOUNT_USRQUOTA		0x100000  
#define EXT4_MOUNT_GRPQUOTA		0x200000  
#define EXT4_MOUNT_DIOREAD_NOLOCK	0x400000  
#define EXT4_MOUNT_JOURNAL_CHECKSUM	0x800000  
#define EXT4_MOUNT_JOURNAL_ASYNC_COMMIT	0x1000000  
#define EXT4_MOUNT_DELALLOC		0x8000000  
#define EXT4_MOUNT_DATA_ERR_ABORT	0x10000000  
#define EXT4_MOUNT_BLOCK_VALIDITY	0x20000000  
#define EXT4_MOUNT_DISCARD		0x40000000  
#define EXT4_MOUNT_INIT_INODE_TABLE	0x80000000  

#define EXT4_MOUNT2_EXPLICIT_DELALLOC	0x00000001  
#define EXT4_MOUNT2_STD_GROUP_SIZE	0x00000002  
#define EXT4_MOUNT2_HURD_COMPAT		0x00000004  

#define EXT4_MOUNT2_EXPLICIT_JOURNAL_CHECKSUM	0x00000008  

#define clear_opt(sb, opt)		EXT4_SB(sb)->s_mount_opt &= \
						~EXT4_MOUNT_##opt
#define set_opt(sb, opt)		EXT4_SB(sb)->s_mount_opt |= \
						EXT4_MOUNT_##opt
#define test_opt(sb, opt)		(EXT4_SB(sb)->s_mount_opt & \
					 EXT4_MOUNT_##opt)

#define clear_opt2(sb, opt)		EXT4_SB(sb)->s_mount_opt2 &= \
						~EXT4_MOUNT2_##opt
#define set_opt2(sb, opt)		EXT4_SB(sb)->s_mount_opt2 |= \
						EXT4_MOUNT2_##opt
#define test_opt2(sb, opt)		(EXT4_SB(sb)->s_mount_opt2 & \
					 EXT4_MOUNT2_##opt)

#define ext4_test_and_set_bit		__test_and_set_bit_le
#define ext4_set_bit			__set_bit_le
#define ext4_set_bit_atomic		ext2_set_bit_atomic
#define ext4_test_and_clear_bit		__test_and_clear_bit_le
#define ext4_clear_bit			__clear_bit_le
#define ext4_clear_bit_atomic		ext2_clear_bit_atomic
#define ext4_test_bit			test_bit_le
#define ext4_find_next_zero_bit		find_next_zero_bit_le
#define ext4_find_next_bit		find_next_bit_le

extern void ext4_set_bits(void *bm, int cur, int len);

#define EXT4_DFL_MAX_MNT_COUNT		20	 
#define EXT4_DFL_CHECKINTERVAL		0	 

#define EXT4_ERRORS_CONTINUE		1	 
#define EXT4_ERRORS_RO			2	 
#define EXT4_ERRORS_PANIC		3	 
#define EXT4_ERRORS_DEFAULT		EXT4_ERRORS_CONTINUE

#define EXT4_CRC32C_CHKSUM		1

struct ext4_super_block {
 	__le32	s_inodes_count;		 
	__le32	s_blocks_count_lo;	 
	__le32	s_r_blocks_count_lo;	 
	__le32	s_free_blocks_count_lo;	 
 	__le32	s_free_inodes_count;	 
	__le32	s_first_data_block;	 
	__le32	s_log_block_size;	 
	__le32	s_log_cluster_size;	 
 	__le32	s_blocks_per_group;	 
	__le32	s_clusters_per_group;	 
	__le32	s_inodes_per_group;	 
	__le32	s_mtime;		 
 	__le32	s_wtime;		 
	__le16	s_mnt_count;		 
	__le16	s_max_mnt_count;	 
	__le16	s_magic;		 
	__le16	s_state;		 
	__le16	s_errors;		 
	__le16	s_minor_rev_level;	 
 	__le32	s_lastcheck;		 
	__le32	s_checkinterval;	 
	__le32	s_creator_os;		 
	__le32	s_rev_level;		 
 	__le16	s_def_resuid;		 
	__le16	s_def_resgid;		 
	 
	__le32	s_first_ino;		 
	__le16  s_inode_size;		 
	__le16	s_block_group_nr;	 
	__le32	s_feature_compat;	 
 	__le32	s_feature_incompat;	 
	__le32	s_feature_ro_compat;	 
 	__u8	s_uuid[16];		 
 	char	s_volume_name[16];	 
 	char	s_last_mounted[64];	 
 	__le32	s_algorithm_usage_bitmap;  
	 
	__u8	s_prealloc_blocks;	 
	__u8	s_prealloc_dir_blocks;	 
	__le16	s_reserved_gdt_blocks;	 
	 
 	__u8	s_journal_uuid[16];	 
 	__le32	s_journal_inum;		 
	__le32	s_journal_dev;		 
	__le32	s_last_orphan;		 
	__le32	s_hash_seed[4];		 
	__u8	s_def_hash_version;	 
	__u8	s_jnl_backup_type;
	__le16  s_desc_size;		 
 	__le32	s_default_mount_opts;
	__le32	s_first_meta_bg;	 
	__le32	s_mkfs_time;		 
	__le32	s_jnl_blocks[17];	 
	 
 	__le32	s_blocks_count_hi;	 
	__le32	s_r_blocks_count_hi;	 
	__le32	s_free_blocks_count_hi;	 
	__le16	s_min_extra_isize;	 
	__le16	s_want_extra_isize; 	 
	__le32	s_flags;		 
	__le16  s_raid_stride;		 
	__le16  s_mmp_update_interval;   
	__le64  s_mmp_block;             
	__le32  s_raid_stripe_width;     
	__u8	s_log_groups_per_flex;   
	__u8	s_checksum_type;	 
	__u8	s_encryption_level;	 
	__u8	s_reserved_pad;		 
	__le64	s_kbytes_written;	 
	__le32	s_snapshot_inum;	 
	__le32	s_snapshot_id;		 
	__le64	s_snapshot_r_blocks_count;  
	__le32	s_snapshot_list;	 
#define EXT4_S_ERR_START offsetof(struct ext4_super_block, s_error_count)
	__le32	s_error_count;		 
	__le32	s_first_error_time;	 
	__le32	s_first_error_ino;	 
	__le64	s_first_error_block;	 
	__u8	s_first_error_func[32];	 
	__le32	s_first_error_line;	 
	__le32	s_last_error_time;	 
	__le32	s_last_error_ino;	 
	__le32	s_last_error_line;	 
	__le64	s_last_error_block;	 
	__u8	s_last_error_func[32];	 
#define EXT4_S_ERR_END offsetof(struct ext4_super_block, s_mount_opts)
	__u8	s_mount_opts[64];
	__le32	s_usr_quota_inum;	 
	__le32	s_grp_quota_inum;	 
	__le32	s_overhead_clusters;	 
	__le32	s_backup_bgs[2];	 
	__u8	s_encrypt_algos[4];	 
	__u8	s_encrypt_pw_salt[16];	 
	__le32	s_lpf_ino;		 
	__le32	s_prj_quota_inum;	 
	__le32	s_checksum_seed;	 
#ifdef MY_ABC_HERE
	__le32	s_reserved[96];	 
	__le32	s_archive_version;	 
	__le32  s_archive_version_obsoleted;
#else
	__le32	s_reserved[98];		 
#endif  
	__le32	s_checksum;		 
};

#define EXT4_S_ERR_LEN (EXT4_S_ERR_END - EXT4_S_ERR_START)

#ifdef __KERNEL__

#define EXT4_MF_MNTDIR_SAMPLED		0x0001
#define EXT4_MF_FS_ABORTED		0x0002	 
#define EXT4_MF_TEST_DUMMY_ENCRYPTION	0x0004

#ifdef CONFIG_EXT4_FS_ENCRYPTION
#define DUMMY_ENCRYPTION_ENABLED(sbi) (unlikely((sbi)->s_mount_flags & \
						EXT4_MF_TEST_DUMMY_ENCRYPTION))
#else
#define DUMMY_ENCRYPTION_ENABLED(sbi) (0)
#endif

#define EXT4_MAXQUOTAS 2

struct ext4_sb_info {
	unsigned long s_desc_size;	 
	unsigned long s_inodes_per_block; 
	unsigned long s_blocks_per_group; 
	unsigned long s_clusters_per_group;  
	unsigned long s_inodes_per_group; 
	unsigned long s_itb_per_group;	 
	unsigned long s_gdb_count;	 
	unsigned long s_desc_per_block;	 
	ext4_group_t s_groups_count;	 
	ext4_group_t s_blockfile_groups; 
	unsigned long s_overhead;   
	unsigned int s_cluster_ratio;	 
	unsigned int s_cluster_bits;	 
	loff_t s_bitmap_maxbytes;	 
	struct buffer_head * s_sbh;	 
	struct ext4_super_block *s_es;	 
	struct buffer_head **s_group_desc;
	unsigned int s_mount_opt;
	unsigned int s_mount_opt2;
	unsigned int s_mount_flags;
	unsigned int s_def_mount_opt;
	ext4_fsblk_t s_sb_block;
	atomic64_t s_resv_clusters;
	kuid_t s_resuid;
	kgid_t s_resgid;
	unsigned short s_mount_state;
	unsigned short s_pad;
	int s_addr_per_block_bits;
	int s_desc_per_block_bits;
	int s_inode_size;
	int s_first_ino;
	unsigned int s_inode_readahead_blks;
	unsigned int s_inode_goal;
	spinlock_t s_next_gen_lock;
	u32 s_next_generation;
	u32 s_hash_seed[4];
	int s_def_hash_version;
	int s_hash_unsigned;	 
	struct percpu_counter s_freeclusters_counter;
	struct percpu_counter s_freeinodes_counter;
	struct percpu_counter s_dirs_counter;
	struct percpu_counter s_dirtyclusters_counter;
	struct blockgroup_lock *s_blockgroup_lock;
	struct proc_dir_entry *s_proc;
	struct kobject s_kobj;
	struct completion s_kobj_unregister;
	struct super_block *s_sb;

	struct journal_s *s_journal;
	struct list_head s_orphan;
	struct mutex s_orphan_lock;
	unsigned long s_resize_flags;		 
	unsigned long s_commit_interval;
	u32 s_max_batch_time;
	u32 s_min_batch_time;
	struct block_device *journal_bdev;
#ifdef CONFIG_QUOTA
	char *s_qf_names[EXT4_MAXQUOTAS];	 
	int s_jquota_fmt;			 
#endif
	unsigned int s_want_extra_isize;  
	struct rb_root system_blks;

#ifdef EXTENTS_STATS
	 
	unsigned long s_ext_min;
	unsigned long s_ext_max;
	unsigned long s_depth_max;
	spinlock_t s_ext_stats_lock;
	unsigned long s_ext_blocks;
	unsigned long s_ext_extents;
#endif

	struct ext4_group_info ***s_group_info;
	struct inode *s_buddy_cache;
	spinlock_t s_md_lock;
	unsigned short *s_mb_offsets;
	unsigned int *s_mb_maxs;
	unsigned int s_group_info_size;

	unsigned long s_stripe;
	unsigned int s_mb_stream_request;
	unsigned int s_mb_max_to_scan;
	unsigned int s_mb_min_to_scan;
	unsigned int s_mb_stats;
	unsigned int s_mb_order2_reqs;
	unsigned int s_mb_group_prealloc;
	unsigned int s_max_dir_size_kb;
	 
	unsigned long s_mb_last_group;
	unsigned long s_mb_last_start;

	atomic_t s_bal_reqs;	 
	atomic_t s_bal_success;	 
	atomic_t s_bal_allocated;	 
	atomic_t s_bal_ex_scanned;	 
	atomic_t s_bal_goals;	 
	atomic_t s_bal_breaks;	 
	atomic_t s_bal_2orders;	 
	spinlock_t s_bal_lock;
	unsigned long s_mb_buddies_generated;
	unsigned long long s_mb_generation_time;
	atomic_t s_mb_lost_chunks;
	atomic_t s_mb_preallocated;
	atomic_t s_mb_discarded;
	atomic_t s_lock_busy;

	struct ext4_locality_group __percpu *s_locality_groups;

	unsigned long s_sectors_written_start;
	u64 s_kbytes_written;

	unsigned int s_extent_max_zeroout_kb;

	unsigned int s_log_groups_per_flex;
	struct flex_groups *s_flex_groups;
	ext4_group_t s_flex_groups_allocated;

#ifdef MY_ABC_HERE
	int s_new_error_fs_event_flag;
	char *s_mount_path;
	unsigned long s_last_notify_time;
#endif  

	struct workqueue_struct *rsv_conversion_wq;

#ifdef MY_ABC_HERE
	atomic_t reada_group_desc_threads;  
	struct workqueue_struct *group_desc_readahead_wq;
#endif  

	struct timer_list s_err_report;

	struct ext4_li_request *s_li_request;
	 
	unsigned int s_li_wait_mult;

	struct task_struct *s_mmp_tsk;

	atomic_t s_last_trim_minblks;

	struct crypto_shash *s_chksum_driver;

	__u32 s_csum_seed;

	struct shrinker s_es_shrinker;
	struct list_head s_es_list;	 
	long s_es_nr_inode;
	struct ext4_es_stats s_es_stats;
	struct mb_cache *s_mb_cache;
	spinlock_t s_es_lock ____cacheline_aligned_in_smp;

	struct ratelimit_state s_err_ratelimit_state;
	struct ratelimit_state s_warning_ratelimit_state;
	struct ratelimit_state s_msg_ratelimit_state;
};

static inline struct ext4_sb_info *EXT4_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}
static inline struct ext4_inode_info *EXT4_I(struct inode *inode)
{
	return container_of(inode, struct ext4_inode_info, vfs_inode);
}

static inline struct timespec ext4_current_time(struct inode *inode)
{
	return (inode->i_sb->s_time_gran < NSEC_PER_SEC) ?
		current_fs_time(inode->i_sb) : CURRENT_TIME_SEC;
}

static inline int ext4_valid_inum(struct super_block *sb, unsigned long ino)
{
	return ino == EXT4_ROOT_INO ||
		ino == EXT4_USR_QUOTA_INO ||
		ino == EXT4_GRP_QUOTA_INO ||
		ino == EXT4_BOOT_LOADER_INO ||
		ino == EXT4_JOURNAL_INO ||
		ino == EXT4_RESIZE_INO ||
		(ino >= EXT4_FIRST_INO(sb) &&
		 ino <= le32_to_cpu(EXT4_SB(sb)->s_es->s_inodes_count));
}

static inline void ext4_set_io_unwritten_flag(struct inode *inode,
					      struct ext4_io_end *io_end)
{
	if (!(io_end->flag & EXT4_IO_END_UNWRITTEN)) {
		io_end->flag |= EXT4_IO_END_UNWRITTEN;
		atomic_inc(&EXT4_I(inode)->i_unwritten);
	}
}

static inline ext4_io_end_t *ext4_inode_aio(struct inode *inode)
{
	return inode->i_private;
}

static inline void ext4_inode_aio_set(struct inode *inode, ext4_io_end_t *io)
{
	inode->i_private = io;
}

enum {
	EXT4_STATE_JDATA,		 
	EXT4_STATE_NEW,			 
	EXT4_STATE_XATTR,		 
	EXT4_STATE_NO_EXPAND,		 
	EXT4_STATE_DA_ALLOC_CLOSE,	 
	EXT4_STATE_EXT_MIGRATE,		 
	EXT4_STATE_DIO_UNWRITTEN,	 
	EXT4_STATE_NEWENTRY,		 
	EXT4_STATE_DIOREAD_LOCK,	 
	EXT4_STATE_MAY_INLINE_DATA,	 
	EXT4_STATE_ORDERED_MODE,	 
	EXT4_STATE_EXT_PRECACHED,	 
};

#define EXT4_INODE_BIT_FNS(name, field, offset)				\
static inline int ext4_test_inode_##name(struct inode *inode, int bit)	\
{									\
	return test_bit(bit + (offset), &EXT4_I(inode)->i_##field);	\
}									\
static inline void ext4_set_inode_##name(struct inode *inode, int bit)	\
{									\
	set_bit(bit + (offset), &EXT4_I(inode)->i_##field);		\
}									\
static inline void ext4_clear_inode_##name(struct inode *inode, int bit) \
{									\
	clear_bit(bit + (offset), &EXT4_I(inode)->i_##field);		\
}

static inline int ext4_test_inode_flag(struct inode *inode, int bit);
static inline void ext4_set_inode_flag(struct inode *inode, int bit);
static inline void ext4_clear_inode_flag(struct inode *inode, int bit);
EXT4_INODE_BIT_FNS(flag, flags, 0)

static inline int ext4_test_inode_state(struct inode *inode, int bit);
static inline void ext4_set_inode_state(struct inode *inode, int bit);
static inline void ext4_clear_inode_state(struct inode *inode, int bit);
#if (BITS_PER_LONG < 64)
EXT4_INODE_BIT_FNS(state, state_flags, 0)

static inline void ext4_clear_state_flags(struct ext4_inode_info *ei)
{
	(ei)->i_state_flags = 0;
}
#else
EXT4_INODE_BIT_FNS(state, flags, 32)

static inline void ext4_clear_state_flags(struct ext4_inode_info *ei)
{
	 
}
#endif
#else
 
#define EXT4_SB(sb)	(sb)
#endif

static inline int ext4_encrypted_inode(struct inode *inode)
{
#ifdef CONFIG_EXT4_FS_ENCRYPTION
	return ext4_test_inode_flag(inode, EXT4_INODE_ENCRYPT);
#else
	return 0;
#endif
}

#define NEXT_ORPHAN(inode) EXT4_I(inode)->i_dtime

#define EXT4_OS_LINUX		0
#define EXT4_OS_HURD		1
#define EXT4_OS_MASIX		2
#define EXT4_OS_FREEBSD		3
#define EXT4_OS_LITES		4

#define EXT4_GOOD_OLD_REV	0	 
#define EXT4_DYNAMIC_REV	1	 

#define EXT4_CURRENT_REV	EXT4_GOOD_OLD_REV
#define EXT4_MAX_SUPP_REV	EXT4_DYNAMIC_REV

#define EXT4_GOOD_OLD_INODE_SIZE 128

#define EXT4_HAS_COMPAT_FEATURE(sb,mask)			\
	((EXT4_SB(sb)->s_es->s_feature_compat & cpu_to_le32(mask)) != 0)
#define EXT4_HAS_RO_COMPAT_FEATURE(sb,mask)			\
	((EXT4_SB(sb)->s_es->s_feature_ro_compat & cpu_to_le32(mask)) != 0)
#define EXT4_HAS_INCOMPAT_FEATURE(sb,mask)			\
	((EXT4_SB(sb)->s_es->s_feature_incompat & cpu_to_le32(mask)) != 0)
#define EXT4_SET_COMPAT_FEATURE(sb,mask)			\
	EXT4_SB(sb)->s_es->s_feature_compat |= cpu_to_le32(mask)
#define EXT4_SET_RO_COMPAT_FEATURE(sb,mask)			\
	EXT4_SB(sb)->s_es->s_feature_ro_compat |= cpu_to_le32(mask)
#define EXT4_SET_INCOMPAT_FEATURE(sb,mask)			\
	EXT4_SB(sb)->s_es->s_feature_incompat |= cpu_to_le32(mask)
#define EXT4_CLEAR_COMPAT_FEATURE(sb,mask)			\
	EXT4_SB(sb)->s_es->s_feature_compat &= ~cpu_to_le32(mask)
#define EXT4_CLEAR_RO_COMPAT_FEATURE(sb,mask)			\
	EXT4_SB(sb)->s_es->s_feature_ro_compat &= ~cpu_to_le32(mask)
#define EXT4_CLEAR_INCOMPAT_FEATURE(sb,mask)			\
	EXT4_SB(sb)->s_es->s_feature_incompat &= ~cpu_to_le32(mask)

#define EXT4_FEATURE_COMPAT_DIR_PREALLOC	0x0001
#define EXT4_FEATURE_COMPAT_IMAGIC_INODES	0x0002
#define EXT4_FEATURE_COMPAT_HAS_JOURNAL		0x0004
#define EXT4_FEATURE_COMPAT_EXT_ATTR		0x0008
#define EXT4_FEATURE_COMPAT_RESIZE_INODE	0x0010
#define EXT4_FEATURE_COMPAT_DIR_INDEX		0x0020
#define EXT4_FEATURE_COMPAT_SPARSE_SUPER2	0x0200

#define EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER	0x0001
#define EXT4_FEATURE_RO_COMPAT_LARGE_FILE	0x0002
#define EXT4_FEATURE_RO_COMPAT_BTREE_DIR	0x0004
#define EXT4_FEATURE_RO_COMPAT_HUGE_FILE        0x0008
#define EXT4_FEATURE_RO_COMPAT_GDT_CSUM		0x0010
#define EXT4_FEATURE_RO_COMPAT_DIR_NLINK	0x0020
#define EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE	0x0040
#define EXT4_FEATURE_RO_COMPAT_QUOTA		0x0100
#define EXT4_FEATURE_RO_COMPAT_BIGALLOC		0x0200
 
#define EXT4_FEATURE_RO_COMPAT_METADATA_CSUM	0x0400
#define EXT4_FEATURE_RO_COMPAT_READONLY		0x1000
#define EXT4_FEATURE_RO_COMPAT_PROJECT		0x2000

#define EXT4_FEATURE_INCOMPAT_COMPRESSION	0x0001
#define EXT4_FEATURE_INCOMPAT_FILETYPE		0x0002
#define EXT4_FEATURE_INCOMPAT_RECOVER		0x0004  
#define EXT4_FEATURE_INCOMPAT_JOURNAL_DEV	0x0008  
#define EXT4_FEATURE_INCOMPAT_META_BG		0x0010
#define EXT4_FEATURE_INCOMPAT_EXTENTS		0x0040  
#define EXT4_FEATURE_INCOMPAT_64BIT		0x0080
#define EXT4_FEATURE_INCOMPAT_MMP               0x0100
#define EXT4_FEATURE_INCOMPAT_FLEX_BG		0x0200
#define EXT4_FEATURE_INCOMPAT_EA_INODE		0x0400  
#define EXT4_FEATURE_INCOMPAT_DIRDATA		0x1000  
#define EXT4_FEATURE_INCOMPAT_CSUM_SEED		0x2000
#define EXT4_FEATURE_INCOMPAT_LARGEDIR		0x4000  
#define EXT4_FEATURE_INCOMPAT_INLINE_DATA	0x8000  
#define EXT4_FEATURE_INCOMPAT_ENCRYPT		0x10000

#define EXT4_FEATURE_COMPAT_FUNCS(name, flagname) \
static inline bool ext4_has_feature_##name(struct super_block *sb) \
{ \
	return ((EXT4_SB(sb)->s_es->s_feature_compat & \
		cpu_to_le32(EXT4_FEATURE_COMPAT_##flagname)) != 0); \
} \
static inline void ext4_set_feature_##name(struct super_block *sb) \
{ \
	EXT4_SB(sb)->s_es->s_feature_compat |= \
		cpu_to_le32(EXT4_FEATURE_COMPAT_##flagname); \
} \
static inline void ext4_clear_feature_##name(struct super_block *sb) \
{ \
	EXT4_SB(sb)->s_es->s_feature_compat &= \
		~cpu_to_le32(EXT4_FEATURE_COMPAT_##flagname); \
}

#define EXT4_FEATURE_RO_COMPAT_FUNCS(name, flagname) \
static inline bool ext4_has_feature_##name(struct super_block *sb) \
{ \
	return ((EXT4_SB(sb)->s_es->s_feature_ro_compat & \
		cpu_to_le32(EXT4_FEATURE_RO_COMPAT_##flagname)) != 0); \
} \
static inline void ext4_set_feature_##name(struct super_block *sb) \
{ \
	EXT4_SB(sb)->s_es->s_feature_ro_compat |= \
		cpu_to_le32(EXT4_FEATURE_RO_COMPAT_##flagname); \
} \
static inline void ext4_clear_feature_##name(struct super_block *sb) \
{ \
	EXT4_SB(sb)->s_es->s_feature_ro_compat &= \
		~cpu_to_le32(EXT4_FEATURE_RO_COMPAT_##flagname); \
}

#define EXT4_FEATURE_INCOMPAT_FUNCS(name, flagname) \
static inline bool ext4_has_feature_##name(struct super_block *sb) \
{ \
	return ((EXT4_SB(sb)->s_es->s_feature_incompat & \
		cpu_to_le32(EXT4_FEATURE_INCOMPAT_##flagname)) != 0); \
} \
static inline void ext4_set_feature_##name(struct super_block *sb) \
{ \
	EXT4_SB(sb)->s_es->s_feature_incompat |= \
		cpu_to_le32(EXT4_FEATURE_INCOMPAT_##flagname); \
} \
static inline void ext4_clear_feature_##name(struct super_block *sb) \
{ \
	EXT4_SB(sb)->s_es->s_feature_incompat &= \
		~cpu_to_le32(EXT4_FEATURE_INCOMPAT_##flagname); \
}

EXT4_FEATURE_COMPAT_FUNCS(dir_prealloc,		DIR_PREALLOC)
EXT4_FEATURE_COMPAT_FUNCS(imagic_inodes,	IMAGIC_INODES)
EXT4_FEATURE_COMPAT_FUNCS(journal,		HAS_JOURNAL)
EXT4_FEATURE_COMPAT_FUNCS(xattr,		EXT_ATTR)
EXT4_FEATURE_COMPAT_FUNCS(resize_inode,		RESIZE_INODE)
EXT4_FEATURE_COMPAT_FUNCS(dir_index,		DIR_INDEX)
EXT4_FEATURE_COMPAT_FUNCS(sparse_super2,	SPARSE_SUPER2)

EXT4_FEATURE_RO_COMPAT_FUNCS(sparse_super,	SPARSE_SUPER)
EXT4_FEATURE_RO_COMPAT_FUNCS(large_file,	LARGE_FILE)
EXT4_FEATURE_RO_COMPAT_FUNCS(btree_dir,		BTREE_DIR)
EXT4_FEATURE_RO_COMPAT_FUNCS(huge_file,		HUGE_FILE)
EXT4_FEATURE_RO_COMPAT_FUNCS(gdt_csum,		GDT_CSUM)
EXT4_FEATURE_RO_COMPAT_FUNCS(dir_nlink,		DIR_NLINK)
EXT4_FEATURE_RO_COMPAT_FUNCS(extra_isize,	EXTRA_ISIZE)
EXT4_FEATURE_RO_COMPAT_FUNCS(quota,		QUOTA)
EXT4_FEATURE_RO_COMPAT_FUNCS(bigalloc,		BIGALLOC)
EXT4_FEATURE_RO_COMPAT_FUNCS(metadata_csum,	METADATA_CSUM)
EXT4_FEATURE_RO_COMPAT_FUNCS(readonly,		READONLY)
EXT4_FEATURE_RO_COMPAT_FUNCS(project,		PROJECT)

EXT4_FEATURE_INCOMPAT_FUNCS(compression,	COMPRESSION)
EXT4_FEATURE_INCOMPAT_FUNCS(filetype,		FILETYPE)
EXT4_FEATURE_INCOMPAT_FUNCS(journal_needs_recovery,	RECOVER)
EXT4_FEATURE_INCOMPAT_FUNCS(journal_dev,	JOURNAL_DEV)
EXT4_FEATURE_INCOMPAT_FUNCS(meta_bg,		META_BG)
EXT4_FEATURE_INCOMPAT_FUNCS(extents,		EXTENTS)
EXT4_FEATURE_INCOMPAT_FUNCS(64bit,		64BIT)
EXT4_FEATURE_INCOMPAT_FUNCS(mmp,		MMP)
EXT4_FEATURE_INCOMPAT_FUNCS(flex_bg,		FLEX_BG)
EXT4_FEATURE_INCOMPAT_FUNCS(ea_inode,		EA_INODE)
EXT4_FEATURE_INCOMPAT_FUNCS(dirdata,		DIRDATA)
EXT4_FEATURE_INCOMPAT_FUNCS(csum_seed,		CSUM_SEED)
EXT4_FEATURE_INCOMPAT_FUNCS(largedir,		LARGEDIR)
EXT4_FEATURE_INCOMPAT_FUNCS(inline_data,	INLINE_DATA)
EXT4_FEATURE_INCOMPAT_FUNCS(encrypt,		ENCRYPT)

#define EXT2_FEATURE_COMPAT_SUPP	EXT4_FEATURE_COMPAT_EXT_ATTR
#define EXT2_FEATURE_INCOMPAT_SUPP	(EXT4_FEATURE_INCOMPAT_FILETYPE| \
					 EXT4_FEATURE_INCOMPAT_META_BG)
#define EXT2_FEATURE_RO_COMPAT_SUPP	(EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER| \
					 EXT4_FEATURE_RO_COMPAT_LARGE_FILE| \
					 EXT4_FEATURE_RO_COMPAT_BTREE_DIR)

#define EXT3_FEATURE_COMPAT_SUPP	EXT4_FEATURE_COMPAT_EXT_ATTR
#define EXT3_FEATURE_INCOMPAT_SUPP	(EXT4_FEATURE_INCOMPAT_FILETYPE| \
					 EXT4_FEATURE_INCOMPAT_RECOVER| \
					 EXT4_FEATURE_INCOMPAT_META_BG)
#define EXT3_FEATURE_RO_COMPAT_SUPP	(EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER| \
					 EXT4_FEATURE_RO_COMPAT_LARGE_FILE| \
					 EXT4_FEATURE_RO_COMPAT_BTREE_DIR)

#define EXT4_FEATURE_COMPAT_SUPP	EXT4_FEATURE_COMPAT_EXT_ATTR
#define EXT4_FEATURE_INCOMPAT_SUPP	(EXT4_FEATURE_INCOMPAT_FILETYPE| \
					 EXT4_FEATURE_INCOMPAT_RECOVER| \
					 EXT4_FEATURE_INCOMPAT_META_BG| \
					 EXT4_FEATURE_INCOMPAT_EXTENTS| \
					 EXT4_FEATURE_INCOMPAT_64BIT| \
					 EXT4_FEATURE_INCOMPAT_FLEX_BG| \
					 EXT4_FEATURE_INCOMPAT_MMP | \
					 EXT4_FEATURE_INCOMPAT_INLINE_DATA | \
					 EXT4_FEATURE_INCOMPAT_ENCRYPT | \
					 EXT4_FEATURE_INCOMPAT_CSUM_SEED)
#define EXT4_FEATURE_RO_COMPAT_SUPP	(EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER| \
					 EXT4_FEATURE_RO_COMPAT_LARGE_FILE| \
					 EXT4_FEATURE_RO_COMPAT_GDT_CSUM| \
					 EXT4_FEATURE_RO_COMPAT_DIR_NLINK | \
					 EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE | \
					 EXT4_FEATURE_RO_COMPAT_BTREE_DIR |\
					 EXT4_FEATURE_RO_COMPAT_HUGE_FILE |\
					 EXT4_FEATURE_RO_COMPAT_BIGALLOC |\
					 EXT4_FEATURE_RO_COMPAT_METADATA_CSUM|\
					 EXT4_FEATURE_RO_COMPAT_QUOTA)

#define EXTN_FEATURE_FUNCS(ver) \
static inline bool ext4_has_unknown_ext##ver##_compat_features(struct super_block *sb) \
{ \
	return ((EXT4_SB(sb)->s_es->s_feature_compat & \
		cpu_to_le32(~EXT##ver##_FEATURE_COMPAT_SUPP)) != 0); \
} \
static inline bool ext4_has_unknown_ext##ver##_ro_compat_features(struct super_block *sb) \
{ \
	return ((EXT4_SB(sb)->s_es->s_feature_ro_compat & \
		cpu_to_le32(~EXT##ver##_FEATURE_RO_COMPAT_SUPP)) != 0); \
} \
static inline bool ext4_has_unknown_ext##ver##_incompat_features(struct super_block *sb) \
{ \
	return ((EXT4_SB(sb)->s_es->s_feature_incompat & \
		cpu_to_le32(~EXT##ver##_FEATURE_INCOMPAT_SUPP)) != 0); \
}

EXTN_FEATURE_FUNCS(2)
EXTN_FEATURE_FUNCS(3)
EXTN_FEATURE_FUNCS(4)

static inline bool ext4_has_compat_features(struct super_block *sb)
{
	return (EXT4_SB(sb)->s_es->s_feature_compat != 0);
}
static inline bool ext4_has_ro_compat_features(struct super_block *sb)
{
	return (EXT4_SB(sb)->s_es->s_feature_ro_compat != 0);
}
static inline bool ext4_has_incompat_features(struct super_block *sb)
{
	return (EXT4_SB(sb)->s_es->s_feature_incompat != 0);
}

#define	EXT4_DEF_RESUID		0
#define	EXT4_DEF_RESGID		0

#define EXT4_DEF_INODE_READAHEAD_BLKS	32

#define EXT4_DEFM_DEBUG		0x0001
#define EXT4_DEFM_BSDGROUPS	0x0002
#define EXT4_DEFM_XATTR_USER	0x0004
#define EXT4_DEFM_ACL		0x0008
#define EXT4_DEFM_UID16		0x0010
#define EXT4_DEFM_JMODE		0x0060
#define EXT4_DEFM_JMODE_DATA	0x0020
#define EXT4_DEFM_JMODE_ORDERED	0x0040
#define EXT4_DEFM_JMODE_WBACK	0x0060
#define EXT4_DEFM_NOBARRIER	0x0100
#define EXT4_DEFM_BLOCK_VALIDITY 0x0200
#define EXT4_DEFM_DISCARD	0x0400
#define EXT4_DEFM_NODELALLOC	0x0800

#define EXT4_DEF_MIN_BATCH_TIME	0
#define EXT4_DEF_MAX_BATCH_TIME	15000  

#define EXT4_FLEX_SIZE_DIR_ALLOC_SCHEME	4

#define EXT4_NAME_LEN 255

struct ext4_dir_entry {
	__le32	inode;			 
	__le16	rec_len;		 
	__le16	name_len;		 
	char	name[EXT4_NAME_LEN];	 
};

struct ext4_dir_entry_2 {
	__le32	inode;			 
	__le16	rec_len;		 
	__u8	name_len;		 
	__u8	file_type;
	char	name[EXT4_NAME_LEN];	 
};

struct ext4_dir_entry_tail {
	__le32	det_reserved_zero1;	 
	__le16	det_rec_len;		 
	__u8	det_reserved_zero2;	 
	__u8	det_reserved_ft;	 
	__le32	det_checksum;		 
};

#define EXT4_DIRENT_TAIL(block, blocksize) \
	((struct ext4_dir_entry_tail *)(((void *)(block)) + \
					((blocksize) - \
					 sizeof(struct ext4_dir_entry_tail))))

#define EXT4_FT_UNKNOWN		0
#define EXT4_FT_REG_FILE	1
#define EXT4_FT_DIR		2
#define EXT4_FT_CHRDEV		3
#define EXT4_FT_BLKDEV		4
#define EXT4_FT_FIFO		5
#define EXT4_FT_SOCK		6
#define EXT4_FT_SYMLINK		7

#define EXT4_FT_MAX		8

#define EXT4_FT_DIR_CSUM	0xDE

#define EXT4_DIR_PAD			4
#define EXT4_DIR_ROUND			(EXT4_DIR_PAD - 1)
#define EXT4_DIR_REC_LEN(name_len)	(((name_len) + 8 + EXT4_DIR_ROUND) & \
					 ~EXT4_DIR_ROUND)
#define EXT4_MAX_REC_LEN		((1<<16)-1)

static inline unsigned int
ext4_rec_len_from_disk(__le16 dlen, unsigned blocksize)
{
	unsigned len = le16_to_cpu(dlen);

#if (PAGE_CACHE_SIZE >= 65536)
	if (len == EXT4_MAX_REC_LEN || len == 0)
		return blocksize;
	return (len & 65532) | ((len & 3) << 16);
#else
	return len;
#endif
}

static inline __le16 ext4_rec_len_to_disk(unsigned len, unsigned blocksize)
{
	if ((len > blocksize) || (blocksize > (1 << 18)) || (len & 3))
		BUG();
#if (PAGE_CACHE_SIZE >= 65536)
	if (len < 65536)
		return cpu_to_le16(len);
	if (len == blocksize) {
		if (blocksize == 65536)
			return cpu_to_le16(EXT4_MAX_REC_LEN);
		else
			return cpu_to_le16(0);
	}
	return cpu_to_le16((len & 65532) | ((len >> 16) & 3));
#else
	return cpu_to_le16(len);
#endif
}

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
#define is_syno_ext(sb) (EXT4_SB(sb)->s_es->s_syno_hash_magic == cpu_to_le32(SYNO_HASH_MAGIC))
#endif  

#ifdef MY_ABC_HERE
#define is_dx(dir) ((EXT4_SB(dir->i_sb)->s_es->s_syno_hash_magic == cpu_to_le32(SYNO_HASH_MAGIC)) && \
					!(ext4_has_feature_dir_index((dir)->i_sb)) && \
					(EXT4_I(dir)->i_flags & EXT4_INDEX_FL))
#else
#define is_dx(dir) (ext4_has_feature_dir_index((dir)->i_sb) && \
		    ext4_test_inode_flag((dir), EXT4_INODE_INDEX))
#endif  
#define EXT4_DIR_LINK_MAX(dir) (!is_dx(dir) && (dir)->i_nlink >= EXT4_LINK_MAX)
#define EXT4_DIR_LINK_EMPTY(dir) ((dir)->i_nlink == 2 || (dir)->i_nlink == 1)

#define DX_HASH_LEGACY		0
#define DX_HASH_HALF_MD4	1
#define DX_HASH_TEA		2
#define DX_HASH_LEGACY_UNSIGNED	3
#define DX_HASH_HALF_MD4_UNSIGNED	4
#define DX_HASH_TEA_UNSIGNED		5

static inline u32 ext4_chksum(struct ext4_sb_info *sbi, u32 crc,
			      const void *address, unsigned int length)
{
	struct {
		struct shash_desc shash;
		char ctx[4];
	} desc;
	int err;

	BUG_ON(crypto_shash_descsize(sbi->s_chksum_driver)!=sizeof(desc.ctx));

	desc.shash.tfm = sbi->s_chksum_driver;
	desc.shash.flags = 0;
	*(u32 *)desc.ctx = crc;

	err = crypto_shash_update(&desc.shash, address, length);
	BUG_ON(err);

	return *(u32 *)desc.ctx;
}

#ifdef __KERNEL__

struct dx_hash_info
{
	u32		hash;
	u32		minor_hash;
	int		hash_version;
	u32		*seed;
};

#define EXT4_HTREE_EOF_32BIT   ((1UL  << (32 - 1)) - 1)
#define EXT4_HTREE_EOF_64BIT   ((1ULL << (64 - 1)) - 1)

#define HASH_NB_ALWAYS		1

struct ext4_filename {
	const struct qstr *usr_fname;
	struct ext4_str disk_name;
	struct dx_hash_info hinfo;
#ifdef CONFIG_EXT4_FS_ENCRYPTION
	struct ext4_str crypto_buf;
#endif
};

#define fname_name(p) ((p)->disk_name.name)
#define fname_len(p)  ((p)->disk_name.len)

struct ext4_iloc
{
	struct buffer_head *bh;
	unsigned long offset;
	ext4_group_t block_group;
};

static inline struct ext4_inode *ext4_raw_inode(struct ext4_iloc *iloc)
{
	return (struct ext4_inode *) (iloc->bh->b_data + iloc->offset);
}

struct dir_private_info {
	struct rb_root	root;
	struct rb_node	*curr_node;
	struct fname	*extra_fname;
	loff_t		last_pos;
	__u32		curr_hash;
	__u32		curr_minor_hash;
	__u32		next_hash;
};

static inline ext4_fsblk_t
ext4_group_first_block_no(struct super_block *sb, ext4_group_t group_no)
{
	return group_no * (ext4_fsblk_t)EXT4_BLOCKS_PER_GROUP(sb) +
		le32_to_cpu(EXT4_SB(sb)->s_es->s_first_data_block);
}

#define ERR_BAD_DX_DIR	(-(MAX_ERRNO - 1))

#ifdef CONFIG_SYNO_EXT4_LAZYINIT_WAIT_MULT
#define EXT4_DEF_LI_WAIT_MULT			CONFIG_SYNO_EXT4_LAZYINIT_WAIT_MULT
#else
#define EXT4_DEF_LI_WAIT_MULT			10
#endif  
#define EXT4_DEF_LI_MAX_START_DELAY		5
#define EXT4_LAZYINIT_QUIT			0x0001
#define EXT4_LAZYINIT_RUNNING			0x0002

struct ext4_lazy_init {
	unsigned long		li_state;
	struct list_head	li_request_list;
	struct mutex		li_list_mtx;
};

struct ext4_li_request {
	struct super_block	*lr_super;
	struct ext4_sb_info	*lr_sbi;
	ext4_group_t		lr_next_group;
	struct list_head	lr_request;
	unsigned long		lr_next_sched;
	unsigned long		lr_timeout;
};

struct ext4_features {
	struct kobject f_kobj;
	struct completion f_kobj_unregister;
};

#define EXT4_MMP_MAGIC     0x004D4D50U  
#define EXT4_MMP_SEQ_CLEAN 0xFF4D4D50U  
#define EXT4_MMP_SEQ_FSCK  0xE24D4D50U  
#define EXT4_MMP_SEQ_MAX   0xE24D4D4FU  

struct mmp_struct {
	__le32	mmp_magic;		 
	__le32	mmp_seq;		 

	__le64	mmp_time;		 
	char	mmp_nodename[64];	 
	char	mmp_bdevname[32];	 

	__le16	mmp_check_interval;

	__le16	mmp_pad1;
	__le32	mmp_pad2[226];
	__le32	mmp_checksum;		 
};

struct mmpd_data {
	struct buffer_head *bh;  
	struct super_block *sb;   
};

#define EXT4_MMP_CHECK_MULT		2UL

#define EXT4_MMP_MIN_CHECK_INTERVAL	5UL

#define EXT4_MMP_MAX_CHECK_INTERVAL	300UL

# define NORET_TYPE	 
# define ATTRIB_NORET	__attribute__((noreturn))
# define NORET_AND	noreturn,

extern unsigned int ext4_count_free(char *bitmap, unsigned numchars);
void ext4_inode_bitmap_csum_set(struct super_block *sb, ext4_group_t group,
				struct ext4_group_desc *gdp,
				struct buffer_head *bh, int sz);
int ext4_inode_bitmap_csum_verify(struct super_block *sb, ext4_group_t group,
				  struct ext4_group_desc *gdp,
				  struct buffer_head *bh, int sz);
void ext4_block_bitmap_csum_set(struct super_block *sb, ext4_group_t group,
				struct ext4_group_desc *gdp,
				struct buffer_head *bh);
int ext4_block_bitmap_csum_verify(struct super_block *sb, ext4_group_t group,
				  struct ext4_group_desc *gdp,
				  struct buffer_head *bh);

extern void ext4_get_group_no_and_offset(struct super_block *sb,
					 ext4_fsblk_t blocknr,
					 ext4_group_t *blockgrpp,
					 ext4_grpblk_t *offsetp);
extern ext4_group_t ext4_get_group_number(struct super_block *sb,
					  ext4_fsblk_t block);

extern unsigned int ext4_block_group(struct super_block *sb,
			ext4_fsblk_t blocknr);
extern ext4_grpblk_t ext4_block_group_offset(struct super_block *sb,
			ext4_fsblk_t blocknr);
extern int ext4_bg_has_super(struct super_block *sb, ext4_group_t group);
extern unsigned long ext4_bg_num_gdb(struct super_block *sb,
			ext4_group_t group);
extern ext4_fsblk_t ext4_new_meta_blocks(handle_t *handle, struct inode *inode,
					 ext4_fsblk_t goal,
					 unsigned int flags,
					 unsigned long *count,
					 int *errp);
extern int ext4_claim_free_clusters(struct ext4_sb_info *sbi,
				    s64 nclusters, unsigned int flags);
extern ext4_fsblk_t ext4_count_free_clusters(struct super_block *);
extern void ext4_check_blocks_bitmap(struct super_block *);
extern struct ext4_group_desc * ext4_get_group_desc(struct super_block * sb,
						    ext4_group_t block_group,
						    struct buffer_head ** bh);
extern int ext4_should_retry_alloc(struct super_block *sb, int *retries);

extern struct buffer_head *ext4_read_block_bitmap_nowait(struct super_block *sb,
						ext4_group_t block_group);
extern int ext4_wait_block_bitmap(struct super_block *sb,
				  ext4_group_t block_group,
				  struct buffer_head *bh);
extern struct buffer_head *ext4_read_block_bitmap(struct super_block *sb,
						  ext4_group_t block_group);
extern unsigned ext4_free_clusters_after_init(struct super_block *sb,
					      ext4_group_t block_group,
					      struct ext4_group_desc *gdp);
ext4_fsblk_t ext4_inode_to_goal_block(struct inode *);

int ext4_is_child_context_consistent_with_parent(struct inode *parent,
						 struct inode *child);
int ext4_inherit_context(struct inode *parent, struct inode *child);
void ext4_to_hex(char *dst, char *src, size_t src_size);
int ext4_process_policy(const struct ext4_encryption_policy *policy,
			struct inode *inode);
int ext4_get_policy(struct inode *inode,
		    struct ext4_encryption_policy *policy);

extern struct kmem_cache *ext4_crypt_info_cachep;
bool ext4_valid_contents_enc_mode(uint32_t mode);
uint32_t ext4_validate_encryption_key_size(uint32_t mode, uint32_t size);
extern struct workqueue_struct *ext4_read_workqueue;
struct ext4_crypto_ctx *ext4_get_crypto_ctx(struct inode *inode);
void ext4_release_crypto_ctx(struct ext4_crypto_ctx *ctx);
void ext4_restore_control_page(struct page *data_page);
struct page *ext4_encrypt(struct inode *inode,
			  struct page *plaintext_page);
int ext4_decrypt(struct page *page);
int ext4_encrypted_zeroout(struct inode *inode, struct ext4_extent *ex);

#ifdef CONFIG_EXT4_FS_ENCRYPTION
int ext4_init_crypto(void);
void ext4_exit_crypto(void);
static inline int ext4_sb_has_crypto(struct super_block *sb)
{
	return ext4_has_feature_encrypt(sb);
}
#else
static inline int ext4_init_crypto(void) { return 0; }
static inline void ext4_exit_crypto(void) { }
static inline int ext4_sb_has_crypto(struct super_block *sb)
{
	return 0;
}
#endif

bool ext4_valid_filenames_enc_mode(uint32_t mode);
u32 ext4_fname_crypto_round_up(u32 size, u32 blksize);
unsigned ext4_fname_encrypted_size(struct inode *inode, u32 ilen);
int ext4_fname_crypto_alloc_buffer(struct inode *inode,
				   u32 ilen, struct ext4_str *crypto_str);
int _ext4_fname_disk_to_usr(struct inode *inode,
			    struct dx_hash_info *hinfo,
			    const struct ext4_str *iname,
			    struct ext4_str *oname);
int ext4_fname_disk_to_usr(struct inode *inode,
			   struct dx_hash_info *hinfo,
			   const struct ext4_dir_entry_2 *de,
			   struct ext4_str *oname);
int ext4_fname_usr_to_disk(struct inode *inode,
			   const struct qstr *iname,
			   struct ext4_str *oname);
#ifdef CONFIG_EXT4_FS_ENCRYPTION
void ext4_fname_crypto_free_buffer(struct ext4_str *crypto_str);
int ext4_fname_setup_filename(struct inode *dir, const struct qstr *iname,
			      int lookup, struct ext4_filename *fname);
void ext4_fname_free_filename(struct ext4_filename *fname);
#else
static inline
int ext4_setup_fname_crypto(struct inode *inode)
{
	return 0;
}
static inline void ext4_fname_crypto_free_buffer(struct ext4_str *p) { }
static inline int ext4_fname_setup_filename(struct inode *dir,
				     const struct qstr *iname,
				     int lookup, struct ext4_filename *fname)
{
	fname->usr_fname = iname;
	fname->disk_name.name = (unsigned char *) iname->name;
	fname->disk_name.len = iname->len;
	return 0;
}
static inline void ext4_fname_free_filename(struct ext4_filename *fname) { }
#endif

void ext4_free_crypt_info(struct ext4_crypt_info *ci);
void ext4_free_encryption_info(struct inode *inode, struct ext4_crypt_info *ci);

#ifdef CONFIG_EXT4_FS_ENCRYPTION
int ext4_has_encryption_key(struct inode *inode);

int ext4_get_encryption_info(struct inode *inode);

static inline struct ext4_crypt_info *ext4_encryption_info(struct inode *inode)
{
	return EXT4_I(inode)->i_crypt_info;
}

#else
static inline int ext4_has_encryption_key(struct inode *inode)
{
	return 0;
}
static inline int ext4_get_encryption_info(struct inode *inode)
{
	return 0;
}
static inline struct ext4_crypt_info *ext4_encryption_info(struct inode *inode)
{
	return NULL;
}
#endif

extern int __ext4_check_dir_entry(const char *, unsigned int, struct inode *,
				  struct file *,
				  struct ext4_dir_entry_2 *,
				  struct buffer_head *, char *, int,
				  unsigned int);
#define ext4_check_dir_entry(dir, filp, de, bh, buf, size, offset)	\
	unlikely(__ext4_check_dir_entry(__func__, __LINE__, (dir), (filp), \
					(de), (bh), (buf), (size), (offset)))
extern int ext4_htree_store_dirent(struct file *dir_file, __u32 hash,
				__u32 minor_hash,
				struct ext4_dir_entry_2 *dirent,
				struct ext4_str *ent_name);
extern void ext4_htree_free_dir_info(struct dir_private_info *p);
extern int ext4_find_dest_de(struct inode *dir, struct inode *inode,
			     struct buffer_head *bh,
			     void *buf, int buf_size,
			     struct ext4_filename *fname,
			     struct ext4_dir_entry_2 **dest_de);
int ext4_insert_dentry(struct inode *dir,
		       struct inode *inode,
		       struct ext4_dir_entry_2 *de,
		       int buf_size,
		       struct ext4_filename *fname);
static inline void ext4_update_dx_flag(struct inode *inode)
{
#ifdef MY_ABC_HERE
	if (EXT4_SB(inode->i_sb)->s_es->s_syno_hash_magic != cpu_to_le32(SYNO_HASH_MAGIC))
#else
	if (!ext4_has_feature_dir_index(inode->i_sb))
#endif  
		ext4_clear_inode_flag(inode, EXT4_INODE_INDEX);
}
static unsigned char ext4_filetype_table[] = {
	DT_UNKNOWN, DT_REG, DT_DIR, DT_CHR, DT_BLK, DT_FIFO, DT_SOCK, DT_LNK
};

static inline  unsigned char get_dtype(struct super_block *sb, int filetype)
{
	if (!ext4_has_feature_filetype(sb) || filetype >= EXT4_FT_MAX)
		return DT_UNKNOWN;

	return ext4_filetype_table[filetype];
}
extern int ext4_check_all_de(struct inode *dir, struct buffer_head *bh,
			     void *buf, int buf_size);

extern int ext4_sync_file(struct file *, loff_t, loff_t, int);

extern int ext4fs_dirhash(const char *name, int len, struct
			  dx_hash_info *hinfo);

extern struct inode *__ext4_new_inode(handle_t *, struct inode *, umode_t,
				      const struct qstr *qstr, __u32 goal,
				      uid_t *owner, int handle_type,
				      unsigned int line_no, int nblocks);

#define ext4_new_inode(handle, dir, mode, qstr, goal, owner) \
	__ext4_new_inode((handle), (dir), (mode), (qstr), (goal), (owner), \
			 0, 0, 0)
#define ext4_new_inode_start_handle(dir, mode, qstr, goal, owner, \
				    type, nblocks)		    \
	__ext4_new_inode(NULL, (dir), (mode), (qstr), (goal), (owner), \
			 (type), __LINE__, (nblocks))

extern void ext4_free_inode(handle_t *, struct inode *);
extern struct inode * ext4_orphan_get(struct super_block *, unsigned long);
extern unsigned long ext4_count_free_inodes(struct super_block *);
extern unsigned long ext4_count_dirs(struct super_block *);
extern void ext4_check_inodes_bitmap(struct super_block *);
extern void ext4_mark_bitmap_end(int start_bit, int end_bit, char *bitmap);
extern int ext4_init_inode_table(struct super_block *sb,
				 ext4_group_t group, int barrier);
extern void ext4_end_bitmap_read(struct buffer_head *bh, int uptodate);

extern const struct file_operations ext4_seq_mb_groups_fops;
extern long ext4_mb_stats;
extern long ext4_mb_max_to_scan;
extern int ext4_mb_init(struct super_block *);
extern int ext4_mb_release(struct super_block *);
extern ext4_fsblk_t ext4_mb_new_blocks(handle_t *,
				struct ext4_allocation_request *, int *);
extern int ext4_mb_reserve_blocks(struct super_block *, int);
extern void ext4_discard_preallocations(struct inode *);
extern int __init ext4_init_mballoc(void);
extern void ext4_exit_mballoc(void);
extern void ext4_free_blocks(handle_t *handle, struct inode *inode,
			     struct buffer_head *bh, ext4_fsblk_t block,
			     unsigned long count, int flags);
extern int ext4_mb_alloc_groupinfo(struct super_block *sb,
				   ext4_group_t ngroups);
extern int ext4_mb_add_groupinfo(struct super_block *sb,
		ext4_group_t i, struct ext4_group_desc *desc);
extern int ext4_group_add_blocks(handle_t *handle, struct super_block *sb,
				ext4_fsblk_t block, unsigned long count);
extern int ext4_trim_fs(struct super_block *, struct fstrim_range *);

int ext4_inode_is_fast_symlink(struct inode *inode);
struct buffer_head *ext4_getblk(handle_t *, struct inode *, ext4_lblk_t, int);
struct buffer_head *ext4_bread(handle_t *, struct inode *, ext4_lblk_t, int);
int ext4_get_block_write(struct inode *inode, sector_t iblock,
			 struct buffer_head *bh_result, int create);
int ext4_get_block_dax(struct inode *inode, sector_t iblock,
			 struct buffer_head *bh_result, int create);
int ext4_get_block(struct inode *inode, sector_t iblock,
				struct buffer_head *bh_result, int create);
int ext4_da_get_block_prep(struct inode *inode, sector_t iblock,
			   struct buffer_head *bh, int create);
int ext4_walk_page_buffers(handle_t *handle,
			   struct buffer_head *head,
			   unsigned from,
			   unsigned to,
			   int *partial,
			   int (*fn)(handle_t *handle,
				     struct buffer_head *bh));
int do_journal_get_write_access(handle_t *handle,
				struct buffer_head *bh);
#define FALL_BACK_TO_NONDELALLOC 1
#define CONVERT_INLINE_DATA	 2

extern struct inode *ext4_iget(struct super_block *, unsigned long);
extern struct inode *ext4_iget_normal(struct super_block *, unsigned long);
extern int  ext4_write_inode(struct inode *, struct writeback_control *);
extern int  ext4_setattr(struct dentry *, struct iattr *);
extern int  ext4_getattr(struct vfsmount *mnt, struct dentry *dentry,
				struct kstat *stat);
extern void ext4_evict_inode(struct inode *);
extern void ext4_clear_inode(struct inode *);
extern int  ext4_sync_inode(handle_t *, struct inode *);
extern void ext4_dirty_inode(struct inode *, int);
extern int ext4_change_inode_journal_flag(struct inode *, int);
extern int ext4_get_inode_loc(struct inode *, struct ext4_iloc *);
extern int ext4_inode_attach_jinode(struct inode *inode);
extern int ext4_can_truncate(struct inode *inode);
extern void ext4_truncate(struct inode *);
extern int ext4_punch_hole(struct inode *inode, loff_t offset, loff_t length);
extern int ext4_truncate_restart_trans(handle_t *, struct inode *, int nblocks);
extern void ext4_set_inode_flags(struct inode *);
extern void ext4_get_inode_flags(struct ext4_inode_info *);
extern int ext4_alloc_da_blocks(struct inode *inode);
extern void ext4_set_aops(struct inode *inode);
#ifdef MY_ABC_HERE
extern void ext4_set_writeback_aops(struct inode *inode);
#endif  
extern int ext4_writepage_trans_blocks(struct inode *);
extern int ext4_chunk_trans_blocks(struct inode *, int nrblocks);
extern int ext4_zero_partial_blocks(handle_t *handle, struct inode *inode,
			     loff_t lstart, loff_t lend);
extern int ext4_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf);
extern int ext4_filemap_fault(struct vm_area_struct *vma, struct vm_fault *vmf);
extern qsize_t *ext4_get_reserved_space(struct inode *inode);
extern void ext4_da_update_reserve_space(struct inode *inode,
					int used, int quota_claim);
#ifdef MY_ABC_HERE
extern int ext4_syno_getattr(struct dentry *d, struct kstat *stat, int flags);
#endif  
#ifdef MY_ABC_HERE
extern int ext4_syno_get_archive_ver(struct dentry *d, u32 *);
extern int ext4_syno_set_archive_ver(struct dentry *d, u32);
#endif  

extern int ext4_ind_map_blocks(handle_t *handle, struct inode *inode,
				struct ext4_map_blocks *map, int flags);
extern ssize_t ext4_ind_direct_IO(struct kiocb *iocb, struct iov_iter *iter,
				  loff_t offset);
extern int ext4_ind_calc_metadata_amount(struct inode *inode, sector_t lblock);
extern int ext4_ind_trans_blocks(struct inode *inode, int nrblocks);
extern void ext4_ind_truncate(handle_t *, struct inode *inode);
extern int ext4_ind_remove_space(handle_t *handle, struct inode *inode,
				 ext4_lblk_t start, ext4_lblk_t end);

extern long ext4_ioctl(struct file *, unsigned int, unsigned long);
extern long ext4_compat_ioctl(struct file *, unsigned int, unsigned long);

extern int ext4_ext_migrate(struct inode *);
extern int ext4_ind_migrate(struct inode *inode);

extern int ext4_dirent_csum_verify(struct inode *inode,
				   struct ext4_dir_entry *dirent);
extern int ext4_orphan_add(handle_t *, struct inode *);
extern int ext4_orphan_del(handle_t *, struct inode *);
extern int ext4_htree_fill_tree(struct file *dir_file, __u32 start_hash,
				__u32 start_minor_hash, __u32 *next_hash);
#ifdef MY_ABC_HERE
extern int ext4_search_dir(struct buffer_head *bh,
			   char *search_buf,
			   int buf_size,
			   struct inode *dir,
			   struct ext4_filename *fname,
			   const struct qstr *d_name,
			   unsigned int offset,
			   struct ext4_dir_entry_2 **res_dir,
			   int caseless);
#else
extern int ext4_search_dir(struct buffer_head *bh,
			   char *search_buf,
			   int buf_size,
			   struct inode *dir,
			   struct ext4_filename *fname,
			   const struct qstr *d_name,
			   unsigned int offset,
			   struct ext4_dir_entry_2 **res_dir);
#endif  
extern int ext4_generic_delete_entry(handle_t *handle,
				     struct inode *dir,
				     struct ext4_dir_entry_2 *de_del,
				     struct buffer_head *bh,
				     void *entry_buf,
				     int buf_size,
				     int csum_size);
extern int ext4_empty_dir(struct inode *inode);

extern int ext4_group_add(struct super_block *sb,
				struct ext4_new_group_data *input);
extern int ext4_group_extend(struct super_block *sb,
				struct ext4_super_block *es,
				ext4_fsblk_t n_blocks_count);
extern int ext4_resize_fs(struct super_block *sb, ext4_fsblk_t n_blocks_count);

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
extern int ext4_is_ext3_sb(struct super_block *sb);
#endif  
extern int ext4_seq_options_show(struct seq_file *seq, void *offset);
extern int ext4_calculate_overhead(struct super_block *sb);
extern void ext4_superblock_csum_set(struct super_block *sb);
extern void *ext4_kvmalloc(size_t size, gfp_t flags);
extern void *ext4_kvzalloc(size_t size, gfp_t flags);
extern int ext4_alloc_flex_bg_array(struct super_block *sb,
				    ext4_group_t ngroup);
extern const char *ext4_decode_error(struct super_block *sb, int errno,
				     char nbuf[16]);

extern __printf(4, 5)
void __ext4_error(struct super_block *, const char *, unsigned int,
		  const char *, ...);
extern __printf(5, 6)
void __ext4_error_inode(struct inode *, const char *, unsigned int, ext4_fsblk_t,
		      const char *, ...);
extern __printf(5, 6)
void __ext4_error_file(struct file *, const char *, unsigned int, ext4_fsblk_t,
		     const char *, ...);
extern void __ext4_std_error(struct super_block *, const char *,
			     unsigned int, int);
extern __printf(4, 5)
void __ext4_abort(struct super_block *, const char *, unsigned int,
		  const char *, ...);
extern __printf(4, 5)
void __ext4_warning(struct super_block *, const char *, unsigned int,
		    const char *, ...);
extern __printf(4, 5)
void __ext4_warning_inode(const struct inode *inode, const char *function,
			  unsigned int line, const char *fmt, ...);
extern __printf(3, 4)
void __ext4_msg(struct super_block *, const char *, const char *, ...);
extern void __dump_mmp_msg(struct super_block *, struct mmp_struct *mmp,
			   const char *, unsigned int, const char *);
extern __printf(7, 8)
void __ext4_grp_locked_error(const char *, unsigned int,
			     struct super_block *, ext4_group_t,
			     unsigned long, ext4_fsblk_t,
			     const char *, ...);

#define EXT4_ERROR_INODE(inode, fmt, a...) \
	ext4_error_inode((inode), __func__, __LINE__, 0, (fmt), ## a)

#define EXT4_ERROR_INODE_BLOCK(inode, block, fmt, a...)			\
	ext4_error_inode((inode), __func__, __LINE__, (block), (fmt), ## a)

#define EXT4_ERROR_FILE(file, block, fmt, a...)				\
	ext4_error_file((file), __func__, __LINE__, (block), (fmt), ## a)

#ifdef CONFIG_PRINTK

#define ext4_error_inode(inode, func, line, block, fmt, ...)		\
	__ext4_error_inode(inode, func, line, block, fmt, ##__VA_ARGS__)
#define ext4_error_file(file, func, line, block, fmt, ...)		\
	__ext4_error_file(file, func, line, block, fmt, ##__VA_ARGS__)
#define ext4_error(sb, fmt, ...)					\
	__ext4_error(sb, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define ext4_abort(sb, fmt, ...)					\
	__ext4_abort(sb, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define ext4_warning(sb, fmt, ...)					\
	__ext4_warning(sb, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define ext4_warning_inode(inode, fmt, ...)				\
	__ext4_warning_inode(inode, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define ext4_msg(sb, level, fmt, ...)				\
	__ext4_msg(sb, level, fmt, ##__VA_ARGS__)
#define dump_mmp_msg(sb, mmp, msg)					\
	__dump_mmp_msg(sb, mmp, __func__, __LINE__, msg)
#define ext4_grp_locked_error(sb, grp, ino, block, fmt, ...)		\
	__ext4_grp_locked_error(__func__, __LINE__, sb, grp, ino, block, \
				fmt, ##__VA_ARGS__)

#else

#define ext4_error_inode(inode, func, line, block, fmt, ...)		\
do {									\
	no_printk(fmt, ##__VA_ARGS__);					\
	__ext4_error_inode(inode, "", 0, block, " ");			\
} while (0)
#define ext4_error_file(file, func, line, block, fmt, ...)		\
do {									\
	no_printk(fmt, ##__VA_ARGS__);					\
	__ext4_error_file(file, "", 0, block, " ");			\
} while (0)
#define ext4_error(sb, fmt, ...)					\
do {									\
	no_printk(fmt, ##__VA_ARGS__);					\
	__ext4_error(sb, "", 0, " ");					\
} while (0)
#define ext4_abort(sb, fmt, ...)					\
do {									\
	no_printk(fmt, ##__VA_ARGS__);					\
	__ext4_abort(sb, "", 0, " ");					\
} while (0)
#define ext4_warning(sb, fmt, ...)					\
do {									\
	no_printk(fmt, ##__VA_ARGS__);					\
	__ext4_warning(sb, "", 0, " ");					\
} while (0)
#define ext4_warning_inode(inode, fmt, ...)				\
do {									\
	no_printk(fmt, ##__VA_ARGS__);					\
	__ext4_warning_inode(inode, "", 0, " ");			\
} while (0)
#define ext4_msg(sb, level, fmt, ...)					\
do {									\
	no_printk(fmt, ##__VA_ARGS__);					\
	__ext4_msg(sb, "", " ");					\
} while (0)
#define dump_mmp_msg(sb, mmp, msg)					\
	__dump_mmp_msg(sb, mmp, "", 0, "")
#define ext4_grp_locked_error(sb, grp, ino, block, fmt, ...)		\
do {									\
	no_printk(fmt, ##__VA_ARGS__);				\
	__ext4_grp_locked_error("", 0, sb, grp, ino, block, " ");	\
} while (0)

#endif

extern void ext4_update_dynamic_rev(struct super_block *sb);
extern int ext4_update_compat_feature(handle_t *handle, struct super_block *sb,
					__u32 compat);
extern int ext4_update_rocompat_feature(handle_t *handle,
					struct super_block *sb,	__u32 rocompat);
extern int ext4_update_incompat_feature(handle_t *handle,
					struct super_block *sb,	__u32 incompat);
extern ext4_fsblk_t ext4_block_bitmap(struct super_block *sb,
				      struct ext4_group_desc *bg);
extern ext4_fsblk_t ext4_inode_bitmap(struct super_block *sb,
				      struct ext4_group_desc *bg);
extern ext4_fsblk_t ext4_inode_table(struct super_block *sb,
				     struct ext4_group_desc *bg);
extern __u32 ext4_free_group_clusters(struct super_block *sb,
				      struct ext4_group_desc *bg);
extern __u32 ext4_free_inodes_count(struct super_block *sb,
				 struct ext4_group_desc *bg);
extern __u32 ext4_used_dirs_count(struct super_block *sb,
				struct ext4_group_desc *bg);
extern __u32 ext4_itable_unused_count(struct super_block *sb,
				   struct ext4_group_desc *bg);
extern void ext4_block_bitmap_set(struct super_block *sb,
				  struct ext4_group_desc *bg, ext4_fsblk_t blk);
extern void ext4_inode_bitmap_set(struct super_block *sb,
				  struct ext4_group_desc *bg, ext4_fsblk_t blk);
extern void ext4_inode_table_set(struct super_block *sb,
				 struct ext4_group_desc *bg, ext4_fsblk_t blk);
extern void ext4_free_group_clusters_set(struct super_block *sb,
					 struct ext4_group_desc *bg,
					 __u32 count);
extern void ext4_free_inodes_set(struct super_block *sb,
				struct ext4_group_desc *bg, __u32 count);
extern void ext4_used_dirs_set(struct super_block *sb,
				struct ext4_group_desc *bg, __u32 count);
extern void ext4_itable_unused_set(struct super_block *sb,
				   struct ext4_group_desc *bg, __u32 count);
extern int ext4_group_desc_csum_verify(struct super_block *sb, __u32 group,
				       struct ext4_group_desc *gdp);
extern void ext4_group_desc_csum_set(struct super_block *sb, __u32 group,
				     struct ext4_group_desc *gdp);
extern int ext4_register_li_request(struct super_block *sb,
				    ext4_group_t first_not_zeroed);

static inline int ext4_has_group_desc_csum(struct super_block *sb)
{
	return ext4_has_feature_gdt_csum(sb) ||
	       EXT4_SB(sb)->s_chksum_driver != NULL;
}

static inline int ext4_has_metadata_csum(struct super_block *sb)
{
	WARN_ON_ONCE(ext4_has_feature_metadata_csum(sb) &&
		     !EXT4_SB(sb)->s_chksum_driver);

	return (EXT4_SB(sb)->s_chksum_driver != NULL);
}
static inline ext4_fsblk_t ext4_blocks_count(struct ext4_super_block *es)
{
	return ((ext4_fsblk_t)le32_to_cpu(es->s_blocks_count_hi) << 32) |
		le32_to_cpu(es->s_blocks_count_lo);
}

static inline ext4_fsblk_t ext4_r_blocks_count(struct ext4_super_block *es)
{
	return ((ext4_fsblk_t)le32_to_cpu(es->s_r_blocks_count_hi) << 32) |
		le32_to_cpu(es->s_r_blocks_count_lo);
}

static inline ext4_fsblk_t ext4_free_blocks_count(struct ext4_super_block *es)
{
	return ((ext4_fsblk_t)le32_to_cpu(es->s_free_blocks_count_hi) << 32) |
		le32_to_cpu(es->s_free_blocks_count_lo);
}

static inline void ext4_blocks_count_set(struct ext4_super_block *es,
					 ext4_fsblk_t blk)
{
	es->s_blocks_count_lo = cpu_to_le32((u32)blk);
	es->s_blocks_count_hi = cpu_to_le32(blk >> 32);
}

static inline void ext4_free_blocks_count_set(struct ext4_super_block *es,
					      ext4_fsblk_t blk)
{
	es->s_free_blocks_count_lo = cpu_to_le32((u32)blk);
	es->s_free_blocks_count_hi = cpu_to_le32(blk >> 32);
}

static inline void ext4_r_blocks_count_set(struct ext4_super_block *es,
					   ext4_fsblk_t blk)
{
	es->s_r_blocks_count_lo = cpu_to_le32((u32)blk);
	es->s_r_blocks_count_hi = cpu_to_le32(blk >> 32);
}

static inline loff_t ext4_isize(struct ext4_inode *raw_inode)
{
	if (S_ISREG(le16_to_cpu(raw_inode->i_mode)))
		return ((loff_t)le32_to_cpu(raw_inode->i_size_high) << 32) |
			le32_to_cpu(raw_inode->i_size_lo);
	else
		return (loff_t) le32_to_cpu(raw_inode->i_size_lo);
}

static inline void ext4_isize_set(struct ext4_inode *raw_inode, loff_t i_size)
{
	raw_inode->i_size_lo = cpu_to_le32(i_size);
	raw_inode->i_size_high = cpu_to_le32(i_size >> 32);
}

static inline
struct ext4_group_info *ext4_get_group_info(struct super_block *sb,
					    ext4_group_t group)
{
	 struct ext4_group_info ***grp_info;
	 long indexv, indexh;
	 BUG_ON(group >= EXT4_SB(sb)->s_groups_count);
	 grp_info = EXT4_SB(sb)->s_group_info;
	 indexv = group >> (EXT4_DESC_PER_BLOCK_BITS(sb));
	 indexh = group & ((EXT4_DESC_PER_BLOCK(sb)) - 1);
	 return grp_info[indexv][indexh];
}

static inline ext4_group_t ext4_get_groups_count(struct super_block *sb)
{
	ext4_group_t	ngroups = EXT4_SB(sb)->s_groups_count;

	smp_rmb();
	return ngroups;
}

static inline ext4_group_t ext4_flex_group(struct ext4_sb_info *sbi,
					     ext4_group_t block_group)
{
	return block_group >> sbi->s_log_groups_per_flex;
}

static inline unsigned int ext4_flex_bg_size(struct ext4_sb_info *sbi)
{
	return 1 << sbi->s_log_groups_per_flex;
}

#define ext4_std_error(sb, errno)				\
do {								\
	if ((errno))						\
		__ext4_std_error((sb), __func__, __LINE__, (errno));	\
} while (0)

#ifdef CONFIG_SMP
 
#define EXT4_FREECLUSTERS_WATERMARK (4 * (percpu_counter_batch * nr_cpu_ids))
#else
#define EXT4_FREECLUSTERS_WATERMARK 0
#endif

static inline void ext4_update_i_disksize(struct inode *inode, loff_t newsize)
{
	WARN_ON_ONCE(S_ISREG(inode->i_mode) &&
		     !inode_is_locked(inode));
	down_write(&EXT4_I(inode)->i_data_sem);
	if (newsize > EXT4_I(inode)->i_disksize)
		EXT4_I(inode)->i_disksize = newsize;
	up_write(&EXT4_I(inode)->i_data_sem);
}

static inline int ext4_update_inode_size(struct inode *inode, loff_t newsize)
{
	int changed = 0;

	if (newsize > inode->i_size) {
		i_size_write(inode, newsize);
		changed = 1;
	}
	if (newsize > EXT4_I(inode)->i_disksize) {
		ext4_update_i_disksize(inode, newsize);
		changed |= 2;
	}
	return changed;
}

int ext4_update_disksize_before_punch(struct inode *inode, loff_t offset,
				      loff_t len);

struct ext4_group_info {
	unsigned long   bb_state;
	struct rb_root  bb_free_root;
	ext4_grpblk_t	bb_first_free;	 
	ext4_grpblk_t	bb_free;	 
	ext4_grpblk_t	bb_fragments;	 
	ext4_grpblk_t	bb_largest_free_order; 
	struct          list_head bb_prealloc_list;
#ifdef DOUBLE_CHECK
	void            *bb_bitmap;
#endif
	struct rw_semaphore alloc_sem;
	ext4_grpblk_t	bb_counters[];	 
};

#define EXT4_GROUP_INFO_NEED_INIT_BIT		0
#define EXT4_GROUP_INFO_WAS_TRIMMED_BIT		1
#define EXT4_GROUP_INFO_BBITMAP_CORRUPT_BIT	2
#define EXT4_GROUP_INFO_IBITMAP_CORRUPT_BIT	3

#define EXT4_MB_GRP_NEED_INIT(grp)	\
	(test_bit(EXT4_GROUP_INFO_NEED_INIT_BIT, &((grp)->bb_state)))
#define EXT4_MB_GRP_BBITMAP_CORRUPT(grp)	\
	(test_bit(EXT4_GROUP_INFO_BBITMAP_CORRUPT_BIT, &((grp)->bb_state)))
#define EXT4_MB_GRP_IBITMAP_CORRUPT(grp)	\
	(test_bit(EXT4_GROUP_INFO_IBITMAP_CORRUPT_BIT, &((grp)->bb_state)))

#define EXT4_MB_GRP_WAS_TRIMMED(grp)	\
	(test_bit(EXT4_GROUP_INFO_WAS_TRIMMED_BIT, &((grp)->bb_state)))
#define EXT4_MB_GRP_SET_TRIMMED(grp)	\
	(set_bit(EXT4_GROUP_INFO_WAS_TRIMMED_BIT, &((grp)->bb_state)))
#define EXT4_MB_GRP_CLEAR_TRIMMED(grp)	\
	(clear_bit(EXT4_GROUP_INFO_WAS_TRIMMED_BIT, &((grp)->bb_state)))

#define EXT4_MAX_CONTENTION		8
#define EXT4_CONTENTION_THRESHOLD	2

static inline spinlock_t *ext4_group_lock_ptr(struct super_block *sb,
					      ext4_group_t group)
{
	return bgl_lock_ptr(EXT4_SB(sb)->s_blockgroup_lock, group);
}

static inline int ext4_fs_is_busy(struct ext4_sb_info *sbi)
{
	return (atomic_read(&sbi->s_lock_busy) > EXT4_CONTENTION_THRESHOLD);
}

static inline void ext4_lock_group(struct super_block *sb, ext4_group_t group)
{
	spinlock_t *lock = ext4_group_lock_ptr(sb, group);
	if (spin_trylock(lock))
		 
		atomic_add_unless(&EXT4_SB(sb)->s_lock_busy, -1, 0);
	else {
		 
		atomic_add_unless(&EXT4_SB(sb)->s_lock_busy, 1,
				  EXT4_MAX_CONTENTION);
		spin_lock(lock);
	}
}

static inline void ext4_unlock_group(struct super_block *sb,
					ext4_group_t group)
{
	spin_unlock(ext4_group_lock_ptr(sb, group));
}

#define ext4_check_indirect_blockref(inode, bh)				\
	ext4_check_blockref(__func__, __LINE__, inode,			\
			    (__le32 *)(bh)->b_data,			\
			    EXT4_ADDR_PER_BLOCK((inode)->i_sb))

#define ext4_ind_check_inode(inode)					\
	ext4_check_blockref(__func__, __LINE__, inode,			\
			    EXT4_I(inode)->i_data,			\
			    EXT4_NDIR_BLOCKS)

extern const struct file_operations ext4_dir_operations;

extern const struct inode_operations ext4_file_inode_operations;
extern const struct file_operations ext4_file_operations;
extern loff_t ext4_llseek(struct file *file, loff_t offset, int origin);

extern int ext4_get_max_inline_size(struct inode *inode);
extern int ext4_find_inline_data_nolock(struct inode *inode);
extern int ext4_init_inline_data(handle_t *handle, struct inode *inode,
				 unsigned int len);
extern int ext4_destroy_inline_data(handle_t *handle, struct inode *inode);

extern int ext4_readpage_inline(struct inode *inode, struct page *page);
extern int ext4_try_to_write_inline_data(struct address_space *mapping,
					 struct inode *inode,
					 loff_t pos, unsigned len,
					 unsigned flags,
					 struct page **pagep);
extern int ext4_write_inline_data_end(struct inode *inode,
				      loff_t pos, unsigned len,
				      unsigned copied,
				      struct page *page);
extern struct buffer_head *
ext4_journalled_write_inline_data(struct inode *inode,
				  unsigned len,
				  struct page *page);
extern int ext4_da_write_inline_data_begin(struct address_space *mapping,
					   struct inode *inode,
					   loff_t pos, unsigned len,
					   unsigned flags,
					   struct page **pagep,
					   void **fsdata);
extern int ext4_da_write_inline_data_end(struct inode *inode, loff_t pos,
					 unsigned len, unsigned copied,
					 struct page *page);
extern int ext4_try_add_inline_entry(handle_t *handle,
				     struct ext4_filename *fname,
				     struct dentry *dentry,
				     struct inode *inode);
extern int ext4_try_create_inline_dir(handle_t *handle,
				      struct inode *parent,
				      struct inode *inode);
extern int ext4_read_inline_dir(struct file *filp,
				struct dir_context *ctx,
				int *has_inline_data);
extern int htree_inlinedir_to_tree(struct file *dir_file,
				   struct inode *dir, ext4_lblk_t block,
				   struct dx_hash_info *hinfo,
				   __u32 start_hash, __u32 start_minor_hash,
				   int *has_inline_data);
#ifdef MY_ABC_HERE
extern struct buffer_head *ext4_find_inline_entry(struct inode *dir,
					struct ext4_filename *fname,
					const struct qstr *d_name,
					struct ext4_dir_entry_2 **res_dir,
					int *has_inline_data,
					int caseless);
#else
extern struct buffer_head *ext4_find_inline_entry(struct inode *dir,
					struct ext4_filename *fname,
					const struct qstr *d_name,
					struct ext4_dir_entry_2 **res_dir,
					int *has_inline_data);
#endif  
extern int ext4_delete_inline_entry(handle_t *handle,
				    struct inode *dir,
				    struct ext4_dir_entry_2 *de_del,
				    struct buffer_head *bh,
				    int *has_inline_data);
extern int empty_inline_dir(struct inode *dir, int *has_inline_data);
extern struct buffer_head *ext4_get_first_inline_block(struct inode *inode,
					struct ext4_dir_entry_2 **parent_de,
					int *retval);
extern int ext4_inline_data_fiemap(struct inode *inode,
				   struct fiemap_extent_info *fieinfo,
				   int *has_inline, __u64 start, __u64 len);
extern int ext4_try_to_evict_inline_data(handle_t *handle,
					 struct inode *inode,
					 int needed);
extern void ext4_inline_data_truncate(struct inode *inode, int *has_inline);

extern int ext4_convert_inline_data(struct inode *inode);

static inline int ext4_has_inline_data(struct inode *inode)
{
	return ext4_test_inode_flag(inode, EXT4_INODE_INLINE_DATA) &&
	       EXT4_I(inode)->i_inline_off;
}

extern const struct inode_operations ext4_dir_inode_operations;
extern const struct inode_operations ext4_special_inode_operations;
extern struct dentry *ext4_get_parent(struct dentry *child);
extern struct ext4_dir_entry_2 *ext4_init_dot_dotdot(struct inode *inode,
				 struct ext4_dir_entry_2 *de,
				 int blocksize, int csum_size,
				 unsigned int parent_ino, int dotdot_real_len);
extern void initialize_dirent_tail(struct ext4_dir_entry_tail *t,
				   unsigned int blocksize);
extern int ext4_handle_dirty_dirent_node(handle_t *handle,
					 struct inode *inode,
					 struct buffer_head *bh);
#define S_SHIFT 12
static unsigned char ext4_type_by_mode[S_IFMT >> S_SHIFT] = {
	[S_IFREG >> S_SHIFT]	= EXT4_FT_REG_FILE,
	[S_IFDIR >> S_SHIFT]	= EXT4_FT_DIR,
	[S_IFCHR >> S_SHIFT]	= EXT4_FT_CHRDEV,
	[S_IFBLK >> S_SHIFT]	= EXT4_FT_BLKDEV,
	[S_IFIFO >> S_SHIFT]	= EXT4_FT_FIFO,
	[S_IFSOCK >> S_SHIFT]	= EXT4_FT_SOCK,
	[S_IFLNK >> S_SHIFT]	= EXT4_FT_SYMLINK,
};

static inline void ext4_set_de_type(struct super_block *sb,
				struct ext4_dir_entry_2 *de,
				umode_t mode) {
	if (ext4_has_feature_filetype(sb))
		de->file_type = ext4_type_by_mode[(mode & S_IFMT)>>S_SHIFT];
}

extern int ext4_mpage_readpages(struct address_space *mapping,
				struct list_head *pages, struct page *page,
				unsigned nr_pages);

extern const struct inode_operations ext4_encrypted_symlink_inode_operations;
extern const struct inode_operations ext4_symlink_inode_operations;
extern const struct inode_operations ext4_fast_symlink_inode_operations;

extern int ext4_register_sysfs(struct super_block *sb);
extern void ext4_unregister_sysfs(struct super_block *sb);
extern int __init ext4_init_sysfs(void);
extern void ext4_exit_sysfs(void);

extern void ext4_release_system_zone(struct super_block *sb);
extern int ext4_setup_system_zone(struct super_block *sb);
extern int __init ext4_init_system_zone(void);
extern void ext4_exit_system_zone(void);
extern int ext4_data_block_valid(struct ext4_sb_info *sbi,
				 ext4_fsblk_t start_blk,
				 unsigned int count);
extern int ext4_check_blockref(const char *, unsigned int,
			       struct inode *, __le32 *, unsigned int);

struct ext4_ext_path;
struct ext4_extent;

#define EXT_MAX_BLOCKS	0xffffffff

extern int ext4_ext_tree_init(handle_t *handle, struct inode *);
extern int ext4_ext_writepage_trans_blocks(struct inode *, int);
extern int ext4_ext_index_trans_blocks(struct inode *inode, int extents);
extern int ext4_ext_map_blocks(handle_t *handle, struct inode *inode,
			       struct ext4_map_blocks *map, int flags);
extern void ext4_ext_truncate(handle_t *, struct inode *);
extern int ext4_ext_remove_space(struct inode *inode, ext4_lblk_t start,
				 ext4_lblk_t end);
extern void ext4_ext_init(struct super_block *);
extern void ext4_ext_release(struct super_block *);
extern long ext4_fallocate(struct file *file, int mode, loff_t offset,
			  loff_t len);
extern int ext4_convert_unwritten_extents(handle_t *handle, struct inode *inode,
					  loff_t offset, ssize_t len);
extern int ext4_map_blocks(handle_t *handle, struct inode *inode,
			   struct ext4_map_blocks *map, int flags);
extern int ext4_ext_calc_metadata_amount(struct inode *inode,
					 ext4_lblk_t lblocks);
extern int ext4_ext_calc_credits_for_single_extent(struct inode *inode,
						   int num,
						   struct ext4_ext_path *path);
extern int ext4_can_extents_be_merged(struct inode *inode,
				      struct ext4_extent *ex1,
				      struct ext4_extent *ex2);
extern int ext4_ext_insert_extent(handle_t *, struct inode *,
				  struct ext4_ext_path **,
				  struct ext4_extent *, int);
extern struct ext4_ext_path *ext4_find_extent(struct inode *, ext4_lblk_t,
					      struct ext4_ext_path **,
					      int flags);
extern void ext4_ext_drop_refs(struct ext4_ext_path *);
extern int ext4_ext_check_inode(struct inode *inode);
extern int ext4_find_delalloc_range(struct inode *inode,
				    ext4_lblk_t lblk_start,
				    ext4_lblk_t lblk_end);
extern int ext4_find_delalloc_cluster(struct inode *inode, ext4_lblk_t lblk);
extern ext4_lblk_t ext4_ext_next_allocated_block(struct ext4_ext_path *path);
extern int ext4_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
			__u64 start, __u64 len);
extern int ext4_ext_precache(struct inode *inode);
extern int ext4_collapse_range(struct inode *inode, loff_t offset, loff_t len);
extern int ext4_insert_range(struct inode *inode, loff_t offset, loff_t len);
extern int ext4_swap_extents(handle_t *handle, struct inode *inode1,
				struct inode *inode2, ext4_lblk_t lblk1,
			     ext4_lblk_t lblk2,  ext4_lblk_t count,
			     int mark_unwritten,int *err);

extern void ext4_double_down_write_data_sem(struct inode *first,
					    struct inode *second);
extern void ext4_double_up_write_data_sem(struct inode *orig_inode,
					  struct inode *donor_inode);
extern int ext4_move_extents(struct file *o_filp, struct file *d_filp,
			     __u64 start_orig, __u64 start_donor,
			     __u64 len, __u64 *moved_len);

extern int __init ext4_init_pageio(void);
extern void ext4_exit_pageio(void);
extern ext4_io_end_t *ext4_init_io_end(struct inode *inode, gfp_t flags);
extern ext4_io_end_t *ext4_get_io_end(ext4_io_end_t *io_end);
extern int ext4_put_io_end(ext4_io_end_t *io_end);
extern void ext4_put_io_end_defer(ext4_io_end_t *io_end);
extern void ext4_io_submit_init(struct ext4_io_submit *io,
				struct writeback_control *wbc);
extern void ext4_end_io_rsv_work(struct work_struct *work);
extern void ext4_io_submit(struct ext4_io_submit *io);
extern int ext4_bio_write_page(struct ext4_io_submit *io,
			       struct page *page,
			       int len,
			       struct writeback_control *wbc,
			       bool keep_towrite);

extern int ext4_multi_mount_protect(struct super_block *, ext4_fsblk_t);

#define BH_BITMAP_UPTODATE BH_JBDPrivateStart

static inline int bitmap_uptodate(struct buffer_head *bh)
{
	return (buffer_uptodate(bh) &&
			test_bit(BH_BITMAP_UPTODATE, &(bh)->b_state));
}
static inline void set_bitmap_uptodate(struct buffer_head *bh)
{
	set_bit(BH_BITMAP_UPTODATE, &(bh)->b_state);
}

static inline void ext4_inode_block_unlocked_dio(struct inode *inode)
{
	ext4_set_inode_state(inode, EXT4_STATE_DIOREAD_LOCK);
	smp_mb();
}
static inline void ext4_inode_resume_unlocked_dio(struct inode *inode)
{
	smp_mb();
	ext4_clear_inode_state(inode, EXT4_STATE_DIOREAD_LOCK);
}

#define in_range(b, first, len)	((b) >= (first) && (b) <= (first) + (len) - 1)

#define EXT4_WQ_HASH_SZ		37
#define ext4_ioend_wq(v)   (&ext4__ioend_wq[((unsigned long)(v)) %\
					    EXT4_WQ_HASH_SZ])
#define ext4_aio_mutex(v)  (&ext4__aio_mutex[((unsigned long)(v)) %\
					     EXT4_WQ_HASH_SZ])
extern wait_queue_head_t ext4__ioend_wq[EXT4_WQ_HASH_SZ];
extern struct mutex ext4__aio_mutex[EXT4_WQ_HASH_SZ];

#define EXT4_RESIZING	0
extern int ext4_resize_begin(struct super_block *sb);
extern void ext4_resize_end(struct super_block *sb);

#endif	 

#define EFSBADCRC	EBADMSG		 
#define EFSCORRUPTED	EUCLEAN		 

#endif	 
