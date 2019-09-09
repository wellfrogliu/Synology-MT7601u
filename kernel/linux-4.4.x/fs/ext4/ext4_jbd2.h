#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef _EXT4_JBD2_H
#define _EXT4_JBD2_H

#include <linux/fs.h>
#include <linux/jbd2.h>
#include "ext4.h"

#define EXT4_JOURNAL(inode)	(EXT4_SB((inode)->i_sb)->s_journal)

#define EXT4_SINGLEDATA_TRANS_BLOCKS(sb)				\
	(ext4_has_feature_extents(sb) ? 20U : 8U)

#define EXT4_XATTR_TRANS_BLOCKS		6U

#define EXT4_DATA_TRANS_BLOCKS(sb)	(EXT4_SINGLEDATA_TRANS_BLOCKS(sb) + \
					 EXT4_XATTR_TRANS_BLOCKS - 2 + \
					 EXT4_MAXQUOTAS_TRANS_BLOCKS(sb))

#define EXT4_META_TRANS_BLOCKS(sb)	(EXT4_XATTR_TRANS_BLOCKS + \
					EXT4_MAXQUOTAS_TRANS_BLOCKS(sb))

#define EXT4_MAX_TRANS_DATA		64U

#define EXT4_RESERVE_TRANS_BLOCKS	12U

#define EXT4_INDEX_EXTRA_TRANS_BLOCKS	8

#ifdef CONFIG_QUOTA
 
#define EXT4_QUOTA_TRANS_BLOCKS(sb) ((test_opt(sb, QUOTA) ||\
		ext4_has_feature_quota(sb)) ? 1 : 0)
 
#define EXT4_QUOTA_INIT_BLOCKS(sb) ((test_opt(sb, QUOTA) ||\
		ext4_has_feature_quota(sb)) ?\
		(DQUOT_INIT_ALLOC*(EXT4_SINGLEDATA_TRANS_BLOCKS(sb)-3)\
		 +3+DQUOT_INIT_REWRITE) : 0)

#define EXT4_QUOTA_DEL_BLOCKS(sb) ((test_opt(sb, QUOTA) ||\
		ext4_has_feature_quota(sb)) ?\
		(DQUOT_DEL_ALLOC*(EXT4_SINGLEDATA_TRANS_BLOCKS(sb)-3)\
		 +3+DQUOT_DEL_REWRITE) : 0)
#else
#define EXT4_QUOTA_TRANS_BLOCKS(sb) 0
#define EXT4_QUOTA_INIT_BLOCKS(sb) 0
#define EXT4_QUOTA_DEL_BLOCKS(sb) 0
#endif
#define EXT4_MAXQUOTAS_TRANS_BLOCKS(sb) (EXT4_MAXQUOTAS*EXT4_QUOTA_TRANS_BLOCKS(sb))
#define EXT4_MAXQUOTAS_INIT_BLOCKS(sb) (EXT4_MAXQUOTAS*EXT4_QUOTA_INIT_BLOCKS(sb))
#define EXT4_MAXQUOTAS_DEL_BLOCKS(sb) (EXT4_MAXQUOTAS*EXT4_QUOTA_DEL_BLOCKS(sb))

static inline int ext4_jbd2_credits_xattr(struct inode *inode)
{
	int credits = EXT4_DATA_TRANS_BLOCKS(inode->i_sb);

	if (ext4_has_inline_data(inode))
		credits += ext4_writepage_trans_blocks(inode) + 1;
	return credits;
}

#define EXT4_HT_MISC             0
#define EXT4_HT_INODE            1
#define EXT4_HT_WRITE_PAGE       2
#define EXT4_HT_MAP_BLOCKS       3
#define EXT4_HT_DIR              4
#define EXT4_HT_TRUNCATE         5
#define EXT4_HT_QUOTA            6
#define EXT4_HT_RESIZE           7
#define EXT4_HT_MIGRATE          8
#define EXT4_HT_MOVE_EXTENTS     9
#define EXT4_HT_XATTR           10
#define EXT4_HT_EXT_CONVERT     11
#if defined(MY_ABC_HERE)
#define EXT4_HT_SYNO            12
#define EXT4_HT_MAX             13
#else
#define EXT4_HT_MAX             12
#endif  

struct ext4_journal_cb_entry {
	 
	struct list_head jce_list;

	void (*jce_func)(struct super_block *sb,
			 struct ext4_journal_cb_entry *jce, int error);

};

static inline void ext4_journal_callback_add(handle_t *handle,
			void (*func)(struct super_block *sb,
				     struct ext4_journal_cb_entry *jce,
				     int rc),
			struct ext4_journal_cb_entry *jce)
{
	struct ext4_sb_info *sbi =
			EXT4_SB(handle->h_transaction->t_journal->j_private);

	jce->jce_func = func;
	spin_lock(&sbi->s_md_lock);
	list_add_tail(&jce->jce_list, &handle->h_transaction->t_private_list);
	spin_unlock(&sbi->s_md_lock);
}

static inline bool ext4_journal_callback_try_del(handle_t *handle,
					     struct ext4_journal_cb_entry *jce)
{
	bool deleted;
	struct ext4_sb_info *sbi =
			EXT4_SB(handle->h_transaction->t_journal->j_private);

	spin_lock(&sbi->s_md_lock);
	deleted = !list_empty(&jce->jce_list);
	list_del_init(&jce->jce_list);
	spin_unlock(&sbi->s_md_lock);
	return deleted;
}

int
ext4_mark_iloc_dirty(handle_t *handle,
		     struct inode *inode,
		     struct ext4_iloc *iloc);

int ext4_reserve_inode_write(handle_t *handle, struct inode *inode,
			struct ext4_iloc *iloc);

int ext4_mark_inode_dirty(handle_t *handle, struct inode *inode);

int __ext4_journal_get_write_access(const char *where, unsigned int line,
				    handle_t *handle, struct buffer_head *bh);

int __ext4_forget(const char *where, unsigned int line, handle_t *handle,
		  int is_metadata, struct inode *inode,
		  struct buffer_head *bh, ext4_fsblk_t blocknr);

int __ext4_journal_get_create_access(const char *where, unsigned int line,
				handle_t *handle, struct buffer_head *bh);

int __ext4_handle_dirty_metadata(const char *where, unsigned int line,
				 handle_t *handle, struct inode *inode,
				 struct buffer_head *bh);

int __ext4_handle_dirty_super(const char *where, unsigned int line,
			      handle_t *handle, struct super_block *sb);

#define ext4_journal_get_write_access(handle, bh) \
	__ext4_journal_get_write_access(__func__, __LINE__, (handle), (bh))
#define ext4_forget(handle, is_metadata, inode, bh, block_nr) \
	__ext4_forget(__func__, __LINE__, (handle), (is_metadata), (inode), \
		      (bh), (block_nr))
#define ext4_journal_get_create_access(handle, bh) \
	__ext4_journal_get_create_access(__func__, __LINE__, (handle), (bh))
#define ext4_handle_dirty_metadata(handle, inode, bh) \
	__ext4_handle_dirty_metadata(__func__, __LINE__, (handle), (inode), \
				     (bh))
#define ext4_handle_dirty_super(handle, sb) \
	__ext4_handle_dirty_super(__func__, __LINE__, (handle), (sb))

handle_t *__ext4_journal_start_sb(struct super_block *sb, unsigned int line,
				  int type, int blocks, int rsv_blocks);
int __ext4_journal_stop(const char *where, unsigned int line, handle_t *handle);

#define EXT4_NOJOURNAL_MAX_REF_COUNT ((unsigned long) 4096)

static inline int ext4_handle_valid(handle_t *handle)
{
	if ((unsigned long)handle < EXT4_NOJOURNAL_MAX_REF_COUNT)
		return 0;
	return 1;
}

static inline void ext4_handle_sync(handle_t *handle)
{
	if (ext4_handle_valid(handle))
		handle->h_sync = 1;
}

static inline int ext4_handle_is_aborted(handle_t *handle)
{
	if (ext4_handle_valid(handle))
		return is_handle_aborted(handle);
	return 0;
}

static inline int ext4_handle_has_enough_credits(handle_t *handle, int needed)
{
	if (ext4_handle_valid(handle) && handle->h_buffer_credits < needed)
		return 0;
	return 1;
}

#define ext4_journal_start_sb(sb, type, nblocks)			\
	__ext4_journal_start_sb((sb), __LINE__, (type), (nblocks), 0)

#define ext4_journal_start(inode, type, nblocks)			\
	__ext4_journal_start((inode), __LINE__, (type), (nblocks), 0)

#define ext4_journal_start_with_reserve(inode, type, blocks, rsv_blocks) \
	__ext4_journal_start((inode), __LINE__, (type), (blocks), (rsv_blocks))

static inline handle_t *__ext4_journal_start(struct inode *inode,
					     unsigned int line, int type,
					     int blocks, int rsv_blocks)
{
	return __ext4_journal_start_sb(inode->i_sb, line, type, blocks,
				       rsv_blocks);
}

#define ext4_journal_stop(handle) \
	__ext4_journal_stop(__func__, __LINE__, (handle))

#define ext4_journal_start_reserved(handle, type) \
	__ext4_journal_start_reserved((handle), __LINE__, (type))

handle_t *__ext4_journal_start_reserved(handle_t *handle, unsigned int line,
					int type);

static inline void ext4_journal_free_reserved(handle_t *handle)
{
	if (ext4_handle_valid(handle))
		jbd2_journal_free_reserved(handle);
}

static inline handle_t *ext4_journal_current_handle(void)
{
	return journal_current_handle();
}

static inline int ext4_journal_extend(handle_t *handle, int nblocks)
{
	if (ext4_handle_valid(handle))
		return jbd2_journal_extend(handle, nblocks);
	return 0;
}

static inline int ext4_journal_restart(handle_t *handle, int nblocks)
{
	if (ext4_handle_valid(handle))
		return jbd2_journal_restart(handle, nblocks);
	return 0;
}

static inline int ext4_journal_blocks_per_page(struct inode *inode)
{
	if (EXT4_JOURNAL(inode) != NULL)
		return jbd2_journal_blocks_per_page(inode);
	return 0;
}

static inline int ext4_journal_force_commit(journal_t *journal)
{
	if (journal)
		return jbd2_journal_force_commit(journal);
	return 0;
}

static inline int ext4_jbd2_file_inode(handle_t *handle, struct inode *inode)
{
	if (ext4_handle_valid(handle))
		return jbd2_journal_file_inode(handle, EXT4_I(inode)->jinode);
	return 0;
}

static inline void ext4_update_inode_fsync_trans(handle_t *handle,
						 struct inode *inode,
						 int datasync)
{
	struct ext4_inode_info *ei = EXT4_I(inode);

	if (ext4_handle_valid(handle)) {
		ei->i_sync_tid = handle->h_transaction->t_tid;
		if (datasync)
			ei->i_datasync_tid = handle->h_transaction->t_tid;
	}
}

int ext4_force_commit(struct super_block *sb);

#define EXT4_INODE_JOURNAL_DATA_MODE	0x01  
#define EXT4_INODE_ORDERED_DATA_MODE	0x02  
#define EXT4_INODE_WRITEBACK_DATA_MODE	0x04  

static inline int ext4_inode_journal_mode(struct inode *inode)
{
	if (EXT4_JOURNAL(inode) == NULL)
		return EXT4_INODE_WRITEBACK_DATA_MODE;	 
	 
	if (!S_ISREG(inode->i_mode) ||
	    test_opt(inode->i_sb, DATA_FLAGS) == EXT4_MOUNT_JOURNAL_DATA ||
	    (ext4_test_inode_flag(inode, EXT4_INODE_JOURNAL_DATA) &&
	    !test_opt(inode->i_sb, DELALLOC))) {
		 
		if (S_ISREG(inode->i_mode) && ext4_encrypted_inode(inode))
			return EXT4_INODE_ORDERED_DATA_MODE;   
		return EXT4_INODE_JOURNAL_DATA_MODE;	 
	}
	if (test_opt(inode->i_sb, DATA_FLAGS) == EXT4_MOUNT_ORDERED_DATA)
		return EXT4_INODE_ORDERED_DATA_MODE;	 
	if (test_opt(inode->i_sb, DATA_FLAGS) == EXT4_MOUNT_WRITEBACK_DATA)
		return EXT4_INODE_WRITEBACK_DATA_MODE;	 
	BUG();
}

static inline int ext4_should_journal_data(struct inode *inode)
{
	return ext4_inode_journal_mode(inode) & EXT4_INODE_JOURNAL_DATA_MODE;
}

static inline int ext4_should_order_data(struct inode *inode)
{
	return ext4_inode_journal_mode(inode) & EXT4_INODE_ORDERED_DATA_MODE;
}

static inline int ext4_should_writeback_data(struct inode *inode)
{
	return ext4_inode_journal_mode(inode) & EXT4_INODE_WRITEBACK_DATA_MODE;
}

static inline int ext4_should_dioread_nolock(struct inode *inode)
{
	if (!test_opt(inode->i_sb, DIOREAD_NOLOCK))
		return 0;
	if (!S_ISREG(inode->i_mode))
		return 0;
	if (!(ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS)))
		return 0;
	if (ext4_should_journal_data(inode))
		return 0;
	return 1;
}

#endif	 
