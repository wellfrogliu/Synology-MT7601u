#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/key.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/file.h>
#include <linux/crypto.h>
#include <linux/statfs.h>
#include <linux/magic.h>
#include "ecryptfs_kernel.h"

struct kmem_cache *ecryptfs_inode_info_cache;

static struct inode *ecryptfs_alloc_inode(struct super_block *sb)
{
	struct ecryptfs_inode_info *inode_info;
	struct inode *inode = NULL;

	inode_info = kmem_cache_alloc(ecryptfs_inode_info_cache, GFP_KERNEL);
	if (unlikely(!inode_info))
		goto out;
	ecryptfs_init_crypt_stat(&inode_info->crypt_stat);
	mutex_init(&inode_info->lower_file_mutex);
	atomic_set(&inode_info->lower_file_count, 0);
	inode_info->lower_file = NULL;
	inode = &inode_info->vfs_inode;
out:
	return inode;
}

static void ecryptfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct ecryptfs_inode_info *inode_info;
	inode_info = ecryptfs_inode_to_private(inode);

	kmem_cache_free(ecryptfs_inode_info_cache, inode_info);
}

static void ecryptfs_destroy_inode(struct inode *inode)
{
	struct ecryptfs_inode_info *inode_info;

	inode_info = ecryptfs_inode_to_private(inode);
	BUG_ON(inode_info->lower_file);
	ecryptfs_destroy_crypt_stat(&inode_info->crypt_stat);
	call_rcu(&inode->i_rcu, ecryptfs_i_callback);
}

static int ecryptfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);
	int rc;

	if (!lower_dentry->d_sb->s_op->statfs)
		return -ENOSYS;

	rc = lower_dentry->d_sb->s_op->statfs(lower_dentry, buf);
	if (rc)
		return rc;

	buf->f_type = ECRYPTFS_SUPER_MAGIC;
	rc = ecryptfs_set_f_namelen(&buf->f_namelen, buf->f_namelen,
	       &ecryptfs_superblock_to_private(dentry->d_sb)->mount_crypt_stat);

	return rc;
}

static void ecryptfs_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
	iput(ecryptfs_inode_to_lower(inode));
}

static int ecryptfs_show_options(struct seq_file *m, struct dentry *root)
{
	struct super_block *sb = root->d_sb;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat =
		&ecryptfs_superblock_to_private(sb)->mount_crypt_stat;
	struct ecryptfs_global_auth_tok *walker;

	mutex_lock(&mount_crypt_stat->global_auth_tok_list_mutex);
	list_for_each_entry(walker,
			    &mount_crypt_stat->global_auth_tok_list,
			    mount_crypt_stat_list) {
		if (walker->flags & ECRYPTFS_AUTH_TOK_FNEK)
			seq_printf(m, ",ecryptfs_fnek_sig=%s", walker->sig);
		else
			seq_printf(m, ",ecryptfs_sig=%s", walker->sig);
	}
	mutex_unlock(&mount_crypt_stat->global_auth_tok_list_mutex);

	seq_printf(m, ",ecryptfs_cipher=%s",
		mount_crypt_stat->global_default_cipher_name);

	if (mount_crypt_stat->global_default_cipher_key_size)
		seq_printf(m, ",ecryptfs_key_bytes=%zd",
			   mount_crypt_stat->global_default_cipher_key_size);
	if (mount_crypt_stat->flags & ECRYPTFS_PLAINTEXT_PASSTHROUGH_ENABLED)
		seq_printf(m, ",ecryptfs_passthrough");
	if (mount_crypt_stat->flags & ECRYPTFS_XATTR_METADATA_ENABLED)
		seq_printf(m, ",ecryptfs_xattr_metadata");
	if (mount_crypt_stat->flags & ECRYPTFS_ENCRYPTED_VIEW_ENABLED)
		seq_printf(m, ",ecryptfs_encrypted_view");
	if (mount_crypt_stat->flags & ECRYPTFS_UNLINK_SIGS)
		seq_printf(m, ",ecryptfs_unlink_sigs");
	if (mount_crypt_stat->flags & ECRYPTFS_GLOBAL_MOUNT_AUTH_TOK_ONLY)
		seq_printf(m, ",ecryptfs_mount_auth_tok_only");
#ifdef MY_ABC_HERE
	if (!(mount_crypt_stat->flags & ECRYPTFS_GLOBAL_FAST_LOOKUP_ENABLED))
		seq_printf(m, ",no_fast_lookup");
#endif  
	return 0;
}

#ifdef MY_ABC_HERE
static int ecryptfs_syno_get_sb_archive_ver(struct super_block *sb, u32 *archive_ver)
{
	struct super_block *lower_sb = ecryptfs_superblock_to_lower(sb);

	if (!lower_sb->s_op->syno_get_sb_archive_ver)
		return -EINVAL;

	return lower_sb->s_op->syno_get_sb_archive_ver(lower_sb, archive_ver);
}

static int ecryptfs_syno_set_sb_archive_ver(struct super_block *sb, u32 archive_ver)
{
	struct super_block *lower_sb = ecryptfs_superblock_to_lower(sb);

	if (!lower_sb->s_op->syno_set_sb_archive_ver)
		return -EINVAL;

	return lower_sb->s_op->syno_set_sb_archive_ver(lower_sb, archive_ver);
}
#endif  

const struct super_operations ecryptfs_sops = {
#ifdef MY_ABC_HERE
	.syno_get_sb_archive_ver = ecryptfs_syno_get_sb_archive_ver,
	.syno_set_sb_archive_ver = ecryptfs_syno_set_sb_archive_ver,
#endif  
	.alloc_inode = ecryptfs_alloc_inode,
	.destroy_inode = ecryptfs_destroy_inode,
	.statfs = ecryptfs_statfs,
	.remount_fs = NULL,
	.evict_inode = ecryptfs_evict_inode,
	.show_options = ecryptfs_show_options
};
