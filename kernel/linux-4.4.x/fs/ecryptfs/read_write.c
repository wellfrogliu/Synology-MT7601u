#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/fs.h>
#include <linux/pagemap.h>
#include "ecryptfs_kernel.h"

#ifdef MY_ABC_HERE
#include <linux/fsnotify.h>

static ssize_t ecryptfs_kernel_write(struct file *file, const char *buf, size_t count, loff_t pos)
{
	mm_segment_t old_fs;
	ssize_t ret;

	if (!(file->f_mode & FMODE_WRITE))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_WRITE))
		return -EINVAL;

	old_fs = get_fs();
	set_fs(get_ds());
	file_start_write(file);
	ret = __vfs_write(file, buf, count, &pos);
	if (ret > 0) {
		fsnotify_modify(file);
		add_wchar(current, ret);
	}
	inc_syscw(current);
	file_end_write(file);
	set_fs(old_fs);

	return ret;
}
#endif  

int ecryptfs_write_lower(struct inode *ecryptfs_inode, char *data,
			 loff_t offset, size_t size)
{
	struct file *lower_file;
	ssize_t rc;

	lower_file = ecryptfs_inode_to_private(ecryptfs_inode)->lower_file;
	if (!lower_file)
		return -EIO;
#ifdef MY_ABC_HERE
	rc = ecryptfs_kernel_write(lower_file, data, size, offset);
#else
	rc = kernel_write(lower_file, data, size, offset);
#endif  
	mark_inode_dirty_sync(ecryptfs_inode);
	return rc;
}

int ecryptfs_write_lower_page_segment(struct inode *ecryptfs_inode,
				      struct page *page_for_lower,
				      size_t offset_in_page, size_t size)
{
	char *virt;
	loff_t offset;
	int rc;

	offset = ((((loff_t)page_for_lower->index) << PAGE_CACHE_SHIFT)
		  + offset_in_page);
	virt = kmap(page_for_lower);
	rc = ecryptfs_write_lower(ecryptfs_inode, virt, offset, size);
	if (rc > 0)
		rc = 0;
	kunmap(page_for_lower);
	return rc;
}

int ecryptfs_write(struct inode *ecryptfs_inode, char *data, loff_t offset,
		   size_t size)
{
	struct page *ecryptfs_page;
	struct ecryptfs_crypt_stat *crypt_stat;
	char *ecryptfs_page_virt;
	loff_t ecryptfs_file_size = i_size_read(ecryptfs_inode);
	loff_t data_offset = 0;
	loff_t pos;
	int rc = 0;

	crypt_stat = &ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat;
	 
	if (offset > ecryptfs_file_size)
		pos = ecryptfs_file_size;
	else
		pos = offset;
	while (pos < (offset + size)) {
		pgoff_t ecryptfs_page_idx = (pos >> PAGE_CACHE_SHIFT);
		size_t start_offset_in_page = (pos & ~PAGE_CACHE_MASK);
		size_t num_bytes = (PAGE_CACHE_SIZE - start_offset_in_page);
		loff_t total_remaining_bytes = ((offset + size) - pos);

		if (fatal_signal_pending(current)) {
			rc = -EINTR;
			break;
		}

		if (num_bytes > total_remaining_bytes)
			num_bytes = total_remaining_bytes;
		if (pos < offset) {
			 
			loff_t total_remaining_zeros = (offset - pos);

			if (num_bytes > total_remaining_zeros)
				num_bytes = total_remaining_zeros;
		}
		ecryptfs_page = ecryptfs_get_locked_page(ecryptfs_inode,
							 ecryptfs_page_idx);
		if (IS_ERR(ecryptfs_page)) {
			rc = PTR_ERR(ecryptfs_page);
			printk(KERN_ERR "%s: Error getting page at "
			       "index [%ld] from eCryptfs inode "
			       "mapping; rc = [%d]\n", __func__,
			       ecryptfs_page_idx, rc);
			goto out;
		}
		ecryptfs_page_virt = kmap_atomic(ecryptfs_page);

		if (pos < offset || !start_offset_in_page) {
			 
			memset(((char *)ecryptfs_page_virt
				+ start_offset_in_page), 0,
				PAGE_CACHE_SIZE - start_offset_in_page);
		}

		if (pos >= offset) {
			memcpy(((char *)ecryptfs_page_virt
				+ start_offset_in_page),
			       (data + data_offset), num_bytes);
			data_offset += num_bytes;
		}
		kunmap_atomic(ecryptfs_page_virt);
		flush_dcache_page(ecryptfs_page);
		SetPageUptodate(ecryptfs_page);
		unlock_page(ecryptfs_page);
		if (crypt_stat->flags & ECRYPTFS_ENCRYPTED)
			rc = ecryptfs_encrypt_page(ecryptfs_page);
		else
			rc = ecryptfs_write_lower_page_segment(ecryptfs_inode,
						ecryptfs_page,
						start_offset_in_page,
						data_offset);
		page_cache_release(ecryptfs_page);
		if (rc) {
			printk(KERN_ERR "%s: Error encrypting "
			       "page; rc = [%d]\n", __func__, rc);
			goto out;
		}
		pos += num_bytes;
	}
	if (pos > ecryptfs_file_size) {
		i_size_write(ecryptfs_inode, pos);
		if (crypt_stat->flags & ECRYPTFS_ENCRYPTED) {
			int rc2;

			rc2 = ecryptfs_write_inode_size_to_metadata(
								ecryptfs_inode);
			if (rc2) {
#ifdef MY_ABC_HERE
				if (-EDQUOT != rc2 && -ENOSPC != rc2)
#endif  
				printk(KERN_ERR	"Problem with "
				       "ecryptfs_write_inode_size_to_metadata; "
				       "rc = [%d]\n", rc2);
				if (!rc)
					rc = rc2;
				goto out;
			}
		}
	}
out:
	return rc;
}

int ecryptfs_read_lower(char *data, loff_t offset, size_t size,
			struct inode *ecryptfs_inode)
{
	struct file *lower_file;
	lower_file = ecryptfs_inode_to_private(ecryptfs_inode)->lower_file;
	if (!lower_file)
		return -EIO;
	return kernel_read(lower_file, offset, data, size);
}

int ecryptfs_read_lower_page_segment(struct page *page_for_ecryptfs,
				     pgoff_t page_index,
				     size_t offset_in_page, size_t size,
				     struct inode *ecryptfs_inode)
{
	char *virt;
	loff_t offset;
	int rc;

	offset = ((((loff_t)page_index) << PAGE_CACHE_SHIFT) + offset_in_page);
	virt = kmap(page_for_ecryptfs);
	rc = ecryptfs_read_lower(virt, offset, size, ecryptfs_inode);
	if (rc > 0)
		rc = 0;
	kunmap(page_for_ecryptfs);
	flush_dcache_page(page_for_ecryptfs);
	return rc;
}
