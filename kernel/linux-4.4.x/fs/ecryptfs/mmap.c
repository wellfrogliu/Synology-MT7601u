#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/page-flags.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <asm/unaligned.h>
#include "ecryptfs_kernel.h"

struct page *ecryptfs_get_locked_page(struct inode *inode, loff_t index)
{
	struct page *page = read_mapping_page(inode->i_mapping, index, NULL);
	if (!IS_ERR(page))
		lock_page(page);
	return page;
}

static int ecryptfs_writepage(struct page *page, struct writeback_control *wbc)
{
	int rc;

	rc = ecryptfs_encrypt_page(page);
	if (rc) {
#ifdef MY_ABC_HERE
		if (-EDQUOT != rc && -ENOSPC != rc)
#endif  
		ecryptfs_printk(KERN_WARNING, "Error encrypting "
				"page (upper index [0x%.16lx])\n", page->index);
		ClearPageUptodate(page);
		goto out;
	}
	SetPageUptodate(page);
out:
	unlock_page(page);
	return rc;
}

static void strip_xattr_flag(char *page_virt,
			     struct ecryptfs_crypt_stat *crypt_stat)
{
	if (crypt_stat->flags & ECRYPTFS_METADATA_IN_XATTR) {
		size_t written;

		crypt_stat->flags &= ~ECRYPTFS_METADATA_IN_XATTR;
		ecryptfs_write_crypt_stat_flags(page_virt, crypt_stat,
						&written);
		crypt_stat->flags |= ECRYPTFS_METADATA_IN_XATTR;
	}
}

static int
ecryptfs_copy_up_encrypted_with_header(struct page *page,
				       struct ecryptfs_crypt_stat *crypt_stat)
{
	loff_t extent_num_in_page = 0;
	loff_t num_extents_per_page = (PAGE_CACHE_SIZE
				       / crypt_stat->extent_size);
	int rc = 0;

	while (extent_num_in_page < num_extents_per_page) {
		loff_t view_extent_num = ((((loff_t)page->index)
					   * num_extents_per_page)
					  + extent_num_in_page);
		size_t num_header_extents_at_front =
			(crypt_stat->metadata_size / crypt_stat->extent_size);

		if (view_extent_num < num_header_extents_at_front) {
			 
			char *page_virt;

			page_virt = kmap_atomic(page);
			memset(page_virt, 0, PAGE_CACHE_SIZE);
			 
			if (view_extent_num == 0) {
				size_t written;

				rc = ecryptfs_read_xattr_region(
					page_virt, page->mapping->host);
				strip_xattr_flag(page_virt + 16, crypt_stat);
				ecryptfs_write_header_metadata(page_virt + 20,
							       crypt_stat,
							       &written);
			}
			kunmap_atomic(page_virt);
			flush_dcache_page(page);
			if (rc) {
				printk(KERN_ERR "%s: Error reading xattr "
				       "region; rc = [%d]\n", __func__, rc);
				goto out;
			}
		} else {
			 
			loff_t lower_offset =
				((view_extent_num * crypt_stat->extent_size)
				 - crypt_stat->metadata_size);

			rc = ecryptfs_read_lower_page_segment(
				page, (lower_offset >> PAGE_CACHE_SHIFT),
				(lower_offset & ~PAGE_CACHE_MASK),
				crypt_stat->extent_size, page->mapping->host);
			if (rc) {
				printk(KERN_ERR "%s: Error attempting to read "
				       "extent at offset [%lld] in the lower "
				       "file; rc = [%d]\n", __func__,
				       lower_offset, rc);
				goto out;
			}
		}
		extent_num_in_page++;
	}
out:
	return rc;
}

static int ecryptfs_readpage(struct file *file, struct page *page)
{
	struct ecryptfs_crypt_stat *crypt_stat =
		&ecryptfs_inode_to_private(page->mapping->host)->crypt_stat;
	int rc = 0;

	if (!crypt_stat || !(crypt_stat->flags & ECRYPTFS_ENCRYPTED)) {
		rc = ecryptfs_read_lower_page_segment(page, page->index, 0,
						      PAGE_CACHE_SIZE,
						      page->mapping->host);
	} else if (crypt_stat->flags & ECRYPTFS_VIEW_AS_ENCRYPTED) {
		if (crypt_stat->flags & ECRYPTFS_METADATA_IN_XATTR) {
			rc = ecryptfs_copy_up_encrypted_with_header(page,
								    crypt_stat);
			if (rc) {
				printk(KERN_ERR "%s: Error attempting to copy "
				       "the encrypted content from the lower "
				       "file whilst inserting the metadata "
				       "from the xattr into the header; rc = "
				       "[%d]\n", __func__, rc);
				goto out;
			}

		} else {
			rc = ecryptfs_read_lower_page_segment(
				page, page->index, 0, PAGE_CACHE_SIZE,
				page->mapping->host);
			if (rc) {
				printk(KERN_ERR "Error reading page; rc = "
				       "[%d]\n", rc);
				goto out;
			}
		}
	} else {
		rc = ecryptfs_decrypt_page(page);
		if (rc) {
			ecryptfs_printk(KERN_ERR, "Error decrypting page; "
					"rc = [%d]\n", rc);
			goto out;
		}
	}
out:
	if (rc)
		ClearPageUptodate(page);
	else
		SetPageUptodate(page);
	ecryptfs_printk(KERN_DEBUG, "Unlocking page with index = [0x%.16lx]\n",
			page->index);
	unlock_page(page);
	return rc;
}

static int fill_zeros_to_end_of_page(struct page *page, unsigned int to)
{
	struct inode *inode = page->mapping->host;
	int end_byte_in_page;

	if ((i_size_read(inode) / PAGE_CACHE_SIZE) != page->index)
		goto out;
	end_byte_in_page = i_size_read(inode) % PAGE_CACHE_SIZE;
	if (to > end_byte_in_page)
		end_byte_in_page = to;
	zero_user_segment(page, end_byte_in_page, PAGE_CACHE_SIZE);
out:
	return 0;
}

static int ecryptfs_write_begin(struct file *file,
			struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	struct page *page;
	loff_t prev_page_end_size;
	int rc = 0;

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;
	*pagep = page;

	prev_page_end_size = ((loff_t)index << PAGE_CACHE_SHIFT);
	if (!PageUptodate(page)) {
		struct ecryptfs_crypt_stat *crypt_stat =
			&ecryptfs_inode_to_private(mapping->host)->crypt_stat;

		if (!(crypt_stat->flags & ECRYPTFS_ENCRYPTED)) {
			rc = ecryptfs_read_lower_page_segment(
				page, index, 0, PAGE_CACHE_SIZE, mapping->host);
			if (rc) {
				printk(KERN_ERR "%s: Error attempting to read "
				       "lower page segment; rc = [%d]\n",
				       __func__, rc);
				ClearPageUptodate(page);
				goto out;
			} else
				SetPageUptodate(page);
		} else if (crypt_stat->flags & ECRYPTFS_VIEW_AS_ENCRYPTED) {
			if (crypt_stat->flags & ECRYPTFS_METADATA_IN_XATTR) {
				rc = ecryptfs_copy_up_encrypted_with_header(
					page, crypt_stat);
				if (rc) {
					printk(KERN_ERR "%s: Error attempting "
					       "to copy the encrypted content "
					       "from the lower file whilst "
					       "inserting the metadata from "
					       "the xattr into the header; rc "
					       "= [%d]\n", __func__, rc);
					ClearPageUptodate(page);
					goto out;
				}
				SetPageUptodate(page);
			} else {
				rc = ecryptfs_read_lower_page_segment(
					page, index, 0, PAGE_CACHE_SIZE,
					mapping->host);
				if (rc) {
					printk(KERN_ERR "%s: Error reading "
					       "page; rc = [%d]\n",
					       __func__, rc);
					ClearPageUptodate(page);
					goto out;
				}
				SetPageUptodate(page);
			}
		} else {
			if (prev_page_end_size
			    >= i_size_read(page->mapping->host)) {
				zero_user(page, 0, PAGE_CACHE_SIZE);
				SetPageUptodate(page);
			} else if (len < PAGE_CACHE_SIZE) {
				rc = ecryptfs_decrypt_page(page);
				if (rc) {
					printk(KERN_ERR "%s: Error decrypting "
					       "page at index [%ld]; "
					       "rc = [%d]\n",
					       __func__, page->index, rc);
					ClearPageUptodate(page);
					goto out;
				}
				SetPageUptodate(page);
			}
		}
	}
	 
#ifdef MY_ABC_HERE
	if (index != 0 && !(AOP_FLAG_RECVFILE_ECRYPTFS_NO_TRUNCATE & flags)) {
#else
	if (index != 0) {
#endif  
		if (prev_page_end_size > i_size_read(page->mapping->host)) {
			rc = ecryptfs_truncate(file->f_path.dentry,
					       prev_page_end_size);
			if (rc) {
				printk(KERN_ERR "%s: Error on attempt to "
				       "truncate to (higher) offset [%lld];"
				       " rc = [%d]\n", __func__,
				       prev_page_end_size, rc);
				goto out;
			}
		}
	}
	 
	if ((i_size_read(mapping->host) == prev_page_end_size)
	    && (pos != 0))
		zero_user(page, 0, PAGE_CACHE_SIZE);
out:
	if (unlikely(rc)) {
		unlock_page(page);
		page_cache_release(page);
		*pagep = NULL;
	}
	return rc;
}

static int ecryptfs_write_inode_size_to_header(struct inode *ecryptfs_inode)
{
	char *file_size_virt;
	int rc;
#ifdef MY_ABC_HERE
	u8 file_size[ECRYPTFS_FILE_SIZE_BYTES];

	rc = ecryptfs_read_lower(file_size, 0, ECRYPTFS_FILE_SIZE_BYTES, ecryptfs_inode);
	if (rc == ECRYPTFS_FILE_SIZE_BYTES &&
	    get_unaligned_be64(file_size) == i_size_read(ecryptfs_inode)) {
		rc = 0;
		goto out;
	}
#endif  
	file_size_virt = kmalloc(sizeof(u64), GFP_KERNEL);
	if (!file_size_virt) {
		rc = -ENOMEM;
		goto out;
	}
	put_unaligned_be64(i_size_read(ecryptfs_inode), file_size_virt);
	rc = ecryptfs_write_lower(ecryptfs_inode, file_size_virt, 0,
				  sizeof(u64));
	kfree(file_size_virt);
#ifdef MY_ABC_HERE
	if (-EDQUOT == rc || -ENOSPC == rc)
		return rc;   
#endif  
	if (rc < 0)
		printk(KERN_ERR "%s: Error writing file size to header; "
		       "rc = [%d]\n", __func__, rc);
	else
		rc = 0;
out:
	return rc;
}

struct kmem_cache *ecryptfs_xattr_cache;

static int ecryptfs_write_inode_size_to_xattr(struct inode *ecryptfs_inode)
{
	ssize_t size;
	void *xattr_virt;
	struct dentry *lower_dentry =
		ecryptfs_inode_to_private(ecryptfs_inode)->lower_file->f_path.dentry;
	struct inode *lower_inode = d_inode(lower_dentry);
	int rc;

	if (!lower_inode->i_op->getxattr || !lower_inode->i_op->setxattr) {
		printk(KERN_WARNING
		       "No support for setting xattr in lower filesystem\n");
		rc = -ENOSYS;
		goto out;
	}
	xattr_virt = kmem_cache_alloc(ecryptfs_xattr_cache, GFP_KERNEL);
	if (!xattr_virt) {
		printk(KERN_ERR "Out of memory whilst attempting to write "
		       "inode size to xattr\n");
		rc = -ENOMEM;
		goto out;
	}
	inode_lock(lower_inode);
	size = lower_inode->i_op->getxattr(lower_dentry, ECRYPTFS_XATTR_NAME,
					   xattr_virt, PAGE_CACHE_SIZE);
	if (size < 0)
		size = 8;
#ifdef MY_ABC_HERE
	else if (size >= 8 &&
	    get_unaligned_be64(xattr_virt) == i_size_read(ecryptfs_inode)) {
		kmem_cache_free(ecryptfs_xattr_cache, xattr_virt);
		inode_unlock(lower_inode);
		return 0;
	}
#endif  
	put_unaligned_be64(i_size_read(ecryptfs_inode), xattr_virt);
	rc = lower_inode->i_op->setxattr(lower_dentry, ECRYPTFS_XATTR_NAME,
					 xattr_virt, size, 0);
	inode_unlock(lower_inode);
	if (rc)
		printk(KERN_ERR "Error whilst attempting to write inode size "
		       "to lower file xattr; rc = [%d]\n", rc);
	kmem_cache_free(ecryptfs_xattr_cache, xattr_virt);
out:
	return rc;
}

int ecryptfs_write_inode_size_to_metadata(struct inode *ecryptfs_inode)
{
	struct ecryptfs_crypt_stat *crypt_stat;
#ifdef MY_ABC_HERE
	int rc = -1;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat =
		&ecryptfs_superblock_to_private(ecryptfs_inode->i_sb)->mount_crypt_stat;
#endif  
	crypt_stat = &ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat;
	BUG_ON(!(crypt_stat->flags & ECRYPTFS_ENCRYPTED));
#ifdef MY_ABC_HERE
	if (mount_crypt_stat->flags & ECRYPTFS_GLOBAL_FAST_LOOKUP_ENABLED) {
		rc = ecryptfs_write_inode_size_to_xattr(ecryptfs_inode);
		if (rc == -EOPNOTSUPP) {
			printk(KERN_WARNING "%s: user xattr not supported, turn off FAST_LOOKUP", __func__);
			mount_crypt_stat->flags &= ~ECRYPTFS_GLOBAL_FAST_LOOKUP_ENABLED;
		}
		return ecryptfs_write_inode_size_to_header(ecryptfs_inode);
	}
#endif  
	if (crypt_stat->flags & ECRYPTFS_METADATA_IN_XATTR)
		return ecryptfs_write_inode_size_to_xattr(ecryptfs_inode);
	else
		return ecryptfs_write_inode_size_to_header(ecryptfs_inode);
}

static int ecryptfs_write_end(struct file *file,
			struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata)
{
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	unsigned from = pos & (PAGE_CACHE_SIZE - 1);
	unsigned to = from + copied;
	struct inode *ecryptfs_inode = mapping->host;
	struct ecryptfs_crypt_stat *crypt_stat =
		&ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat;
	int rc;

	ecryptfs_printk(KERN_DEBUG, "Calling fill_zeros_to_end_of_page"
			"(page w/ index = [0x%.16lx], to = [%d])\n", index, to);
	if (!(crypt_stat->flags & ECRYPTFS_ENCRYPTED)) {
		rc = ecryptfs_write_lower_page_segment(ecryptfs_inode, page, 0,
						       to);
		if (!rc) {
			rc = copied;
			fsstack_copy_inode_size(ecryptfs_inode,
				ecryptfs_inode_to_lower(ecryptfs_inode));
		}
		goto out;
	}
	if (!PageUptodate(page)) {
		if (copied < PAGE_CACHE_SIZE) {
			rc = 0;
			goto out;
		}
		SetPageUptodate(page);
	}
	 
	rc = fill_zeros_to_end_of_page(page, to);
	if (rc) {
		ecryptfs_printk(KERN_WARNING, "Error attempting to fill "
			"zeros in page with index = [0x%.16lx]\n", index);
		goto out;
	}
	rc = ecryptfs_encrypt_page(page);
	if (rc) {
#ifdef MY_ABC_HERE
		if (-EDQUOT != rc && -ENOSPC != rc)
#endif  
		ecryptfs_printk(KERN_WARNING, "Error encrypting page (upper "
				"index [0x%.16lx])\n", index);
		goto out;
	}
	if (pos + copied > i_size_read(ecryptfs_inode)) {
		i_size_write(ecryptfs_inode, pos + copied);
		ecryptfs_printk(KERN_DEBUG, "Expanded file size to "
			"[0x%.16llx]\n",
			(unsigned long long)i_size_read(ecryptfs_inode));
	}
	rc = ecryptfs_write_inode_size_to_metadata(ecryptfs_inode);
#ifdef MY_ABC_HERE
	if (-EDQUOT == rc || -ENOSPC == rc) {
		goto out;  
	}
#endif  
	if (rc)
		printk(KERN_ERR "Error writing inode size to metadata; "
		       "rc = [%d]\n", rc);
	else
		rc = copied;
out:
	unlock_page(page);
	page_cache_release(page);
	return rc;
}

#ifdef MY_ABC_HERE
static int ecryptfs_aggregate_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page **pages, void *fsdata, unsigned page_num)
{
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	unsigned from = pos & (PAGE_CACHE_SIZE - 1);
	unsigned to = from + copied;
	struct inode *ecryptfs_inode = mapping->host;
	struct ecryptfs_crypt_stat *crypt_stat =
		&ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat;
	int rc = 0, i;

	ecryptfs_printk(KERN_DEBUG, "Calling fill_zeros_to_end_of_page"
			"(page w/ index = [0x%.16lx], to = [%d])\n", index, to);
	if (!page_num)
		goto out;
	if (!(crypt_stat->flags & ECRYPTFS_ENCRYPTED)) {
		for (i = 0;i < page_num;i++) {
			rc = ecryptfs_write_lower_page_segment(ecryptfs_inode, pages[i], 0,
							       PAGE_CACHE_SIZE);
			if (!rc) {
				fsstack_copy_inode_size(ecryptfs_inode,
					ecryptfs_inode_to_lower(ecryptfs_inode));
			} else {
				break;
			}
		}
		if (!rc) {
			rc = copied;
		}
		goto out;
	}
	for (i = 0;i < page_num;i++) {
		if (!PageUptodate(pages[i])) {
			if (i == 0 && copied < PAGE_CACHE_SIZE) {
				rc = 0;
				goto out;
			}
			SetPageUptodate(pages[i]);
		}
	}
	if (to % PAGE_CACHE_SIZE) {
		fill_zeros_to_end_of_page(pages[page_num-1], to);
	}

	for (i = 0;i < page_num;i++) {
		rc = ecryptfs_encrypt_page(pages[i]);
		if (rc) {
#ifdef MY_ABC_HERE
			if (-EDQUOT != rc && -ENOSPC != rc)
#endif  
			ecryptfs_printk(KERN_WARNING, "Error encrypting page (upper "
					"index [0x%.16lx])\n", index);
			goto out;
		}
	}

	if (pos + copied > i_size_read(ecryptfs_inode)) {
		i_size_write(ecryptfs_inode, pos + copied);
		ecryptfs_printk(KERN_DEBUG, "Expanded file size to "
			"[0x%.16llx]\n",
			(unsigned long long)i_size_read(ecryptfs_inode));
	}
	rc = ecryptfs_write_inode_size_to_metadata(ecryptfs_inode);
#ifdef MY_ABC_HERE
	if (-EDQUOT == rc || -ENOSPC == rc) {
		goto out;  
	}
#endif  
	if (rc)
		printk(KERN_ERR "Error writing inode size to metadata; "
		       "rc = [%d]\n", rc);
	else
		rc = copied;
out:
	for (i = 0;i < page_num;i++) {
		unlock_page(pages[i]);
		page_cache_release(pages[i]);
	}
	return rc;
}
#endif  

static sector_t ecryptfs_bmap(struct address_space *mapping, sector_t block)
{
	int rc = 0;
	struct inode *inode;
	struct inode *lower_inode;

	inode = (struct inode *)mapping->host;
	lower_inode = ecryptfs_inode_to_lower(inode);
	if (lower_inode->i_mapping->a_ops->bmap)
		rc = lower_inode->i_mapping->a_ops->bmap(lower_inode->i_mapping,
							 block);
	return rc;
}

const struct address_space_operations ecryptfs_aops = {
	.writepage = ecryptfs_writepage,
	.readpage = ecryptfs_readpage,
	.write_begin = ecryptfs_write_begin,
	.write_end = ecryptfs_write_end,
	.bmap = ecryptfs_bmap,
#ifdef MY_ABC_HERE
	.aggregate_write_end	= ecryptfs_aggregate_write_end,
#endif  
};
