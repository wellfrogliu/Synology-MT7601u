#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/vmalloc.h>

#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>
#ifdef MY_ABC_HERE
#include <linux/sched.h>
#endif
#include <linux/module.h>

struct fis_image_desc {
    unsigned char name[16];       
    uint32_t	  flash_base;     
    uint32_t	  mem_base;       
    uint32_t	  size;           
    uint32_t	  entry_point;    
    uint32_t	  data_length;    
    unsigned char _pad[256-(16+7*sizeof(uint32_t))];
    uint32_t	  desc_cksum;     
    uint32_t	  file_cksum;     
};

struct fis_list {
	struct fis_image_desc *img;
	struct fis_list *next;
};

static int directory = CONFIG_MTD_REDBOOT_DIRECTORY_BLOCK;
module_param(directory, int, 0);

static inline int redboot_checksum(struct fis_image_desc *img)
{
	 
	return 1;
}

static int parse_redboot_partitions(struct mtd_info *master,
				    struct mtd_partition **pparts,
				    struct mtd_part_parser_data *data)
{
	int nrparts = 0;
	struct fis_image_desc *buf;
	struct mtd_partition *parts;
	struct fis_list *fl = NULL, *tmp_fl;
	int ret, i;
	size_t retlen;
	char *names;
	char *nullname;
	int namelen = 0;
	int nulllen = 0;
	int numslots;
	unsigned long offset;
#ifdef CONFIG_MTD_REDBOOT_PARTS_UNALLOCATED
	static char nullstring[] = "unallocated";
#endif

	if ( directory < 0 ) {
		offset = master->size + directory * master->erasesize;
		while (mtd_block_isbad(master, offset)) {
			if (!offset) {
			nogood:
				printk(KERN_NOTICE "Failed to find a non-bad block to check for RedBoot partition table\n");
				return -EIO;
			}
			offset -= master->erasesize;
		}
	} else {
		offset = directory * master->erasesize;
		while (mtd_block_isbad(master, offset)) {
			offset += master->erasesize;
			if (offset == master->size)
				goto nogood;
		}
	}
	buf = vmalloc(master->erasesize);

	if (!buf)
		return -ENOMEM;

	printk(KERN_NOTICE "Searching for RedBoot partition table in %s at offset 0x%lx\n",
	       master->name, offset);

	ret = mtd_read(master, offset, master->erasesize, &retlen,
		       (void *)buf);

	if (ret)
		goto out;

	if (retlen != master->erasesize) {
		ret = -EIO;
		goto out;
	}

	numslots = (master->erasesize / sizeof(struct fis_image_desc));
	for (i = 0; i < numslots; i++) {
		if (!memcmp(buf[i].name, "FIS directory", 14)) {
			 
			if (swab32(buf[i].size) == master->erasesize ||
			    (buf[i].size > master->erasesize
			     && swab32(buf[i].size) < master->erasesize)) {
				int j;
				 
				numslots = swab32(buf[i].size) / sizeof (struct fis_image_desc);
				for (j = 0; j < numslots; ++j) {

					if (buf[j].name[0] == 0xff) {
				  		if (buf[j].name[1] == 0xff) {
							break;
						} else {
							continue;
						}
					}

					swab32s(&buf[j].flash_base);
					swab32s(&buf[j].mem_base);
					swab32s(&buf[j].size);
					swab32s(&buf[j].entry_point);
					swab32s(&buf[j].data_length);
					swab32s(&buf[j].desc_cksum);
					swab32s(&buf[j].file_cksum);
				}
			} else if (buf[i].size < master->erasesize) {
				 
				numslots = buf[i].size / sizeof(struct fis_image_desc);
			}
			break;
		}
	}
	if (i == numslots) {
		 
		printk(KERN_NOTICE "No RedBoot partition table detected in %s\n",
		       master->name);
		ret = 0;
		goto out;
	}

	for (i = 0; i < numslots; i++) {
		struct fis_list *new_fl, **prev;

		if (buf[i].name[0] == 0xff) {
			if (buf[i].name[1] == 0xff) {
				break;
			} else {
				continue;
			}
		}
		if (!redboot_checksum(&buf[i]))
			break;

		new_fl = kmalloc(sizeof(struct fis_list), GFP_KERNEL);
		namelen += strlen(buf[i].name)+1;
		if (!new_fl) {
			ret = -ENOMEM;
			goto out;
		}
		new_fl->img = &buf[i];
		if (data && data->origin)
			buf[i].flash_base -= data->origin;
		else
			buf[i].flash_base &= master->size-1;

		prev = &fl;
		while(*prev && (*prev)->img->flash_base < new_fl->img->flash_base)
			prev = &(*prev)->next;
		new_fl->next = *prev;
		*prev = new_fl;

		nrparts++;
	}
#ifdef CONFIG_MTD_REDBOOT_PARTS_UNALLOCATED
	if (fl->img->flash_base) {
		nrparts++;
		nulllen = sizeof(nullstring);
	}

	for (tmp_fl = fl; tmp_fl->next; tmp_fl = tmp_fl->next) {
		if (tmp_fl->img->flash_base + tmp_fl->img->size + master->erasesize <= tmp_fl->next->img->flash_base) {
			nrparts++;
			nulllen = sizeof(nullstring);
		}
	}
#endif
	parts = kzalloc(sizeof(*parts)*nrparts + nulllen + namelen, GFP_KERNEL);

	if (!parts) {
		ret = -ENOMEM;
		goto out;
	}

	nullname = (char *)&parts[nrparts];
#ifdef CONFIG_MTD_REDBOOT_PARTS_UNALLOCATED
	if (nulllen > 0) {
		strcpy(nullname, nullstring);
	}
#endif
	names = nullname + nulllen;

	i=0;

#ifdef CONFIG_MTD_REDBOOT_PARTS_UNALLOCATED
	if (fl->img->flash_base) {
	       parts[0].name = nullname;
	       parts[0].size = fl->img->flash_base;
	       parts[0].offset = 0;
		i++;
	}
#endif
	for ( ; i<nrparts; i++) {
		parts[i].size = fl->img->size;
		parts[i].offset = fl->img->flash_base;
		parts[i].name = names;

		strcpy(names, fl->img->name);
#ifdef CONFIG_MTD_REDBOOT_PARTS_READONLY
		if (!memcmp(names, "RedBoot", 8) ||
				!memcmp(names, "RedBoot config", 15) ||
				!memcmp(names, "FIS directory", 14)) {
			parts[i].mask_flags = MTD_WRITEABLE;
		}
#endif
		names += strlen(names)+1;

#ifdef CONFIG_MTD_REDBOOT_PARTS_UNALLOCATED
		if(fl->next && fl->img->flash_base + fl->img->size + master->erasesize <= fl->next->img->flash_base) {
			i++;
			parts[i].offset = parts[i-1].size + parts[i-1].offset;
			parts[i].size = fl->next->img->flash_base - parts[i].offset;
			parts[i].name = nullname;
		}
#endif
		tmp_fl = fl;
		fl = fl->next;
		kfree(tmp_fl);
	}
	ret = nrparts;
	*pparts = parts;
 out:
	while (fl) {
		struct fis_list *old = fl;
		fl = fl->next;
		kfree(old);
	}
	vfree(buf);
	return ret;
}

static struct mtd_part_parser redboot_parser = {
	.owner = THIS_MODULE,
	.parse_fn = parse_redboot_partitions,
	.name = "RedBoot",
};

MODULE_ALIAS("RedBoot");

static int __init redboot_parser_init(void)
{
	register_mtd_parser(&redboot_parser);
	return 0;
}

static void __exit redboot_parser_exit(void)
{
	deregister_mtd_parser(&redboot_parser);
}

#ifdef MY_ABC_HERE
static void mtd_erase_callback_in_redboot (struct erase_info *instr)
{
	wake_up((wait_queue_head_t *)instr->priv);
}

int SYNOMTDModifyFisInfo(struct mtd_info *mtd, struct SYNO_MTD_FIS_INFO SynoMtdFisInfo)
{
	struct fis_image_desc *buf;
	int ret, i;
	size_t retlen;

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);

	if (!buf) {
		return -ENOMEM;
	}

	ret = mtd_read(mtd, 0, PAGE_SIZE, &retlen, (void *)buf);

	if (ret)
		goto out;

	if (retlen != PAGE_SIZE) {
		ret = -EIO;
		goto out;
	}

	for (i = 0; i < PAGE_SIZE / sizeof(struct fis_image_desc); i++) {
		if (buf[i].name[0] == 0xff) {  
			ret = -ENOENT;  
			break;
		}

		if (0 == strcmp(buf[i].name, SynoMtdFisInfo.name)) {  
			int lockret, eraseret;
			struct erase_info einfo;

			buf[i].flash_base = SynoMtdFisInfo.offset;
			buf[i].size = SynoMtdFisInfo.size;
			buf[i].data_length = SynoMtdFisInfo.data_length;
			lockret = mtd_unlock(mtd, 0, mtd->erasesize);
			if (lockret) {
				printk(KERN_NOTICE "Failed to unlock [%s], error [%d]\n", mtd->name, lockret*(-1));
			}
			 
			{
				wait_queue_head_t waitq;
				DECLARE_WAITQUEUE(wait, current);

				init_waitqueue_head(&waitq);

				memset (&einfo, 0, sizeof(struct erase_info));
				einfo.addr = 0;
				einfo.len = mtd->erasesize;
				einfo.mtd = mtd;
				einfo.callback = mtd_erase_callback_in_redboot;
				einfo.priv = (unsigned long)&waitq;

				eraseret = mtd_erase(mtd, &einfo);
				if (!eraseret) {
					set_current_state(TASK_UNINTERRUPTIBLE);
					add_wait_queue(&waitq, &wait);
					if (einfo.state != MTD_ERASE_DONE &&
						einfo.state != MTD_ERASE_FAILED)
						schedule();
					remove_wait_queue(&waitq, &wait);
					set_current_state(TASK_RUNNING);

					eraseret = (einfo.state == MTD_ERASE_FAILED)?-EIO:0;
				}
			}
			if (eraseret) {
				ret = eraseret;
				printk(KERN_NOTICE "Failed to erase [%s], error [%d]\n", mtd->name, eraseret*(-1));
			}
			else {
				 
				ret = mtd_write(mtd, 0, PAGE_SIZE, &retlen, (const u_char*)buf);
				if (ret) {
					printk(KERN_NOTICE "Failed to write [%s], error [%d]\n", mtd->name, ret*(-1));
				}
			}
			lockret = mtd_lock(mtd, 0, mtd->erasesize);
			if (lockret) {
				printk(KERN_NOTICE "Failed to lock [%s], error [%d]\n", mtd->name, lockret*(-1));
			}
			if (ret) {
				goto out;
			}

			if (retlen != PAGE_SIZE) {
				ret = -EIO;
				goto out;
			}
			break;
		}
	}  

out:
	kfree(buf);
	return ret;
}
#endif  

module_init(redboot_parser_init);
module_exit(redboot_parser_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("David Woodhouse <dwmw2@infradead.org>");
MODULE_DESCRIPTION("Parsing code for RedBoot Flash Image System (FIS) tables");
