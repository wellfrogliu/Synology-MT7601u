#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef _LINUX_DM_IO_H
#define _LINUX_DM_IO_H

#ifdef __KERNEL__

#include <linux/types.h>

struct dm_io_region {
	struct block_device *bdev;
	sector_t sector;
	sector_t count;		 
};

struct page_list {
	struct page_list *next;
	struct page *page;
};

typedef void (*io_notify_fn)(unsigned long error, void *context);

enum dm_io_mem_type {
	DM_IO_PAGE_LIST, 
	DM_IO_BIO,	 
	DM_IO_VMA,	 
	DM_IO_KMEM,	 
};

struct dm_io_memory {
	enum dm_io_mem_type type;

	unsigned offset;

	union {
		struct page_list *pl;
		struct bio *bio;
		void *vma;
		void *addr;
	} ptr;
};

struct dm_io_notify {
	io_notify_fn fn;	 
	void *context;		 
};

struct dm_io_client;
struct dm_io_request {
	int bi_rw;			 
	struct dm_io_memory mem;	 
	struct dm_io_notify notify;	 
	struct dm_io_client *client;	 
};

struct dm_io_client *dm_io_client_create(void);
void dm_io_client_destroy(struct dm_io_client *client);

#ifdef MY_ABC_HERE
int syno_dm_io(struct dm_io_request *io_req, unsigned num_regions,
		struct dm_io_region *region, unsigned long *sync_error_bits, unsigned long bi_flags);
#endif  
int dm_io(struct dm_io_request *io_req, unsigned num_regions,
	  struct dm_io_region *region, unsigned long *sync_error_bits);

#endif	 
#endif	 
