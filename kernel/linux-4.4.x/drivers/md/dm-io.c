#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include "dm.h"

#include <linux/device-mapper.h>

#include <linux/bio.h>
#include <linux/completion.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/dm-io.h>

#define DM_MSG_PREFIX "io"

#define DM_IO_MAX_REGIONS	BITS_PER_LONG

struct dm_io_client {
	mempool_t *pool;
	struct bio_set *bios;
};

#define sinfo(fmt, args...)

struct io {
	unsigned long error_bits;
	atomic_t count;
	struct dm_io_client *client;
	io_notify_fn callback;
	void *context;
	void *vma_invalidate_address;
	unsigned long vma_invalidate_size;
#ifdef MY_ABC_HERE
	unsigned long bi_flags;
#endif  
} __attribute__((aligned(DM_IO_MAX_REGIONS)));

#ifdef MY_ABC_HERE
static int has_correction_flag(unsigned long bi_flags)
{
	return 0;
}
#endif  

static struct kmem_cache *_dm_io_cache;

struct dm_io_client *dm_io_client_create(void)
{
	struct dm_io_client *client;
	unsigned min_ios = dm_get_reserved_bio_based_ios();

	client = kmalloc(sizeof(*client), GFP_KERNEL);
	if (!client)
		return ERR_PTR(-ENOMEM);

	client->pool = mempool_create_slab_pool(min_ios, _dm_io_cache);
	if (!client->pool)
		goto bad;

	client->bios = bioset_create(min_ios, 0);
	if (!client->bios)
		goto bad;

	return client;

   bad:
	mempool_destroy(client->pool);
	kfree(client);
	return ERR_PTR(-ENOMEM);
}
EXPORT_SYMBOL(dm_io_client_create);

void dm_io_client_destroy(struct dm_io_client *client)
{
	mempool_destroy(client->pool);
	bioset_free(client->bios);
	kfree(client);
}
EXPORT_SYMBOL(dm_io_client_destroy);

static void store_io_and_region_in_bio(struct bio *bio, struct io *io,
				       unsigned region)
{
	if (unlikely(!IS_ALIGNED((unsigned long)io, DM_IO_MAX_REGIONS))) {
		DMCRIT("Unaligned struct io pointer %p", io);
		BUG();
	}

	bio->bi_private = (void *)((unsigned long)io | region);
}

static void retrieve_io_and_region_from_bio(struct bio *bio, struct io **io,
				       unsigned *region)
{
	unsigned long val = (unsigned long)bio->bi_private;

	*io = (void *)(val & -(unsigned long)DM_IO_MAX_REGIONS);
	*region = val & (DM_IO_MAX_REGIONS - 1);
}

static void complete_io(struct io *io)
{
	unsigned long error_bits = io->error_bits;
	io_notify_fn fn = io->callback;
	void *context = io->context;

	if (io->vma_invalidate_size)
		invalidate_kernel_vmap_range(io->vma_invalidate_address,
					     io->vma_invalidate_size);

	mempool_free(io, io->client->pool);
	fn(error_bits, context);
}

#ifdef MY_ABC_HERE
static void dec_count_common(struct io *io, unsigned int region, int error, unsigned long bi_flags)
#else
static void dec_count(struct io *io, unsigned int region, int error)
#endif  
{
	if (error)
		set_bit(region, &io->error_bits);

	if (atomic_dec_and_test(&io->count))
		complete_io(io);
}

#ifdef MY_ABC_HERE
static void dec_count(struct io *io, unsigned int region, int error)
{
	dec_count_common(io, region, error, 0);
}
#endif

static void endio(struct bio *bio)
{
	struct io *io;
	unsigned region;
	int error;

	if (bio->bi_error && bio_data_dir(bio) == READ)
		zero_fill_bio(bio);

	retrieve_io_and_region_from_bio(bio, &io, &region);

	error = bio->bi_error;
	bio_put(bio);

	dec_count(io, region, error);
}

struct dpages {
	void (*get_page)(struct dpages *dp,
			 struct page **p, unsigned long *len, unsigned *offset);
	void (*next_page)(struct dpages *dp);

	unsigned context_u;
	void *context_ptr;

	void *vma_invalidate_address;
	unsigned long vma_invalidate_size;
};

static void list_get_page(struct dpages *dp,
		  struct page **p, unsigned long *len, unsigned *offset)
{
	unsigned o = dp->context_u;
	struct page_list *pl = (struct page_list *) dp->context_ptr;

	*p = pl->page;
	*len = PAGE_SIZE - o;
	*offset = o;
}

static void list_next_page(struct dpages *dp)
{
	struct page_list *pl = (struct page_list *) dp->context_ptr;
	dp->context_ptr = pl->next;
	dp->context_u = 0;
}

static void list_dp_init(struct dpages *dp, struct page_list *pl, unsigned offset)
{
	dp->get_page = list_get_page;
	dp->next_page = list_next_page;
	dp->context_u = offset;
	dp->context_ptr = pl;
}

static void bio_get_page(struct dpages *dp, struct page **p,
			 unsigned long *len, unsigned *offset)
{
	struct bio_vec *bvec = dp->context_ptr;
	*p = bvec->bv_page;
	*len = bvec->bv_len - dp->context_u;
	*offset = bvec->bv_offset + dp->context_u;
}

static void bio_next_page(struct dpages *dp)
{
	struct bio_vec *bvec = dp->context_ptr;
	dp->context_ptr = bvec + 1;
	dp->context_u = 0;
}

static void bio_dp_init(struct dpages *dp, struct bio *bio)
{
	dp->get_page = bio_get_page;
	dp->next_page = bio_next_page;
	dp->context_ptr = __bvec_iter_bvec(bio->bi_io_vec, bio->bi_iter);
	dp->context_u = bio->bi_iter.bi_bvec_done;
}

static void vm_get_page(struct dpages *dp,
		 struct page **p, unsigned long *len, unsigned *offset)
{
	*p = vmalloc_to_page(dp->context_ptr);
	*offset = dp->context_u;
	*len = PAGE_SIZE - dp->context_u;
}

static void vm_next_page(struct dpages *dp)
{
	dp->context_ptr += PAGE_SIZE - dp->context_u;
	dp->context_u = 0;
}

static void vm_dp_init(struct dpages *dp, void *data)
{
	dp->get_page = vm_get_page;
	dp->next_page = vm_next_page;
	dp->context_u = ((unsigned long) data) & (PAGE_SIZE - 1);
	dp->context_ptr = data;
}

static void km_get_page(struct dpages *dp, struct page **p, unsigned long *len,
			unsigned *offset)
{
	*p = virt_to_page(dp->context_ptr);
	*offset = dp->context_u;
	*len = PAGE_SIZE - dp->context_u;
}

static void km_next_page(struct dpages *dp)
{
	dp->context_ptr += PAGE_SIZE - dp->context_u;
	dp->context_u = 0;
}

static void km_dp_init(struct dpages *dp, void *data)
{
	dp->get_page = km_get_page;
	dp->next_page = km_next_page;
	dp->context_u = ((unsigned long) data) & (PAGE_SIZE - 1);
	dp->context_ptr = data;
}

static void do_region(int rw, unsigned region, struct dm_io_region *where,
		      struct dpages *dp, struct io *io)
{
	struct bio *bio;
	struct page *page;
	unsigned long len;
	unsigned offset;
	unsigned num_bvecs;
	sector_t remaining = where->count;
	struct request_queue *q = bdev_get_queue(where->bdev);
	unsigned short logical_block_size = queue_logical_block_size(q);
	sector_t num_sectors;
	unsigned int uninitialized_var(special_cmd_max_sectors);

	if (rw & REQ_DISCARD)
		special_cmd_max_sectors = q->limits.max_discard_sectors;
	else if (rw & REQ_WRITE_SAME)
		special_cmd_max_sectors = q->limits.max_write_same_sectors;
	if ((rw & (REQ_DISCARD | REQ_WRITE_SAME)) && special_cmd_max_sectors == 0) {
		dec_count(io, region, -EOPNOTSUPP);
		return;
	}

	do {
		 
		if ((rw & REQ_DISCARD) || (rw & REQ_WRITE_SAME))
			num_bvecs = 1;
		else
			num_bvecs = min_t(int, BIO_MAX_PAGES,
					  dm_sector_div_up(remaining, (PAGE_SIZE >> SECTOR_SHIFT)));

		bio = bio_alloc_bioset(GFP_NOIO, num_bvecs, io->client->bios);
		bio->bi_iter.bi_sector = where->sector + (where->count - remaining);
		bio->bi_bdev = where->bdev;
		bio->bi_end_io = endio;

		store_io_and_region_in_bio(bio, io, region);

		if (rw & REQ_DISCARD) {
			num_sectors = min_t(sector_t, special_cmd_max_sectors, remaining);
			bio->bi_iter.bi_size = num_sectors << SECTOR_SHIFT;
			remaining -= num_sectors;
		} else if (rw & REQ_WRITE_SAME) {
			 
			dp->get_page(dp, &page, &len, &offset);
			bio_add_page(bio, page, logical_block_size, offset);
			num_sectors = min_t(sector_t, special_cmd_max_sectors, remaining);
			bio->bi_iter.bi_size = num_sectors << SECTOR_SHIFT;

			offset = 0;
			remaining -= num_sectors;
			dp->next_page(dp);
		} else while (remaining) {
			 
			dp->get_page(dp, &page, &len, &offset);
			len = min(len, to_bytes(remaining));
			if (!bio_add_page(bio, page, len, offset))
				break;

			offset = 0;
			remaining -= to_sector(len);
			dp->next_page(dp);
		}

		atomic_inc(&io->count);
#ifdef MY_ABC_HERE
		bio->bi_flags |= io->bi_flags;
		if (has_correction_flag(io->bi_flags)) {
			sinfo("bio start=%llu size=%llu", (u64)bio->bi_iter.bi_sector, (u64)to_sector(bio->bi_iter.bi_size));
		}
#endif  
		submit_bio(rw, bio);
	} while (remaining);
}

static void dispatch_io(int rw, unsigned int num_regions,
			struct dm_io_region *where, struct dpages *dp,
			struct io *io, int sync)
{
	int i;
	struct dpages old_pages = *dp;

	BUG_ON(num_regions > DM_IO_MAX_REGIONS);

	if (sync)
		rw |= REQ_SYNC;

	for (i = 0; i < num_regions; i++) {
		*dp = old_pages;
		if (where[i].count || (rw & REQ_FLUSH))
			do_region(rw, i, where + i, dp, io);
	}

	dec_count(io, 0, 0);
}

struct sync_io {
	unsigned long error_bits;
	struct completion wait;
};

static void sync_io_complete(unsigned long error, void *context)
{
	struct sync_io *sio = context;

	sio->error_bits = error;
	complete(&sio->wait);
}

#ifdef MY_ABC_HERE
static int sync_io(struct dm_io_client *client, unsigned int num_regions,
		   struct dm_io_region *where, int rw, struct dpages *dp,
		   unsigned long *error_bits, unsigned long bi_flags)
#else
static int sync_io(struct dm_io_client *client, unsigned int num_regions,
		   struct dm_io_region *where, int rw, struct dpages *dp,
		   unsigned long *error_bits)
#endif  
{
	struct io *io;
	struct sync_io sio;

	if (num_regions > 1 && (rw & RW_MASK) != WRITE) {
		WARN_ON(1);
		return -EIO;
	}

	init_completion(&sio.wait);

	io = mempool_alloc(client->pool, GFP_NOIO);
	io->error_bits = 0;
	atomic_set(&io->count, 1);  
	io->client = client;
	io->callback = sync_io_complete;
	io->context = &sio;

	io->vma_invalidate_address = dp->vma_invalidate_address;
	io->vma_invalidate_size = dp->vma_invalidate_size;
#ifdef MY_ABC_HERE
	if (has_correction_flag(bi_flags)) {
		sinfo("add io flags start");
	}

	io->bi_flags = bi_flags;

	if (has_correction_flag(bi_flags)) {
		sinfo("add io flags finish");
	}
#endif  

	dispatch_io(rw, num_regions, where, dp, io, 1);

	wait_for_completion_io(&sio.wait);

	if (error_bits)
		*error_bits = sio.error_bits;

	return sio.error_bits ? -EIO : 0;
}

#ifdef MY_ABC_HERE
static int async_io(struct dm_io_client *client, unsigned int num_regions,
		    struct dm_io_region *where, int rw, struct dpages *dp,
		    io_notify_fn fn, void *context, unsigned long bi_flags)
#else
static int async_io(struct dm_io_client *client, unsigned int num_regions,
		    struct dm_io_region *where, int rw, struct dpages *dp,
		    io_notify_fn fn, void *context)
#endif  
{
	struct io *io;

	if (num_regions > 1 && (rw & RW_MASK) != WRITE) {
		WARN_ON(1);
		fn(1, context);
		return -EIO;
	}

	io = mempool_alloc(client->pool, GFP_NOIO);
	io->error_bits = 0;
	atomic_set(&io->count, 1);  
	io->client = client;
	io->callback = fn;
	io->context = context;
#ifdef MY_ABC_HERE
	io->bi_flags = bi_flags;

	if (has_correction_flag(bi_flags)) {
		sinfo("set bi_flags=%lx", bi_flags);
	}
#endif  

	io->vma_invalidate_address = dp->vma_invalidate_address;
	io->vma_invalidate_size = dp->vma_invalidate_size;

	dispatch_io(rw, num_regions, where, dp, io, 0);
	return 0;
}

static int dp_init(struct dm_io_request *io_req, struct dpages *dp,
		   unsigned long size)
{
	 
	dp->vma_invalidate_address = NULL;
	dp->vma_invalidate_size = 0;

	switch (io_req->mem.type) {
	case DM_IO_PAGE_LIST:
		list_dp_init(dp, io_req->mem.ptr.pl, io_req->mem.offset);
		break;

	case DM_IO_BIO:
		bio_dp_init(dp, io_req->mem.ptr.bio);
		break;

	case DM_IO_VMA:
		flush_kernel_vmap_range(io_req->mem.ptr.vma, size);
		if ((io_req->bi_rw & RW_MASK) == READ) {
			dp->vma_invalidate_address = io_req->mem.ptr.vma;
			dp->vma_invalidate_size = size;
		}
		vm_dp_init(dp, io_req->mem.ptr.vma);
		break;

	case DM_IO_KMEM:
		km_dp_init(dp, io_req->mem.ptr.addr);
		break;

	default:
		return -EINVAL;
	}

	return 0;
}
#ifdef MY_ABC_HERE
 
int syno_dm_io(struct dm_io_request *io_req, unsigned num_regions,
	  struct dm_io_region *where, unsigned long *sync_error_bits, unsigned long bi_flags)
{
	int r;
	struct dpages dp;
	if (has_correction_flag(bi_flags)) {
		sinfo("set extra bi_flags=%lx", bi_flags);
	}

	bi_flags |= 1 << BIO_MD_RETURN_ERROR;

	r = dp_init(io_req, &dp, (unsigned long)where->count << SECTOR_SHIFT);
	if (r)
		return r;

	if (!io_req->notify.fn)
		return sync_io(io_req->client, num_regions, where,
			       io_req->bi_rw, &dp, sync_error_bits, bi_flags);
	return async_io(io_req->client, num_regions, where, io_req->bi_rw,
			&dp, io_req->notify.fn, io_req->notify.context, bi_flags);
}
EXPORT_SYMBOL(syno_dm_io);
#endif  

int dm_io(struct dm_io_request *io_req, unsigned num_regions,
	  struct dm_io_region *where, unsigned long *sync_error_bits)
{
	int r;
	struct dpages dp;

	r = dp_init(io_req, &dp, (unsigned long)where->count << SECTOR_SHIFT);
	if (r)
		return r;

#ifdef MY_ABC_HERE
	if (!io_req->notify.fn)
		return sync_io(io_req->client, num_regions, where,
			       io_req->bi_rw, &dp, sync_error_bits, 0);
	return async_io(io_req->client, num_regions, where, io_req->bi_rw,
			&dp, io_req->notify.fn, io_req->notify.context, 0);
#else
	if (!io_req->notify.fn)
		return sync_io(io_req->client, num_regions, where,
			       io_req->bi_rw, &dp, sync_error_bits);

	return async_io(io_req->client, num_regions, where, io_req->bi_rw,
			&dp, io_req->notify.fn, io_req->notify.context);
#endif  
}
EXPORT_SYMBOL(dm_io);

int __init dm_io_init(void)
{
	_dm_io_cache = KMEM_CACHE(io, 0);
	if (!_dm_io_cache)
		return -ENOMEM;

	return 0;
}

void dm_io_exit(void)
{
	kmem_cache_destroy(_dm_io_cache);
	_dm_io_cache = NULL;
}
