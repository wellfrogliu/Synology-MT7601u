#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/uio.h>
#include <linux/iocontext.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/mempool.h>
#include <linux/workqueue.h>
#include <linux/cgroup.h>

#include <trace/events/block.h>

#define BIO_INLINE_VECS		4

#define BV(x) { .nr_vecs = x, .name = "biovec-"__stringify(x) }
static struct biovec_slab bvec_slabs[BIOVEC_NR_POOLS] __read_mostly = {
	BV(1), BV(4), BV(16), BV(64), BV(128), BV(BIO_MAX_PAGES),
};
#undef BV

struct bio_set *fs_bio_set;
EXPORT_SYMBOL(fs_bio_set);

struct bio_slab {
	struct kmem_cache *slab;
	unsigned int slab_ref;
	unsigned int slab_size;
	char name[8];
};
static DEFINE_MUTEX(bio_slab_lock);
static struct bio_slab *bio_slabs;
static unsigned int bio_slab_nr, bio_slab_max;

static struct kmem_cache *bio_find_or_create_slab(unsigned int extra_size)
{
	unsigned int sz = sizeof(struct bio) + extra_size;
	struct kmem_cache *slab = NULL;
	struct bio_slab *bslab, *new_bio_slabs;
	unsigned int new_bio_slab_max;
	unsigned int i, entry = -1;

	mutex_lock(&bio_slab_lock);

	i = 0;
	while (i < bio_slab_nr) {
		bslab = &bio_slabs[i];

		if (!bslab->slab && entry == -1)
			entry = i;
		else if (bslab->slab_size == sz) {
			slab = bslab->slab;
			bslab->slab_ref++;
			break;
		}
		i++;
	}

	if (slab)
		goto out_unlock;

	if (bio_slab_nr == bio_slab_max && entry == -1) {
		new_bio_slab_max = bio_slab_max << 1;
		new_bio_slabs = krealloc(bio_slabs,
					 new_bio_slab_max * sizeof(struct bio_slab),
					 GFP_KERNEL);
		if (!new_bio_slabs)
			goto out_unlock;
		bio_slab_max = new_bio_slab_max;
		bio_slabs = new_bio_slabs;
	}
	if (entry == -1)
		entry = bio_slab_nr++;

	bslab = &bio_slabs[entry];

	snprintf(bslab->name, sizeof(bslab->name), "bio-%d", entry);
	slab = kmem_cache_create(bslab->name, sz, ARCH_KMALLOC_MINALIGN,
				 SLAB_HWCACHE_ALIGN, NULL);
	if (!slab)
		goto out_unlock;

	bslab->slab = slab;
	bslab->slab_ref = 1;
	bslab->slab_size = sz;
out_unlock:
	mutex_unlock(&bio_slab_lock);
	return slab;
}

static void bio_put_slab(struct bio_set *bs)
{
	struct bio_slab *bslab = NULL;
	unsigned int i;

	mutex_lock(&bio_slab_lock);

	for (i = 0; i < bio_slab_nr; i++) {
		if (bs->bio_slab == bio_slabs[i].slab) {
			bslab = &bio_slabs[i];
			break;
		}
	}

	if (WARN(!bslab, KERN_ERR "bio: unable to find slab!\n"))
		goto out;

	WARN_ON(!bslab->slab_ref);

	if (--bslab->slab_ref)
		goto out;

	kmem_cache_destroy(bslab->slab);
	bslab->slab = NULL;

out:
	mutex_unlock(&bio_slab_lock);
}

unsigned int bvec_nr_vecs(unsigned short idx)
{
	return bvec_slabs[idx].nr_vecs;
}

void bvec_free(mempool_t *pool, struct bio_vec *bv, unsigned int idx)
{
	BIO_BUG_ON(idx >= BIOVEC_NR_POOLS);

	if (idx == BIOVEC_MAX_IDX)
		mempool_free(bv, pool);
	else {
		struct biovec_slab *bvs = bvec_slabs + idx;

		kmem_cache_free(bvs->slab, bv);
	}
}

struct bio_vec *bvec_alloc(gfp_t gfp_mask, int nr, unsigned long *idx,
			   mempool_t *pool)
{
	struct bio_vec *bvl;

	switch (nr) {
	case 1:
		*idx = 0;
		break;
	case 2 ... 4:
		*idx = 1;
		break;
	case 5 ... 16:
		*idx = 2;
		break;
	case 17 ... 64:
		*idx = 3;
		break;
	case 65 ... 128:
		*idx = 4;
		break;
	case 129 ... BIO_MAX_PAGES:
		*idx = 5;
		break;
	default:
		return NULL;
	}

	if (*idx == BIOVEC_MAX_IDX) {
fallback:
		bvl = mempool_alloc(pool, gfp_mask);
	} else {
		struct biovec_slab *bvs = bvec_slabs + *idx;
		gfp_t __gfp_mask = gfp_mask & ~(__GFP_DIRECT_RECLAIM | __GFP_IO);

		__gfp_mask |= __GFP_NOMEMALLOC | __GFP_NORETRY | __GFP_NOWARN;

		bvl = kmem_cache_alloc(bvs->slab, __gfp_mask);
		if (unlikely(!bvl && (gfp_mask & __GFP_DIRECT_RECLAIM))) {
			*idx = BIOVEC_MAX_IDX;
			goto fallback;
		}
	}

	return bvl;
}

static void __bio_free(struct bio *bio)
{
	bio_disassociate_task(bio);

	if (bio_integrity(bio))
		bio_integrity_free(bio);
}

static void bio_free(struct bio *bio)
{
	struct bio_set *bs = bio->bi_pool;
	void *p;

	__bio_free(bio);

	if (bs) {
		if (bio_flagged(bio, BIO_OWNS_VEC))
			bvec_free(bs->bvec_pool, bio->bi_io_vec, BIO_POOL_IDX(bio));

		p = bio;
		p -= bs->front_pad;

		mempool_free(p, bs->bio_pool);
	} else {
		 
		kfree(bio);
	}
}

void bio_init(struct bio *bio)
{
	memset(bio, 0, sizeof(*bio));
	atomic_set(&bio->__bi_remaining, 1);
	atomic_set(&bio->__bi_cnt, 1);
}
EXPORT_SYMBOL(bio_init);

void bio_reset(struct bio *bio)
{
	unsigned long flags = bio->bi_flags & (~0UL << BIO_RESET_BITS);

	__bio_free(bio);

	memset(bio, 0, BIO_RESET_BYTES);
	bio->bi_flags = flags;
	atomic_set(&bio->__bi_remaining, 1);
}
EXPORT_SYMBOL(bio_reset);

static void bio_chain_endio(struct bio *bio)
{
	struct bio *parent = bio->bi_private;

	parent->bi_error = bio->bi_error;
	bio_endio(parent);
	bio_put(bio);
}

static inline void bio_inc_remaining(struct bio *bio)
{
	bio_set_flag(bio, BIO_CHAIN);
	smp_mb__before_atomic();
	atomic_inc(&bio->__bi_remaining);
}

void bio_chain(struct bio *bio, struct bio *parent)
{
	BUG_ON(bio->bi_private || bio->bi_end_io);

	bio->bi_private = parent;
	bio->bi_end_io	= bio_chain_endio;
	bio_inc_remaining(parent);
}
EXPORT_SYMBOL(bio_chain);

static void bio_alloc_rescue(struct work_struct *work)
{
	struct bio_set *bs = container_of(work, struct bio_set, rescue_work);
	struct bio *bio;

	while (1) {
		spin_lock(&bs->rescue_lock);
		bio = bio_list_pop(&bs->rescue_list);
		spin_unlock(&bs->rescue_lock);

		if (!bio)
			break;

		generic_make_request(bio);
	}
}

static void punt_bios_to_rescuer(struct bio_set *bs)
{
	struct bio_list punt, nopunt;
	struct bio *bio;

	bio_list_init(&punt);
	bio_list_init(&nopunt);

	while ((bio = bio_list_pop(current->bio_list)))
		bio_list_add(bio->bi_pool == bs ? &punt : &nopunt, bio);

	*current->bio_list = nopunt;

	spin_lock(&bs->rescue_lock);
	bio_list_merge(&bs->rescue_list, &punt);
	spin_unlock(&bs->rescue_lock);

	queue_work(bs->rescue_workqueue, &bs->rescue_work);
}

struct bio *bio_alloc_bioset(gfp_t gfp_mask, int nr_iovecs, struct bio_set *bs)
{
	gfp_t saved_gfp = gfp_mask;
	unsigned front_pad;
	unsigned inline_vecs;
	unsigned long idx = BIO_POOL_NONE;
	struct bio_vec *bvl = NULL;
	struct bio *bio;
	void *p;

	if (!bs) {
		if (nr_iovecs > UIO_MAXIOV)
			return NULL;

		p = kmalloc(sizeof(struct bio) +
			    nr_iovecs * sizeof(struct bio_vec),
			    gfp_mask);
		front_pad = 0;
		inline_vecs = nr_iovecs;
	} else {
		 
		if (WARN_ON_ONCE(!bs->bvec_pool && nr_iovecs > 0))
			return NULL;
		 
		if (current->bio_list && !bio_list_empty(current->bio_list))
			gfp_mask &= ~__GFP_DIRECT_RECLAIM;

		p = mempool_alloc(bs->bio_pool, gfp_mask);
		if (!p && gfp_mask != saved_gfp) {
			punt_bios_to_rescuer(bs);
			gfp_mask = saved_gfp;
			p = mempool_alloc(bs->bio_pool, gfp_mask);
		}

		front_pad = bs->front_pad;
		inline_vecs = BIO_INLINE_VECS;
	}

	if (unlikely(!p))
		return NULL;

	bio = p + front_pad;
	bio_init(bio);

	if (nr_iovecs > inline_vecs) {
		bvl = bvec_alloc(gfp_mask, nr_iovecs, &idx, bs->bvec_pool);
		if (!bvl && gfp_mask != saved_gfp) {
			punt_bios_to_rescuer(bs);
			gfp_mask = saved_gfp;
			bvl = bvec_alloc(gfp_mask, nr_iovecs, &idx, bs->bvec_pool);
		}

		if (unlikely(!bvl))
			goto err_free;

		bio_set_flag(bio, BIO_OWNS_VEC);
	} else if (nr_iovecs) {
		bvl = bio->bi_inline_vecs;
	}

	bio->bi_pool = bs;
	bio->bi_flags |= idx << BIO_POOL_OFFSET;
	bio->bi_max_vecs = nr_iovecs;
	bio->bi_io_vec = bvl;
	return bio;

err_free:
	mempool_free(p, bs->bio_pool);
	return NULL;
}
EXPORT_SYMBOL(bio_alloc_bioset);

void zero_fill_bio(struct bio *bio)
{
	unsigned long flags;
	struct bio_vec bv;
	struct bvec_iter iter;

	bio_for_each_segment(bv, bio, iter) {
		char *data = bvec_kmap_irq(&bv, &flags);
		memset(data, 0, bv.bv_len);
		flush_dcache_page(bv.bv_page);
		bvec_kunmap_irq(data, &flags);
	}
}
EXPORT_SYMBOL(zero_fill_bio);

void bio_put(struct bio *bio)
{
	if (!bio_flagged(bio, BIO_REFFED))
		bio_free(bio);
	else {
		BIO_BUG_ON(!atomic_read(&bio->__bi_cnt));

		if (atomic_dec_and_test(&bio->__bi_cnt))
			bio_free(bio);
	}
}
EXPORT_SYMBOL(bio_put);

inline int bio_phys_segments(struct request_queue *q, struct bio *bio)
{
	if (unlikely(!bio_flagged(bio, BIO_SEG_VALID)))
		blk_recount_segments(q, bio);

	return bio->bi_phys_segments;
}
EXPORT_SYMBOL(bio_phys_segments);

void __bio_clone_fast(struct bio *bio, struct bio *bio_src)
{
	BUG_ON(bio->bi_pool && BIO_POOL_IDX(bio) != BIO_POOL_NONE);

	bio->bi_bdev = bio_src->bi_bdev;
	bio_set_flag(bio, BIO_CLONED);
	bio->bi_rw = bio_src->bi_rw;
	bio->bi_iter = bio_src->bi_iter;
	bio->bi_io_vec = bio_src->bi_io_vec;
#ifdef MY_ABC_HERE
	 
	bio->bi_vcnt = bio_src->bi_vcnt;
#endif

	bio_clone_blkcg_association(bio, bio_src);
}
EXPORT_SYMBOL(__bio_clone_fast);

struct bio *bio_clone_fast(struct bio *bio, gfp_t gfp_mask, struct bio_set *bs)
{
	struct bio *b;

	b = bio_alloc_bioset(gfp_mask, 0, bs);
	if (!b)
		return NULL;

	__bio_clone_fast(b, bio);

	if (bio_integrity(bio)) {
		int ret;

		ret = bio_integrity_clone(b, bio, gfp_mask);

		if (ret < 0) {
			bio_put(b);
			return NULL;
		}
	}

	return b;
}
EXPORT_SYMBOL(bio_clone_fast);

struct bio *bio_clone_bioset(struct bio *bio_src, gfp_t gfp_mask,
			     struct bio_set *bs)
{
	struct bvec_iter iter;
	struct bio_vec bv;
	struct bio *bio;

	bio = bio_alloc_bioset(gfp_mask, bio_segments(bio_src), bs);
	if (!bio)
		return NULL;

	bio->bi_bdev		= bio_src->bi_bdev;
	bio->bi_rw		= bio_src->bi_rw;
	bio->bi_iter.bi_sector	= bio_src->bi_iter.bi_sector;
	bio->bi_iter.bi_size	= bio_src->bi_iter.bi_size;

	if (bio->bi_rw & REQ_DISCARD)
		goto integrity_clone;

	if (bio->bi_rw & REQ_WRITE_SAME) {
		bio->bi_io_vec[bio->bi_vcnt++] = bio_src->bi_io_vec[0];
		goto integrity_clone;
	}

	bio_for_each_segment(bv, bio_src, iter)
		bio->bi_io_vec[bio->bi_vcnt++] = bv;

integrity_clone:
	if (bio_integrity(bio_src)) {
		int ret;

		ret = bio_integrity_clone(bio, bio_src, gfp_mask);
		if (ret < 0) {
			bio_put(bio);
			return NULL;
		}
	}

	bio_clone_blkcg_association(bio, bio_src);

	return bio;
}
EXPORT_SYMBOL(bio_clone_bioset);

int bio_add_pc_page(struct request_queue *q, struct bio *bio, struct page
		    *page, unsigned int len, unsigned int offset)
{
	int retried_segments = 0;
	struct bio_vec *bvec;

	if (unlikely(bio_flagged(bio, BIO_CLONED)))
		return 0;

	if (((bio->bi_iter.bi_size + len) >> 9) > queue_max_hw_sectors(q))
		return 0;

	if (bio->bi_vcnt > 0) {
		struct bio_vec *prev = &bio->bi_io_vec[bio->bi_vcnt - 1];

		if (page == prev->bv_page &&
		    offset == prev->bv_offset + prev->bv_len) {
			prev->bv_len += len;
			bio->bi_iter.bi_size += len;
			goto done;
		}

		if (bvec_gap_to_prev(q, prev, offset))
			return 0;
	}

	if (bio->bi_vcnt >= bio->bi_max_vecs)
		return 0;

	bvec = &bio->bi_io_vec[bio->bi_vcnt];
	bvec->bv_page = page;
	bvec->bv_len = len;
	bvec->bv_offset = offset;
	bio->bi_vcnt++;
	bio->bi_phys_segments++;
	bio->bi_iter.bi_size += len;

	while (bio->bi_phys_segments > queue_max_segments(q)) {

		if (retried_segments)
			goto failed;

		retried_segments = 1;
		blk_recount_segments(q, bio);
	}

	if (bio->bi_vcnt > 1 && (BIOVEC_PHYS_MERGEABLE(bvec-1, bvec)))
		bio_clear_flag(bio, BIO_SEG_VALID);

 done:
	return len;

 failed:
	bvec->bv_page = NULL;
	bvec->bv_len = 0;
	bvec->bv_offset = 0;
	bio->bi_vcnt--;
	bio->bi_iter.bi_size -= len;
	blk_recount_segments(q, bio);
	return 0;
}
EXPORT_SYMBOL(bio_add_pc_page);

int bio_add_page(struct bio *bio, struct page *page,
		 unsigned int len, unsigned int offset)
{
	struct bio_vec *bv;

	if (WARN_ON_ONCE(bio_flagged(bio, BIO_CLONED)))
		return 0;

	if (bio->bi_vcnt > 0) {
		bv = &bio->bi_io_vec[bio->bi_vcnt - 1];

		if (page == bv->bv_page &&
		    offset == bv->bv_offset + bv->bv_len) {
			bv->bv_len += len;
			goto done;
		}
	}

	if (bio->bi_vcnt >= bio->bi_max_vecs)
		return 0;

	bv		= &bio->bi_io_vec[bio->bi_vcnt];
	bv->bv_page	= page;
	bv->bv_len	= len;
	bv->bv_offset	= offset;

	bio->bi_vcnt++;
done:
	bio->bi_iter.bi_size += len;
	return len;
}
EXPORT_SYMBOL(bio_add_page);

struct submit_bio_ret {
	struct completion event;
	int error;
};

static void submit_bio_wait_endio(struct bio *bio)
{
	struct submit_bio_ret *ret = bio->bi_private;

	ret->error = bio->bi_error;
	complete(&ret->event);
}

int submit_bio_wait(int rw, struct bio *bio)
{
	struct submit_bio_ret ret;

	rw |= REQ_SYNC;
	init_completion(&ret.event);
	bio->bi_private = &ret;
	bio->bi_end_io = submit_bio_wait_endio;
	submit_bio(rw, bio);
	wait_for_completion(&ret.event);

	return ret.error;
}
EXPORT_SYMBOL(submit_bio_wait);

void bio_advance(struct bio *bio, unsigned bytes)
{
	if (bio_integrity(bio))
		bio_integrity_advance(bio, bytes);

	bio_advance_iter(bio, &bio->bi_iter, bytes);
}
EXPORT_SYMBOL(bio_advance);

int bio_alloc_pages(struct bio *bio, gfp_t gfp_mask)
{
	int i;
	struct bio_vec *bv;

	bio_for_each_segment_all(bv, bio, i) {
		bv->bv_page = alloc_page(gfp_mask);
		if (!bv->bv_page) {
			while (--bv >= bio->bi_io_vec)
				__free_page(bv->bv_page);
			return -ENOMEM;
		}
	}

	return 0;
}
EXPORT_SYMBOL(bio_alloc_pages);

void bio_copy_data(struct bio *dst, struct bio *src)
{
	struct bvec_iter src_iter, dst_iter;
	struct bio_vec src_bv, dst_bv;
	void *src_p, *dst_p;
	unsigned bytes;

	src_iter = src->bi_iter;
	dst_iter = dst->bi_iter;

	while (1) {
		if (!src_iter.bi_size) {
			src = src->bi_next;
			if (!src)
				break;

			src_iter = src->bi_iter;
		}

		if (!dst_iter.bi_size) {
			dst = dst->bi_next;
			if (!dst)
				break;

			dst_iter = dst->bi_iter;
		}

		src_bv = bio_iter_iovec(src, src_iter);
		dst_bv = bio_iter_iovec(dst, dst_iter);

		bytes = min(src_bv.bv_len, dst_bv.bv_len);

		src_p = kmap_atomic(src_bv.bv_page);
		dst_p = kmap_atomic(dst_bv.bv_page);

		memcpy(dst_p + dst_bv.bv_offset,
		       src_p + src_bv.bv_offset,
		       bytes);

		kunmap_atomic(dst_p);
		kunmap_atomic(src_p);

		bio_advance_iter(src, &src_iter, bytes);
		bio_advance_iter(dst, &dst_iter, bytes);
	}
}
EXPORT_SYMBOL(bio_copy_data);

struct bio_map_data {
	int is_our_pages;
	struct iov_iter iter;
	struct iovec iov[];
};

static struct bio_map_data *bio_alloc_map_data(unsigned int iov_count,
					       gfp_t gfp_mask)
{
	if (iov_count > UIO_MAXIOV)
		return NULL;

	return kmalloc(sizeof(struct bio_map_data) +
		       sizeof(struct iovec) * iov_count, gfp_mask);
}

static int bio_copy_from_iter(struct bio *bio, struct iov_iter iter)
{
	int i;
	struct bio_vec *bvec;

	bio_for_each_segment_all(bvec, bio, i) {
		ssize_t ret;

		ret = copy_page_from_iter(bvec->bv_page,
					  bvec->bv_offset,
					  bvec->bv_len,
					  &iter);

		if (!iov_iter_count(&iter))
			break;

		if (ret < bvec->bv_len)
			return -EFAULT;
	}

	return 0;
}

static int bio_copy_to_iter(struct bio *bio, struct iov_iter iter)
{
	int i;
	struct bio_vec *bvec;

	bio_for_each_segment_all(bvec, bio, i) {
		ssize_t ret;

		ret = copy_page_to_iter(bvec->bv_page,
					bvec->bv_offset,
					bvec->bv_len,
					&iter);

		if (!iov_iter_count(&iter))
			break;

		if (ret < bvec->bv_len)
			return -EFAULT;
	}

	return 0;
}

static void bio_free_pages(struct bio *bio)
{
	struct bio_vec *bvec;
	int i;

	bio_for_each_segment_all(bvec, bio, i)
		__free_page(bvec->bv_page);
}

int bio_uncopy_user(struct bio *bio)
{
	struct bio_map_data *bmd = bio->bi_private;
	int ret = 0;

	if (!bio_flagged(bio, BIO_NULL_MAPPED)) {
		 
		if (!current->mm)
			ret = -EINTR;
		else if (bio_data_dir(bio) == READ)
			ret = bio_copy_to_iter(bio, bmd->iter);
		if (bmd->is_our_pages)
			bio_free_pages(bio);
	}
	kfree(bmd);
	bio_put(bio);
	return ret;
}
EXPORT_SYMBOL(bio_uncopy_user);

struct bio *bio_copy_user_iov(struct request_queue *q,
			      struct rq_map_data *map_data,
			      const struct iov_iter *iter,
			      gfp_t gfp_mask)
{
	struct bio_map_data *bmd;
	struct page *page;
	struct bio *bio;
	int i, ret;
	int nr_pages = 0;
	unsigned int len = iter->count;
	unsigned int offset = map_data ? map_data->offset & ~PAGE_MASK : 0;

	for (i = 0; i < iter->nr_segs; i++) {
		unsigned long uaddr;
		unsigned long end;
		unsigned long start;

		uaddr = (unsigned long) iter->iov[i].iov_base;
		end = (uaddr + iter->iov[i].iov_len + PAGE_SIZE - 1)
			>> PAGE_SHIFT;
		start = uaddr >> PAGE_SHIFT;

		if (end < start)
			return ERR_PTR(-EINVAL);

		nr_pages += end - start;
	}

	if (offset)
		nr_pages++;

	bmd = bio_alloc_map_data(iter->nr_segs, gfp_mask);
	if (!bmd)
		return ERR_PTR(-ENOMEM);

	bmd->is_our_pages = map_data ? 0 : 1;
	memcpy(bmd->iov, iter->iov, sizeof(struct iovec) * iter->nr_segs);
	iov_iter_init(&bmd->iter, iter->type, bmd->iov,
			iter->nr_segs, iter->count);

	ret = -ENOMEM;
	bio = bio_kmalloc(gfp_mask, nr_pages);
	if (!bio)
		goto out_bmd;

	if (iter->type & WRITE)
		bio->bi_rw |= REQ_WRITE;

	ret = 0;

	if (map_data) {
		nr_pages = 1 << map_data->page_order;
		i = map_data->offset / PAGE_SIZE;
	}
	while (len) {
		unsigned int bytes = PAGE_SIZE;

		bytes -= offset;

		if (bytes > len)
			bytes = len;

		if (map_data) {
			if (i == map_data->nr_entries * nr_pages) {
				ret = -ENOMEM;
				break;
			}

			page = map_data->pages[i / nr_pages];
			page += (i % nr_pages);

			i++;
		} else {
			page = alloc_page(q->bounce_gfp | gfp_mask);
			if (!page) {
				ret = -ENOMEM;
				break;
			}
		}

		if (bio_add_pc_page(q, bio, page, bytes, offset) < bytes)
			break;

		len -= bytes;
		offset = 0;
	}

	if (ret)
		goto cleanup;

	if (((iter->type & WRITE) && (!map_data || !map_data->null_mapped)) ||
	    (map_data && map_data->from_user)) {
		ret = bio_copy_from_iter(bio, *iter);
		if (ret)
			goto cleanup;
	}

	bio->bi_private = bmd;
	return bio;
cleanup:
	if (!map_data)
		bio_free_pages(bio);
	bio_put(bio);
out_bmd:
	kfree(bmd);
	return ERR_PTR(ret);
}

struct bio *bio_map_user_iov(struct request_queue *q,
			     const struct iov_iter *iter,
			     gfp_t gfp_mask)
{
	int j;
	int nr_pages = 0;
	struct page **pages;
	struct bio *bio;
	int cur_page = 0;
	int ret, offset;
	struct iov_iter i;
	struct iovec iov;

	iov_for_each(iov, i, *iter) {
		unsigned long uaddr = (unsigned long) iov.iov_base;
		unsigned long len = iov.iov_len;
		unsigned long end = (uaddr + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
		unsigned long start = uaddr >> PAGE_SHIFT;

		if (end < start)
			return ERR_PTR(-EINVAL);

		nr_pages += end - start;
		 
		if (uaddr & queue_dma_alignment(q))
			return ERR_PTR(-EINVAL);
	}

	if (!nr_pages)
		return ERR_PTR(-EINVAL);

	bio = bio_kmalloc(gfp_mask, nr_pages);
	if (!bio)
		return ERR_PTR(-ENOMEM);

	ret = -ENOMEM;
	pages = kcalloc(nr_pages, sizeof(struct page *), gfp_mask);
	if (!pages)
		goto out;

	iov_for_each(iov, i, *iter) {
		unsigned long uaddr = (unsigned long) iov.iov_base;
		unsigned long len = iov.iov_len;
		unsigned long end = (uaddr + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
		unsigned long start = uaddr >> PAGE_SHIFT;
		const int local_nr_pages = end - start;
		const int page_limit = cur_page + local_nr_pages;

		ret = get_user_pages_fast(uaddr, local_nr_pages,
				(iter->type & WRITE) != WRITE,
				&pages[cur_page]);
		if (ret < local_nr_pages) {
			ret = -EFAULT;
			goto out_unmap;
		}

		offset = uaddr & ~PAGE_MASK;
		for (j = cur_page; j < page_limit; j++) {
			unsigned int bytes = PAGE_SIZE - offset;

			if (len <= 0)
				break;
			
			if (bytes > len)
				bytes = len;

			if (bio_add_pc_page(q, bio, pages[j], bytes, offset) <
					    bytes)
				break;

			len -= bytes;
			offset = 0;
		}

		cur_page = j;
		 
		while (j < page_limit)
			page_cache_release(pages[j++]);
	}

	kfree(pages);

	if (iter->type & WRITE)
		bio->bi_rw |= REQ_WRITE;

	bio_set_flag(bio, BIO_USER_MAPPED);

	bio_get(bio);
	return bio;

 out_unmap:
	for (j = 0; j < nr_pages; j++) {
		if (!pages[j])
			break;
		page_cache_release(pages[j]);
	}
 out:
	kfree(pages);
	bio_put(bio);
	return ERR_PTR(ret);
}

static void __bio_unmap_user(struct bio *bio)
{
	struct bio_vec *bvec;
	int i;

	bio_for_each_segment_all(bvec, bio, i) {
		if (bio_data_dir(bio) == READ)
			set_page_dirty_lock(bvec->bv_page);

		page_cache_release(bvec->bv_page);
	}

	bio_put(bio);
}

void bio_unmap_user(struct bio *bio)
{
	__bio_unmap_user(bio);
	bio_put(bio);
}
EXPORT_SYMBOL(bio_unmap_user);

static void bio_map_kern_endio(struct bio *bio)
{
	bio_put(bio);
}

struct bio *bio_map_kern(struct request_queue *q, void *data, unsigned int len,
			 gfp_t gfp_mask)
{
	unsigned long kaddr = (unsigned long)data;
	unsigned long end = (kaddr + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	unsigned long start = kaddr >> PAGE_SHIFT;
	const int nr_pages = end - start;
	int offset, i;
	struct bio *bio;

	bio = bio_kmalloc(gfp_mask, nr_pages);
	if (!bio)
		return ERR_PTR(-ENOMEM);

	offset = offset_in_page(kaddr);
	for (i = 0; i < nr_pages; i++) {
		unsigned int bytes = PAGE_SIZE - offset;

		if (len <= 0)
			break;

		if (bytes > len)
			bytes = len;

		if (bio_add_pc_page(q, bio, virt_to_page(data), bytes,
				    offset) < bytes) {
			 
			bio_put(bio);
			return ERR_PTR(-EINVAL);
		}

		data += bytes;
		len -= bytes;
		offset = 0;
	}

	bio->bi_end_io = bio_map_kern_endio;
	return bio;
}
EXPORT_SYMBOL(bio_map_kern);

static void bio_copy_kern_endio(struct bio *bio)
{
	bio_free_pages(bio);
	bio_put(bio);
}

static void bio_copy_kern_endio_read(struct bio *bio)
{
	char *p = bio->bi_private;
	struct bio_vec *bvec;
	int i;

	bio_for_each_segment_all(bvec, bio, i) {
		memcpy(p, page_address(bvec->bv_page), bvec->bv_len);
		p += bvec->bv_len;
	}

	bio_copy_kern_endio(bio);
}

struct bio *bio_copy_kern(struct request_queue *q, void *data, unsigned int len,
			  gfp_t gfp_mask, int reading)
{
	unsigned long kaddr = (unsigned long)data;
	unsigned long end = (kaddr + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	unsigned long start = kaddr >> PAGE_SHIFT;
	struct bio *bio;
	void *p = data;
	int nr_pages = 0;

	if (end < start)
		return ERR_PTR(-EINVAL);

	nr_pages = end - start;
	bio = bio_kmalloc(gfp_mask, nr_pages);
	if (!bio)
		return ERR_PTR(-ENOMEM);

	while (len) {
		struct page *page;
		unsigned int bytes = PAGE_SIZE;

		if (bytes > len)
			bytes = len;

		page = alloc_page(q->bounce_gfp | gfp_mask);
		if (!page)
			goto cleanup;

		if (!reading)
			memcpy(page_address(page), p, bytes);

		if (bio_add_pc_page(q, bio, page, bytes, 0) < bytes)
			break;

		len -= bytes;
		p += bytes;
	}

	if (reading) {
		bio->bi_end_io = bio_copy_kern_endio_read;
		bio->bi_private = data;
	} else {
		bio->bi_end_io = bio_copy_kern_endio;
		bio->bi_rw |= REQ_WRITE;
	}

	return bio;

cleanup:
	bio_free_pages(bio);
	bio_put(bio);
	return ERR_PTR(-ENOMEM);
}
EXPORT_SYMBOL(bio_copy_kern);

void bio_set_pages_dirty(struct bio *bio)
{
	struct bio_vec *bvec;
	int i;

	bio_for_each_segment_all(bvec, bio, i) {
		struct page *page = bvec->bv_page;

		if (page && !PageCompound(page))
			set_page_dirty_lock(page);
	}
}

static void bio_release_pages(struct bio *bio)
{
	struct bio_vec *bvec;
	int i;

	bio_for_each_segment_all(bvec, bio, i) {
		struct page *page = bvec->bv_page;

		if (page)
			put_page(page);
	}
}

static void bio_dirty_fn(struct work_struct *work);

static DECLARE_WORK(bio_dirty_work, bio_dirty_fn);
static DEFINE_SPINLOCK(bio_dirty_lock);
static struct bio *bio_dirty_list;

static void bio_dirty_fn(struct work_struct *work)
{
	unsigned long flags;
	struct bio *bio;

	spin_lock_irqsave(&bio_dirty_lock, flags);
	bio = bio_dirty_list;
	bio_dirty_list = NULL;
	spin_unlock_irqrestore(&bio_dirty_lock, flags);

	while (bio) {
		struct bio *next = bio->bi_private;

		bio_set_pages_dirty(bio);
		bio_release_pages(bio);
		bio_put(bio);
		bio = next;
	}
}

void bio_check_pages_dirty(struct bio *bio)
{
	struct bio_vec *bvec;
	int nr_clean_pages = 0;
	int i;

	bio_for_each_segment_all(bvec, bio, i) {
		struct page *page = bvec->bv_page;

		if (PageDirty(page) || PageCompound(page)) {
			page_cache_release(page);
			bvec->bv_page = NULL;
		} else {
			nr_clean_pages++;
		}
	}

	if (nr_clean_pages) {
		unsigned long flags;

		spin_lock_irqsave(&bio_dirty_lock, flags);
		bio->bi_private = bio_dirty_list;
		bio_dirty_list = bio;
		spin_unlock_irqrestore(&bio_dirty_lock, flags);
		schedule_work(&bio_dirty_work);
	} else {
		bio_put(bio);
	}
}

void generic_start_io_acct(int rw, unsigned long sectors,
			   struct hd_struct *part)
{
	int cpu = part_stat_lock();

	part_round_stats(cpu, part);
	part_stat_inc(cpu, part, ios[rw]);
	part_stat_add(cpu, part, sectors[rw], sectors);
	part_inc_in_flight(part, rw);

	part_stat_unlock();
}
EXPORT_SYMBOL(generic_start_io_acct);

void generic_end_io_acct(int rw, struct hd_struct *part,
			 unsigned long start_time)
{
	unsigned long duration = jiffies - start_time;
	int cpu = part_stat_lock();

	part_stat_add(cpu, part, ticks[rw], duration);
	part_round_stats(cpu, part);
	part_dec_in_flight(part, rw);

	part_stat_unlock();
}
EXPORT_SYMBOL(generic_end_io_acct);

#if ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE
void bio_flush_dcache_pages(struct bio *bi)
{
	struct bio_vec bvec;
	struct bvec_iter iter;

	bio_for_each_segment(bvec, bi, iter)
		flush_dcache_page(bvec.bv_page);
}
EXPORT_SYMBOL(bio_flush_dcache_pages);
#endif

static inline bool bio_remaining_done(struct bio *bio)
{
	 
	if (!bio_flagged(bio, BIO_CHAIN))
		return true;

	BUG_ON(atomic_read(&bio->__bi_remaining) <= 0);

	if (atomic_dec_and_test(&bio->__bi_remaining)) {
		bio_clear_flag(bio, BIO_CHAIN);
		return true;
	}

	return false;
}

void bio_endio(struct bio *bio)
{
	while (bio) {
		if (unlikely(!bio_remaining_done(bio)))
			break;

		if (bio->bi_end_io == bio_chain_endio) {
			struct bio *parent = bio->bi_private;
			parent->bi_error = bio->bi_error;
			bio_put(bio);
			bio = parent;
		} else {
			if (bio->bi_end_io)
				bio->bi_end_io(bio);
			bio = NULL;
		}
	}
}
EXPORT_SYMBOL(bio_endio);

struct bio *bio_split(struct bio *bio, int sectors,
		      gfp_t gfp, struct bio_set *bs)
{
	struct bio *split = NULL;

	BUG_ON(sectors <= 0);
	BUG_ON(sectors >= bio_sectors(bio));

	if (bio->bi_rw & REQ_DISCARD)
		split = bio_clone_bioset(bio, gfp, bs);
	else
		split = bio_clone_fast(bio, gfp, bs);

	if (!split)
		return NULL;

	split->bi_iter.bi_size = sectors << 9;

	if (bio_integrity(split))
		bio_integrity_trim(split, 0, sectors);

	bio_advance(bio, split->bi_iter.bi_size);

	return split;
}
EXPORT_SYMBOL(bio_split);

void bio_trim(struct bio *bio, int offset, int size)
{
	 
	size <<= 9;
	if (offset == 0 && size == bio->bi_iter.bi_size)
		return;

	bio_clear_flag(bio, BIO_SEG_VALID);

	bio_advance(bio, offset << 9);

	bio->bi_iter.bi_size = size;
}
EXPORT_SYMBOL_GPL(bio_trim);

mempool_t *biovec_create_pool(int pool_entries)
{
	struct biovec_slab *bp = bvec_slabs + BIOVEC_MAX_IDX;

	return mempool_create_slab_pool(pool_entries, bp->slab);
}

void bioset_free(struct bio_set *bs)
{
	if (bs->rescue_workqueue)
		destroy_workqueue(bs->rescue_workqueue);

	if (bs->bio_pool)
		mempool_destroy(bs->bio_pool);

	if (bs->bvec_pool)
		mempool_destroy(bs->bvec_pool);

	bioset_integrity_free(bs);
	bio_put_slab(bs);

	kfree(bs);
}
EXPORT_SYMBOL(bioset_free);

static struct bio_set *__bioset_create(unsigned int pool_size,
				       unsigned int front_pad,
				       bool create_bvec_pool)
{
	unsigned int back_pad = BIO_INLINE_VECS * sizeof(struct bio_vec);
	struct bio_set *bs;

	bs = kzalloc(sizeof(*bs), GFP_KERNEL);
	if (!bs)
		return NULL;

	bs->front_pad = front_pad;

	spin_lock_init(&bs->rescue_lock);
	bio_list_init(&bs->rescue_list);
	INIT_WORK(&bs->rescue_work, bio_alloc_rescue);

	bs->bio_slab = bio_find_or_create_slab(front_pad + back_pad);
	if (!bs->bio_slab) {
		kfree(bs);
		return NULL;
	}

	bs->bio_pool = mempool_create_slab_pool(pool_size, bs->bio_slab);
	if (!bs->bio_pool)
		goto bad;

	if (create_bvec_pool) {
		bs->bvec_pool = biovec_create_pool(pool_size);
		if (!bs->bvec_pool)
			goto bad;
	}

	bs->rescue_workqueue = alloc_workqueue("bioset", WQ_MEM_RECLAIM, 0);
	if (!bs->rescue_workqueue)
		goto bad;

	return bs;
bad:
	bioset_free(bs);
	return NULL;
}

struct bio_set *bioset_create(unsigned int pool_size, unsigned int front_pad)
{
	return __bioset_create(pool_size, front_pad, true);
}
EXPORT_SYMBOL(bioset_create);

struct bio_set *bioset_create_nobvec(unsigned int pool_size, unsigned int front_pad)
{
	return __bioset_create(pool_size, front_pad, false);
}
EXPORT_SYMBOL(bioset_create_nobvec);

#ifdef CONFIG_BLK_CGROUP

int bio_associate_blkcg(struct bio *bio, struct cgroup_subsys_state *blkcg_css)
{
	if (unlikely(bio->bi_css))
		return -EBUSY;
	css_get(blkcg_css);
	bio->bi_css = blkcg_css;
	return 0;
}
EXPORT_SYMBOL_GPL(bio_associate_blkcg);

int bio_associate_current(struct bio *bio)
{
	struct io_context *ioc;

	if (bio->bi_css)
		return -EBUSY;

	ioc = current->io_context;
	if (!ioc)
		return -ENOENT;

	get_io_context_active(ioc);
	bio->bi_ioc = ioc;
	bio->bi_css = task_get_css(current, io_cgrp_id);
	return 0;
}
EXPORT_SYMBOL_GPL(bio_associate_current);

void bio_disassociate_task(struct bio *bio)
{
	if (bio->bi_ioc) {
		put_io_context(bio->bi_ioc);
		bio->bi_ioc = NULL;
	}
	if (bio->bi_css) {
		css_put(bio->bi_css);
		bio->bi_css = NULL;
	}
}

void bio_clone_blkcg_association(struct bio *dst, struct bio *src)
{
	if (src->bi_css)
		WARN_ON(bio_associate_blkcg(dst, src->bi_css));
}

#endif  

static void __init biovec_init_slabs(void)
{
	int i;

	for (i = 0; i < BIOVEC_NR_POOLS; i++) {
		int size;
		struct biovec_slab *bvs = bvec_slabs + i;

		if (bvs->nr_vecs <= BIO_INLINE_VECS) {
			bvs->slab = NULL;
			continue;
		}

		size = bvs->nr_vecs * sizeof(struct bio_vec);
		bvs->slab = kmem_cache_create(bvs->name, size, 0,
                                SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);
	}
}

static int __init init_bio(void)
{
	bio_slab_max = 2;
	bio_slab_nr = 0;
	bio_slabs = kzalloc(bio_slab_max * sizeof(struct bio_slab), GFP_KERNEL);
	if (!bio_slabs)
		panic("bio: can't allocate bios\n");

	bio_integrity_init();
	biovec_init_slabs();

	fs_bio_set = bioset_create(BIO_POOL_SIZE, 0);
	if (!fs_bio_set)
		panic("bio: can't allocate bios\n");

	if (bioset_integrity_create(fs_bio_set, BIO_POOL_SIZE))
		panic("bio: can't create integrity pool\n");

	return 0;
}
subsys_initcall(init_bio);
