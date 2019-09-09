#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef __LINUX_BLK_TYPES_H
#define __LINUX_BLK_TYPES_H

#include <linux/types.h>

struct bio_set;
struct bio;
struct bio_integrity_payload;
struct page;
struct block_device;
struct io_context;
struct cgroup_subsys_state;
typedef void (bio_end_io_t) (struct bio *);
typedef void (bio_destructor_t) (struct bio *);

struct bio_vec {
	struct page	*bv_page;
	unsigned int	bv_len;
	unsigned int	bv_offset;
};

#ifdef CONFIG_BLOCK

struct bvec_iter {
	sector_t		bi_sector;	 
	unsigned int		bi_size;	 

	unsigned int		bi_idx;		 

	unsigned int            bi_bvec_done;	 
};

struct bio {
	struct bio		*bi_next;	 
	struct block_device	*bi_bdev;
	unsigned int		bi_flags;	 
	int			bi_error;
	unsigned long		bi_rw;		 

	struct bvec_iter	bi_iter;

	unsigned int		bi_phys_segments;

	unsigned int		bi_seg_front_size;
	unsigned int		bi_seg_back_size;

	atomic_t		__bi_remaining;

	bio_end_io_t		*bi_end_io;

	void			*bi_private;
#ifdef CONFIG_BLK_CGROUP
	 
	struct io_context	*bi_ioc;
	struct cgroup_subsys_state *bi_css;
#endif
	union {
#if defined(CONFIG_BLK_DEV_INTEGRITY)
		struct bio_integrity_payload *bi_integrity;  
#endif
	};

	unsigned short		bi_vcnt;	 

	unsigned short		bi_max_vecs;	 

	atomic_t		__bi_cnt;	 

	struct bio_vec		*bi_io_vec;	 

	struct bio_set		*bi_pool;

	struct bio_vec		bi_inline_vecs[0];
};

#define BIO_RESET_BYTES		offsetof(struct bio, bi_max_vecs)

#define BIO_SEG_VALID	1	 
#define BIO_CLONED	2	 
#define BIO_BOUNCED	3	 
#define BIO_USER_MAPPED 4	 
#define BIO_NULL_MAPPED 5	 
#define BIO_QUIET	6	 
#define BIO_CHAIN	7	 
#define BIO_REFFED	8	 

#define BIO_RESET_BITS	13
#define BIO_OWNS_VEC	13	 
#ifdef MY_ABC_HERE
#define BIO_AUTO_REMAP 14	 
#endif  
#ifdef MY_ABC_HERE
 
#define BIO_MD_RETURN_ERROR 15
#endif  

#define BIO_POOL_BITS		(4)
#define BIO_POOL_NONE		((1UL << BIO_POOL_BITS) - 1)
#define BIO_POOL_OFFSET		(32 - BIO_POOL_BITS)
#define BIO_POOL_MASK		(1UL << BIO_POOL_OFFSET)
#define BIO_POOL_IDX(bio)	((bio)->bi_flags >> BIO_POOL_OFFSET)

#endif  

enum rq_flag_bits {
	 
	__REQ_WRITE,		 
	__REQ_FAILFAST_DEV,	 
	__REQ_FAILFAST_TRANSPORT,  
	__REQ_FAILFAST_DRIVER,	 

	__REQ_SYNC,		 
	__REQ_META,		 
	__REQ_PRIO,		 
	__REQ_DISCARD,		 
	__REQ_SECURE,		 
	__REQ_WRITE_SAME,	 

	__REQ_NOIDLE,		 
	__REQ_INTEGRITY,	 
	__REQ_FUA,		 
	__REQ_FLUSH,		 
	__REQ_BG,		 

	__REQ_RAHEAD,		 
	__REQ_THROTTLED,	 

	__REQ_SORTED,		 
	__REQ_SOFTBARRIER,	 
	__REQ_NOMERGE,		 
	__REQ_STARTED,		 
	__REQ_DONTPREP,		 
	__REQ_QUEUED,		 
	__REQ_ELVPRIV,		 
	__REQ_FAILED,		 
	__REQ_QUIET,		 
	__REQ_PREEMPT,		 
	__REQ_ALLOCED,		 
	__REQ_COPY_USER,	 
	__REQ_FLUSH_SEQ,	 
	__REQ_IO_STAT,		 
	__REQ_MIXED_MERGE,	 
	__REQ_PM,		 
	__REQ_HASHED,		 
	__REQ_MQ_INFLIGHT,	 
	__REQ_NO_TIMEOUT,	 
	__REQ_NR_BITS,		 
};

#define REQ_WRITE		(1ULL << __REQ_WRITE)
#define REQ_FAILFAST_DEV	(1ULL << __REQ_FAILFAST_DEV)
#define REQ_FAILFAST_TRANSPORT	(1ULL << __REQ_FAILFAST_TRANSPORT)
#define REQ_FAILFAST_DRIVER	(1ULL << __REQ_FAILFAST_DRIVER)
#define REQ_SYNC		(1ULL << __REQ_SYNC)
#define REQ_META		(1ULL << __REQ_META)
#define REQ_PRIO		(1ULL << __REQ_PRIO)
#define REQ_DISCARD		(1ULL << __REQ_DISCARD)
#define REQ_WRITE_SAME		(1ULL << __REQ_WRITE_SAME)
#define REQ_NOIDLE		(1ULL << __REQ_NOIDLE)
#define REQ_INTEGRITY		(1ULL << __REQ_INTEGRITY)

#define REQ_FAILFAST_MASK \
	(REQ_FAILFAST_DEV | REQ_FAILFAST_TRANSPORT | REQ_FAILFAST_DRIVER)
#define REQ_COMMON_MASK \
	(REQ_WRITE | REQ_FAILFAST_MASK | REQ_SYNC | REQ_META | REQ_PRIO | \
	 REQ_DISCARD | REQ_WRITE_SAME | REQ_NOIDLE | REQ_FLUSH | REQ_FUA | \
	 REQ_SECURE | REQ_INTEGRITY | REQ_BG)
#define REQ_CLONE_MASK		REQ_COMMON_MASK

#define BIO_NO_ADVANCE_ITER_MASK	(REQ_DISCARD|REQ_WRITE_SAME)

#define REQ_NOMERGE_FLAGS \
	(REQ_NOMERGE | REQ_STARTED | REQ_SOFTBARRIER | REQ_FLUSH | REQ_FUA | REQ_FLUSH_SEQ)

#define REQ_RAHEAD		(1ULL << __REQ_RAHEAD)
#define REQ_THROTTLED		(1ULL << __REQ_THROTTLED)

#define REQ_SORTED		(1ULL << __REQ_SORTED)
#define REQ_SOFTBARRIER		(1ULL << __REQ_SOFTBARRIER)
#define REQ_FUA			(1ULL << __REQ_FUA)
#define REQ_NOMERGE		(1ULL << __REQ_NOMERGE)
#define REQ_STARTED		(1ULL << __REQ_STARTED)
#define REQ_DONTPREP		(1ULL << __REQ_DONTPREP)
#define REQ_QUEUED		(1ULL << __REQ_QUEUED)
#define REQ_ELVPRIV		(1ULL << __REQ_ELVPRIV)
#define REQ_FAILED		(1ULL << __REQ_FAILED)
#define REQ_QUIET		(1ULL << __REQ_QUIET)
#define REQ_PREEMPT		(1ULL << __REQ_PREEMPT)
#define REQ_ALLOCED		(1ULL << __REQ_ALLOCED)
#define REQ_COPY_USER		(1ULL << __REQ_COPY_USER)
#define REQ_FLUSH		(1ULL << __REQ_FLUSH)
#define REQ_FLUSH_SEQ		(1ULL << __REQ_FLUSH_SEQ)
#define REQ_BG			(1ULL << __REQ_BG)
#define REQ_IO_STAT		(1ULL << __REQ_IO_STAT)
#define REQ_MIXED_MERGE		(1ULL << __REQ_MIXED_MERGE)
#define REQ_SECURE		(1ULL << __REQ_SECURE)
#define REQ_PM			(1ULL << __REQ_PM)
#define REQ_HASHED		(1ULL << __REQ_HASHED)
#define REQ_MQ_INFLIGHT		(1ULL << __REQ_MQ_INFLIGHT)
#define REQ_NO_TIMEOUT		(1ULL << __REQ_NO_TIMEOUT)

typedef unsigned int blk_qc_t;
#define BLK_QC_T_NONE	-1U
#define BLK_QC_T_SHIFT	16

static inline bool blk_qc_t_valid(blk_qc_t cookie)
{
	return cookie != BLK_QC_T_NONE;
}

static inline blk_qc_t blk_tag_to_qc_t(unsigned int tag, unsigned int queue_num)
{
	return tag | (queue_num << BLK_QC_T_SHIFT);
}

static inline unsigned int blk_qc_t_to_queue_num(blk_qc_t cookie)
{
	return cookie >> BLK_QC_T_SHIFT;
}

static inline unsigned int blk_qc_t_to_tag(blk_qc_t cookie)
{
	return cookie & ((1u << BLK_QC_T_SHIFT) - 1);
}

#define BLK_RQ_STAT_BATCH	64

struct blk_rq_stat {
	s64 mean;
	u64 min;
	u64 max;
	s32 nr_samples;
	s32 nr_batch;
	u64 batch;
	s64 time;
};

#endif  
