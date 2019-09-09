#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#ifndef _RAID10_H
#define _RAID10_H

struct raid10_info {
	struct md_rdev	*rdev, *replacement;
	sector_t	head_position;
	int		recovery_disabled;	 
};

struct r10conf {
	struct mddev		*mddev;
	struct raid10_info	*mirrors;
	struct raid10_info	*mirrors_new, *mirrors_old;
	spinlock_t		device_lock;

	struct geom {
		int		raid_disks;
		int		near_copies;   
		int		far_copies;    
		int		far_offset;    
		sector_t	stride;	       
		int             far_set_size;  
		int		chunk_shift;  
		sector_t	chunk_mask;
	} prev, geo;
	int			copies;	       

	sector_t		dev_sectors;   
	sector_t		reshape_progress;
	sector_t		reshape_safe;
	unsigned long		reshape_checkpoint;
	sector_t		offset_diff;

	struct list_head	retry_list;
	 
	struct list_head	bio_end_io_list;

	struct bio_list		pending_bio_list;
	int			pending_count;

	spinlock_t		resync_lock;
	int			nr_pending;
	int			nr_waiting;
	int			nr_queued;
	int			barrier;
	sector_t		next_resync;
	int			fullsync;   
	int			have_replacement;  
	wait_queue_head_t	wait_barrier;

	mempool_t		*r10bio_pool;
	mempool_t		*r10buf_pool;
	struct page		*tmppage;

	struct md_thread	*thread;
};

struct r10bio {
	atomic_t		remaining;  
	sector_t		sector;	 
	int			sectors;
	unsigned long		state;
	struct mddev		*mddev;
	 
	struct bio		*master_bio;
	 
	int			read_slot;

	struct list_head	retry_list;
	 
	struct r10dev {
		struct bio	*bio;
		union {
			struct bio	*repl_bio;  
			struct md_rdev	*rdev;	    
		};
		sector_t	addr;
		int		devnum;
	} devs[0];
};

enum r10bio_state {
	R10BIO_Uptodate,
	R10BIO_IsSync,
	R10BIO_IsRecover,
	R10BIO_IsReshape,
	R10BIO_Degraded,
 
	R10BIO_ReadError,
 
	R10BIO_MadeGood,
	R10BIO_WriteError,
 
	R10BIO_Previous,
#ifdef MY_ABC_HERE
	R10BIO_FIX_READ_ERROR,
#endif  
};
#endif
