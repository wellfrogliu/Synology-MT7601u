#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#ifndef _RAID1_H
#define _RAID1_H

struct raid1_info {
	struct md_rdev	*rdev;
	sector_t	head_position;

	sector_t	next_seq_sect;
	sector_t	seq_start;
};

struct pool_info {
	struct mddev *mddev;
	int	raid_disks;
};

struct r1conf {
	struct mddev		*mddev;
	struct raid1_info	*mirrors;	 
	int			raid_disks;

	sector_t		next_resync;

#ifdef MY_ABC_HERE
#else  
	 
	sector_t		start_next_window;
	int			current_window_requests;
	int			next_window_requests;
#endif  

	spinlock_t		device_lock;

	struct list_head	retry_list;
	 
	struct list_head	bio_end_io_list;

	struct bio_list		pending_bio_list;
	int			pending_count;

	wait_queue_head_t	wait_barrier;
	spinlock_t		resync_lock;
	int			nr_pending;
	int			nr_waiting;
	int			nr_queued;
	int			barrier;
	int			array_frozen;

	int			fullsync;

	int			recovery_disabled;

	struct pool_info	*poolinfo;
	mempool_t		*r1bio_pool;
	mempool_t		*r1buf_pool;

	struct page		*tmppage;

	struct md_thread	*thread;

	sector_t		cluster_sync_low;
	sector_t		cluster_sync_high;

};

struct r1bio {
	atomic_t		remaining;  
	atomic_t		behind_remaining;  
	sector_t		sector;
#ifdef MY_ABC_HERE
#else  
	sector_t		start_next_window;
#endif  
	int			sectors;
	unsigned long		state;
	struct mddev		*mddev;
	 
	struct bio		*master_bio;
	 
	int			read_disk;

	struct list_head	retry_list;
	 
	struct bio_vec		*behind_bvecs;
	int			behind_page_count;
	 
	struct bio		*bios[0];
	 
};

#define	R1BIO_Uptodate	0
#define	R1BIO_IsSync	1
#define	R1BIO_Degraded	2
#define	R1BIO_BehindIO	3
 
#define R1BIO_ReadError 4
 
#define	R1BIO_Returned 6
 
#define	R1BIO_MadeGood 7
#define	R1BIO_WriteError 8
#endif
