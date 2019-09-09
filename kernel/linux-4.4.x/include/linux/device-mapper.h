#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef _LINUX_DEVICE_MAPPER_H
#define _LINUX_DEVICE_MAPPER_H

#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/math64.h>
#include <linux/ratelimit.h>

struct dm_dev;
struct dm_target;
struct dm_table;
struct mapped_device;
struct bio_vec;

typedef enum { STATUSTYPE_INFO, STATUSTYPE_TABLE } status_type_t;

union map_info {
	void *ptr;
};

typedef int (*dm_ctr_fn) (struct dm_target *target,
			  unsigned int argc, char **argv);

typedef void (*dm_dtr_fn) (struct dm_target *ti);

typedef int (*dm_map_fn) (struct dm_target *ti, struct bio *bio);
typedef int (*dm_map_request_fn) (struct dm_target *ti, struct request *clone,
				  union map_info *map_context);
typedef int (*dm_clone_and_map_request_fn) (struct dm_target *ti,
					    struct request *rq,
					    union map_info *map_context,
					    struct request **clone);
typedef void (*dm_release_clone_request_fn) (struct request *clone);

typedef int (*dm_endio_fn) (struct dm_target *ti,
			    struct bio *bio, int error);
typedef int (*dm_request_endio_fn) (struct dm_target *ti,
				    struct request *clone, int error,
				    union map_info *map_context);

typedef void (*dm_presuspend_fn) (struct dm_target *ti);
typedef void (*dm_presuspend_undo_fn) (struct dm_target *ti);
typedef void (*dm_postsuspend_fn) (struct dm_target *ti);
typedef int (*dm_preresume_fn) (struct dm_target *ti);
typedef void (*dm_resume_fn) (struct dm_target *ti);

typedef void (*dm_status_fn) (struct dm_target *ti, status_type_t status_type,
			      unsigned status_flags, char *result, unsigned maxlen);

typedef int (*dm_message_fn) (struct dm_target *ti, unsigned argc, char **argv);

#ifdef MY_ABC_HERE
typedef int (*dm_extra_ioctl_fn) (struct dm_target *ti,
		unsigned int cmd, unsigned long arg);
#endif  
typedef int (*dm_prepare_ioctl_fn) (struct dm_target *ti,
			    struct block_device **bdev, fmode_t *mode);

typedef int (*iterate_devices_callout_fn) (struct dm_target *ti,
					   struct dm_dev *dev,
					   sector_t start, sector_t len,
					   void *data);

typedef int (*dm_iterate_devices_fn) (struct dm_target *ti,
				      iterate_devices_callout_fn fn,
				      void *data);
#ifdef MY_ABC_HERE
typedef int (*dm_handle_4kn_target_support_fn) (struct dm_target *ti,
				      iterate_devices_callout_fn fn,
				      void *data);
#endif  

typedef void (*dm_io_hints_fn) (struct dm_target *ti,
				struct queue_limits *limits);

typedef int (*dm_busy_fn) (struct dm_target *ti);

#ifdef MY_ABC_HERE
typedef void (*dm_lvinfoset_fn) (struct dm_target *ti);
typedef sector_t (*dm_lg_sector_get_fn) (sector_t sector, struct dm_target *ti);
#endif  

void dm_error(const char *message);

struct dm_dev {
	struct block_device *bdev;
	fmode_t mode;
	char name[16];
};

dev_t dm_get_dev_t(const char *path);

int dm_get_device(struct dm_target *ti, const char *path, fmode_t mode,
		  struct dm_dev **result);
void dm_put_device(struct dm_target *ti, struct dm_dev *d);

struct target_type {
	uint64_t features;
	const char *name;
	struct module *module;
	unsigned version[3];
	dm_ctr_fn ctr;
	dm_dtr_fn dtr;
	dm_map_fn map;
	dm_map_request_fn map_rq;
	dm_clone_and_map_request_fn clone_and_map_rq;
	dm_release_clone_request_fn release_clone_rq;
	dm_endio_fn end_io;
	dm_request_endio_fn rq_end_io;
	dm_presuspend_fn presuspend;
	dm_presuspend_undo_fn presuspend_undo;
	dm_postsuspend_fn postsuspend;
	dm_preresume_fn preresume;
	dm_resume_fn resume;
	dm_status_fn status;
	dm_message_fn message;
#ifdef MY_ABC_HERE
	dm_extra_ioctl_fn extra_ioctl;
#endif  
	dm_prepare_ioctl_fn prepare_ioctl;
	dm_busy_fn busy;
	dm_iterate_devices_fn iterate_devices;
#ifdef MY_ABC_HERE
	dm_handle_4kn_target_support_fn handle_4kn_target_support;
#endif  
	dm_io_hints_fn io_hints;
#ifdef MY_ABC_HERE
	dm_lvinfoset_fn lvinfoset;
	dm_lg_sector_get_fn lg_sector_get;
#endif  

	struct list_head list;
};

#define DM_TARGET_SINGLETON		0x00000001
#define dm_target_needs_singleton(type)	((type)->features & DM_TARGET_SINGLETON)

#define DM_TARGET_ALWAYS_WRITEABLE	0x00000002
#define dm_target_always_writeable(type) \
		((type)->features & DM_TARGET_ALWAYS_WRITEABLE)

#define DM_TARGET_IMMUTABLE		0x00000004
#define dm_target_is_immutable(type)	((type)->features & DM_TARGET_IMMUTABLE)

typedef unsigned (*dm_num_write_bios_fn) (struct dm_target *ti, struct bio *bio);

struct dm_target {
	struct dm_table *table;
	struct target_type *type;

	sector_t begin;
	sector_t len;

	uint32_t max_io_len;

	unsigned num_flush_bios;

	unsigned num_discard_bios;

	unsigned num_write_same_bios;

	unsigned per_bio_data_size;

	dm_num_write_bios_fn num_write_bios;

	void *private;

	char *error;

	bool flush_supported:1;

	bool discards_supported:1;

	bool split_discard_bios:1;

	bool discard_zeroes_data_unsupported:1;
};

struct dm_target_callbacks {
	struct list_head list;
	int (*congested_fn) (struct dm_target_callbacks *, int);
};

struct dm_target_io {
	struct dm_io *io;
	struct dm_target *ti;
	unsigned target_bio_nr;
	unsigned *len_ptr;
	struct bio clone;
};

static inline void *dm_per_bio_data(struct bio *bio, size_t data_size)
{
	return (char *)bio - offsetof(struct dm_target_io, clone) - data_size;
}

static inline struct bio *dm_bio_from_per_bio_data(void *data, size_t data_size)
{
	return (struct bio *)((char *)data + data_size + offsetof(struct dm_target_io, clone));
}

static inline unsigned dm_bio_get_target_bio_nr(const struct bio *bio)
{
	return container_of(bio, struct dm_target_io, clone)->target_bio_nr;
}

int dm_register_target(struct target_type *t);
void dm_unregister_target(struct target_type *t);

struct dm_arg_set {
	unsigned argc;
	char **argv;
};

struct dm_arg {
	unsigned min;
	unsigned max;
	char *error;
};

int dm_read_arg(struct dm_arg *arg, struct dm_arg_set *arg_set,
		unsigned *value, char **error);

int dm_read_arg_group(struct dm_arg *arg, struct dm_arg_set *arg_set,
		      unsigned *num_args, char **error);

const char *dm_shift_arg(struct dm_arg_set *as);

void dm_consume_args(struct dm_arg_set *as, unsigned num_args);

#define DM_ANY_MINOR (-1)
int dm_create(int minor, struct mapped_device **md);

struct mapped_device *dm_get_md(dev_t dev);
void dm_get(struct mapped_device *md);
int dm_hold(struct mapped_device *md);
void dm_put(struct mapped_device *md);

void dm_set_mdptr(struct mapped_device *md, void *ptr);
void *dm_get_mdptr(struct mapped_device *md);

int dm_suspend(struct mapped_device *md, unsigned suspend_flags);
int dm_resume(struct mapped_device *md);
#ifdef MY_ABC_HERE
int dm_active_get(struct mapped_device *md);
int dm_active_set(struct mapped_device *md, int value);
#endif  

uint32_t dm_get_event_nr(struct mapped_device *md);
int dm_wait_event(struct mapped_device *md, int event_nr);
uint32_t dm_next_uevent_seq(struct mapped_device *md);
void dm_uevent_add(struct mapped_device *md, struct list_head *elist);

const char *dm_device_name(struct mapped_device *md);
int dm_copy_name_and_uuid(struct mapped_device *md, char *name, char *uuid);
struct gendisk *dm_disk(struct mapped_device *md);
int dm_suspended(struct dm_target *ti);
int dm_noflush_suspending(struct dm_target *ti);
void dm_accept_partial_bio(struct bio *bio, unsigned n_sectors);
union map_info *dm_get_rq_mapinfo(struct request *rq);

struct queue_limits *dm_get_queue_limits(struct mapped_device *md);

int dm_get_geometry(struct mapped_device *md, struct hd_geometry *geo);
int dm_set_geometry(struct mapped_device *md, struct hd_geometry *geo);

int dm_table_create(struct dm_table **result, fmode_t mode,
		    unsigned num_targets, struct mapped_device *md);

int dm_table_add_target(struct dm_table *t, const char *type,
			sector_t start, sector_t len, char *params);

void dm_table_add_target_callbacks(struct dm_table *t, struct dm_target_callbacks *cb);

int dm_table_complete(struct dm_table *t);

int __must_check dm_set_target_max_io_len(struct dm_target *ti, sector_t len);

struct dm_table *dm_get_live_table(struct mapped_device *md, int *srcu_idx);
void dm_put_live_table(struct mapped_device *md, int srcu_idx);
void dm_sync_table(struct mapped_device *md);

sector_t dm_table_get_size(struct dm_table *t);
unsigned int dm_table_get_num_targets(struct dm_table *t);
fmode_t dm_table_get_mode(struct dm_table *t);
struct mapped_device *dm_table_get_md(struct dm_table *t);

void dm_table_event(struct dm_table *t);

void dm_table_run_md_queue_async(struct dm_table *t);

struct dm_table *dm_swap_table(struct mapped_device *md,
			       struct dm_table *t);

void *dm_vcalloc(unsigned long nmemb, unsigned long elem_size);

#define DM_NAME "device-mapper"

#ifdef CONFIG_PRINTK
extern struct ratelimit_state dm_ratelimit_state;

#define dm_ratelimit()	__ratelimit(&dm_ratelimit_state)
#else
#define dm_ratelimit()	0
#endif

#define DMCRIT(f, arg...) \
	printk(KERN_CRIT DM_NAME ": " DM_MSG_PREFIX ": " f "\n", ## arg)

#define DMERR(f, arg...) \
	printk(KERN_ERR DM_NAME ": " DM_MSG_PREFIX ": " f "\n", ## arg)
#define DMERR_LIMIT(f, arg...) \
	do { \
		if (dm_ratelimit())	\
			printk(KERN_ERR DM_NAME ": " DM_MSG_PREFIX ": " \
			       f "\n", ## arg); \
	} while (0)

#define DMWARN(f, arg...) \
	printk(KERN_WARNING DM_NAME ": " DM_MSG_PREFIX ": " f "\n", ## arg)
#define DMWARN_LIMIT(f, arg...) \
	do { \
		if (dm_ratelimit())	\
			printk(KERN_WARNING DM_NAME ": " DM_MSG_PREFIX ": " \
			       f "\n", ## arg); \
	} while (0)

#define DMINFO(f, arg...) \
	printk(KERN_INFO DM_NAME ": " DM_MSG_PREFIX ": " f "\n", ## arg)
#define DMINFO_LIMIT(f, arg...) \
	do { \
		if (dm_ratelimit())	\
			printk(KERN_INFO DM_NAME ": " DM_MSG_PREFIX ": " f \
			       "\n", ## arg); \
	} while (0)

#ifdef CONFIG_DM_DEBUG
#  define DMDEBUG(f, arg...) \
	printk(KERN_DEBUG DM_NAME ": " DM_MSG_PREFIX " DEBUG: " f "\n", ## arg)
#  define DMDEBUG_LIMIT(f, arg...) \
	do { \
		if (dm_ratelimit())	\
			printk(KERN_DEBUG DM_NAME ": " DM_MSG_PREFIX ": " f \
			       "\n", ## arg); \
	} while (0)
#else
#  define DMDEBUG(f, arg...) do {} while (0)
#  define DMDEBUG_LIMIT(f, arg...) do {} while (0)
#endif

#define DMEMIT(x...) sz += ((sz >= maxlen) ? \
			  0 : scnprintf(result + sz, maxlen - sz, x))

#define SECTOR_SHIFT 9

#define DM_ENDIO_INCOMPLETE	1
#define DM_ENDIO_REQUEUE	2

#define DM_MAPIO_SUBMITTED	0
#define DM_MAPIO_REMAPPED	1
#define DM_MAPIO_REQUEUE	DM_ENDIO_REQUEUE

#define dm_sector_div64(x, y)( \
{ \
	u64 _res; \
	(x) = div64_u64_rem(x, y, &_res); \
	_res; \
} \
)

#define dm_div_up(n, sz) (((n) + (sz) - 1) / (sz))

#define dm_sector_div_up(n, sz) ( \
{ \
	sector_t _r = ((n) + (sz) - 1); \
	sector_div(_r, (sz)); \
	_r; \
} \
)

#define dm_round_up(n, sz) (dm_div_up((n), (sz)) * (sz))

#define dm_array_too_big(fixed, obj, num) \
	((num) > (UINT_MAX - (fixed)) / (obj))

#define dm_target_offset(ti, sector) ((sector) - (ti)->begin)

static inline sector_t to_sector(unsigned long n)
{
	return (n >> SECTOR_SHIFT);
}

static inline unsigned long to_bytes(sector_t n)
{
	return (n << SECTOR_SHIFT);
}

#endif	 
