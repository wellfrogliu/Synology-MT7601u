#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef _FS_FUSE_I_H
#define _FS_FUSE_I_H

#include <linux/fuse.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/backing-dev.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/rbtree.h>
#include <linux/poll.h>
#include <linux/workqueue.h>
#include <linux/kref.h>

#ifdef MY_ABC_HERE
#define FUSE_MAX_PAGES_PER_REQ 256
#else
#define FUSE_MAX_PAGES_PER_REQ 32
#endif  

#ifdef MY_ABC_HERE
#define SYNO_FUSE_ENTRY_NAME_LEN 255
#define FUSE_SYNOSTAT_SIZE (SYNO_FUSE_ENTRY_NAME_LEN + 1 + sizeof(struct fuse_synostat))
#endif  

#ifdef MY_ABC_HERE
#define XATTR_SYNO_ARCHIVE_VERSION_GLUSTER "archive_version_gluster"
#define XATTR_SYNO_ARCHIVE_VERSION_VOLUME_GLUSTER "archive_version_volume_gluster"
#endif  

#ifdef MY_ABC_HERE
 
struct syno_gf_xattr_crtime {
	__le64 sec;
	__le32 nsec;
} __attribute__ ((__packed__));
#endif  

#define FUSE_NOWRITE INT_MIN

#define FUSE_NAME_MAX 1024

#define FUSE_CTL_NUM_DENTRIES 5

#define FUSE_DEFAULT_PERMISSIONS (1 << 0)

#define FUSE_ALLOW_OTHER         (1 << 1)

#define FUSE_REQ_INLINE_PAGES 1

extern struct list_head fuse_conn_list;

extern struct mutex fuse_mutex;

extern unsigned max_user_bgreq;
extern unsigned max_user_congthresh;

struct fuse_forget_link {
	struct fuse_forget_one forget_one;
	struct fuse_forget_link *next;
};

struct fuse_inode {
	 
	struct inode inode;

	u64 nodeid;

	u64 nlookup;

	struct fuse_forget_link *forget;

	u64 i_time;

	umode_t orig_i_mode;

	u64 orig_ino;

	u64 attr_version;

	struct list_head write_files;

	struct list_head queued_writes;

	int writectr;

	wait_queue_head_t page_waitq;

	struct list_head writepages;

	unsigned long state;
};

enum {
	 
	FUSE_I_ADVISE_RDPLUS,
	 
	FUSE_I_INIT_RDPLUS,
	 
	FUSE_I_SIZE_UNSTABLE,
};

struct fuse_conn;

struct fuse_file {
	 
	struct fuse_conn *fc;

	struct fuse_req *reserved_req;

	u64 kh;

	u64 fh;

	u64 nodeid;

	atomic_t count;

	u32 open_flags;

	struct list_head write_entry;

	struct rb_node polled_node;

	wait_queue_head_t poll_wait;

	bool flock:1;
};

struct fuse_in_arg {
	unsigned size;
	const void *value;
};

struct fuse_in {
	 
	struct fuse_in_header h;

	unsigned argpages:1;

	unsigned numargs;

	struct fuse_in_arg args[3];
};

struct fuse_arg {
	unsigned size;
	void *value;
};

struct fuse_out {
	 
	struct fuse_out_header h;

	unsigned argvar:1;

	unsigned argpages:1;

	unsigned page_zeroing:1;

	unsigned page_replace:1;

	unsigned numargs;

	struct fuse_arg args[2];
};

struct fuse_page_desc {
	unsigned int length;
	unsigned int offset;
};

struct fuse_args {
	struct {
		struct {
			uint32_t opcode;
			uint64_t nodeid;
		} h;
		unsigned numargs;
		struct fuse_in_arg args[3];

	} in;
	struct {
		unsigned argvar:1;
		unsigned numargs;
		struct fuse_arg args[2];
	} out;
};

#define FUSE_ARGS(args) struct fuse_args args = {}

struct fuse_io_priv {
	struct kref refcnt;
	int async;
	spinlock_t lock;
	unsigned reqs;
	ssize_t bytes;
	size_t size;
	__u64 offset;
	bool write;
	int err;
	struct kiocb *iocb;
	struct file *file;
	struct completion *done;
};

#define FUSE_IO_PRIV_SYNC(f) \
{					\
	.refcnt = { ATOMIC_INIT(1) },	\
	.async = 0,			\
	.file = f,			\
}

enum fuse_req_flag {
	FR_ISREPLY,
	FR_FORCE,
	FR_BACKGROUND,
	FR_WAITING,
	FR_ABORTED,
	FR_INTERRUPTED,
	FR_LOCKED,
	FR_PENDING,
	FR_SENT,
	FR_FINISHED,
	FR_PRIVATE,
};

struct fuse_req {
	 
	struct list_head list;

	struct list_head intr_entry;

	atomic_t count;

	u64 intr_unique;

	unsigned long flags;

	struct fuse_in in;

	struct fuse_out out;

	wait_queue_head_t waitq;

	union {
		struct {
			struct fuse_release_in in;
			struct inode *inode;
		} release;
		struct fuse_init_in init_in;
		struct fuse_init_out init_out;
		struct cuse_init_in cuse_init_in;
		struct {
			struct fuse_read_in in;
			u64 attr_ver;
		} read;
		struct {
			struct fuse_write_in in;
			struct fuse_write_out out;
			struct fuse_req *next;
		} write;
		struct fuse_notify_retrieve_in retrieve_in;
	} misc;

	struct page **pages;

	struct fuse_page_desc *page_descs;

	unsigned max_pages;

	struct page *inline_pages[FUSE_REQ_INLINE_PAGES];

	struct fuse_page_desc inline_page_descs[FUSE_REQ_INLINE_PAGES];

	unsigned num_pages;

	struct fuse_file *ff;

	struct inode *inode;

	struct fuse_io_priv *io;

	struct list_head writepages_entry;

	void (*end)(struct fuse_conn *, struct fuse_req *);

	struct file *stolen_file;
};

struct fuse_iqueue {
	 
	unsigned connected;

	wait_queue_head_t waitq;

	u64 reqctr;

	struct list_head pending;

	struct list_head interrupts;

	struct fuse_forget_link forget_list_head;
	struct fuse_forget_link *forget_list_tail;

	int forget_batch;

	struct fasync_struct *fasync;
};

struct fuse_pqueue {
	 
	unsigned connected;

	spinlock_t lock;

	struct list_head processing;

	struct list_head io;
};

struct fuse_dev {
	 
	struct fuse_conn *fc;

	struct fuse_pqueue pq;

	struct list_head entry;
};

struct fuse_conn {
	 
	spinlock_t lock;

	atomic_t count;

	atomic_t dev_count;

	struct rcu_head rcu;

	kuid_t user_id;

	kgid_t group_id;

	unsigned flags;

	unsigned max_read;

	unsigned max_write;

	struct fuse_iqueue iq;

	u64 khctr;

	struct rb_root polled_files;

	unsigned max_background;

	unsigned congestion_threshold;

	unsigned num_background;

	unsigned active_background;

	struct list_head bg_queue;

	int initialized;

	int blocked;

	wait_queue_head_t blocked_waitq;

	wait_queue_head_t reserved_req_waitq;

	unsigned connected;

	unsigned conn_error:1;

	unsigned conn_init:1;

	unsigned async_read:1;

	unsigned atomic_o_trunc:1;

	unsigned export_support:1;

	unsigned bdi_initialized:1;

	unsigned writeback_cache:1;

	unsigned no_open:1;

	unsigned no_fsync:1;

	unsigned no_fsyncdir:1;

	unsigned no_flush:1;

	unsigned no_setxattr:1;

	unsigned no_getxattr:1;

	unsigned no_listxattr:1;

	unsigned no_removexattr:1;

	unsigned no_lock:1;

	unsigned no_access:1;

	unsigned no_create:1;

	unsigned no_interrupt:1;

	unsigned no_bmap:1;

	unsigned no_poll:1;

	unsigned big_writes:1;

	unsigned dont_mask:1;

	unsigned no_flock:1;

	unsigned no_fallocate:1;

	unsigned no_rename2:1;

	unsigned auto_inval_data:1;

	unsigned do_readdirplus:1;

	unsigned readdirplus_auto:1;

	unsigned async_dio:1;

	atomic_t num_waiting;

	unsigned minor;

	struct backing_dev_info bdi;

	struct list_head entry;

	dev_t dev;

	struct dentry *ctl_dentry[FUSE_CTL_NUM_DENTRIES];

	int ctl_ndents;

	u32 scramble_key[4];

	struct fuse_req *destroy_req;

	u64 attr_version;

	void (*release)(struct fuse_conn *);

	struct super_block *sb;

	struct rw_semaphore killsb;

	struct list_head devices;
};

static inline struct fuse_conn *get_fuse_conn_super(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct fuse_conn *get_fuse_conn(struct inode *inode)
{
	return get_fuse_conn_super(inode->i_sb);
}

static inline struct fuse_inode *get_fuse_inode(struct inode *inode)
{
	return container_of(inode, struct fuse_inode, inode);
}

static inline u64 get_node_id(struct inode *inode)
{
	return get_fuse_inode(inode)->nodeid;
}

extern const struct file_operations fuse_dev_operations;

extern const struct dentry_operations fuse_dentry_operations;

int fuse_inode_eq(struct inode *inode, void *_nodeidp);

struct inode *fuse_iget(struct super_block *sb, u64 nodeid,
			int generation, struct fuse_attr *attr,
			u64 attr_valid, u64 attr_version);

#ifdef MY_ABC_HERE
int fuse_lookup_name(struct super_block *sb, u64 nodeid, struct qstr *name,
		     struct fuse_entry_out *outarg, struct inode **inode,
		     struct fuse_synostat *synostat, int syno_stat_flags);
#else
int fuse_lookup_name(struct super_block *sb, u64 nodeid, struct qstr *name,
		     struct fuse_entry_out *outarg, struct inode **inode);
#endif  

void fuse_queue_forget(struct fuse_conn *fc, struct fuse_forget_link *forget,
		       u64 nodeid, u64 nlookup);

struct fuse_forget_link *fuse_alloc_forget(void);

void fuse_force_forget(struct file *file, u64 nodeid);

void fuse_read_fill(struct fuse_req *req, struct file *file,
		    loff_t pos, size_t count, int opcode);

int fuse_open_common(struct inode *inode, struct file *file, bool isdir);

struct fuse_file *fuse_file_alloc(struct fuse_conn *fc);
struct fuse_file *fuse_file_get(struct fuse_file *ff);
void fuse_file_free(struct fuse_file *ff);
void fuse_finish_open(struct inode *inode, struct file *file);

void fuse_sync_release(struct fuse_file *ff, int flags);

void fuse_release_common(struct file *file, int opcode);

int fuse_fsync_common(struct file *file, loff_t start, loff_t end,
		      int datasync, int isdir);

int fuse_notify_poll_wakeup(struct fuse_conn *fc,
			    struct fuse_notify_poll_wakeup_out *outarg);

void fuse_init_file_inode(struct inode *inode);

void fuse_init_common(struct inode *inode);

void fuse_init_dir(struct inode *inode);

void fuse_init_symlink(struct inode *inode);

void fuse_change_attributes(struct inode *inode, struct fuse_attr *attr,
			    u64 attr_valid, u64 attr_version);

void fuse_change_attributes_common(struct inode *inode, struct fuse_attr *attr,
				   u64 attr_valid);

int fuse_dev_init(void);

void fuse_dev_cleanup(void);

int fuse_ctl_init(void);
void __exit fuse_ctl_cleanup(void);

struct fuse_req *fuse_request_alloc(unsigned npages);

struct fuse_req *fuse_request_alloc_nofs(unsigned npages);

void fuse_request_free(struct fuse_req *req);

struct fuse_req *fuse_get_req(struct fuse_conn *fc, unsigned npages);
struct fuse_req *fuse_get_req_for_background(struct fuse_conn *fc,
					     unsigned npages);

void __fuse_get_request(struct fuse_req *req);

struct fuse_req *fuse_get_req_nofail_nopages(struct fuse_conn *fc,
					     struct file *file);

void fuse_put_request(struct fuse_conn *fc, struct fuse_req *req);

void fuse_request_send(struct fuse_conn *fc, struct fuse_req *req);

ssize_t fuse_simple_request(struct fuse_conn *fc, struct fuse_args *args);

#ifdef MY_ABC_HERE
ssize_t fuse_send_syno_request(struct fuse_conn *fc, struct fuse_args *args);
#endif  

void fuse_request_send_background(struct fuse_conn *fc, struct fuse_req *req);

void fuse_request_send_background_locked(struct fuse_conn *fc,
					 struct fuse_req *req);

void fuse_abort_conn(struct fuse_conn *fc);

void fuse_invalidate_attr(struct inode *inode);

void fuse_invalidate_entry_cache(struct dentry *entry);

void fuse_invalidate_atime(struct inode *inode);

struct fuse_conn *fuse_conn_get(struct fuse_conn *fc);

void fuse_conn_init(struct fuse_conn *fc);

void fuse_conn_put(struct fuse_conn *fc);

struct fuse_dev *fuse_dev_alloc(struct fuse_conn *fc);
void fuse_dev_free(struct fuse_dev *fud);

int fuse_ctl_add_conn(struct fuse_conn *fc);

void fuse_ctl_remove_conn(struct fuse_conn *fc);

int fuse_valid_type(int m);

int fuse_allow_current_process(struct fuse_conn *fc);

u64 fuse_lock_owner_id(struct fuse_conn *fc, fl_owner_t id);

int fuse_update_attributes(struct inode *inode, struct kstat *stat,
			   struct file *file, bool *refreshed);

void fuse_flush_writepages(struct inode *inode);

void fuse_set_nowrite(struct inode *inode);
void fuse_release_nowrite(struct inode *inode);

u64 fuse_get_attr_version(struct fuse_conn *fc);

int fuse_reverse_inval_inode(struct super_block *sb, u64 nodeid,
			     loff_t offset, loff_t len);

int fuse_reverse_inval_entry(struct super_block *sb, u64 parent_nodeid,
			     u64 child_nodeid, struct qstr *name);

int fuse_do_open(struct fuse_conn *fc, u64 nodeid, struct file *file,
		 bool isdir);

#define FUSE_DIO_WRITE (1 << 0)

#define FUSE_DIO_CUSE  (1 << 1)

ssize_t fuse_direct_io(struct fuse_io_priv *io, struct iov_iter *iter,
		       loff_t *ppos, int flags);
long fuse_do_ioctl(struct file *file, unsigned int cmd, unsigned long arg,
		   unsigned int flags);
long fuse_ioctl_common(struct file *file, unsigned int cmd,
		       unsigned long arg, unsigned int flags);
unsigned fuse_file_poll(struct file *file, poll_table *wait);
int fuse_dev_release(struct inode *inode, struct file *file);

bool fuse_write_update_size(struct inode *inode, loff_t pos);

int fuse_flush_times(struct inode *inode, struct fuse_file *ff);
int fuse_write_inode(struct inode *inode, struct writeback_control *wbc);

int fuse_do_setattr(struct inode *inode, struct iattr *attr,
		    struct file *file);

void fuse_set_initialized(struct fuse_conn *fc);

#ifdef MY_ABC_HERE
ssize_t fuse_getxattr(struct dentry *entry, const char *name,
			     void *value, size_t size);

int fuse_setxattr(struct dentry *entry, const char *name,
			 const void *value, size_t size, int flags);
#endif  

#endif  
