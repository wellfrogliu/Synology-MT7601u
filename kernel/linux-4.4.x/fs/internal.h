#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
struct super_block;
struct file_system_type;
struct linux_binprm;
struct path;
struct mount;
struct shrink_control;

#ifdef CONFIG_BLOCK
extern void __init bdev_cache_init(void);

extern int __sync_blockdev(struct block_device *bdev, int wait);

#else
static inline void bdev_cache_init(void)
{
}

static inline int __sync_blockdev(struct block_device *bdev, int wait)
{
	return 0;
}
#endif

extern void guard_bio_eod(int rw, struct bio *bio);

extern void __init chrdev_init(void);

extern int user_path_mountpoint_at(int, const char __user *, unsigned int, struct path *);
extern int vfs_path_lookup(struct dentry *, struct vfsmount *,
			   const char *, unsigned int, struct path *);

extern int copy_mount_options(const void __user *, unsigned long *);
extern char *copy_mount_string(const void __user *);

extern struct vfsmount *lookup_mnt(struct path *);
extern int finish_automount(struct vfsmount *, struct path *);

extern int sb_prepare_remount_readonly(struct super_block *);

extern void __init mnt_init(void);

extern int __mnt_want_write(struct vfsmount *);
extern int __mnt_want_write_file(struct file *);
extern void __mnt_drop_write(struct vfsmount *);
extern void __mnt_drop_write_file(struct file *);

extern void chroot_fs_refs(const struct path *, const struct path *);

#ifdef MY_ABC_HERE
extern void file_sb_list_add(struct file *f, struct super_block *sb);
extern void file_sb_list_del(struct file *f);
extern void fs_show_opened_file(struct mount *m);
#endif  
extern struct file *get_empty_filp(void);

extern int do_remount_sb(struct super_block *, int, void *, int);
extern bool trylock_super(struct super_block *sb);
extern struct dentry *mount_fs(struct file_system_type *,
			       int, const char *, void *);
extern struct super_block *user_get_super(dev_t);

struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};
extern struct file *do_filp_open(int dfd, struct filename *pathname,
		const struct open_flags *op);
extern struct file *do_file_open_root(struct dentry *, struct vfsmount *,
		const char *, const struct open_flags *);

extern long do_handle_open(int mountdirfd,
			   struct file_handle __user *ufh, int open_flag);
extern int open_check_o_direct(struct file *f);
extern int vfs_open(const struct path *, struct file *, const struct cred *);

extern long prune_icache_sb(struct super_block *sb, struct shrink_control *sc);
extern void inode_add_lru(struct inode *inode);

extern void inode_io_list_del(struct inode *inode);

extern long get_nr_dirty_inodes(void);
extern void evict_inodes(struct super_block *);
extern int invalidate_inodes(struct super_block *, bool);

extern struct dentry *__d_alloc(struct super_block *, const struct qstr *);
extern int d_set_mounted(struct dentry *dentry);
extern long prune_dcache_sb(struct super_block *sb, struct shrink_control *sc);

extern int rw_verify_area(int, struct file *, const loff_t *, size_t);

extern const struct file_operations pipefifo_fops;

extern void group_pin_kill(struct hlist_head *p);
extern void mnt_pin_kill(struct mount *m);

extern struct dentry_operations ns_dentry_operations;
