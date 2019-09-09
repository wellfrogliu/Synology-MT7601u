#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include "fuse_i.h"

#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include <linux/slab.h>
#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
#include <linux/xattr.h>
#endif  

#ifdef MY_ABC_HERE
#include "../synoacl_int.h"
#endif  

#ifdef MY_ABC_HERE
#include "../ntfs/time.h"
#include "../ntfs/endian.h"
#endif  

static bool fuse_use_readdirplus(struct inode *dir, struct dir_context *ctx)
{
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_inode *fi = get_fuse_inode(dir);

	if (!fc->do_readdirplus)
		return false;
	if (!fc->readdirplus_auto)
		return true;
	if (test_and_clear_bit(FUSE_I_ADVISE_RDPLUS, &fi->state))
		return true;
	if (ctx->pos == 0)
		return true;
	return false;
}

static void fuse_advise_use_readdirplus(struct inode *dir)
{
	struct fuse_inode *fi = get_fuse_inode(dir);

	set_bit(FUSE_I_ADVISE_RDPLUS, &fi->state);
}

#if BITS_PER_LONG >= 64
static inline void fuse_dentry_settime(struct dentry *entry, u64 time)
{
	entry->d_time = time;
}

static inline u64 fuse_dentry_time(struct dentry *entry)
{
	return entry->d_time;
}
#else
 
static void fuse_dentry_settime(struct dentry *entry, u64 time)
{
	entry->d_time = time;
	entry->d_fsdata = (void *) (unsigned long) (time >> 32);
}

static u64 fuse_dentry_time(struct dentry *entry)
{
	return (u64) entry->d_time +
		((u64) (unsigned long) entry->d_fsdata << 32);
}
#endif

static u64 time_to_jiffies(unsigned long sec, unsigned long nsec)
{
	if (sec || nsec) {
		struct timespec ts = {sec, nsec};
		return get_jiffies_64() + timespec_to_jiffies(&ts);
	} else
		return 0;
}

static void fuse_change_entry_timeout(struct dentry *entry,
				      struct fuse_entry_out *o)
{
	fuse_dentry_settime(entry,
		time_to_jiffies(o->entry_valid, o->entry_valid_nsec));
}

static u64 attr_timeout(struct fuse_attr_out *o)
{
	return time_to_jiffies(o->attr_valid, o->attr_valid_nsec);
}

static u64 entry_attr_timeout(struct fuse_entry_out *o)
{
	return time_to_jiffies(o->attr_valid, o->attr_valid_nsec);
}

void fuse_invalidate_attr(struct inode *inode)
{
	get_fuse_inode(inode)->i_time = 0;
}

void fuse_invalidate_atime(struct inode *inode)
{
	if (!IS_RDONLY(inode))
		fuse_invalidate_attr(inode);
}

void fuse_invalidate_entry_cache(struct dentry *entry)
{
	fuse_dentry_settime(entry, 0);
}

static void fuse_invalidate_entry(struct dentry *entry)
{
	d_invalidate(entry);
	fuse_invalidate_entry_cache(entry);
}

static void fuse_lookup_init(struct fuse_conn *fc, struct fuse_args *args,
			     u64 nodeid, struct qstr *name,
			     struct fuse_entry_out *outarg)
{
	memset(outarg, 0, sizeof(struct fuse_entry_out));
	args->in.h.opcode = FUSE_LOOKUP;
	args->in.h.nodeid = nodeid;
	args->in.numargs = 1;
	args->in.args[0].size = name->len + 1;
	args->in.args[0].value = name->name;
	args->out.numargs = 1;
	args->out.args[0].size = sizeof(struct fuse_entry_out);
	args->out.args[0].value = outarg;
}

u64 fuse_get_attr_version(struct fuse_conn *fc)
{
	u64 curr_version;

	spin_lock(&fc->lock);
	curr_version = fc->attr_version;
	spin_unlock(&fc->lock);

	return curr_version;
}

static int fuse_dentry_revalidate(struct dentry *entry, unsigned int flags)
{
	struct inode *inode;
	struct dentry *parent;
	struct fuse_conn *fc;
	struct fuse_inode *fi;
	int ret;

	inode = d_inode_rcu(entry);
	if (inode && is_bad_inode(inode))
		goto invalid;
	else if (time_before64(fuse_dentry_time(entry), get_jiffies_64()) ||
		 (flags & LOOKUP_REVAL)) {
		struct fuse_entry_out outarg;
		FUSE_ARGS(args);
		struct fuse_forget_link *forget;
		u64 attr_version;

		if (!inode)
			goto invalid;

		ret = -ECHILD;
		if (flags & LOOKUP_RCU)
			goto out;

		fc = get_fuse_conn(inode);

		forget = fuse_alloc_forget();
		ret = -ENOMEM;
		if (!forget)
			goto out;

		attr_version = fuse_get_attr_version(fc);

		parent = dget_parent(entry);
		fuse_lookup_init(fc, &args, get_node_id(d_inode(parent)),
				 &entry->d_name, &outarg);
		ret = fuse_simple_request(fc, &args);
		dput(parent);
		 
		if (!ret && !outarg.nodeid)
			ret = -ENOENT;
		if (!ret) {
			fi = get_fuse_inode(inode);
			if (outarg.nodeid != get_node_id(inode)) {
				fuse_queue_forget(fc, forget, outarg.nodeid, 1);
				goto invalid;
			}
			spin_lock(&fc->lock);
			fi->nlookup++;
			spin_unlock(&fc->lock);
		}
		kfree(forget);
		if (ret == -ENOMEM)
			goto out;
		if (ret || (outarg.attr.mode ^ inode->i_mode) & S_IFMT)
			goto invalid;

		fuse_change_attributes(inode, &outarg.attr,
				       entry_attr_timeout(&outarg),
				       attr_version);
		fuse_change_entry_timeout(entry, &outarg);
	} else if (inode) {
		fi = get_fuse_inode(inode);
		if (flags & LOOKUP_RCU) {
			if (test_bit(FUSE_I_INIT_RDPLUS, &fi->state))
				return -ECHILD;
		} else if (test_and_clear_bit(FUSE_I_INIT_RDPLUS, &fi->state)) {
			parent = dget_parent(entry);
			fuse_advise_use_readdirplus(d_inode(parent));
			dput(parent);
		}
	}
	ret = 1;
out:
	return ret;

invalid:
	ret = 0;
	goto out;
}

static int invalid_nodeid(u64 nodeid)
{
	return !nodeid || nodeid == FUSE_ROOT_ID;
}

const struct dentry_operations fuse_dentry_operations = {
	.d_revalidate	= fuse_dentry_revalidate,
};

int fuse_valid_type(int m)
{
	return S_ISREG(m) || S_ISDIR(m) || S_ISLNK(m) || S_ISCHR(m) ||
		S_ISBLK(m) || S_ISFIFO(m) || S_ISSOCK(m);
}

#ifdef MY_ABC_HERE
int fuse_lookup_name(struct super_block *sb, u64 nodeid, struct qstr *name,
		     struct fuse_entry_out *outarg, struct inode **inode,
			 struct fuse_synostat *synostat, int syno_stat_flags)
#else
int fuse_lookup_name(struct super_block *sb, u64 nodeid, struct qstr *name,
		     struct fuse_entry_out *outarg, struct inode **inode)
#endif  
{
	struct fuse_conn *fc = get_fuse_conn_super(sb);
	FUSE_ARGS(args);
	struct fuse_forget_link *forget;
	u64 attr_version;
	int err;
#ifdef MY_ABC_HERE
	char *result_name = NULL;
	int result_name_len = 0;
	int glsfs_caseless_lookup = IS_GLUSTER_FS_SB(sb) && (syno_stat_flags & SYNOST_IS_CASELESS);
	char *new_dname = NULL;
	const char *extra_dname = NULL;
#endif  

	*inode = NULL;
	err = -ENAMETOOLONG;
	if (name->len > FUSE_NAME_MAX)
		goto out;

	forget = fuse_alloc_forget();
	err = -ENOMEM;
	if (!forget)
		goto out;

	attr_version = fuse_get_attr_version(fc);

	fuse_lookup_init(fc, &args, nodeid, name, outarg);
#ifdef MY_ABC_HERE
	if (IS_GLUSTER_FS_SB(sb)) {
		args.in.numargs = 2;
		args.in.args[1].size = sizeof(syno_stat_flags);
		args.in.args[1].value = &syno_stat_flags;
		if (synostat) {
			args.out.numargs = 2;
			args.out.argvar = 1;
			args.out.args[1].size = FUSE_SYNOSTAT_SIZE;
			args.out.args[1].value = synostat;
		}
	}
	if (glsfs_caseless_lookup && synostat) {
		result_name = synostat->name;
		synostat->name_len = SYNO_FUSE_ENTRY_NAME_LEN + 1;
	}
	err = fuse_send_syno_request(fc, &args);
#else
	err = fuse_simple_request(fc, &args);
#endif  
	 
	if (err || !outarg->nodeid)
		goto out_put_forget;

	err = -EIO;
	if (!outarg->nodeid)
		goto out_put_forget;
	if (!fuse_valid_type(outarg->attr.mode))
		goto out_put_forget;

	*inode = fuse_iget(sb, outarg->nodeid, outarg->generation,
			   &outarg->attr, entry_attr_timeout(outarg),
			   attr_version);
#ifdef MY_ABC_HERE
	 
	if (glsfs_caseless_lookup && synostat) {
		result_name_len = args.out.args[1].size - sizeof(*synostat);
		result_name[result_name_len] = '\0';

		if (dentry_string_cmp(name->name, result_name, result_name_len)) {
			if (result_name_len > (DNAME_INLINE_LEN - 1) && result_name_len > name->len) {
				new_dname = kmalloc(result_name_len + 1, GFP_KERNEL);
				if (!new_dname) {
					return -ENOMEM;
				}
				 
				if (name->len > (DNAME_INLINE_LEN - 1)) {
					extra_dname = name->name;
				}
				memcpy((unsigned char*)new_dname, result_name, result_name_len);
				new_dname[result_name_len] = '\0';

				name->len = result_name_len;
				name->name = new_dname;

				if (extra_dname) {
					kfree(extra_dname);
				}
			} else {
				memcpy((unsigned char *)name->name, result_name, result_name_len);
				((char*)name->name)[result_name_len] = '\0';
				name->len = result_name_len;
			}
		}
	}
#endif  
	err = -ENOMEM;
	if (!*inode) {
		fuse_queue_forget(fc, forget, outarg->nodeid, 1);
		goto out;
	}
	err = 0;

 out_put_forget:
	kfree(forget);
 out:
	return err;
}

static struct dentry *fuse_lookup(struct inode *dir, struct dentry *entry,
				  unsigned int flags)
{
	int err;
	struct fuse_entry_out outarg;
#ifdef MY_ABC_HERE
	struct fuse_synostat *synostat = NULL;
#endif  
	struct inode *inode;
	struct dentry *newent;
	bool outarg_valid = true;

#ifdef MY_ABC_HERE
	if ((flags & LOOKUP_CASELESS_COMPARE) && IS_GLUSTER_FS(dir)) {
		synostat = kmalloc(FUSE_SYNOSTAT_SIZE, GFP_KERNEL);
		memset(synostat, 0, FUSE_SYNOSTAT_SIZE);
	}
	err = fuse_lookup_name(dir->i_sb, get_node_id(dir), &entry->d_name,
			       &outarg, &inode, synostat,
				   (flags & LOOKUP_CASELESS_COMPARE) ? SYNOST_IS_CASELESS : 0);
	kfree(synostat);
#else
	err = fuse_lookup_name(dir->i_sb, get_node_id(dir), &entry->d_name,
			       &outarg, &inode);
#endif  
	if (err == -ENOENT) {
		outarg_valid = false;
		err = 0;
	}
	if (err)
		goto out_err;

	err = -EIO;
	if (inode && get_node_id(inode) == FUSE_ROOT_ID)
		goto out_iput;

	newent = d_splice_alias(inode, entry);
	err = PTR_ERR(newent);
	if (IS_ERR(newent))
		goto out_err;

	entry = newent ? newent : entry;
	if (outarg_valid)
		fuse_change_entry_timeout(entry, &outarg);
	else
		fuse_invalidate_entry_cache(entry);

	fuse_advise_use_readdirplus(dir);
	return newent;

 out_iput:
	iput(inode);
 out_err:
	return ERR_PTR(err);
}

static int fuse_create_open(struct inode *dir, struct dentry *entry,
			    struct file *file, unsigned flags,
			    umode_t mode, int *opened)
{
	int err;
	struct inode *inode;
	struct fuse_conn *fc = get_fuse_conn(dir);
	FUSE_ARGS(args);
	struct fuse_forget_link *forget;
	struct fuse_create_in inarg;
	struct fuse_open_out outopen;
	struct fuse_entry_out outentry;
	struct fuse_file *ff;

	BUG_ON((mode & S_IFMT) != S_IFREG);

	forget = fuse_alloc_forget();
	err = -ENOMEM;
	if (!forget)
		goto out_err;

	err = -ENOMEM;
	ff = fuse_file_alloc(fc);
	if (!ff)
		goto out_put_forget_req;

	if (!fc->dont_mask)
		mode &= ~current_umask();

	flags &= ~O_NOCTTY;
	memset(&inarg, 0, sizeof(inarg));
	memset(&outentry, 0, sizeof(outentry));
	inarg.flags = flags;
	inarg.mode = mode;
	inarg.umask = current_umask();
	args.in.h.opcode = FUSE_CREATE;
	args.in.h.nodeid = get_node_id(dir);
	args.in.numargs = 2;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.in.args[1].size = entry->d_name.len + 1;
	args.in.args[1].value = entry->d_name.name;
	args.out.numargs = 2;
	args.out.args[0].size = sizeof(outentry);
	args.out.args[0].value = &outentry;
	args.out.args[1].size = sizeof(outopen);
	args.out.args[1].value = &outopen;
	err = fuse_simple_request(fc, &args);
	if (err)
		goto out_free_ff;

	err = -EIO;
	if (!S_ISREG(outentry.attr.mode) || invalid_nodeid(outentry.nodeid))
		goto out_free_ff;

	ff->fh = outopen.fh;
	ff->nodeid = outentry.nodeid;
	ff->open_flags = outopen.open_flags;
	inode = fuse_iget(dir->i_sb, outentry.nodeid, outentry.generation,
			  &outentry.attr, entry_attr_timeout(&outentry), 0);
	if (!inode) {
		flags &= ~(O_CREAT | O_EXCL | O_TRUNC);
		fuse_sync_release(ff, flags);
		fuse_queue_forget(fc, forget, outentry.nodeid, 1);
		err = -ENOMEM;
		goto out_err;
	}
	kfree(forget);
	d_instantiate(entry, inode);
	fuse_change_entry_timeout(entry, &outentry);
	fuse_invalidate_attr(dir);
	err = finish_open(file, entry, generic_file_open, opened);
	if (err) {
		fuse_sync_release(ff, flags);
	} else {
		file->private_data = fuse_file_get(ff);
		fuse_finish_open(inode, file);
	}
	return err;

out_free_ff:
	fuse_file_free(ff);
out_put_forget_req:
	kfree(forget);
out_err:
	return err;
}

static int fuse_mknod(struct inode *, struct dentry *, umode_t, dev_t);
static int fuse_atomic_open(struct inode *dir, struct dentry *entry,
			    struct file *file, unsigned flags,
			    umode_t mode, int *opened)
{
	int err;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct dentry *res = NULL;

	if (d_unhashed(entry)) {
		res = fuse_lookup(dir, entry, 0);
		if (IS_ERR(res))
			return PTR_ERR(res);

		if (res)
			entry = res;
	}

	if (!(flags & O_CREAT) || d_really_is_positive(entry))
		goto no_open;

	*opened |= FILE_CREATED;

	if (fc->no_create)
		goto mknod;

	err = fuse_create_open(dir, entry, file, flags, mode, opened);
	if (err == -ENOSYS) {
		fc->no_create = 1;
		goto mknod;
	}
out_dput:
	dput(res);
	return err;

mknod:
	err = fuse_mknod(dir, entry, mode, 0);
	if (err)
		goto out_dput;
no_open:
	return finish_no_open(file, res);
}

static int create_new_entry(struct fuse_conn *fc, struct fuse_args *args,
			    struct inode *dir, struct dentry *entry,
			    umode_t mode)
{
	struct fuse_entry_out outarg;
	struct inode *inode;
	int err;
	struct fuse_forget_link *forget;

	forget = fuse_alloc_forget();
	if (!forget)
		return -ENOMEM;

	memset(&outarg, 0, sizeof(outarg));
	args->in.h.nodeid = get_node_id(dir);
	args->out.numargs = 1;
	args->out.args[0].size = sizeof(outarg);
	args->out.args[0].value = &outarg;
	err = fuse_simple_request(fc, args);
	if (err)
		goto out_put_forget_req;

	err = -EIO;
	if (invalid_nodeid(outarg.nodeid))
		goto out_put_forget_req;

	if ((outarg.attr.mode ^ mode) & S_IFMT)
		goto out_put_forget_req;

	inode = fuse_iget(dir->i_sb, outarg.nodeid, outarg.generation,
			  &outarg.attr, entry_attr_timeout(&outarg), 0);
	if (!inode) {
		fuse_queue_forget(fc, forget, outarg.nodeid, 1);
		return -ENOMEM;
	}
	kfree(forget);

	err = d_instantiate_no_diralias(entry, inode);
	if (err)
		return err;

	fuse_change_entry_timeout(entry, &outarg);
	fuse_invalidate_attr(dir);
	return 0;

 out_put_forget_req:
	kfree(forget);
	return err;
}

static int fuse_mknod(struct inode *dir, struct dentry *entry, umode_t mode,
		      dev_t rdev)
{
	struct fuse_mknod_in inarg;
	struct fuse_conn *fc = get_fuse_conn(dir);
	FUSE_ARGS(args);

	if (!fc->dont_mask)
		mode &= ~current_umask();

	memset(&inarg, 0, sizeof(inarg));
	inarg.mode = mode;
	inarg.rdev = new_encode_dev(rdev);
	inarg.umask = current_umask();
	args.in.h.opcode = FUSE_MKNOD;
	args.in.numargs = 2;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.in.args[1].size = entry->d_name.len + 1;
	args.in.args[1].value = entry->d_name.name;
	return create_new_entry(fc, &args, dir, entry, mode);
}

static int fuse_create(struct inode *dir, struct dentry *entry, umode_t mode,
		       bool excl)
{
	return fuse_mknod(dir, entry, mode, 0);
}

static int fuse_mkdir(struct inode *dir, struct dentry *entry, umode_t mode)
{
	struct fuse_mkdir_in inarg;
	struct fuse_conn *fc = get_fuse_conn(dir);
	FUSE_ARGS(args);

	if (!fc->dont_mask)
		mode &= ~current_umask();

	memset(&inarg, 0, sizeof(inarg));
	inarg.mode = mode;
	inarg.umask = current_umask();
	args.in.h.opcode = FUSE_MKDIR;
	args.in.numargs = 2;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.in.args[1].size = entry->d_name.len + 1;
	args.in.args[1].value = entry->d_name.name;
	return create_new_entry(fc, &args, dir, entry, S_IFDIR);
}

static int fuse_symlink(struct inode *dir, struct dentry *entry,
			const char *link)
{
	struct fuse_conn *fc = get_fuse_conn(dir);
	unsigned len = strlen(link) + 1;
	FUSE_ARGS(args);

	args.in.h.opcode = FUSE_SYMLINK;
	args.in.numargs = 2;
	args.in.args[0].size = entry->d_name.len + 1;
	args.in.args[0].value = entry->d_name.name;
	args.in.args[1].size = len;
	args.in.args[1].value = link;
	return create_new_entry(fc, &args, dir, entry, S_IFLNK);
}

static inline void fuse_update_ctime(struct inode *inode)
{
	if (!IS_NOCMTIME(inode)) {
		inode->i_ctime = current_fs_time(inode->i_sb);
		mark_inode_dirty_sync(inode);
	}
}

static int fuse_unlink(struct inode *dir, struct dentry *entry)
{
	int err;
	struct fuse_conn *fc = get_fuse_conn(dir);
	FUSE_ARGS(args);

	args.in.h.opcode = FUSE_UNLINK;
	args.in.h.nodeid = get_node_id(dir);
	args.in.numargs = 1;
	args.in.args[0].size = entry->d_name.len + 1;
	args.in.args[0].value = entry->d_name.name;
	err = fuse_simple_request(fc, &args);
	if (!err) {
		struct inode *inode = d_inode(entry);
		struct fuse_inode *fi = get_fuse_inode(inode);

		spin_lock(&fc->lock);
		fi->attr_version = ++fc->attr_version;
		 
		if (inode->i_nlink > 0)
			drop_nlink(inode);
		spin_unlock(&fc->lock);
		fuse_invalidate_attr(inode);
		fuse_invalidate_attr(dir);
		fuse_invalidate_entry_cache(entry);
		fuse_update_ctime(inode);
	} else if (err == -EINTR)
		fuse_invalidate_entry(entry);
	return err;
}

static int fuse_rmdir(struct inode *dir, struct dentry *entry)
{
	int err;
	struct fuse_conn *fc = get_fuse_conn(dir);
	FUSE_ARGS(args);

	args.in.h.opcode = FUSE_RMDIR;
	args.in.h.nodeid = get_node_id(dir);
	args.in.numargs = 1;
	args.in.args[0].size = entry->d_name.len + 1;
	args.in.args[0].value = entry->d_name.name;
	err = fuse_simple_request(fc, &args);
	if (!err) {
		clear_nlink(d_inode(entry));
		fuse_invalidate_attr(dir);
		fuse_invalidate_entry_cache(entry);
	} else if (err == -EINTR)
		fuse_invalidate_entry(entry);
	return err;
}

static int fuse_rename_common(struct inode *olddir, struct dentry *oldent,
			      struct inode *newdir, struct dentry *newent,
			      unsigned int flags, int opcode, size_t argsize)
{
	int err;
	struct fuse_rename2_in inarg;
	struct fuse_conn *fc = get_fuse_conn(olddir);
	FUSE_ARGS(args);

	memset(&inarg, 0, argsize);
	inarg.newdir = get_node_id(newdir);
	inarg.flags = flags;
	args.in.h.opcode = opcode;
	args.in.h.nodeid = get_node_id(olddir);
	args.in.numargs = 3;
	args.in.args[0].size = argsize;
	args.in.args[0].value = &inarg;
	args.in.args[1].size = oldent->d_name.len + 1;
	args.in.args[1].value = oldent->d_name.name;
	args.in.args[2].size = newent->d_name.len + 1;
	args.in.args[2].value = newent->d_name.name;
	err = fuse_simple_request(fc, &args);
	if (!err) {
		 
		fuse_invalidate_attr(d_inode(oldent));
		fuse_update_ctime(d_inode(oldent));

		if (flags & RENAME_EXCHANGE) {
			fuse_invalidate_attr(d_inode(newent));
			fuse_update_ctime(d_inode(newent));
		}

		fuse_invalidate_attr(olddir);
		if (olddir != newdir)
			fuse_invalidate_attr(newdir);

		if (!(flags & RENAME_EXCHANGE) && d_really_is_positive(newent)) {
			fuse_invalidate_attr(d_inode(newent));
			fuse_invalidate_entry_cache(newent);
			fuse_update_ctime(d_inode(newent));
		}
	} else if (err == -EINTR) {
		 
		fuse_invalidate_entry(oldent);
		if (d_really_is_positive(newent))
			fuse_invalidate_entry(newent);
	}

	return err;
}

static int fuse_rename2(struct inode *olddir, struct dentry *oldent,
			struct inode *newdir, struct dentry *newent,
			unsigned int flags)
{
	struct fuse_conn *fc = get_fuse_conn(olddir);
	int err;

	if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE))
		return -EINVAL;

	if (flags) {
		if (fc->no_rename2 || fc->minor < 23)
			return -EINVAL;

		err = fuse_rename_common(olddir, oldent, newdir, newent, flags,
					 FUSE_RENAME2,
					 sizeof(struct fuse_rename2_in));
		if (err == -ENOSYS) {
			fc->no_rename2 = 1;
			err = -EINVAL;
		}
	} else {
		err = fuse_rename_common(olddir, oldent, newdir, newent, 0,
					 FUSE_RENAME,
					 sizeof(struct fuse_rename_in));
	}

	return err;
}

static int fuse_link(struct dentry *entry, struct inode *newdir,
		     struct dentry *newent)
{
	int err;
	struct fuse_link_in inarg;
	struct inode *inode = d_inode(entry);
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);

	memset(&inarg, 0, sizeof(inarg));
	inarg.oldnodeid = get_node_id(inode);
	args.in.h.opcode = FUSE_LINK;
	args.in.numargs = 2;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.in.args[1].size = newent->d_name.len + 1;
	args.in.args[1].value = newent->d_name.name;
	err = create_new_entry(fc, &args, newdir, newent, inode->i_mode);
	 
	if (!err) {
		struct fuse_inode *fi = get_fuse_inode(inode);

		spin_lock(&fc->lock);
		fi->attr_version = ++fc->attr_version;
		inc_nlink(inode);
		spin_unlock(&fc->lock);
		fuse_invalidate_attr(inode);
		fuse_update_ctime(inode);
	} else if (err == -EINTR) {
		fuse_invalidate_attr(inode);
	}
	return err;
}

static void fuse_fillattr(struct inode *inode, struct fuse_attr *attr,
			  struct kstat *stat)
{
	unsigned int blkbits;
	struct fuse_conn *fc = get_fuse_conn(inode);

	if (fc->writeback_cache && S_ISREG(inode->i_mode)) {
		attr->size = i_size_read(inode);
		attr->mtime = inode->i_mtime.tv_sec;
		attr->mtimensec = inode->i_mtime.tv_nsec;
		attr->ctime = inode->i_ctime.tv_sec;
		attr->ctimensec = inode->i_ctime.tv_nsec;
	}

	stat->dev = inode->i_sb->s_dev;
	stat->ino = attr->ino;
	stat->mode = (inode->i_mode & S_IFMT) | (attr->mode & 07777);
	stat->nlink = attr->nlink;
	stat->uid = make_kuid(&init_user_ns, attr->uid);
	stat->gid = make_kgid(&init_user_ns, attr->gid);
	stat->rdev = inode->i_rdev;
	stat->atime.tv_sec = attr->atime;
	stat->atime.tv_nsec = attr->atimensec;
	stat->mtime.tv_sec = attr->mtime;
	stat->mtime.tv_nsec = attr->mtimensec;
	stat->ctime.tv_sec = attr->ctime;
	stat->ctime.tv_nsec = attr->ctimensec;
	stat->size = attr->size;
	stat->blocks = attr->blocks;

	if (attr->blksize != 0)
		blkbits = ilog2(attr->blksize);
	else
		blkbits = inode->i_sb->s_blocksize_bits;

	stat->blksize = 1 << blkbits;
}

static int fuse_do_getattr(struct inode *inode, struct kstat *stat,
			   struct file *file)
{
	int err;
	struct fuse_getattr_in inarg;
	struct fuse_attr_out outarg;
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);
	u64 attr_version;

	attr_version = fuse_get_attr_version(fc);

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));
	 
	if (file && S_ISREG(inode->i_mode)) {
		struct fuse_file *ff = file->private_data;

		inarg.getattr_flags |= FUSE_GETATTR_FH;
		inarg.fh = ff->fh;
	}
	args.in.h.opcode = FUSE_GETATTR;
	args.in.h.nodeid = get_node_id(inode);
	args.in.numargs = 1;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.out.numargs = 1;
	args.out.args[0].size = sizeof(outarg);
	args.out.args[0].value = &outarg;
	err = fuse_simple_request(fc, &args);
	if (!err) {
		if ((inode->i_mode ^ outarg.attr.mode) & S_IFMT) {
			make_bad_inode(inode);
			err = -EIO;
		} else {
			fuse_change_attributes(inode, &outarg.attr,
					       attr_timeout(&outarg),
					       attr_version);
			if (stat)
				fuse_fillattr(inode, &outarg.attr, stat);
		}
	}
	return err;
}

int fuse_update_attributes(struct inode *inode, struct kstat *stat,
			   struct file *file, bool *refreshed)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	int err;
	bool r;

	if (time_before64(fi->i_time, get_jiffies_64())) {
		r = true;
		err = fuse_do_getattr(inode, stat, file);
	} else {
		r = false;
		err = 0;
		if (stat) {
			generic_fillattr(inode, stat);
			stat->mode = fi->orig_i_mode;
			stat->ino = fi->orig_ino;
		}
	}

	if (refreshed != NULL)
		*refreshed = r;

	return err;
}

int fuse_reverse_inval_entry(struct super_block *sb, u64 parent_nodeid,
			     u64 child_nodeid, struct qstr *name)
{
	int err = -ENOTDIR;
	struct inode *parent;
	struct dentry *dir;
	struct dentry *entry;

	parent = ilookup5(sb, parent_nodeid, fuse_inode_eq, &parent_nodeid);
	if (!parent)
		return -ENOENT;

	inode_lock(parent);
	if (!S_ISDIR(parent->i_mode))
		goto unlock;

	err = -ENOENT;
	dir = d_find_alias(parent);
	if (!dir)
		goto unlock;

	entry = d_lookup(dir, name);
	dput(dir);
	if (!entry)
		goto unlock;

	fuse_invalidate_attr(parent);
	fuse_invalidate_entry(entry);

	if (child_nodeid != 0 && d_really_is_positive(entry)) {
		inode_lock(d_inode(entry));
		if (get_node_id(d_inode(entry)) != child_nodeid) {
			err = -ENOENT;
			goto badentry;
		}
		if (d_mountpoint(entry)) {
			err = -EBUSY;
			goto badentry;
		}
		if (d_is_dir(entry)) {
			shrink_dcache_parent(entry);
			if (!simple_empty(entry)) {
				err = -ENOTEMPTY;
				goto badentry;
			}
			d_inode(entry)->i_flags |= S_DEAD;
		}
		dont_mount(entry);
		clear_nlink(d_inode(entry));
		err = 0;
 badentry:
		inode_unlock(d_inode(entry));
		if (!err)
			d_delete(entry);
	} else {
		err = 0;
	}
	dput(entry);

 unlock:
	inode_unlock(parent);
	iput(parent);
	return err;
}

int fuse_allow_current_process(struct fuse_conn *fc)
{
	const struct cred *cred;

	if (fc->flags & FUSE_ALLOW_OTHER)
		return 1;

	cred = current_cred();
	if (uid_eq(cred->euid, fc->user_id) &&
	    uid_eq(cred->suid, fc->user_id) &&
	    uid_eq(cred->uid,  fc->user_id) &&
	    gid_eq(cred->egid, fc->group_id) &&
	    gid_eq(cred->sgid, fc->group_id) &&
	    gid_eq(cred->gid,  fc->group_id))
		return 1;

	return 0;
}

#ifdef MY_ABC_HERE
static int fuse_access(struct inode *inode, int mask, int syno_acl_access)
#else
static int fuse_access(struct inode *inode, int mask)
#endif  
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);
	struct fuse_access_in inarg;
	int err;

#ifdef MY_ABC_HERE
	if (!syno_acl_access)
#endif  
	BUG_ON(mask & MAY_NOT_BLOCK);

	if (fc->no_access)
		return 0;

	memset(&inarg, 0, sizeof(inarg));
#ifdef MY_ABC_HERE
	inarg.syno_acl_access = syno_acl_access;
	if (IS_GLUSTER_FS(inode) && syno_acl_access) {
		inarg.mask = mask & SYNO_PERM_FULL_CONTROL;
	} else
#endif  
	inarg.mask = mask & (MAY_READ | MAY_WRITE | MAY_EXEC);
	args.in.h.opcode = FUSE_ACCESS;
	args.in.h.nodeid = get_node_id(inode);
	args.in.numargs = 1;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	err = fuse_simple_request(fc, &args);
	if (err == -ENOSYS) {
		fc->no_access = 1;
		err = 0;
	}
	return err;
}

static int fuse_perm_getattr(struct inode *inode, int mask)
{
	if (mask & MAY_NOT_BLOCK)
		return -ECHILD;

	return fuse_do_getattr(inode, NULL, NULL);
}

static int fuse_permission(struct inode *inode, int mask)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	bool refreshed = false;
	int err = 0;

	if (!fuse_allow_current_process(fc))
		return -EACCES;

	if ((fc->flags & FUSE_DEFAULT_PERMISSIONS) ||
	    ((mask & MAY_EXEC) && S_ISREG(inode->i_mode))) {
		struct fuse_inode *fi = get_fuse_inode(inode);

		if (time_before64(fi->i_time, get_jiffies_64())) {
			refreshed = true;

			err = fuse_perm_getattr(inode, mask);
			if (err)
				return err;
		}
	}

	if (fc->flags & FUSE_DEFAULT_PERMISSIONS) {
		err = generic_permission(inode, mask);

		if (err == -EACCES && !refreshed) {
			err = fuse_perm_getattr(inode, mask);
			if (!err)
				err = generic_permission(inode, mask);
		}

	} else if (mask & (MAY_ACCESS | MAY_CHDIR)) {
#ifdef MY_ABC_HERE
		err = fuse_access(inode, mask, 0);
#else
		err = fuse_access(inode, mask);
#endif  
	} else if ((mask & MAY_EXEC) && S_ISREG(inode->i_mode)) {
#ifdef MY_ABC_HERE
		if (IS_GLUSTER_FS(inode)) {
			return fuse_access(inode, mask, 0);
		}
#endif  
		if (!(inode->i_mode & S_IXUGO)) {
			if (refreshed)
				return -EACCES;

			err = fuse_perm_getattr(inode, mask);
			if (!err && !(inode->i_mode & S_IXUGO))
				return -EACCES;
		}
	}
	return err;
}

static int parse_dirfile(char *buf, size_t nbytes, struct file *file,
			 struct dir_context *ctx)
{
	while (nbytes >= FUSE_NAME_OFFSET) {
		struct fuse_dirent *dirent = (struct fuse_dirent *) buf;
		size_t reclen = FUSE_DIRENT_SIZE(dirent);
		if (!dirent->namelen || dirent->namelen > FUSE_NAME_MAX)
			return -EIO;
		if (reclen > nbytes)
			break;
		if (memchr(dirent->name, '/', dirent->namelen) != NULL)
			return -EIO;

		if (!dir_emit(ctx, dirent->name, dirent->namelen,
			       dirent->ino, dirent->type))
			break;

		buf += reclen;
		nbytes -= reclen;
		ctx->pos = dirent->off;
	}

	return 0;
}

static int fuse_direntplus_link(struct file *file,
				struct fuse_direntplus *direntplus,
				u64 attr_version)
{
	int err;
	struct fuse_entry_out *o = &direntplus->entry_out;
	struct fuse_dirent *dirent = &direntplus->dirent;
	struct dentry *parent = file->f_path.dentry;
	struct qstr name = QSTR_INIT(dirent->name, dirent->namelen);
	struct dentry *dentry;
	struct dentry *alias;
	struct inode *dir = d_inode(parent);
	struct fuse_conn *fc;
	struct inode *inode;

	if (!o->nodeid) {
		 
		return 0;
	}

	if (name.name[0] == '.') {
		 
		if (name.len == 1)
			return 0;
		if (name.name[1] == '.' && name.len == 2)
			return 0;
	}

	if (invalid_nodeid(o->nodeid))
		return -EIO;
	if (!fuse_valid_type(o->attr.mode))
		return -EIO;

	fc = get_fuse_conn(dir);

	name.hash = full_name_hash(name.name, name.len);
	dentry = d_lookup(parent, &name);
	if (dentry) {
		inode = d_inode(dentry);
		if (!inode) {
			d_drop(dentry);
		} else if (get_node_id(inode) != o->nodeid ||
			   ((o->attr.mode ^ inode->i_mode) & S_IFMT)) {
			d_invalidate(dentry);
		} else if (is_bad_inode(inode)) {
			err = -EIO;
			goto out;
		} else {
			struct fuse_inode *fi;
			fi = get_fuse_inode(inode);
			spin_lock(&fc->lock);
			fi->nlookup++;
			spin_unlock(&fc->lock);

			fuse_change_attributes(inode, &o->attr,
					       entry_attr_timeout(o),
					       attr_version);

			goto found;
		}
		dput(dentry);
	}

	dentry = d_alloc(parent, &name);
	err = -ENOMEM;
	if (!dentry)
		goto out;

	inode = fuse_iget(dir->i_sb, o->nodeid, o->generation,
			  &o->attr, entry_attr_timeout(o), attr_version);
	if (!inode)
		goto out;

	alias = d_splice_alias(inode, dentry);
	err = PTR_ERR(alias);
	if (IS_ERR(alias))
		goto out;

	if (alias) {
		dput(dentry);
		dentry = alias;
	}

found:
	if (fc->readdirplus_auto)
		set_bit(FUSE_I_INIT_RDPLUS, &get_fuse_inode(inode)->state);
	fuse_change_entry_timeout(dentry, o);

	err = 0;
out:
	dput(dentry);
	return err;
}

static int parse_dirplusfile(char *buf, size_t nbytes, struct file *file,
			     struct dir_context *ctx, u64 attr_version)
{
	struct fuse_direntplus *direntplus;
	struct fuse_dirent *dirent;
	size_t reclen;
	int over = 0;
	int ret;

	while (nbytes >= FUSE_NAME_OFFSET_DIRENTPLUS) {
		direntplus = (struct fuse_direntplus *) buf;
		dirent = &direntplus->dirent;
		reclen = FUSE_DIRENTPLUS_SIZE(direntplus);

		if (!dirent->namelen || dirent->namelen > FUSE_NAME_MAX)
			return -EIO;
		if (reclen > nbytes)
			break;
		if (memchr(dirent->name, '/', dirent->namelen) != NULL)
			return -EIO;

		if (!over) {
			 
			over = !dir_emit(ctx, dirent->name, dirent->namelen,
				       dirent->ino, dirent->type);
			ctx->pos = dirent->off;
		}

		buf += reclen;
		nbytes -= reclen;

		ret = fuse_direntplus_link(file, direntplus, attr_version);
		if (ret)
			fuse_force_forget(file, direntplus->entry_out.nodeid);
	}

	return 0;
}

static int fuse_readdir(struct file *file, struct dir_context *ctx)
{
	int plus, err;
	size_t nbytes;
	struct page *page;
	struct inode *inode = file_inode(file);
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	u64 attr_version = 0;

	if (is_bad_inode(inode))
		return -EIO;

	req = fuse_get_req(fc, 1);
	if (IS_ERR(req))
		return PTR_ERR(req);

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		fuse_put_request(fc, req);
		return -ENOMEM;
	}

	plus = fuse_use_readdirplus(inode, ctx);
	req->out.argpages = 1;
	req->num_pages = 1;
	req->pages[0] = page;
	req->page_descs[0].length = PAGE_SIZE;
	if (plus) {
		attr_version = fuse_get_attr_version(fc);
		fuse_read_fill(req, file, ctx->pos, PAGE_SIZE,
			       FUSE_READDIRPLUS);
	} else {
		fuse_read_fill(req, file, ctx->pos, PAGE_SIZE,
			       FUSE_READDIR);
	}
	fuse_request_send(fc, req);
	nbytes = req->out.args[0].size;
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err) {
		if (plus) {
			err = parse_dirplusfile(page_address(page), nbytes,
						file, ctx,
						attr_version);
		} else {
			err = parse_dirfile(page_address(page), nbytes, file,
					    ctx);
		}
	}

	__free_page(page);
	fuse_invalidate_atime(inode);
	return err;
}

static const char *fuse_follow_link(struct dentry *dentry, void **cookie)
{
	struct inode *inode = d_inode(dentry);
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);
	char *link;
	ssize_t ret;

	link = (char *) __get_free_page(GFP_KERNEL);
	if (!link)
		return ERR_PTR(-ENOMEM);

	args.in.h.opcode = FUSE_READLINK;
	args.in.h.nodeid = get_node_id(inode);
	args.out.argvar = 1;
	args.out.numargs = 1;
	args.out.args[0].size = PAGE_SIZE - 1;
	args.out.args[0].value = link;
	ret = fuse_simple_request(fc, &args);
	if (ret < 0) {
		free_page((unsigned long) link);
		link = ERR_PTR(ret);
	} else {
		link[ret] = '\0';
		*cookie = link;
	}
	fuse_invalidate_atime(inode);
	return link;
}

static int fuse_dir_open(struct inode *inode, struct file *file)
{
	return fuse_open_common(inode, file, true);
}

static int fuse_dir_release(struct inode *inode, struct file *file)
{
	fuse_release_common(file, FUSE_RELEASEDIR);

	return 0;
}

static int fuse_dir_fsync(struct file *file, loff_t start, loff_t end,
			  int datasync)
{
	return fuse_fsync_common(file, start, end, datasync, 1);
}

static long fuse_dir_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	struct fuse_conn *fc = get_fuse_conn(file->f_mapping->host);

	if (fc->minor < 18)
		return -ENOTTY;

	return fuse_ioctl_common(file, cmd, arg, FUSE_IOCTL_DIR);
}

static long fuse_dir_compat_ioctl(struct file *file, unsigned int cmd,
				   unsigned long arg)
{
	struct fuse_conn *fc = get_fuse_conn(file->f_mapping->host);

	if (fc->minor < 18)
		return -ENOTTY;

	return fuse_ioctl_common(file, cmd, arg,
				 FUSE_IOCTL_COMPAT | FUSE_IOCTL_DIR);
}

static bool update_mtime(unsigned ivalid, bool trust_local_mtime)
{
	 
	if (ivalid & ATTR_MTIME_SET)
		return true;

	if (trust_local_mtime)
		return true;

	if ((ivalid & ATTR_SIZE) && (ivalid & (ATTR_OPEN | ATTR_FILE)))
		return false;

	return true;
}

static void iattr_to_fattr(struct iattr *iattr, struct fuse_setattr_in *arg,
			   bool trust_local_cmtime)
{
	unsigned ivalid = iattr->ia_valid;

	if (ivalid & ATTR_MODE)
		arg->valid |= FATTR_MODE,   arg->mode = iattr->ia_mode;
	if (ivalid & ATTR_UID)
		arg->valid |= FATTR_UID,    arg->uid = from_kuid(&init_user_ns, iattr->ia_uid);
	if (ivalid & ATTR_GID)
		arg->valid |= FATTR_GID,    arg->gid = from_kgid(&init_user_ns, iattr->ia_gid);
	if (ivalid & ATTR_SIZE)
		arg->valid |= FATTR_SIZE,   arg->size = iattr->ia_size;
	if (ivalid & ATTR_ATIME) {
		arg->valid |= FATTR_ATIME;
		arg->atime = iattr->ia_atime.tv_sec;
		arg->atimensec = iattr->ia_atime.tv_nsec;
		if (!(ivalid & ATTR_ATIME_SET))
			arg->valid |= FATTR_ATIME_NOW;
	}
	if ((ivalid & ATTR_MTIME) && update_mtime(ivalid, trust_local_cmtime)) {
		arg->valid |= FATTR_MTIME;
		arg->mtime = iattr->ia_mtime.tv_sec;
		arg->mtimensec = iattr->ia_mtime.tv_nsec;
		if (!(ivalid & ATTR_MTIME_SET) && !trust_local_cmtime)
			arg->valid |= FATTR_MTIME_NOW;
	}
	if ((ivalid & ATTR_CTIME) && trust_local_cmtime) {
		arg->valid |= FATTR_CTIME;
		arg->ctime = iattr->ia_ctime.tv_sec;
		arg->ctimensec = iattr->ia_ctime.tv_nsec;
	}
}

void fuse_set_nowrite(struct inode *inode)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);

	BUG_ON(!inode_is_locked(inode));

	spin_lock(&fc->lock);
	BUG_ON(fi->writectr < 0);
	fi->writectr += FUSE_NOWRITE;
	spin_unlock(&fc->lock);
	wait_event(fi->page_waitq, fi->writectr == FUSE_NOWRITE);
}

static void __fuse_release_nowrite(struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	BUG_ON(fi->writectr != FUSE_NOWRITE);
	fi->writectr = 0;
	fuse_flush_writepages(inode);
}

void fuse_release_nowrite(struct inode *inode)
{
	struct fuse_conn *fc = get_fuse_conn(inode);

	spin_lock(&fc->lock);
	__fuse_release_nowrite(inode);
	spin_unlock(&fc->lock);
}

static void fuse_setattr_fill(struct fuse_conn *fc, struct fuse_args *args,
			      struct inode *inode,
			      struct fuse_setattr_in *inarg_p,
			      struct fuse_attr_out *outarg_p)
{
	args->in.h.opcode = FUSE_SETATTR;
	args->in.h.nodeid = get_node_id(inode);
	args->in.numargs = 1;
	args->in.args[0].size = sizeof(*inarg_p);
	args->in.args[0].value = inarg_p;
	args->out.numargs = 1;
	args->out.args[0].size = sizeof(*outarg_p);
	args->out.args[0].value = outarg_p;
}

int fuse_flush_times(struct inode *inode, struct fuse_file *ff)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);
	struct fuse_setattr_in inarg;
	struct fuse_attr_out outarg;

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));

	inarg.valid = FATTR_MTIME;
	inarg.mtime = inode->i_mtime.tv_sec;
	inarg.mtimensec = inode->i_mtime.tv_nsec;
	if (fc->minor >= 23) {
		inarg.valid |= FATTR_CTIME;
		inarg.ctime = inode->i_ctime.tv_sec;
		inarg.ctimensec = inode->i_ctime.tv_nsec;
	}
	if (ff) {
		inarg.valid |= FATTR_FH;
		inarg.fh = ff->fh;
	}
	fuse_setattr_fill(fc, &args, inode, &inarg, &outarg);

	return fuse_simple_request(fc, &args);
}

int fuse_do_setattr(struct inode *inode, struct iattr *attr,
		    struct file *file)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	FUSE_ARGS(args);
	struct fuse_setattr_in inarg;
	struct fuse_attr_out outarg;
	bool is_truncate = false;
	bool is_wb = fc->writeback_cache;
	loff_t oldsize;
	int err;
	bool trust_local_cmtime = is_wb && S_ISREG(inode->i_mode);

	if (!(fc->flags & FUSE_DEFAULT_PERMISSIONS))
		attr->ia_valid |= ATTR_FORCE;

	err = inode_change_ok(inode, attr);
	if (err)
		return err;

	if (attr->ia_valid & ATTR_OPEN) {
		if (fc->atomic_o_trunc)
			return 0;
		file = NULL;
	}

	if (attr->ia_valid & ATTR_SIZE)
		is_truncate = true;

	if (is_truncate) {
		fuse_set_nowrite(inode);
		set_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
		if (trust_local_cmtime && attr->ia_size != inode->i_size)
			attr->ia_valid |= ATTR_MTIME | ATTR_CTIME;
	}

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));
	iattr_to_fattr(attr, &inarg, trust_local_cmtime);
	if (file) {
		struct fuse_file *ff = file->private_data;
		inarg.valid |= FATTR_FH;
		inarg.fh = ff->fh;
	}
	if (attr->ia_valid & ATTR_SIZE) {
		 
		inarg.valid |= FATTR_LOCKOWNER;
		inarg.lock_owner = fuse_lock_owner_id(fc, current->files);
	}
	fuse_setattr_fill(fc, &args, inode, &inarg, &outarg);
	err = fuse_simple_request(fc, &args);
	if (err) {
		if (err == -EINTR)
			fuse_invalidate_attr(inode);
		goto error;
	}

	if ((inode->i_mode ^ outarg.attr.mode) & S_IFMT) {
		make_bad_inode(inode);
		err = -EIO;
		goto error;
	}

	spin_lock(&fc->lock);
	 
	if (trust_local_cmtime) {
		if (attr->ia_valid & ATTR_MTIME)
			inode->i_mtime = attr->ia_mtime;
		if (attr->ia_valid & ATTR_CTIME)
			inode->i_ctime = attr->ia_ctime;
		 
	}

	fuse_change_attributes_common(inode, &outarg.attr,
				      attr_timeout(&outarg));
	oldsize = inode->i_size;
	 
	if (!is_wb || is_truncate || !S_ISREG(inode->i_mode))
		i_size_write(inode, outarg.attr.size);

	if (is_truncate) {
		 
		__fuse_release_nowrite(inode);
	}
	spin_unlock(&fc->lock);

	if ((is_truncate || !is_wb) &&
	    S_ISREG(inode->i_mode) && oldsize != outarg.attr.size) {
		truncate_pagecache(inode, outarg.attr.size);
		invalidate_inode_pages2(inode->i_mapping);
	}

	clear_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
	return 0;

error:
	if (is_truncate)
		fuse_release_nowrite(inode);

	clear_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
	return err;
}

static int fuse_setattr(struct dentry *entry, struct iattr *attr)
{
	struct inode *inode = d_inode(entry);
	struct file *file = (attr->ia_valid & ATTR_FILE) ? attr->ia_file : NULL;
	int ret;

	if (!fuse_allow_current_process(get_fuse_conn(inode)))
		return -EACCES;

	if (attr->ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID)) {
		int kill;

		attr->ia_valid &= ~(ATTR_KILL_SUID | ATTR_KILL_SGID |
				    ATTR_MODE);
		 
		ret = fuse_do_getattr(inode, NULL, file);
		if (ret)
			return ret;

		attr->ia_mode = inode->i_mode;
		kill = should_remove_suid(entry);
		if (kill & ATTR_KILL_SUID) {
			attr->ia_valid |= ATTR_MODE;
			attr->ia_mode &= ~S_ISUID;
		}
		if (kill & ATTR_KILL_SGID) {
			attr->ia_valid |= ATTR_MODE;
			attr->ia_mode &= ~S_ISGID;
		}
	}
	if (!attr->ia_valid)
		return 0;

	ret = fuse_do_setattr(inode, attr, file);
	if (!ret) {
		 
		if (d_is_dir(entry) && (attr->ia_valid & ATTR_MODE))
			fuse_invalidate_entry_cache(entry);
	}
	return ret;
}

static int fuse_getattr(struct vfsmount *mnt, struct dentry *entry,
			struct kstat *stat)
{
	struct inode *inode = d_inode(entry);
	struct fuse_conn *fc = get_fuse_conn(inode);

	if (!fuse_allow_current_process(fc))
		return -EACCES;

	return fuse_update_attributes(inode, stat, NULL, NULL);
}

#ifdef MY_ABC_HERE
int fuse_setxattr(struct dentry *entry, const char *name,
			 const void *value, size_t size, int flags)
#else
static int fuse_setxattr(struct dentry *entry, const char *name,
			 const void *value, size_t size, int flags)
#endif  
{
	struct inode *inode = d_inode(entry);
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);
	struct fuse_setxattr_in inarg;
	int err;

	if (fc->no_setxattr)
		return -EOPNOTSUPP;

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	inarg.flags = flags;
	args.in.h.opcode = FUSE_SETXATTR;
	args.in.h.nodeid = get_node_id(inode);
	args.in.numargs = 3;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.in.args[1].size = strlen(name) + 1;
	args.in.args[1].value = name;
	args.in.args[2].size = size;
	args.in.args[2].value = value;
	err = fuse_simple_request(fc, &args);
	if (err == -ENOSYS) {
		fc->no_setxattr = 1;
		err = -EOPNOTSUPP;
	}
	if (!err) {
		fuse_invalidate_attr(inode);
		fuse_update_ctime(inode);
	}
	return err;
}

#ifdef MY_ABC_HERE
ssize_t fuse_getxattr(struct dentry *entry, const char *name,
			     void *value, size_t size)
#else
static ssize_t fuse_getxattr(struct dentry *entry, const char *name,
			     void *value, size_t size)
#endif  
{
	struct inode *inode = d_inode(entry);
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);
	struct fuse_getxattr_in inarg;
	struct fuse_getxattr_out outarg;
	ssize_t ret;

	if (fc->no_getxattr)
		return -EOPNOTSUPP;

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	args.in.h.opcode = FUSE_GETXATTR;
	args.in.h.nodeid = get_node_id(inode);
	args.in.numargs = 2;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.in.args[1].size = strlen(name) + 1;
	args.in.args[1].value = name;
	 
	args.out.numargs = 1;
	if (size) {
		args.out.argvar = 1;
		args.out.args[0].size = size;
		args.out.args[0].value = value;
	} else {
		args.out.args[0].size = sizeof(outarg);
		args.out.args[0].value = &outarg;
	}
	ret = fuse_simple_request(fc, &args);
	if (!ret && !size)
		ret = outarg.size;
	if (ret == -ENOSYS) {
		fc->no_getxattr = 1;
		ret = -EOPNOTSUPP;
	}
	return ret;
}

static int fuse_verify_xattr_list(char *list, size_t size)
{
	size_t origsize = size;

	while (size) {
		size_t thislen = strnlen(list, size);

		if (!thislen || thislen == size)
			return -EIO;

		size -= thislen + 1;
		list += thislen + 1;
	}

	return origsize;
}

static ssize_t fuse_listxattr(struct dentry *entry, char *list, size_t size)
{
	struct inode *inode = d_inode(entry);
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);
	struct fuse_getxattr_in inarg;
	struct fuse_getxattr_out outarg;
	ssize_t ret;

	if (!fuse_allow_current_process(fc))
		return -EACCES;

	if (fc->no_listxattr)
		return -EOPNOTSUPP;

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	args.in.h.opcode = FUSE_LISTXATTR;
	args.in.h.nodeid = get_node_id(inode);
	args.in.numargs = 1;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	 
	args.out.numargs = 1;
	if (size) {
		args.out.argvar = 1;
		args.out.args[0].size = size;
		args.out.args[0].value = list;
	} else {
		args.out.args[0].size = sizeof(outarg);
		args.out.args[0].value = &outarg;
	}
	ret = fuse_simple_request(fc, &args);
	if (!ret && !size)
		ret = outarg.size;
	if (ret > 0 && size)
		ret = fuse_verify_xattr_list(list, ret);
	if (ret == -ENOSYS) {
		fc->no_listxattr = 1;
		ret = -EOPNOTSUPP;
	}
	return ret;
}

static int fuse_removexattr(struct dentry *entry, const char *name)
{
	struct inode *inode = d_inode(entry);
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);
	int err;

	if (fc->no_removexattr)
		return -EOPNOTSUPP;

	args.in.h.opcode = FUSE_REMOVEXATTR;
	args.in.h.nodeid = get_node_id(inode);
	args.in.numargs = 1;
	args.in.args[0].size = strlen(name) + 1;
	args.in.args[0].value = name;
	err = fuse_simple_request(fc, &args);
	if (err == -ENOSYS) {
		fc->no_removexattr = 1;
		err = -EOPNOTSUPP;
	}
	if (!err) {
		fuse_invalidate_attr(inode);
		fuse_update_ctime(inode);
	}
	return err;
}

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
#define SZ_FS_NTFS	"ntfs"
#define IS_NTFS_FS(inode) (inode->i_sb->s_subtype && !strcmp(SZ_FS_NTFS, inode->i_sb->s_subtype))
#endif  
#ifdef MY_ABC_HERE
#define XATTR_NTFS_CREATE_TIME "ntfs_crtime"
#endif  
#ifdef MY_ABC_HERE
static int fuse_syno_glusterfs_getattr(struct dentry *dentry, struct kstat *stat, int stat_flag)
{
	int err = 0;
	struct inode *dir;
	struct fuse_entry_out outarg;
	struct fuse_synostat *synostat = NULL;
	struct inode *inode;
	struct qstr name;

	dir = dentry->d_parent->d_inode;

	if (stat_flag & (SYNOST_ALL | SYNOST_IS_CASELESS)) {
		synostat = kmalloc(FUSE_SYNOSTAT_SIZE, GFP_KERNEL);
		memset(synostat, 0, FUSE_SYNOSTAT_SIZE);
	}
	if (get_node_id(dentry->d_inode) == FUSE_ROOT_ID) {
		 
		name.name = ".";
		name.len = 1;
		err = fuse_lookup_name(dir->i_sb, get_node_id(dir), &name,
				       &outarg, &inode, synostat, stat_flag);
	} else {
		err = fuse_lookup_name(dir->i_sb, get_node_id(dir), &dentry->d_name,
				       &outarg, &inode, synostat, stat_flag);
	}
	if (err)
		goto out;

#ifdef MY_ABC_HERE
	if (stat_flag & SYNOST_ARCHIVE_BIT) {
		stat->syno_archive_bit = synostat->archive_bit;
	}
#endif  
#ifdef MY_ABC_HERE
	if (stat_flag & SYNOST_CREATE_TIME) {
		stat->syno_create_time.tv_sec = synostat->create_time_sec;
		stat->syno_create_time.tv_nsec = synostat->create_time_nsec;
	}
#endif  
#ifdef MY_ABC_HERE
	if (stat_flag & SYNOST_ARCHIVE_VER) {
		stat->syno_archive_version = synostat->archive_version;
	}
#endif  
out:
	kfree (synostat);
	iput(inode);
	return err;
}

static int fuse_syno_ntfs_getattr(struct dentry *dentry, struct kstat *stat, int stat_flag)
{
#ifdef MY_ABC_HERE
	int size = 0;
	sle64 time_le = 0;
	s64 time_s = 0;

	size = fuse_getxattr(dentry, XATTR_SYSTEM_PREFIX XATTR_NTFS_CREATE_TIME, &time_s, sizeof(time_s));
	if (size == sizeof(time_s)) {
		time_le = cpu_to_sle64(time_s);
		stat->syno_create_time = ntfs2utc(time_le);
	} else {
		memset(&stat->syno_create_time, 0, sizeof(stat->syno_create_time));
	}
#endif  
#ifdef MY_ABC_HERE
	stat->syno_archive_bit = dentry->d_inode->i_archive_bit;
#endif  
#ifdef MY_ABC_HERE
	stat->syno_archive_version = dentry->d_inode->i_archive_version;
#endif  
	return 0;
}

static int fuse_syno_getattr(struct dentry *dentry, struct kstat *stat, int stat_flag)
{
	if (!dentry->d_parent || !dentry->d_parent->d_inode) {
		printk(KERN_WARNING"fuse syno getattr null entry\n");
		return -EINVAL;
	}

	if (IS_GLUSTER_FS(dentry->d_inode)) {
		return fuse_syno_glusterfs_getattr(dentry, stat, stat_flag);
	} else if (IS_NTFS_FS(dentry->d_inode)) {
		return fuse_syno_ntfs_getattr(dentry, stat, stat_flag);
	}

#ifdef MY_ABC_HERE
	stat->syno_create_time = dentry->d_inode->i_create_time;
#endif  
#ifdef MY_ABC_HERE
	stat->syno_archive_bit = dentry->d_inode->i_archive_bit;
#endif  
#ifdef MY_ABC_HERE
	stat->syno_archive_version = dentry->d_inode->i_archive_version;
#endif  
	return 0;
}
#endif  

#ifdef MY_ABC_HERE
static int fuse_syno_set_archive_version(struct dentry *dentry, u32 archive_version)
{
	struct syno_xattr_archive_version value;

	value.v_magic = cpu_to_le16(0x2552);
	value.v_struct_version = cpu_to_le16(1);
	value.v_archive_version = cpu_to_le32(archive_version);

	return fuse_setxattr(dentry, XATTR_SYNO_PREFIX XATTR_SYNO_ARCHIVE_VERSION_GLUSTER, &value, sizeof(value), 0);
}
#endif  

#ifdef MY_ABC_HERE
static int fuse_syno_set_glusterfs_create_time(struct dentry *dentry, struct timespec* time)
{
	struct syno_gf_xattr_crtime time_le;

	time_le.sec = cpu_to_le64(time->tv_sec);
	time_le.nsec = cpu_to_le32(time->tv_nsec);

	return fuse_setxattr(dentry, XATTR_SYNO_PREFIX XATTR_SYNO_CREATE_TIME, &time_le, sizeof(time_le), 0);
}

static int fuse_syno_set_ntfs_create_time(struct dentry *dentry, struct timespec* time)
{
	sle64 time_le;
	s64 time_s;

	time_le = utc2ntfs(*time);
	time_s = sle64_to_cpu(time_le);

	return fuse_setxattr(dentry, XATTR_SYSTEM_PREFIX XATTR_NTFS_CREATE_TIME, &time_s, sizeof(time_s), 0);
}

static int fuse_syno_set_create_time(struct dentry *dentry, struct timespec* time)
{
	struct inode *inode = dentry->d_inode;

	if (IS_GLUSTER_FS(inode)) {
		return fuse_syno_set_glusterfs_create_time(dentry, time);
	} else if (IS_NTFS_FS(inode)) {
		return fuse_syno_set_ntfs_create_time(dentry, time);
	}
	return -EOPNOTSUPP;
}
#endif  

#ifdef MY_ABC_HERE
static int fuse_syno_get_archive_bit(struct dentry *entry, unsigned int *archive_bit)
{
	int err;
	struct inode *inode = entry->d_inode;
	struct kstat stat;

	if (!IS_GLUSTER_FS(inode)) {
		*archive_bit = inode->i_archive_bit;
		return 0;
	}

	memset (&stat, 0, sizeof(stat));
	err = fuse_syno_getattr(entry, &stat, SYNOST_ARCHIVE_BIT);
	if (err) {
		return err;
	}

	*archive_bit = stat.syno_archive_bit;
	return 0;
}

static int fuse_syno_set_archive_bit(struct dentry *dentry, unsigned int arbit)
{
	int err;
	struct inode *inode = dentry->d_inode;
	__le32 arbit_le32 = cpu_to_le32(arbit);

	if (!IS_GLUSTER_FS(inode)) {
		inode->i_archive_bit = arbit;
		inode->i_ctime = CURRENT_TIME;
		mark_inode_dirty_sync(inode);
		return 0;
	}

	err = fuse_setxattr(dentry, XATTR_SYNO_PREFIX XATTR_SYNO_ARCHIVE_BIT, &arbit_le32, sizeof(arbit_le32), 0);
	if (err) {
		return err;
	}

	inode->i_archive_bit = arbit;
	return 0;
}
#endif  

#ifdef MY_ABC_HERE
static int fuse_syno_acl_sys_get_perm(struct dentry *dentry, int *allow_out)
{
	__le32 allow_le32 = 0;
	int error;

	if (!IS_GLUSTER_FS(dentry->d_inode)) {
		return -EOPNOTSUPP;
	}

	error = fuse_getxattr(dentry, SYNO_ACL_XATTR_PERM, &allow_le32, sizeof(allow_le32));
	if (error >= 0) {
		error = 0;
		*allow_out = le32_to_cpu(allow_le32);
	}

	return error;
}

static int fuse_syno_acl_sys_is_support(struct dentry *dentry, int tag)
{
	struct inode *inode = dentry->d_inode;
	uint32_t archive_bit = 0;
	int error;

	if (!IS_GLUSTER_FS(inode)) {
		return -EOPNOTSUPP;
	}

	if (SYNO_KERNEL_IS_FS_SUPPORT == tag) {
		return 1;
	} else if (SYNO_KERNEL_IS_FILE_SUPPORT == tag) {
		error = inode->i_op->syno_get_archive_bit(dentry, &archive_bit);
		if (0 == error) {
			return !!(archive_bit & S2_SYNO_ACL_SUPPORT);
		}
	} else {
		return 0;
	}
	return error;
}

static int fuse_syno_acl_sys_check_perm(struct dentry *dentry, int mask)
{
	if (!IS_GLUSTER_FS(dentry->d_inode)) {
		return -EOPNOTSUPP;
	}
	return fuse_access(dentry->d_inode, mask, 1);
}

static int fuse_syno_acl_xattr_get(struct dentry *dentry, int cmd, void *value, size_t size)
{
	if (IS_GLUSTER_FS(dentry->d_inode)) {
		if (SYNO_ACL_INHERITED == cmd)
			return fuse_getxattr(dentry, SYNO_ACL_XATTR_INHERIT, value, size);
		else if (SYNO_ACL_PSEUDO_INHERIT_ONLY == cmd)
			return fuse_getxattr(dentry, SYNO_ACL_XATTR_PSEUDO_INHERIT_ONLY, value, size);
		else
			return -EOPNOTSUPP;
	}
	return synoacl_mod_get_acl_xattr(dentry, cmd, value, size);
}

static int fuse_syno_bypass_is_synoacl(struct dentry *dentry, int cmd, int reterror)
{
	if (IS_GLUSTER_FS(dentry->d_inode)) {
		return 0;
	}
	if (cmd == BYPASS_SYNOACL_SYNOARCHIVE_OVERWRITE) {
		if (inode_owner_or_capable(dentry->d_inode)) {
			return 0;
		}
	}
	return reterror;
}

static int fuse_syno_archive_bit_change_ok(struct dentry *dentry, unsigned int cmd, int tag, int mask)
{
	if (IS_GLUSTER_FS(dentry->d_inode)) {
		return 0;
	}

	if ((NEED_INODE_ACL_SUPPORT | NEED_FS_ACL_SUPPORT) & tag) {
		return -EOPNOTSUPP;
	}

	return 0;
}
#endif  

static const struct inode_operations fuse_dir_inode_operations = {
	.lookup		= fuse_lookup,
	.mkdir		= fuse_mkdir,
	.symlink	= fuse_symlink,
	.unlink		= fuse_unlink,
	.rmdir		= fuse_rmdir,
	.rename2	= fuse_rename2,
	.link		= fuse_link,
	.setattr	= fuse_setattr,
	.create		= fuse_create,
	.atomic_open	= fuse_atomic_open,
	.mknod		= fuse_mknod,
	.permission	= fuse_permission,
	.getattr	= fuse_getattr,
	.setxattr	= fuse_setxattr,
	.getxattr	= fuse_getxattr,
	.listxattr	= fuse_listxattr,
	.removexattr	= fuse_removexattr,
#ifdef MY_ABC_HERE
	.syno_getattr	= fuse_syno_getattr,
#endif  
#ifdef MY_ABC_HERE
	 
	.syno_set_archive_ver	= fuse_syno_set_archive_version,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_crtime	= fuse_syno_set_create_time,
#endif  
#ifdef MY_ABC_HERE
	.syno_get_archive_bit	= fuse_syno_get_archive_bit,
	.syno_set_archive_bit	= fuse_syno_set_archive_bit,
#endif  
#ifdef MY_ABC_HERE
	.syno_acl_sys_get_perm	= fuse_syno_acl_sys_get_perm,
	.syno_acl_sys_is_support	= fuse_syno_acl_sys_is_support,
	.syno_acl_sys_check_perm	= fuse_syno_acl_sys_check_perm,
	.syno_acl_xattr_get	= fuse_syno_acl_xattr_get,
	.syno_bypass_is_synoacl = fuse_syno_bypass_is_synoacl,
	.syno_arbit_chg_ok = fuse_syno_archive_bit_change_ok,
#endif  
};

static const struct file_operations fuse_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate	= fuse_readdir,
	.open		= fuse_dir_open,
	.release	= fuse_dir_release,
	.fsync		= fuse_dir_fsync,
	.unlocked_ioctl	= fuse_dir_ioctl,
	.compat_ioctl	= fuse_dir_compat_ioctl,
};

static const struct inode_operations fuse_common_inode_operations = {
	.setattr	= fuse_setattr,
	.permission	= fuse_permission,
	.getattr	= fuse_getattr,
	.setxattr	= fuse_setxattr,
	.getxattr	= fuse_getxattr,
	.listxattr	= fuse_listxattr,
	.removexattr	= fuse_removexattr,
#ifdef MY_ABC_HERE
	.syno_getattr	= fuse_syno_getattr,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_archive_ver	= fuse_syno_set_archive_version,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_crtime	= fuse_syno_set_create_time,
#endif  
#ifdef MY_ABC_HERE
	.syno_get_archive_bit	= fuse_syno_get_archive_bit,
	.syno_set_archive_bit	= fuse_syno_set_archive_bit,
#endif  
#ifdef MY_ABC_HERE
	.syno_acl_sys_get_perm	= fuse_syno_acl_sys_get_perm,
	.syno_acl_sys_is_support	= fuse_syno_acl_sys_is_support,
	.syno_acl_sys_check_perm	= fuse_syno_acl_sys_check_perm,
	.syno_acl_xattr_get	= fuse_syno_acl_xattr_get,
	.syno_bypass_is_synoacl = fuse_syno_bypass_is_synoacl,
	.syno_arbit_chg_ok = fuse_syno_archive_bit_change_ok,
#endif  
};

static const struct inode_operations fuse_symlink_inode_operations = {
	.setattr	= fuse_setattr,
	.follow_link	= fuse_follow_link,
	.put_link	= free_page_put_link,
	.readlink	= generic_readlink,
	.getattr	= fuse_getattr,
	.setxattr	= fuse_setxattr,
	.getxattr	= fuse_getxattr,
	.listxattr	= fuse_listxattr,
	.removexattr	= fuse_removexattr,
#ifdef MY_ABC_HERE
	.syno_getattr	= fuse_syno_getattr,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_archive_ver	= fuse_syno_set_archive_version,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_crtime	= fuse_syno_set_create_time,
#endif  
#ifdef MY_ABC_HERE
	.syno_get_archive_bit	= fuse_syno_get_archive_bit,
	.syno_set_archive_bit	= fuse_syno_set_archive_bit,
#endif  
#ifdef MY_ABC_HERE
	.syno_acl_sys_get_perm	= fuse_syno_acl_sys_get_perm,
	.syno_acl_sys_is_support	= fuse_syno_acl_sys_is_support,
	.syno_acl_sys_check_perm	= fuse_syno_acl_sys_check_perm,
	.syno_acl_xattr_get	= fuse_syno_acl_xattr_get,
	.syno_bypass_is_synoacl = fuse_syno_bypass_is_synoacl,
	.syno_arbit_chg_ok = fuse_syno_archive_bit_change_ok,
#endif  
};

void fuse_init_common(struct inode *inode)
{
	inode->i_op = &fuse_common_inode_operations;
}

void fuse_init_dir(struct inode *inode)
{
	inode->i_op = &fuse_dir_inode_operations;
	inode->i_fop = &fuse_dir_operations;
}

void fuse_init_symlink(struct inode *inode)
{
	inode->i_op = &fuse_symlink_inode_operations;
}
