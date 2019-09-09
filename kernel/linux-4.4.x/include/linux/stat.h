#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#ifndef _LINUX_STAT_H
#define _LINUX_STAT_H

#include <asm/stat.h>
#include <uapi/linux/stat.h>

#define S_IRWXUGO	(S_IRWXU|S_IRWXG|S_IRWXO)
#define S_IALLUGO	(S_ISUID|S_ISGID|S_ISVTX|S_IRWXUGO)
#define S_IRUGO		(S_IRUSR|S_IRGRP|S_IROTH)
#define S_IWUGO		(S_IWUSR|S_IWGRP|S_IWOTH)
#define S_IXUGO		(S_IXUSR|S_IXGRP|S_IXOTH)

#define UTIME_NOW	((1l << 30) - 1l)
#define UTIME_OMIT	((1l << 30) - 2l)

#include <linux/types.h>
#include <linux/time.h>
#include <linux/uidgid.h>

struct kstat {
	u64		ino;
	dev_t		dev;
	umode_t		mode;
#ifdef MY_ABC_HERE
	__u32		syno_archive_bit;
#endif  
#ifdef MY_ABC_HERE
	__u32		syno_archive_version;
#endif  
	unsigned int	nlink;
	kuid_t		uid;
	kgid_t		gid;
	dev_t		rdev;
	loff_t		size;
	struct timespec  atime;
	struct timespec	mtime;
	struct timespec	ctime;
#ifdef MY_ABC_HERE
	struct timespec syno_create_time;
#endif  
	unsigned long	blksize;
	unsigned long long	blocks;
};

#ifdef MY_ABC_HERE
struct SYNOSTAT_EXTRA {
	struct timespec create_time;
	unsigned int archive_version;
	unsigned int archive_bit;
};
struct SYNOSTAT {
	struct stat st;
	struct SYNOSTAT_EXTRA ext;
};

#ifdef MY_ABC_HERE
 
#define SYNOST_STAT         0x00000001   
#define SYNOST_ARCHIVE_BIT  0x00000002   
#define SYNOST_ARCHIVE_VER  0x00000004   
#define SYNOST_CREATE_TIME  0x00000008   

#define SYNOST_ALL          SYNOST_STAT|SYNOST_ARCHIVE_BIT|SYNOST_ARCHIVE_VER|SYNOST_CREATE_TIME
#define SYNOST_IS_CASELESS      0x10000000       

#endif  
#endif  

#endif
