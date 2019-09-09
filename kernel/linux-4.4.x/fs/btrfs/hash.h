 
#ifndef __HASH__
#define __HASH__

int __init btrfs_hash_init(void);

void btrfs_hash_exit(void);
const char* btrfs_crc32c_impl(void);

u32 btrfs_crc32c(u32 crc, const void *address, unsigned int length);

static inline u64 btrfs_name_hash(const char *name, int len)
{
	return btrfs_crc32c((u32)~1, name, len);
}

static inline u64 btrfs_extref_hash(u64 parent_objectid, const char *name,
				    int len)
{
	return (u64) btrfs_crc32c(parent_objectid, name, len);
}

#endif
