#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#ifndef __EXTENTMAP__
#define __EXTENTMAP__

#include <linux/rbtree.h>

#define EXTENT_MAP_LAST_BYTE ((u64)-4)
#define EXTENT_MAP_HOLE ((u64)-3)
#define EXTENT_MAP_INLINE ((u64)-2)
#define EXTENT_MAP_DELALLOC ((u64)-1)

#define EXTENT_FLAG_PINNED 0  
#define EXTENT_FLAG_COMPRESSED 1
#define EXTENT_FLAG_VACANCY 2  
#define EXTENT_FLAG_PREALLOC 3  
#define EXTENT_FLAG_LOGGING 4  
#define EXTENT_FLAG_FILLING 5  
#define EXTENT_FLAG_FS_MAPPING 6  

struct extent_map {
	struct rb_node rb_node;

	u64 start;
	u64 len;
	u64 mod_start;
	u64 mod_len;
	u64 orig_start;
	u64 orig_block_len;
	u64 ram_bytes;
	u64 block_start;
	u64 block_len;
	u64 generation;
	unsigned long flags;
	union {
		struct block_device *bdev;

		struct map_lookup *map_lookup;
	};
	atomic_t refs;
	unsigned int compress_type;
	struct list_head list;
#ifdef MY_ABC_HERE
	struct list_head free_list;
#endif  
};

#ifdef MY_ABC_HERE
struct btrfs_inode;
#endif  
struct extent_map_tree {
	struct rb_root map;
	struct list_head modified_extents;
	rwlock_t lock;
#ifdef MY_ABC_HERE
	struct list_head not_modified_extents;
	struct list_head syno_modified_extents;
	atomic_t nr_extent_maps;
	struct btrfs_inode *inode;
#endif  
};

static inline int extent_map_in_tree(const struct extent_map *em)
{
	return !RB_EMPTY_NODE(&em->rb_node);
}

static inline u64 extent_map_end(struct extent_map *em)
{
	if (em->start + em->len < em->start)
		return (u64)-1;
	return em->start + em->len;
}

static inline u64 extent_map_block_end(struct extent_map *em)
{
	if (em->block_start + em->block_len < em->block_start)
		return (u64)-1;
	return em->block_start + em->block_len;
}

void extent_map_tree_init(struct extent_map_tree *tree);
struct extent_map *lookup_extent_mapping(struct extent_map_tree *tree,
					 u64 start, u64 len);
int add_extent_mapping(struct extent_map_tree *tree,
		       struct extent_map *em, int modified);
int remove_extent_mapping(struct extent_map_tree *tree, struct extent_map *em);
void replace_extent_mapping(struct extent_map_tree *tree,
			    struct extent_map *cur,
			    struct extent_map *new,
			    int modified);

struct extent_map *alloc_extent_map(void);
void free_extent_map(struct extent_map *em);
int __init extent_map_init(void);
void extent_map_exit(void);
int unpin_extent_cache(struct extent_map_tree *tree, u64 start, u64 len, u64 gen);
void clear_em_logging(struct extent_map_tree *tree, struct extent_map *em);
struct extent_map *search_extent_mapping(struct extent_map_tree *tree,
					 u64 start, u64 len);
#endif
