#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef __ULIST__
#define __ULIST__

#include <linux/list.h>
#include <linux/rbtree.h>

struct ulist_iterator {
#ifdef CONFIG_BTRFS_DEBUG
	int i;
#endif
	struct list_head *cur_list;   
};

struct ulist_node {
	u64 val;		 
	u64 aux;		 

#ifdef CONFIG_BTRFS_DEBUG
	int seqnum;		 
#endif

	struct list_head list;   
	struct rb_node rb_node;	 
};

struct ulist {
	 
	unsigned long nnodes;

	struct list_head nodes;
	struct rb_root root;
};

void ulist_init(struct ulist *ulist);
void ulist_reinit(struct ulist *ulist);
struct ulist *ulist_alloc(gfp_t gfp_mask);
void ulist_free(struct ulist *ulist);
int ulist_add(struct ulist *ulist, u64 val, u64 aux, gfp_t gfp_mask);
int ulist_add_merge(struct ulist *ulist, u64 val, u64 aux,
		    u64 *old_aux, gfp_t gfp_mask);
int ulist_del(struct ulist *ulist, u64 val, u64 aux);

static inline int ulist_add_merge_ptr(struct ulist *ulist, u64 val, void *aux,
				      void **old_aux, gfp_t gfp_mask)
{
#if BITS_PER_LONG == 32
	u64 old64 = (uintptr_t)*old_aux;
	int ret = ulist_add_merge(ulist, val, (uintptr_t)aux, &old64, gfp_mask);
	*old_aux = (void *)((uintptr_t)old64);
	return ret;
#else
	return ulist_add_merge(ulist, val, (u64)aux, (u64 *)old_aux, gfp_mask);
#endif
}

struct ulist_node *ulist_next(struct ulist *ulist,
			      struct ulist_iterator *uiter);

#define ULIST_ITER_INIT(uiter) ((uiter)->cur_list = NULL)

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
#define ULIST_NODES_MAX 65536  
int ulist_add_lru_adjust(struct ulist *ulist, u64 val, u64 aux, gfp_t gfp_mask);
void ulist_remove_first(struct ulist *ulist);
#endif  
#if defined(MY_ABC_HERE) || \
    defined(MY_ABC_HERE)
struct ulist_node * ulist_search(struct ulist *ulist, u64 val);
#endif  

#endif
