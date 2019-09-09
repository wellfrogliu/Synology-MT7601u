#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/slab.h>
#include "ulist.h"
#include "ctree.h"

void ulist_init(struct ulist *ulist)
{
	INIT_LIST_HEAD(&ulist->nodes);
	ulist->root = RB_ROOT;
	ulist->nnodes = 0;
}

static void ulist_fini(struct ulist *ulist)
{
	struct ulist_node *node;
	struct ulist_node *next;

	list_for_each_entry_safe(node, next, &ulist->nodes, list) {
		kfree(node);
	}
	ulist->root = RB_ROOT;
	INIT_LIST_HEAD(&ulist->nodes);
}

void ulist_reinit(struct ulist *ulist)
{
	ulist_fini(ulist);
	ulist_init(ulist);
}

struct ulist *ulist_alloc(gfp_t gfp_mask)
{
	struct ulist *ulist = kmalloc(sizeof(*ulist), gfp_mask);

	if (!ulist)
		return NULL;

	ulist_init(ulist);

	return ulist;
}

void ulist_free(struct ulist *ulist)
{
	if (!ulist)
		return;
	ulist_fini(ulist);
	kfree(ulist);
}

static struct ulist_node *ulist_rbtree_search(struct ulist *ulist, u64 val)
{
	struct rb_node *n = ulist->root.rb_node;
	struct ulist_node *u = NULL;

	while (n) {
		u = rb_entry(n, struct ulist_node, rb_node);
		if (u->val < val)
			n = n->rb_right;
		else if (u->val > val)
			n = n->rb_left;
		else
			return u;
	}
	return NULL;
}

static void ulist_rbtree_erase(struct ulist *ulist, struct ulist_node *node)
{
	rb_erase(&node->rb_node, &ulist->root);
	list_del(&node->list);
	kfree(node);
	BUG_ON(ulist->nnodes == 0);
	ulist->nnodes--;
}

static int ulist_rbtree_insert(struct ulist *ulist, struct ulist_node *ins)
{
	struct rb_node **p = &ulist->root.rb_node;
	struct rb_node *parent = NULL;
	struct ulist_node *cur = NULL;

	while (*p) {
		parent = *p;
		cur = rb_entry(parent, struct ulist_node, rb_node);

		if (cur->val < ins->val)
			p = &(*p)->rb_right;
		else if (cur->val > ins->val)
			p = &(*p)->rb_left;
		else
			return -EEXIST;
	}
	rb_link_node(&ins->rb_node, parent, p);
	rb_insert_color(&ins->rb_node, &ulist->root);
	return 0;
}

int ulist_add(struct ulist *ulist, u64 val, u64 aux, gfp_t gfp_mask)
{
	return ulist_add_merge(ulist, val, aux, NULL, gfp_mask);
}

int ulist_add_merge(struct ulist *ulist, u64 val, u64 aux,
		    u64 *old_aux, gfp_t gfp_mask)
{
	int ret;
	struct ulist_node *node;

	node = ulist_rbtree_search(ulist, val);
	if (node) {
		if (old_aux)
			*old_aux = node->aux;
		return 0;
	}
	node = kmalloc(sizeof(*node), gfp_mask);
	if (!node)
		return -ENOMEM;

	node->val = val;
	node->aux = aux;

	ret = ulist_rbtree_insert(ulist, node);
	ASSERT(!ret);
	list_add_tail(&node->list, &ulist->nodes);
	ulist->nnodes++;

	return 1;
}

int ulist_del(struct ulist *ulist, u64 val, u64 aux)
{
	struct ulist_node *node;

	node = ulist_rbtree_search(ulist, val);
	 
	if (!node)
		return 1;

	if (node->aux != aux)
		return 1;

	ulist_rbtree_erase(ulist, node);
	return 0;
}

struct ulist_node *ulist_next(struct ulist *ulist, struct ulist_iterator *uiter)
{
	struct ulist_node *node;

	if (list_empty(&ulist->nodes))
		return NULL;
	if (uiter->cur_list && uiter->cur_list->next == &ulist->nodes)
		return NULL;
	if (uiter->cur_list) {
		uiter->cur_list = uiter->cur_list->next;
	} else {
		uiter->cur_list = ulist->nodes.next;
	}
	node = list_entry(uiter->cur_list, struct ulist_node, list);
	return node;
}

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
int ulist_add_lru_adjust(struct ulist *ulist, u64 val, u64 aux, gfp_t gfp_mask)
{
	int ret;
	struct ulist_node *node;

	node = ulist_rbtree_search(ulist, val);
	if (node) {
		list_del(&node->list);
		list_add_tail(&node->list, &ulist->nodes);
		return 0;
	}
	node = kmalloc(sizeof(*node), gfp_mask);
	if (!node)
		return -ENOMEM;

	node->val = val;
	node->aux = aux;
#ifdef CONFIG_BTRFS_DEBUG
	node->seqnum = ulist->nnodes;
#endif

	ret = ulist_rbtree_insert(ulist, node);
	ASSERT(!ret);
	list_add_tail(&node->list, &ulist->nodes);
	ulist->nnodes++;

	return 1;
}

void ulist_remove_first(struct ulist *ulist)
{
	struct ulist_node *node;

	if (!ulist->nnodes)
		return;

	node = list_entry(ulist->nodes.next, struct ulist_node, list);
	rb_erase(&node->rb_node, &ulist->root);
	list_del(&node->list);
	ulist->nnodes--;
	kfree(node);
}
#endif  

#if defined(MY_ABC_HERE) || \
    defined(MY_ABC_HERE)
struct ulist_node * ulist_search(struct ulist *ulist, u64 val)
{
	struct rb_node *n = ulist->root.rb_node;
	struct ulist_node *u = NULL;

	while (n) {
		u = rb_entry(n, struct ulist_node, rb_node);
		if (u->val < val)
			n = n->rb_right;
		else if (u->val > val)
			n = n->rb_left;
		else
			return u;
	}
	return NULL;
}
#endif  
