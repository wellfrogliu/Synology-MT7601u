#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef TEST                         
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/export.h>
#endif
#include <linux/err.h>
#include <linux/string.h>
#include <linux/idr.h>
#include <linux/spinlock.h>
#include <linux/percpu.h>

#define MAX_IDR_SHIFT		(sizeof(int) * 8 - 1)
#define MAX_IDR_BIT		(1U << MAX_IDR_SHIFT)

#define MAX_IDR_LEVEL ((MAX_IDR_SHIFT + IDR_BITS - 1) / IDR_BITS)

#define MAX_IDR_FREE (MAX_IDR_LEVEL * 2)

static struct kmem_cache *idr_layer_cache;
static DEFINE_PER_CPU(struct idr_layer *, idr_preload_head);
static DEFINE_PER_CPU(int, idr_preload_cnt);
static DEFINE_SPINLOCK(simple_ida_lock);

static int idr_max(int layers)
{
	int bits = min_t(int, layers * IDR_BITS, MAX_IDR_SHIFT);

	return (1 << bits) - 1;
}

static int idr_layer_prefix_mask(int layer)
{
	return ~idr_max(layer + 1);
}

static struct idr_layer *get_from_free_list(struct idr *idp)
{
	struct idr_layer *p;
	unsigned long flags;

	spin_lock_irqsave(&idp->lock, flags);
	if ((p = idp->id_free)) {
		idp->id_free = p->ary[0];
		idp->id_free_cnt--;
		p->ary[0] = NULL;
	}
	spin_unlock_irqrestore(&idp->lock, flags);
	return(p);
}

static struct idr_layer *idr_layer_alloc(gfp_t gfp_mask, struct idr *layer_idr)
{
	struct idr_layer *new;

	if (layer_idr)
		return get_from_free_list(layer_idr);

	new = kmem_cache_zalloc(idr_layer_cache, gfp_mask | __GFP_NOWARN);
	if (new)
		return new;

	if (!in_interrupt()) {
		preempt_disable();
		new = __this_cpu_read(idr_preload_head);
		if (new) {
			__this_cpu_write(idr_preload_head, new->ary[0]);
			__this_cpu_dec(idr_preload_cnt);
			new->ary[0] = NULL;
		}
		preempt_enable();
		if (new)
			return new;
	}

	return kmem_cache_zalloc(idr_layer_cache, gfp_mask);
}

static void idr_layer_rcu_free(struct rcu_head *head)
{
	struct idr_layer *layer;

	layer = container_of(head, struct idr_layer, rcu_head);
	kmem_cache_free(idr_layer_cache, layer);
}

static inline void free_layer(struct idr *idr, struct idr_layer *p)
{
	if (idr->hint == p)
		RCU_INIT_POINTER(idr->hint, NULL);
	call_rcu(&p->rcu_head, idr_layer_rcu_free);
}

static void __move_to_free_list(struct idr *idp, struct idr_layer *p)
{
	p->ary[0] = idp->id_free;
	idp->id_free = p;
	idp->id_free_cnt++;
}

static void move_to_free_list(struct idr *idp, struct idr_layer *p)
{
	unsigned long flags;

	spin_lock_irqsave(&idp->lock, flags);
	__move_to_free_list(idp, p);
	spin_unlock_irqrestore(&idp->lock, flags);
}

static void idr_mark_full(struct idr_layer **pa, int id)
{
	struct idr_layer *p = pa[0];
	int l = 0;

	__set_bit(id & IDR_MASK, p->bitmap);
	 
	while (bitmap_full(p->bitmap, IDR_SIZE)) {
		if (!(p = pa[++l]))
			break;
		id = id >> IDR_BITS;
		__set_bit((id & IDR_MASK), p->bitmap);
	}
}

static int __idr_pre_get(struct idr *idp, gfp_t gfp_mask)
{
	while (idp->id_free_cnt < MAX_IDR_FREE) {
		struct idr_layer *new;
		new = kmem_cache_zalloc(idr_layer_cache, gfp_mask);
		if (new == NULL)
			return (0);
		move_to_free_list(idp, new);
	}
	return 1;
}

static int sub_alloc(struct idr *idp, int *starting_id, struct idr_layer **pa,
		     gfp_t gfp_mask, struct idr *layer_idr)
{
	int n, m, sh;
	struct idr_layer *p, *new;
	int l, id, oid;

	id = *starting_id;
 restart:
	p = idp->top;
	l = idp->layers;
	pa[l--] = NULL;
	while (1) {
		 
		n = (id >> (IDR_BITS*l)) & IDR_MASK;
		m = find_next_zero_bit(p->bitmap, IDR_SIZE, n);
		if (m == IDR_SIZE) {
			 
			l++;
			oid = id;
			id = (id | ((1 << (IDR_BITS * l)) - 1)) + 1;

			if (id > idr_max(idp->layers)) {
				*starting_id = id;
				return -EAGAIN;
			}
			p = pa[l];
			BUG_ON(!p);

			sh = IDR_BITS * (l + 1);
			if (oid >> sh == id >> sh)
				continue;
			else
				goto restart;
		}
		if (m != n) {
			sh = IDR_BITS*l;
			id = ((id >> sh) ^ n ^ m) << sh;
		}
		if ((id >= MAX_IDR_BIT) || (id < 0))
			return -ENOSPC;
		if (l == 0)
			break;
		 
		if (!p->ary[m]) {
			new = idr_layer_alloc(gfp_mask, layer_idr);
			if (!new)
				return -ENOMEM;
			new->layer = l-1;
			new->prefix = id & idr_layer_prefix_mask(new->layer);
			rcu_assign_pointer(p->ary[m], new);
			p->count++;
		}
		pa[l--] = p;
		p = p->ary[m];
	}

	pa[l] = p;
	return id;
}

static int idr_get_empty_slot(struct idr *idp, int starting_id,
			      struct idr_layer **pa, gfp_t gfp_mask,
			      struct idr *layer_idr)
{
	struct idr_layer *p, *new;
	int layers, v, id;
	unsigned long flags;

	id = starting_id;
build_up:
	p = idp->top;
	layers = idp->layers;
	if (unlikely(!p)) {
		if (!(p = idr_layer_alloc(gfp_mask, layer_idr)))
			return -ENOMEM;
		p->layer = 0;
		layers = 1;
	}
	 
	while (id > idr_max(layers)) {
		layers++;
		if (!p->count) {
			 
			p->layer++;
			WARN_ON_ONCE(p->prefix);
			continue;
		}
		if (!(new = idr_layer_alloc(gfp_mask, layer_idr))) {
			 
			spin_lock_irqsave(&idp->lock, flags);
			for (new = p; p && p != idp->top; new = p) {
				p = p->ary[0];
				new->ary[0] = NULL;
				new->count = 0;
				bitmap_clear(new->bitmap, 0, IDR_SIZE);
				__move_to_free_list(idp, new);
			}
			spin_unlock_irqrestore(&idp->lock, flags);
			return -ENOMEM;
		}
		new->ary[0] = p;
		new->count = 1;
		new->layer = layers-1;
		new->prefix = id & idr_layer_prefix_mask(new->layer);
		if (bitmap_full(p->bitmap, IDR_SIZE))
			__set_bit(0, new->bitmap);
		p = new;
	}
	rcu_assign_pointer(idp->top, p);
	idp->layers = layers;
	v = sub_alloc(idp, &id, pa, gfp_mask, layer_idr);
	if (v == -EAGAIN)
		goto build_up;
	return(v);
}

static void idr_fill_slot(struct idr *idr, void *ptr, int id,
			  struct idr_layer **pa)
{
	 
	rcu_assign_pointer(idr->hint, pa[0]);

	rcu_assign_pointer(pa[0]->ary[id & IDR_MASK], (struct idr_layer *)ptr);
	pa[0]->count++;
	idr_mark_full(pa, id);
}

void idr_preload(gfp_t gfp_mask)
{
	 
	WARN_ON_ONCE(in_interrupt());
	might_sleep_if(gfpflags_allow_blocking(gfp_mask));

	preempt_disable();

	while (__this_cpu_read(idr_preload_cnt) < MAX_IDR_FREE) {
		struct idr_layer *new;

		preempt_enable();
		new = kmem_cache_zalloc(idr_layer_cache, gfp_mask);
		preempt_disable();
		if (!new)
			break;

		new->ary[0] = __this_cpu_read(idr_preload_head);
		__this_cpu_write(idr_preload_head, new);
		__this_cpu_inc(idr_preload_cnt);
	}
}
EXPORT_SYMBOL(idr_preload);

int idr_alloc(struct idr *idr, void *ptr, int start, int end, gfp_t gfp_mask)
{
	int max = end > 0 ? end - 1 : INT_MAX;	 
	struct idr_layer *pa[MAX_IDR_LEVEL + 1];
	int id;

	might_sleep_if(gfpflags_allow_blocking(gfp_mask));

	if (WARN_ON_ONCE(start < 0))
		return -EINVAL;
	if (unlikely(max < start))
		return -ENOSPC;

	id = idr_get_empty_slot(idr, start, pa, gfp_mask, NULL);
	if (unlikely(id < 0))
		return id;
	if (unlikely(id > max))
		return -ENOSPC;

	idr_fill_slot(idr, ptr, id, pa);
	return id;
}
EXPORT_SYMBOL_GPL(idr_alloc);

int idr_alloc_cyclic(struct idr *idr, void *ptr, int start, int end,
			gfp_t gfp_mask)
{
	int id;

	id = idr_alloc(idr, ptr, max(start, idr->cur), end, gfp_mask);
	if (id == -ENOSPC)
		id = idr_alloc(idr, ptr, start, end, gfp_mask);

	if (likely(id >= 0))
		idr->cur = id + 1;
	return id;
}
EXPORT_SYMBOL(idr_alloc_cyclic);

static void idr_remove_warning(int id)
{
	WARN(1, "idr_remove called for id=%d which is not allocated.\n", id);
}

static void sub_remove(struct idr *idp, int shift, int id)
{
	struct idr_layer *p = idp->top;
	struct idr_layer **pa[MAX_IDR_LEVEL + 1];
	struct idr_layer ***paa = &pa[0];
	struct idr_layer *to_free;
	int n;

	*paa = NULL;
	*++paa = &idp->top;

	while ((shift > 0) && p) {
		n = (id >> shift) & IDR_MASK;
		__clear_bit(n, p->bitmap);
		*++paa = &p->ary[n];
		p = p->ary[n];
		shift -= IDR_BITS;
	}
	n = id & IDR_MASK;
	if (likely(p != NULL && test_bit(n, p->bitmap))) {
		__clear_bit(n, p->bitmap);
		RCU_INIT_POINTER(p->ary[n], NULL);
		to_free = NULL;
		while(*paa && ! --((**paa)->count)){
			if (to_free)
				free_layer(idp, to_free);
			to_free = **paa;
			**paa-- = NULL;
		}
		if (!*paa)
			idp->layers = 0;
		if (to_free)
			free_layer(idp, to_free);
	} else
		idr_remove_warning(id);
}

void idr_remove(struct idr *idp, int id)
{
	struct idr_layer *p;
	struct idr_layer *to_free;

	if (id < 0)
		return;

	if (id > idr_max(idp->layers)) {
		idr_remove_warning(id);
		return;
	}

	sub_remove(idp, (idp->layers - 1) * IDR_BITS, id);
	if (idp->top && idp->top->count == 1 && (idp->layers > 1) &&
	    idp->top->ary[0]) {
		 
		to_free = idp->top;
		p = idp->top->ary[0];
		rcu_assign_pointer(idp->top, p);
		--idp->layers;
		to_free->count = 0;
		bitmap_clear(to_free->bitmap, 0, IDR_SIZE);
		free_layer(idp, to_free);
	}
}
EXPORT_SYMBOL(idr_remove);

static void __idr_remove_all(struct idr *idp)
{
	int n, id, max;
	int bt_mask;
	struct idr_layer *p;
	struct idr_layer *pa[MAX_IDR_LEVEL + 1];
	struct idr_layer **paa = &pa[0];

	n = idp->layers * IDR_BITS;
	*paa = idp->top;
	RCU_INIT_POINTER(idp->top, NULL);
	max = idr_max(idp->layers);

	id = 0;
	while (id >= 0 && id <= max) {
		p = *paa;
		while (n > IDR_BITS && p) {
			n -= IDR_BITS;
			p = p->ary[(id >> n) & IDR_MASK];
			*++paa = p;
		}

		bt_mask = id;
		id += 1 << n;
		 
		while (n < fls(id ^ bt_mask)) {
			if (*paa)
				free_layer(idp, *paa);
			n += IDR_BITS;
			--paa;
		}
	}
	idp->layers = 0;
}

void idr_destroy(struct idr *idp)
{
	__idr_remove_all(idp);

	while (idp->id_free_cnt) {
		struct idr_layer *p = get_from_free_list(idp);
		kmem_cache_free(idr_layer_cache, p);
	}
}
EXPORT_SYMBOL(idr_destroy);

void *idr_find_slowpath(struct idr *idp, int id)
{
	int n;
	struct idr_layer *p;

	if (id < 0)
		return NULL;

	p = rcu_dereference_raw(idp->top);
	if (!p)
		return NULL;
	n = (p->layer+1) * IDR_BITS;

	if (id > idr_max(p->layer + 1))
		return NULL;
	BUG_ON(n == 0);

	while (n > 0 && p) {
		n -= IDR_BITS;
		BUG_ON(n != p->layer*IDR_BITS);
		p = rcu_dereference_raw(p->ary[(id >> n) & IDR_MASK]);
	}
	return((void *)p);
}
EXPORT_SYMBOL(idr_find_slowpath);

int idr_for_each(struct idr *idp,
		 int (*fn)(int id, void *p, void *data), void *data)
{
	int n, id, max, error = 0;
	struct idr_layer *p;
	struct idr_layer *pa[MAX_IDR_LEVEL + 1];
	struct idr_layer **paa = &pa[0];

	n = idp->layers * IDR_BITS;
	*paa = rcu_dereference_raw(idp->top);
	max = idr_max(idp->layers);

	id = 0;
	while (id >= 0 && id <= max) {
		p = *paa;
		while (n > 0 && p) {
			n -= IDR_BITS;
			p = rcu_dereference_raw(p->ary[(id >> n) & IDR_MASK]);
			*++paa = p;
		}

		if (p) {
			error = fn(id, (void *)p, data);
			if (error)
				break;
		}

		id += 1 << n;
		while (n < fls(id)) {
			n += IDR_BITS;
			--paa;
		}
	}

	return error;
}
EXPORT_SYMBOL(idr_for_each);

void *idr_get_next(struct idr *idp, int *nextidp)
{
	struct idr_layer *p, *pa[MAX_IDR_LEVEL + 1];
	struct idr_layer **paa = &pa[0];
	int id = *nextidp;
	int n, max;

	p = *paa = rcu_dereference_raw(idp->top);
	if (!p)
		return NULL;
	n = (p->layer + 1) * IDR_BITS;
	max = idr_max(p->layer + 1);

	while (id >= 0 && id <= max) {
		p = *paa;
		while (n > 0 && p) {
			n -= IDR_BITS;
			p = rcu_dereference_raw(p->ary[(id >> n) & IDR_MASK]);
			*++paa = p;
		}

		if (p) {
			*nextidp = id;
			return p;
		}

		id = round_up(id + 1, 1 << n);
		while (n < fls(id)) {
			n += IDR_BITS;
			--paa;
		}
	}
	return NULL;
}
EXPORT_SYMBOL(idr_get_next);

void *idr_replace(struct idr *idp, void *ptr, int id)
{
	int n;
	struct idr_layer *p, *old_p;

	if (id < 0)
		return ERR_PTR(-EINVAL);

	p = idp->top;
	if (!p)
		return ERR_PTR(-ENOENT);

	if (id > idr_max(p->layer + 1))
		return ERR_PTR(-ENOENT);

	n = p->layer * IDR_BITS;
	while ((n > 0) && p) {
		p = p->ary[(id >> n) & IDR_MASK];
		n -= IDR_BITS;
	}

	n = id & IDR_MASK;
	if (unlikely(p == NULL || !test_bit(n, p->bitmap)))
		return ERR_PTR(-ENOENT);

	old_p = p->ary[n];
	rcu_assign_pointer(p->ary[n], ptr);

	return old_p;
}
EXPORT_SYMBOL(idr_replace);

void __init idr_init_cache(void)
{
	idr_layer_cache = kmem_cache_create("idr_layer_cache",
				sizeof(struct idr_layer), 0, SLAB_PANIC, NULL);
}

void idr_init(struct idr *idp)
{
	memset(idp, 0, sizeof(struct idr));
	spin_lock_init(&idp->lock);
}
EXPORT_SYMBOL(idr_init);

static int idr_has_entry(int id, void *p, void *data)
{
	return 1;
}

bool idr_is_empty(struct idr *idp)
{
	return !idr_for_each(idp, idr_has_entry, NULL);
}
EXPORT_SYMBOL(idr_is_empty);

static void free_bitmap(struct ida *ida, struct ida_bitmap *bitmap)
{
	unsigned long flags;

	if (!ida->free_bitmap) {
		spin_lock_irqsave(&ida->idr.lock, flags);
		if (!ida->free_bitmap) {
			ida->free_bitmap = bitmap;
			bitmap = NULL;
		}
		spin_unlock_irqrestore(&ida->idr.lock, flags);
	}

	kfree(bitmap);
}

int ida_pre_get(struct ida *ida, gfp_t gfp_mask)
{
	 
	if (!__idr_pre_get(&ida->idr, gfp_mask))
		return 0;

	if (!ida->free_bitmap) {
		struct ida_bitmap *bitmap;

		bitmap = kmalloc(sizeof(struct ida_bitmap), gfp_mask);
		if (!bitmap)
			return 0;

		free_bitmap(ida, bitmap);
	}

	return 1;
}
EXPORT_SYMBOL(ida_pre_get);

int ida_get_new_above(struct ida *ida, int starting_id, int *p_id)
{
	struct idr_layer *pa[MAX_IDR_LEVEL + 1];
	struct ida_bitmap *bitmap;
	unsigned long flags;
	int idr_id = starting_id / IDA_BITMAP_BITS;
	int offset = starting_id % IDA_BITMAP_BITS;
	int t, id;

 restart:
	 
	t = idr_get_empty_slot(&ida->idr, idr_id, pa, 0, &ida->idr);
	if (t < 0)
		return t == -ENOMEM ? -EAGAIN : t;

	if (t * IDA_BITMAP_BITS >= MAX_IDR_BIT)
		return -ENOSPC;

	if (t != idr_id)
		offset = 0;
	idr_id = t;

	bitmap = (void *)pa[0]->ary[idr_id & IDR_MASK];
	if (!bitmap) {
		spin_lock_irqsave(&ida->idr.lock, flags);
		bitmap = ida->free_bitmap;
		ida->free_bitmap = NULL;
		spin_unlock_irqrestore(&ida->idr.lock, flags);

		if (!bitmap)
			return -EAGAIN;

		memset(bitmap, 0, sizeof(struct ida_bitmap));
		rcu_assign_pointer(pa[0]->ary[idr_id & IDR_MASK],
				(void *)bitmap);
		pa[0]->count++;
	}

	t = find_next_zero_bit(bitmap->bitmap, IDA_BITMAP_BITS, offset);
	if (t == IDA_BITMAP_BITS) {
		 
		idr_id++;
		offset = 0;
		goto restart;
	}

	id = idr_id * IDA_BITMAP_BITS + t;
	if (id >= MAX_IDR_BIT)
		return -ENOSPC;

	__set_bit(t, bitmap->bitmap);
	if (++bitmap->nr_busy == IDA_BITMAP_BITS)
		idr_mark_full(pa, idr_id);

	*p_id = id;

	if (ida->idr.id_free_cnt || ida->free_bitmap) {
		struct idr_layer *p = get_from_free_list(&ida->idr);
		if (p)
			kmem_cache_free(idr_layer_cache, p);
	}

	return 0;
}
EXPORT_SYMBOL(ida_get_new_above);

#ifdef MY_ABC_HERE
int syno_ida_get_new(struct ida *idp, int starting_id, int *id)
{
	return ida_get_new_above(idp, starting_id, id);
}
EXPORT_SYMBOL(syno_ida_get_new);
#endif  

void ida_remove(struct ida *ida, int id)
{
	struct idr_layer *p = ida->idr.top;
	int shift = (ida->idr.layers - 1) * IDR_BITS;
	int idr_id = id / IDA_BITMAP_BITS;
	int offset = id % IDA_BITMAP_BITS;
	int n;
	struct ida_bitmap *bitmap;

	if (idr_id > idr_max(ida->idr.layers))
		goto err;

	while ((shift > 0) && p) {
		n = (idr_id >> shift) & IDR_MASK;
		__clear_bit(n, p->bitmap);
		p = p->ary[n];
		shift -= IDR_BITS;
	}

	if (p == NULL)
		goto err;

	n = idr_id & IDR_MASK;
	__clear_bit(n, p->bitmap);

	bitmap = (void *)p->ary[n];
	if (!bitmap || !test_bit(offset, bitmap->bitmap))
		goto err;

	__clear_bit(offset, bitmap->bitmap);
	if (--bitmap->nr_busy == 0) {
		__set_bit(n, p->bitmap);	 
		idr_remove(&ida->idr, idr_id);
		free_bitmap(ida, bitmap);
	}

	return;

 err:
	WARN(1, "ida_remove called for id=%d which is not allocated.\n", id);
}
EXPORT_SYMBOL(ida_remove);

void ida_destroy(struct ida *ida)
{
	idr_destroy(&ida->idr);
	kfree(ida->free_bitmap);
}
EXPORT_SYMBOL(ida_destroy);

int ida_simple_get(struct ida *ida, unsigned int start, unsigned int end,
		   gfp_t gfp_mask)
{
	int ret, id;
	unsigned int max;
	unsigned long flags;

	BUG_ON((int)start < 0);
	BUG_ON((int)end < 0);

	if (end == 0)
		max = 0x80000000;
	else {
		BUG_ON(end < start);
		max = end - 1;
	}

again:
	if (!ida_pre_get(ida, gfp_mask))
		return -ENOMEM;

	spin_lock_irqsave(&simple_ida_lock, flags);
	ret = ida_get_new_above(ida, start, &id);
	if (!ret) {
		if (id > max) {
			ida_remove(ida, id);
			ret = -ENOSPC;
		} else {
			ret = id;
		}
	}
	spin_unlock_irqrestore(&simple_ida_lock, flags);

	if (unlikely(ret == -EAGAIN))
		goto again;

	return ret;
}
EXPORT_SYMBOL(ida_simple_get);

void ida_simple_remove(struct ida *ida, unsigned int id)
{
	unsigned long flags;

	BUG_ON((int)id < 0);
	spin_lock_irqsave(&simple_ida_lock, flags);
	ida_remove(ida, id);
	spin_unlock_irqrestore(&simple_ida_lock, flags);
}
EXPORT_SYMBOL(ida_simple_remove);

void ida_init(struct ida *ida)
{
	memset(ida, 0, sizeof(struct ida));
	idr_init(&ida->idr);

}
EXPORT_SYMBOL(ida_init);
