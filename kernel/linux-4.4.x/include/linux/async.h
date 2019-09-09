#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef __ASYNC_H__
#define __ASYNC_H__

#include <linux/types.h>
#include <linux/list.h>

typedef u64 async_cookie_t;
typedef void (*async_func_t) (void *data, async_cookie_t cookie);
struct async_domain {
	struct list_head pending;
	unsigned registered:1;
};

#define ASYNC_DOMAIN(_name) \
	struct async_domain _name = { .pending = LIST_HEAD_INIT(_name.pending),	\
				      .registered = 1 }

#define ASYNC_DOMAIN_EXCLUSIVE(_name) \
	struct async_domain _name = { .pending = LIST_HEAD_INIT(_name.pending), \
				      .registered = 0 }

#ifdef MY_ABC_HERE
extern void syno_async_schedule_enabled_set(int iValue);
extern int syno_async_schedule_enabled_get(void);
#endif  

extern async_cookie_t async_schedule(async_func_t func, void *data);
extern async_cookie_t async_schedule_domain(async_func_t func, void *data,
					    struct async_domain *domain);
void async_unregister_domain(struct async_domain *domain);
extern void async_synchronize_full(void);
extern void async_synchronize_full_domain(struct async_domain *domain);
extern void async_synchronize_cookie(async_cookie_t cookie);
extern void async_synchronize_cookie_domain(async_cookie_t cookie,
					    struct async_domain *domain);
extern bool current_is_async(void);
#endif
