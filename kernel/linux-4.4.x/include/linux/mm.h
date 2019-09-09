#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#ifndef _LINUX_MM_H
#define _LINUX_MM_H

#include <linux/errno.h>

#ifdef __KERNEL__

#include <linux/mmdebug.h>
#include <linux/gfp.h>
#include <linux/bug.h>
#include <linux/list.h>
#include <linux/mmzone.h>
#include <linux/rbtree.h>
#include <linux/atomic.h>
#include <linux/debug_locks.h>
#include <linux/mm_types.h>
#include <linux/range.h>
#include <linux/pfn.h>
#include <linux/bit_spinlock.h>
#include <linux/shrinker.h>
#include <linux/resource.h>
#include <linux/page_ext.h>
#include <linux/err.h>

struct mempolicy;
struct anon_vma;
struct anon_vma_chain;
struct file_ra_state;
struct user_struct;
struct writeback_control;
struct bdi_writeback;

#ifndef CONFIG_NEED_MULTIPLE_NODES	 
extern unsigned long max_mapnr;

static inline void set_max_mapnr(unsigned long limit)
{
	max_mapnr = limit;
}
#else
static inline void set_max_mapnr(unsigned long limit) { }
#endif

extern unsigned long totalram_pages;
extern void * high_memory;
extern int page_cluster;

#ifdef CONFIG_SYSCTL
extern int sysctl_legacy_va_layout;
#else
#define sysctl_legacy_va_layout 0
#endif

#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/processor.h>

#ifndef __pa_symbol
#define __pa_symbol(x)  __pa(RELOC_HIDE((unsigned long)(x), 0))
#endif

#ifndef mm_forbids_zeropage
#define mm_forbids_zeropage(X)	(0)
#endif

extern unsigned long sysctl_user_reserve_kbytes;
extern unsigned long sysctl_admin_reserve_kbytes;

extern int sysctl_overcommit_memory;
extern int sysctl_overcommit_ratio;
extern unsigned long sysctl_overcommit_kbytes;

extern int overcommit_ratio_handler(struct ctl_table *, int, void __user *,
				    size_t *, loff_t *);
extern int overcommit_kbytes_handler(struct ctl_table *, int, void __user *,
				    size_t *, loff_t *);

#define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))

#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)

#define PAGE_ALIGNED(addr)	IS_ALIGNED((unsigned long)addr, PAGE_SIZE)

extern struct kmem_cache *vm_area_cachep;

#ifndef CONFIG_MMU
extern struct rb_root nommu_region_tree;
extern struct rw_semaphore nommu_region_sem;

extern unsigned int kobjsize(const void *objp);
#endif

#define VM_NONE		0x00000000

#define VM_READ		0x00000001	 
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008

#define VM_MAYREAD	0x00000010	 
#define VM_MAYWRITE	0x00000020
#define VM_MAYEXEC	0x00000040
#define VM_MAYSHARE	0x00000080

#define VM_GROWSDOWN	0x00000100	 
#define VM_UFFD_MISSING	0x00000200	 
#define VM_PFNMAP	0x00000400	 
#define VM_DENYWRITE	0x00000800	 
#define VM_UFFD_WP	0x00001000	 

#define VM_LOCKED	0x00002000
#define VM_IO           0x00004000	 

#define VM_SEQ_READ	0x00008000	 
#define VM_RAND_READ	0x00010000	 

#define VM_DONTCOPY	0x00020000       
#define VM_DONTEXPAND	0x00040000	 
#define VM_LOCKONFAULT	0x00080000	 
#define VM_ACCOUNT	0x00100000	 
#define VM_NORESERVE	0x00200000	 
#define VM_HUGETLB	0x00400000	 
#define VM_ARCH_1	0x01000000	 
#define VM_ARCH_2	0x02000000
#define VM_DONTDUMP	0x04000000	 

#ifdef CONFIG_MEM_SOFT_DIRTY
# define VM_SOFTDIRTY	0x08000000	 
#else
# define VM_SOFTDIRTY	0
#endif

#define VM_MIXEDMAP	0x10000000	 
#define VM_HUGEPAGE	0x20000000	 
#define VM_NOHUGEPAGE	0x40000000	 
#define VM_MERGEABLE	0x80000000	 

#if defined(CONFIG_X86)
# define VM_PAT		VM_ARCH_1	 
#elif defined(CONFIG_PPC)
# define VM_SAO		VM_ARCH_1	 
#elif defined(CONFIG_PARISC)
# define VM_GROWSUP	VM_ARCH_1
#elif defined(CONFIG_METAG)
# define VM_GROWSUP	VM_ARCH_1
#elif defined(CONFIG_IA64)
# define VM_GROWSUP	VM_ARCH_1
#elif !defined(CONFIG_MMU)
# define VM_MAPPED_COPY	VM_ARCH_1	 
#endif

#if defined(CONFIG_X86)
 
# define VM_MPX		VM_ARCH_2
#endif

#ifndef VM_GROWSUP
# define VM_GROWSUP	VM_NONE
#endif

#define VM_STACK_INCOMPLETE_SETUP	(VM_RAND_READ | VM_SEQ_READ)

#ifndef VM_STACK_DEFAULT_FLAGS		 
#define VM_STACK_DEFAULT_FLAGS VM_DATA_DEFAULT_FLAGS
#endif

#ifdef CONFIG_STACK_GROWSUP
#define VM_STACK_FLAGS	(VM_GROWSUP | VM_STACK_DEFAULT_FLAGS | VM_ACCOUNT)
#else
#define VM_STACK_FLAGS	(VM_GROWSDOWN | VM_STACK_DEFAULT_FLAGS | VM_ACCOUNT)
#endif

#define VM_SPECIAL (VM_IO | VM_DONTEXPAND | VM_PFNMAP | VM_MIXEDMAP)

#define VM_INIT_DEF_MASK	VM_NOHUGEPAGE

#define VM_LOCKED_CLEAR_MASK	(~(VM_LOCKED | VM_LOCKONFAULT))

extern pgprot_t protection_map[16];

#define FAULT_FLAG_WRITE	0x01	 
#define FAULT_FLAG_MKWRITE	0x02	 
#define FAULT_FLAG_ALLOW_RETRY	0x04	 
#define FAULT_FLAG_RETRY_NOWAIT	0x08	 
#define FAULT_FLAG_KILLABLE	0x10	 
#define FAULT_FLAG_TRIED	0x20	 
#define FAULT_FLAG_USER		0x40	 

struct vm_fault {
	unsigned int flags;		 
	pgoff_t pgoff;			 
	void __user *virtual_address;	 

	struct page *cow_page;		 
	struct page *page;		 
	 
	pgoff_t max_pgoff;		 
	pte_t *pte;			 
};

struct vm_operations_struct {
	void (*open)(struct vm_area_struct * area);
	void (*close)(struct vm_area_struct * area);
	int (*mremap)(struct vm_area_struct * area);
	int (*fault)(struct vm_area_struct *vma, struct vm_fault *vmf);
	int (*pmd_fault)(struct vm_area_struct *, unsigned long address,
						pmd_t *, unsigned int flags);
	void (*map_pages)(struct vm_area_struct *vma, struct vm_fault *vmf);

	int (*page_mkwrite)(struct vm_area_struct *vma, struct vm_fault *vmf);

	int (*pfn_mkwrite)(struct vm_area_struct *vma, struct vm_fault *vmf);

	int (*access)(struct vm_area_struct *vma, unsigned long addr,
		      void *buf, int len, int write);

	const char *(*name)(struct vm_area_struct *vma);

#ifdef CONFIG_NUMA
	 
	int (*set_policy)(struct vm_area_struct *vma, struct mempolicy *new);

	struct mempolicy *(*get_policy)(struct vm_area_struct *vma,
					unsigned long addr);
#endif
	 
	struct page *(*find_special_page)(struct vm_area_struct *vma,
					  unsigned long addr);
};

struct mmu_gather;
struct inode;

#define page_private(page)		((page)->private)
#define set_page_private(page, v)	((page)->private = (v))

#include <linux/page-flags.h>
#include <linux/huge_mm.h>

static inline int put_page_testzero(struct page *page)
{
	VM_BUG_ON_PAGE(atomic_read(&page->_count) == 0, page);
	return atomic_dec_and_test(&page->_count);
}

static inline int get_page_unless_zero(struct page *page)
{
	return atomic_inc_not_zero(&page->_count);
}

extern int page_is_ram(unsigned long pfn);

enum {
	REGION_INTERSECTS,
	REGION_DISJOINT,
	REGION_MIXED,
};

int region_intersects(resource_size_t offset, size_t size, const char *type);

struct page *vmalloc_to_page(const void *addr);
unsigned long vmalloc_to_pfn(const void *addr);

static inline int is_vmalloc_addr(const void *x)
{
#ifdef CONFIG_MMU
	unsigned long addr = (unsigned long)x;

	return addr >= VMALLOC_START && addr < VMALLOC_END;
#else
	return 0;
#endif
}
#ifdef CONFIG_MMU
extern int is_vmalloc_or_module_addr(const void *x);
#else
static inline int is_vmalloc_or_module_addr(const void *x)
{
	return 0;
}
#endif

extern void kvfree(const void *addr);

static inline void compound_lock(struct page *page)
{
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	VM_BUG_ON_PAGE(PageSlab(page), page);
	bit_spin_lock(PG_compound_lock, &page->flags);
#endif
}

static inline void compound_unlock(struct page *page)
{
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	VM_BUG_ON_PAGE(PageSlab(page), page);
	bit_spin_unlock(PG_compound_lock, &page->flags);
#endif
}

static inline unsigned long compound_lock_irqsave(struct page *page)
{
	unsigned long uninitialized_var(flags);
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	local_irq_save(flags);
	compound_lock(page);
#endif
	return flags;
}

static inline void compound_unlock_irqrestore(struct page *page,
					      unsigned long flags)
{
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	compound_unlock(page);
	local_irq_restore(flags);
#endif
}

static inline void page_mapcount_reset(struct page *page)
{
	atomic_set(&(page)->_mapcount, -1);
}

static inline int page_mapcount(struct page *page)
{
	VM_BUG_ON_PAGE(PageSlab(page), page);
	return atomic_read(&page->_mapcount) + 1;
}

static inline int page_count(struct page *page)
{
	return atomic_read(&compound_head(page)->_count);
}

static inline bool __compound_tail_refcounted(struct page *page)
{
	return PageAnon(page) && !PageSlab(page) && !PageHeadHuge(page);
}

static inline bool compound_tail_refcounted(struct page *page)
{
	VM_BUG_ON_PAGE(!PageHead(page), page);
	return __compound_tail_refcounted(page);
}

static inline void get_huge_page_tail(struct page *page)
{
	 
	VM_BUG_ON_PAGE(!PageTail(page), page);
	VM_BUG_ON_PAGE(page_mapcount(page) < 0, page);
	VM_BUG_ON_PAGE(atomic_read(&page->_count) != 0, page);
	if (compound_tail_refcounted(compound_head(page)))
		atomic_inc(&page->_mapcount);
}

extern bool __get_page_tail(struct page *page);

static inline void get_page(struct page *page)
{
	if (unlikely(PageTail(page)))
		if (likely(__get_page_tail(page)))
			return;
	 
	VM_BUG_ON_PAGE(atomic_read(&page->_count) <= 0, page);
	atomic_inc(&page->_count);
}

static inline struct page *virt_to_head_page(const void *x)
{
	struct page *page = virt_to_page(x);

	return compound_head(page);
}

static inline void init_page_count(struct page *page)
{
	atomic_set(&page->_count, 1);
}

void put_page(struct page *page);
void put_pages_list(struct list_head *pages);

void split_page(struct page *page, unsigned int order);
int split_free_page(struct page *page);

typedef void compound_page_dtor(struct page *);

enum compound_dtor_id {
	NULL_COMPOUND_DTOR,
	COMPOUND_PAGE_DTOR,
#ifdef CONFIG_HUGETLB_PAGE
	HUGETLB_PAGE_DTOR,
#endif
	NR_COMPOUND_DTORS,
};
extern compound_page_dtor * const compound_page_dtors[];

static inline void set_compound_page_dtor(struct page *page,
		enum compound_dtor_id compound_dtor)
{
	VM_BUG_ON_PAGE(compound_dtor >= NR_COMPOUND_DTORS, page);
	page[1].compound_dtor = compound_dtor;
}

static inline compound_page_dtor *get_compound_page_dtor(struct page *page)
{
	VM_BUG_ON_PAGE(page[1].compound_dtor >= NR_COMPOUND_DTORS, page);
	return compound_page_dtors[page[1].compound_dtor];
}

static inline unsigned int compound_order(struct page *page)
{
	if (!PageHead(page))
		return 0;
	return page[1].compound_order;
}

static inline void set_compound_order(struct page *page, unsigned int order)
{
	page[1].compound_order = order;
}

#ifdef CONFIG_MMU
 
static inline pte_t maybe_mkwrite(pte_t pte, struct vm_area_struct *vma)
{
	if (likely(vma->vm_flags & VM_WRITE))
		pte = pte_mkwrite(pte);
	return pte;
}

void do_set_pte(struct vm_area_struct *vma, unsigned long address,
		struct page *page, pte_t *pte, bool write, bool anon);
#endif

#define SECTIONS_PGOFF		((sizeof(unsigned long)*8) - SECTIONS_WIDTH)
#define NODES_PGOFF		(SECTIONS_PGOFF - NODES_WIDTH)
#define ZONES_PGOFF		(NODES_PGOFF - ZONES_WIDTH)
#define LAST_CPUPID_PGOFF	(ZONES_PGOFF - LAST_CPUPID_WIDTH)

#define SECTIONS_PGSHIFT	(SECTIONS_PGOFF * (SECTIONS_WIDTH != 0))
#define NODES_PGSHIFT		(NODES_PGOFF * (NODES_WIDTH != 0))
#define ZONES_PGSHIFT		(ZONES_PGOFF * (ZONES_WIDTH != 0))
#define LAST_CPUPID_PGSHIFT	(LAST_CPUPID_PGOFF * (LAST_CPUPID_WIDTH != 0))

#ifdef NODE_NOT_IN_PAGE_FLAGS
#define ZONEID_SHIFT		(SECTIONS_SHIFT + ZONES_SHIFT)
#define ZONEID_PGOFF		((SECTIONS_PGOFF < ZONES_PGOFF)? \
						SECTIONS_PGOFF : ZONES_PGOFF)
#else
#define ZONEID_SHIFT		(NODES_SHIFT + ZONES_SHIFT)
#define ZONEID_PGOFF		((NODES_PGOFF < ZONES_PGOFF)? \
						NODES_PGOFF : ZONES_PGOFF)
#endif

#define ZONEID_PGSHIFT		(ZONEID_PGOFF * (ZONEID_SHIFT != 0))

#if SECTIONS_WIDTH+NODES_WIDTH+ZONES_WIDTH > BITS_PER_LONG - NR_PAGEFLAGS
#error SECTIONS_WIDTH+NODES_WIDTH+ZONES_WIDTH > BITS_PER_LONG - NR_PAGEFLAGS
#endif

#define ZONES_MASK		((1UL << ZONES_WIDTH) - 1)
#define NODES_MASK		((1UL << NODES_WIDTH) - 1)
#define SECTIONS_MASK		((1UL << SECTIONS_WIDTH) - 1)
#define LAST_CPUPID_MASK	((1UL << LAST_CPUPID_SHIFT) - 1)
#define ZONEID_MASK		((1UL << ZONEID_SHIFT) - 1)

static inline enum zone_type page_zonenum(const struct page *page)
{
	return (page->flags >> ZONES_PGSHIFT) & ZONES_MASK;
}

#if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
#define SECTION_IN_PAGE_FLAGS
#endif

static inline int page_zone_id(struct page *page)
{
	return (page->flags >> ZONEID_PGSHIFT) & ZONEID_MASK;
}

static inline int zone_to_nid(struct zone *zone)
{
#ifdef CONFIG_NUMA
	return zone->node;
#else
	return 0;
#endif
}

#ifdef NODE_NOT_IN_PAGE_FLAGS
extern int page_to_nid(const struct page *page);
#else
static inline int page_to_nid(const struct page *page)
{
	return (page->flags >> NODES_PGSHIFT) & NODES_MASK;
}
#endif

#ifdef CONFIG_NUMA_BALANCING
static inline int cpu_pid_to_cpupid(int cpu, int pid)
{
	return ((cpu & LAST__CPU_MASK) << LAST__PID_SHIFT) | (pid & LAST__PID_MASK);
}

static inline int cpupid_to_pid(int cpupid)
{
	return cpupid & LAST__PID_MASK;
}

static inline int cpupid_to_cpu(int cpupid)
{
	return (cpupid >> LAST__PID_SHIFT) & LAST__CPU_MASK;
}

static inline int cpupid_to_nid(int cpupid)
{
	return cpu_to_node(cpupid_to_cpu(cpupid));
}

static inline bool cpupid_pid_unset(int cpupid)
{
	return cpupid_to_pid(cpupid) == (-1 & LAST__PID_MASK);
}

static inline bool cpupid_cpu_unset(int cpupid)
{
	return cpupid_to_cpu(cpupid) == (-1 & LAST__CPU_MASK);
}

static inline bool __cpupid_match_pid(pid_t task_pid, int cpupid)
{
	return (task_pid & LAST__PID_MASK) == cpupid_to_pid(cpupid);
}

#define cpupid_match_pid(task, cpupid) __cpupid_match_pid(task->pid, cpupid)
#ifdef LAST_CPUPID_NOT_IN_PAGE_FLAGS
static inline int page_cpupid_xchg_last(struct page *page, int cpupid)
{
	return xchg(&page->_last_cpupid, cpupid & LAST_CPUPID_MASK);
}

static inline int page_cpupid_last(struct page *page)
{
	return page->_last_cpupid;
}
static inline void page_cpupid_reset_last(struct page *page)
{
	page->_last_cpupid = -1 & LAST_CPUPID_MASK;
}
#else
static inline int page_cpupid_last(struct page *page)
{
	return (page->flags >> LAST_CPUPID_PGSHIFT) & LAST_CPUPID_MASK;
}

extern int page_cpupid_xchg_last(struct page *page, int cpupid);

static inline void page_cpupid_reset_last(struct page *page)
{
	int cpupid = (1 << LAST_CPUPID_SHIFT) - 1;

	page->flags &= ~(LAST_CPUPID_MASK << LAST_CPUPID_PGSHIFT);
	page->flags |= (cpupid & LAST_CPUPID_MASK) << LAST_CPUPID_PGSHIFT;
}
#endif  
#else  
static inline int page_cpupid_xchg_last(struct page *page, int cpupid)
{
	return page_to_nid(page);  
}

static inline int page_cpupid_last(struct page *page)
{
	return page_to_nid(page);  
}

static inline int cpupid_to_nid(int cpupid)
{
	return -1;
}

static inline int cpupid_to_pid(int cpupid)
{
	return -1;
}

static inline int cpupid_to_cpu(int cpupid)
{
	return -1;
}

static inline int cpu_pid_to_cpupid(int nid, int pid)
{
	return -1;
}

static inline bool cpupid_pid_unset(int cpupid)
{
	return 1;
}

static inline void page_cpupid_reset_last(struct page *page)
{
}

static inline bool cpupid_match_pid(struct task_struct *task, int cpupid)
{
	return false;
}
#endif  

static inline struct zone *page_zone(const struct page *page)
{
	return &NODE_DATA(page_to_nid(page))->node_zones[page_zonenum(page)];
}

#ifdef SECTION_IN_PAGE_FLAGS
static inline void set_page_section(struct page *page, unsigned long section)
{
	page->flags &= ~(SECTIONS_MASK << SECTIONS_PGSHIFT);
	page->flags |= (section & SECTIONS_MASK) << SECTIONS_PGSHIFT;
}

static inline unsigned long page_to_section(const struct page *page)
{
	return (page->flags >> SECTIONS_PGSHIFT) & SECTIONS_MASK;
}
#endif

static inline void set_page_zone(struct page *page, enum zone_type zone)
{
	page->flags &= ~(ZONES_MASK << ZONES_PGSHIFT);
	page->flags |= (zone & ZONES_MASK) << ZONES_PGSHIFT;
}

static inline void set_page_node(struct page *page, unsigned long node)
{
	page->flags &= ~(NODES_MASK << NODES_PGSHIFT);
	page->flags |= (node & NODES_MASK) << NODES_PGSHIFT;
}

static inline void set_page_links(struct page *page, enum zone_type zone,
	unsigned long node, unsigned long pfn)
{
	set_page_zone(page, zone);
	set_page_node(page, node);
#ifdef SECTION_IN_PAGE_FLAGS
	set_page_section(page, pfn_to_section_nr(pfn));
#endif
}

#ifdef CONFIG_MEMCG
static inline struct mem_cgroup *page_memcg(struct page *page)
{
	return page->mem_cgroup;
}

static inline void set_page_memcg(struct page *page, struct mem_cgroup *memcg)
{
	page->mem_cgroup = memcg;
}
#else
static inline struct mem_cgroup *page_memcg(struct page *page)
{
	return NULL;
}

static inline void set_page_memcg(struct page *page, struct mem_cgroup *memcg)
{
}
#endif

#include <linux/vmstat.h>

static __always_inline void *lowmem_page_address(const struct page *page)
{
	return __va(PFN_PHYS(page_to_pfn(page)));
}

#if defined(CONFIG_HIGHMEM) && !defined(WANT_PAGE_VIRTUAL)
#define HASHED_PAGE_VIRTUAL
#endif

#if defined(WANT_PAGE_VIRTUAL)
static inline void *page_address(const struct page *page)
{
	return page->virtual;
}
static inline void set_page_address(struct page *page, void *address)
{
	page->virtual = address;
}
#define page_address_init()  do { } while(0)
#endif

#if defined(HASHED_PAGE_VIRTUAL)
void *page_address(const struct page *page);
void set_page_address(struct page *page, void *virtual);
void page_address_init(void);
#endif

#if !defined(HASHED_PAGE_VIRTUAL) && !defined(WANT_PAGE_VIRTUAL)
#define page_address(page) lowmem_page_address(page)
#define set_page_address(page, address)  do { } while(0)
#define page_address_init()  do { } while(0)
#endif

extern void *page_rmapping(struct page *page);
extern struct anon_vma *page_anon_vma(struct page *page);
extern struct address_space *page_mapping(struct page *page);

extern struct address_space *__page_file_mapping(struct page *);

static inline
struct address_space *page_file_mapping(struct page *page)
{
	if (unlikely(PageSwapCache(page)))
		return __page_file_mapping(page);

	return page->mapping;
}

static inline pgoff_t page_index(struct page *page)
{
	if (unlikely(PageSwapCache(page)))
		return page_private(page);
	return page->index;
}

extern pgoff_t __page_file_index(struct page *page);

static inline pgoff_t page_file_index(struct page *page)
{
	if (unlikely(PageSwapCache(page)))
		return __page_file_index(page);

	return page->index;
}

static inline int page_mapped(struct page *page)
{
	return atomic_read(&(page)->_mapcount) >= 0;
}

static inline bool page_is_pfmemalloc(struct page *page)
{
	 
	return page->index == -1UL;
}

static inline void set_page_pfmemalloc(struct page *page)
{
	page->index = -1UL;
}

static inline void clear_page_pfmemalloc(struct page *page)
{
	page->index = 0;
}

#define VM_FAULT_MINOR	0  

#define VM_FAULT_OOM	0x0001
#define VM_FAULT_SIGBUS	0x0002
#define VM_FAULT_MAJOR	0x0004
#define VM_FAULT_WRITE	0x0008	 
#define VM_FAULT_HWPOISON 0x0010	 
#define VM_FAULT_HWPOISON_LARGE 0x0020   
#define VM_FAULT_SIGSEGV 0x0040

#define VM_FAULT_NOPAGE	0x0100	 
#define VM_FAULT_LOCKED	0x0200	 
#define VM_FAULT_RETRY	0x0400	 
#define VM_FAULT_FALLBACK 0x0800	 

#define VM_FAULT_HWPOISON_LARGE_MASK 0xf000  

#define VM_FAULT_ERROR	(VM_FAULT_OOM | VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV | \
			 VM_FAULT_HWPOISON | VM_FAULT_HWPOISON_LARGE | \
			 VM_FAULT_FALLBACK)

#define VM_FAULT_SET_HINDEX(x) ((x) << 12)
#define VM_FAULT_GET_HINDEX(x) (((x) >> 12) & 0xf)

extern void pagefault_out_of_memory(void);

#define offset_in_page(p)	((unsigned long)(p) & ~PAGE_MASK)

#define SHOW_MEM_FILTER_NODES		(0x0001u)	 

extern void show_free_areas(unsigned int flags);
extern bool skip_free_areas_node(unsigned int flags, int nid);

int shmem_zero_setup(struct vm_area_struct *);
#ifdef CONFIG_SHMEM
bool shmem_mapping(struct address_space *mapping);
#else
static inline bool shmem_mapping(struct address_space *mapping)
{
	return false;
}
#endif

extern int can_do_mlock(void);
extern int user_shm_lock(size_t, struct user_struct *);
extern void user_shm_unlock(size_t, struct user_struct *);

struct zap_details {
	struct address_space *check_mapping;	 
	pgoff_t	first_index;			 
	pgoff_t last_index;			 
};

struct page *vm_normal_page(struct vm_area_struct *vma, unsigned long addr,
		pte_t pte);
struct page *vm_normal_page_pmd(struct vm_area_struct *vma, unsigned long addr,
				pmd_t pmd);

int zap_vma_ptes(struct vm_area_struct *vma, unsigned long address,
		unsigned long size);
void zap_page_range(struct vm_area_struct *vma, unsigned long address,
		unsigned long size, struct zap_details *);
void unmap_vmas(struct mmu_gather *tlb, struct vm_area_struct *start_vma,
		unsigned long start, unsigned long end);

struct mm_walk {
	int (*pmd_entry)(pmd_t *pmd, unsigned long addr,
			 unsigned long next, struct mm_walk *walk);
	int (*pte_entry)(pte_t *pte, unsigned long addr,
			 unsigned long next, struct mm_walk *walk);
	int (*pte_hole)(unsigned long addr, unsigned long next,
			struct mm_walk *walk);
	int (*hugetlb_entry)(pte_t *pte, unsigned long hmask,
			     unsigned long addr, unsigned long next,
			     struct mm_walk *walk);
	int (*test_walk)(unsigned long addr, unsigned long next,
			struct mm_walk *walk);
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	void *private;
};

int walk_page_range(unsigned long addr, unsigned long end,
		struct mm_walk *walk);
int walk_page_vma(struct vm_area_struct *vma, struct mm_walk *walk);
void free_pgd_range(struct mmu_gather *tlb, unsigned long addr,
		unsigned long end, unsigned long floor, unsigned long ceiling);
int copy_page_range(struct mm_struct *dst, struct mm_struct *src,
			struct vm_area_struct *vma);
void unmap_mapping_range(struct address_space *mapping,
		loff_t const holebegin, loff_t const holelen, int even_cows);
int follow_pfn(struct vm_area_struct *vma, unsigned long address,
	unsigned long *pfn);
int follow_phys(struct vm_area_struct *vma, unsigned long address,
		unsigned int flags, unsigned long *prot, resource_size_t *phys);
int generic_access_phys(struct vm_area_struct *vma, unsigned long addr,
			void *buf, int len, int write);

static inline void unmap_shared_mapping_range(struct address_space *mapping,
		loff_t const holebegin, loff_t const holelen)
{
	unmap_mapping_range(mapping, holebegin, holelen, 0);
}

extern void truncate_pagecache(struct inode *inode, loff_t new);
extern void truncate_setsize(struct inode *inode, loff_t newsize);
#ifdef MY_ABC_HERE
extern void ecryptfs_truncate_setsize(struct inode *inode, loff_t newsize);
#endif  
void pagecache_isize_extended(struct inode *inode, loff_t from, loff_t to);
void truncate_pagecache_range(struct inode *inode, loff_t offset, loff_t end);
int truncate_inode_page(struct address_space *mapping, struct page *page);
int generic_error_remove_page(struct address_space *mapping, struct page *page);
int invalidate_inode_page(struct page *page);

#ifdef CONFIG_MMU
extern int handle_mm_fault(struct mm_struct *mm, struct vm_area_struct *vma,
			unsigned long address, unsigned int flags);
extern int fixup_user_fault(struct task_struct *tsk, struct mm_struct *mm,
			    unsigned long address, unsigned int fault_flags);
#else
static inline int handle_mm_fault(struct mm_struct *mm,
			struct vm_area_struct *vma, unsigned long address,
			unsigned int flags)
{
	 
	BUG();
	return VM_FAULT_SIGBUS;
}
static inline int fixup_user_fault(struct task_struct *tsk,
		struct mm_struct *mm, unsigned long address,
		unsigned int fault_flags)
{
	 
	BUG();
	return -EFAULT;
}
#endif

#ifdef CONFIG_AUFS_FHSM
extern void vma_do_file_update_time(struct vm_area_struct *, const char[], int);
extern struct file *vma_do_pr_or_file(struct vm_area_struct *, const char[],
				      int);
extern void vma_do_get_file(struct vm_area_struct *, const char[], int);
extern void vma_do_fput(struct vm_area_struct *, const char[], int);

#define vma_file_update_time(vma)	vma_do_file_update_time(vma, __func__, \
								__LINE__)
#define vma_pr_or_file(vma)		vma_do_pr_or_file(vma, __func__, \
							  __LINE__)
#define vma_get_file(vma)		vma_do_get_file(vma, __func__, __LINE__)
#define vma_fput(vma)			vma_do_fput(vma, __func__, __LINE__)

#ifndef CONFIG_MMU
extern struct file *vmr_do_pr_or_file(struct vm_region *, const char[], int);
extern void vmr_do_fput(struct vm_region *, const char[], int);

#define vmr_pr_or_file(region)		vmr_do_pr_or_file(region, __func__, \
							  __LINE__)
#define vmr_fput(region)		vmr_do_fput(region, __func__, __LINE__)
#endif  
#endif  

extern int access_process_vm(struct task_struct *tsk, unsigned long addr, void *buf, int len, int write);
extern int access_remote_vm(struct mm_struct *mm, unsigned long addr,
		void *buf, int len, int write);

long __get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
		      unsigned long start, unsigned long nr_pages,
		      unsigned int foll_flags, struct page **pages,
		      struct vm_area_struct **vmas, int *nonblocking);
long get_user_pages_remote(struct task_struct *tsk, struct mm_struct *mm,
			    unsigned long start, unsigned long nr_pages,
			    int write, int force, struct page **pages,
			    struct vm_area_struct **vmas);
long get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
		    unsigned long start, unsigned long nr_pages,
		    int write, int force, struct page **pages,
		    struct vm_area_struct **vmas);
long get_user_pages_locked(struct task_struct *tsk, struct mm_struct *mm,
		    unsigned long start, unsigned long nr_pages,
		    int write, int force, struct page **pages,
		    int *locked);
long __get_user_pages_unlocked(struct task_struct *tsk, struct mm_struct *mm,
			       unsigned long start, unsigned long nr_pages,
			       int write, int force, struct page **pages,
			       unsigned int gup_flags);
long get_user_pages_unlocked(struct task_struct *tsk, struct mm_struct *mm,
		    unsigned long start, unsigned long nr_pages,
		    int write, int force, struct page **pages);
int get_user_pages_fast(unsigned long start, int nr_pages, int write,
			struct page **pages);

struct frame_vector {
	unsigned int nr_allocated;	 
	unsigned int nr_frames;	 
	bool got_ref;		 
	bool is_pfns;		 
	void *ptrs[0];		 
};

struct frame_vector *frame_vector_create(unsigned int nr_frames);
void frame_vector_destroy(struct frame_vector *vec);
int get_vaddr_frames(unsigned long start, unsigned int nr_pfns,
		     bool write, bool force, struct frame_vector *vec);
void put_vaddr_frames(struct frame_vector *vec);
int frame_vector_to_pages(struct frame_vector *vec);
void frame_vector_to_pfns(struct frame_vector *vec);

static inline unsigned int frame_vector_count(struct frame_vector *vec)
{
	return vec->nr_frames;
}

static inline struct page **frame_vector_pages(struct frame_vector *vec)
{
	if (vec->is_pfns) {
		int err = frame_vector_to_pages(vec);

		if (err)
			return ERR_PTR(err);
	}
	return (struct page **)(vec->ptrs);
}

static inline unsigned long *frame_vector_pfns(struct frame_vector *vec)
{
	if (!vec->is_pfns)
		frame_vector_to_pfns(vec);
	return (unsigned long *)(vec->ptrs);
}

struct kvec;
int get_kernel_pages(const struct kvec *iov, int nr_pages, int write,
			struct page **pages);
int get_kernel_page(unsigned long start, int write, struct page **pages);
struct page *get_dump_page(unsigned long addr);

extern int try_to_release_page(struct page * page, gfp_t gfp_mask);
extern void do_invalidatepage(struct page *page, unsigned int offset,
			      unsigned int length);

int __set_page_dirty_nobuffers(struct page *page);
int __set_page_dirty_no_writeback(struct page *page);
int redirty_page_for_writepage(struct writeback_control *wbc,
				struct page *page);
void account_page_dirtied(struct page *page, struct address_space *mapping,
			  struct mem_cgroup *memcg);
void account_page_cleaned(struct page *page, struct address_space *mapping,
			  struct mem_cgroup *memcg, struct bdi_writeback *wb);
int set_page_dirty(struct page *page);
int set_page_dirty_lock(struct page *page);
void cancel_dirty_page(struct page *page);
int clear_page_dirty_for_io(struct page *page);

int get_cmdline(struct task_struct *task, char *buffer, int buflen);

static inline bool vma_is_anonymous(struct vm_area_struct *vma)
{
	return !vma->vm_ops;
}

int vma_is_stack_for_task(struct vm_area_struct *vma, struct task_struct *t);

extern unsigned long move_page_tables(struct vm_area_struct *vma,
		unsigned long old_addr, struct vm_area_struct *new_vma,
		unsigned long new_addr, unsigned long len,
		bool need_rmap_locks);
extern unsigned long change_protection(struct vm_area_struct *vma, unsigned long start,
			      unsigned long end, pgprot_t newprot,
			      int dirty_accountable, int prot_numa);
extern int mprotect_fixup(struct vm_area_struct *vma,
			  struct vm_area_struct **pprev, unsigned long start,
			  unsigned long end, unsigned long newflags);

int __get_user_pages_fast(unsigned long start, int nr_pages, int write,
			  struct page **pages);
 
static inline unsigned long get_mm_counter(struct mm_struct *mm, int member)
{
	long val = atomic_long_read(&mm->rss_stat.count[member]);

#ifdef SPLIT_RSS_COUNTING
	 
	if (val < 0)
		val = 0;
#endif
	return (unsigned long)val;
}

static inline void add_mm_counter(struct mm_struct *mm, int member, long value)
{
	atomic_long_add(value, &mm->rss_stat.count[member]);
}

static inline void inc_mm_counter(struct mm_struct *mm, int member)
{
	atomic_long_inc(&mm->rss_stat.count[member]);
}

static inline void dec_mm_counter(struct mm_struct *mm, int member)
{
	atomic_long_dec(&mm->rss_stat.count[member]);
}

static inline unsigned long get_mm_rss(struct mm_struct *mm)
{
	return get_mm_counter(mm, MM_FILEPAGES) +
		get_mm_counter(mm, MM_ANONPAGES);
}

static inline unsigned long get_mm_hiwater_rss(struct mm_struct *mm)
{
	return max(mm->hiwater_rss, get_mm_rss(mm));
}

static inline unsigned long get_mm_hiwater_vm(struct mm_struct *mm)
{
	return max(mm->hiwater_vm, mm->total_vm);
}

static inline void update_hiwater_rss(struct mm_struct *mm)
{
	unsigned long _rss = get_mm_rss(mm);

	if ((mm)->hiwater_rss < _rss)
		(mm)->hiwater_rss = _rss;
}

static inline void update_hiwater_vm(struct mm_struct *mm)
{
	if (mm->hiwater_vm < mm->total_vm)
		mm->hiwater_vm = mm->total_vm;
}

static inline void reset_mm_hiwater_rss(struct mm_struct *mm)
{
	mm->hiwater_rss = get_mm_rss(mm);
}

static inline void setmax_mm_hiwater_rss(unsigned long *maxrss,
					 struct mm_struct *mm)
{
	unsigned long hiwater_rss = get_mm_hiwater_rss(mm);

	if (*maxrss < hiwater_rss)
		*maxrss = hiwater_rss;
}

#if defined(SPLIT_RSS_COUNTING)
void sync_mm_rss(struct mm_struct *mm);
#else
static inline void sync_mm_rss(struct mm_struct *mm)
{
}
#endif

int vma_wants_writenotify(struct vm_area_struct *vma);

extern pte_t *__get_locked_pte(struct mm_struct *mm, unsigned long addr,
			       spinlock_t **ptl);
static inline pte_t *get_locked_pte(struct mm_struct *mm, unsigned long addr,
				    spinlock_t **ptl)
{
	pte_t *ptep;
	__cond_lock(*ptl, ptep = __get_locked_pte(mm, addr, ptl));
	return ptep;
}

#ifdef __PAGETABLE_PUD_FOLDED
static inline int __pud_alloc(struct mm_struct *mm, pgd_t *pgd,
						unsigned long address)
{
	return 0;
}
#else
int __pud_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address);
#endif

#if defined(__PAGETABLE_PMD_FOLDED) || !defined(CONFIG_MMU)
static inline int __pmd_alloc(struct mm_struct *mm, pud_t *pud,
						unsigned long address)
{
	return 0;
}

static inline void mm_nr_pmds_init(struct mm_struct *mm) {}

static inline unsigned long mm_nr_pmds(struct mm_struct *mm)
{
	return 0;
}

static inline void mm_inc_nr_pmds(struct mm_struct *mm) {}
static inline void mm_dec_nr_pmds(struct mm_struct *mm) {}

#else
int __pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address);

static inline void mm_nr_pmds_init(struct mm_struct *mm)
{
	atomic_long_set(&mm->nr_pmds, 0);
}

static inline unsigned long mm_nr_pmds(struct mm_struct *mm)
{
	return atomic_long_read(&mm->nr_pmds);
}

static inline void mm_inc_nr_pmds(struct mm_struct *mm)
{
	atomic_long_inc(&mm->nr_pmds);
}

static inline void mm_dec_nr_pmds(struct mm_struct *mm)
{
	atomic_long_dec(&mm->nr_pmds);
}
#endif

int __pte_alloc(struct mm_struct *mm, struct vm_area_struct *vma,
		pmd_t *pmd, unsigned long address);
int __pte_alloc_kernel(pmd_t *pmd, unsigned long address);

#if defined(CONFIG_MMU) && !defined(__ARCH_HAS_4LEVEL_HACK)
static inline pud_t *pud_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
	return (unlikely(pgd_none(*pgd)) && __pud_alloc(mm, pgd, address))?
		NULL: pud_offset(pgd, address);
}

static inline pmd_t *pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	return (unlikely(pud_none(*pud)) && __pmd_alloc(mm, pud, address))?
		NULL: pmd_offset(pud, address);
}
#endif  

#if USE_SPLIT_PTE_PTLOCKS
#if ALLOC_SPLIT_PTLOCKS
void __init ptlock_cache_init(void);
extern bool ptlock_alloc(struct page *page);
extern void ptlock_free(struct page *page);

static inline spinlock_t *ptlock_ptr(struct page *page)
{
	return page->ptl;
}
#else  
static inline void ptlock_cache_init(void)
{
}

static inline bool ptlock_alloc(struct page *page)
{
	return true;
}

static inline void ptlock_free(struct page *page)
{
}

static inline spinlock_t *ptlock_ptr(struct page *page)
{
	return &page->ptl;
}
#endif  

static inline spinlock_t *pte_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
	return ptlock_ptr(pmd_page(*pmd));
}

static inline bool ptlock_init(struct page *page)
{
	 
	VM_BUG_ON_PAGE(*(unsigned long *)&page->ptl, page);
	if (!ptlock_alloc(page))
		return false;
	spin_lock_init(ptlock_ptr(page));
	return true;
}

static inline void pte_lock_deinit(struct page *page)
{
	page->mapping = NULL;
	ptlock_free(page);
}

#else	 
 
static inline spinlock_t *pte_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
	return &mm->page_table_lock;
}
static inline void ptlock_cache_init(void) {}
static inline bool ptlock_init(struct page *page) { return true; }
static inline void pte_lock_deinit(struct page *page) {}
#endif  

static inline void pgtable_init(void)
{
	ptlock_cache_init();
	pgtable_cache_init();
}

static inline bool pgtable_page_ctor(struct page *page)
{
	if (!ptlock_init(page))
		return false;
	inc_zone_page_state(page, NR_PAGETABLE);
	return true;
}

static inline void pgtable_page_dtor(struct page *page)
{
	pte_lock_deinit(page);
	dec_zone_page_state(page, NR_PAGETABLE);
}

#define pte_offset_map_lock(mm, pmd, address, ptlp)	\
({							\
	spinlock_t *__ptl = pte_lockptr(mm, pmd);	\
	pte_t *__pte = pte_offset_map(pmd, address);	\
	*(ptlp) = __ptl;				\
	spin_lock(__ptl);				\
	__pte;						\
})

#define pte_unmap_unlock(pte, ptl)	do {		\
	spin_unlock(ptl);				\
	pte_unmap(pte);					\
} while (0)

#define pte_alloc_map(mm, vma, pmd, address)				\
	((unlikely(pmd_none(*(pmd))) && __pte_alloc(mm, vma,	\
							pmd, address))?	\
	 NULL: pte_offset_map(pmd, address))

#define pte_alloc_map_lock(mm, pmd, address, ptlp)	\
	((unlikely(pmd_none(*(pmd))) && __pte_alloc(mm, NULL,	\
							pmd, address))?	\
		NULL: pte_offset_map_lock(mm, pmd, address, ptlp))

#define pte_alloc_kernel(pmd, address)			\
	((unlikely(pmd_none(*(pmd))) && __pte_alloc_kernel(pmd, address))? \
		NULL: pte_offset_kernel(pmd, address))

#if USE_SPLIT_PMD_PTLOCKS

static struct page *pmd_to_page(pmd_t *pmd)
{
	unsigned long mask = ~(PTRS_PER_PMD * sizeof(pmd_t) - 1);
	return virt_to_page((void *)((unsigned long) pmd & mask));
}

static inline spinlock_t *pmd_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
	return ptlock_ptr(pmd_to_page(pmd));
}

static inline bool pgtable_pmd_page_ctor(struct page *page)
{
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	page->pmd_huge_pte = NULL;
#endif
	return ptlock_init(page);
}

static inline void pgtable_pmd_page_dtor(struct page *page)
{
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	VM_BUG_ON_PAGE(page->pmd_huge_pte, page);
#endif
	ptlock_free(page);
}

#define pmd_huge_pte(mm, pmd) (pmd_to_page(pmd)->pmd_huge_pte)

#else

static inline spinlock_t *pmd_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
	return &mm->page_table_lock;
}

static inline bool pgtable_pmd_page_ctor(struct page *page) { return true; }
static inline void pgtable_pmd_page_dtor(struct page *page) {}

#define pmd_huge_pte(mm, pmd) ((mm)->pmd_huge_pte)

#endif

static inline spinlock_t *pmd_lock(struct mm_struct *mm, pmd_t *pmd)
{
	spinlock_t *ptl = pmd_lockptr(mm, pmd);
	spin_lock(ptl);
	return ptl;
}

extern void free_area_init(unsigned long * zones_size);
extern void free_area_init_node(int nid, unsigned long * zones_size,
		unsigned long zone_start_pfn, unsigned long *zholes_size);
extern void free_initmem(void);

extern unsigned long free_reserved_area(void *start, void *end,
					int poison, char *s);

#ifdef	CONFIG_HIGHMEM
 
extern void free_highmem_page(struct page *page);
#endif

extern void adjust_managed_page_count(struct page *page, long count);
extern void mem_init_print_info(const char *str);

extern void reserve_bootmem_region(phys_addr_t start, phys_addr_t end);

static inline void __free_reserved_page(struct page *page)
{
	ClearPageReserved(page);
	init_page_count(page);
	__free_page(page);
}

static inline void free_reserved_page(struct page *page)
{
	__free_reserved_page(page);
	adjust_managed_page_count(page, 1);
}

static inline void mark_page_reserved(struct page *page)
{
	SetPageReserved(page);
	adjust_managed_page_count(page, -1);
}

static inline unsigned long free_initmem_default(int poison)
{
	extern char __init_begin[], __init_end[];

	return free_reserved_area(&__init_begin, &__init_end,
				  poison, "unused kernel");
}

static inline unsigned long get_num_physpages(void)
{
	int nid;
	unsigned long phys_pages = 0;

	for_each_online_node(nid)
		phys_pages += node_present_pages(nid);

	return phys_pages;
}

#ifdef CONFIG_HAVE_MEMBLOCK_NODE_MAP
 
extern void free_area_init_nodes(unsigned long *max_zone_pfn);
unsigned long node_map_pfn_alignment(void);
unsigned long __absent_pages_in_range(int nid, unsigned long start_pfn,
						unsigned long end_pfn);
extern unsigned long absent_pages_in_range(unsigned long start_pfn,
						unsigned long end_pfn);
extern void get_pfn_range_for_nid(unsigned int nid,
			unsigned long *start_pfn, unsigned long *end_pfn);
extern unsigned long find_min_pfn_with_active_regions(void);
extern void free_bootmem_with_active_regions(int nid,
						unsigned long max_low_pfn);
extern void sparse_memory_present_with_active_regions(int nid);

#endif  

#if !defined(CONFIG_HAVE_MEMBLOCK_NODE_MAP) && \
    !defined(CONFIG_HAVE_ARCH_EARLY_PFN_TO_NID)
static inline int __early_pfn_to_nid(unsigned long pfn,
					struct mminit_pfnnid_cache *state)
{
	return 0;
}
#else
 
extern int __meminit early_pfn_to_nid(unsigned long pfn);
 
extern int __meminit __early_pfn_to_nid(unsigned long pfn,
					struct mminit_pfnnid_cache *state);
#endif

extern void set_dma_reserve(unsigned long new_dma_reserve);
extern void memmap_init_zone(unsigned long, int, unsigned long,
				unsigned long, enum memmap_context);
extern void setup_per_zone_wmarks(void);
extern int __meminit init_per_zone_wmark_min(void);
extern void mem_init(void);
extern void __init mmap_init(void);
extern void show_mem(unsigned int flags);
extern long si_mem_available(void);
extern void si_meminfo(struct sysinfo * val);
extern void si_meminfo_node(struct sysinfo *val, int nid);

extern __printf(3, 4)
void warn_alloc_failed(gfp_t gfp_mask, unsigned int order,
		const char *fmt, ...);

extern void setup_per_cpu_pageset(void);

extern void zone_pcp_update(struct zone *zone);
extern void zone_pcp_reset(struct zone *zone);

extern int min_free_kbytes;

extern atomic_long_t mmap_pages_allocated;
extern int nommu_shrink_inode_mappings(struct inode *, size_t, size_t);

void vma_interval_tree_insert(struct vm_area_struct *node,
			      struct rb_root *root);
void vma_interval_tree_insert_after(struct vm_area_struct *node,
				    struct vm_area_struct *prev,
				    struct rb_root *root);
void vma_interval_tree_remove(struct vm_area_struct *node,
			      struct rb_root *root);
struct vm_area_struct *vma_interval_tree_iter_first(struct rb_root *root,
				unsigned long start, unsigned long last);
struct vm_area_struct *vma_interval_tree_iter_next(struct vm_area_struct *node,
				unsigned long start, unsigned long last);

#define vma_interval_tree_foreach(vma, root, start, last)		\
	for (vma = vma_interval_tree_iter_first(root, start, last);	\
	     vma; vma = vma_interval_tree_iter_next(vma, start, last))

void anon_vma_interval_tree_insert(struct anon_vma_chain *node,
				   struct rb_root *root);
void anon_vma_interval_tree_remove(struct anon_vma_chain *node,
				   struct rb_root *root);
struct anon_vma_chain *anon_vma_interval_tree_iter_first(
	struct rb_root *root, unsigned long start, unsigned long last);
struct anon_vma_chain *anon_vma_interval_tree_iter_next(
	struct anon_vma_chain *node, unsigned long start, unsigned long last);
#ifdef CONFIG_DEBUG_VM_RB
void anon_vma_interval_tree_verify(struct anon_vma_chain *node);
#endif

#define anon_vma_interval_tree_foreach(avc, root, start, last)		 \
	for (avc = anon_vma_interval_tree_iter_first(root, start, last); \
	     avc; avc = anon_vma_interval_tree_iter_next(avc, start, last))

extern int __vm_enough_memory(struct mm_struct *mm, long pages, int cap_sys_admin);
extern int vma_adjust(struct vm_area_struct *vma, unsigned long start,
	unsigned long end, pgoff_t pgoff, struct vm_area_struct *insert);
extern struct vm_area_struct *vma_merge(struct mm_struct *,
	struct vm_area_struct *prev, unsigned long addr, unsigned long end,
	unsigned long vm_flags, struct anon_vma *, struct file *, pgoff_t,
	struct mempolicy *, struct vm_userfaultfd_ctx);
extern struct anon_vma *find_mergeable_anon_vma(struct vm_area_struct *);
extern int split_vma(struct mm_struct *,
	struct vm_area_struct *, unsigned long addr, int new_below);
extern int insert_vm_struct(struct mm_struct *, struct vm_area_struct *);
extern void __vma_link_rb(struct mm_struct *, struct vm_area_struct *,
	struct rb_node **, struct rb_node *);
extern void unlink_file_vma(struct vm_area_struct *);
extern struct vm_area_struct *copy_vma(struct vm_area_struct **,
	unsigned long addr, unsigned long len, pgoff_t pgoff,
	bool *need_rmap_locks);
extern void exit_mmap(struct mm_struct *);

static inline int check_data_rlimit(unsigned long rlim,
				    unsigned long new,
				    unsigned long start,
				    unsigned long end_data,
				    unsigned long start_data)
{
	if (rlim < RLIM_INFINITY) {
		if (((new - start) + (end_data - start_data)) > rlim)
			return -ENOSPC;
	}

	return 0;
}

extern int mm_take_all_locks(struct mm_struct *mm);
extern void mm_drop_all_locks(struct mm_struct *mm);

extern void set_mm_exe_file(struct mm_struct *mm, struct file *new_exe_file);
extern struct file *get_mm_exe_file(struct mm_struct *mm);
extern struct file *get_task_exe_file(struct task_struct *task);

extern int may_expand_vm(struct mm_struct *mm, unsigned long npages);
extern struct vm_area_struct *_install_special_mapping(struct mm_struct *mm,
				   unsigned long addr, unsigned long len,
				   unsigned long flags,
				   const struct vm_special_mapping *spec);
 
extern int install_special_mapping(struct mm_struct *mm,
				   unsigned long addr, unsigned long len,
				   unsigned long flags, struct page **pages);

extern unsigned long get_unmapped_area(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);

extern unsigned long mmap_region(struct file *file, unsigned long addr,
	unsigned long len, vm_flags_t vm_flags, unsigned long pgoff);
extern unsigned long do_mmap(struct file *file, unsigned long addr,
	unsigned long len, unsigned long prot, unsigned long flags,
	vm_flags_t vm_flags, unsigned long pgoff, unsigned long *populate);
extern int do_munmap(struct mm_struct *, unsigned long, size_t);

static inline unsigned long
do_mmap_pgoff(struct file *file, unsigned long addr,
	unsigned long len, unsigned long prot, unsigned long flags,
	unsigned long pgoff, unsigned long *populate)
{
	return do_mmap(file, addr, len, prot, flags, 0, pgoff, populate);
}

#ifdef CONFIG_MMU
extern int __mm_populate(unsigned long addr, unsigned long len,
			 int ignore_errors);
static inline void mm_populate(unsigned long addr, unsigned long len)
{
	 
	(void) __mm_populate(addr, len, 1);
}
#else
static inline void mm_populate(unsigned long addr, unsigned long len) {}
#endif

extern unsigned long vm_brk(unsigned long, unsigned long);
extern int vm_munmap(unsigned long, size_t);
extern unsigned long vm_mmap(struct file *, unsigned long,
        unsigned long, unsigned long,
        unsigned long, unsigned long);

struct vm_unmapped_area_info {
#define VM_UNMAPPED_AREA_TOPDOWN 1
	unsigned long flags;
	unsigned long length;
	unsigned long low_limit;
	unsigned long high_limit;
	unsigned long align_mask;
	unsigned long align_offset;
};

extern unsigned long unmapped_area(struct vm_unmapped_area_info *info);
extern unsigned long unmapped_area_topdown(struct vm_unmapped_area_info *info);

static inline unsigned long
vm_unmapped_area(struct vm_unmapped_area_info *info)
{
	if (info->flags & VM_UNMAPPED_AREA_TOPDOWN)
		return unmapped_area_topdown(info);
	else
		return unmapped_area(info);
}

extern void truncate_inode_pages(struct address_space *, loff_t);
extern void truncate_inode_pages_range(struct address_space *,
				       loff_t lstart, loff_t lend);
extern void truncate_inode_pages_final(struct address_space *);

extern int filemap_fault(struct vm_area_struct *, struct vm_fault *);
extern void filemap_map_pages(struct vm_area_struct *vma, struct vm_fault *vmf);
extern int filemap_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf);

int write_one_page(struct page *page, int wait);
void task_dirty_inc(struct task_struct *tsk);

#ifdef MY_ABC_HERE
#define VM_MAX_READAHEAD        CONFIG_SYNO_MAX_READAHEAD_SIZE
#else  
#define VM_MAX_READAHEAD	128	 
#endif  
#define VM_MIN_READAHEAD	16	 

int force_page_cache_readahead(struct address_space *mapping, struct file *filp,
			pgoff_t offset, unsigned long nr_to_read);

void page_cache_sync_readahead(struct address_space *mapping,
			       struct file_ra_state *ra,
			       struct file *filp,
			       pgoff_t offset,
			       unsigned long size);

void page_cache_async_readahead(struct address_space *mapping,
				struct file_ra_state *ra,
				struct file *filp,
				struct page *pg,
				pgoff_t offset,
				unsigned long size);

extern unsigned long stack_guard_gap;
 
extern int expand_stack(struct vm_area_struct *vma, unsigned long address);

extern int expand_downwards(struct vm_area_struct *vma,
		unsigned long address);
#if VM_GROWSUP
extern int expand_upwards(struct vm_area_struct *vma, unsigned long address);
#else
  #define expand_upwards(vma, address) (0)
#endif

extern struct vm_area_struct * find_vma(struct mm_struct * mm, unsigned long addr);
extern struct vm_area_struct * find_vma_prev(struct mm_struct * mm, unsigned long addr,
					     struct vm_area_struct **pprev);

static inline struct vm_area_struct * find_vma_intersection(struct mm_struct * mm, unsigned long start_addr, unsigned long end_addr)
{
	struct vm_area_struct * vma = find_vma(mm,start_addr);

	if (vma && end_addr <= vma->vm_start)
		vma = NULL;
	return vma;
}

static inline unsigned long vm_start_gap(struct vm_area_struct *vma)
{
	unsigned long vm_start = vma->vm_start;

	if (vma->vm_flags & VM_GROWSDOWN) {
		vm_start -= stack_guard_gap;
		if (vm_start > vma->vm_start)
			vm_start = 0;
	}
	return vm_start;
}

static inline unsigned long vm_end_gap(struct vm_area_struct *vma)
{
	unsigned long vm_end = vma->vm_end;

	if (vma->vm_flags & VM_GROWSUP) {
		vm_end += stack_guard_gap;
		if (vm_end < vma->vm_end)
			vm_end = -PAGE_SIZE;
	}
	return vm_end;
}

static inline unsigned long vma_pages(struct vm_area_struct *vma)
{
	return (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
}

static inline struct vm_area_struct *find_exact_vma(struct mm_struct *mm,
				unsigned long vm_start, unsigned long vm_end)
{
	struct vm_area_struct *vma = find_vma(mm, vm_start);

	if (vma && (vma->vm_start != vm_start || vma->vm_end != vm_end))
		vma = NULL;

	return vma;
}

#ifdef CONFIG_MMU
pgprot_t vm_get_page_prot(unsigned long vm_flags);
void vma_set_page_prot(struct vm_area_struct *vma);
#else
static inline pgprot_t vm_get_page_prot(unsigned long vm_flags)
{
	return __pgprot(0);
}
static inline void vma_set_page_prot(struct vm_area_struct *vma)
{
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
}
#endif

#ifdef CONFIG_NUMA_BALANCING
unsigned long change_prot_numa(struct vm_area_struct *vma,
			unsigned long start, unsigned long end);
#endif

struct vm_area_struct *find_extend_vma(struct mm_struct *, unsigned long addr);
int remap_pfn_range(struct vm_area_struct *, unsigned long addr,
			unsigned long pfn, unsigned long size, pgprot_t);
int vm_insert_page(struct vm_area_struct *, unsigned long addr, struct page *);
int vm_insert_pfn(struct vm_area_struct *vma, unsigned long addr,
			unsigned long pfn);
int vm_insert_mixed(struct vm_area_struct *vma, unsigned long addr,
			unsigned long pfn);
int vm_iomap_memory(struct vm_area_struct *vma, phys_addr_t start, unsigned long len);

struct page *follow_page_mask(struct vm_area_struct *vma,
			      unsigned long address, unsigned int foll_flags,
			      unsigned int *page_mask);

static inline struct page *follow_page(struct vm_area_struct *vma,
		unsigned long address, unsigned int foll_flags)
{
	unsigned int unused_page_mask;
	return follow_page_mask(vma, address, foll_flags, &unused_page_mask);
}

#define FOLL_WRITE	0x01	 
#define FOLL_TOUCH	0x02	 
#define FOLL_GET	0x04	 
#define FOLL_DUMP	0x08	 
#define FOLL_FORCE	0x10	 
#define FOLL_NOWAIT	0x20	 
#define FOLL_POPULATE	0x40	 
#define FOLL_SPLIT	0x80	 
#define FOLL_HWPOISON	0x100	 
#define FOLL_NUMA	0x200	 
#define FOLL_MIGRATION	0x400	 
#define FOLL_TRIED	0x800	 
#define FOLL_MLOCK	0x1000	 
#define FOLL_REMOTE	0x2000	 
#define FOLL_COW	0x4000	 

typedef int (*pte_fn_t)(pte_t *pte, pgtable_t token, unsigned long addr,
			void *data);
extern int apply_to_page_range(struct mm_struct *mm, unsigned long address,
			       unsigned long size, pte_fn_t fn, void *data);

#ifdef CONFIG_PROC_FS
void vm_stat_account(struct mm_struct *, unsigned long, struct file *, long);
#else
static inline void vm_stat_account(struct mm_struct *mm,
			unsigned long flags, struct file *file, long pages)
{
	mm->total_vm += pages;
}
#endif  

#ifdef CONFIG_DEBUG_PAGEALLOC
extern bool _debug_pagealloc_enabled;
extern void __kernel_map_pages(struct page *page, int numpages, int enable);

static inline bool debug_pagealloc_enabled(void)
{
	return _debug_pagealloc_enabled;
}

static inline void
kernel_map_pages(struct page *page, int numpages, int enable)
{
	if (!debug_pagealloc_enabled())
		return;

	__kernel_map_pages(page, numpages, enable);
}
#ifdef CONFIG_HIBERNATION
extern bool kernel_page_present(struct page *page);
#endif  
#else
static inline void
kernel_map_pages(struct page *page, int numpages, int enable) {}
#ifdef CONFIG_HIBERNATION
static inline bool kernel_page_present(struct page *page) { return true; }
#endif  
#endif

#ifdef __HAVE_ARCH_GATE_AREA
extern struct vm_area_struct *get_gate_vma(struct mm_struct *mm);
extern int in_gate_area_no_mm(unsigned long addr);
extern int in_gate_area(struct mm_struct *mm, unsigned long addr);
#else
static inline struct vm_area_struct *get_gate_vma(struct mm_struct *mm)
{
	return NULL;
}
static inline int in_gate_area_no_mm(unsigned long addr) { return 0; }
static inline int in_gate_area(struct mm_struct *mm, unsigned long addr)
{
	return 0;
}
#endif	 

#ifdef CONFIG_SYSCTL
extern int sysctl_drop_caches;
int drop_caches_sysctl_handler(struct ctl_table *, int,
					void __user *, size_t *, loff_t *);
#endif

void drop_slab(void);
void drop_slab_node(int nid);

#ifndef CONFIG_MMU
#define randomize_va_space 0
#else
extern int randomize_va_space;
#endif

const char * arch_vma_name(struct vm_area_struct *vma);
void print_vma_addr(char *prefix, unsigned long rip);

void sparse_mem_maps_populate_node(struct page **map_map,
				   unsigned long pnum_begin,
				   unsigned long pnum_end,
				   unsigned long map_count,
				   int nodeid);

struct page *sparse_mem_map_populate(unsigned long pnum, int nid);
pgd_t *vmemmap_pgd_populate(unsigned long addr, int node);
pud_t *vmemmap_pud_populate(pgd_t *pgd, unsigned long addr, int node);
pmd_t *vmemmap_pmd_populate(pud_t *pud, unsigned long addr, int node);
pte_t *vmemmap_pte_populate(pmd_t *pmd, unsigned long addr, int node);
void *vmemmap_alloc_block(unsigned long size, int node);
void *vmemmap_alloc_block_buf(unsigned long size, int node);
void vmemmap_verify(pte_t *, int, unsigned long, unsigned long);
int vmemmap_populate_basepages(unsigned long start, unsigned long end,
			       int node);
int vmemmap_populate(unsigned long start, unsigned long end, int node);
void vmemmap_populate_print_last(void);
#ifdef CONFIG_MEMORY_HOTPLUG
void vmemmap_free(unsigned long start, unsigned long end);
#endif
void register_page_bootmem_memmap(unsigned long section_nr, struct page *map,
				  unsigned long size);

enum mf_flags {
	MF_COUNT_INCREASED = 1 << 0,
	MF_ACTION_REQUIRED = 1 << 1,
	MF_MUST_KILL = 1 << 2,
	MF_SOFT_OFFLINE = 1 << 3,
};
extern int memory_failure(unsigned long pfn, int trapno, int flags);
extern void memory_failure_queue(unsigned long pfn, int trapno, int flags);
extern int unpoison_memory(unsigned long pfn);
extern int get_hwpoison_page(struct page *page);
extern void put_hwpoison_page(struct page *page);
extern int sysctl_memory_failure_early_kill;
extern int sysctl_memory_failure_recovery;
extern void shake_page(struct page *p, int access);
extern atomic_long_t num_poisoned_pages;
extern int soft_offline_page(struct page *page, int flags);

enum mf_result {
	MF_IGNORED,	 
	MF_FAILED,	 
	MF_DELAYED,	 
	MF_RECOVERED,	 
};

enum mf_action_page_type {
	MF_MSG_KERNEL,
	MF_MSG_KERNEL_HIGH_ORDER,
	MF_MSG_SLAB,
	MF_MSG_DIFFERENT_COMPOUND,
	MF_MSG_POISONED_HUGE,
	MF_MSG_HUGE,
	MF_MSG_FREE_HUGE,
	MF_MSG_UNMAP_FAILED,
	MF_MSG_DIRTY_SWAPCACHE,
	MF_MSG_CLEAN_SWAPCACHE,
	MF_MSG_DIRTY_MLOCKED_LRU,
	MF_MSG_CLEAN_MLOCKED_LRU,
	MF_MSG_DIRTY_UNEVICTABLE_LRU,
	MF_MSG_CLEAN_UNEVICTABLE_LRU,
	MF_MSG_DIRTY_LRU,
	MF_MSG_CLEAN_LRU,
	MF_MSG_TRUNCATED_LRU,
	MF_MSG_BUDDY,
	MF_MSG_BUDDY_2ND,
	MF_MSG_UNKNOWN,
};

#if defined(CONFIG_TRANSPARENT_HUGEPAGE) || defined(CONFIG_HUGETLBFS)
extern void clear_huge_page(struct page *page,
			    unsigned long addr,
			    unsigned int pages_per_huge_page);
extern void copy_user_huge_page(struct page *dst, struct page *src,
				unsigned long addr, struct vm_area_struct *vma,
				unsigned int pages_per_huge_page);
#endif  

extern struct page_ext_operations debug_guardpage_ops;
extern struct page_ext_operations page_poisoning_ops;

#ifdef CONFIG_DEBUG_PAGEALLOC
extern unsigned int _debug_guardpage_minorder;
extern bool _debug_guardpage_enabled;

static inline unsigned int debug_guardpage_minorder(void)
{
	return _debug_guardpage_minorder;
}

static inline bool debug_guardpage_enabled(void)
{
	return _debug_guardpage_enabled;
}

static inline bool page_is_guard(struct page *page)
{
	struct page_ext *page_ext;

	if (!debug_guardpage_enabled())
		return false;

	page_ext = lookup_page_ext(page);
	return test_bit(PAGE_EXT_DEBUG_GUARD, &page_ext->flags);
}
#else
static inline unsigned int debug_guardpage_minorder(void) { return 0; }
static inline bool debug_guardpage_enabled(void) { return false; }
static inline bool page_is_guard(struct page *page) { return false; }
#endif  

#if MAX_NUMNODES > 1
void __init setup_nr_node_ids(void);
#else
static inline void setup_nr_node_ids(void) {}
#endif

#endif  
#endif  
