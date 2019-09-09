#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
/*
 * Based on arch/arm/include/asm/io.h
 *
 * Copyright (C) 1996-2000 Russell King
 * Copyright (C) 2012 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __ASM_IO_H
#define __ASM_IO_H

#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/blk_types.h>

#include <asm/byteorder.h>
#include <asm/barrier.h>
#include <asm/memory.h>
#include <asm/pgtable.h>
#include <asm/early_ioremap.h>
#include <asm/alternative.h>
#include <asm/cpufeature.h>

#include <xen/xen.h>

#if defined(CONFIG_PCIE_RTD1295) && defined(MY_DEF_HERE)
u8 rtk_pcie1_readb(const volatile void __iomem *addr);
u16 rtk_pcie1_readw(const volatile void __iomem *addr);
u32 rtk_pcie1_readl(const volatile void __iomem *addr);
u64 rtk_pcie1_readq(const volatile void __iomem *addr);

void rtk_pcie1_writeb(u8 val, volatile void __iomem *addr);
void rtk_pcie1_writew(u16 val, volatile void __iomem *addr);
void rtk_pcie1_writel(u32 val, volatile void __iomem *addr);
void rtk_pcie1_writeq(u64 val, volatile void __iomem *addr);

static inline int is_pcie1_memory(u64 addr)
{
	return ((addr & 0xfffffffff1000000) == 0xc0000000);
}
#endif /* CONFIG_PCIE_RTD1295 && MY_DEF_HERE */

#if defined(CONFIG_PCIE2_RTD1295) && defined(MY_DEF_HERE)
u8 rtk_pcie2_readb(const volatile void __iomem *addr);
u16 rtk_pcie2_readw(const volatile void __iomem *addr);
u32 rtk_pcie2_readl(const volatile void __iomem *addr);
u64 rtk_pcie2_readq(const volatile void __iomem *addr);

void rtk_pcie2_writeb(u8 val, volatile void __iomem *addr);
void rtk_pcie2_writew(u16 val, volatile void __iomem *addr);
void rtk_pcie2_writel(u32 val, volatile void __iomem *addr);
void rtk_pcie2_writeq(u64 val, volatile void __iomem *addr);

static inline int is_pcie2_memory(u64 addr)
{
	return ((addr & 0xfffffffff1000000) == 0xc1000000);
}
#endif /* CONFIG_PCIE2_RTD1295 && MY_DEF_HERE */

/*
 * Generic IO read/write.  These perform native-endian accesses.
 */
#define __raw_writeb __raw_writeb
static inline void __raw_writeb(u8 val, volatile void __iomem *addr)
{
	asm volatile("strb %w0, [%1]" : : "r" (val), "r" (addr));
}

#define __raw_writew __raw_writew
static inline void __raw_writew(u16 val, volatile void __iomem *addr)
{
	asm volatile("strh %w0, [%1]" : : "r" (val), "r" (addr));
}

#define __raw_writel __raw_writel
static inline void __raw_writel(u32 val, volatile void __iomem *addr)
{
	asm volatile("str %w0, [%1]" : : "r" (val), "r" (addr));
}

#define __raw_writeq __raw_writeq
static inline void __raw_writeq(u64 val, volatile void __iomem *addr)
{
	asm volatile("str %0, [%1]" : : "r" (val), "r" (addr));
}

#define __raw_readb __raw_readb
static inline u8 __raw_readb(const volatile void __iomem *addr)
{
	u8 val;
	asm volatile(ALTERNATIVE("ldrb %w0, [%1]",
				 "ldarb %w0, [%1]",
				 ARM64_WORKAROUND_DEVICE_LOAD_ACQUIRE)
		     : "=r" (val) : "r" (addr));
	return val;
}

#define __raw_readw __raw_readw
static inline u16 __raw_readw(const volatile void __iomem *addr)
{
	u16 val;

	asm volatile(ALTERNATIVE("ldrh %w0, [%1]",
				 "ldarh %w0, [%1]",
				 ARM64_WORKAROUND_DEVICE_LOAD_ACQUIRE)
		     : "=r" (val) : "r" (addr));
	return val;
}

#define __raw_readl __raw_readl
static inline u32 __raw_readl(const volatile void __iomem *addr)
{
	u32 val;
	asm volatile(ALTERNATIVE("ldr %w0, [%1]",
				 "ldar %w0, [%1]",
				 ARM64_WORKAROUND_DEVICE_LOAD_ACQUIRE)
		     : "=r" (val) : "r" (addr));
	return val;
}

#define __raw_readq __raw_readq
static inline u64 __raw_readq(const volatile void __iomem *addr)
{
	u64 val;
	asm volatile(ALTERNATIVE("ldr %0, [%1]",
				 "ldar %0, [%1]",
				 ARM64_WORKAROUND_DEVICE_LOAD_ACQUIRE)
		     : "=r" (val) : "r" (addr));
	return val;
}

/* IO barriers */
#define __iormb()		rmb()
#define __iowmb()		wmb()

#define mmiowb()		do { } while (0)

/*
 * Relaxed I/O memory access primitives. These follow the Device memory
 * ordering rules but do not guarantee any ordering relative to Normal memory
 * accesses.
 */
#define readb_relaxed(c)	({ u8  __r = __raw_readb(c); __r; })
#define readw_relaxed(c)	({ u16 __r = le16_to_cpu((__force __le16)__raw_readw(c)); __r; })
#define readl_relaxed(c)	({ u32 __r = le32_to_cpu((__force __le32)__raw_readl(c)); __r; })
#define readq_relaxed(c)	({ u64 __r = le64_to_cpu((__force __le64)__raw_readq(c)); __r; })

#define writeb_relaxed(v,c)	((void)__raw_writeb((v),(c)))
#define writew_relaxed(v,c)	((void)__raw_writew((__force u16)cpu_to_le16(v),(c)))
#define writel_relaxed(v,c)	((void)__raw_writel((__force u32)cpu_to_le32(v),(c)))
#define writeq_relaxed(v,c)	((void)__raw_writeq((__force u64)cpu_to_le64(v),(c)))

/*
 * I/O memory access primitives. Reads are ordered relative to any
 * following Normal memory access. Writes are ordered relative to any prior
 * Normal memory access.
 */
#ifdef MY_DEF_HERE

#define readb_raw(c)		({ u8  __v = readb_relaxed(c); __iormb(); __v; })
#define readw_raw(c)		({ u16 __v = readw_relaxed(c); __iormb(); __v; })
#define readl_raw(c)		({ u32 __v = readl_relaxed(c); __iormb(); __v; })
#define readq_raw(c)		({ u64 __v = readq_relaxed(c); __iormb(); __v; })

#define writeb_raw(v,c)		({ __iowmb(); writeb_relaxed((v),(c)); })
#define writew_raw(v,c)		({ __iowmb(); writew_relaxed((v),(c)); })
#define writel_raw(v,c)		({ __iowmb(); writel_relaxed((v),(c)); })
#define writeq_raw(v,c)		({ __iowmb(); writeq_relaxed((v),(c)); })

#define readb readb
static inline u8 readb(const volatile void __iomem *addr)
{
#ifdef CONFIG_PCIE_RTD1295
	if (is_pcie1_memory((u64)addr))
		return rtk_pcie1_readb(addr);
#endif

#ifdef CONFIG_PCIE2_RTD1295
	if (is_pcie2_memory((u64)addr))
		return rtk_pcie2_readb(addr);
#endif

	return readb_raw(addr);
}

#define readw readw
static inline u16 readw(const volatile void __iomem *addr)
{
#ifdef CONFIG_PCIE_RTD1295
	if (is_pcie1_memory((u64)addr))
		return rtk_pcie1_readw(addr);
#endif

#ifdef CONFIG_PCIE2_RTD1295
	if (is_pcie2_memory((u64)addr))
		return rtk_pcie2_readw(addr);
#endif

	return readw_raw(addr);
}

#define readl readl
static inline u32 readl(const volatile void __iomem *addr)
{
#ifdef CONFIG_PCIE_RTD1295
	if (is_pcie1_memory((u64)addr))
		return rtk_pcie1_readl(addr);
#endif

#ifdef CONFIG_PCIE2_RTD1295
	if (is_pcie2_memory((u64)addr))
		return rtk_pcie2_readl(addr);
#endif

	return readl_raw(addr);
}

#define readq readq
static inline u64 readq(const volatile void __iomem *addr)
{
#ifdef CONFIG_PCIE_RTD1295
	if (is_pcie1_memory((u64)addr))
		return rtk_pcie1_readq(addr);
#endif

#ifdef CONFIG_PCIE2_RTD1295
	if (is_pcie2_memory((u64)addr))
		return rtk_pcie2_readq(addr);
#endif

	return readq_raw(addr);
}

#define writeb writeb
static inline void writeb(u8 val, volatile void __iomem *addr)
{
#ifdef CONFIG_PCIE_RTD1295
	if (is_pcie1_memory((u64)addr)) {
		rtk_pcie1_writeb(val, addr);
		return;
	}
#endif

#ifdef CONFIG_PCIE2_RTD1295
	if (is_pcie2_memory((u64)addr)) {
		rtk_pcie2_writeb(val, addr);
		return;
	}
#endif

	writeb_raw(val, addr);
}

#define writew writew
static inline void writew(u16 val, volatile void __iomem *addr)
{
#ifdef CONFIG_PCIE_RTD1295
	if (is_pcie1_memory((u64)addr)) {
		rtk_pcie1_writew(val, addr);
		return;
	}
#endif

#ifdef CONFIG_PCIE2_RTD1295
	if (is_pcie2_memory((u64)addr)) {
		rtk_pcie2_writew(val, addr);
		return;
	}
#endif

	writew_raw(val, addr);
}

#define writel writel
static inline void writel(u32 val, volatile void __iomem *addr)
{
#ifdef CONFIG_PCIE_RTD1295
	if (is_pcie1_memory((u64)addr)) {
		rtk_pcie1_writel(val, addr);
		return;
	}
#endif

#ifdef CONFIG_PCIE2_RTD1295
	if (is_pcie2_memory((u64)addr)) {
		rtk_pcie2_writel(val, addr);
		return;
	}
#endif

	writel_raw(val, addr);
}

#define writeq writeq
static inline void writeq(u64 val, volatile void __iomem *addr)
{
#ifdef CONFIG_PCIE_RTD1295
	if (is_pcie1_memory((u64)addr)) {
		rtk_pcie1_writeq(val, addr);
		return;
	}
#endif

#ifdef CONFIG_PCIE2_RTD1295
	if (is_pcie2_memory((u64)addr)) {
		rtk_pcie2_writeq(val, addr);
		return;
	}
#endif

	writeq_raw(val, addr);
}

#else /* MY_DEF_HERE */

#define readb(c)		({ u8  __v = readb_relaxed(c); __iormb(); __v; })
#define readw(c)		({ u16 __v = readw_relaxed(c); __iormb(); __v; })
#define readl(c)		({ u32 __v = readl_relaxed(c); __iormb(); __v; })
#define readq(c)		({ u64 __v = readq_relaxed(c); __iormb(); __v; })

#define writeb(v,c)		({ __iowmb(); writeb_relaxed((v),(c)); })
#define writew(v,c)		({ __iowmb(); writew_relaxed((v),(c)); })
#define writel(v,c)		({ __iowmb(); writel_relaxed((v),(c)); })
#define writeq(v,c)		({ __iowmb(); writeq_relaxed((v),(c)); })

#endif /* MY_DEF_HERE */
/*
 *  I/O port access primitives.
 */
#define arch_has_dev_port()	(1)
#define IO_SPACE_LIMIT		(PCI_IO_SIZE - 1)
#define PCI_IOBASE		((void __iomem *)PCI_IO_START)

/*
 * String version of I/O memory access operations.
 */
extern void __memcpy_fromio(void *, const volatile void __iomem *, size_t);
extern void __memcpy_toio(volatile void __iomem *, const void *, size_t);
extern void __memset_io(volatile void __iomem *, int, size_t);

#define memset_io(c,v,l)	__memset_io((c),(v),(l))
#define memcpy_fromio(a,c,l)	__memcpy_fromio((a),(c),(l))
#define memcpy_toio(c,a,l)	__memcpy_toio((c),(a),(l))

/*
 * I/O memory mapping functions.
 */
extern void __iomem *__ioremap(phys_addr_t phys_addr, size_t size, pgprot_t prot);
extern void __iounmap(volatile void __iomem *addr);
extern void __iomem *ioremap_cache(phys_addr_t phys_addr, size_t size);

#define ioremap(addr, size)		__ioremap((addr), (size), __pgprot(PROT_DEVICE_nGnRE))
#define ioremap_nocache(addr, size)	__ioremap((addr), (size), __pgprot(PROT_DEVICE_nGnRE))
#define ioremap_wc(addr, size)		__ioremap((addr), (size), __pgprot(PROT_NORMAL_NC))
#define ioremap_wt(addr, size)		__ioremap((addr), (size), __pgprot(PROT_DEVICE_nGnRE))
#define iounmap				__iounmap

/*
 * io{read,write}{16,32}be() macros
 */
#define ioread16be(p)		({ __u16 __v = be16_to_cpu((__force __be16)__raw_readw(p)); __iormb(); __v; })
#define ioread32be(p)		({ __u32 __v = be32_to_cpu((__force __be32)__raw_readl(p)); __iormb(); __v; })

#define iowrite16be(v,p)	({ __iowmb(); __raw_writew((__force __u16)cpu_to_be16(v), p); })
#define iowrite32be(v,p)	({ __iowmb(); __raw_writel((__force __u32)cpu_to_be32(v), p); })

/*
 * Convert a physical pointer to a virtual kernel pointer for /dev/mem
 * access
 */
#define xlate_dev_mem_ptr(p)	__va(p)

/*
 * Convert a virtual cached pointer to an uncached pointer
 */
#define xlate_dev_kmem_ptr(p)	p

#include <asm-generic/io.h>

/*
 * More restrictive address range checking than the default implementation
 * (PHYS_OFFSET and PHYS_MASK taken into account).
 */
#define ARCH_HAS_VALID_PHYS_ADDR_RANGE
extern int valid_phys_addr_range(phys_addr_t addr, size_t size);
extern int valid_mmap_phys_addr_range(unsigned long pfn, size_t size);

extern int devmem_is_allowed(unsigned long pfn);

struct bio_vec;
extern bool xen_biovec_phys_mergeable(const struct bio_vec *vec1,
				      const struct bio_vec *vec2);
#define BIOVEC_PHYS_MERGEABLE(vec1, vec2)				\
	(__BIOVEC_PHYS_MERGEABLE(vec1, vec2) &&				\
	 (!xen_domain() || xen_biovec_phys_mergeable(vec1, vec2)))

#endif	/* __KERNEL__ */
#endif	/* __ASM_IO_H */
