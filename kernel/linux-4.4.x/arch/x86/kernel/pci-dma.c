#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#include <linux/dma-mapping.h>
#include <linux/dma-debug.h>
#include <linux/dmar.h>
#include <linux/export.h>
#include <linux/bootmem.h>
#include <linux/gfp.h>
#include <linux/pci.h>
#include <linux/kmemleak.h>

#include <asm/proto.h>
#include <asm/dma.h>
#include <asm/iommu.h>
#include <asm/gart.h>
#include <asm/calgary.h>
#include <asm/x86_init.h>
#include <asm/iommu_table.h>

static int forbid_dac __read_mostly;

struct dma_map_ops *dma_ops = &nommu_dma_ops;
EXPORT_SYMBOL(dma_ops);

static int iommu_sac_force __read_mostly;

#ifdef CONFIG_IOMMU_DEBUG
int panic_on_overflow __read_mostly = 1;
int force_iommu __read_mostly = 1;
#else
int panic_on_overflow __read_mostly = 0;
int force_iommu __read_mostly = 0;
#endif

int iommu_merge __read_mostly = 0;

int no_iommu __read_mostly;
 
int iommu_detected __read_mostly = 0;

#ifdef MY_DEF_HERE
int iommu_pass_through __read_mostly = 1;
#else  
int iommu_pass_through __read_mostly;
#endif  

extern struct iommu_table_entry __iommu_table[], __iommu_table_end[];

struct device x86_dma_fallback_dev = {
	.init_name = "fallback device",
	.coherent_dma_mask = ISA_DMA_BIT_MASK,
	.dma_mask = &x86_dma_fallback_dev.coherent_dma_mask,
};
EXPORT_SYMBOL(x86_dma_fallback_dev);

#define PREALLOC_DMA_DEBUG_ENTRIES       65536

void __init pci_iommu_alloc(void)
{
	struct iommu_table_entry *p;

	sort_iommu_table(__iommu_table, __iommu_table_end);
	check_iommu_entries(__iommu_table, __iommu_table_end);

	for (p = __iommu_table; p < __iommu_table_end; p++) {
		if (p && p->detect && p->detect() > 0) {
			p->flags |= IOMMU_DETECTED;
			if (p->early_init)
				p->early_init();
			if (p->flags & IOMMU_FINISH_IF_DETECTED)
				break;
		}
	}
}
void *dma_generic_alloc_coherent(struct device *dev, size_t size,
				 dma_addr_t *dma_addr, gfp_t flag,
				 struct dma_attrs *attrs)
{
	unsigned long dma_mask;
	struct page *page;
	unsigned int count = PAGE_ALIGN(size) >> PAGE_SHIFT;
	dma_addr_t addr;

	dma_mask = dma_alloc_coherent_mask(dev, flag);

	flag &= ~__GFP_ZERO;
again:
	page = NULL;
	 
	if (gfpflags_allow_blocking(flag)) {
		page = dma_alloc_from_contiguous(dev, count, get_order(size));
		if (page && page_to_phys(page) + size > dma_mask) {
			dma_release_from_contiguous(dev, page, count);
			page = NULL;
		}
	}
	 
	if (!page)
		page = alloc_pages_node(dev_to_node(dev), flag, get_order(size));
	if (!page)
		return NULL;

	addr = page_to_phys(page);
	if (addr + size > dma_mask) {
		__free_pages(page, get_order(size));

		if (dma_mask < DMA_BIT_MASK(32) && !(flag & GFP_DMA)) {
			flag = (flag & ~GFP_DMA32) | GFP_DMA;
			goto again;
		}

		return NULL;
	}
	memset(page_address(page), 0, size);
	*dma_addr = addr;
	return page_address(page);
}

void dma_generic_free_coherent(struct device *dev, size_t size, void *vaddr,
			       dma_addr_t dma_addr, struct dma_attrs *attrs)
{
	unsigned int count = PAGE_ALIGN(size) >> PAGE_SHIFT;
	struct page *page = virt_to_page(vaddr);

	if (!dma_release_from_contiguous(dev, page, count))
		free_pages((unsigned long)vaddr, get_order(size));
}

bool arch_dma_alloc_attrs(struct device **dev, gfp_t *gfp)
{
	if (!*dev)
		*dev = &x86_dma_fallback_dev;

	*gfp &= ~(__GFP_DMA | __GFP_HIGHMEM | __GFP_DMA32);
	*gfp = dma_alloc_coherent_gfp_flags(*dev, *gfp);

	if (!is_device_dma_capable(*dev))
		return false;
	return true;

}
EXPORT_SYMBOL(arch_dma_alloc_attrs);

static __init int iommu_setup(char *p)
{
	iommu_merge = 1;

	if (!p)
		return -EINVAL;

	while (*p) {
		if (!strncmp(p, "off", 3))
			no_iommu = 1;
		 
		if (!strncmp(p, "force", 5))
			force_iommu = 1;
		if (!strncmp(p, "noforce", 7)) {
			iommu_merge = 0;
			force_iommu = 0;
		}

		if (!strncmp(p, "biomerge", 8)) {
			iommu_merge = 1;
			force_iommu = 1;
		}
		if (!strncmp(p, "panic", 5))
			panic_on_overflow = 1;
		if (!strncmp(p, "nopanic", 7))
			panic_on_overflow = 0;
		if (!strncmp(p, "merge", 5)) {
			iommu_merge = 1;
			force_iommu = 1;
		}
		if (!strncmp(p, "nomerge", 7))
			iommu_merge = 0;
		if (!strncmp(p, "forcesac", 8))
			iommu_sac_force = 1;
		if (!strncmp(p, "allowdac", 8))
			forbid_dac = 0;
		if (!strncmp(p, "nodac", 5))
			forbid_dac = 1;
		if (!strncmp(p, "usedac", 6)) {
			forbid_dac = -1;
			return 1;
		}
#ifdef CONFIG_SWIOTLB
		if (!strncmp(p, "soft", 4))
			swiotlb = 1;
#endif
		if (!strncmp(p, "pt", 2))
			iommu_pass_through = 1;

		gart_parse_options(p);

#ifdef CONFIG_CALGARY_IOMMU
		if (!strncmp(p, "calgary", 7))
			use_calgary = 1;
#endif  

		p += strcspn(p, ",");
		if (*p == ',')
			++p;
	}
	return 0;
}
early_param("iommu", iommu_setup);

int dma_supported(struct device *dev, u64 mask)
{
	struct dma_map_ops *ops = get_dma_ops(dev);

#ifdef CONFIG_PCI
	if (mask > 0xffffffff && forbid_dac > 0) {
		dev_info(dev, "PCI: Disallowing DAC for device\n");
		return 0;
	}
#endif

	if (ops->dma_supported)
		return ops->dma_supported(dev, mask);

	if (mask < DMA_BIT_MASK(24))
		return 0;

	if (iommu_sac_force && (mask >= DMA_BIT_MASK(40))) {
		dev_info(dev, "Force SAC with mask %Lx\n", mask);
		return 0;
	}

	return 1;
}
EXPORT_SYMBOL(dma_supported);

static int __init pci_iommu_init(void)
{
	struct iommu_table_entry *p;
	dma_debug_init(PREALLOC_DMA_DEBUG_ENTRIES);

#ifdef CONFIG_PCI
	dma_debug_add_bus(&pci_bus_type);
#endif
	x86_init.iommu.iommu_init();

	for (p = __iommu_table; p < __iommu_table_end; p++) {
		if (p && (p->flags & IOMMU_DETECTED) && p->late_init)
			p->late_init();
	}

	return 0;
}
 
rootfs_initcall(pci_iommu_init);

#ifdef CONFIG_PCI
 
static void via_no_dac(struct pci_dev *dev)
{
	if (forbid_dac == 0) {
		dev_info(&dev->dev, "disabling DAC on VIA PCI bridge\n");
		forbid_dac = 1;
	}
}
DECLARE_PCI_FIXUP_CLASS_FINAL(PCI_VENDOR_ID_VIA, PCI_ANY_ID,
				PCI_CLASS_BRIDGE_PCI, 8, via_no_dac);
#endif
