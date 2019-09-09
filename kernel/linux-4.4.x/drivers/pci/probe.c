 
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/of_device.h>
#include <linux/of_pci.h>
#include <linux/pci_hotplug.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/cpumask.h>
#include <linux/pci-aspm.h>
#include <linux/aer.h>
#include <linux/acpi.h>
#include <asm-generic/pci-bridge.h>
#include "pci.h"

#define CARDBUS_LATENCY_TIMER	176	 
#define CARDBUS_RESERVE_BUSNR	3

static struct resource busn_resource = {
	.name	= "PCI busn",
	.start	= 0,
	.end	= 255,
	.flags	= IORESOURCE_BUS,
};

LIST_HEAD(pci_root_buses);
EXPORT_SYMBOL(pci_root_buses);

static LIST_HEAD(pci_domain_busn_res_list);

struct pci_domain_busn_res {
	struct list_head list;
	struct resource res;
	int domain_nr;
};

static struct resource *get_pci_domain_busn_res(int domain_nr)
{
	struct pci_domain_busn_res *r;

	list_for_each_entry(r, &pci_domain_busn_res_list, list)
		if (r->domain_nr == domain_nr)
			return &r->res;

	r = kzalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return NULL;

	r->domain_nr = domain_nr;
	r->res.start = 0;
	r->res.end = 0xff;
	r->res.flags = IORESOURCE_BUS | IORESOURCE_PCI_FIXED;

	list_add_tail(&r->list, &pci_domain_busn_res_list);

	return &r->res;
}

static int find_anything(struct device *dev, void *data)
{
	return 1;
}

int no_pci_devices(void)
{
	struct device *dev;
	int no_devices;

	dev = bus_find_device(&pci_bus_type, NULL, NULL, find_anything);
	no_devices = (dev == NULL);
	put_device(dev);
	return no_devices;
}
EXPORT_SYMBOL(no_pci_devices);

static void release_pcibus_dev(struct device *dev)
{
	struct pci_bus *pci_bus = to_pci_bus(dev);

	put_device(pci_bus->bridge);
	pci_bus_remove_resources(pci_bus);
	pci_release_bus_of_node(pci_bus);
	kfree(pci_bus);
}

static struct class pcibus_class = {
	.name		= "pci_bus",
	.dev_release	= &release_pcibus_dev,
	.dev_groups	= pcibus_groups,
};

static int __init pcibus_class_init(void)
{
	return class_register(&pcibus_class);
}
postcore_initcall(pcibus_class_init);

static u64 pci_size(u64 base, u64 maxbase, u64 mask)
{
	u64 size = mask & maxbase;	 
	if (!size)
		return 0;

	size = (size & ~(size-1)) - 1;

	if (base == maxbase && ((base | size) & mask) != mask)
		return 0;

	return size;
}

static inline unsigned long decode_bar(struct pci_dev *dev, u32 bar)
{
	u32 mem_type;
	unsigned long flags;

	if ((bar & PCI_BASE_ADDRESS_SPACE) == PCI_BASE_ADDRESS_SPACE_IO) {
		flags = bar & ~PCI_BASE_ADDRESS_IO_MASK;
		flags |= IORESOURCE_IO;
		return flags;
	}

	flags = bar & ~PCI_BASE_ADDRESS_MEM_MASK;
	flags |= IORESOURCE_MEM;
	if (flags & PCI_BASE_ADDRESS_MEM_PREFETCH)
		flags |= IORESOURCE_PREFETCH;

	mem_type = bar & PCI_BASE_ADDRESS_MEM_TYPE_MASK;
	switch (mem_type) {
	case PCI_BASE_ADDRESS_MEM_TYPE_32:
		break;
	case PCI_BASE_ADDRESS_MEM_TYPE_1M:
		 
		break;
	case PCI_BASE_ADDRESS_MEM_TYPE_64:
		flags |= IORESOURCE_MEM_64;
		break;
	default:
		 
		break;
	}
	return flags;
}

#define PCI_COMMAND_DECODE_ENABLE	(PCI_COMMAND_MEMORY | PCI_COMMAND_IO)

int __pci_read_base(struct pci_dev *dev, enum pci_bar_type type,
		    struct resource *res, unsigned int pos)
{
	u32 l, sz, mask;
	u64 l64, sz64, mask64;
	u16 orig_cmd;
	struct pci_bus_region region, inverted_region;

	mask = type ? PCI_ROM_ADDRESS_MASK : ~0;
#ifdef CONFIG_SYNO_USB_ICH_UHCI_NO_MMIO_OFF
	if (PCI_VENDOR_ID_INTEL == dev->vendor && 0x2934 == dev->device) {
		dev_printk(KERN_INFO, &dev->dev, "[%04x:%04x] Reading BAR - reg %x\n",
		   dev->vendor, dev->device, pos);
	}
#endif  

	if (!dev->mmio_always_on) {
		pci_read_config_word(dev, PCI_COMMAND, &orig_cmd);
		if (orig_cmd & PCI_COMMAND_DECODE_ENABLE) {
			pci_write_config_word(dev, PCI_COMMAND,
				orig_cmd & ~PCI_COMMAND_DECODE_ENABLE);
		}
	}

	res->name = pci_name(dev);

	pci_read_config_dword(dev, pos, &l);
	pci_write_config_dword(dev, pos, l | mask);
	pci_read_config_dword(dev, pos, &sz);
	pci_write_config_dword(dev, pos, l);

	if (sz == 0xffffffff)
		sz = 0;

	if (l == 0xffffffff)
		l = 0;

	if (type == pci_bar_unknown) {
		res->flags = decode_bar(dev, l);
		res->flags |= IORESOURCE_SIZEALIGN;
		if (res->flags & IORESOURCE_IO) {
			l64 = l & PCI_BASE_ADDRESS_IO_MASK;
			sz64 = sz & PCI_BASE_ADDRESS_IO_MASK;
			mask64 = PCI_BASE_ADDRESS_IO_MASK & (u32)IO_SPACE_LIMIT;
		} else {
			l64 = l & PCI_BASE_ADDRESS_MEM_MASK;
			sz64 = sz & PCI_BASE_ADDRESS_MEM_MASK;
			mask64 = (u32)PCI_BASE_ADDRESS_MEM_MASK;
		}
	} else {
		if (l & PCI_ROM_ADDRESS_ENABLE)
			res->flags |= IORESOURCE_ROM_ENABLE;
		l64 = l & PCI_ROM_ADDRESS_MASK;
		sz64 = sz & PCI_ROM_ADDRESS_MASK;
		mask64 = (u32)PCI_ROM_ADDRESS_MASK;
	}

	if (res->flags & IORESOURCE_MEM_64) {
		pci_read_config_dword(dev, pos + 4, &l);
		pci_write_config_dword(dev, pos + 4, ~0);
		pci_read_config_dword(dev, pos + 4, &sz);
		pci_write_config_dword(dev, pos + 4, l);

		l64 |= ((u64)l << 32);
		sz64 |= ((u64)sz << 32);
		mask64 |= ((u64)~0 << 32);
	}

	if (!dev->mmio_always_on && (orig_cmd & PCI_COMMAND_DECODE_ENABLE))
		pci_write_config_word(dev, PCI_COMMAND, orig_cmd);

	if (!sz64)
		goto fail;

	sz64 = pci_size(l64, sz64, mask64);
	if (!sz64) {
		dev_info(&dev->dev, FW_BUG "reg 0x%x: invalid BAR (can't size)\n",
			 pos);
		goto fail;
	}

	if (res->flags & IORESOURCE_MEM_64) {
		if ((sizeof(pci_bus_addr_t) < 8 || sizeof(resource_size_t) < 8)
		    && sz64 > 0x100000000ULL) {
			res->flags |= IORESOURCE_UNSET | IORESOURCE_DISABLED;
			res->start = 0;
			res->end = 0;
			dev_err(&dev->dev, "reg 0x%x: can't handle BAR larger than 4GB (size %#010llx)\n",
				pos, (unsigned long long)sz64);
			goto out;
		}

		if ((sizeof(pci_bus_addr_t) < 8) && l) {
			 
			res->flags |= IORESOURCE_UNSET;
			res->start = 0;
			res->end = sz64;
			dev_info(&dev->dev, "reg 0x%x: can't handle BAR above 4GB (bus address %#010llx)\n",
				 pos, (unsigned long long)l64);
			goto out;
		}
	}

	region.start = l64;
	region.end = l64 + sz64;

	pcibios_bus_to_resource(dev->bus, res, &region);
	pcibios_resource_to_bus(dev->bus, &inverted_region, res);

	if (inverted_region.start != region.start) {
		res->flags |= IORESOURCE_UNSET;
		res->start = 0;
		res->end = region.end - region.start;
		dev_info(&dev->dev, "reg 0x%x: initial BAR value %#010llx invalid\n",
			 pos, (unsigned long long)region.start);
	}

	goto out;

fail:
	res->flags = 0;
out:
#ifdef CONFIG_SYNO_USB_ICH_UHCI_NO_MMIO_OFF
	if (PCI_VENDOR_ID_INTEL == dev->vendor && 0x2934 == dev->device) {
		dev_printk(KERN_INFO, &dev->dev, "[%04x:%04x] Sizing Complete - reg %x\n",
		   dev->vendor, dev->device, pos);
	}
#endif  
	if (res->flags)
		dev_printk(KERN_DEBUG, &dev->dev, "reg 0x%x: %pR\n", pos, res);

	return (res->flags & IORESOURCE_MEM_64) ? 1 : 0;
}

static void pci_read_bases(struct pci_dev *dev, unsigned int howmany, int rom)
{
	unsigned int pos, reg;

	if (dev->non_compliant_bars)
		return;

	for (pos = 0; pos < howmany; pos++) {
		struct resource *res = &dev->resource[pos];
		reg = PCI_BASE_ADDRESS_0 + (pos << 2);
		pos += __pci_read_base(dev, pci_bar_unknown, res, reg);
	}

	if (rom) {
		struct resource *res = &dev->resource[PCI_ROM_RESOURCE];
		dev->rom_base_reg = rom;
		res->flags = IORESOURCE_MEM | IORESOURCE_PREFETCH |
				IORESOURCE_READONLY | IORESOURCE_SIZEALIGN;
		__pci_read_base(dev, pci_bar_mem32, res, rom);
	}
}

static void pci_read_bridge_io(struct pci_bus *child)
{
	struct pci_dev *dev = child->self;
	u8 io_base_lo, io_limit_lo;
	unsigned long io_mask, io_granularity, base, limit;
	struct pci_bus_region region;
	struct resource *res;

	io_mask = PCI_IO_RANGE_MASK;
	io_granularity = 0x1000;
	if (dev->io_window_1k) {
		 
		io_mask = PCI_IO_1K_RANGE_MASK;
		io_granularity = 0x400;
	}

	res = child->resource[0];
	pci_read_config_byte(dev, PCI_IO_BASE, &io_base_lo);
	pci_read_config_byte(dev, PCI_IO_LIMIT, &io_limit_lo);
	base = (io_base_lo & io_mask) << 8;
	limit = (io_limit_lo & io_mask) << 8;

	if ((io_base_lo & PCI_IO_RANGE_TYPE_MASK) == PCI_IO_RANGE_TYPE_32) {
		u16 io_base_hi, io_limit_hi;

		pci_read_config_word(dev, PCI_IO_BASE_UPPER16, &io_base_hi);
		pci_read_config_word(dev, PCI_IO_LIMIT_UPPER16, &io_limit_hi);
		base |= ((unsigned long) io_base_hi << 16);
		limit |= ((unsigned long) io_limit_hi << 16);
	}

	if (base <= limit) {
		res->flags = (io_base_lo & PCI_IO_RANGE_TYPE_MASK) | IORESOURCE_IO;
		region.start = base;
		region.end = limit + io_granularity - 1;
		pcibios_bus_to_resource(dev->bus, res, &region);
		dev_printk(KERN_DEBUG, &dev->dev, "  bridge window %pR\n", res);
	}
}

static void pci_read_bridge_mmio(struct pci_bus *child)
{
	struct pci_dev *dev = child->self;
	u16 mem_base_lo, mem_limit_lo;
	unsigned long base, limit;
	struct pci_bus_region region;
	struct resource *res;

	res = child->resource[1];
	pci_read_config_word(dev, PCI_MEMORY_BASE, &mem_base_lo);
	pci_read_config_word(dev, PCI_MEMORY_LIMIT, &mem_limit_lo);
	base = ((unsigned long) mem_base_lo & PCI_MEMORY_RANGE_MASK) << 16;
	limit = ((unsigned long) mem_limit_lo & PCI_MEMORY_RANGE_MASK) << 16;
	if (base <= limit) {
		res->flags = (mem_base_lo & PCI_MEMORY_RANGE_TYPE_MASK) | IORESOURCE_MEM;
		region.start = base;
		region.end = limit + 0xfffff;
		pcibios_bus_to_resource(dev->bus, res, &region);
		dev_printk(KERN_DEBUG, &dev->dev, "  bridge window %pR\n", res);
	}
}

static void pci_read_bridge_mmio_pref(struct pci_bus *child)
{
	struct pci_dev *dev = child->self;
	u16 mem_base_lo, mem_limit_lo;
	u64 base64, limit64;
	pci_bus_addr_t base, limit;
	struct pci_bus_region region;
	struct resource *res;

	res = child->resource[2];
	pci_read_config_word(dev, PCI_PREF_MEMORY_BASE, &mem_base_lo);
	pci_read_config_word(dev, PCI_PREF_MEMORY_LIMIT, &mem_limit_lo);
	base64 = (mem_base_lo & PCI_PREF_RANGE_MASK) << 16;
	limit64 = (mem_limit_lo & PCI_PREF_RANGE_MASK) << 16;

	if ((mem_base_lo & PCI_PREF_RANGE_TYPE_MASK) == PCI_PREF_RANGE_TYPE_64) {
		u32 mem_base_hi, mem_limit_hi;

		pci_read_config_dword(dev, PCI_PREF_BASE_UPPER32, &mem_base_hi);
		pci_read_config_dword(dev, PCI_PREF_LIMIT_UPPER32, &mem_limit_hi);

		if (mem_base_hi <= mem_limit_hi) {
			base64 |= (u64) mem_base_hi << 32;
			limit64 |= (u64) mem_limit_hi << 32;
		}
	}

	base = (pci_bus_addr_t) base64;
	limit = (pci_bus_addr_t) limit64;

	if (base != base64) {
		dev_err(&dev->dev, "can't handle bridge window above 4GB (bus address %#010llx)\n",
			(unsigned long long) base64);
		return;
	}

	if (base <= limit) {
		res->flags = (mem_base_lo & PCI_PREF_RANGE_TYPE_MASK) |
					 IORESOURCE_MEM | IORESOURCE_PREFETCH;
		if (res->flags & PCI_PREF_RANGE_TYPE_64)
			res->flags |= IORESOURCE_MEM_64;
		region.start = base;
		region.end = limit + 0xfffff;
		pcibios_bus_to_resource(dev->bus, res, &region);
		dev_printk(KERN_DEBUG, &dev->dev, "  bridge window %pR\n", res);
	}
}

void pci_read_bridge_bases(struct pci_bus *child)
{
	struct pci_dev *dev = child->self;
	struct resource *res;
	int i;

	if (pci_is_root_bus(child))	 
		return;

	dev_info(&dev->dev, "PCI bridge to %pR%s\n",
		 &child->busn_res,
		 dev->transparent ? " (subtractive decode)" : "");

	pci_bus_remove_resources(child);
	for (i = 0; i < PCI_BRIDGE_RESOURCE_NUM; i++)
		child->resource[i] = &dev->resource[PCI_BRIDGE_RESOURCES+i];

	pci_read_bridge_io(child);
	pci_read_bridge_mmio(child);
	pci_read_bridge_mmio_pref(child);

	if (dev->transparent) {
		pci_bus_for_each_resource(child->parent, res, i) {
			if (res && res->flags) {
				pci_bus_add_resource(child, res,
						     PCI_SUBTRACTIVE_DECODE);
				dev_printk(KERN_DEBUG, &dev->dev,
					   "  bridge window %pR (subtractive decode)\n",
					   res);
			}
		}
	}
}

static struct pci_bus *pci_alloc_bus(struct pci_bus *parent)
{
	struct pci_bus *b;

	b = kzalloc(sizeof(*b), GFP_KERNEL);
	if (!b)
		return NULL;

	INIT_LIST_HEAD(&b->node);
	INIT_LIST_HEAD(&b->children);
	INIT_LIST_HEAD(&b->devices);
	INIT_LIST_HEAD(&b->slots);
	INIT_LIST_HEAD(&b->resources);
	b->max_bus_speed = PCI_SPEED_UNKNOWN;
	b->cur_bus_speed = PCI_SPEED_UNKNOWN;
#ifdef CONFIG_PCI_DOMAINS_GENERIC
	if (parent)
		b->domain_nr = parent->domain_nr;
#endif
	return b;
}

static void pci_release_host_bridge_dev(struct device *dev)
{
	struct pci_host_bridge *bridge = to_pci_host_bridge(dev);

	if (bridge->release_fn)
		bridge->release_fn(bridge);

	pci_free_resource_list(&bridge->windows);

	kfree(bridge);
}

static struct pci_host_bridge *pci_alloc_host_bridge(struct pci_bus *b)
{
	struct pci_host_bridge *bridge;

	bridge = kzalloc(sizeof(*bridge), GFP_KERNEL);
	if (!bridge)
		return NULL;

	INIT_LIST_HEAD(&bridge->windows);
	bridge->bus = b;
	return bridge;
}

static const unsigned char pcix_bus_speed[] = {
	PCI_SPEED_UNKNOWN,		 
	PCI_SPEED_66MHz_PCIX,		 
	PCI_SPEED_100MHz_PCIX,		 
	PCI_SPEED_133MHz_PCIX,		 
	PCI_SPEED_UNKNOWN,		 
	PCI_SPEED_66MHz_PCIX_ECC,	 
	PCI_SPEED_100MHz_PCIX_ECC,	 
	PCI_SPEED_133MHz_PCIX_ECC,	 
	PCI_SPEED_UNKNOWN,		 
	PCI_SPEED_66MHz_PCIX_266,	 
	PCI_SPEED_100MHz_PCIX_266,	 
	PCI_SPEED_133MHz_PCIX_266,	 
	PCI_SPEED_UNKNOWN,		 
	PCI_SPEED_66MHz_PCIX_533,	 
	PCI_SPEED_100MHz_PCIX_533,	 
	PCI_SPEED_133MHz_PCIX_533	 
};

const unsigned char pcie_link_speed[] = {
	PCI_SPEED_UNKNOWN,		 
	PCIE_SPEED_2_5GT,		 
	PCIE_SPEED_5_0GT,		 
	PCIE_SPEED_8_0GT,		 
	PCI_SPEED_UNKNOWN,		 
	PCI_SPEED_UNKNOWN,		 
	PCI_SPEED_UNKNOWN,		 
	PCI_SPEED_UNKNOWN,		 
	PCI_SPEED_UNKNOWN,		 
	PCI_SPEED_UNKNOWN,		 
	PCI_SPEED_UNKNOWN,		 
	PCI_SPEED_UNKNOWN,		 
	PCI_SPEED_UNKNOWN,		 
	PCI_SPEED_UNKNOWN,		 
	PCI_SPEED_UNKNOWN,		 
	PCI_SPEED_UNKNOWN		 
};

void pcie_update_link_speed(struct pci_bus *bus, u16 linksta)
{
	bus->cur_bus_speed = pcie_link_speed[linksta & PCI_EXP_LNKSTA_CLS];
}
EXPORT_SYMBOL_GPL(pcie_update_link_speed);

static unsigned char agp_speeds[] = {
	AGP_UNKNOWN,
	AGP_1X,
	AGP_2X,
	AGP_4X,
	AGP_8X
};

static enum pci_bus_speed agp_speed(int agp3, int agpstat)
{
	int index = 0;

	if (agpstat & 4)
		index = 3;
	else if (agpstat & 2)
		index = 2;
	else if (agpstat & 1)
		index = 1;
	else
		goto out;

	if (agp3) {
		index += 2;
		if (index == 5)
			index = 0;
	}

 out:
	return agp_speeds[index];
}

static void pci_set_bus_speed(struct pci_bus *bus)
{
	struct pci_dev *bridge = bus->self;
	int pos;

	pos = pci_find_capability(bridge, PCI_CAP_ID_AGP);
	if (!pos)
		pos = pci_find_capability(bridge, PCI_CAP_ID_AGP3);
	if (pos) {
		u32 agpstat, agpcmd;

		pci_read_config_dword(bridge, pos + PCI_AGP_STATUS, &agpstat);
		bus->max_bus_speed = agp_speed(agpstat & 8, agpstat & 7);

		pci_read_config_dword(bridge, pos + PCI_AGP_COMMAND, &agpcmd);
		bus->cur_bus_speed = agp_speed(agpstat & 8, agpcmd & 7);
	}

	pos = pci_find_capability(bridge, PCI_CAP_ID_PCIX);
	if (pos) {
		u16 status;
		enum pci_bus_speed max;

		pci_read_config_word(bridge, pos + PCI_X_BRIDGE_SSTATUS,
				     &status);

		if (status & PCI_X_SSTATUS_533MHZ) {
			max = PCI_SPEED_133MHz_PCIX_533;
		} else if (status & PCI_X_SSTATUS_266MHZ) {
			max = PCI_SPEED_133MHz_PCIX_266;
		} else if (status & PCI_X_SSTATUS_133MHZ) {
			if ((status & PCI_X_SSTATUS_VERS) == PCI_X_SSTATUS_V2)
				max = PCI_SPEED_133MHz_PCIX_ECC;
			else
				max = PCI_SPEED_133MHz_PCIX;
		} else {
			max = PCI_SPEED_66MHz_PCIX;
		}

		bus->max_bus_speed = max;
		bus->cur_bus_speed = pcix_bus_speed[
			(status & PCI_X_SSTATUS_FREQ) >> 6];

		return;
	}

	if (pci_is_pcie(bridge)) {
		u32 linkcap;
		u16 linksta;

		pcie_capability_read_dword(bridge, PCI_EXP_LNKCAP, &linkcap);
		bus->max_bus_speed = pcie_link_speed[linkcap & PCI_EXP_LNKCAP_SLS];

		pcie_capability_read_word(bridge, PCI_EXP_LNKSTA, &linksta);
		pcie_update_link_speed(bus, linksta);
	}
}

static struct irq_domain *pci_host_bridge_msi_domain(struct pci_bus *bus)
{
	struct irq_domain *d;

	d = pci_host_bridge_of_msi_domain(bus);

	return d;
}

static void pci_set_bus_msi_domain(struct pci_bus *bus)
{
	struct irq_domain *d;
	struct pci_bus *b;

	for (b = bus, d = NULL; !d && !pci_is_root_bus(b); b = b->parent) {
		if (b->self)
			d = dev_get_msi_domain(&b->self->dev);
	}

	if (!d)
		d = pci_host_bridge_msi_domain(b);

	dev_set_msi_domain(&bus->dev, d);
}

static struct pci_bus *pci_alloc_child_bus(struct pci_bus *parent,
					   struct pci_dev *bridge, int busnr)
{
	struct pci_bus *child;
	int i;
	int ret;

	child = pci_alloc_bus(parent);
	if (!child)
		return NULL;

	child->parent = parent;
	child->ops = parent->ops;
	child->msi = parent->msi;
	child->sysdata = parent->sysdata;
	child->bus_flags = parent->bus_flags;

	child->dev.class = &pcibus_class;
	dev_set_name(&child->dev, "%04x:%02x", pci_domain_nr(child), busnr);

	child->number = child->busn_res.start = busnr;
	child->primary = parent->busn_res.start;
	child->busn_res.end = 0xff;

	if (!bridge) {
		child->dev.parent = parent->bridge;
		goto add_dev;
	}

	child->self = bridge;
	child->bridge = get_device(&bridge->dev);
	child->dev.parent = child->bridge;
	pci_set_bus_of_node(child);
	pci_set_bus_speed(child);

	for (i = 0; i < PCI_BRIDGE_RESOURCE_NUM; i++) {
		child->resource[i] = &bridge->resource[PCI_BRIDGE_RESOURCES+i];
		child->resource[i]->name = child->name;
	}
	bridge->subordinate = child;

add_dev:
	pci_set_bus_msi_domain(child);
	ret = device_register(&child->dev);
	WARN_ON(ret < 0);

	pcibios_add_bus(child);

	pci_create_legacy_files(child);

	return child;
}

struct pci_bus *pci_add_new_bus(struct pci_bus *parent, struct pci_dev *dev,
				int busnr)
{
	struct pci_bus *child;

	child = pci_alloc_child_bus(parent, dev, busnr);
	if (child) {
		down_write(&pci_bus_sem);
		list_add_tail(&child->node, &parent->children);
		up_write(&pci_bus_sem);
	}
	return child;
}
EXPORT_SYMBOL(pci_add_new_bus);

static void pci_enable_crs(struct pci_dev *pdev)
{
	u16 root_cap = 0;

	pcie_capability_read_word(pdev, PCI_EXP_RTCAP, &root_cap);
	if (root_cap & PCI_EXP_RTCAP_CRSVIS)
		pcie_capability_set_word(pdev, PCI_EXP_RTCTL,
					 PCI_EXP_RTCTL_CRSSVE);
}

int pci_scan_bridge(struct pci_bus *bus, struct pci_dev *dev, int max, int pass)
{
	struct pci_bus *child;
	int is_cardbus = (dev->hdr_type == PCI_HEADER_TYPE_CARDBUS);
	u32 buses, i, j = 0;
	u16 bctl;
	u8 primary, secondary, subordinate;
	int broken = 0;

	pci_read_config_dword(dev, PCI_PRIMARY_BUS, &buses);
	primary = buses & 0xFF;
	secondary = (buses >> 8) & 0xFF;
	subordinate = (buses >> 16) & 0xFF;

	dev_dbg(&dev->dev, "scanning [bus %02x-%02x] behind bridge, pass %d\n",
		secondary, subordinate, pass);

	if (!primary && (primary != bus->number) && secondary && subordinate) {
		dev_warn(&dev->dev, "Primary bus is hard wired to 0\n");
		primary = bus->number;
	}

	if (!pass &&
	    (primary != bus->number || secondary <= bus->number ||
	     secondary > subordinate)) {
		dev_info(&dev->dev, "bridge configuration invalid ([bus %02x-%02x]), reconfiguring\n",
			 secondary, subordinate);
		broken = 1;
	}

	pci_read_config_word(dev, PCI_BRIDGE_CONTROL, &bctl);
	pci_write_config_word(dev, PCI_BRIDGE_CONTROL,
			      bctl & ~PCI_BRIDGE_CTL_MASTER_ABORT);

	pci_enable_crs(dev);

	if ((secondary || subordinate) && !pcibios_assign_all_busses() &&
	    !is_cardbus && !broken) {
		unsigned int cmax;
		 
		if (pass)
			goto out;

		child = pci_find_bus(pci_domain_nr(bus), secondary);
		if (!child) {
			child = pci_add_new_bus(bus, dev, secondary);
			if (!child)
				goto out;
			child->primary = primary;
			pci_bus_insert_busn_res(child, secondary, subordinate);
			child->bridge_ctl = bctl;
		}

		cmax = pci_scan_child_bus(child);
		if (cmax > subordinate)
			dev_warn(&dev->dev, "bridge has subordinate %02x but max busn %02x\n",
				 subordinate, cmax);
		 
		if (subordinate > max)
			max = subordinate;
	} else {
		 
		if (!pass) {
			if (pcibios_assign_all_busses() || broken || is_cardbus)
				 
				pci_write_config_dword(dev, PCI_PRIMARY_BUS,
						       buses & ~0xffffff);
			goto out;
		}

		pci_write_config_word(dev, PCI_STATUS, 0xffff);

		child = pci_find_bus(pci_domain_nr(bus), max+1);
		if (!child) {
			child = pci_add_new_bus(bus, dev, max+1);
			if (!child)
				goto out;
			pci_bus_insert_busn_res(child, max+1, 0xff);
		}
		max++;
		buses = (buses & 0xff000000)
		      | ((unsigned int)(child->primary)     <<  0)
		      | ((unsigned int)(child->busn_res.start)   <<  8)
		      | ((unsigned int)(child->busn_res.end) << 16);

		if (is_cardbus) {
			buses &= ~0xff000000;
			buses |= CARDBUS_LATENCY_TIMER << 24;
		}

		pci_write_config_dword(dev, PCI_PRIMARY_BUS, buses);

		if (!is_cardbus) {
			child->bridge_ctl = bctl;
			max = pci_scan_child_bus(child);
		} else {
			 
			for (i = 0; i < CARDBUS_RESERVE_BUSNR; i++) {
				struct pci_bus *parent = bus;
				if (pci_find_bus(pci_domain_nr(bus),
							max+i+1))
					break;
				while (parent->parent) {
					if ((!pcibios_assign_all_busses()) &&
					    (parent->busn_res.end > max) &&
					    (parent->busn_res.end <= max+i)) {
						j = 1;
					}
					parent = parent->parent;
				}
				if (j) {
					 
					i /= 2;
					break;
				}
			}
			max += i;
		}
		 
		pci_bus_update_busn_res_end(child, max);
		pci_write_config_byte(dev, PCI_SUBORDINATE_BUS, max);
	}

	sprintf(child->name,
		(is_cardbus ? "PCI CardBus %04x:%02x" : "PCI Bus %04x:%02x"),
		pci_domain_nr(bus), child->number);

	while (bus->parent) {
		if ((child->busn_res.end > bus->busn_res.end) ||
		    (child->number > bus->busn_res.end) ||
		    (child->number < bus->number) ||
		    (child->busn_res.end < bus->number)) {
			dev_info(&child->dev, "%pR %s hidden behind%s bridge %s %pR\n",
				&child->busn_res,
				(bus->number > child->busn_res.end &&
				 bus->busn_res.end < child->number) ?
					"wholly" : "partially",
				bus->self->transparent ? " transparent" : "",
				dev_name(&bus->dev),
				&bus->busn_res);
		}
		bus = bus->parent;
	}

out:
	pci_write_config_word(dev, PCI_BRIDGE_CONTROL, bctl);

	return max;
}
EXPORT_SYMBOL(pci_scan_bridge);

static void pci_read_irq(struct pci_dev *dev)
{
	unsigned char irq;

	pci_read_config_byte(dev, PCI_INTERRUPT_PIN, &irq);
	dev->pin = irq;
	if (irq)
		pci_read_config_byte(dev, PCI_INTERRUPT_LINE, &irq);
	dev->irq = irq;
}

void set_pcie_port_type(struct pci_dev *pdev)
{
	int pos;
	u16 reg16;
	int type;
	struct pci_dev *parent;

	pos = pci_find_capability(pdev, PCI_CAP_ID_EXP);
	if (!pos)
		return;

	pdev->pcie_cap = pos;
	pci_read_config_word(pdev, pos + PCI_EXP_FLAGS, &reg16);
	pdev->pcie_flags_reg = reg16;
	pci_read_config_word(pdev, pos + PCI_EXP_DEVCAP, &reg16);
	pdev->pcie_mpss = reg16 & PCI_EXP_DEVCAP_PAYLOAD;

	type = pci_pcie_type(pdev);
	if (type == PCI_EXP_TYPE_ROOT_PORT ||
	    type == PCI_EXP_TYPE_PCIE_BRIDGE)
		pdev->has_secondary_link = 1;
	else if (type == PCI_EXP_TYPE_UPSTREAM ||
		 type == PCI_EXP_TYPE_DOWNSTREAM) {
		parent = pci_upstream_bridge(pdev);

		if (parent && !parent->has_secondary_link)
			pdev->has_secondary_link = 1;
	}
}

void set_pcie_hotplug_bridge(struct pci_dev *pdev)
{
	u32 reg32;

	pcie_capability_read_dword(pdev, PCI_EXP_SLTCAP, &reg32);
	if (reg32 & PCI_EXP_SLTCAP_HPC)
		pdev->is_hotplug_bridge = 1;
}

static bool pci_ext_cfg_is_aliased(struct pci_dev *dev)
{
#ifdef CONFIG_PCI_QUIRKS
	int pos;
	u32 header, tmp;

	pci_read_config_dword(dev, PCI_VENDOR_ID, &header);

	for (pos = PCI_CFG_SPACE_SIZE;
	     pos < PCI_CFG_SPACE_EXP_SIZE; pos += PCI_CFG_SPACE_SIZE) {
		if (pci_read_config_dword(dev, pos, &tmp) != PCIBIOS_SUCCESSFUL
		    || header != tmp)
			return false;
	}

	return true;
#else
	return false;
#endif
}

static int pci_cfg_space_size_ext(struct pci_dev *dev)
{
	u32 status;
	int pos = PCI_CFG_SPACE_SIZE;

	if (pci_read_config_dword(dev, pos, &status) != PCIBIOS_SUCCESSFUL)
		goto fail;
	if (status == 0xffffffff || pci_ext_cfg_is_aliased(dev))
		goto fail;

	return PCI_CFG_SPACE_EXP_SIZE;

 fail:
	return PCI_CFG_SPACE_SIZE;
}

int pci_cfg_space_size(struct pci_dev *dev)
{
	int pos;
	u32 status;
	u16 class;

	class = dev->class >> 8;
	if (class == PCI_CLASS_BRIDGE_HOST)
		return pci_cfg_space_size_ext(dev);

	if (!pci_is_pcie(dev)) {
		pos = pci_find_capability(dev, PCI_CAP_ID_PCIX);
		if (!pos)
			goto fail;

		pci_read_config_dword(dev, pos + PCI_X_STATUS, &status);
		if (!(status & (PCI_X_STATUS_266MHZ | PCI_X_STATUS_533MHZ)))
			goto fail;
	}

	return pci_cfg_space_size_ext(dev);

 fail:
	return PCI_CFG_SPACE_SIZE;
}

#define LEGACY_IO_RESOURCE	(IORESOURCE_IO | IORESOURCE_PCI_FIXED)

void pci_msi_setup_pci_dev(struct pci_dev *dev)
{
	 
	dev->msi_cap = pci_find_capability(dev, PCI_CAP_ID_MSI);
	if (dev->msi_cap)
		pci_msi_set_enable(dev, 0);

	dev->msix_cap = pci_find_capability(dev, PCI_CAP_ID_MSIX);
	if (dev->msix_cap)
		pci_msix_clear_and_set_ctrl(dev, PCI_MSIX_FLAGS_ENABLE, 0);
}

int pci_setup_device(struct pci_dev *dev)
{
	u32 class;
	u16 cmd;
	u8 hdr_type;
	int pos = 0;
	struct pci_bus_region region;
	struct resource *res;

	if (pci_read_config_byte(dev, PCI_HEADER_TYPE, &hdr_type))
		return -EIO;

	dev->sysdata = dev->bus->sysdata;
	dev->dev.parent = dev->bus->bridge;
	dev->dev.bus = &pci_bus_type;
	dev->hdr_type = hdr_type & 0x7f;
	dev->multifunction = !!(hdr_type & 0x80);
	dev->error_state = pci_channel_io_normal;
	set_pcie_port_type(dev);

	pci_dev_assign_slot(dev);
	 
	dev->dma_mask = 0xffffffff;

	dev_set_name(&dev->dev, "%04x:%02x:%02x.%d", pci_domain_nr(dev->bus),
		     dev->bus->number, PCI_SLOT(dev->devfn),
		     PCI_FUNC(dev->devfn));

	pci_read_config_dword(dev, PCI_CLASS_REVISION, &class);
	dev->revision = class & 0xff;
	dev->class = class >> 8;		     

	dev_printk(KERN_DEBUG, &dev->dev, "[%04x:%04x] type %02x class %#08x\n",
		   dev->vendor, dev->device, dev->hdr_type, dev->class);

	dev->cfg_size = pci_cfg_space_size(dev);

	dev->current_state = PCI_UNKNOWN;

	pci_msi_setup_pci_dev(dev);

	pci_fixup_device(pci_fixup_early, dev);
	 
	class = dev->class >> 8;

	if (dev->non_compliant_bars) {
		pci_read_config_word(dev, PCI_COMMAND, &cmd);
		if (cmd & (PCI_COMMAND_IO | PCI_COMMAND_MEMORY)) {
			dev_info(&dev->dev, "device has non-compliant BARs; disabling IO/MEM decoding\n");
			cmd &= ~PCI_COMMAND_IO;
			cmd &= ~PCI_COMMAND_MEMORY;
			pci_write_config_word(dev, PCI_COMMAND, cmd);
		}
	}

	switch (dev->hdr_type) {		     
	case PCI_HEADER_TYPE_NORMAL:		     
		if (class == PCI_CLASS_BRIDGE_PCI)
			goto bad;
		pci_read_irq(dev);
		pci_read_bases(dev, 6, PCI_ROM_ADDRESS);
		pci_read_config_word(dev, PCI_SUBSYSTEM_VENDOR_ID, &dev->subsystem_vendor);
		pci_read_config_word(dev, PCI_SUBSYSTEM_ID, &dev->subsystem_device);

		if (class == PCI_CLASS_STORAGE_IDE) {
			u8 progif;
			pci_read_config_byte(dev, PCI_CLASS_PROG, &progif);
			if ((progif & 1) == 0) {
				region.start = 0x1F0;
				region.end = 0x1F7;
				res = &dev->resource[0];
				res->flags = LEGACY_IO_RESOURCE;
				pcibios_bus_to_resource(dev->bus, res, &region);
				dev_info(&dev->dev, "legacy IDE quirk: reg 0x10: %pR\n",
					 res);
				region.start = 0x3F6;
				region.end = 0x3F6;
				res = &dev->resource[1];
				res->flags = LEGACY_IO_RESOURCE;
				pcibios_bus_to_resource(dev->bus, res, &region);
				dev_info(&dev->dev, "legacy IDE quirk: reg 0x14: %pR\n",
					 res);
			}
			if ((progif & 4) == 0) {
				region.start = 0x170;
				region.end = 0x177;
				res = &dev->resource[2];
				res->flags = LEGACY_IO_RESOURCE;
				pcibios_bus_to_resource(dev->bus, res, &region);
				dev_info(&dev->dev, "legacy IDE quirk: reg 0x18: %pR\n",
					 res);
				region.start = 0x376;
				region.end = 0x376;
				res = &dev->resource[3];
				res->flags = LEGACY_IO_RESOURCE;
				pcibios_bus_to_resource(dev->bus, res, &region);
				dev_info(&dev->dev, "legacy IDE quirk: reg 0x1c: %pR\n",
					 res);
			}
		}
		break;

	case PCI_HEADER_TYPE_BRIDGE:		     
		if (class != PCI_CLASS_BRIDGE_PCI)
			goto bad;
		 
		pci_read_irq(dev);
		dev->transparent = ((dev->class & 0xff) == 1);
		pci_read_bases(dev, 2, PCI_ROM_ADDRESS1);
		set_pcie_hotplug_bridge(dev);
		pos = pci_find_capability(dev, PCI_CAP_ID_SSVID);
		if (pos) {
			pci_read_config_word(dev, pos + PCI_SSVID_VENDOR_ID, &dev->subsystem_vendor);
			pci_read_config_word(dev, pos + PCI_SSVID_DEVICE_ID, &dev->subsystem_device);
		}
		break;

	case PCI_HEADER_TYPE_CARDBUS:		     
		if (class != PCI_CLASS_BRIDGE_CARDBUS)
			goto bad;
		pci_read_irq(dev);
		pci_read_bases(dev, 1, 0);
		pci_read_config_word(dev, PCI_CB_SUBSYSTEM_VENDOR_ID, &dev->subsystem_vendor);
		pci_read_config_word(dev, PCI_CB_SUBSYSTEM_ID, &dev->subsystem_device);
		break;

	default:				     
		dev_err(&dev->dev, "unknown header type %02x, ignoring device\n",
			dev->hdr_type);
		return -EIO;

	bad:
		dev_err(&dev->dev, "ignoring class %#08x (doesn't match header type %02x)\n",
			dev->class, dev->hdr_type);
		dev->class = PCI_CLASS_NOT_DEFINED << 8;
	}

	return 0;
}

static void pci_configure_mps(struct pci_dev *dev)
{
	struct pci_dev *bridge = pci_upstream_bridge(dev);
	int mps, p_mps, rc;

	if (!pci_is_pcie(dev) || !bridge || !pci_is_pcie(bridge))
		return;

	mps = pcie_get_mps(dev);
	p_mps = pcie_get_mps(bridge);

	if (mps == p_mps)
		return;

	if (pcie_bus_config == PCIE_BUS_TUNE_OFF) {
		dev_warn(&dev->dev, "Max Payload Size %d, but upstream %s set to %d; if necessary, use \"pci=pcie_bus_safe\" and report a bug\n",
			 mps, pci_name(bridge), p_mps);
		return;
	}

	if (pcie_bus_config != PCIE_BUS_DEFAULT)
		return;

	rc = pcie_set_mps(dev, p_mps);
	if (rc) {
		dev_warn(&dev->dev, "can't set Max Payload Size to %d; if necessary, use \"pci=pcie_bus_safe\" and report a bug\n",
			 p_mps);
		return;
	}

	dev_info(&dev->dev, "Max Payload Size set to %d (was %d, max %d)\n",
		 p_mps, mps, 128 << dev->pcie_mpss);
}

static struct hpp_type0 pci_default_type0 = {
	.revision = 1,
	.cache_line_size = 8,
	.latency_timer = 0x40,
	.enable_serr = 0,
	.enable_perr = 0,
};

static void program_hpp_type0(struct pci_dev *dev, struct hpp_type0 *hpp)
{
	u16 pci_cmd, pci_bctl;

	if (!hpp)
		hpp = &pci_default_type0;

	if (hpp->revision > 1) {
		dev_warn(&dev->dev,
			 "PCI settings rev %d not supported; using defaults\n",
			 hpp->revision);
		hpp = &pci_default_type0;
	}

	pci_write_config_byte(dev, PCI_CACHE_LINE_SIZE, hpp->cache_line_size);
	pci_write_config_byte(dev, PCI_LATENCY_TIMER, hpp->latency_timer);
	pci_read_config_word(dev, PCI_COMMAND, &pci_cmd);
	if (hpp->enable_serr)
		pci_cmd |= PCI_COMMAND_SERR;
	if (hpp->enable_perr)
		pci_cmd |= PCI_COMMAND_PARITY;
	pci_write_config_word(dev, PCI_COMMAND, pci_cmd);

	if ((dev->class >> 8) == PCI_CLASS_BRIDGE_PCI) {
		pci_write_config_byte(dev, PCI_SEC_LATENCY_TIMER,
				      hpp->latency_timer);
		pci_read_config_word(dev, PCI_BRIDGE_CONTROL, &pci_bctl);
		if (hpp->enable_serr)
			pci_bctl |= PCI_BRIDGE_CTL_SERR;
		if (hpp->enable_perr)
			pci_bctl |= PCI_BRIDGE_CTL_PARITY;
		pci_write_config_word(dev, PCI_BRIDGE_CONTROL, pci_bctl);
	}
}

static void program_hpp_type1(struct pci_dev *dev, struct hpp_type1 *hpp)
{
	if (hpp)
		dev_warn(&dev->dev, "PCI-X settings not supported\n");
}

static bool pcie_root_rcb_set(struct pci_dev *dev)
{
	struct pci_dev *rp = pcie_find_root_port(dev);
	u16 lnkctl;

	if (!rp)
		return false;

	pcie_capability_read_word(rp, PCI_EXP_LNKCTL, &lnkctl);
	if (lnkctl & PCI_EXP_LNKCTL_RCB)
		return true;

	return false;
}

static void program_hpp_type2(struct pci_dev *dev, struct hpp_type2 *hpp)
{
	int pos;
	u32 reg32;

	if (!hpp)
		return;

	if (hpp->revision > 1) {
		dev_warn(&dev->dev, "PCIe settings rev %d not supported\n",
			 hpp->revision);
		return;
	}

	hpp->pci_exp_devctl_and |= PCI_EXP_DEVCTL_PAYLOAD |
				    PCI_EXP_DEVCTL_READRQ;
	hpp->pci_exp_devctl_or &= ~(PCI_EXP_DEVCTL_PAYLOAD |
				    PCI_EXP_DEVCTL_READRQ);

	pcie_capability_clear_and_set_word(dev, PCI_EXP_DEVCTL,
			~hpp->pci_exp_devctl_and, hpp->pci_exp_devctl_or);

	if (pcie_cap_has_lnkctl(dev)) {

		hpp->pci_exp_lnkctl_and |= PCI_EXP_LNKCTL_RCB;
		hpp->pci_exp_lnkctl_or &= ~PCI_EXP_LNKCTL_RCB;
		if (pcie_root_rcb_set(dev))
			hpp->pci_exp_lnkctl_or |= PCI_EXP_LNKCTL_RCB;

		pcie_capability_clear_and_set_word(dev, PCI_EXP_LNKCTL,
			~hpp->pci_exp_lnkctl_and, hpp->pci_exp_lnkctl_or);
	}

	pos = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_ERR);
	if (!pos)
		return;

	pci_read_config_dword(dev, pos + PCI_ERR_UNCOR_MASK, &reg32);
	reg32 = (reg32 & hpp->unc_err_mask_and) | hpp->unc_err_mask_or;
	pci_write_config_dword(dev, pos + PCI_ERR_UNCOR_MASK, reg32);

	pci_read_config_dword(dev, pos + PCI_ERR_UNCOR_SEVER, &reg32);
	reg32 = (reg32 & hpp->unc_err_sever_and) | hpp->unc_err_sever_or;
	pci_write_config_dword(dev, pos + PCI_ERR_UNCOR_SEVER, reg32);

	pci_read_config_dword(dev, pos + PCI_ERR_COR_MASK, &reg32);
	reg32 = (reg32 & hpp->cor_err_mask_and) | hpp->cor_err_mask_or;
	pci_write_config_dword(dev, pos + PCI_ERR_COR_MASK, reg32);

	pci_read_config_dword(dev, pos + PCI_ERR_CAP, &reg32);
	reg32 = (reg32 & hpp->adv_err_cap_and) | hpp->adv_err_cap_or;
	pci_write_config_dword(dev, pos + PCI_ERR_CAP, reg32);

}

static void pci_configure_device(struct pci_dev *dev)
{
	struct hotplug_params hpp;
	int ret;

	pci_configure_mps(dev);

	memset(&hpp, 0, sizeof(hpp));
	ret = pci_get_hp_params(dev, &hpp);
	if (ret)
		return;

	program_hpp_type2(dev, hpp.t2);
	program_hpp_type1(dev, hpp.t1);
	program_hpp_type0(dev, hpp.t0);
}

static void pci_release_capabilities(struct pci_dev *dev)
{
	pci_vpd_release(dev);
	pci_iov_release(dev);
	pci_free_cap_save_buffers(dev);
}

static void pci_release_dev(struct device *dev)
{
	struct pci_dev *pci_dev;

	pci_dev = to_pci_dev(dev);
	pci_release_capabilities(pci_dev);
	pci_release_of_node(pci_dev);
	pcibios_release_device(pci_dev);
	pci_bus_put(pci_dev->bus);
	kfree(pci_dev->driver_override);
	kfree(pci_dev);
}

struct pci_dev *pci_alloc_dev(struct pci_bus *bus)
{
	struct pci_dev *dev;

	dev = kzalloc(sizeof(struct pci_dev), GFP_KERNEL);
	if (!dev)
		return NULL;

	INIT_LIST_HEAD(&dev->bus_list);
	dev->dev.type = &pci_dev_type;
	dev->bus = pci_bus_get(bus);

	return dev;
}
EXPORT_SYMBOL(pci_alloc_dev);

bool pci_bus_read_dev_vendor_id(struct pci_bus *bus, int devfn, u32 *l,
				int crs_timeout)
{
	int delay = 1;

	if (pci_bus_read_config_dword(bus, devfn, PCI_VENDOR_ID, l))
		return false;

	if (*l == 0xffffffff || *l == 0x00000000 ||
	    *l == 0x0000ffff || *l == 0xffff0000)
		return false;

	while ((*l & 0xffff) == 0x0001) {
		if (!crs_timeout)
			return false;

		msleep(delay);
		delay *= 2;
		if (pci_bus_read_config_dword(bus, devfn, PCI_VENDOR_ID, l))
			return false;
		 
		if (delay > crs_timeout) {
			printk(KERN_WARNING "pci %04x:%02x:%02x.%d: not responding\n",
			       pci_domain_nr(bus), bus->number, PCI_SLOT(devfn),
			       PCI_FUNC(devfn));
			return false;
		}
	}

	return true;
}
EXPORT_SYMBOL(pci_bus_read_dev_vendor_id);

static struct pci_dev *pci_scan_device(struct pci_bus *bus, int devfn)
{
	struct pci_dev *dev;
	u32 l;

	if (!pci_bus_read_dev_vendor_id(bus, devfn, &l, 60*1000))
		return NULL;

	dev = pci_alloc_dev(bus);
	if (!dev)
		return NULL;

	dev->devfn = devfn;
	dev->vendor = l & 0xffff;
	dev->device = (l >> 16) & 0xffff;

	pci_set_of_node(dev);

	if (pci_setup_device(dev)) {
		pci_bus_put(dev->bus);
		kfree(dev);
		return NULL;
	}

	return dev;
}

static void pci_init_capabilities(struct pci_dev *dev)
{
	 
	pci_ea_init(dev);

	pci_msi_init_pci_dev(dev);

	pci_allocate_cap_save_buffers(dev);

	pci_pm_init(dev);

	pci_vpd_pci22_init(dev);

	pci_configure_ari(dev);

	pci_iov_init(dev);

	pci_ats_init(dev);

	pci_enable_acs(dev);

	pci_cleanup_aer_error_status_regs(dev);
}

static struct irq_domain *pci_dev_msi_domain(struct pci_dev *dev)
{
	struct irq_domain *d;

	d = dev_get_msi_domain(&dev->dev);
	if (d)
		return d;

	d = pci_msi_get_device_domain(dev);
	if (d)
		return d;

	return NULL;
}

static void pci_set_msi_domain(struct pci_dev *dev)
{
	struct irq_domain *d;

	d = pci_dev_msi_domain(dev);
	if (!d)
		d = dev_get_msi_domain(&dev->bus->dev);

	dev_set_msi_domain(&dev->dev, d);
}

static void pci_dma_configure(struct pci_dev *dev)
{
	struct device *bridge = pci_get_host_bridge_device(dev);

	if (IS_ENABLED(CONFIG_OF) &&
		bridge->parent && bridge->parent->of_node) {
			of_dma_configure(&dev->dev, bridge->parent->of_node);
	} else if (has_acpi_companion(bridge)) {
		struct acpi_device *adev = to_acpi_device_node(bridge->fwnode);
		enum dev_dma_attr attr = acpi_get_dma_attr(adev);

		if (attr == DEV_DMA_NOT_SUPPORTED)
			dev_warn(&dev->dev, "DMA not supported.\n");
		else
			arch_setup_dma_ops(&dev->dev, 0, 0, NULL,
					   attr == DEV_DMA_COHERENT);
	}

	pci_put_host_bridge_device(bridge);
}

void pci_device_add(struct pci_dev *dev, struct pci_bus *bus)
{
	int ret;

	pci_configure_device(dev);

	device_initialize(&dev->dev);
	dev->dev.release = pci_release_dev;

	set_dev_node(&dev->dev, pcibus_to_node(bus));
	dev->dev.dma_mask = &dev->dma_mask;
	dev->dev.dma_parms = &dev->dma_parms;
	dev->dev.coherent_dma_mask = 0xffffffffull;
	pci_dma_configure(dev);

	pci_set_dma_max_seg_size(dev, 65536);
	pci_set_dma_seg_boundary(dev, 0xffffffff);

	pci_fixup_device(pci_fixup_header, dev);

	pci_reassigndev_resource_alignment(dev);

	dev->state_saved = false;

	pci_init_capabilities(dev);

	down_write(&pci_bus_sem);
	list_add_tail(&dev->bus_list, &bus->devices);
	up_write(&pci_bus_sem);

	ret = pcibios_add_device(dev);
	WARN_ON(ret < 0);

	pci_set_msi_domain(dev);

	dev->match_driver = false;
	ret = device_add(&dev->dev);
	WARN_ON(ret < 0);
}

struct pci_dev *pci_scan_single_device(struct pci_bus *bus, int devfn)
{
	struct pci_dev *dev;

	dev = pci_get_slot(bus, devfn);
	if (dev) {
		pci_dev_put(dev);
		return dev;
	}

	dev = pci_scan_device(bus, devfn);
	if (!dev)
		return NULL;

	pci_device_add(dev, bus);

	return dev;
}
EXPORT_SYMBOL(pci_scan_single_device);

static unsigned next_fn(struct pci_bus *bus, struct pci_dev *dev, unsigned fn)
{
	int pos;
	u16 cap = 0;
	unsigned next_fn;

	if (pci_ari_enabled(bus)) {
		if (!dev)
			return 0;
		pos = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_ARI);
		if (!pos)
			return 0;

		pci_read_config_word(dev, pos + PCI_ARI_CAP, &cap);
		next_fn = PCI_ARI_CAP_NFN(cap);
		if (next_fn <= fn)
			return 0;	 

		return next_fn;
	}

	if (!dev || dev->multifunction)
		return (fn + 1) % 8;

	return 0;
}

static int only_one_child(struct pci_bus *bus)
{
	struct pci_dev *parent = bus->self;

	if (!parent || !pci_is_pcie(parent))
		return 0;
	if (pci_pcie_type(parent) == PCI_EXP_TYPE_ROOT_PORT)
		return 1;
	if (parent->has_secondary_link &&
	    !pci_has_flag(PCI_SCAN_ALL_PCIE_DEVS))
		return 1;
	return 0;
}

int pci_scan_slot(struct pci_bus *bus, int devfn)
{
	unsigned fn, nr = 0;
	struct pci_dev *dev;

	if (only_one_child(bus) && (devfn > 0))
		return 0;  

	dev = pci_scan_single_device(bus, devfn);
	if (!dev)
		return 0;
	if (!dev->is_added)
		nr++;

	for (fn = next_fn(bus, dev, 0); fn > 0; fn = next_fn(bus, dev, fn)) {
		dev = pci_scan_single_device(bus, devfn + fn);
		if (dev) {
			if (!dev->is_added)
				nr++;
			dev->multifunction = 1;
		}
	}

	if (bus->self && nr)
		pcie_aspm_init_link_state(bus->self);

	return nr;
}
EXPORT_SYMBOL(pci_scan_slot);

static int pcie_find_smpss(struct pci_dev *dev, void *data)
{
	u8 *smpss = data;

	if (!pci_is_pcie(dev))
		return 0;

	if (dev->is_hotplug_bridge &&
	    pci_pcie_type(dev) != PCI_EXP_TYPE_ROOT_PORT)
		*smpss = 0;

	if (*smpss > dev->pcie_mpss)
		*smpss = dev->pcie_mpss;

	return 0;
}

static void pcie_write_mps(struct pci_dev *dev, int mps)
{
	int rc;

	if (pcie_bus_config == PCIE_BUS_PERFORMANCE) {
		mps = 128 << dev->pcie_mpss;

		if (pci_pcie_type(dev) != PCI_EXP_TYPE_ROOT_PORT &&
		    dev->bus->self)
			 
			mps = min(mps, pcie_get_mps(dev->bus->self));
	}

	rc = pcie_set_mps(dev, mps);
	if (rc)
		dev_err(&dev->dev, "Failed attempting to set the MPS\n");
}

static void pcie_write_mrrs(struct pci_dev *dev)
{
	int rc, mrrs;

	if (pcie_bus_config != PCIE_BUS_PERFORMANCE)
		return;

	mrrs = pcie_get_mps(dev);

	while (mrrs != pcie_get_readrq(dev) && mrrs >= 128) {
		rc = pcie_set_readrq(dev, mrrs);
		if (!rc)
			break;

		dev_warn(&dev->dev, "Failed attempting to set the MRRS\n");
		mrrs /= 2;
	}

	if (mrrs < 128)
		dev_err(&dev->dev, "MRRS was unable to be configured with a safe value.  If problems are experienced, try running with pci=pcie_bus_safe\n");
}

static int pcie_bus_configure_set(struct pci_dev *dev, void *data)
{
	int mps, orig_mps;

	if (!pci_is_pcie(dev))
		return 0;

	if (pcie_bus_config == PCIE_BUS_TUNE_OFF ||
	    pcie_bus_config == PCIE_BUS_DEFAULT)
		return 0;

	mps = 128 << *(u8 *)data;
	orig_mps = pcie_get_mps(dev);

	pcie_write_mps(dev, mps);
	pcie_write_mrrs(dev);

	dev_info(&dev->dev, "Max Payload Size set to %4d/%4d (was %4d), Max Read Rq %4d\n",
		 pcie_get_mps(dev), 128 << dev->pcie_mpss,
		 orig_mps, pcie_get_readrq(dev));

	return 0;
}

void pcie_bus_configure_settings(struct pci_bus *bus)
{
	u8 smpss = 0;

	if (!bus->self)
		return;

	if (!pci_is_pcie(bus->self))
		return;

	if (pcie_bus_config == PCIE_BUS_PEER2PEER)
		smpss = 0;

	if (pcie_bus_config == PCIE_BUS_SAFE) {
		smpss = bus->self->pcie_mpss;

		pcie_find_smpss(bus->self, &smpss);
		pci_walk_bus(bus, pcie_find_smpss, &smpss);
	}

	pcie_bus_configure_set(bus->self, &smpss);
	pci_walk_bus(bus, pcie_bus_configure_set, &smpss);
}
EXPORT_SYMBOL_GPL(pcie_bus_configure_settings);

unsigned int pci_scan_child_bus(struct pci_bus *bus)
{
	unsigned int devfn, pass, max = bus->busn_res.start;
	struct pci_dev *dev;

	dev_dbg(&bus->dev, "scanning bus\n");

	for (devfn = 0; devfn < 0x100; devfn += 8)
		pci_scan_slot(bus, devfn);

	max += pci_iov_bus_range(bus);

	if (!bus->is_added) {
		dev_dbg(&bus->dev, "fixups for bus\n");
		pcibios_fixup_bus(bus);
		bus->is_added = 1;
	}

	for (pass = 0; pass < 2; pass++)
		list_for_each_entry(dev, &bus->devices, bus_list) {
			if (pci_is_bridge(dev))
				max = pci_scan_bridge(bus, dev, max, pass);
		}

	dev_dbg(&bus->dev, "bus scan returning with max=%02x\n", max);
	return max;
}
EXPORT_SYMBOL_GPL(pci_scan_child_bus);

int __weak pcibios_root_bridge_prepare(struct pci_host_bridge *bridge)
{
	return 0;
}

void __weak pcibios_add_bus(struct pci_bus *bus)
{
}

void __weak pcibios_remove_bus(struct pci_bus *bus)
{
}

struct pci_bus *pci_create_root_bus(struct device *parent, int bus,
		struct pci_ops *ops, void *sysdata, struct list_head *resources)
{
	int error;
	struct pci_host_bridge *bridge;
	struct pci_bus *b, *b2;
	struct resource_entry *window, *n;
	struct resource *res;
	resource_size_t offset;
	char bus_addr[64];
	char *fmt;

	b = pci_alloc_bus(NULL);
	if (!b)
		return NULL;

	b->sysdata = sysdata;
	b->ops = ops;
	b->number = b->busn_res.start = bus;
	pci_bus_assign_domain_nr(b, parent);
	b2 = pci_find_bus(pci_domain_nr(b), bus);
	if (b2) {
		 
		dev_dbg(&b2->dev, "bus already known\n");
		goto err_out;
	}

	bridge = pci_alloc_host_bridge(b);
	if (!bridge)
		goto err_out;

	bridge->dev.parent = parent;
	bridge->dev.release = pci_release_host_bridge_dev;
	dev_set_name(&bridge->dev, "pci%04x:%02x", pci_domain_nr(b), bus);
	error = pcibios_root_bridge_prepare(bridge);
	if (error) {
		kfree(bridge);
		goto err_out;
	}

	error = device_register(&bridge->dev);
	if (error) {
		put_device(&bridge->dev);
		goto err_out;
	}
	b->bridge = get_device(&bridge->dev);
	device_enable_async_suspend(b->bridge);
	pci_set_bus_of_node(b);
	pci_set_bus_msi_domain(b);

	if (!parent)
		set_dev_node(b->bridge, pcibus_to_node(b));

	b->dev.class = &pcibus_class;
	b->dev.parent = b->bridge;
	dev_set_name(&b->dev, "%04x:%02x", pci_domain_nr(b), bus);
	error = device_register(&b->dev);
	if (error)
		goto class_dev_reg_err;

	pcibios_add_bus(b);

	pci_create_legacy_files(b);

	if (parent)
		dev_info(parent, "PCI host bridge to bus %s\n", dev_name(&b->dev));
	else
		printk(KERN_INFO "PCI host bridge to bus %s\n", dev_name(&b->dev));

	resource_list_for_each_entry_safe(window, n, resources) {
		list_move_tail(&window->node, &bridge->windows);
		res = window->res;
		offset = window->offset;
		if (res->flags & IORESOURCE_BUS)
			pci_bus_insert_busn_res(b, bus, res->end);
		else
			pci_bus_add_resource(b, res, 0);
		if (offset) {
			if (resource_type(res) == IORESOURCE_IO)
				fmt = " (bus address [%#06llx-%#06llx])";
			else
				fmt = " (bus address [%#010llx-%#010llx])";
			snprintf(bus_addr, sizeof(bus_addr), fmt,
				 (unsigned long long) (res->start - offset),
				 (unsigned long long) (res->end - offset));
		} else
			bus_addr[0] = '\0';
		dev_info(&b->dev, "root bus resource %pR%s\n", res, bus_addr);
	}

	down_write(&pci_bus_sem);
	list_add_tail(&b->node, &pci_root_buses);
	up_write(&pci_bus_sem);

	return b;

class_dev_reg_err:
	put_device(&bridge->dev);
	device_unregister(&bridge->dev);
err_out:
	kfree(b);
	return NULL;
}
EXPORT_SYMBOL_GPL(pci_create_root_bus);

int pci_bus_insert_busn_res(struct pci_bus *b, int bus, int bus_max)
{
	struct resource *res = &b->busn_res;
	struct resource *parent_res, *conflict;

	res->start = bus;
	res->end = bus_max;
	res->flags = IORESOURCE_BUS;

	if (!pci_is_root_bus(b))
		parent_res = &b->parent->busn_res;
	else {
		parent_res = get_pci_domain_busn_res(pci_domain_nr(b));
		res->flags |= IORESOURCE_PCI_FIXED;
	}

	conflict = request_resource_conflict(parent_res, res);

	if (conflict)
		dev_printk(KERN_DEBUG, &b->dev,
			   "busn_res: can not insert %pR under %s%pR (conflicts with %s %pR)\n",
			    res, pci_is_root_bus(b) ? "domain " : "",
			    parent_res, conflict->name, conflict);

	return conflict == NULL;
}

int pci_bus_update_busn_res_end(struct pci_bus *b, int bus_max)
{
	struct resource *res = &b->busn_res;
	struct resource old_res = *res;
	resource_size_t size;
	int ret;

	if (res->start > bus_max)
		return -EINVAL;

	size = bus_max - res->start + 1;
	ret = adjust_resource(res, res->start, size);
	dev_printk(KERN_DEBUG, &b->dev,
			"busn_res: %pR end %s updated to %02x\n",
			&old_res, ret ? "can not be" : "is", bus_max);

	if (!ret && !res->parent)
		pci_bus_insert_busn_res(b, res->start, res->end);

	return ret;
}

void pci_bus_release_busn_res(struct pci_bus *b)
{
	struct resource *res = &b->busn_res;
	int ret;

	if (!res->flags || !res->parent)
		return;

	ret = release_resource(res);
	dev_printk(KERN_DEBUG, &b->dev,
			"busn_res: %pR %s released\n",
			res, ret ? "can not be" : "is");
}

struct pci_bus *pci_scan_root_bus_msi(struct device *parent, int bus,
		struct pci_ops *ops, void *sysdata,
		struct list_head *resources, struct msi_controller *msi)
{
	struct resource_entry *window;
	bool found = false;
	struct pci_bus *b;
	int max;

	resource_list_for_each_entry(window, resources)
		if (window->res->flags & IORESOURCE_BUS) {
			found = true;
			break;
		}

	b = pci_create_root_bus(parent, bus, ops, sysdata, resources);
	if (!b)
		return NULL;

	b->msi = msi;

	if (!found) {
		dev_info(&b->dev,
		 "No busn resource found for root bus, will use [bus %02x-ff]\n",
			bus);
		pci_bus_insert_busn_res(b, bus, 255);
	}

	max = pci_scan_child_bus(b);

	if (!found)
		pci_bus_update_busn_res_end(b, max);

	return b;
}

struct pci_bus *pci_scan_root_bus(struct device *parent, int bus,
		struct pci_ops *ops, void *sysdata, struct list_head *resources)
{
	return pci_scan_root_bus_msi(parent, bus, ops, sysdata, resources,
				     NULL);
}
EXPORT_SYMBOL(pci_scan_root_bus);

struct pci_bus *pci_scan_bus(int bus, struct pci_ops *ops,
					void *sysdata)
{
	LIST_HEAD(resources);
	struct pci_bus *b;

	pci_add_resource(&resources, &ioport_resource);
	pci_add_resource(&resources, &iomem_resource);
	pci_add_resource(&resources, &busn_resource);
	b = pci_create_root_bus(NULL, bus, ops, sysdata, &resources);
	if (b) {
		pci_scan_child_bus(b);
	} else {
		pci_free_resource_list(&resources);
	}
	return b;
}
EXPORT_SYMBOL(pci_scan_bus);

unsigned int pci_rescan_bus_bridge_resize(struct pci_dev *bridge)
{
	unsigned int max;
	struct pci_bus *bus = bridge->subordinate;

	max = pci_scan_child_bus(bus);

	pci_assign_unassigned_bridge_resources(bridge);

	pci_bus_add_devices(bus);

	return max;
}

unsigned int pci_rescan_bus(struct pci_bus *bus)
{
	unsigned int max;

	max = pci_scan_child_bus(bus);
	pci_assign_unassigned_bus_resources(bus);
	pci_bus_add_devices(bus);

	return max;
}
EXPORT_SYMBOL_GPL(pci_rescan_bus);

static DEFINE_MUTEX(pci_rescan_remove_lock);

void pci_lock_rescan_remove(void)
{
	mutex_lock(&pci_rescan_remove_lock);
}
EXPORT_SYMBOL_GPL(pci_lock_rescan_remove);

void pci_unlock_rescan_remove(void)
{
	mutex_unlock(&pci_rescan_remove_lock);
}
EXPORT_SYMBOL_GPL(pci_unlock_rescan_remove);

static int __init pci_sort_bf_cmp(const struct device *d_a,
				  const struct device *d_b)
{
	const struct pci_dev *a = to_pci_dev(d_a);
	const struct pci_dev *b = to_pci_dev(d_b);

	if      (pci_domain_nr(a->bus) < pci_domain_nr(b->bus)) return -1;
	else if (pci_domain_nr(a->bus) > pci_domain_nr(b->bus)) return  1;

	if      (a->bus->number < b->bus->number) return -1;
	else if (a->bus->number > b->bus->number) return  1;

	if      (a->devfn < b->devfn) return -1;
	else if (a->devfn > b->devfn) return  1;

	return 0;
}

void __init pci_sort_breadthfirst(void)
{
	bus_sort_breadthfirst(&pci_bus_type, &pci_sort_bf_cmp);
}
