#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/screen_info.h>
#include <linux/ioport.h>
#include <linux/acpi.h>
#include <linux/sfi.h>
#include <linux/apm_bios.h>
#include <linux/initrd.h>
#include <linux/bootmem.h>
#include <linux/memblock.h>
#include <linux/seq_file.h>
#include <linux/console.h>
#include <linux/root_dev.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/efi.h>
#include <linux/init.h>
#include <linux/edd.h>
#include <linux/iscsi_ibft.h>
#include <linux/nodemask.h>
#include <linux/kexec.h>
#include <linux/dmi.h>
#include <linux/pfn.h>
#include <linux/pci.h>
#include <asm/pci-direct.h>
#include <linux/init_ohci1394_dma.h>
#include <linux/kvm_para.h>
#include <linux/dma-contiguous.h>

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/ptrace.h>
#include <linux/user.h>
#include <linux/delay.h>

#include <linux/kallsyms.h>
#include <linux/cpufreq.h>
#include <linux/dma-mapping.h>
#include <linux/ctype.h>
#include <linux/uaccess.h>

#include <linux/percpu.h>
#include <linux/crash_dump.h>
#include <linux/tboot.h>
#include <linux/jiffies.h>

#include <video/edid.h>

#include <asm/mtrr.h>
#include <asm/apic.h>
#include <asm/realmode.h>
#include <asm/e820.h>
#include <asm/mpspec.h>
#include <asm/setup.h>
#include <asm/efi.h>
#include <asm/timer.h>
#include <asm/i8259.h>
#include <asm/sections.h>
#include <asm/io_apic.h>
#include <asm/ist.h>
#include <asm/setup_arch.h>
#include <asm/bios_ebda.h>
#include <asm/cacheflush.h>
#include <asm/processor.h>
#include <asm/bugs.h>
#include <asm/kasan.h>

#include <asm/vsyscall.h>
#include <asm/cpu.h>
#include <asm/desc.h>
#include <asm/dma.h>
#include <asm/iommu.h>
#include <asm/gart.h>
#include <asm/mmu_context.h>
#include <asm/proto.h>

#include <asm/paravirt.h>
#include <asm/hypervisor.h>
#include <asm/olpc_ofw.h>

#include <asm/percpu.h>
#include <asm/topology.h>
#include <asm/apicdef.h>
#include <asm/amd_nb.h>
#include <asm/mce.h>
#include <asm/alternative.h>
#include <asm/prom.h>
#include <asm/microcode.h>

#if defined(MY_ABC_HERE) && defined(MY_ABC_HERE)
#include  <linux/synobios.h>

#ifdef MY_ABC_HERE
#include <linux/gpio.h>
#endif  

#ifdef MY_DEF_HERE
extern u32 syno_pch_lpc_gpio_pin(int pin, int *pValue, int isWrite);
#endif  
#endif  

#ifdef MY_ABC_HERE
extern long g_syno_hdd_powerup_seq;
#endif  

unsigned long max_low_pfn_mapped;
unsigned long max_pfn_mapped;

#ifdef CONFIG_DMI
RESERVE_BRK(dmi_alloc, 65536);
#endif

static __initdata unsigned long _brk_start = (unsigned long)__brk_base;
unsigned long _brk_end = (unsigned long)__brk_base;

#ifdef CONFIG_X86_64
int default_cpu_present_to_apicid(int mps_cpu)
{
	return __default_cpu_present_to_apicid(mps_cpu);
}

int default_check_phys_apicid_present(int phys_apicid)
{
	return __default_check_phys_apicid_present(phys_apicid);
}
#endif

struct boot_params boot_params;

static struct resource data_resource = {
	.name	= "Kernel data",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_MEM
};

static struct resource code_resource = {
	.name	= "Kernel code",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_MEM
};

static struct resource bss_resource = {
	.name	= "Kernel bss",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_MEM
};

#ifdef CONFIG_X86_32
 
struct cpuinfo_x86 new_cpu_data = {
	.wp_works_ok = -1,
};
 
struct cpuinfo_x86 boot_cpu_data __read_mostly = {
	.wp_works_ok = -1,
};
EXPORT_SYMBOL(boot_cpu_data);

unsigned int def_to_bigsmp;

unsigned int machine_id;
unsigned int machine_submodel_id;
unsigned int BIOS_revision;

struct apm_info apm_info;
EXPORT_SYMBOL(apm_info);

#if defined(CONFIG_X86_SPEEDSTEP_SMI) || \
	defined(CONFIG_X86_SPEEDSTEP_SMI_MODULE)
struct ist_info ist_info;
EXPORT_SYMBOL(ist_info);
#else
struct ist_info ist_info;
#endif

#else
struct cpuinfo_x86 boot_cpu_data __read_mostly = {
	.x86_phys_bits = MAX_PHYSMEM_BITS,
};
EXPORT_SYMBOL(boot_cpu_data);
#endif

#if !defined(CONFIG_X86_PAE) || defined(CONFIG_X86_64)
__visible unsigned long mmu_cr4_features;
#else
__visible unsigned long mmu_cr4_features = X86_CR4_PAE;
#endif

int bootloader_type, bootloader_version;

struct screen_info screen_info;
EXPORT_SYMBOL(screen_info);
struct edid_info edid_info;
EXPORT_SYMBOL_GPL(edid_info);

extern int root_mountflags;

unsigned long saved_video_mode;

#define RAMDISK_IMAGE_START_MASK	0x07FF
#define RAMDISK_PROMPT_FLAG		0x8000
#define RAMDISK_LOAD_FLAG		0x4000

static char __initdata command_line[COMMAND_LINE_SIZE];
#ifdef CONFIG_CMDLINE_BOOL
static char __initdata builtin_cmdline[COMMAND_LINE_SIZE] = CONFIG_CMDLINE;
#endif

#if defined(CONFIG_EDD) || defined(CONFIG_EDD_MODULE)
struct edd edd;
#ifdef CONFIG_EDD_MODULE
EXPORT_SYMBOL(edd);
#endif
 
static inline void __init copy_edd(void)
{
     memcpy(edd.mbr_signature, boot_params.edd_mbr_sig_buffer,
	    sizeof(edd.mbr_signature));
     memcpy(edd.edd_info, boot_params.eddbuf, sizeof(edd.edd_info));
     edd.mbr_signature_nr = boot_params.edd_mbr_sig_buf_entries;
     edd.edd_info_nr = boot_params.eddbuf_entries;
}
#else
static inline void __init copy_edd(void)
{
}
#endif

void * __init extend_brk(size_t size, size_t align)
{
	size_t mask = align - 1;
	void *ret;

	BUG_ON(_brk_start == 0);
	BUG_ON(align & mask);

	_brk_end = (_brk_end + mask) & ~mask;
	BUG_ON((char *)(_brk_end + size) > __brk_limit);

	ret = (void *)_brk_end;
	_brk_end += size;

	memset(ret, 0, size);

	return ret;
}

#if defined(MY_ABC_HERE) && defined(MY_ABC_HERE) && !defined(MY_DEF_HERE) && !defined(MY_ABC_HERE) && !defined(MY_DEF_HERE)
 
#define SYNO_MAX_HDD_PRZ	4
#define GPIO_UNDEF			0xFF

static u8 SYNO_GET_HDD_ENABLE_PIN(const int index)
{
	u8 ret = GPIO_UNDEF;

#if defined(MY_DEF_HERE)
	u8 HddEnPinMap[] = {10, 15, 16, 17};
#else
	u8 *HddEnPinMap = NULL;
#endif

	if (NULL == HddEnPinMap) {
		goto END;
	}

	if (1 > index || (0 < g_syno_hdd_powerup_seq && g_syno_hdd_powerup_seq < index)) {
		printk("SYNO_GET_HDD_ENABLE_PIN(%d) is illegal", index);
		WARN_ON(1);
		goto END;
	}

	ret = HddEnPinMap[index-1];

END:
	return ret;
}

static u32 SYNO_X86_GPIO_PIN_SET(int pin, int *pValue)
{
	u32 ret = 0;

#if defined(MY_DEF_HERE)
	ret = syno_pch_lpc_gpio_pin(pin, pValue, 1);
#elif defined(MY_ABC_HERE)
	ret = syno_gpio_value_set(pin, *pValue);
#endif  
	return ret;
}

int SYNO_CTRL_HDD_POWERON(int index, int value)
{
	int iRet = -EINVAL;

	if (syno_is_hw_version(HW_DS415p)) {
		switch (index) {
			case 0:
				 
				SYNO_X86_GPIO_PIN_SET(SYNO_GET_HDD_ENABLE_PIN(1), &value);
				mdelay(200);
				SYNO_X86_GPIO_PIN_SET(SYNO_GET_HDD_ENABLE_PIN(2) , &value);
				mdelay(200);
				SYNO_X86_GPIO_PIN_SET(SYNO_GET_HDD_ENABLE_PIN(3) , &value);
				mdelay(200);
				SYNO_X86_GPIO_PIN_SET(SYNO_GET_HDD_ENABLE_PIN(4) , &value);
				break;
			case 1 ... 4:
				SYNO_X86_GPIO_PIN_SET(SYNO_GET_HDD_ENABLE_PIN(index) , &value);
				break;
			default:
				goto END;
		}
	 
	}else if(syno_is_hw_version(HW_DS716p) ||
		syno_is_hw_version(HW_DS216p) ||
		syno_is_hw_version(HW_DS216pII) ||
		syno_is_hw_version(HW_DS716pII)) {
		switch(index){
			case 0:
				 
				SYNO_X86_GPIO_PIN_SET(SYNO_GET_HDD_ENABLE_PIN(1) , &value);
				mdelay(200);
				SYNO_X86_GPIO_PIN_SET(SYNO_GET_HDD_ENABLE_PIN(2) , &value);
				break;
			case 1 ... 2:
				SYNO_X86_GPIO_PIN_SET(SYNO_GET_HDD_ENABLE_PIN(index) , &value);
				break;
			default:
				goto END;
		}
	 
	} else {
		goto END;
	}

	iRet = 0;
END:
	return iRet;
}

static u8 SYNO_GET_HDD_PRESENT_PIN(const int index)
{
	u8 ret = GPIO_UNDEF;

#if defined(MY_DEF_HERE)
	u8 przPinMap[] = {18, 28, 34, 44};
#else
	u8 *przPinMap = NULL;
#endif

	if (NULL == przPinMap) {
		goto END;
	}

	if (1 > index || (0 < g_syno_hdd_powerup_seq && g_syno_hdd_powerup_seq < index)) {
		printk("SYNO_GET_HDD_PRESENT_PIN(%d) is illegal", index);
		WARN_ON(1);
		goto END;
	}

	ret = przPinMap[index-1];

END:
	return ret;
}

int SYNO_CHECK_HDD_PRESENT(int index)
{
	int iPrzVal = 1;  
	u8 iPin = SYNO_GET_HDD_PRESENT_PIN(index);

#if defined(MY_DEF_HERE)
	const int iInverseValue = 1;
#else
	const int iInverseValue = 0;
#endif

	if (GPIO_UNDEF == iPin) {
		goto END;
	}

	if (0 < g_syno_hdd_powerup_seq && g_syno_hdd_powerup_seq < index) {
		goto END;
	}

#if defined(MY_DEF_HERE)
	syno_pch_lpc_gpio_pin(iPin, &iPrzVal, 0);
#elif defined(MY_ABC_HERE)
	syno_gpio_value_get(iPin, &iPrzVal);
#endif  

	if (iInverseValue) {
		if (iPrzVal) {
			iPrzVal = 0;
		} else {
			iPrzVal = 1;
		}
	}

END:
	return iPrzVal;
}

int SYNO_SUPPORT_HDD_DYNAMIC_ENABLE_POWER(void)
{
	int iRet = 0;

	if (0 > g_syno_hdd_powerup_seq || SYNO_MAX_HDD_PRZ < g_syno_hdd_powerup_seq) {
		goto END;
	}

	if (syno_is_hw_version(HW_DS415p) ||
	    syno_is_hw_version(HW_DS916p) ||
	    syno_is_hw_version(HW_DS713p) ||
	    syno_is_hw_version(HW_DS716p) ||
	    syno_is_hw_version(HW_DS416play) ||
	    syno_is_hw_version(HW_DS216p) ||
	    syno_is_hw_version(HW_DS216pII) ||
	    syno_is_hw_version(HW_DS716pII)) {
		iRet = 1;
	} else {
		goto END;
	}

END:
	return iRet;
}

EXPORT_SYMBOL(SYNO_CTRL_HDD_POWERON);
EXPORT_SYMBOL(SYNO_CHECK_HDD_PRESENT);
EXPORT_SYMBOL(SYNO_SUPPORT_HDD_DYNAMIC_ENABLE_POWER);
#endif  

#ifdef MY_DEF_HERE
 
int SynoProcEncPwrCtl(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int iValue = 0;

	if (write) {
		if (-1 == SYNO_X86_GPIO_PIN_SET(20, &iValue)) {
			printk("fail to drive PCH GPIO20 to low\n");
		}
	}

	return proc_dointvec(table, write, buffer, lenp, ppos);
}
EXPORT_SYMBOL(SynoProcEncPwrCtl);
#endif  

#ifdef CONFIG_X86_32
static void __init cleanup_highmap(void)
{
}
#endif

static void __init reserve_brk(void)
{
	if (_brk_end > _brk_start)
		memblock_reserve(__pa_symbol(_brk_start),
				 _brk_end - _brk_start);

	_brk_start = 0;
}

u64 relocated_ramdisk;

#ifdef CONFIG_BLK_DEV_INITRD

static u64 __init get_ramdisk_image(void)
{
	u64 ramdisk_image = boot_params.hdr.ramdisk_image;

	ramdisk_image |= (u64)boot_params.ext_ramdisk_image << 32;

	return ramdisk_image;
}
static u64 __init get_ramdisk_size(void)
{
	u64 ramdisk_size = boot_params.hdr.ramdisk_size;

	ramdisk_size |= (u64)boot_params.ext_ramdisk_size << 32;

	return ramdisk_size;
}

static void __init relocate_initrd(void)
{
	 
	u64 ramdisk_image = get_ramdisk_image();
	u64 ramdisk_size  = get_ramdisk_size();
	u64 area_size     = PAGE_ALIGN(ramdisk_size);

	relocated_ramdisk = memblock_find_in_range(0, PFN_PHYS(max_pfn_mapped),
						   area_size, PAGE_SIZE);

	if (!relocated_ramdisk)
		panic("Cannot find place for new RAMDISK of size %lld\n",
		      ramdisk_size);

	memblock_reserve(relocated_ramdisk, area_size);
	initrd_start = relocated_ramdisk + PAGE_OFFSET;
	initrd_end   = initrd_start + ramdisk_size;
	printk(KERN_INFO "Allocated new RAMDISK: [mem %#010llx-%#010llx]\n",
	       relocated_ramdisk, relocated_ramdisk + ramdisk_size - 1);

	copy_from_early_mem((void *)initrd_start, ramdisk_image, ramdisk_size);

	printk(KERN_INFO "Move RAMDISK from [mem %#010llx-%#010llx] to"
		" [mem %#010llx-%#010llx]\n",
		ramdisk_image, ramdisk_image + ramdisk_size - 1,
		relocated_ramdisk, relocated_ramdisk + ramdisk_size - 1);
}

static void __init early_reserve_initrd(void)
{
	 
	u64 ramdisk_image = get_ramdisk_image();
	u64 ramdisk_size  = get_ramdisk_size();
	u64 ramdisk_end   = PAGE_ALIGN(ramdisk_image + ramdisk_size);

	if (!boot_params.hdr.type_of_loader ||
	    !ramdisk_image || !ramdisk_size)
		return;		 

	memblock_reserve(ramdisk_image, ramdisk_end - ramdisk_image);
}
static void __init reserve_initrd(void)
{
	 
	u64 ramdisk_image = get_ramdisk_image();
	u64 ramdisk_size  = get_ramdisk_size();
	u64 ramdisk_end   = PAGE_ALIGN(ramdisk_image + ramdisk_size);
	u64 mapped_size;

	if (!boot_params.hdr.type_of_loader ||
	    !ramdisk_image || !ramdisk_size)
		return;		 

	initrd_start = 0;

	mapped_size = memblock_mem_size(max_pfn_mapped);
	if (ramdisk_size >= (mapped_size>>1))
		panic("initrd too large to handle, "
		       "disabling initrd (%lld needed, %lld available)\n",
		       ramdisk_size, mapped_size>>1);

	printk(KERN_INFO "RAMDISK: [mem %#010llx-%#010llx]\n", ramdisk_image,
			ramdisk_end - 1);

	if (pfn_range_is_mapped(PFN_DOWN(ramdisk_image),
				PFN_DOWN(ramdisk_end))) {
		 
		initrd_start = ramdisk_image + PAGE_OFFSET;
		initrd_end = initrd_start + ramdisk_size;
		return;
	}

	relocate_initrd();

	memblock_free(ramdisk_image, ramdisk_end - ramdisk_image);
}
#else
static void __init early_reserve_initrd(void)
{
}
static void __init reserve_initrd(void)
{
}
#endif  

static void __init parse_setup_data(void)
{
	struct setup_data *data;
	u64 pa_data, pa_next;

	pa_data = boot_params.hdr.setup_data;
	while (pa_data) {
		u32 data_len, data_type;

		data = early_memremap(pa_data, sizeof(*data));
		data_len = data->len + sizeof(struct setup_data);
		data_type = data->type;
		pa_next = data->next;
		early_memunmap(data, sizeof(*data));

		switch (data_type) {
		case SETUP_E820_EXT:
			parse_e820_ext(pa_data, data_len);
			break;
		case SETUP_DTB:
			add_dtb(pa_data);
			break;
		case SETUP_EFI:
			parse_efi_setup(pa_data, data_len);
			break;
		default:
			break;
		}
		pa_data = pa_next;
	}
}

static void __init e820_reserve_setup_data(void)
{
	struct setup_data *data;
	u64 pa_data;

	pa_data = boot_params.hdr.setup_data;
	if (!pa_data)
		return;

	while (pa_data) {
		data = early_memremap(pa_data, sizeof(*data));
		e820_update_range(pa_data, sizeof(*data)+data->len,
			 E820_RAM, E820_RESERVED_KERN);
		pa_data = data->next;
		early_memunmap(data, sizeof(*data));
	}

	sanitize_e820_map(e820.map, ARRAY_SIZE(e820.map), &e820.nr_map);
	memcpy(&e820_saved, &e820, sizeof(struct e820map));
	printk(KERN_INFO "extended physical RAM map:\n");
	e820_print_map("reserve setup_data");
}

static void __init memblock_x86_reserve_range_setup_data(void)
{
	struct setup_data *data;
	u64 pa_data;

	pa_data = boot_params.hdr.setup_data;
	while (pa_data) {
		data = early_memremap(pa_data, sizeof(*data));
		memblock_reserve(pa_data, sizeof(*data) + data->len);
		pa_data = data->next;
		early_memunmap(data, sizeof(*data));
	}
}

#ifdef CONFIG_KEXEC_CORE

#define CRASH_ALIGN		(16 << 20)

#ifdef CONFIG_X86_32
# define CRASH_ADDR_LOW_MAX	(512 << 20)
# define CRASH_ADDR_HIGH_MAX	(512 << 20)
#else
# define CRASH_ADDR_LOW_MAX	(896UL << 20)
# define CRASH_ADDR_HIGH_MAX	MAXMEM
#endif

static int __init reserve_crashkernel_low(void)
{
#ifdef CONFIG_X86_64
	unsigned long long base, low_base = 0, low_size = 0;
	unsigned long total_low_mem;
	int ret;

	total_low_mem = memblock_mem_size(1UL << (32 - PAGE_SHIFT));

	ret = parse_crashkernel_low(boot_command_line, total_low_mem, &low_size, &base);
	if (ret) {
		 
		low_size = max(swiotlb_size_or_default() + (8UL << 20), 256UL << 20);
	} else {
		 
		if (!low_size)
			return 0;
	}

	low_base = memblock_find_in_range(low_size, 1ULL << 32, low_size, CRASH_ALIGN);
	if (!low_base) {
		pr_err("Cannot reserve %ldMB crashkernel low memory, please try smaller size.\n",
		       (unsigned long)(low_size >> 20));
		return -ENOMEM;
	}

	ret = memblock_reserve(low_base, low_size);
	if (ret) {
		pr_err("%s: Error reserving crashkernel low memblock.\n", __func__);
		return ret;
	}

	pr_info("Reserving %ldMB of low memory at %ldMB for crashkernel (System low RAM: %ldMB)\n",
		(unsigned long)(low_size >> 20),
		(unsigned long)(low_base >> 20),
		(unsigned long)(total_low_mem >> 20));

	crashk_low_res.start = low_base;
	crashk_low_res.end   = low_base + low_size - 1;
	insert_resource(&iomem_resource, &crashk_low_res);
#endif
	return 0;
}

static void __init reserve_crashkernel(void)
{
	unsigned long long crash_size, crash_base, total_mem;
	bool high = false;
	int ret;

	total_mem = memblock_phys_mem_size();

	ret = parse_crashkernel(boot_command_line, total_mem, &crash_size, &crash_base);
	if (ret != 0 || crash_size <= 0) {
		 
		ret = parse_crashkernel_high(boot_command_line, total_mem,
					     &crash_size, &crash_base);
		if (ret != 0 || crash_size <= 0)
			return;
		high = true;
	}

	if (crash_base <= 0) {
		 
		crash_base = memblock_find_in_range(CRASH_ALIGN,
						    high ? CRASH_ADDR_HIGH_MAX
							 : CRASH_ADDR_LOW_MAX,
						    crash_size, CRASH_ALIGN);
		if (!crash_base) {
			pr_info("crashkernel reservation failed - No suitable area found.\n");
			return;
		}

	} else {
		unsigned long long start;

		start = memblock_find_in_range(crash_base,
					       crash_base + crash_size,
					       crash_size, 1 << 20);
		if (start != crash_base) {
			pr_info("crashkernel reservation failed - memory is in use.\n");
			return;
		}
	}
	ret = memblock_reserve(crash_base, crash_size);
	if (ret) {
		pr_err("%s: Error reserving crashkernel memblock.\n", __func__);
		return;
	}

	if (crash_base >= (1ULL << 32) && reserve_crashkernel_low()) {
		memblock_free(crash_base, crash_size);
		return;
	}

	pr_info("Reserving %ldMB of memory at %ldMB for crashkernel (System RAM: %ldMB)\n",
		(unsigned long)(crash_size >> 20),
		(unsigned long)(crash_base >> 20),
		(unsigned long)(total_mem >> 20));

	crashk_res.start = crash_base;
	crashk_res.end   = crash_base + crash_size - 1;
	insert_resource(&iomem_resource, &crashk_res);
}
#else
static void __init reserve_crashkernel(void)
{
}
#endif

static struct resource standard_io_resources[] = {
	{ .name = "dma1", .start = 0x00, .end = 0x1f,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "pic1", .start = 0x20, .end = 0x21,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "timer0", .start = 0x40, .end = 0x43,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "timer1", .start = 0x50, .end = 0x53,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "keyboard", .start = 0x60, .end = 0x60,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "keyboard", .start = 0x64, .end = 0x64,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "dma page reg", .start = 0x80, .end = 0x8f,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "pic2", .start = 0xa0, .end = 0xa1,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "dma2", .start = 0xc0, .end = 0xdf,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "fpu", .start = 0xf0, .end = 0xff,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO }
};

void __init reserve_standard_io_resources(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(standard_io_resources); i++)
		request_resource(&ioport_resource, &standard_io_resources[i]);

}

static __init void reserve_ibft_region(void)
{
	unsigned long addr, size = 0;

	addr = find_ibft_region(&size);

	if (size)
		memblock_reserve(addr, size);
}

static bool __init snb_gfx_workaround_needed(void)
{
#ifdef CONFIG_PCI
	int i;
	u16 vendor, devid;
	static const __initconst u16 snb_ids[] = {
		0x0102,
		0x0112,
		0x0122,
		0x0106,
		0x0116,
		0x0126,
		0x010a,
	};

	if (!early_pci_allowed())
		return false;

	vendor = read_pci_config_16(0, 2, 0, PCI_VENDOR_ID);
	if (vendor != 0x8086)
		return false;

	devid = read_pci_config_16(0, 2, 0, PCI_DEVICE_ID);
	for (i = 0; i < ARRAY_SIZE(snb_ids); i++)
		if (devid == snb_ids[i])
			return true;
#endif

	return false;
}

static void __init trim_snb_memory(void)
{
	static const __initconst unsigned long bad_pages[] = {
		0x20050000,
		0x20110000,
		0x20130000,
		0x20138000,
		0x40004000,
	};
	int i;

	if (!snb_gfx_workaround_needed())
		return;

	printk(KERN_DEBUG "reserving inaccessible SNB gfx pages\n");

	memblock_reserve(0, 1<<20);
	
	for (i = 0; i < ARRAY_SIZE(bad_pages); i++) {
		if (memblock_reserve(bad_pages[i], PAGE_SIZE))
			printk(KERN_WARNING "failed to reserve 0x%08lx\n",
			       bad_pages[i]);
	}
}

static void __init trim_platform_memory_ranges(void)
{
	trim_snb_memory();
}

static void __init trim_bios_range(void)
{
	 
	e820_update_range(0, PAGE_SIZE, E820_RAM, E820_RESERVED);

	e820_remove_range(BIOS_BEGIN, BIOS_END - BIOS_BEGIN, E820_RAM, 1);

	sanitize_e820_map(e820.map, ARRAY_SIZE(e820.map), &e820.nr_map);
}

static void __init e820_add_kernel_range(void)
{
	u64 start = __pa_symbol(_text);
	u64 size = __pa_symbol(_end) - start;

	if (e820_all_mapped(start, start + size, E820_RAM))
		return;

	pr_warn(".text .data .bss are not marked as E820_RAM!\n");
	e820_remove_range(start, size, E820_RAM, 0);
	e820_add_region(start, size, E820_RAM);
}

static unsigned reserve_low = CONFIG_X86_RESERVE_LOW << 10;

static int __init parse_reservelow(char *p)
{
	unsigned long long size;

	if (!p)
		return -EINVAL;

	size = memparse(p, &p);

	if (size < 4096)
		size = 4096;

	if (size > 640*1024)
		size = 640*1024;

	reserve_low = size;

	return 0;
}

early_param("reservelow", parse_reservelow);

static void __init trim_low_memory_range(void)
{
	memblock_reserve(0, ALIGN(reserve_low, PAGE_SIZE));
}
	
static int
dump_kernel_offset(struct notifier_block *self, unsigned long v, void *p)
{
	if (kaslr_enabled()) {
		pr_emerg("Kernel Offset: 0x%lx from 0x%lx (relocation range: 0x%lx-0x%lx)\n",
			 kaslr_offset(),
			 __START_KERNEL,
			 __START_KERNEL_map,
			 MODULES_VADDR-1);
	} else {
		pr_emerg("Kernel Offset: disabled\n");
	}

	return 0;
}

void __init setup_arch(char **cmdline_p)
{
	memblock_reserve(__pa_symbol(_text),
			 (unsigned long)__bss_stop - (unsigned long)_text);

	early_reserve_initrd();

#ifdef CONFIG_X86_32
	memcpy(&boot_cpu_data, &new_cpu_data, sizeof(new_cpu_data));

	clone_pgd_range(swapper_pg_dir     + KERNEL_PGD_BOUNDARY,
			initial_page_table + KERNEL_PGD_BOUNDARY,
			KERNEL_PGD_PTRS);

	load_cr3(swapper_pg_dir);
	 
	__flush_tlb_all();
#else
	printk(KERN_INFO "Command line: %s\n", boot_command_line);
#endif

	olpc_ofw_detect();

	early_trap_init();
	early_cpu_init();
	early_ioremap_init();

	setup_olpc_ofw_pgd();

	ROOT_DEV = old_decode_dev(boot_params.hdr.root_dev);
	screen_info = boot_params.screen_info;
	edid_info = boot_params.edid_info;
#ifdef CONFIG_X86_32
	apm_info.bios = boot_params.apm_bios_info;
	ist_info = boot_params.ist_info;
#endif
	saved_video_mode = boot_params.hdr.vid_mode;
	bootloader_type = boot_params.hdr.type_of_loader;
	if ((bootloader_type >> 4) == 0xe) {
		bootloader_type &= 0xf;
		bootloader_type |= (boot_params.hdr.ext_loader_type+0x10) << 4;
	}
	bootloader_version  = bootloader_type & 0xf;
	bootloader_version |= boot_params.hdr.ext_loader_ver << 4;

#ifdef CONFIG_BLK_DEV_RAM
	rd_image_start = boot_params.hdr.ram_size & RAMDISK_IMAGE_START_MASK;
	rd_prompt = ((boot_params.hdr.ram_size & RAMDISK_PROMPT_FLAG) != 0);
	rd_doload = ((boot_params.hdr.ram_size & RAMDISK_LOAD_FLAG) != 0);
#endif
#ifdef CONFIG_EFI
	if (!strncmp((char *)&boot_params.efi_info.efi_loader_signature,
		     EFI32_LOADER_SIGNATURE, 4)) {
		set_bit(EFI_BOOT, &efi.flags);
	} else if (!strncmp((char *)&boot_params.efi_info.efi_loader_signature,
		     EFI64_LOADER_SIGNATURE, 4)) {
		set_bit(EFI_BOOT, &efi.flags);
		set_bit(EFI_64BIT, &efi.flags);
	}

	if (efi_enabled(EFI_BOOT))
		efi_memblock_x86_reserve_range();
#endif

	x86_init.oem.arch_setup();

	iomem_resource.end = (1ULL << boot_cpu_data.x86_phys_bits) - 1;
	setup_memory_map();
	parse_setup_data();

	copy_edd();

	if (!boot_params.hdr.root_flags)
		root_mountflags &= ~MS_RDONLY;
	init_mm.start_code = (unsigned long) _text;
	init_mm.end_code = (unsigned long) _etext;
	init_mm.end_data = (unsigned long) _edata;
	init_mm.brk = _brk_end;

	mpx_mm_init(&init_mm);

	code_resource.start = __pa_symbol(_text);
	code_resource.end = __pa_symbol(_etext)-1;
	data_resource.start = __pa_symbol(_etext);
	data_resource.end = __pa_symbol(_edata)-1;
	bss_resource.start = __pa_symbol(__bss_start);
	bss_resource.end = __pa_symbol(__bss_stop)-1;

#ifdef CONFIG_CMDLINE_BOOL
#ifdef CONFIG_CMDLINE_OVERRIDE
	strlcpy(boot_command_line, builtin_cmdline, COMMAND_LINE_SIZE);
#else
	if (builtin_cmdline[0]) {
		 
		strlcat(builtin_cmdline, " ", COMMAND_LINE_SIZE);
		strlcat(builtin_cmdline, boot_command_line, COMMAND_LINE_SIZE);
		strlcpy(boot_command_line, builtin_cmdline, COMMAND_LINE_SIZE);
	}
#endif
#endif

	strlcpy(command_line, boot_command_line, COMMAND_LINE_SIZE);
	*cmdline_p = command_line;

	x86_configure_nx();

	parse_early_param();

	x86_report_nx();

	memblock_x86_reserve_range_setup_data();

	if (acpi_mps_check()) {
#ifdef CONFIG_X86_LOCAL_APIC
		disable_apic = 1;
#endif
		setup_clear_cpu_cap(X86_FEATURE_APIC);
	}

#ifdef CONFIG_PCI
	if (pci_early_dump_regs)
		early_dump_pci_devices();
#endif

	e820_reserve_setup_data();
	finish_e820_parsing();

	if (efi_enabled(EFI_BOOT))
		efi_init();

	dmi_scan_machine();
	dmi_memdev_walk();
	dmi_set_dump_stack_arch_desc();

	init_hypervisor_platform();

	x86_init.resources.probe_roms();

	insert_resource(&iomem_resource, &code_resource);
	insert_resource(&iomem_resource, &data_resource);
	insert_resource(&iomem_resource, &bss_resource);

	e820_add_kernel_range();
	trim_bios_range();
#ifdef CONFIG_X86_32
	if (ppro_with_ram_bug()) {
		e820_update_range(0x70000000ULL, 0x40000ULL, E820_RAM,
				  E820_RESERVED);
		sanitize_e820_map(e820.map, ARRAY_SIZE(e820.map), &e820.nr_map);
		printk(KERN_INFO "fixed physical RAM map:\n");
		e820_print_map("bad_ppro");
	}
#else
	early_gart_iommu_check();
#endif

	max_pfn = e820_end_of_ram_pfn();

	mtrr_bp_init();
	if (mtrr_trim_uncached_memory(max_pfn))
		max_pfn = e820_end_of_ram_pfn();

#ifdef CONFIG_X86_32
	 
	find_low_pfn_range();
#else
	check_x2apic();

	if (max_pfn > (1UL<<(32 - PAGE_SHIFT)))
		max_low_pfn = e820_end_of_low_ram_pfn();
	else
		max_low_pfn = max_pfn;

	high_memory = (void *)__va(max_pfn * PAGE_SIZE - 1) + 1;
#endif

	find_smp_config();

	reserve_ibft_region();

	early_alloc_pgt_buf();

	reserve_brk();

	cleanup_highmap();

	memblock_set_current_limit(ISA_END_ADDRESS);
	memblock_x86_fill();

	if (efi_enabled(EFI_BOOT)) {
		efi_fake_memmap();
		efi_find_mirror();
	}

	if (efi_enabled(EFI_MEMMAP))
		efi_reserve_boot_services();

	early_reserve_e820_mpc_new();

#ifdef CONFIG_X86_CHECK_BIOS_CORRUPTION
	setup_bios_corruption_check();
#endif

#ifdef CONFIG_X86_32
	printk(KERN_DEBUG "initial memory mapped: [mem 0x00000000-%#010lx]\n",
			(max_pfn_mapped<<PAGE_SHIFT) - 1);
#endif

	reserve_real_mode();

	trim_platform_memory_ranges();
	trim_low_memory_range();

	init_mem_mapping();

	early_trap_pf_init();

	setup_real_mode();

	memblock_set_current_limit(get_max_mapped());

#ifdef CONFIG_PROVIDE_OHCI1394_DMA_INIT
	if (init_ohci1394_dma_early)
		init_ohci1394_dma_on_all_controllers();
#endif
	 
	setup_log_buf(1);

	reserve_initrd();

#if defined(CONFIG_ACPI) && defined(CONFIG_BLK_DEV_INITRD)
	acpi_initrd_override((void *)initrd_start, initrd_end - initrd_start);
#endif

	vsmp_init();

	io_delay_init();

	acpi_boot_table_init();

	early_acpi_boot_init();

	initmem_init();
	dma_contiguous_reserve(max_pfn_mapped << PAGE_SHIFT);

	reserve_crashkernel();

	memblock_find_dma_reserve();

#ifdef CONFIG_KVM_GUEST
	kvmclock_init();
#endif

	x86_init.paging.pagetable_init();

	kasan_init();

	if (boot_cpu_data.cpuid_level >= 0) {
		 
		mmu_cr4_features = __read_cr4();
		if (trampoline_cr4_features)
			*trampoline_cr4_features = mmu_cr4_features;
	}

#ifdef CONFIG_X86_32
	 
	clone_pgd_range(initial_page_table + KERNEL_PGD_BOUNDARY,
			swapper_pg_dir     + KERNEL_PGD_BOUNDARY,
			KERNEL_PGD_PTRS);

	clone_pgd_range(initial_page_table,
			swapper_pg_dir     + KERNEL_PGD_BOUNDARY,
			min(KERNEL_PGD_PTRS, KERNEL_PGD_BOUNDARY));
#endif

	tboot_probe();

	map_vsyscall();

	generic_apic_probe();

	early_quirks();

	acpi_boot_init();
	sfi_init();
	x86_dtb_init();

	if (smp_found_config)
		get_smp_config();

	prefill_possible_map();

	init_cpu_to_node();

	init_apic_mappings();
	io_apic_init_mappings();

	kvm_guest_init();

	e820_reserve_resources();
	e820_mark_nosave_regions(max_low_pfn);

	x86_init.resources.reserve_resources();

	e820_setup_gap();

#ifdef CONFIG_VT
#if defined(CONFIG_VGA_CONSOLE)
	if (!efi_enabled(EFI_BOOT) || (efi_mem_type(0xa0000) != EFI_CONVENTIONAL_MEMORY))
		conswitchp = &vga_con;
#elif defined(CONFIG_DUMMY_CONSOLE)
	conswitchp = &dummy_con;
#endif
#endif
	x86_init.oem.banner();

	x86_init.timers.wallclock_init();

	mcheck_init();

	arch_init_ideal_nops();

	register_refined_jiffies(CLOCK_TICK_RATE);

#ifdef CONFIG_EFI
	if (efi_enabled(EFI_BOOT))
		efi_apply_memmap_quirks();
#endif
}

#ifdef CONFIG_X86_32

static struct resource video_ram_resource = {
	.name	= "Video RAM area",
	.start	= 0xa0000,
	.end	= 0xbffff,
	.flags	= IORESOURCE_BUSY | IORESOURCE_MEM
};

void __init i386_reserve_resources(void)
{
	request_resource(&iomem_resource, &video_ram_resource);
	reserve_standard_io_resources();
}

#endif  

static struct notifier_block kernel_offset_notifier = {
	.notifier_call = dump_kernel_offset
};

static int __init register_kernel_offset_dumper(void)
{
	atomic_notifier_chain_register(&panic_notifier_list,
					&kernel_offset_notifier);
	return 0;
}
__initcall(register_kernel_offset_dumper);
