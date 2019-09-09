#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#include <linux/pm.h>
#include <linux/suspend.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/clk.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_gpio.h>
#include <linux/of_irq.h>
#include <linux/reboot.h>
#include <linux/clocksource.h>
#include <linux/clockchips.h>
#include <linux/cpu_pm.h>
#include <linux/vmalloc.h>
#include <linux/tick.h>
#include <linux/slab.h>
#include <asm/io.h>
#include <asm/system_misc.h>
#include <asm/cacheflush.h>
#include <asm/suspend.h>

#include <linux/irqchip/arm-gic.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/of_address.h>
#include <linux/of_device.h>

#include <soc/realtek/memory.h>
#include "rtd129x_suspend.h"
#if defined(MY_DEF_HERE) && defined(MY_DEF_HERE)
#include "rtd129x_syno_uart1.h"
#endif /* MY_DEF_HERE && MY_DEF_HERE */

static int suspend_version = 2;
static unsigned int suspend_context = 0;
static enum _suspend_mode suspend_mode = SUSPEND_TO_COOLBOOT;
typedef struct RTK119X_ipc_shm RTD1295_ipc_shm;

#define SUSPEND_VERSION_MASK(v)    ((v&0xffff) << 16)
#define BT_WAKEUP_IGPIO(n)    (0x1 << n)//n:0 to 20

void __iomem *RTK_CRT_BASE;
void __iomem *RTK_AIO_BASE;
void __iomem *RTK_ISO_BASE;
void __iomem *RTK_TVE_BASE;
void __iomem *RTK_SB2_BASE;
void __iomem *RTK_MISC_BASE;
void __iomem *RTK_GIC_DIST_BASE;
void __iomem *RTK_CPU_WRAPPER_BASE;

#define rtk_suspend_shm_func(_name, _offset, _def)                                  \
void rtk_suspend_##_name##_set(unsigned int val)                                    \
{                                                                                   \
    RTD1295_ipc_shm __iomem *ipc = (void __iomem *)IPC_SHM_VIRT;                    \
    writel(__cpu_to_be32(SUSPEND_MAGIC_MASK | _def##_MASK(val)), &(ipc->_offset));  \
}                                                                                   \
unsigned int rtk_suspend_##_name##_get(void)                                        \
{                                                                                   \
    RTD1295_ipc_shm __iomem *ipc = (void __iomem *)IPC_SHM_VIRT;                    \
    unsigned int val = __be32_to_cpu(readl(&(ipc->_offset)));                       \
    if (SUSPEND_MAGIC_GET(val) != SUSPEND_MAGIC_KEY) {                              \
        printk(KERN_ERR "[RTD129x_PM] Error! val = 0x%08x\n", val);               \
        return -1;                                                                  \
    }                                                                               \
    return _def##_GET(val);                                                         \
}

rtk_suspend_shm_func(wakeup_flags, suspend_wakeup_flag, WAKEUP_FLAGS);
rtk_suspend_shm_func(resume_state, acpu_resume_state, RESUME_STATE);
rtk_suspend_shm_func(resume_data, acpu_resume_state, RESUME_DATA);
rtk_suspend_shm_func(gpio_wakeup_en, gpio_wakeup_enable, GPIO_WAKEUP_EN);
rtk_suspend_shm_func(gpio_wakeup_act, gpio_wakeup_activity, GPIO_WAKEUP_ACT);
rtk_suspend_shm_func(gpio_output_change_en, gpio_output_change_enable, GPIO_OUTPUT_CHANGE_EN);
rtk_suspend_shm_func(gpio_output_change_act, gpio_output_change_activity, GPIO_OUTPUT_CHANGE_ACT);
rtk_suspend_shm_func(gpio_wakeup_en2, gpio_wakeup_enable2, GPIO_WAKEUP_EN2);
rtk_suspend_shm_func(gpio_wakeup_act2, gpio_wakeup_activity2, GPIO_WAKEUP_ACT2);
rtk_suspend_shm_func(gpio_output_change_en2, gpio_output_change_enable2, GPIO_OUTPUT_CHANGE_EN2);
rtk_suspend_shm_func(gpio_output_change_act2, gpio_output_change_activity2, GPIO_OUTPUT_CHANGE_ACT2);
rtk_suspend_shm_func(timer_sec, audio_reciprocal_timer_sec, AUDIO_RECIPROCAL_TIMER);

static int suspend_mode_stored = 0;

int rtk_set_suspend_mode(const char *buf, int n)
{
    const char *p;
    int len;
    bool to_mem;

    p = memchr(buf, '\n', n);
    len = p ? p - buf : n;

    if (strncmp(buf, "standby", len) == 0) {
        pr_debug("[RTD129x_PM] GET state = standby\n");
        pr_debug("[RTD129x_PM] SET state = mem, suepend_mode = wfi\n");
        suspend_mode = SUSPEND_TO_WFI;
        to_mem = true;
    } else if (strncmp(buf, "sleep", len) == 0) {
        pr_debug("[RTD129x_PM] GET state = sleep\n");
        pr_debug("[RTD129x_PM] SET state = mem, suepend_mode = ram\n");
        suspend_mode = SUSPEND_TO_RAM;
        to_mem = true;
    } else if (strncmp(buf, "off", len) == 0) {
         pr_debug("[RTD129x_PM] GET state = off\n");
         pr_debug("[RTD129x_PM] SET state = mem, suepend_mode = coolboot\n");
        suspend_mode = SUSPEND_TO_COOLBOOT;
        to_mem = true;
    } else if (strncmp(buf, "mem", len) == 0) {
        if (suspend_mode_stored) {
            pr_info("[RTD129x_PM] GET state = mem, suepend_mode = %s\n", rtk_suspend_states[suspend_mode]);
            pr_info("[RTD129x_PM] compatible mode: suepend_mode will be reset AFTER THIS SUSPEND\n");
        } else {
            pr_debug("[RTD129x_PM] GET state = mem\n");
            pr_debug("[RTD129x_PM] SET state = mem, suepend_mode = ram\n");
            suspend_mode = SUSPEND_TO_RAM;
        }
        to_mem = true;
    } else
        to_mem = false;

    suspend_mode_stored = 0;

    if (to_mem)
        strcpy((char *)buf, "mem\n");

    return strlen(buf);
}
EXPORT_SYMBOL(rtk_set_suspend_mode);

int rtk_get_coolboot_mode(void) {
	return (suspend_mode == SUSPEND_TO_COOLBOOT) ? 1 : 0;
}
EXPORT_SYMBOL(rtk_get_coolboot_mode);

static void hexdump(char *note, unsigned char *buf, unsigned int len)
{
    printk(KERN_CRIT "%s\n", note);
    print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET, 16, 1, buf, len, false);
}

void acpu_set_flag(uint32_t flag)
{
    RTD1295_ipc_shm __iomem *ipc = (void __iomem *)IPC_SHM_VIRT;

    writel(__cpu_to_be32(SUSPEND_VERSION_MASK(suspend_version)), &(ipc->suspend_mask));
    if (suspend_version == 1)
        writel(__cpu_to_be32(flag), &(ipc->suspend_flag));
    else
        writel(__cpu_to_be32(flag | AUTHOR_MASK(AUTHOR_SCPU)), &(ipc->suspend_flag));
}

void notify_acpu(enum _notify_flag flag)
{
    printk(KERN_INFO "[RTD129x_PM] Notify ACPU, flag= %d\n", flag);

    switch (flag) {
        case NOTIFY_SUSPEND_TO_RAM:
        case NOTIFY_SUSPEND_TO_COOLBOOT:
        case NOTIFY_SUSPEND_TO_WFI:
            if (suspend_version == 1) {
                acpu_set_flag(0x000018ff); //suspend
                return;
            }
            break;
        case NOTIFY_RESUME_PLATFORM:
            if (suspend_version == 1) {
                acpu_set_flag(0x00000000);
                return;
            }
            break;
        default:
            break;
    }
    if (suspend_version == 1)
        return;
    acpu_set_flag(NOTIFY_MASK(flag));
}

int rtk_suspend_wakeup_acpu(void)
{
    printk(KERN_INFO "[RTD129x_PM] Wakeup ACPU.\n");

    writel(0x00000000, RTK_SB2_BASE + 0x138);
    __delay(1000);
    writel(0x00000008, RTK_CRT_BASE + 0x328);
    writel(0x0000ace7, RTK_CRT_BASE + 0x320);
    writel(0x0000000c, RTK_CRT_BASE + 0x328);
    __delay(1000);
    return 0;
}

struct _memory_verified_handle {
    unsigned char * memAddress;
    size_t memByte;
};

typedef struct _memory_verified_handle * memory_verified_handle_t;

unsigned char memory_verified_datagen(int i)
{
    return (unsigned char) (i & 0xff);
}

struct _memory_verified_handle * memory_verified_handle_create(size_t byte)
{
    int i = 0;

    struct _memory_verified_handle * handle =
        (struct _memory_verified_handle *) kmalloc(sizeof(struct _memory_verified_handle), GFP_KERNEL);

    if (!handle)
        return NULL;

    /*
     * > 32KB : vmalloc
     * < 32KB : kmalloc
     */
    if (byte > 0x8000)
        handle->memAddress = (char *) vmalloc(byte);
    else
        handle->memAddress = (char *) kmalloc(byte, GFP_KERNEL);

    if (!handle->memAddress) {
        kfree(handle);
        return NULL;
    }

    for (i=0; i<byte; i++)
        handle->memAddress[i] = memory_verified_datagen(i);

    handle->memByte = byte;

    return handle;
}

int memory_verified_release(struct _memory_verified_handle * handle)
{
    int ret = 0, i = 0;
    if (!handle) {
        printk(KERN_ERR "[RTD129x_PM] handle is NULL !\n");
        return -1;
    }

    if (!handle->memByte) {
        ret = -2;
        printk(KERN_INFO "[RTD129x_PM] handle %p (memByte = %ld, memAddress = 0x%08lx)\n",
                (void *) handle, (long int) handle->memByte, (unsigned long) handle->memAddress);
        if (handle->memAddress)
            goto free1;
        else
            goto free0;
    }

    for (i=0; i < handle->memByte; i++) {
        unsigned char data = memory_verified_datagen(i);
        if (handle->memAddress[i] != data) {
            printk(KERN_INFO "[RTD129x_PM] handle %p memAddress[0x%x] => 0x%x != 0x%x (%ld bytes at 0x%08lx)\n",
                    (void *) handle, i, handle->memAddress[i], data,
                    (long int) handle->memByte, (unsigned long) handle->memAddress);
            ret = -4;
        }
    }

    if (ret == -4) {
        printk(KERN_ERR "[RTD129x_PM] memory phyAddt 0x%08llx\n", __pa(handle->memAddress));
        hexdump("[RTD129x_PM] memory verified error\n", handle->memAddress, handle->memByte);
    }

free1:
    kfree(handle->memAddress);
free0:
    kfree(handle);

    return ret;
}

int rtk_suspend_valid(suspend_state_t state)
{
    return state == PM_SUSPEND_MEM || state == PM_SUSPEND_STANDBY;
}

static int notrace rtk_iso_suspend(unsigned long param)
{
    enum _suspend_mode mode = (enum _suspend_mode)param;

    printk(KERN_INFO "[RTD129x_PM] Flush Cache ...\n");
    flush_cache_all();

#ifdef CONFIG_SMP
    dsb(ishst);
    sev();
#endif

    printk(KERN_INFO "[RTD129x_PM] Ready to Suspend ! (mode:%d)", mode);
    if (mode == SUSPEND_TO_COOLBOOT)
        notify_acpu(NOTIFY_SUSPEND_TO_COOLBOOT);
    else if (mode == SUSPEND_TO_RAM){
        notify_acpu(NOTIFY_SUSPEND_TO_RAM);
    }else {
        printk(KERN_ERR "[RTD129x_PM] Suspend Mode Not Support : %d\n" ,mode);
        BUG();
    }

    {
        int MaxCounter = 100,i = 0;
        for (i = MaxCounter; i > 0 ; i--) {
            __delay(10000000);
        }
    }

    BUG();

    return  -EINVAL;
}

enum irq_report_state {
    IRQ_REPORT_PREPARE,
    IRQ_REPORT_PRINT,
};

static void rtk_suspend_irq_report(enum irq_report_state state)
{
    int i;
    static unsigned int data [32];
    void __iomem * interrupt_state = RTK_GIC_DIST_BASE + 0x200;

    switch (state) {
        case IRQ_REPORT_PREPARE:
            for (i = 0 ; i < 32 ; i++)
                data[i] = *(volatile unsigned int *)(interrupt_state + (i * 4));
            break;
        case IRQ_REPORT_PRINT:
            for (i = 0 ; i < 32 ; i++) {
                unsigned int temp =
                    *(volatile unsigned int *)(interrupt_state + (i * 4));
                if (temp != data[i]) {
                    int j, irq = i * 32;
                    printk(KERN_WARNING "[RTD129x_PM] Interrupt Addr:0x%08lx State: 0x%08x => 0x%08x\n",
                            (unsigned long)(interrupt_state + (i*4)),
                            data[i], temp);
                    for (j = 0 ; j < 32 ; j++) {
                        unsigned int mask = 0x1U << j;
                        if (mask & temp)
                            printk(KERN_WARNING "[RTD129x_PM] IRQ: %d\n", (irq+j));
                    }
                }
            }
            break;
        default:
            printk(KERN_ERR "[RTD129x_PM] Unknow CMD! %d\n", state);
    }
}

static int rtk_suspend_to_wfi(void)
{
    notify_acpu(NOTIFY_SUSPEND_TO_WFI);

    rtk_suspend_irq_report(IRQ_REPORT_PREPARE);

    printk(KERN_INFO "[RTD129x_PM] wait for interrupt.\n");

    asm("WFI");

    rtk_suspend_irq_report(IRQ_REPORT_PRINT);

    return 0;
}

static int rtk_suspend_to_ram(void)
{
    const int  MEM_VERIFIED_CNT = 20;
    int ret = 0, i = 0;
    memory_verified_handle_t mem_vhandle[MEM_VERIFIED_CNT];
    void __iomem * resumeAddr = RTK_ISO_BASE + 0x54;
    unsigned int ISODummy1Data = readl(resumeAddr);

    printk(KERN_INFO "[RTD129x_PM] CPU Resume vaddr: 0x%08lx paddr: 0x%08lx\n", (unsigned long)cpu_resume, (unsigned long)__pa(cpu_resume));

    hexdump("[RTD129x_PM] CPU Resume Entry Dump:", (unsigned char *) cpu_resume, 0x100);

#ifdef CONFIG_TEE_SUSPEND
    writel(0x10120000, resumeAddr); //When resuming, core0 jumps to BL31 entry first
    //Save kernel resume entry to BL31
    asm volatile("isb" : : : "cc");
    asm volatile("mov x1, %0" : : "r" (__pa(cpu_resume)) : "cc");
    asm volatile("ldr x0, =0x8400ff04" : : : "cc"); //RTK_SET_KERNEL_REUMSE_ENTRY
    asm volatile("isb" : : : "cc");
    asm volatile("smc #0" : : : "cc");
    asm volatile("isb" : : : "cc");
    //Info TEE OS to suspend
    asm volatile("isb" : : : "cc");
    asm volatile("ldr x0, =0xBf00ff04" : : : "cc"); //TEESMC_KERNEL_SUSPEND
    asm volatile("isb" : : : "cc");
    asm volatile("smc #0" : : : "cc");
    asm volatile("isb" : : : "cc");
#else
    writel(__pa(cpu_resume), resumeAddr);
#endif

    BUG_ON(!irqs_disabled());

    for (i=0; i<MEM_VERIFIED_CNT; i++)
        mem_vhandle[i] = memory_verified_handle_create(0x4000);

    ret = cpu_suspend((unsigned long)SUSPEND_TO_RAM, rtk_iso_suspend);

    if (ret)
        return ret;

    /* Restore iso dummy data */
    writel(ISODummy1Data, resumeAddr);

    writel(readl(RTK_ISO_BASE + 0x0418) | BIT(0), RTK_ISO_BASE + 0x0418);
    writel(readl(RTK_ISO_BASE + 0x0410) & ~BIT(10), RTK_ISO_BASE + 0x0410);

    rtk_suspend_irq_report(IRQ_REPORT_PRINT);

    rtk_suspend_wakeup_acpu();

    flush_cache_all();

    printk(KERN_INFO "[RTD129x_PM] Resume Memory Verifying ... State 0\n");
    for (i=0; i<MEM_VERIFIED_CNT; i++)
        memory_verified_release(mem_vhandle[i]);

    printk(KERN_INFO "[RTD129x_PM] Resume Memory Verifying ... State 1\n");
    for (i=0; i<MEM_VERIFIED_CNT; i++)
        mem_vhandle[i] = memory_verified_handle_create(0x4000);

    for (i=0; i<MEM_VERIFIED_CNT; i++)
        memory_verified_release(mem_vhandle[i]);

#ifdef CONFIG_SMP
    dsb(ishst);
    sev();
#endif

    return ret;
}

static int rtk_suspend_to_coolboot(void)
{
    int ret = 0;
   ret = cpu_suspend((unsigned long)SUSPEND_TO_COOLBOOT, rtk_iso_suspend);
    return ret;
}

void rtk_suspend_gpip_output_change_suspend(void)
{
    int i = 0;
    unsigned int val;
	unsigned int mask;

    val = rtk_suspend_gpio_output_change_en_get();
	if (val == -1U)
		val = 0;

    for (i = 0 ; i < GPIO_OUTPUT_CHANGE_EN_BITS ; i++) {// IGPIO0 ~ IGPIO23
        mask = 0x1U << i;

        if (!(val & mask))
            continue;

        printk(KERN_INFO "[RTD129x_PM] gpio:%d set ouput =>  %s\n", i + SUSPEND_ISO_GPIO_BASE,
                (rtk_suspend_gpio_output_change_act_get() & mask) ? "HIGH" : "LOW");

        gpio_direction_output(i+SUSPEND_ISO_GPIO_BASE,
                (rtk_suspend_gpio_output_change_act_get() & mask) ? 1 : 0 );
    }

	val = rtk_suspend_gpio_output_change_en2_get();
	if (val == -1U)
		val = 0;

	for (i = GPIO_OUTPUT_CHANGE_EN_BITS ; i < SUSPEND_ISO_GPIO_SIZE ; i++) {// IGPIO24 ~ IGPIO34
        mask = 0x1U << (i-GPIO_OUTPUT_CHANGE_EN_BITS);

        if (!(val & mask))
            continue;

        printk(KERN_INFO "[RTD129x_PM] gpio:%d set ouput =>  %s\n", i + SUSPEND_ISO_GPIO_BASE,
                (rtk_suspend_gpio_output_change_act2_get() & mask) ? "HIGH" : "LOW");

        gpio_direction_output(i+SUSPEND_ISO_GPIO_BASE,
                (rtk_suspend_gpio_output_change_act2_get() & mask) ? 1 : 0 );
    }
}

void rtk_suspend_gpip_output_change_resume(void)
{
    int i = 0;
    unsigned int val;
    unsigned int mask;

    val = rtk_suspend_gpio_output_change_en_get();
    if (val == -1U)
		val = 0;

    for (i = 0 ; i < GPIO_OUTPUT_CHANGE_EN_BITS ; i++) {// IGPIO0 ~ IGPIO23
        mask = 0x1U << i;

        if (!(val & mask))
            continue;

        printk(KERN_INFO "[RTD129x_PM] gpio:%d set ouput =>  %s\n", i + SUSPEND_ISO_GPIO_BASE,
                (rtk_suspend_gpio_output_change_act_get() & mask) ? "LOW" : "HIGH");

        gpio_direction_output(i+SUSPEND_ISO_GPIO_BASE,
                (rtk_suspend_gpio_output_change_act_get() & mask) ? 0 : 1 );
    }

	val = rtk_suspend_gpio_output_change_en2_get();
	if (val == -1U)
		val = 0;

	for (i = GPIO_OUTPUT_CHANGE_EN_BITS ; i < SUSPEND_ISO_GPIO_SIZE ; i++) {// IGPIO24 ~ IGPIO34
        mask = 0x1U << (i-GPIO_OUTPUT_CHANGE_EN_BITS);

        if (!(val & mask))
            continue;

        printk(KERN_INFO "[RTD129x_PM] gpio:%d set ouput =>  %s\n", i + SUSPEND_ISO_GPIO_BASE,
                (rtk_suspend_gpio_output_change_act2_get() & mask) ? "LOW" : "HIGH");

        gpio_direction_output(i+SUSPEND_ISO_GPIO_BASE,
                (rtk_suspend_gpio_output_change_act2_get() & mask) ? 0 : 1 );
    }

}

static int rtk_suspend_enter(suspend_state_t suspend_state)
{
    int ret = 0;

    printk(KERN_INFO "[RTD129x_PM] Platform Suspend Enter ...\n");

    if (!rtk_suspend_valid(suspend_state)) {
        printk(KERN_ERR "[RTD129x_PM] suspend_state:%d not support !\n", (int) suspend_state);
        return  -EINVAL;
    }

    switch(suspend_state) {
        case PM_SUSPEND_STANDBY:
            if (suspend_mode == SUSPEND_TO_WFI)
                 ret = rtk_suspend_to_wfi();
            printk(KERN_INFO "[RTD129x_PM] Platform Resume ...\n");
            notify_acpu(NOTIFY_RESUME_PLATFORM);
            break;
        case PM_SUSPEND_MEM:
			rtk_suspend_gpip_output_change_suspend();

            if (suspend_mode == SUSPEND_TO_WFI)
                ret = rtk_suspend_to_wfi();
            else if (suspend_mode == SUSPEND_TO_COOLBOOT)
                ret = rtk_suspend_to_coolboot();
            else if (suspend_mode == SUSPEND_TO_RAM)
                ret = rtk_suspend_to_ram();
            else
                BUG();

            suspend_context++;

            if (ret) {
                printk(KERN_ERR "[RTD129x_PM] ERROR ! to suspend! (%d)\n", ret);
                BUG();
                break;
            }

            printk(KERN_INFO "[RTD129x_PM] Platform Resume ...\n");
            notify_acpu(NOTIFY_RESUME_PLATFORM);

			rtk_suspend_gpip_output_change_resume();
            break;
        default:
            ret = -EINVAL;
            break;
    }

    return  ret;
}

static int rtk_suspend_begin(suspend_state_t suspend_state)
{
    printk(KERN_INFO "[RTD129x_PM] Suspend Begin\n");

    if (!rtk_suspend_valid(suspend_state)) {
        printk(KERN_ERR "[RTD129x_PM] suspend_state:%d not Support!\n",(int) suspend_state);
        return  -EINVAL;
    }

    switch(suspend_state) {
        case PM_SUSPEND_STANDBY:
            cpu_idle_poll_ctrl(true);
            break;
        case PM_SUSPEND_MEM:
            cpu_idle_poll_ctrl(true);
            break;
        default:
            return  -EINVAL;
    }
    return 0;
}

static void rtk_suspend_end(void)
{
    printk(KERN_INFO "[RTD129x_PM] Suspend End\n");

    notify_acpu(NOTIFY_RESUME_END);
    cpu_idle_poll_ctrl(false);
}

struct platform_suspend_ops rtk_suspend_ops = {
    .begin = rtk_suspend_begin,
    .end = rtk_suspend_end,
    .enter = rtk_suspend_enter,
    .valid = rtk_suspend_valid,
};

static void rtk_poweroff_to_suspend_prepare(void)
{
    printk(KERN_INFO "[RTD129x_PM] Power off to Suspend Prepare.\n");

#if defined(MY_DEF_HERE) && defined(MY_DEF_HERE)
    syno_uart1_write(SOFTWARE_POWER_LED_BLINK);
    syno_uart1_write(SOFTWARE_SHUTDOWN); // clear AC recovery flag
#endif /* MY_DEF_HERE && MY_DEF_HERE */

    suspend_mode = SUSPEND_TO_COOLBOOT;
    pm_suspend(PM_SUSPEND_MEM);
    return;
};

static void rtk_poweroff_to_suspend(void)
{
	printk(KERN_INFO "[RTD129x_PM] Power off to Suspend.\n");
	return;
}

int __init rtk_suspend_init(void)
{
    struct device_node *p_suspend_nd = NULL;
    struct device_node *p_gic_nd = NULL;
    struct device_node *p_cpu_wrapper_nd = NULL;

    acpu_set_flag(0x00000000);
    rtk_suspend_wakeup_flags_set(0);
    rtk_suspend_resume_state_set(RESUME_NONE);
    rtk_suspend_resume_data_set(0);
    rtk_suspend_gpio_wakeup_en_set(0);
    rtk_suspend_gpio_wakeup_act_set(0);
    rtk_suspend_gpio_output_change_en_set(0);
    rtk_suspend_gpio_output_change_act_set(0);
    rtk_suspend_gpio_wakeup_en2_set(0);
    rtk_suspend_gpio_wakeup_act2_set(0);
    rtk_suspend_gpio_output_change_en2_set(0);
    rtk_suspend_gpio_output_change_act2_set(0);
    rtk_suspend_timer_sec_set(0);

    printk(KERN_INFO "[RTD129x_PM] Initial RTD129x Power Management Driver.\n");

    p_suspend_nd = of_find_compatible_node(NULL, NULL, "Realtek,power-management");
    p_gic_nd = of_find_compatible_node(NULL, NULL, "arm,cortex-a15-gic");
    p_cpu_wrapper_nd = of_find_compatible_node(NULL, NULL, "Realtek,rtk-scpu_wrapper");

    RTK_CPU_WRAPPER_BASE = of_iomap(p_cpu_wrapper_nd, 0);
    RTK_GIC_DIST_BASE = of_iomap(p_gic_nd, 0);
    RTK_CRT_BASE = of_iomap(p_suspend_nd, 0);
    RTK_AIO_BASE = of_iomap(p_suspend_nd, 1);
    RTK_ISO_BASE = of_iomap(p_suspend_nd, 2);
    RTK_TVE_BASE = of_iomap(p_suspend_nd, 3);
    RTK_SB2_BASE = of_iomap(p_suspend_nd, 4);
    RTK_MISC_BASE = of_iomap(p_suspend_nd, 5);

    if(p_suspend_nd && of_device_is_available(p_suspend_nd)){
        const u32 *prop;
        int size;

        {
            int cnt_wakeup_gpio_en = 0;
            int cnt_wakeup_gpio_act = 0;
            int cnt_wakeup_gpio_list = of_gpio_named_count(p_suspend_nd, "wakeup-gpio-list");
            const u32 * prop_en = of_get_property(p_suspend_nd, "wakeup-gpio-enable", &cnt_wakeup_gpio_en);
            const u32 * prop_act = of_get_property(p_suspend_nd, "wakeup-gpio-activity", &cnt_wakeup_gpio_act);

            cnt_wakeup_gpio_en  /= sizeof(u32);
            cnt_wakeup_gpio_act /= sizeof(u32);

            printk(KERN_INFO "[RTD129x_PM] wakeup-gpio Cnt: en(%d) act(%d) list(%d)\n",
                    cnt_wakeup_gpio_en,
                    cnt_wakeup_gpio_act,
                    cnt_wakeup_gpio_list);

            if (cnt_wakeup_gpio_en != 0
                && (cnt_wakeup_gpio_en == cnt_wakeup_gpio_act)
                && (cnt_wakeup_gpio_act == cnt_wakeup_gpio_list)){

                int i = 0;
                for (i = 0 ; i < cnt_wakeup_gpio_list ; i++) {

                    int en  = of_read_number(prop_en,   1 + i);
                    int act = of_read_number(prop_act,  1 + i);
                    int wakeup_gpio = of_get_named_gpio(p_suspend_nd, "wakeup-gpio-list", i);
                    int gpio_iso_num = wakeup_gpio - SUSPEND_ISO_GPIO_BASE;

                    if (!en) {
                        printk(KERN_WARNING "[RTD129x_PM] wakeup-gpio[%d] States is disable! (en:%d act:%d gpio:%d)\n",
                                i, en, act, wakeup_gpio);
                        continue;
                    }

                    if (gpio_iso_num < 0 || gpio_iso_num >= SUSPEND_ISO_GPIO_SIZE) {
                        printk(KERN_ERR "[RTD129x_PM] wakeup-gpio[%d] Out of iso range! (en:%d act:%d gpio:%d)\n",
                                i, en, act, wakeup_gpio);
                        continue;
                    }

                    if(gpio_request(wakeup_gpio, p_suspend_nd->name)) {
                        printk(KERN_ERR "[RTD129x_PM] wakeup-gpio[%d] Request failed! (en:%d act:%d gpio:%d)\n",
                                i, en, act, wakeup_gpio);
					} else {
						gpio_free(wakeup_gpio);
					}

                    printk(KERN_INFO "[RTD129x_PM] wakeup-gpio[%d] Successful registration! (en:%d act:%d gpio:%d)\n",
                            i, en, act, wakeup_gpio);

					if(gpio_iso_num<GPIO_WAKEUP_EN_BITS)// IGPIO0 ~ IGPIO23
                    {
                        unsigned int val;
                        val = rtk_suspend_gpio_wakeup_en_get();
                        if (val == -1U)
                            val = 0;
                        if (en)
                            val |= (0x1U << gpio_iso_num);
                        else
                            val &= ~(0x1U << gpio_iso_num);
                        rtk_suspend_gpio_wakeup_en_set(val);

                        val = rtk_suspend_gpio_wakeup_act_get();
                        if (act)
                            val |= (0x1U << gpio_iso_num);
                        else
                            val &= ~(0x1U << gpio_iso_num);
                        rtk_suspend_gpio_wakeup_act_set(val);
                    }
                    else// IGPIO24 ~ IGPIO34
                    {
						unsigned int val;
						val = rtk_suspend_gpio_wakeup_en2_get();
						if (val == -1U)
							val = 0;
						if (en)
							val |= (0x1U << (gpio_iso_num-GPIO_WAKEUP_EN_BITS));
						else
							val &= ~(0x1U << (gpio_iso_num-GPIO_WAKEUP_EN_BITS));
                        rtk_suspend_gpio_wakeup_en2_set(val);

                        val = rtk_suspend_gpio_wakeup_act2_get();
                        if (act)
                            val |= (0x1U << (gpio_iso_num-GPIO_WAKEUP_EN_BITS));
                        else
                            val &= ~(0x1U << (gpio_iso_num-GPIO_WAKEUP_EN_BITS));
                        rtk_suspend_gpio_wakeup_act2_set(val);
                    }
                }
            }
        }

        {
            int cnt_output_change_gpio_en = 0;
            int cnt_output_change_gpio_act = 0;
            int cnt_output_change_gpio_list = of_gpio_named_count(p_suspend_nd, "gpio-output-change-list");
            const u32 * prop_en = of_get_property(p_suspend_nd, "gpio-output-change-enable", &cnt_output_change_gpio_en);
            const u32 * prop_act = of_get_property(p_suspend_nd, "gpio-output-change-activity", &cnt_output_change_gpio_act);

            cnt_output_change_gpio_en /= sizeof(u32);
            cnt_output_change_gpio_act /= sizeof(u32);

            printk(KERN_INFO "[RTD129x_PM] gpio-output-change Cnt: en(%d) act(%d) list(%d)\n",
                    cnt_output_change_gpio_en,
                    cnt_output_change_gpio_act,
                    cnt_output_change_gpio_list);

            if (cnt_output_change_gpio_en != 0
                    && (cnt_output_change_gpio_en == cnt_output_change_gpio_act)
                    && (cnt_output_change_gpio_act == cnt_output_change_gpio_list))
            {
                int i;
                for (i = 0 ; i < cnt_output_change_gpio_list ; i++) {
                    int en  = of_read_number(prop_en, 1 + i);
                    int act = of_read_number(prop_act, 1 + i);
                    int output_change_gpio = of_get_named_gpio(p_suspend_nd, "gpio-output-change-list", i);
                    int gpio_iso_num = output_change_gpio - SUSPEND_ISO_GPIO_BASE;

                    if (!en) {
                        printk(KERN_WARNING "[RTD129x_PM] gpio-output-change[%d] States is disable! (en:%d act:%d gpio:%d)\n",
                                i, en, act, output_change_gpio);
                        continue;
                    }

                    if (gpio_iso_num < 0 || gpio_iso_num >= SUSPEND_ISO_GPIO_SIZE) {
                        printk(KERN_ERR "[RTD129x_PM] gpio-output-change[%d] Out of iso range! (en:%d act:%d gpio:%d)\n",
                                i, en, act, output_change_gpio);
                        continue;
                    }

                    if(gpio_request(output_change_gpio, p_suspend_nd->name)) {
                        printk(KERN_ERR "[RTD129x_PM] gpio-output-change[%d] Request failed! (en:%d act:%d gpio:%d)\n",
                                i, en, act, output_change_gpio);
					} else {
						gpio_free(output_change_gpio);
					}

                    printk(KERN_INFO "[RTD129x_PM] gpio-output-change[%d] Successful registration! (en:%d act:%d gpio:%d)\n",
                            i, en, act, output_change_gpio);

					if(gpio_iso_num<GPIO_OUTPUT_CHANGE_EN_BITS)// IGPIO0 ~ IGPIO23
                    {
                        unsigned int val;
                        val = rtk_suspend_gpio_output_change_en_get();
                        if (val == -1U)
                            val = 0;
                        if (en)
                            val |= (0x1U << gpio_iso_num);
                        else
                            val &= ~(0x1U << gpio_iso_num);
                        rtk_suspend_gpio_output_change_en_set(val);
                        val = rtk_suspend_gpio_output_change_act_get();
                        if (act)
                            val |= (0x1U << gpio_iso_num);
                        else
                            val &= ~(0x1U << gpio_iso_num);
                        rtk_suspend_gpio_output_change_act_set(val);
                    }
                    else// IGPIO24 ~ IGPIO34
                    {
						unsigned int val;
                        val = rtk_suspend_gpio_output_change_en2_get();
                        if (val == -1U)
                            val = 0;
                        if (en)
                            val |= (0x1U << (gpio_iso_num-GPIO_OUTPUT_CHANGE_EN_BITS));
                        else
                            val &= ~(0x1U << (gpio_iso_num-GPIO_OUTPUT_CHANGE_EN_BITS));
                        rtk_suspend_gpio_output_change_en2_set(val);
                        val = rtk_suspend_gpio_output_change_act2_get();
                        if (act)
                            val |= (0x1U << (gpio_iso_num-GPIO_OUTPUT_CHANGE_EN_BITS));
                        else
                            val &= ~(0x1U << (gpio_iso_num-GPIO_OUTPUT_CHANGE_EN_BITS));
                        rtk_suspend_gpio_output_change_act2_set(val);
                    }
                }
            }
        }

        /*
         * Suspend Mode
         */
        prop = of_get_property(p_suspend_nd, "suspend-mode", &size);
        if(prop){
            int temp = of_read_number(prop,1);
            if(temp > MAX_SUSPEND_MODE || temp < 0){
                printk(KERN_ERR "[RTD129x_PM] Set suspend-mode Error! %d (default:%d) \n",temp,(int)suspend_mode);
            }else{
                suspend_mode = temp;
                printk(KERN_INFO "[RTD129x_PM] Set suspend-mode = %s\n", rtk_suspend_states[suspend_mode]);
            }
        }

        /*
         * wakeup flags
         */
        prop = of_get_property(p_suspend_nd, "wakeup-flags", &size);
        if(prop){
            int temp = of_read_number(prop,1);
            if(temp < 0){
                printk(KERN_ERR "[RTD129x_PM] Set wakeup-flags error! 0x%x\n", temp);
                rtk_suspend_wakeup_flags_set(fWAKEUP_ON_IR|fWAKEUP_ON_GPIO|fWAKEUP_ON_ALARM|fWAKEUP_ON_CEC);
                printk(KERN_INFO "[RTD129x_PM] wakeup flags set default : 0x%x\n", rtk_suspend_wakeup_flags_get());
            }else{
                rtk_suspend_wakeup_flags_set(temp);
                printk(KERN_INFO "[RTD129x_PM] Set set wakeup-flags = 0x%x\n", rtk_suspend_wakeup_flags_get());
            }
        }else{
            rtk_suspend_wakeup_flags_set(fWAKEUP_ON_GPIO|fWAKEUP_ON_ALARM|fWAKEUP_ON_CEC|fWAKEUP_ON_LAN);
            printk(KERN_INFO "[RTD129x_PM] Wakeup Flags Set Default : 0x%x\n", rtk_suspend_wakeup_flags_get());
        }
    }

    suspend_set_ops(&rtk_suspend_ops);

    pm_power_off_prepare = rtk_poweroff_to_suspend_prepare;
    pm_power_off = rtk_poweroff_to_suspend;

    return 0;
}

subsys_initcall(rtk_suspend_init);

#ifdef CONFIG_SYSFS
#define RTK_SUSPEND_ATTR(_name)             \
{                                           \
    .attr = {.name = #_name, .mode = 0644}, \
    .show =  rtk_suspend_##_name##_show,    \
    .store = rtk_suspend_##_name##_store,   \
}

static enum _suspend_mode rtk_suspend_decode_mode(const char *buf, size_t n)
{
    const char * const *s;
    char *p;
    int len;
    int i;

    p = memchr(buf, '\n', n);
    len = p ? p - buf : n;

    for (i=0;i<MAX_SUSPEND_MODE;i++) {
        s = &rtk_suspend_states[i];
        if (*s && len == strlen(*s) && !strncmp(buf, *s, len))
            return i;
    }

    return MAX_SUSPEND_MODE;
}

static ssize_t rtk_suspend_mode_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int i,n = 0;
    for (i=0;i<MAX_SUSPEND_MODE;i++) {
        if (i == suspend_mode)
            n += sprintf(buf+n, "=> ");
        else
            n += sprintf(buf+n, "   ");
        n += sprintf(buf+n, "%s\n",rtk_suspend_states[i]);
    }
    n += sprintf(buf+n, "\n");
    return n;
}

static ssize_t rtk_suspend_mode_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    enum _suspend_mode mode = rtk_suspend_decode_mode(buf,count);
    if (mode < MAX_SUSPEND_MODE) {
        suspend_mode = mode;
        suspend_mode_stored = 1;
        return count;
    }
    return -ENOMEM;
}

static enum _suspend_wakeup rtk_suspend_decode_wakeup(const char *buf, size_t n)
{
    const char * const *s;
    char *p;
    int len;
    int i;

    p = memchr(buf, '\n', n);
    len = p ? p - buf : n;

    for (i=0;i<eWAKEUP_ON_MAX;i++) {
        s = &rtk_suspend_wakeup_states[i];
        if (*s && len == strlen(*s) && !strncmp(buf, *s, len))
            return i;
    }

    return eWAKEUP_ON_MAX;
}

static ssize_t rtk_suspend_wakeup_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int i,n = 0;
    unsigned int val = rtk_suspend_wakeup_flags_get();
    for (i=0;i<eWAKEUP_ON_MAX;i++) {

        if (val & (0x1U << i))
            n += sprintf(buf+n, " * ");
        else
            n += sprintf(buf+n, "   ");
        n += sprintf(buf+n, "%s\n", rtk_suspend_wakeup_states[i]);
    }
    n += sprintf(buf+n, "\n");
    return n;
}

static ssize_t rtk_suspend_wakeup_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    enum _suspend_wakeup wakeup = rtk_suspend_decode_wakeup(buf,count);
    if (wakeup < eWAKEUP_ON_MAX) {
        rtk_suspend_wakeup_flags_set(rtk_suspend_wakeup_flags_get() ^ (0x1U << wakeup));
        return count;
    }
    return -ENOMEM;
}

static ssize_t rtk_suspend_resume_state_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int n = 0;
    unsigned int val = rtk_suspend_resume_state_get();
    if (val >= RESUME_MAX_STATE) {
        n += sprintf(buf+n, "(not ready)\n");
        goto done;
    }

    if (val == RESUME_GPIO)
        n += sprintf(buf+n, " %s %d\n",rtk_suspend_resume_states[val], rtk_suspend_resume_data_get() + SUSPEND_ISO_GPIO_BASE);
    else
        n += sprintf(buf+n, " %s %d\n",rtk_suspend_resume_states[val], rtk_suspend_resume_data_get());

done:
    n += sprintf(buf+n, " (write reset => change state to 'none')\n");
    return n;
}

static ssize_t rtk_suspend_resume_state_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    const char * const s = "reset";
    char *p;
    int len;

    p = memchr(buf, '\n', count);

    len = p ? p - buf : count;

    if (s && len == strlen(s) && !strncmp(buf, s, len))
        rtk_suspend_resume_state_set(RESUME_NONE);

    return count;
}

static ssize_t rtk_suspend_gpio_wakeup_en_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int i,n = 0;
    unsigned int val,val2;

	val = rtk_suspend_gpio_wakeup_en_get();
	val2 = rtk_suspend_gpio_wakeup_en2_get();

    if ((val == -1U)&&(val2 == -1U))
        return sprintf(buf, "(not ready)\n");

    n += sprintf(buf+n, " En | GPIO(ISO)\n");
    n += sprintf(buf+n, " ---+----------\n");
	for (i=0;i<GPIO_WAKEUP_EN_BITS;i++) {
		if (val == -1U)
			n += sprintf(buf+n, "    |  %d\n",i);
        else if (val & (0x1U << i))
            n += sprintf(buf+n, "  * |  %d\n",i);
        else
            n += sprintf(buf+n, "    |  %d\n",i);
    }

    for (i=0;i<GPIO_WAKEUP_EN2_BITS;i++) {
		if (val2 == -1U)
			n += sprintf(buf+n, "    |  %d\n",i+GPIO_WAKEUP_EN_BITS);
        else if (val2 & (0x1U << i))
            n += sprintf(buf+n, "  * |  %d\n",i+GPIO_WAKEUP_EN_BITS);
        else
            n += sprintf(buf+n, "    |  %d\n",i+GPIO_WAKEUP_EN_BITS);
    }
    n += sprintf(buf+n, "\n");
    return n;

}

static ssize_t rtk_suspend_gpio_wakeup_en_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    long val;
    int ret = kstrtol(buf, 10, &val);
    if (ret < 0)
        return -ENOMEM;

    if (val >= SUSPEND_ISO_GPIO_SIZE)
        return -ENOMEM;

#if 1
    return count;
#endif

	if(val<GPIO_WAKEUP_EN_BITS)
		rtk_suspend_gpio_wakeup_en_set(rtk_suspend_gpio_wakeup_en_get() ^ (0x1U << val));
	else
		rtk_suspend_gpio_wakeup_en2_set(rtk_suspend_gpio_wakeup_en2_get() ^ (0x1U << (val-GPIO_WAKEUP_EN_BITS)));

    return count;
}

static ssize_t rtk_suspend_gpio_wakeup_act_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int i,n = 0;
    unsigned int val,val2;

    val = rtk_suspend_gpio_wakeup_act_get();
    val2 = rtk_suspend_gpio_wakeup_act2_get();

    if ((val == -1U)&&(val2 == -1U))
        return sprintf(buf, "(not ready)\n");

    n += sprintf(buf+n, " Act| GPIO(ISO)\n");
    n += sprintf(buf+n, " ---+----------\n");
    for (i=0;i<GPIO_WAKEUP_ACT_BITS;i++) {
		if (val == -1U)
			n += sprintf(buf+n, "    |  %d\n",i);
        else if (!(rtk_suspend_gpio_wakeup_en_get() &  (0x1U << i)))
            n += sprintf(buf+n, "    |  %d\n",i);
        else if (val & (0x1U << i))
            n += sprintf(buf+n, "  H |  %d\n",i);
        else
            n += sprintf(buf+n, "  L |  %d\n",i);
    }

    for (i=0;i<GPIO_WAKEUP_ACT2_BITS;i++) {
		if (val2 == -1U)
			n += sprintf(buf+n, "    |  %d\n",i+GPIO_WAKEUP_ACT_BITS);
        else if (!(rtk_suspend_gpio_wakeup_en2_get() &  (0x1U << i)))
            n += sprintf(buf+n, "    |  %d\n",i+GPIO_WAKEUP_ACT_BITS);
        else if (val2 & (0x1U << i))
            n += sprintf(buf+n, "  H |  %d\n",i+GPIO_WAKEUP_ACT_BITS);
        else
            n += sprintf(buf+n, "  L |  %d\n",i+GPIO_WAKEUP_ACT_BITS);
    }
    n += sprintf(buf+n, "\n");

    return n;
}

static ssize_t rtk_suspend_gpio_wakeup_act_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    long val;
    int ret = kstrtol(buf, 10, &val);
    if (ret < 0)
        return -ENOMEM;

    if (val >= SUSPEND_ISO_GPIO_SIZE)
        return -ENOMEM;

#if 1
    return count;
#endif

	if(val<GPIO_WAKEUP_ACT_BITS)
	{
		if (rtk_suspend_gpio_wakeup_en_get() &  (0x1U << val))
			rtk_suspend_gpio_wakeup_act_set(rtk_suspend_gpio_wakeup_act_get() ^ (0x1U << val));
	}
	else
	{
		if (rtk_suspend_gpio_wakeup_en2_get() &  (0x1U << (val-GPIO_WAKEUP_ACT_BITS)))
			rtk_suspend_gpio_wakeup_act2_set(rtk_suspend_gpio_wakeup_act2_get() ^ (0x1U << (val-GPIO_WAKEUP_ACT_BITS)));
	}

    return count;
}

static ssize_t rtk_suspend_gpio_output_change_en_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int i,n = 0;
    unsigned int val,val2;

	val = rtk_suspend_gpio_output_change_en_get();
	val2 = rtk_suspend_gpio_output_change_en2_get();

    if ((val == -1U)&&(val2 == -1U))
        return sprintf(buf, "(not ready)\n");

    n += sprintf(buf+n, " En | GPIO(ISO)\n");
    n += sprintf(buf+n, " ---+----------\n");
    for (i=0;i<GPIO_OUTPUT_CHANGE_EN_BITS;i++) {
		if(val == -1U)
			n += sprintf(buf+n, "    |  %d\n",i);
        else if (val & (0x1U << i))
            n += sprintf(buf+n, "  * |  %d\n",i);
        else
            n += sprintf(buf+n, "    |  %d\n",i);
    }

	for (i=0;i<GPIO_OUTPUT_CHANGE_EN2_BITS;i++) {
		if(val2 == -1U)
			n += sprintf(buf+n, "    |  %d\n",i+GPIO_OUTPUT_CHANGE_EN_BITS);
        else if (val2 & (0x1U << i))
            n += sprintf(buf+n, "  * |  %d\n",i+GPIO_OUTPUT_CHANGE_EN_BITS);
        else
            n += sprintf(buf+n, "    |  %d\n",i+GPIO_OUTPUT_CHANGE_EN_BITS);
    }
    n += sprintf(buf+n, "\n");
    return n;

}

static ssize_t rtk_suspend_gpio_output_change_en_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    long val;
    int ret = kstrtol(buf, 10, &val);
    if (ret < 0)
        return -ENOMEM;

    if (val >= SUSPEND_ISO_GPIO_SIZE)
        return -ENOMEM;

#if 1
    return count;
#endif

	if(val<GPIO_OUTPUT_CHANGE_EN_BITS)
		rtk_suspend_gpio_output_change_en_set(rtk_suspend_gpio_output_change_en_get() ^ (0x1U << val));
	else
		rtk_suspend_gpio_output_change_en2_set(rtk_suspend_gpio_output_change_en2_get() ^ (0x1U << (val-GPIO_OUTPUT_CHANGE_EN_BITS)));

    return count;
}

static ssize_t rtk_suspend_gpio_output_change_act_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int i,n = 0;
    unsigned int val,val2;

    val = rtk_suspend_gpio_output_change_act_get();
    val2 = rtk_suspend_gpio_output_change_act2_get();

    if ((val == -1U)&&(val2 == -1U))
        return sprintf(buf, "(not ready)\n");

    n += sprintf(buf+n, " Act| GPIO(ISO)\n");
    n += sprintf(buf+n, " ---+----------\n");
    for (i=0;i<GPIO_OUTPUT_CHANGE_ACT_BITS;i++) {
		if(val == -1U)
			n += sprintf(buf+n, "    |  %d\n",i);
        else if (!(rtk_suspend_gpio_output_change_en_get() &  (0x1U << i)))
            n += sprintf(buf+n, "    |  %d\n",i);
        else if (val & (0x1U << i))
            n += sprintf(buf+n, "  H |  %d\n",i);
        else
            n += sprintf(buf+n, "  L |  %d\n",i);
    }

	for (i=0;i<GPIO_WAKEUP_ACT2_BITS;i++) {
		if(val2 == -1U)
			n += sprintf(buf+n, "    |  %d\n",i+GPIO_OUTPUT_CHANGE_ACT_BITS);
        else if (!(rtk_suspend_gpio_output_change_en2_get() &  (0x1U << i)))
            n += sprintf(buf+n, "    |  %d\n",i+GPIO_OUTPUT_CHANGE_ACT_BITS);
        else if (val2 & (0x1U << i))
            n += sprintf(buf+n, "  H |  %d\n",i+GPIO_OUTPUT_CHANGE_ACT_BITS);
        else
            n += sprintf(buf+n, "  L |  %d\n",i+GPIO_OUTPUT_CHANGE_ACT_BITS);
    }
    n += sprintf(buf+n, "\n");

    return n;
}

static ssize_t rtk_suspend_gpio_output_change_act_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    long val;
    int ret = kstrtol(buf, 10, &val);
    if (ret < 0)
        return -ENOMEM;

    if (val >= SUSPEND_ISO_GPIO_SIZE)
        return -ENOMEM;

#if 1
    return count;
#endif

	if(val<GPIO_OUTPUT_CHANGE_ACT_BITS)
	{
		if (rtk_suspend_gpio_output_change_en_get() &  (0x1U << val))
			rtk_suspend_gpio_output_change_act_set(rtk_suspend_gpio_output_change_act_get() ^ (0x1U << val));
	}
	else
	{
		if (rtk_suspend_gpio_output_change_en2_get() &  (0x1U << (val-GPIO_OUTPUT_CHANGE_ACT_BITS)))
			rtk_suspend_gpio_output_change_act2_set(rtk_suspend_gpio_output_change_act2_get() ^ (0x1U << (val-GPIO_OUTPUT_CHANGE_ACT_BITS)));
	}

    return count;
}

static ssize_t rtk_suspend_timer_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, " %d sec (reciprocal timer)\n", rtk_suspend_timer_sec_get());
}

static ssize_t rtk_suspend_timer_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    long val;
    int ret = kstrtol(buf, 10, &val);
    if (ret < 0)
        return -ENOMEM;

    if (val > (AUDIO_RECIPROCAL_TIMER_GET(-1UL)))
        return -ENOMEM;

    rtk_suspend_timer_sec_set(val);
    return count;
}

static ssize_t rtk_suspend_context_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d \n", suspend_context);
}

static ssize_t rtk_suspend_context_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    long val;
    int ret = kstrtol(buf, 10, &val);
    if (ret < 0)
        return -ENOMEM;
    suspend_context = val;
    return count;
}

static struct kobj_attribute rtk_suspend_mode_attr = RTK_SUSPEND_ATTR(mode);
static struct kobj_attribute rtk_suspend_wakeup_attr = RTK_SUSPEND_ATTR(wakeup);
static struct kobj_attribute rtk_suspend_resume_state_attr = RTK_SUSPEND_ATTR(resume_state);
static struct kobj_attribute rtk_suspend_gpio_wakeup_en_attr = RTK_SUSPEND_ATTR(gpio_wakeup_en);
static struct kobj_attribute rtk_suspend_gpio_wakeup_act_attr = RTK_SUSPEND_ATTR(gpio_wakeup_act);
static struct kobj_attribute rtk_suspend_gpio_output_change_en_attr = RTK_SUSPEND_ATTR(gpio_output_change_en);
static struct kobj_attribute rtk_suspend_gpio_output_change_act_attr = RTK_SUSPEND_ATTR(gpio_output_change_act);
static struct kobj_attribute rtk_suspend_timer_attr = RTK_SUSPEND_ATTR(timer);
static struct kobj_attribute rtk_suspend_context_attr = RTK_SUSPEND_ATTR(context);

static struct attribute *rtk_suspend_attrs[] = {
    &rtk_suspend_mode_attr.attr,
    &rtk_suspend_wakeup_attr.attr,
    &rtk_suspend_resume_state_attr.attr,
    &rtk_suspend_gpio_wakeup_en_attr.attr,
    &rtk_suspend_gpio_wakeup_act_attr.attr,
    &rtk_suspend_gpio_output_change_en_attr.attr,
    &rtk_suspend_gpio_output_change_act_attr.attr,
    &rtk_suspend_timer_attr.attr,
    &rtk_suspend_context_attr.attr,
    NULL,
};

static struct attribute_group rtk_suspend_attr_group = {
    .attrs = rtk_suspend_attrs,
};

static struct kobject *rtk_suspend_kobj;

static int __init suspend_sysfs_init(void)
{
    int ret;

    rtk_suspend_kobj = kobject_create_and_add("suspend", kernel_kobj);
    if (!rtk_suspend_kobj)
        return -ENOMEM;
    ret = sysfs_create_group(rtk_suspend_kobj, &rtk_suspend_attr_group);
    if (ret)
        kobject_put(rtk_suspend_kobj);
    return ret;
}

module_init(suspend_sysfs_init)
#endif
