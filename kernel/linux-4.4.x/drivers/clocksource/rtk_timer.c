#include <linux/clockchips.h>
#include <linux/clocksource.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/clk.h>
#include <linux/clockchips.h>
#include <linux/irq.h>
#include <linux/irqreturn.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/io.h>
#include <linux/sched_clock.h>

#define TIMER0                        0
#define TIMER1                        1
#define TIMER2                        2
#define TIMER_MAX                     (TIMER2 + 1)

#define SYSTEM_TIMER                  TIMER0

#define COUNTER                       0
#define TIMER                         1

#define TIMERINFO_TIMER_ENABLE        (1 << 31)
#define TIMERINFO_TIMER_MODE          (1 << 30)
#define TIMERINFO_TIMER_PAUSE         (1 << 29)
#define TIMERINFO_INTERRUPT_ENABLE    (1 << 31)

#define MISC_OFFSET                   0x0001B000
#define UMSK_ISR_OFFSET               0x00000008
#define ISR_OFFSET                    0x0000000C
#define UMSK_ISR_SWC                  0x00000010
#define ISR_SWC                       0x00000014
#define SETTING_SWC                   0x00000018
#define FAST_INT_EN_0                 0x0000001C
#define FAST_INT_EN_1                 0x00000020
#define FAST_ISR                      0x00000024
#define MISC_DBG                      0x0000002C
#define MISC_DUMMY                    0x00000030

#define TCTVR_OFFSET                  0x00000500
#define TCCVR_OFFSET                  0x0000050C
#define TCCR_OFFSET                   0x00000518
#define TCICR_OFFSET                  0x00000524

#define RTK_TIMER_HZ    CONFIG_HZ
#define IOMEM(x)    ((void __force __iomem *)(x))

void rtk_clockevent_init(int index, const char *name, void __iomem *base, int irq, unsigned long freq);
void rtk_clocksource_init(int index);

/* HW timer command enum description */
enum hwtimer_commands {
    HWT_START = 0x80, /* Start a timer/counter */
    HWT_STOP, /* Stop a timer/counter */
    HWT_PAUSE, /* Pause a timer/counter */
    HWT_RESUME, /* Restart a timer/counter */
    HWT_INT_ENABLE, /* Enable timer/counter interrupt */
    HWT_INT_DISABLE, /* Disable timer/counter interrupt */
    HWT_INT_CLEAR, /* Clear timer/counter interrupt pending bit */
};

int UMSK_TC_shift[2] = {
    (1 << 6),
    (1 << 7),
};

static irqreturn_t rtk_clock_event_isr(int, void*);
static int rtk_clkevt_set_next(int index, unsigned long, struct clock_event_device*);
int rtk_timer_control(unsigned char id, unsigned int cmd);
int rtk_timer_get_value(unsigned char id);
int rtk_timer_set_value(unsigned char id, unsigned int value);
int rtk_timer_set_target(unsigned char id, unsigned int value);
static cycle_t rtk_read_sched_clock0(struct clocksource *cs);
static cycle_t rtk_read_sched_clock1(struct clocksource *cs);

struct _suspend_data {
    unsigned int value;
    unsigned char mode;
};

static struct _suspend_data sTimerSuspendData[TIMER_MAX];

static void __iomem *timer_base;
unsigned long clk_freq;

#define MISC_IO_ADDR(pa)    (timer_base + pa)

#define rtd_setbits(offset, Mask)    __raw_writel(((__raw_readl(offset) | Mask)), offset)
#define rtd_clearbits(offset, Mask)    __raw_writel(((__raw_readl(offset) & ~Mask)), offset)

static void rtk_clocksource0_suspend(struct clocksource *cs)
{
    int nr = TIMER1;

    printk(KERN_INFO "[RTK-TIMER0] Enter %s\n", __func__);

    for (nr = 0 ; nr < TIMER_MAX ; nr++)
        sTimerSuspendData[nr].value = rtk_timer_get_value(nr);

    printk(KERN_INFO "[RTK-TIMER0] Exit %s\n", __func__);
}

static void rtk_clocksource0_resume(struct clocksource *cs)
{
    int nr = TIMER1;

    printk(KERN_INFO "[RTK-TIMER0] Enter %s\n", __func__);

    for (nr = 0 ; nr < TIMER_MAX ; nr++)
        rtk_timer_set_value(nr, sTimerSuspendData[nr].value);

    printk(KERN_INFO "[RTK-TIMER0] Exit %s\n", __func__);

}

static void rtk_clocksource1_suspend(struct clocksource *cs)
{
    int nr = TIMER1;

    printk(KERN_INFO "[RTK-TIMER1] Enter %s\n", __func__);

    for (nr = 0 ; nr < TIMER_MAX ; nr++)
        sTimerSuspendData[nr].value = rtk_timer_get_value(nr);

    printk(KERN_INFO "[RTK-TIMER1] Exit %s\n", __func__);
}

static void rtk_clocksource1_resume(struct clocksource *cs)
{
    int nr = TIMER1;

    printk(KERN_INFO "[RTK-TIMER1] Enter %s\n", __func__);

    for (nr = 0 ; nr < TIMER_MAX ; nr++)
        rtk_timer_set_value(nr, sTimerSuspendData[nr].value);

    printk(KERN_INFO "[RTK-TIMER1] Exit %s\n", __func__);
}

int rtk_timer_set_mode(unsigned char id, unsigned char mode)
{
    switch(mode) {
        case COUNTER:
            rtd_clearbits((MISC_IO_ADDR(TCCR_OFFSET + (id<<2))), TIMERINFO_TIMER_MODE);
            break;
        case TIMER:
            rtd_setbits((MISC_IO_ADDR(TCCR_OFFSET + (id<<2))), TIMERINFO_TIMER_MODE);
            break;
        default:
            return 1;
    }

    return 0;
}

unsigned char rtk_timer_get_mode(unsigned char id)
{
    unsigned int reg =  __raw_readl(MISC_IO_ADDR(TCCR_OFFSET + (id<<2)));
    return (reg & TIMERINFO_TIMER_MODE)? TIMER : COUNTER;
}

int rtk_timer_control(unsigned char id, unsigned int cmd)
{
    switch (cmd) {
        case HWT_INT_CLEAR:
            rtd_setbits(MISC_IO_ADDR(UMSK_ISR_OFFSET), UMSK_TC_shift[id]);
            break;
        case HWT_START:
            rtd_setbits(MISC_IO_ADDR(TCCR_OFFSET+(id<<2)), TIMERINFO_TIMER_ENABLE);
            rtd_setbits(MISC_IO_ADDR(ISR_OFFSET), UMSK_TC_shift[id]); // Clear Interrupt Pending (must after enable)
            break;
        case HWT_STOP:
            rtd_clearbits(MISC_IO_ADDR(TCCR_OFFSET+(id<<2)), TIMERINFO_TIMER_ENABLE);
            break;
        case HWT_PAUSE:
            rtd_setbits(MISC_IO_ADDR(TCCR_OFFSET+(id<<2)), TIMERINFO_TIMER_PAUSE);
            break;
        case HWT_RESUME:
            rtd_clearbits(MISC_IO_ADDR(TCCR_OFFSET+(id<<2)), TIMERINFO_TIMER_PAUSE);
            break;
        case HWT_INT_ENABLE:
            rtd_setbits(MISC_IO_ADDR(TCICR_OFFSET+(id<<2)), TIMERINFO_INTERRUPT_ENABLE);
            break;
        case HWT_INT_DISABLE:
            rtd_clearbits(MISC_IO_ADDR(TCICR_OFFSET+(id<<2)), TIMERINFO_INTERRUPT_ENABLE);
            break;
        default:
            return 1;
    }
    return 0;
}

int rtk_timer_get_value(unsigned char id)
{
    return __raw_readl(MISC_IO_ADDR(TCCVR_OFFSET + (id<<2))); // get the current timer's value
}

int rtk_timer_set_value(unsigned char id, unsigned int value)
{
    __raw_writel(value, MISC_IO_ADDR(TCCVR_OFFSET + (id<<2))); // set the timer's initial value
    return 0;
}

int rtk_timer_set_target(unsigned char id, unsigned int value)
{
    __raw_writel(value, MISC_IO_ADDR(TCTVR_OFFSET+(id<<2))); // set the timer's initial value
    return 0;
}
static int rtk_timer_set_state_resume(int nr, struct clock_event_device *evt)
{
    printk(KERN_INFO "[RTK-TIMER%d] set mode: CLOCK_EVT_MODE_RESUME\n", nr);
    rtk_timer_set_value(nr, sTimerSuspendData[nr].value);
    rtk_timer_set_target(nr, DIV_ROUND_UP(clk_freq, HZ));
    rtk_timer_set_mode(nr, sTimerSuspendData[nr].mode);
    rtk_timer_control(nr, HWT_RESUME);
    rtk_timer_control(nr, HWT_INT_ENABLE);

    return 0;
}

static int rtk_timer_set_state_shutdown(int nr, struct clock_event_device *evt)
{
    printk(KERN_INFO "[RTK-TIMER%d] set mode: CLOCK_EVT_MODE_SHUTDOWN\n", nr);
    sTimerSuspendData[nr].value = rtk_timer_get_value(nr);
    sTimerSuspendData[nr].mode = rtk_timer_get_mode(nr);
    rtk_timer_control(nr, HWT_INT_DISABLE);
    rtk_timer_control(nr, HWT_STOP);

    return 0;
}

static int rtk_timer_set_state_periodic(int nr, struct clock_event_device *evt)
{
    printk(KERN_INFO "[RTK-TIMER%d] set mode: CLOCK_EVT_MODE_PERIODIC\n", nr);
    rtk_timer_control(nr, HWT_INT_DISABLE);
    rtk_timer_control(nr, HWT_STOP);
    rtk_timer_set_value(nr, sTimerSuspendData[nr].value);
    rtk_timer_set_target(nr, DIV_ROUND_UP(clk_freq, HZ));
    rtk_timer_set_mode(nr, TIMER);
    rtk_timer_control(nr, HWT_START);
    rtk_timer_control(nr, HWT_INT_ENABLE);
    return 0;
}

static int rtk_timer_set_state_oneshot(int nr, struct clock_event_device *evt)
{
    /* period set, and timer enabled in 'next event' hook */
    printk(KERN_INFO "[RTK-TIMER%d] set mode: CLOCK_EVT_MODE_ONESHOT\n", nr);
    rtk_timer_control(nr, HWT_INT_DISABLE);
    rtk_timer_control(nr, HWT_STOP);
    rtk_timer_set_value(nr, sTimerSuspendData[nr].value);
    rtk_timer_set_target(nr, DIV_ROUND_UP(clk_freq, HZ));
    rtk_timer_set_mode(nr, COUNTER);
    rtk_timer_control(nr, HWT_START);
    rtk_timer_control(nr, HWT_INT_ENABLE);

    return 0;
}

static int rtk_timer0_set_next(unsigned long cycles, struct clock_event_device *evt)
{
    return rtk_clkevt_set_next(TIMER0, cycles, evt);
}

static int rtk_timer0_set_state_resume(struct clock_event_device *evt)
{
    return rtk_timer_set_state_resume(TIMER0, evt);
}

static int rtk_timer0_set_state_shutdown(struct clock_event_device *evt)
{
    return rtk_timer_set_state_shutdown(TIMER0, evt);
}

static int rtk_timer0_set_state_periodic(struct clock_event_device *evt)
{
    return rtk_timer_set_state_periodic(TIMER0, evt);
}

static int rtk_timer0_set_state_oneshot(struct clock_event_device *evt)
{
    return rtk_timer_set_state_oneshot(TIMER0, evt);
}

static cycle_t rtk_read_sched_clock0(struct clocksource *cs)
{
    return (cycle_t)rtk_timer_get_value(TIMER0);
}

static struct clocksource rtk_cs0 = {
    .name = "rtk_timer0_counter",
    .rating = 400,
    .read = rtk_read_sched_clock0,
    .mask = CLOCKSOURCE_MASK(32),
    .flags = CLOCK_SOURCE_IS_CONTINUOUS,
    .mult = 0,
    .shift = 10,
    .suspend = rtk_clocksource0_suspend,
    .resume = rtk_clocksource0_resume,
};

static struct clock_event_device timer0_clockevent = {
    .rating = 100,
    .shift = 32,
    .features = CLOCK_EVT_FEAT_PERIODIC | CLOCK_EVT_FEAT_ONESHOT,
    .set_next_event = rtk_timer0_set_next,
    .set_state_shutdown = rtk_timer0_set_state_shutdown,
    .set_state_periodic = rtk_timer0_set_state_periodic,
    .set_state_oneshot  = rtk_timer0_set_state_oneshot,
    .tick_resume	= rtk_timer0_set_state_resume,
};

static struct irqaction timer0_irq = {
    .flags = IRQF_TIMER | IRQF_IRQPOLL,
    .handler = rtk_clock_event_isr,
    .dev_id = &timer0_clockevent,
};

static int rtk_timer1_set_next(unsigned long cycles, struct clock_event_device *evt)
{
    return rtk_clkevt_set_next(TIMER1, cycles, evt);
}

static int rtk_timer1_set_state_resume(struct clock_event_device *evt)
{
    return rtk_timer_set_state_resume(TIMER1, evt);
}

static int rtk_timer1_set_state_shutdown(struct clock_event_device *evt)
{
    return rtk_timer_set_state_shutdown(TIMER1, evt);
}

static int rtk_timer1_set_state_periodic(struct clock_event_device *evt)
{
    return rtk_timer_set_state_periodic(TIMER1, evt);
}

static int rtk_timer1_set_state_oneshot(struct clock_event_device *evt)
{
    return rtk_timer_set_state_oneshot(TIMER1, evt);
}

static cycle_t rtk_read_sched_clock1(struct clocksource *cs)
{
    return (cycle_t)rtk_timer_get_value(TIMER1);
}

static struct clocksource rtk_cs1 = {
    .name = "rtk_timer1_counter",
    .rating    = 400,
    .read = rtk_read_sched_clock1,
    .mask = CLOCKSOURCE_MASK(32),
    .flags = CLOCK_SOURCE_IS_CONTINUOUS,
    .mult = 0,
    .shift = 10,
    .suspend = rtk_clocksource1_suspend,
    .resume = rtk_clocksource1_resume,
};

static struct clock_event_device timer1_clockevent = {
    .rating = 400,
    .shift = 32,
    .features = CLOCK_EVT_FEAT_PERIODIC | CLOCK_EVT_FEAT_ONESHOT,
    .set_next_event = rtk_timer1_set_next,
    .set_state_shutdown = rtk_timer1_set_state_shutdown,
    .set_state_periodic = rtk_timer1_set_state_periodic,
    .set_state_oneshot  = rtk_timer1_set_state_oneshot,
    .tick_resume	= rtk_timer1_set_state_resume,
};

static struct irqaction timer1_irq = {
    .flags = IRQF_TIMER,
    .handler = rtk_clock_event_isr,
    .dev_id = &timer1_clockevent,
};

struct rtk_clock_event_device {
    int index;
    struct clock_event_device *evt;
    struct irqaction *irq_action;
};

static struct rtk_clock_event_device rtk_evt[] = {
    { 0, &timer0_clockevent, &timer0_irq },
    { 1, &timer1_clockevent, &timer1_irq },
};

static irqreturn_t rtk_clock_event_isr(int irq, void *dev_id)
{
    struct rtk_clock_event_device *clkevt = (struct rtk_clock_event_device*)dev_id;
    struct clock_event_device *evt = clkevt->evt;
    int nr = clkevt->index;

    rtd_setbits(MISC_IO_ADDR(ISR_OFFSET), UMSK_TC_shift[nr]);

    if (!evt->event_handler) {
        return IRQ_HANDLED;
    }

    evt->event_handler(evt);

    return IRQ_HANDLED;
}

static int rtk_clkevt_set_next(int nr, unsigned long cycles, struct clock_event_device *evt)
{
    unsigned int cnt = 0;
    int ret = 0;

    rtk_timer_control(nr, HWT_INT_ENABLE);
    cnt = rtk_timer_get_value(nr);
    cnt += cycles;
    rtk_timer_set_target(nr, cnt);

    ret = ((rtk_timer_get_value(nr) - cnt) > 0) ? -ETIME : 0;

    return ret;
}

void rtk_clockevent_init(int index, const char *name, void __iomem *base, int irq, unsigned long freq)
{
    struct rtk_clock_event_device *clkevt = &rtk_evt[index];
    struct clock_event_device *evt = clkevt->evt;

    timer_base = base;
    clk_freq = freq;
    evt->irq = irq;
    evt->name = name;
    evt->cpumask = cpumask_of(smp_processor_id());

    memset(sTimerSuspendData, 0, sizeof(sTimerSuspendData[0]) * TIMER_MAX);

    clkevt->irq_action->name = name;
    clkevt->irq_action->irq = irq;
    clkevt->irq_action->dev_id = clkevt;

    setup_irq(irq, clkevt->irq_action);

    clockevents_config_and_register(evt, clk_freq, 0xF, UINT_MAX);
}

void rtk_clocksource_init(int index)
{
    struct clocksource *cs = &rtk_cs0;
    struct clocksource *cs1 = &rtk_cs1;

    printk(KERN_INFO "[RTK-TIMER%d] clocksource %d register HZ\n", index, index);

    if(index == 0){
        if (clocksource_register_hz(cs, clk_freq))
            printk(KERN_ERR "[RTK-TIMER%d] timer%d can't register clocksource\n", index, index);
    }else{
        if (clocksource_register_hz(cs1, clk_freq))
            printk(KERN_ERR "[RTK-TIMER%d] timer%d can't register clocksource\n", index, index);
    }
}

static void rtk129x_timer0_init(struct device_node *np)
{
    int ret = 0;
    void __iomem *iobase;
    int irq = 0;
    int rate = 0;

    iobase = of_iomap(np, 0);
    if (!iobase) {
        printk(KERN_ERR "[RTK-TIMER0] failed to get base address\n");
        return;
    }

    irq = irq_of_parse_and_map(np, 0);
    if (irq <= 0){
        printk(KERN_ERR "[RTK-TIMER0] can't parse IRQ\n");
        return;
    }

    ret = of_property_read_u32(np, "clock-frequency", &rate);
    if(ret){
        printk(KERN_ERR "[RTK-TIMER0] can't get clock-frequency\n");
        return;
    }

    rtk_clockevent_init(TIMER0, np->name, iobase, irq, rate);
    rtk_clocksource_init(TIMER0);
}

static void rtk129x_timer1_init(struct device_node *np)
{
    int ret = 0;
    void __iomem *iobase;
    int irq = 0;
    int rate = 0;

    iobase = of_iomap(np, 0);
    if (!iobase) {
        printk(KERN_ERR "[RTK-TIMER1] failed to get base address\n");
        return;
    }

    irq = irq_of_parse_and_map(np, 0);
    if (irq <= 0){
        printk(KERN_ERR "[RTK-TIMER1] can't parse IRQ\n");
        return;
    }

    ret = of_property_read_u32(np, "clock-frequency", &rate);
    if(ret){
        printk(KERN_ERR "[RTK-TIMER1] can't get clock-frequency\n");
        return;
    }

    rtk_clockevent_init(TIMER1, np->name, iobase, irq, rate);
    rtk_clocksource_init(TIMER1);
}

CLOCKSOURCE_OF_DECLARE(realtek_timer0, "Realtek,rtd129x-timer0", rtk129x_timer0_init);
CLOCKSOURCE_OF_DECLARE(realtek_timer1, "Realtek,rtd129x-timer1", rtk129x_timer1_init);
