#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/console.h>
#include <linux/sysrq.h>
#include <linux/delay.h>
#include <linux/platform_device.h>
#include <linux/tty.h>
#include <linux/ratelimit.h>
#include <linux/tty_flip.h>
#include <linux/serial.h>
#include <linux/serial_8250.h>
#include <linux/nmi.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/pm_runtime.h>
#include <linux/io.h>
#ifdef CONFIG_SPARC
#include <linux/sunserialcore.h>
#endif

#include <asm/irq.h>

#include "8250.h"

#ifdef MY_DEF_HERE
#include <linux/pci_regs.h>
#include <asm/pci-direct.h>

extern char gszSynoTtyS0[50];
extern char gszSynoTtyS1[50];

static unsigned long syno_parse_ttys_port(char* s);
#endif  

static unsigned int share_irqs = SERIAL8250_SHARE_IRQS;

static unsigned int nr_uarts = CONFIG_SERIAL_8250_RUNTIME_UARTS;

static struct uart_driver serial8250_reg;

static unsigned int skip_txen_test;  

#define PASS_LIMIT	512

#include <asm/serial.h>
 
#ifndef SERIAL_PORT_DFNS
#define SERIAL_PORT_DFNS
#endif

static const struct old_serial_port old_serial_port[] = {
	SERIAL_PORT_DFNS  
};

#define UART_NR	CONFIG_SERIAL_8250_NR_UARTS

#ifdef CONFIG_SERIAL_8250_RSA

#define PORT_RSA_MAX 4
static unsigned long probe_rsa[PORT_RSA_MAX];
static unsigned int probe_rsa_count;
#endif  

struct irq_info {
	struct			hlist_node node;
	int			irq;
	spinlock_t		lock;	 
	struct list_head	*head;
};

#define NR_IRQ_HASH		32	 
static struct hlist_head irq_lists[NR_IRQ_HASH];
static DEFINE_MUTEX(hash_mutex);	 

static irqreturn_t serial8250_interrupt(int irq, void *dev_id)
{
	struct irq_info *i = dev_id;
	struct list_head *l, *end = NULL;
	int pass_counter = 0, handled = 0;

	DEBUG_INTR("serial8250_interrupt(%d)...", irq);

	spin_lock(&i->lock);

	l = i->head;
	do {
		struct uart_8250_port *up;
		struct uart_port *port;

		up = list_entry(l, struct uart_8250_port, list);
		port = &up->port;

		if (port->handle_irq(port)) {
			handled = 1;
			end = NULL;
		} else if (end == NULL)
			end = l;

		l = l->next;

		if (l == i->head && pass_counter++ > PASS_LIMIT) {
			 
			printk_ratelimited(KERN_ERR
				"serial8250: too much work for irq%d\n", irq);
			break;
		}
	} while (l != end);

	spin_unlock(&i->lock);

	DEBUG_INTR("end.\n");

	return IRQ_RETVAL(handled);
}

static void serial_do_unlink(struct irq_info *i, struct uart_8250_port *up)
{
	spin_lock_irq(&i->lock);

	if (!list_empty(i->head)) {
		if (i->head == &up->list)
			i->head = i->head->next;
		list_del(&up->list);
	} else {
		BUG_ON(i->head != &up->list);
		i->head = NULL;
	}
	spin_unlock_irq(&i->lock);
	 
	if (i->head == NULL) {
		hlist_del(&i->node);
		kfree(i);
	}
}

static int serial_link_irq_chain(struct uart_8250_port *up)
{
	struct hlist_head *h;
	struct hlist_node *n;
	struct irq_info *i;
	int ret, irq_flags = up->port.flags & UPF_SHARE_IRQ ? IRQF_SHARED : 0;

	mutex_lock(&hash_mutex);

	h = &irq_lists[up->port.irq % NR_IRQ_HASH];

	hlist_for_each(n, h) {
		i = hlist_entry(n, struct irq_info, node);
		if (i->irq == up->port.irq)
			break;
	}

	if (n == NULL) {
		i = kzalloc(sizeof(struct irq_info), GFP_KERNEL);
		if (i == NULL) {
			mutex_unlock(&hash_mutex);
			return -ENOMEM;
		}
		spin_lock_init(&i->lock);
		i->irq = up->port.irq;
		hlist_add_head(&i->node, h);
	}
	mutex_unlock(&hash_mutex);

	spin_lock_irq(&i->lock);

	if (i->head) {
		list_add(&up->list, i->head);
		spin_unlock_irq(&i->lock);

		ret = 0;
	} else {
		INIT_LIST_HEAD(&up->list);
		i->head = &up->list;
		spin_unlock_irq(&i->lock);
		irq_flags |= up->port.irqflags;
		ret = request_irq(up->port.irq, serial8250_interrupt,
				  irq_flags, "serial", i);
		if (ret < 0)
			serial_do_unlink(i, up);
	}

	return ret;
}

static void serial_unlink_irq_chain(struct uart_8250_port *up)
{
	 
	struct irq_info *i;
	struct hlist_node *n;
	struct hlist_head *h;

	mutex_lock(&hash_mutex);

	h = &irq_lists[up->port.irq % NR_IRQ_HASH];

	hlist_for_each(n, h) {
		i = hlist_entry(n, struct irq_info, node);
		if (i->irq == up->port.irq)
			break;
	}

	BUG_ON(n == NULL);
	BUG_ON(i->head == NULL);

	if (list_empty(i->head))
		free_irq(up->port.irq, i);

	serial_do_unlink(i, up);
	mutex_unlock(&hash_mutex);
}

static void serial8250_timeout(unsigned long data)
{
	struct uart_8250_port *up = (struct uart_8250_port *)data;

	up->port.handle_irq(&up->port);
	mod_timer(&up->timer, jiffies + uart_poll_timeout(&up->port));
}

static void serial8250_backup_timeout(unsigned long data)
{
	struct uart_8250_port *up = (struct uart_8250_port *)data;
	unsigned int iir, ier = 0, lsr;
	unsigned long flags;

	spin_lock_irqsave(&up->port.lock, flags);

	if (up->port.irq) {
		ier = serial_in(up, UART_IER);
		serial_out(up, UART_IER, 0);
	}

	iir = serial_in(up, UART_IIR);

	lsr = serial_in(up, UART_LSR);
	up->lsr_saved_flags |= lsr & LSR_SAVE_FLAGS;
	if ((iir & UART_IIR_NO_INT) && (up->ier & UART_IER_THRI) &&
	    (!uart_circ_empty(&up->port.state->xmit) || up->port.x_char) &&
	    (lsr & UART_LSR_THRE)) {
		iir &= ~(UART_IIR_ID | UART_IIR_NO_INT);
		iir |= UART_IIR_THRI;
	}

	if (!(iir & UART_IIR_NO_INT))
		serial8250_tx_chars(up);

	if (up->port.irq)
		serial_out(up, UART_IER, ier);

	spin_unlock_irqrestore(&up->port.lock, flags);

	mod_timer(&up->timer,
		jiffies + uart_poll_timeout(&up->port) + HZ / 5);
}

static int univ8250_setup_irq(struct uart_8250_port *up)
{
	struct uart_port *port = &up->port;
	int retval = 0;

	if (up->bugs & UART_BUG_THRE) {
		pr_debug("ttyS%d - using backup timer\n", serial_index(port));

		up->timer.function = serial8250_backup_timeout;
		up->timer.data = (unsigned long)up;
		mod_timer(&up->timer, jiffies +
			  uart_poll_timeout(port) + HZ / 5);
	}

	if (!port->irq) {
		up->timer.data = (unsigned long)up;
		mod_timer(&up->timer, jiffies + uart_poll_timeout(port));
	} else
		retval = serial_link_irq_chain(up);

	return retval;
}

static void univ8250_release_irq(struct uart_8250_port *up)
{
	struct uart_port *port = &up->port;

	del_timer_sync(&up->timer);
	up->timer.function = serial8250_timeout;
	if (port->irq)
		serial_unlink_irq_chain(up);
}

#ifdef CONFIG_SERIAL_8250_RSA
static int serial8250_request_rsa_resource(struct uart_8250_port *up)
{
	unsigned long start = UART_RSA_BASE << up->port.regshift;
	unsigned int size = 8 << up->port.regshift;
	struct uart_port *port = &up->port;
	int ret = -EINVAL;

	switch (port->iotype) {
	case UPIO_HUB6:
	case UPIO_PORT:
		start += port->iobase;
		if (request_region(start, size, "serial-rsa"))
			ret = 0;
		else
			ret = -EBUSY;
		break;
	}

	return ret;
}

static void serial8250_release_rsa_resource(struct uart_8250_port *up)
{
	unsigned long offset = UART_RSA_BASE << up->port.regshift;
	unsigned int size = 8 << up->port.regshift;
	struct uart_port *port = &up->port;

	switch (port->iotype) {
	case UPIO_HUB6:
	case UPIO_PORT:
		release_region(port->iobase + offset, size);
		break;
	}
}
#endif

static const struct uart_ops *base_ops;
static struct uart_ops univ8250_port_ops;

static const struct uart_8250_ops univ8250_driver_ops = {
	.setup_irq	= univ8250_setup_irq,
	.release_irq	= univ8250_release_irq,
};

static struct uart_8250_port serial8250_ports[UART_NR];

struct uart_8250_port *serial8250_get_port(int line)
{
	return &serial8250_ports[line];
}
EXPORT_SYMBOL_GPL(serial8250_get_port);

static void (*serial8250_isa_config)(int port, struct uart_port *up,
	unsigned short *capabilities);

void serial8250_set_isa_configurator(
	void (*v)(int port, struct uart_port *up, unsigned short *capabilities))
{
	serial8250_isa_config = v;
}
EXPORT_SYMBOL(serial8250_set_isa_configurator);

#ifdef CONFIG_SERIAL_8250_RSA

static void univ8250_config_port(struct uart_port *port, int flags)
{
	struct uart_8250_port *up = up_to_u8250p(port);

	up->probe &= ~UART_PROBE_RSA;
	if (port->type == PORT_RSA) {
		if (serial8250_request_rsa_resource(up) == 0)
			up->probe |= UART_PROBE_RSA;
	} else if (flags & UART_CONFIG_TYPE) {
		int i;

		for (i = 0; i < probe_rsa_count; i++) {
			if (probe_rsa[i] == up->port.iobase) {
				if (serial8250_request_rsa_resource(up) == 0)
					up->probe |= UART_PROBE_RSA;
				break;
			}
		}
	}

	base_ops->config_port(port, flags);

	if (port->type != PORT_RSA && up->probe & UART_PROBE_RSA)
		serial8250_release_rsa_resource(up);
}

static int univ8250_request_port(struct uart_port *port)
{
	struct uart_8250_port *up = up_to_u8250p(port);
	int ret;

	ret = base_ops->request_port(port);
	if (ret == 0 && port->type == PORT_RSA) {
		ret = serial8250_request_rsa_resource(up);
		if (ret < 0)
			base_ops->release_port(port);
	}

	return ret;
}

static void univ8250_release_port(struct uart_port *port)
{
	struct uart_8250_port *up = up_to_u8250p(port);

	if (port->type == PORT_RSA)
		serial8250_release_rsa_resource(up);
	base_ops->release_port(port);
}

static void univ8250_rsa_support(struct uart_ops *ops)
{
	ops->config_port  = univ8250_config_port;
	ops->request_port = univ8250_request_port;
	ops->release_port = univ8250_release_port;
}

#else
#define univ8250_rsa_support(x)		do { } while (0)
#endif  

static void __init serial8250_isa_init_ports(void)
{
	struct uart_8250_port *up;
	static int first = 1;
	int i, irqflag = 0;

	if (!first)
		return;
	first = 0;

	if (nr_uarts > UART_NR)
		nr_uarts = UART_NR;

	for (i = 0; i < nr_uarts; i++) {
		struct uart_8250_port *up = &serial8250_ports[i];
		struct uart_port *port = &up->port;

		port->line = i;
		serial8250_init_port(up);
		if (!base_ops)
			base_ops = port->ops;
		port->ops = &univ8250_port_ops;

		init_timer(&up->timer);
		up->timer.function = serial8250_timeout;

		up->ops = &univ8250_driver_ops;

		up->mcr_mask = ~ALPHA_KLUDGE_MCR;
		up->mcr_force = ALPHA_KLUDGE_MCR;
	}

	univ8250_port_ops = *base_ops;
	univ8250_rsa_support(&univ8250_port_ops);

	if (share_irqs)
		irqflag = IRQF_SHARED;

	for (i = 0, up = serial8250_ports;
	     i < ARRAY_SIZE(old_serial_port) && i < nr_uarts;
	     i++, up++) {
		struct uart_port *port = &up->port;
#ifdef MY_DEF_HERE
		 
		char *str;
		if ((0 == i) && (!strncmp(gszSynoTtyS0, "serial", 6))) {
			str = &gszSynoTtyS0[6];
			if (syno_parse_ttys_port(str)) {
				port->iobase = syno_parse_ttys_port(str);
			} else {
				port->iobase = old_serial_port[i].port;
			}
		} else if ((1 == i) && (!strncmp(gszSynoTtyS1, "serial", 6))) {
			str = &gszSynoTtyS1[6];
			if (syno_parse_ttys_port(str)) {
				port->iobase = syno_parse_ttys_port(str);
			} else {
				port->iobase = old_serial_port[i].port;
			}
		}
#else  
		port->iobase   = old_serial_port[i].port;
#endif  
		port->irq      = irq_canonicalize(old_serial_port[i].irq);
		port->irqflags = old_serial_port[i].irqflags;
		port->uartclk  = old_serial_port[i].baud_base * 16;
		port->flags    = old_serial_port[i].flags;
		port->hub6     = old_serial_port[i].hub6;
		port->membase  = old_serial_port[i].iomem_base;
		port->iotype   = old_serial_port[i].io_type;
		port->regshift = old_serial_port[i].iomem_reg_shift;
		serial8250_set_defaults(up);

		port->irqflags |= irqflag;
		if (serial8250_isa_config != NULL)
			serial8250_isa_config(i, &up->port, &up->capabilities);
	}
}

static void __init
serial8250_register_ports(struct uart_driver *drv, struct device *dev)
{
	int i;

	for (i = 0; i < nr_uarts; i++) {
		struct uart_8250_port *up = &serial8250_ports[i];

		if (up->port.type == PORT_8250_CIR)
			continue;

		if (up->port.dev)
			continue;

		up->port.dev = dev;

		if (skip_txen_test)
			up->port.flags |= UPF_NO_TXEN_TEST;

		uart_add_one_port(drv, &up->port);
	}
}

#ifdef CONFIG_SERIAL_8250_CONSOLE

static void univ8250_console_write(struct console *co, const char *s,
				   unsigned int count)
{
	struct uart_8250_port *up = &serial8250_ports[co->index];

	serial8250_console_write(up, s, count);
}

static int univ8250_console_setup(struct console *co, char *options)
{
	struct uart_port *port;

	if (co->index >= nr_uarts)
		co->index = 0;
	port = &serial8250_ports[co->index].port;
	 
	port->cons = co;

	return serial8250_console_setup(port, options, false);
}

static int univ8250_console_match(struct console *co, char *name, int idx,
				  char *options)
{
	char match[] = "uart";	 
	unsigned char iotype;
	unsigned long addr;
	int i;

	if (strncmp(name, match, 4) != 0)
		return -ENODEV;

	if (uart_parse_earlycon(options, &iotype, &addr, &options))
		return -ENODEV;

	for (i = 0; i < nr_uarts; i++) {
		struct uart_port *port = &serial8250_ports[i].port;

		if (port->iotype != iotype)
			continue;
		if ((iotype == UPIO_MEM || iotype == UPIO_MEM32) &&
		    (port->mapbase != addr))
			continue;
		if (iotype == UPIO_PORT && port->iobase != addr)
			continue;

		co->index = i;
		port->cons = co;
		return serial8250_console_setup(port, options, true);
	}

	return -ENODEV;
}

static struct console univ8250_console = {
	.name		= "ttyS",
	.write		= univ8250_console_write,
	.device		= uart_console_device,
	.setup		= univ8250_console_setup,
	.match		= univ8250_console_match,
	.flags		= CON_PRINTBUFFER | CON_ANYTIME,
	.index		= -1,
	.data		= &serial8250_reg,
};

static int __init univ8250_console_init(void)
{
	if (nr_uarts == 0)
		return -ENODEV;

#if defined(MY_ABC_HERE) || defined(MY_DEF_HERE)
	return -ENODEV;
#endif  

	serial8250_isa_init_ports();
	register_console(&univ8250_console);
	return 0;
}
console_initcall(univ8250_console_init);

#define SERIAL8250_CONSOLE	&univ8250_console
#else
#define SERIAL8250_CONSOLE	NULL
#endif

static struct uart_driver serial8250_reg = {
	.owner			= THIS_MODULE,
	.driver_name		= "serial",
	.dev_name		= "ttyS",
	.major			= TTY_MAJOR,
	.minor			= 64,
	.cons			= SERIAL8250_CONSOLE,
};

int __init early_serial_setup(struct uart_port *port)
{
	struct uart_port *p;

	if (port->line >= ARRAY_SIZE(serial8250_ports) || nr_uarts == 0)
		return -ENODEV;

	serial8250_isa_init_ports();
	p = &serial8250_ports[port->line].port;
	p->iobase       = port->iobase;
	p->membase      = port->membase;
	p->irq          = port->irq;
	p->irqflags     = port->irqflags;
	p->uartclk      = port->uartclk;
	p->fifosize     = port->fifosize;
	p->regshift     = port->regshift;
	p->iotype       = port->iotype;
	p->flags        = port->flags;
	p->mapbase      = port->mapbase;
	p->mapsize      = port->mapsize;
	p->private_data = port->private_data;
	p->type		= port->type;
	p->line		= port->line;

	serial8250_set_defaults(up_to_u8250p(p));

	if (port->serial_in)
		p->serial_in = port->serial_in;
	if (port->serial_out)
		p->serial_out = port->serial_out;
	if (port->handle_irq)
		p->handle_irq = port->handle_irq;

	return 0;
}

void serial8250_suspend_port(int line)
{
	struct uart_8250_port *up = &serial8250_ports[line];
	struct uart_port *port = &up->port;

	if (!console_suspend_enabled && uart_console(port) &&
	    port->type != PORT_8250) {
		unsigned char canary = 0xa5;
		serial_out(up, UART_SCR, canary);
		if (serial_in(up, UART_SCR) == canary)
			up->canary = canary;
	}

	uart_suspend_port(&serial8250_reg, port);
}

void serial8250_resume_port(int line)
{
	struct uart_8250_port *up = &serial8250_ports[line];
	struct uart_port *port = &up->port;

	up->canary = 0;

	if (up->capabilities & UART_NATSEMI) {
		 
		serial_port_out(port, UART_LCR, 0xE0);

		ns16550a_goto_highspeed(up);

		serial_port_out(port, UART_LCR, 0);
		port->uartclk = 921600*16;
	}
	uart_resume_port(&serial8250_reg, port);
}

static int serial8250_probe(struct platform_device *dev)
{
	struct plat_serial8250_port *p = dev_get_platdata(&dev->dev);
	struct uart_8250_port uart;
	int ret, i, irqflag = 0;

	memset(&uart, 0, sizeof(uart));

	if (share_irqs)
		irqflag = IRQF_SHARED;

	for (i = 0; p && p->flags != 0; p++, i++) {
		uart.port.iobase	= p->iobase;
		uart.port.membase	= p->membase;
		uart.port.irq		= p->irq;
		uart.port.irqflags	= p->irqflags;
		uart.port.uartclk	= p->uartclk;
		uart.port.regshift	= p->regshift;
		uart.port.iotype	= p->iotype;
		uart.port.flags		= p->flags;
		uart.port.mapbase	= p->mapbase;
		uart.port.hub6		= p->hub6;
		uart.port.private_data	= p->private_data;
		uart.port.type		= p->type;
		uart.port.serial_in	= p->serial_in;
		uart.port.serial_out	= p->serial_out;
		uart.port.handle_irq	= p->handle_irq;
		uart.port.handle_break	= p->handle_break;
		uart.port.set_termios	= p->set_termios;
		uart.port.pm		= p->pm;
		uart.port.dev		= &dev->dev;
		uart.port.irqflags	|= irqflag;
		ret = serial8250_register_8250_port(&uart);
		if (ret < 0) {
			dev_err(&dev->dev, "unable to register port at index %d "
				"(IO%lx MEM%llx IRQ%d): %d\n", i,
				p->iobase, (unsigned long long)p->mapbase,
				p->irq, ret);
		}
	}
	return 0;
}

static int serial8250_remove(struct platform_device *dev)
{
	int i;

	for (i = 0; i < nr_uarts; i++) {
		struct uart_8250_port *up = &serial8250_ports[i];

		if (up->port.dev == &dev->dev)
			serial8250_unregister_port(i);
	}
	return 0;
}

static int serial8250_suspend(struct platform_device *dev, pm_message_t state)
{
	int i;

	for (i = 0; i < UART_NR; i++) {
		struct uart_8250_port *up = &serial8250_ports[i];

		if (up->port.type != PORT_UNKNOWN && up->port.dev == &dev->dev)
			uart_suspend_port(&serial8250_reg, &up->port);
	}

	return 0;
}

static int serial8250_resume(struct platform_device *dev)
{
	int i;

	for (i = 0; i < UART_NR; i++) {
		struct uart_8250_port *up = &serial8250_ports[i];

		if (up->port.type != PORT_UNKNOWN && up->port.dev == &dev->dev)
			serial8250_resume_port(i);
	}

	return 0;
}

static struct platform_driver serial8250_isa_driver = {
	.probe		= serial8250_probe,
	.remove		= serial8250_remove,
	.suspend	= serial8250_suspend,
	.resume		= serial8250_resume,
	.driver		= {
		.name	= "serial8250",
	},
};

static struct platform_device *serial8250_isa_devs;

static DEFINE_MUTEX(serial_mutex);

#ifdef MY_DEF_HERE
static unsigned long syno_parse_ttys_port(char* s)
{
	unsigned long Ret = 0;
	char *e;

	if (*s == ',')
                ++s;

	if (!strncmp(s, "0x", 2)) {
		Ret = simple_strtoul(s, &e, 16);
	}	
	
	return Ret;
}

static unsigned long syno_parse_ttys_pci(char *s)
{
	unsigned long Ret = 0;
	u8 bus, slot, func;
	u32 bar0;
	char *e;

	if (*s == ',')
                ++s;

        if (*s == 0)
                goto End;
        bus = (u8)simple_strtoul(s, &e, 16);
        s = e;
        if (*s != ':')
                goto End;
        ++s;
        slot = (u8)simple_strtoul(s, &e, 16);
        s = e;
        if (*s != '.')
                goto End;
        ++s;
        func = (u8)simple_strtoul(s, &e, 16);
        s = e;

        if (*s == ',')
                s++;

	bar0 = read_pci_config(bus, slot, func, PCI_BASE_ADDRESS_0);		
	
	if (bar0 & 0x01) {
                 
		Ret = bar0 & 0xfffffffc;
        } else if (!(bar0 & 0x01)) {
                 
		Ret = bar0 & 0xfffffff0;
        }		

End:	
	return Ret;	
}
#endif  

static struct uart_8250_port *serial8250_find_match_or_unused(struct uart_port *port)
{
	int i;

#ifdef MY_DEF_HERE
	char *str;
	switch (port->iotype) {
		case UPIO_PORT:
		case UPIO_HUB6:
			if (!strncmp(gszSynoTtyS0, "serial", 6)) {
				str = &gszSynoTtyS0[6];
				if (port->iobase == syno_parse_ttys_port(str)) {
					return &serial8250_ports[0];
				}
			}

			if (!strncmp(gszSynoTtyS1, "serial", 6)){
				str = &gszSynoTtyS1[6];
				if (port->iobase == syno_parse_ttys_port(str)) {
					return &serial8250_ports[1];
				}
			} 

			break;
		case UPIO_MEM:
		case UPIO_MEM32:
		case UPIO_MEM32BE:
		case UPIO_AU:
		case UPIO_TSI:
			if (!strncmp(gszSynoTtyS0, "pciserial", 9)) {
				str = &gszSynoTtyS0[9];
				if ((virt_to_phys((volatile void *)port->mapbase) & 0xffffffff) == syno_parse_ttys_pci(str)) {
					return &serial8250_ports[0];
				}
			}
			if (!strncmp(gszSynoTtyS1, "pciserial", 9)) {
				str = &gszSynoTtyS1[9];
				if ((virt_to_phys((volatile void *)port->mapbase) & 0xffffffff) == syno_parse_ttys_pci(str)) {
					return &serial8250_ports[1];
				}
			}
			break;
		default:
			break;	
	}
 
#endif  
	 
#ifdef MY_DEF_HERE
	for (i = CONFIG_SYNO_TTYS_FUN_NUM; i < nr_uarts; i++)
#else  
	for (i = 0; i < nr_uarts; i++)
#endif  
		if (uart_match_port(&serial8250_ports[i].port, port))
			return &serial8250_ports[i];

	i = port->line;
	if (i < nr_uarts && serial8250_ports[i].port.type == PORT_UNKNOWN &&
			serial8250_ports[i].port.iobase == 0
#ifdef MY_DEF_HERE
			&& i > (CONFIG_SYNO_TTYS_FUN_NUM - 1)
#endif  
	)
		return &serial8250_ports[i];
	 
#ifdef MY_DEF_HERE
	for (i = CONFIG_SYNO_TTYS_FUN_NUM; i < nr_uarts; i++)
#else  
	for (i = 0; i < nr_uarts; i++)
#endif  
		if (serial8250_ports[i].port.type == PORT_UNKNOWN &&
		    serial8250_ports[i].port.iobase == 0)
			return &serial8250_ports[i];

#ifdef MY_DEF_HERE
	for (i = CONFIG_SYNO_TTYS_FUN_NUM; i < nr_uarts; i++)
#else  
	for (i = 0; i < nr_uarts; i++)
#endif  
		if (serial8250_ports[i].port.type == PORT_UNKNOWN)
			return &serial8250_ports[i];

	return NULL;
}

int serial8250_register_8250_port(struct uart_8250_port *up)
{
	struct uart_8250_port *uart;
	int ret = -ENOSPC;

	if (up->port.uartclk == 0)
		return -EINVAL;

	mutex_lock(&serial_mutex);

	uart = serial8250_find_match_or_unused(&up->port);
	if (uart && uart->port.type != PORT_8250_CIR) {
		if (uart->port.dev)
			uart_remove_one_port(&serial8250_reg, &uart->port);

		uart->port.iobase       = up->port.iobase;
		uart->port.membase      = up->port.membase;
		uart->port.irq          = up->port.irq;
		uart->port.irqflags     = up->port.irqflags;
		uart->port.uartclk      = up->port.uartclk;
		uart->port.fifosize     = up->port.fifosize;
		uart->port.regshift     = up->port.regshift;
		uart->port.iotype       = up->port.iotype;
		uart->port.flags        = up->port.flags | UPF_BOOT_AUTOCONF;
		uart->bugs		= up->bugs;
		uart->port.mapbase      = up->port.mapbase;
		uart->port.mapsize      = up->port.mapsize;
		uart->port.private_data = up->port.private_data;
		uart->tx_loadsz		= up->tx_loadsz;
		uart->capabilities	= up->capabilities;
		uart->port.throttle	= up->port.throttle;
		uart->port.unthrottle	= up->port.unthrottle;
		uart->port.rs485_config	= up->port.rs485_config;
		uart->port.rs485	= up->port.rs485;
		uart->dma		= up->dma;

		if (uart->port.fifosize && !uart->tx_loadsz)
			uart->tx_loadsz = uart->port.fifosize;

		if (up->port.dev)
			uart->port.dev = up->port.dev;

		if (skip_txen_test)
			uart->port.flags |= UPF_NO_TXEN_TEST;

		if (up->port.flags & UPF_FIXED_TYPE)
			uart->port.type = up->port.type;

		serial8250_set_defaults(uart);

		if (up->port.serial_in)
			uart->port.serial_in = up->port.serial_in;
		if (up->port.serial_out)
			uart->port.serial_out = up->port.serial_out;
		if (up->port.handle_irq)
			uart->port.handle_irq = up->port.handle_irq;
		 
		if (up->port.set_termios)
			uart->port.set_termios = up->port.set_termios;
		if (up->port.set_mctrl)
			uart->port.set_mctrl = up->port.set_mctrl;
		if (up->port.startup)
			uart->port.startup = up->port.startup;
		if (up->port.shutdown)
			uart->port.shutdown = up->port.shutdown;
		if (up->port.pm)
			uart->port.pm = up->port.pm;
		if (up->port.handle_break)
			uart->port.handle_break = up->port.handle_break;
		if (up->dl_read)
			uart->dl_read = up->dl_read;
		if (up->dl_write)
			uart->dl_write = up->dl_write;

		if (uart->port.type != PORT_8250_CIR) {
			if (serial8250_isa_config != NULL)
				serial8250_isa_config(0, &uart->port,
						&uart->capabilities);

			ret = uart_add_one_port(&serial8250_reg,
						&uart->port);
			if (ret == 0)
				ret = uart->port.line;
		} else {
			dev_info(uart->port.dev,
				"skipping CIR port at 0x%lx / 0x%llx, IRQ %d\n",
				uart->port.iobase,
				(unsigned long long)uart->port.mapbase,
				uart->port.irq);

			ret = 0;
		}
	}
	mutex_unlock(&serial_mutex);

	return ret;
}
EXPORT_SYMBOL(serial8250_register_8250_port);

void serial8250_unregister_port(int line)
{
	struct uart_8250_port *uart = &serial8250_ports[line];

	mutex_lock(&serial_mutex);
	uart_remove_one_port(&serial8250_reg, &uart->port);
	if (serial8250_isa_devs) {
		uart->port.flags &= ~UPF_BOOT_AUTOCONF;
		if (skip_txen_test)
			uart->port.flags |= UPF_NO_TXEN_TEST;
		uart->port.type = PORT_UNKNOWN;
		uart->port.dev = &serial8250_isa_devs->dev;
		uart->capabilities = 0;
		uart_add_one_port(&serial8250_reg, &uart->port);
	} else {
		uart->port.dev = NULL;
	}
	mutex_unlock(&serial_mutex);
}
EXPORT_SYMBOL(serial8250_unregister_port);

static int __init serial8250_init(void)
{
	int ret;

	if (nr_uarts == 0)
		return -ENODEV;

	serial8250_isa_init_ports();

	printk(KERN_INFO "Serial: 8250/16550 driver, "
		"%d ports, IRQ sharing %sabled\n", nr_uarts,
		share_irqs ? "en" : "dis");

#ifdef CONFIG_SPARC
	ret = sunserial_register_minors(&serial8250_reg, UART_NR);
#else
	serial8250_reg.nr = UART_NR;
	ret = uart_register_driver(&serial8250_reg);
#endif
	if (ret)
		goto out;

	ret = serial8250_pnp_init();
	if (ret)
		goto unreg_uart_drv;

	serial8250_isa_devs = platform_device_alloc("serial8250",
						    PLAT8250_DEV_LEGACY);
	if (!serial8250_isa_devs) {
		ret = -ENOMEM;
		goto unreg_pnp;
	}

	ret = platform_device_add(serial8250_isa_devs);
	if (ret)
		goto put_dev;

	serial8250_register_ports(&serial8250_reg, &serial8250_isa_devs->dev);

	ret = platform_driver_register(&serial8250_isa_driver);
	if (ret == 0)
		goto out;

	platform_device_del(serial8250_isa_devs);
put_dev:
	platform_device_put(serial8250_isa_devs);
unreg_pnp:
	serial8250_pnp_exit();
unreg_uart_drv:
#ifdef CONFIG_SPARC
	sunserial_unregister_minors(&serial8250_reg, UART_NR);
#else
	uart_unregister_driver(&serial8250_reg);
#endif
out:
	return ret;
}

static void __exit serial8250_exit(void)
{
	struct platform_device *isa_dev = serial8250_isa_devs;

	serial8250_isa_devs = NULL;

	platform_driver_unregister(&serial8250_isa_driver);
	platform_device_unregister(isa_dev);

	serial8250_pnp_exit();

#ifdef CONFIG_SPARC
	sunserial_unregister_minors(&serial8250_reg, UART_NR);
#else
	uart_unregister_driver(&serial8250_reg);
#endif
}

module_init(serial8250_init);
module_exit(serial8250_exit);

EXPORT_SYMBOL(serial8250_suspend_port);
EXPORT_SYMBOL(serial8250_resume_port);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Generic 8250/16x50 serial driver");

module_param(share_irqs, uint, 0644);
MODULE_PARM_DESC(share_irqs, "Share IRQs with other non-8250/16x50 devices"
	" (unsafe)");

module_param(nr_uarts, uint, 0644);
MODULE_PARM_DESC(nr_uarts, "Maximum number of UARTs supported. (1-" __MODULE_STRING(CONFIG_SERIAL_8250_NR_UARTS) ")");

module_param(skip_txen_test, uint, 0644);
MODULE_PARM_DESC(skip_txen_test, "Skip checking for the TXEN bug at init time");

#ifdef CONFIG_SERIAL_8250_RSA
module_param_array(probe_rsa, ulong, &probe_rsa_count, 0444);
MODULE_PARM_DESC(probe_rsa, "Probe I/O ports for RSA");
#endif
MODULE_ALIAS_CHARDEV_MAJOR(TTY_MAJOR);

#ifdef CONFIG_SERIAL_8250_DEPRECATED_OPTIONS
#ifndef MODULE
 
static void __used s8250_options(void)
{
#undef MODULE_PARAM_PREFIX
#define MODULE_PARAM_PREFIX "8250_core."

	module_param_cb(share_irqs, &param_ops_uint, &share_irqs, 0644);
	module_param_cb(nr_uarts, &param_ops_uint, &nr_uarts, 0644);
	module_param_cb(skip_txen_test, &param_ops_uint, &skip_txen_test, 0644);
#ifdef CONFIG_SERIAL_8250_RSA
	__module_param_call(MODULE_PARAM_PREFIX, probe_rsa,
		&param_array_ops, .arr = &__param_arr_probe_rsa,
		0444, -1, 0);
#endif
}
#else
MODULE_ALIAS("8250_core");
#endif
#endif
