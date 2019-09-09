#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/console.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/nmi.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/interrupt.h>			 
#include <linux/delay.h>
#include <linux/smp.h>
#include <linux/security.h>
#include <linux/bootmem.h>
#include <linux/memblock.h>
#include <linux/syscalls.h>
#include <linux/kexec.h>
#include <linux/kdb.h>
#include <linux/ratelimit.h>
#include <linux/kmsg_dump.h>
#include <linux/syslog.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/rculist.h>
#include <linux/poll.h>
#include <linux/irq_work.h>
#include <linux/utsname.h>
#include <linux/ctype.h>
#include <linux/uio.h>

#include <asm/uaccess.h>

#define CREATE_TRACE_POINTS
#include <trace/events/printk.h>

#include "console_cmdline.h"
#include "braille.h"

int console_printk[4] = {
	CONSOLE_LOGLEVEL_DEFAULT,	 
	MESSAGE_LOGLEVEL_DEFAULT,	 
	CONSOLE_LOGLEVEL_MIN,		 
	CONSOLE_LOGLEVEL_DEFAULT,	 
};

int oops_in_progress;
EXPORT_SYMBOL(oops_in_progress);

static DEFINE_SEMAPHORE(console_sem);
struct console *console_drivers;
EXPORT_SYMBOL_GPL(console_drivers);

#ifdef CONFIG_LOCKDEP
static struct lockdep_map console_lock_dep_map = {
	.name = "console_lock"
};
#endif

static int nr_ext_console_drivers;

#define down_console_sem() do { \
	down(&console_sem);\
	mutex_acquire(&console_lock_dep_map, 0, 0, _RET_IP_);\
} while (0)

static int __down_trylock_console_sem(unsigned long ip)
{
	if (down_trylock(&console_sem))
		return 1;
	mutex_acquire(&console_lock_dep_map, 0, 1, ip);
	return 0;
}
#define down_trylock_console_sem() __down_trylock_console_sem(_RET_IP_)

#define up_console_sem() do { \
	mutex_release(&console_lock_dep_map, 1, _RET_IP_);\
	up(&console_sem);\
} while (0)

static int console_locked, console_suspended;

static struct console *exclusive_console;

#define MAX_CMDLINECONSOLES 8

static struct console_cmdline console_cmdline[MAX_CMDLINECONSOLES];

static int selected_console = -1;
static int preferred_console = -1;
int console_set_on_cmdline;
EXPORT_SYMBOL(console_set_on_cmdline);

static int console_may_schedule;

enum log_flags {
	LOG_NOCONS	= 1,	 
	LOG_NEWLINE	= 2,	 
	LOG_PREFIX	= 4,	 
	LOG_CONT	= 8,	 
};

struct printk_log {
	u64 ts_nsec;		 
	u16 len;		 
	u16 text_len;		 
	u16 dict_len;		 
	u8 facility;		 
	u8 flags:5;		 
	u8 level:3;		 
};

static DEFINE_RAW_SPINLOCK(logbuf_lock);

#ifdef CONFIG_PRINTK
DECLARE_WAIT_QUEUE_HEAD(log_wait);
 
static u64 syslog_seq;
static u32 syslog_idx;
static enum log_flags syslog_prev;
static size_t syslog_partial;

#if defined(MY_DEF_HERE)
static u64 dnv_console_seq = 0;
static u32 dnv_console_idx = 0;
#endif

static u64 log_first_seq;
static u32 log_first_idx;

static u64 log_next_seq;
static u32 log_next_idx;

static u64 console_seq;
static u32 console_idx;
static enum log_flags console_prev;

static u64 clear_seq;
static u32 clear_idx;

#define PREFIX_MAX		32
#define LOG_LINE_MAX		(1024 - PREFIX_MAX)

#define LOG_LEVEL(v)		((v) & 0x07)
#define LOG_FACILITY(v)		((v) >> 3 & 0xff)

#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
#define LOG_ALIGN 4
#else
#define LOG_ALIGN __alignof__(struct printk_log)
#endif
#define __LOG_BUF_LEN (1 << CONFIG_LOG_BUF_SHIFT)
static char __log_buf[__LOG_BUF_LEN] __aligned(LOG_ALIGN);
static char *log_buf = __log_buf;
static u32 log_buf_len = __LOG_BUF_LEN;

char *log_buf_addr_get(void)
{
	return log_buf;
}

u32 log_buf_len_get(void)
{
	return log_buf_len;
}

static char *log_text(const struct printk_log *msg)
{
	return (char *)msg + sizeof(struct printk_log);
}

static char *log_dict(const struct printk_log *msg)
{
	return (char *)msg + sizeof(struct printk_log) + msg->text_len;
}

static struct printk_log *log_from_idx(u32 idx)
{
	struct printk_log *msg = (struct printk_log *)(log_buf + idx);

	if (!msg->len)
		return (struct printk_log *)log_buf;
	return msg;
}

static u32 log_next(u32 idx)
{
	struct printk_log *msg = (struct printk_log *)(log_buf + idx);

	if (!msg->len) {
		msg = (struct printk_log *)log_buf;
		return msg->len;
	}
	return idx + msg->len;
}

static int logbuf_has_space(u32 msg_size, bool empty)
{
	u32 free;

	if (log_next_idx > log_first_idx || empty)
		free = max(log_buf_len - log_next_idx, log_first_idx);
	else
		free = log_first_idx - log_next_idx;

	return free >= msg_size + sizeof(struct printk_log);
}

static int log_make_free_space(u32 msg_size)
{
	while (log_first_seq < log_next_seq) {
		if (logbuf_has_space(msg_size, false))
			return 0;
		 
		log_first_idx = log_next(log_first_idx);
		log_first_seq++;
	}

	if (logbuf_has_space(msg_size, true))
		return 0;

	return -ENOMEM;
}

static u32 msg_used_size(u16 text_len, u16 dict_len, u32 *pad_len)
{
	u32 size;

	size = sizeof(struct printk_log) + text_len + dict_len;
	*pad_len = (-size) & (LOG_ALIGN - 1);
	size += *pad_len;

	return size;
}

#define MAX_LOG_TAKE_PART 4
static const char trunc_msg[] = "<truncated>";

static u32 truncate_msg(u16 *text_len, u16 *trunc_msg_len,
			u16 *dict_len, u32 *pad_len)
{
	 
	u32 max_text_len = log_buf_len / MAX_LOG_TAKE_PART;
	if (*text_len > max_text_len)
		*text_len = max_text_len;
	 
	*trunc_msg_len = strlen(trunc_msg);
	 
	*dict_len = 0;
	 
	return msg_used_size(*text_len + *trunc_msg_len, 0, pad_len);
}

static int log_store(int facility, int level,
		     enum log_flags flags, u64 ts_nsec,
		     const char *dict, u16 dict_len,
		     const char *text, u16 text_len)
{
	struct printk_log *msg;
	u32 size, pad_len;
	u16 trunc_msg_len = 0;

	size = msg_used_size(text_len, dict_len, &pad_len);

	if (log_make_free_space(size)) {
		 
		size = truncate_msg(&text_len, &trunc_msg_len,
				    &dict_len, &pad_len);
		 
		if (log_make_free_space(size))
			return 0;
	}

	if (log_next_idx + size + sizeof(struct printk_log) > log_buf_len) {
		 
		memset(log_buf + log_next_idx, 0, sizeof(struct printk_log));
		log_next_idx = 0;
	}

	msg = (struct printk_log *)(log_buf + log_next_idx);
	memcpy(log_text(msg), text, text_len);
	msg->text_len = text_len;
	if (trunc_msg_len) {
		memcpy(log_text(msg) + text_len, trunc_msg, trunc_msg_len);
		msg->text_len += trunc_msg_len;
	}
	memcpy(log_dict(msg), dict, dict_len);
	msg->dict_len = dict_len;
	msg->facility = facility;
	msg->level = level & 7;
	msg->flags = flags & 0x1f;
	if (ts_nsec > 0)
		msg->ts_nsec = ts_nsec;
	else
		msg->ts_nsec = local_clock();
	memset(log_dict(msg) + dict_len, 0, pad_len);
	msg->len = size;

	log_next_idx += msg->len;
	log_next_seq++;

	return msg->text_len;
}

int dmesg_restrict = IS_ENABLED(CONFIG_SECURITY_DMESG_RESTRICT);

static int syslog_action_restricted(int type)
{
	if (dmesg_restrict)
		return 1;
	 
	return type != SYSLOG_ACTION_READ_ALL &&
	       type != SYSLOG_ACTION_SIZE_BUFFER;
}

int check_syslog_permissions(int type, int source)
{
	 
	if (source == SYSLOG_FROM_PROC && type != SYSLOG_ACTION_OPEN)
		goto ok;

	if (syslog_action_restricted(type)) {
		if (capable(CAP_SYSLOG))
			goto ok;
		 
		if (capable(CAP_SYS_ADMIN)) {
			pr_warn_once("%s (%d): Attempt to access syslog with "
				     "CAP_SYS_ADMIN but no CAP_SYSLOG "
				     "(deprecated).\n",
				 current->comm, task_pid_nr(current));
			goto ok;
		}
		return -EPERM;
	}
ok:
	return security_syslog(type);
}
EXPORT_SYMBOL_GPL(check_syslog_permissions);

static void append_char(char **pp, char *e, char c)
{
	if (*pp < e)
		*(*pp)++ = c;
}

static ssize_t msg_print_ext_header(char *buf, size_t size,
				    struct printk_log *msg, u64 seq,
				    enum log_flags prev_flags)
{
	u64 ts_usec = msg->ts_nsec;
	char cont = '-';

	do_div(ts_usec, 1000);

	if (msg->flags & LOG_CONT && !(prev_flags & LOG_CONT))
		cont = 'c';
	else if ((msg->flags & LOG_CONT) ||
		 ((prev_flags & LOG_CONT) && !(msg->flags & LOG_PREFIX)))
		cont = '+';

	return scnprintf(buf, size, "%u,%llu,%llu,%c;",
		       (msg->facility << 3) | msg->level, seq, ts_usec, cont);
}

static ssize_t msg_print_ext_body(char *buf, size_t size,
				  char *dict, size_t dict_len,
				  char *text, size_t text_len)
{
	char *p = buf, *e = buf + size;
	size_t i;

	for (i = 0; i < text_len; i++) {
		unsigned char c = text[i];

		if (c < ' ' || c >= 127 || c == '\\')
			p += scnprintf(p, e - p, "\\x%02x", c);
		else
			append_char(&p, e, c);
	}
	append_char(&p, e, '\n');

	if (dict_len) {
		bool line = true;

		for (i = 0; i < dict_len; i++) {
			unsigned char c = dict[i];

			if (line) {
				append_char(&p, e, ' ');
				line = false;
			}

			if (c == '\0') {
				append_char(&p, e, '\n');
				line = true;
				continue;
			}

			if (c < ' ' || c >= 127 || c == '\\') {
				p += scnprintf(p, e - p, "\\x%02x", c);
				continue;
			}

			append_char(&p, e, c);
		}
		append_char(&p, e, '\n');
	}

	return p - buf;
}

struct devkmsg_user {
	u64 seq;
	u32 idx;
	enum log_flags prev;
	struct mutex lock;
	char buf[CONSOLE_EXT_LOG_MAX];
};

static ssize_t devkmsg_write(struct kiocb *iocb, struct iov_iter *from)
{
	char *buf, *line;
	int level = default_message_loglevel;
	int facility = 1;	 
	size_t len = iov_iter_count(from);
	ssize_t ret = len;

	if (len > LOG_LINE_MAX)
		return -EINVAL;
	buf = kmalloc(len+1, GFP_KERNEL);
	if (buf == NULL)
		return -ENOMEM;

	buf[len] = '\0';
	if (copy_from_iter(buf, len, from) != len) {
		kfree(buf);
		return -EFAULT;
	}

	line = buf;
	if (line[0] == '<') {
		char *endp = NULL;
		unsigned int u;

		u = simple_strtoul(line + 1, &endp, 10);
		if (endp && endp[0] == '>') {
			level = LOG_LEVEL(u);
			if (LOG_FACILITY(u) != 0)
				facility = LOG_FACILITY(u);
			endp++;
			len -= endp - line;
			line = endp;
		}
	}

	printk_emit(facility, level, NULL, 0, "%s", line);
	kfree(buf);
	return ret;
}

static ssize_t devkmsg_read(struct file *file, char __user *buf,
			    size_t count, loff_t *ppos)
{
	struct devkmsg_user *user = file->private_data;
	struct printk_log *msg;
	size_t len;
	ssize_t ret;

	if (!user)
		return -EBADF;

	ret = mutex_lock_interruptible(&user->lock);
	if (ret)
		return ret;
	raw_spin_lock_irq(&logbuf_lock);
	while (user->seq == log_next_seq) {
		if (file->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			raw_spin_unlock_irq(&logbuf_lock);
			goto out;
		}

		raw_spin_unlock_irq(&logbuf_lock);
		ret = wait_event_interruptible(log_wait,
					       user->seq != log_next_seq);
		if (ret)
			goto out;
		raw_spin_lock_irq(&logbuf_lock);
	}

	if (user->seq < log_first_seq) {
		 
		user->idx = log_first_idx;
		user->seq = log_first_seq;
		ret = -EPIPE;
		raw_spin_unlock_irq(&logbuf_lock);
		goto out;
	}

	msg = log_from_idx(user->idx);
	len = msg_print_ext_header(user->buf, sizeof(user->buf),
				   msg, user->seq, user->prev);
	len += msg_print_ext_body(user->buf + len, sizeof(user->buf) - len,
				  log_dict(msg), msg->dict_len,
				  log_text(msg), msg->text_len);

	user->prev = msg->flags;
	user->idx = log_next(user->idx);
	user->seq++;
	raw_spin_unlock_irq(&logbuf_lock);

	if (len > count) {
		ret = -EINVAL;
		goto out;
	}

	if (copy_to_user(buf, user->buf, len)) {
		ret = -EFAULT;
		goto out;
	}
	ret = len;
out:
	mutex_unlock(&user->lock);
	return ret;
}

static loff_t devkmsg_llseek(struct file *file, loff_t offset, int whence)
{
	struct devkmsg_user *user = file->private_data;
	loff_t ret = 0;

	if (!user)
		return -EBADF;
	if (offset)
		return -ESPIPE;

	raw_spin_lock_irq(&logbuf_lock);
	switch (whence) {
	case SEEK_SET:
		 
		user->idx = log_first_idx;
		user->seq = log_first_seq;
		break;
	case SEEK_DATA:
		 
		user->idx = clear_idx;
		user->seq = clear_seq;
		break;
	case SEEK_END:
		 
		user->idx = log_next_idx;
		user->seq = log_next_seq;
		break;
	default:
		ret = -EINVAL;
	}
	raw_spin_unlock_irq(&logbuf_lock);
	return ret;
}

static unsigned int devkmsg_poll(struct file *file, poll_table *wait)
{
	struct devkmsg_user *user = file->private_data;
	int ret = 0;

	if (!user)
		return POLLERR|POLLNVAL;

	poll_wait(file, &log_wait, wait);

	raw_spin_lock_irq(&logbuf_lock);
	if (user->seq < log_next_seq) {
		 
		if (user->seq < log_first_seq)
			ret = POLLIN|POLLRDNORM|POLLERR|POLLPRI;
		else
			ret = POLLIN|POLLRDNORM;
	}
	raw_spin_unlock_irq(&logbuf_lock);

	return ret;
}

static int devkmsg_open(struct inode *inode, struct file *file)
{
	struct devkmsg_user *user;
	int err;

	if ((file->f_flags & O_ACCMODE) == O_WRONLY)
		return 0;

	err = check_syslog_permissions(SYSLOG_ACTION_READ_ALL,
				       SYSLOG_FROM_READER);
	if (err)
		return err;

	user = kmalloc(sizeof(struct devkmsg_user), GFP_KERNEL);
	if (!user)
		return -ENOMEM;

	mutex_init(&user->lock);

	raw_spin_lock_irq(&logbuf_lock);
	user->idx = log_first_idx;
	user->seq = log_first_seq;
	raw_spin_unlock_irq(&logbuf_lock);

	file->private_data = user;
	return 0;
}

static int devkmsg_release(struct inode *inode, struct file *file)
{
	struct devkmsg_user *user = file->private_data;

	if (!user)
		return 0;

	mutex_destroy(&user->lock);
	kfree(user);
	return 0;
}

const struct file_operations kmsg_fops = {
	.open = devkmsg_open,
	.read = devkmsg_read,
	.write_iter = devkmsg_write,
	.llseek = devkmsg_llseek,
	.poll = devkmsg_poll,
	.release = devkmsg_release,
};

#ifdef CONFIG_KEXEC_CORE
 
void log_buf_kexec_setup(void)
{
	VMCOREINFO_SYMBOL(log_buf);
	VMCOREINFO_SYMBOL(log_buf_len);
	VMCOREINFO_SYMBOL(log_first_idx);
	VMCOREINFO_SYMBOL(log_next_idx);
	 
	VMCOREINFO_STRUCT_SIZE(printk_log);
	VMCOREINFO_OFFSET(printk_log, ts_nsec);
	VMCOREINFO_OFFSET(printk_log, len);
	VMCOREINFO_OFFSET(printk_log, text_len);
	VMCOREINFO_OFFSET(printk_log, dict_len);
}
#endif

static unsigned long __initdata new_log_buf_len;

static void __init log_buf_len_update(unsigned size)
{
	if (size)
		size = roundup_pow_of_two(size);
	if (size > log_buf_len)
		new_log_buf_len = size;
}

static int __init log_buf_len_setup(char *str)
{
	unsigned size = memparse(str, &str);

	log_buf_len_update(size);

	return 0;
}
early_param("log_buf_len", log_buf_len_setup);

#ifdef CONFIG_SMP
#define __LOG_CPU_MAX_BUF_LEN (1 << CONFIG_LOG_CPU_MAX_BUF_SHIFT)

static void __init log_buf_add_cpu(void)
{
	unsigned int cpu_extra;

	if (num_possible_cpus() == 1)
		return;

	cpu_extra = (num_possible_cpus() - 1) * __LOG_CPU_MAX_BUF_LEN;

	if (cpu_extra <= __LOG_BUF_LEN / 2)
		return;

	pr_info("log_buf_len individual max cpu contribution: %d bytes\n",
		__LOG_CPU_MAX_BUF_LEN);
	pr_info("log_buf_len total cpu_extra contributions: %d bytes\n",
		cpu_extra);
	pr_info("log_buf_len min size: %d bytes\n", __LOG_BUF_LEN);

	log_buf_len_update(cpu_extra + __LOG_BUF_LEN);
}
#else  
static inline void log_buf_add_cpu(void) {}
#endif  

void __init setup_log_buf(int early)
{
	unsigned long flags;
	char *new_log_buf;
	int free;

	if (log_buf != __log_buf)
		return;

	if (!early && !new_log_buf_len)
		log_buf_add_cpu();

	if (!new_log_buf_len)
		return;

	if (early) {
		new_log_buf =
			memblock_virt_alloc(new_log_buf_len, LOG_ALIGN);
	} else {
		new_log_buf = memblock_virt_alloc_nopanic(new_log_buf_len,
							  LOG_ALIGN);
	}

	if (unlikely(!new_log_buf)) {
		pr_err("log_buf_len: %ld bytes not available\n",
			new_log_buf_len);
		return;
	}

	raw_spin_lock_irqsave(&logbuf_lock, flags);
	log_buf_len = new_log_buf_len;
	log_buf = new_log_buf;
	new_log_buf_len = 0;
	free = __LOG_BUF_LEN - log_next_idx;
	memcpy(log_buf, __log_buf, __LOG_BUF_LEN);
	raw_spin_unlock_irqrestore(&logbuf_lock, flags);

	pr_info("log_buf_len: %d bytes\n", log_buf_len);
	pr_info("early log buf free: %d(%d%%)\n",
		free, (free * 100) / __LOG_BUF_LEN);
}

static bool __read_mostly ignore_loglevel;

static int __init ignore_loglevel_setup(char *str)
{
	ignore_loglevel = true;
	pr_info("debug: ignoring loglevel setting.\n");

	return 0;
}

early_param("ignore_loglevel", ignore_loglevel_setup);
module_param(ignore_loglevel, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(ignore_loglevel,
		 "ignore loglevel setting (prints all kernel messages to the console)");

#ifdef CONFIG_BOOT_PRINTK_DELAY

static int boot_delay;  
static unsigned long long loops_per_msec;	 

static int __init boot_delay_setup(char *str)
{
	unsigned long lpj;

	lpj = preset_lpj ? preset_lpj : 1000000;	 
	loops_per_msec = (unsigned long long)lpj / 1000 * HZ;

	get_option(&str, &boot_delay);
	if (boot_delay > 10 * 1000)
		boot_delay = 0;

	pr_debug("boot_delay: %u, preset_lpj: %ld, lpj: %lu, "
		"HZ: %d, loops_per_msec: %llu\n",
		boot_delay, preset_lpj, lpj, HZ, loops_per_msec);
	return 0;
}
early_param("boot_delay", boot_delay_setup);

static void boot_delay_msec(int level)
{
	unsigned long long k;
	unsigned long timeout;

	if ((boot_delay == 0 || system_state != SYSTEM_BOOTING)
		|| (level >= console_loglevel && !ignore_loglevel)) {
		return;
	}

	k = (unsigned long long)loops_per_msec * boot_delay;

	timeout = jiffies + msecs_to_jiffies(boot_delay);
	while (k) {
		k--;
		cpu_relax();
		 
		if (time_after(jiffies, timeout))
			break;
		touch_nmi_watchdog();
	}
}
#else
static inline void boot_delay_msec(int level)
{
}
#endif

static bool printk_time = IS_ENABLED(CONFIG_PRINTK_TIME);
module_param_named(time, printk_time, bool, S_IRUGO | S_IWUSR);

static size_t print_time(u64 ts, char *buf)
{
	unsigned long rem_nsec;

	if (!printk_time)
		return 0;

	rem_nsec = do_div(ts, 1000000000);

	if (!buf)
		return snprintf(NULL, 0, "[%5lu.000000] ", (unsigned long)ts);

	return sprintf(buf, "[%5lu.%06lu] ",
		       (unsigned long)ts, rem_nsec / 1000);
}

static size_t print_prefix(const struct printk_log *msg, bool syslog, char *buf)
{
	size_t len = 0;
	unsigned int prefix = (msg->facility << 3) | msg->level;

	if (syslog) {
		if (buf) {
			len += sprintf(buf, "<%u>", prefix);
		} else {
			len += 3;
			if (prefix > 999)
				len += 3;
			else if (prefix > 99)
				len += 2;
			else if (prefix > 9)
				len++;
		}
	}

	len += print_time(msg->ts_nsec, buf ? buf + len : NULL);
	return len;
}

static size_t msg_print_text(const struct printk_log *msg, enum log_flags prev,
			     bool syslog, char *buf, size_t size)
{
	const char *text = log_text(msg);
	size_t text_size = msg->text_len;
	bool prefix = true;
	bool newline = true;
	size_t len = 0;

	if ((prev & LOG_CONT) && !(msg->flags & LOG_PREFIX))
		prefix = false;

	if (msg->flags & LOG_CONT) {
		if ((prev & LOG_CONT) && !(prev & LOG_NEWLINE))
			prefix = false;

		if (!(msg->flags & LOG_NEWLINE))
			newline = false;
	}

	do {
		const char *next = memchr(text, '\n', text_size);
		size_t text_len;

		if (next) {
			text_len = next - text;
			next++;
			text_size -= next - text;
		} else {
			text_len = text_size;
		}

		if (buf) {
			if (print_prefix(msg, syslog, NULL) +
			    text_len + 1 >= size - len)
				break;

			if (prefix)
				len += print_prefix(msg, syslog, buf + len);
			memcpy(buf + len, text, text_len);
			len += text_len;
			if (next || newline)
				buf[len++] = '\n';
		} else {
			 
			if (prefix)
				len += print_prefix(msg, syslog, NULL);
			len += text_len;
			if (next || newline)
				len++;
		}

		prefix = true;
		text = next;
	} while (text);

	return len;
}

static int syslog_print(char __user *buf, int size)
{
	char *text;
	struct printk_log *msg;
	int len = 0;

	text = kmalloc(LOG_LINE_MAX + PREFIX_MAX, GFP_KERNEL);
	if (!text)
		return -ENOMEM;

	while (size > 0) {
		size_t n;
		size_t skip;

		raw_spin_lock_irq(&logbuf_lock);
		if (syslog_seq < log_first_seq) {
			 
			syslog_seq = log_first_seq;
			syslog_idx = log_first_idx;
			syslog_prev = 0;
			syslog_partial = 0;
		}
		if (syslog_seq == log_next_seq) {
			raw_spin_unlock_irq(&logbuf_lock);
			break;
		}

		skip = syslog_partial;
		msg = log_from_idx(syslog_idx);
		n = msg_print_text(msg, syslog_prev, true, text,
				   LOG_LINE_MAX + PREFIX_MAX);
		if (n - syslog_partial <= size) {
			 
			syslog_idx = log_next(syslog_idx);
			syslog_seq++;
			syslog_prev = msg->flags;
			n -= syslog_partial;
			syslog_partial = 0;
		} else if (!len){
			 
			n = size;
			syslog_partial += n;
		} else
			n = 0;
		raw_spin_unlock_irq(&logbuf_lock);

		if (!n)
			break;

		if (copy_to_user(buf, text + skip, n)) {
			if (!len)
				len = -EFAULT;
			break;
		}

		len += n;
		size -= n;
		buf += n;
	}

	kfree(text);
	return len;
}

static int syslog_print_all(char __user *buf, int size, bool clear)
{
	char *text;
	int len = 0;

	text = kmalloc(LOG_LINE_MAX + PREFIX_MAX, GFP_KERNEL);
	if (!text)
		return -ENOMEM;

	raw_spin_lock_irq(&logbuf_lock);
	if (buf) {
		u64 next_seq;
		u64 seq;
		u32 idx;
		enum log_flags prev;

		if (clear_seq < log_first_seq) {
			 
			clear_seq = log_first_seq;
			clear_idx = log_first_idx;
		}

		seq = clear_seq;
		idx = clear_idx;
		prev = 0;
		while (seq < log_next_seq) {
			struct printk_log *msg = log_from_idx(idx);

			len += msg_print_text(msg, prev, true, NULL, 0);
			prev = msg->flags;
			idx = log_next(idx);
			seq++;
		}

		seq = clear_seq;
		idx = clear_idx;
		prev = 0;
		while (len > size && seq < log_next_seq) {
			struct printk_log *msg = log_from_idx(idx);

			len -= msg_print_text(msg, prev, true, NULL, 0);
			prev = msg->flags;
			idx = log_next(idx);
			seq++;
		}

		next_seq = log_next_seq;

		len = 0;
		while (len >= 0 && seq < next_seq) {
			struct printk_log *msg = log_from_idx(idx);
			int textlen;

			textlen = msg_print_text(msg, prev, true, text,
						 LOG_LINE_MAX + PREFIX_MAX);
			if (textlen < 0) {
				len = textlen;
				break;
			}
			idx = log_next(idx);
			seq++;
			prev = msg->flags;

			raw_spin_unlock_irq(&logbuf_lock);
			if (copy_to_user(buf + len, text, textlen))
				len = -EFAULT;
			else
				len += textlen;
			raw_spin_lock_irq(&logbuf_lock);

			if (seq < log_first_seq) {
				 
				seq = log_first_seq;
				idx = log_first_idx;
				prev = 0;
			}
		}
	}

	if (clear) {
		clear_seq = log_next_seq;
		clear_idx = log_next_idx;
	}
	raw_spin_unlock_irq(&logbuf_lock);

	kfree(text);
	return len;
}

int do_syslog(int type, char __user *buf, int len, int source)
{
	bool clear = false;
	static int saved_console_loglevel = LOGLEVEL_DEFAULT;
	int error;

	error = check_syslog_permissions(type, source);
	if (error)
		goto out;

	switch (type) {
	case SYSLOG_ACTION_CLOSE:	 
		break;
	case SYSLOG_ACTION_OPEN:	 
		break;
	case SYSLOG_ACTION_READ:	 
		error = -EINVAL;
		if (!buf || len < 0)
			goto out;
		error = 0;
		if (!len)
			goto out;
		if (!access_ok(VERIFY_WRITE, buf, len)) {
			error = -EFAULT;
			goto out;
		}
		error = wait_event_interruptible(log_wait,
						 syslog_seq != log_next_seq);
		if (error)
			goto out;
		error = syslog_print(buf, len);
		break;
	 
	case SYSLOG_ACTION_READ_CLEAR:
		clear = true;
		 
	case SYSLOG_ACTION_READ_ALL:
		error = -EINVAL;
		if (!buf || len < 0)
			goto out;
		error = 0;
		if (!len)
			goto out;
		if (!access_ok(VERIFY_WRITE, buf, len)) {
			error = -EFAULT;
			goto out;
		}
		error = syslog_print_all(buf, len, clear);
		break;
	 
	case SYSLOG_ACTION_CLEAR:
		syslog_print_all(NULL, 0, true);
		break;
	 
	case SYSLOG_ACTION_CONSOLE_OFF:
		if (saved_console_loglevel == LOGLEVEL_DEFAULT)
			saved_console_loglevel = console_loglevel;
		console_loglevel = minimum_console_loglevel;
		break;
	 
	case SYSLOG_ACTION_CONSOLE_ON:
		if (saved_console_loglevel != LOGLEVEL_DEFAULT) {
			console_loglevel = saved_console_loglevel;
			saved_console_loglevel = LOGLEVEL_DEFAULT;
		}
		break;
	 
	case SYSLOG_ACTION_CONSOLE_LEVEL:
		error = -EINVAL;
		if (len < 1 || len > 8)
			goto out;
		if (len < minimum_console_loglevel)
			len = minimum_console_loglevel;
		console_loglevel = len;
		 
		saved_console_loglevel = LOGLEVEL_DEFAULT;
		error = 0;
		break;
	 
	case SYSLOG_ACTION_SIZE_UNREAD:
		raw_spin_lock_irq(&logbuf_lock);
		if (syslog_seq < log_first_seq) {
			 
			syslog_seq = log_first_seq;
			syslog_idx = log_first_idx;
			syslog_prev = 0;
			syslog_partial = 0;
		}
		if (source == SYSLOG_FROM_PROC) {
			 
			error = log_next_seq - syslog_seq;
		} else {
			u64 seq = syslog_seq;
			u32 idx = syslog_idx;
			enum log_flags prev = syslog_prev;

			error = 0;
			while (seq < log_next_seq) {
				struct printk_log *msg = log_from_idx(idx);

				error += msg_print_text(msg, prev, true, NULL, 0);
				idx = log_next(idx);
				seq++;
				prev = msg->flags;
			}
			error -= syslog_partial;
		}
		raw_spin_unlock_irq(&logbuf_lock);
		break;
	 
	case SYSLOG_ACTION_SIZE_BUFFER:
		error = log_buf_len;
		break;
	default:
		error = -EINVAL;
		break;
	}
out:
	return error;
}

SYSCALL_DEFINE3(syslog, int, type, char __user *, buf, int, len)
{
	return do_syslog(type, buf, len, SYSLOG_FROM_READER);
}

static void call_console_drivers(int level,
				 const char *ext_text, size_t ext_len,
				 const char *text, size_t len)
{
	struct console *con;

	trace_console_rcuidle(text, len);

	if (level >= console_loglevel && !ignore_loglevel)
		return;
	if (!console_drivers)
		return;

	for_each_console(con) {
		if (exclusive_console && con != exclusive_console)
			continue;
		if (!(con->flags & CON_ENABLED))
			continue;
		if (!con->write)
			continue;
		if (!cpu_online(smp_processor_id()) &&
		    !(con->flags & CON_ANYTIME))
			continue;
		if (con->flags & CON_EXTENDED)
			con->write(con, ext_text, ext_len);
		else
			con->write(con, text, len);
	}
}

static void zap_locks(void)
{
	static unsigned long oops_timestamp;

	if (time_after_eq(jiffies, oops_timestamp) &&
	    !time_after(jiffies, oops_timestamp + 30 * HZ))
		return;

	oops_timestamp = jiffies;

	debug_locks_off();
	 
	raw_spin_lock_init(&logbuf_lock);
	 
	sema_init(&console_sem, 1);
}

static int have_callable_console(void)
{
	struct console *con;

	for_each_console(con)
		if (con->flags & CON_ANYTIME)
			return 1;

	return 0;
}

static inline int can_use_console(unsigned int cpu)
{
	return cpu_online(cpu) || have_callable_console();
}

static int console_trylock_for_printk(void)
{
	unsigned int cpu = smp_processor_id();

	if (!console_trylock())
		return 0;
	 
	if (!can_use_console(cpu)) {
		console_locked = 0;
		up_console_sem();
		return 0;
	}
	return 1;
}

int printk_delay_msec __read_mostly;

static inline void printk_delay(void)
{
	if (unlikely(printk_delay_msec)) {
		int m = printk_delay_msec;

		while (m--) {
			mdelay(1);
			touch_nmi_watchdog();
		}
	}
}

static struct cont {
	char buf[LOG_LINE_MAX];
	size_t len;			 
	size_t cons;			 
	struct task_struct *owner;	 
	u64 ts_nsec;			 
	u8 level;			 
	u8 facility;			 
	enum log_flags flags;		 
	bool flushed:1;			 
} cont;

static void cont_flush(enum log_flags flags)
{
	if (cont.flushed)
		return;
	if (cont.len == 0)
		return;

	if (cont.cons) {
		 
		log_store(cont.facility, cont.level, flags | LOG_NOCONS,
			  cont.ts_nsec, NULL, 0, cont.buf, cont.len);
		cont.flags = flags;
		cont.flushed = true;
	} else {
		 
		log_store(cont.facility, cont.level, flags, 0,
			  NULL, 0, cont.buf, cont.len);
		cont.len = 0;
	}
}

static bool cont_add(int facility, int level, const char *text, size_t len)
{
	if (cont.len && cont.flushed)
		return false;

	if (nr_ext_console_drivers || cont.len + len > sizeof(cont.buf)) {
		cont_flush(LOG_CONT);
		return false;
	}

	if (!cont.len) {
		cont.facility = facility;
		cont.level = level;
		cont.owner = current;
		cont.ts_nsec = local_clock();
		cont.flags = 0;
		cont.cons = 0;
		cont.flushed = false;
	}

	memcpy(cont.buf + cont.len, text, len);
	cont.len += len;

	if (cont.len > (sizeof(cont.buf) * 80) / 100)
		cont_flush(LOG_CONT);

	return true;
}

static size_t cont_print_text(char *text, size_t size)
{
	size_t textlen = 0;
	size_t len;

	if (cont.cons == 0 && (console_prev & LOG_NEWLINE)) {
		textlen += print_time(cont.ts_nsec, text);
		size -= textlen;
	}

	len = cont.len - cont.cons;
	if (len > 0) {
		if (len+1 > size)
			len = size-1;
		memcpy(text + textlen, cont.buf + cont.cons, len);
		textlen += len;
		cont.cons = cont.len;
	}

	if (cont.flushed) {
		if (cont.flags & LOG_NEWLINE)
			text[textlen++] = '\n';
		 
		cont.len = 0;
	}
	return textlen;
}

asmlinkage int vprintk_emit(int facility, int level,
			    const char *dict, size_t dictlen,
			    const char *fmt, va_list args)
{
	static int recursion_bug;
	static char textbuf[LOG_LINE_MAX];
	char *text = textbuf;
	size_t text_len = 0;
	enum log_flags lflags = 0;
	unsigned long flags;
	int this_cpu;
	int printed_len = 0;
	bool in_sched = false;
	 
	static unsigned int logbuf_cpu = UINT_MAX;

	if (level == LOGLEVEL_SCHED) {
		level = LOGLEVEL_DEFAULT;
		in_sched = true;
	}

	boot_delay_msec(level);
	printk_delay();

	local_irq_save(flags);
	this_cpu = smp_processor_id();

	if (unlikely(logbuf_cpu == this_cpu)) {
		 
		if (!oops_in_progress && !lockdep_recursing(current)) {
			recursion_bug = 1;
			local_irq_restore(flags);
			return 0;
		}
		zap_locks();
	}

	lockdep_off();
	raw_spin_lock(&logbuf_lock);
	logbuf_cpu = this_cpu;

	if (unlikely(recursion_bug)) {
		static const char recursion_msg[] =
			"BUG: recent printk recursion!";

		recursion_bug = 0;
		 
		printed_len += log_store(0, 2, LOG_PREFIX|LOG_NEWLINE, 0,
					 NULL, 0, recursion_msg,
					 strlen(recursion_msg));
	}

	text_len = vscnprintf(text, sizeof(textbuf), fmt, args);

	if (text_len && text[text_len-1] == '\n') {
		text_len--;
		lflags |= LOG_NEWLINE;
	}

	if (facility == 0) {
		int kern_level = printk_get_level(text);

		if (kern_level) {
			const char *end_of_header = printk_skip_level(text);
			switch (kern_level) {
			case '0' ... '7':
				if (level == LOGLEVEL_DEFAULT)
					level = kern_level - '0';
				 
			case 'd':	 
				lflags |= LOG_PREFIX;
			}
			 
			text_len -= end_of_header - text;
			text = (char *)end_of_header;
		}
	}

	if (level == LOGLEVEL_DEFAULT)
		level = default_message_loglevel;

	if (dict)
		lflags |= LOG_PREFIX|LOG_NEWLINE;

	if (!(lflags & LOG_NEWLINE)) {
		 
		if (cont.len && (lflags & LOG_PREFIX || cont.owner != current))
			cont_flush(LOG_NEWLINE);

		if (cont_add(facility, level, text, text_len))
			printed_len += text_len;
		else
			printed_len += log_store(facility, level,
						 lflags | LOG_CONT, 0,
						 dict, dictlen, text, text_len);
	} else {
		bool stored = false;

		if (cont.len) {
			if (cont.owner == current && !(lflags & LOG_PREFIX))
				stored = cont_add(facility, level, text,
						  text_len);
			cont_flush(LOG_NEWLINE);
		}

		if (stored)
			printed_len += text_len;
		else
			printed_len += log_store(facility, level, lflags, 0,
						 dict, dictlen, text, text_len);
	}

	logbuf_cpu = UINT_MAX;
	raw_spin_unlock(&logbuf_lock);
	lockdep_on();
	local_irq_restore(flags);

	if (!in_sched) {
		lockdep_off();
		 
		preempt_disable();

		if (console_trylock_for_printk())
			console_unlock();
		preempt_enable();
		lockdep_on();
	}

	return printed_len;
}
EXPORT_SYMBOL(vprintk_emit);

asmlinkage int vprintk(const char *fmt, va_list args)
{
	return vprintk_emit(0, LOGLEVEL_DEFAULT, NULL, 0, fmt, args);
}
EXPORT_SYMBOL(vprintk);

asmlinkage int printk_emit(int facility, int level,
			   const char *dict, size_t dictlen,
			   const char *fmt, ...)
{
	va_list args;
	int r;

	va_start(args, fmt);
	r = vprintk_emit(facility, level, dict, dictlen, fmt, args);
	va_end(args);

	return r;
}
EXPORT_SYMBOL(printk_emit);

int vprintk_default(const char *fmt, va_list args)
{
	int r;

#ifdef CONFIG_KGDB_KDB
	if (unlikely(kdb_trap_printk)) {
		r = vkdb_printf(KDB_MSGSRC_PRINTK, fmt, args);
		return r;
	}
#endif
	r = vprintk_emit(0, LOGLEVEL_DEFAULT, NULL, 0, fmt, args);

	return r;
}
EXPORT_SYMBOL_GPL(vprintk_default);

DEFINE_PER_CPU(printk_func_t, printk_func) = vprintk_default;

asmlinkage __visible int printk(const char *fmt, ...)
{
	printk_func_t vprintk_func;
	va_list args;
	int r;

	va_start(args, fmt);

	vprintk_func = this_cpu_read(printk_func);
	r = vprintk_func(fmt, args);

	va_end(args);

	return r;
}
EXPORT_SYMBOL(printk);

#else  

#define LOG_LINE_MAX		0
#define PREFIX_MAX		0

static u64 syslog_seq;
static u32 syslog_idx;
static u64 console_seq;
static u32 console_idx;
static enum log_flags syslog_prev;
static u64 log_first_seq;
static u32 log_first_idx;
static u64 log_next_seq;
static enum log_flags console_prev;
static struct cont {
	size_t len;
	size_t cons;
	u8 level;
	bool flushed:1;
} cont;
static char *log_text(const struct printk_log *msg) { return NULL; }
static char *log_dict(const struct printk_log *msg) { return NULL; }
static struct printk_log *log_from_idx(u32 idx) { return NULL; }
static u32 log_next(u32 idx) { return 0; }
static ssize_t msg_print_ext_header(char *buf, size_t size,
				    struct printk_log *msg, u64 seq,
				    enum log_flags prev_flags) { return 0; }
static ssize_t msg_print_ext_body(char *buf, size_t size,
				  char *dict, size_t dict_len,
				  char *text, size_t text_len) { return 0; }
static void call_console_drivers(int level,
				 const char *ext_text, size_t ext_len,
				 const char *text, size_t len) {}
static size_t msg_print_text(const struct printk_log *msg, enum log_flags prev,
			     bool syslog, char *buf, size_t size) { return 0; }
static size_t cont_print_text(char *text, size_t size) { return 0; }

DEFINE_PER_CPU(printk_func_t, printk_func);

#endif  

#ifdef CONFIG_EARLY_PRINTK
struct console *early_console;

asmlinkage __visible void early_printk(const char *fmt, ...)
{
	va_list ap;
	char buf[512];
	int n;

	if (!early_console)
		return;

	va_start(ap, fmt);
	n = vscnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	early_console->write(early_console, buf, n);
}
#endif

static int __add_preferred_console(char *name, int idx, char *options,
				   char *brl_options)
{
	struct console_cmdline *c;
	int i;

	for (i = 0, c = console_cmdline;
	     i < MAX_CMDLINECONSOLES && c->name[0];
	     i++, c++) {
		if (strcmp(c->name, name) == 0 && c->index == idx) {
			if (!brl_options)
				selected_console = i;
			return 0;
		}
	}
	if (i == MAX_CMDLINECONSOLES)
		return -E2BIG;
	if (!brl_options)
		selected_console = i;
	strlcpy(c->name, name, sizeof(c->name));
	c->options = options;
	braille_set_options(c, brl_options);

	c->index = idx;
	return 0;
}
 
static int __init console_setup(char *str)
{
	char buf[sizeof(console_cmdline[0].name) + 4];  
	char *s, *options, *brl_options = NULL;
	int idx;

	if (_braille_console_setup(&str, &brl_options))
		return 1;

	if (str[0] >= '0' && str[0] <= '9') {
		strcpy(buf, "ttyS");
		strncpy(buf + 4, str, sizeof(buf) - 5);
	} else {
		strncpy(buf, str, sizeof(buf) - 1);
	}
	buf[sizeof(buf) - 1] = 0;
	options = strchr(str, ',');
	if (options)
		*(options++) = 0;
#ifdef __sparc__
	if (!strcmp(str, "ttya"))
		strcpy(buf, "ttyS0");
	if (!strcmp(str, "ttyb"))
		strcpy(buf, "ttyS1");
#endif
	for (s = buf; *s; s++)
		if (isdigit(*s) || *s == ',')
			break;
	idx = simple_strtoul(s, NULL, 10);
	*s = 0;

	__add_preferred_console(buf, idx, options, brl_options);
	console_set_on_cmdline = 1;
	return 1;
}
__setup("console=", console_setup);

int add_preferred_console(char *name, int idx, char *options)
{
	return __add_preferred_console(name, idx, options, NULL);
}

bool console_suspend_enabled = true;
EXPORT_SYMBOL(console_suspend_enabled);

static int __init console_suspend_disable(char *str)
{
	console_suspend_enabled = false;
	return 1;
}
__setup("no_console_suspend", console_suspend_disable);
module_param_named(console_suspend, console_suspend_enabled,
		bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(console_suspend, "suspend console during suspend"
	" and hibernate operations");

void suspend_console(void)
{
	if (!console_suspend_enabled)
		return;
	printk("Suspending console(s) (use no_console_suspend to debug)\n");
	console_lock();
	console_suspended = 1;
	up_console_sem();
}

void resume_console(void)
{
	if (!console_suspend_enabled)
		return;
	down_console_sem();
	console_suspended = 0;
	console_unlock();
}

static int console_cpu_notify(struct notifier_block *self,
	unsigned long action, void *hcpu)
{
	switch (action) {
	case CPU_ONLINE:
	case CPU_DEAD:
	case CPU_DOWN_FAILED:
	case CPU_UP_CANCELED:
		console_lock();
		console_unlock();
	}
	return NOTIFY_OK;
}

void console_lock(void)
{
	might_sleep();

	down_console_sem();
	if (console_suspended)
		return;
	console_locked = 1;
	console_may_schedule = 1;
}
EXPORT_SYMBOL(console_lock);

int console_trylock(void)
{
	if (down_trylock_console_sem())
		return 0;
	if (console_suspended) {
		up_console_sem();
		return 0;
	}
	console_locked = 1;
	console_may_schedule = 0;
	return 1;
}
EXPORT_SYMBOL(console_trylock);

int is_console_locked(void)
{
	return console_locked;
}

static void console_cont_flush(char *text, size_t size)
{
	unsigned long flags;
	size_t len;

	raw_spin_lock_irqsave(&logbuf_lock, flags);

	if (!cont.len)
		goto out;

	if (console_seq < log_next_seq && !cont.cons)
		goto out;

	len = cont_print_text(text, size);
	raw_spin_unlock(&logbuf_lock);
	stop_critical_timings();
	call_console_drivers(cont.level, NULL, 0, text, len);
	start_critical_timings();
	local_irq_restore(flags);
	return;
out:
	raw_spin_unlock_irqrestore(&logbuf_lock, flags);
}

void console_unlock(void)
{
	static char ext_text[CONSOLE_EXT_LOG_MAX];
	static char text[LOG_LINE_MAX + PREFIX_MAX];
	static u64 seen_seq;
	unsigned long flags;
	bool wake_klogd = false;
	bool do_cond_resched, retry;

	if (console_suspended) {
		up_console_sem();
		return;
	}

	do_cond_resched = console_may_schedule;
	console_may_schedule = 0;

	console_cont_flush(text, sizeof(text));
again:
	for (;;) {
		struct printk_log *msg;
		size_t ext_len = 0;
		size_t len;
		int level;

		raw_spin_lock_irqsave(&logbuf_lock, flags);
		if (seen_seq != log_next_seq) {
			wake_klogd = true;
			seen_seq = log_next_seq;
		}

		if (console_seq < log_first_seq) {
			len = sprintf(text, "** %u printk messages dropped ** ",
				      (unsigned)(log_first_seq - console_seq));

			console_seq = log_first_seq;
			console_idx = log_first_idx;
			console_prev = 0;
		} else {
			len = 0;
		}
skip:
		if (console_seq == log_next_seq)
			break;

		msg = log_from_idx(console_idx);
		if (msg->flags & LOG_NOCONS) {
			 
			console_idx = log_next(console_idx);
			console_seq++;
			 
			msg->flags &= ~LOG_NOCONS;
			console_prev = msg->flags;
			goto skip;
		}

		level = msg->level;
		len += msg_print_text(msg, console_prev, false,
				      text + len, sizeof(text) - len);
		if (nr_ext_console_drivers) {
			ext_len = msg_print_ext_header(ext_text,
						sizeof(ext_text),
						msg, console_seq, console_prev);
			ext_len += msg_print_ext_body(ext_text + ext_len,
						sizeof(ext_text) - ext_len,
						log_dict(msg), msg->dict_len,
						log_text(msg), msg->text_len);
		}
		console_idx = log_next(console_idx);
		console_seq++;
		console_prev = msg->flags;
		raw_spin_unlock(&logbuf_lock);

		stop_critical_timings();	 
		call_console_drivers(level, ext_text, ext_len, text, len);
		start_critical_timings();
		local_irq_restore(flags);

		if (do_cond_resched)
			cond_resched();
	}
	console_locked = 0;

	if (unlikely(exclusive_console))
		exclusive_console = NULL;

	raw_spin_unlock(&logbuf_lock);

	up_console_sem();

	raw_spin_lock(&logbuf_lock);
	retry = console_seq != log_next_seq;
	raw_spin_unlock_irqrestore(&logbuf_lock, flags);

	if (retry && console_trylock())
		goto again;

	if (wake_klogd)
		wake_up_klogd();
}
EXPORT_SYMBOL(console_unlock);

void __sched console_conditional_schedule(void)
{
	if (console_may_schedule)
		cond_resched();
}
EXPORT_SYMBOL(console_conditional_schedule);

void console_unblank(void)
{
	struct console *c;

	if (oops_in_progress) {
		if (down_trylock_console_sem() != 0)
			return;
	} else
		console_lock();

	console_locked = 1;
	console_may_schedule = 0;
	for_each_console(c)
		if ((c->flags & CON_ENABLED) && c->unblank)
			c->unblank();
	console_unlock();
}

void console_flush_on_panic(void)
{
	 
	console_trylock();
	console_may_schedule = 0;
	console_unlock();
}

struct tty_driver *console_device(int *index)
{
	struct console *c;
	struct tty_driver *driver = NULL;

	console_lock();
	for_each_console(c) {
		if (!c->device)
			continue;
		driver = c->device(c, index);
		if (driver)
			break;
	}
	console_unlock();
	return driver;
}

void console_stop(struct console *console)
{
	console_lock();
	console->flags &= ~CON_ENABLED;
	console_unlock();
}
EXPORT_SYMBOL(console_stop);

void console_start(struct console *console)
{
	console_lock();
	console->flags |= CON_ENABLED;
	console_unlock();
}
EXPORT_SYMBOL(console_start);

static int __read_mostly keep_bootcon;

static int __init keep_bootcon_setup(char *str)
{
	keep_bootcon = 1;
	pr_info("debug: skip boot console de-registration.\n");

	return 0;
}

early_param("keep_bootcon", keep_bootcon_setup);

void register_console(struct console *newcon)
{
	int i;
	unsigned long flags;
	struct console *bcon = NULL;
	struct console_cmdline *c;

	if (console_drivers)
		for_each_console(bcon)
			if (WARN(bcon == newcon,
					"console '%s%d' already registered\n",
					bcon->name, bcon->index))
				return;

	if (console_drivers && newcon->flags & CON_BOOT) {
		 
		for_each_console(bcon) {
			if (!(bcon->flags & CON_BOOT)) {
				pr_info("Too late to register bootconsole %s%d\n",
					newcon->name, newcon->index);
				return;
			}
		}
	}

	if (console_drivers && console_drivers->flags & CON_BOOT)
		bcon = console_drivers;

	if (preferred_console < 0 || bcon || !console_drivers)
		preferred_console = selected_console;

	if (preferred_console < 0) {
		if (newcon->index < 0)
			newcon->index = 0;
		if (newcon->setup == NULL ||
		    newcon->setup(newcon, NULL) == 0) {
			newcon->flags |= CON_ENABLED;
			if (newcon->device) {
				newcon->flags |= CON_CONSDEV;
				preferred_console = 0;
			}
		}
	}

	for (i = 0, c = console_cmdline;
	     i < MAX_CMDLINECONSOLES && c->name[0];
	     i++, c++) {
		if (!newcon->match ||
		    newcon->match(newcon, c->name, c->index, c->options) != 0) {
			 
			BUILD_BUG_ON(sizeof(c->name) != sizeof(newcon->name));
			if (strcmp(c->name, newcon->name) != 0)
				continue;
			if (newcon->index >= 0 &&
			    newcon->index != c->index)
				continue;
			if (newcon->index < 0)
				newcon->index = c->index;

			if (_braille_register_console(newcon, c))
				return;

			if (newcon->setup &&
			    newcon->setup(newcon, c->options) != 0)
				break;
		}

		newcon->flags |= CON_ENABLED;
		if (i == selected_console) {
			newcon->flags |= CON_CONSDEV;
			preferred_console = selected_console;
		}
		break;
	}

	if (!(newcon->flags & CON_ENABLED))
		return;

	if (bcon && ((newcon->flags & (CON_CONSDEV | CON_BOOT)) == CON_CONSDEV))
		newcon->flags &= ~CON_PRINTBUFFER;

	console_lock();
	if ((newcon->flags & CON_CONSDEV) || console_drivers == NULL) {
		newcon->next = console_drivers;
		console_drivers = newcon;
		if (newcon->next)
			newcon->next->flags &= ~CON_CONSDEV;
	} else {
		newcon->next = console_drivers->next;
		console_drivers->next = newcon;
	}

	if (newcon->flags & CON_EXTENDED)
		if (!nr_ext_console_drivers++)
			pr_info("printk: continuation disabled due to ext consoles, expect more fragments in /dev/kmsg\n");

	if (newcon->flags & CON_PRINTBUFFER) {
		 
		raw_spin_lock_irqsave(&logbuf_lock, flags);
#if defined(MY_DEF_HERE)
		console_seq = dnv_console_seq;
		console_idx = dnv_console_idx;
#else
		console_seq = syslog_seq;
		console_idx = syslog_idx;
#endif
		console_prev = syslog_prev;
		raw_spin_unlock_irqrestore(&logbuf_lock, flags);
		 
		exclusive_console = newcon;
	}
	console_unlock();
	console_sysfs_notify();

	pr_info("%sconsole [%s%d] enabled\n",
		(newcon->flags & CON_BOOT) ? "boot" : "" ,
		newcon->name, newcon->index);
	if (bcon &&
	    ((newcon->flags & (CON_CONSDEV | CON_BOOT)) == CON_CONSDEV) &&
	    !keep_bootcon) {
		 
		for_each_console(bcon)
			if (bcon->flags & CON_BOOT)
				unregister_console(bcon);
	}
}
EXPORT_SYMBOL(register_console);

#if defined(MY_ABC_HERE) || defined(MY_DEF_HERE)
static void __ref pci_console_unmap_memory(void __iomem *addr, u32 size)
{
	if (!addr || !size)
		return;

	else
		early_iounmap(addr, size);
}
#endif  

int unregister_console(struct console *console)
{
        struct console *a, *b;
	int res;

	pr_info("%sconsole [%s%d] disabled\n",
		(console->flags & CON_BOOT) ? "boot" : "" ,
		console->name, console->index);

#if defined(MY_DEF_HERE)
	dnv_console_seq = console_seq;
	dnv_console_idx = console_idx;
#endif

	res = _braille_unregister_console(console);
	if (res)
		return res;

	res = 1;
	console_lock();
	if (console_drivers == console) {
		console_drivers=console->next;
		res = 0;
	} else if (console_drivers) {
		for (a=console_drivers->next, b=console_drivers ;
		     a; b=a, a=b->next) {
			if (a == console) {
				b->next = a->next;
				res = 0;
				break;
			}
		}
	}

	if (!res && (console->flags & CON_EXTENDED))
		nr_ext_console_drivers--;

	if (console_drivers != NULL && console->flags & CON_CONSDEV)
		console_drivers->flags |= CON_CONSDEV;

	console->flags &= ~CON_ENABLED;
	console_unlock();
	console_sysfs_notify();
#if defined(MY_ABC_HERE) || defined(MY_DEF_HERE)
	if (console->pcimapaddress) {
		pci_console_unmap_memory(console->pcimapaddress, console->pcimapsize);
	}
#endif  
	return res;
}
EXPORT_SYMBOL(unregister_console);

static int __init printk_late_init(void)
{
	struct console *con;

	for_each_console(con) {
		if (!keep_bootcon && con->flags & CON_BOOT) {
			unregister_console(con);
		}
	}
	hotcpu_notifier(console_cpu_notify, 0);
	return 0;
}
late_initcall(printk_late_init);

#if defined CONFIG_PRINTK
 
#define PRINTK_PENDING_WAKEUP	0x01
#define PRINTK_PENDING_OUTPUT	0x02

static DEFINE_PER_CPU(int, printk_pending);

static void wake_up_klogd_work_func(struct irq_work *irq_work)
{
	int pending = __this_cpu_xchg(printk_pending, 0);

	if (pending & PRINTK_PENDING_OUTPUT) {
		 
		if (console_trylock())
			console_unlock();
	}

	if (pending & PRINTK_PENDING_WAKEUP)
		wake_up_interruptible(&log_wait);
}

static DEFINE_PER_CPU(struct irq_work, wake_up_klogd_work) = {
	.func = wake_up_klogd_work_func,
	.flags = IRQ_WORK_LAZY,
};

void wake_up_klogd(void)
{
	preempt_disable();
	if (waitqueue_active(&log_wait)) {
		this_cpu_or(printk_pending, PRINTK_PENDING_WAKEUP);
		irq_work_queue(this_cpu_ptr(&wake_up_klogd_work));
	}
	preempt_enable();
}

int printk_deferred(const char *fmt, ...)
{
	va_list args;
	int r;

	preempt_disable();
	va_start(args, fmt);
	r = vprintk_emit(0, LOGLEVEL_SCHED, NULL, 0, fmt, args);
	va_end(args);

	__this_cpu_or(printk_pending, PRINTK_PENDING_OUTPUT);
	irq_work_queue(this_cpu_ptr(&wake_up_klogd_work));
	preempt_enable();

	return r;
}

DEFINE_RATELIMIT_STATE(printk_ratelimit_state, 5 * HZ, 10);

int __printk_ratelimit(const char *func)
{
	return ___ratelimit(&printk_ratelimit_state, func);
}
EXPORT_SYMBOL(__printk_ratelimit);

bool printk_timed_ratelimit(unsigned long *caller_jiffies,
			unsigned int interval_msecs)
{
	unsigned long elapsed = jiffies - *caller_jiffies;

	if (*caller_jiffies && elapsed <= msecs_to_jiffies(interval_msecs))
		return false;

	*caller_jiffies = jiffies;
	return true;
}
EXPORT_SYMBOL(printk_timed_ratelimit);

static DEFINE_SPINLOCK(dump_list_lock);
static LIST_HEAD(dump_list);

int kmsg_dump_register(struct kmsg_dumper *dumper)
{
	unsigned long flags;
	int err = -EBUSY;

	if (!dumper->dump)
		return -EINVAL;

	spin_lock_irqsave(&dump_list_lock, flags);
	 
	if (!dumper->registered) {
		dumper->registered = 1;
		list_add_tail_rcu(&dumper->list, &dump_list);
		err = 0;
	}
	spin_unlock_irqrestore(&dump_list_lock, flags);

	return err;
}
EXPORT_SYMBOL_GPL(kmsg_dump_register);

int kmsg_dump_unregister(struct kmsg_dumper *dumper)
{
	unsigned long flags;
	int err = -EINVAL;

	spin_lock_irqsave(&dump_list_lock, flags);
	if (dumper->registered) {
		dumper->registered = 0;
		list_del_rcu(&dumper->list);
		err = 0;
	}
	spin_unlock_irqrestore(&dump_list_lock, flags);
	synchronize_rcu();

	return err;
}
EXPORT_SYMBOL_GPL(kmsg_dump_unregister);

static bool always_kmsg_dump;
module_param_named(always_kmsg_dump, always_kmsg_dump, bool, S_IRUGO | S_IWUSR);

void kmsg_dump(enum kmsg_dump_reason reason)
{
	struct kmsg_dumper *dumper;
	unsigned long flags;

	if ((reason > KMSG_DUMP_OOPS) && !always_kmsg_dump)
		return;

	rcu_read_lock();
	list_for_each_entry_rcu(dumper, &dump_list, list) {
		if (dumper->max_reason && reason > dumper->max_reason)
			continue;

		dumper->active = true;

		raw_spin_lock_irqsave(&logbuf_lock, flags);
		dumper->cur_seq = clear_seq;
		dumper->cur_idx = clear_idx;
		dumper->next_seq = log_next_seq;
		dumper->next_idx = log_next_idx;
		raw_spin_unlock_irqrestore(&logbuf_lock, flags);

		dumper->dump(dumper, reason);

		dumper->active = false;
	}
	rcu_read_unlock();
}

bool kmsg_dump_get_line_nolock(struct kmsg_dumper *dumper, bool syslog,
			       char *line, size_t size, size_t *len)
{
	struct printk_log *msg;
	size_t l = 0;
	bool ret = false;

	if (!dumper->active)
		goto out;

	if (dumper->cur_seq < log_first_seq) {
		 
		dumper->cur_seq = log_first_seq;
		dumper->cur_idx = log_first_idx;
	}

	if (dumper->cur_seq >= log_next_seq)
		goto out;

	msg = log_from_idx(dumper->cur_idx);
	l = msg_print_text(msg, 0, syslog, line, size);

	dumper->cur_idx = log_next(dumper->cur_idx);
	dumper->cur_seq++;
	ret = true;
out:
	if (len)
		*len = l;
	return ret;
}

bool kmsg_dump_get_line(struct kmsg_dumper *dumper, bool syslog,
			char *line, size_t size, size_t *len)
{
	unsigned long flags;
	bool ret;

	raw_spin_lock_irqsave(&logbuf_lock, flags);
	ret = kmsg_dump_get_line_nolock(dumper, syslog, line, size, len);
	raw_spin_unlock_irqrestore(&logbuf_lock, flags);

	return ret;
}
EXPORT_SYMBOL_GPL(kmsg_dump_get_line);

bool kmsg_dump_get_buffer(struct kmsg_dumper *dumper, bool syslog,
			  char *buf, size_t size, size_t *len)
{
	unsigned long flags;
	u64 seq;
	u32 idx;
	u64 next_seq;
	u32 next_idx;
	enum log_flags prev;
	size_t l = 0;
	bool ret = false;

	if (!dumper->active)
		goto out;

	raw_spin_lock_irqsave(&logbuf_lock, flags);
	if (dumper->cur_seq < log_first_seq) {
		 
		dumper->cur_seq = log_first_seq;
		dumper->cur_idx = log_first_idx;
	}

	if (dumper->cur_seq >= dumper->next_seq) {
		raw_spin_unlock_irqrestore(&logbuf_lock, flags);
		goto out;
	}

	seq = dumper->cur_seq;
	idx = dumper->cur_idx;
	prev = 0;
	while (seq < dumper->next_seq) {
		struct printk_log *msg = log_from_idx(idx);

		l += msg_print_text(msg, prev, true, NULL, 0);
		idx = log_next(idx);
		seq++;
		prev = msg->flags;
	}

	seq = dumper->cur_seq;
	idx = dumper->cur_idx;
	prev = 0;
	while (l > size && seq < dumper->next_seq) {
		struct printk_log *msg = log_from_idx(idx);

		l -= msg_print_text(msg, prev, true, NULL, 0);
		idx = log_next(idx);
		seq++;
		prev = msg->flags;
	}

	next_seq = seq;
	next_idx = idx;

	l = 0;
	while (seq < dumper->next_seq) {
		struct printk_log *msg = log_from_idx(idx);

		l += msg_print_text(msg, prev, syslog, buf + l, size - l);
		idx = log_next(idx);
		seq++;
		prev = msg->flags;
	}

	dumper->next_seq = next_seq;
	dumper->next_idx = next_idx;
	ret = true;
	raw_spin_unlock_irqrestore(&logbuf_lock, flags);
out:
	if (len)
		*len = l;
	return ret;
}
EXPORT_SYMBOL_GPL(kmsg_dump_get_buffer);

void kmsg_dump_rewind_nolock(struct kmsg_dumper *dumper)
{
	dumper->cur_seq = clear_seq;
	dumper->cur_idx = clear_idx;
	dumper->next_seq = log_next_seq;
	dumper->next_idx = log_next_idx;
}

void kmsg_dump_rewind(struct kmsg_dumper *dumper)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&logbuf_lock, flags);
	kmsg_dump_rewind_nolock(dumper);
	raw_spin_unlock_irqrestore(&logbuf_lock, flags);
}
EXPORT_SYMBOL_GPL(kmsg_dump_rewind);

static char dump_stack_arch_desc_str[128];

void __init dump_stack_set_arch_desc(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vsnprintf(dump_stack_arch_desc_str, sizeof(dump_stack_arch_desc_str),
		  fmt, args);
	va_end(args);
}

void dump_stack_print_info(const char *log_lvl)
{
	printk("%sCPU: %d PID: %d Comm: %.20s %s %s %.*s\n",
	       log_lvl, raw_smp_processor_id(), current->pid, current->comm,
	       print_tainted(), init_utsname()->release,
	       (int)strcspn(init_utsname()->version, " "),
	       init_utsname()->version);

	if (dump_stack_arch_desc_str[0] != '\0')
		printk("%sHardware name: %s\n",
		       log_lvl, dump_stack_arch_desc_str);

	print_worker_info(log_lvl, current);
}

void show_regs_print_info(const char *log_lvl)
{
	dump_stack_print_info(log_lvl);

	printk("%stask: %p ti: %p task.ti: %p\n",
	       log_lvl, current, current_thread_info(),
	       task_thread_info(current));
}

#endif
