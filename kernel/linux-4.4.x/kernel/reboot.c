#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#define pr_fmt(fmt)	"reboot: " fmt

#include <linux/ctype.h>
#include <linux/export.h>
#include <linux/kexec.h>
#include <linux/kmod.h>
#include <linux/kmsg_dump.h>
#include <linux/reboot.h>
#include <linux/suspend.h>
#include <linux/syscalls.h>
#include <linux/syscore_ops.h>
#include <linux/uaccess.h>
#if defined(MY_ABC_HERE) && defined(MY_ABC_HERE)
#include <linux/tty.h>
#endif  
#ifdef MY_ABC_HERE
#include <linux/gpio.h>
#include <linux/delay.h>
#ifdef MY_DEF_HERE
extern u32 syno_pch_lpc_gpio_pin(int pin, int *pValue, int isWrite);
#endif  
extern char gSynoUsbVbusHostAddr[CONFIG_SYNO_USB_VBUS_NUM_GPIO][13];
extern int gSynoUsbVbusPort[CONFIG_SYNO_USB_VBUS_NUM_GPIO];
extern unsigned gSynoUsbVbusGpp[CONFIG_SYNO_USB_VBUS_NUM_GPIO];
extern unsigned gSynoUsbVbusGppPol[CONFIG_SYNO_USB_VBUS_NUM_GPIO];
#endif  

#ifdef MY_ABC_HERE
#include <linux/syno_gpio.h>
extern SYNO_GPIO syno_gpio;
extern void SYNO_GPIO_WRITE(int pin, int pValue);
#endif  

int C_A_D = 1;
struct pid *cad_pid;
EXPORT_SYMBOL(cad_pid);

#if defined(CONFIG_ARM) || defined(CONFIG_UNICORE32)
#define DEFAULT_REBOOT_MODE		= REBOOT_HARD
#else
#define DEFAULT_REBOOT_MODE
#endif
enum reboot_mode reboot_mode DEFAULT_REBOOT_MODE;

int reboot_default = 1;
int reboot_cpu;
enum reboot_type reboot_type = BOOT_ACPI;
int reboot_force;

void (*pm_power_off_prepare)(void);

void emergency_restart(void)
{
	kmsg_dump(KMSG_DUMP_EMERG);
	machine_emergency_restart();
}
EXPORT_SYMBOL_GPL(emergency_restart);

#ifdef MY_ABC_HERE
static void syno_turnoff_all_usb_vbus_gpio(void)
{
        int gpio_off_value = 0;
        int i = 0;
        for (i = 0; i < CONFIG_SYNO_USB_VBUS_NUM_GPIO; i++) {
                if (0 != gSynoUsbVbusGpp[i]) {
#ifdef MY_DEF_HERE
                        gpio_off_value = !(gpio_off_value ^ gSynoUsbVbusGppPol[i]);
                        syno_pch_lpc_gpio_pin(gSynoUsbVbusGpp[i],
                                              &gpio_off_value, 1);
#elif defined(MY_ABC_HERE)
                        SYNO_GPIO_WRITE(gSynoUsbVbusGpp[i],
                                !(gpio_off_value ^ gSynoUsbVbusGppPol[i]));
#endif  
                        printk(KERN_INFO "Turned off USB vbus gpio %u (%s)\n",
                               gSynoUsbVbusGpp[i],
			       gSynoUsbVbusGppPol[i] ? "ACTIVE_HIGH" : "ACTIVE_LOW");
                }
        }
#ifdef CONFIG_SYNO_USB_POWER_OFF_TIME
	mdelay(CONFIG_SYNO_USB_POWER_OFF_TIME);
#endif  
}
#endif  

void kernel_restart_prepare(char *cmd)
{
	blocking_notifier_call_chain(&reboot_notifier_list, SYS_RESTART, cmd);
	system_state = SYSTEM_RESTART;
	usermodehelper_disable();
	device_shutdown();
#ifdef MY_ABC_HERE
	if (SYSTEM_RESTART == system_state)
		syno_turnoff_all_usb_vbus_gpio();
#endif  
}

int register_reboot_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&reboot_notifier_list, nb);
}
EXPORT_SYMBOL(register_reboot_notifier);

int unregister_reboot_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&reboot_notifier_list, nb);
}
EXPORT_SYMBOL(unregister_reboot_notifier);

static ATOMIC_NOTIFIER_HEAD(restart_handler_list);

int register_restart_handler(struct notifier_block *nb)
{
	return atomic_notifier_chain_register(&restart_handler_list, nb);
}
EXPORT_SYMBOL(register_restart_handler);

int unregister_restart_handler(struct notifier_block *nb)
{
	return atomic_notifier_chain_unregister(&restart_handler_list, nb);
}
EXPORT_SYMBOL(unregister_restart_handler);

void do_kernel_restart(char *cmd)
{
	atomic_notifier_call_chain(&restart_handler_list, reboot_mode, cmd);
}

void migrate_to_reboot_cpu(void)
{
	 
	int cpu = reboot_cpu;

	cpu_hotplug_disable();

	if (!cpu_online(cpu))
		cpu = cpumask_first(cpu_online_mask);

	current->flags |= PF_NO_SETAFFINITY;

	set_cpus_allowed_ptr(current, cpumask_of(cpu));
}

void kernel_restart(char *cmd)
{
	kernel_restart_prepare(cmd);
	migrate_to_reboot_cpu();
	syscore_shutdown();
	if (!cmd)
		pr_emerg("Restarting system\n");
	else
		pr_emerg("Restarting system with command '%s'\n", cmd);
	kmsg_dump(KMSG_DUMP_RESTART);
	machine_restart(cmd);
}
EXPORT_SYMBOL_GPL(kernel_restart);

static void kernel_shutdown_prepare(enum system_states state)
{
	blocking_notifier_call_chain(&reboot_notifier_list,
		(state == SYSTEM_HALT) ? SYS_HALT : SYS_POWER_OFF, NULL);
	system_state = state;
#ifdef MY_DEF_HERE
	if (state != SYSTEM_POWER_OFF)
		usermodehelper_disable();
#else  
	usermodehelper_disable();
#endif  

#if defined(CONFIG_ARCH_RTD129X) && defined(MY_DEF_HERE)
	if (state != SYSTEM_POWER_OFF)
		device_shutdown();
#else
	device_shutdown();
#endif
#ifdef MY_ABC_HERE
	if (SYSTEM_POWER_OFF == system_state)
		syno_turnoff_all_usb_vbus_gpio();
#endif  
#if defined(MY_ABC_HERE) && defined(MY_ABC_HERE)
	 
	if (syno_is_hw_version(HW_DS718p) || syno_is_hw_version(HW_DS218p)) {
		SYNO_GPIO_WRITE (PHY_LED_CTRL_PIN(), 0);
	}
#endif  
}
 
void kernel_halt(void)
{
	kernel_shutdown_prepare(SYSTEM_HALT);
	migrate_to_reboot_cpu();
	syscore_shutdown();
	pr_emerg("System halted\n");
	kmsg_dump(KMSG_DUMP_HALT);
	machine_halt();
}
EXPORT_SYMBOL_GPL(kernel_halt);

#ifdef MY_ABC_HERE
extern int syno_schedule_power_on_prepare(void);
#endif  
void kernel_power_off(void)
{
	kernel_shutdown_prepare(SYSTEM_POWER_OFF);
#ifdef MY_ABC_HERE 
	syno_schedule_power_on_prepare();
#endif  
	if (pm_power_off_prepare)
		pm_power_off_prepare();
	migrate_to_reboot_cpu();
	syscore_shutdown();
	pr_emerg("Power down\n");
	kmsg_dump(KMSG_DUMP_POWEROFF);
	machine_power_off();
}
EXPORT_SYMBOL_GPL(kernel_power_off);

#if defined(MY_ABC_HERE) && defined(MY_ABC_HERE)
#define UART_TTYS_INDEX 1

#define UART_CMD_REBOOT 67  
#define UART_CMD_POWEROFF 49  
#endif  

static DEFINE_MUTEX(reboot_mutex);

SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,
		void __user *, arg)
{
	struct pid_namespace *pid_ns = task_active_pid_ns(current);
	char buffer[256];
	int ret = 0;
#if defined(MY_ABC_HERE) && defined(MY_ABC_HERE)
	char szBuf[2];
#endif  

	if (!ns_capable(pid_ns->user_ns, CAP_SYS_BOOT))
		return -EPERM;

	if (magic1 != LINUX_REBOOT_MAGIC1 ||
			(magic2 != LINUX_REBOOT_MAGIC2 &&
			magic2 != LINUX_REBOOT_MAGIC2A &&
			magic2 != LINUX_REBOOT_MAGIC2B &&
			magic2 != LINUX_REBOOT_MAGIC2C))
		return -EINVAL;

	ret = reboot_pid_ns(pid_ns, cmd);
	if (ret)
		return ret;

	if ((cmd == LINUX_REBOOT_CMD_POWER_OFF) && !pm_power_off)
		cmd = LINUX_REBOOT_CMD_HALT;

	mutex_lock(&reboot_mutex);
	switch (cmd) {
	case LINUX_REBOOT_CMD_RESTART:
#if defined(MY_ABC_HERE) && defined(MY_ABC_HERE)
		szBuf[0] = UART_CMD_REBOOT;
		szBuf[1] = '\0';
		syno_ttys_write(UART_TTYS_INDEX, szBuf);
#endif  
		kernel_restart(NULL);
		break;

	case LINUX_REBOOT_CMD_CAD_ON:
		C_A_D = 1;
		break;

	case LINUX_REBOOT_CMD_CAD_OFF:
		C_A_D = 0;
		break;

	case LINUX_REBOOT_CMD_HALT:
		kernel_halt();
		do_exit(0);
		panic("cannot halt");

	case LINUX_REBOOT_CMD_POWER_OFF:
#if defined(MY_ABC_HERE) && defined(MY_ABC_HERE)
		szBuf[0] = UART_CMD_POWEROFF;
		szBuf[1] = '\0';
		syno_ttys_write(UART_TTYS_INDEX, szBuf);
#endif  
		kernel_power_off();
		do_exit(0);
		break;

	case LINUX_REBOOT_CMD_RESTART2:
		ret = strncpy_from_user(&buffer[0], arg, sizeof(buffer) - 1);
		if (ret < 0) {
			ret = -EFAULT;
			break;
		}
		buffer[sizeof(buffer) - 1] = '\0';

		kernel_restart(buffer);
		break;

#ifdef CONFIG_KEXEC_CORE
	case LINUX_REBOOT_CMD_KEXEC:
		ret = kernel_kexec();
		break;
#endif

#ifdef CONFIG_HIBERNATION
	case LINUX_REBOOT_CMD_SW_SUSPEND:
		ret = hibernate();
		break;
#endif

	default:
		ret = -EINVAL;
		break;
	}
	mutex_unlock(&reboot_mutex);
	return ret;
}

static void deferred_cad(struct work_struct *dummy)
{
	kernel_restart(NULL);
}

void ctrl_alt_del(void)
{
	static DECLARE_WORK(cad_work, deferred_cad);

	if (C_A_D)
		schedule_work(&cad_work);
	else
		kill_cad_pid(SIGINT, 1);
}

char poweroff_cmd[POWEROFF_CMD_PATH_LEN] = "/sbin/poweroff";
static const char reboot_cmd[] = "/sbin/reboot";

static int run_cmd(const char *cmd)
{
	char **argv;
	static char *envp[] = {
		"HOME=/",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin",
		NULL
	};
	int ret;
	argv = argv_split(GFP_KERNEL, cmd, NULL);
	if (argv) {
		ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
		argv_free(argv);
	} else {
		ret = -ENOMEM;
	}

	return ret;
}

static int __orderly_reboot(void)
{
	int ret;

	ret = run_cmd(reboot_cmd);

	if (ret) {
		pr_warn("Failed to start orderly reboot: forcing the issue\n");
		emergency_sync();
		kernel_restart(NULL);
	}

	return ret;
}

static int __orderly_poweroff(bool force)
{
	int ret;

	ret = run_cmd(poweroff_cmd);

	if (ret && force) {
		pr_warn("Failed to start orderly shutdown: forcing the issue\n");

		emergency_sync();
		kernel_power_off();
	}

	return ret;
}

static bool poweroff_force;

static void poweroff_work_func(struct work_struct *work)
{
	__orderly_poweroff(poweroff_force);
}

static DECLARE_WORK(poweroff_work, poweroff_work_func);

void orderly_poweroff(bool force)
{
	if (force)  
		poweroff_force = true;
	schedule_work(&poweroff_work);
}
EXPORT_SYMBOL_GPL(orderly_poweroff);

static void reboot_work_func(struct work_struct *work)
{
	__orderly_reboot();
}

static DECLARE_WORK(reboot_work, reboot_work_func);

void orderly_reboot(void)
{
	schedule_work(&reboot_work);
}
EXPORT_SYMBOL_GPL(orderly_reboot);

static int __init reboot_setup(char *str)
{
	for (;;) {
		 
		reboot_default = 0;

		switch (*str) {
		case 'w':
			reboot_mode = REBOOT_WARM;
			break;

		case 'c':
			reboot_mode = REBOOT_COLD;
			break;

		case 'h':
			reboot_mode = REBOOT_HARD;
			break;

		case 's':
		{
			int rc;

			if (isdigit(*(str+1))) {
				rc = kstrtoint(str+1, 0, &reboot_cpu);
				if (rc)
					return rc;
			} else if (str[1] == 'm' && str[2] == 'p' &&
				   isdigit(*(str+3))) {
				rc = kstrtoint(str+3, 0, &reboot_cpu);
				if (rc)
					return rc;
			} else
				reboot_mode = REBOOT_SOFT;
			break;
		}
		case 'g':
			reboot_mode = REBOOT_GPIO;
			break;

		case 'b':
		case 'a':
		case 'k':
		case 't':
		case 'e':
		case 'p':
			reboot_type = *str;
			break;

		case 'f':
			reboot_force = 1;
			break;
		}

		str = strchr(str, ',');
		if (str)
			str++;
		else
			break;
	}
	return 1;
}
__setup("reboot=", reboot_setup);
