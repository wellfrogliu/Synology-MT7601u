#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/jiffies.h>
#include <linux/hwmon.h>
#include <linux/sysfs.h>
#include <linux/hwmon-sysfs.h>
#include <linux/err.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/platform_device.h>
#include <linux/cpu.h>
#include <linux/smp.h>
#include <linux/moduleparam.h>
#include <linux/pci.h>
#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/cpu_device_id.h>

#define DRVNAME	"coretemp"

static int force_tjmax;
module_param_named(tjmax, force_tjmax, int, 0444);
MODULE_PARM_DESC(tjmax, "TjMax value in degrees Celsius");

#define BASE_SYSFS_ATTR_NO	2	 
#define NUM_REAL_CORES		128	 
#define CORETEMP_NAME_LENGTH	19	 
#define MAX_CORE_ATTRS		4	 
#define TOTAL_ATTRS		(MAX_CORE_ATTRS + 1)
#define MAX_CORE_DATA		(NUM_REAL_CORES + BASE_SYSFS_ATTR_NO)

#define TO_PHYS_ID(cpu)		(cpu_data(cpu).phys_proc_id)
#define TO_CORE_ID(cpu)		(cpu_data(cpu).cpu_core_id)
#define TO_ATTR_NO(cpu)		(TO_CORE_ID(cpu) + BASE_SYSFS_ATTR_NO)

#ifdef CONFIG_SMP
#define for_each_sibling(i, cpu) \
	for_each_cpu(i, topology_sibling_cpumask(cpu))
#else
#define for_each_sibling(i, cpu)	for (i = 0; false; )
#endif

struct temp_data {
	int temp;
	int ttarget;
	int tjmax;
	unsigned long last_updated;
	unsigned int cpu;
	u32 cpu_core_id;
	u32 status_reg;
	int attr_size;
	bool is_pkg_data;
	bool valid;
	struct sensor_device_attribute sd_attrs[TOTAL_ATTRS];
	char attr_name[TOTAL_ATTRS][CORETEMP_NAME_LENGTH];
	struct attribute *attrs[TOTAL_ATTRS + 1];
	struct attribute_group attr_group;
	struct mutex update_lock;
};

struct platform_data {
	struct device *hwmon_dev;
	u16 phys_proc_id;
	struct temp_data *core_data[MAX_CORE_DATA];
	struct device_attribute name_attr;
};

struct pdev_entry {
	struct list_head list;
	struct platform_device *pdev;
	u16 phys_proc_id;
};

static LIST_HEAD(pdev_list);
static DEFINE_MUTEX(pdev_list_mutex);

static ssize_t show_label(struct device *dev,
				struct device_attribute *devattr, char *buf)
{
	struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
	struct platform_data *pdata = dev_get_drvdata(dev);
	struct temp_data *tdata = pdata->core_data[attr->index];

	if (tdata->is_pkg_data)
		return sprintf(buf, "Physical id %u\n", pdata->phys_proc_id);

	return sprintf(buf, "Core %u\n", tdata->cpu_core_id);
}

static ssize_t show_crit_alarm(struct device *dev,
				struct device_attribute *devattr, char *buf)
{
	u32 eax, edx;
	struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
	struct platform_data *pdata = dev_get_drvdata(dev);
	struct temp_data *tdata = pdata->core_data[attr->index];

	rdmsr_on_cpu(tdata->cpu, tdata->status_reg, &eax, &edx);

	return sprintf(buf, "%d\n", (eax >> 5) & 1);
}

static ssize_t show_tjmax(struct device *dev,
			struct device_attribute *devattr, char *buf)
{
	struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
	struct platform_data *pdata = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", pdata->core_data[attr->index]->tjmax);
}

static ssize_t show_ttarget(struct device *dev,
				struct device_attribute *devattr, char *buf)
{
	struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
	struct platform_data *pdata = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", pdata->core_data[attr->index]->ttarget);
}

static ssize_t show_temp(struct device *dev,
			struct device_attribute *devattr, char *buf)
{
	u32 eax, edx;
	struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
	struct platform_data *pdata = dev_get_drvdata(dev);
	struct temp_data *tdata = pdata->core_data[attr->index];

	mutex_lock(&tdata->update_lock);

	if (!tdata->valid || time_after(jiffies, tdata->last_updated + HZ)) {
		rdmsr_on_cpu(tdata->cpu, tdata->status_reg, &eax, &edx);
		 
		tdata->temp = tdata->tjmax - ((eax >> 16) & 0x7f) * 1000;
		tdata->valid = 1;
		tdata->last_updated = jiffies;
	}

	mutex_unlock(&tdata->update_lock);
	return sprintf(buf, "%d\n", tdata->temp);
}

struct tjmax_pci {
	unsigned int device;
	int tjmax;
};

static const struct tjmax_pci tjmax_pci_table[] = {
	{ 0x0708, 110000 },	 
	{ 0x0c72, 102000 },	 
	{ 0x0c73, 95000 },	 
	{ 0x0c75, 95000 },	 
};

struct tjmax {
	char const *id;
	int tjmax;
};

static const struct tjmax tjmax_table[] = {
	{ "CPU  230", 100000 },		 
	{ "CPU  330", 125000 },		 
};

struct tjmax_model {
	u8 model;
	u8 mask;
	int tjmax;
};

#define ANY 0xff

static const struct tjmax_model tjmax_model_table[] = {
	{ 0x1c, 10, 100000 },	 
	{ 0x1c, ANY, 90000 },	 
	{ 0x26, ANY, 90000 },	 
	{ 0x27, ANY, 90000 },	 
	{ 0x35, ANY, 90000 },	 
	{ 0x36, ANY, 100000 },	 
};

static int adjust_tjmax(struct cpuinfo_x86 *c, u32 id, struct device *dev)
{
	 
	int tjmax = 100000;
	int tjmax_ee = 85000;
	int usemsr_ee = 1;
	int err;
	u32 eax, edx;
	int i;
	struct pci_dev *host_bridge = pci_get_bus_and_slot(0, PCI_DEVFN(0, 0));

	if (host_bridge && host_bridge->vendor == PCI_VENDOR_ID_INTEL) {
		for (i = 0; i < ARRAY_SIZE(tjmax_pci_table); i++) {
			if (host_bridge->device == tjmax_pci_table[i].device)
				return tjmax_pci_table[i].tjmax;
		}
	}

	for (i = 0; i < ARRAY_SIZE(tjmax_table); i++) {
		if (strstr(c->x86_model_id, tjmax_table[i].id))
			return tjmax_table[i].tjmax;
	}

	for (i = 0; i < ARRAY_SIZE(tjmax_model_table); i++) {
		const struct tjmax_model *tm = &tjmax_model_table[i];
		if (c->x86_model == tm->model &&
		    (tm->mask == ANY || c->x86_mask == tm->mask))
			return tm->tjmax;
	}

	if (c->x86_model == 0xf && c->x86_mask < 4)
		usemsr_ee = 0;

	if (c->x86_model > 0xe && usemsr_ee) {
		u8 platform_id;

		err = rdmsr_safe_on_cpu(id, 0x17, &eax, &edx);
		if (err) {
			dev_warn(dev,
				 "Unable to access MSR 0x17, assuming desktop"
				 " CPU\n");
			usemsr_ee = 0;
		} else if (c->x86_model < 0x17 && !(eax & 0x10000000)) {
			 
			usemsr_ee = 0;
		} else {
			 
			platform_id = (edx >> 18) & 0x7;

			if (c->x86_model == 0x17 &&
			    (platform_id == 5 || platform_id == 7)) {
				 
				tjmax_ee = 90000;
				tjmax = 105000;
			}
		}
	}

	if (usemsr_ee) {
		err = rdmsr_safe_on_cpu(id, 0xee, &eax, &edx);
		if (err) {
			dev_warn(dev,
				 "Unable to access MSR 0xEE, for Tjmax, left"
				 " at default\n");
		} else if (eax & 0x40000000) {
			tjmax = tjmax_ee;
		}
	} else if (tjmax == 100000) {
		 
		dev_warn(dev, "Using relative temperature scale!\n");
	}

	return tjmax;
}

static bool cpu_has_tjmax(struct cpuinfo_x86 *c)
{
	u8 model = c->x86_model;

	return model > 0xe &&
	       model != 0x1c &&
	       model != 0x26 &&
	       model != 0x27 &&
	       model != 0x35 &&
	       model != 0x36;
}

static int get_tjmax(struct cpuinfo_x86 *c, u32 id, struct device *dev)
{
	int err;
	u32 eax, edx;
	u32 val;

	err = rdmsr_safe_on_cpu(id, MSR_IA32_TEMPERATURE_TARGET, &eax, &edx);
	if (err) {
		if (cpu_has_tjmax(c))
			dev_warn(dev, "Unable to read TjMax from CPU %u\n", id);
	} else {
		val = (eax >> 16) & 0xff;
		 
		if (val) {
			dev_dbg(dev, "TjMax is %d degrees C\n", val);
			return val * 1000;
		}
	}

	if (force_tjmax) {
		dev_notice(dev, "TjMax forced to %d degrees C by user\n",
			   force_tjmax);
		return force_tjmax * 1000;
	}

	return adjust_tjmax(c, id, dev);
}

static int create_core_attrs(struct temp_data *tdata, struct device *dev,
			     int attr_no)
{
	int i;
	static ssize_t (*const rd_ptr[TOTAL_ATTRS]) (struct device *dev,
			struct device_attribute *devattr, char *buf) = {
			show_label, show_crit_alarm, show_temp, show_tjmax,
			show_ttarget };
	static const char *const suffixes[TOTAL_ATTRS] = {
		"label", "crit_alarm", "input", "crit", "max"
	};

	for (i = 0; i < tdata->attr_size; i++) {
		snprintf(tdata->attr_name[i], CORETEMP_NAME_LENGTH,
			 "temp%d_%s", attr_no, suffixes[i]);
		sysfs_attr_init(&tdata->sd_attrs[i].dev_attr.attr);
		tdata->sd_attrs[i].dev_attr.attr.name = tdata->attr_name[i];
		tdata->sd_attrs[i].dev_attr.attr.mode = S_IRUGO;
		tdata->sd_attrs[i].dev_attr.show = rd_ptr[i];
		tdata->sd_attrs[i].index = attr_no;
		tdata->attrs[i] = &tdata->sd_attrs[i].dev_attr.attr;
	}
	tdata->attr_group.attrs = tdata->attrs;
	return sysfs_create_group(&dev->kobj, &tdata->attr_group);
}

static int chk_ucode_version(unsigned int cpu)
{
	struct cpuinfo_x86 *c = &cpu_data(cpu);

	if (c->x86_model == 0xe && c->x86_mask < 0xc && c->microcode < 0x39) {
		pr_err("Errata AE18 not fixed, update BIOS or microcode of the CPU!\n");
		return -ENODEV;
	}
	return 0;
}

static struct platform_device *coretemp_get_pdev(unsigned int cpu)
{
	u16 phys_proc_id = TO_PHYS_ID(cpu);
	struct pdev_entry *p;

	mutex_lock(&pdev_list_mutex);

	list_for_each_entry(p, &pdev_list, list)
		if (p->phys_proc_id == phys_proc_id) {
			mutex_unlock(&pdev_list_mutex);
			return p->pdev;
		}

	mutex_unlock(&pdev_list_mutex);
	return NULL;
}

static struct temp_data *init_temp_data(unsigned int cpu, int pkg_flag)
{
	struct temp_data *tdata;

	tdata = kzalloc(sizeof(struct temp_data), GFP_KERNEL);
	if (!tdata)
		return NULL;

	tdata->status_reg = pkg_flag ? MSR_IA32_PACKAGE_THERM_STATUS :
							MSR_IA32_THERM_STATUS;
	tdata->is_pkg_data = pkg_flag;
	tdata->cpu = cpu;
	tdata->cpu_core_id = TO_CORE_ID(cpu);
#ifdef MY_ABC_HERE
	 
	tdata->temp = 20 * 1000;
#endif  
	tdata->attr_size = MAX_CORE_ATTRS;
	mutex_init(&tdata->update_lock);
	return tdata;
}

static int create_core_data(struct platform_device *pdev, unsigned int cpu,
			    int pkg_flag)
{
	struct temp_data *tdata;
	struct platform_data *pdata = platform_get_drvdata(pdev);
	struct cpuinfo_x86 *c = &cpu_data(cpu);
	u32 eax, edx;
	int err, attr_no;

	attr_no = pkg_flag ? 1 : TO_ATTR_NO(cpu);

	if (attr_no > MAX_CORE_DATA - 1)
		return -ERANGE;

	if (pdata->core_data[attr_no] != NULL)
		return 0;

	tdata = init_temp_data(cpu, pkg_flag);
	if (!tdata)
		return -ENOMEM;

	err = rdmsr_safe_on_cpu(cpu, tdata->status_reg, &eax, &edx);
	if (err)
		goto exit_free;

	tdata->tjmax = get_tjmax(c, cpu, &pdev->dev);

	if (c->x86_model > 0xe && c->x86_model != 0x1c) {
		err = rdmsr_safe_on_cpu(cpu, MSR_IA32_TEMPERATURE_TARGET,
					&eax, &edx);
		if (!err) {
			tdata->ttarget
			  = tdata->tjmax - ((eax >> 8) & 0xff) * 1000;
			tdata->attr_size++;
		}
	}

	pdata->core_data[attr_no] = tdata;

	err = create_core_attrs(tdata, pdata->hwmon_dev, attr_no);
	if (err)
		goto exit_free;

	return 0;
exit_free:
	pdata->core_data[attr_no] = NULL;
	kfree(tdata);
	return err;
}

static void coretemp_add_core(unsigned int cpu, int pkg_flag)
{
	struct platform_device *pdev = coretemp_get_pdev(cpu);
	int err;

	if (!pdev)
		return;

	err = create_core_data(pdev, cpu, pkg_flag);
	if (err)
		dev_err(&pdev->dev, "Adding Core %u failed\n", cpu);
}

static void coretemp_remove_core(struct platform_data *pdata,
				 int indx)
{
	struct temp_data *tdata = pdata->core_data[indx];

	sysfs_remove_group(&pdata->hwmon_dev->kobj, &tdata->attr_group);

	kfree(pdata->core_data[indx]);
	pdata->core_data[indx] = NULL;
}

static int coretemp_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct platform_data *pdata;

	pdata = devm_kzalloc(dev, sizeof(struct platform_data), GFP_KERNEL);
	if (!pdata)
		return -ENOMEM;

	pdata->phys_proc_id = pdev->id;
	platform_set_drvdata(pdev, pdata);

	pdata->hwmon_dev = devm_hwmon_device_register_with_groups(dev, DRVNAME,
								  pdata, NULL);
	return PTR_ERR_OR_ZERO(pdata->hwmon_dev);
}

static int coretemp_remove(struct platform_device *pdev)
{
	struct platform_data *pdata = platform_get_drvdata(pdev);
	int i;

	for (i = MAX_CORE_DATA - 1; i >= 0; --i)
		if (pdata->core_data[i])
			coretemp_remove_core(pdata, i);

	return 0;
}

static struct platform_driver coretemp_driver = {
	.driver = {
		.name = DRVNAME,
	},
	.probe = coretemp_probe,
	.remove = coretemp_remove,
};

static int coretemp_device_add(unsigned int cpu)
{
	int err;
	struct platform_device *pdev;
	struct pdev_entry *pdev_entry;

	mutex_lock(&pdev_list_mutex);

	pdev = platform_device_alloc(DRVNAME, TO_PHYS_ID(cpu));
	if (!pdev) {
		err = -ENOMEM;
		pr_err("Device allocation failed\n");
		goto exit;
	}

	pdev_entry = kzalloc(sizeof(struct pdev_entry), GFP_KERNEL);
	if (!pdev_entry) {
		err = -ENOMEM;
		goto exit_device_put;
	}

	err = platform_device_add(pdev);
	if (err) {
		pr_err("Device addition failed (%d)\n", err);
		goto exit_device_free;
	}

	pdev_entry->pdev = pdev;
	pdev_entry->phys_proc_id = pdev->id;

	list_add_tail(&pdev_entry->list, &pdev_list);
	mutex_unlock(&pdev_list_mutex);

	return 0;

exit_device_free:
	kfree(pdev_entry);
exit_device_put:
	platform_device_put(pdev);
exit:
	mutex_unlock(&pdev_list_mutex);
	return err;
}

static void coretemp_device_remove(unsigned int cpu)
{
	struct pdev_entry *p, *n;
	u16 phys_proc_id = TO_PHYS_ID(cpu);

	mutex_lock(&pdev_list_mutex);
	list_for_each_entry_safe(p, n, &pdev_list, list) {
		if (p->phys_proc_id != phys_proc_id)
			continue;
		platform_device_unregister(p->pdev);
		list_del(&p->list);
		kfree(p);
	}
	mutex_unlock(&pdev_list_mutex);
}

static bool is_any_core_online(struct platform_data *pdata)
{
	int i;

	for (i = MAX_CORE_DATA - 1; i >= 0; --i) {
		if (pdata->core_data[i] &&
			!pdata->core_data[i]->is_pkg_data) {
			return true;
		}
	}
	return false;
}

static void get_core_online(unsigned int cpu)
{
	struct cpuinfo_x86 *c = &cpu_data(cpu);
	struct platform_device *pdev = coretemp_get_pdev(cpu);
	int err;

	if (!cpu_has(c, X86_FEATURE_DTHERM))
		return;

	if (!pdev) {
		 
		if (chk_ucode_version(cpu))
			return;

		err = coretemp_device_add(cpu);
		if (err)
			return;
		 
		if (cpu_has(c, X86_FEATURE_PTS))
			coretemp_add_core(cpu, 1);
	}
	 
	coretemp_add_core(cpu, 0);
}

static void put_core_offline(unsigned int cpu)
{
	int i, indx;
	struct platform_data *pdata;
	struct platform_device *pdev = coretemp_get_pdev(cpu);

	if (!pdev)
		return;

	pdata = platform_get_drvdata(pdev);

	indx = TO_ATTR_NO(cpu);

	if (indx > MAX_CORE_DATA - 1)
		return;

	if (pdata->core_data[indx] && pdata->core_data[indx]->cpu == cpu)
		coretemp_remove_core(pdata, indx);

	for_each_sibling(i, cpu) {
		if (i != cpu) {
			get_core_online(i);
			 
			break;
		}
	}
	 
	if (!is_any_core_online(pdata))
		coretemp_device_remove(cpu);
}

static int coretemp_cpu_callback(struct notifier_block *nfb,
				 unsigned long action, void *hcpu)
{
	unsigned int cpu = (unsigned long) hcpu;

	switch (action) {
	case CPU_ONLINE:
	case CPU_DOWN_FAILED:
		get_core_online(cpu);
		break;
	case CPU_DOWN_PREPARE:
		put_core_offline(cpu);
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block coretemp_cpu_notifier __refdata = {
	.notifier_call = coretemp_cpu_callback,
};

static const struct x86_cpu_id __initconst coretemp_ids[] = {
	{ X86_VENDOR_INTEL, X86_FAMILY_ANY, X86_MODEL_ANY, X86_FEATURE_DTHERM },
	{}
};
MODULE_DEVICE_TABLE(x86cpu, coretemp_ids);

static int __init coretemp_init(void)
{
	int i, err;

	if (!x86_match_cpu(coretemp_ids))
		return -ENODEV;

	err = platform_driver_register(&coretemp_driver);
	if (err)
		goto exit;

	cpu_notifier_register_begin();
	for_each_online_cpu(i)
		get_core_online(i);

#ifndef CONFIG_HOTPLUG_CPU
	if (list_empty(&pdev_list)) {
		cpu_notifier_register_done();
		err = -ENODEV;
		goto exit_driver_unreg;
	}
#endif

	__register_hotcpu_notifier(&coretemp_cpu_notifier);
	cpu_notifier_register_done();
	return 0;

#ifndef CONFIG_HOTPLUG_CPU
exit_driver_unreg:
	platform_driver_unregister(&coretemp_driver);
#endif
exit:
	return err;
}

static void __exit coretemp_exit(void)
{
	struct pdev_entry *p, *n;

	cpu_notifier_register_begin();
	__unregister_hotcpu_notifier(&coretemp_cpu_notifier);
	mutex_lock(&pdev_list_mutex);
	list_for_each_entry_safe(p, n, &pdev_list, list) {
		platform_device_unregister(p->pdev);
		list_del(&p->list);
		kfree(p);
	}
	mutex_unlock(&pdev_list_mutex);
	cpu_notifier_register_done();
	platform_driver_unregister(&coretemp_driver);
}

#ifdef MY_ABC_HERE
#include <linux/synobios.h>
 
static void syno_update_temp(struct temp_data *tdata)
{
	u32 eax, edx;

	mutex_lock(&tdata->update_lock);
	 
	if (!tdata->valid || time_after(jiffies, tdata->last_updated + HZ)) {
		rdmsr_on_cpu(tdata->cpu, tdata->status_reg, &eax, &edx);
		tdata->valid = 0;
		 
		if (eax & 0x80000000) {
			tdata->temp = tdata->tjmax -
					((eax >> 16) & 0x7f) * 1000;
			tdata->valid = 1;
		}
		tdata->last_updated = jiffies;
	}
	mutex_unlock(&tdata->update_lock);
}

int syno_cpu_temperature(struct _SynoCpuTemp *pCpuTemp)
{
	struct platform_data *pdata = NULL;
	struct pdev_entry *p = NULL;
	struct pdev_entry *n = NULL;
	struct temp_data *tdata = NULL;
	int    iCpuCount = 0;
	int    iIndex = 0;

	if (NULL == pCpuTemp) {
		printk("coretemp: parameter error.\n");
		return -1;
	}

	mutex_lock(&pdev_list_mutex);
	list_for_each_entry_safe(p, n, &pdev_list, list) {
		pdata = dev_get_drvdata(&(p->pdev->dev));
		if (!pdata) {
			printk("Can't get Core %d data\n", p->phys_proc_id);
			continue;
		}
		iIndex = TO_ATTR_NO(p->phys_proc_id);
		tdata = pdata->core_data[iIndex];
		if (!tdata) {
			printk("Can't get Core %d temperature data\n", p->phys_proc_id);
			continue;
		}
		if (MAX_CPU <= iCpuCount) {
			printk("CPU count larger than MAX_CPU %d: %d\n", MAX_CPU, iCpuCount);
		} else {
			 
			syno_update_temp(tdata);
			pCpuTemp->cpu_temp[iCpuCount] = tdata->temp / 1000;
			++iCpuCount;
		}
	}
	mutex_unlock(&pdev_list_mutex);
	pCpuTemp->cpu_num = iCpuCount;

	return 0;
}
EXPORT_SYMBOL(syno_cpu_temperature);
#endif  

MODULE_AUTHOR("Rudolf Marek <r.marek@assembler.cz>");
MODULE_DESCRIPTION("Intel Core temperature monitor");
MODULE_LICENSE("GPL");

module_init(coretemp_init)
module_exit(coretemp_exit)
